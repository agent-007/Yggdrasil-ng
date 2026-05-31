//! Encrypted PacketConn wrapper.
//!
//! Wraps a network-level `PacketConnImpl` with end-to-end XSalsa20-Poly1305 encryption
//! (via RustCrypto's `crypto_box` crate), session management, and key ratcheting for forward secrecy.

pub(crate) mod crypto;
pub(crate) mod session;

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;

use crate::config::Config;
use crate::core::PacketConnImpl;
use crate::types::{Addr, Error, Result};

use self::crypto::{ed25519_private_to_curve25519, CurvePrivateKey};
use self::session::{ConcurrentSessionManager, OutAction, SESSION_TRAFFIC_OVERHEAD};

/// Maximum number of decrypted packets buffered for read_from.
const BUFFER_CAPACITY: usize = 64;

/// A decrypted message waiting to be delivered.
#[derive(Clone)]
struct QueuedMessage {
    source: crate::crypto::PublicKey,
    data: Vec<u8>,
}

/// Shared buffer between the background reader and `read_from`.
struct TrafficBuffer {
    queue: Mutex<VecDeque<QueuedMessage>>,
    notify: tokio::sync::Notify,
}

impl TrafficBuffer {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::with_capacity(BUFFER_CAPACITY)),
            notify: tokio::sync::Notify::new(),
        })
    }

    /// Push a decrypted message. Returns true if a reader should be woken.
    async fn push(&self, msg: QueuedMessage) {
        let was_empty = {
            let mut q = self.queue.lock().await;
            let was_empty = q.is_empty();
            if q.len() < BUFFER_CAPACITY {
                q.push_back(msg);
            }
            was_empty
        };
        // Wake a reader only if the queue was empty (a reader might be sleeping).
        // If non-empty, readers are already in a pop loop.
        if was_empty {
            self.notify.notify_one();
        }
    }

    /// Try to pop a message without waiting. Returns immediately.
    async fn try_pop(&self) -> Option<QueuedMessage> {
        let mut q = self.queue.lock().await;
        q.pop_front()
    }

    /// Wait for a message or cancellation.
    async fn pop_or_wait(&self, cancel: &CancellationToken) -> Option<QueuedMessage> {
        loop {
            // Check queue first
            {
                let mut q = self.queue.lock().await;
                if let Some(msg) = q.pop_front() {
                    return Some(msg);
                }
            }
            // Wait for notification or cancellation
            tokio::select! {
                _ = cancel.cancelled() => return None,
                _ = self.notify.notified() => {}
            }
        }
    }
}

/// Public session entry returned by `get_sessions()`.
#[derive(Clone, Debug)]
pub struct SessionEntry {
    pub key: [u8; 32],
    pub uptime_seconds: f64,
    pub bytes_sent: u64,
    pub bytes_recvd: u64,
}

/// Encrypted PacketConn: wraps a network `PacketConnImpl` with encryption.
///
/// A background reader task (`session_handler_loop`) continuously reads raw
/// packets from the inner PacketConn, decrypts them, and routes session
/// protocol messages (init/ack) inline.  Decrypted traffic packets are pushed
/// into a low-overhead `TrafficBuffer` — a `VecDeque` behind a `tokio::sync::Mutex`
/// with a `Notify` for wakeup.  This replaces the heavier `mpsc` channel used
/// previously.
///
/// `read_from` pops from this buffer.  If the buffer is empty, `read_from`
/// reads and decrypts directly from the inner PacketConn, avoiding the
/// intermediate wakeup entirely on the hot path.
pub struct EncryptedPacketConn {
    /// The underlying network-level PacketConn.
    inner: Arc<PacketConnImpl>,
    /// Our Ed25519 signing key.
    signing_key: SigningKey,
    /// Our Curve25519 private key (derived from Ed25519 seed).
    curve_priv: CurvePrivateKey,
    /// Session manager with per-session locking.
    sessions: Arc<ConcurrentSessionManager>,
    /// Buffered decrypted traffic from background reader.
    buffer: Arc<TrafficBuffer>,
    /// Serialises access to `inner.read_from()` between the background reader
    /// and the inline read in `read_from`.  Both tasks may call inner.read_from()
    /// concurrently, so a mutex ensures packets are not stolen mid-read.
    inner_lock: Arc<Mutex<()>>,
    /// Whether this conn is closed.
    closed: AtomicBool,
    /// Cancellation for background tasks.
    cancel: CancellationToken,
    /// Background reader task handle.
    reader_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Session cleanup task handle.
    cleanup_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl EncryptedPacketConn {
    /// Create a new EncryptedPacketConn with the given private key and config.
    pub fn new(secret: SigningKey, config: Config) -> Self {
        let curve_priv = ed25519_private_to_curve25519(&secret);
        let inner = Arc::new(PacketConnImpl::new(secret.clone(), config));
        let sessions = Arc::new(ConcurrentSessionManager::new());
        let buffer = TrafficBuffer::new();
        let inner_lock = Arc::new(Mutex::new(()));
        let cancel = CancellationToken::new();

        // Spawn background reader for session management and traffic buffering
        let reader_handle = {
            let inner = inner.clone();
            let sessions = sessions.clone();
            let buffer = buffer.clone();
            let inner_lock = inner_lock.clone();
            let cancel = cancel.clone();
            let signing_key = secret.clone();
            let curve_priv = curve_priv;
            tokio::spawn(session_handler_loop(
                inner, sessions, buffer, inner_lock, cancel,
                signing_key, curve_priv,
            ))
        };

        // Spawn session cleanup task: removes expired sessions every 30s
        let cleanup_handle = {
            let sessions = sessions.clone();
            let cancel = cancel.clone();
            tokio::spawn(session_cleanup_loop(sessions, cancel))
        };

        Self {
            inner,
            signing_key: secret,
            curve_priv,
            sessions,
            buffer,
            inner_lock,
            closed: AtomicBool::new(false),
            cancel,
            reader_handle: Mutex::new(Some(reader_handle)),
            cleanup_handle: Mutex::new(Some(cleanup_handle)),
        }
    }

    /// Get info about all connected peers (delegates to inner).
    pub async fn get_peers(&self) -> Vec<crate::core::PeerInfo> {
        self.inner.get_peers().await
    }

    /// Get spanning tree entries (delegates to inner).
    pub async fn get_tree(&self) -> Vec<crate::core::TreeEntry> {
        self.inner.get_tree().await
    }

    /// Get the number of routing entries.
    pub async fn routing_entries(&self) -> usize {
        self.inner.routing_entries().await
    }

    /// Get our current tree coordinates (path from root).
    pub async fn tree_coordinates(&self) -> Vec<crate::wire::PeerPort> {
        self.inner.tree_coordinates().await
    }

    /// Get all cached paths (delegates to inner).
    pub async fn get_paths(&self) -> Vec<crate::core::PathEntry> {
        self.inner.get_paths().await
    }

    /// Get all active encrypted sessions.
    pub async fn get_sessions(&self) -> Vec<SessionEntry> {
        use std::time::Instant;
        let now = Instant::now();
        let snapshot = self.sessions.get_all_sessions();
        let mut result = Vec::with_capacity(snapshot.len());
        for (key, tx, rx, since) in snapshot {
            result.push(SessionEntry {
                key,
                uptime_seconds: now.duration_since(since).as_secs_f64(),
                bytes_sent: tx,
                bytes_recvd: rx,
            });
        }
        result.sort_by(|a, b| a.key.cmp(&b.key));
        result
    }

    /// Get routing peer keys (direct neighbors in spanning tree).
    pub async fn get_routing_peer_keys(&self) -> Vec<crate::crypto::PublicKey> {
        self.inner.get_routing_peer_keys().await
    }

    /// Get a diagnostic snapshot of internal routing state.
    pub async fn get_debug_snapshot(&self) -> crate::core::DebugSnapshot {
        self.inner.get_debug_snapshot().await
    }

    /// Count how many on-tree peers' bloom filters cover the given destination key.
    /// Returns (xformed_key, multicast_count).
    pub async fn count_lookup_targets(&self, dest: crate::crypto::PublicKey) -> (crate::crypto::PublicKey, usize) {
        self.inner.count_lookup_targets(dest).await
    }

    /// Force a path lookup for the given destination, bypassing the rumor throttle.
    /// Returns the number of peers the lookup was multicast to.
    pub async fn force_lookup(&self, dest: crate::crypto::PublicKey) -> usize {
        self.inner.force_lookup(dest).await
    }

    /// Force an immediate router refresh / re-announce (delegates to inner).
    pub fn force_refresh(&self) {
        self.inner.force_refresh();
    }
}

/// Background task that periodically cleans up expired sessions and buffers.
/// Runs every 30 seconds to remove sessions/buffers older than SESSION_TIMEOUT (60s).
async fn session_cleanup_loop(sessions: Arc<ConcurrentSessionManager>, cancel: CancellationToken) {
    use std::time::Duration;

    let mut interval = tokio::time::interval(Duration::from_secs(30));
    interval.tick().await; // Skip first immediate tick

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = interval.tick() => {
                sessions.cleanup_expired();
            }
        }
    }
}

/// Background reader: reads raw packets from inner, decrypts, and either
/// handles session protocol inline or buffers traffic for `read_from`.
async fn session_handler_loop(
    inner: Arc<PacketConnImpl>,
    sessions: Arc<ConcurrentSessionManager>,
    buffer: Arc<TrafficBuffer>,
    inner_lock: Arc<Mutex<()>>,
    cancel: CancellationToken,
    signing_key: SigningKey,
    curve_priv: CurvePrivateKey,
) {
    use crate::types::PacketConn;

    let mut buf = vec![0u8; 128 * 1024];

    loop {
        let read_result = {
            let _guard = inner_lock.lock().await;
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = inner.read_from(&mut buf) => result,
            }
        };

        let (n, from_addr) = match read_result {
            Ok((n, addr)) => (n, addr),
            Err(_) => break,
        };

        let from_key = from_addr.0;

        let actions = sessions.handle_data(
            &from_key, &buf[..n],
            &curve_priv, &signing_key,
        );

        for action in actions {
            match action {
                OutAction::SendToInner { dest, data } => {
                    let _ = inner.write_to(data, &Addr(dest)).await;
                }
                OutAction::Deliver { source, data } => {
                    buffer.push(QueuedMessage { source, data }).await;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl crate::types::PacketConn for EncryptedPacketConn {
    /// Read and decrypt a packet from the network.
    ///
    /// Hot path: first tries the traffic buffer (pushed by the background
    /// session handler).  If empty, reads directly from inner and decrypts
    /// inline — this eliminates the task wakeup when the calling task is
    /// the one waiting on `inner.read_from()`.
    async fn read_from(&self, buf: &mut [u8]) -> Result<(usize, Addr)> {
        use crate::types::PacketConn;

        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        // Fast path: check buffer first (cheap, no wakeup needed)
        if let Some(msg) = self.buffer.try_pop().await {
            let n = buf.len().min(msg.data.len());
            buf[..n].copy_from_slice(&msg.data[..n]);
            return Ok((n, Addr(msg.source)));
        }

        // Slow path: nothing buffered — read from inner directly.
        // This avoids the context switch between background reader and us.
        let cancel = self.cancel.clone();
        let mut inner_buf = vec![0u8; 128 * 1024];

        loop {
            let read_result = {
                let _guard = self.inner_lock.lock().await;
                tokio::select! {
                    _ = cancel.cancelled() => return Err(Error::Closed),
                    result = self.inner.read_from(&mut inner_buf) => result,
                }
            };

            let (n, from_addr) = read_result?;
            let from_key = from_addr.0;

            let actions = self.sessions.handle_data(
                &from_key, &inner_buf[..n],
                &self.curve_priv, &self.signing_key,
            );

            for action in actions {
                match action {
                    OutAction::SendToInner { dest, data } => {
                        let _ = self.inner.write_to(data, &Addr(dest)).await;
                    }
                    OutAction::Deliver { source, data } => {
                        let n = buf.len().min(data.len());
                        buf[..n].copy_from_slice(&data[..n]);
                        return Ok((n, Addr(source)));
                    }
                }
            }
        }
    }

    async fn write_to(&self, buf: Vec<u8>, addr: &Addr) -> Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Closed);
        }

        let len = buf.len();
        let mtu = self.mtu();
        if len as u64 > mtu {
            return Err(Error::OversizedMessage);
        }

        let dest = addr.0;

        let actions = self.sessions.write_to(&dest, &buf, &self.signing_key);

        for action in actions {
            match action {
                OutAction::SendToInner { dest, data } => {
                    self.inner.write_to(data, &Addr(dest)).await?;
                }
                OutAction::Deliver { .. } => {
                    // write_to never produces Deliver — only handle_data does
                }
            }
        }

        Ok(len)
    }

    async fn handle_conn(&self, key: Addr, conn: Box<dyn crate::types::AsyncConn>, prio: u8) -> Result<()> {
        self.inner.handle_conn(key, conn, prio).await
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn private_key(&self) -> &SigningKey {
        &self.signing_key
    }

    fn mtu(&self) -> u64 {
        self.inner.mtu().saturating_sub(SESSION_TRAFFIC_OVERHEAD)
    }

    async fn send_lookup(&self, target: Addr) {
        self.inner.send_lookup(target).await;
    }

    async fn close(&self) -> Result<()> {
        if self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_err()
        {
            return Err(Error::Closed);
        }

        // Cancel background tasks
        self.cancel.cancel();

        // Wait for background tasks to finish gracefully
        if let Some(handle) = self.reader_handle.lock().await.take() {
            let _ = handle.await;
        }
        if let Some(handle) = self.cleanup_handle.lock().await.take() {
            let _ = handle.await;
        }

        // Close the inner connection
        self.inner.close().await
    }

    fn local_addr(&self) -> Addr {
        self.inner.local_addr()
    }
}

/// Create a new EncryptedPacketConn.
pub fn new_encrypted_packet_conn(secret: SigningKey, config: Config) -> Arc<EncryptedPacketConn> {
    Arc::new(EncryptedPacketConn::new(secret, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[tokio::test]
    async fn encrypted_create_and_close() {
        let key = SigningKey::generate(&mut OsRng);
        let config = Config::default();
        let conn = new_encrypted_packet_conn(key, config);

        use crate::types::PacketConn;
        assert!(!conn.is_closed());
        conn.close().await.unwrap();
        assert!(conn.is_closed());
    }

    #[tokio::test]
    async fn encrypted_mtu_accounts_for_overhead() {
        let key = SigningKey::generate(&mut OsRng);
        let conn = new_encrypted_packet_conn(key.clone(), Config::default());

        use crate::types::PacketConn;
        let inner_conn = crate::core::new_packet_conn(key, Config::default());
        let inner_mtu = inner_conn.mtu();
        let encrypted_mtu = conn.mtu();

        assert!(encrypted_mtu < inner_mtu);
        assert_eq!(encrypted_mtu, inner_mtu - SESSION_TRAFFIC_OVERHEAD);

        conn.close().await.unwrap();
        inner_conn.close().await.unwrap();
    }
}
