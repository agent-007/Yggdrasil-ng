# PR: Reduce context switches in inbound packet path

## Problem

The inbound packet path had 3 context switches (mpsc channel hops) per packet:

```
peer_reader → router → encrypted_reader_loop → recv_tx → Core::read_from → rwc.read → tun_write_loop
```

The `encrypted_reader_loop` decrypted packets and sent them via `mpsc` channel
to `tun_write_loop`. This added one context switch per inbound packet.

At 40 Mbps (~3500 pps), this is 3500 unnecessary CS/second.

## Fix

Replace `mpsc` channel with `TrafficBuffer` (VecDeque + tokio::sync::Mutex + Notify).

`read_from` first checks the buffer (fast path — pop). If empty, reads and
decrypts inline from `inner.read_from()` — zero extra CS on the hot path when
the TUN writer is the one waiting.

A background `session_handler_loop` still reads from inner to process session
handshake messages (init/ack), ensuring write_to-only nodes complete the
handshake. `inner_lock` (Arc<Mutex<()>>) serialises access between the
background reader and the inline `read_from`.

**Changes:** 1 file (crates/ironwood/src/encrypted/mod.rs).

**Result:** -1 context switch per inbound packet.

## Benchmarks (hAP ax³, 40 Mbps)

Combined with Vec ownership patch (patch 03):

| Before (both patches) | 30% CPU |
| After (both patches)  | 24% CPU |

## No breaking changes
