# PR-04: Fix read_from — remove inline-read, always pop_or_wait

## Problem

cs-v1 (TrafficBuffer) introduced an inline `read_from` path that reads
directly from `inner` when the TrafficBuffer is empty. This creates
lock contention with the background `session_handler_loop` when only
1 peer is connected:

```
Background reader: inner_lock.lock() → inner.read_from() → decrypt → push
read_from (inline): inner_lock.lock() → inner.read_from() → decrypt → deliver
                     ^^^ CONTENTION ^^^
```

With 7+ mesh peers, the buffer is always full and the fast path
(`try_pop`) always hits — the inline slow path is never triggered.
With 1 peer, `try_pop` frequently misses, triggering the inline slow
path which serializes on `inner_lock` with the background reader.

## Root cause

Two tasks (background reader + inline read_from) both call
`inner.read_from()` under the same `inner_lock`, causing:
- Lock contention → added latency
- Packet stealing → reordering between buffer and inline read
- In 0.2.0: 28→649ms jitter, 25% loss with 1 peer

## Fix

Remove the inline read_from path entirely. `read_from` always blocks
on `pop_or_wait` from the TrafficBuffer. The background reader is the
sole reader of `inner` — no lock contention.

Cleanup:
- Removed `inner_lock` from EncryptedPacketConn (no longer needed)
- Removed `curve_priv` from EncryptedPacketConn (only used by inline read)
- Removed `try_pop` from TrafficBuffer (no callers remain)
- Bumped BUFFER_CAPACITY 64→512 (matches original mpsc capacity)

## Benchmarks

**Before (v0.2.0, 1 peer):**
- ya.ru: 28→205ms (±177ms jitter), 25% loss
- 8.8.8.8: 43→649ms (±517ms jitter)

**After (v0.2.1, 1 peer):**
- ya.ru: 27ms ±1.5ms, 0% loss
- 8.8.8.8: 45ms ±2ms, 0% loss

Parity with stock v0.1.6 while preserving jemalloc + Vec-ownership CPU savings.

## Files changed

`crates/ironwood/src/encrypted/mod.rs`: 28 insertions, 73 deletions
