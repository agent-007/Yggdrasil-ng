# PR: Replace mpsc channel with TrafficBuffer in encrypted reader

## Problem

The inbound packet path contains three cross-task hops:

```
peer_reader → router → encrypted_reader_loop → tun_write_loop
             ①         ②                         ③
```

Each hop is a context switch (tokio task wakeup). On a single-core pinned
deployment, each CS costs 5-10µs. At 3500 pps (40 Mbps), that's ~10,500 CS/sec
just for inbound.

The third hop (③ `encrypted_reader_loop → tun_write_loop` via mpsc) is the
easiest to eliminate: decrypt and TUN-write can happen in the **same task**.

## Fix

Replace `mpsc` channel with `TrafficBuffer` (VecDeque + tokio::sync::Mutex + Notify).

`read_from()` has two paths:
1. **Fast path** — pop from buffer. Zero extra CS.
2. **Slow path** — `inner.read_from()` + decrypt inline. Same task, no CS.

Background `session_handler_loop` handles session handshake (init/ack) only.
`inner_lock: Arc<Mutex<()>>` serialises `inner.read_from()` between background
and inline reader.

**Changes:** 1 file, ~100 lines.

## Benchmarks (hAP ax³, 40 Mbps, +jemalloc +cortex-a53 +cpu3)

| Approach | CPU | CS/inbound |
|----------|-----|------------|
| mpsc channel | 30% | 3 |
| **TrafficBuffer** | -1 CS | combined with pool → 24% total |

## Why universal

Any async runtime pays for cross-task wakeups. On x86 the percentage is smaller
but the absolute overhead is identical.

## No breaking changes
