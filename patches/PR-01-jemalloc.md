# PR: Replace system allocator with jemalloc

## Problem

On musl-based targets (Alpine Linux, RouterOS containers, embedded systems),
`musl malloc` uses a **global lock** for all memory allocations. Under multi-threaded
workloads, this lock becomes the dominant bottleneck:

```
Thread A (crypto):  malloc(512)  ──┐
Thread B (routing): malloc(1024) ──┤── wait for global lock
Thread C (TUN r/w): free(ptr)    ──┘
```

yggdrasil-ng has 4-5 active threads under load: crypto (ed25519 sign/verify),
routing (tree maintenance, bloom filters), TUN reader+writer, admin API handler.

At 40 Mbps on a hAP ax³ (4×Cortex-A53), musl malloc contention causes **67% CPU**
with 9 retransmits.

## Fix

Replace with **jemalloc** (via `jemallocator` crate). Per-thread arenas eliminate
lock contention:

```
Thread A: malloc(512)  ── arena 1 ── no wait
Thread B: malloc(1024) ── arena 2 ── no wait
Thread C: free(ptr)    ── arena 3 ── no wait
```

**Changes:** 2 files, 3 lines.

## Benchmarks (hAP ax³, 40 Mbps)

| Allocator | CPU | Retransmits |
|-----------|-----|-------------|
| musl malloc | 67% | 9 |
| **jemalloc** | **47%** | **1** |

## Why universal

- **musl targets:** Immediate benefit — musl malloc is the bottleneck on all musl distributions
- **glibc targets:** Smaller but measurable improvement from per-thread arenas
- **No API changes:** `#[global_allocator]` replaces the allocator globally

## No breaking changes
