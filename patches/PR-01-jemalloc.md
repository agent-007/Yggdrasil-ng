# PR: Replace system allocator with jemalloc

## Problem

On musl-based targets (Alpine Linux, RouterOS containers, embedded systems),
`musl malloc` uses a **global lock** for all memory allocations. Under multi-threaded
workloads, this lock becomes the dominant bottleneck.

yggdrasil-ng has 4-5 active threads under load: crypto (ed25519 sign/verify),
routing (tree maintenance, bloom filters), TUN reader+writer, admin API handler.

At 40 Mbps on a hAP ax³ (4×Cortex-A53), musl malloc contention causes **67% CPU**
with 9 retransmits.

## Fix

Replace with **jemalloc** (via `jemallocator` crate). Per-thread arenas eliminate
lock contention.

**Changes:** 2 files (Cargo.toml + main.rs), ~5 lines, plus Cargo.lock update.

Jemalloc is enabled via target-gated dependencies — only on platforms where
`jemalloc-sys` (native C build) can compile.

## Platforms where jemalloc is excluded

| Platform | Reason |
|----------|--------|
| Windows | No C cross-compiler on GitHub Actions runner |
| MIPS / mips64 | `__popcountdi2` undefined |
| armv7 / armhf | `__ffsdi2` undefined |

On x86_64 and aarch64 Linux/macOS, jemalloc is enabled unconditionally.

## Benchmarks (hAP ax³, 40 Mbps)

| Allocator | CPU | Retransmits |
|-----------|-----|-------------|
| musl malloc | 67% | 9 |
| **jemalloc** | **47%** | **1** |

## Why universal

- **musl targets:** Immediate benefit — musl malloc is the bottleneck
- **glibc targets:** Smaller but measurable improvement from per-thread arenas
- **No API changes:** `#[global_allocator]` replaces the allocator globally
- **No breakage on unsupported platforms:** cfg-gated

## No breaking changes
