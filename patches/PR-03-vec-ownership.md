# PR: Pass Vec<u8> by ownership through write_to chain

## Problem

`PacketConn::write_to(&self, buf: &[u8], addr)` forces a `buf.to_vec()` inside
`PacketConnImpl` to create `TrafficPacket`. But the encrypted layer **already
holds owned `Vec<u8>`** from session encryption. Passing by reference → extra
allocation+memcpy per outbound packet.

At 3500 pps × 1400 bytes = **4.9 MB/s of unnecessary copies**.

## Fix

Change trait signature to `write_to(&self, buf: Vec<u8>, addr)`. The owned Vec
moves directly into `TrafficPacket::new` without copying.

All 3 impls already hold or produce `Vec<u8>` at the call site. The change is
mechanical.

**Changes:** 6 files, ~30 lines net.

## Breaking change — reasoning

`pub trait PacketConn` — `&[u8]` → `Vec<u8>`. Only 3 impls exist (all in
`ironwood`). No external implementors.

## Benchmarks (hAP ax³, 40 Mbps, +jemalloc +cs-v1 +cortex-a53 +cpu3)

| Approach | CPU |
|----------|-----|
| &[u8] (before) | ~27% |
| **Vec<u8> (after)** | **24%** |

## Why universal

Eliminates one heap allocation + memcpy per outbound packet on any platform.
