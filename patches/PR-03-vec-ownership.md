# PR: Pass Vec<u8> by ownership through write_to chain

## Problem

`PacketConn::write_to` took `&[u8]` and internally called `buf.to_vec()` to
create a `TrafficPacket`. The encrypted data was already an owned `Vec<u8>`
from the encryption layer — passing it by reference forced an extra allocation
+ memcpy per outbound packet (~1400 bytes).

## Fix

Changed `write_to(&self, buf: &[u8], addr)` to `write_to(&self, buf: Vec<u8>, addr)`
in the trait and all implementations:

- `crates/ironwood/src/types.rs` (trait definition)
- `crates/ironwood/src/core.rs` (PacketConnImpl)
- `crates/ironwood/src/encrypted/mod.rs` (EncryptedPacketConn)
- `crates/ironwood/src/signed.rs` (SignedPacketConn)

All callers that already own a `Vec<u8>` (encrypted data from session layer,
signed data from SignedPacketConn) now pass by move instead of `&data` → `to_vec()`.

**Changes:** 4 files, 31 insertions, 27 deletions.

**Result:** -1 allocation + memcpy per outbound packet.

## Benchmarks (hAP ax³, 40 Mbps)

Combined with cs-v1 patch (patch 02):

| Before (both patches) | 30% CPU |
| After (both patches)  | 24% CPU |

## Breaking change

`PacketConn::write_to` signature changed — all implementations must be updated.
This is an internal trait (not part of the public API), so no downstream breakage.
