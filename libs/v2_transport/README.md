# `v2_transport` — ZeroDesk V2 Channel-Aware Transport Stack

Clean-room Rust implementation of the ZeroDesk V2 (`v1.2-FROZEN`) client transport stack designed to sit directly below `Connection` / `Remote::io_loop` (replacing V1 `hbb_common::Stream`):

- **L2 Access Framing (`access.rs`)**: 28B v1.1 UDP access header (+ 24B v1.0 interop), TCP-443/WSS stream framing (`34..=1232` strict length gate + 80ms HOL discard), HKDF-SHA256 `v2mac-v1` precomputed directional keys with `subtle` constant-time MAC verification, `{cur-1, cur, cur+1}` `access_epoch` state machine, modular `leg_seq` dedup window, 150ms/512KB `LegCiphertextCache` (`LEG_NACK` anti-amplification & 100% billing), and stateful `BwHintController`.
- **Dual-Layer Noise Handshake (`handshake.rs`)**: `snow`-backed `Noise_IK_25519_{AESGCM,ChaChaPoly}_SHA256` & `Noise_XX_25519_*` wrappers, 204B deterministic anti-downgrade `prologue`, raw `Split()` directional key extraction, and 10,000-entry `ZeroRttGuard` LRU idempotency cache + piggybacked frame filter.
- **L3 E2EE (`l3.rs`)**: 16B header, `unified_seq = [e2ee_epoch:16][pkt_seq:48]` 96-bit AEAD Nonce, AES-256-GCM & ChaCha20-Poly1305, dual 2048-bit sliding replay/dedup windows with `max(2s, 4*RTT)` rekey grace, and `chan_id <-> pp` consistency enforcement.
- **L4 7+2 Channels (`l4.rs`)**: 8B common header, ARQ (64-bit SACK, RTO backoff capped at 3000ms, 8-retry path failure, HID 150ms drop with relative mouse accumulation), MTU<=1200B video slicing/reassembly & dual-slot LTR recovery ladder, `0x07 RealtimeActuator` (50ms future-skew guard, 1..150ms TTL, CA-signed `ControlPreemptToken` preemption), and `0x08 Telemetry`.
- **PathSet, Policy & Diagnostics (`path.rs`, `policy.rs`, `diagnostics.rs`, `transport.rs`)**: `TransportV2` trait, `PathSet` hot switch with CC bandwidth inheritance & 200~300ms dual-send, `VerifiedTenantPolicy` hard ceiling (blocking `0x05 FileTransfer` & `Cliprdr` file-clipboard bypass on free tier), and sanitized `DiagnosticBundle`.

## Standalone Build & Test

Because `libs/hbb_common` is an uninitialized upstream submodule during Phase 0, this crate declares its own `[workspace]` table so it compiles and passes all unit + cross-repo conformance vector tests independently:

```sh
ZERODESK_VECTORS_DIR=/path/to/protocol-spec/vectors \
  cargo test --manifest-path libs/v2_transport/Cargo.toml
```

If `ZERODESK_VECTORS_DIR` is unset, tests default to `/Volumes/data/github/zerodesk/protocol-spec/vectors`.
