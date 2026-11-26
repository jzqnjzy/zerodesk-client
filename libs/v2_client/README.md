# `v2_client` — Clean-Room AGPL-3.0 ZeroDesk V2 Client Runtime

Clean-room Rust client runtime for ZeroDesk V2 (`v1.2-FROZEN`), built strictly from `protocol-spec` (Apache-2.0) on top of `v2_identity` and `v2_transport` with zero C++/vcpkg/Flutter dependencies:

- **Layer 1 — Control Plane, Signaling & Noise_IK Access Control**:
  - `control_plane.rs`: Pure-Rust `rustls` + `webpki-roots` + fail-closed custom CA DER (`--cp-ca-der`) with IP SAN verification and loopback-only `http://` guard. Implements P-256 low-S signed `POST /v2/devices/register`, `POST /v2/leases/renew` (initial issue + renewal), `POST /v2/metering/client-report`, `GET /v2/ca/pubkey`, and `GET /healthz`.
  - `signaling.rs`: `v2-signaling` TCP reachability probe + Protobuf3 length-prefixed framing per `protocol-spec/proto/v2/signaling.proto`.
  - `access_ctrl.rs`: `snow` `Noise_IK_25519_AESGCM_SHA256` TCP client with 55-byte prologue (`V2-ACCESS-IK-v1 || pop_id[8] || edge_cert_hash[32]`), `RelayBindReq/Resp`, `LeaseRenewReq/Resp`, `RebindReq/Resp`, and `v2_transport` HKDF directional key derivation.
- **Layer 2 — UDP 28B Access Data-Plane, `LEG_NACK`, `RS(6,4)` & E2EE L3/L4**:
  - `udp_session.rs`: Loopback (`127.0.0.1:0`) / WAN (`0.0.0.0:0`) UDP socket, 28B `AccessHeaderV11` + HMAC-SHA256-64 via `v2_transport`, `EdgeCtrl::Ping/Pong` with retry, `LEG_NACK` gap tracking & `rtx=1` retransmission cache, `RS(6,4)` Survival Mode shard encoding/decoding via `v2_transport`, client↔client E2EE `Noise_IK` + 2048-bit replay window + 9-channel L4 multiplexer (`0x00..0x08`, including policy-gated `0x07 RealtimeActuator` & `ActuatorReceiver`).
- **Layer 3 — Dual TLS-443 Fallback & Integration Seams**:
  - `tls443.rs`: Independent `Realtime` (`role=1`) + `Bulk` (`role=2`) TLS 1.3 streams with 9B preface `[role][route_cid]`, role-isolated 15B HKDF stream keys, first-frame authenticated `EdgeCtrl::Ping` within 5s deadline, `EdgeCtrl::BwHint` congestion control, and >80ms HoL discard of complete non-reference video frames.
  - `bridge.rs`: `V2ServiceStream` (`std::io::Read + std::io::Write` multiplexed per `ChannelId`) and `V2LoopbackBridge` (loopback-only TCP proxy tunneling raw bytes over the authenticated E2EE V2 session).
- **CLI (`zerodesk-v2-cli`)**:
  - `probe --config <cluster.json> [--count 20] [--cp-ca-der <path>]`
  - `e2e --config <cluster.json> [--cp-ca-der <path>]`
  - `loopback-bridge --listen 127.0.0.1:<port> --config <cluster.json> [--target 127.0.0.1:<port>] [--cp-ca-der <path>]`

## Standalone Build & Test

```sh
RUSTFLAGS="-D warnings" cargo test --manifest-path libs/v2_client/Cargo.toml
cargo clippy --manifest-path libs/v2_client/Cargo.toml --all-targets -- -D warnings
```
