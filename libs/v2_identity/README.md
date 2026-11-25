# `v2_identity` — ZeroDesk V2 Device Identity & Key Rotation

Clean-room implementation of ZeroDesk V2 (`v1.2-FROZEN`) identity primitives:

- `DeviceKeyStore` trait for long-term P-256 identity keys, with an explicit `hardware_backed(&self) -> bool` attestation flag so software fallback stores (`SoftwareDeviceKeyStore`) never claim hardware-backed E2EE.
- Deterministic Big-Endian TBS builders and ECDSA P-256 **low-S** verifiers for:
  - `DeviceCert` (`V2-DEVCERT-v1`)
  - `EdgeCert` (`V2-EDGECERT-v1`)
  - `DelegationStatement` (`V2-X25519-DELEGATE`)
  - `TenantPolicyBlob` (`V2-TENANT-POLICY-v1`)
  - `RevocationNotice` (`V2-REVOCATION-v1`)
  - `ControlPreemptToken` (`V2-PREEMPT-v1`)
- 12-hour time-slice X25519 static key rotator (`X25519StaticKeyRotator`) with `ZeroizeOnDrop` memory hygiene, 2-generation retention (`>= 48h` window), anti-rollback / anti-substitution `(device_id -> (delegation_seq, x25519_pub))` cache, and `StaticKeyHint` single-retry validator.

## Standalone Build & Test

Because `libs/hbb_common` is an uninitialized upstream submodule during Phase 0, this crate declares its own `[workspace]` table so it can be built and tested completely offline/standalone:

```sh
cargo test --manifest-path libs/v2_identity/Cargo.toml
```
