# ZeroDesk Client

**ZeroDesk Client** is an open-source remote desktop client **derived from [RustDesk](https://github.com/rustdesk/rustdesk)** and licensed under the **GNU Affero General Public License v3.0 (`AGPL-3.0-only`)**.

- **License:** [LICENSE](LICENSE) (exact verbatim copy of upstream [LICENCE](LICENCE), GNU AGPL-3.0)
- **Attribution & Notices:** [NOTICE](NOTICE)
- **Upstream Project:** [RustDesk](https://github.com/rustdesk/rustdesk) — all upstream copyright notices, license terms, and sub-crate licenses are preserved intact. ZeroDesk is an independent derivative project and is not affiliated with or endorsed by RustDesk.

> [!CAUTION]
> **Misuse Disclaimer:**
> ZeroDesk Contributors and upstream RustDesk developers do not condone or support any unethical or illegal use of this software, including unauthorized access, control, or invasion of privacy. Users are solely responsible for ensuring authorized use.

## Protocol & Clean-Room Architecture

ZeroDesk Client adds opt-in support for the **ZeroDesk V2** remote desktop protocol (feature flag: `zerodesk-v2`) alongside the upstream RustDesk client foundation.

The V2 client stack is implemented in a clean-room fashion strictly against the Apache-2.0 **ZeroDesk V2 Protocol Specification** (`zerodesk-protocol-spec`, currently **`v1.2.3`**), independently of any proprietary server or cloud backend:

- [`libs/v2_identity`](libs/v2_identity/README.md) — P-256 device identity (`DeviceKeyStore`), deterministic Big-Endian TBS certificates with low-S ECDSA verification, and 12-hour X25519 static key rotation.
- [`libs/v2_transport`](libs/v2_transport/README.md) — Channel-aware E2EE transport stack: 28-byte v1.1 UDP access framing with HMAC-SHA256-64, `LEG_NACK`, `RS(6,4)` Survival Mode FEC, dual-layer `Noise_IK`/`Noise_XX` handshakes, L3 AEAD + replay windows, and L4 7+2 channel multiplexing (`0x00`..`0x08`).
- [`libs/v2_client`](libs/v2_client/README.md) — Pure-Rust V2 client runtime (Control-Plane HTTPS/HTTP, Signaling, `Noise_IK` access control tunnel, UDP 28B data plane, Dual TLS-443 fallback, `V2ServiceStream` / `V2LoopbackBridge`, and `zerodesk-v2-cli`).
- `src/v2_session` — Desktop session integration (`zerodesk-v2` feature): screen/synthetic capture pipeline, VP9/AV1 `scrap` video codecs, P0 HID frame codec, and safe HID executor/watchdog.
- [`libs/v2_e2e`](libs/v2_e2e/README.md) — Headless desktop VP9/AV1 + P0 HID + `dual-e2e` + `wan-bench` end-to-end verification harness (`zerodesk-desktop-e2e`).

## AGPL-3.0 §13 Source Availability

This software is distributed under the **GNU Affero General Public License v3.0 (`AGPL-3.0-only`)**. In compliance with **AGPL-3.0 §5 and §13**:

- All modified upstream files carry prominent modification notices (`Modified by ZeroDesk Contributors (2026) under GNU AGPL-3.0-only.`).
- All ZeroDesk-added source files carry `SPDX-License-Identifier: AGPL-3.0-only` headers.
- Every recipient of binaries and every user interacting with this client (or a modified version of it) over a computer network is entitled to receive the complete **Corresponding Source** of the exact version running, free of charge, from the source repository accompanying the distribution (or via the public ZeroDesk Client source release corresponding to the distributed build tag/commit).
- See [LICENSE](LICENSE) / [LICENCE](LICENCE) for the full text of the GNU AGPL v3.0 and [NOTICE](NOTICE) for third-party and upstream attributions.

## Build & Test Quickstart

### Standalone ZeroDesk V2 Crates

The standalone V2 crates (`v2_identity`, `v2_transport`, `v2_client`) require only a standard Rust toolchain and have no C++/vcpkg/Flutter dependencies:

```sh
# 1. Identity & key rotation
cargo clippy --manifest-path libs/v2_identity/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path libs/v2_identity/Cargo.toml

# 2. Transport stack (set ZERODESK_VECTORS_DIR to run cross-repo conformance vectors)
cargo clippy --manifest-path libs/v2_transport/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path libs/v2_transport/Cargo.toml

# 3. V2 client runtime & zerodesk-v2-cli
cargo clippy --manifest-path libs/v2_client/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path libs/v2_client/Cargo.toml
```

If cross-repo conformance vectors are not present locally, skip vector tests with:

```sh
cargo test --manifest-path libs/v2_identity/Cargo.toml -- --skip golden_vector_
cargo test --manifest-path libs/v2_transport/Cargo.toml --test transport_tests
```

### Headless Desktop Media & E2E Harness (`v2_e2e`)

`libs/v2_e2e` builds against `libs/scrap` (VP9/AV1 codecs and `libyuv`). On macOS with a local `libyuv` prefix (e.g., Homebrew or `~/.local/libyuv`):

```sh
ZERODESK_LIBYUV_PREFIX=/path/to/libyuv \
  cargo clippy --manifest-path libs/v2_e2e/Cargo.toml --no-deps --all-targets -- -D warnings
ZERODESK_LIBYUV_PREFIX=/path/to/libyuv \
  cargo test --manifest-path libs/v2_e2e/Cargo.toml
```

See [`libs/v2_e2e/README.md`](libs/v2_e2e/README.md) for `codec-selftest`, `e2e`, `dual-e2e`, `wan-bench`, and `capture-probe` usage.

### Full Desktop / Mobile Client Build

For full Flutter GUI and native desktop/mobile packaging (which requires Flutter, C++ toolchain, and `vcpkg` dependencies such as `libvpx`, `libyuv`, `opus`, and `aom`), see `.github/workflows/flutter-build.yml` and `build.py`.

## Repository Layout

| Path | Description |
| --- | --- |
| `src/` | Core Rust client application (`src/v2_session/` for ZeroDesk V2 session logic) |
| `flutter/` | Cross-platform Flutter UI (Desktop & Mobile) |
| `libs/v2_identity/` | ZeroDesk V2 device identity, TBS certs, and X25519 key rotation (`AGPL-3.0-only`) |
| `libs/v2_transport/` | ZeroDesk V2 channel-aware E2EE transport stack (`AGPL-3.0-only`) |
| `libs/v2_client/` | ZeroDesk V2 pure-Rust client runtime & CLI (`AGPL-3.0-only`) |
| `libs/v2_e2e/` | ZeroDesk V2 headless desktop VP9/AV1 + HID + WAN E2E harness (`AGPL-3.0-only`) |
| `libs/scrap/`, `libs/enigo/`, `libs/base/`, `libs/clipboard/` | Upstream capture, input, common, and clipboard libraries |
| `LICENSE`, `LICENCE`, `NOTICE` | GNU AGPL-3.0 license texts and attribution notices |
