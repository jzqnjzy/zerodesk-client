# `v2_e2e` — ZeroDesk V2 Headless Desktop Media & HID E2E Harness

Clean-room headless verification library and CLI runner (`zerodesk-desktop-e2e`) for ZeroDesk V2 (`v1.2.3`) desktop media and input sessions, licensed under **GNU AGPL-3.0-only** (`Copyright (c) 2026 ZeroDesk Contributors`).

## Capabilities

- **Real Desktop Video Codecs (`scrap` VP9 / AV1)**: Encodes and decodes 1280x720 I420 video streams via `src/v2_session` and `libs/scrap`, asserting Y-plane PSNR (`>= 32.0 dB`) and SSIM (`>= 0.95`) along with IDR resynchronization (`CTRL_MSG_REQUEST_IDR`) and out-of-order frame dropping.
- **P0 HID Transport & Safe Input Watchdog**: Exercises low-latency P0 HID mouse/keyboard frame encoding, echo acknowledgment, stuck-key/button watchdog release, and optional OS input injection (`--features os-input` + `--enable-os-input`).
- **Dual-Process Desktop Session (`dual-e2e`)**: Orchestrates independent `host` and `controller` child processes over a ZeroDesk V2 cluster with rendezvous coordination and JSONL audit trails.
- **WAN Preemption & Codec Benchmark (`wan-bench`)**: Measures P0 HID preemption latency, loss/wire-bandwidth gates, and real-codec telemetry under concurrent video and background traffic.

## CLI Subcommands (`zerodesk-desktop-e2e`)

- `codec-selftest [--frames 30] [--av1-frames 10]` — Offline VP9/AV1 encode/decode quality check.
- `capture-probe --source screen|synthetic [--frames 30] [--timeout-ms 5000]` — Verify capture pipeline and frame pacing.
- `e2e --config <cluster.json> [--ca-der <ca.der>] [--frames 300] [--codec vp9|av1] [--bg-mbps 20] [--av1-burst 10]` — Single-process live desktop media + P0 HID E2E test.
- `dual-e2e --config <cluster.json> [--ca-der <ca.der>] [--codec vp9|av1] [--frames 60]` — Dual-process (`host` + `controller`) E2E session verification.
- `wan-bench --config <cluster.json> [--ca-der <ca.der>] [--frames 120] [--codec vp9|av1] [--bg-mbps 8] [--rounds 3] [--probes-per-round 200] [--max-wire-mbps 8]` — Multi-round WAN P0 HID preemption and real-codec benchmark.
- `host` / `controller` — Standalone child roles invoked directly or by `dual-e2e`.

## Build & Test

On macOS (with `libyuv` installed under `ZERODESK_LIBYUV_PREFIX`):

```sh
ZERODESK_LIBYUV_PREFIX=/path/to/libyuv \
  cargo clippy --manifest-path libs/v2_e2e/Cargo.toml --no-deps --all-targets -- -D warnings

ZERODESK_LIBYUV_PREFIX=/path/to/libyuv \
  cargo test --manifest-path libs/v2_e2e/Cargo.toml --quiet
```

## License

Licensed under **GNU Affero General Public License v3.0 (`AGPL-3.0-only`)**. See the repository root [LICENSE](../../LICENSE) and [NOTICE](../../NOTICE).
