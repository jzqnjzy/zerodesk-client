<!-- SPDX-License-Identifier: AGPL-3.0-only -->
<!-- Copyright (c) 2026 ZeroDesk Contributors -->

# ZeroDesk Weak-Network Adaptive QoE (Phase 9A)

## 1. Architecture Overview

Phase 9A introduces a 100% platform-agnostic, zero-new-dependency weak-network QoE engine under `libs/zerodesk_core/src/qoe/`:

```text
libs/zerodesk_core/src/qoe/
├── congestion.rs   — Dual-signal GCC-like CC FSM + asymmetric resolution/FPS ladder + FEC budget coupling
├── fec.rs          — Zero-dependency GF(2^8) Cauchy RS-FEC (0x11D) + adaptive controller + hard-wait reorder buffer
├── fast_start.rs   — FastStart 1500 kbps 3-frame probe + H.264/HEVC Annex-B SPS/PPS/VPS inliner + ZeroBufferPacer
├── mod.rs          — Unified QoeEngine facade + decoupled HardwareVideoEncoder / V2VideoEncoder / DesktopHostSession hooks
└── wan_sim.rs      — Deterministic fixed-seed discrete-event WAN simulator (zero Instant / zero OS RNG)
```

All existing V2 wire-protocol framing and all 11 Phase 8A JSON-ABI v2 golden snapshots remain **0-byte untouched**.

---

## 2. Module Specifications & Hard Parameters

### 2.1 Dual-Signal Congestion Control (`qoe/congestion.rs`)

| Parameter | Value / Rule | Purpose |
|---|---|---|
| Primary Signal 1 | Inter-arrival OLS trendline slope (`> 0.045 ms/ms`) & queue delay (`>= 28 ms`) | Proactive bufferbloat suppression (**strictly prioritized over packet loss**) |
| Primary Signal 2 | Rolling 1s packet-counted loss + EWMA + significant burst guard (`>= 8%` EWMA or `>= 12%` with `>= 6` lost) | Non-congestive / burst loss recovery without false-triggering on 5% random loss |
| Auxiliary Signals | SRTT + aging 10s rolling `min_rtt` + receiver `jitter_buffer_ms` | Baseline drift prevention & receiver pacing awareness |
| FSM States (`CcState`) | `Startup` (`<= x1.6`/RTT), `Steady` (nominal `+5%`, `<= x1.2`, `<= 1/sec`), `Drain` (`x0.85` immediate, `>= x0.5` step floor, dwell `>= 1*RTT`), `Recover` (`90%` of last steady, dwell until baseline RTT) | Clean separation of startup ramp, steady stability, queue drain, and loss recovery |
| Confirmation Hysteresis | `>= 3` consecutive windows AND `>= 200 ms` span for normal transitions/upgrades | Anti-oscillation & zero `>= 3` consecutive up/down flips |
| Resolution Ladder | `[1920x1080, 1280x720, 960x540, 640x360]` | Downgrade `>= 2000 ms`, upgrade `>= 5000 ms`, always sets `force_idr = true` |
| Minimum Protection | `min_bitrate_kbps = 300`, `min_fps = 5` (FPS scaled at 360p; never drops below 360p) | Preserves legibility under extreme congestion |
| Encoder Throttle | `set_bitrate` throttled `>= 100 ms` unless urgent Drain/Recover or resolution downgrade | Prevents hardware encoder thrashing |
| FEC Budget Coupling | `media_bitrate_kbps + fec_budget_kbps <= total_bitrate_kbps` | Eliminates FEC vs. media self-congestion loops |

### 2.2 Zero-Dependency GF(2^8) Cauchy Reed-Solomon FEC (`qoe/fec.rs`)

| Parameter | Value / Rule |
|---|---|
| Finite Field | GF(2^8), primitive polynomial `0x11D` (`x^8 + x^4 + x^3 + x^2 + 1`), compile-time `exp`/`log` tables |
| Code Structure | Systematic RS: `k` unmodified data shards (`1 <= k <= 16`) + `m` parity shards (`1 <= m <= 4`); `m == 1` uses lightweight XOR fast path; `m >= 2` uses Cauchy matrix `inv((k+r)^j)` + Gauss-Jordan inversion |
| Unequal Shards | Compact `2*k`-byte big-endian length table prepended to parity shards; zero-padded during math and truncated to exact original byte length |
| Loss Mapping | `< 1%` -> OFF (`0%`); `1%–3%` -> `5%`; `3%–8%` -> `10%–15%`; `> 8%` -> scales dynamically to hard cap `25%` |
| Debounce Hysteresis | `>= 2000 ms` continuous same-direction confirmation for ON/OFF toggle |
| Receiver Hard Wait | `fec_wait_ms = clamp(2 * measured_jitter_ms, 5, 40)` capped by `frame_interval_ms` (`33ms` @ 30fps, `16ms` @ 60fps); expires immediately to NACK without blocking |

### 2.3 First-Frame Fast Start (`qoe/fast_start.rs`)

- **Immediate IDR + Probe Launch**: `FastStartController::on_session_connected()` immediately asserts `force_idr = true` at `1500 kbps` for the first 3 frames, handing off smoothly to `CongestionController::Startup` once the 3 probe frames launch and first receiver feedback arrives.
- **Annex-B Parameter Set Auto-Inliner (`ParameterSetInliner`)**: Caches latest H.264 `SPS(7)/PPS(8)` and HEVC `VPS(32)/SPS(33)/PPS(34)` across 3-byte and 4-byte Annex-B start codes and automatically inlines missing parameter sets before every IDR (`H.264 NAL 5`, `HEVC NAL 19/20`).
- **Zero-Buffer Direct Output (`ZeroBufferPacer`)**: Displays the first decoded IDR with complete parameter sets at `wait_ms = 0` and records exact `ttff_ms`.

---

## 3. Deterministic WAN Simulation Benchmark Results

Executed via `cargo test --manifest-path libs/zerodesk_core/Cargo.toml -p zerodesk_core --test qoe_wan_bench -- --nocapture` (fixed-seed SplitMix64 PRNG, virtual microsecond clock, exercising real `QoeEngine`, real `RsCodec`, real `FecReorderBuffer`, real `ParameterSetInliner`, and real `ZeroBufferPacer`):

| Gate | Scenario | Hard Threshold | Measured Result | Status |
|---|---|---|---|---|
| **Gate 1 — TTFF** | RTT 20ms (20 seeds) | `P50 <= 300ms`, `P95 <= 1.5*P50` | `P50 = 53.0ms`, `P95 = 54.0ms` (1.02x) | **PASS** |
| **Gate 1 — TTFF** | RTT 120ms (20 seeds) | `P50 <= 600ms`, `P95 <= 1.5*P50` | `P50 = 208.5ms`, `P95 = 211.1ms` (1.01x) | **PASS** |
| **Gate 1 — TTFF** | RTT 220ms (20 seeds) | `P50 <= 900ms`, `P95 <= 1.5*P50` | `P50 = 361.0ms`, `P95 = 364.0ms` (1.01x) | **PASS** |
| **Gate 2 — Steady G2G** | RTT 20 / 120 / 220ms | `P50 <= RTT+150ms`, `P95 <= RTT+250ms` | 20ms: `52.0 / 59.0ms`; 120ms: `100.0 / 106.0ms`; 220ms: `147.0 / 157.2ms` | **PASS** |
| **Gate 3A — 5% Random Loss** | 4.5 Mbps, 60ms RTT, 5% loss | Frame recovery `>= 95%`, FEC delay `<= 30ms` | **97.54%** (437/448) vs 65.40% No-FEC; 223 pkts recovered; FEC delay `P50 = 2.0ms`, `P95 = 7.0ms`, `max = 12ms`; `0` decode errors | **PASS** |
| **Gate 3B — Gilbert-Elliott Burst** | 4.5 Mbps, 60ms RTT, Markov burst | FEC >> No-FEC, FEC delay `<= 30ms` | **95.76%** vs 82.37% No-FEC (+13.39%); FEC delay `P95 = 5.0ms`; `0` decode errors | **PASS** |
| **Gate 4 — BW Step-Down** | `20 -> 2 -> 15 Mbps`, 40ms RTT | Converge `<= 2000ms` (`±15%`), freezes `<= 2`, err `= 0` | Converged in **620ms** (`2092 kbps`), climbed to `3193 kbps` after 15 Mbps recovery, `1` freeze, `0` decode errors | **PASS** |
| **Gate 5 — Bufferbloat** | 4 Mbps link, 400ms router queue | Queue delta `<= 100ms` | `P95 = 8.5ms`, `max = 31.0ms` | **PASS** |
| **Gate 6 — Anti-Oscillation** | Clean 6 Mbps & 2% Loss 6 Mbps | Steady changes `<= 1.0/s`, flips `< 3` | Clean: `0.79/s`, `0` flips; 2% Loss: `0.86/s`, `0` flips | **PASS** |
| **Gate 7 — 3x Determinism** | Mixed step + 2% loss (3 runs) | 0 deviation across all metrics & trajectory hash | Exact bit-for-bit equality (`hash = 0x5b39defd8668b06d`) | **PASS** |
