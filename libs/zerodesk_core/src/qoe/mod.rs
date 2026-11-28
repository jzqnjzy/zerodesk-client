// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Weak-network adaptive QoE engine for ZeroDesk V2 (Phase 9A).
//!
//! Combines:
//! - Dual-signal GCC-like congestion control (`congestion`)
//! - Zero-dependency GF(2^8) Cauchy Reed-Solomon adaptive FEC (`fec`)
//! - First-frame fast-start & Annex-B SPS/PPS/VPS inliner (`fast_start`)
//! - Deterministic discrete-event WAN simulation benchmark harness (`wan_sim`)

pub mod congestion;
pub mod fast_start;
pub mod fec;
pub mod wan_sim;

pub use congestion::{
    CcState, CcTransitionEvent, CongestionConfig, CongestionController, DelaySignal, EncoderTarget,
    FeedbackSample, CC_DEFAULT_MAX_BITRATE_KBPS, CC_DEFAULT_MAX_FPS,
    CC_DEFAULT_START_BITRATE_KBPS, CC_MIN_BITRATE_KBPS, CC_MIN_FPS_CAP, RESOLUTION_LADDER,
};
pub use fast_start::{
    FastStartController, FastStartDirective, FastStartPhase, InlineOutcome, PacerDecision,
    ParameterSetInliner, ZeroBufferPacer, FAST_START_PROBE_BITRATE_KBPS, FAST_START_PROBE_FRAMES,
};
pub use fec::{
    cauchy_coeff, compute_fec_wait_ms, gf_inv, gf_mul, AdaptiveFecController, FecDecision,
    FecError, FecGroupOutcome, FecReceiverStats, FecReorderBuffer, RsCodec, FEC_DEBOUNCE_MS,
    FEC_MAX_DATA_SHARDS, FEC_MAX_PARITY_SHARDS, FEC_MAX_REDUNDANCY_RATIO, FEC_WAIT_MAX_MS,
    FEC_WAIT_MIN_MS, GF256_PRIMITIVE_POLY,
};
pub use wan_sim::{
    BandwidthStep, LossModel, WanBenchMetrics, WanScenario, WanSimulator,
};

use crate::{
    os::HardwareVideoEncoder,
    session::{
        session::DesktopHostSession,
        video::{V2VideoEncoder, VideoCodec, VideoError},
    },
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

const FEC_LOSS_WINDOW_MS: u64 = 1_000;

/// Unified configuration for `QoeEngine`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct QoeConfig {
    pub congestion: CongestionConfig,
    pub fec_debounce_ms: u64,
    pub fec_enabled_by_policy: bool,
    pub fast_start_probe_bitrate_kbps: u32,
    pub fast_start_probe_frames: u32,
}

impl Default for QoeConfig {
    fn default() -> Self {
        Self {
            congestion: CongestionConfig::default(),
            fec_debounce_ms: FEC_DEBOUNCE_MS,
            fec_enabled_by_policy: true,
            fast_start_probe_bitrate_kbps: FAST_START_PROBE_BITRATE_KBPS,
            fast_start_probe_frames: FAST_START_PROBE_FRAMES,
        }
    }
}

/// Internal diagnostic snapshot for telemetry/logging (does NOT modify Phase 8A JSON-ABI v2).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QoeDiagnosticsSnapshot {
    pub cc_state: CcState,
    pub fast_start_phase: FastStartPhase,
    pub media_bitrate_kbps: u32,
    pub fec_budget_kbps: u32,
    pub total_bitrate_kbps: u32,
    pub width: u32,
    pub height: u32,
    pub fps_cap: u32,
    pub fec_enabled: bool,
    pub fec_redundancy_ratio: f64,
    pub srtt_ms: f64,
    pub min_rtt_ms: f64,
    pub queue_delay_ms: f64,
    pub loss_rate: f64,
    pub delay_slope: f64,
    pub jitter_buffer_ms: f64,
    pub param_sets_inlined: u64,
    pub transitions_count: usize,
}

/// Unified sender-side QoE facade combining congestion control, adaptive RS-FEC,
/// fast-start probing, and Annex-B parameter-set inlining.
#[derive(Debug, Clone)]
pub struct QoeEngine {
    cfg: QoeConfig,
    congestion: CongestionController,
    fec: AdaptiveFecController,
    fast_start: FastStartController,
    param_inliner: ParameterSetInliner,
    fec_loss_window: VecDeque<(u64, u32, u32)>,
    last_target: EncoderTarget,
}

impl Default for QoeEngine {
    fn default() -> Self {
        Self::new(QoeConfig::default())
    }
}

impl QoeEngine {
    pub fn new(cfg: QoeConfig) -> Self {
        let congestion = CongestionController::new(cfg.congestion);
        let fec = AdaptiveFecController::with_debounce_ms(cfg.fec_debounce_ms);
        let fast_start = FastStartController::with_params(
            cfg.fast_start_probe_bitrate_kbps,
            cfg.fast_start_probe_frames,
        );
        let last_target = congestion.current_target(false, false);
        Self {
            cfg,
            congestion,
            fec,
            fast_start,
            param_inliner: ParameterSetInliner::new(),
            fec_loss_window: VecDeque::with_capacity(32),
            last_target,
        }
    }

    pub fn congestion(&self) -> &CongestionController {
        &self.congestion
    }

    pub fn fec(&self) -> &AdaptiveFecController {
        &self.fec
    }

    pub fn fec_mut(&mut self) -> &mut AdaptiveFecController {
        &mut self.fec
    }

    pub fn fast_start(&self) -> &FastStartController {
        &self.fast_start
    }

    pub fn param_inliner(&self) -> &ParameterSetInliner {
        &self.param_inliner
    }

    pub fn last_target(&self) -> EncoderTarget {
        self.last_target
    }

    /// Invoked immediately when a V2 session connects: pre-triggers an immediate IDR at the
    /// lightweight `1500 kbps` FastStart probe bitrate.
    pub fn on_session_connected(&mut self, now_ms: u64) -> EncoderTarget {
        let dir = self.fast_start.on_session_connected(now_ms);
        let probe = dir
            .probe_bitrate_kbps
            .unwrap_or(self.cfg.fast_start_probe_bitrate_kbps)
            .clamp(
                self.cfg.congestion.min_bitrate_kbps,
                self.cfg.congestion.max_bitrate_kbps,
            );
        let (width, height) = self.congestion.current_resolution();
        let target = EncoderTarget {
            media_bitrate_kbps: probe,
            fec_budget_kbps: 0,
            total_bitrate_kbps: probe,
            width,
            height,
            fps_cap: self.congestion.fps_cap(),
            force_idr: dir.force_idr,
            bitrate_changed: true,
        };
        self.last_target = target;
        target
    }

    /// Processes a newly encoded Annex-B frame, ensuring H.264/HEVC IDRs inline SPS/PPS(/VPS)
    /// and advancing the 3-frame FastStart probe counter.
    pub fn on_frame_encoded(
        &mut self,
        codec: VideoCodec,
        bitstream: &[u8],
        is_idr: bool,
    ) -> InlineOutcome {
        let outcome = self.param_inliner.inline_if_needed(codec, bitstream);
        let _ = self.fast_start.on_frame_encoded(is_idr || outcome.contains_idr);
        outcome
    }

    /// Processes a receiver feedback window, updating adaptive FEC, FastStart handoff,
    /// and dual-signal congestion control.
    pub fn on_feedback(&mut self, sample: FeedbackSample) -> EncoderTarget {
        // Compute rolling 1-second packet loss rate so short feedback intervals with
        // stochastic 0-loss ticks do not reset AdaptiveFecController's 2000ms debounce timer.
        self.fec_loss_window
            .push_back((sample.now_ms, sample.packets_received, sample.packets_lost));
        let cutoff = sample.now_ms.saturating_sub(FEC_LOSS_WINDOW_MS);
        while let Some(&(ts, _, _)) = self.fec_loss_window.front() {
            if ts < cutoff {
                self.fec_loss_window.pop_front();
            } else {
                break;
            }
        }
        let mut win_recv = 0u64;
        let mut win_lost = 0u64;
        for &(_, r, l) in &self.fec_loss_window {
            win_recv = win_recv.saturating_add(u64::from(r));
            win_lost = win_lost.saturating_add(u64::from(l));
        }
        let total_pkts = win_recv.saturating_add(win_lost);
        let rolling_loss = if total_pkts > 0 {
            (win_lost as f64) / (total_pkts as f64)
        } else {
            0.0
        };

        let fec_ratio = if self.cfg.fec_enabled_by_policy {
            self.fec
                .on_loss_sample(sample.now_ms, rolling_loss)
                .redundancy_ratio
        } else {
            0.0
        };

        let fs_dir = self.fast_start.on_feedback(sample.now_ms);
        let mut target = self.congestion.on_feedback(sample, fec_ratio);

        // During the initial 3-frame FastStart probe window, hold bitrate at the probe ceiling
        // while still keeping FEC budget strictly coupled inside total_bitrate_kbps.
        if let Some(probe_kbps) = fs_dir.probe_bitrate_kbps {
            let capped_total = target.total_bitrate_kbps.min(probe_kbps).max(CC_MIN_BITRATE_KBPS);
            let media = ((capped_total as f64) / (1.0 + fec_ratio)).floor() as u32;
            let media = media.max(CC_MIN_BITRATE_KBPS).min(capped_total);
            let fec = capped_total.saturating_sub(media);
            target.total_bitrate_kbps = capped_total;
            target.media_bitrate_kbps = media;
            target.fec_budget_kbps = fec;
            target.force_idr |= fs_dir.force_idr;
        }

        self.last_target = target;
        target
    }

    /// Plans how many RS parity shards `m` to emit for a frame/group of `k` media packets.
    pub fn parity_shards_for_group(&self, k: usize) -> usize {
        if !self.cfg.fec_enabled_by_policy {
            return 0;
        }
        self.fec.parity_shards_for_group(k)
    }

    /// Applies an `EncoderTarget` onto any cross-platform `HardwareVideoEncoder`
    /// (macOS VideoToolbox, Windows Media Foundation, or test double).
    pub fn apply_to_hardware_encoder<E: HardwareVideoEncoder + ?Sized>(
        &self,
        encoder: &mut E,
        target: &EncoderTarget,
    ) -> Result<(), VideoError> {
        if target.bitrate_changed {
            encoder.set_bitrate(target.media_bitrate_kbps.saturating_mul(1_000))?;
        }
        if target.force_idr {
            encoder.force_next_idr();
        }
        Ok(())
    }

    /// Applies an `EncoderTarget` onto `V2VideoEncoder`.
    pub fn apply_to_v2_encoder(
        &self,
        encoder: &mut V2VideoEncoder,
        target: &EncoderTarget,
    ) -> Result<(), VideoError> {
        if target.bitrate_changed {
            encoder.set_bitrate(target.media_bitrate_kbps.saturating_mul(1_000))?;
        }
        if target.force_idr {
            encoder.force_next_idr();
        }
        Ok(())
    }

    /// Applies an `EncoderTarget` onto a live `DesktopHostSession` without modifying
    /// any V2 wire framing or Phase 8A JSON-ABI structs.
    pub fn apply_to_host_session(
        &self,
        session: &DesktopHostSession,
        target: &EncoderTarget,
    ) -> Result<(), VideoError> {
        if target.bitrate_changed {
            session.set_bitrate(target.media_bitrate_kbps.saturating_mul(1_000))?;
        }
        if target.force_idr {
            session.force_next_idr();
        }
        Ok(())
    }

    /// Captures an internal diagnostic snapshot for logging and benchmark inspection.
    pub fn snapshot(&self) -> QoeDiagnosticsSnapshot {
        let (width, height) = self.congestion.current_resolution();
        QoeDiagnosticsSnapshot {
            cc_state: self.congestion.state(),
            fast_start_phase: self.fast_start.phase(),
            media_bitrate_kbps: self.last_target.media_bitrate_kbps,
            fec_budget_kbps: self.last_target.fec_budget_kbps,
            total_bitrate_kbps: self.last_target.total_bitrate_kbps,
            width,
            height,
            fps_cap: self.congestion.fps_cap(),
            fec_enabled: self.fec.is_enabled(),
            fec_redundancy_ratio: self.fec.redundancy_ratio(),
            srtt_ms: self.congestion.srtt_ms(),
            min_rtt_ms: self.congestion.min_rtt_ms(),
            queue_delay_ms: self.congestion.queue_delay_ms(),
            loss_rate: self.congestion.loss_rate(),
            delay_slope: self.congestion.delay_slope(),
            jitter_buffer_ms: self.congestion.jitter_buffer_ms(),
            param_sets_inlined: self.param_inliner.inlined_count(),
            transitions_count: self.congestion.transitions().len(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        os::{
            CapturedFrame, HardwareCodec, HardwareCodecEvent, HardwareCodecKind,
            HardwareCodecState, HardwareEncodedPacket,
        },
        session::video::I420Frame,
    };

    struct MockHwEncoder {
        last_bitrate_bps: Option<u32>,
        bitrate_calls: u32,
        idr_calls: u32,
    }

    impl HardwareCodec for MockHwEncoder {
        fn codec(&self) -> HardwareCodecKind {
            HardwareCodecKind::H264
        }
        fn backend_name(&self) -> &'static str {
            "mock_hw"
        }
        fn state(&self) -> HardwareCodecState {
            HardwareCodecState::HardwareReady
        }
        fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
            Vec::new()
        }
    }

    impl HardwareVideoEncoder for MockHwEncoder {
        fn encode_frame(
            &mut self,
            _frame: &CapturedFrame,
            _force_idr: bool,
        ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
            Ok(Vec::new())
        }
        fn encode_i420(
            &mut self,
            _frame: &I420Frame,
            _pts_us: i64,
            _force_idr: bool,
        ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
            Ok(Vec::new())
        }
        fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError> {
            self.last_bitrate_bps = Some(bitrate_bps);
            self.bitrate_calls += 1;
            Ok(())
        }
        fn force_next_idr(&mut self) {
            self.idr_calls += 1;
        }
        fn reinit(&mut self) -> Result<(), VideoError> {
            Ok(())
        }
    }

    #[test]
    fn qoe_engine_wires_fast_start_and_hardware_encoder_hooks_cleanly() {
        let mut engine = QoeEngine::default();
        let mut mock = MockHwEncoder {
            last_bitrate_bps: None,
            bitrate_calls: 0,
            idr_calls: 0,
        };

        let t0 = engine.on_session_connected(0);
        assert!(t0.force_idr);
        assert_eq!(t0.media_bitrate_kbps, 1_500);
        engine.apply_to_hardware_encoder(&mut mock, &t0).unwrap();
        assert_eq!(mock.last_bitrate_bps, Some(1_500_000));
        assert_eq!(mock.idr_calls, 1);
        assert_eq!(mock.bitrate_calls, 1);

        // Encode first 3 probe frames with Annex-B H.264 SPS/PPS/IDR on frame 0 and bare IDR on frame 2.
        let idr_with_ps = [
            0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1E, 0, 0, 0, 1, 0x68, 0xCE, 0x3C, 0, 0, 0, 1, 0x65,
            0x88,
        ];
        let o0 = engine.on_frame_encoded(VideoCodec::H264, &idr_with_ps, true);
        assert!(o0.has_complete_param_sets);
        let p1 = [0, 0, 0, 1, 0x41, 0x01];
        let _ = engine.on_frame_encoded(VideoCodec::H264, &p1, false);
        let bare_idr = [0, 0, 0, 1, 0x65, 0x99];
        let o2 = engine.on_frame_encoded(VideoCodec::H264, &bare_idr, true);
        assert!(o2.inlined_param_sets);
        assert!(o2.has_complete_param_sets);

        // Feedback arrives -> hands off to CC Startup and ramps cleanly.
        let t1 = engine.on_feedback(FeedbackSample {
            now_ms: 150,
            rtt_ms: 25.0,
            delay_delta_ms: 0.0,
            packets_received: 30,
            packets_lost: 0,
            jitter_ms: 1.0,
            jitter_buffer_ms: 4.0,
            delivery_rate_kbps: Some(12_000.0),
        });
        assert_eq!(engine.fast_start().phase(), FastStartPhase::HandedOff);
        assert!(t1.media_bitrate_kbps + t1.fec_budget_kbps <= t1.total_bitrate_kbps);
        let snap = engine.snapshot();
        assert_eq!(snap.param_sets_inlined, 1);
    }
}
