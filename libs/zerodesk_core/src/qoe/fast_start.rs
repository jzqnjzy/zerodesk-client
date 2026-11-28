// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! First-frame fast-start controller, H.264/HEVC Annex-B parameter set auto-inliner,
//! and zero-buffer direct display pacer (pure control & payload layer, zero wire-format changes).

use crate::session::video::VideoCodec;
use serde::{Deserialize, Serialize};

/// Lightweight probe bitrate (kbps) used for the first 3 frames before CC Startup ramp.
pub const FAST_START_PROBE_BITRATE_KBPS: u32 = 1_500;
/// Number of initial frames encoded at the lightweight probe bitrate.
pub const FAST_START_PROBE_FRAMES: u32 = 3;
/// Maximum duration (ms) to remain in `Probing` if feedback is delayed or lost.
pub const FAST_START_TIMEOUT_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FastStartPhase {
    Idle,
    Probing,
    HandedOff,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FastStartDirective {
    pub phase: FastStartPhase,
    pub force_idr: bool,
    pub probe_bitrate_kbps: Option<u32>,
    pub handed_off_now: bool,
}

/// Coordinates session-connect immediate IDR, 3-frame 1500 kbps probe launch,
/// and smooth handoff into `CongestionController::Startup` upon first receiver feedback.
#[derive(Debug, Clone)]
pub struct FastStartController {
    phase: FastStartPhase,
    probe_bitrate_kbps: u32,
    probe_frame_limit: u32,
    connected_at_ms: Option<u64>,
    first_feedback_at_ms: Option<u64>,
    frames_encoded: u32,
    initial_idr_pending: bool,
}

impl Default for FastStartController {
    fn default() -> Self {
        Self::new()
    }
}

impl FastStartController {
    pub fn new() -> Self {
        Self::with_params(FAST_START_PROBE_BITRATE_KBPS, FAST_START_PROBE_FRAMES)
    }

    pub fn with_params(probe_bitrate_kbps: u32, probe_frame_limit: u32) -> Self {
        Self {
            phase: FastStartPhase::Idle,
            probe_bitrate_kbps: probe_bitrate_kbps.max(300),
            probe_frame_limit: probe_frame_limit.max(1),
            connected_at_ms: None,
            first_feedback_at_ms: None,
            frames_encoded: 0,
            initial_idr_pending: false,
        }
    }

    pub fn phase(&self) -> FastStartPhase {
        self.phase
    }

    pub fn is_probing(&self) -> bool {
        self.phase == FastStartPhase::Probing
    }

    pub fn is_handed_off(&self) -> bool {
        self.phase == FastStartPhase::HandedOff
    }

    pub fn connected_at_ms(&self) -> Option<u64> {
        self.connected_at_ms
    }

    pub fn first_feedback_at_ms(&self) -> Option<u64> {
        self.first_feedback_at_ms
    }

    pub fn probe_bitrate_kbps(&self) -> u32 {
        self.probe_bitrate_kbps
    }

    /// Invoked immediately upon session connection / media readiness.
    /// Pre-triggers an immediate forced IDR at `1500 kbps` probe bitrate.
    pub fn on_session_connected(&mut self, now_ms: u64) -> FastStartDirective {
        self.phase = FastStartPhase::Probing;
        self.connected_at_ms = Some(now_ms);
        self.first_feedback_at_ms = None;
        self.frames_encoded = 0;
        self.initial_idr_pending = true;
        FastStartDirective {
            phase: self.phase,
            force_idr: true,
            probe_bitrate_kbps: Some(self.probe_bitrate_kbps),
            handed_off_now: false,
        }
    }

    /// Records an encoded frame. First 3 frames remain capped at the lightweight probe bitrate.
    pub fn on_frame_encoded(&mut self, is_idr: bool) -> FastStartDirective {
        if self.phase != FastStartPhase::Probing {
            return FastStartDirective {
                phase: self.phase,
                force_idr: false,
                probe_bitrate_kbps: None,
                handed_off_now: false,
            };
        }

        if is_idr {
            self.initial_idr_pending = false;
        }
        self.frames_encoded = self.frames_encoded.saturating_add(1);

        if self.frames_encoded >= self.probe_frame_limit && self.first_feedback_at_ms.is_some() {
            self.phase = FastStartPhase::HandedOff;
            return FastStartDirective {
                phase: self.phase,
                force_idr: self.initial_idr_pending,
                probe_bitrate_kbps: None,
                handed_off_now: true,
            };
        }

        FastStartDirective {
            phase: self.phase,
            force_idr: self.initial_idr_pending,
            probe_bitrate_kbps: Some(self.probe_bitrate_kbps),
            handed_off_now: false,
        }
    }

    /// Watchdog tick: hands off cleanly from `Probing` to `HandedOff` if feedback is delayed
    /// past `FAST_START_TIMEOUT_MS` (2000ms) so bitrate is never stuck at the probe ceiling.
    pub fn on_tick(&mut self, now_ms: u64) -> FastStartDirective {
        if self.phase == FastStartPhase::Probing
            && self
                .connected_at_ms
                .is_some_and(|c| now_ms.saturating_sub(c) >= FAST_START_TIMEOUT_MS)
        {
            self.phase = FastStartPhase::HandedOff;
            return FastStartDirective {
                phase: self.phase,
                force_idr: self.initial_idr_pending,
                probe_bitrate_kbps: None,
                handed_off_now: true,
            };
        }
        FastStartDirective {
            phase: self.phase,
            force_idr: self.initial_idr_pending,
            probe_bitrate_kbps: if self.phase == FastStartPhase::Probing {
                Some(self.probe_bitrate_kbps)
            } else {
                None
            },
            handed_off_now: false,
        }
    }

    /// Records receiver feedback arrival. Hands off smoothly to CC `Startup` once
    /// the first 3 lightweight probe frames have launched (or if `FAST_START_TIMEOUT_MS` elapsed).
    pub fn on_feedback(&mut self, now_ms: u64) -> FastStartDirective {
        if self.first_feedback_at_ms.is_none() {
            self.first_feedback_at_ms = Some(now_ms);
        }
        let timed_out = self
            .connected_at_ms
            .is_some_and(|c| now_ms.saturating_sub(c) >= FAST_START_TIMEOUT_MS);
        if self.phase == FastStartPhase::Probing
            && (self.frames_encoded >= self.probe_frame_limit || timed_out)
        {
            self.phase = FastStartPhase::HandedOff;
            return FastStartDirective {
                phase: self.phase,
                force_idr: self.initial_idr_pending,
                probe_bitrate_kbps: None,
                handed_off_now: true,
            };
        }
        FastStartDirective {
            phase: self.phase,
            force_idr: self.initial_idr_pending,
            probe_bitrate_kbps: if self.phase == FastStartPhase::Probing {
                Some(self.probe_bitrate_kbps)
            } else {
                None
            },
            handed_off_now: false,
        }
    }
}

/// Annex-B NAL unit span inside a raw bitstream slice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AnnexBNal<'a> {
    start_code_offset: usize,
    payload: &'a [u8],
}

/// Parses Annex-B (`00 00 01` and `00 00 00 01`) NAL units safely without panicking on any input.
fn parse_annex_b_nals(data: &[u8]) -> Vec<AnnexBNal<'_>> {
    let mut positions: Vec<(usize, usize)> = Vec::new();
    let len = data.len();
    let mut i = 0usize;
    while i + 2 < len {
        if data[i] == 0 && data[i + 1] == 0 {
            if data[i + 2] == 1 {
                positions.push((i, i + 3));
                i += 3;
                continue;
            } else if i + 3 < len && data[i + 2] == 0 && data[i + 3] == 1 {
                positions.push((i, i + 4));
                i += 4;
                continue;
            }
        }
        i += 1;
    }

    let mut nals = Vec::with_capacity(positions.len());
    for idx in 0..positions.len() {
        let (sc_off, payload_start) = positions[idx];
        let payload_end = if idx + 1 < positions.len() {
            positions[idx + 1].0
        } else {
            len
        };
        if payload_start < payload_end {
            nals.push(AnnexBNal {
                start_code_offset: sc_off,
                payload: &data[payload_start..payload_end],
            });
        }
    }
    nals
}

#[inline]
fn h264_nal_type(payload: &[u8]) -> Option<u8> {
    payload.first().map(|b| b & 0x1F)
}

#[inline]
fn hevc_nal_type(payload: &[u8]) -> Option<u8> {
    payload.first().map(|b| (b >> 1) & 0x3F)
}

/// Result metadata from `ParameterSetInliner::inline_if_needed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineOutcome {
    pub data: Vec<u8>,
    pub contains_idr: bool,
    pub inlined_param_sets: bool,
    pub has_complete_param_sets: bool,
}

/// Caches latest H.264 (`SPS=7`, `PPS=8`) and HEVC (`VPS=32`, `SPS=33`, `PPS=34`) Annex-B
/// parameter sets and guarantees every IDR frame (`H.264 NAL 5`, `HEVC NAL 19/20`) carries
/// complete parameter sets inline so decoders can output the first frame immediately.
#[derive(Debug, Clone, Default)]
pub struct ParameterSetInliner {
    h264_sps: Option<Vec<u8>>,
    h264_pps: Option<Vec<u8>>,
    hevc_vps: Option<Vec<u8>>,
    hevc_sps: Option<Vec<u8>>,
    hevc_pps: Option<Vec<u8>>,
    inlined_count: u64,
}

impl ParameterSetInliner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn inlined_count(&self) -> u64 {
        self.inlined_count
    }

    pub fn has_complete_param_sets(&self, codec: VideoCodec) -> bool {
        match codec {
            VideoCodec::H264 => self.h264_sps.is_some() && self.h264_pps.is_some(),
            VideoCodec::Hevc => {
                self.hevc_vps.is_some() && self.hevc_sps.is_some() && self.hevc_pps.is_some()
            }
            VideoCodec::Vp9 | VideoCodec::Av1 => true,
        }
    }

    /// Inspects an Annex-B bitstream to verify whether an IDR frame already carries all
    /// required parameter sets ahead of its IDR slice.
    pub fn bitstream_has_complete_param_sets(codec: VideoCodec, bitstream: &[u8]) -> bool {
        match codec {
            VideoCodec::Vp9 | VideoCodec::Av1 => true,
            VideoCodec::H264 => {
                let nals = parse_annex_b_nals(bitstream);
                let mut seen_sps = false;
                let mut seen_pps = false;
                for nal in nals {
                    match h264_nal_type(nal.payload) {
                        Some(7) => seen_sps = true,
                        Some(8) => seen_pps = true,
                        Some(5) => return seen_sps && seen_pps,
                        _ => {}
                    }
                }
                seen_sps && seen_pps
            }
            VideoCodec::Hevc => {
                let nals = parse_annex_b_nals(bitstream);
                let mut seen_vps = false;
                let mut seen_sps = false;
                let mut seen_pps = false;
                for nal in nals {
                    match hevc_nal_type(nal.payload) {
                        Some(32) => seen_vps = true,
                        Some(33) => seen_sps = true,
                        Some(34) => seen_pps = true,
                        Some(19 | 20) => return seen_vps && seen_sps && seen_pps,
                        _ => {}
                    }
                }
                seen_vps && seen_sps && seen_pps
            }
        }
    }

    /// Scans `bitstream`, caches any new parameter sets, and if `bitstream` contains an IDR
    /// missing required parameter sets, prepends the cached parameter sets right before the
    /// IDR NAL unit (using canonical 4-byte Annex-B `00 00 00 01` start codes).
    pub fn inline_if_needed(&mut self, codec: VideoCodec, bitstream: &[u8]) -> InlineOutcome {
        match codec {
            VideoCodec::Vp9 | VideoCodec::Av1 => InlineOutcome {
                data: bitstream.to_vec(),
                contains_idr: false,
                inlined_param_sets: false,
                has_complete_param_sets: true,
            },
            VideoCodec::H264 => self.process_h264(bitstream),
            VideoCodec::Hevc => self.process_hevc(bitstream),
        }
    }

    fn process_h264(&mut self, bitstream: &[u8]) -> InlineOutcome {
        let nals = parse_annex_b_nals(bitstream);
        let mut has_sps_before_idr = false;
        let mut has_pps_before_idr = false;
        let mut first_idr_offset: Option<usize> = None;

        for nal in &nals {
            match h264_nal_type(nal.payload) {
                Some(7) => {
                    self.h264_sps = Some(nal.payload.to_vec());
                    if first_idr_offset.is_none() {
                        has_sps_before_idr = true;
                    }
                }
                Some(8) => {
                    self.h264_pps = Some(nal.payload.to_vec());
                    if first_idr_offset.is_none() {
                        has_pps_before_idr = true;
                    }
                }
                Some(5) => {
                    if first_idr_offset.is_none() {
                        first_idr_offset = Some(nal.start_code_offset);
                    }
                }
                _ => {}
            }
        }

        let Some(idr_off) = first_idr_offset else {
            return InlineOutcome {
                data: bitstream.to_vec(),
                contains_idr: false,
                inlined_param_sets: false,
                has_complete_param_sets: self.has_complete_param_sets(VideoCodec::H264),
            };
        };

        if has_sps_before_idr && has_pps_before_idr {
            return InlineOutcome {
                data: bitstream.to_vec(),
                contains_idr: true,
                inlined_param_sets: false,
                has_complete_param_sets: true,
            };
        }

        let mut inserted = false;
        let mut out = Vec::with_capacity(bitstream.len() + 128);
        out.extend_from_slice(&bitstream[..idr_off]);
        if !has_sps_before_idr {
            if let Some(sps) = &self.h264_sps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(sps);
                has_sps_before_idr = true;
                inserted = true;
            }
        }
        if !has_pps_before_idr {
            if let Some(pps) = &self.h264_pps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(pps);
                has_pps_before_idr = true;
                inserted = true;
            }
        }
        out.extend_from_slice(&bitstream[idr_off..]);

        if inserted {
            self.inlined_count = self.inlined_count.saturating_add(1);
        }

        InlineOutcome {
            data: out,
            contains_idr: true,
            inlined_param_sets: inserted,
            has_complete_param_sets: has_sps_before_idr && has_pps_before_idr,
        }
    }

    fn process_hevc(&mut self, bitstream: &[u8]) -> InlineOutcome {
        let nals = parse_annex_b_nals(bitstream);
        let mut has_vps_before_idr = false;
        let mut has_sps_before_idr = false;
        let mut has_pps_before_idr = false;
        let mut first_idr_offset: Option<usize> = None;

        for nal in &nals {
            match hevc_nal_type(nal.payload) {
                Some(32) => {
                    self.hevc_vps = Some(nal.payload.to_vec());
                    if first_idr_offset.is_none() {
                        has_vps_before_idr = true;
                    }
                }
                Some(33) => {
                    self.hevc_sps = Some(nal.payload.to_vec());
                    if first_idr_offset.is_none() {
                        has_sps_before_idr = true;
                    }
                }
                Some(34) => {
                    self.hevc_pps = Some(nal.payload.to_vec());
                    if first_idr_offset.is_none() {
                        has_pps_before_idr = true;
                    }
                }
                Some(19 | 20) => {
                    if first_idr_offset.is_none() {
                        first_idr_offset = Some(nal.start_code_offset);
                    }
                }
                _ => {}
            }
        }

        let Some(idr_off) = first_idr_offset else {
            return InlineOutcome {
                data: bitstream.to_vec(),
                contains_idr: false,
                inlined_param_sets: false,
                has_complete_param_sets: self.has_complete_param_sets(VideoCodec::Hevc),
            };
        };

        if has_vps_before_idr && has_sps_before_idr && has_pps_before_idr {
            return InlineOutcome {
                data: bitstream.to_vec(),
                contains_idr: true,
                inlined_param_sets: false,
                has_complete_param_sets: true,
            };
        }

        let mut inserted = false;
        let mut out = Vec::with_capacity(bitstream.len() + 192);
        out.extend_from_slice(&bitstream[..idr_off]);
        if !has_vps_before_idr {
            if let Some(vps) = &self.hevc_vps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(vps);
                has_vps_before_idr = true;
                inserted = true;
            }
        }
        if !has_sps_before_idr {
            if let Some(sps) = &self.hevc_sps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(sps);
                has_sps_before_idr = true;
                inserted = true;
            }
        }
        if !has_pps_before_idr {
            if let Some(pps) = &self.hevc_pps {
                out.extend_from_slice(&[0, 0, 0, 1]);
                out.extend_from_slice(pps);
                has_pps_before_idr = true;
                inserted = true;
            }
        }
        out.extend_from_slice(&bitstream[idr_off..]);

        if inserted {
            self.inlined_count = self.inlined_count.saturating_add(1);
        }

        InlineOutcome {
            data: out,
            contains_idr: true,
            inlined_param_sets: inserted,
            has_complete_param_sets: has_vps_before_idr && has_sps_before_idr && has_pps_before_idr,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PacerDecision {
    /// First keyframe with complete parameter sets arrived: bypass all playout buffering
    /// and display immediately (`wait_ms = 0`).
    RenderImmediately { wait_ms: u64, ttff_ms: u64 },
    /// Normal post-startup frame ready for low-latency display.
    RenderNormal { pacing_delay_ms: u64 },
    /// Non-IDR or parameter-set-incomplete frame arrived before the first IDR; wait for IDR.
    WaitForIdr,
}

/// Decoder-side zero-buffer direct output pacer that eliminates first-frame playout queue delay
/// and records exact time-to-first-frame (`ttff_ms`).
#[derive(Debug, Clone, Default)]
pub struct ZeroBufferPacer {
    connected_at_ms: Option<u64>,
    first_frame_displayed_at_ms: Option<u64>,
    ttff_ms: Option<u64>,
    frames_rendered: u64,
    dropped_before_first_idr: u64,
}

impl ZeroBufferPacer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_session_connected(&mut self, now_ms: u64) {
        self.connected_at_ms = Some(now_ms);
        self.first_frame_displayed_at_ms = None;
        self.ttff_ms = None;
        self.frames_rendered = 0;
        self.dropped_before_first_idr = 0;
    }

    pub fn ttff_ms(&self) -> Option<u64> {
        self.ttff_ms
    }

    pub fn has_displayed_first_frame(&self) -> bool {
        self.first_frame_displayed_at_ms.is_some()
    }

    pub fn frames_rendered(&self) -> u64 {
        self.frames_rendered
    }

    pub fn dropped_before_first_idr(&self) -> u64 {
        self.dropped_before_first_idr
    }

    /// Evaluates a decoded frame ready for presentation at monotonic timestamp `now_ms`.
    pub fn on_decoded_frame_ready(
        &mut self,
        now_ms: u64,
        is_idr: bool,
        has_param_sets: bool,
    ) -> PacerDecision {
        if self.first_frame_displayed_at_ms.is_none() {
            if is_idr && has_param_sets {
                let start = self.connected_at_ms.unwrap_or(now_ms);
                let ttff = now_ms.saturating_sub(start);
                self.first_frame_displayed_at_ms = Some(now_ms);
                self.ttff_ms = Some(ttff);
                self.frames_rendered = self.frames_rendered.saturating_add(1);
                return PacerDecision::RenderImmediately {
                    wait_ms: 0,
                    ttff_ms: ttff,
                };
            }
            self.dropped_before_first_idr = self.dropped_before_first_idr.saturating_add(1);
            return PacerDecision::WaitForIdr;
        }

        self.frames_rendered = self.frames_rendered.saturating_add(1);
        PacerDecision::RenderNormal { pacing_delay_ms: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_start_forces_idr_probes_3_frames_at_1500_then_hands_off_on_feedback() {
        let mut fs = FastStartController::new();
        let d0 = fs.on_session_connected(100);
        assert_eq!(d0.phase, FastStartPhase::Probing);
        assert!(d0.force_idr);
        assert_eq!(d0.probe_bitrate_kbps, Some(1500));

        // Frame 1 (IDR)
        let f1 = fs.on_frame_encoded(true);
        assert_eq!(f1.phase, FastStartPhase::Probing);
        assert!(!f1.force_idr);
        assert_eq!(f1.probe_bitrate_kbps, Some(1500));

        // Early feedback at frame 1 does NOT end 3-frame probe prematurely.
        let fb1 = fs.on_feedback(130);
        assert_eq!(fb1.phase, FastStartPhase::Probing);
        assert!(!fb1.handed_off_now);

        // Frame 2
        assert_eq!(fs.on_frame_encoded(false).phase, FastStartPhase::Probing);

        // Frame 3 completes 3 probe frames with feedback already present -> smooth handoff!
        let f3 = fs.on_frame_encoded(false);
        assert_eq!(f3.phase, FastStartPhase::HandedOff);
        assert!(f3.handed_off_now);
        assert_eq!(f3.probe_bitrate_kbps, None);
    }

    #[test]
    fn fast_start_timeout_watchdog_hands_off_after_2000ms_and_preserves_pending_idr() {
        let mut fs = FastStartController::new();
        fs.on_session_connected(500);
        // No feedback and no IDR yet at +1999ms -> still Probing.
        let t1 = fs.on_tick(500 + FAST_START_TIMEOUT_MS - 1);
        assert_eq!(t1.phase, FastStartPhase::Probing);
        assert!(!t1.handed_off_now);
        assert!(t1.force_idr);

        // At +2000ms -> hands off cleanly while keeping pending force_idr = true!
        let t2 = fs.on_tick(500 + FAST_START_TIMEOUT_MS);
        assert_eq!(t2.phase, FastStartPhase::HandedOff);
        assert!(t2.handed_off_now);
        assert_eq!(t2.probe_bitrate_kbps, None);
        assert!(t2.force_idr);
    }

    #[test]
    fn parameter_set_inliner_caches_and_inlines_h264_sps_pps_on_subsequent_idrs() {
        let mut inliner = ParameterSetInliner::new();
        // Frame 1: 3-byte and 4-byte Annex-B start codes with SPS(7), PPS(8), IDR(5)
        let frame1 = [
            0, 0, 0, 1, 0x67, 0x42, 0xE0, 0x1F, // SPS (type 7)
            0, 0, 1, 0x68, 0xCE, 0x3C, 0x80, // PPS (type 8)
            0, 0, 0, 1, 0x65, 0x88, 0x84, // IDR (type 5)
        ];
        let r1 = inliner.inline_if_needed(VideoCodec::H264, &frame1);
        assert!(r1.contains_idr);
        assert!(!r1.inlined_param_sets);
        assert!(r1.has_complete_param_sets);

        // Frame 2: bare IDR (type 5) missing SPS & PPS
        let bare_idr = [0, 0, 1, 0x65, 0xAA, 0xBB, 0xCC];
        assert!(!ParameterSetInliner::bitstream_has_complete_param_sets(
            VideoCodec::H264,
            &bare_idr
        ));
        let r2 = inliner.inline_if_needed(VideoCodec::H264, &bare_idr);
        assert!(r2.contains_idr);
        assert!(r2.inlined_param_sets);
        assert!(r2.has_complete_param_sets);
        assert_eq!(inliner.inlined_count(), 1);
        assert!(ParameterSetInliner::bitstream_has_complete_param_sets(
            VideoCodec::H264,
            &r2.data
        ));

        // Non-IDR P-frame (type 1) is NOT modified.
        let p_frame = [0, 0, 0, 1, 0x41, 0x9A, 0x01];
        let r3 = inliner.inline_if_needed(VideoCodec::H264, &p_frame);
        assert!(!r3.contains_idr);
        assert!(!r3.inlined_param_sets);
        assert_eq!(r3.data, p_frame);
    }

    #[test]
    fn parameter_set_inliner_caches_and_inlines_hevc_vps_sps_pps() {
        let mut inliner = ParameterSetInliner::new();
        // HEVC NAL header byte 0 = (nal_type << 1):
        // VPS=32 -> 0x40, SPS=33 -> 0x42, PPS=34 -> 0x44, IDR_W_RADL=19 -> 0x26, IDR_N_LP=20 -> 0x28
        let frame1 = [
            0, 0, 0, 1, 0x40, 0x01, 0xAA, // VPS (32)
            0, 0, 0, 1, 0x42, 0x01, 0xBB, // SPS (33)
            0, 0, 1, 0x44, 0x01, 0xCC, // PPS (34)
            0, 0, 0, 1, 0x26, 0x01, 0xDD, // IDR_W_RADL (19)
        ];
        let r1 = inliner.inline_if_needed(VideoCodec::Hevc, &frame1);
        assert!(r1.contains_idr && r1.has_complete_param_sets && !r1.inlined_param_sets);

        // Bare IDR_N_LP (20) missing VPS/SPS/PPS
        let bare_idr = [0, 0, 0, 1, 0x28, 0x01, 0xEE, 0xFF];
        let r2 = inliner.inline_if_needed(VideoCodec::Hevc, &bare_idr);
        assert!(r2.contains_idr);
        assert!(r2.inlined_param_sets);
        assert!(r2.has_complete_param_sets);
        assert!(ParameterSetInliner::bitstream_has_complete_param_sets(
            VideoCodec::Hevc,
            &r2.data
        ));

        // Empty / garbage input never panics.
        let r_empty = inliner.inline_if_needed(VideoCodec::Hevc, &[]);
        assert!(r_empty.data.is_empty());
        let r_short = inliner.inline_if_needed(VideoCodec::H264, &[0, 0, 1]);
        assert_eq!(r_short.data, &[0, 0, 1]);
    }

    #[test]
    fn zero_buffer_pacer_renders_first_valid_idr_with_zero_wait() {
        let mut pacer = ZeroBufferPacer::new();
        pacer.on_session_connected(1_000);
        assert_eq!(
            pacer.on_decoded_frame_ready(1_040, false, true),
            PacerDecision::WaitForIdr
        );
        assert_eq!(
            pacer.on_decoded_frame_ready(1_050, true, false),
            PacerDecision::WaitForIdr
        );
        assert_eq!(
            pacer.on_decoded_frame_ready(1_085, true, true),
            PacerDecision::RenderImmediately {
                wait_ms: 0,
                ttff_ms: 85,
            }
        );
        assert_eq!(pacer.ttff_ms(), Some(85));
        assert_eq!(pacer.dropped_before_first_idr(), 2);
        assert_eq!(
            pacer.on_decoded_frame_ready(1_118, false, false),
            PacerDecision::RenderNormal { pacing_delay_ms: 0 }
        );
    }
}
