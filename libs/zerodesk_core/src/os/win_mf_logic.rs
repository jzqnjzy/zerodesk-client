// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic Windows Media Foundation Hardware MFT selection, LUID
//! matching, strict first-IDR readiness state machine, non-silent degradation
//! / renegotiation policy, and CPU color-space conversion helpers.
//!
//! Hardware encoding policy:
//! - Uses Windows Media Foundation hardware MFTs ONLY (`MFTEnumEx` with
//!   `MFT_ENUM_FLAG_HARDWARE`); ZERO proprietary NVENC/AMF/QSV SDKs.
//! - Enumeration NEVER marks the encoder `HardwareReady`; readiness occurs ONLY
//!   after the first IDR keyframe encodes with non-zero bytes.
//! - Mid-stream hardware failures perform bounded MFT reinit retries, then emit
//!   explicit `"hardware_encoder_failed_renegotiate_vp9"` (NEVER silent SW fallback).
//! - CPU `bgra_to_nv12` / `bgra_to_i420` helpers are color-space conversion
//!   fallbacks ONLY when D3D11 NV12 zero-copy is unavailable — NOT software encoding.

use super::{
    traits::{
        HardwareCodecEvent, HardwareCodecKind, HardwareCodecState,
        HW_ENCODER_FAILED_RENEGOTIATE_EVENT,
    },
    win_dxgi_logic::DxgiAdapterLuid,
};
use crate::session::video::{I420Frame, VideoCodec, VideoError};
use serde::{Deserialize, Serialize};

pub const DEFAULT_MF_MAX_REINIT_RETRIES: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfHwCodec {
    H264,
    Hevc,
    Av1,
}

impl MfHwCodec {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::H264 => "h264",
            Self::Hevc => "hevc",
            Self::Av1 => "av1",
        }
    }

    pub fn to_hardware_codec_kind(self) -> HardwareCodecKind {
        match self {
            Self::H264 => HardwareCodecKind::H264,
            Self::Hevc => HardwareCodecKind::Hevc,
            Self::Av1 => HardwareCodecKind::Av1,
        }
    }

    pub fn to_video_codec(self) -> VideoCodec {
        match self {
            Self::H264 => VideoCodec::H264,
            Self::Hevc => VideoCodec::Hevc,
            Self::Av1 => VideoCodec::Av1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfHwVendor {
    Nvidia,
    Amd,
    Intel,
    Qualcomm,
    Unknown,
}

impl MfHwVendor {
    pub fn infer_from_friendly_name(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        if lower.contains("nvidia") || lower.contains("nvenc") {
            Self::Nvidia
        } else if lower.contains("amd") || lower.contains("amf") || lower.contains("radeon") {
            Self::Amd
        } else if lower.contains("intel") || lower.contains("qsv") || lower.contains("quicksync") {
            Self::Intel
        } else if lower.contains("qualcomm") || lower.contains("adreno") {
            Self::Qualcomm
        } else {
            Self::Unknown
        }
    }
}

/// Platform-agnostic descriptor of an enumerated Media Foundation hardware MFT.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MfHwMftDescriptor {
    pub friendly_name: String,
    pub codec: MfHwCodec,
    pub adapter_luid: Option<DxgiAdapterLuid>,
    pub is_hardware: bool,
    pub supports_d3d11_aware: bool,
    pub vendor: MfHwVendor,
}

/// Result of matching enumerated hardware MFTs against the DXGI capture adapter LUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LuidMatchOutcome {
    ExactLuidZeroCopy {
        selected_index: usize,
        adapter_luid: DxgiAdapterLuid,
        d3d11_aware: bool,
    },
    LuidMismatchDiagnostic {
        selected_index: Option<usize>,
        capture_luid: DxgiAdapterLuid,
        candidate_luids: Vec<Option<DxgiAdapterLuid>>,
        diagnostic: String,
    },
    NoHardwareMftAvailable {
        codec: MfHwCodec,
        diagnostic: String,
    },
}

/// Selects a Media Foundation hardware MFT for `codec` matching `capture_luid`.
///
/// Rules:
/// 1. Non-hardware MFTs (`!is_hardware`) are NEVER considered.
/// 2. Exact `MFT_ENUM_ADAPTER_LUID == Some(capture_luid)` is strongly preferred
///    (with `supports_d3d11_aware == true` ranked first for D3D11 NV12 zero-copy).
/// 3. If no candidate matches `capture_luid`, returns `LuidMismatchDiagnostic`
///    with explicit diagnostic text (optionally pointing at a cross-adapter HW MFT
///    only when `allow_cross_adapter_copy == true`).
pub fn select_hw_mft_for_luid(
    candidates: &[MfHwMftDescriptor],
    codec: MfHwCodec,
    capture_luid: DxgiAdapterLuid,
    allow_cross_adapter_copy: bool,
) -> LuidMatchOutcome {
    let hw_indices: Vec<usize> = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.is_hardware && c.codec == codec)
        .map(|(i, _)| i)
        .collect();

    if hw_indices.is_empty() {
        return LuidMatchOutcome::NoHardwareMftAvailable {
            codec,
            diagnostic: format!(
                "no Media Foundation hardware encoder MFT enumerated for {}",
                codec.as_str()
            ),
        };
    }

    // Priority 1: exact LUID match + D3D11-aware (true zero-copy NV12 path).
    if let Some(&idx) = hw_indices.iter().find(|&&i| {
        candidates[i].adapter_luid == Some(capture_luid) && candidates[i].supports_d3d11_aware
    }) {
        return LuidMatchOutcome::ExactLuidZeroCopy {
            selected_index: idx,
            adapter_luid: capture_luid,
            d3d11_aware: true,
        };
    }

    // Priority 2: exact LUID match (adapter-matched HW MFT even if D3D11 attribute omitted).
    if let Some(&idx) = hw_indices
        .iter()
        .find(|&&i| candidates[i].adapter_luid == Some(capture_luid))
    {
        return LuidMatchOutcome::ExactLuidZeroCopy {
            selected_index: idx,
            adapter_luid: capture_luid,
            d3d11_aware: false,
        };
    }

    let candidate_luids: Vec<Option<DxgiAdapterLuid>> = hw_indices
        .iter()
        .map(|&i| candidates[i].adapter_luid)
        .collect();
    let selected_index = if allow_cross_adapter_copy {
        hw_indices
            .iter()
            .copied()
            .find(|&i| candidates[i].supports_d3d11_aware)
            .or_else(|| hw_indices.first().copied())
    } else {
        None
    };

    LuidMatchOutcome::LuidMismatchDiagnostic {
        selected_index,
        capture_luid,
        candidate_luids,
        diagnostic: format!(
            "DXGI capture adapter LUID ({:#x}, {}) did not match any {} hardware MFT MFT_ENUM_ADAPTER_LUID; zero-copy D3D11 NV12 unavailable",
            capture_luid.low_part,
            capture_luid.high_part,
            codec.as_str()
        ),
    }
}

/// Strict Windows Media Foundation hardware encoder verification & degradation
/// state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MfHwEncoderState {
    Enumerated,
    Initialized,
    WaitingFirstIdr,
    HardwareReady,
    ReinitRetry(u8),
    FailedNeedsRenegotiation { reason: String },
}

impl MfHwEncoderState {
    pub fn to_hardware_codec_state(&self, max_reinit_retries: u8) -> HardwareCodecState {
        match self {
            Self::Enumerated => HardwareCodecState::Enumerated,
            Self::Initialized => HardwareCodecState::Initialized,
            Self::WaitingFirstIdr => HardwareCodecState::WaitingFirstIdr,
            Self::HardwareReady => HardwareCodecState::HardwareReady,
            Self::ReinitRetry(attempt) => HardwareCodecState::ReinitRetry {
                attempt: *attempt,
                max_attempts: max_reinit_retries,
            },
            Self::FailedNeedsRenegotiation { reason } => {
                HardwareCodecState::FailedNeedsRenegotiation {
                    reason: reason.clone(),
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MfErrorDecision {
    RetryReinit { attempt: u8 },
    FailedNeedsRenegotiation { event_code: &'static str, reason: String },
}

#[derive(Debug, Clone)]
pub struct MfHwEncoderStateMachine {
    codec: MfHwCodec,
    mft_name: String,
    state: MfHwEncoderState,
    reinit_attempts: u8,
    max_reinit_retries: u8,
    idr_frames_encoded: u64,
    total_frames_encoded: u64,
    events: Vec<HardwareCodecEvent>,
}

impl MfHwEncoderStateMachine {
    pub fn new(codec: MfHwCodec, mft_name: impl Into<String>) -> Self {
        Self {
            codec,
            mft_name: mft_name.into(),
            state: MfHwEncoderState::Enumerated,
            reinit_attempts: 0,
            max_reinit_retries: DEFAULT_MF_MAX_REINIT_RETRIES,
            idr_frames_encoded: 0,
            total_frames_encoded: 0,
            events: Vec::new(),
        }
    }

    pub fn with_max_reinit_retries(mut self, max_retries: u8) -> Self {
        self.max_reinit_retries = max_retries;
        self
    }

    pub fn codec(&self) -> MfHwCodec {
        self.codec
    }

    pub fn mft_name(&self) -> &str {
        &self.mft_name
    }

    pub fn state(&self) -> &MfHwEncoderState {
        &self.state
    }

    pub fn hardware_codec_state(&self) -> HardwareCodecState {
        self.state.to_hardware_codec_state(self.max_reinit_retries)
    }

    pub fn is_hardware_ready(&self) -> bool {
        matches!(self.state, MfHwEncoderState::HardwareReady)
    }

    pub fn needs_renegotiation(&self) -> bool {
        matches!(self.state, MfHwEncoderState::FailedNeedsRenegotiation { .. })
    }

    pub fn reinit_attempts(&self) -> u8 {
        self.reinit_attempts
    }

    pub fn idr_frames_encoded(&self) -> u64 {
        self.idr_frames_encoded
    }

    pub fn total_frames_encoded(&self) -> u64 {
        self.total_frames_encoded
    }

    pub fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn on_initialized(&mut self) -> Result<(), VideoError> {
        if matches!(
            self.state,
            MfHwEncoderState::Enumerated | MfHwEncoderState::ReinitRetry(_)
        ) {
            self.state = MfHwEncoderState::Initialized;
            Ok(())
        } else {
            Err(VideoError::Encoder(format!(
                "invalid MF transition on_initialized from {:?}",
                self.state
            )))
        }
    }

    pub fn on_streaming_started(&mut self) -> Result<(), VideoError> {
        if matches!(self.state, MfHwEncoderState::Initialized) {
            self.state = MfHwEncoderState::WaitingFirstIdr;
            Ok(())
        } else {
            Err(VideoError::Encoder(format!(
                "invalid MF transition on_streaming_started from {:?}",
                self.state
            )))
        }
    }

    /// Records an encoded output sample.
    ///
    /// Contract: transitions to `HardwareReady` ONLY when `is_idr == true` AND
    /// `byte_len > 0` while in `WaitingFirstIdr`. Non-IDR or empty samples NEVER
    /// promote the encoder to `HardwareReady`.
    pub fn on_sample_encoded(&mut self, is_idr: bool, byte_len: usize) -> bool {
        if byte_len == 0 {
            return false;
        }
        self.total_frames_encoded = self.total_frames_encoded.saturating_add(1);
        if is_idr {
            self.idr_frames_encoded = self.idr_frames_encoded.saturating_add(1);
        }
        if matches!(self.state, MfHwEncoderState::WaitingFirstIdr) && is_idr {
            self.state = MfHwEncoderState::HardwareReady;
            self.events.push(HardwareCodecEvent::HardwareReady {
                codec: self.codec.to_hardware_codec_kind(),
                backend: format!("windows_mf_hw:{}", self.mft_name),
            });
            return true;
        }
        false
    }

    /// Convenience alias matching the strict first-IDR contract.
    pub fn on_first_idr_encoded(&mut self, byte_len: usize) -> bool {
        self.on_sample_encoded(true, byte_len)
    }

    /// Handles a mid-stream or startup hardware MFT error:
    /// - If `reinit_attempts < max_reinit_retries`: increments attempt count,
    ///   transitions to `ReinitRetry(attempt)`, emits `ReinitScheduled`.
    /// - Otherwise: transitions permanently to `FailedNeedsRenegotiation` and
    ///   emits `"hardware_encoder_failed_renegotiate_vp9"` (NEVER silent SW fallback).
    pub fn on_hw_error(&mut self, reason: impl Into<String>) -> MfErrorDecision {
        let reason_str = reason.into();
        if self.reinit_attempts < self.max_reinit_retries {
            self.reinit_attempts = self.reinit_attempts.saturating_add(1);
            let attempt = self.reinit_attempts;
            self.state = MfHwEncoderState::ReinitRetry(attempt);
            self.events.push(HardwareCodecEvent::ReinitScheduled {
                codec: self.codec.to_hardware_codec_kind(),
                attempt,
                reason: reason_str,
            });
            MfErrorDecision::RetryReinit { attempt }
        } else {
            self.state = MfHwEncoderState::FailedNeedsRenegotiation {
                reason: reason_str.clone(),
            };
            self.events
                .push(HardwareCodecEvent::HardwareFailedRenegotiate {
                    codec: self.codec.to_hardware_codec_kind(),
                    event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT.to_string(),
                    reason: reason_str.clone(),
                });
            MfErrorDecision::FailedNeedsRenegotiation {
                event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT,
                reason: reason_str,
            }
        }
    }

    /// Marks MFT reinitialization complete and returns to `WaitingFirstIdr` so
    /// the freshly rebuilt hardware MFT must again prove itself with a real IDR.
    pub fn on_reinit_succeeded(&mut self) -> Result<(), VideoError> {
        if matches!(self.state, MfHwEncoderState::ReinitRetry(_)) {
            self.state = MfHwEncoderState::WaitingFirstIdr;
            Ok(())
        } else {
            Err(VideoError::Encoder(format!(
                "invalid MF transition on_reinit_succeeded from {:?}",
                self.state
            )))
        }
    }
}

/// Color matrix for CPU BGRA -> NV12 / I420 color-space conversion fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ColorMatrix {
    Bt601,
    Bt709,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nv12Buffer {
    pub width: usize,
    pub height: usize,
    pub y_stride: usize,
    pub uv_stride: usize,
    pub y_plane: Vec<u8>,
    pub uv_plane: Vec<u8>,
}

fn validate_bgra_conversion_inputs(
    bgra: &[u8],
    width: usize,
    height: usize,
    bgra_stride: usize,
) -> Result<(), VideoError> {
    if width == 0 || height == 0 || (width & 1) != 0 || (height & 1) != 0 {
        return Err(VideoError::InvalidInput(format!(
            "color conversion dimensions must be positive and even, got {width}x{height}"
        )));
    }
    let min_stride = width
        .checked_mul(4)
        .ok_or_else(|| VideoError::InvalidInput("BGRA stride overflow".into()))?;
    if bgra_stride < min_stride {
        return Err(VideoError::InvalidInput(format!(
            "BGRA stride {bgra_stride} < width*4 ({min_stride})"
        )));
    }
    let needed = bgra_stride
        .checked_mul(height)
        .ok_or_else(|| VideoError::InvalidInput("BGRA byte length overflow".into()))?;
    if bgra.len() < needed {
        return Err(VideoError::InvalidInput(format!(
            "BGRA buffer len {} < stride*height ({needed})",
            bgra.len()
        )));
    }
    Ok(())
}

#[inline]
fn rgb_to_y(r: i32, g: i32, b: i32, matrix: ColorMatrix) -> u8 {
    let raw = match matrix {
        ColorMatrix::Bt601 => ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16,
        ColorMatrix::Bt709 => ((47 * r + 157 * g + 16 * b + 128) >> 8) + 16,
    };
    raw.clamp(16, 235) as u8
}

#[inline]
fn rgb_to_uv(r: i32, g: i32, b: i32, matrix: ColorMatrix) -> (u8, u8) {
    let (u, v) = match matrix {
        ColorMatrix::Bt601 => (
            ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128,
            ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128,
        ),
        ColorMatrix::Bt709 => (
            ((-26 * r - 87 * g + 112 * b + 128) >> 8) + 128,
            ((112 * r - 102 * g - 10 * b + 128) >> 8) + 128,
        ),
    };
    (u.clamp(16, 240) as u8, v.clamp(16, 240) as u8)
}

/// CPU color-space conversion fallback: strided BGRA8 -> tightly-packed NV12
/// (video-range BT.601 or BT.709).
///
/// NOTE: This helper is strictly a color-space conversion fallback for feeding
/// a hardware MFT when D3D11 Video Processor NV12 zero-copy is unavailable —
/// it is NEVER a software video encoder.
pub fn bgra_to_nv12(
    bgra: &[u8],
    width: usize,
    height: usize,
    bgra_stride: usize,
    matrix: ColorMatrix,
) -> Result<Nv12Buffer, VideoError> {
    validate_bgra_conversion_inputs(bgra, width, height, bgra_stride)?;
    let mut y_plane = vec![0u8; width * height];
    let mut uv_plane = vec![0u8; width * (height / 2)];

    for row in 0..height {
        let src_row = row * bgra_stride;
        let dst_y_row = row * width;
        for col in 0..width {
            let p = src_row + col * 4;
            let b = i32::from(bgra[p]);
            let g = i32::from(bgra[p + 1]);
            let r = i32::from(bgra[p + 2]);
            y_plane[dst_y_row + col] = rgb_to_y(r, g, b, matrix);
        }
    }

    for by in 0..(height / 2) {
        let r0 = (by * 2) * bgra_stride;
        let r1 = (by * 2 + 1) * bgra_stride;
        let dst_uv_row = by * width;
        for bx in 0..(width / 2) {
            let c0 = bx * 8;
            let c1 = c0 + 4;
            let b = (i32::from(bgra[r0 + c0])
                + i32::from(bgra[r0 + c1])
                + i32::from(bgra[r1 + c0])
                + i32::from(bgra[r1 + c1])
                + 2)
                >> 2;
            let g = (i32::from(bgra[r0 + c0 + 1])
                + i32::from(bgra[r0 + c1 + 1])
                + i32::from(bgra[r1 + c0 + 1])
                + i32::from(bgra[r1 + c1 + 1])
                + 2)
                >> 2;
            let r = (i32::from(bgra[r0 + c0 + 2])
                + i32::from(bgra[r0 + c1 + 2])
                + i32::from(bgra[r1 + c0 + 2])
                + i32::from(bgra[r1 + c1 + 2])
                + 2)
                >> 2;
            let (u, v) = rgb_to_uv(r, g, b, matrix);
            uv_plane[dst_uv_row + bx * 2] = u;
            uv_plane[dst_uv_row + bx * 2 + 1] = v;
        }
    }

    Ok(Nv12Buffer {
        width,
        height,
        y_stride: width,
        uv_stride: width,
        y_plane,
        uv_plane,
    })
}

/// CPU color-space conversion fallback: strided BGRA8 -> planar I420
/// (video-range BT.601 or BT.709). Color-space conversion only, NOT software encoding.
pub fn bgra_to_i420(
    bgra: &[u8],
    width: usize,
    height: usize,
    bgra_stride: usize,
    matrix: ColorMatrix,
) -> Result<I420Frame, VideoError> {
    let nv12 = bgra_to_nv12(bgra, width, height, bgra_stride, matrix)?;
    let uv_w = width / 2;
    let uv_h = height / 2;
    let mut u = vec![0u8; uv_w * uv_h];
    let mut v = vec![0u8; uv_w * uv_h];
    for row in 0..uv_h {
        let src_row = row * nv12.uv_stride;
        let dst_row = row * uv_w;
        for col in 0..uv_w {
            u[dst_row + col] = nv12.uv_plane[src_row + col * 2];
            v[dst_row + col] = nv12.uv_plane[src_row + col * 2 + 1];
        }
    }
    I420Frame::new(width, height, nv12.y_plane, u, v)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_mft(
        name: &str,
        codec: MfHwCodec,
        luid: Option<DxgiAdapterLuid>,
        is_hardware: bool,
        d3d11: bool,
    ) -> MfHwMftDescriptor {
        MfHwMftDescriptor {
            friendly_name: name.into(),
            codec,
            adapter_luid: luid,
            is_hardware,
            supports_d3d11_aware: d3d11,
            vendor: MfHwVendor::infer_from_friendly_name(name),
        }
    }

    #[test]
    fn luid_selection_prefers_exact_d3d11_hw_mft_and_rejects_software() {
        let capture_luid = DxgiAdapterLuid::new(0x1234, 0);
        let other_luid = DxgiAdapterLuid::new(0x9999, 0);
        let candidates = vec![
            make_mft("Microsoft H264 SW Encoder", MfHwCodec::H264, Some(capture_luid), false, true),
            make_mft("Intel QuickSync H.264", MfHwCodec::H264, Some(other_luid), true, true),
            make_mft("NVIDIA H.264 Encoder MFT", MfHwCodec::H264, Some(capture_luid), true, false),
            make_mft("NVIDIA H.264 D3D11 MFT", MfHwCodec::H264, Some(capture_luid), true, true),
        ];
        assert_eq!(
            select_hw_mft_for_luid(&candidates, MfHwCodec::H264, capture_luid, false),
            LuidMatchOutcome::ExactLuidZeroCopy {
                selected_index: 3,
                adapter_luid: capture_luid,
                d3d11_aware: true,
            }
        );

        // Mismatch returns explicit diagnostic (no silent zero-copy claim)
        let mismatch = select_hw_mft_for_luid(
            &[make_mft("AMD AMF H264", MfHwCodec::H264, Some(other_luid), true, true)],
            MfHwCodec::H264,
            capture_luid,
            false,
        );
        assert!(matches!(
            mismatch,
            LuidMatchOutcome::LuidMismatchDiagnostic {
                selected_index: None,
                ..
            }
        ));

        // Software-only candidate list -> NoHardwareMftAvailable
        let sw_only = select_hw_mft_for_luid(
            &[make_mft("MS SW H264", MfHwCodec::H264, Some(capture_luid), false, true)],
            MfHwCodec::H264,
            capture_luid,
            true,
        );
        assert!(matches!(
            sw_only,
            LuidMatchOutcome::NoHardwareMftAvailable {
                codec: MfHwCodec::H264,
                ..
            }
        ));
    }

    #[test]
    fn encoder_state_machine_enforces_first_idr_gate_and_non_silent_degradation() {
        let mut sm = MfHwEncoderStateMachine::new(MfHwCodec::H264, "NVIDIA H.264 Encoder MFT");
        // Enumeration alone NEVER marks HardwareReady.
        assert_eq!(sm.state(), &MfHwEncoderState::Enumerated);
        assert!(!sm.is_hardware_ready());

        sm.on_initialized().unwrap();
        assert_eq!(sm.state(), &MfHwEncoderState::Initialized);
        assert!(!sm.is_hardware_ready());

        sm.on_streaming_started().unwrap();
        assert_eq!(sm.state(), &MfHwEncoderState::WaitingFirstIdr);
        assert!(!sm.is_hardware_ready());

        // Non-IDR or 0-byte IDR MUST NOT advance to HardwareReady.
        assert!(!sm.on_sample_encoded(false, 4096));
        assert!(!sm.is_hardware_ready());
        assert!(!sm.on_first_idr_encoded(0));
        assert!(!sm.is_hardware_ready());

        // First real IDR keyframe promotes to HardwareReady and emits event.
        assert!(sm.on_first_idr_encoded(12_345));
        assert!(sm.is_hardware_ready());
        let events = sm.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], HardwareCodecEvent::HardwareReady { .. }));

        // Mid-stream failure 1 -> ReinitRetry(1)
        assert_eq!(
            sm.on_hw_error("MF_E_TRANSFORM_STREAM_CHANGE"),
            MfErrorDecision::RetryReinit { attempt: 1 }
        );
        assert!(!sm.is_hardware_ready());
        assert_eq!(sm.state(), &MfHwEncoderState::ReinitRetry(1));

        // Reinit succeeded -> back to WaitingFirstIdr (must prove IDR again!)
        sm.on_reinit_succeeded().unwrap();
        assert_eq!(sm.state(), &MfHwEncoderState::WaitingFirstIdr);
        assert!(!sm.is_hardware_ready());
        assert!(sm.on_first_idr_encoded(8_192));
        assert!(sm.is_hardware_ready());

        // Mid-stream failure 2 -> ReinitRetry(2)
        assert_eq!(
            sm.on_hw_error("DXGI_ERROR_DEVICE_RESET"),
            MfErrorDecision::RetryReinit { attempt: 2 }
        );
        // Failure 3 exhausts retries -> explicit FailedNeedsRenegotiation (NEVER silent SW fallback)
        assert_eq!(
            sm.on_hw_error("MFT hardware reset failed"),
            MfErrorDecision::FailedNeedsRenegotiation {
                event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT,
                reason: "MFT hardware reset failed".into(),
            }
        );
        assert!(sm.needs_renegotiation());
        assert!(!sm.is_hardware_ready());
        let evs = sm.drain_events();
        assert!(evs.iter().any(|e| matches!(
            e,
            HardwareCodecEvent::HardwareFailedRenegotiate { event_code, .. }
                if event_code == "hardware_encoder_failed_renegotiate_vp9"
        )));
    }

    #[test]
    fn bgra_to_nv12_and_i420_verify_dimensions_strides_and_bt709_bt601_planes() {
        // 8x6 BGRA with padded stride (40 bytes instead of 32)
        let w = 8usize;
        let h = 6usize;
        let stride = 40usize;
        let mut white_bgra = vec![0u8; stride * h];
        for row in 0..h {
            for col in 0..w {
                let p = row * stride + col * 4;
                white_bgra[p] = 255; // B
                white_bgra[p + 1] = 255; // G
                white_bgra[p + 2] = 255; // R
                white_bgra[p + 3] = 255; // A
            }
        }

        for matrix in [ColorMatrix::Bt601, ColorMatrix::Bt709] {
            let nv12 = bgra_to_nv12(&white_bgra, w, h, stride, matrix).unwrap();
            assert_eq!(nv12.width, w);
            assert_eq!(nv12.height, h);
            assert_eq!(nv12.y_stride, w);
            assert_eq!(nv12.uv_stride, w);
            assert_eq!(nv12.y_plane.len(), w * h);
            assert_eq!(nv12.uv_plane.len(), w * (h / 2));
            assert!(nv12.y_plane.iter().all(|&y| y == 235));
            assert!(nv12.uv_plane.iter().all(|&c| (127..=129).contains(&c)));

            let i420 = bgra_to_i420(&white_bgra, w, h, stride, matrix).unwrap();
            assert_eq!(i420.width, w);
            assert_eq!(i420.height, h);
            assert_eq!(i420.y.len(), w * h);
            assert_eq!(i420.u.len(), (w / 2) * (h / 2));
            assert_eq!(i420.v.len(), (w / 2) * (h / 2));
        }

        // Pure red distinguishes BT.601 (Y~82) vs BT.709 (Y~63) and has high V chroma (>200).
        let mut red_bgra = vec![0u8; w * 4 * h];
        for px in red_bgra.chunks_exact_mut(4) {
            px[0] = 0; // B
            px[1] = 0; // G
            px[2] = 255; // R
            px[3] = 255; // A
        }
        let red_601 = bgra_to_nv12(&red_bgra, w, h, w * 4, ColorMatrix::Bt601).unwrap();
        let red_709 = bgra_to_nv12(&red_bgra, w, h, w * 4, ColorMatrix::Bt709).unwrap();
        assert!(red_601.y_plane[0] > red_709.y_plane[0]);
        assert!(red_709.uv_plane[1] > 200); // V channel high for red

        // Odd dimensions & short buffer rejected
        assert!(bgra_to_nv12(&red_bgra, 7, 6, 28, ColorMatrix::Bt709).is_err());
        assert!(bgra_to_nv12(&red_bgra[..16], w, h, w * 4, ColorMatrix::Bt709).is_err());
    }
}
