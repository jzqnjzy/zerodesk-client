// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic Linux VA-API hardware video codec state machine, open-source
//! driver allowlist classifier (Intel `iHD` / `i965` & AMD Mesa `radeonsi` ONLY),
//! strict first-IDR readiness gate, 30-frame reinit stability window, `VAStatus`
//! classifier, H.264/HEVC profile & entrypoint selector, and Phase 9A `EncoderTarget`
//! parameter validator.
//!
//! Hardware encoding policy (identical to Phase 8B Windows MF redlines):
//! - Targets Intel/AMD open-source VA-API drivers ONLY; ZERO proprietary SDKs
//!   (no Intel MediaSDK, no NVENC) and ZERO software rasterizer fallback
//!   (`llvmpipe` / `swrast` explicitly rejected).
//! - Enumeration / `vaInitialize` NEVER marks the encoder `HardwareReady`;
//!   readiness occurs ONLY after the first IDR keyframe encodes cleanly with
//!   non-zero bytes (with bounded frame & wall-clock timeout while `WaitingFirstIdr`).
//! - Mid-stream errors perform bounded reinit retries; `reinit_attempts` resets
//!   ONLY after `STABLE_FRAMES_TO_RESET_REINIT` (30) consecutive good frames in
//!   `HardwareReady` to prevent infinite flapping. Exhaustion transitions to
//!   terminal idempotent `FailedNeedsRenegotiation` emitting
//!   `"hardware_encoder_failed_renegotiate_vp9"` — NEVER silently switching to SW!

use super::traits::{
    HardwareCodecEvent, HardwareCodecKind, HardwareCodecState, HW_ENCODER_FAILED_RENEGOTIATE_EVENT,
};
use crate::{
    qoe::{EncoderTarget, CC_MIN_BITRATE_KBPS, CC_MIN_FPS_CAP},
    session::video::{VideoCodec, VideoError},
};
use serde::{Deserialize, Serialize};

pub const DEFAULT_VAAPI_MAX_REINIT_RETRIES: u8 = 2;
pub const DEFAULT_VAAPI_MAX_FRAMES_BEFORE_FIRST_IDR: u32 = 15;
pub const DEFAULT_VAAPI_FIRST_IDR_TIMEOUT_MS: u64 = 2_000;
pub const STABLE_FRAMES_TO_RESET_REINIT: u32 = 30;

pub const VAAPI_MIN_BITRATE_BPS: u32 = CC_MIN_BITRATE_KBPS * 1_000;
pub const VAAPI_MAX_BITRATE_BPS: u32 = 100_000_000;
pub const VAAPI_MAX_FPS: u32 = 120;
pub const VAAPI_MIN_DIM: u32 = 64;
pub const VAAPI_MAX_DIM: u32 = 7_680;

// Clean-room VA-API numeric ABI status codes (matching libva 1.x/2.x stable C ABI).
pub const VA_STATUS_SUCCESS: i32 = 0x0000_0000;
pub const VA_STATUS_ERROR_OPERATION_FAILED: i32 = 0x0000_0001;
pub const VA_STATUS_ERROR_ALLOCATION_FAILED: i32 = 0x0000_0002;
pub const VA_STATUS_ERROR_INVALID_DISPLAY: i32 = 0x0000_0003;
pub const VA_STATUS_ERROR_INVALID_CONFIG: i32 = 0x0000_0004;
pub const VA_STATUS_ERROR_INVALID_CONTEXT: i32 = 0x0000_0005;
pub const VA_STATUS_ERROR_INVALID_SURFACE: i32 = 0x0000_0006;
pub const VA_STATUS_ERROR_INVALID_BUFFER: i32 = 0x0000_0007;
pub const VA_STATUS_ERROR_UNSUPPORTED_PROFILE: i32 = 0x0000_000C;
pub const VA_STATUS_ERROR_UNSUPPORTED_ENTRYPOINT: i32 = 0x0000_000D;
pub const VA_STATUS_ERROR_SURFACE_BUSY: i32 = 0x0000_0016;
pub const VA_STATUS_ERROR_INVALID_PARAMETER: i32 = 0x0000_0012;
pub const VA_STATUS_ERROR_TIMEDOUT: i32 = 0x0000_0025;
pub const VA_STATUS_ERROR_HW_BUSY: i32 = 0x0000_0022;

// Clean-room VA-API stable profile & entrypoint numeric IDs.
pub const VA_PROFILE_H264_MAIN: i32 = 6;
pub const VA_PROFILE_H264_HIGH: i32 = 7;
pub const VA_PROFILE_H264_CONSTRAINED_BASELINE: i32 = 13;
pub const VA_PROFILE_HEVC_MAIN: i32 = 17;
pub const VA_PROFILE_HEVC_MAIN10: i32 = 18;

pub const VA_ENTRYPOINT_VLD: i32 = 1;
pub const VA_ENTRYPOINT_ENC_SLICE: i32 = 6;
pub const VA_ENTRYPOINT_ENC_SLICE_LP: i32 = 8;

/// Classification of VA-API driver vendor strings returned by `vaQueryVendorString`.
///
/// Only open-source Intel (`iHD` / `i965`) and AMD Mesa (`radeonsi`) hardware
/// stacks are allowed. Software rasterizers (`llvmpipe`, `swrast`, `softpipe`)
/// and proprietary/unknown stacks are explicitly rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaapiDriverClass {
    IntelIhd,
    IntelI965,
    AmdRadeonsiMesa,
    RejectedSoftwareRasterizer,
    RejectedProprietaryOrUnknown,
}

impl VaapiDriverClass {
    pub const fn is_allowed_open_source_hw(self) -> bool {
        matches!(self, Self::IntelIhd | Self::IntelI965 | Self::AmdRadeonsiMesa)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IntelIhd => "intel_ihd",
            Self::IntelI965 => "intel_i965",
            Self::AmdRadeonsiMesa => "amd_radeonsi_mesa",
            Self::RejectedSoftwareRasterizer => "rejected_software_rasterizer",
            Self::RejectedProprietaryOrUnknown => "rejected_proprietary_or_unknown",
        }
    }
}

/// Classifies a VA-API vendor string (`vaQueryVendorString`) against the
/// ZeroDesk open-source hardware driver allowlist.
pub fn classify_vaapi_vendor_string(vendor: &str) -> VaapiDriverClass {
    let trimmed = vendor.trim();
    if trimmed.is_empty() {
        return VaapiDriverClass::RejectedProprietaryOrUnknown;
    }
    let lower = trimmed.to_ascii_lowercase();

    // Reject software rasterizers FIRST even if "mesa" appears in the vendor string.
    if lower.contains("llvmpipe")
        || lower.contains("swrast")
        || lower.contains("softpipe")
        || lower.contains("lavapipe")
        || lower.contains("virgl")
    {
        return VaapiDriverClass::RejectedSoftwareRasterizer;
    }

    // Reject proprietary / closed-source bridges explicitly.
    if lower.contains("nvidia")
        || lower.contains("nvenc")
        || lower.contains("vdpau")
        || lower.contains("mediasdk")
        || lower.contains("mfx")
    {
        return VaapiDriverClass::RejectedProprietaryOrUnknown;
    }

    // Allow open-source Intel VA-API drivers (`intel-media-driver` iHD & legacy `intel-vaapi-driver` i965).
    if lower.contains("intel ihd") || lower.contains("ihd driver") || lower.contains("intel-media")
    {
        return VaapiDriverClass::IntelIhd;
    }
    if lower.contains("intel i965") || lower.contains("i965 driver") {
        return VaapiDriverClass::IntelI965;
    }

    // Allow open-source AMD Mesa Gallium VA-API (`radeonsi` / `amdgpu`).
    if (lower.contains("mesa") || lower.contains("gallium"))
        && (lower.contains("radeon") || lower.contains("amd") || lower.contains("radeonsi"))
    {
        return VaapiDriverClass::AmdRadeonsiMesa;
    }
    if lower.contains("radeonsi") {
        return VaapiDriverClass::AmdRadeonsiMesa;
    }

    VaapiDriverClass::RejectedProprietaryOrUnknown
}

/// Classification of VA-API `VAStatus` return values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaStatusClass {
    Success,
    Transient,
    NeedsReinit,
    Fatal,
}

pub const fn classify_va_status(status: i32) -> VaStatusClass {
    match status {
        VA_STATUS_SUCCESS => VaStatusClass::Success,
        VA_STATUS_ERROR_SURFACE_BUSY | VA_STATUS_ERROR_HW_BUSY | VA_STATUS_ERROR_TIMEDOUT => {
            VaStatusClass::Transient
        }
        VA_STATUS_ERROR_OPERATION_FAILED
        | VA_STATUS_ERROR_ALLOCATION_FAILED
        | VA_STATUS_ERROR_INVALID_CONTEXT
        | VA_STATUS_ERROR_INVALID_SURFACE
        | VA_STATUS_ERROR_INVALID_BUFFER => VaStatusClass::NeedsReinit,
        VA_STATUS_ERROR_INVALID_DISPLAY
        | VA_STATUS_ERROR_INVALID_CONFIG
        | VA_STATUS_ERROR_UNSUPPORTED_PROFILE
        | VA_STATUS_ERROR_UNSUPPORTED_ENTRYPOINT
        | VA_STATUS_ERROR_INVALID_PARAMETER => VaStatusClass::Fatal,
        _ => VaStatusClass::Fatal,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VaapiCodec {
    H264,
    Hevc,
}

impl VaapiCodec {
    pub const fn to_hardware_codec_kind(self) -> HardwareCodecKind {
        match self {
            Self::H264 => HardwareCodecKind::H264,
            Self::Hevc => HardwareCodecKind::Hevc,
        }
    }

    pub const fn to_video_codec(self) -> VideoCodec {
        match self {
            Self::H264 => VideoCodec::H264,
            Self::Hevc => VideoCodec::Hevc,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VaapiProfileEntrypoint {
    pub profile_id: i32,
    pub entrypoint_id: i32,
    pub low_power: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct VaapiCodecCapabilities {
    pub supported_profiles: Vec<VaapiProfileEntrypoint>,
}

/// Selects the preferred VA-API encode `(profile_id, entrypoint_id)` for `codec`
/// from queried driver capabilities. Prefers low-power `VAEntrypointEncSliceLP`
/// when supported, falling back to standard `VAEntrypointEncSlice`.
pub fn select_vaapi_encode_profile(
    codec: VaapiCodec,
    caps: &VaapiCodecCapabilities,
) -> Result<VaapiProfileEntrypoint, VideoError> {
    let preferred_profiles: &[i32] = match codec {
        VaapiCodec::H264 => &[
            VA_PROFILE_H264_CONSTRAINED_BASELINE,
            VA_PROFILE_H264_MAIN,
            VA_PROFILE_H264_HIGH,
        ],
        VaapiCodec::Hevc => &[VA_PROFILE_HEVC_MAIN, VA_PROFILE_HEVC_MAIN10],
    };

    for &ep in &[VA_ENTRYPOINT_ENC_SLICE_LP, VA_ENTRYPOINT_ENC_SLICE] {
        for &prof in preferred_profiles {
            if let Some(&found) = caps
                .supported_profiles
                .iter()
                .find(|p| p.profile_id == prof && p.entrypoint_id == ep)
            {
                return Ok(found);
            }
        }
    }

    Err(VideoError::HardwareUnavailable(format!(
        "VA-API driver exposes no supported hardware encode profile/entrypoint for {codec:?}"
    )))
}

/// Validated & safely clamped dynamic encoder parameters derived from Phase 9A
/// `qoe::EncoderTarget` (or direct bitrate/fps control).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaapiRateControlParams {
    pub bitrate_bps: u32,
    pub fps_cap: u32,
    pub width: u32,
    pub height: u32,
    pub force_idr: bool,
}

/// Validates and clamps a Phase 9A `EncoderTarget` onto safe VA-API hardware limits.
/// Ensures even dimensions (required by NV12/VA-API) and rejects degenerate geometry.
pub fn validate_and_clamp_rate_control(
    target: &EncoderTarget,
    max_width: u32,
    max_height: u32,
) -> Result<VaapiRateControlParams, VideoError> {
    if max_width < VAAPI_MIN_DIM || max_height < VAAPI_MIN_DIM {
        return Err(VideoError::InvalidInput(format!(
            "VA-API max dimensions {max_width}x{max_height} below minimum {VAAPI_MIN_DIM}"
        )));
    }
    let clamped_w = target
        .width
        .clamp(VAAPI_MIN_DIM, max_width.min(VAAPI_MAX_DIM))
        & !1;
    let clamped_h = target
        .height
        .clamp(VAAPI_MIN_DIM, max_height.min(VAAPI_MAX_DIM))
        & !1;
    if clamped_w < VAAPI_MIN_DIM || clamped_h < VAAPI_MIN_DIM {
        return Err(VideoError::InvalidInput(format!(
            "VA-API even-aligned dimensions {clamped_w}x{clamped_h} below minimum {VAAPI_MIN_DIM}"
        )));
    }
    let bitrate_bps = target
        .media_bitrate_kbps
        .saturating_mul(1_000)
        .clamp(VAAPI_MIN_BITRATE_BPS, VAAPI_MAX_BITRATE_BPS);
    let fps_cap = target.fps_cap.clamp(CC_MIN_FPS_CAP, VAAPI_MAX_FPS);
    Ok(VaapiRateControlParams {
        bitrate_bps,
        fps_cap,
        width: clamped_w,
        height: clamped_h,
        force_idr: target.force_idr,
    })
}

/// Clamps a direct `set_bitrate` call onto safe VA-API bounds.
pub fn clamp_vaapi_bitrate_bps(bitrate_bps: u32) -> Result<u32, VideoError> {
    if bitrate_bps == 0 {
        return Err(VideoError::InvalidInput(
            "VA-API target bitrate must be non-zero".into(),
        ));
    }
    Ok(bitrate_bps.clamp(VAAPI_MIN_BITRATE_BPS, VAAPI_MAX_BITRATE_BPS))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VaapiErrorDecision {
    RetryFrameTransient,
    TriggerReinit { attempt: u8, max_attempts: u8 },
    FailedNeedsRenegotiation { event_code: String, reason: String },
}

/// Platform-agnostic VA-API hardware encoder lifecycle state machine.
///
/// Guarantees:
/// - `HardwareReady` entered ONLY on first valid IDR (`is_idr && byte_len > 0`);
/// - Explicit first-IDR timeout (both frame-count & elapsed-ms ceilings) while
///   `WaitingFirstIdr` — NEVER silently falls back to software encoding;
/// - 30-frame stability window (`STABLE_FRAMES_TO_RESET_REINIT`) before resetting
///   `reinit_attempts = 0` to defeat rapid failure flapping;
/// - Terminal `FailedNeedsRenegotiation` is strictly idempotent.
#[derive(Debug, Clone)]
pub struct VaapiHwEncoderStateMachine {
    codec: VaapiCodec,
    driver_class: VaapiDriverClass,
    state: HardwareCodecState,
    reinit_attempts: u8,
    max_reinit_retries: u8,
    frames_since_first_idr_wait: u32,
    max_frames_before_first_idr: u32,
    first_idr_wait_start_ms: Option<u64>,
    first_idr_timeout_ms: u64,
    stable_frames_in_ready: u32,
    events: Vec<HardwareCodecEvent>,
}

impl VaapiHwEncoderStateMachine {
    pub fn new(codec: VaapiCodec, driver_class: VaapiDriverClass) -> Result<Self, VideoError> {
        if !driver_class.is_allowed_open_source_hw() {
            return Err(VideoError::HardwareUnavailable(format!(
                "VA-API driver rejected by open-source hardware allowlist: {}",
                driver_class.as_str()
            )));
        }
        Ok(Self {
            codec,
            driver_class,
            state: HardwareCodecState::Enumerated,
            reinit_attempts: 0,
            max_reinit_retries: DEFAULT_VAAPI_MAX_REINIT_RETRIES,
            frames_since_first_idr_wait: 0,
            max_frames_before_first_idr: DEFAULT_VAAPI_MAX_FRAMES_BEFORE_FIRST_IDR,
            first_idr_wait_start_ms: None,
            first_idr_timeout_ms: DEFAULT_VAAPI_FIRST_IDR_TIMEOUT_MS,
            stable_frames_in_ready: 0,
            events: Vec::new(),
        })
    }

    pub fn with_limits(
        mut self,
        max_reinit_retries: u8,
        max_frames_before_first_idr: u32,
        first_idr_timeout_ms: u64,
    ) -> Self {
        self.max_reinit_retries = max_reinit_retries;
        self.max_frames_before_first_idr = max_frames_before_first_idr.max(1);
        self.first_idr_timeout_ms = first_idr_timeout_ms.max(1);
        self
    }

    pub fn codec(&self) -> VaapiCodec {
        self.codec
    }

    pub fn driver_class(&self) -> VaapiDriverClass {
        self.driver_class
    }

    pub fn state(&self) -> HardwareCodecState {
        self.state.clone()
    }

    pub fn is_hardware_ready(&self) -> bool {
        matches!(self.state, HardwareCodecState::HardwareReady)
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            HardwareCodecState::FailedNeedsRenegotiation { .. }
        )
    }

    pub fn reinit_attempts(&self) -> u8 {
        self.reinit_attempts
    }

    pub fn stable_frames_in_ready(&self) -> u32 {
        self.stable_frames_in_ready
    }

    pub fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn ensure_not_terminal(&self) -> Result<(), VideoError> {
        if let HardwareCodecState::FailedNeedsRenegotiation { reason } = &self.state {
            return Err(VideoError::CodecFailed {
                codec: self.codec.to_video_codec(),
                reason: reason.clone(),
            });
        }
        Ok(())
    }

    pub fn mark_initialized(&mut self) -> Result<(), VideoError> {
        self.ensure_not_terminal()?;
        self.state = HardwareCodecState::Initialized;
        Ok(())
    }

    pub fn begin_waiting_first_idr(&mut self, now_ms: u64) -> Result<(), VideoError> {
        self.ensure_not_terminal()?;
        self.state = HardwareCodecState::WaitingFirstIdr;
        self.frames_since_first_idr_wait = 0;
        self.first_idr_wait_start_ms = Some(now_ms);
        self.stable_frames_in_ready = 0;
        Ok(())
    }

    /// Called before each input frame is submitted while waiting for the first IDR.
    /// Enforces BOTH frame-count and wall-clock timeout ceilings.
    pub fn on_input_submitted(&mut self, now_ms: u64) -> Result<(), VaapiErrorDecision> {
        if let HardwareCodecState::FailedNeedsRenegotiation { reason } = &self.state {
            return Err(VaapiErrorDecision::FailedNeedsRenegotiation {
                event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT.to_string(),
                reason: reason.clone(),
            });
        }
        if matches!(self.state, HardwareCodecState::WaitingFirstIdr) {
            self.frames_since_first_idr_wait = self.frames_since_first_idr_wait.saturating_add(1);
            let start = *self.first_idr_wait_start_ms.get_or_insert(now_ms);
            let elapsed = now_ms.saturating_sub(start);
            if elapsed >= self.first_idr_timeout_ms {
                let decision = self.fail_or_reinit(&format!(
                    "VA-API first-IDR wall-clock timeout ({elapsed}ms >= {}ms)",
                    self.first_idr_timeout_ms
                ));
                return Err(decision);
            }
            if self.frames_since_first_idr_wait > self.max_frames_before_first_idr {
                let decision = self.fail_or_reinit(&format!(
                    "VA-API first-IDR frame budget exceeded ({} > {})",
                    self.frames_since_first_idr_wait, self.max_frames_before_first_idr
                ));
                return Err(decision);
            }
        }
        Ok(())
    }

    /// Processes an encoded packet emitted by VA-API.
    /// Enters `HardwareReady` ONLY when `is_idr && byte_len > 0`.
    /// Resets `reinit_attempts = 0` ONLY after `STABLE_FRAMES_TO_RESET_REINIT` (30)
    /// consecutive non-empty frames in `HardwareReady`.
    pub fn on_encoded_packet(&mut self, is_idr: bool, byte_len: usize) {
        if self.is_terminal() || byte_len == 0 {
            return;
        }
        match self.state {
            HardwareCodecState::WaitingFirstIdr
            | HardwareCodecState::Initialized
            | HardwareCodecState::Enumerated
            | HardwareCodecState::ReinitRetry { .. } => {
                if is_idr {
                    self.state = HardwareCodecState::HardwareReady;
                    self.frames_since_first_idr_wait = 0;
                    self.first_idr_wait_start_ms = None;
                    self.stable_frames_in_ready = 1;
                    self.events.push(HardwareCodecEvent::HardwareReady {
                        codec: self.codec.to_hardware_codec_kind(),
                        backend: format!("linux_vaapi_{}", self.driver_class.as_str()),
                    });
                }
            }
            HardwareCodecState::HardwareReady => {
                self.stable_frames_in_ready = self.stable_frames_in_ready.saturating_add(1);
                if self.stable_frames_in_ready >= STABLE_FRAMES_TO_RESET_REINIT
                    && self.reinit_attempts > 0
                {
                    self.reinit_attempts = 0;
                }
            }
            HardwareCodecState::FailedNeedsRenegotiation { .. } => {}
        }
    }

    /// Processes a non-success `VAStatus` from VA-API encoding.
    pub fn on_va_status_error(&mut self, status: i32, detail: &str) -> VaapiErrorDecision {
        if let HardwareCodecState::FailedNeedsRenegotiation { reason } = &self.state {
            return VaapiErrorDecision::FailedNeedsRenegotiation {
                event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT.to_string(),
                reason: reason.clone(),
            };
        }
        match classify_va_status(status) {
            VaStatusClass::Success | VaStatusClass::Transient => {
                VaapiErrorDecision::RetryFrameTransient
            }
            VaStatusClass::NeedsReinit => {
                self.fail_or_reinit(&format!("VAStatus {status:#x}: {detail}"))
            }
            VaStatusClass::Fatal => self.enter_terminal(&format!(
                "fatal VAStatus {status:#x} ({}): {detail}",
                self.driver_class.as_str()
            )),
        }
    }

    fn fail_or_reinit(&mut self, reason: &str) -> VaapiErrorDecision {
        self.stable_frames_in_ready = 0;
        let next = self.reinit_attempts.saturating_add(1);
        if next > self.max_reinit_retries {
            return self.enter_terminal(&format!(
                "VA-API reinit budget exhausted ({}/{}): {reason}",
                self.reinit_attempts, self.max_reinit_retries
            ));
        }
        self.reinit_attempts = next;
        self.frames_since_first_idr_wait = 0;
        self.first_idr_wait_start_ms = None;
        self.state = HardwareCodecState::ReinitRetry {
            attempt: next,
            max_attempts: self.max_reinit_retries,
        };
        self.events.push(HardwareCodecEvent::ReinitScheduled {
            codec: self.codec.to_hardware_codec_kind(),
            attempt: next,
            reason: reason.to_string(),
        });
        VaapiErrorDecision::TriggerReinit {
            attempt: next,
            max_attempts: self.max_reinit_retries,
        }
    }

    fn enter_terminal(&mut self, reason: &str) -> VaapiErrorDecision {
        if let HardwareCodecState::FailedNeedsRenegotiation { reason: existing } = &self.state {
            return VaapiErrorDecision::FailedNeedsRenegotiation {
                event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT.to_string(),
                reason: existing.clone(),
            };
        }
        self.state = HardwareCodecState::FailedNeedsRenegotiation {
            reason: reason.to_string(),
        };
        self.events
            .push(HardwareCodecEvent::HardwareFailedRenegotiate {
                codec: self.codec.to_hardware_codec_kind(),
                event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT.to_string(),
                reason: reason.to_string(),
            });
        VaapiErrorDecision::FailedNeedsRenegotiation {
            event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT.to_string(),
            reason: reason.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn driver_allowlist_accepts_intel_and_amd_open_source_and_rejects_sw_and_proprietary() {
        assert_eq!(
            classify_vaapi_vendor_string("Intel iHD driver for Intel(R) Gen Graphics - 24.1.0"),
            VaapiDriverClass::IntelIhd
        );
        assert!(VaapiDriverClass::IntelIhd.is_allowed_open_source_hw());

        assert_eq!(
            classify_vaapi_vendor_string("Intel i965 driver for Intel(R) Haswell Desktop - 2.4.1"),
            VaapiDriverClass::IntelI965
        );
        assert!(VaapiDriverClass::IntelI965.is_allowed_open_source_hw());

        assert_eq!(
            classify_vaapi_vendor_string("Mesa Gallium driver 24.0.9 for AMD Radeon RX 7800 XT (radeonsi)"),
            VaapiDriverClass::AmdRadeonsiMesa
        );
        assert!(VaapiDriverClass::AmdRadeonsiMesa.is_allowed_open_source_hw());

        // Software rasterizers MUST be rejected even when "Mesa" is present.
        assert_eq!(
            classify_vaapi_vendor_string("Mesa Gallium driver 24.0.9 for llvmpipe (LLVM 17.0.6)"),
            VaapiDriverClass::RejectedSoftwareRasterizer
        );
        assert!(!VaapiDriverClass::RejectedSoftwareRasterizer.is_allowed_open_source_hw());

        assert_eq!(
            classify_vaapi_vendor_string("Mesa swrast software rasterizer"),
            VaapiDriverClass::RejectedSoftwareRasterizer
        );

        // Proprietary / closed bridges MUST be rejected.
        assert_eq!(
            classify_vaapi_vendor_string("NVIDIA VDPAU/NVENC VA-API bridge"),
            VaapiDriverClass::RejectedProprietaryOrUnknown
        );
        assert_eq!(
            classify_vaapi_vendor_string("Intel MediaSDK proprietary wrapper"),
            VaapiDriverClass::RejectedProprietaryOrUnknown
        );
        assert_eq!(
            classify_vaapi_vendor_string(""),
            VaapiDriverClass::RejectedProprietaryOrUnknown
        );

        // State machine refuses disallowed driver at construction time.
        assert!(VaapiHwEncoderStateMachine::new(
            VaapiCodec::H264,
            VaapiDriverClass::RejectedSoftwareRasterizer
        )
        .is_err());
    }

    #[test]
    fn first_idr_gate_and_timeout_prevent_premature_ready_and_silent_sw_fallback() {
        let mut sm = VaapiHwEncoderStateMachine::new(VaapiCodec::H264, VaapiDriverClass::IntelIhd)
            .unwrap()
            .with_limits(1, 3, 500);
        assert!(!sm.is_hardware_ready());
        sm.mark_initialized().unwrap();
        sm.begin_waiting_first_idr(1_000).unwrap();

        // P-frame or zero-byte IDR must NOT enter HardwareReady.
        sm.on_encoded_packet(false, 4096);
        assert!(!sm.is_hardware_ready());
        sm.on_encoded_packet(true, 0);
        assert!(!sm.is_hardware_ready());

        // Wall-clock timeout triggers reinit attempt 1.
        let err1 = sm.on_input_submitted(1_500).unwrap_err();
        assert_eq!(
            err1,
            VaapiErrorDecision::TriggerReinit {
                attempt: 1,
                max_attempts: 1,
            }
        );

        // Re-wait and exhaust frame budget -> terminal FailedNeedsRenegotiation.
        sm.begin_waiting_first_idr(2_000).unwrap();
        assert!(sm.on_input_submitted(2_010).is_ok());
        assert!(sm.on_input_submitted(2_020).is_ok());
        assert!(sm.on_input_submitted(2_030).is_ok());
        let err2 = sm.on_input_submitted(2_040).unwrap_err();
        assert!(matches!(
            err2,
            VaapiErrorDecision::FailedNeedsRenegotiation { ref event_code, .. }
                if event_code == HW_ENCODER_FAILED_RENEGOTIATE_EVENT
        ));
        assert!(sm.is_terminal());

        // Idempotent terminal: repeated errors do NOT emit duplicate events.
        let _ = sm.drain_events();
        let _ = sm.on_va_status_error(VA_STATUS_ERROR_OPERATION_FAILED, "after terminal");
        assert!(sm.drain_events().is_empty());
    }

    #[test]
    fn thirty_frame_stability_window_defeats_flapping_and_resets_after_30_good_frames() {
        let mut sm =
            VaapiHwEncoderStateMachine::new(VaapiCodec::Hevc, VaapiDriverClass::AmdRadeonsiMesa)
                .unwrap()
                .with_limits(2, 15, 2_000);
        sm.mark_initialized().unwrap();
        sm.begin_waiting_first_idr(0).unwrap();
        sm.on_encoded_packet(true, 2048);
        assert!(sm.is_hardware_ready());
        assert_eq!(sm.drain_events().len(), 1);

        // Failure #1 -> Reinit attempt 1.
        assert_eq!(
            sm.on_va_status_error(VA_STATUS_ERROR_INVALID_CONTEXT, "gpu reset 1"),
            VaapiErrorDecision::TriggerReinit {
                attempt: 1,
                max_attempts: 2,
            }
        );
        sm.begin_waiting_first_idr(100).unwrap();
        sm.on_encoded_packet(true, 1024); // frame 1 of 30
        for _ in 0..10 {
            sm.on_encoded_packet(false, 512);
        }
        // Only 11 good frames (< 30): reinit_attempts MUST still be 1 (flapping protection!).
        assert_eq!(sm.reinit_attempts(), 1);

        // Failure #2 while flapping -> Reinit attempt 2.
        assert_eq!(
            sm.on_va_status_error(VA_STATUS_ERROR_OPERATION_FAILED, "gpu reset 2"),
            VaapiErrorDecision::TriggerReinit {
                attempt: 2,
                max_attempts: 2,
            }
        );

        // Now sustain 30 consecutive good frames (1 IDR + 29 P-frames) -> resets counter to 0!
        sm.begin_waiting_first_idr(200).unwrap();
        sm.on_encoded_packet(true, 1024);
        for _ in 0..28 {
            sm.on_encoded_packet(false, 512);
        }
        assert_eq!(sm.reinit_attempts(), 2);
        sm.on_encoded_packet(false, 512); // 30th frame!
        assert_eq!(sm.reinit_attempts(), 0);

        // Transient error does NOT consume reinit budget.
        assert_eq!(
            sm.on_va_status_error(VA_STATUS_ERROR_HW_BUSY, "busy"),
            VaapiErrorDecision::RetryFrameTransient
        );
        assert_eq!(sm.reinit_attempts(), 0);
    }

    #[test]
    fn profile_selection_prefers_low_power_and_qoe_rate_control_clamps_safely() {
        let caps = VaapiCodecCapabilities {
            supported_profiles: vec![
                VaapiProfileEntrypoint {
                    profile_id: VA_PROFILE_H264_HIGH,
                    entrypoint_id: VA_ENTRYPOINT_ENC_SLICE,
                    low_power: false,
                },
                VaapiProfileEntrypoint {
                    profile_id: VA_PROFILE_H264_MAIN,
                    entrypoint_id: VA_ENTRYPOINT_ENC_SLICE_LP,
                    low_power: true,
                },
            ],
        };
        let selected = select_vaapi_encode_profile(VaapiCodec::H264, &caps).unwrap();
        assert_eq!(selected.profile_id, VA_PROFILE_H264_MAIN);
        assert!(selected.low_power);
        assert!(select_vaapi_encode_profile(VaapiCodec::Hevc, &caps).is_err());

        let target = EncoderTarget {
            media_bitrate_kbps: 100, // below 300 kbps floor -> clamped up
            fec_budget_kbps: 50,
            total_bitrate_kbps: 150,
            width: 1921, // odd -> even-aligned
            height: 1081,
            fps_cap: 240, // above 120 -> clamped
            force_idr: true,
            bitrate_changed: true,
        };
        let rc = validate_and_clamp_rate_control(&target, 3840, 2160).unwrap();
        assert_eq!(rc.bitrate_bps, VAAPI_MIN_BITRATE_BPS);
        assert_eq!(rc.fps_cap, VAAPI_MAX_FPS);
        assert_eq!(rc.width, 1920);
        assert_eq!(rc.height, 1080);
        assert!(rc.force_idr);
        assert!(clamp_vaapi_bitrate_bps(0).is_err());
    }
}
