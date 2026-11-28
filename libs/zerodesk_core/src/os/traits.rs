// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Cross-platform OS adapter traits for screen capture, hardware video codecs,
//! OS input injection, and independent HID watchdog supervision.
//!
//! Existing macOS implementations (`ScreenCaptureKit`, `MacOsScreenCapture`,
//! `VideoToolbox`, `MacOsHidSink`, `HidWatchdogSupervisor`) adapt cleanly onto
//! these traits with zero behavioral changes.

use super::{
    input::is_accessibility_trusted,
    watchdog_supervisor::{HidWatchdogConfig, HidWatchdogSupervisor},
    EmergencyKeyReleaser, OsError, OsHidSink, OsPermission, OsScreenCapture, RawCapturedFrame,
    ReleaseReport,
};
use crate::{
    frame::PixelFormat,
    session::{
        hid::{KeyEvent, MouseEvent},
        video::{DecodedVideoFrame, I420Frame, VideoCodec, VideoError},
        vt_codec::{VtDecoder, VtEncoder},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

/// Event code emitted when a hardware video encoder exhausts its bounded reinit
/// budget and requires explicit session-level renegotiation (NEVER silent SW fallback).
pub const HW_ENCODER_FAILED_RENEGOTIATE_EVENT: &str = "hardware_encoder_failed_renegotiate_vp9";
pub const HW_DECODER_FAILED_RENEGOTIATE_EVENT: &str = "hardware_decoder_failed_renegotiate_vp9";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CursorShapeKind {
    Monochrome,
    Color,
    MaskedColor,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CursorMetadata {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub hotspot_x: u32,
    pub hotspot_y: u32,
    pub shape_kind: Option<CursorShapeKind>,
    pub shape_width: u32,
    pub shape_height: u32,
    pub shape_pitch: u32,
    #[serde(skip)]
    pub shape_bytes: Option<Vec<u8>>,
}

impl fmt::Debug for CursorMetadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CursorMetadata")
            .field("visible", &self.visible)
            .field("x", &self.x)
            .field("y", &self.y)
            .field("hotspot_x", &self.hotspot_x)
            .field("hotspot_y", &self.hotspot_y)
            .field("shape_kind", &self.shape_kind)
            .field("shape_width", &self.shape_width)
            .field("shape_height", &self.shape_height)
            .field("shape_pitch", &self.shape_pitch)
            .field("shape_bytes_len", &self.shape_bytes.as_ref().map(Vec::len))
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum D3d11SurfaceFormat {
    Bgra8Unorm,
    Nv12,
}

/// Platform-agnostic captured frame backing surface.
#[derive(Clone)]
pub enum CapturedSurface {
    Bgra8 {
        data: Vec<u8>,
    },
    Rgba8 {
        data: Vec<u8>,
    },
    Nv12 {
        y_stride: u32,
        uv_stride: u32,
        y_plane: Vec<u8>,
        uv_plane: Vec<u8>,
    },
    /// Opaque Windows D3D11 shared texture handle plus owning DXGI adapter LUID
    /// for zero-copy Media Foundation hardware encoding.
    D3d11TextureHandle {
        shared_handle: u64,
        adapter_luid: (u32, i32),
        format: D3d11SurfaceFormat,
    },
}

impl fmt::Debug for CapturedSurface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bgra8 { data } => f
                .debug_struct("Bgra8")
                .field("data_len", &data.len())
                .finish(),
            Self::Rgba8 { data } => f
                .debug_struct("Rgba8")
                .field("data_len", &data.len())
                .finish(),
            Self::Nv12 {
                y_stride,
                uv_stride,
                y_plane,
                uv_plane,
            } => f
                .debug_struct("Nv12")
                .field("y_stride", y_stride)
                .field("uv_stride", uv_stride)
                .field("y_len", &y_plane.len())
                .field("uv_len", &uv_plane.len())
                .finish(),
            Self::D3d11TextureHandle {
                shared_handle,
                adapter_luid,
                format,
            } => f
                .debug_struct("D3d11TextureHandle")
                .field("shared_handle", shared_handle)
                .field("adapter_luid", adapter_luid)
                .field("format", format)
                .finish(),
        }
    }
}

/// Platform-agnostic captured frame descriptor emitted by `ScreenCapturer`.
#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub surface: CapturedSurface,
    pub timestamp_us: i64,
    pub monitor_id: u32,
    pub cursor: Option<CursorMetadata>,
}

impl CapturedFrame {
    pub fn from_raw(raw: RawCapturedFrame, monitor_id: u32, timestamp_us: i64) -> Self {
        let surface = match raw.pixel_format {
            PixelFormat::Bgra8 => CapturedSurface::Bgra8 { data: raw.data },
            PixelFormat::Rgba8 => CapturedSurface::Rgba8 { data: raw.data },
        };
        Self {
            width: raw.width,
            height: raw.height,
            stride: raw.stride,
            surface,
            timestamp_us,
            monitor_id,
            cursor: None,
        }
    }

    pub fn to_raw_captured_frame(&self) -> Option<RawCapturedFrame> {
        match &self.surface {
            CapturedSurface::Bgra8 { data } => Some(RawCapturedFrame {
                width: self.width,
                height: self.height,
                stride: self.stride,
                pixel_format: PixelFormat::Bgra8,
                data: data.clone(),
            }),
            CapturedSurface::Rgba8 { data } => Some(RawCapturedFrame {
                width: self.width,
                height: self.height,
                stride: self.stride,
                pixel_format: PixelFormat::Rgba8,
                data: data.clone(),
            }),
            CapturedSurface::Nv12 { .. } | CapturedSurface::D3d11TextureHandle { .. } => None,
        }
    }
}

/// Cross-platform capture error taxonomy distinguishing normal frame timeouts,
/// recoverable duplication/stream reinitialization, temporary desktop pauses
/// (UAC/lock-screen/RDP), OS permission denial, and fatal errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    Timeout,
    ReinitRequired(String),
    DesktopUnavailable(String),
    PermissionDenied(OsPermission),
    Fatal(String),
}

impl CaptureError {
    pub fn into_os_error(self) -> OsError {
        match self {
            Self::Timeout => OsError::Timeout,
            Self::ReinitRequired(msg) | Self::DesktopUnavailable(msg) | Self::Fatal(msg) => {
                OsError::CaptureFailed(msg)
            }
            Self::PermissionDenied(p) => OsError::PermissionDenied(p),
        }
    }
}

impl From<OsError> for CaptureError {
    fn from(err: OsError) -> Self {
        match err {
            OsError::Timeout => Self::Timeout,
            OsError::PermissionDenied(p) => Self::PermissionDenied(p),
            OsError::NotPermitted => Self::PermissionDenied(OsPermission::ScreenRecording),
            OsError::CaptureFailed(msg)
            | OsError::InvalidData(msg)
            | OsError::AudioUnavailable(msg)
            | OsError::UnsupportedAudioFormat(msg)
            | OsError::ClipboardUnavailable(msg) => Self::Fatal(msg),
            OsError::UnsupportedPlatform(msg) => Self::Fatal(msg.to_string()),
            OsError::Interlocked => Self::Fatal("capture adapter interlocked".into()),
        }
    }
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "capture frame timed out (no new desktop update)"),
            Self::ReinitRequired(msg) => write!(f, "capture reinitialization required: {msg}"),
            Self::DesktopUnavailable(msg) => {
                write!(f, "desktop temporarily unavailable (UAC/lock/session): {msg}")
            }
            Self::PermissionDenied(p) => write!(f, "capture permission denied: {p:?}"),
            Self::Fatal(msg) => write!(f, "fatal capture error: {msg}"),
        }
    }
}

impl std::error::Error for CaptureError {}

/// Platform-agnostic screen capturer trait implemented by macOS ScreenCaptureKit /
/// CoreGraphics adapters, synthetic test sources, and Windows DXGI Desktop Duplication.
pub trait ScreenCapturer: Send {
    fn dimensions(&self) -> (u32, u32);
    fn monitor_id(&self) -> u32 {
        0
    }
    fn capture_next_frame(&mut self) -> Result<CapturedFrame, CaptureError>;
}

fn now_epoch_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// Thin zero-behavior-change adapter bridging any existing `OsScreenCapture`
/// (including macOS `ScreenCaptureKit` and `MacOsScreenCapture`) onto `ScreenCapturer`.
pub struct OsScreenCaptureAdapter<T: OsScreenCapture> {
    inner: T,
    monitor_id: u32,
}

impl<T: OsScreenCapture> OsScreenCaptureAdapter<T> {
    pub fn new(inner: T, monitor_id: u32) -> Self {
        Self { inner, monitor_id }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: OsScreenCapture> ScreenCapturer for OsScreenCaptureAdapter<T> {
    fn dimensions(&self) -> (u32, u32) {
        self.inner.dimensions()
    }

    fn monitor_id(&self) -> u32 {
        self.monitor_id
    }

    fn capture_next_frame(&mut self) -> Result<CapturedFrame, CaptureError> {
        let raw = self.inner.capture_frame().map_err(CaptureError::from)?;
        Ok(CapturedFrame::from_raw(raw, self.monitor_id, now_epoch_us()))
    }
}

impl ScreenCapturer for Box<dyn OsScreenCapture> {
    fn dimensions(&self) -> (u32, u32) {
        (**self).dimensions()
    }

    fn capture_next_frame(&mut self) -> Result<CapturedFrame, CaptureError> {
        let raw = (**self).capture_frame().map_err(CaptureError::from)?;
        Ok(CapturedFrame::from_raw(raw, 0, now_epoch_us()))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareCodecKind {
    H264,
    Hevc,
    Vp9,
    Av1,
}

impl From<VideoCodec> for HardwareCodecKind {
    fn from(v: VideoCodec) -> Self {
        match v {
            VideoCodec::H264 => Self::H264,
            VideoCodec::Hevc => Self::Hevc,
            VideoCodec::Vp9 => Self::Vp9,
            VideoCodec::Av1 => Self::Av1,
        }
    }
}

impl From<HardwareCodecKind> for VideoCodec {
    fn from(k: HardwareCodecKind) -> Self {
        match k {
            HardwareCodecKind::H264 => Self::H264,
            HardwareCodecKind::Hevc => Self::Hevc,
            HardwareCodecKind::Vp9 => Self::Vp9,
            HardwareCodecKind::Av1 => Self::Av1,
        }
    }
}

/// Hardware availability lifecycle state.
///
/// Contract: enumeration does NOT prove usability. A hardware encoder MUST NOT
/// transition to `HardwareReady` until its FIRST IDR keyframe encodes cleanly
/// with non-empty output bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareCodecState {
    Enumerated,
    Initialized,
    WaitingFirstIdr,
    HardwareReady,
    ReinitRetry { attempt: u8, max_attempts: u8 },
    FailedNeedsRenegotiation { reason: String },
}

/// Explicit, non-silent lifecycle event emitted by a `HardwareCodec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HardwareCodecEvent {
    HardwareReady {
        codec: HardwareCodecKind,
        backend: String,
    },
    ReinitScheduled {
        codec: HardwareCodecKind,
        attempt: u8,
        reason: String,
    },
    HardwareFailedRenegotiate {
        codec: HardwareCodecKind,
        event_code: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardwareEncodedPacket {
    pub data: Vec<u8>,
    pub is_idr: bool,
    pub pts_us: i64,
    pub codec: HardwareCodecKind,
}

/// Common hardware codec lifecycle contract (encoder and decoder).
pub trait HardwareCodec: Send {
    fn codec(&self) -> HardwareCodecKind;
    fn backend_name(&self) -> &'static str;
    fn state(&self) -> HardwareCodecState;
    fn is_hardware_ready(&self) -> bool {
        matches!(self.state(), HardwareCodecState::HardwareReady)
    }
    fn drain_events(&mut self) -> Vec<HardwareCodecEvent>;
}

/// Cross-platform hardware video encoder trait (VideoToolbox on macOS,
/// Media Foundation Hardware MFT on Windows).
pub trait HardwareVideoEncoder: HardwareCodec {
    fn encode_frame(
        &mut self,
        frame: &CapturedFrame,
        force_idr: bool,
    ) -> Result<HardwareEncodedPacket, VideoError>;
    fn encode_i420(
        &mut self,
        frame: &I420Frame,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<HardwareEncodedPacket, VideoError>;
    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError>;
    fn force_next_idr(&mut self);
}

/// Cross-platform hardware video decoder trait.
pub trait HardwareVideoDecoder: HardwareCodec {
    fn decode_packet(&mut self, data: &[u8]) -> Result<DecodedVideoFrame, VideoError>;
}

/// Thin macOS VideoToolbox encoder adapter implementing `HardwareCodec` +
/// `HardwareVideoEncoder` without modifying any existing `VtEncoder` path.
pub struct MacVtHardwareEncoder {
    codec: HardwareCodecKind,
    inner: VtEncoder,
    state: HardwareCodecState,
    events: Vec<HardwareCodecEvent>,
}

impl MacVtHardwareEncoder {
    pub fn new(
        codec: VideoCodec,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_bps: u32,
        max_keyframe_interval: u32,
    ) -> Result<Self, VideoError> {
        let inner = VtEncoder::new(
            codec,
            width,
            height,
            fps,
            bitrate_bps,
            max_keyframe_interval,
        )?;
        Ok(Self {
            codec: HardwareCodecKind::from(codec),
            inner,
            state: HardwareCodecState::WaitingFirstIdr,
            events: Vec::new(),
        })
    }

    fn record_encode_outcome(&mut self, is_idr: bool, byte_len: usize) {
        if is_idr && byte_len > 0 && !matches!(self.state, HardwareCodecState::HardwareReady) {
            self.state = HardwareCodecState::HardwareReady;
            self.events.push(HardwareCodecEvent::HardwareReady {
                codec: self.codec,
                backend: self.backend_name().to_string(),
            });
        }
    }

    fn record_encode_error(&mut self, err: &VideoError) {
        if let VideoError::CodecFailed { reason, .. } = err {
            self.state = HardwareCodecState::FailedNeedsRenegotiation {
                reason: reason.clone(),
            };
            self.events
                .push(HardwareCodecEvent::HardwareFailedRenegotiate {
                    codec: self.codec,
                    event_code: HW_ENCODER_FAILED_RENEGOTIATE_EVENT.to_string(),
                    reason: reason.clone(),
                });
        }
    }
}

impl HardwareCodec for MacVtHardwareEncoder {
    fn codec(&self) -> HardwareCodecKind {
        self.codec
    }

    fn backend_name(&self) -> &'static str {
        "macos_videotoolbox"
    }

    fn state(&self) -> HardwareCodecState {
        self.state.clone()
    }

    fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        std::mem::take(&mut self.events)
    }
}

impl HardwareVideoEncoder for MacVtHardwareEncoder {
    fn encode_frame(
        &mut self,
        frame: &CapturedFrame,
        force_idr: bool,
    ) -> Result<HardwareEncodedPacket, VideoError> {
        let res = match &frame.surface {
            CapturedSurface::Bgra8 { data } => self.inner.encode_bgra(
                data,
                frame.width as usize,
                frame.height as usize,
                frame.stride as usize,
                frame.timestamp_us,
                force_idr,
            ),
            CapturedSurface::Rgba8 { .. }
            | CapturedSurface::Nv12 { .. }
            | CapturedSurface::D3d11TextureHandle { .. } => Err(VideoError::InvalidInput(
                "MacVtHardwareEncoder expects BGRA8 CapturedFrame or encode_i420".into(),
            )),
        };
        match res {
            Ok((data, is_idr)) => {
                self.record_encode_outcome(is_idr, data.len());
                Ok(HardwareEncodedPacket {
                    data,
                    is_idr,
                    pts_us: frame.timestamp_us,
                    codec: self.codec,
                })
            }
            Err(err) => {
                self.record_encode_error(&err);
                Err(err)
            }
        }
    }

    fn encode_i420(
        &mut self,
        frame: &I420Frame,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<HardwareEncodedPacket, VideoError> {
        match self.inner.encode_i420(frame, pts_us, force_idr) {
            Ok((data, is_idr)) => {
                self.record_encode_outcome(is_idr, data.len());
                Ok(HardwareEncodedPacket {
                    data,
                    is_idr,
                    pts_us,
                    codec: self.codec,
                })
            }
            Err(err) => {
                self.record_encode_error(&err);
                Err(err)
            }
        }
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError> {
        self.inner.set_bitrate(bitrate_bps)
    }

    fn force_next_idr(&mut self) {
        self.inner.force_next_idr();
    }
}

/// Thin macOS VideoToolbox decoder adapter implementing `HardwareCodec` +
/// `HardwareVideoDecoder`.
pub struct MacVtHardwareDecoder {
    codec: HardwareCodecKind,
    inner: VtDecoder,
    state: HardwareCodecState,
    events: Vec<HardwareCodecEvent>,
}

impl MacVtHardwareDecoder {
    pub fn new(codec: VideoCodec) -> Result<Self, VideoError> {
        let inner = VtDecoder::new(codec)?;
        Ok(Self {
            codec: HardwareCodecKind::from(codec),
            inner,
            state: HardwareCodecState::WaitingFirstIdr,
            events: Vec::new(),
        })
    }
}

impl HardwareCodec for MacVtHardwareDecoder {
    fn codec(&self) -> HardwareCodecKind {
        self.codec
    }

    fn backend_name(&self) -> &'static str {
        "macos_videotoolbox"
    }

    fn state(&self) -> HardwareCodecState {
        self.state.clone()
    }

    fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        std::mem::take(&mut self.events)
    }
}

impl HardwareVideoDecoder for MacVtHardwareDecoder {
    fn decode_packet(&mut self, data: &[u8]) -> Result<DecodedVideoFrame, VideoError> {
        match self.inner.decode_annexb_i420(data) {
            Ok(i420) => {
                if !matches!(self.state, HardwareCodecState::HardwareReady) {
                    self.state = HardwareCodecState::HardwareReady;
                    self.events.push(HardwareCodecEvent::HardwareReady {
                        codec: self.codec,
                        backend: self.backend_name().to_string(),
                    });
                }
                Ok(DecodedVideoFrame::I420(i420))
            }
            Err(err) => {
                if let VideoError::CodecFailed { reason, .. } = &err {
                    self.state = HardwareCodecState::FailedNeedsRenegotiation {
                        reason: reason.clone(),
                    };
                    self.events
                        .push(HardwareCodecEvent::HardwareFailedRenegotiate {
                            codec: self.codec,
                            event_code: HW_DECODER_FAILED_RENEGOTIATE_EVENT.to_string(),
                            reason: reason.clone(),
                        });
                }
                Err(err)
            }
        }
    }
}

/// Cross-platform OS input privilege / trust summary (macOS TCC Accessibility
/// vs Windows UIPI elevation & Secure Desktop status).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputPrivilegeStatus {
    pub accessibility_granted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uipi_elevated: Option<bool>,
    pub secure_desktop_blocked: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Platform-agnostic OS input injector trait.
pub trait OsInputInjector: Send {
    fn inject_key(&mut self, ev: &KeyEvent) -> Result<(), OsError>;
    fn inject_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError>;
    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser>;
    fn release_all(&self) -> ReleaseReport {
        self.emergency_releaser().release_all_keys()
    }
    fn privilege_status(&self) -> InputPrivilegeStatus;
}

/// Thin adapter exposing any existing `OsHidSink` (`MacOsHidSink`, `DryRunHidSink`,
/// `GatedOsHidSink`, etc.) through `OsInputInjector` with zero behavior change.
pub struct OsHidSinkInjector<T: OsHidSink> {
    inner: T,
}

impl<T: OsHidSink> OsHidSinkInjector<T> {
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T: OsHidSink> OsInputInjector for OsHidSinkInjector<T> {
    fn inject_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
        self.inner.send_key(ev)
    }

    fn inject_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError> {
        self.inner.send_mouse(ev)
    }

    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
        self.inner.emergency_releaser()
    }

    fn privilege_status(&self) -> InputPrivilegeStatus {
        let ax = is_accessibility_trusted();
        InputPrivilegeStatus {
            accessibility_granted: ax,
            uipi_elevated: None,
            secure_desktop_blocked: false,
            note: if ax {
                None
            } else {
                Some("macOS Accessibility trust not granted".into())
            },
        }
    }
}

/// Cross-platform independent HID watchdog supervisor lifecycle trait.
pub trait HidWatchdogBackend: Send {
    fn spawn(&mut self, cfg: HidWatchdogConfig) -> Result<u32, OsError>;
    fn heartbeat(&self) -> Result<(), OsError>;
    fn release_all(&self, local_releaser: Option<&dyn EmergencyKeyReleaser>) -> Result<(), OsError>;
    fn shutdown(&mut self, local_releaser: Option<&dyn EmergencyKeyReleaser>);
    fn accessibility_or_uipi_status(&self) -> InputPrivilegeStatus;
}

/// Zero-behavior-change Unix/macOS `HidWatchdogBackend` wrapping `HidWatchdogSupervisor`.
#[derive(Default)]
pub struct UnixHidWatchdogBackend {
    supervisor: Option<HidWatchdogSupervisor>,
}

impl UnixHidWatchdogBackend {
    pub fn new() -> Self {
        Self { supervisor: None }
    }

    pub fn supervisor(&self) -> Option<&HidWatchdogSupervisor> {
        self.supervisor.as_ref()
    }
}

impl HidWatchdogBackend for UnixHidWatchdogBackend {
    fn spawn(&mut self, cfg: HidWatchdogConfig) -> Result<u32, OsError> {
        if let Some(old) = self.supervisor.take() {
            old.shutdown(None);
        }
        let sup = HidWatchdogSupervisor::spawn(cfg)?;
        let pid = sup.child_pid().unwrap_or(0);
        self.supervisor = Some(sup);
        Ok(pid)
    }

    fn heartbeat(&self) -> Result<(), OsError> {
        let Some(sup) = &self.supervisor else {
            return Err(OsError::Interlocked);
        };
        if !sup.is_open() {
            return Err(OsError::Interlocked);
        }
        let _ = sup.accessibility_trusted();
        Ok(())
    }

    fn release_all(&self, local_releaser: Option<&dyn EmergencyKeyReleaser>) -> Result<(), OsError> {
        if let Some(releaser) = local_releaser {
            let _ = releaser.release_all_keys();
        }
        Ok(())
    }

    fn shutdown(&mut self, local_releaser: Option<&dyn EmergencyKeyReleaser>) {
        if let Some(sup) = self.supervisor.take() {
            sup.shutdown(local_releaser);
        }
    }

    fn accessibility_or_uipi_status(&self) -> InputPrivilegeStatus {
        let ax = self
            .supervisor
            .as_ref()
            .map(HidWatchdogSupervisor::accessibility_trusted)
            .unwrap_or_else(is_accessibility_trusted);
        InputPrivilegeStatus {
            accessibility_granted: ax,
            uipi_elevated: None,
            secure_desktop_blocked: false,
            note: if ax {
                None
            } else {
                Some("Accessibility trust not granted on watchdog/host".into())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::dryrun::{DryRunHidSink, SyntheticScreenSource};

    #[test]
    fn screen_capturer_adapter_wraps_synthetic_source_cleanly() {
        let mut cap = OsScreenCaptureAdapter::new(SyntheticScreenSource::new(64, 48), 2);
        assert_eq!(cap.dimensions(), (64, 48));
        assert_eq!(cap.monitor_id(), 2);
        let frame = cap.capture_next_frame().unwrap();
        assert_eq!(frame.width, 64);
        assert_eq!(frame.height, 48);
        assert_eq!(frame.monitor_id, 2);
        assert!(frame.timestamp_us > 0);
        let raw = frame.to_raw_captured_frame().unwrap();
        assert_eq!(raw.pixel_format, PixelFormat::Bgra8);
        assert_eq!(raw.data.len(), 64 * 48 * 4);
    }

    #[test]
    fn os_hid_sink_injector_adapter_delegates_and_releases() {
        let sink = DryRunHidSink::new();
        let mut injector = OsHidSinkInjector::new(sink);
        injector
            .inject_key(&KeyEvent {
                down: true,
                modifiers: 0,
                usb_hid_usage: 0x04,
                unicode_scalar: 0,
                client_ts_ms: 1,
            })
            .unwrap();
        let report = injector.release_all();
        assert_eq!(report.released_keys, 1);
        assert_eq!(report.residual_keys, 0);
    }

    #[test]
    fn capture_error_maps_to_os_error_deterministically() {
        assert_eq!(CaptureError::Timeout.into_os_error(), OsError::Timeout);
        assert_eq!(
            CaptureError::PermissionDenied(OsPermission::ScreenRecording).into_os_error(),
            OsError::PermissionDenied(OsPermission::ScreenRecording)
        );
        assert_eq!(
            CaptureError::from(OsError::Timeout),
            CaptureError::Timeout
        );
    }
}
