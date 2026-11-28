// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Cross-platform OS adapter traits for screen capture, hardware video codecs,
//! OS input injection, and independent HID watchdog supervision.
//!
//! Existing macOS implementations (`ScreenCaptureKit`, `MacOsScreenCapture`,
//! `VideoToolbox`, `MacOsHidSink`, `HidWatchdogSupervisor`) adapt cleanly onto
//! these traits with zero behavioral changes.

use super::{
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
    num::{NonZeroU32, NonZeroU64},
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

/// RAII-owned Windows D3D11 GPU frame wrapper shared via `Arc<D3d11SharedFrame>`
/// so cloning a `CapturedFrame` keeps the underlying COM `ID3D11Texture2D` alive
/// (never exposing a dangling raw handle).
pub struct D3d11SharedFrame {
    adapter_luid: (u32, i32),
    format: D3d11SurfaceFormat,
    shared_handle: Option<NonZeroU64>,
    #[cfg(windows)]
    texture: Option<windows::Win32::Graphics::Direct3D11::ID3D11Texture2D>,
    #[cfg(windows)]
    owned_handle: Option<windows::Win32::Foundation::HANDLE>,
}

// SAFETY: On Windows, `ID3D11Texture2D` is a COM reference-counted interface created on
// a `COINIT_MULTITHREADED` D3D11 device with `ID3D11Multithread::SetMultithreadProtected(true)`
// enabled, and `D3d11SharedFrame` exposes only shared immutable reads while owning cleanup on Drop.
unsafe impl Send for D3d11SharedFrame {}
unsafe impl Sync for D3d11SharedFrame {}

impl D3d11SharedFrame {
    pub fn from_metadata(
        adapter_luid: (u32, i32),
        format: D3d11SurfaceFormat,
        shared_handle: Option<NonZeroU64>,
    ) -> Self {
        Self {
            adapter_luid,
            format,
            shared_handle,
            #[cfg(windows)]
            texture: None,
            #[cfg(windows)]
            owned_handle: None,
        }
    }

    #[cfg(windows)]
    pub fn from_texture(
        texture: windows::Win32::Graphics::Direct3D11::ID3D11Texture2D,
        adapter_luid: (u32, i32),
        format: D3d11SurfaceFormat,
        owned_handle: Option<windows::Win32::Foundation::HANDLE>,
    ) -> Self {
        let shared_handle = owned_handle
            .filter(|h| !h.is_invalid() && h.0 != 0)
            .and_then(|h| NonZeroU64::new(h.0 as usize as u64));
        Self {
            adapter_luid,
            format,
            shared_handle,
            texture: Some(texture),
            owned_handle,
        }
    }

    pub fn adapter_luid(&self) -> (u32, i32) {
        self.adapter_luid
    }

    pub fn format(&self) -> D3d11SurfaceFormat {
        self.format
    }

    pub fn shared_handle(&self) -> Option<NonZeroU64> {
        self.shared_handle
    }

    #[cfg(windows)]
    pub fn texture(&self) -> Option<&windows::Win32::Graphics::Direct3D11::ID3D11Texture2D> {
        self.texture.as_ref()
    }
}

#[cfg(windows)]
impl Drop for D3d11SharedFrame {
    fn drop(&mut self) {
        if let Some(h) = self.owned_handle.take() {
            if !h.is_invalid() && h.0 != 0 {
                unsafe {
                    let _ = windows::Win32::Foundation::CloseHandle(h);
                }
            }
        }
    }
}

impl fmt::Debug for D3d11SharedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("D3d11SharedFrame")
            .field("adapter_luid", &self.adapter_luid)
            .field("format", &self.format)
            .field("shared_handle", &self.shared_handle)
            .finish()
    }
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
    /// RAII-owned Windows D3D11 GPU texture frame for zero-copy Media Foundation
    /// hardware encoding (`Arc` prevents dangling raw handles on clone).
    D3d11Texture(Arc<D3d11SharedFrame>),
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
            Self::D3d11Texture(frame) => f.debug_tuple("D3d11Texture").field(frame).finish(),
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
            CapturedSurface::Nv12 { .. } | CapturedSurface::D3d11Texture(_) => None,
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
    /// Legacy compatibility bridge to `OsError` for existing macOS `OsScreenCapture` callers.
    /// New `ScreenCapturer` callers MUST match on typed `CaptureError` variants directly.
    #[doc(hidden)]
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
    CpuColorConvertFallback {
        codec: HardwareCodecKind,
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

/// Pure, platform-agnostic hardware codec lifecycle state machine shared by
/// adapters (e.g. `MacVtHardwareEncoder` / `MacVtHardwareDecoder`) to guarantee:
/// - `HardwareReady` is entered only on valid IDR/decoded output;
/// - `FailedNeedsRenegotiation` is strictly terminal & idempotent (never spams
///   duplicate `HardwareFailedRenegotiate` events);
/// - active work short-circuits immediately once terminal until explicit `reset_for_reinit()`.
#[derive(Debug, Clone)]
pub struct CodecLifecycle {
    codec: HardwareCodecKind,
    backend: &'static str,
    failed_event_code: &'static str,
    state: HardwareCodecState,
    events: Vec<HardwareCodecEvent>,
}

impl CodecLifecycle {
    pub fn new(
        codec: HardwareCodecKind,
        backend: &'static str,
        failed_event_code: &'static str,
    ) -> Self {
        Self {
            codec,
            backend,
            failed_event_code,
            state: HardwareCodecState::WaitingFirstIdr,
            events: Vec::new(),
        }
    }

    pub fn state(&self) -> HardwareCodecState {
        self.state.clone()
    }

    pub fn is_terminal(&self) -> bool {
        matches!(
            self.state,
            HardwareCodecState::FailedNeedsRenegotiation { .. }
        )
    }

    pub fn ensure_not_terminal(&self) -> Result<(), VideoError> {
        if let HardwareCodecState::FailedNeedsRenegotiation { reason } = &self.state {
            return Err(VideoError::CodecFailed {
                codec: VideoCodec::from(self.codec),
                reason: reason.clone(),
            });
        }
        Ok(())
    }

    pub fn on_idr_or_output_ready(&mut self, is_ready_sample: bool, byte_len: usize) {
        if self.is_terminal() || !is_ready_sample || byte_len == 0 {
            return;
        }
        if !matches!(self.state, HardwareCodecState::HardwareReady) {
            self.state = HardwareCodecState::HardwareReady;
            self.events.push(HardwareCodecEvent::HardwareReady {
                codec: self.codec,
                backend: self.backend.to_string(),
            });
        }
    }

    pub fn on_terminal_failure(&mut self, reason: impl Into<String>) {
        if self.is_terminal() {
            return;
        }
        let reason = reason.into();
        self.state = HardwareCodecState::FailedNeedsRenegotiation {
            reason: reason.clone(),
        };
        self.events
            .push(HardwareCodecEvent::HardwareFailedRenegotiate {
                codec: self.codec,
                event_code: self.failed_event_code.to_string(),
                reason,
            });
    }

    pub fn reset_for_reinit(&mut self) {
        self.state = HardwareCodecState::WaitingFirstIdr;
    }

    pub fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        std::mem::take(&mut self.events)
    }
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
///
/// `encode_frame` and `encode_i420` return `Vec<HardwareEncodedPacket>` (0..n packets
/// per input) to support asynchronous hardware MFTs cleanly.
pub trait HardwareVideoEncoder: HardwareCodec {
    fn encode_frame(
        &mut self,
        frame: &CapturedFrame,
        force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError>;
    fn encode_i420(
        &mut self,
        frame: &I420Frame,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError>;
    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError>;
    fn force_next_idr(&mut self);
    fn reinit(&mut self) -> Result<(), VideoError>;
}

/// Cross-platform hardware video decoder trait.
pub trait HardwareVideoDecoder: HardwareCodec {
    fn decode_packet(&mut self, data: &[u8]) -> Result<DecodedVideoFrame, VideoError>;
}

/// Thin macOS VideoToolbox encoder adapter implementing `HardwareCodec` +
/// `HardwareVideoEncoder` without modifying any existing `VtEncoder` path.
pub struct MacVtHardwareEncoder {
    codec: VideoCodec,
    width: u32,
    height: u32,
    fps: u32,
    bitrate_bps: u32,
    max_keyframe_interval: u32,
    inner: VtEncoder,
    lifecycle: CodecLifecycle,
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
            codec,
            width,
            height,
            fps,
            bitrate_bps,
            max_keyframe_interval,
            inner,
            lifecycle: CodecLifecycle::new(
                HardwareCodecKind::from(codec),
                "macos_videotoolbox",
                HW_ENCODER_FAILED_RENEGOTIATE_EVENT,
            ),
        })
    }

    fn record_encode_error(&mut self, err: &VideoError) {
        if let VideoError::CodecFailed { reason, .. } = err {
            self.lifecycle.on_terminal_failure(reason.clone());
        }
    }
}

impl HardwareCodec for MacVtHardwareEncoder {
    fn codec(&self) -> HardwareCodecKind {
        HardwareCodecKind::from(self.codec)
    }

    fn backend_name(&self) -> &'static str {
        "macos_videotoolbox"
    }

    fn state(&self) -> HardwareCodecState {
        self.lifecycle.state()
    }

    fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        self.lifecycle.drain_events()
    }
}

impl HardwareVideoEncoder for MacVtHardwareEncoder {
    fn encode_frame(
        &mut self,
        frame: &CapturedFrame,
        force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        self.lifecycle.ensure_not_terminal()?;
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
            | CapturedSurface::D3d11Texture(_) => Err(VideoError::InvalidInput(
                "MacVtHardwareEncoder expects BGRA8 CapturedFrame or encode_i420".into(),
            )),
        };
        match res {
            Ok((data, is_idr)) => {
                self.lifecycle.on_idr_or_output_ready(is_idr, data.len());
                Ok(vec![HardwareEncodedPacket {
                    data,
                    is_idr,
                    pts_us: frame.timestamp_us,
                    codec: HardwareCodecKind::from(self.codec),
                }])
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
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        self.lifecycle.ensure_not_terminal()?;
        match self.inner.encode_i420(frame, pts_us, force_idr) {
            Ok((data, is_idr)) => {
                self.lifecycle.on_idr_or_output_ready(is_idr, data.len());
                Ok(vec![HardwareEncodedPacket {
                    data,
                    is_idr,
                    pts_us,
                    codec: HardwareCodecKind::from(self.codec),
                }])
            }
            Err(err) => {
                self.record_encode_error(&err);
                Err(err)
            }
        }
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError> {
        self.lifecycle.ensure_not_terminal()?;
        self.inner.set_bitrate(bitrate_bps)?;
        self.bitrate_bps = bitrate_bps;
        Ok(())
    }

    fn force_next_idr(&mut self) {
        self.inner.force_next_idr();
    }

    fn reinit(&mut self) -> Result<(), VideoError> {
        let fresh = VtEncoder::new(
            self.codec,
            self.width,
            self.height,
            self.fps,
            self.bitrate_bps,
            self.max_keyframe_interval,
        )?;
        self.inner = fresh;
        self.lifecycle.reset_for_reinit();
        Ok(())
    }
}

/// Thin macOS VideoToolbox decoder adapter implementing `HardwareCodec` +
/// `HardwareVideoDecoder`.
pub struct MacVtHardwareDecoder {
    codec: HardwareCodecKind,
    inner: VtDecoder,
    lifecycle: CodecLifecycle,
}

impl MacVtHardwareDecoder {
    pub fn new(codec: VideoCodec) -> Result<Self, VideoError> {
        let inner = VtDecoder::new(codec)?;
        let kind = HardwareCodecKind::from(codec);
        Ok(Self {
            codec: kind,
            inner,
            lifecycle: CodecLifecycle::new(
                kind,
                "macos_videotoolbox",
                HW_DECODER_FAILED_RENEGOTIATE_EVENT,
            ),
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
        self.lifecycle.state()
    }

    fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        self.lifecycle.drain_events()
    }
}

impl HardwareVideoDecoder for MacVtHardwareDecoder {
    fn decode_packet(&mut self, data: &[u8]) -> Result<DecodedVideoFrame, VideoError> {
        self.lifecycle.ensure_not_terminal()?;
        match self.inner.decode_annexb_i420(data) {
            Ok(i420) => {
                self.lifecycle.on_idr_or_output_ready(true, i420.y.len());
                Ok(DecodedVideoFrame::I420(i420))
            }
            Err(err) => {
                if let VideoError::CodecFailed { reason, .. } = &err {
                    self.lifecycle.on_terminal_failure(reason.clone());
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
        #[cfg(target_os = "macos")]
        {
            let ax = super::input::is_accessibility_trusted();
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
        #[cfg(windows)]
        {
            super::win_input::win_input_privilege_status()
        }
        #[cfg(not(any(target_os = "macos", windows)))]
        {
            InputPrivilegeStatus {
                accessibility_granted: false,
                uipi_elevated: None,
                secure_desktop_blocked: false,
                note: Some("OS input privilege status probe not implemented on this platform".into()),
            }
        }
    }
}

/// Validates a `ReleaseReport` returned by an emergency key releaser, failing closed
/// if any keys or mouse buttons remain unreleased (`residual_* > 0`).
pub fn check_release_report(report: ReleaseReport) -> Result<ReleaseReport, OsError> {
    if report.residual_keys > 0 || report.residual_buttons > 0 {
        return Err(OsError::CaptureFailed(format!(
            "emergency input release incomplete: residual_keys={}, residual_buttons={}",
            report.residual_keys, report.residual_buttons
        )));
    }
    Ok(report)
}

/// Cross-platform independent HID watchdog supervisor lifecycle trait.
pub trait HidWatchdogBackend: Send {
    /// Spawns the watchdog subprocess and returns its validated non-zero PID.
    fn spawn(&mut self, cfg: HidWatchdogConfig) -> Result<Option<NonZeroU32>, OsError>;
    fn heartbeat(&self) -> Result<(), OsError>;
    /// Releases all held keys/buttons via `local_releaser`. Returns `Err` if
    /// `local_releaser` is `None` or if any keys/buttons remain unreleased.
    fn release_all(
        &self,
        local_releaser: Option<&dyn EmergencyKeyReleaser>,
    ) -> Result<ReleaseReport, OsError>;
    /// Shuts down the watchdog subprocess and invokes `local_releaser` even when
    /// no active supervisor exists.
    fn shutdown(
        &mut self,
        local_releaser: Option<&dyn EmergencyKeyReleaser>,
    ) -> Result<ReleaseReport, OsError>;
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
    fn spawn(&mut self, cfg: HidWatchdogConfig) -> Result<Option<NonZeroU32>, OsError> {
        if let Some(old) = self.supervisor.take() {
            old.shutdown(None);
        }
        let sup = HidWatchdogSupervisor::spawn(cfg)?;
        let pid = sup.child_pid().and_then(NonZeroU32::new);
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

    fn release_all(
        &self,
        local_releaser: Option<&dyn EmergencyKeyReleaser>,
    ) -> Result<ReleaseReport, OsError> {
        let Some(releaser) = local_releaser else {
            return Err(OsError::InvalidData(
                "release_all requires a local EmergencyKeyReleaser".into(),
            ));
        };
        check_release_report(releaser.release_all_keys())
    }

    fn shutdown(
        &mut self,
        local_releaser: Option<&dyn EmergencyKeyReleaser>,
    ) -> Result<ReleaseReport, OsError> {
        let report = local_releaser.map(EmergencyKeyReleaser::release_all_keys);
        if let Some(sup) = self.supervisor.take() {
            // Local releaser was already executed above (if provided), so avoid double-release.
            sup.shutdown(None);
        }
        match report {
            Some(rep) => check_release_report(rep),
            None => Ok(ReleaseReport::default()),
        }
    }

    fn accessibility_or_uipi_status(&self) -> InputPrivilegeStatus {
        let ax = self
            .supervisor
            .as_ref()
            .map(HidWatchdogSupervisor::accessibility_trusted)
            .unwrap_or_else(super::input::is_accessibility_trusted);
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

    struct StubReleaser {
        report: ReleaseReport,
        calls: std::sync::atomic::AtomicUsize,
    }

    impl EmergencyKeyReleaser for StubReleaser {
        fn release_all_keys(&self) -> ReleaseReport {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.report
        }
    }

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
    fn codec_lifecycle_is_terminal_and_idempotent_without_event_spam() {
        let mut lc = CodecLifecycle::new(
            HardwareCodecKind::H264,
            "test_hw",
            HW_ENCODER_FAILED_RENEGOTIATE_EVENT,
        );
        assert_eq!(lc.state(), HardwareCodecState::WaitingFirstIdr);
        lc.on_idr_or_output_ready(false, 512);
        assert_eq!(lc.state(), HardwareCodecState::WaitingFirstIdr);
        lc.on_idr_or_output_ready(true, 1024);
        assert_eq!(lc.state(), HardwareCodecState::HardwareReady);
        assert_eq!(lc.drain_events().len(), 1);

        // Terminal failure emits event ONCE; repeated failures do NOT spam.
        lc.on_terminal_failure("gpu reset");
        lc.on_terminal_failure("second failure");
        assert!(lc.is_terminal());
        assert!(lc.ensure_not_terminal().is_err());
        let evs = lc.drain_events();
        assert_eq!(evs.len(), 1);
        assert!(matches!(
            &evs[0],
            HardwareCodecEvent::HardwareFailedRenegotiate {
                codec: HardwareCodecKind::H264,
                event_code,
                ..
            } if event_code == HW_ENCODER_FAILED_RENEGOTIATE_EVENT
        ));

        // Output after terminal failure cannot resurrect HardwareReady without explicit reset_for_reinit.
        lc.on_idr_or_output_ready(true, 2048);
        assert!(lc.is_terminal());
        lc.reset_for_reinit();
        assert_eq!(lc.state(), HardwareCodecState::WaitingFirstIdr);
    }

    #[test]
    fn watchdog_backend_release_all_and_shutdown_enforce_releaser_contract() {
        let mut wd = UnixHidWatchdogBackend::new();
        assert!(wd.release_all(None).is_err());

        let partial = StubReleaser {
            report: ReleaseReport {
                released_keys: 1,
                released_buttons: 0,
                residual_keys: 1,
                residual_buttons: 0,
            },
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        assert!(wd.release_all(Some(&partial)).is_err());

        // Shutdown invokes local_releaser even when supervisor is None.
        let clean = StubReleaser {
            report: ReleaseReport {
                released_keys: 2,
                released_buttons: 1,
                residual_keys: 0,
                residual_buttons: 0,
            },
            calls: std::sync::atomic::AtomicUsize::new(0),
        };
        let rep = wd.shutdown(Some(&clean)).unwrap();
        assert_eq!(rep.released_keys, 2);
        assert_eq!(clean.calls.load(std::sync::atomic::Ordering::Acquire), 1);
    }

    #[test]
    fn d3d11_shared_frame_wrapper_keeps_metadata_and_clones_arc() {
        let f = Arc::new(D3d11SharedFrame::from_metadata(
            (0x1234, 0),
            D3d11SurfaceFormat::Nv12,
            NonZeroU64::new(0xCAFE),
        ));
        let surface = CapturedSurface::D3d11Texture(Arc::clone(&f));
        assert_eq!(f.adapter_luid(), (0x1234, 0));
        assert_eq!(f.format(), D3d11SurfaceFormat::Nv12);
        assert_eq!(f.shared_handle(), NonZeroU64::new(0xCAFE));
        let cloned = surface.clone();
        assert_eq!(Arc::strong_count(&f), 3);
        drop(cloned);
        assert_eq!(Arc::strong_count(&f), 2);
    }

    #[test]
    fn capture_error_maps_to_os_error_deterministically() {
        assert_eq!(CaptureError::Timeout.into_os_error(), OsError::Timeout);
        assert_eq!(
            CaptureError::PermissionDenied(OsPermission::ScreenRecording).into_os_error(),
            OsError::PermissionDenied(OsPermission::ScreenRecording)
        );
        assert_eq!(CaptureError::from(OsError::Timeout), CaptureError::Timeout);
    }
}
