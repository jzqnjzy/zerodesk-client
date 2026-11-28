// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic Linux Wayland (`xdg-desktop-portal` ScreenCast + PipeWire)
//! and X11 (`XShm` / `XRandR` / `XFixes`) capture state machines, session detector,
//! multi-monitor topology + rotation helpers, cursor ARGB validation, dirty-region
//! union, and overflow-safe SHM row copy helpers.
//!
//! Compiled and unit-tested on ALL platforms (including macOS) without any
//! Linux system `.so` or kernel header dependency.

use super::traits::{CaptureError, CursorMetadata, CursorShapeKind};
use super::OsPermission;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub const DEFAULT_PORTAL_MAX_RECOVERY_ATTEMPTS: u32 = 3;
pub const DEFAULT_PORTAL_BASE_BACKOFF_MS: u64 = 100;
pub const DEFAULT_PORTAL_MAX_BACKOFF_MS: u64 = 2_000;

pub const DEFAULT_X11_MAX_RECREATE_ATTEMPTS: u32 = 5;
pub const DEFAULT_X11_BASE_BACKOFF_MS: u64 = 50;
pub const DEFAULT_X11_MAX_BACKOFF_MS: u64 = 2_000;

/// Hard safety ceiling for XFixes cursor dimensions (prevents malformed/corrupt
/// server replies from triggering huge allocations or integer overflows).
pub const MAX_XFIXES_CURSOR_DIM: u32 = 512;

/// Hard safety ceiling for captured frame dimensions (16K x 16K).
pub const MAX_CAPTURE_FRAME_DIM: u32 = 16_384;

/// Active Linux graphical session class inferred from environment variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxSessionKind {
    Wayland,
    X11,
    Headless,
}

impl LinuxSessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Wayland => "wayland",
            Self::X11 => "x11",
            Self::Headless => "headless",
        }
    }
}

/// Pure session detection from `XDG_SESSION_TYPE`, `WAYLAND_DISPLAY`, and `DISPLAY`.
///
/// Priority:
/// 1. Explicit `XDG_SESSION_TYPE` (`wayland` / `x11`), provided the matching display
///    socket env var isn't completely contradicted (if `XDG_SESSION_TYPE=wayland`
///    is set, returns `Wayland`; if `x11`, returns `X11`; if `tty`/`unspecified`
///    and no display sockets are present, returns `Headless`).
/// 2. Fallback to `WAYLAND_DISPLAY` (non-empty) -> `Wayland`.
/// 3. Fallback to `DISPLAY` (non-empty) -> `X11`.
/// 4. Otherwise -> `Headless`.
pub fn detect_linux_session_kind(
    xdg_session_type: Option<&str>,
    wayland_display: Option<&str>,
    display: Option<&str>,
) -> LinuxSessionKind {
    fn clean(v: Option<&str>) -> Option<&str> {
        v.map(str::trim).filter(|s| !s.is_empty())
    }
    let xdg = clean(xdg_session_type);
    let wl = clean(wayland_display);
    let x11 = clean(display);

    if let Some(kind) = xdg {
        if kind.eq_ignore_ascii_case("wayland") {
            return LinuxSessionKind::Wayland;
        }
        if kind.eq_ignore_ascii_case("x11") {
            return LinuxSessionKind::X11;
        }
        if kind.eq_ignore_ascii_case("tty") {
            return LinuxSessionKind::Headless;
        }
    }
    if wl.is_some() {
        return LinuxSessionKind::Wayland;
    }
    if x11.is_some() {
        return LinuxSessionKind::X11;
    }
    LinuxSessionKind::Headless
}

// ============================================================================
// Wayland xdg-desktop-portal ScreenCast + PipeWire State Machine
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipeWireBufferKind {
    DmaBuf,
    MemFdShm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PipeWirePixelFormat {
    Bgra8,
    Rgba8,
    Bgrx8,
    Rgbx8,
    Nv12,
}

impl PipeWirePixelFormat {
    /// Bytes per pixel for packed 32-bit RGB formats (`None` for planar `Nv12`).
    pub const fn packed_bpp(self) -> Option<usize> {
        match self {
            Self::Bgra8 | Self::Rgba8 | Self::Bgrx8 | Self::Rgbx8 => Some(4),
            Self::Nv12 => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PipeWireStreamParams {
    pub node_id: u32,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub format: PipeWirePixelFormat,
    pub buffer_kind: PipeWireBufferKind,
    pub drm_modifier: u64,
}

impl PipeWireStreamParams {
    /// Validates dimensions, stride, and minimum required buffer size without integer overflow.
    pub fn validate(&self) -> Result<usize, CaptureError> {
        if self.node_id == 0 {
            return Err(CaptureError::Fatal("PipeWire node_id must be non-zero".into()));
        }
        if self.width == 0
            || self.height == 0
            || self.width > MAX_CAPTURE_FRAME_DIM
            || self.height > MAX_CAPTURE_FRAME_DIM
        {
            return Err(CaptureError::Fatal(format!(
                "invalid PipeWire frame dimensions {}x{}",
                self.width, self.height
            )));
        }
        match self.format.packed_bpp() {
            Some(bpp) => {
                let min_row_bytes = (self.width as usize)
                    .checked_mul(bpp)
                    .ok_or_else(|| CaptureError::Fatal("PipeWire row bytes overflow".into()))?;
                let stride = self.stride as usize;
                if stride < min_row_bytes {
                    return Err(CaptureError::Fatal(format!(
                        "PipeWire stride {stride} < min row bytes {min_row_bytes}"
                    )));
                }
                stride
                    .checked_mul(self.height as usize)
                    .ok_or_else(|| CaptureError::Fatal("PipeWire frame byte length overflow".into()))
            }
            None => {
                // NV12 requires even dimensions and stride >= width; total bytes = stride * height * 3 / 2.
                if !self.width.is_multiple_of(2) || !self.height.is_multiple_of(2) {
                    return Err(CaptureError::Fatal(format!(
                        "PipeWire NV12 dimensions must be even, got {}x{}",
                        self.width, self.height
                    )));
                }
                let stride = self.stride as usize;
                if stride < self.width as usize {
                    return Err(CaptureError::Fatal(format!(
                        "PipeWire NV12 stride {stride} < width {}",
                        self.width
                    )));
                }
                let y_bytes = stride
                    .checked_mul(self.height as usize)
                    .ok_or_else(|| CaptureError::Fatal("PipeWire NV12 Y plane overflow".into()))?;
                let uv_bytes = stride
                    .checked_mul((self.height / 2) as usize)
                    .ok_or_else(|| CaptureError::Fatal("PipeWire NV12 UV plane overflow".into()))?;
                y_bytes
                    .checked_add(uv_bytes)
                    .ok_or_else(|| CaptureError::Fatal("PipeWire NV12 total size overflow".into()))
            }
        }
    }
}

/// Overflow-safe row-by-row copy from an untrusted SHM / MemFd / XShm source buffer
/// into a tightly packed (or `dst_stride`-padded) output buffer.
///
/// Rejects zero/oversized dimensions, stride smaller than `width * bpp`,
/// `src.len()` shorter than `height * src_stride`, and any arithmetic overflow.
pub fn copy_shm_frame_rows(
    src: &[u8],
    width: u32,
    height: u32,
    src_stride: usize,
    bpp: usize,
    dst_stride: usize,
) -> Result<Vec<u8>, CaptureError> {
    if width == 0
        || height == 0
        || width > MAX_CAPTURE_FRAME_DIM
        || height > MAX_CAPTURE_FRAME_DIM
        || bpp == 0
        || bpp > 8
    {
        return Err(CaptureError::Fatal(format!(
            "invalid SHM frame geometry: {width}x{height} bpp={bpp}"
        )));
    }
    let row_bytes = (width as usize)
        .checked_mul(bpp)
        .ok_or_else(|| CaptureError::Fatal("SHM row_bytes overflow".into()))?;
    if src_stride < row_bytes {
        return Err(CaptureError::Fatal(format!(
            "SHM src_stride {src_stride} < row_bytes {row_bytes}"
        )));
    }
    if dst_stride < row_bytes {
        return Err(CaptureError::Fatal(format!(
            "SHM dst_stride {dst_stride} < row_bytes {row_bytes}"
        )));
    }
    let h = height as usize;
    let required_src = (h - 1)
        .checked_mul(src_stride)
        .and_then(|off| off.checked_add(row_bytes))
        .ok_or_else(|| CaptureError::Fatal("SHM source size overflow".into()))?;
    if src.len() < required_src {
        return Err(CaptureError::Fatal(format!(
            "SHM source buffer truncated: len {} < required {required_src}",
            src.len()
        )));
    }
    let dst_len = h
        .checked_mul(dst_stride)
        .ok_or_else(|| CaptureError::Fatal("SHM destination size overflow".into()))?;
    let mut dst = vec![0u8; dst_len];
    for row in 0..h {
        let s_off = row * src_stride;
        let d_off = row * dst_stride;
        dst[d_off..d_off + row_bytes].copy_from_slice(&src[s_off..s_off + row_bytes]);
    }
    Ok(dst)
}

/// Bounded ring tracking PipeWire frame arrivals, monotonic sequence numbers,
/// and dropped/overwritten frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeWireFrameArrival {
    pub seq: u64,
    pub pts_us: i64,
    pub byte_len: usize,
    pub buffer_kind: PipeWireBufferKind,
}

#[derive(Debug, Clone)]
pub struct PipeWireFrameArrivalRing {
    capacity: usize,
    entries: VecDeque<PipeWireFrameArrival>,
    total_received: u64,
    total_dropped: u64,
    last_seq: Option<u64>,
}

impl PipeWireFrameArrivalRing {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            entries: VecDeque::with_capacity(cap),
            total_received: 0,
            total_dropped: 0,
            last_seq: None,
        }
    }

    pub fn push(&mut self, arrival: PipeWireFrameArrival) {
        if let Some(prev) = self.last_seq {
            if arrival.seq > prev.saturating_add(1) {
                self.total_dropped = self
                    .total_dropped
                    .saturating_add(arrival.seq - prev - 1);
            }
        }
        self.last_seq = Some(arrival.seq);
        if self.entries.len() == self.capacity {
            let _ = self.entries.pop_front();
            self.total_dropped = self.total_dropped.saturating_add(1);
        }
        self.entries.push_back(arrival);
        self.total_received = self.total_received.saturating_add(1);
    }

    pub fn pop(&mut self) -> Option<PipeWireFrameArrival> {
        self.entries.pop_front()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_received(&self) -> u64 {
        self.total_received
    }

    pub fn total_dropped(&self) -> u64 {
        self.total_dropped
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// `xdg-desktop-portal` ScreenCast restore token lifecycle.
/// Stores only a non-secret token fingerprint / presence state for diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RestoreTokenState {
    Absent,
    Stored {
        token_fingerprint: String,
        persist_mode: u32,
        uses_count: u32,
    },
    Invalidated {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalPhase {
    Idle,
    CreatingSession,
    SelectingSources,
    StartingStream,
    NegotiatingPipeWire,
    Streaming,
    Recovering {
        attempt: u32,
        max_attempts: u32,
        backoff_ms: u64,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PortalErrorKind {
    AccessDenied,
    CancelledByUser,
    StreamEnded,
    NodeUnavailable,
    PipeWireDisconnected,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalTransition {
    Continue(PortalPhase),
    ScheduleRecovery {
        attempt: u32,
        backoff_ms: u64,
        preserve_restore_token: bool,
    },
    TerminalFailure(CaptureError),
}

/// Pure state machine driving Wayland `xdg-desktop-portal` ScreenCast + PipeWire capture.
#[derive(Debug, Clone)]
pub struct WaylandPortalCaptureStateMachine {
    phase: PortalPhase,
    restore_token: RestoreTokenState,
    negotiated_stream: Option<PipeWireStreamParams>,
    recovery_attempts: u32,
    max_recovery_attempts: u32,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
    frames: PipeWireFrameArrivalRing,
}

impl Default for WaylandPortalCaptureStateMachine {
    fn default() -> Self {
        Self::new(
            DEFAULT_PORTAL_MAX_RECOVERY_ATTEMPTS,
            DEFAULT_PORTAL_BASE_BACKOFF_MS,
            DEFAULT_PORTAL_MAX_BACKOFF_MS,
            8,
        )
    }
}

impl WaylandPortalCaptureStateMachine {
    pub fn new(
        max_recovery_attempts: u32,
        base_backoff_ms: u64,
        max_backoff_ms: u64,
        ring_capacity: usize,
    ) -> Self {
        Self {
            phase: PortalPhase::Idle,
            restore_token: RestoreTokenState::Absent,
            negotiated_stream: None,
            recovery_attempts: 0,
            max_recovery_attempts,
            base_backoff_ms: base_backoff_ms.max(10),
            max_backoff_ms: max_backoff_ms.max(base_backoff_ms.max(10)),
            frames: PipeWireFrameArrivalRing::new(ring_capacity),
        }
    }

    pub fn phase(&self) -> &PortalPhase {
        &self.phase
    }

    pub fn restore_token(&self) -> &RestoreTokenState {
        &self.restore_token
    }

    pub fn negotiated_stream(&self) -> Option<&PipeWireStreamParams> {
        self.negotiated_stream.as_ref()
    }

    pub fn frame_ring(&self) -> &PipeWireFrameArrivalRing {
        &self.frames
    }

    pub fn frame_ring_mut(&mut self) -> &mut PipeWireFrameArrivalRing {
        &mut self.frames
    }

    pub fn recovery_attempts(&self) -> u32 {
        self.recovery_attempts
    }

    pub fn load_restore_token(&mut self, token_fingerprint: impl Into<String>, persist_mode: u32) {
        let fp = token_fingerprint.into();
        if !fp.trim().is_empty() {
            self.restore_token = RestoreTokenState::Stored {
                token_fingerprint: fp,
                persist_mode,
                uses_count: 0,
            };
        }
    }

    pub fn begin_create_session(&mut self) -> Result<PortalPhase, CaptureError> {
        match &self.phase {
            PortalPhase::Idle | PortalPhase::Recovering { .. } => {
                self.phase = PortalPhase::CreatingSession;
                Ok(self.phase.clone())
            }
            PortalPhase::Failed { reason } => Err(CaptureError::Fatal(reason.clone())),
            other => Err(CaptureError::Fatal(format!(
                "cannot CreateSession from portal phase {other:?}"
            ))),
        }
    }

    pub fn on_session_created(&mut self) -> Result<PortalPhase, CaptureError> {
        if self.phase != PortalPhase::CreatingSession {
            return Err(CaptureError::Fatal(format!(
                "unexpected SessionCreated in phase {:?}",
                self.phase
            )));
        }
        if let RestoreTokenState::Stored { uses_count, .. } = &mut self.restore_token {
            *uses_count = uses_count.saturating_add(1);
        }
        self.phase = PortalPhase::SelectingSources;
        Ok(self.phase.clone())
    }

    pub fn on_sources_selected(&mut self) -> Result<PortalPhase, CaptureError> {
        if self.phase != PortalPhase::SelectingSources {
            return Err(CaptureError::Fatal(format!(
                "unexpected SourcesSelected in phase {:?}",
                self.phase
            )));
        }
        self.phase = PortalPhase::StartingStream;
        Ok(self.phase.clone())
    }

    pub fn on_stream_started(
        &mut self,
        node_id: u32,
        new_restore_token_fp: Option<String>,
        persist_mode: u32,
    ) -> Result<PortalPhase, CaptureError> {
        if self.phase != PortalPhase::StartingStream {
            return Err(CaptureError::Fatal(format!(
                "unexpected StreamStarted in phase {:?}",
                self.phase
            )));
        }
        if node_id == 0 {
            return Err(CaptureError::Fatal(
                "portal Start returned invalid PipeWire node_id 0".into(),
            ));
        }
        if let Some(fp) = new_restore_token_fp {
            if !fp.trim().is_empty() {
                self.restore_token = RestoreTokenState::Stored {
                    token_fingerprint: fp,
                    persist_mode,
                    uses_count: 0,
                };
            }
        }
        self.phase = PortalPhase::NegotiatingPipeWire;
        Ok(self.phase.clone())
    }

    pub fn on_pipewire_negotiated(
        &mut self,
        params: PipeWireStreamParams,
    ) -> Result<PortalPhase, CaptureError> {
        if self.phase != PortalPhase::NegotiatingPipeWire && self.phase != PortalPhase::Streaming {
            return Err(CaptureError::Fatal(format!(
                "unexpected PipeWire negotiation in phase {:?}",
                self.phase
            )));
        }
        let _required_bytes = params.validate()?;
        self.negotiated_stream = Some(params);
        self.recovery_attempts = 0;
        self.phase = PortalPhase::Streaming;
        Ok(self.phase.clone())
    }

    pub fn on_frame_arrived(&mut self, arrival: PipeWireFrameArrival) -> Result<(), CaptureError> {
        if self.phase != PortalPhase::Streaming {
            return Err(CaptureError::ReinitRequired(format!(
                "frame arrived while portal phase is {:?}",
                self.phase
            )));
        }
        let Some(stream) = &self.negotiated_stream else {
            return Err(CaptureError::Fatal(
                "PipeWire frame arrived without negotiated stream params".into(),
            ));
        };
        let min_bytes = stream.validate()?;
        if arrival.buffer_kind == PipeWireBufferKind::MemFdShm && arrival.byte_len < min_bytes {
            return Err(CaptureError::Fatal(format!(
                "PipeWire MemFd frame truncated: {} < required {min_bytes}",
                arrival.byte_len
            )));
        }
        self.frames.push(arrival);
        Ok(())
    }

    /// Handles a portal or PipeWire error with bounded recovery for transient stream end /
    /// disconnects and fail-closed invalidation on `AccessDenied` / user cancel.
    pub fn on_error(&mut self, kind: PortalErrorKind, detail: &str) -> PortalTransition {
        if let PortalPhase::Failed { reason } = &self.phase {
            return PortalTransition::TerminalFailure(CaptureError::Fatal(reason.clone()));
        }
        match kind {
            PortalErrorKind::AccessDenied | PortalErrorKind::CancelledByUser => {
                self.restore_token = RestoreTokenState::Invalidated {
                    reason: format!("{kind:?}: {detail}"),
                };
                self.negotiated_stream = None;
                self.frames.clear();
                let reason = format!("Wayland ScreenCast portal denied ({kind:?}): {detail}");
                self.phase = PortalPhase::Failed {
                    reason: reason.clone(),
                };
                PortalTransition::TerminalFailure(CaptureError::PermissionDenied(
                    OsPermission::ScreenRecording,
                ))
            }
            PortalErrorKind::StreamEnded
            | PortalErrorKind::NodeUnavailable
            | PortalErrorKind::PipeWireDisconnected => {
                self.negotiated_stream = None;
                self.frames.clear();
                let next_attempt = self.recovery_attempts.saturating_add(1);
                if next_attempt > self.max_recovery_attempts {
                    let reason = format!(
                        "Wayland PipeWire recovery exhausted ({}/{}) after {kind:?}: {detail}",
                        self.recovery_attempts, self.max_recovery_attempts
                    );
                    self.phase = PortalPhase::Failed {
                        reason: reason.clone(),
                    };
                    return PortalTransition::TerminalFailure(CaptureError::Fatal(reason));
                }
                self.recovery_attempts = next_attempt;
                let shift = next_attempt.saturating_sub(1).min(8);
                let backoff_ms = self
                    .base_backoff_ms
                    .saturating_mul(1u64 << shift)
                    .min(self.max_backoff_ms);
                self.phase = PortalPhase::Recovering {
                    attempt: next_attempt,
                    max_attempts: self.max_recovery_attempts,
                    backoff_ms,
                };
                let preserve_restore_token =
                    matches!(self.restore_token, RestoreTokenState::Stored { .. });
                PortalTransition::ScheduleRecovery {
                    attempt: next_attempt,
                    backoff_ms,
                    preserve_restore_token,
                }
            }
            PortalErrorKind::Fatal => {
                self.negotiated_stream = None;
                self.frames.clear();
                let reason = format!("Wayland portal fatal error: {detail}");
                self.phase = PortalPhase::Failed {
                    reason: reason.clone(),
                };
                PortalTransition::TerminalFailure(CaptureError::Fatal(reason))
            }
        }
    }
}

// ============================================================================
// X11 XShm / XRandR Multi-Monitor, Rotation, XFixes Cursor, Damage Union
// ============================================================================

/// Computes effective `(width, height)` after applying clockwise XRandR rotation
/// (`0`, `90`, `180`, `270` degrees).
pub const fn linux_rotated_dims(width: u32, height: u32, rotation_degrees: u16) -> (u32, u32) {
    match rotation_degrees % 360 {
        90 | 270 => (height, width),
        _ => (width, height),
    }
}

/// Maps a point `(x, y)` in unrotated monitor coordinates `(width, height)` to
/// rotated coordinates according to clockwise XRandR rotation (`0`, `90`, `180`, `270`).
pub fn linux_rotate_point(
    x: i32,
    y: i32,
    width: u32,
    height: u32,
    rotation_degrees: u16,
) -> (i32, i32) {
    let w = i32::try_from(width).unwrap_or(i32::MAX);
    let h = i32::try_from(height).unwrap_or(i32::MAX);
    match rotation_degrees % 360 {
        90 => (h.saturating_sub(1).saturating_sub(y), x),
        180 => (
            w.saturating_sub(1).saturating_sub(x),
            h.saturating_sub(1).saturating_sub(y),
        ),
        270 => (y, w.saturating_sub(1).saturating_sub(x)),
        _ => (x, y),
    }
}

/// Enumerated XRandR monitor descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X11OutputDescriptor {
    pub monitor_id: u32,
    pub name: String,
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub rotation_degrees: u16,
    pub is_primary: bool,
}

impl X11OutputDescriptor {
    pub fn effective_dims(&self) -> (u32, u32) {
        linux_rotated_dims(self.width, self.height, self.rotation_degrees)
    }

    pub fn contains_point(&self, px: i32, py: i32) -> bool {
        let right = i64::from(self.x) + i64::from(self.width);
        let bottom = i64::from(self.y) + i64::from(self.height);
        let px64 = i64::from(px);
        let py64 = i64::from(py);
        px64 >= i64::from(self.x)
            && px64 < right
            && py64 >= i64::from(self.y)
            && py64 < bottom
    }
}

/// Multi-monitor XRandR virtual desktop topology.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct X11MonitorTopology {
    pub outputs: Vec<X11OutputDescriptor>,
}

impl X11MonitorTopology {
    pub fn from_outputs(outputs: Vec<X11OutputDescriptor>) -> Result<Self, CaptureError> {
        let valid: Vec<X11OutputDescriptor> = outputs
            .into_iter()
            .filter(|o| {
                o.width > 0
                    && o.height > 0
                    && o.width <= MAX_CAPTURE_FRAME_DIM
                    && o.height <= MAX_CAPTURE_FRAME_DIM
            })
            .collect();
        if valid.is_empty() {
            return Err(CaptureError::Fatal(
                "XRandR topology contains no active outputs with valid dimensions".into(),
            ));
        }
        Ok(Self { outputs: valid })
    }

    pub fn select_monitor(&self, requested_id: Option<u32>) -> Option<&X11OutputDescriptor> {
        if let Some(id) = requested_id {
            if let Some(found) = self.outputs.iter().find(|o| o.monitor_id == id) {
                return Some(found);
            }
        }
        self.outputs
            .iter()
            .find(|o| o.is_primary)
            .or_else(|| self.outputs.first())
    }

    /// Computes bounding box `(left, top, width, height)` of the virtual X11 root desktop.
    pub fn virtual_bounds(&self) -> Option<(i32, i32, u32, u32)> {
        let mut min_x = i64::MAX;
        let mut min_y = i64::MAX;
        let mut max_x = i64::MIN;
        let mut max_y = i64::MIN;
        for o in &self.outputs {
            min_x = min_x.min(i64::from(o.x));
            min_y = min_y.min(i64::from(o.y));
            max_x = max_x.max(i64::from(o.x) + i64::from(o.width));
            max_y = max_y.max(i64::from(o.y) + i64::from(o.height));
        }
        if min_x >= max_x || min_y >= max_y {
            return None;
        }
        let left = i32::try_from(min_x).ok()?;
        let top = i32::try_from(min_y).ok()?;
        let width = u32::try_from(max_x - min_x).ok()?;
        let height = u32::try_from(max_y - min_y).ok()?;
        Some((left, top, width, height))
    }

    pub fn has_layout_changed(&self, other: &Self) -> bool {
        self.outputs != other.outputs
    }
}

/// Validates XFixes cursor dimensions and ARGB pixel slice length against integer
/// overflow, zero dimensions, oversize attacks, and hotspot bounds.
/// Returns exact required BGRA byte count (`width * height * 4`).
pub fn validate_xfixes_cursor_argb(
    width: u32,
    height: u32,
    hotspot_x: u32,
    hotspot_y: u32,
    argb_pixels_len: usize,
) -> Result<usize, CaptureError> {
    if width == 0 || height == 0 {
        return Err(CaptureError::Fatal(
            "XFixes cursor width and height must be non-zero".into(),
        ));
    }
    if width > MAX_XFIXES_CURSOR_DIM || height > MAX_XFIXES_CURSOR_DIM {
        return Err(CaptureError::Fatal(format!(
            "XFixes cursor dimensions {width}x{height} exceed safety ceiling {MAX_XFIXES_CURSOR_DIM}"
        )));
    }
    if hotspot_x >= width || hotspot_y >= height {
        return Err(CaptureError::Fatal(format!(
            "XFixes cursor hotspot ({hotspot_x}, {hotspot_y}) out of bounds for {width}x{height}"
        )));
    }
    let pixel_count = (width as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| CaptureError::Fatal("XFixes cursor pixel count overflow".into()))?;
    if argb_pixels_len != pixel_count {
        return Err(CaptureError::Fatal(format!(
            "XFixes cursor pixel buffer length {argb_pixels_len} != expected {pixel_count}"
        )));
    }
    pixel_count
        .checked_mul(4)
        .ok_or_else(|| CaptureError::Fatal("XFixes cursor BGRA byte length overflow".into()))
}

/// Input payload describing an XFixes ARGB cursor snapshot.
#[derive(Debug, Clone, Copy)]
pub struct XFixesCursorInput<'a> {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
    pub hotspot_x: u32,
    pub hotspot_y: u32,
    pub visible: bool,
    pub argb_pixels: &'a [u32],
}

/// Converts XFixes `0xAARRGGBB` (`u32` / low 32 bits of Xlib `unsigned long`) pixels
/// into packed little-endian `BGRA8` bytes after strict bounds verification.
pub fn convert_xfixes_argb_to_cursor_metadata(
    input: &XFixesCursorInput<'_>,
) -> Result<CursorMetadata, CaptureError> {
    let byte_len = validate_xfixes_cursor_argb(
        input.width,
        input.height,
        input.hotspot_x,
        input.hotspot_y,
        input.argb_pixels.len(),
    )?;
    let mut bgra = Vec::with_capacity(byte_len);
    for &px in input.argb_pixels {
        let a = ((px >> 24) & 0xFF) as u8;
        let r = ((px >> 16) & 0xFF) as u8;
        let g = ((px >> 8) & 0xFF) as u8;
        let b = (px & 0xFF) as u8;
        bgra.push(b);
        bgra.push(g);
        bgra.push(r);
        bgra.push(a);
    }
    let pitch = input
        .width
        .checked_mul(4)
        .ok_or_else(|| CaptureError::Fatal("XFixes cursor pitch overflow".into()))?;
    Ok(CursorMetadata {
        visible: input.visible,
        x: input.x,
        y: input.y,
        hotspot_x: input.hotspot_x,
        hotspot_y: input.hotspot_y,
        shape_kind: Some(CursorShapeKind::Color),
        shape_width: input.width,
        shape_height: input.height,
        shape_pitch: pitch,
        shape_bytes: Some(bgra),
    })
}

/// Rectangular dirty/damage region in monitor-local coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DamageRect {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// Merges a slice of dirty/damage rects into their tight bounding union clamped
/// to `[0, bounds_w) x [0, bounds_h)`. Empty or out-of-bounds rects are ignored.
pub fn merge_damage_rects(
    rects: &[DamageRect],
    bounds_w: u32,
    bounds_h: u32,
) -> Option<DamageRect> {
    if bounds_w == 0 || bounds_h == 0 {
        return None;
    }
    let bw = i64::from(bounds_w);
    let bh = i64::from(bounds_h);
    let mut min_x = i64::MAX;
    let mut min_y = i64::MAX;
    let mut max_x = i64::MIN;
    let mut max_y = i64::MIN;
    let mut any = false;

    for r in rects {
        if r.width == 0 || r.height == 0 {
            continue;
        }
        let x0 = i64::from(r.x).clamp(0, bw);
        let y0 = i64::from(r.y).clamp(0, bh);
        let x1 = (i64::from(r.x) + i64::from(r.width)).clamp(0, bw);
        let y1 = (i64::from(r.y) + i64::from(r.height)).clamp(0, bh);
        if x1 <= x0 || y1 <= y0 {
            continue;
        }
        min_x = min_x.min(x0);
        min_y = min_y.min(y0);
        max_x = max_x.max(x1);
        max_y = max_y.max(y1);
        any = true;
    }

    if !any {
        return None;
    }
    Some(DamageRect {
        x: min_x as i32,
        y: min_y as i32,
        width: (max_x - min_x) as u32,
        height: (max_y - min_y) as u32,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum X11CaptureErrorKind {
    Timeout,
    BadMatch,
    MonitorLayoutChanged,
    ShmAttachFailed,
    DisplayDisconnected,
    Fatal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum X11CapturePhase {
    Active,
    Recreating {
        attempt: u32,
        max_attempts: u32,
        backoff_ms: u64,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum X11CaptureDecision {
    TimeoutNoChange,
    RecreateShm { attempt: u32, backoff_ms: u64 },
    TerminalFailure(CaptureError),
}

/// Pure X11 XShm capture recovery state machine handling `BadMatch`, XRandR layout
/// changes, and `XShm` re-attachment with bounded exponential backoff.
#[derive(Debug, Clone)]
pub struct X11CaptureStateMachine {
    phase: X11CapturePhase,
    recreate_attempts: u32,
    max_recreate_attempts: u32,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
}

impl Default for X11CaptureStateMachine {
    fn default() -> Self {
        Self::new(
            DEFAULT_X11_MAX_RECREATE_ATTEMPTS,
            DEFAULT_X11_BASE_BACKOFF_MS,
            DEFAULT_X11_MAX_BACKOFF_MS,
        )
    }
}

impl X11CaptureStateMachine {
    pub fn new(max_recreate_attempts: u32, base_backoff_ms: u64, max_backoff_ms: u64) -> Self {
        Self {
            phase: X11CapturePhase::Active,
            recreate_attempts: 0,
            max_recreate_attempts,
            base_backoff_ms: base_backoff_ms.max(10),
            max_backoff_ms: max_backoff_ms.max(base_backoff_ms.max(10)),
        }
    }

    pub fn phase(&self) -> &X11CapturePhase {
        &self.phase
    }

    pub fn recreate_attempts(&self) -> u32 {
        self.recreate_attempts
    }

    pub fn on_frame_ok(&mut self) {
        if !matches!(self.phase, X11CapturePhase::Failed { .. }) {
            self.recreate_attempts = 0;
            self.phase = X11CapturePhase::Active;
        }
    }

    pub fn on_recreated(&mut self) -> Result<(), CaptureError> {
        if let X11CapturePhase::Failed { reason } = &self.phase {
            return Err(CaptureError::Fatal(reason.clone()));
        }
        self.phase = X11CapturePhase::Active;
        Ok(())
    }

    pub fn on_error(&mut self, kind: X11CaptureErrorKind, detail: &str) -> X11CaptureDecision {
        if let X11CapturePhase::Failed { reason } = &self.phase {
            return X11CaptureDecision::TerminalFailure(CaptureError::Fatal(reason.clone()));
        }
        match kind {
            X11CaptureErrorKind::Timeout => X11CaptureDecision::TimeoutNoChange,
            X11CaptureErrorKind::BadMatch
            | X11CaptureErrorKind::MonitorLayoutChanged
            | X11CaptureErrorKind::ShmAttachFailed => {
                let next_attempt = self.recreate_attempts.saturating_add(1);
                if next_attempt > self.max_recreate_attempts {
                    let reason = format!(
                        "X11 XShm recreate exhausted ({}/{}) on {kind:?}: {detail}",
                        self.recreate_attempts, self.max_recreate_attempts
                    );
                    self.phase = X11CapturePhase::Failed {
                        reason: reason.clone(),
                    };
                    return X11CaptureDecision::TerminalFailure(CaptureError::Fatal(reason));
                }
                self.recreate_attempts = next_attempt;
                let shift = next_attempt.saturating_sub(1).min(8);
                let backoff_ms = self
                    .base_backoff_ms
                    .saturating_mul(1u64 << shift)
                    .min(self.max_backoff_ms);
                self.phase = X11CapturePhase::Recreating {
                    attempt: next_attempt,
                    max_attempts: self.max_recreate_attempts,
                    backoff_ms,
                };
                X11CaptureDecision::RecreateShm {
                    attempt: next_attempt,
                    backoff_ms,
                }
            }
            X11CaptureErrorKind::DisplayDisconnected | X11CaptureErrorKind::Fatal => {
                let reason = format!("X11 capture fatal ({kind:?}): {detail}");
                self.phase = X11CapturePhase::Failed {
                    reason: reason.clone(),
                };
                X11CaptureDecision::TerminalFailure(CaptureError::Fatal(reason))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_detection_handles_wayland_x11_and_headless_precedence() {
        assert_eq!(
            detect_linux_session_kind(Some("wayland"), Some("wayland-0"), Some(":0")),
            LinuxSessionKind::Wayland
        );
        assert_eq!(
            detect_linux_session_kind(Some("X11"), None, Some(":0")),
            LinuxSessionKind::X11
        );
        assert_eq!(
            detect_linux_session_kind(Some("tty"), None, None),
            LinuxSessionKind::Headless
        );
        assert_eq!(
            detect_linux_session_kind(None, Some("wayland-1"), Some(":0")),
            LinuxSessionKind::Wayland
        );
        assert_eq!(
            detect_linux_session_kind(Some("  "), Some(""), Some(":1")),
            LinuxSessionKind::X11
        );
        assert_eq!(
            detect_linux_session_kind(None, None, None),
            LinuxSessionKind::Headless
        );
    }

    #[test]
    fn wayland_portal_full_lifecycle_and_bounded_recovery() {
        let mut sm = WaylandPortalCaptureStateMachine::new(2, 100, 1_000, 4);
        sm.load_restore_token("sha256:abc123", 2);
        assert_eq!(sm.begin_create_session().unwrap(), PortalPhase::CreatingSession);
        assert_eq!(sm.on_session_created().unwrap(), PortalPhase::SelectingSources);
        assert_eq!(
            sm.restore_token(),
            &RestoreTokenState::Stored {
                token_fingerprint: "sha256:abc123".into(),
                persist_mode: 2,
                uses_count: 1,
            }
        );
        assert_eq!(sm.on_sources_selected().unwrap(), PortalPhase::StartingStream);
        assert_eq!(
            sm.on_stream_started(42, Some("sha256:def456".into()), 2).unwrap(),
            PortalPhase::NegotiatingPipeWire
        );

        let params = PipeWireStreamParams {
            node_id: 42,
            width: 1920,
            height: 1080,
            stride: 1920 * 4,
            format: PipeWirePixelFormat::Bgra8,
            buffer_kind: PipeWireBufferKind::MemFdShm,
            drm_modifier: 0,
        };
        assert_eq!(sm.on_pipewire_negotiated(params.clone()).unwrap(), PortalPhase::Streaming);

        // Truncated SHM frame is rejected cleanly.
        let bad_frame = PipeWireFrameArrival {
            seq: 1,
            pts_us: 1000,
            byte_len: 1024,
            buffer_kind: PipeWireBufferKind::MemFdShm,
        };
        assert!(sm.on_frame_arrived(bad_frame).is_err());

        // Valid frame accepted into ring.
        sm.on_frame_arrived(PipeWireFrameArrival {
            seq: 1,
            pts_us: 1000,
            byte_len: 1920 * 1080 * 4,
            buffer_kind: PipeWireBufferKind::MemFdShm,
        })
        .unwrap();
        assert_eq!(sm.frame_ring().len(), 1);

        // StreamEnded triggers bounded recovery 1 & 2, preserving restore token.
        assert_eq!(
            sm.on_error(PortalErrorKind::StreamEnded, "compositor restarted"),
            PortalTransition::ScheduleRecovery {
                attempt: 1,
                backoff_ms: 100,
                preserve_restore_token: true,
            }
        );
        assert_eq!(
            sm.on_error(PortalErrorKind::PipeWireDisconnected, "pw restart"),
            PortalTransition::ScheduleRecovery {
                attempt: 2,
                backoff_ms: 200,
                preserve_restore_token: true,
            }
        );
        // 3rd failure exceeds max_recovery_attempts=2 -> terminal fail-closed.
        assert!(matches!(
            sm.on_error(PortalErrorKind::StreamEnded, "exhausted"),
            PortalTransition::TerminalFailure(CaptureError::Fatal(_))
        ));
    }

    #[test]
    fn wayland_portal_access_denied_invalidates_restore_token_immediately() {
        let mut sm = WaylandPortalCaptureStateMachine::default();
        sm.load_restore_token("sha256:old", 2);
        sm.begin_create_session().unwrap();
        let tr = sm.on_error(PortalErrorKind::AccessDenied, "user clicked deny");
        assert_eq!(
            tr,
            PortalTransition::TerminalFailure(CaptureError::PermissionDenied(
                OsPermission::ScreenRecording
            ))
        );
        assert!(matches!(
            sm.restore_token(),
            RestoreTokenState::Invalidated { .. }
        ));
        assert!(sm.begin_create_session().is_err());
    }

    #[test]
    fn copy_shm_frame_rows_handles_stride_padding_and_rejects_truncation_or_overflow() {
        // 2x2 BGRA with padded src_stride=16 -> packed dst_stride=8.
        let mut src = vec![0xAAu8; 32];
        src[0..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        src[16..24].copy_from_slice(&[9, 10, 11, 12, 13, 14, 15, 16]);
        let dst = copy_shm_frame_rows(&src, 2, 2, 16, 4, 8).unwrap();
        assert_eq!(dst, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);

        // Truncated source rejected.
        assert!(copy_shm_frame_rows(&src[..20], 2, 2, 16, 4, 8).is_err());
        // Stride smaller than row_bytes rejected.
        assert!(copy_shm_frame_rows(&src, 2, 2, 4, 4, 8).is_err());
        // Overflowing stride rejected.
        assert!(copy_shm_frame_rows(&src, 2, 2, usize::MAX, 4, 8).is_err());
        // Oversized dimensions rejected.
        assert!(copy_shm_frame_rows(&src, MAX_CAPTURE_FRAME_DIM + 1, 1, 16, 4, 16).is_err());
    }

    #[test]
    fn x11_topology_rotation_and_damage_rect_union() {
        let topo = X11MonitorTopology::from_outputs(vec![
            X11OutputDescriptor {
                monitor_id: 0,
                name: "DP-1".into(),
                x: 0,
                y: 0,
                width: 1920,
                height: 1080,
                rotation_degrees: 0,
                is_primary: true,
            },
            X11OutputDescriptor {
                monitor_id: 1,
                name: "HDMI-1".into(),
                x: 1920,
                y: 0,
                width: 1080,
                height: 1920,
                rotation_degrees: 90,
                is_primary: false,
            },
        ])
        .unwrap();

        assert_eq!(topo.virtual_bounds(), Some((0, 0, 3000, 1920)));
        assert_eq!(topo.select_monitor(None).unwrap().name, "DP-1");
        assert_eq!(topo.select_monitor(Some(1)).unwrap().effective_dims(), (1920, 1080));
        assert_eq!(linux_rotated_dims(1920, 1080, 270), (1080, 1920));
        assert_eq!(linux_rotate_point(10, 20, 100, 50, 90), (29, 10));
        assert_eq!(linux_rotate_point(10, 20, 100, 50, 180), (89, 29));
        assert_eq!(linux_rotate_point(10, 20, 100, 50, 270), (20, 89));

        // Damage rect union clamps to monitor bounds and ignores empty/out-of-bounds rects.
        let merged = merge_damage_rects(
            &[
                DamageRect { x: -10, y: 10, width: 30, height: 20 },
                DamageRect { x: 100, y: 50, width: 200, height: 100 },
                DamageRect { x: 500, y: 500, width: 0, height: 10 },
                DamageRect { x: 5000, y: 5000, width: 50, height: 50 },
            ],
            250,
            120,
        )
        .unwrap();
        assert_eq!(
            merged,
            DamageRect {
                x: 0,
                y: 10,
                width: 250,
                height: 110,
            }
        );
    }

    #[test]
    fn xfixes_cursor_validation_and_argb_conversion() {
        let pixels = vec![0x80_11_22_33u32, 0xFF_44_55_66, 0x00_77_88_99, 0xCC_AA_BB_CC];
        let meta = convert_xfixes_argb_to_cursor_metadata(&XFixesCursorInput {
            x: 100,
            y: 200,
            width: 2,
            height: 2,
            hotspot_x: 1,
            hotspot_y: 0,
            visible: true,
            argb_pixels: &pixels,
        })
        .unwrap();
        assert_eq!(meta.shape_pitch, 8);
        let bytes = meta.shape_bytes.unwrap();
        assert_eq!(&bytes[0..4], &[0x33, 0x22, 0x11, 0x80]); // BGRA
        assert_eq!(&bytes[4..8], &[0x66, 0x55, 0x44, 0xFF]);

        // Mismatched buffer length rejected.
        assert!(validate_xfixes_cursor_argb(2, 2, 0, 0, 3).is_err());
        // Hotspot out of bounds rejected.
        assert!(validate_xfixes_cursor_argb(2, 2, 2, 0, 4).is_err());
        // Oversized cursor rejected.
        assert!(validate_xfixes_cursor_argb(MAX_XFIXES_CURSOR_DIM + 1, 1, 0, 0, 513).is_err());
    }

    #[test]
    fn x11_state_machine_auto_recreates_on_bad_match_and_layout_change() {
        let mut sm = X11CaptureStateMachine::new(2, 50, 500);
        assert_eq!(
            sm.on_error(X11CaptureErrorKind::Timeout, "no damage"),
            X11CaptureDecision::TimeoutNoChange
        );
        assert_eq!(
            sm.on_error(X11CaptureErrorKind::BadMatch, "resize mid-grab"),
            X11CaptureDecision::RecreateShm {
                attempt: 1,
                backoff_ms: 50,
            }
        );
        sm.on_recreated().unwrap();
        sm.on_frame_ok();
        assert_eq!(sm.recreate_attempts(), 0);

        assert_eq!(
            sm.on_error(X11CaptureErrorKind::MonitorLayoutChanged, "XRandR"),
            X11CaptureDecision::RecreateShm {
                attempt: 1,
                backoff_ms: 50,
            }
        );
        assert_eq!(
            sm.on_error(X11CaptureErrorKind::ShmAttachFailed, "shm"),
            X11CaptureDecision::RecreateShm {
                attempt: 2,
                backoff_ms: 100,
            }
        );
        assert!(matches!(
            sm.on_error(X11CaptureErrorKind::BadMatch, "exhausted"),
            X11CaptureDecision::TerminalFailure(CaptureError::Fatal(_))
        ));
    }
}
