// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic Windows DXGI Desktop Duplication state machine, 3-class
//! HRESULT classifier, multi-monitor / LUID selection, rotation helpers, cursor
//! tracking, and dirty/move rect utilities.
//!
//! Compiled and unit-tested on ALL platforms (including macOS) without any
//! Windows SDK dependency.

use super::traits::{CaptureError, CursorMetadata, CursorShapeKind};
use serde::{Deserialize, Serialize};

pub const S_OK: i32 = 0;
pub const DXGI_ERROR_WAIT_TIMEOUT: i32 = 0x887A_0027u32 as i32;
pub const DXGI_ERROR_ACCESS_LOST: i32 = 0x887A_0026u32 as i32;
pub const DXGI_ERROR_MODE_CHANGE_IN_PROGRESS: i32 = 0x887A_0025u32 as i32;
pub const DXGI_ERROR_DEVICE_REMOVED: i32 = 0x887A_0005u32 as i32;
pub const DXGI_ERROR_DEVICE_RESET: i32 = 0x887A_0007u32 as i32;
pub const DXGI_ERROR_UNSUPPORTED: i32 = 0x887A_0004u32 as i32;
pub const DXGI_ERROR_SESSION_DISCONNECTED: i32 = 0x887A_0028u32 as i32;
pub const E_INVALIDARG: i32 = 0x8007_0057u32 as i32;
pub const E_ACCESSDENIED: i32 = 0x8007_0005u32 as i32;

pub const DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME: u32 = 0x1;
pub const DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR: u32 = 0x2;
pub const DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR: u32 = 0x4;

pub const DEFAULT_DXGI_BASE_BACKOFF_MS: u64 = 50;
pub const DEFAULT_DXGI_MAX_BACKOFF_MS: u64 = 2_000;
pub const DEFAULT_DXGI_DESKTOP_RETRY_MS: u64 = 500;
pub const DEFAULT_DXGI_MAX_RECREATE_ATTEMPTS: u32 = 10;

/// 3-class DXGI HRESULT decision (plus `Fatal` for unexpected errors).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DxgiAction {
    NormalTimeout,
    RecreateDuplication,
    PauseAndWaitDesktop,
    Fatal(i32),
}

/// Classifies a DXGI `AcquireNextFrame` / `DuplicateOutput` HRESULT into one of
/// the 3 standard operational classes or `Fatal(hr)`.
pub fn classify_dxgi_hresult(hr: i32) -> DxgiAction {
    match hr {
        DXGI_ERROR_WAIT_TIMEOUT => DxgiAction::NormalTimeout,
        DXGI_ERROR_ACCESS_LOST
        | E_INVALIDARG
        | DXGI_ERROR_MODE_CHANGE_IN_PROGRESS
        | DXGI_ERROR_DEVICE_REMOVED
        | DXGI_ERROR_DEVICE_RESET => DxgiAction::RecreateDuplication,
        DXGI_ERROR_UNSUPPORTED | DXGI_ERROR_SESSION_DISCONNECTED | E_ACCESSDENIED => {
            DxgiAction::PauseAndWaitDesktop
        }
        other => DxgiAction::Fatal(other),
    }
}

/// Computes effective desktop `(width, height)` after applying DXGI output
/// rotation (`0`, `90`, `180`, `270` degrees clockwise).
pub const fn rotated_dims(width: u32, height: u32, rotation_degrees: u16) -> (u32, u32) {
    match rotation_degrees % 360 {
        90 | 270 => (height, width),
        _ => (width, height),
    }
}

/// Maps a point `(x, y)` in unrotated surface coordinates `(width, height)` to
/// rotated desktop coordinates according to DXGI rotation (`0`, `90`, `180`, `270`).
pub fn rotate_point(x: i32, y: i32, width: u32, height: u32, rotation_degrees: u16) -> (i32, i32) {
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

/// Platform-agnostic representation of Windows `LUID` (`LowPart: u32`, `HighPart: i32`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub struct DxgiAdapterLuid {
    pub low_part: u32,
    pub high_part: i32,
}

impl DxgiAdapterLuid {
    pub const fn new(low_part: u32, high_part: i32) -> Self {
        Self {
            low_part,
            high_part,
        }
    }

    pub const fn as_tuple(self) -> (u32, i32) {
        (self.low_part, self.high_part)
    }

    pub const fn as_u64(self) -> u64 {
        ((self.high_part as u32 as u64) << 32) | (self.low_part as u64)
    }

    pub const fn from_u64(raw: u64) -> Self {
        Self {
            low_part: (raw & 0xFFFF_FFFF) as u32,
            high_part: (raw >> 32) as u32 as i32,
        }
    }

    pub const fn is_zero(self) -> bool {
        self.low_part == 0 && self.high_part == 0
    }
}

/// Enumerated DXGI output (monitor) descriptor with owning GPU adapter LUID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DxgiOutputDescriptor {
    pub monitor_index: u32,
    pub adapter_index: u32,
    pub output_index: u32,
    pub adapter_luid: DxgiAdapterLuid,
    pub adapter_name: String,
    pub device_name: String,
    pub left: i32,
    pub top: i32,
    pub width: u32,
    pub height: u32,
    pub is_primary: bool,
    pub rotation_degrees: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DxgiPauseReason {
    Unsupported,
    SessionDisconnected,
    AccessDenied,
}

impl DxgiPauseReason {
    pub fn from_hresult(hr: i32) -> Option<Self> {
        match hr {
            DXGI_ERROR_UNSUPPORTED => Some(Self::Unsupported),
            DXGI_ERROR_SESSION_DISCONNECTED => Some(Self::SessionDisconnected),
            E_ACCESSDENIED => Some(Self::AccessDenied),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DxgiCapturePhase {
    Active,
    Recreating {
        backoff_ms: u64,
        attempt: u32,
    },
    DesktopPaused {
        reason: DxgiPauseReason,
        retry_after_ms: u64,
    },
    Failed {
        hresult: i32,
    },
}

/// Action returned by `DxgiCaptureStateMachine` after processing an HRESULT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DxgiTransitionOutcome {
    FrameReady,
    TimeoutNoChange,
    ScheduleRecreate {
        backoff_ms: u64,
        attempt: u32,
    },
    PauseDesktop {
        reason: DxgiPauseReason,
        retry_after_ms: u64,
    },
    Failed {
        hresult: i32,
        error: CaptureError,
    },
}

/// Cursor position & shape state tracked across DXGI frames (persists across
/// frames where only position or only shape changed).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CursorState {
    pub visible: bool,
    pub x: i32,
    pub y: i32,
    pub last_mouse_update_time: i64,
    pub hotspot_x: u32,
    pub hotspot_y: u32,
    pub shape_kind: Option<CursorShapeKind>,
    pub shape_width: u32,
    pub shape_height: u32,
    pub shape_pitch: u32,
    pub shape_bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CursorShapeUpdate {
    pub raw_shape_type: u32,
    pub width: u32,
    pub height: u32,
    pub pitch: u32,
    pub hotspot_x: u32,
    pub hotspot_y: u32,
    pub bytes: Vec<u8>,
}

impl CursorState {
    pub fn update_position(&mut self, x: i32, y: i32, visible: bool, update_time: i64) -> bool {
        if update_time == 0 {
            return false;
        }
        self.x = x;
        self.y = y;
        self.visible = visible;
        self.last_mouse_update_time = update_time;
        true
    }

    pub fn update_shape(&mut self, update: CursorShapeUpdate) -> Result<(), CaptureError> {
        let kind = parse_dxgi_cursor_shape_type(update.raw_shape_type)?;
        let required =
            expected_cursor_shape_bytes(kind, update.width, update.height, update.pitch)?;
        if update.bytes.len() != required {
            return Err(CaptureError::Fatal(format!(
                "DXGI cursor shape buffer len {} != required {required} for {kind:?}",
                update.bytes.len()
            )));
        }
        self.shape_kind = Some(kind);
        self.shape_width = update.width;
        self.shape_height = update.height;
        self.shape_pitch = update.pitch;
        self.hotspot_x = update.hotspot_x;
        self.hotspot_y = update.hotspot_y;
        self.shape_bytes = update.bytes;
        Ok(())
    }

    pub fn to_metadata(&self) -> CursorMetadata {
        CursorMetadata {
            visible: self.visible,
            x: self.x,
            y: self.y,
            hotspot_x: self.hotspot_x,
            hotspot_y: self.hotspot_y,
            shape_kind: self.shape_kind,
            shape_width: self.shape_width,
            shape_height: self.shape_height,
            shape_pitch: self.shape_pitch,
            shape_bytes: if self.shape_bytes.is_empty() {
                None
            } else {
                Some(self.shape_bytes.clone())
            },
        }
    }
}

pub fn parse_dxgi_cursor_shape_type(raw: u32) -> Result<CursorShapeKind, CaptureError> {
    match raw {
        DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME => Ok(CursorShapeKind::Monochrome),
        DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR => Ok(CursorShapeKind::Color),
        DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR => Ok(CursorShapeKind::MaskedColor),
        other => Err(CaptureError::Fatal(format!(
            "unsupported DXGI pointer shape type {other:#x}"
        ))),
    }
}

/// Computes exact required DXGI pointer shape buffer size in bytes.
///
/// For `DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME`, the buffer holds BOTH the
/// AND mask and XOR mask (`2 * pitch * height`); for `Color` and `MaskedColor`,
/// it holds `pitch * height`.
pub fn expected_cursor_shape_bytes(
    kind: CursorShapeKind,
    width: u32,
    height: u32,
    pitch: u32,
) -> Result<usize, CaptureError> {
    if width == 0 || height == 0 || pitch == 0 {
        return Err(CaptureError::Fatal(format!(
            "invalid DXGI cursor shape geometry {width}x{height} pitch={pitch}"
        )));
    }
    let min_pitch = match kind {
        CursorShapeKind::Monochrome => width.div_ceil(8),
        CursorShapeKind::Color | CursorShapeKind::MaskedColor => width
            .checked_mul(4)
            .ok_or_else(|| CaptureError::Fatal("cursor width overflow".into()))?,
    };
    if pitch < min_pitch {
        return Err(CaptureError::Fatal(format!(
            "DXGI cursor pitch {pitch} < minimum {min_pitch} for {kind:?}"
        )));
    }
    let plane_bytes = (pitch as usize)
        .checked_mul(height as usize)
        .ok_or_else(|| CaptureError::Fatal("cursor buffer size overflow".into()))?;
    match kind {
        CursorShapeKind::Monochrome => plane_bytes
            .checked_mul(2)
            .ok_or_else(|| CaptureError::Fatal("monochrome cursor buffer size overflow".into())),
        CursorShapeKind::Color | CursorShapeKind::MaskedColor => Ok(plane_bytes),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DxgiDirtyRect {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

impl DxgiDirtyRect {
    pub fn is_non_empty(&self) -> bool {
        self.right > self.left && self.bottom > self.top
    }

    pub fn width(&self) -> u32 {
        self.right.saturating_sub(self.left).max(0) as u32
    }

    pub fn height(&self) -> u32 {
        self.bottom.saturating_sub(self.top).max(0) as u32
    }

    pub fn clamp_to_bounds(&self, frame_width: u32, frame_height: u32) -> Option<Self> {
        let max_w = i32::try_from(frame_width).unwrap_or(i32::MAX);
        let max_h = i32::try_from(frame_height).unwrap_or(i32::MAX);
        let clamped = Self {
            left: self.left.clamp(0, max_w),
            top: self.top.clamp(0, max_h),
            right: self.right.clamp(0, max_w),
            bottom: self.bottom.clamp(0, max_h),
        };
        clamped.is_non_empty().then_some(clamped)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DxgiMoveRect {
    pub src_x: i32,
    pub src_y: i32,
    pub dst: DxgiDirtyRect,
}

impl DxgiMoveRect {
    /// Returns the source rectangle corresponding to this move rect (`src_x..src_x+dst.width`).
    pub fn src_rect(&self) -> DxgiDirtyRect {
        let w = i32::try_from(self.dst.width()).unwrap_or(i32::MAX);
        let h = i32::try_from(self.dst.height()).unwrap_or(i32::MAX);
        DxgiDirtyRect {
            left: self.src_x,
            top: self.src_y,
            right: self.src_x.saturating_add(w),
            bottom: self.src_y.saturating_add(h),
        }
    }
}

/// Computes the union bounding box of all valid dirty rects and BOTH source and
/// destination rectangles of all move rects, clamped to `frame_width x frame_height`.
pub fn merge_damage_bounding_box(
    dirty_rects: &[DxgiDirtyRect],
    move_rects: &[DxgiMoveRect],
    frame_width: u32,
    frame_height: u32,
) -> Option<DxgiDirtyRect> {
    let mut merged: Option<DxgiDirtyRect> = None;
    let all_rects = dirty_rects
        .iter()
        .copied()
        .chain(move_rects.iter().flat_map(|m| [m.src_rect(), m.dst]));
    for rect in all_rects {
        let Some(clamped) = rect.clamp_to_bounds(frame_width, frame_height) else {
            continue;
        };
        merged = Some(match merged {
            None => clamped,
            Some(acc) => DxgiDirtyRect {
                left: acc.left.min(clamped.left),
                top: acc.top.min(clamped.top),
                right: acc.right.max(clamped.right),
                bottom: acc.bottom.max(clamped.bottom),
            },
        });
    }
    merged
}

/// Platform-agnostic DXGI Desktop Duplication lifecycle state machine.
#[derive(Debug, Clone)]
pub struct DxgiCaptureStateMachine {
    phase: DxgiCapturePhase,
    outputs: Vec<DxgiOutputDescriptor>,
    active_monitor_index: u32,
    active_output_identity: Option<(String, DxgiAdapterLuid)>,
    active_adapter_luid: Option<DxgiAdapterLuid>,
    cursor: CursorState,
    consecutive_timeouts: u64,
    base_backoff_ms: u64,
    max_backoff_ms: u64,
    desktop_retry_ms: u64,
    max_recreate_attempts: u32,
}

impl Default for DxgiCaptureStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl DxgiCaptureStateMachine {
    pub fn new() -> Self {
        Self {
            phase: DxgiCapturePhase::Active,
            outputs: Vec::new(),
            active_monitor_index: 0,
            active_output_identity: None,
            active_adapter_luid: None,
            cursor: CursorState::default(),
            consecutive_timeouts: 0,
            base_backoff_ms: DEFAULT_DXGI_BASE_BACKOFF_MS,
            max_backoff_ms: DEFAULT_DXGI_MAX_BACKOFF_MS,
            desktop_retry_ms: DEFAULT_DXGI_DESKTOP_RETRY_MS,
            max_recreate_attempts: DEFAULT_DXGI_MAX_RECREATE_ATTEMPTS,
        }
    }

    pub fn with_backoff_policy(
        mut self,
        base_backoff_ms: u64,
        max_backoff_ms: u64,
        desktop_retry_ms: u64,
        max_recreate_attempts: u32,
    ) -> Self {
        self.base_backoff_ms = base_backoff_ms.max(1);
        self.max_backoff_ms = max_backoff_ms.max(self.base_backoff_ms);
        self.desktop_retry_ms = desktop_retry_ms.max(1);
        self.max_recreate_attempts = max_recreate_attempts.max(1);
        self
    }

    pub fn phase(&self) -> &DxgiCapturePhase {
        &self.phase
    }

    pub fn is_failed(&self) -> bool {
        matches!(self.phase, DxgiCapturePhase::Failed { .. })
    }

    /// Explicitly resets a terminal `Failed` state machine back to `Recreating`
    /// so caller-driven recovery can attempt fresh duplication initialization.
    pub fn reset(&mut self) {
        self.phase = DxgiCapturePhase::Recreating {
            backoff_ms: 0,
            attempt: 1,
        };
        self.consecutive_timeouts = 0;
        self.cursor = CursorState::default();
    }

    pub fn outputs(&self) -> &[DxgiOutputDescriptor] {
        &self.outputs
    }

    pub fn active_monitor_index(&self) -> u32 {
        self.active_monitor_index
    }

    pub fn active_adapter_luid(&self) -> Option<DxgiAdapterLuid> {
        self.active_adapter_luid
    }

    pub fn consecutive_timeouts(&self) -> u64 {
        self.consecutive_timeouts
    }

    pub fn cursor(&self) -> &CursorState {
        &self.cursor
    }

    pub fn cursor_mut(&mut self) -> &mut CursorState {
        &mut self.cursor
    }

    /// Updates the enumerated DXGI outputs list after initial discovery or monitor
    /// hotplug, tracking the previously selected output by stable `(device_name, adapter_luid)`
    /// first, then falling back to `monitor_index`, primary output, or first output.
    /// Resets `CursorState` whenever the resolved active output identity changes.
    pub fn set_outputs(&mut self, outputs: Vec<DxgiOutputDescriptor>) {
        let prev_identity = self.active_output_identity.clone();
        self.outputs = outputs;
        let matched = self
            .active_output_identity
            .as_ref()
            .and_then(|(dev, luid)| {
                self.outputs
                    .iter()
                    .find(|o| &o.device_name == dev && o.adapter_luid == *luid)
            })
            .or_else(|| {
                self.outputs
                    .iter()
                    .find(|o| o.monitor_index == self.active_monitor_index)
            })
            .or_else(|| self.outputs.iter().find(|o| o.is_primary))
            .or_else(|| self.outputs.first());

        if let Some(out) = matched {
            let new_identity = (out.device_name.clone(), out.adapter_luid);
            let changed = prev_identity.as_ref() != Some(&new_identity);
            self.active_monitor_index = out.monitor_index;
            self.active_adapter_luid = Some(out.adapter_luid);
            self.active_output_identity = Some(new_identity);
            if changed {
                self.cursor = CursorState::default();
            }
        } else {
            self.active_adapter_luid = None;
            self.active_output_identity = None;
            self.cursor = CursorState::default();
        }
    }

    pub fn select_monitor(
        &mut self,
        monitor_index: u32,
    ) -> Result<&DxgiOutputDescriptor, CaptureError> {
        let Some(pos) = self
            .outputs
            .iter()
            .position(|o| o.monitor_index == monitor_index)
        else {
            return Err(CaptureError::Fatal(format!(
                "DXGI monitor_index {monitor_index} not found (available: {})",
                self.outputs.len()
            )));
        };
        let new_identity = (
            self.outputs[pos].device_name.clone(),
            self.outputs[pos].adapter_luid,
        );
        let switched = self.active_output_identity.as_ref() != Some(&new_identity);
        self.active_monitor_index = monitor_index;
        self.active_adapter_luid = Some(self.outputs[pos].adapter_luid);
        self.active_output_identity = Some(new_identity);
        if switched {
            self.cursor = CursorState::default();
            if !self.is_failed() {
                self.phase = DxgiCapturePhase::Recreating {
                    backoff_ms: 0,
                    attempt: 1,
                };
            }
            self.consecutive_timeouts = 0;
        }
        Ok(&self.outputs[pos])
    }

    pub fn active_output(&self) -> Option<&DxgiOutputDescriptor> {
        if let Some((dev, luid)) = &self.active_output_identity {
            if let Some(out) = self
                .outputs
                .iter()
                .find(|o| &o.device_name == dev && o.adapter_luid == *luid)
            {
                return Some(out);
            }
        }
        self.outputs
            .iter()
            .find(|o| o.monitor_index == self.active_monitor_index)
    }

    fn compute_backoff_ms(&self, attempt: u32) -> u64 {
        let shift = attempt.saturating_sub(1).min(16);
        let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
        self.base_backoff_ms
            .saturating_mul(factor)
            .min(self.max_backoff_ms)
    }

    fn terminal_failed_outcome(hresult: i32) -> DxgiTransitionOutcome {
        DxgiTransitionOutcome::Failed {
            hresult,
            error: CaptureError::Fatal(format!(
                "DXGI capturer is in terminal Failed state (hr={:#010x}); explicit reset() required",
                hresult as u32
            )),
        }
    }

    pub fn on_frame_acquired(&mut self) -> DxgiTransitionOutcome {
        if let DxgiCapturePhase::Failed { hresult } = self.phase {
            return Self::terminal_failed_outcome(hresult);
        }
        self.phase = DxgiCapturePhase::Active;
        self.consecutive_timeouts = 0;
        DxgiTransitionOutcome::FrameReady
    }

    pub fn on_acquire_hresult(&mut self, hr: i32) -> DxgiTransitionOutcome {
        if let DxgiCapturePhase::Failed { hresult } = self.phase {
            return Self::terminal_failed_outcome(hresult);
        }
        if hr == S_OK {
            return self.on_frame_acquired();
        }
        match classify_dxgi_hresult(hr) {
            DxgiAction::NormalTimeout => {
                self.consecutive_timeouts = self.consecutive_timeouts.saturating_add(1);
                DxgiTransitionOutcome::TimeoutNoChange
            }
            DxgiAction::RecreateDuplication => {
                let next_attempt = match self.phase {
                    DxgiCapturePhase::Recreating { attempt, .. } => attempt.saturating_add(1),
                    _ => 1,
                };
                if next_attempt > self.max_recreate_attempts {
                    self.phase = DxgiCapturePhase::Failed { hresult: hr };
                    return DxgiTransitionOutcome::Failed {
                        hresult: hr,
                        error: CaptureError::Fatal(format!(
                            "DXGI duplication recreate exhausted {} attempts (last hr={:#010x})",
                            self.max_recreate_attempts, hr as u32
                        )),
                    };
                }
                let backoff_ms = self.compute_backoff_ms(next_attempt);
                self.phase = DxgiCapturePhase::Recreating {
                    backoff_ms,
                    attempt: next_attempt,
                };
                self.consecutive_timeouts = 0;
                DxgiTransitionOutcome::ScheduleRecreate {
                    backoff_ms,
                    attempt: next_attempt,
                }
            }
            DxgiAction::PauseAndWaitDesktop => {
                let reason =
                    DxgiPauseReason::from_hresult(hr).unwrap_or(DxgiPauseReason::Unsupported);
                let retry_after_ms = self.desktop_retry_ms;
                self.phase = DxgiCapturePhase::DesktopPaused {
                    reason,
                    retry_after_ms,
                };
                self.consecutive_timeouts = 0;
                DxgiTransitionOutcome::PauseDesktop {
                    reason,
                    retry_after_ms,
                }
            }
            DxgiAction::Fatal(code) => {
                self.phase = DxgiCapturePhase::Failed { hresult: code };
                DxgiTransitionOutcome::Failed {
                    hresult: code,
                    error: CaptureError::Fatal(format!(
                        "unexpected fatal DXGI HRESULT {:#010x}",
                        code as u32
                    )),
                }
            }
        }
    }

    pub fn on_recreate_succeeded(&mut self) -> Result<(), CaptureError> {
        if let DxgiCapturePhase::Failed { hresult } = self.phase {
            return Err(CaptureError::Fatal(format!(
                "cannot mark recreate succeeded from terminal Failed state (hr={:#010x}); call reset() first",
                hresult as u32
            )));
        }
        self.phase = DxgiCapturePhase::Active;
        self.consecutive_timeouts = 0;
        Ok(())
    }

    pub fn on_recreate_failed(&mut self, hr: i32) -> DxgiTransitionOutcome {
        self.on_acquire_hresult(hr)
    }

    /// Transitions `DesktopPaused` -> `Recreating { backoff_ms: 0, attempt: 1 }`
    /// so caller MUST recreate `IDXGIOutputDuplication` and call `on_recreate_succeeded()`
    /// before resuming `Active` capture (never reuses an invalidated duplication!).
    pub fn on_desktop_resumed(&mut self) -> Result<(), CaptureError> {
        if let DxgiCapturePhase::Failed { hresult } = self.phase {
            return Err(CaptureError::Fatal(format!(
                "cannot resume desktop from terminal Failed state (hr={:#010x}); call reset() first",
                hresult as u32
            )));
        }
        if matches!(self.phase, DxgiCapturePhase::DesktopPaused { .. }) {
            self.phase = DxgiCapturePhase::Recreating {
                backoff_ms: 0,
                attempt: 1,
            };
            self.consecutive_timeouts = 0;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_outputs() -> Vec<DxgiOutputDescriptor> {
        vec![
            DxgiOutputDescriptor {
                monitor_index: 0,
                adapter_index: 0,
                output_index: 0,
                adapter_luid: DxgiAdapterLuid::new(0x1111, 0),
                adapter_name: "GPU-A".into(),
                device_name: r"\\.\DISPLAY1".into(),
                left: 0,
                top: 0,
                width: 1920,
                height: 1080,
                is_primary: true,
                rotation_degrees: 0,
            },
            DxgiOutputDescriptor {
                monitor_index: 1,
                adapter_index: 1,
                output_index: 0,
                adapter_luid: DxgiAdapterLuid::new(0x2222, 1),
                adapter_name: "GPU-B".into(),
                device_name: r"\\.\DISPLAY2".into(),
                left: 1920,
                top: 0,
                width: 2560,
                height: 1440,
                is_primary: false,
                rotation_degrees: 0,
            },
        ]
    }

    #[test]
    fn hresult_classifier_covers_all_three_classes_and_fatal() {
        assert_eq!(
            classify_dxgi_hresult(DXGI_ERROR_WAIT_TIMEOUT),
            DxgiAction::NormalTimeout
        );
        for hr in [
            DXGI_ERROR_ACCESS_LOST,
            E_INVALIDARG,
            DXGI_ERROR_MODE_CHANGE_IN_PROGRESS,
            DXGI_ERROR_DEVICE_REMOVED,
            DXGI_ERROR_DEVICE_RESET,
        ] {
            assert_eq!(
                classify_dxgi_hresult(hr),
                DxgiAction::RecreateDuplication,
                "expected RecreateDuplication for {hr:#010x}"
            );
        }
        for hr in [
            DXGI_ERROR_UNSUPPORTED,
            DXGI_ERROR_SESSION_DISCONNECTED,
            E_ACCESSDENIED,
        ] {
            assert_eq!(
                classify_dxgi_hresult(hr),
                DxgiAction::PauseAndWaitDesktop,
                "expected PauseAndWaitDesktop for {hr:#010x}"
            );
        }
        let unexpected = 0x8000_FFFFu32 as i32;
        assert_eq!(
            classify_dxgi_hresult(unexpected),
            DxgiAction::Fatal(unexpected)
        );
    }

    #[test]
    fn state_machine_backoff_terminal_failed_and_desktop_resume_recreate() {
        let mut sm = DxgiCaptureStateMachine::new().with_backoff_policy(50, 200, 500, 3);
        assert_eq!(sm.phase(), &DxgiCapturePhase::Active);

        assert_eq!(
            sm.on_acquire_hresult(DXGI_ERROR_WAIT_TIMEOUT),
            DxgiTransitionOutcome::TimeoutNoChange
        );
        assert_eq!(sm.consecutive_timeouts(), 1);
        assert_eq!(sm.phase(), &DxgiCapturePhase::Active);

        assert_eq!(
            sm.on_acquire_hresult(DXGI_ERROR_ACCESS_LOST),
            DxgiTransitionOutcome::ScheduleRecreate {
                backoff_ms: 50,
                attempt: 1
            }
        );
        assert_eq!(
            sm.on_recreate_failed(DXGI_ERROR_MODE_CHANGE_IN_PROGRESS),
            DxgiTransitionOutcome::ScheduleRecreate {
                backoff_ms: 100,
                attempt: 2
            }
        );
        assert_eq!(
            sm.on_recreate_failed(DXGI_ERROR_DEVICE_RESET),
            DxgiTransitionOutcome::ScheduleRecreate {
                backoff_ms: 200,
                attempt: 3
            }
        );
        assert!(matches!(
            sm.on_recreate_failed(DXGI_ERROR_DEVICE_REMOVED),
            DxgiTransitionOutcome::Failed {
                hresult: DXGI_ERROR_DEVICE_REMOVED,
                ..
            }
        ));
        assert!(sm.is_failed());

        // Failed state is strictly terminal until explicit reset()!
        assert!(matches!(
            sm.on_frame_acquired(),
            DxgiTransitionOutcome::Failed { .. }
        ));
        assert!(matches!(
            sm.on_acquire_hresult(S_OK),
            DxgiTransitionOutcome::Failed { .. }
        ));
        assert!(sm.on_recreate_succeeded().is_err());
        assert!(sm.on_desktop_resumed().is_err());

        // Explicit reset() enables recreate -> Active.
        sm.reset();
        assert!(matches!(
            sm.phase(),
            DxgiCapturePhase::Recreating { attempt: 1, .. }
        ));
        sm.on_recreate_succeeded().unwrap();
        assert_eq!(sm.phase(), &DxgiCapturePhase::Active);

        // UAC / lock screen pause -> on_desktop_resumed transitions to Recreating, NOT Active!
        assert_eq!(
            sm.on_acquire_hresult(DXGI_ERROR_SESSION_DISCONNECTED),
            DxgiTransitionOutcome::PauseDesktop {
                reason: DxgiPauseReason::SessionDisconnected,
                retry_after_ms: 500
            }
        );
        sm.on_desktop_resumed().unwrap();
        assert_eq!(
            sm.phase(),
            &DxgiCapturePhase::Recreating {
                backoff_ms: 0,
                attempt: 1
            }
        );
        sm.on_recreate_succeeded().unwrap();
        assert_eq!(sm.phase(), &DxgiCapturePhase::Active);
    }

    #[test]
    fn monitor_hotplug_tracks_stable_device_luid_and_resets_cursor_on_switch() {
        let mut sm = DxgiCaptureStateMachine::new();
        sm.set_outputs(sample_outputs());
        sm.select_monitor(1).unwrap();
        sm.cursor_mut().update_position(500, 600, true, 100);
        assert_eq!(sm.cursor().x, 500);

        // Hotplug reorders DISPLAY2 from monitor_index 1 -> monitor_index 0: stable (device_name, luid) stays selected!
        let mut reordered = vec![sample_outputs()[1].clone(), sample_outputs()[0].clone()];
        reordered[0].monitor_index = 0;
        reordered[1].monitor_index = 1;
        sm.set_outputs(reordered);
        assert_eq!(sm.active_monitor_index(), 0);
        assert_eq!(
            sm.active_output().unwrap().device_name,
            r"\\.\DISPLAY2"
        );
        assert_eq!(sm.cursor().x, 500);

        // Switching to DISPLAY1 resets CursorState!
        sm.select_monitor(1).unwrap();
        assert_eq!(sm.cursor().x, 0);
        assert_eq!(sm.cursor().last_mouse_update_time, 0);
        assert!(sm.select_monitor(99).is_err());
    }

    #[test]
    fn rotation_helpers_transform_dims_and_points_accurately() {
        assert_eq!(rotated_dims(1920, 1080, 0), (1920, 1080));
        assert_eq!(rotated_dims(1920, 1080, 90), (1080, 1920));
        assert_eq!(rotated_dims(1920, 1080, 180), (1920, 1080));
        assert_eq!(rotated_dims(1920, 1080, 270), (1080, 1920));

        assert_eq!(rotate_point(10, 20, 100, 50, 0), (10, 20));
        assert_eq!(rotate_point(10, 20, 100, 50, 90), (29, 10));
        assert_eq!(rotate_point(10, 20, 100, 50, 180), (89, 29));
        assert_eq!(rotate_point(10, 20, 100, 50, 270), (20, 89));
    }

    #[test]
    fn luid_u64_round_trip_preserves_signed_high_part() {
        let luid = DxgiAdapterLuid::new(0xDEAD_BEEF, -42);
        let packed = luid.as_u64();
        assert_eq!(DxgiAdapterLuid::from_u64(packed), luid);
        assert_eq!(luid.as_tuple(), (0xDEAD_BEEF, -42));
    }

    #[test]
    fn cursor_state_updates_position_and_validates_monochrome_and_color_shapes() {
        let mut c = CursorState::default();
        assert!(!c.update_position(10, 20, true, 0));
        assert!(c.update_position(120, 240, true, 999));
        assert_eq!((c.x, c.y, c.visible), (120, 240, true));

        // Valid 16x16 color cursor (pitch = 64, exact bytes = 1024)
        c.update_shape(CursorShapeUpdate {
            raw_shape_type: DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR,
            width: 16,
            height: 16,
            pitch: 64,
            hotspot_x: 2,
            hotspot_y: 3,
            bytes: vec![0xAA; 1024],
        })
        .unwrap();
        let meta = c.to_metadata();
        assert_eq!(meta.shape_kind, Some(CursorShapeKind::Color));
        assert_eq!(meta.hotspot_x, 2);
        assert_eq!(meta.hotspot_y, 3);
        assert_eq!(meta.shape_bytes.as_ref().map(Vec::len), Some(1024));

        // Monochrome cursor (16x32, pitch=2): MUST require 2 * pitch * height = 128 bytes (AND + XOR masks)!
        assert!(c
            .update_shape(CursorShapeUpdate {
                raw_shape_type: DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME,
                width: 16,
                height: 32,
                pitch: 2,
                hotspot_x: 0,
                hotspot_y: 0,
                bytes: vec![0x55; 64],
            })
            .is_err());
        c.update_shape(CursorShapeUpdate {
            raw_shape_type: DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MONOCHROME,
            width: 16,
            height: 32,
            pitch: 2,
            hotspot_x: 0,
            hotspot_y: 0,
            bytes: vec![0x55; 128],
        })
        .unwrap();
        assert_eq!(c.shape_kind, Some(CursorShapeKind::Monochrome));
        assert_eq!(c.shape_bytes.len(), 128);

        // Truncated or oversized buffer rejected (strict len != required)
        assert!(c
            .update_shape(CursorShapeUpdate {
                raw_shape_type: DXGI_OUTDUPL_POINTER_SHAPE_TYPE_MASKED_COLOR,
                width: 16,
                height: 16,
                pitch: 64,
                hotspot_x: 0,
                hotspot_y: 0,
                bytes: vec![0; 100],
            })
            .is_err());
        assert!(c
            .update_shape(CursorShapeUpdate {
                raw_shape_type: DXGI_OUTDUPL_POINTER_SHAPE_TYPE_COLOR,
                width: 16,
                height: 16,
                pitch: 64,
                hotspot_x: 0,
                hotspot_y: 0,
                bytes: vec![0; 2048],
            })
            .is_err());
        // Unknown shape type rejected
        assert!(c
            .update_shape(CursorShapeUpdate {
                raw_shape_type: 0x99,
                width: 16,
                height: 16,
                pitch: 64,
                hotspot_x: 0,
                hotspot_y: 0,
                bytes: vec![0; 1024],
            })
            .is_err());
    }

    #[test]
    fn dirty_and_move_rect_unions_src_and_dst_and_avoids_i32_overflow() {
        // Extreme coordinates must not panic on subtraction.
        let extreme = DxgiDirtyRect {
            left: i32::MIN,
            top: i32::MIN,
            right: i32::MAX,
            bottom: i32::MAX,
        };
        assert_eq!(extreme.width(), i32::MAX as u32);
        assert_eq!(extreme.height(), i32::MAX as u32);

        // Move rect whose src=(10, 10, 60, 50) lies far from dst=(500, 400, 550, 440):
        // bounding box MUST union BOTH src AND dst!
        let moves = [DxgiMoveRect {
            src_x: 10,
            src_y: 10,
            dst: DxgiDirtyRect {
                left: 500,
                top: 400,
                right: 550,
                bottom: 440,
            },
        }];
        let merged = merge_damage_bounding_box(&[], &moves, 1920, 1080).unwrap();
        assert_eq!(
            merged,
            DxgiDirtyRect {
                left: 10,
                top: 10,
                right: 550,
                bottom: 440,
            }
        );
    }
}
