// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::video::{generate_animated_i420, I420Frame, MAX_FRAME_DIM};
use scrap::{
    ABGRToI420, ARGBToI420, Capturer, Display, Frame as ScrapFrame, Pixfmt, TraitCapturer,
    TraitPixelBuffer,
};
use std::{
    fmt, io,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::watch;

pub const MIN_CAPTURE_DIM: usize = 32;
pub const DEFAULT_SYNTHETIC_WIDTH: usize = 1280;
pub const DEFAULT_SYNTHETIC_HEIGHT: usize = 720;
pub const ZERO_VARIANCE_WARN_THRESHOLD: u32 = 10;

#[derive(Debug, Clone)]
pub struct CapturedFrame {
    pub seq: u64,
    pub captured_at_ms: u64,
    pub frame: Arc<I420Frame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    PermissionDenied(String),
    Unavailable(String),
    InvalidDimensions(String),
    Backend(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg) => write!(f, "screen capture permission denied: {msg}"),
            Self::Unavailable(msg) => write!(f, "screen capture unavailable: {msg}"),
            Self::InvalidDimensions(msg) => write!(f, "invalid capture dimensions: {msg}"),
            Self::Backend(msg) => write!(f, "screen capture backend error: {msg}"),
        }
    }
}

impl std::error::Error for CaptureError {}

pub trait ScreenCaptureSource: Send {
    fn dimensions(&self) -> (usize, usize);

    /// Returns the next captured frame, or `Ok(None)` on `WouldBlock` / unchanged display.
    fn next_frame(&mut self) -> Result<Option<CapturedFrame>, CaptureError>;

    fn zero_variance_warning(&self) -> bool {
        false
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Crops odd dimensions down by 1 pixel to even and validates `[MIN_CAPTURE_DIM, MAX_FRAME_DIM]`.
pub fn crop_and_validate_dimensions(
    raw_width: usize,
    raw_height: usize,
) -> Result<(usize, usize), CaptureError> {
    let w = raw_width & !1;
    let h = raw_height & !1;
    if w < MIN_CAPTURE_DIM || h < MIN_CAPTURE_DIM || w > MAX_FRAME_DIM || h > MAX_FRAME_DIM {
        return Err(CaptureError::InvalidDimensions(format!(
            "capture dimensions raw={raw_width}x{raw_height} cropped={w}x{h} outside [{MIN_CAPTURE_DIM}, {MAX_FRAME_DIM}]"
        )));
    }
    Ok((w, h))
}

/// Computes exact population variance of the Y luma plane.
pub fn compute_y_variance(frame: &I420Frame) -> f64 {
    if frame.y.is_empty() {
        return 0.0;
    }
    let n = frame.y.len() as f64;
    let mut sum = 0.0f64;
    let mut sum_sq = 0.0f64;
    for &px in &frame.y {
        let v = px as f64;
        sum += v;
        sum_sq += v * v;
    }
    let mean = sum / n;
    (sum_sq / n - mean * mean).max(0.0)
}

/// Draws a deterministic high-contrast target marker centered at `(mx, my)` on `frame`:
/// - Outer 32x32 dark border (`Y = 18`)
/// - Inner 20x20 bright core (`Y = 248`) with distinct magenta chroma (`U = 40, V = 220`)
/// - Bright crosshair arms inside the dark frame
pub fn overlay_visual_marker(frame: &mut I420Frame, mx: i32, my: i32) {
    let w = frame.width as i32;
    let h = frame.height as i32;
    if w < 32 || h < 32 {
        return;
    }
    let cx = mx.clamp(16, w - 16);
    let cy = my.clamp(16, h - 16);

    let y_start = (cy - 16).max(0);
    let y_end = (cy + 16).min(h);
    let x_start = (cx - 16).max(0);
    let x_end = (cx + 16).min(w);

    for py in y_start..y_end {
        let row_off = (py as usize) * frame.width;
        let dy = (py - cy).abs();
        for px in x_start..x_end {
            let dx = (px - cx).abs();
            let val = if dx < 10 && dy < 10 {
                248u8
            } else if dx <= 1 || dy <= 1 {
                244u8
            } else {
                18u8
            };
            frame.y[row_off + (px as usize)] = val;
        }
    }

    let uv_w = frame.width / 2;
    let uv_h = frame.height / 2;
    let uv_x0 = ((cx - 10).max(0) as usize) / 2;
    let uv_x1 = (((cx + 10).min(w) as usize) / 2).min(uv_w);
    let uv_y0 = ((cy - 10).max(0) as usize) / 2;
    let uv_y1 = (((cy + 10).min(h) as usize) / 2).min(uv_h);
    for row in uv_y0..uv_y1 {
        let row_off = row * uv_w;
        for col in uv_x0..uv_x1 {
            frame.u[row_off + col] = 40;
            frame.v[row_off + col] = 220;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct VisualMarkerCheck {
    pub detected: bool,
    pub inner_mean_y: f64,
    pub border_mean_y: f64,
    pub inner_mean_v: f64,
}

/// Checks whether a decoded I420 frame contains the deterministic marker centered at `(mx, my)`.
pub fn detect_visual_marker(frame: &I420Frame, mx: i32, my: i32) -> VisualMarkerCheck {
    let w = frame.width as i32;
    let h = frame.height as i32;
    if w < 32 || h < 32 {
        return VisualMarkerCheck {
            detected: false,
            inner_mean_y: 0.0,
            border_mean_y: 0.0,
            inner_mean_v: 0.0,
        };
    }
    let cx = mx.clamp(16, w - 16);
    let cy = my.clamp(16, h - 16);

    let mut inner_sum = 0.0f64;
    let mut inner_cnt = 0usize;
    let mut border_sum = 0.0f64;
    let mut border_cnt = 0usize;

    for py in (cy - 15).max(0)..(cy + 15).min(h) {
        let row_off = (py as usize) * frame.width;
        let dy = (py - cy).abs();
        for px in (cx - 15).max(0)..(cx + 15).min(w) {
            let dx = (px - cx).abs();
            let v = frame.y[row_off + (px as usize)] as f64;
            if dx <= 6 && dy <= 6 {
                inner_sum += v;
                inner_cnt += 1;
            } else if (dx >= 12 || dy >= 12) && dx > 2 && dy > 2 {
                border_sum += v;
                border_cnt += 1;
            }
        }
    }

    let uv_w = frame.width / 2;
    let uv_h = frame.height / 2;
    let uv_x0 = ((cx - 6).max(0) as usize) / 2;
    let uv_x1 = (((cx + 6).min(w) as usize) / 2).min(uv_w);
    let uv_y0 = ((cy - 6).max(0) as usize) / 2;
    let uv_y1 = (((cy + 6).min(h) as usize) / 2).min(uv_h);
    let mut v_sum = 0.0f64;
    let mut v_cnt = 0usize;
    for row in uv_y0..uv_y1 {
        let row_off = row * uv_w;
        for col in uv_x0..uv_x1 {
            v_sum += frame.v[row_off + col] as f64;
            v_cnt += 1;
        }
    }

    let inner_mean_y = if inner_cnt > 0 {
        inner_sum / (inner_cnt as f64)
    } else {
        0.0
    };
    let border_mean_y = if border_cnt > 0 {
        border_sum / (border_cnt as f64)
    } else {
        255.0
    };
    let inner_mean_v = if v_cnt > 0 {
        v_sum / (v_cnt as f64)
    } else {
        128.0
    };

    let detected = inner_mean_y >= 215.0 && border_mean_y <= 65.0 && inner_mean_v >= 180.0;
    VisualMarkerCheck {
        detected,
        inner_mean_y,
        border_mean_y,
        inner_mean_v,
    }
}

pub type SharedVisualMarker = Arc<Mutex<Option<(i32, i32)>>>;

/// Deterministic animated I420 capture source with optional HID-driven visual marker overlay.
pub struct SyntheticAnimatedSource {
    width: usize,
    height: usize,
    seq: u64,
    last_ts_ms: u64,
    frame_interval: Duration,
    last_emit: Option<Instant>,
    visual_marker: Option<SharedVisualMarker>,
}

impl SyntheticAnimatedSource {
    pub fn new(
        width: usize,
        height: usize,
        fps: u32,
        visual_marker: Option<SharedVisualMarker>,
    ) -> Result<Self, CaptureError> {
        let (w, h) = crop_and_validate_dimensions(width, height)?;
        let fps = fps.max(1);
        Ok(Self {
            width: w,
            height: h,
            seq: 0,
            last_ts_ms: 0,
            frame_interval: Duration::from_nanos(1_000_000_000u64 / u64::from(fps)),
            last_emit: None,
            visual_marker,
        })
    }

    pub fn new_720p(fps: u32, visual_marker: Option<SharedVisualMarker>) -> Self {
        Self {
            width: DEFAULT_SYNTHETIC_WIDTH,
            height: DEFAULT_SYNTHETIC_HEIGHT,
            seq: 0,
            last_ts_ms: 0,
            frame_interval: Duration::from_nanos(1_000_000_000u64 / u64::from(fps.max(1))),
            last_emit: None,
            visual_marker,
        }
    }
}

impl ScreenCaptureSource for SyntheticAnimatedSource {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    fn next_frame(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        if let Some(prev) = self.last_emit {
            let elapsed = prev.elapsed();
            if elapsed < self.frame_interval {
                // Return Ok(None) (WouldBlock) until next frame interval so the capture thread
                // checks `stop_flag` promptly without long blocking sleeps.
                return Ok(None);
            }
        }
        self.last_emit = Some(Instant::now());
        let frame_idx = self.seq as u32;
        self.seq = self.seq.saturating_add(1);
        let now = epoch_ms().max(self.last_ts_ms);
        self.last_ts_ms = now;

        let mut frame = generate_animated_i420(self.width, self.height, frame_idx);
        if let Some(marker) = &self.visual_marker {
            if let Ok(guard) = marker.lock() {
                if let Some((mx, my)) = *guard {
                    overlay_visual_marker(&mut frame, mx, my);
                }
            }
        }

        Ok(Some(CapturedFrame {
            seq: self.seq,
            captured_at_ms: now,
            frame: Arc::new(frame),
        }))
    }
}

#[cfg(target_os = "macos")]
mod macos_tcc {
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        // CoreGraphics `boolean_t` is C `unsigned int` (`u32`).
        fn CGPreflightScreenCaptureAccess() -> u32;
    }

    pub fn preflight_screen_capture() -> bool {
        unsafe { CGPreflightScreenCaptureAccess() != 0 }
    }
}

/// Pure-Rust BT.601 studio-swing BGRA->I420 conversion helper for non-standard formats and tests.
pub fn bgra_to_i420_bt601(
    bgra: &[u8],
    stride: usize,
    raw_width: usize,
    raw_height: usize,
) -> Result<I420Frame, CaptureError> {
    let (w, h) = crop_and_validate_dimensions(raw_width, raw_height)?;
    let min_row_bytes = w
        .checked_mul(4)
        .ok_or_else(|| CaptureError::InvalidDimensions("BGRA row byte overflow".into()))?;
    if stride < min_row_bytes {
        return Err(CaptureError::InvalidDimensions(format!(
            "BGRA stride {stride} smaller than row bytes {min_row_bytes}"
        )));
    }
    let needed = stride
        .checked_mul(h.saturating_sub(1))
        .and_then(|v| v.checked_add(min_row_bytes))
        .ok_or_else(|| CaptureError::InvalidDimensions("BGRA buffer size overflow".into()))?;
    if bgra.len() < needed {
        return Err(CaptureError::Backend(format!(
            "BGRA buffer truncated: {} < {needed}",
            bgra.len()
        )));
    }

    let uv_w = w / 2;
    let uv_h = h / 2;
    let mut y = vec![0u8; w * h];
    let mut u = vec![128u8; uv_w * uv_h];
    let mut v = vec![128u8; uv_w * uv_h];

    for row in 0..h {
        let src_row = &bgra[row * stride..row * stride + min_row_bytes];
        let y_row = &mut y[row * w..(row + 1) * w];
        for col in 0..w {
            let b = i32::from(src_row[col * 4]);
            let g = i32::from(src_row[col * 4 + 1]);
            let r = i32::from(src_row[col * 4 + 2]);
            let y_val = ((66 * r + 129 * g + 25 * b + 128) >> 8) + 16;
            y_row[col] = y_val.clamp(0, 255) as u8;
        }
    }

    for row in 0..uv_h {
        let r0 = &bgra[(row * 2) * stride..(row * 2) * stride + min_row_bytes];
        let r1 = &bgra[(row * 2 + 1) * stride..(row * 2 + 1) * stride + min_row_bytes];
        let u_row = &mut u[row * uv_w..(row + 1) * uv_w];
        let v_row = &mut v[row * uv_w..(row + 1) * uv_w];
        for col in 0..uv_w {
            let c0 = col * 8;
            let c1 = c0 + 4;
            let b = (i32::from(r0[c0]) + i32::from(r0[c1]) + i32::from(r1[c0]) + i32::from(r1[c1]) + 2) >> 2;
            let g = (i32::from(r0[c0 + 1])
                + i32::from(r0[c1 + 1])
                + i32::from(r1[c0 + 1])
                + i32::from(r1[c1 + 1])
                + 2)
                >> 2;
            let r = (i32::from(r0[c0 + 2])
                + i32::from(r0[c1 + 2])
                + i32::from(r1[c0 + 2])
                + i32::from(r1[c1 + 2])
                + 2)
                >> 2;
            let u_val = ((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128;
            let v_val = ((112 * r - 94 * g - 18 * b + 128) >> 8) + 128;
            u_row[col] = u_val.clamp(0, 255) as u8;
            v_row[col] = v_val.clamp(0, 255) as u8;
        }
    }

    I420Frame::new(w, h, y, u, v).map_err(|e| CaptureError::Backend(e.to_string()))
}

fn convert_pixel_buffer_to_i420(
    src: &[u8],
    stride: usize,
    raw_width: usize,
    raw_height: usize,
    pixfmt: Pixfmt,
) -> Result<I420Frame, CaptureError> {
    let (w, h) = crop_and_validate_dimensions(raw_width, raw_height)?;
    let bpp = pixfmt.bytes_per_pixel();
    if bpp != 4 {
        return Err(CaptureError::Backend(format!(
            "unsupported captured pixel format {pixfmt:?}"
        )));
    }
    let min_row_bytes = w
        .checked_mul(4)
        .ok_or_else(|| CaptureError::InvalidDimensions("row byte length overflow".into()))?;
    if stride < min_row_bytes {
        return Err(CaptureError::InvalidDimensions(format!(
            "captured stride {stride} < row bytes {min_row_bytes}"
        )));
    }
    let needed = stride
        .checked_mul(h.saturating_sub(1))
        .and_then(|v| v.checked_add(min_row_bytes))
        .ok_or_else(|| CaptureError::InvalidDimensions("pixel buffer length overflow".into()))?;
    if src.len() < needed {
        return Err(CaptureError::Backend(format!(
            "captured pixel buffer truncated: {} < {needed}",
            src.len()
        )));
    }

    let uv_w = w / 2;
    let uv_h = h / 2;
    let mut y = vec![0u8; w * h];
    let mut u = vec![0u8; uv_w * uv_h];
    let mut v = vec![0u8; uv_w * uv_h];

    let rc = match pixfmt {
        Pixfmt::BGRA => unsafe {
            ARGBToI420(
                src.as_ptr(),
                stride as i32,
                y.as_mut_ptr(),
                w as i32,
                u.as_mut_ptr(),
                uv_w as i32,
                v.as_mut_ptr(),
                uv_w as i32,
                w as i32,
                h as i32,
            )
        },
        Pixfmt::RGBA => unsafe {
            ABGRToI420(
                src.as_ptr(),
                stride as i32,
                y.as_mut_ptr(),
                w as i32,
                u.as_mut_ptr(),
                uv_w as i32,
                v.as_mut_ptr(),
                uv_w as i32,
                w as i32,
                h as i32,
            )
        },
        other => {
            return Err(CaptureError::Backend(format!(
                "unsupported pixel format {other:?} for I420 conversion"
            )));
        }
    };
    if rc != 0 {
        return Err(CaptureError::Backend(format!(
            "libyuv BGRA/RGBA->I420 returned error code {rc}"
        )));
    }
    I420Frame::new(w, h, y, u, v).map_err(|e| CaptureError::Backend(e.to_string()))
}

struct SendCapturer(Capturer);

// SAFETY: `scrap::Capturer` is only ever accessed via `&mut self` on a single owner thread
// (transferred once into the dedicated capture thread and never shared concurrently).
unsafe impl Send for SendCapturer {}

fn panic_payload_to_string(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "unknown FFI panic".to_string()
    }
}

/// Real OS screen capture source backed by `scrap::Display::primary()`, `scrap::Capturer`,
/// and `libyuv` BGRA-to-I420 conversion, with macOS TCC preflight, panic containment,
/// odd-dimension cropping, and consecutive zero-variance detection.
pub struct ScrapDisplaySource {
    capturer: SendCapturer,
    width: usize,
    height: usize,
    seq: u64,
    last_ts_ms: u64,
    consecutive_zero_variance: u32,
    zero_variance_warning: bool,
}

impl ScrapDisplaySource {
    pub fn new() -> Result<Self, CaptureError> {
        #[cfg(target_os = "macos")]
        {
            if !macos_tcc::preflight_screen_capture() {
                return Err(CaptureError::PermissionDenied(
                    "macOS Screen Recording permission denied (CGPreflightScreenCaptureAccess=false)"
                        .into(),
                ));
            }
        }

        let created = catch_unwind(AssertUnwindSafe(|| -> Result<(Capturer, usize, usize), CaptureError> {
            let display = Display::primary()
                .map_err(|e| CaptureError::Unavailable(format!("Display::primary failed: {e}")))?;
            let (width, height) = crop_and_validate_dimensions(display.width(), display.height())?;
            let capturer = Capturer::new(display)
                .map_err(|e| CaptureError::Unavailable(format!("Capturer::new failed: {e}")))?;
            Ok((capturer, width, height))
        }));

        let (mut capturer, width, height) = match created {
            Ok(Ok(v)) => v,
            Ok(Err(e)) => return Err(e),
            Err(payload) => {
                return Err(CaptureError::Unavailable(format!(
                    "FFI panic during capture initialization: {}",
                    panic_payload_to_string(payload)
                )));
            }
        };

        // Non-blocking first-frame panic probe (WouldBlock is expected immediately after stream start).
        let probe = catch_unwind(AssertUnwindSafe(|| {
            capturer.frame(Duration::from_millis(1)).map(|_| ())
        }));
        match probe {
            Ok(Ok(())) => {}
            Ok(Err(e)) if e.kind() == io::ErrorKind::WouldBlock => {}
            Ok(Err(e)) => {
                return Err(CaptureError::Unavailable(format!(
                    "initial capture frame probe failed: {e}"
                )));
            }
            Err(payload) => {
                return Err(CaptureError::Unavailable(format!(
                    "FFI panic during first-frame capture probe: {}",
                    panic_payload_to_string(payload)
                )));
            }
        }

        Ok(Self {
            capturer: SendCapturer(capturer),
            width,
            height,
            seq: 0,
            last_ts_ms: 0,
            consecutive_zero_variance: 0,
            zero_variance_warning: false,
        })
    }

    pub fn consecutive_zero_variance(&self) -> u32 {
        self.consecutive_zero_variance
    }
}

impl ScreenCaptureSource for ScrapDisplaySource {
    fn dimensions(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    fn zero_variance_warning(&self) -> bool {
        self.zero_variance_warning
    }

    fn next_frame(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
        let captured = catch_unwind(AssertUnwindSafe(|| {
            match self.capturer.0.frame(Duration::from_millis(16)) {
                Ok(ScrapFrame::PixelBuffer(pb)) => {
                    let strides = pb.stride();
                    if strides.is_empty() {
                        return Err(CaptureError::Backend("captured frame missing stride".into()));
                    }
                    let i420 = convert_pixel_buffer_to_i420(
                        pb.data(),
                        strides[0],
                        pb.width(),
                        pb.height(),
                        pb.pixfmt(),
                    )?;
                    Ok(Some(i420))
                }
                Ok(_) => Err(CaptureError::Backend(
                    "unsupported non-PixelBuffer scrap frame variant".into(),
                )),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(e) => Err(CaptureError::Backend(format!("scrap frame error: {e}"))),
            }
        }));

        let Some(frame) = (match captured {
            Ok(Ok(opt)) => opt,
            Ok(Err(e)) => return Err(e),
            Err(payload) => {
                return Err(CaptureError::Unavailable(format!(
                    "FFI panic during screen capture: {}",
                    panic_payload_to_string(payload)
                )));
            }
        }) else {
            return Ok(None);
        };

        if compute_y_variance(&frame) <= 1e-9 {
            self.consecutive_zero_variance = self.consecutive_zero_variance.saturating_add(1);
            if self.consecutive_zero_variance >= ZERO_VARIANCE_WARN_THRESHOLD {
                self.zero_variance_warning = true;
            }
        } else {
            self.consecutive_zero_variance = 0;
        }

        self.width = frame.width;
        self.height = frame.height;
        self.seq = self.seq.saturating_add(1);
        let now = epoch_ms().max(self.last_ts_ms);
        self.last_ts_ms = now;

        Ok(Some(CapturedFrame {
            seq: self.seq,
            captured_at_ms: now,
            frame: Arc::new(frame),
        }))
    }
}

#[derive(Debug, Default)]
pub struct CaptureStats {
    pub frames_captured: AtomicU64,
    pub frames_overwritten: AtomicU64,
    pub would_block_count: AtomicU64,
    pub zero_variance_warning: AtomicBool,
    pub thread_exited: AtomicBool,
    last_consumed_seq: AtomicU64,
    last_error: Mutex<Option<CaptureError>>,
}

impl CaptureStats {
    pub fn mark_consumed(&self, seq: u64) {
        self.last_consumed_seq.fetch_max(seq, Ordering::AcqRel);
    }

    pub fn is_thread_exited(&self) -> bool {
        self.thread_exited.load(Ordering::Acquire)
    }

    pub fn last_error(&self) -> Option<CaptureError> {
        self.last_error.lock().ok().and_then(|g| g.clone())
    }

    fn set_error(&self, err: CaptureError) {
        if let Ok(mut g) = self.last_error.lock() {
            *g = Some(err);
        }
    }
}

struct ThreadExitGuard(Arc<CaptureStats>);

impl Drop for ThreadExitGuard {
    fn drop(&mut self) {
        self.0.thread_exited.store(true, Ordering::Release);
    }
}

pub struct CapturePipelineHandle {
    pub rx: watch::Receiver<Option<CapturedFrame>>,
    stop_flag: Arc<AtomicBool>,
    stats: Arc<CaptureStats>,
    dimensions: (usize, usize),
    join_handle: Option<JoinHandle<()>>,
    last_sent_seq: u64,
    last_sent_at: Option<Instant>,
}

impl CapturePipelineHandle {
    pub fn dimensions(&self) -> (usize, usize) {
        self.dimensions
    }

    pub fn stats(&self) -> &Arc<CaptureStats> {
        &self.stats
    }

    pub fn stop_flag(&self) -> &Arc<AtomicBool> {
        &self.stop_flag
    }

    pub fn is_thread_exited(&self) -> bool {
        self.stats.is_thread_exited()
    }

    /// Returns the newest captured frame if unseen, or re-emits the latest frame once
    /// `keepalive_interval` has elapsed so unchanged screens never starve decoder recovery.
    /// Once the capture thread has exited (error, panic, or stop), never emits stale keepalives.
    pub fn try_take_latest_or_keepalive(
        &mut self,
        keepalive_interval: Duration,
    ) -> Option<CapturedFrame> {
        if self.stats.is_thread_exited() {
            return None;
        }
        let latest = self.rx.borrow_and_update().clone()?;
        if latest.seq > self.last_sent_seq {
            self.last_sent_seq = latest.seq;
            self.last_sent_at = Some(Instant::now());
            self.stats.mark_consumed(latest.seq);
            return Some(latest);
        }
        let due_keepalive = self
            .last_sent_at
            .map(|t| t.elapsed() >= keepalive_interval)
            .unwrap_or(true);
        if due_keepalive {
            self.last_sent_at = Some(Instant::now());
            return Some(latest);
        }
        None
    }

    /// Async consumer helper pulling at `target_fps` while honoring `keepalive_interval`.
    /// Immediately returns `None` if the capture thread exits (`RecvError` or `thread_exited`).
    pub async fn next_frame_for_sender(
        &mut self,
        target_fps: u32,
        keepalive_interval: Duration,
        timeout: Duration,
    ) -> Option<CapturedFrame> {
        let frame_period = Duration::from_nanos(1_000_000_000u64 / u64::from(target_fps.max(1)));
        let deadline = Instant::now() + timeout;
        loop {
            if self.stats.is_thread_exited() {
                return None;
            }
            if let Some(frame) = self.try_take_latest_or_keepalive(keepalive_interval) {
                return Some(frame);
            }
            let rem = deadline.checked_duration_since(Instant::now())?;
            if rem.is_zero() {
                return None;
            }
            let wait = rem.min(frame_period).min(keepalive_interval);
            match tokio::time::timeout(wait, self.rx.changed()).await {
                Ok(Ok(())) => {}
                Ok(Err(_closed)) => return None,
                Err(_elapsed) => {}
            }
            if self.stats.is_thread_exited() || self.stop_flag.load(Ordering::Acquire) {
                return None;
            }
        }
    }

    /// Signals the capture thread to stop and joins it to guarantee full reclamation on shutdown.
    pub fn stop_and_join(&mut self) -> Result<(), CaptureError> {
        self.stop_flag.store(true, Ordering::Release);
        if let Some(handle) = self.join_handle.take() {
            handle.join().map_err(|_| {
                CaptureError::Backend("zd-v2-capture thread panicked during shutdown".into())
            })?;
        }
        Ok(())
    }
}

impl Drop for CapturePipelineHandle {
    fn drop(&mut self) {
        self.stop_flag.store(true, Ordering::Release);
        if let Some(handle) = self.join_handle.take() {
            let _ = handle.join();
        }
    }
}

/// Spawns the dedicated `zd-v2-capture` OS thread publishing into a single-slot `tokio::sync::watch`
/// channel (latest-frame overwrite, never queuing stale frames and never stalling the capture source).
pub fn spawn_capture_pipeline<S: ScreenCaptureSource + 'static>(
    mut source: S,
    stop_flag: Arc<AtomicBool>,
) -> Result<CapturePipelineHandle, CaptureError> {
    let dimensions = source.dimensions();
    let (tx, rx) = watch::channel::<Option<CapturedFrame>>(None);
    let stats = Arc::new(CaptureStats::default());
    let thread_stats = Arc::clone(&stats);
    let thread_stop = Arc::clone(&stop_flag);

    let join_handle = thread::Builder::new()
        .name("zd-v2-capture".to_string())
        .spawn(move || {
            let _exit_guard = ThreadExitGuard(Arc::clone(&thread_stats));
            let mut last_published_seq = 0u64;
            while !thread_stop.load(Ordering::Acquire) {
                match source.next_frame() {
                    Ok(Some(captured)) => {
                        let seq = captured.seq;
                        if source.zero_variance_warning() {
                            thread_stats
                                .zero_variance_warning
                                .store(true, Ordering::Release);
                        }
                        if last_published_seq > 0
                            && last_published_seq
                                > thread_stats.last_consumed_seq.load(Ordering::Acquire)
                        {
                            thread_stats
                                .frames_overwritten
                                .fetch_add(1, Ordering::Relaxed);
                        }
                        last_published_seq = seq;
                        let _ = tx.send_replace(Some(captured));
                        thread_stats.frames_captured.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(None) => {
                        thread_stats
                            .would_block_count
                            .fetch_add(1, Ordering::Relaxed);
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(e) => {
                        thread_stats.set_error(e);
                        break;
                    }
                }
            }
        })
        .map_err(|e| CaptureError::Backend(format!("failed to spawn zd-v2-capture thread: {e}")))?;

    Ok(CapturePipelineHandle {
        rx,
        stop_flag,
        stats,
        dimensions,
        join_handle: Some(join_handle),
        last_sent_seq: 0,
        last_sent_at: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2_session::video::{V2VideoDecoder, V2VideoEncoder, VideoCodec};

    struct ZeroVarianceMockSource {
        seq: u64,
        consecutive_zero: u32,
        warn: bool,
    }

    impl ScreenCaptureSource for ZeroVarianceMockSource {
        fn dimensions(&self) -> (usize, usize) {
            (64, 64)
        }

        fn zero_variance_warning(&self) -> bool {
            self.warn
        }

        fn next_frame(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
            self.seq += 1;
            let frame = I420Frame::new(64, 64, vec![0u8; 64 * 64], vec![128u8; 32 * 32], vec![128u8; 32 * 32])
                .unwrap();
            if compute_y_variance(&frame) <= 1e-9 {
                self.consecutive_zero += 1;
                if self.consecutive_zero >= ZERO_VARIANCE_WARN_THRESHOLD {
                    self.warn = true;
                }
            }
            Ok(Some(CapturedFrame {
                seq: self.seq,
                captured_at_ms: self.seq * 16,
                frame: Arc::new(frame),
            }))
        }
    }

    #[test]
    fn dimension_cropping_and_bounds_validation() {
        assert_eq!(crop_and_validate_dimensions(1921, 1081).unwrap(), (1920, 1080));
        assert_eq!(crop_and_validate_dimensions(1280, 720).unwrap(), (1280, 720));
        assert!(matches!(
            crop_and_validate_dimensions(31, 64),
            Err(CaptureError::InvalidDimensions(_))
        ));
        assert!(matches!(
            crop_and_validate_dimensions(MAX_FRAME_DIM + 2, 720),
            Err(CaptureError::InvalidDimensions(_))
        ));
    }

    #[test]
    fn visual_marker_survives_vp9_codec_and_has_zero_false_positive() {
        let mut enc = V2VideoEncoder::new(VideoCodec::Vp9, 320, 240, 2.0, Some(30)).unwrap();
        let mut dec = V2VideoDecoder::new(VideoCodec::Vp9).unwrap();

        let plain = generate_animated_i420(320, 240, 0);
        let plain_enc = enc.encode_i420(&plain, 0).unwrap();
        let plain_dec = dec.decode_raw(&plain_enc.data).unwrap();
        assert!(
            !detect_visual_marker(&plain_dec, 160, 120).detected,
            "plain frame should not falsely detect marker"
        );

        let mut marked = generate_animated_i420(320, 240, 1);
        overlay_visual_marker(&mut marked, 160, 120);
        let marked_enc = enc.encode_i420(&marked, 33).unwrap();
        let marked_dec = dec.decode_raw(&marked_enc.data).unwrap();
        let check = detect_visual_marker(&marked_dec, 160, 120);
        assert!(
            check.detected,
            "marked frame should detect visual marker after VP9 roundtrip: {check:?}"
        );
    }

    #[test]
    fn bgra_to_i420_bt601_converts_with_odd_crop() {
        let raw_w = 35usize;
        let raw_h = 33usize;
        let stride = raw_w * 4;
        let mut bgra = vec![0u8; stride * raw_h];
        for row in 0..raw_h {
            for col in 0..raw_w {
                let off = row * stride + col * 4;
                bgra[off] = (col * 5) as u8; // B
                bgra[off + 1] = (row * 7) as u8; // G
                bgra[off + 2] = 200; // R
                bgra[off + 3] = 255; // A
            }
        }
        let i420 = bgra_to_i420_bt601(&bgra, stride, raw_w, raw_h).unwrap();
        assert_eq!((i420.width, i420.height), (34, 32));
        assert!(compute_y_variance(&i420) > 1.0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn watch_capture_pipeline_overwrites_latest_and_joins_cleanly() {
        let marker: SharedVisualMarker = Arc::new(Mutex::new(Some((640, 360))));
        let source = SyntheticAnimatedSource::new_720p(120, Some(marker));
        let stop = Arc::new(AtomicBool::new(false));
        let mut handle = spawn_capture_pipeline(source, Arc::clone(&stop)).unwrap();

        // Let producer overwrite slots while consumer is busy.
        tokio::time::sleep(Duration::from_millis(80)).await;
        let frame = handle
            .next_frame_for_sender(30, Duration::from_millis(200), Duration::from_secs(2))
            .await
            .expect("expected captured frame");
        assert!(frame.seq >= 1);
        assert!(detect_visual_marker(&frame.frame, 640, 360).detected);
        assert!(handle.stats().frames_captured.load(Ordering::Relaxed) >= 2);
        assert!(handle.stats().frames_overwritten.load(Ordering::Relaxed) >= 1);

        handle.stop_and_join().unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn zero_variance_guard_sets_warning_after_threshold() {
        let source = ZeroVarianceMockSource {
            seq: 0,
            consecutive_zero: 0,
            warn: false,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let mut handle = spawn_capture_pipeline(source, stop).unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(handle.stats().zero_variance_warning.load(Ordering::Acquire));
        handle.stop_and_join().unwrap();
    }

    #[test]
    fn visual_marker_at_minimum_32x32_dimensions_never_panics() {
        for &(mx, my) in &[(0, 0), (16, 16), (31, 31), (-10, 100)] {
            let mut frame = generate_animated_i420(32, 32, 0);
            overlay_visual_marker(&mut frame, mx, my);
            let check = detect_visual_marker(&frame, mx, my);
            assert!(
                check.detected,
                "32x32 marker at ({mx}, {my}) should be detected cleanly: {check:?}"
            );
        }
    }

    struct FailingAfterOneFrameSource {
        emitted: bool,
    }

    impl ScreenCaptureSource for FailingAfterOneFrameSource {
        fn dimensions(&self) -> (usize, usize) {
            (64, 64)
        }

        fn next_frame(&mut self) -> Result<Option<CapturedFrame>, CaptureError> {
            if !self.emitted {
                self.emitted = true;
                let frame = generate_animated_i420(64, 64, 0);
                return Ok(Some(CapturedFrame {
                    seq: 1,
                    captured_at_ms: 1,
                    frame: Arc::new(frame),
                }));
            }
            Err(CaptureError::Backend("simulated display disconnect".into()))
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_thread_error_returns_none_immediately_without_stale_keepalive() {
        let stop = Arc::new(AtomicBool::new(false));
        let mut handle =
            spawn_capture_pipeline(FailingAfterOneFrameSource { emitted: false }, stop).unwrap();

        // Wait briefly for the source to emit 1 frame then fail and exit the thread.
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(handle.is_thread_exited());
        assert!(matches!(
            handle.stats().last_error(),
            Some(CaptureError::Backend(_))
        ));

        // Must never emit a stale keepalive frame.
        assert!(handle
            .try_take_latest_or_keepalive(Duration::from_millis(1))
            .is_none());

        // `next_frame_for_sender` must return `None` immediately (not wait out the 2s timeout).
        let started = Instant::now();
        let next = handle
            .next_frame_for_sender(30, Duration::from_millis(10), Duration::from_secs(2))
            .await;
        assert!(next.is_none());
        assert!(
            started.elapsed() < Duration::from_millis(200),
            "next_frame_for_sender stalled after capture thread exit: {:?}",
            started.elapsed()
        );
        handle.stop_and_join().unwrap();
    }
}
