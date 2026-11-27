// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::pool::FramePool;
use crate::session::video::I420Frame;
use scrap::{I420ToABGR, I420ToARGB};
use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

pub const MAX_MAILBOX_WIDTH: u32 = 4096;
pub const MAX_MAILBOX_HEIGHT: u32 = 2160;
pub const MAX_MAILBOX_PIXELS: usize = (MAX_MAILBOX_WIDTH as usize) * (MAX_MAILBOX_HEIGHT as usize);
pub const MAX_STRIDE_PADDING_BYTES: usize = 4096;

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PixelFormat {
    Bgra8 = 1,
    Rgba8 = 2,
}

impl PixelFormat {
    pub fn from_u32(v: u32) -> Option<Self> {
        match v {
            1 => Some(Self::Bgra8),
            2 => Some(Self::Rgba8),
            _ => None,
        }
    }

    pub fn as_u32(self) -> u32 {
        self as u32
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    InvalidDimensions(String),
    Overflow,
    ExceedsMaxPixels { pixels: usize, max: usize },
    BufferTooSmall { required: usize, provided: usize },
    NoFrame,
    StaleGeneration,
    ConversionFailed(String),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDimensions(msg) => write!(f, "invalid frame dimensions: {msg}"),
            Self::Overflow => write!(f, "frame dimension arithmetic overflow"),
            Self::ExceedsMaxPixels { pixels, max } => {
                write!(f, "frame pixel count {pixels} exceeds max {max}")
            }
            Self::BufferTooSmall { required, provided } => {
                write!(
                    f,
                    "output buffer too small: required {required} bytes, provided {provided} bytes"
                )
            }
            Self::NoFrame => write!(f, "no decoded frame available in mailbox"),
            Self::StaleGeneration => write!(f, "frame dropped due to stale session generation"),
            Self::ConversionFailed(msg) => write!(f, "I420 pixel conversion failed: {msg}"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Validated byte length calculation using checked arithmetic (`width * height * 4` / `stride * height`).
/// Supports both landscape and portrait orientations (e.g., 2160x3840) and enforces an upper bound
/// on row padding (`stride <= width * 4 + 4096`).
pub fn checked_frame_byte_len(width: u32, height: u32, stride: u32) -> Result<usize, FrameError> {
    if width == 0 || height == 0 {
        return Err(FrameError::InvalidDimensions(format!(
            "width ({width}) and height ({height}) must be > 0"
        )));
    }
    let (long, short) = (width.max(height), width.min(height));
    if long > MAX_MAILBOX_WIDTH || short > MAX_MAILBOX_HEIGHT {
        return Err(FrameError::InvalidDimensions(format!(
            "{width}x{height} exceeds {MAX_MAILBOX_WIDTH}x{MAX_MAILBOX_HEIGHT} orientation-agnostic cap"
        )));
    }
    let w = width as usize;
    let h = height as usize;
    let s = stride as usize;
    let pixels = w.checked_mul(h).ok_or(FrameError::Overflow)?;
    if pixels > MAX_MAILBOX_PIXELS {
        return Err(FrameError::ExceedsMaxPixels {
            pixels,
            max: MAX_MAILBOX_PIXELS,
        });
    }
    let min_stride = w.checked_mul(4).ok_or(FrameError::Overflow)?;
    let max_stride = min_stride.saturating_add(MAX_STRIDE_PADDING_BYTES);
    if s < min_stride || s > max_stride {
        return Err(FrameError::InvalidDimensions(format!(
            "stride {s} outside [{min_stride}, {max_stride}]"
        )));
    }
    let byte_len = s.checked_mul(h).ok_or(FrameError::Overflow)?;
    let tight_len = pixels.checked_mul(4).ok_or(FrameError::Overflow)?;
    if byte_len < tight_len {
        return Err(FrameError::Overflow);
    }
    Ok(byte_len)
}

pub struct DecodedFrame {
    pub seq: u64,
    pub session_gen: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: PixelFormat,
    pub pts_ms: u64,
    pub data: Vec<u8>,
    taken: AtomicBool,
}

impl fmt::Debug for DecodedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecodedFrame")
            .field("seq", &self.seq)
            .field("session_gen", &self.session_gen)
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .field("pixel_format", &self.pixel_format)
            .field("pts_ms", &self.pts_ms)
            .field("data_len", &self.data.len())
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameInfo {
    pub seq: u64,
    pub session_gen: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: PixelFormat,
    pub byte_len: usize,
    pub pts_ms: u64,
    pub dropped_ui_frames: u64,
}

struct MailboxSlot {
    frame: Option<Arc<DecodedFrame>>,
    session_gen: u64,
}

/// Latest-frame `Arc<DecodedFrame>` mailbox with zero-tear `FramePool` recycling,
/// checked dimension arithmetic, idempotent `dropped_ui_frames` tracking, and lock-free memcpy.
pub struct FrameMailbox {
    slot: Mutex<MailboxSlot>,
    pool: FramePool,
    next_seq: AtomicU64,
    latest_seq: AtomicU64,
    frames_written: AtomicU64,
    frames_taken: AtomicU64,
    invalid_frames_dropped: AtomicU64,
    stale_gen_frames_dropped: AtomicU64,
}

impl Default for FrameMailbox {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameMailbox {
    pub fn new() -> Self {
        Self {
            slot: Mutex::new(MailboxSlot {
                frame: None,
                session_gen: 0,
            }),
            pool: FramePool::default(),
            next_seq: AtomicU64::new(1),
            latest_seq: AtomicU64::new(0),
            frames_written: AtomicU64::new(0),
            frames_taken: AtomicU64::new(0),
            invalid_frames_dropped: AtomicU64::new(0),
            stale_gen_frames_dropped: AtomicU64::new(0),
        }
    }

    pub fn pool(&self) -> &FramePool {
        &self.pool
    }

    pub fn latest_seq(&self) -> u64 {
        self.latest_seq.load(Ordering::Acquire)
    }

    pub fn session_gen(&self) -> u64 {
        self.slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .session_gen
    }

    pub fn set_session_gen(&self, gen: u64) {
        self.slot
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .session_gen = gen;
    }

    pub fn frames_written(&self) -> u64 {
        self.frames_written.load(Ordering::Acquire)
    }

    pub fn frames_taken(&self) -> u64 {
        self.frames_taken.load(Ordering::Acquire)
    }

    pub fn invalid_frames_dropped(&self) -> u64 {
        self.invalid_frames_dropped.load(Ordering::Relaxed)
    }

    pub fn stale_gen_frames_dropped(&self) -> u64 {
        self.stale_gen_frames_dropped.load(Ordering::Relaxed)
    }

    /// Number of frames written by the decoder that were never taken by the UI.
    /// Repeated reads of the same `seq` are idempotent.
    pub fn dropped_ui_frames(&self) -> u64 {
        self.frames_written
            .load(Ordering::Acquire)
            .saturating_sub(self.frames_taken.load(Ordering::Acquire))
    }

    #[allow(clippy::too_many_arguments)]
    fn publish_raw_inner(
        &self,
        expected_gen: Option<u64>,
        width: u32,
        height: u32,
        stride: u32,
        pixel_format: PixelFormat,
        pts_ms: u64,
        data: Vec<u8>,
    ) -> Result<u64, FrameError> {
        let expected_len = match checked_frame_byte_len(width, height, stride) {
            Ok(n) => n,
            Err(e) => {
                self.invalid_frames_dropped.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        if data.len() != expected_len {
            self.invalid_frames_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(FrameError::InvalidDimensions(format!(
                "data len {} != expected stride*height ({expected_len})",
                data.len()
            )));
        }

        // Assign `seq`, check `expected_gen`, and update `latest_seq` atomically under `slot` lock
        // so concurrent publishers or `reset_for_session` can never reorder or cross-stamp frames.
        let (seq, prev, dropped_buf) = {
            let mut g = self.slot.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(eg) = expected_gen {
                if eg != g.session_gen {
                    self.stale_gen_frames_dropped
                        .fetch_add(1, Ordering::Relaxed);
                    (0, None, Some(data))
                } else {
                    let seq = self.next_seq.fetch_add(1, Ordering::AcqRel);
                    let new_frame = Arc::new(DecodedFrame {
                        seq,
                        session_gen: g.session_gen,
                        width,
                        height,
                        stride,
                        pixel_format,
                        pts_ms,
                        data,
                        taken: AtomicBool::new(false),
                    });
                    let prev = g.frame.replace(new_frame);
                    self.frames_written.fetch_add(1, Ordering::AcqRel);
                    self.latest_seq.store(seq, Ordering::Release);
                    (seq, prev, None)
                }
            } else {
                let seq = self.next_seq.fetch_add(1, Ordering::AcqRel);
                let new_frame = Arc::new(DecodedFrame {
                    seq,
                    session_gen: g.session_gen,
                    width,
                    height,
                    stride,
                    pixel_format,
                    pts_ms,
                    data,
                    taken: AtomicBool::new(false),
                });
                let prev = g.frame.replace(new_frame);
                self.frames_written.fetch_add(1, Ordering::AcqRel);
                self.latest_seq.store(seq, Ordering::Release);
                (seq, prev, None)
            }
        };
        if let Some(mut stale_data) = dropped_buf {
            for b in stale_data.iter_mut() {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
            self.pool.release(stale_data);
            return Err(FrameError::StaleGeneration);
        }
        if let Some(old_arc) = prev {
            // Recycle ONLY outside the mailbox mutex and ONLY when Arc::try_unwrap succeeds.
            self.pool.recycle_arc(old_arc, |owned| owned.data);
        }

        Ok(seq)
    }

    /// Publishes an already-formatted BGRA8/RGBA8 frame into the mailbox slot.
    /// Rejects invalid/overflowing dimensions fail-closed and increments `invalid_frames_dropped`.
    pub fn publish_raw(
        &self,
        width: u32,
        height: u32,
        stride: u32,
        pixel_format: PixelFormat,
        pts_ms: u64,
        data: Vec<u8>,
    ) -> Result<u64, FrameError> {
        self.publish_raw_inner(None, width, height, stride, pixel_format, pts_ms, data)
    }

    /// Generation-checked variant of `publish_raw`: drops the frame and returns
    /// `Err(FrameError::StaleGeneration)` if `expected_gen != current session_gen`.
    #[allow(clippy::too_many_arguments)]
    pub fn publish_raw_for_session(
        &self,
        expected_gen: u64,
        width: u32,
        height: u32,
        stride: u32,
        pixel_format: PixelFormat,
        pts_ms: u64,
        data: Vec<u8>,
    ) -> Result<u64, FrameError> {
        self.publish_raw_inner(
            Some(expected_gen),
            width,
            height,
            stride,
            pixel_format,
            pts_ms,
            data,
        )
    }

    fn publish_i420_inner(
        &self,
        expected_gen: Option<u64>,
        frame: &I420Frame,
        pixel_format: PixelFormat,
        pts_ms: u64,
    ) -> Result<u64, FrameError> {
        if let Some(eg) = expected_gen {
            if self.session_gen() != eg {
                self.stale_gen_frames_dropped
                    .fetch_add(1, Ordering::Relaxed);
                return Err(FrameError::StaleGeneration);
            }
        }
        let width = u32::try_from(frame.width).map_err(|_| {
            self.invalid_frames_dropped.fetch_add(1, Ordering::Relaxed);
            FrameError::Overflow
        })?;
        let height = u32::try_from(frame.height).map_err(|_| {
            self.invalid_frames_dropped.fetch_add(1, Ordering::Relaxed);
            FrameError::Overflow
        })?;
        let stride = width.checked_mul(4).ok_or_else(|| {
            self.invalid_frames_dropped.fetch_add(1, Ordering::Relaxed);
            FrameError::Overflow
        })?;
        let byte_len = match checked_frame_byte_len(width, height, stride) {
            Ok(n) => n,
            Err(e) => {
                self.invalid_frames_dropped.fetch_add(1, Ordering::Relaxed);
                return Err(e);
            }
        };
        let uv_w = frame.width / 2;
        let uv_h = frame.height / 2;
        if !frame.width.is_multiple_of(2)
            || !frame.height.is_multiple_of(2)
            || frame.y.len() < frame.width.saturating_mul(frame.height)
            || frame.u.len() < uv_w.saturating_mul(uv_h)
            || frame.v.len() < uv_w.saturating_mul(uv_h)
        {
            self.invalid_frames_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(FrameError::InvalidDimensions(
                "I420 planes do not match even width/height".into(),
            ));
        }

        let mut dst = self.pool.acquire(byte_len);
        let rc = unsafe {
            match pixel_format {
                // In libyuv on little-endian, ARGB byte order in memory is [B, G, R, A] (BGRA8).
                PixelFormat::Bgra8 => I420ToARGB(
                    frame.y.as_ptr(),
                    frame.width as i32,
                    frame.u.as_ptr(),
                    uv_w as i32,
                    frame.v.as_ptr(),
                    uv_w as i32,
                    dst.as_mut_ptr(),
                    stride as i32,
                    frame.width as i32,
                    frame.height as i32,
                ),
                // In libyuv on little-endian, ABGR byte order in memory is [R, G, B, A] (RGBA8).
                PixelFormat::Rgba8 => I420ToABGR(
                    frame.y.as_ptr(),
                    frame.width as i32,
                    frame.u.as_ptr(),
                    uv_w as i32,
                    frame.v.as_ptr(),
                    uv_w as i32,
                    dst.as_mut_ptr(),
                    stride as i32,
                    frame.width as i32,
                    frame.height as i32,
                ),
            }
        };
        if rc != 0 {
            self.pool.release(dst);
            self.invalid_frames_dropped.fetch_add(1, Ordering::Relaxed);
            return Err(FrameError::ConversionFailed(format!(
                "libyuv returned error code {rc}"
            )));
        }

        self.publish_raw_inner(
            expected_gen,
            width,
            height,
            stride,
            pixel_format,
            pts_ms,
            dst,
        )
    }

    /// Converts a decoded `I420Frame` into BGRA8 or RGBA8 using `libyuv` and a pooled buffer,
    /// then publishes it into the mailbox.
    pub fn publish_i420(
        &self,
        frame: &I420Frame,
        pixel_format: PixelFormat,
        pts_ms: u64,
    ) -> Result<u64, FrameError> {
        self.publish_i420_inner(None, frame, pixel_format, pts_ms)
    }

    /// Generation-checked variant of `publish_i420`: drops stale-gen frames before or under
    /// the mailbox slot lock so prior-session frames can never be stamped with a new `session_gen`.
    pub fn publish_i420_for_session(
        &self,
        expected_gen: u64,
        frame: &I420Frame,
        pixel_format: PixelFormat,
        pts_ms: u64,
    ) -> Result<u64, FrameError> {
        self.publish_i420_inner(Some(expected_gen), frame, pixel_format, pts_ms)
    }

    /// Clones the latest `Arc<DecodedFrame>` under a short lock without copying pixels.
    pub fn latest_arc(&self) -> Option<Arc<DecodedFrame>> {
        let g = self.slot.lock().unwrap_or_else(|e| e.into_inner());
        g.frame.as_ref().map(Arc::clone)
    }

    /// Phase 1: queries metadata for the current latest frame without copying pixels.
    pub fn frame_info(&self) -> Result<FrameInfo, FrameError> {
        let frame = self.latest_arc().ok_or(FrameError::NoFrame)?;
        Ok(FrameInfo {
            seq: frame.seq,
            session_gen: frame.session_gen,
            width: frame.width,
            height: frame.height,
            stride: frame.stride,
            pixel_format: frame.pixel_format,
            byte_len: frame.data.len(),
            pts_ms: frame.pts_ms,
            dropped_ui_frames: self.dropped_ui_frames(),
        })
    }

    /// Phase 2: copies the latest frame into `out_buf` OUTSIDE the mailbox lock.
    /// On `BufferTooSmall`, returns `Err((FrameError::BufferTooSmall { .. }, info))` with required
    /// `info.byte_len` populated and ZERO bytes written into `out_buf`.
    pub fn take_latest_into_with_info(
        &self,
        out_buf: &mut [u8],
    ) -> Result<FrameInfo, (FrameError, Option<FrameInfo>)> {
        let frame = self.latest_arc().ok_or((FrameError::NoFrame, None))?;
        let required = frame.data.len();
        if out_buf.len() < required {
            let info = FrameInfo {
                seq: frame.seq,
                session_gen: frame.session_gen,
                width: frame.width,
                height: frame.height,
                stride: frame.stride,
                pixel_format: frame.pixel_format,
                byte_len: required,
                pts_ms: frame.pts_ms,
                dropped_ui_frames: self.dropped_ui_frames(),
            };
            return Err((
                FrameError::BufferTooSmall {
                    required,
                    provided: out_buf.len(),
                },
                Some(info),
            ));
        }

        // Perform memcpy completely outside the mailbox mutex.
        out_buf[..required].copy_from_slice(&frame.data);

        // Count each distinct `seq` as taken at most once (idempotent repeated reads).
        if !frame.taken.swap(true, Ordering::AcqRel) {
            self.frames_taken.fetch_add(1, Ordering::AcqRel);
        }

        Ok(FrameInfo {
            seq: frame.seq,
            session_gen: frame.session_gen,
            width: frame.width,
            height: frame.height,
            stride: frame.stride,
            pixel_format: frame.pixel_format,
            byte_len: required,
            pts_ms: frame.pts_ms,
            dropped_ui_frames: self.dropped_ui_frames(),
        })
    }

    pub fn take_latest_into(&self, out_buf: &mut [u8]) -> Result<FrameInfo, FrameError> {
        self.take_latest_into_with_info(out_buf)
            .map_err(|(e, _)| e)
    }

    fn zeroize_frame_arc(prev: Option<Arc<DecodedFrame>>) {
        if let Some(old_arc) = prev {
            if let Ok(mut owned) = Arc::try_unwrap(old_arc) {
                for b in owned.data.iter_mut() {
                    unsafe { std::ptr::write_volatile(b, 0) };
                }
            }
        }
    }

    /// Clears the mailbox slot and zeroizes all buffered pixel memory in both slot and pool.
    pub fn clear(&self) {
        let prev = {
            let mut g = self.slot.lock().unwrap_or_else(|e| e.into_inner());
            g.frame.take()
        };
        Self::zeroize_frame_arc(prev);
        self.pool.clear_zeroize();
    }

    /// Atomically updates `session_gen` and clears any prior session's frame in a single
    /// critical section (never resetting monotonic `next_seq`), then zeroizes freed pixels.
    pub fn reset_for_session(&self, gen: u64) {
        let prev = {
            let mut g = self.slot.lock().unwrap_or_else(|e| e.into_inner());
            g.session_gen = gen;
            g.frame.take()
        };
        Self::zeroize_frame_arc(prev);
        self.pool.clear_zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::video::generate_animated_i420;

    #[test]
    fn mailbox_zero_tear_recycling_and_dropped_ui_accounting() {
        let mb = FrameMailbox::new();
        assert_eq!(mb.frame_info(), Err(FrameError::NoFrame));

        // Publish frame 1, hold an Arc clone (simulating active UI memcpy)
        let seq1 = mb
            .publish_raw(4, 4, 16, PixelFormat::Bgra8, 10, vec![0xAA; 64])
            .unwrap();
        assert_eq!(seq1, 1);
        let held_ui_frame = mb.latest_arc().unwrap();
        assert_eq!(held_ui_frame.data[0], 0xAA);
        // Debug output must NEVER dump raw pixel values
        let dbg_str = format!("{held_ui_frame:?}");
        assert!(dbg_str.contains("data_len: 64"));
        assert!(!dbg_str.contains("170, 170"));

        // Overwrite slot with frame 2 while UI still holds frame 1 -> must NOT recycle frame 1!
        let seq2 = mb
            .publish_raw(4, 4, 16, PixelFormat::Bgra8, 20, vec![0xBB; 64])
            .unwrap();
        assert_eq!(seq2, 2);
        assert_eq!(mb.pool().recycle_skipped_in_use(), 1);
        assert_eq!(mb.pool().pooled_count(), 0);
        // Frame 1 bytes held by UI MUST remain untouched (zero tear)
        assert!(held_ui_frame.data.iter().all(|&b| b == 0xAA));
        drop(held_ui_frame);

        // Overwrite slot with frame 3 while nobody holds frame 2 -> frame 2 IS recycled into pool
        let seq3 = mb
            .publish_raw(4, 4, 16, PixelFormat::Bgra8, 30, vec![0xCC; 64])
            .unwrap();
        assert_eq!(seq3, 3);
        assert_eq!(mb.pool().pooled_count(), 1);

        // Buffer-too-small must NOT write any byte into out_buf and must report required byte_len
        let mut small = [0x5Au8; 16];
        let (err, info_opt) = mb.take_latest_into_with_info(&mut small).unwrap_err();
        assert_eq!(
            err,
            FrameError::BufferTooSmall {
                required: 64,
                provided: 16
            }
        );
        assert_eq!(info_opt.unwrap().byte_len, 64);
        assert!(small.iter().all(|&b| b == 0x5A));
        assert_eq!(mb.frames_taken(), 0);
        assert_eq!(mb.dropped_ui_frames(), 3);

        // Valid copy of frame 3: frames_written=3, frames_taken=1 => dropped_ui_frames=2
        let mut out = vec![0u8; 64];
        let info = mb.take_latest_into(&mut out).unwrap();
        assert_eq!(info.seq, 3);
        assert_eq!(info.dropped_ui_frames, 2);
        assert!(out.iter().all(|&b| b == 0xCC));

        // Repeated read of the same seq=3 is idempotent!
        let info_repeat = mb.take_latest_into(&mut out).unwrap();
        assert_eq!(info_repeat.seq, 3);
        assert_eq!(info_repeat.dropped_ui_frames, 2);
        assert_eq!(mb.frames_taken(), 1);

        // clear() drops slot and empties/zeroizes pool
        mb.clear();
        assert_eq!(mb.frame_info(), Err(FrameError::NoFrame));
        assert_eq!(mb.pool().pooled_count(), 0);
    }

    #[test]
    fn mailbox_checked_math_rejects_overflow_stride_cap_and_accepts_portrait_4k() {
        assert!(matches!(
            checked_frame_byte_len(0, 100, 400),
            Err(FrameError::InvalidDimensions(_))
        ));
        assert!(matches!(
            checked_frame_byte_len(5000, 2160, 20000),
            Err(FrameError::InvalidDimensions(_))
        ));
        // Huge stride (u32::MAX or > width*4 + 4096) MUST be rejected fail-closed
        assert!(matches!(
            checked_frame_byte_len(100, 100, u32::MAX),
            Err(FrameError::InvalidDimensions(_))
        ));
        assert!(matches!(
            checked_frame_byte_len(100, 100, 400 + 4097),
            Err(FrameError::InvalidDimensions(_))
        ));
        assert_eq!(
            checked_frame_byte_len(100, 100, 400 + 4096).unwrap(),
            (400 + 4096) * 100
        );
        // Portrait 4K (2160x3840) MUST be accepted!
        assert_eq!(
            checked_frame_byte_len(2160, 3840, 2160 * 4).unwrap(),
            2160 * 3840 * 4
        );
        // 3000x3000 exceeds MAX_MAILBOX_HEIGHT (2160) on short axis -> rejected
        assert!(matches!(
            checked_frame_byte_len(3000, 3000, 3000 * 4),
            Err(FrameError::InvalidDimensions(_))
        ));

        let mb = FrameMailbox::new();
        assert!(mb
            .publish_raw(4097, 2160, 4097 * 4, PixelFormat::Bgra8, 0, vec![])
            .is_err());
        assert_eq!(mb.invalid_frames_dropped(), 1);
    }

    #[test]
    fn mailbox_concurrent_publishers_keep_latest_seq_monotonic() {
        let mb = Arc::new(FrameMailbox::new());
        let mut handles = Vec::new();
        for t in 0..4u8 {
            let mb_c = Arc::clone(&mb);
            handles.push(std::thread::spawn(move || {
                for i in 0..25u64 {
                    let _ = mb_c.publish_raw(
                        4,
                        4,
                        16,
                        PixelFormat::Bgra8,
                        i,
                        vec![t; 64],
                    );
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let info = mb.frame_info().unwrap();
        assert_eq!(info.seq, 100);
        assert_eq!(mb.latest_seq(), 100);
    }

    #[test]
    fn mailbox_publishes_i420_via_libyuv_with_non_zero_bgra_pixels() {
        let mb = FrameMailbox::new();
        let i420 = generate_animated_i420(64, 64, 7);
        let seq = mb.publish_i420(&i420, PixelFormat::Bgra8, 123).unwrap();
        assert_eq!(seq, 1);
        let info = mb.frame_info().unwrap();
        assert_eq!(info.width, 64);
        assert_eq!(info.height, 64);
        assert_eq!(info.stride, 256);
        assert_eq!(info.byte_len, 64 * 64 * 4);
        let mut buf = vec![0u8; info.byte_len];
        let taken = mb.take_latest_into(&mut buf).unwrap();
        assert_eq!(taken.dropped_ui_frames, 0);
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn mailbox_reset_for_session_drops_stale_gen_publishes_and_keeps_seq_monotonic() {
        let mb = FrameMailbox::new();
        mb.reset_for_session(1);
        let seq1 = mb
            .publish_raw_for_session(1, 4, 4, 16, PixelFormat::Bgra8, 10, vec![0x11; 64])
            .unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(mb.frame_info().unwrap().session_gen, 1);

        // Atomically advance to session_gen 2 -> clears slot, keeps next_seq monotonic.
        mb.reset_for_session(2);
        assert_eq!(mb.frame_info(), Err(FrameError::NoFrame));

        // Stale gen=1 raw and I420 publishes MUST be rejected and counted.
        assert_eq!(
            mb.publish_raw_for_session(1, 4, 4, 16, PixelFormat::Bgra8, 20, vec![0x22; 64]),
            Err(FrameError::StaleGeneration)
        );
        let i420 = generate_animated_i420(32, 32, 1);
        assert_eq!(
            mb.publish_i420_for_session(1, &i420, PixelFormat::Bgra8, 25),
            Err(FrameError::StaleGeneration)
        );
        assert_eq!(mb.stale_gen_frames_dropped(), 2);
        assert_eq!(mb.frame_info(), Err(FrameError::NoFrame));

        // Current gen=2 publish succeeds with strictly greater seq > seq1!
        let seq2 = mb
            .publish_i420_for_session(2, &i420, PixelFormat::Bgra8, 30)
            .unwrap();
        assert!(seq2 > seq1);
        let info2 = mb.frame_info().unwrap();
        assert_eq!(info2.seq, seq2);
        assert_eq!(info2.session_gen, 2);
    }
}
