// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! macOS ScreenCaptureKit bridge adapter (Video + System Audio Loopback) implementing
//! `OsScreenCapture` and `OsAudioCapture`.
//!
//! Pure-Rust audio ASBD parser (`ingest_sck_audio_buffers`) and video ingestion
//! (`ingest_sck_bgra_frame` / `SckVideoSlot`) are compiled on all platforms and 100%
//! unit-testable without OS permissions or display hardware.

use super::{
    audio::{
        create_spsc_audio_ring, SpscAudioConsumer, SpscAudioProducer, OS_AUDIO_CHANNELS,
        OS_AUDIO_FRAME_SAMPLES, OS_AUDIO_SAMPLE_RATE,
    },
    capture::convert_captured_stride_to_i420,
    OsAudioCapture, OsCapturePair, OsError, OsPermission, OsScreenCapture, RawCapturedFrame,
};
use crate::{
    frame::{checked_frame_byte_len, PixelFormat},
    session::video::I420Frame,
};
use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Condvar, Mutex,
    },
    time::{Duration, Instant},
};

/// CoreAudio `AudioFormatFlags` constants (matching `<CoreAudioTypes/CoreAudioBaseTypes.h>`).
pub const K_AUDIO_FORMAT_FLAG_IS_FLOAT: u32 = 1 << 0;
pub const K_AUDIO_FORMAT_FLAG_IS_BIG_ENDIAN: u32 = 1 << 1;
pub const K_AUDIO_FORMAT_FLAG_IS_PACKED: u32 = 1 << 3;
pub const K_AUDIO_FORMAT_FLAG_IS_NON_INTERLEAVED: u32 = 1 << 5;

/// Stack chunk size for zero-allocation audio interleaving / ingestion on the RT callback path.
const AUDIO_INGEST_STACK_CHUNK: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SckAudioAsbd {
    pub sample_rate: f64,
    pub channels: u32,
    pub format_flags: u32,
    pub bits_per_channel: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SckCaptureConfig {
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub display_index: u32,
    pub capture_audio: bool,
    pub exclude_self_audio: bool,
}

impl Default for SckCaptureConfig {
    fn default() -> Self {
        Self {
            width: 0,
            height: 0,
            fps: 30,
            display_index: 0,
            capture_audio: true,
            exclude_self_audio: true,
        }
    }
}

/// Validates CoreAudio `AudioStreamBasicDescription` fields strictly for 48kHz / 2ch / f32 LE.
/// Rejects 44.1kHz, mono (1ch), surround (>2ch), integer formats, and big-endian formats with
/// `OsError::UnsupportedAudioFormat`.
pub fn validate_sck_audio_asbd(asbd: &SckAudioAsbd) -> Result<(), OsError> {
    if !asbd.sample_rate.is_finite()
        || (asbd.sample_rate - f64::from(OS_AUDIO_SAMPLE_RATE)).abs() > 1e-3
    {
        return Err(OsError::UnsupportedAudioFormat(format!(
            "unsupported sample rate {} Hz (expected {OS_AUDIO_SAMPLE_RATE} Hz)",
            asbd.sample_rate
        )));
    }
    if asbd.channels != u32::from(OS_AUDIO_CHANNELS) {
        return Err(OsError::UnsupportedAudioFormat(format!(
            "unsupported channel count {} (expected {OS_AUDIO_CHANNELS})",
            asbd.channels
        )));
    }
    if (asbd.format_flags & K_AUDIO_FORMAT_FLAG_IS_FLOAT) == 0 {
        return Err(OsError::UnsupportedAudioFormat(format!(
            "non-float audio format flags={:#x} (expected float32)",
            asbd.format_flags
        )));
    }
    if (asbd.format_flags & K_AUDIO_FORMAT_FLAG_IS_BIG_ENDIAN) != 0 {
        return Err(OsError::UnsupportedAudioFormat(
            "big-endian audio format is unsupported".into(),
        ));
    }
    if asbd.bits_per_channel != 32 {
        return Err(OsError::UnsupportedAudioFormat(format!(
            "unsupported bits_per_channel {} (expected 32)",
            asbd.bits_per_channel
        )));
    }
    Ok(())
}

/// Zero-allocation audio buffer ingestion supporting BOTH:
/// - **Interleaved** (`buffers.len() == 1` of `[L0, R0, L1, R1, ...]`)
/// - **Planar / non-interleaved** (`kAudioFormatFlagIsNonInterleaved`, `buffers.len() == 2` of
///   `[L0, L1, ...]` and `[R0, R1, ...]`)
///
/// Writes interleaved `f32` samples directly into the lock-free `SpscAudioProducer` using a
/// small stack buffer (zero heap allocations on the real-time audio callback path).
pub fn ingest_sck_audio_buffers(
    asbd: &SckAudioAsbd,
    buffers: &[&[u8]],
    producer: &mut SpscAudioProducer,
) -> Result<usize, OsError> {
    validate_sck_audio_asbd(asbd)?;
    let is_planar = (asbd.format_flags & K_AUDIO_FORMAT_FLAG_IS_NON_INTERLEAVED) != 0;

    let mut stack_buf = [0.0f32; AUDIO_INGEST_STACK_CHUNK];
    let mut total_pushed = 0usize;

    if is_planar {
        if buffers.len() != 2 {
            return Err(OsError::UnsupportedAudioFormat(format!(
                "planar stereo audio requires 2 buffers, got {}",
                buffers.len()
            )));
        }
        let left = buffers[0];
        let right = buffers[1];
        if left.len() != right.len() {
            return Err(OsError::UnsupportedAudioFormat(format!(
                "mismatched planar buffer byte lengths: L={} vs R={}",
                left.len(),
                right.len()
            )));
        }
        if !left.len().is_multiple_of(4) {
            return Err(OsError::UnsupportedAudioFormat(format!(
                "unaligned f32 planar buffer byte length: {}",
                left.len()
            )));
        }
        let frames = left.len() / 4;
        let max_frames_per_chunk = AUDIO_INGEST_STACK_CHUNK / 2;
        let mut frame_off = 0usize;
        while frame_off < frames {
            let chunk_frames = (frames - frame_off).min(max_frames_per_chunk);
            for i in 0..chunk_frames {
                let byte_off = (frame_off + i) * 4;
                let l = f32::from_le_bytes([
                    left[byte_off],
                    left[byte_off + 1],
                    left[byte_off + 2],
                    left[byte_off + 3],
                ]);
                let r = f32::from_le_bytes([
                    right[byte_off],
                    right[byte_off + 1],
                    right[byte_off + 2],
                    right[byte_off + 3],
                ]);
                stack_buf[i * 2] = l;
                stack_buf[i * 2 + 1] = r;
            }
            total_pushed += producer.push_slice(&stack_buf[..(chunk_frames * 2)]);
            frame_off += chunk_frames;
        }
    } else {
        if buffers.len() != 1 {
            return Err(OsError::UnsupportedAudioFormat(format!(
                "interleaved stereo audio requires 1 buffer, got {}",
                buffers.len()
            )));
        }
        let bytes = buffers[0];
        if !bytes.len().is_multiple_of(8) {
            return Err(OsError::UnsupportedAudioFormat(format!(
                "unaligned interleaved stereo f32 buffer byte length: {}",
                bytes.len()
            )));
        }
        let total_samples = bytes.len() / 4;
        let mut sample_off = 0usize;
        while sample_off < total_samples {
            let chunk_samples = (total_samples - sample_off).min(AUDIO_INGEST_STACK_CHUNK);
            for (i, dst) in stack_buf.iter_mut().enumerate().take(chunk_samples) {
                let byte_off = (sample_off + i) * 4;
                *dst = f32::from_le_bytes([
                    bytes[byte_off],
                    bytes[byte_off + 1],
                    bytes[byte_off + 2],
                    bytes[byte_off + 3],
                ]);
            }
            total_pushed += producer.push_slice(&stack_buf[..chunk_samples]);
            sample_off += chunk_samples;
        }
    }

    Ok(total_pushed)
}

/// Stored latest video frame produced by ScreenCaptureKit (single-slot overwrite).
pub struct SckLatestFrame {
    pub raw: RawCapturedFrame,
    pub i420: I420Frame,
    pub scale_factor: f32,
    pub pts_us: i64,
    pub seq: u64,
}

struct SckVideoSlotInner {
    latest: Option<SckLatestFrame>,
    seq: u64,
    closed: bool,
}

/// Single-slot latest-frame video buffer: overwrites stale unconsumed frames so slow
/// encoders drop old frames with zero unbounded memory growth.
pub struct SckVideoSlot {
    inner: Mutex<SckVideoSlotInner>,
    cvar: Condvar,
    dropped_stale_frames: AtomicU64,
}

impl Default for SckVideoSlot {
    fn default() -> Self {
        Self::new()
    }
}

impl SckVideoSlot {
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(SckVideoSlotInner {
                latest: None,
                seq: 0,
                closed: false,
            }),
            cvar: Condvar::new(),
            dropped_stale_frames: AtomicU64::new(0),
        }
    }

    pub fn publish(&self, mut frame: SckLatestFrame) -> u64 {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if g.latest.is_some() {
            self.dropped_stale_frames.fetch_add(1, Ordering::Relaxed);
        }
        g.seq = g.seq.saturating_add(1);
        frame.seq = g.seq;
        let seq = frame.seq;
        g.latest = Some(frame);
        self.cvar.notify_all();
        seq
    }

    pub fn take_latest(&self) -> Option<SckLatestFrame> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.latest.take()
    }

    pub fn take_latest_wait(&self, timeout: Duration) -> Option<SckLatestFrame> {
        let deadline = Instant::now() + timeout;
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if let Some(frame) = g.latest.take() {
                return Some(frame);
            }
            if g.closed {
                return None;
            }
            let rem = deadline.checked_duration_since(Instant::now())?;
            if rem.is_zero() {
                return None;
            }
            let (guard, wait_res) = self
                .cvar
                .wait_timeout(g, rem)
                .unwrap_or_else(|e| e.into_inner());
            g = guard;
            if let Some(frame) = g.latest.take() {
                return Some(frame);
            }
            if wait_res.timed_out() || g.closed {
                return None;
            }
        }
    }

    pub fn close(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.closed = true;
        self.cvar.notify_all();
    }

    pub fn dropped_stale_frames(&self) -> u64 {
        self.dropped_stale_frames.load(Ordering::Relaxed)
    }
}

/// Validates even dimensions & `bytes_per_row` stride, converts BGRA -> I420 via `libyuv`
/// (`convert_captured_stride_to_i420`), and publishes into the single-slot `SckVideoSlot`
/// (dropping any unconsumed stale frame).
pub fn ingest_sck_bgra_frame(
    slot: &SckVideoSlot,
    bgra: &[u8],
    width: u32,
    height: u32,
    bytes_per_row: u32,
    scale_factor: f32,
    pts_us: i64,
) -> Result<u64, OsError> {
    if width < 2 || height < 2 || (width & 1) != 0 || (height & 1) != 0 {
        return Err(OsError::InvalidData(format!(
            "SCK video dimensions must be >= 2 and even, got {width}x{height}"
        )));
    }
    let expected = checked_frame_byte_len(width, height, bytes_per_row)
        .map_err(|e| OsError::InvalidData(e.to_string()))?;
    if bgra.len() < expected {
        return Err(OsError::InvalidData(format!(
            "SCK BGRA buffer len {} < stride*height ({expected})",
            bgra.len()
        )));
    }
    let raw = RawCapturedFrame {
        width,
        height,
        stride: bytes_per_row,
        pixel_format: PixelFormat::Bgra8,
        data: bgra[..expected].to_vec(),
    };
    let i420 = convert_captured_stride_to_i420(&raw)?;
    let seq = slot.publish(SckLatestFrame {
        raw,
        i420,
        scale_factor: if scale_factor > 0.0 {
            scale_factor
        } else {
            1.0
        },
        pts_us,
        seq: 0,
    });
    Ok(seq)
}

/// Pure permission-gate check helper so unit tests can verify fail-closed denial deterministically
/// regardless of host TCC state.
pub fn enforce_sck_permission_preflight(granted: bool) -> Result<(), OsError> {
    if granted {
        Ok(())
    } else {
        Err(OsError::PermissionDenied(OsPermission::ScreenRecording))
    }
}

/// Non-interactive ScreenCaptureKit permission preflight (`CGPreflightScreenCaptureAccess()` ONLY;
/// NEVER invokes `CGRequestScreenCaptureAccess()`).
pub fn preflight_sck_permission() -> Result<bool, OsError> {
    #[cfg(all(target_os = "macos", feature = "os-sck"))]
    {
        Ok(macos_sck_impl::preflight())
    }
    #[cfg(not(all(target_os = "macos", feature = "os-sck")))]
    {
        Err(OsError::UnsupportedPlatform(
            "ScreenCaptureKit adapter unavailable on this platform/feature set",
        ))
    }
}

#[cfg(all(target_os = "macos", feature = "os-sck"))]
mod macos_sck_impl {
    use super::*;
    use std::{
        cell::UnsafeCell,
        ffi::{c_char, c_void, CStr},
        sync::atomic::AtomicBool,
    };

    const ZD_SCK_OK: i32 = 0;
    const ZD_SCK_ERR_PERMISSION: i32 = -2;
    const ZD_SCK_ERR_NO_DISPLAY: i32 = -3;
    const ZD_SCK_DEFAULT_STOP_TIMEOUT_MS: u32 = 2000;

    #[repr(C)]
    struct ZdSckHandle {
        _opaque: [u8; 0],
    }

    #[repr(C)]
    struct ZdSckConfig {
        width: u32,
        height: u32,
        fps: u32,
        display_index: u32,
        capture_audio: u8,
        exclude_self_audio: u8,
        _reserved: [u8; 2],
    }

    #[repr(C)]
    struct ZdSckAudioBuffer {
        data: *const u8,
        byte_len: u32,
        channels: u32,
    }

    type ZdSckVideoCallback = extern "C" fn(
        user_ctx: *mut c_void,
        bgra_base: *const u8,
        width: u32,
        height: u32,
        bytes_per_row: u32,
        scale_factor: f32,
        pts_us: i64,
    );

    type ZdSckAudioCallback = extern "C" fn(
        user_ctx: *mut c_void,
        sample_rate: f64,
        channels: u32,
        format_flags: u32,
        bits_per_channel: u32,
        num_buffers: u32,
        buffers: *const ZdSckAudioBuffer,
        pts_us: i64,
    );

    type ZdSckErrorCallback =
        extern "C" fn(user_ctx: *mut c_void, error_code: i32, message: *const c_char);

    extern "C" {
        fn zd_sck_preflight_permission() -> i32;
        fn zd_sck_create(
            cfg: *const ZdSckConfig,
            video_cb: Option<ZdSckVideoCallback>,
            audio_cb: Option<ZdSckAudioCallback>,
            err_cb: Option<ZdSckErrorCallback>,
            user_ctx: *mut c_void,
        ) -> *mut ZdSckHandle;
        fn zd_sck_start(h: *mut ZdSckHandle) -> i32;
        fn zd_sck_stop(h: *mut ZdSckHandle, timeout_ms: u32) -> i32;
        fn zd_sck_destroy(h: *mut ZdSckHandle);
        fn zd_sck_get_dimensions(
            h: *const ZdSckHandle,
            out_width: *mut u32,
            out_height: *mut u32,
        ) -> i32;
    }

    pub fn preflight() -> bool {
        unsafe { zd_sck_preflight_permission() != 0 }
    }

    struct SckCallbackCtx {
        video_slot: Arc<SckVideoSlot>,
        // Accessed exclusively on the serial `com.zerodesk.sck.audio` GCD queue.
        audio_producer: UnsafeCell<Option<SpscAudioProducer>>,
        stream_failed: Arc<AtomicBool>,
        last_error: Arc<Mutex<Option<String>>>,
        dimensions: Arc<Mutex<(u32, u32)>>,
    }

    // SAFETY: `video_slot`, `stream_failed`, `last_error`, `dimensions` are Send+Sync;
    // `audio_producer` is touched strictly on the single serial `audio_queue` GCD queue,
    // which is drained via `dispatch_sync` in `zd_sck_destroy` before `SckCallbackCtx` drops.
    unsafe impl Sync for SckCallbackCtx {}
    unsafe impl Send for SckCallbackCtx {}

    extern "C" fn on_sck_video(
        user_ctx: *mut c_void,
        bgra_base: *const u8,
        width: u32,
        height: u32,
        bytes_per_row: u32,
        scale_factor: f32,
        pts_us: i64,
    ) {
        if user_ctx.is_null() || bgra_base.is_null() {
            return;
        }
        let ctx = unsafe { &*(user_ctx as *const SckCallbackCtx) };
        let Ok(byte_len) = checked_frame_byte_len(width, height, bytes_per_row) else {
            return;
        };
        let slice = unsafe { std::slice::from_raw_parts(bgra_base, byte_len) };
        if ingest_sck_bgra_frame(
            &ctx.video_slot,
            slice,
            width,
            height,
            bytes_per_row,
            scale_factor,
            pts_us,
        )
        .is_ok()
        {
            let mut dims = ctx.dimensions.lock().unwrap_or_else(|e| e.into_inner());
            *dims = (width, height);
        }
    }

    extern "C" fn on_sck_audio(
        user_ctx: *mut c_void,
        sample_rate: f64,
        channels: u32,
        format_flags: u32,
        bits_per_channel: u32,
        num_buffers: u32,
        buffers: *const ZdSckAudioBuffer,
        _pts_us: i64,
    ) {
        if user_ctx.is_null() || buffers.is_null() || num_buffers == 0 || num_buffers > 8 {
            return;
        }
        let ctx = unsafe { &*(user_ctx as *const SckCallbackCtx) };
        let prod_opt = unsafe { &mut *ctx.audio_producer.get() };
        let Some(producer) = prod_opt.as_mut() else {
            return;
        };

        let raw_bufs = unsafe { std::slice::from_raw_parts(buffers, num_buffers as usize) };
        // Stack array of slices — zero heap allocation on the RT audio callback path.
        let mut slices: [&[u8]; 8] = [&[]; 8];
        for (i, b) in raw_bufs.iter().enumerate() {
            if b.data.is_null() || b.byte_len == 0 {
                slices[i] = &[];
            } else {
                slices[i] = unsafe { std::slice::from_raw_parts(b.data, b.byte_len as usize) };
            }
        }
        let asbd = SckAudioAsbd {
            sample_rate,
            channels,
            format_flags,
            bits_per_channel,
        };
        let _ = ingest_sck_audio_buffers(&asbd, &slices[..(num_buffers as usize)], producer);
    }

    extern "C" fn on_sck_error(
        user_ctx: *mut c_void,
        error_code: i32,
        message: *const c_char,
    ) {
        if user_ctx.is_null() {
            return;
        }
        let ctx = unsafe { &*(user_ctx as *const SckCallbackCtx) };
        let msg = if message.is_null() {
            format!("SCStream error code {error_code}")
        } else {
            unsafe { CStr::from_ptr(message) }
                .to_string_lossy()
                .into_owned()
        };
        *ctx.last_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(msg);
        ctx.stream_failed.store(true, Ordering::Release);
        ctx.video_slot.close();
    }

    struct SckStreamInner {
        handle: *mut ZdSckHandle,
        ctx_ptr: *mut SckCallbackCtx,
        video_slot: Arc<SckVideoSlot>,
        stream_failed: Arc<AtomicBool>,
        last_error: Arc<Mutex<Option<String>>>,
        dimensions: Arc<Mutex<(u32, u32)>>,
    }

    // SAFETY: `ZdSckHandle` uses internal atomics & dedicated serial GCD queues (`stop_queue`,
    // `video_queue`, `audio_queue`), and `zd_sck_destroy` drains all queues before freeing `ctx_ptr`.
    unsafe impl Send for SckStreamInner {}
    unsafe impl Sync for SckStreamInner {}

    impl Drop for SckStreamInner {
        fn drop(&mut self) {
            self.video_slot.close();
            if !self.handle.is_null() {
                unsafe {
                    let _ = zd_sck_stop(self.handle, ZD_SCK_DEFAULT_STOP_TIMEOUT_MS);
                    zd_sck_destroy(self.handle);
                }
                self.handle = std::ptr::null_mut();
            }
            // Safe to free callback context ONLY AFTER `zd_sck_destroy` drained both GCD queues.
            if !self.ctx_ptr.is_null() {
                unsafe {
                    drop(Box::from_raw(self.ctx_ptr));
                }
                self.ctx_ptr = std::ptr::null_mut();
            }
        }
    }

    pub struct MacOsSckScreenCapture {
        inner: Arc<SckStreamInner>,
        last_raw: Option<RawCapturedFrame>,
    }

    impl OsScreenCapture for MacOsSckScreenCapture {
        fn dimensions(&self) -> (u32, u32) {
            *self
                .inner
                .dimensions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
        }

        fn capture_frame(&mut self) -> Result<RawCapturedFrame, OsError> {
            if self.inner.stream_failed.load(Ordering::Acquire) {
                let msg = self
                    .inner
                    .last_error
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .clone()
                    .unwrap_or_else(|| "ScreenCaptureKit stream stopped".into());
                return Err(OsError::CaptureFailed(msg));
            }
            if let Some(latest) = self.inner.video_slot.take_latest_wait(Duration::from_millis(250))
            {
                self.last_raw = Some(latest.raw.clone());
                return Ok(latest.raw);
            }
            // ScreenCaptureKit delivers frames on display damage; reuse last frame when idle.
            if let Some(prev) = &self.last_raw {
                return Ok(prev.clone());
            }
            Err(OsError::CaptureFailed(
                "ScreenCaptureKit produced no initial frame within timeout".into(),
            ))
        }
    }

    pub struct MacOsSckAudioCapture {
        inner: Arc<SckStreamInner>,
        consumer: SpscAudioConsumer,
    }

    impl OsAudioCapture for MacOsSckAudioCapture {
        fn read_frame(&mut self, out_pcm: &mut [f32]) -> Result<bool, OsError> {
            if out_pcm.len() != OS_AUDIO_FRAME_SAMPLES {
                return Err(OsError::InvalidData(format!(
                    "expected {OS_AUDIO_FRAME_SAMPLES} PCM samples, got {}",
                    out_pcm.len()
                )));
            }
            if self.inner.stream_failed.load(Ordering::Acquire) {
                return Err(OsError::AudioUnavailable(
                    "ScreenCaptureKit audio stream reported error".into(),
                ));
            }
            let _ = self.consumer.trim_backlog_to_low_latency();
            if self.consumer.available() < out_pcm.len() {
                return Ok(false);
            }
            let n = self.consumer.pop_slice(out_pcm);
            Ok(n == out_pcm.len())
        }

        fn dropped_frames(&self) -> u64 {
            self.consumer.dropped_frames()
        }

        fn has_stream_error(&self) -> bool {
            self.inner.stream_failed.load(Ordering::Acquire)
        }
    }

    pub fn open_sck(cfg: SckCaptureConfig) -> Result<OsCapturePair, OsError> {
        // Non-interactive preflight BEFORE allocating or touching SCShareableContent.
        enforce_sck_permission_preflight(preflight())?;

        let (audio_prod, audio_cons) = if cfg.capture_audio {
            let (p, c) = create_spsc_audio_ring();
            (Some(p), Some(c))
        } else {
            (None, None)
        };

        let video_slot = Arc::new(SckVideoSlot::new());
        let stream_failed = Arc::new(AtomicBool::new(false));
        let last_error = Arc::new(Mutex::new(None));
        let dimensions = Arc::new(Mutex::new((
            if cfg.width >= 2 { cfg.width & !1 } else { 1280 },
            if cfg.height >= 2 { cfg.height & !1 } else { 720 },
        )));

        let ctx = Box::new(SckCallbackCtx {
            video_slot: Arc::clone(&video_slot),
            audio_producer: UnsafeCell::new(audio_prod),
            stream_failed: Arc::clone(&stream_failed),
            last_error: Arc::clone(&last_error),
            dimensions: Arc::clone(&dimensions),
        });
        let ctx_ptr = Box::into_raw(ctx);

        let c_cfg = ZdSckConfig {
            width: cfg.width,
            height: cfg.height,
            fps: cfg.fps,
            display_index: cfg.display_index,
            capture_audio: u8::from(cfg.capture_audio),
            exclude_self_audio: u8::from(cfg.exclude_self_audio),
            _reserved: [0, 0],
        };

        let handle = unsafe {
            zd_sck_create(
                &c_cfg,
                Some(on_sck_video),
                if cfg.capture_audio {
                    Some(on_sck_audio)
                } else {
                    None
                },
                Some(on_sck_error),
                ctx_ptr as *mut c_void,
            )
        };
        if handle.is_null() {
            unsafe {
                drop(Box::from_raw(ctx_ptr));
            }
            return Err(OsError::CaptureFailed("zd_sck_create returned NULL".into()));
        }

        let inner = Arc::new(SckStreamInner {
            handle,
            ctx_ptr,
            video_slot,
            stream_failed,
            last_error,
            dimensions: Arc::clone(&dimensions),
        });

        let start_rc = unsafe { zd_sck_start(inner.handle) };
        if start_rc != ZD_SCK_OK {
            return Err(match start_rc {
                ZD_SCK_ERR_PERMISSION => OsError::PermissionDenied(OsPermission::ScreenRecording),
                ZD_SCK_ERR_NO_DISPLAY => {
                    OsError::CaptureFailed("ScreenCaptureKit found no shareable display".into())
                }
                other => OsError::CaptureFailed(format!(
                    "ScreenCaptureKit start failed (code {other})"
                )),
            });
        }

        let mut actual_w = 0u32;
        let mut actual_h = 0u32;
        if unsafe { zd_sck_get_dimensions(inner.handle, &mut actual_w, &mut actual_h) } == ZD_SCK_OK
            && actual_w >= 2
            && actual_h >= 2
        {
            *dimensions.lock().unwrap_or_else(|e| e.into_inner()) = (actual_w, actual_h);
        }

        let video_cap: Box<dyn OsScreenCapture> = Box::new(MacOsSckScreenCapture {
            inner: Arc::clone(&inner),
            last_raw: None,
        });
        let audio_cap: Option<Box<dyn OsAudioCapture>> = audio_cons.map(|consumer| {
            Box::new(MacOsSckAudioCapture {
                inner: Arc::clone(&inner),
                consumer,
            }) as Box<dyn OsAudioCapture>
        });
        Ok((video_cap, audio_cap))
    }
}

/// Opens a macOS ScreenCaptureKit capture session (video + optional 48kHz/2ch system audio loopback).
/// Fails closed with `OsError::PermissionDenied(OsPermission::ScreenRecording)` when Screen
/// Recording permission is not granted (NEVER triggers an OS permission dialog).
pub fn open_sck_capture(cfg: SckCaptureConfig) -> Result<OsCapturePair, OsError> {
    #[cfg(all(target_os = "macos", feature = "os-sck"))]
    {
        macos_sck_impl::open_sck(cfg)
    }
    #[cfg(not(all(target_os = "macos", feature = "os-sck")))]
    {
        let _ = cfg;
        Err(OsError::UnsupportedPlatform(
            "ScreenCaptureKit adapter unavailable on this platform/feature set",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f32_slice_to_le_bytes(samples: &[f32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(samples.len() * 4);
        for &s in samples {
            out.extend_from_slice(&s.to_le_bytes());
        }
        out
    }

    #[test]
    fn unauthorized_preflight_returns_permission_denied_without_prompt() {
        // Pure deterministic permission gate check:
        assert_eq!(
            enforce_sck_permission_preflight(false),
            Err(OsError::PermissionDenied(OsPermission::ScreenRecording))
        );
        assert_eq!(enforce_sck_permission_preflight(true), Ok(()));

        // Live non-interactive preflight on macOS MUST return promptly without popping any dialog.
        #[cfg(all(target_os = "macos", feature = "os-sck"))]
        {
            let granted = preflight_sck_permission().expect("preflight must not fail on macOS");
            if !granted {
                let err = match open_sck_capture(SckCaptureConfig::default()) {
                    Ok(_) => panic!("ungranted SCK open must fail closed"),
                    Err(e) => e,
                };
                assert_eq!(err, OsError::PermissionDenied(OsPermission::ScreenRecording));
            }
        }
    }

    #[test]
    fn planar_48khz_2ch_f32_interleaves_exact_samples_into_spsc_ring() {
        let (mut prod, mut cons) = create_spsc_audio_ring();
        let left_samples: Vec<f32> = (0..960).map(|i| (i as f32) * 0.001).collect();
        let right_samples: Vec<f32> = (0..960).map(|i| -((i as f32) * 0.002) - 0.5).collect();
        let left_bytes = f32_slice_to_le_bytes(&left_samples);
        let right_bytes = f32_slice_to_le_bytes(&right_samples);

        let asbd = SckAudioAsbd {
            sample_rate: 48_000.0,
            channels: 2,
            format_flags: K_AUDIO_FORMAT_FLAG_IS_FLOAT
                | K_AUDIO_FORMAT_FLAG_IS_PACKED
                | K_AUDIO_FORMAT_FLAG_IS_NON_INTERLEAVED,
            bits_per_channel: 32,
        };
        let pushed =
            ingest_sck_audio_buffers(&asbd, &[&left_bytes, &right_bytes], &mut prod).unwrap();
        assert_eq!(pushed, OS_AUDIO_FRAME_SAMPLES);
        assert_eq!(cons.available(), OS_AUDIO_FRAME_SAMPLES);

        let mut out = vec![0.0f32; OS_AUDIO_FRAME_SAMPLES];
        assert_eq!(cons.pop_slice(&mut out), OS_AUDIO_FRAME_SAMPLES);
        for i in 0..960 {
            assert_eq!(out[i * 2], left_samples[i], "L sample mismatch at frame {i}");
            assert_eq!(
                out[i * 2 + 1],
                right_samples[i],
                "R sample mismatch at frame {i}"
            );
        }
    }

    #[test]
    fn interleaved_48khz_2ch_f32_writes_exact_samples_into_spsc_ring() {
        let (mut prod, mut cons) = create_spsc_audio_ring();
        let interleaved: Vec<f32> = (0..OS_AUDIO_FRAME_SAMPLES)
            .map(|i| ((i as f32) - 500.0) * 0.0005)
            .collect();
        let bytes = f32_slice_to_le_bytes(&interleaved);

        let asbd = SckAudioAsbd {
            sample_rate: 48_000.0,
            channels: 2,
            format_flags: K_AUDIO_FORMAT_FLAG_IS_FLOAT | K_AUDIO_FORMAT_FLAG_IS_PACKED,
            bits_per_channel: 32,
        };
        let pushed = ingest_sck_audio_buffers(&asbd, &[&bytes], &mut prod).unwrap();
        assert_eq!(pushed, OS_AUDIO_FRAME_SAMPLES);

        let mut out = vec![0.0f32; OS_AUDIO_FRAME_SAMPLES];
        assert_eq!(cons.pop_slice(&mut out), OS_AUDIO_FRAME_SAMPLES);
        assert_eq!(out, interleaved);
    }

    #[test]
    fn audio_asbd_boundary_rejections() {
        let (mut prod, _cons) = create_spsc_audio_ring();
        let valid_bytes = f32_slice_to_le_bytes(&[0.1, -0.1, 0.2, -0.2]);

        // 44.1 kHz -> rejected
        let bad_rate = SckAudioAsbd {
            sample_rate: 44_100.0,
            channels: 2,
            format_flags: K_AUDIO_FORMAT_FLAG_IS_FLOAT,
            bits_per_channel: 32,
        };
        assert!(matches!(
            ingest_sck_audio_buffers(&bad_rate, &[&valid_bytes], &mut prod),
            Err(OsError::UnsupportedAudioFormat(_))
        ));

        // 1ch mono -> rejected
        let mono = SckAudioAsbd {
            sample_rate: 48_000.0,
            channels: 1,
            format_flags: K_AUDIO_FORMAT_FLAG_IS_FLOAT,
            bits_per_channel: 32,
        };
        assert!(matches!(
            ingest_sck_audio_buffers(&mono, &[&valid_bytes], &mut prod),
            Err(OsError::UnsupportedAudioFormat(_))
        ));

        // 6ch surround -> rejected
        let surround = SckAudioAsbd {
            sample_rate: 48_000.0,
            channels: 6,
            format_flags: K_AUDIO_FORMAT_FLAG_IS_FLOAT,
            bits_per_channel: 32,
        };
        assert!(matches!(
            ingest_sck_audio_buffers(&surround, &[&valid_bytes], &mut prod),
            Err(OsError::UnsupportedAudioFormat(_))
        ));

        // 16-bit integer -> rejected
        let pcm16 = SckAudioAsbd {
            sample_rate: 48_000.0,
            channels: 2,
            format_flags: K_AUDIO_FORMAT_FLAG_IS_PACKED,
            bits_per_channel: 16,
        };
        assert!(matches!(
            ingest_sck_audio_buffers(&pcm16, &[&valid_bytes], &mut prod),
            Err(OsError::UnsupportedAudioFormat(_))
        ));

        // Big-endian float32 -> rejected
        let big_endian = SckAudioAsbd {
            sample_rate: 48_000.0,
            channels: 2,
            format_flags: K_AUDIO_FORMAT_FLAG_IS_FLOAT | K_AUDIO_FORMAT_FLAG_IS_BIG_ENDIAN,
            bits_per_channel: 32,
        };
        assert!(matches!(
            ingest_sck_audio_buffers(&big_endian, &[&valid_bytes], &mut prod),
            Err(OsError::UnsupportedAudioFormat(_))
        ));

        // Mismatched planar buffer lengths -> rejected
        let planar_ok = SckAudioAsbd {
            sample_rate: 48_000.0,
            channels: 2,
            format_flags: K_AUDIO_FORMAT_FLAG_IS_FLOAT | K_AUDIO_FORMAT_FLAG_IS_NON_INTERLEAVED,
            bits_per_channel: 32,
        };
        let short_bytes = f32_slice_to_le_bytes(&[0.5]);
        assert!(matches!(
            ingest_sck_audio_buffers(&planar_ok, &[&valid_bytes, &short_bytes], &mut prod),
            Err(OsError::UnsupportedAudioFormat(_))
        ));
    }

    #[test]
    fn bgra_padded_stride_converts_to_i420_and_overwrites_latest_slot() {
        let slot = SckVideoSlot::new();
        let w = 64u32;
        let h = 32u32;
        let stride = 320u32; // 64 bytes extra row padding beyond 64*4=256

        let make_frame = |b: u8, g: u8, r: u8| -> Vec<u8> {
            let mut buf = vec![0xAAu8; (stride as usize) * (h as usize)];
            for row in 0..(h as usize) {
                for col in 0..(w as usize) {
                    let off = row * (stride as usize) + col * 4;
                    buf[off] = b;
                    buf[off + 1] = g;
                    buf[off + 2] = r;
                    buf[off + 3] = 255;
                }
            }
            buf
        };

        // Odd dimensions rejected fail-closed.
        let dummy = vec![0u8; 64 * 64 * 4];
        assert!(ingest_sck_bgra_frame(&slot, &dummy, 63, 32, 256, 2.0, 100).is_err());

        // Publish 2 frames back-to-back without consuming -> 1st is overwritten (dropped_stale = 1).
        let dark = make_frame(10, 10, 10);
        let bright = make_frame(230, 230, 230);
        let seq1 = ingest_sck_bgra_frame(&slot, &dark, w, h, stride, 2.0, 1000).unwrap();
        let seq2 = ingest_sck_bgra_frame(&slot, &bright, w, h, stride, 2.0, 2000).unwrap();
        assert_eq!(seq1, 1);
        assert_eq!(seq2, 2);
        assert_eq!(slot.dropped_stale_frames(), 1);

        let latest = slot.take_latest().expect("latest frame present");
        assert_eq!(latest.seq, 2);
        assert_eq!(latest.pts_us, 2000);
        assert_eq!(latest.scale_factor, 2.0);
        assert_eq!(latest.i420.width, 64);
        assert_eq!(latest.i420.height, 32);
        assert!(latest.i420.y.iter().all(|&y| y > 180));
        assert!(slot.take_latest().is_none());
    }
}
