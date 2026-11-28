// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#[cfg(target_os = "macos")]
use super::video::{CODEC_ID_H264, CODEC_ID_HEVC};
use super::video::{BgraFrame, I420Frame, VideoCodec, VideoError};
#[cfg(any(target_os = "macos", test))]
use std::{collections::VecDeque, time::Instant};
use std::time::Duration;
#[cfg(target_os = "macos")]
use v2_transport::{CAP_CODEC_H264, CAP_CODEC_HEVC_OS_HW};

#[cfg(target_os = "macos")]
use std::sync::OnceLock;

pub const VT_REBUILD_WINDOW: Duration = Duration::from_secs(30);
pub const VT_MAX_REBUILDS_IN_WINDOW: usize = 1;
pub const VT_DISABLE_ENV_VAR: &str = "ZERODESK_DISABLE_VT_HW";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnnexbParseSummary {
    pub nal_count: u32,
    pub vps_count: u32,
    pub sps_count: u32,
    pub pps_count: u32,
    pub vcl_count: u32,
    pub has_idr: bool,
    pub total_param_bytes: usize,
}

#[cfg(any(target_os = "macos", test))]
#[derive(Debug, Default)]
pub(crate) struct VtRebuildTracker {
    rebuild_times: VecDeque<Instant>,
    total_rebuilds: u64,
}

#[cfg(any(target_os = "macos", test))]
impl VtRebuildTracker {
    pub(crate) fn record_and_allow(&mut self, now: Instant) -> bool {
        while let Some(&oldest) = self.rebuild_times.front() {
            if now.saturating_duration_since(oldest) >= VT_REBUILD_WINDOW {
                self.rebuild_times.pop_front();
            } else {
                break;
            }
        }
        if self.rebuild_times.len() >= VT_MAX_REBUILDS_IN_WINDOW {
            return false;
        }
        self.rebuild_times.push_back(now);
        self.total_rebuilds = self.total_rebuilds.saturating_add(1);
        true
    }

    pub(crate) fn total_rebuilds(&self) -> u64 {
        self.total_rebuilds
    }
}

fn env_disables_vt_hw() -> bool {
    std::env::var(VT_DISABLE_ENV_VAR)
        .ok()
        .is_some_and(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
}

pub fn probed_vt_cap_bits() -> u64 {
    probed_vt_cap_bits_with_disable(env_disables_vt_hw())
}

pub fn probed_vt_cap_bits_with_disable(disable_hw: bool) -> u64 {
    if disable_hw {
        return 0;
    }
    #[cfg(target_os = "macos")]
    {
        static VT_CAPS_CACHE: OnceLock<u64> = OnceLock::new();
        *VT_CAPS_CACHE.get_or_init(probe_vt_cap_bits_uncached)
    }
    #[cfg(not(target_os = "macos"))]
    {
        0
    }
}

#[cfg(target_os = "macos")]
mod macos_ffi {
    use super::*;
    use std::ptr::NonNull;

    pub const ZD_VT_OK: i32 = 0;
    pub const ZD_VT_ERR_INVALID_ARG: i32 = -1;
    pub const ZD_VT_ERR_HW_UNAVAILABLE: i32 = -2;
    pub const ZD_VT_ERR_SESSION_INVALID: i32 = -3;
    pub const ZD_VT_ERR_NEED_IDR: i32 = -4;
    pub const ZD_VT_ERR_ALLOC: i32 = -5;
    pub const ZD_VT_ERR_DECODE_ASYNC: i32 = -6;
    pub const ZD_VT_ERR_NO_OUTPUT: i32 = -7;
    pub const ZD_VT_ERR_SAFETY_CAP: i32 = -8;
    pub const ZD_VT_ERR_INTERNAL: i32 = -9;

    pub const ZD_VT_CAP_H264: u32 = 1 << 0;
    pub const ZD_VT_CAP_HEVC: u32 = 1 << 1;
    pub const ZD_VT_MAX_NALS_PER_FRAME: usize = 64;

    #[repr(C)]
    pub struct ZdVtEncoder {
        _private: [u8; 0],
    }

    #[repr(C)]
    pub struct ZdVtDecoder {
        _private: [u8; 0],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ZdVtEncoderConfig {
        pub codec_id: u32,
        pub width: u32,
        pub height: u32,
        pub fps: u32,
        pub bitrate_bps: u32,
        pub max_keyframe_interval: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ZdVtEncodedFrame {
        pub data: *const u8,
        pub len: usize,
        pub is_idr: u8,
        pub _pad: [u8; 3],
        pub os_status: i32,
    }

    impl Default for ZdVtEncodedFrame {
        fn default() -> Self {
            Self {
                data: std::ptr::null(),
                len: 0,
                is_idr: 0,
                _pad: [0; 3],
                os_status: 0,
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ZdVtDecodedBgraFrame {
        pub data: *const u8,
        pub len: usize,
        pub width: u32,
        pub height: u32,
        pub stride: u32,
        pub os_status: i32,
    }

    impl Default for ZdVtDecodedBgraFrame {
        fn default() -> Self {
            Self {
                data: std::ptr::null(),
                len: 0,
                width: 0,
                height: 0,
                stride: 0,
                os_status: 0,
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ZdVtDecodedNv12Frame {
        pub y_data: *const u8,
        pub uv_data: *const u8,
        pub width: u32,
        pub height: u32,
        pub y_stride: u32,
        pub uv_stride: u32,
        pub os_status: i32,
    }

    impl Default for ZdVtDecodedNv12Frame {
        fn default() -> Self {
            Self {
                y_data: std::ptr::null(),
                uv_data: std::ptr::null(),
                width: 0,
                height: 0,
                y_stride: 0,
                uv_stride: 0,
                os_status: 0,
            }
        }
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct ZdVtAnnexbSlice {
        pub offset: usize,
        pub len: usize,
        pub nal_type: u8,
        pub _pad: [u8; 7],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct ZdVtAnnexbParseResult {
        pub nal_count: u32,
        pub vps_count: u32,
        pub sps_count: u32,
        pub pps_count: u32,
        pub vcl_count: u32,
        pub has_idr: u8,
        pub _pad: [u8; 3],
        pub total_param_bytes: usize,
        pub nals: [ZdVtAnnexbSlice; ZD_VT_MAX_NALS_PER_FRAME],
    }

    impl Default for ZdVtAnnexbParseResult {
        fn default() -> Self {
            Self {
                nal_count: 0,
                vps_count: 0,
                sps_count: 0,
                pps_count: 0,
                vcl_count: 0,
                has_idr: 0,
                _pad: [0; 3],
                total_param_bytes: 0,
                nals: [ZdVtAnnexbSlice::default(); ZD_VT_MAX_NALS_PER_FRAME],
            }
        }
    }

    extern "C" {
        pub fn zd_vt_parse_annexb(
            codec_id: u32,
            data: *const u8,
            len: usize,
            out: *mut ZdVtAnnexbParseResult,
        ) -> i32;

        pub fn zd_vt_enc_create(
            cfg: *const ZdVtEncoderConfig,
            out_enc: *mut *mut ZdVtEncoder,
        ) -> i32;

        pub fn zd_vt_enc_set_bitrate(enc: *mut ZdVtEncoder, bitrate_bps: u32) -> i32;

        pub fn zd_vt_enc_encode_nv12(
            enc: *mut ZdVtEncoder,
            y_ptr: *const u8,
            y_stride: u32,
            uv_ptr: *const u8,
            uv_stride: u32,
            width: u32,
            height: u32,
            pts_us: i64,
            force_idr: u8,
            out_frame: *mut ZdVtEncodedFrame,
        ) -> i32;

        pub fn zd_vt_enc_destroy(enc: *mut ZdVtEncoder);

        pub fn zd_vt_dec_create(codec_id: u32, out_dec: *mut *mut ZdVtDecoder) -> i32;

        pub fn zd_vt_dec_decode_annexb_into(
            dec: *mut ZdVtDecoder,
            data: *const u8,
            len: usize,
            dst_bgra: *mut u8,
            dst_bgra_cap: usize,
            out_frame: *mut ZdVtDecodedBgraFrame,
        ) -> i32;

        pub fn zd_vt_dec_decode_annexb_nv12(
            dec: *mut ZdVtDecoder,
            data: *const u8,
            len: usize,
            out_frame: *mut ZdVtDecodedNv12Frame,
        ) -> i32;

        pub fn zd_vt_dec_destroy(dec: *mut ZdVtDecoder);

        pub fn zd_vt_probe_capabilities() -> u32;

        #[cfg(test)]
        pub fn zd_vt_enc_invalidate_session_for_test(enc: *mut ZdVtEncoder);

        #[cfg(test)]
        pub fn zd_vt_dec_invalidate_session_for_test(dec: *mut ZdVtDecoder);
    }

    pub fn codec_to_vt_id(codec: VideoCodec) -> Result<u32, VideoError> {
        match codec {
            VideoCodec::H264 => Ok(CODEC_ID_H264 as u32),
            VideoCodec::Hevc => Ok(CODEC_ID_HEVC as u32),
            other => Err(VideoError::InvalidInput(format!(
                "codec {} is not a VideoToolbox codec",
                other.name()
            ))),
        }
    }

    pub struct RawVtEncoder(NonNull<ZdVtEncoder>);

    // Owned exclusively by a single VtEncoder instance; never shared concurrently without &mut/Mutex.
    unsafe impl Send for RawVtEncoder {}

    impl RawVtEncoder {
        pub fn new(cfg: &ZdVtEncoderConfig) -> Result<Self, VideoError> {
            let mut ptr: *mut ZdVtEncoder = std::ptr::null_mut();
            let rc = unsafe { zd_vt_enc_create(cfg, &mut ptr) };
            if rc != ZD_VT_OK {
                return Err(map_vt_error(rc, 0, true));
            }
            let nn = NonNull::new(ptr).ok_or_else(|| {
                VideoError::Encoder("VideoToolbox encoder creation returned null handle".into())
            })?;
            Ok(Self(nn))
        }

        pub fn as_ptr(&self) -> *mut ZdVtEncoder {
            self.0.as_ptr()
        }
    }

    impl Drop for RawVtEncoder {
        fn drop(&mut self) {
            unsafe { zd_vt_enc_destroy(self.0.as_ptr()) };
        }
    }

    pub struct RawVtDecoder(NonNull<ZdVtDecoder>);

    // Owned exclusively by a single VtDecoder instance; never shared concurrently without &mut/Mutex.
    unsafe impl Send for RawVtDecoder {}

    impl RawVtDecoder {
        pub fn new(codec_id: u32) -> Result<Self, VideoError> {
            let mut ptr: *mut ZdVtDecoder = std::ptr::null_mut();
            let rc = unsafe { zd_vt_dec_create(codec_id, &mut ptr) };
            if rc != ZD_VT_OK {
                return Err(map_vt_error(rc, 0, false));
            }
            let nn = NonNull::new(ptr).ok_or_else(|| {
                VideoError::Decoder("VideoToolbox decoder creation returned null handle".into())
            })?;
            Ok(Self(nn))
        }

        pub fn as_ptr(&self) -> *mut ZdVtDecoder {
            self.0.as_ptr()
        }
    }

    impl Drop for RawVtDecoder {
        fn drop(&mut self) {
            unsafe { zd_vt_dec_destroy(self.0.as_ptr()) };
        }
    }

    pub fn map_vt_error(rc: i32, os_status: i32, is_encoder: bool) -> VideoError {
        match rc {
            ZD_VT_ERR_INVALID_ARG => VideoError::InvalidInput(format!(
                "invalid VideoToolbox argument (os_status={os_status})"
            )),
            ZD_VT_ERR_HW_UNAVAILABLE => VideoError::HardwareUnavailable(format!(
                "VideoToolbox hardware acceleration unavailable (os_status={os_status})"
            )),
            ZD_VT_ERR_NEED_IDR => VideoError::NeedIdr(format!(
                "VideoToolbox decoder requires IDR frame (os_status={os_status})"
            )),
            ZD_VT_ERR_SAFETY_CAP => VideoError::NeedIdr(format!(
                "Annex-B frame rejected by decoder safety cap (os_status={os_status})"
            )),
            ZD_VT_ERR_NO_OUTPUT => VideoError::NoOutputFrame,
            ZD_VT_ERR_ALLOC => {
                if is_encoder {
                    VideoError::Encoder(format!(
                        "VideoToolbox encoder allocation failed (os_status={os_status})"
                    ))
                } else {
                    VideoError::Decoder(format!(
                        "VideoToolbox decoder allocation failed (os_status={os_status})"
                    ))
                }
            }
            other => {
                if is_encoder {
                    VideoError::Encoder(format!(
                        "VideoToolbox encoder failed (rc={other}, os_status={os_status})"
                    ))
                } else {
                    VideoError::Decoder(format!(
                        "VideoToolbox decoder failed (rc={other}, os_status={os_status})"
                    ))
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
pub fn probe_vt_cap_bits_uncached() -> u64 {
    let raw = unsafe { macos_ffi::zd_vt_probe_capabilities() };
    let mut caps = 0u64;
    if (raw & macos_ffi::ZD_VT_CAP_H264) != 0 {
        caps |= CAP_CODEC_H264;
    }
    if (raw & macos_ffi::ZD_VT_CAP_HEVC) != 0 {
        caps |= CAP_CODEC_HEVC_OS_HW;
    }
    caps
}

#[cfg(not(target_os = "macos"))]
pub fn probe_vt_cap_bits_uncached() -> u64 {
    0
}

#[cfg(target_os = "macos")]
pub fn parse_annexb_checked(codec: VideoCodec, data: &[u8]) -> Result<AnnexbParseSummary, VideoError> {
    let codec_id = macos_ffi::codec_to_vt_id(codec)?;
    if data.is_empty() {
        return Err(VideoError::NeedIdr("empty Annex-B frame".into()));
    }
    let mut parsed = macos_ffi::ZdVtAnnexbParseResult::default();
    let rc = unsafe { macos_ffi::zd_vt_parse_annexb(codec_id, data.as_ptr(), data.len(), &mut parsed) };
    if rc != macos_ffi::ZD_VT_OK {
        return Err(macos_ffi::map_vt_error(rc, 0, false));
    }
    Ok(AnnexbParseSummary {
        nal_count: parsed.nal_count,
        vps_count: parsed.vps_count,
        sps_count: parsed.sps_count,
        pps_count: parsed.pps_count,
        vcl_count: parsed.vcl_count,
        has_idr: parsed.has_idr != 0,
        total_param_bytes: parsed.total_param_bytes,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn parse_annexb_checked(codec: VideoCodec, _data: &[u8]) -> Result<AnnexbParseSummary, VideoError> {
    Err(VideoError::HardwareUnavailable(format!(
        "VideoToolbox Annex-B parser unavailable on non-macOS target for {}",
        codec.name()
    )))
}

/// Converts BGRA8 (tightly or strided) to BT.709 video-range I420 using `libyuv` SIMD.
pub fn bgra_to_i420_bt709(frame: &BgraFrame) -> Result<I420Frame, VideoError> {
    let w = frame.width;
    let h = frame.height;
    if w == 0 || h == 0 || (w & 1) != 0 || (h & 1) != 0 {
        return Err(VideoError::InvalidInput(format!(
            "BGRA dimensions must be positive and even, got {w}x{h}"
        )));
    }
    let min_stride = w
        .checked_mul(4)
        .ok_or_else(|| VideoError::InvalidInput("BGRA stride overflow".into()))?;
    if frame.stride < min_stride {
        return Err(VideoError::InvalidInput(format!(
            "BGRA stride {} smaller than width*4 ({min_stride})",
            frame.stride
        )));
    }
    let needed = frame
        .stride
        .checked_mul(h)
        .ok_or_else(|| VideoError::InvalidInput("BGRA byte length overflow".into()))?;
    if frame.data.len() < needed {
        return Err(VideoError::InvalidInput("BGRA buffer truncated".into()));
    }

    let uv_w = w / 2;
    let uv_h = h / 2;
    let mut y = vec![0u8; w * h];
    let mut u = vec![0u8; uv_w * uv_h];
    let mut v = vec![0u8; uv_w * uv_h];

    let rc = unsafe {
        scrap::ARGBToI420Matrix(
            frame.data.as_ptr(),
            frame.stride as i32,
            y.as_mut_ptr(),
            w as i32,
            u.as_mut_ptr(),
            uv_w as i32,
            v.as_mut_ptr(),
            uv_w as i32,
            &scrap::kArgbH709Constants,
            w as i32,
            h as i32,
        )
    };
    if rc != 0 {
        return Err(VideoError::Decoder(format!(
            "libyuv ARGBToI420Matrix(BT.709) failed with rc={rc}"
        )));
    }
    I420Frame::new(w, h, y, u, v)
}

#[cfg(target_os = "macos")]
pub(crate) struct VtEncoder {
    codec: VideoCodec,
    cfg: macos_ffi::ZdVtEncoderConfig,
    raw: macos_ffi::RawVtEncoder,
    nv12_y: Vec<u8>,
    nv12_uv: Vec<u8>,
    rebuilds: VtRebuildTracker,
    pending_force_idr: bool,
}

#[cfg(target_os = "macos")]
impl VtEncoder {
    pub(crate) fn new(
        codec: VideoCodec,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_bps: u32,
        max_keyframe_interval: u32,
    ) -> Result<Self, VideoError> {
        if env_disables_vt_hw() {
            return Err(VideoError::HardwareUnavailable(format!(
                "VideoToolbox disabled via {VT_DISABLE_ENV_VAR}"
            )));
        }
        let codec_id = macos_ffi::codec_to_vt_id(codec)?;
        let cfg = macos_ffi::ZdVtEncoderConfig {
            codec_id,
            width,
            height,
            fps: fps.max(1),
            bitrate_bps: bitrate_bps.max(64_000),
            max_keyframe_interval,
        };
        let raw = macos_ffi::RawVtEncoder::new(&cfg)?;
        let w = width as usize;
        let h = height as usize;
        Ok(Self {
            codec,
            cfg,
            raw,
            nv12_y: vec![0u8; w * h],
            nv12_uv: vec![0u8; w * (h / 2)],
            rebuilds: VtRebuildTracker::default(),
            pending_force_idr: false,
        })
    }

    pub(crate) fn force_next_idr(&mut self) {
        self.pending_force_idr = true;
    }

    pub(crate) fn total_rebuilds(&self) -> u64 {
        self.rebuilds.total_rebuilds()
    }

    pub(crate) fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError> {
        if bitrate_bps == 0 {
            return Err(VideoError::InvalidInput("bitrate_bps must be > 0".into()));
        }
        self.cfg.bitrate_bps = bitrate_bps;
        let rc = unsafe { macos_ffi::zd_vt_enc_set_bitrate(self.raw.as_ptr(), bitrate_bps) };
        if rc == macos_ffi::ZD_VT_OK {
            return Ok(());
        }
        if rc == macos_ffi::ZD_VT_ERR_SESSION_INVALID {
            self.rebuild_session("set_bitrate kVTInvalidSessionErr")?;
            return Ok(());
        }
        Err(macos_ffi::map_vt_error(rc, 0, true))
    }

    pub(crate) fn encode_i420(
        &mut self,
        frame: &I420Frame,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<(Vec<u8>, bool), VideoError> {
        frame.validate()?;
        let w = self.cfg.width as usize;
        let h = self.cfg.height as usize;
        if frame.width != w || frame.height != h {
            return Err(VideoError::InvalidInput(format!(
                "I420 frame dimensions {}x{} do not match VT encoder {}x{}",
                frame.width, frame.height, w, h
            )));
        }
        let uv_w = w / 2;
        let rc = unsafe {
            scrap::I420ToNV12(
                frame.y.as_ptr(),
                w as i32,
                frame.u.as_ptr(),
                uv_w as i32,
                frame.v.as_ptr(),
                uv_w as i32,
                self.nv12_y.as_mut_ptr(),
                w as i32,
                self.nv12_uv.as_mut_ptr(),
                w as i32,
                w as i32,
                h as i32,
            )
        };
        if rc != 0 {
            return Err(VideoError::Encoder(format!(
                "libyuv I420ToNV12 failed with rc={rc}"
            )));
        }
        let y_ptr = self.nv12_y.as_ptr();
        let uv_ptr = self.nv12_uv.as_ptr();
        self.encode_nv12_ptrs(y_ptr, uv_ptr, pts_us, force_idr)
    }

    pub(crate) fn encode_bgra(
        &mut self,
        bgra: &[u8],
        width: usize,
        height: usize,
        stride: usize,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<(Vec<u8>, bool), VideoError> {
        let w = self.cfg.width as usize;
        let h = self.cfg.height as usize;
        if width != w || height != h {
            return Err(VideoError::InvalidInput(format!(
                "BGRA frame dimensions {width}x{height} do not match VT encoder {w}x{h}"
            )));
        }
        let min_stride = w * 4;
        if stride < min_stride || bgra.len() < stride.saturating_mul(h) {
            return Err(VideoError::InvalidInput(
                "BGRA frame stride or buffer length invalid".into(),
            ));
        }
        let rc = unsafe {
            scrap::ARGBToNV12Matrix(
                bgra.as_ptr(),
                stride as i32,
                self.nv12_y.as_mut_ptr(),
                w as i32,
                self.nv12_uv.as_mut_ptr(),
                w as i32,
                &scrap::kArgbH709Constants,
                w as i32,
                h as i32,
            )
        };
        if rc != 0 {
            return Err(VideoError::Encoder(format!(
                "libyuv ARGBToNV12Matrix(BT.709) failed with rc={rc}"
            )));
        }
        let y_ptr = self.nv12_y.as_ptr();
        let uv_ptr = self.nv12_uv.as_ptr();
        self.encode_nv12_ptrs(y_ptr, uv_ptr, pts_us, force_idr)
    }

    fn rebuild_session(&mut self, reason: &str) -> Result<(), VideoError> {
        if !self.rebuilds.record_and_allow(Instant::now()) {
            return Err(VideoError::CodecFailed {
                codec: self.codec,
                reason: format!(
                    "VideoToolbox encoder exceeded 1 rebuild per 30s window ({reason})"
                ),
            });
        }
        let fresh = macos_ffi::RawVtEncoder::new(&self.cfg).map_err(|e| {
            VideoError::CodecFailed {
                codec: self.codec,
                reason: format!("VideoToolbox encoder rebuild failed ({reason}): {e}"),
            }
        })?;
        self.raw = fresh;
        self.pending_force_idr = true;
        Ok(())
    }

    fn encode_nv12_ptrs(
        &mut self,
        y_ptr: *const u8,
        uv_ptr: *const u8,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<(Vec<u8>, bool), VideoError> {
        let want_idr = force_idr || self.pending_force_idr;
        let mut out = macos_ffi::ZdVtEncodedFrame::default();
        let rc = unsafe {
            macos_ffi::zd_vt_enc_encode_nv12(
                self.raw.as_ptr(),
                y_ptr,
                self.cfg.width,
                uv_ptr,
                self.cfg.width,
                self.cfg.width,
                self.cfg.height,
                pts_us,
                u8::from(want_idr),
                &mut out,
            )
        };

        if rc == macos_ffi::ZD_VT_OK {
            if out.data.is_null() || out.len == 0 {
                return Err(VideoError::NoOutputFrame);
            }
            self.pending_force_idr = false;
            let bytes = unsafe { std::slice::from_raw_parts(out.data, out.len) }.to_vec();
            return Ok((bytes, out.is_idr != 0));
        }

        if rc == macos_ffi::ZD_VT_ERR_SESSION_INVALID || rc == macos_ffi::ZD_VT_ERR_INTERNAL {
            self.rebuild_session(&format!("encode rc={rc}, os_status={}", out.os_status))?;
            let mut retry_out = macos_ffi::ZdVtEncodedFrame::default();
            let retry_rc = unsafe {
                macos_ffi::zd_vt_enc_encode_nv12(
                    self.raw.as_ptr(),
                    y_ptr,
                    self.cfg.width,
                    uv_ptr,
                    self.cfg.width,
                    self.cfg.width,
                    self.cfg.height,
                    pts_us,
                    1u8, // force IDR immediately after rebuild
                    &mut retry_out,
                )
            };
            if retry_rc == macos_ffi::ZD_VT_OK
                && !retry_out.data.is_null()
                && retry_out.len > 0
            {
                self.pending_force_idr = false;
                let bytes =
                    unsafe { std::slice::from_raw_parts(retry_out.data, retry_out.len) }.to_vec();
                return Ok((bytes, retry_out.is_idr != 0));
            }
            return Err(VideoError::CodecFailed {
                codec: self.codec,
                reason: format!(
                    "VideoToolbox encoder retry after rebuild failed (rc={retry_rc}, os_status={})",
                    retry_out.os_status
                ),
            });
        }

        Err(macos_ffi::map_vt_error(rc, out.os_status, true))
    }

    #[cfg(test)]
    pub(crate) fn invalidate_session_for_test(&mut self) {
        unsafe { macos_ffi::zd_vt_enc_invalidate_session_for_test(self.raw.as_ptr()) };
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) struct VtEncoder;

#[cfg(not(target_os = "macos"))]
impl VtEncoder {
    pub(crate) fn new(
        codec: VideoCodec,
        _width: u32,
        _height: u32,
        _fps: u32,
        _bitrate_bps: u32,
        _max_keyframe_interval: u32,
    ) -> Result<Self, VideoError> {
        Err(VideoError::HardwareUnavailable(format!(
            "VideoToolbox encoder unavailable on non-macOS target for {}",
            codec.name()
        )))
    }

    pub(crate) fn force_next_idr(&mut self) {}
    pub(crate) fn total_rebuilds(&self) -> u64 {
        0
    }
    pub(crate) fn set_bitrate(&mut self, _bitrate_bps: u32) -> Result<(), VideoError> {
        Err(VideoError::HardwareUnavailable(
            "VideoToolbox unavailable".into(),
        ))
    }
    pub(crate) fn encode_i420(
        &mut self,
        _frame: &I420Frame,
        _pts_us: i64,
        _force_idr: bool,
    ) -> Result<(Vec<u8>, bool), VideoError> {
        Err(VideoError::HardwareUnavailable(
            "VideoToolbox unavailable".into(),
        ))
    }
    pub(crate) fn encode_bgra(
        &mut self,
        _bgra: &[u8],
        _width: usize,
        _height: usize,
        _stride: usize,
        _pts_us: i64,
        _force_idr: bool,
    ) -> Result<(Vec<u8>, bool), VideoError> {
        Err(VideoError::HardwareUnavailable(
            "VideoToolbox unavailable".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VtOutputMode {
    Bgra,
    Nv12,
}

#[cfg(target_os = "macos")]
pub(crate) struct VtDecoder {
    codec: VideoCodec,
    codec_id: u32,
    raw: macos_ffi::RawVtDecoder,
    rebuilds: VtRebuildTracker,
    last_bgra_len: usize,
    output_mode: Option<VtOutputMode>,
}

#[cfg(target_os = "macos")]
impl VtDecoder {
    pub(crate) fn new(codec: VideoCodec) -> Result<Self, VideoError> {
        if env_disables_vt_hw() {
            return Err(VideoError::HardwareUnavailable(format!(
                "VideoToolbox disabled via {VT_DISABLE_ENV_VAR}"
            )));
        }
        let codec_id = macos_ffi::codec_to_vt_id(codec)?;
        let raw = macos_ffi::RawVtDecoder::new(codec_id)?;
        Ok(Self {
            codec,
            codec_id,
            raw,
            rebuilds: VtRebuildTracker::default(),
            last_bgra_len: 0,
            output_mode: None,
        })
    }

    pub(crate) fn total_rebuilds(&self) -> u64 {
        self.rebuilds.total_rebuilds()
    }

    fn handle_session_invalid(&mut self, os_status: i32) -> VideoError {
        if !self.rebuilds.record_and_allow(Instant::now()) {
            return VideoError::CodecFailed {
                codec: self.codec,
                reason: format!(
                    "VideoToolbox decoder exceeded 1 rebuild per 30s window (os_status={os_status})"
                ),
            };
        }
        match macos_ffi::RawVtDecoder::new(self.codec_id) {
            Ok(fresh) => {
                self.raw = fresh;
                self.output_mode = None;
                VideoError::NeedIdr(format!(
                    "VideoToolbox decoder rebuilt after session invalidation (os_status={os_status}); IDR required"
                ))
            }
            Err(e) => VideoError::CodecFailed {
                codec: self.codec,
                reason: format!("VideoToolbox decoder rebuild failed: {e}"),
            },
        }
    }

    pub(crate) fn decode_annexb_i420(&mut self, data: &[u8]) -> Result<I420Frame, VideoError> {
        if data.is_empty() {
            return Err(VideoError::InvalidInput("empty Annex-B video frame".into()));
        }
        if self.output_mode == Some(VtOutputMode::Bgra) {
            let bgra = self.decode_annexb_bgra(data)?;
            return bgra_to_i420_bt709(&bgra);
        }

        let mut out = macos_ffi::ZdVtDecodedNv12Frame::default();
        let rc = unsafe {
            macos_ffi::zd_vt_dec_decode_annexb_nv12(
                self.raw.as_ptr(),
                data.as_ptr(),
                data.len(),
                &mut out,
            )
        };
        match rc {
            macos_ffi::ZD_VT_OK => {
                if out.y_data.is_null()
                    || out.uv_data.is_null()
                    || out.width == 0
                    || out.height == 0
                    || (out.width & 1) != 0
                    || (out.height & 1) != 0
                {
                    return Err(VideoError::NoOutputFrame);
                }
                self.output_mode = Some(VtOutputMode::Nv12);
                let w = out.width as usize;
                let h = out.height as usize;
                let uv_w = w / 2;
                let uv_h = h / 2;
                let mut y = vec![0u8; w * h];
                let mut u = vec![0u8; uv_w * uv_h];
                let mut v = vec![0u8; uv_w * uv_h];
                let cvt_rc = unsafe {
                    scrap::NV12ToI420(
                        out.y_data,
                        out.y_stride as i32,
                        out.uv_data,
                        out.uv_stride as i32,
                        y.as_mut_ptr(),
                        w as i32,
                        u.as_mut_ptr(),
                        uv_w as i32,
                        v.as_mut_ptr(),
                        uv_w as i32,
                        w as i32,
                        h as i32,
                    )
                };
                if cvt_rc != 0 {
                    return Err(VideoError::Decoder(format!(
                        "libyuv NV12ToI420 failed with rc={cvt_rc}"
                    )));
                }
                I420Frame::new(w, h, y, u, v)
            }
            macos_ffi::ZD_VT_ERR_DECODE_ASYNC => Err(VideoError::CodecFailed {
                codec: self.codec,
                reason: "VideoToolbox decoder violated synchronous invariant (kVTDecodeInfo_Asynchronous)"
                    .into(),
            }),
            macos_ffi::ZD_VT_ERR_SESSION_INVALID => Err(self.handle_session_invalid(out.os_status)),
            other => Err(macos_ffi::map_vt_error(other, out.os_status, false)),
        }
    }

    pub(crate) fn decode_annexb_bgra_into(
        &mut self,
        data: &[u8],
        dst: &mut Vec<u8>,
    ) -> Result<(usize, usize, usize), VideoError> {
        if data.is_empty() {
            return Err(VideoError::InvalidInput("empty Annex-B video frame".into()));
        }
        if self.output_mode == Some(VtOutputMode::Nv12) {
            let i420 = self.decode_annexb_i420(data)?;
            let stride = i420.width * 4;
            let byte_len = stride * i420.height;
            dst.resize(byte_len, 0);
            let uv_w = i420.width / 2;
            let rc = unsafe {
                scrap::H420ToARGB(
                    i420.y.as_ptr(),
                    i420.width as i32,
                    i420.u.as_ptr(),
                    uv_w as i32,
                    i420.v.as_ptr(),
                    uv_w as i32,
                    dst.as_mut_ptr(),
                    stride as i32,
                    i420.width as i32,
                    i420.height as i32,
                )
            };
            if rc != 0 {
                return Err(VideoError::Decoder(format!(
                    "libyuv H420ToARGB failed with rc={rc}"
                )));
            }
            return Ok((i420.width, i420.height, stride));
        }

        dst.clear();
        if self.last_bgra_len > dst.capacity() {
            dst.reserve(self.last_bgra_len);
        }
        let dst_cap = dst.capacity();
        let dst_ptr = if dst_cap > 0 {
            dst.as_mut_ptr()
        } else {
            std::ptr::null_mut()
        };

        let mut out = macos_ffi::ZdVtDecodedBgraFrame::default();
        let rc = unsafe {
            macos_ffi::zd_vt_dec_decode_annexb_into(
                self.raw.as_ptr(),
                data.as_ptr(),
                data.len(),
                dst_ptr,
                dst_cap,
                &mut out,
            )
        };
        match rc {
            macos_ffi::ZD_VT_OK => {
                if out.data.is_null() || out.len == 0 || out.width == 0 || out.height == 0 {
                    return Err(VideoError::NoOutputFrame);
                }
                self.output_mode = Some(VtOutputMode::Bgra);
                self.last_bgra_len = out.len;
                if !dst_ptr.is_null() && std::ptr::eq(out.data, dst_ptr) && out.len <= dst_cap {
                    // C callback copied directly from CVPixelBuffer into `dst` (single copy!).
                    unsafe { dst.set_len(out.len) };
                } else {
                    let bytes = unsafe { std::slice::from_raw_parts(out.data, out.len) };
                    dst.extend_from_slice(bytes);
                }
                Ok((out.width as usize, out.height as usize, out.stride as usize))
            }
            macos_ffi::ZD_VT_ERR_DECODE_ASYNC => Err(VideoError::CodecFailed {
                codec: self.codec,
                reason: "VideoToolbox decoder violated synchronous invariant (kVTDecodeInfo_Asynchronous)"
                    .into(),
            }),
            macos_ffi::ZD_VT_ERR_SESSION_INVALID => Err(self.handle_session_invalid(out.os_status)),
            other => Err(macos_ffi::map_vt_error(other, out.os_status, false)),
        }
    }

    pub(crate) fn decode_annexb_bgra(&mut self, data: &[u8]) -> Result<BgraFrame, VideoError> {
        let mut buf = Vec::with_capacity(self.last_bgra_len);
        let (width, height, stride) = self.decode_annexb_bgra_into(data, &mut buf)?;
        Ok(BgraFrame {
            width,
            height,
            stride,
            data: buf,
        })
    }

    #[cfg(test)]
    pub(crate) fn invalidate_session_for_test(&mut self) {
        unsafe { macos_ffi::zd_vt_dec_invalidate_session_for_test(self.raw.as_ptr()) };
    }
}

#[cfg(not(target_os = "macos"))]
pub(crate) struct VtDecoder;

#[cfg(not(target_os = "macos"))]
impl VtDecoder {
    pub(crate) fn new(codec: VideoCodec) -> Result<Self, VideoError> {
        Err(VideoError::HardwareUnavailable(format!(
            "VideoToolbox decoder unavailable on non-macOS target for {}",
            codec.name()
        )))
    }

    pub(crate) fn total_rebuilds(&self) -> u64 {
        0
    }

    pub(crate) fn decode_annexb_i420(&mut self, _data: &[u8]) -> Result<I420Frame, VideoError> {
        Err(VideoError::HardwareUnavailable(
            "VideoToolbox unavailable".into(),
        ))
    }

    pub(crate) fn decode_annexb_bgra_into(
        &mut self,
        _data: &[u8],
        _dst: &mut Vec<u8>,
    ) -> Result<(usize, usize, usize), VideoError> {
        Err(VideoError::HardwareUnavailable(
            "VideoToolbox unavailable".into(),
        ))
    }

    pub(crate) fn decode_annexb_bgra(&mut self, _data: &[u8]) -> Result<BgraFrame, VideoError> {
        Err(VideoError::HardwareUnavailable(
            "VideoToolbox unavailable".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_os = "macos")]
    use crate::session::{
        capture::{detect_visual_marker, overlay_visual_marker},
        video::{
            compute_y_psnr, compute_y_ssim, generate_animated_i420, generate_desktop_scene_i420,
            local_v2_cap_bits, read_desktop_scene_frame_idx, DecodedVideoFrame, V2VideoDecoder,
            V2VideoEncoder, DEFAULT_H264_1080P_BITRATE_BPS, DEFAULT_HEVC_1080P_BITRATE_BPS,
            MAX_CONSECUTIVE_DECODE_FAILURES,
        },
    };
    use crate::session::video::{local_v2_cap_bits_with_vt_disable, negotiate_video_codec};
    #[cfg(target_os = "macos")]
    use v2_transport::{VideoReassembler, VideoSlice};
    use v2_transport::{CAP_CODEC_AV1, CAP_CODEC_H264, CAP_CODEC_HEVC_OS_HW, CAP_CODEC_VP9};

    #[test]
    fn capability_negotiation_priority_and_explicit_preference_fail_closed() {
        let full = CAP_CODEC_AV1 | CAP_CODEC_VP9 | CAP_CODEC_H264 | CAP_CODEC_HEVC_OS_HW;
        assert_eq!(
            negotiate_video_codec(full, full, None).unwrap(),
            VideoCodec::Hevc
        );
        assert_eq!(
            negotiate_video_codec(full, full & !CAP_CODEC_HEVC_OS_HW, None).unwrap(),
            VideoCodec::H264
        );
        assert_eq!(
            negotiate_video_codec(full, CAP_CODEC_VP9 | CAP_CODEC_AV1, None).unwrap(),
            VideoCodec::Vp9
        );
        assert_eq!(
            negotiate_video_codec(full, CAP_CODEC_AV1, None).unwrap(),
            VideoCodec::Av1
        );
        // Explicit preference MUST fail closed when not in common caps (never silently switch).
        assert!(matches!(
            negotiate_video_codec(full, CAP_CODEC_VP9, Some(VideoCodec::Hevc)),
            Err(VideoError::NoCommonCodec {
                preferred: Some(VideoCodec::Hevc),
                ..
            })
        ));
        assert!(matches!(
            negotiate_video_codec(full, CAP_CODEC_VP9, Some(VideoCodec::H264)),
            Err(VideoError::NoCommonCodec {
                preferred: Some(VideoCodec::H264),
                ..
            })
        ));
        assert_eq!(
            negotiate_video_codec(full, full, Some(VideoCodec::H264)).unwrap(),
            VideoCodec::H264
        );

        // Simulated ZERODESK_DISABLE_VT_HW=1 clears HW bits and negotiates cleanly to VP9.
        let disabled_local = local_v2_cap_bits_with_vt_disable(true);
        assert_eq!(disabled_local & CAP_CODEC_H264, 0);
        assert_eq!(disabled_local & CAP_CODEC_HEVC_OS_HW, 0);
        assert_eq!(
            negotiate_video_codec(disabled_local, full, None).unwrap(),
            VideoCodec::Vp9
        );
    }

    #[test]
    fn vt_rebuild_tracker_sliding_30s_window() {
        let mut tracker = VtRebuildTracker::default();
        let t0 = Instant::now();
        assert!(tracker.record_and_allow(t0));
        assert_eq!(tracker.total_rebuilds(), 1);
        // 2nd failure within 30s is rejected.
        assert!(!tracker.record_and_allow(t0 + Duration::from_secs(10)));
        assert!(!tracker.record_and_allow(t0 + Duration::from_secs(29)));
        // After 30s window elapses, 1 rebuild is allowed again.
        assert!(tracker.record_and_allow(t0 + Duration::from_secs(30)));
        assert_eq!(tracker.total_rebuilds(), 2);
        assert!(!tracker.record_and_allow(t0 + Duration::from_secs(31)));
    }

    #[test]
    fn video_codec_parse_display_and_ids() {
        for (codec, name, id, cap) in [
            (VideoCodec::Av1, "av1", 1u8, CAP_CODEC_AV1),
            (VideoCodec::Vp9, "vp9", 2u8, CAP_CODEC_VP9),
            (VideoCodec::H264, "h264", 3u8, CAP_CODEC_H264),
            (VideoCodec::Hevc, "hevc", 4u8, CAP_CODEC_HEVC_OS_HW),
        ] {
            assert_eq!(codec.name(), name);
            assert_eq!(codec.to_string(), name);
            assert_eq!(codec.codec_id(), id);
            assert_eq!(codec.cap_bit(), cap);
            assert_eq!(VideoCodec::from_codec_id(id).unwrap(), codec);
            assert_eq!(name.parse::<VideoCodec>().unwrap(), codec);
            assert_eq!(name.to_ascii_uppercase().parse::<VideoCodec>().unwrap(), codec);
        }
        assert!(VideoCodec::from_codec_id(0).is_err());
        assert!(VideoCodec::from_codec_id(5).is_err());
        assert!("x264".parse::<VideoCodec>().is_err());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vt_probe_detects_h264_and_hevc_hw() {
        let caps = probed_vt_cap_bits_with_disable(false);
        assert_ne!(caps & CAP_CODEC_H264, 0, "expected H.264 HW cap on Apple Silicon");
        assert_ne!(
            caps & CAP_CODEC_HEVC_OS_HW,
            0,
            "expected HEVC OS-HW cap on Apple Silicon"
        );
        let local = local_v2_cap_bits();
        assert_ne!(local & CAP_CODEC_H264, 0);
        assert_ne!(local & CAP_CODEC_HEVC_OS_HW, 0);
        assert_eq!(
            negotiate_video_codec(local, local, None).unwrap(),
            VideoCodec::Hevc
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vt_1080p_h264_and_hevc_roundtrip_quality_and_invariants() {
        for (codec, bitrate_bps) in [
            (VideoCodec::H264, DEFAULT_H264_1080P_BITRATE_BPS),
            (VideoCodec::Hevc, DEFAULT_HEVC_1080P_BITRATE_BPS),
        ] {
            let mut enc =
                V2VideoEncoder::new_with_vt_config(codec, 1920, 1080, 60, bitrate_bps, 120)
                    .unwrap();
            let mut dec = V2VideoDecoder::new(codec).unwrap();
            let mut bgra_buf = vec![0u8; 1920 * 1080 * 4];
            let mut sum_psnr = 0.0f64;
            let mut sum_ssim = 0.0f64;
            let mut first_idr_bytes: Option<Vec<u8>> = None;

            for idx in 0..16u32 {
                if idx == 8 {
                    enc.set_bitrate(bitrate_bps + 500_000).unwrap();
                }
                let src = generate_desktop_scene_i420(1920, 1080, idx);
                let encoded = enc
                    .encode_i420_with_idr(&src, (idx as i64) * 16, idx == 0)
                    .unwrap();
                assert_eq!(encoded.meta.codec_id, codec.codec_id());
                assert_eq!(encoded.meta.frame_id, idx + 1);
                if idx == 0 {
                    assert!(encoded.meta.is_idr, "{} frame 0 must be IDR", codec.name());
                    let summary = parse_annexb_checked(codec, &encoded.data).unwrap();
                    assert!(summary.has_idr);
                    assert!(summary.sps_count > 0 && summary.pps_count > 0);
                    if codec == VideoCodec::Hevc {
                        assert!(summary.vps_count > 0);
                    }
                    first_idr_bytes = Some(encoded.data.clone());
                }

                let (dw, dh, dstride) = dec
                    .decode_raw_bgra_into(&encoded.data, &mut bgra_buf)
                    .unwrap();
                assert_eq!((dw, dh, dstride), (1920, 1080, 1920 * 4));
                let bgra = BgraFrame {
                    width: dw,
                    height: dh,
                    stride: dstride,
                    data: std::mem::take(&mut bgra_buf),
                };
                let dec_i420 = bgra_to_i420_bt709(&bgra).unwrap();
                bgra_buf = bgra.data;

                assert_eq!(
                    read_desktop_scene_frame_idx(&dec_i420),
                    Some(idx),
                    "{} monotonic frame ordering failed at frame {idx}",
                    codec.name()
                );
                sum_psnr += compute_y_psnr(&src, &dec_i420).unwrap();
                sum_ssim += compute_y_ssim(&src, &dec_i420).unwrap();
            }

            // Cold-start standalone IDR decode on a brand-new decoder + direct DecodedVideoFrame::Bgra check.
            let idr = first_idr_bytes.unwrap();
            let mut fresh_dec = V2VideoDecoder::new(codec).unwrap();
            let frame = fresh_dec.decode_raw_frame(&idr).unwrap();
            assert!(
                matches!(frame, DecodedVideoFrame::Bgra(ref b) if b.width == 1920 && b.height == 1080),
                "{} must return direct DecodedVideoFrame::Bgra",
                codec.name()
            );

            // Also verify direct BGRA encode path works end-to-end.
            if let DecodedVideoFrame::Bgra(bgra_in) = frame {
                let re_enc = enc
                    .encode_bgra(&bgra_in.data, bgra_in.width, bgra_in.height, bgra_in.stride, 500, true)
                    .unwrap();
                assert!(re_enc.meta.is_idr);
                let re_dec = fresh_dec.decode_raw_bgra(&re_enc.data).unwrap();
                assert_eq!((re_dec.width, re_dec.height), (1920, 1080));
            }

            let avg_psnr = sum_psnr / 16.0;
            let avg_ssim = sum_ssim / 16.0;
            assert!(
                avg_psnr >= 40.0,
                "{} 1080p avg PSNR {avg_psnr:.2} dB < 40.0 dB",
                codec.name()
            );
            assert!(
                avg_ssim >= 0.98,
                "{} 1080p avg SSIM {avg_ssim:.4} < 0.98",
                codec.name()
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vt_runtime_session_invalidation_recovery_and_fail_closed() {
        for codec in [VideoCodec::H264, VideoCodec::Hevc] {
            // --- Encoder recovery ---
            let mut enc =
                V2VideoEncoder::new_with_vt_config(codec, 320, 240, 30, 1_500_000, 60).unwrap();
            let mut dec = V2VideoDecoder::new(codec).unwrap();

            let f0 = generate_desktop_scene_i420(320, 240, 0);
            let e0 = enc.encode_i420_with_idr(&f0, 0, true).unwrap();
            assert!(e0.meta.is_idr);
            let _ = dec.decode_raw_bgra(&e0.data).unwrap();

            // Inject genuine Apple kVTInvalidSessionErr (-12903).
            enc.invalidate_vt_session_for_test();
            let f1 = generate_desktop_scene_i420(320, 240, 1);
            let t0 = Instant::now();
            let e1 = enc.encode_i420(&f1, 33).unwrap();
            let rebuild_ms = t0.elapsed().as_millis();
            assert!(
                rebuild_ms <= 200,
                "{} encoder rebuild took {rebuild_ms}ms (> 200ms)",
                codec.name()
            );
            assert_eq!(enc.vt_rebuild_count(), 1);
            assert!(e1.meta.is_idr, "{} rebuild must force IDR", codec.name());
            let _ = dec.decode_raw_bgra(&e1.data).unwrap();

            // 2nd invalidation within 30s window MUST fail closed with CodecFailed (never switch codec).
            enc.invalidate_vt_session_for_test();
            let f2 = generate_desktop_scene_i420(320, 240, 2);
            let err = enc.encode_i420(&f2, 66).unwrap_err();
            assert!(
                matches!(err, VideoError::CodecFailed { codec: c, .. } if c == codec),
                "{} expected CodecFailed on 2nd invalidation, got {err:?}",
                codec.name()
            );

            // --- Decoder recovery ---
            let mut enc2 =
                V2VideoEncoder::new_with_vt_config(codec, 320, 240, 30, 1_500_000, 60).unwrap();
            let idr_a = enc2.encode_i420_with_idr(&f0, 0, true).unwrap();
            let p_b = enc2.encode_i420(&f1, 33).unwrap();
            let idr_c = enc2.encode_i420_with_idr(&f2, 66, true).unwrap();

            let mut dec2 = V2VideoDecoder::new(codec).unwrap();
            let _ = dec2.decode_raw_bgra(&idr_a.data).unwrap();

            dec2.invalidate_vt_session_for_test();
            let t_dec = Instant::now();
            let dec_err1 = dec2.decode_raw_bgra(&p_b.data).unwrap_err();
            let dec_rebuild_ms = t_dec.elapsed().as_millis();
            assert!(
                dec_rebuild_ms <= 200,
                "{} decoder rebuild took {dec_rebuild_ms}ms (> 200ms)",
                codec.name()
            );
            assert!(
                matches!(dec_err1, VideoError::NeedIdr(_)),
                "{} 1st decoder invalidation should rebuild & request IDR, got {dec_err1:?}",
                codec.name()
            );
            assert_eq!(dec2.vt_rebuild_count(), 1);
            // Fresh IDR recovers immediately after 1st rebuild.
            let _ = dec2.decode_raw_bgra(&idr_c.data).unwrap();

            // 2nd decoder invalidation within 30s -> CodecFailed.
            dec2.invalidate_vt_session_for_test();
            let dec_err2 = dec2.decode_raw_bgra(&p_b.data).unwrap_err();
            assert!(
                matches!(dec_err2, VideoError::CodecFailed { codec: c, .. } if c == codec),
                "{} expected CodecFailed on 2nd decoder invalidation, got {dec_err2:?}",
                codec.name()
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vt_30_consecutive_decode_failures_fails_closed() {
        for codec in [VideoCodec::H264, VideoCodec::Hevc] {
            let mut enc =
                V2VideoEncoder::new_with_vt_config(codec, 128, 128, 30, 500_000, 60).unwrap();
            let f0 = generate_desktop_scene_i420(128, 128, 0);
            let idr = enc.encode_i420_with_idr(&f0, 0, true).unwrap();

            let mut dec = V2VideoDecoder::new(codec).unwrap();
            // Prolonged NeedIdr (e.g. non-IDR P-frames awaiting IDR after packet loss) must NOT
            // accumulate consecutive_decode_failures or falsely disconnect.
            let non_idr = [0x00u8, 0x00, 0x00, 0x01, 0x01, 0xAA, 0xBB];
            for _ in 0..(MAX_CONSECUTIVE_DECODE_FAILURES + 10) {
                let err = dec.decode_raw_bgra(&non_idr).unwrap_err();
                assert!(matches!(err, VideoError::NeedIdr(_)));
                assert_eq!(dec.consecutive_decode_failures(), 0);
            }

            // 29 consecutive real decode errors increment the counter without failing closed yet.
            for attempt in 1..MAX_CONSECUTIVE_DECODE_FAILURES {
                let err = dec.decode_raw_bgra(&[]).unwrap_err();
                assert!(matches!(err, VideoError::InvalidInput(_)));
                assert_eq!(dec.consecutive_decode_failures(), attempt);
            }
            // Valid IDR resets consecutive failure counter to 0.
            let _ = dec.decode_raw_bgra(&idr.data).unwrap();
            assert_eq!(dec.consecutive_decode_failures(), 0);

            // 30 consecutive real decode errors escalate to CodecFailed and reset counter to 0.
            for attempt in 1..MAX_CONSECUTIVE_DECODE_FAILURES {
                let err = dec.decode_raw_bgra(&[]).unwrap_err();
                assert!(!matches!(err, VideoError::CodecFailed { .. }));
                assert_eq!(dec.consecutive_decode_failures(), attempt);
            }
            let fatal = dec.decode_raw_bgra(&[]).unwrap_err();
            assert!(
                matches!(fatal, VideoError::CodecFailed { codec: c, .. } if c == codec),
                "{} expected CodecFailed at 30th consecutive failure, got {fatal:?}",
                codec.name()
            );
            assert_eq!(dec.consecutive_decode_failures(), 0);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vt_visual_marker_and_color_card_accuracy_h264_hevc() {
        const W: usize = 1280;
        const H: usize = 720;
        const MARKER_X: i32 = 320;
        const MARKER_Y: i32 = 240;

        // Part 1: Exact v2-hostd visual marker (SyntheticAnimatedSource + overlay_visual_marker)
        // round-tripped through real VideoToolbox H.264 & HEVC encode_i420 -> decode_raw -> detect_visual_marker.
        for codec in [VideoCodec::H264, VideoCodec::Hevc] {
            let mut enc = V2VideoEncoder::new(codec, W as u32, H as u32, 2.0, Some(60)).unwrap();
            let mut dec = V2VideoDecoder::new(codec).unwrap();

            for idx in 0..15u32 {
                let mut src = generate_animated_i420(W, H, idx);
                let marked = idx >= 2;
                if marked {
                    overlay_visual_marker(&mut src, MARKER_X, MARKER_Y);
                }
                let encoded = enc.encode_i420(&src, (idx as i64) * 33).unwrap();
                let decoded_i420 = dec.decode_raw(&encoded.data).unwrap();
                let check = detect_visual_marker(&decoded_i420, MARKER_X, MARKER_Y);
                if marked {
                    assert!(
                        check.detected,
                        "{} frame {idx} missed visual marker: inner_y={:.1}, border_y={:.1}, inner_v={:.1}",
                        codec.name(),
                        check.inner_mean_y,
                        check.border_mean_y,
                        check.inner_mean_v
                    );
                } else {
                    assert!(
                        !check.detected,
                        "{} unmarked frame {idx} falsely detected visual marker",
                        codec.name()
                    );
                }
            }
        }

        // Part 2: Known 8-patch RGB color card through direct 32BGRA encode_bgra -> decode_raw_bgra.
        // Verifies BT.709 colorimetry accuracy (<= 5 per R/G/B channel) and zero R/B channel swap.
        const CW: usize = 512;
        const CH: usize = 128;
        let patches: &[(u8, u8, u8, &str)] = &[
            (255, 0, 0, "red"),
            (0, 255, 0, "green"),
            (0, 0, 255, "blue"),
            (255, 255, 255, "white"),
            (0, 0, 0, "black"),
            (255, 255, 0, "yellow"),
            (0, 255, 255, "cyan"),
            (255, 0, 255, "magenta"),
        ];
        let patch_w = CW / patches.len();
        let mut bgra_card = vec![0u8; CW * CH * 4];
        for row in 0..CH {
            for (p_idx, &(r, g, b, _)) in patches.iter().enumerate() {
                for col in (p_idx * patch_w)..((p_idx + 1) * patch_w) {
                    let off = (row * CW + col) * 4;
                    // BGRA8 byte order in memory: [B, G, R, A]
                    bgra_card[off] = b;
                    bgra_card[off + 1] = g;
                    bgra_card[off + 2] = r;
                    bgra_card[off + 3] = 255;
                }
            }
        }

        for codec in [VideoCodec::H264, VideoCodec::Hevc] {
            let mut enc =
                V2VideoEncoder::new_with_vt_config(codec, CW as u32, CH as u32, 30, 8_000_000, 60)
                    .unwrap();
            let mut dec = V2VideoDecoder::new(codec).unwrap();
            let encoded = enc
                .encode_bgra(&bgra_card, CW, CH, CW * 4, 0, true)
                .unwrap();
            let decoded = dec.decode_raw_bgra(&encoded.data).unwrap();
            assert_eq!((decoded.width, decoded.height), (CW, CH));

            for (p_idx, &(er, eg, eb, label)) in patches.iter().enumerate() {
                let x0 = p_idx * patch_w + 16;
                let x1 = (p_idx + 1) * patch_w - 16;
                let mut sum_b = 0.0f64;
                let mut sum_g = 0.0f64;
                let mut sum_r = 0.0f64;
                let mut cnt = 0.0f64;
                for row in 24..(CH - 24) {
                    for col in x0..x1 {
                        let off = row * decoded.stride + col * 4;
                        sum_b += decoded.data[off] as f64;
                        sum_g += decoded.data[off + 1] as f64;
                        sum_r += decoded.data[off + 2] as f64;
                        cnt += 1.0;
                    }
                }
                let mr = sum_r / cnt;
                let mg = sum_g / cnt;
                let mb = sum_b / cnt;
                assert!(
                    (mr - er as f64).abs() <= 5.0
                        && (mg - eg as f64).abs() <= 5.0
                        && (mb - eb as f64).abs() <= 5.0,
                    "{} color card patch '{label}' mismatch: expected RGB=({er},{eg},{eb}), got ({mr:.1},{mg:.1},{mb:.1})",
                    codec.name()
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    struct BitWriter {
        bytes: Vec<u8>,
        cur: u8,
        bits_used: u8,
    }

    #[cfg(target_os = "macos")]
    impl BitWriter {
        fn new() -> Self {
            Self {
                bytes: Vec::new(),
                cur: 0,
                bits_used: 0,
            }
        }
        fn push_bit(&mut self, bit: u8) {
            self.cur = (self.cur << 1) | (bit & 1);
            self.bits_used += 1;
            if self.bits_used == 8 {
                self.bytes.push(self.cur);
                self.cur = 0;
                self.bits_used = 0;
            }
        }
        fn push_bits(&mut self, val: u32, n: u8) {
            for shift in (0..n).rev() {
                self.push_bit(((val >> shift) & 1) as u8);
            }
        }
        fn push_ue(&mut self, val: u32) {
            let code_num = val + 1;
            let len = 32 - code_num.leading_zeros();
            for _ in 0..(len - 1) {
                self.push_bit(0);
            }
            self.push_bits(code_num, len as u8);
        }
        fn finish_rbsp(mut self) -> Vec<u8> {
            self.push_bit(1);
            while self.bits_used != 0 {
                self.push_bit(0);
            }
            // Add emulation prevention bytes (0x03) after 00 00 00..03.
            let mut out = Vec::with_capacity(self.bytes.len() + 4);
            let mut zeros = 0u8;
            for b in self.bytes {
                if zeros == 2 && b <= 3 {
                    out.push(0x03);
                    zeros = 0;
                }
                out.push(b);
                zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
            }
            out
        }
    }

    #[cfg(target_os = "macos")]
    fn build_h264_baseline_sps(width_mbs: u32, height_mbs: u32) -> Vec<u8> {
        let mut bw = BitWriter::new();
        bw.push_bits(66, 8); // profile_idc = Baseline
        bw.push_bits(0xC0, 8); // constraint_set0..1
        bw.push_bits(52, 8); // level_idc = 5.2
        bw.push_ue(0); // seq_parameter_set_id
        bw.push_ue(0); // log2_max_frame_num_minus4
        bw.push_ue(0); // pic_order_cnt_type
        bw.push_ue(0); // log2_max_pic_order_cnt_lsb_minus4
        bw.push_ue(1); // max_num_ref_frames
        bw.push_bit(0); // gaps_in_frame_num_value_allowed_flag
        bw.push_ue(width_mbs - 1);
        bw.push_ue(height_mbs - 1);
        bw.push_bit(1); // frame_mbs_only_flag
        bw.push_bit(1); // direct_8x8_inference_flag
        bw.push_bit(0); // frame_cropping_flag
        bw.push_bit(0); // vui_parameters_present_flag
        let mut nal = vec![0x67u8];
        nal.extend_from_slice(&bw.finish_rbsp());
        nal
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vt_annexb_safety_caps_and_non_idr_param_isolation() {
        // 1. > 64 NALs rejected
        let mut many_nals = Vec::new();
        for _ in 0..65 {
            many_nals.extend_from_slice(&[0, 0, 0, 1, 0x41, 0x9A]);
        }
        assert!(matches!(
            parse_annexb_checked(VideoCodec::H264, &many_nals),
            Err(VideoError::NeedIdr(_))
        ));

        // 2. > 16 param sets per type rejected
        let mut many_sps = Vec::new();
        for _ in 0..17 {
            many_sps.extend_from_slice(&[0, 0, 0, 1, 0x67, 0x42, 0x00, 0x1E]);
        }
        many_sps.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88]);
        assert!(matches!(
            parse_annexb_checked(VideoCodec::H264, &many_sps),
            Err(VideoError::NeedIdr(_))
        ));

        // 3. > 4 KiB single param set rejected
        let mut huge_sps = vec![0, 0, 0, 1, 0x67];
        huge_sps.resize(4 + 4097, 0x11);
        huge_sps.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88]);
        assert!(matches!(
            parse_annexb_checked(VideoCodec::H264, &huge_sps),
            Err(VideoError::NeedIdr(_))
        ));

        // 4. > 16 KiB total param sets rejected (5 x 3500B = 17500B > 16384B)
        let mut huge_total = Vec::new();
        for _ in 0..5 {
            huge_total.extend_from_slice(&[0, 0, 0, 1, 0x67]);
            huge_total.extend(std::iter::repeat_n(0x22u8, 3499));
        }
        huge_total.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88]);
        assert!(matches!(
            parse_annexb_checked(VideoCodec::H264, &huge_total),
            Err(VideoError::NeedIdr(_))
        ));

        // 5. Oversized SPS dimensions (> 8192 width AND > 33 MP 6000x6000) rejected fail-closed!
        let pps = [0x68u8, 0xCE, 0x38, 0x80];
        let dummy_idr = [0x65u8, 0x88, 0x84, 0x00, 0x10];
        for (w_mbs, h_mbs) in [(513u32, 68u32), (375u32, 375u32)] {
            let sps = build_h264_baseline_sps(w_mbs, h_mbs);
            let mut frame = Vec::new();
            frame.extend_from_slice(&[0, 0, 0, 1]);
            frame.extend_from_slice(&sps);
            frame.extend_from_slice(&[0, 0, 0, 1]);
            frame.extend_from_slice(&pps);
            frame.extend_from_slice(&[0, 0, 0, 1]);
            frame.extend_from_slice(&dummy_idr);

            let mut dec = V2VideoDecoder::new(VideoCodec::H264).unwrap();
            let err = dec.decode_raw_bgra(&frame).unwrap_err();
            assert!(
                matches!(err, VideoError::NeedIdr(_)),
                "oversized SPS ({}x{}) must be rejected with NeedIdr, got {err:?}",
                w_mbs * 16,
                h_mbs * 16
            );
        }

        // 6. Parameter sets carried on a non-IDR frame MUST NOT activate or replace active session.
        let mut enc_small =
            V2VideoEncoder::new_with_vt_config(VideoCodec::H264, 128, 128, 30, 500_000, 60)
                .unwrap();
        let mut enc_big =
            V2VideoEncoder::new_with_vt_config(VideoCodec::H264, 256, 256, 30, 800_000, 60)
                .unwrap();
        let idr_small = enc_small
            .encode_i420_with_idr(&generate_desktop_scene_i420(128, 128, 0), 0, true)
            .unwrap();
        let p_small = enc_small
            .encode_i420(&generate_desktop_scene_i420(128, 128, 1), 33)
            .unwrap();
        assert!(!p_small.meta.is_idr);
        let idr_big = enc_big
            .encode_i420_with_idr(&generate_desktop_scene_i420(256, 256, 0), 0, true)
            .unwrap();

        // Extract big SPS/PPS prefix (everything before IDR NAL) and prepend to small P-frame!
        let mut dec = V2VideoDecoder::new(VideoCodec::H264).unwrap();
        // Before any IDR, P-frame with prepended SPS/PPS MUST still fail with NeedIdr!
        let mut poisoned_p = idr_big.data.clone();
        // Replace IDR slice with non-IDR P slice from p_small:
        if let Some(pos) = poisoned_p.windows(5).rposition(|w| w[0..4] == [0, 0, 0, 1] && (w[4] & 0x1F) == 5) {
            poisoned_p.truncate(pos);
            poisoned_p.extend_from_slice(&p_small.data);
            assert!(matches!(
                dec.decode_raw_bgra(&poisoned_p),
                Err(VideoError::NeedIdr(_))
            ));
            // Activate valid 128x128 session via IDR.
            let ok0 = dec.decode_raw_bgra(&idr_small.data).unwrap();
            assert_eq!((ok0.width, ok0.height), (128, 128));
            // Feeding non-IDR P-frame carrying 256x256 SPS/PPS MUST ignore the non-IDR param sets
            // and keep decoding at 128x128 cleanly!
            let ok1 = dec.decode_raw_bgra(&poisoned_p).unwrap();
            assert_eq!((ok1.width, ok1.height), (128, 128));
        }
    }

    #[cfg(target_os = "macos")]
    fn run_annexb_fuzz_iterations(iterations: usize) {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
        let next_u64 = |s: &mut u64| -> u64 {
            let mut x = *s;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *s = x;
            x
        };

        let mut buf = Vec::with_capacity(2048);
        for iter in 0..iterations {
            buf.clear();
            let codec = if (iter & 1) == 0 {
                VideoCodec::H264
            } else {
                VideoCodec::Hevc
            };
            let mode = next_u64(&mut state) % 6;
            match mode {
                0 => {
                    // Pure random bytes
                    let len = (next_u64(&mut state) % 256) as usize;
                    for _ in 0..len {
                        buf.push(next_u64(&mut state) as u8);
                    }
                }
                1 => {
                    // Structure-aware valid/mutated multi-NAL Annex-B with 3B & 4B start codes
                    let nals = ((next_u64(&mut state) % 70) + 1) as usize;
                    for _ in 0..nals {
                        if (next_u64(&mut state) & 1) == 0 {
                            buf.extend_from_slice(&[0, 0, 0, 1]);
                        } else {
                            buf.extend_from_slice(&[0, 0, 1]);
                        }
                        let nlen = (next_u64(&mut state) % 24) as usize;
                        for _ in 0..nlen {
                            buf.push(next_u64(&mut state) as u8);
                        }
                    }
                }
                2 => {
                    // Parameter-set flood (SPS/PPS/VPS boundary testing)
                    let cnt = ((next_u64(&mut state) % 22) + 1) as usize;
                    for _ in 0..cnt {
                        buf.extend_from_slice(&[0, 0, 0, 1]);
                        if codec == VideoCodec::H264 {
                            let hdr = if (next_u64(&mut state) & 1) == 0 { 0x67 } else { 0x68 };
                            buf.push(hdr);
                        } else {
                            let nt = 32u8 + (next_u64(&mut state) % 3) as u8;
                            buf.push(nt << 1);
                            buf.push(0x01);
                        }
                        let plen = (next_u64(&mut state) % 64) as usize;
                        for _ in 0..plen {
                            buf.push(next_u64(&mut state) as u8);
                        }
                    }
                    buf.extend_from_slice(&[0, 0, 0, 1]);
                    if codec == VideoCodec::H264 {
                        buf.extend_from_slice(&[0x65, 0x88, 0x84]);
                    } else {
                        buf.extend_from_slice(&[0x26, 0x01, 0xAF]);
                    }
                }
                3 => {
                    // Edge start-code patterns (consecutive start codes, trailing start codes, zeros)
                    let len = (next_u64(&mut state) % 48) as usize;
                    for _ in 0..len {
                        let b = match next_u64(&mut state) % 4 {
                            0 | 1 => 0x00,
                            2 => 0x01,
                            _ => (next_u64(&mut state) & 0xFF) as u8,
                        };
                        buf.push(b);
                    }
                }
                4 => {
                    // Forbidden zero bit and truncated HEVC 1-byte NALs
                    buf.extend_from_slice(&[0, 0, 0, 1]);
                    buf.push(0x80 | (next_u64(&mut state) as u8));
                    if (next_u64(&mut state) & 1) == 0 {
                        buf.push(next_u64(&mut state) as u8);
                    }
                }
                _ => {
                    // Oversized parameter set boundary around 4096 bytes
                    buf.extend_from_slice(&[0, 0, 0, 1]);
                    if codec == VideoCodec::H264 {
                        buf.push(0x67);
                    } else {
                        buf.extend_from_slice(&[0x42, 0x01]);
                    }
                    let sz = 4090 + (next_u64(&mut state) % 16) as usize;
                    buf.resize(buf.len() + sz, 0x33);
                    buf.extend_from_slice(&[0, 0, 0, 1, 0x65, 0x88]);
                }
            }
            let _ = parse_annexb_checked(codec, &buf);
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vt_annexb_parser_fuzz_50k_fast() {
        run_annexb_fuzz_iterations(50_000);
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "heavy 1,000,000-iteration Annex-B parser fuzz test (run with --release -- --ignored --nocapture)"]
    fn macos_vt_annexb_parser_fuzz_1m_iterations() {
        let t0 = Instant::now();
        run_annexb_fuzz_iterations(1_000_000);
        eprintln!(
            "Annex-B fuzz 1,000,000 iterations passed with 0 panics/UB in {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_vt_5pct_slice_loss_recovery_within_1_idr() {
        for codec in [VideoCodec::H264, VideoCodec::Hevc] {
            let mut enc =
                V2VideoEncoder::new_with_vt_config(codec, 640, 360, 30, 2_000_000, 120).unwrap();
            let mut dec = V2VideoDecoder::new(codec).unwrap();
            let mut reassembler = VideoReassembler::default();
            let mut slice_counter = 0usize;
            let mut dropped_slices = 0usize;
            let mut total_slices = 0usize;
            let mut need_idr = false;
            let mut loss_events = 0usize;
            let mut max_recovery_frames = 0usize;
            let mut frames_since_loss = 0usize;
            let mut dropped_frames = 0usize;
            let mut decoded_ok = 0usize;
            let mut max_recovery_dur = Duration::ZERO;
            let mut loss_started_at: Option<Instant> = None;

            for idx in 0..90u32 {
                let src = generate_desktop_scene_i420(640, 360, idx);
                let force_idr = idx == 0 || need_idr;
                let encoded = enc
                    .encode_i420_with_idr(&src, (idx as i64) * 33, force_idr)
                    .unwrap();
                let chunk_size = 900usize;
                let slice_cnt = encoded.data.len().div_ceil(chunk_size).max(1) as u16;
                let mut assembled = None;
                for s_idx in 0..slice_cnt {
                    total_slices += 1;
                    slice_counter += 1;
                    // Deterministic 5% slice drop (every 20th slice), except frame 0 cold-start IDR
                    // and recovery IDRs so we test recovery within 1 IDR roundtrip cleanly.
                    let drop_this = idx > 0 && !force_idr && slice_counter.is_multiple_of(20);
                    if drop_this {
                        dropped_slices += 1;
                        continue;
                    }
                    let start = (s_idx as usize) * chunk_size;
                    let end = (start + chunk_size).min(encoded.data.len());
                    let slice = VideoSlice {
                        codec_id: encoded.meta.codec_id,
                        frame_id: encoded.meta.frame_id,
                        ref_frame_id: encoded.meta.ref_frame_id,
                        ltr_slot: 0,
                        is_idr: encoded.meta.is_idr,
                        is_ref: true,
                        max_age_ms: 200,
                        slice_idx: s_idx,
                        slice_cnt,
                        data: encoded.data[start..end].to_vec(),
                    };
                    if let Some(frame) = reassembler.push_slice(slice, (idx as u64) * 33) {
                        assembled = Some(frame);
                    }
                }
                if let Some(frame) = assembled {
                    let dec_res = dec.decode_raw_bgra(&frame.data);
                    assert!(
                        dec_res.is_ok(),
                        "{} frame {idx} (is_idr={}) decode failed after reassembly: {dec_res:?}",
                        codec.name(),
                        frame.is_idr
                    );
                    decoded_ok += 1;
                    if need_idr && frame.is_idr {
                        need_idr = false;
                        max_recovery_frames = max_recovery_frames.max(frames_since_loss);
                        if let Some(t_loss) = loss_started_at.take() {
                            max_recovery_dur = max_recovery_dur.max(t_loss.elapsed());
                        }
                        frames_since_loss = 0;
                    }
                } else {
                    dropped_frames += 1;
                    // Frame lost due to dropped slice -> request immediate IDR on next frame (1 RTT).
                    if !need_idr {
                        loss_events += 1;
                        frames_since_loss = 1;
                        loss_started_at = Some(Instant::now());
                    } else {
                        frames_since_loss += 1;
                    }
                    need_idr = true;
                }
            }
            assert!(
                dropped_slices > 0 && loss_events > 0 && total_slices > 0,
                "{} expected simulated 5% drops",
                codec.name()
            );
            assert!(
                max_recovery_frames <= 1 && max_recovery_dur <= Duration::from_secs(1),
                "{} recovery exceeded 1 IDR / 1s (frames={max_recovery_frames}, dur={max_recovery_dur:?})",
                codec.name()
            );
            assert_eq!(
                decoded_ok + dropped_frames,
                90,
                "{} every non-dropped frame must decode cleanly",
                codec.name()
            );
            assert!(
                decoded_ok >= 45,
                "{} unexpectedly low decoded frame count: {decoded_ok} (total_slices={total_slices}, dropped={dropped_slices})",
                codec.name()
            );
        }
    }

    #[cfg(target_os = "macos")]
    fn current_rss_bytes() -> Option<u64> {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) };
        if rc == 0 {
            let u = unsafe { usage.assume_init() };
            // On macOS, ru_maxrss is in bytes.
            Some(u.ru_maxrss as u64)
        } else {
            None
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    #[ignore = "heavy 10,000-frame + 100-rebuild stability/leak test (run with --release -- --ignored --nocapture)"]
    fn macos_vt_stability_10k_frames_and_100_rebuilds() {
        let t0 = Instant::now();
        for codec in [VideoCodec::H264, VideoCodec::Hevc] {
            let mut enc =
                V2VideoEncoder::new_with_vt_config(codec, 128, 128, 60, 500_000, 120).unwrap();
            let mut dec = V2VideoDecoder::new(codec).unwrap();
            let mut bgra = vec![0u8; 128 * 128 * 4];
            let frame_a = generate_desktop_scene_i420(128, 128, 0);
            let frame_b = generate_desktop_scene_i420(128, 128, 1);

            // Warm up 100 frames before capturing baseline RSS.
            for idx in 0..100u32 {
                let src = if (idx & 1) == 0 { &frame_a } else { &frame_b };
                let e = enc.encode_i420_with_idr(src, (idx as i64) * 16, idx == 0).unwrap();
                let _ = dec.decode_raw_bgra_into(&e.data, &mut bgra).unwrap();
            }
            let rss_before = current_rss_bytes().unwrap_or(0);

            // 10,000 continuous frames + 100 full encoder/decoder rebuilds.
            for idx in 0..10_000u32 {
                let is_rebuild = idx > 0 && idx.is_multiple_of(100);
                if is_rebuild {
                    enc = V2VideoEncoder::new_with_vt_config(codec, 128, 128, 60, 500_000, 120)
                        .unwrap();
                    dec = V2VideoDecoder::new(codec).unwrap();
                }
                let src = if (idx & 1) == 0 { &frame_a } else { &frame_b };
                let e = enc
                    .encode_i420_with_idr(src, (idx as i64) * 16, idx == 0 || is_rebuild)
                    .unwrap();
                let (w, h, _) = dec.decode_raw_bgra_into(&e.data, &mut bgra).unwrap();
                assert_eq!((w, h), (128, 128));
            }
            let rss_after = current_rss_bytes().unwrap_or(0);
            let growth_mib = rss_after.saturating_sub(rss_before) as f64 / (1024.0 * 1024.0);
            eprintln!(
                "VT stability {}: 10,000 frames + 100 rebuilds ok; maxrss before={:.2} MiB after={:.2} MiB delta={:.2} MiB",
                codec.name(),
                rss_before as f64 / (1024.0 * 1024.0),
                rss_after as f64 / (1024.0 * 1024.0),
                growth_mib
            );
            assert!(
                growth_mib < 64.0,
                "{} unexpected RSS growth after 10k frames + 100 rebuilds: {growth_mib:.2} MiB",
                codec.name()
            );
        }
        eprintln!(
            "Total 20,000-frame + 200-rebuild stability test finished in {:.2}s",
            t0.elapsed().as_secs_f64()
        );
    }
}
