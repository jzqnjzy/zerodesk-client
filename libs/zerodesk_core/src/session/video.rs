// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    manager::DEFAULT_V2_CAP_BITS,
    vt_codec::{self, VtDecoder, VtEncoder},
};
use scrap::{
    aom::{aom_img_fmt, AomDecoder, AomEncoder, AomEncoderConfig},
    codec::{EncoderApi, EncoderCfg},
    EncodeYuvFormat, GoogleImage, Pixfmt, VpxDecoder, VpxDecoderConfig, VpxEncoder,
    VpxEncoderConfig, VpxVideoCodecId, STRIDE_ALIGN,
};
use std::{fmt, str::FromStr};
use v2_transport::{
    AssembledVideoFrame, VideoFrameMeta, CAP_CODEC_AV1, CAP_CODEC_H264, CAP_CODEC_HEVC_OS_HW,
    CAP_CODEC_VP9, VIDEO_REASSEMBLER_MAX_AGE_MS,
};

pub const CODEC_ID_AV1: u8 = 1;
pub const CODEC_ID_VP9: u8 = 2;
pub const CODEC_ID_H264: u8 = 3;
pub const CODEC_ID_HEVC: u8 = 4;
pub const MAX_FRAME_DIM: usize = 8192;
pub const MAX_CONSECUTIVE_DECODE_FAILURES: u32 = 30;
pub const DEFAULT_H264_1080P_BITRATE_BPS: u32 = 8_000_000;
pub const DEFAULT_HEVC_1080P_BITRATE_BPS: u32 = 6_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VideoCodec {
    Vp9,
    Av1,
    H264,
    Hevc,
}

impl VideoCodec {
    pub fn codec_id(self) -> u8 {
        match self {
            Self::Av1 => CODEC_ID_AV1,
            Self::Vp9 => CODEC_ID_VP9,
            Self::H264 => CODEC_ID_H264,
            Self::Hevc => CODEC_ID_HEVC,
        }
    }

    pub fn from_codec_id(id: u8) -> Result<Self, VideoError> {
        match id {
            CODEC_ID_AV1 => Ok(Self::Av1),
            CODEC_ID_VP9 => Ok(Self::Vp9),
            CODEC_ID_H264 => Ok(Self::H264),
            CODEC_ID_HEVC => Ok(Self::Hevc),
            other => Err(VideoError::UnsupportedCodecId(other)),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Vp9 => "vp9",
            Self::Av1 => "av1",
            Self::H264 => "h264",
            Self::Hevc => "hevc",
        }
    }

    pub fn parse_name(s: &str) -> Result<Self, VideoError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "vp9" => Ok(Self::Vp9),
            "av1" => Ok(Self::Av1),
            "h264" => Ok(Self::H264),
            "hevc" => Ok(Self::Hevc),
            _ => Err(VideoError::InvalidInput(format!(
                "unsupported codec '{s}' (expected vp9, av1, h264, or hevc)"
            ))),
        }
    }

    pub fn cap_bit(self) -> u64 {
        match self {
            Self::Av1 => CAP_CODEC_AV1,
            Self::Vp9 => CAP_CODEC_VP9,
            Self::H264 => CAP_CODEC_H264,
            Self::Hevc => CAP_CODEC_HEVC_OS_HW,
        }
    }

    pub fn is_hw_vt(self) -> bool {
        matches!(self, Self::H264 | Self::Hevc)
    }
}

impl fmt::Display for VideoCodec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for VideoCodec {
    type Err = VideoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse_name(s)
    }
}

/// Returns the local V2 capability bitmask, OR'ing `DEFAULT_V2_CAP_BITS` with any OS-hardware
/// H.264/HEVC capabilities verified by `zd_vt_probe_capabilities()` (cached once per process).
pub fn local_v2_cap_bits() -> u64 {
    DEFAULT_V2_CAP_BITS | vt_codec::probed_vt_cap_bits()
}

/// Deterministic helper for testing HW-disabled fallback without mutating process environment.
pub fn local_v2_cap_bits_with_vt_disable(disable_hw: bool) -> u64 {
    DEFAULT_V2_CAP_BITS | vt_codec::probed_vt_cap_bits_with_disable(disable_hw)
}

/// Negotiates a common video codec from local and peer capability bitmasks.
/// - When `preferred` is `None`, selects in strict priority order: `Hevc > H264 > Vp9 > Av1`.
/// - When `preferred` is `Some(c)`, verifies `c.cap_bit()` is present in `local_caps & peer_caps`;
///   if absent, fails closed with `VideoError::NoCommonCodec` (never silently switches).
pub fn negotiate_video_codec(
    local_caps: u64,
    peer_caps: u64,
    preferred: Option<VideoCodec>,
) -> Result<VideoCodec, VideoError> {
    let common = local_caps & peer_caps;
    if let Some(pref) = preferred {
        if (common & pref.cap_bit()) != 0 {
            return Ok(pref);
        }
        return Err(VideoError::NoCommonCodec {
            local_caps,
            peer_caps,
            preferred: Some(pref),
        });
    }
    for candidate in [
        VideoCodec::Hevc,
        VideoCodec::H264,
        VideoCodec::Vp9,
        VideoCodec::Av1,
    ] {
        if (common & candidate.cap_bit()) != 0 {
            return Ok(candidate);
        }
    }
    Err(VideoError::NoCommonCodec {
        local_caps,
        peer_caps,
        preferred: None,
    })
}

#[derive(Debug)]
pub enum VideoError {
    InvalidInput(String),
    UnsupportedCodecId(u8),
    CodecMismatch { expected: u8, actual: u8 },
    HardwareUnavailable(String),
    NeedIdr(String),
    CodecFailed { codec: VideoCodec, reason: String },
    NoCommonCodec {
        local_caps: u64,
        peer_caps: u64,
        preferred: Option<VideoCodec>,
    },
    Encoder(String),
    Decoder(String),
    NoOutputFrame,
}

impl fmt::Display for VideoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidInput(msg) => write!(f, "invalid video input: {msg}"),
            Self::UnsupportedCodecId(id) => write!(f, "unsupported V2 codec_id {id}"),
            Self::CodecMismatch { expected, actual } => {
                write!(f, "codec_id mismatch: expected {expected}, got {actual}")
            }
            Self::HardwareUnavailable(msg) => write!(f, "hardware video codec unavailable: {msg}"),
            Self::NeedIdr(msg) => write!(f, "video decoder requires IDR: {msg}"),
            Self::CodecFailed { codec, reason } => {
                write!(f, "video codec {} failed closed: {reason}", codec.name())
            }
            Self::NoCommonCodec {
                local_caps,
                peer_caps,
                preferred,
            } => write!(
                f,
                "no common video codec (local={local_caps:#x}, peer={peer_caps:#x}, preferred={preferred:?})"
            ),
            Self::Encoder(msg) => write!(f, "video encoder error: {msg}"),
            Self::Decoder(msg) => write!(f, "video decoder error: {msg}"),
            Self::NoOutputFrame => write!(f, "codec produced no output frame"),
        }
    }
}

impl std::error::Error for VideoError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BgraFrame {
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub enum DecodedVideoFrame {
    I420(I420Frame),
    Bgra(BgraFrame),
}

impl DecodedVideoFrame {
    pub fn into_i420(self) -> Result<I420Frame, VideoError> {
        match self {
            Self::I420(f) => Ok(f),
            Self::Bgra(b) => vt_codec::bgra_to_i420_bt709(&b),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I420Frame {
    pub width: usize,
    pub height: usize,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

impl I420Frame {
    pub fn validate(&self) -> Result<(), VideoError> {
        if self.width == 0
            || self.height == 0
            || (self.width & 1) != 0
            || (self.height & 1) != 0
            || self.width > MAX_FRAME_DIM
            || self.height > MAX_FRAME_DIM
        {
            return Err(VideoError::InvalidInput(format!(
                "I420 dimensions must be positive, even, and <= {MAX_FRAME_DIM}, got {}x{}",
                self.width, self.height
            )));
        }
        let y_len = self
            .width
            .checked_mul(self.height)
            .ok_or_else(|| VideoError::InvalidInput("I420 Y plane size overflow".into()))?;
        let uv_len = (self.width / 2)
            .checked_mul(self.height / 2)
            .ok_or_else(|| VideoError::InvalidInput("I420 UV plane size overflow".into()))?;
        if self.y.len() != y_len || self.u.len() != uv_len || self.v.len() != uv_len {
            return Err(VideoError::InvalidInput(format!(
                "I420 plane sizes mismatch for {}x{}: y={} (expected {y_len}), u={} (expected {uv_len}), v={} (expected {uv_len})",
                self.width,
                self.height,
                self.y.len(),
                self.u.len(),
                self.v.len()
            )));
        }
        Ok(())
    }

    pub fn new(width: usize, height: usize, y: Vec<u8>, u: Vec<u8>, v: Vec<u8>) -> Result<Self, VideoError> {
        let frame = Self {
            width,
            height,
            y,
            u,
            v,
        };
        frame.validate()?;
        Ok(frame)
    }

    pub fn pack_for_encoder(&self, fmt: &EncodeYuvFormat) -> Result<Vec<u8>, VideoError> {
        self.validate()?;
        if fmt.pixfmt != Pixfmt::I420 {
            return Err(VideoError::InvalidInput(format!(
                "expected I420 encoder format, got {:?}",
                fmt.pixfmt
            )));
        }
        if self.width != fmt.w || self.height != fmt.h {
            return Err(VideoError::InvalidInput(format!(
                "frame dimensions {}x{} do not match encoder {}x{}",
                self.width, self.height, fmt.w, fmt.h
            )));
        }
        if fmt.stride.len() < 3 {
            return Err(VideoError::InvalidInput("encoder EncodeYuvFormat missing strides".into()));
        }
        let y_stride = fmt.stride[0];
        let u_stride = fmt.stride[1];
        let v_stride = fmt.stride[2];
        let uv_w = self.width / 2;
        let uv_h = self.height / 2;
        if y_stride < self.width || u_stride < uv_w || v_stride < uv_w {
            return Err(VideoError::InvalidInput("encoder stride smaller than plane width".into()));
        }
        let y_end = y_stride
            .checked_mul(self.height)
            .ok_or_else(|| VideoError::InvalidInput("encoder Y plane byte length overflow".into()))?;
        let u_size = u_stride
            .checked_mul(uv_h)
            .ok_or_else(|| VideoError::InvalidInput("encoder U plane byte length overflow".into()))?;
        let v_size = v_stride
            .checked_mul(uv_h)
            .ok_or_else(|| VideoError::InvalidInput("encoder V plane byte length overflow".into()))?;
        let u_end = fmt
            .u
            .checked_add(u_size)
            .ok_or_else(|| VideoError::InvalidInput("encoder U plane offset overflow".into()))?;
        let v_end = fmt
            .v
            .checked_add(v_size)
            .ok_or_else(|| VideoError::InvalidInput("encoder V plane offset overflow".into()))?;
        let total = y_end.max(u_end).max(v_end);

        let mut buf = vec![0u8; total];
        for row in 0..self.height {
            let src = &self.y[row * self.width..(row + 1) * self.width];
            let dst = &mut buf[row * y_stride..row * y_stride + self.width];
            dst.copy_from_slice(src);
        }
        for row in 0..uv_h {
            let src_u = &self.u[row * uv_w..(row + 1) * uv_w];
            let dst_u = &mut buf[fmt.u + row * u_stride..fmt.u + row * u_stride + uv_w];
            dst_u.copy_from_slice(src_u);

            let src_v = &self.v[row * uv_w..(row + 1) * uv_w];
            let dst_v = &mut buf[fmt.v + row * v_stride..fmt.v + row * v_stride + uv_w];
            dst_v.copy_from_slice(src_v);
        }
        Ok(buf)
    }

    pub fn from_google_image(img: &impl GoogleImage) -> Result<Self, VideoError> {
        let chroma = format!("{:?}", img.chroma());
        if chroma != "I420" {
            return Err(VideoError::Decoder(format!(
                "decoded image has unsupported chroma format {chroma} (expected I420)"
            )));
        }
        let width = img.width();
        let height = img.height();
        if width == 0
            || height == 0
            || (width & 1) != 0
            || (height & 1) != 0
            || width > MAX_FRAME_DIM
            || height > MAX_FRAME_DIM
        {
            return Err(VideoError::Decoder(format!(
                "decoded image has invalid I420 dimensions {width}x{height} (max {MAX_FRAME_DIM})"
            )));
        }
        let strides = img.stride();
        if strides.len() < 3 || strides[0] <= 0 || strides[1] <= 0 || strides[2] <= 0 {
            return Err(VideoError::Decoder("decoded image has invalid strides".into()));
        }
        let y_stride = strides[0] as usize;
        let u_stride = strides[1] as usize;
        let v_stride = strides[2] as usize;
        let uv_w = width / 2;
        let uv_h = height / 2;
        if y_stride < width || u_stride < uv_w || v_stride < uv_w {
            return Err(VideoError::Decoder("decoded image stride smaller than width".into()));
        }
        if u_stride != v_stride {
            return Err(VideoError::Decoder(format!(
                "decoded image has mismatched UV strides: u={u_stride}, v={v_stride}"
            )));
        }
        let planes = img.planes();
        if planes.len() < 3
            || planes[0].is_null()
            || planes[1].is_null()
            || planes[2].is_null()
        {
            return Err(VideoError::Decoder("decoded image has missing or null plane pointers".into()));
        }
        let y_needed = y_stride
            .checked_mul(height)
            .ok_or_else(|| VideoError::Decoder("decoded Y plane size overflow".into()))?;
        let u_needed = u_stride
            .checked_mul(uv_h)
            .ok_or_else(|| VideoError::Decoder("decoded U plane size overflow".into()))?;
        let v_needed = v_stride
            .checked_mul(uv_h)
            .ok_or_else(|| VideoError::Decoder("decoded V plane size overflow".into()))?;

        let (y_src, u_src, v_src) = img.data();
        if y_src.len() < y_needed || u_src.len() < u_needed || v_src.len() < v_needed {
            return Err(VideoError::Decoder("decoded image plane buffer truncated".into()));
        }

        let mut y = Vec::with_capacity(width * height);
        for row in 0..height {
            let start = row * y_stride;
            y.extend_from_slice(&y_src[start..start + width]);
        }
        let mut u = Vec::with_capacity(uv_w * uv_h);
        for row in 0..uv_h {
            let start = row * u_stride;
            u.extend_from_slice(&u_src[start..start + uv_w]);
        }
        let mut v = Vec::with_capacity(uv_w * uv_h);
        for row in 0..uv_h {
            let start = row * v_stride;
            v.extend_from_slice(&v_src[start..start + uv_w]);
        }
        Self::new(width, height, y, u, v)
    }
}

/// Synthesizes a deterministic animated I420 frame with a smooth moving background gradient,
/// high-contrast moving geometric blocks, a bottom frame-counter progress bar, and top-left
/// frame-index indicator tiles so inter-frame prediction is genuinely exercised.
pub fn generate_animated_i420(width: usize, height: usize, frame_idx: u32) -> I420Frame {
    let width = width.clamp(2, MAX_FRAME_DIM) & !1;
    let height = height.clamp(2, MAX_FRAME_DIM) & !1;
    let f = frame_idx as usize;
    let mut y = vec![0u8; width * height];
    let uv_w = width / 2;
    let uv_h = height / 2;
    let mut u = vec![128u8; uv_w * uv_h];
    let mut v = vec![128u8; uv_w * uv_h];

    let x_shift = (f * 3) % width;
    let y_shift = (f * 2) % height;

    // Smooth moving gradient background (keeps high spatial correlation like a real desktop).
    for row in 0..height {
        let row_off = row * width;
        let gy = ((row + y_shift) * 90) / height;
        for col in 0..width {
            let gx = ((col + x_shift) * 110) / width;
            y[row_off + col] = (32 + ((gx + gy) % 160)) as u8;
        }
    }

    // Moving high-contrast UI window rectangle #1 (bright card with dark border).
    let box_w = (width / 5).max(32).min(width);
    let box_h = (height / 4).max(32).min(height);
    let max_box_x = width.saturating_sub(box_w);
    let max_box_y = height.saturating_sub(box_h);
    let box_x = if max_box_x == 0 {
        0
    } else {
        (f * 7) % max_box_x
    };
    let box_y = if max_box_y == 0 {
        0
    } else {
        (height / 6 + (f * 3) % (height / 2).max(1)).min(max_box_y)
    };
    let border = 4usize.min(box_w / 2).min(box_h / 2);
    for row in box_y..(box_y + box_h) {
        let row_off = row * width;
        let is_border_y = row < box_y + border || row >= box_y + box_h - border;
        for col in box_x..(box_x + box_w) {
            let is_border_x = col < box_x + border || col >= box_x + box_w - border;
            y[row_off + col] = if is_border_x || is_border_y { 24 } else { 228 };
        }
    }

    // Moving high-contrast rectangle #2 moving in opposite horizontal direction.
    let box2_w = (width / 7).max(24).min(width);
    let box2_h = (height / 5).max(24).min(height);
    let max_box2_x = width.saturating_sub(box2_w);
    let max_box2_y = height.saturating_sub(box2_h);
    let box2_x = if max_box2_x == 0 {
        0
    } else {
        max_box2_x - ((f * 5) % max_box2_x)
    };
    let box2_y = if max_box2_y == 0 {
        0
    } else {
        (height / 2 + (f * 2) % (height / 4).max(1)).min(max_box2_y)
    };
    for row in box2_y..(box2_y + box2_h) {
        let row_off = row * width;
        for col in box2_x..(box2_x + box2_w) {
            y[row_off + col] = 48;
        }
    }

    // Top-left 12-bit binary frame index indicator tiles (each 16x16 px).
    let tile = 16usize;
    if width >= tile * 14 && height >= tile * 3 {
        for bit in 0..12usize {
            let set = ((frame_idx >> bit) & 1) != 0;
            let val = if set { 235u8 } else { 20u8 };
            let tx0 = tile + bit * (tile + 4);
            let ty0 = tile;
            for row in ty0..(ty0 + tile) {
                let row_off = row * width;
                for col in tx0..(tx0 + tile) {
                    y[row_off + col] = val;
                }
            }
        }
    }

    // Bottom frame counter progress bar.
    let bar_h = 20usize.min(height / 8);
    let bar_y0 = height
        .saturating_sub(bar_h.saturating_add(12))
        .min(height.saturating_sub(bar_h));
    let filled_w = (((f % 300) + 1) * width) / 300;
    for row in bar_y0..(bar_y0 + bar_h) {
        let row_off = row * width;
        for col in 0..width {
            y[row_off + col] = if col < filled_w { 230 } else { 40 };
        }
    }

    // Smooth chroma planes with colored accent inside moving rectangle #1.
    for row in 0..uv_h {
        let row_off = row * uv_w;
        for col in 0..uv_w {
            let px = col * 2;
            let py = row * 2;
            if px >= box_x && px < box_x + box_w && py >= box_y && py < box_y + box_h {
                u[row_off + col] = 168;
                v[row_off + col] = 96;
            } else if px >= box2_x && px < box2_x + box2_w && py >= box2_y && py < box2_y + box2_h {
                u[row_off + col] = 96;
                v[row_off + col] = 176;
            } else {
                u[row_off + col] = (108 + ((col + (x_shift / 2)) * 40 / uv_w.max(1))) as u8;
                v[row_off + col] = (108 + ((row + (y_shift / 2)) * 40 / uv_h.max(1))) as u8;
            }
        }
    }

    I420Frame {
        width,
        height,
        y,
        u,
        v,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FrameQualityMetrics {
    pub psnr_db: f64,
    pub ssim: f64,
}

/// Computes exact Y-plane PSNR in dB (capped at `99.99` dB for lossless/exact match so JSON stays finite).
pub fn compute_y_psnr(reference: &I420Frame, decoded: &I420Frame) -> Result<f64, VideoError> {
    reference.validate()?;
    decoded.validate()?;
    if reference.width != decoded.width || reference.height != decoded.height {
        return Err(VideoError::InvalidInput(format!(
            "PSNR dimension mismatch: ref {}x{} vs dec {}x{}",
            reference.width, reference.height, decoded.width, decoded.height
        )));
    }
    let count = reference.y.len();
    let mut sum_sq = 0.0f64;
    for (&r, &d) in reference.y.iter().zip(decoded.y.iter()) {
        let diff = (r as f64) - (d as f64);
        sum_sq += diff * diff;
    }
    let mse = sum_sq / (count as f64);
    if mse <= 1e-12 {
        Ok(99.99)
    } else {
        Ok(10.0 * ((255.0 * 255.0) / mse).log10())
    }
}

/// Computes Y-plane SSIM (Wang et al. 2004) over non-overlapping 8x8 blocks with `C1=(0.01*255)^2`, `C2=(0.03*255)^2`.
pub fn compute_y_ssim(reference: &I420Frame, decoded: &I420Frame) -> Result<f64, VideoError> {
    reference.validate()?;
    decoded.validate()?;
    if reference.width != decoded.width || reference.height != decoded.height {
        return Err(VideoError::InvalidInput(format!(
            "SSIM dimension mismatch: ref {}x{} vs dec {}x{}",
            reference.width, reference.height, decoded.width, decoded.height
        )));
    }
    let w = reference.width;
    let h = reference.height;
    let bx_cnt = w / 8;
    let by_cnt = h / 8;
    if bx_cnt == 0 || by_cnt == 0 {
        return Err(VideoError::InvalidInput("frame too small for 8x8 SSIM".into()));
    }
    const C1: f64 = 6.5025; // (0.01 * 255)^2
    const C2: f64 = 58.5225; // (0.03 * 255)^2
    const N: f64 = 64.0;

    let mut ssim_sum = 0.0f64;
    for by in 0..by_cnt {
        let y0 = by * 8;
        for bx in 0..bx_cnt {
            let x0 = bx * 8;
            let mut sum_x = 0.0f64;
            let mut sum_y = 0.0f64;
            let mut sum_x2 = 0.0f64;
            let mut sum_y2 = 0.0f64;
            let mut sum_xy = 0.0f64;
            for dy in 0..8 {
                let row_off = (y0 + dy) * w + x0;
                for dx in 0..8 {
                    let xv = reference.y[row_off + dx] as f64;
                    let yv = decoded.y[row_off + dx] as f64;
                    sum_x += xv;
                    sum_y += yv;
                    sum_x2 += xv * xv;
                    sum_y2 += yv * yv;
                    sum_xy += xv * yv;
                }
            }
            let mu_x = sum_x / N;
            let mu_y = sum_y / N;
            let sigma_x2 = (sum_x2 / N - mu_x * mu_x).max(0.0);
            let sigma_y2 = (sum_y2 / N - mu_y * mu_y).max(0.0);
            let sigma_xy = sum_xy / N - mu_x * mu_y;

            let num = (2.0 * mu_x * mu_y + C1) * (2.0 * sigma_xy + C2);
            let den = (mu_x * mu_x + mu_y * mu_y + C1) * (sigma_x2 + sigma_y2 + C2);
            ssim_sum += num / den;
        }
    }
    Ok(ssim_sum / ((bx_cnt * by_cnt) as f64))
}

/// Synthesizes a deterministic BT.709 video-range (`Y ∈ [16..235]`, `UV ∈ [16..240]`) remote
/// desktop scene combining crisp desktop text/UI panels, a smooth multi-frequency synthetic photo
/// panel, a moving floating window & cursor, and 12-bit binary frame-index tiles.
pub fn generate_desktop_scene_i420(width: usize, height: usize, frame_idx: u32) -> I420Frame {
    let width = width.clamp(2, MAX_FRAME_DIM) & !1;
    let height = height.clamp(2, MAX_FRAME_DIM) & !1;
    let f = frame_idx as usize;
    let mut y = vec![230u8; width * height];
    let uv_w = width / 2;
    let uv_h = height / 2;
    let mut u = vec![128u8; uv_w * uv_h];
    let mut v = vec![128u8; uv_w * uv_h];

    // 1. Desktop background & top menu bar (light neutral workspace).
    let top_bar_h = (height / 24).max(16).min(height);
    for row in 0..top_bar_h {
        let off = row * width;
        for col in 0..width {
            y[off + col] = 44;
        }
    }

    // 2. Left sidebar + crisp synthetic desktop text lines (high-contrast glyph blocks).
    let split_x = (width * 55) / 100;
    let sidebar_w = (width / 7).min(split_x);
    for row in top_bar_h..height {
        let off = row * width;
        for col in 0..sidebar_w {
            y[off + col] = 212;
        }
    }
    let scroll_y = (f * 2) % 36;
    for row in (top_bar_h + 48)..height.saturating_sub(48) {
        let off = row * width;
        let line_y = (row + scroll_y) % 24;
        if (6..16).contains(&line_y) {
            let line_idx = (row + scroll_y) / 24;
            let text_end = sidebar_w + 32 + ((line_idx * 97 + 211) % (split_x.saturating_sub(sidebar_w + 64).max(1)));
            for col in (sidebar_w + 24)..text_end.min(split_x.saturating_sub(16)) {
                let cell = (col - sidebar_w) % 10;
                if cell < 6 && !(col / 10 + line_idx).is_multiple_of(7) {
                    // Anti-aliased-like stroke edges for realistic desktop font rendering.
                    let edge = line_y == 6 || line_y == 15 || cell == 0 || cell == 5;
                    y[off + col] = if edge { 88 } else { 28 };
                }
            }
        }
    }

    // 3. Right-hand synthetic photographic panel (smooth multi-frequency gradient + subtle motion).
    let photo_x0 = split_x + 12;
    let photo_x1 = width.saturating_sub(16);
    let photo_y0 = top_bar_h + 24;
    let photo_y1 = height.saturating_sub(48);
    if photo_x1 > photo_x0 + 8 && photo_y1 > photo_y0 + 8 {
        let pw = photo_x1 - photo_x0;
        let ph = photo_y1 - photo_y0;
        for row in photo_y0..photo_y1 {
            let off = row * width;
            let ry = row - photo_y0;
            let wy = ((ry + f) * 180) / ph.max(1);
            for col in photo_x0..photo_x1 {
                let rx = col - photo_x0;
                let wx = ((rx + f * 2) * 180) / pw.max(1);
                let wave = ((wx + wy) % 180) as i32;
                let tri = if wave < 90 { wave } else { 180 - wave };
                let luma = (32 + (tri * 2).min(196)) as u8;
                y[off + col] = luma;
            }
        }
        for row in (photo_y0 / 2)..(photo_y1 / 2) {
            let off = row * uv_w;
            let ry = row.saturating_sub(photo_y0 / 2);
            for col in (photo_x0 / 2)..(photo_x1 / 2) {
                let rx = col.saturating_sub(photo_x0 / 2);
                u[off + col] = (84 + ((rx + f) * 88 / (pw / 2).max(1)) % 88) as u8;
                v[off + col] = (84 + ((ry + f) * 88 / (ph / 2).max(1)) % 88) as u8;
            }
        }
    }

    // 4. Moving floating UI card + cursor (exercises inter-frame motion vectors cleanly).
    let card_w = (width / 6).max(32).min(width);
    let card_h = (height / 5).max(32).min(height);
    let max_cx = width.saturating_sub(card_w);
    let max_cy = height.saturating_sub(card_h);
    let card_x = if max_cx == 0 { 0 } else { (f * 6) % max_cx };
    let card_y = if max_cy == 0 {
        0
    } else {
        (top_bar_h + 64 + (f * 2) % (height / 3).max(1)).min(max_cy)
    };
    let border = 3usize.min(card_w / 2).min(card_h / 2);
    for row in card_y..(card_y + card_h) {
        let off = row * width;
        let is_b = row < card_y + border || row >= card_y + card_h - border;
        let is_hdr = row < card_y + 18.min(card_h);
        for col in card_x..(card_x + card_w) {
            let is_bx = col < card_x + border || col >= card_x + card_w - border;
            y[off + col] = if is_b || is_bx {
                30
            } else if is_hdr {
                72
            } else {
                224
            };
        }
    }
    for row in (card_y / 2)..((card_y + card_h) / 2).min(uv_h) {
        let off = row * uv_w;
        for col in (card_x / 2)..((card_x + card_w) / 2).min(uv_w) {
            u[off + col] = 152;
            v[off + col] = 108;
        }
    }

    // 5. Top-left 12-bit binary frame index indicator tiles (16x16 px) inside top bar / header.
    let tile = 16usize;
    if width >= tile * 14 && height >= top_bar_h + tile + 8 {
        let ty0 = top_bar_h + 6;
        for bit in 0..12usize {
            let set = ((frame_idx >> bit) & 1) != 0;
            let val = if set { 228u8 } else { 24u8 };
            let tx0 = tile + bit * (tile + 4);
            for row in ty0..(ty0 + tile) {
                let off = row * width;
                for col in tx0..(tx0 + tile) {
                    y[off + col] = val;
                }
            }
        }
    }

    I420Frame {
        width,
        height,
        y,
        u,
        v,
    }
}

/// Decodes the 12-bit binary frame-index indicator tiles written by `generate_desktop_scene_i420`.
pub fn read_desktop_scene_frame_idx(frame: &I420Frame) -> Option<u32> {
    let tile = 16usize;
    let top_bar_h = (frame.height / 24).max(16).min(frame.height);
    if frame.width < tile * 14 || frame.height < top_bar_h + tile + 8 {
        return None;
    }
    let ty0 = top_bar_h + 6;
    let mut out = 0u32;
    for bit in 0..12usize {
        let tx0 = tile + bit * (tile + 4);
        let mut sum = 0u64;
        let mut cnt = 0u64;
        for row in (ty0 + 4)..(ty0 + tile - 4) {
            let off = row * frame.width;
            for col in (tx0 + 4)..(tx0 + tile - 4) {
                sum += frame.y[off + col] as u64;
                cnt += 1;
            }
        }
        if cnt > 0 && (sum / cnt) >= 126 {
            out |= 1u32 << bit;
        }
    }
    Some(out)
}

#[derive(Debug, Clone)]
pub struct EncodedV2Frame {
    pub meta: VideoFrameMeta,
    pub data: Vec<u8>,
}

enum InnerEncoder {
    Vp9(VpxEncoder),
    Av1(AomEncoder),
    Vt(VtEncoder),
}

fn default_vt_bitrate_bps(codec: VideoCodec, width: u32, height: u32, quality: f32) -> u32 {
    let base_1080p = match codec {
        VideoCodec::Hevc => DEFAULT_HEVC_1080P_BITRATE_BPS as f64,
        _ => DEFAULT_H264_1080P_BITRATE_BPS as f64,
    };
    let area_ratio = ((width as f64) * (height as f64)) / (1920.0 * 1080.0);
    let q_scale = (quality.clamp(0.5, 4.0) as f64) / 2.0;
    let bps = (base_1080p * area_ratio.max(0.05) * q_scale).round();
    (bps as u64).clamp(500_000, 50_000_000) as u32
}

fn vt_i420_format(width: u32, height: u32) -> EncodeYuvFormat {
    let w = width as usize;
    let h = height as usize;
    let uv_w = w / 2;
    let y_len = w * h;
    let u_len = uv_w * (h / 2);
    EncodeYuvFormat {
        pixfmt: Pixfmt::I420,
        w,
        h,
        stride: vec![w, uv_w, uv_w],
        u: y_len,
        v: y_len + u_len,
    }
}

/// Video encoder supporting VP9 (`libvpx`), AV1 (`libaom`), and OS-hardware VideoToolbox
/// H.264/HEVC producing raw elementary bitstreams mapped to `v2_transport::VideoFrameMeta`.
///
/// Per `protocol-spec/spec/04-inner-channels.md` §3.3, `ltr_slot` is always `0` (and
/// `CAP_VIDEO_LTR` must remain `0`) until true encoder `mark_ltr` / `force_ref_ltr` is wired.
pub struct V2VideoEncoder {
    codec: VideoCodec,
    inner: InnerEncoder,
    yuvfmt: EncodeYuvFormat,
    next_frame_id: u32,
    prev_frame_id: Option<u32>,
}

impl V2VideoEncoder {
    pub fn new(
        codec: VideoCodec,
        width: u32,
        height: u32,
        quality: f32,
        keyframe_interval: Option<usize>,
    ) -> Result<Self, VideoError> {
        let w = width as usize;
        let h = height as usize;
        if w == 0 || h == 0 || (w & 1) != 0 || (h & 1) != 0 || w > MAX_FRAME_DIM || h > MAX_FRAME_DIM
        {
            return Err(VideoError::InvalidInput(format!(
                "encoder dimensions must be positive, even, and <= {MAX_FRAME_DIM}, got {width}x{height}"
            )));
        }
        let (inner, yuvfmt) = match codec {
            VideoCodec::Vp9 => {
                let enc = VpxEncoder::new(
                    EncoderCfg::VPX(VpxEncoderConfig {
                        width,
                        height,
                        quality,
                        codec: VpxVideoCodecId::VP9,
                        keyframe_interval,
                    }),
                    false,
                )
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
                let fmt = enc.yuvfmt();
                (InnerEncoder::Vp9(enc), fmt)
            }
            VideoCodec::Av1 => {
                let enc = AomEncoder::new(
                    EncoderCfg::AOM(AomEncoderConfig {
                        width,
                        height,
                        quality,
                        keyframe_interval,
                    }),
                    false,
                )
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
                let fmt = enc.yuvfmt();
                (InnerEncoder::Av1(enc), fmt)
            }
            VideoCodec::H264 | VideoCodec::Hevc => {
                let bitrate_bps = default_vt_bitrate_bps(codec, width, height, quality);
                let max_kf = keyframe_interval.unwrap_or(60).clamp(1, 600) as u32;
                let enc = VtEncoder::new(codec, width, height, 30, bitrate_bps, max_kf)?;
                (InnerEncoder::Vt(enc), vt_i420_format(width, height))
            }
        };
        Ok(Self {
            codec,
            inner,
            yuvfmt,
            next_frame_id: 1,
            prev_frame_id: None,
        })
    }

    /// Creates a VideoToolbox H.264/HEVC encoder with explicit FPS, bitrate, and keyframe interval.
    pub fn new_with_vt_config(
        codec: VideoCodec,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_bps: u32,
        max_keyframe_interval: u32,
    ) -> Result<Self, VideoError> {
        if !codec.is_hw_vt() {
            return Err(VideoError::InvalidInput(format!(
                "new_with_vt_config requires H264 or Hevc, got {}",
                codec.name()
            )));
        }
        let w = width as usize;
        let h = height as usize;
        if w == 0 || h == 0 || (w & 1) != 0 || (h & 1) != 0 || w > MAX_FRAME_DIM || h > MAX_FRAME_DIM
        {
            return Err(VideoError::InvalidInput(format!(
                "encoder dimensions must be positive, even, and <= {MAX_FRAME_DIM}, got {width}x{height}"
            )));
        }
        let enc = VtEncoder::new(codec, width, height, fps, bitrate_bps, max_keyframe_interval)?;
        Ok(Self {
            codec,
            inner: InnerEncoder::Vt(enc),
            yuvfmt: vt_i420_format(width, height),
            next_frame_id: 1,
            prev_frame_id: None,
        })
    }

    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    pub fn yuvfmt(&self) -> &EncodeYuvFormat {
        &self.yuvfmt
    }

    pub fn next_frame_id(&self) -> u32 {
        self.next_frame_id
    }

    pub fn vt_rebuild_count(&self) -> u64 {
        match &self.inner {
            InnerEncoder::Vt(enc) => enc.total_rebuilds(),
            _ => 0,
        }
    }

    pub fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError> {
        match &mut self.inner {
            InnerEncoder::Vt(enc) => enc.set_bitrate(bitrate_bps),
            _ => Ok(()),
        }
    }

    pub fn force_next_idr(&mut self) {
        if let InnerEncoder::Vt(enc) = &mut self.inner {
            enc.force_next_idr();
        }
    }

    /// Ensures `next_frame_id` is at least `min_next` so `frame_id` stays strictly monotonic
    /// across encoder replacements.
    pub fn advance_next_frame_id_at_least(&mut self, min_next: u32) {
        let floor = min_next.max(1);
        if floor > self.next_frame_id {
            self.next_frame_id = floor;
        }
    }

    fn finish_encoded_frame(&mut self, raw_data: Vec<u8>, is_key: bool) -> EncodedV2Frame {
        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1).max(1);

        let ref_frame_id = if is_key {
            frame_id
        } else {
            self.prev_frame_id.unwrap_or(frame_id)
        };
        self.prev_frame_id = Some(frame_id);

        let meta = VideoFrameMeta {
            display_idx: 0,
            codec_id: self.codec.codec_id(),
            frame_id,
            ref_frame_id,
            ltr_slot: 0,
            is_idr: is_key,
            is_ref: true,
            max_age_ms: VIDEO_REASSEMBLER_MAX_AGE_MS,
        };

        EncodedV2Frame {
            meta,
            data: raw_data,
        }
    }

    pub fn encode_i420(&mut self, frame: &I420Frame, pts_ms: i64) -> Result<EncodedV2Frame, VideoError> {
        self.encode_i420_with_idr(frame, pts_ms, false)
    }

    pub fn encode_i420_with_idr(
        &mut self,
        frame: &I420Frame,
        pts_ms: i64,
        force_idr: bool,
    ) -> Result<EncodedV2Frame, VideoError> {
        let (raw_data, is_key) = match &mut self.inner {
            InnerEncoder::Vt(enc) => {
                let pts_us = pts_ms.saturating_mul(1000);
                enc.encode_i420(frame, pts_us, force_idr)?
            }
            InnerEncoder::Vp9(enc) => {
                let aligned = frame.pack_for_encoder(&self.yuvfmt)?;
                let mut out: Option<(Vec<u8>, bool)> = None;
                for pkt in enc
                    .encode(pts_ms, &aligned, STRIDE_ALIGN)
                    .map_err(|e| VideoError::Encoder(e.to_string()))?
                {
                    if out.is_some() {
                        return Err(VideoError::Encoder(
                            "VP9 encoder unexpectedly emitted multiple packets for one input frame"
                                .into(),
                        ));
                    }
                    out = Some((pkt.data.to_vec(), pkt.key));
                }
                if out.is_none() {
                    for pkt in enc.flush().map_err(|e| VideoError::Encoder(e.to_string()))? {
                        if out.is_some() {
                            return Err(VideoError::Encoder(
                                "VP9 encoder flush unexpectedly emitted multiple packets".into(),
                            ));
                        }
                        out = Some((pkt.data.to_vec(), pkt.key));
                    }
                }
                out.ok_or(VideoError::NoOutputFrame)?
            }
            InnerEncoder::Av1(enc) => {
                let aligned = frame.pack_for_encoder(&self.yuvfmt)?;
                let mut out: Option<(Vec<u8>, bool)> = None;
                for pkt in enc
                    .encode(pts_ms, &aligned, STRIDE_ALIGN)
                    .map_err(|e| VideoError::Encoder(e.to_string()))?
                {
                    if out.is_some() {
                        return Err(VideoError::Encoder(
                            "AV1 encoder unexpectedly emitted multiple packets for one input frame"
                                .into(),
                        ));
                    }
                    out = Some((pkt.data.to_vec(), pkt.key));
                }
                out.ok_or(VideoError::NoOutputFrame)?
            }
        };

        Ok(self.finish_encoded_frame(raw_data, is_key))
    }

    pub fn encode_bgra(
        &mut self,
        bgra: &[u8],
        width: usize,
        height: usize,
        stride: usize,
        pts_ms: i64,
        force_idr: bool,
    ) -> Result<EncodedV2Frame, VideoError> {
        match &mut self.inner {
            InnerEncoder::Vt(enc) => {
                let pts_us = pts_ms.saturating_mul(1000);
                let (raw_data, is_key) =
                    enc.encode_bgra(bgra, width, height, stride, pts_us, force_idr)?;
                Ok(self.finish_encoded_frame(raw_data, is_key))
            }
            _ => {
                let frame = BgraFrame {
                    width,
                    height,
                    stride,
                    data: bgra.to_vec(),
                };
                let i420 = vt_codec::bgra_to_i420_bt709(&frame)?;
                self.encode_i420_with_idr(&i420, pts_ms, force_idr)
            }
        }
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn invalidate_vt_session_for_test(&mut self) {
        if let InnerEncoder::Vt(enc) = &mut self.inner {
            enc.invalidate_session_for_test();
        }
    }
}

fn extract_vpx_i420(img: &scrap::vpxcodec::Image) -> Result<I420Frame, VideoError> {
    if img.is_null() {
        return Err(VideoError::Decoder("VP9 decoder yielded null image".into()));
    }
    let raw = img.inner();
    let fmt_name = format!("{:?}", raw.fmt);
    if fmt_name != "VPX_IMG_FMT_I420"
        || raw.bit_depth != 8
        || raw.x_chroma_shift != 1
        || raw.y_chroma_shift != 1
    {
        return Err(VideoError::Decoder(format!(
            "unsupported VP9 decoded pixel format: fmt={fmt_name}, bit_depth={}, shift=({}, {})",
            raw.bit_depth, raw.x_chroma_shift, raw.y_chroma_shift
        )));
    }
    I420Frame::from_google_image(img)
}

fn extract_aom_i420(img: &scrap::aom::Image) -> Result<I420Frame, VideoError> {
    if img.is_null() {
        return Err(VideoError::Decoder("AV1 decoder yielded null image".into()));
    }
    let raw = img.inner();
    if raw.fmt != aom_img_fmt::AOM_IMG_FMT_I420
        || raw.bit_depth != 8
        || raw.monochrome != 0
        || raw.x_chroma_shift != 1
        || raw.y_chroma_shift != 1
    {
        return Err(VideoError::Decoder(format!(
            "unsupported AV1 decoded pixel format: fmt={:?}, bit_depth={}, mono={}, shift=({}, {})",
            raw.fmt, raw.bit_depth, raw.monochrome, raw.x_chroma_shift, raw.y_chroma_shift
        )));
    }
    I420Frame::from_google_image(img)
}

enum InnerDecoder {
    Vp9(VpxDecoder),
    Av1(AomDecoder),
    Vt(VtDecoder),
}

/// Real video decoder supporting VP9 (`libvpx`), AV1 (`libaom`), and OS-hardware VideoToolbox
/// H.264/HEVC (with direct 32BGRA output to avoid redundant BGRA->I420->BGRA roundtrips).
pub struct V2VideoDecoder {
    codec: VideoCodec,
    inner: InnerDecoder,
    consecutive_failures: u32,
}

impl V2VideoDecoder {
    pub fn new(codec: VideoCodec) -> Result<Self, VideoError> {
        let inner = match codec {
            VideoCodec::Vp9 => InnerDecoder::Vp9(
                VpxDecoder::new(VpxDecoderConfig {
                    codec: VpxVideoCodecId::VP9,
                })
                .map_err(|e| VideoError::Decoder(e.to_string()))?,
            ),
            VideoCodec::Av1 => {
                InnerDecoder::Av1(AomDecoder::new().map_err(|e| VideoError::Decoder(e.to_string()))?)
            }
            VideoCodec::H264 | VideoCodec::Hevc => InnerDecoder::Vt(VtDecoder::new(codec)?),
        };
        Ok(Self {
            codec,
            inner,
            consecutive_failures: 0,
        })
    }

    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    pub fn consecutive_decode_failures(&self) -> u32 {
        self.consecutive_failures
    }

    pub fn vt_rebuild_count(&self) -> u64 {
        match &self.inner {
            InnerDecoder::Vt(dec) => dec.total_rebuilds(),
            _ => 0,
        }
    }

    fn track_decode_outcome<T>(&mut self, res: Result<T, VideoError>) -> Result<T, VideoError> {
        match res {
            Ok(val) => {
                self.consecutive_failures = 0;
                Ok(val)
            }
            Err(err @ VideoError::CodecFailed { .. }) => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                Err(err)
            }
            Err(err) => {
                self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                if self.consecutive_failures >= MAX_CONSECUTIVE_DECODE_FAILURES {
                    Err(VideoError::CodecFailed {
                        codec: self.codec,
                        reason: format!(
                            "{} consecutive decode failures (last: {err})",
                            self.consecutive_failures
                        ),
                    })
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Decodes a raw frame returning the decoder's native pixel representation (`Bgra` for
    /// VideoToolbox H.264/HEVC with zero color-space roundtrip, `I420` for VP9/AV1).
    pub fn decode_raw_frame(&mut self, data: &[u8]) -> Result<DecodedVideoFrame, VideoError> {
        if data.is_empty() {
            return self.track_decode_outcome(Err(VideoError::InvalidInput(
                "empty compressed video frame".into(),
            )));
        }
        let res = match &mut self.inner {
            InnerDecoder::Vt(dec) => dec.decode_annexb_bgra(data).map(DecodedVideoFrame::Bgra),
            InnerDecoder::Vp9(dec) => {
                let mut decoded: Option<I420Frame> = None;
                for img in dec
                    .decode(data)
                    .map_err(|e| VideoError::Decoder(e.to_string()))?
                {
                    if decoded.is_some() {
                        return self.track_decode_outcome(Err(VideoError::Decoder(
                            "VP9 decoder unexpectedly emitted multiple frames for one packet".into(),
                        )));
                    }
                    decoded = Some(extract_vpx_i420(&img)?);
                }
                if decoded.is_none() {
                    for img in dec
                        .flush()
                        .map_err(|e| VideoError::Decoder(e.to_string()))?
                    {
                        if decoded.is_some() {
                            return self.track_decode_outcome(Err(VideoError::Decoder(
                                "VP9 decoder flush unexpectedly emitted multiple frames".into(),
                            )));
                        }
                        decoded = Some(extract_vpx_i420(&img)?);
                    }
                }
                decoded
                    .map(DecodedVideoFrame::I420)
                    .ok_or(VideoError::NoOutputFrame)
            }
            InnerDecoder::Av1(dec) => {
                let mut decoded: Option<I420Frame> = None;
                for img in dec
                    .decode(data)
                    .map_err(|e| VideoError::Decoder(e.to_string()))?
                {
                    if decoded.is_some() {
                        return self.track_decode_outcome(Err(VideoError::Decoder(
                            "AV1 decoder unexpectedly emitted multiple frames for one packet".into(),
                        )));
                    }
                    decoded = Some(extract_aom_i420(&img)?);
                }
                if decoded.is_none() {
                    for img in dec
                        .flush()
                        .map_err(|e| VideoError::Decoder(e.to_string()))?
                    {
                        if decoded.is_some() {
                            return self.track_decode_outcome(Err(VideoError::Decoder(
                                "AV1 decoder flush unexpectedly emitted multiple frames".into(),
                            )));
                        }
                        decoded = Some(extract_aom_i420(&img)?);
                    }
                }
                decoded
                    .map(DecodedVideoFrame::I420)
                    .ok_or(VideoError::NoOutputFrame)
            }
        };
        self.track_decode_outcome(res)
    }

    /// Zero-extra-copy decode into a caller-provided BGRA buffer (reusing pooled memory with
    /// zero per-frame 8 MiB heap allocations or double copies).
    pub fn decode_raw_bgra_into(
        &mut self,
        data: &[u8],
        dst: &mut Vec<u8>,
    ) -> Result<(usize, usize, usize), VideoError> {
        if data.is_empty() {
            return self.track_decode_outcome(Err(VideoError::InvalidInput(
                "empty compressed video frame".into(),
            )));
        }
        let res = match &mut self.inner {
            InnerDecoder::Vt(dec) => dec.decode_annexb_bgra_into(data, dst),
            _ => {
                let bgra = self.decode_raw_bgra(data)?;
                dst.clear();
                dst.extend_from_slice(&bgra.data);
                return Ok((bgra.width, bgra.height, bgra.stride));
            }
        };
        self.track_decode_outcome(res)
    }

    pub fn decode_raw_bgra(&mut self, data: &[u8]) -> Result<BgraFrame, VideoError> {
        match self.decode_raw_frame(data)? {
            DecodedVideoFrame::Bgra(bgra) => Ok(bgra),
            DecodedVideoFrame::I420(i420) => {
                let stride = i420.width * 4;
                let mut out = vec![0u8; stride * i420.height];
                let uv_w = i420.width / 2;
                let rc = unsafe {
                    scrap::I420ToARGB(
                        i420.y.as_ptr(),
                        i420.width as i32,
                        i420.u.as_ptr(),
                        uv_w as i32,
                        i420.v.as_ptr(),
                        uv_w as i32,
                        out.as_mut_ptr(),
                        stride as i32,
                        i420.width as i32,
                        i420.height as i32,
                    )
                };
                if rc != 0 {
                    return Err(VideoError::Decoder(format!(
                        "libyuv I420ToARGB failed with rc={rc}"
                    )));
                }
                Ok(BgraFrame {
                    width: i420.width,
                    height: i420.height,
                    stride,
                    data: out,
                })
            }
        }
    }

    pub fn decode_raw(&mut self, data: &[u8]) -> Result<I420Frame, VideoError> {
        self.decode_raw_frame(data)?.into_i420()
    }

    pub fn decode_assembled_frame(
        &mut self,
        frame: &AssembledVideoFrame,
    ) -> Result<DecodedVideoFrame, VideoError> {
        let expected = self.codec.codec_id();
        if frame.codec_id != expected {
            return Err(VideoError::CodecMismatch {
                expected,
                actual: frame.codec_id,
            });
        }
        self.decode_raw_frame(&frame.data)
    }

    pub fn decode_assembled(&mut self, frame: &AssembledVideoFrame) -> Result<I420Frame, VideoError> {
        self.decode_assembled_frame(frame)?.into_i420()
    }

    pub fn decode_and_measure(
        &mut self,
        frame: &AssembledVideoFrame,
        reference: &I420Frame,
    ) -> Result<(I420Frame, FrameQualityMetrics), VideoError> {
        let decoded = self.decode_assembled(frame)?;
        let psnr_db = compute_y_psnr(reference, &decoded)?;
        let ssim = compute_y_ssim(reference, &decoded)?;
        Ok((decoded, FrameQualityMetrics { psnr_db, ssim }))
    }

    pub fn flush_pending(&mut self) -> Result<Vec<I420Frame>, VideoError> {
        let mut flushed = Vec::new();
        match &mut self.inner {
            InnerDecoder::Vp9(dec) => {
                for img in dec
                    .flush()
                    .map_err(|e| VideoError::Decoder(e.to_string()))?
                {
                    flushed.push(extract_vpx_i420(&img)?);
                }
            }
            InnerDecoder::Av1(dec) => {
                for img in dec
                    .flush()
                    .map_err(|e| VideoError::Decoder(e.to_string()))?
                {
                    flushed.push(extract_aom_i420(&img)?);
                }
            }
            InnerDecoder::Vt(_) => {
                // Synchronous VT decoding emits every decoded frame immediately with 0 pending queue.
            }
        }
        Ok(flushed)
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn invalidate_vt_session_for_test(&mut self) {
        if let InnerDecoder::Vt(dec) = &mut self.inner {
            dec.invalidate_session_for_test();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vp9_encode_decode_720p_quality() {
        let mut enc = V2VideoEncoder::new(VideoCodec::Vp9, 1280, 720, 2.0, Some(60)).unwrap();
        let mut dec = V2VideoDecoder::new(VideoCodec::Vp9).unwrap();
        let mut prev_id = None;
        for idx in 0..10u32 {
            let src = generate_animated_i420(1280, 720, idx);
            let encoded = enc.encode_i420(&src, (idx as i64) * 33).unwrap();
            assert_eq!(encoded.meta.codec_id, CODEC_ID_VP9);
            assert_eq!(encoded.meta.ltr_slot, 0);
            if encoded.meta.is_idr {
                assert_eq!(encoded.meta.ref_frame_id, encoded.meta.frame_id);
            } else {
                assert_eq!(Some(encoded.meta.ref_frame_id), prev_id);
            }
            prev_id = Some(encoded.meta.frame_id);
            assert!(!encoded.data.is_empty());
            let decoded = dec.decode_raw(&encoded.data).unwrap();
            let psnr = compute_y_psnr(&src, &decoded).unwrap();
            let ssim = compute_y_ssim(&src, &decoded).unwrap();
            assert!(psnr >= 32.0, "frame {idx} VP9 PSNR too low: {psnr:.2} dB");
            assert!(ssim >= 0.95, "frame {idx} VP9 SSIM too low: {ssim:.4}");
        }
    }

    #[test]
    fn av1_encode_decode_720p_quality() {
        let mut enc = V2VideoEncoder::new(VideoCodec::Av1, 1280, 720, 2.0, Some(60)).unwrap();
        let mut dec = V2VideoDecoder::new(VideoCodec::Av1).unwrap();
        let mut prev_id = None;
        for idx in 0..5u32 {
            let src = generate_animated_i420(1280, 720, idx);
            let encoded = enc.encode_i420(&src, (idx as i64) * 33).unwrap();
            assert_eq!(encoded.meta.codec_id, CODEC_ID_AV1);
            assert_eq!(encoded.meta.ltr_slot, 0);
            if encoded.meta.is_idr {
                assert_eq!(encoded.meta.ref_frame_id, encoded.meta.frame_id);
            } else {
                assert_eq!(Some(encoded.meta.ref_frame_id), prev_id);
            }
            prev_id = Some(encoded.meta.frame_id);
            assert!(!encoded.data.is_empty());
            let decoded = dec.decode_raw(&encoded.data).unwrap();
            let psnr = compute_y_psnr(&src, &decoded).unwrap();
            let ssim = compute_y_ssim(&src, &decoded).unwrap();
            assert!(psnr >= 32.0, "frame {idx} AV1 PSNR too low: {psnr:.2} dB");
            assert!(ssim >= 0.95, "frame {idx} AV1 SSIM too low: {ssim:.4}");
        }
    }

    #[test]
    fn i420_validation_guards_truncated_and_oversized_frames() {
        let good = generate_animated_i420(16, 16, 0);
        let mut bad_y = good.clone();
        bad_y.y.truncate(10);
        assert!(matches!(
            compute_y_psnr(&bad_y, &good),
            Err(VideoError::InvalidInput(_))
        ));
        assert!(matches!(
            compute_y_ssim(&bad_y, &good),
            Err(VideoError::InvalidInput(_))
        ));
        let fmt = EncodeYuvFormat {
            pixfmt: Pixfmt::I420,
            w: 16,
            h: 16,
            stride: vec![16, 8, 8],
            u: 256,
            v: 320,
        };
        assert!(matches!(
            bad_y.pack_for_encoder(&fmt),
            Err(VideoError::InvalidInput(_))
        ));
        assert!(matches!(
            I420Frame::new(MAX_FRAME_DIM + 2, 16, vec![], vec![], vec![]),
            Err(VideoError::InvalidInput(_))
        ));
        assert!(matches!(
            V2VideoEncoder::new(VideoCodec::Vp9, (MAX_FRAME_DIM + 2) as u32, 16, 2.0, Some(60)),
            Err(VideoError::InvalidInput(_))
        ));
    }

    #[test]
    fn generate_animated_i420_safe_for_small_dimensions() {
        for &(w, h) in &[(0usize, 0usize), (2, 2), (8, 8), (16, 16), (32, 32)] {
            let f = generate_animated_i420(w, h, 3);
            assert!(f.validate().is_ok());
        }
    }
}
