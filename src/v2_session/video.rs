use scrap::{
    aom::{AomDecoder, AomEncoder, AomEncoderConfig},
    codec::{EncoderApi, EncoderCfg},
    EncodeYuvFormat, GoogleImage, VpxDecoder, VpxDecoderConfig, VpxEncoder, VpxEncoderConfig,
    VpxVideoCodecId, STRIDE_ALIGN,
};
use std::fmt;
use v2_transport::{AssembledVideoFrame, VideoFrameMeta, VIDEO_REASSEMBLER_MAX_AGE_MS};

pub const CODEC_ID_AV1: u8 = 1;
pub const CODEC_ID_VP9: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    Vp9,
    Av1,
}

impl VideoCodec {
    pub fn codec_id(self) -> u8 {
        match self {
            Self::Av1 => CODEC_ID_AV1,
            Self::Vp9 => CODEC_ID_VP9,
        }
    }

    pub fn from_codec_id(id: u8) -> Result<Self, VideoError> {
        match id {
            CODEC_ID_AV1 => Ok(Self::Av1),
            CODEC_ID_VP9 => Ok(Self::Vp9),
            other => Err(VideoError::UnsupportedCodecId(other)),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Vp9 => "vp9",
            Self::Av1 => "av1",
        }
    }

    pub fn parse_name(s: &str) -> Result<Self, VideoError> {
        match s.to_ascii_lowercase().as_str() {
            "vp9" => Ok(Self::Vp9),
            "av1" => Ok(Self::Av1),
            _ => Err(VideoError::InvalidInput(format!("unsupported codec '{s}' (expected vp9 or av1)"))),
        }
    }
}

#[derive(Debug)]
pub enum VideoError {
    InvalidInput(String),
    UnsupportedCodecId(u8),
    CodecMismatch { expected: u8, actual: u8 },
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
            Self::Encoder(msg) => write!(f, "video encoder error: {msg}"),
            Self::Decoder(msg) => write!(f, "video decoder error: {msg}"),
            Self::NoOutputFrame => write!(f, "codec produced no output frame"),
        }
    }
}

impl std::error::Error for VideoError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct I420Frame {
    pub width: usize,
    pub height: usize,
    pub y: Vec<u8>,
    pub u: Vec<u8>,
    pub v: Vec<u8>,
}

impl I420Frame {
    pub fn new(width: usize, height: usize, y: Vec<u8>, u: Vec<u8>, v: Vec<u8>) -> Result<Self, VideoError> {
        if width == 0 || height == 0 || (width & 1) != 0 || (height & 1) != 0 {
            return Err(VideoError::InvalidInput(format!(
                "I420 dimensions must be positive and even, got {width}x{height}"
            )));
        }
        let y_len = width.saturating_mul(height);
        let uv_len = (width / 2).saturating_mul(height / 2);
        if y.len() != y_len || u.len() != uv_len || v.len() != uv_len {
            return Err(VideoError::InvalidInput(format!(
                "I420 plane sizes mismatch for {width}x{height}: y={}, u={}, v={}",
                y.len(),
                u.len(),
                v.len()
            )));
        }
        Ok(Self {
            width,
            height,
            y,
            u,
            v,
        })
    }

    pub fn pack_for_encoder(&self, fmt: &EncodeYuvFormat) -> Result<Vec<u8>, VideoError> {
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
        let y_end = y_stride.saturating_mul(self.height);
        let u_end = fmt.u.saturating_add(u_stride.saturating_mul(uv_h));
        let v_end = fmt.v.saturating_add(v_stride.saturating_mul(uv_h));
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
        let width = img.width();
        let height = img.height();
        if width == 0 || height == 0 || (width & 1) != 0 || (height & 1) != 0 {
            return Err(VideoError::Decoder(format!(
                "decoded image has invalid I420 dimensions {width}x{height}"
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
        let (y_src, u_src, v_src) = img.data();
        if y_src.len() < y_stride * height
            || u_src.len() < u_stride * uv_h
            || v_src.len() < v_stride * uv_h
        {
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
    let f = frame_idx as usize;
    let mut y = vec![0u8; width * height];
    let uv_w = width / 2;
    let uv_h = height / 2;
    let mut u = vec![128u8; uv_w * uv_h];
    let mut v = vec![128u8; uv_w * uv_h];

    let x_shift = (f * 3) % width.max(1);
    let y_shift = (f * 2) % height.max(1);

    // Smooth moving gradient background (keeps high spatial correlation like a real desktop).
    for row in 0..height {
        let row_off = row * width;
        let gy = ((row + y_shift) * 90) / height.max(1);
        for col in 0..width {
            let gx = ((col + x_shift) * 110) / width.max(1);
            y[row_off + col] = (32 + ((gx + gy) % 160)) as u8;
        }
    }

    // Moving high-contrast UI window rectangle #1 (bright card with dark border).
    let box_w = (width / 5).max(32);
    let box_h = (height / 4).max(32);
    let box_x = (f * 7) % (width.saturating_sub(box_w).max(1));
    let box_y = (height / 6 + (f * 3) % (height / 2).max(1)).min(height.saturating_sub(box_h));
    for row in box_y..(box_y + box_h) {
        let row_off = row * width;
        let is_border_y = row < box_y + 4 || row >= box_y + box_h - 4;
        for col in box_x..(box_x + box_w) {
            let is_border_x = col < box_x + 4 || col >= box_x + box_w - 4;
            y[row_off + col] = if is_border_x || is_border_y { 24 } else { 228 };
        }
    }

    // Moving high-contrast rectangle #2 moving in opposite horizontal direction.
    let box2_w = (width / 7).max(24);
    let box2_h = (height / 5).max(24);
    let span2 = width.saturating_sub(box2_w).max(1);
    let box2_x = span2 - ((f * 5) % span2);
    let box2_y = (height / 2 + (f * 2) % (height / 4).max(1)).min(height.saturating_sub(box2_h));
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
    let bar_y0 = height.saturating_sub(bar_h + 12);
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
    if reference.width != decoded.width || reference.height != decoded.height {
        return Err(VideoError::InvalidInput(format!(
            "PSNR dimension mismatch: ref {}x{} vs dec {}x{}",
            reference.width, reference.height, decoded.width, decoded.height
        )));
    }
    let count = reference.y.len();
    if count == 0 || count != decoded.y.len() {
        return Err(VideoError::InvalidInput("empty or mismatched Y plane".into()));
    }
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

#[derive(Debug, Clone)]
pub struct EncodedV2Frame {
    pub meta: VideoFrameMeta,
    pub data: Vec<u8>,
}

enum InnerEncoder {
    Vp9(VpxEncoder),
    Av1(AomEncoder),
}

/// Real `scrap` VP9 (`libvpx`) / AV1 (`libaom`) encoder producing raw elementary bitstreams
/// directly mapped to `v2_transport::VideoFrameMeta` (zero RustDesk protobuf on the wire).
pub struct V2VideoEncoder {
    codec: VideoCodec,
    inner: InnerEncoder,
    yuvfmt: EncodeYuvFormat,
    next_frame_id: u32,
    last_anchor_frame_id: u32,
    ltr_slot_toggle: u8,
}

impl V2VideoEncoder {
    pub fn new(
        codec: VideoCodec,
        width: u32,
        height: u32,
        quality: f32,
        keyframe_interval: Option<usize>,
    ) -> Result<Self, VideoError> {
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
        };
        Ok(Self {
            codec,
            inner,
            yuvfmt,
            next_frame_id: 1,
            last_anchor_frame_id: 1,
            ltr_slot_toggle: 1,
        })
    }

    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    pub fn yuvfmt(&self) -> &EncodeYuvFormat {
        &self.yuvfmt
    }

    pub fn encode_i420(&mut self, frame: &I420Frame, pts_ms: i64) -> Result<EncodedV2Frame, VideoError> {
        let aligned = frame.pack_for_encoder(&self.yuvfmt)?;
        let (raw_data, is_key) = match &mut self.inner {
            InnerEncoder::Vp9(enc) => {
                let mut out: Option<(Vec<u8>, bool)> = None;
                for pkt in enc
                    .encode(pts_ms, &aligned, STRIDE_ALIGN)
                    .map_err(|e| VideoError::Encoder(e.to_string()))?
                {
                    out = Some((pkt.data.to_vec(), pkt.key));
                }
                if out.is_none() {
                    for pkt in enc.flush().map_err(|e| VideoError::Encoder(e.to_string()))? {
                        out = Some((pkt.data.to_vec(), pkt.key));
                    }
                }
                out.ok_or(VideoError::NoOutputFrame)?
            }
            InnerEncoder::Av1(enc) => {
                let mut out: Option<(Vec<u8>, bool)> = None;
                for pkt in enc
                    .encode(pts_ms, &aligned, STRIDE_ALIGN)
                    .map_err(|e| VideoError::Encoder(e.to_string()))?
                {
                    out = Some((pkt.data.to_vec(), pkt.key));
                }
                out.ok_or(VideoError::NoOutputFrame)?
            }
        };

        let frame_id = self.next_frame_id;
        self.next_frame_id = self.next_frame_id.wrapping_add(1).max(1);

        let (ref_frame_id, ltr_slot) = if is_key || frame_id == 1 {
            let slot = self.ltr_slot_toggle;
            self.ltr_slot_toggle = if slot == 1 { 2 } else { 1 };
            self.last_anchor_frame_id = frame_id;
            (frame_id, slot)
        } else {
            (self.last_anchor_frame_id, 0)
        };

        let meta = VideoFrameMeta {
            display_idx: 0,
            codec_id: self.codec.codec_id(),
            frame_id,
            ref_frame_id,
            ltr_slot,
            is_idr: is_key,
            is_ref: true,
            max_age_ms: VIDEO_REASSEMBLER_MAX_AGE_MS,
        };

        Ok(EncodedV2Frame {
            meta,
            data: raw_data,
        })
    }
}

enum InnerDecoder {
    Vp9(VpxDecoder),
    Av1(AomDecoder),
}

/// Real `scrap` VP9 (`libvpx`) / AV1 (`libaom`) decoder returning decoded I420 planes directly
/// from raw V2 elementary bitstreams.
pub struct V2VideoDecoder {
    codec: VideoCodec,
    inner: InnerDecoder,
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
        };
        Ok(Self { codec, inner })
    }

    pub fn codec(&self) -> VideoCodec {
        self.codec
    }

    pub fn decode_raw(&mut self, data: &[u8]) -> Result<I420Frame, VideoError> {
        if data.is_empty() {
            return Err(VideoError::InvalidInput("empty compressed video frame".into()));
        }
        match &mut self.inner {
            InnerDecoder::Vp9(dec) => {
                let mut decoded: Option<I420Frame> = None;
                for img in dec
                    .decode(data)
                    .map_err(|e| VideoError::Decoder(e.to_string()))?
                {
                    decoded = Some(I420Frame::from_google_image(&img)?);
                }
                if decoded.is_none() {
                    for img in dec
                        .flush()
                        .map_err(|e| VideoError::Decoder(e.to_string()))?
                    {
                        decoded = Some(I420Frame::from_google_image(&img)?);
                    }
                }
                decoded.ok_or(VideoError::NoOutputFrame)
            }
            InnerDecoder::Av1(dec) => {
                let mut decoded: Option<I420Frame> = None;
                for img in dec
                    .decode(data)
                    .map_err(|e| VideoError::Decoder(e.to_string()))?
                {
                    decoded = Some(I420Frame::from_google_image(&img)?);
                }
                if decoded.is_none() {
                    for img in dec
                        .flush()
                        .map_err(|e| VideoError::Decoder(e.to_string()))?
                    {
                        decoded = Some(I420Frame::from_google_image(&img)?);
                    }
                }
                decoded.ok_or(VideoError::NoOutputFrame)
            }
        }
    }

    pub fn decode_assembled(&mut self, frame: &AssembledVideoFrame) -> Result<I420Frame, VideoError> {
        let expected = self.codec.codec_id();
        if frame.codec_id != expected {
            return Err(VideoError::CodecMismatch {
                expected,
                actual: frame.codec_id,
            });
        }
        self.decode_raw(&frame.data)
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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vp9_encode_decode_720p_quality() {
        let mut enc = V2VideoEncoder::new(VideoCodec::Vp9, 1280, 720, 2.0, Some(60)).unwrap();
        let mut dec = V2VideoDecoder::new(VideoCodec::Vp9).unwrap();
        for idx in 0..10u32 {
            let src = generate_animated_i420(1280, 720, idx);
            let encoded = enc.encode_i420(&src, (idx as i64) * 33).unwrap();
            assert_eq!(encoded.meta.codec_id, CODEC_ID_VP9);
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
        for idx in 0..5u32 {
            let src = generate_animated_i420(1280, 720, idx);
            let encoded = enc.encode_i420(&src, (idx as i64) * 33).unwrap();
            assert_eq!(encoded.meta.codec_id, CODEC_ID_AV1);
            assert!(!encoded.data.is_empty());
            let decoded = dec.decode_raw(&encoded.data).unwrap();
            let psnr = compute_y_psnr(&src, &decoded).unwrap();
            let ssim = compute_y_ssim(&src, &decoded).unwrap();
            assert!(psnr >= 32.0, "frame {idx} AV1 PSNR too low: {psnr:.2} dB");
            assert!(ssim >= 0.95, "frame {idx} AV1 SSIM too low: {ssim:.4}");
        }
    }
}
