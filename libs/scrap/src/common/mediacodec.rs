use hbb_common::{anyhow::Error, bail, log, ResultType};
use ndk::media::media_codec::{MediaCodec, MediaCodecDirection, MediaFormat};
use std::ops::Deref;
use std::{
    io::Write,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use crate::ImageFormat;
use crate::{
    codec::{EncoderApi, EncoderCfg},
    CodecFormat, I420ToABGR, I420ToARGB, ImageRgb,
};

/// MediaCodec mime type name
const H264_MIME_TYPE: &str = "video/avc";
const H265_MIME_TYPE: &str = "video/hevc";
// const VP8_MIME_TYPE: &str = "video/x-vnd.on2.vp8";
// const VP9_MIME_TYPE: &str = "video/x-vnd.on2.vp9";

// TODO MediaCodecEncoder

pub static H264_DECODER_SUPPORT: AtomicBool = AtomicBool::new(false);
pub static H265_DECODER_SUPPORT: AtomicBool = AtomicBool::new(false);

pub struct MediaCodecDecoder {
    decoder: MediaCodec,
    name: String,
}

impl Deref for MediaCodecDecoder {
    type Target = MediaCodec;

    fn deref(&self) -> &Self::Target {
        &self.decoder
    }
}

impl MediaCodecDecoder {
    pub fn new(format: CodecFormat) -> Option<MediaCodecDecoder> {
        match format {
            CodecFormat::H264 => create_media_codec(H264_MIME_TYPE, MediaCodecDirection::Decoder),
            CodecFormat::H265 => create_media_codec(H265_MIME_TYPE, MediaCodecDirection::Decoder),
            _ => {
                log::error!("Unsupported codec format: {}", format);
                None
            }
        }
    }

    // rgb [in/out] fmt and stride must be set in ImageRgb
    pub fn decode(&mut self, data: &[u8], rgb: &mut ImageRgb) -> ResultType<bool> {
        // take dst_stride into account please
        let dst_stride = rgb.stride();
        match self.dequeue_input_buffer(Duration::from_millis(10))? {
            Some(mut input_buffer) => {
                let mut buf = input_buffer.buffer_mut();
                if data.len() > buf.len() {
                    log::error!("Failed to decode, the input data size is bigger than input buf");
                    bail!("The input data size is bigger than input buf");
                }
                buf.write_all(&data)?;
                self.queue_input_buffer(input_buffer, 0, data.len(), 0, 0)?;
            }
            None => {
                log::debug!("Failed to dequeue_input_buffer: No available input_buffer");
            }
        };

        return match self.dequeue_output_buffer(Duration::from_millis(100))? {
            Some(output_buffer) => {
                let res_format = self.output_format();
                let w = res_format
                    .i32("width")
                    .ok_or(Error::msg("Failed to dequeue_output_buffer, width is None"))?
                    as usize;
                let h = res_format.i32("height").ok_or(Error::msg(
                    "Failed to dequeue_output_buffer, height is None",
                ))? as usize;
                let stride = res_format.i32("stride").ok_or(Error::msg(
                    "Failed to dequeue_output_buffer, stride is None",
                ))?;
                let buf = output_buffer.buffer();
                let bps = 4;
                let u = buf.len() * 2 / 3;
                let v = buf.len() * 5 / 6;
                rgb.raw.resize(h * w * bps, 0);
                let y_ptr = buf.as_ptr();
                let u_ptr = buf[u..].as_ptr();
                let v_ptr = buf[v..].as_ptr();
                unsafe {
                    match rgb.fmt() {
                        ImageFormat::ARGB => {
                            I420ToARGB(
                                y_ptr,
                                stride,
                                u_ptr,
                                stride / 2,
                                v_ptr,
                                stride / 2,
                                rgb.raw.as_mut_ptr(),
                                (w * bps) as _,
                                w as _,
                                h as _,
                            );
                        }
                        ImageFormat::ARGB => {
                            I420ToABGR(
                                y_ptr,
                                stride,
                                u_ptr,
                                stride / 2,
                                v_ptr,
                                stride / 2,
                                rgb.raw.as_mut_ptr(),
                                (w * bps) as _,
                                w as _,
                                h as _,
                            );
                        }
                        _ => {
                            bail!("Unsupported image format");
                        }
                    }
                }
                self.release_output_buffer(output_buffer, false)?;
                Ok(true)
            }
            None => {
                log::debug!("Failed to dequeue_output: No available dequeue_output");
                Ok(false)
            }
        };
    }
}

pub fn is_software_mediacodec_name(codec_name: &str) -> bool {
    let lower = codec_name.to_ascii_lowercase();
    lower.starts_with("c2.android.")
        || lower.starts_with("omx.google.")
        || lower.starts_with("omx.ffmpeg.")
        || lower.starts_with("c2.ffmpeg.")
        || lower.contains(".sw.")
        || lower.contains("software")
}

pub fn is_hardware_mediacodec_decoder(codec_name: &str, hw_flag: Option<bool>) -> bool {
    if is_software_mediacodec_name(codec_name) {
        return false;
    }
    !matches!(hw_flag, Some(false))
}

fn select_hardware_hevc_decoder_name() -> Option<String> {
    #[cfg(target_os = "android")]
    {
        let infos = crate::android::ffi::get_codec_info()?;
        infos
            .codecs
            .into_iter()
            .find(|c| {
                !c.is_encoder
                    && c.mime_type == H265_MIME_TYPE
                    && is_hardware_mediacodec_decoder(&c.name, c.hw)
            })
            .map(|c| c.name)
    }
    #[cfg(not(target_os = "android"))]
    {
        None
    }
}

pub fn has_hardware_h265_decoder() -> bool {
    H265_DECODER_SUPPORT.load(Ordering::SeqCst) && select_hardware_hevc_decoder_name().is_some()
}

fn create_media_codec(mime_type: &str, direction: MediaCodecDirection) -> Option<MediaCodecDecoder> {
    let (codec, resolved_name) = if mime_type == H265_MIME_TYPE {
        // ZeroDesk HEVC_OS_HW_ONLY: never use from_decoder_type() for HEVC because Android
        // silently selects software decoders (c2.android.hevc.decoder / OMX.google.hevc.decoder).
        let hw_name = select_hardware_hevc_decoder_name()?;
        let codec = MediaCodec::from_codec_name(&hw_name)?;
        (codec, hw_name)
    } else {
        let codec = MediaCodec::from_decoder_type(mime_type)?;
        (codec, mime_type.to_owned())
    };
    let media_format = MediaFormat::new();
    media_format.set_str("mime", mime_type);
    media_format.set_i32("width", 0);
    media_format.set_i32("height", 0);
    media_format.set_i32("color-format", 19); // COLOR_FormatYUV420Planar
    if let Err(e) = codec.configure(&media_format, None, direction) {
        log::error!("Failed to init decoder: {:?}", e);
        return None;
    };
    log::error!("decoder init success");
    if let Err(e) = codec.start() {
        log::error!("Failed to start decoder: {:?}", e);
        return None;
    };
    log::debug!("Init decoder succeeded!: {:?}", resolved_name);
    return Some(MediaCodecDecoder {
        decoder: codec,
        name: resolved_name,
    });
}

pub fn check_mediacodec() {
    std::thread::spawn(move || {
        // check decoders
        let h264 = MediaCodecDecoder::new(CodecFormat::H264);
        let h265 = MediaCodecDecoder::new(CodecFormat::H265);
        H264_DECODER_SUPPORT.swap(h264.is_some(), Ordering::SeqCst);
        H265_DECODER_SUPPORT.swap(h265.is_some(), Ordering::SeqCst);
        h264.map(|d| d.stop());
        h265.map(|d| d.stop());
        // TODO encoders
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_android_software_hevc_decoders() {
        for sw in [
            "c2.android.hevc.decoder",
            "OMX.google.hevc.decoder",
            "omx.google.hevc.decoder",
            "c2.ffmpeg.hevc.decoder",
            "OMX.vendor.hevc.sw.decoder",
            "vendor.software.hevc",
        ] {
            assert!(is_software_mediacodec_name(sw), "{sw}");
            assert!(!is_hardware_mediacodec_decoder(sw, Some(true)), "{sw}");
            assert!(!is_hardware_mediacodec_decoder(sw, None), "{sw}");
        }
        assert!(!is_hardware_mediacodec_decoder(
            "c2.qti.hevc.decoder",
            Some(false)
        ));
        assert!(is_hardware_mediacodec_decoder(
            "c2.qti.hevc.decoder",
            Some(true)
        ));
        assert!(is_hardware_mediacodec_decoder(
            "OMX.qcom.video.decoder.hevc",
            None
        ));
    }
}
