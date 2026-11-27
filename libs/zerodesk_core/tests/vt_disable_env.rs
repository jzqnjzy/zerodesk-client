// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use v2_transport::{CAP_CODEC_H264, CAP_CODEC_HEVC_OS_HW, CAP_CODEC_VP9};
use zerodesk_core::session::{
    local_v2_cap_bits, negotiate_video_codec, probed_vt_cap_bits, V2VideoDecoder, V2VideoEncoder,
    VideoCodec, VideoError, VT_DISABLE_ENV_VAR,
};

#[test]
fn env_zerodesk_disable_vt_hw_falls_back_cleanly_to_vp9() {
    std::env::set_var(VT_DISABLE_ENV_VAR, "1");

    assert_eq!(probed_vt_cap_bits(), 0);
    let local = local_v2_cap_bits();
    assert_eq!(local & CAP_CODEC_H264, 0);
    assert_eq!(local & CAP_CODEC_HEVC_OS_HW, 0);
    assert_ne!(local & CAP_CODEC_VP9, 0);

    let peer_all = local | CAP_CODEC_H264 | CAP_CODEC_HEVC_OS_HW;
    assert_eq!(
        negotiate_video_codec(local, peer_all, None).unwrap(),
        VideoCodec::Vp9
    );
    assert!(matches!(
        negotiate_video_codec(local, peer_all, Some(VideoCodec::Hevc)),
        Err(VideoError::NoCommonCodec {
            preferred: Some(VideoCodec::Hevc),
            ..
        })
    ));
    assert!(matches!(
        V2VideoEncoder::new(VideoCodec::H264, 128, 128, 2.0, Some(60)),
        Err(VideoError::HardwareUnavailable(_))
    ));
    assert!(matches!(
        V2VideoDecoder::new(VideoCodec::Hevc),
        Err(VideoError::HardwareUnavailable(_))
    ));
}
