// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#ifndef ZERODESK_MACOS_VT_H
#define ZERODESK_MACOS_VT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZD_VT_CODEC_H264 3u
#define ZD_VT_CODEC_HEVC 4u

#define ZD_VT_OK                    0
#define ZD_VT_ERR_INVALID_ARG      -1
#define ZD_VT_ERR_HW_UNAVAILABLE   -2
#define ZD_VT_ERR_SESSION_INVALID  -3
#define ZD_VT_ERR_NEED_IDR         -4
#define ZD_VT_ERR_ALLOC            -5
#define ZD_VT_ERR_DECODE_ASYNC     -6
#define ZD_VT_ERR_NO_OUTPUT        -7
#define ZD_VT_ERR_SAFETY_CAP       -8
#define ZD_VT_ERR_INTERNAL         -9

#define ZD_VT_CAP_H264 (1u << 0)
#define ZD_VT_CAP_HEVC (1u << 1)

/* Annex-B & decoder safety caps (fail-closed) */
#define ZD_VT_MAX_NALS_PER_FRAME       64u
#define ZD_VT_MAX_PARAM_SETS_PER_TYPE  16u
#define ZD_VT_MAX_PARAM_SET_BYTES      4096u
#define ZD_VT_MAX_TOTAL_PARAM_BYTES    16384u
#define ZD_VT_MAX_WIDTH                8192u
#define ZD_VT_MAX_HEIGHT               8192u
#define ZD_VT_MAX_PIXELS               33000000ULL

typedef struct ZdVtEncoder ZdVtEncoder;
typedef struct ZdVtDecoder ZdVtDecoder;

typedef struct ZdVtEncoderConfig {
    uint32_t codec_id;              /* ZD_VT_CODEC_H264 (3) or ZD_VT_CODEC_HEVC (4) */
    uint32_t width;                 /* even, 2..=8192 */
    uint32_t height;                /* even, 2..=8192 */
    uint32_t fps;                   /* 1..=240 (0 -> 30) */
    uint32_t bitrate_bps;           /* > 0 */
    uint32_t max_keyframe_interval; /* 0 -> fps * 2 */
} ZdVtEncoderConfig;

typedef struct ZdVtEncodedFrame {
    const uint8_t *data; /* borrowed until next encode or destroy */
    size_t len;
    uint8_t is_idr;
    uint8_t _pad[3];
    int32_t os_status;
} ZdVtEncodedFrame;

typedef struct ZdVtDecodedBgraFrame {
    const uint8_t *data; /* borrowed tightly-packed BGRA8 until next decode or destroy */
    size_t len;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    int32_t os_status;
} ZdVtDecodedBgraFrame;

typedef struct ZdVtAnnexbSlice {
    size_t offset;
    size_t len;
    uint8_t nal_type;
    uint8_t _pad[7];
} ZdVtAnnexbSlice;

typedef struct ZdVtAnnexbParseResult {
    uint32_t nal_count;
    uint32_t vps_count;
    uint32_t sps_count;
    uint32_t pps_count;
    uint32_t vcl_count;
    uint8_t has_idr;
    uint8_t _pad[3];
    size_t total_param_bytes;
    ZdVtAnnexbSlice nals[ZD_VT_MAX_NALS_PER_FRAME];
} ZdVtAnnexbParseResult;

/* Pure-C Annex-B parser enforcing all NAL and parameter-set safety caps. */
int32_t zd_vt_parse_annexb(
    uint32_t codec_id,
    const uint8_t *data,
    size_t len,
    ZdVtAnnexbParseResult *out
);

/* Encoder lifecycle (strict hardware-accelerated VTCompressionSession, NV12 input, Annex-B output). */
int32_t zd_vt_enc_create(const ZdVtEncoderConfig *cfg, ZdVtEncoder **out_enc);
int32_t zd_vt_enc_set_bitrate(ZdVtEncoder *enc, uint32_t bitrate_bps);
int32_t zd_vt_enc_encode_nv12(
    ZdVtEncoder *enc,
    const uint8_t *y_ptr,
    uint32_t y_stride,
    const uint8_t *uv_ptr,
    uint32_t uv_stride,
    uint32_t width,
    uint32_t height,
    int64_t pts_us,
    uint8_t force_idr,
    ZdVtEncodedFrame *out_frame
);
void zd_vt_enc_destroy(ZdVtEncoder *enc);

/* Decoder lifecycle (strict hardware-accelerated synchronous VTDecompressionSession, 32BGRA output). */
int32_t zd_vt_dec_create(uint32_t codec_id, ZdVtDecoder **out_dec);
int32_t zd_vt_dec_decode_annexb(
    ZdVtDecoder *dec,
    const uint8_t *data,
    size_t len,
    ZdVtDecodedBgraFrame *out_frame
);
/* Zero-extra-copy decode variant: when dst_bgra is non-NULL and dst_bgra_cap >= w*h*4,
 * copies tightly-packed BGRA directly from CVPixelBuffer into dst_bgra (out_frame->data == dst_bgra).
 * Falls back to decoder's internal buffer if dst_bgra is NULL or smaller than required. */
int32_t zd_vt_dec_decode_annexb_into(
    ZdVtDecoder *dec,
    const uint8_t *data,
    size_t len,
    uint8_t *dst_bgra,
    size_t dst_bgra_cap,
    ZdVtDecodedBgraFrame *out_frame
);
void zd_vt_dec_destroy(ZdVtDecoder *dec);

/* Silent 64x64 real HW encode+decode capability probe.
 * Sets ZD_VT_CAP_H264 only if BOTH H.264 HW encode and decode succeed;
 * sets ZD_VT_CAP_HEVC only if BOTH HEVC HW encode and decode succeed. */
uint32_t zd_vt_probe_capabilities(void);

/* Test-only helper: invalidates underlying VT session so next encode/decode triggers
 * genuine Apple kVTInvalidSessionErr (-12903) for runtime recovery verification. */
void zd_vt_enc_invalidate_session_for_test(ZdVtEncoder *enc);
void zd_vt_dec_invalidate_session_for_test(ZdVtDecoder *dec);

#ifdef __cplusplus
}
#endif

#endif /* ZERODESK_MACOS_VT_H */
