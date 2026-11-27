// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#include "macos_vt.h"

#include <CoreFoundation/CoreFoundation.h>
#include <CoreMedia/CoreMedia.h>
#include <CoreVideo/CoreVideo.h>
#include <VideoToolbox/VideoToolbox.h>

#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#define ZD_VT_MAX_OUTPUT_BYTES (16u * 1024u * 1024u)
#define ZD_VT_MAX_AVCC_BYTES   (16u * 1024u * 1024u)
#define ZD_VT_MAX_PS_TOTAL     (ZD_VT_MAX_PARAM_SETS_PER_TYPE * 3u)

static const uint8_t ZD_ANNEXB_SC[4] = {0x00u, 0x00u, 0x00u, 0x01u};

/* ============================================================================
 * Helpers
 * ========================================================================== */

static bool zd_vt_dims_valid(uint32_t w, uint32_t h) {
    if (w == 0u || h == 0u || w > ZD_VT_MAX_WIDTH || h > ZD_VT_MAX_HEIGHT) {
        return false;
    }
    uint64_t pixels = (uint64_t)w * (uint64_t)h;
    return pixels <= ZD_VT_MAX_PIXELS;
}

static int32_t zd_vt_map_enc_osstatus(OSStatus st) {
    if (st == noErr) {
        return ZD_VT_OK;
    }
    if (st == kVTInvalidSessionErr || st == kVTVideoEncoderMalfunctionErr) {
        return ZD_VT_ERR_SESSION_INVALID;
    }
    if (st == kVTVideoEncoderNotAvailableNowErr || st == kVTCouldNotFindVideoEncoderErr) {
        return ZD_VT_ERR_HW_UNAVAILABLE;
    }
    return ZD_VT_ERR_INTERNAL;
}

static int32_t zd_vt_map_dec_osstatus(OSStatus st) {
    if (st == noErr) {
        return ZD_VT_OK;
    }
    if (st == kVTInvalidSessionErr || st == kVTVideoDecoderMalfunctionErr) {
        return ZD_VT_ERR_SESSION_INVALID;
    }
    if (st == kVTVideoDecoderNotAvailableNowErr || st == kVTCouldNotFindVideoDecoderErr) {
        return ZD_VT_ERR_HW_UNAVAILABLE;
    }
    if (st == kVTVideoDecoderBadDataErr || st == kVTVideoDecoderReferenceMissingErr) {
        return ZD_VT_ERR_NEED_IDR;
    }
    return ZD_VT_ERR_INTERNAL;
}

static bool zd_vt_buf_reserve(uint8_t **buf, size_t *cap, size_t needed, size_t hard_cap) {
    if (needed > hard_cap) {
        return false;
    }
    if (needed <= *cap) {
        return true;
    }
    size_t new_cap = (*cap == 0u) ? 4096u : *cap;
    while (new_cap < needed) {
        if (new_cap > hard_cap / 2u) {
            new_cap = hard_cap;
            break;
        }
        new_cap *= 2u;
    }
    uint8_t *grown = (uint8_t *)realloc(*buf, new_cap);
    if (grown == NULL) {
        return false;
    }
    *buf = grown;
    *cap = new_cap;
    return true;
}

static bool zd_vt_dict_set_int32(CFMutableDictionaryRef dict, CFStringRef key, int32_t val) {
    CFNumberRef num = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &val);
    if (num == NULL) {
        return false;
    }
    CFDictionarySetValue(dict, key, num);
    CFRelease(num);
    return true;
}

static OSStatus zd_vt_session_set_int32(VTSessionRef session, CFStringRef key, int32_t val) {
    CFNumberRef num = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt32Type, &val);
    if (num == NULL) {
        return kVTAllocationFailedErr;
    }
    OSStatus st = VTSessionSetProperty(session, key, num);
    CFRelease(num);
    return st;
}

static OSStatus zd_vt_session_set_double(VTSessionRef session, CFStringRef key, double val) {
    CFNumberRef num = CFNumberCreate(kCFAllocatorDefault, kCFNumberFloat64Type, &val);
    if (num == NULL) {
        return kVTAllocationFailedErr;
    }
    OSStatus st = VTSessionSetProperty(session, key, num);
    CFRelease(num);
    return st;
}

static OSStatus zd_vt_session_set_data_rate_limits(VTSessionRef session, uint32_t bitrate_bps) {
    /* kVTCompressionPropertyKey_DataRateLimits expects [bytes, seconds].
     * Target ceiling = bitrate_bps / 8 * 1.25 = bitrate_bps * 5 / 32 bytes per 1.0 sec. */
    uint64_t bytes_u64 = ((uint64_t)bitrate_bps * 5ULL) / 32ULL;
    if (bytes_u64 < 1024ULL) {
        bytes_u64 = 1024ULL;
    }
    if (bytes_u64 > (uint64_t)INT64_MAX) {
        bytes_u64 = (uint64_t)INT64_MAX;
    }
    int64_t bytes_per_sec = (int64_t)bytes_u64;
    double window_sec = 1.0;

    CFNumberRef num_bytes = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &bytes_per_sec);
    if (num_bytes == NULL) {
        return kVTAllocationFailedErr;
    }
    CFNumberRef num_sec = CFNumberCreate(kCFAllocatorDefault, kCFNumberFloat64Type, &window_sec);
    if (num_sec == NULL) {
        CFRelease(num_bytes);
        return kVTAllocationFailedErr;
    }
    const void *vals[2] = {num_bytes, num_sec};
    CFArrayRef arr = CFArrayCreate(kCFAllocatorDefault, vals, 2, &kCFTypeArrayCallBacks);
    CFRelease(num_bytes);
    CFRelease(num_sec);
    if (arr == NULL) {
        return kVTAllocationFailedErr;
    }
    OSStatus st = VTSessionSetProperty(session, kVTCompressionPropertyKey_DataRateLimits, arr);
    CFRelease(arr);
    return st;
}

static bool zd_vt_verify_hw_property(VTSessionRef session, CFStringRef prop_key) {
    CFTypeRef val = NULL;
    OSStatus st = VTSessionCopyProperty(session, prop_key, kCFAllocatorDefault, &val);
    if (st != noErr || val == NULL) {
        if (val != NULL) {
            CFRelease(val);
        }
        return false;
    }
    bool is_hw = false;
    if (CFGetTypeID(val) == CFBooleanGetTypeID()) {
        is_hw = CFBooleanGetValue((CFBooleanRef)val) ? true : false;
    }
    CFRelease(val);
    return is_hw;
}

static bool zd_vt_is_param_nal(uint32_t codec_id, uint8_t nal_type) {
    if (codec_id == ZD_VT_CODEC_H264) {
        return nal_type == 7u || nal_type == 8u;
    }
    return nal_type == 32u || nal_type == 33u || nal_type == 34u;
}

static bool zd_vt_is_idr_nal(uint32_t codec_id, uint8_t nal_type) {
    if (codec_id == ZD_VT_CODEC_H264) {
        return nal_type == 5u;
    }
    return nal_type == 19u || nal_type == 20u;
}

static bool zd_vt_is_vcl_nal(uint32_t codec_id, uint8_t nal_type) {
    if (codec_id == ZD_VT_CODEC_H264) {
        return nal_type >= 1u && nal_type <= 5u;
    }
    return nal_type <= 31u;
}

/* ============================================================================
 * Pure-C Annex-B Parser with Strict Safety Caps
 * ========================================================================== */

int32_t zd_vt_parse_annexb(
    uint32_t codec_id,
    const uint8_t *data,
    size_t len,
    ZdVtAnnexbParseResult *out
) {
    if ((codec_id != ZD_VT_CODEC_H264 && codec_id != ZD_VT_CODEC_HEVC) ||
        data == NULL || len == 0u || out == NULL) {
        return ZD_VT_ERR_INVALID_ARG;
    }

    memset(out, 0, sizeof(*out));

    /* Must begin with 00 00 00 01 or 00 00 01 at byte 0 (fail-closed on leading junk). */
    size_t pos = 0u;
    if (len >= 4u && data[0] == 0u && data[1] == 0u && data[2] == 0u && data[3] == 1u) {
        pos = 4u;
    } else if (len >= 3u && data[0] == 0u && data[1] == 0u && data[2] == 1u) {
        pos = 3u;
    } else {
        return ZD_VT_ERR_NEED_IDR;
    }

    while (pos < len) {
        size_t nal_start = pos;
        size_t nal_end = len;
        size_t next_pos = len;

        /* Find next 00 00 01 (and absorb preceding 00 if part of 00 00 00 01). */
        for (size_t j = nal_start; j + 2u < len; ++j) {
            if (data[j] == 0u && data[j + 1u] == 0u && data[j + 2u] == 1u) {
                nal_end = (j > nal_start && data[j - 1u] == 0u) ? (j - 1u) : j;
                next_pos = j + 3u;
                break;
            }
        }

        if (nal_end <= nal_start) {
            return ZD_VT_ERR_NEED_IDR;
        }
        size_t nal_len = nal_end - nal_start;

        if (out->nal_count >= ZD_VT_MAX_NALS_PER_FRAME) {
            return ZD_VT_ERR_SAFETY_CAP;
        }

        uint8_t b0 = data[nal_start];
        if ((b0 & 0x80u) != 0u) {
            /* forbidden_zero_bit must be 0 in both H.264 and HEVC. */
            return ZD_VT_ERR_NEED_IDR;
        }

        uint8_t nal_type = 0u;
        if (codec_id == ZD_VT_CODEC_H264) {
            nal_type = (uint8_t)(b0 & 0x1Fu);
            if (nal_type == 7u) {
                if (nal_len > ZD_VT_MAX_PARAM_SET_BYTES ||
                    out->sps_count >= ZD_VT_MAX_PARAM_SETS_PER_TYPE ||
                    out->total_param_bytes > ZD_VT_MAX_TOTAL_PARAM_BYTES - nal_len) {
                    return ZD_VT_ERR_SAFETY_CAP;
                }
                out->sps_count += 1u;
                out->total_param_bytes += nal_len;
            } else if (nal_type == 8u) {
                if (nal_len > ZD_VT_MAX_PARAM_SET_BYTES ||
                    out->pps_count >= ZD_VT_MAX_PARAM_SETS_PER_TYPE ||
                    out->total_param_bytes > ZD_VT_MAX_TOTAL_PARAM_BYTES - nal_len) {
                    return ZD_VT_ERR_SAFETY_CAP;
                }
                out->pps_count += 1u;
                out->total_param_bytes += nal_len;
            } else if (nal_type == 5u) {
                out->has_idr = 1u;
                out->vcl_count += 1u;
            } else if (nal_type >= 1u && nal_type <= 4u) {
                out->vcl_count += 1u;
            }
        } else {
            if (nal_len < 2u) {
                return ZD_VT_ERR_NEED_IDR;
            }
            nal_type = (uint8_t)((b0 >> 1) & 0x3Fu);
            if (nal_type == 32u) {
                if (nal_len > ZD_VT_MAX_PARAM_SET_BYTES ||
                    out->vps_count >= ZD_VT_MAX_PARAM_SETS_PER_TYPE ||
                    out->total_param_bytes > ZD_VT_MAX_TOTAL_PARAM_BYTES - nal_len) {
                    return ZD_VT_ERR_SAFETY_CAP;
                }
                out->vps_count += 1u;
                out->total_param_bytes += nal_len;
            } else if (nal_type == 33u) {
                if (nal_len > ZD_VT_MAX_PARAM_SET_BYTES ||
                    out->sps_count >= ZD_VT_MAX_PARAM_SETS_PER_TYPE ||
                    out->total_param_bytes > ZD_VT_MAX_TOTAL_PARAM_BYTES - nal_len) {
                    return ZD_VT_ERR_SAFETY_CAP;
                }
                out->sps_count += 1u;
                out->total_param_bytes += nal_len;
            } else if (nal_type == 34u) {
                if (nal_len > ZD_VT_MAX_PARAM_SET_BYTES ||
                    out->pps_count >= ZD_VT_MAX_PARAM_SETS_PER_TYPE ||
                    out->total_param_bytes > ZD_VT_MAX_TOTAL_PARAM_BYTES - nal_len) {
                    return ZD_VT_ERR_SAFETY_CAP;
                }
                out->pps_count += 1u;
                out->total_param_bytes += nal_len;
            } else if (nal_type == 19u || nal_type == 20u) {
                out->has_idr = 1u;
                out->vcl_count += 1u;
            } else if (nal_type <= 31u) {
                out->vcl_count += 1u;
            }
        }

        ZdVtAnnexbSlice *sl = &out->nals[out->nal_count];
        sl->offset = nal_start;
        sl->len = nal_len;
        sl->nal_type = nal_type;
        out->nal_count += 1u;

        if (next_pos >= len) {
            /* Trailing start code with no NAL bytes after it is malformed. */
            if (nal_end < len && next_pos == len) {
                return ZD_VT_ERR_NEED_IDR;
            }
            break;
        }
        pos = next_pos;
    }

    if (out->vcl_count == 0u) {
        return ZD_VT_ERR_NEED_IDR;
    }
    return ZD_VT_OK;
}

/* ============================================================================
 * VideoToolbox Hardware Encoder (VTCompressionSession)
 * ========================================================================== */

struct ZdVtEncoder {
    uint32_t codec_id;
    uint32_t width;
    uint32_t height;
    uint32_t fps;
    VTCompressionSessionRef session;
    CVPixelBufferPoolRef pool;
    pthread_mutex_t mu;
    bool mu_init;

    /* Owned Annex-B output buffer written by VT callback under `mu`. */
    uint8_t *out_buf;
    size_t out_len;
    size_t out_cap;
    uint8_t out_is_idr;
    int32_t out_status;
    int32_t out_os_status;
    bool has_output;
};

static bool zd_vt_enc_append(ZdVtEncoder *enc, const uint8_t *src, size_t n) {
    if (n > ZD_VT_MAX_OUTPUT_BYTES || enc->out_len > ZD_VT_MAX_OUTPUT_BYTES - n) {
        return false;
    }
    if (!zd_vt_buf_reserve(&enc->out_buf, &enc->out_cap, enc->out_len + n, ZD_VT_MAX_OUTPUT_BYTES)) {
        return false;
    }
    memcpy(enc->out_buf + enc->out_len, src, n);
    enc->out_len += n;
    return true;
}

static bool zd_vt_read_nal_len(const uint8_t *p, int nal_len_size, size_t *out_len) {
    if (nal_len_size == 4) {
        *out_len = ((size_t)p[0] << 24) | ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | (size_t)p[3];
        return true;
    }
    if (nal_len_size == 2) {
        *out_len = ((size_t)p[0] << 8) | (size_t)p[1];
        return true;
    }
    if (nal_len_size == 1) {
        *out_len = (size_t)p[0];
        return true;
    }
    return false;
}

static void zd_vt_enc_output_cb(
    void *outputCallbackRefCon,
    void *sourceFrameRefCon,
    OSStatus status,
    VTEncodeInfoFlags infoFlags,
    CMSampleBufferRef sampleBuffer
) {
    (void)sourceFrameRefCon;
    (void)infoFlags;

    ZdVtEncoder *enc = (ZdVtEncoder *)outputCallbackRefCon;
    if (enc == NULL) {
        return;
    }

    pthread_mutex_lock(&enc->mu);
    enc->out_len = 0u;
    enc->out_is_idr = 0u;
    enc->out_os_status = (int32_t)status;
    enc->has_output = true;

    if (status != noErr) {
        enc->out_status = zd_vt_map_enc_osstatus(status);
        pthread_mutex_unlock(&enc->mu);
        return;
    }

    if (sampleBuffer == NULL || !CMSampleBufferDataIsReady(sampleBuffer)) {
        enc->out_status = ZD_VT_ERR_NO_OUTPUT;
        pthread_mutex_unlock(&enc->mu);
        return;
    }

    CMFormatDescriptionRef fmt = CMSampleBufferGetFormatDescription(sampleBuffer);
    CMBlockBufferRef block = CMSampleBufferGetDataBuffer(sampleBuffer);
    if (fmt == NULL || block == NULL) {
        enc->out_status = ZD_VT_ERR_INTERNAL;
        pthread_mutex_unlock(&enc->mu);
        return;
    }

    size_t ps_count = 0u;
    int nal_len_size = 4;
    OSStatus ps_st = noErr;
    if (enc->codec_id == ZD_VT_CODEC_H264) {
        ps_st = CMVideoFormatDescriptionGetH264ParameterSetAtIndex(
            fmt, 0u, NULL, NULL, &ps_count, &nal_len_size
        );
    } else {
        ps_st = CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(
            fmt, 0u, NULL, NULL, &ps_count, &nal_len_size
        );
    }
    if (ps_st != noErr || (nal_len_size != 4 && nal_len_size != 2 && nal_len_size != 1)) {
        enc->out_status = ZD_VT_ERR_INTERNAL;
        enc->out_os_status = (int32_t)ps_st;
        pthread_mutex_unlock(&enc->mu);
        return;
    }

    size_t total_len = CMBlockBufferGetDataLength(block);
    if (total_len == 0u || total_len > ZD_VT_MAX_OUTPUT_BYTES) {
        enc->out_status = ZD_VT_ERR_NO_OUTPUT;
        pthread_mutex_unlock(&enc->mu);
        return;
    }

    const uint8_t *raw_ptr = NULL;
    uint8_t *heap_copy = NULL;
    size_t len_at_offset = 0u;
    char *data_ptr = NULL;
    OSStatus blk_st = CMBlockBufferGetDataPointer(block, 0u, &len_at_offset, NULL, &data_ptr);
    if (blk_st == noErr && data_ptr != NULL && len_at_offset >= total_len) {
        raw_ptr = (const uint8_t *)data_ptr;
    } else {
        heap_copy = (uint8_t *)malloc(total_len);
        if (heap_copy == NULL) {
            enc->out_status = ZD_VT_ERR_ALLOC;
            pthread_mutex_unlock(&enc->mu);
            return;
        }
        blk_st = CMBlockBufferCopyDataBytes(block, 0u, total_len, heap_copy);
        if (blk_st != noErr) {
            free(heap_copy);
            enc->out_status = ZD_VT_ERR_INTERNAL;
            enc->out_os_status = (int32_t)blk_st;
            pthread_mutex_unlock(&enc->mu);
            return;
        }
        raw_ptr = heap_copy;
    }

    /* Pass 1: determine actual is_idr strictly from NAL unit type (never trust NotSync alone). */
    bool is_idr = false;
    size_t off = 0u;
    bool scan_ok = true;
    while (off < total_len) {
        if ((size_t)nal_len_size > total_len - off) {
            scan_ok = false;
            break;
        }
        size_t nal_len = 0u;
        if (!zd_vt_read_nal_len(raw_ptr + off, nal_len_size, &nal_len)) {
            scan_ok = false;
            break;
        }
        off += (size_t)nal_len_size;
        if (nal_len == 0u || nal_len > total_len - off) {
            scan_ok = false;
            break;
        }
        uint8_t nal_type = (enc->codec_id == ZD_VT_CODEC_H264)
            ? (uint8_t)(raw_ptr[off] & 0x1Fu)
            : (uint8_t)((raw_ptr[off] >> 1) & 0x3Fu);
        if (zd_vt_is_idr_nal(enc->codec_id, nal_type)) {
            is_idr = true;
        }
        off += nal_len;
    }

    if (!scan_ok) {
        free(heap_copy);
        enc->out_status = ZD_VT_ERR_INTERNAL;
        pthread_mutex_unlock(&enc->mu);
        return;
    }

    enc->out_is_idr = is_idr ? 1u : 0u;

    /* Pass 2: if IDR, ALWAYS prepend full parameter sets (H.264 SPS+PPS / HEVC VPS+SPS+PPS). */
    if (is_idr) {
        for (size_t idx = 0u; idx < ps_count; ++idx) {
            const uint8_t *ps_ptr = NULL;
            size_t ps_size = 0u;
            OSStatus st_i = (enc->codec_id == ZD_VT_CODEC_H264)
                ? CMVideoFormatDescriptionGetH264ParameterSetAtIndex(fmt, idx, &ps_ptr, &ps_size, NULL, NULL)
                : CMVideoFormatDescriptionGetHEVCParameterSetAtIndex(fmt, idx, &ps_ptr, &ps_size, NULL, NULL);
            if (st_i != noErr || ps_ptr == NULL || ps_size == 0u) {
                free(heap_copy);
                enc->out_status = ZD_VT_ERR_INTERNAL;
                enc->out_os_status = (int32_t)st_i;
                pthread_mutex_unlock(&enc->mu);
                return;
            }
            if (!zd_vt_enc_append(enc, ZD_ANNEXB_SC, 4u) ||
                !zd_vt_enc_append(enc, ps_ptr, ps_size)) {
                free(heap_copy);
                enc->out_status = ZD_VT_ERR_ALLOC;
                pthread_mutex_unlock(&enc->mu);
                return;
            }
        }
    }

    /* Pass 3: convert AVCC/HVCC length-prefixed NALs to Annex-B (00 00 00 01). */
    off = 0u;
    while (off < total_len) {
        size_t nal_len = 0u;
        (void)zd_vt_read_nal_len(raw_ptr + off, nal_len_size, &nal_len);
        off += (size_t)nal_len_size;

        uint8_t nal_type = (enc->codec_id == ZD_VT_CODEC_H264)
            ? (uint8_t)(raw_ptr[off] & 0x1Fu)
            : (uint8_t)((raw_ptr[off] >> 1) & 0x3Fu);

        /* Skip inline parameter sets on IDR since we already emitted the canonical set from fmt. */
        if (!(is_idr && zd_vt_is_param_nal(enc->codec_id, nal_type))) {
            if (!zd_vt_enc_append(enc, ZD_ANNEXB_SC, 4u) ||
                !zd_vt_enc_append(enc, raw_ptr + off, nal_len)) {
                free(heap_copy);
                enc->out_status = ZD_VT_ERR_ALLOC;
                pthread_mutex_unlock(&enc->mu);
                return;
            }
        }
        off += nal_len;
    }

    free(heap_copy);
    enc->out_status = (enc->out_len > 0u) ? ZD_VT_OK : ZD_VT_ERR_NO_OUTPUT;
    pthread_mutex_unlock(&enc->mu);
}

static CVPixelBufferPoolRef zd_vt_create_nv12_pool(uint32_t width, uint32_t height) {
    CFMutableDictionaryRef pb_attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    if (pb_attrs == NULL) {
        return NULL;
    }
    CFMutableDictionaryRef io_surf = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    if (io_surf == NULL) {
        CFRelease(pb_attrs);
        return NULL;
    }

    bool ok = zd_vt_dict_set_int32(pb_attrs, kCVPixelBufferPixelFormatTypeKey,
                                   (int32_t)kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange) &&
              zd_vt_dict_set_int32(pb_attrs, kCVPixelBufferWidthKey, (int32_t)width) &&
              zd_vt_dict_set_int32(pb_attrs, kCVPixelBufferHeightKey, (int32_t)height);
    CFDictionarySetValue(pb_attrs, kCVPixelBufferIOSurfacePropertiesKey, io_surf);
    CFRelease(io_surf);

    CVPixelBufferPoolRef pool = NULL;
    if (ok) {
        CVReturn cv_rc = CVPixelBufferPoolCreate(kCFAllocatorDefault, NULL, pb_attrs, &pool);
        if (cv_rc != kCVReturnSuccess) {
            pool = NULL;
        }
    }
    CFRelease(pb_attrs);
    return pool;
}

int32_t zd_vt_enc_create(const ZdVtEncoderConfig *cfg, ZdVtEncoder **out_enc) {
    if (cfg == NULL || out_enc == NULL) {
        return ZD_VT_ERR_INVALID_ARG;
    }
    *out_enc = NULL;

    if ((cfg->codec_id != ZD_VT_CODEC_H264 && cfg->codec_id != ZD_VT_CODEC_HEVC) ||
        !zd_vt_dims_valid(cfg->width, cfg->height) ||
        (cfg->width & 1u) != 0u || (cfg->height & 1u) != 0u ||
        cfg->bitrate_bps == 0u) {
        return ZD_VT_ERR_INVALID_ARG;
    }

    uint32_t fps = (cfg->fps == 0u) ? 30u : cfg->fps;
    if (fps > 240u) {
        fps = 240u;
    }
    uint32_t max_kf = (cfg->max_keyframe_interval == 0u) ? (fps * 2u) : cfg->max_keyframe_interval;

    ZdVtEncoder *enc = (ZdVtEncoder *)calloc(1u, sizeof(ZdVtEncoder));
    if (enc == NULL) {
        return ZD_VT_ERR_ALLOC;
    }
    enc->codec_id = cfg->codec_id;
    enc->width = cfg->width;
    enc->height = cfg->height;
    enc->fps = fps;

    if (pthread_mutex_init(&enc->mu, NULL) != 0) {
        free(enc);
        return ZD_VT_ERR_ALLOC;
    }
    enc->mu_init = true;

    CFMutableDictionaryRef enc_spec = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFMutableDictionaryRef src_attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 4, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFMutableDictionaryRef io_surf = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    if (enc_spec == NULL || src_attrs == NULL || io_surf == NULL) {
        if (enc_spec != NULL) { CFRelease(enc_spec); }
        if (src_attrs != NULL) { CFRelease(src_attrs); }
        if (io_surf != NULL) { CFRelease(io_surf); }
        zd_vt_enc_destroy(enc);
        return ZD_VT_ERR_ALLOC;
    }

    /* Strict hardware encoder enforcement for BOTH H.264 and HEVC (zero SW fallback!). */
    CFDictionarySetValue(
        enc_spec,
        kVTVideoEncoderSpecification_RequireHardwareAcceleratedVideoEncoder,
        kCFBooleanTrue
    );
    CFDictionarySetValue(
        enc_spec,
        kVTVideoEncoderSpecification_EnableHardwareAcceleratedVideoEncoder,
        kCFBooleanTrue
    );

    bool attrs_ok = zd_vt_dict_set_int32(
                        src_attrs, kCVPixelBufferPixelFormatTypeKey,
                        (int32_t)kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange) &&
                    zd_vt_dict_set_int32(src_attrs, kCVPixelBufferWidthKey, (int32_t)cfg->width) &&
                    zd_vt_dict_set_int32(src_attrs, kCVPixelBufferHeightKey, (int32_t)cfg->height);
    CFDictionarySetValue(src_attrs, kCVPixelBufferIOSurfacePropertiesKey, io_surf);
    CFRelease(io_surf);

    if (!attrs_ok) {
        CFRelease(enc_spec);
        CFRelease(src_attrs);
        zd_vt_enc_destroy(enc);
        return ZD_VT_ERR_ALLOC;
    }

    CMVideoCodecType cm_codec = (cfg->codec_id == ZD_VT_CODEC_H264)
        ? kCMVideoCodecType_H264
        : kCMVideoCodecType_HEVC;

    OSStatus st = VTCompressionSessionCreate(
        kCFAllocatorDefault,
        (int32_t)cfg->width,
        (int32_t)cfg->height,
        cm_codec,
        enc_spec,
        src_attrs,
        kCFAllocatorDefault,
        zd_vt_enc_output_cb,
        enc,
        &enc->session
    );
    CFRelease(enc_spec);
    CFRelease(src_attrs);

    if (st != noErr || enc->session == NULL) {
        zd_vt_enc_destroy(enc);
        return zd_vt_map_enc_osstatus(st);
    }

    /* Post-creation hardware verification: MUST be true, NEVER silently accept software! */
    if (!zd_vt_verify_hw_property(enc->session,
                                  kVTCompressionPropertyKey_UsingHardwareAcceleratedVideoEncoder)) {
        zd_vt_enc_destroy(enc);
        return ZD_VT_ERR_HW_UNAVAILABLE;
    }

    /* Low-latency real-time properties (0 B-frames, monotonic output order). */
    st = VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_RealTime, kCFBooleanTrue);
    if (st != noErr) {
        zd_vt_enc_destroy(enc);
        return zd_vt_map_enc_osstatus(st);
    }
    st = VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_AllowFrameReordering, kCFBooleanFalse);
    if (st != noErr) {
        zd_vt_enc_destroy(enc);
        return zd_vt_map_enc_osstatus(st);
    }
    (void)VTSessionSetProperty(
        enc->session,
        kVTCompressionPropertyKey_PrioritizeEncodingSpeedOverQuality,
        kCFBooleanTrue
    );

    CFStringRef profile = (cfg->codec_id == ZD_VT_CODEC_H264)
        ? kVTProfileLevel_H264_High_AutoLevel
        : kVTProfileLevel_HEVC_Main_AutoLevel;
    (void)VTSessionSetProperty(enc->session, kVTCompressionPropertyKey_ProfileLevel, profile);

    (void)zd_vt_session_set_int32(enc->session, kVTCompressionPropertyKey_ExpectedFrameRate, (int32_t)fps);
    (void)zd_vt_session_set_int32(enc->session, kVTCompressionPropertyKey_MaxKeyFrameInterval, (int32_t)max_kf);
    (void)zd_vt_session_set_double(
        enc->session,
        kVTCompressionPropertyKey_MaxKeyFrameIntervalDuration,
        (double)max_kf / (double)fps
    );

    st = zd_vt_session_set_int32(
        enc->session,
        kVTCompressionPropertyKey_AverageBitRate,
        (cfg->bitrate_bps > (uint32_t)INT32_MAX) ? INT32_MAX : (int32_t)cfg->bitrate_bps
    );
    if (st != noErr) {
        zd_vt_enc_destroy(enc);
        return zd_vt_map_enc_osstatus(st);
    }
    (void)zd_vt_session_set_data_rate_limits(enc->session, cfg->bitrate_bps);

    /* Explicit BT.709 colorimetry to prevent YCbCr matrix / color shift. */
    (void)VTSessionSetProperty(
        enc->session,
        kVTCompressionPropertyKey_ColorPrimaries,
        kCVImageBufferColorPrimaries_ITU_R_709_2
    );
    (void)VTSessionSetProperty(
        enc->session,
        kVTCompressionPropertyKey_TransferFunction,
        kCVImageBufferTransferFunction_ITU_R_709_2
    );
    (void)VTSessionSetProperty(
        enc->session,
        kVTCompressionPropertyKey_YCbCrMatrix,
        kCVImageBufferYCbCrMatrix_ITU_R_709_2
    );

    st = VTCompressionSessionPrepareToEncodeFrames(enc->session);
    if (st != noErr) {
        zd_vt_enc_destroy(enc);
        return zd_vt_map_enc_osstatus(st);
    }

    CVPixelBufferPoolRef session_pool = VTCompressionSessionGetPixelBufferPool(enc->session);
    if (session_pool != NULL) {
        CFRetain(session_pool);
        enc->pool = session_pool;
    } else {
        enc->pool = zd_vt_create_nv12_pool(cfg->width, cfg->height);
        if (enc->pool == NULL) {
            zd_vt_enc_destroy(enc);
            return ZD_VT_ERR_ALLOC;
        }
    }

    *out_enc = enc;
    return ZD_VT_OK;
}

int32_t zd_vt_enc_set_bitrate(ZdVtEncoder *enc, uint32_t bitrate_bps) {
    if (enc == NULL || enc->session == NULL || bitrate_bps == 0u) {
        return ZD_VT_ERR_INVALID_ARG;
    }
    OSStatus st = zd_vt_session_set_int32(
        enc->session,
        kVTCompressionPropertyKey_AverageBitRate,
        (bitrate_bps > (uint32_t)INT32_MAX) ? INT32_MAX : (int32_t)bitrate_bps
    );
    if (st != noErr) {
        return zd_vt_map_enc_osstatus(st);
    }
    st = zd_vt_session_set_data_rate_limits(enc->session, bitrate_bps);
    if (st != noErr) {
        return zd_vt_map_enc_osstatus(st);
    }
    return ZD_VT_OK;
}

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
) {
    if (enc == NULL || enc->session == NULL || enc->pool == NULL ||
        y_ptr == NULL || uv_ptr == NULL || out_frame == NULL ||
        width != enc->width || height != enc->height ||
        y_stride < width || uv_stride < width) {
        return ZD_VT_ERR_INVALID_ARG;
    }
    memset(out_frame, 0, sizeof(*out_frame));

    CVPixelBufferRef pb = NULL;
    CVReturn cv_rc = CVPixelBufferPoolCreatePixelBuffer(kCFAllocatorDefault, enc->pool, &pb);
    if (cv_rc != kCVReturnSuccess || pb == NULL) {
        return ZD_VT_ERR_ALLOC;
    }

    CVBufferSetAttachment(
        pb, kCVImageBufferColorPrimariesKey, kCVImageBufferColorPrimaries_ITU_R_709_2,
        kCVAttachmentMode_ShouldPropagate
    );
    CVBufferSetAttachment(
        pb, kCVImageBufferTransferFunctionKey, kCVImageBufferTransferFunction_ITU_R_709_2,
        kCVAttachmentMode_ShouldPropagate
    );
    CVBufferSetAttachment(
        pb, kCVImageBufferYCbCrMatrixKey, kCVImageBufferYCbCrMatrix_ITU_R_709_2,
        kCVAttachmentMode_ShouldPropagate
    );

    cv_rc = CVPixelBufferLockBaseAddress(pb, 0);
    if (cv_rc != kCVReturnSuccess) {
        CFRelease(pb);
        return ZD_VT_ERR_INTERNAL;
    }

    uint8_t *dst_y = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 0u);
    size_t dst_y_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 0u);
    uint8_t *dst_uv = (uint8_t *)CVPixelBufferGetBaseAddressOfPlane(pb, 1u);
    size_t dst_uv_stride = CVPixelBufferGetBytesPerRowOfPlane(pb, 1u);

    if (dst_y == NULL || dst_uv == NULL || dst_y_stride < width || dst_uv_stride < width) {
        CVPixelBufferUnlockBaseAddress(pb, 0);
        CFRelease(pb);
        return ZD_VT_ERR_INTERNAL;
    }

    if (dst_y_stride == width && y_stride == width) {
        memcpy(dst_y, y_ptr, (size_t)width * (size_t)height);
    } else {
        for (uint32_t row = 0u; row < height; ++row) {
            memcpy(dst_y + (size_t)row * dst_y_stride, y_ptr + (size_t)row * (size_t)y_stride, width);
        }
    }
    uint32_t uv_h = height / 2u;
    if (dst_uv_stride == width && uv_stride == width) {
        memcpy(dst_uv, uv_ptr, (size_t)width * (size_t)uv_h);
    } else {
        for (uint32_t row = 0u; row < uv_h; ++row) {
            memcpy(dst_uv + (size_t)row * dst_uv_stride, uv_ptr + (size_t)row * (size_t)uv_stride, width);
        }
    }
    CVPixelBufferUnlockBaseAddress(pb, 0);

    pthread_mutex_lock(&enc->mu);
    enc->has_output = false;
    enc->out_len = 0u;
    enc->out_is_idr = 0u;
    enc->out_status = ZD_VT_OK;
    enc->out_os_status = 0;
    pthread_mutex_unlock(&enc->mu);

    CFMutableDictionaryRef frame_props = NULL;
    if (force_idr != 0u) {
        frame_props = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
        );
        if (frame_props == NULL) {
            CFRelease(pb);
            return ZD_VT_ERR_ALLOC;
        }
        CFDictionarySetValue(frame_props, kVTEncodeFrameOptionKey_ForceKeyFrame, kCFBooleanTrue);
    }

    CMTime pts = CMTimeMake(pts_us, 1000000);
    CMTime dur = CMTimeMake((int64_t)(1000000u / enc->fps), 1000000);
    VTEncodeInfoFlags info_flags = 0;

    OSStatus enc_st = VTCompressionSessionEncodeFrame(
        enc->session, pb, pts, dur, frame_props, NULL, &info_flags
    );
    if (frame_props != NULL) {
        CFRelease(frame_props);
    }
    CFRelease(pb);

    if (enc_st != noErr) {
        out_frame->os_status = (int32_t)enc_st;
        return zd_vt_map_enc_osstatus(enc_st);
    }

    OSStatus flush_st = VTCompressionSessionCompleteFrames(enc->session, pts);
    if (flush_st != noErr) {
        out_frame->os_status = (int32_t)flush_st;
        return zd_vt_map_enc_osstatus(flush_st);
    }

    pthread_mutex_lock(&enc->mu);
    int32_t res = enc->has_output ? enc->out_status : ZD_VT_ERR_NO_OUTPUT;
    out_frame->os_status = enc->out_os_status;
    if (res == ZD_VT_OK) {
        out_frame->data = enc->out_buf;
        out_frame->len = enc->out_len;
        out_frame->is_idr = enc->out_is_idr;
    }
    pthread_mutex_unlock(&enc->mu);

    return res;
}

void zd_vt_enc_destroy(ZdVtEncoder *enc) {
    if (enc == NULL) {
        return;
    }
    if (enc->session != NULL) {
        VTCompressionSessionInvalidate(enc->session);
        CFRelease(enc->session);
        enc->session = NULL;
    }
    if (enc->pool != NULL) {
        CFRelease(enc->pool);
        enc->pool = NULL;
    }
    if (enc->mu_init) {
        pthread_mutex_destroy(&enc->mu);
        enc->mu_init = false;
    }
    free(enc->out_buf);
    enc->out_buf = NULL;
    free(enc);
}

void zd_vt_enc_invalidate_session_for_test(ZdVtEncoder *enc) {
    if (enc != NULL && enc->session != NULL) {
        VTCompressionSessionInvalidate(enc->session);
    }
}

/* ============================================================================
 * VideoToolbox Hardware Decoder (VTDecompressionSession, Synchronous 32BGRA)
 * ========================================================================== */

struct ZdVtDecoder {
    uint32_t codec_id;
    OSType output_pixfmt;
    CMVideoFormatDescriptionRef format_desc;
    VTDecompressionSessionRef session;

    /* Canonical serialized active parameter sets for byte-for-byte change detection. */
    uint8_t *active_ps_blob;
    size_t active_ps_len;

    /* Reusable AVCC/HVCC conversion buffer (4-byte BE length prefixes). */
    uint8_t *avcc_buf;
    size_t avcc_cap;

    /* Tightly-packed 32BGRA output buffer written synchronously by VT callback. */
    uint8_t *bgra_buf;
    size_t bgra_len;
    size_t bgra_cap;
    /* Optional caller-provided direct destination buffer for zero-extra-copy decode. */
    uint8_t *caller_bgra_dst;
    size_t caller_bgra_cap;
    const uint8_t *out_bgra_ptr;

    /* Tightly-packed native NV12 output buffers for zero-clipping I420 callers. */
    uint8_t *nv12_y_buf;
    size_t nv12_y_cap;
    uint8_t *nv12_uv_buf;
    size_t nv12_uv_cap;

    uint32_t out_width;
    uint32_t out_height;
    uint32_t out_stride;
    uint32_t out_uv_stride;
    int32_t out_status;
    int32_t out_os_status;
    bool has_output;
};

static void zd_vt_dec_release_session(ZdVtDecoder *dec) {
    if (dec->session != NULL) {
        VTDecompressionSessionWaitForAsynchronousFrames(dec->session);
        VTDecompressionSessionInvalidate(dec->session);
        CFRelease(dec->session);
        dec->session = NULL;
    }
    if (dec->format_desc != NULL) {
        CFRelease(dec->format_desc);
        dec->format_desc = NULL;
    }
}

static void zd_vt_dec_output_cb(
    void *decompressionOutputRefCon,
    void *sourceFrameRefCon,
    OSStatus status,
    VTDecodeInfoFlags infoFlags,
    CVImageBufferRef imageBuffer,
    CMTime presentationTimeStamp,
    CMTime presentationDuration
) {
    (void)sourceFrameRefCon;
    (void)presentationTimeStamp;
    (void)presentationDuration;

    ZdVtDecoder *dec = (ZdVtDecoder *)decompressionOutputRefCon;
    if (dec == NULL) {
        return;
    }

    dec->has_output = true;
    dec->out_os_status = (int32_t)status;
    dec->bgra_len = 0u;
    dec->out_bgra_ptr = NULL;
    dec->out_width = 0u;
    dec->out_height = 0u;
    dec->out_stride = 0u;
    dec->out_uv_stride = 0u;

    if ((infoFlags & kVTDecodeInfo_Asynchronous) != 0u) {
        dec->out_status = ZD_VT_ERR_DECODE_ASYNC;
        return;
    }
    if (status != noErr) {
        dec->out_status = zd_vt_map_dec_osstatus(status);
        return;
    }
    if (imageBuffer == NULL) {
        dec->out_status = ZD_VT_ERR_NO_OUTPUT;
        return;
    }

    OSType pixfmt = CVPixelBufferGetPixelFormatType(imageBuffer);
    size_t w_sz = CVPixelBufferGetWidth(imageBuffer);
    size_t h_sz = CVPixelBufferGetHeight(imageBuffer);

    if (w_sz > UINT32_MAX || h_sz > UINT32_MAX ||
        !zd_vt_dims_valid((uint32_t)w_sz, (uint32_t)h_sz)) {
        dec->out_status = ZD_VT_ERR_SAFETY_CAP;
        return;
    }

    uint32_t w = (uint32_t)w_sz;
    uint32_t h = (uint32_t)h_sz;

    if (pixfmt == kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange) {
        if ((w & 1u) != 0u || (h & 1u) != 0u) {
            dec->out_status = ZD_VT_ERR_SAFETY_CAP;
            return;
        }
        size_t y_bytes = (size_t)w * (size_t)h;
        size_t uv_h = (size_t)(h / 2u);
        size_t uv_bytes = (size_t)w * uv_h;
        size_t max_y_bytes = (size_t)ZD_VT_MAX_PIXELS;
        if (!zd_vt_buf_reserve(&dec->nv12_y_buf, &dec->nv12_y_cap, y_bytes, max_y_bytes) ||
            !zd_vt_buf_reserve(&dec->nv12_uv_buf, &dec->nv12_uv_cap, uv_bytes, max_y_bytes)) {
            dec->out_status = ZD_VT_ERR_ALLOC;
            return;
        }

        CVReturn lock_rc = CVPixelBufferLockBaseAddress(imageBuffer, kCVPixelBufferLock_ReadOnly);
        if (lock_rc != kCVReturnSuccess) {
            dec->out_status = ZD_VT_ERR_INTERNAL;
            return;
        }
        const uint8_t *src_y = (const uint8_t *)CVPixelBufferGetBaseAddressOfPlane(imageBuffer, 0u);
        size_t src_y_bpr = CVPixelBufferGetBytesPerRowOfPlane(imageBuffer, 0u);
        const uint8_t *src_uv = (const uint8_t *)CVPixelBufferGetBaseAddressOfPlane(imageBuffer, 1u);
        size_t src_uv_bpr = CVPixelBufferGetBytesPerRowOfPlane(imageBuffer, 1u);
        if (src_y == NULL || src_uv == NULL || src_y_bpr < (size_t)w || src_uv_bpr < (size_t)w) {
            CVPixelBufferUnlockBaseAddress(imageBuffer, kCVPixelBufferLock_ReadOnly);
            dec->out_status = ZD_VT_ERR_INTERNAL;
            return;
        }
        if (src_y_bpr == (size_t)w) {
            memcpy(dec->nv12_y_buf, src_y, y_bytes);
        } else {
            for (uint32_t row = 0u; row < h; ++row) {
                memcpy(dec->nv12_y_buf + (size_t)row * (size_t)w, src_y + (size_t)row * src_y_bpr, w);
            }
        }
        if (src_uv_bpr == (size_t)w) {
            memcpy(dec->nv12_uv_buf, src_uv, uv_bytes);
        } else {
            for (size_t row = 0u; row < uv_h; ++row) {
                memcpy(dec->nv12_uv_buf + row * (size_t)w, src_uv + row * src_uv_bpr, w);
            }
        }
        CVPixelBufferUnlockBaseAddress(imageBuffer, kCVPixelBufferLock_ReadOnly);

        dec->out_width = w;
        dec->out_height = h;
        dec->out_stride = w;
        dec->out_uv_stride = w;
        dec->out_status = ZD_VT_OK;
        return;
    }

    if (pixfmt != kCVPixelFormatType_32BGRA) {
        dec->out_status = ZD_VT_ERR_INTERNAL;
        return;
    }

    size_t bpr = CVPixelBufferGetBytesPerRow(imageBuffer);
    size_t row_bytes = (size_t)w * 4u;
    if (bpr < row_bytes) {
        dec->out_status = ZD_VT_ERR_INTERNAL;
        return;
    }

    size_t total_bytes = row_bytes * (size_t)h;
    size_t max_bgra_bytes = (size_t)ZD_VT_MAX_PIXELS * 4u;
    uint8_t *dst_ptr = NULL;
    if (dec->caller_bgra_dst != NULL && dec->caller_bgra_cap >= total_bytes) {
        dst_ptr = dec->caller_bgra_dst;
    } else {
        if (!zd_vt_buf_reserve(&dec->bgra_buf, &dec->bgra_cap, total_bytes, max_bgra_bytes)) {
            dec->out_status = ZD_VT_ERR_ALLOC;
            return;
        }
        dst_ptr = dec->bgra_buf;
    }

    CVReturn lock_rc = CVPixelBufferLockBaseAddress(imageBuffer, kCVPixelBufferLock_ReadOnly);
    if (lock_rc != kCVReturnSuccess) {
        dec->out_status = ZD_VT_ERR_INTERNAL;
        return;
    }
    const uint8_t *src = (const uint8_t *)CVPixelBufferGetBaseAddress(imageBuffer);
    if (src == NULL) {
        CVPixelBufferUnlockBaseAddress(imageBuffer, kCVPixelBufferLock_ReadOnly);
        dec->out_status = ZD_VT_ERR_INTERNAL;
        return;
    }

    if (bpr == row_bytes) {
        memcpy(dst_ptr, src, total_bytes);
    } else {
        for (uint32_t row = 0u; row < h; ++row) {
            memcpy(dst_ptr + (size_t)row * row_bytes, src + (size_t)row * bpr, row_bytes);
        }
    }
    CVPixelBufferUnlockBaseAddress(imageBuffer, kCVPixelBufferLock_ReadOnly);

    dec->out_bgra_ptr = dst_ptr;
    dec->bgra_len = total_bytes;
    dec->out_width = w;
    dec->out_height = h;
    dec->out_stride = (uint32_t)row_bytes;
    dec->out_status = ZD_VT_OK;
}

static int32_t zd_vt_dec_configure_from_idr(
    ZdVtDecoder *dec,
    const uint8_t *data,
    const ZdVtAnnexbParseResult *parsed,
    int32_t *out_os_status
) {
    bool has_required = (dec->codec_id == ZD_VT_CODEC_H264)
        ? (parsed->sps_count > 0u && parsed->pps_count > 0u)
        : (parsed->vps_count > 0u && parsed->sps_count > 0u && parsed->pps_count > 0u);

    if (!has_required) {
        return (dec->session != NULL && dec->format_desc != NULL) ? ZD_VT_OK : ZD_VT_ERR_NEED_IDR;
    }

    const uint8_t *ps_ptrs[ZD_VT_MAX_PS_TOTAL];
    size_t ps_sizes[ZD_VT_MAX_PS_TOTAL];
    uint8_t ps_types[ZD_VT_MAX_PS_TOTAL];
    size_t ps_count = 0u;
    size_t blob_len = 0u;

    for (uint32_t i = 0u; i < parsed->nal_count; ++i) {
        const ZdVtAnnexbSlice *sl = &parsed->nals[i];
        if (!zd_vt_is_param_nal(dec->codec_id, sl->nal_type)) {
            continue;
        }
        if (ps_count >= ZD_VT_MAX_PS_TOTAL) {
            return ZD_VT_ERR_SAFETY_CAP;
        }
        ps_ptrs[ps_count] = data + sl->offset;
        ps_sizes[ps_count] = sl->len;
        ps_types[ps_count] = sl->nal_type;
        ps_count += 1u;
        blob_len += 5u + sl->len;
    }

    uint8_t *blob = (uint8_t *)malloc(blob_len);
    if (blob == NULL) {
        return ZD_VT_ERR_ALLOC;
    }
    size_t boff = 0u;
    for (size_t i = 0u; i < ps_count; ++i) {
        uint32_t sz32 = (uint32_t)ps_sizes[i];
        blob[boff++] = ps_types[i];
        blob[boff++] = (uint8_t)((sz32 >> 24) & 0xFFu);
        blob[boff++] = (uint8_t)((sz32 >> 16) & 0xFFu);
        blob[boff++] = (uint8_t)((sz32 >> 8) & 0xFFu);
        blob[boff++] = (uint8_t)(sz32 & 0xFFu);
        memcpy(blob + boff, ps_ptrs[i], ps_sizes[i]);
        boff += ps_sizes[i];
    }

    if (dec->session != NULL && dec->format_desc != NULL &&
        dec->active_ps_blob != NULL && dec->active_ps_len == blob_len &&
        memcmp(dec->active_ps_blob, blob, blob_len) == 0) {
        free(blob);
        return ZD_VT_OK;
    }

    CMVideoFormatDescriptionRef new_fmt = NULL;
    OSStatus st = noErr;
    if (dec->codec_id == ZD_VT_CODEC_H264) {
        st = CMVideoFormatDescriptionCreateFromH264ParameterSets(
            kCFAllocatorDefault, ps_count, ps_ptrs, ps_sizes, 4, &new_fmt
        );
    } else {
        st = CMVideoFormatDescriptionCreateFromHEVCParameterSets(
            kCFAllocatorDefault, ps_count, ps_ptrs, ps_sizes, 4, NULL, &new_fmt
        );
    }
    if (st != noErr || new_fmt == NULL) {
        free(blob);
        *out_os_status = (int32_t)st;
        return ZD_VT_ERR_NEED_IDR;
    }

    /* Validate decoded dimensions from parsed SPS before creating decoder session! */
    CMVideoDimensions dims = CMVideoFormatDescriptionGetDimensions(new_fmt);
    if (dims.width <= 0 || dims.height <= 0 ||
        !zd_vt_dims_valid((uint32_t)dims.width, (uint32_t)dims.height)) {
        CFRelease(new_fmt);
        free(blob);
        return ZD_VT_ERR_SAFETY_CAP;
    }

    CFMutableDictionaryRef dec_spec = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFMutableDictionaryRef dst_attrs = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 2, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    CFMutableDictionaryRef io_surf = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks
    );
    if (dec_spec == NULL || dst_attrs == NULL || io_surf == NULL) {
        if (dec_spec != NULL) { CFRelease(dec_spec); }
        if (dst_attrs != NULL) { CFRelease(dst_attrs); }
        if (io_surf != NULL) { CFRelease(io_surf); }
        CFRelease(new_fmt);
        free(blob);
        return ZD_VT_ERR_ALLOC;
    }

    /* Strict hardware decoder enforcement for BOTH H.264 and HEVC! */
    CFDictionarySetValue(
        dec_spec,
        kVTVideoDecoderSpecification_RequireHardwareAcceleratedVideoDecoder,
        kCFBooleanTrue
    );
    CFDictionarySetValue(
        dec_spec,
        kVTVideoDecoderSpecification_EnableHardwareAcceleratedVideoDecoder,
        kCFBooleanTrue
    );

    OSType dst_pixfmt = (dec->output_pixfmt != 0u) ? dec->output_pixfmt : kCVPixelFormatType_32BGRA;
    bool ok = zd_vt_dict_set_int32(dst_attrs, kCVPixelBufferPixelFormatTypeKey,
                                   (int32_t)dst_pixfmt);
    CFDictionarySetValue(dst_attrs, kCVPixelBufferIOSurfacePropertiesKey, io_surf);
    CFRelease(io_surf);

    if (!ok) {
        CFRelease(dec_spec);
        CFRelease(dst_attrs);
        CFRelease(new_fmt);
        free(blob);
        return ZD_VT_ERR_ALLOC;
    }

    VTDecompressionOutputCallbackRecord cb;
    cb.decompressionOutputCallback = zd_vt_dec_output_cb;
    cb.decompressionOutputRefCon = dec;

    VTDecompressionSessionRef new_sess = NULL;
    st = VTDecompressionSessionCreate(
        kCFAllocatorDefault, new_fmt, dec_spec, dst_attrs, &cb, &new_sess
    );
    CFRelease(dec_spec);
    CFRelease(dst_attrs);

    if (st != noErr || new_sess == NULL) {
        CFRelease(new_fmt);
        free(blob);
        *out_os_status = (int32_t)st;
        return zd_vt_map_dec_osstatus(st);
    }

    if (!zd_vt_verify_hw_property(new_sess,
                                  kVTDecompressionPropertyKey_UsingHardwareAcceleratedVideoDecoder)) {
        VTDecompressionSessionInvalidate(new_sess);
        CFRelease(new_sess);
        CFRelease(new_fmt);
        free(blob);
        return ZD_VT_ERR_HW_UNAVAILABLE;
    }

    (void)VTSessionSetProperty(new_sess, kVTDecompressionPropertyKey_RealTime, kCFBooleanTrue);

    zd_vt_dec_release_session(dec);
    free(dec->active_ps_blob);

    dec->format_desc = new_fmt;
    dec->session = new_sess;
    dec->active_ps_blob = blob;
    dec->active_ps_len = blob_len;
    return ZD_VT_OK;
}

int32_t zd_vt_dec_create(uint32_t codec_id, ZdVtDecoder **out_dec) {
    if ((codec_id != ZD_VT_CODEC_H264 && codec_id != ZD_VT_CODEC_HEVC) || out_dec == NULL) {
        return ZD_VT_ERR_INVALID_ARG;
    }
    *out_dec = NULL;

    ZdVtDecoder *dec = (ZdVtDecoder *)calloc(1u, sizeof(ZdVtDecoder));
    if (dec == NULL) {
        return ZD_VT_ERR_ALLOC;
    }
    dec->codec_id = codec_id;
    *out_dec = dec;
    return ZD_VT_OK;
}

static int32_t zd_vt_dec_decode_annexb_common(
    ZdVtDecoder *dec,
    const uint8_t *data,
    size_t len,
    OSType desired_pixfmt,
    uint8_t *dst_bgra,
    size_t dst_bgra_cap,
    int32_t *out_os_status
) {
    if (dec->output_pixfmt == 0u) {
        dec->output_pixfmt = desired_pixfmt;
    } else if (dec->output_pixfmt != desired_pixfmt) {
        return ZD_VT_ERR_INVALID_ARG;
    }

    ZdVtAnnexbParseResult parsed;
    int32_t parse_rc = zd_vt_parse_annexb(dec->codec_id, data, len, &parsed);
    if (parse_rc != ZD_VT_OK) {
        return parse_rc;
    }

    if (parsed.has_idr != 0u) {
        int32_t cfg_os = 0;
        int32_t cfg_rc = zd_vt_dec_configure_from_idr(dec, data, &parsed, &cfg_os);
        if (cfg_rc != ZD_VT_OK) {
            *out_os_status = cfg_os;
            return cfg_rc;
        }
    } else if (dec->session == NULL || dec->format_desc == NULL) {
        /* Non-IDR frame before any valid IDR parameter sets are active: fail-closed NEED_IDR. */
        return ZD_VT_ERR_NEED_IDR;
    }

    /* Convert VCL (non-parameter-set) NALs to 4-byte BE length-prefixed AVCC/HVCC. */
    size_t avcc_len = 0u;
    for (uint32_t i = 0u; i < parsed.nal_count; ++i) {
        const ZdVtAnnexbSlice *sl = &parsed.nals[i];
        if (!zd_vt_is_vcl_nal(dec->codec_id, sl->nal_type)) {
            continue;
        }
        if (sl->len > ZD_VT_MAX_AVCC_BYTES - 4u || avcc_len > ZD_VT_MAX_AVCC_BYTES - (4u + sl->len)) {
            return ZD_VT_ERR_SAFETY_CAP;
        }
        avcc_len += 4u + sl->len;
    }
    if (avcc_len == 0u) {
        return ZD_VT_ERR_NEED_IDR;
    }

    if (!zd_vt_buf_reserve(&dec->avcc_buf, &dec->avcc_cap, avcc_len, ZD_VT_MAX_AVCC_BYTES)) {
        return ZD_VT_ERR_ALLOC;
    }

    size_t off = 0u;
    for (uint32_t i = 0u; i < parsed.nal_count; ++i) {
        const ZdVtAnnexbSlice *sl = &parsed.nals[i];
        if (!zd_vt_is_vcl_nal(dec->codec_id, sl->nal_type)) {
            continue;
        }
        uint32_t nlen = (uint32_t)sl->len;
        dec->avcc_buf[off++] = (uint8_t)((nlen >> 24) & 0xFFu);
        dec->avcc_buf[off++] = (uint8_t)((nlen >> 16) & 0xFFu);
        dec->avcc_buf[off++] = (uint8_t)((nlen >> 8) & 0xFFu);
        dec->avcc_buf[off++] = (uint8_t)(nlen & 0xFFu);
        memcpy(dec->avcc_buf + off, data + sl->offset, sl->len);
        off += sl->len;
    }

    CMBlockBufferRef block = NULL;
    OSStatus st = CMBlockBufferCreateWithMemoryBlock(
        kCFAllocatorDefault,
        dec->avcc_buf,
        avcc_len,
        kCFAllocatorNull,
        NULL,
        0u,
        avcc_len,
        0u,
        &block
    );
    if (st != noErr || block == NULL) {
        *out_os_status = (int32_t)st;
        return ZD_VT_ERR_INTERNAL;
    }

    CMSampleBufferRef sample = NULL;
    const size_t sample_size = avcc_len;
    st = CMSampleBufferCreateReady(
        kCFAllocatorDefault,
        block,
        dec->format_desc,
        1,
        0,
        NULL,
        1,
        &sample_size,
        &sample
    );
    CFRelease(block);

    if (st != noErr || sample == NULL) {
        *out_os_status = (int32_t)st;
        return ZD_VT_ERR_INTERNAL;
    }

    dec->caller_bgra_dst = dst_bgra;
    dec->caller_bgra_cap = dst_bgra_cap;
    dec->out_bgra_ptr = NULL;
    dec->has_output = false;
    dec->out_status = ZD_VT_OK;
    dec->out_os_status = 0;
    dec->bgra_len = 0u;
    dec->out_width = 0u;
    dec->out_height = 0u;
    dec->out_stride = 0u;
    dec->out_uv_stride = 0u;

    VTDecodeInfoFlags info_flags = 0;
    OSStatus dec_st = VTDecompressionSessionDecodeFrame(
        dec->session,
        sample,
        0u, /* synchronous decodeFlags = 0 */
        NULL,
        &info_flags
    );
    CFRelease(sample);
    dec->caller_bgra_dst = NULL;
    dec->caller_bgra_cap = 0u;

    if ((info_flags & kVTDecodeInfo_Asynchronous) != 0u) {
        VTDecompressionSessionWaitForAsynchronousFrames(dec->session);
        *out_os_status = (int32_t)dec_st;
        return ZD_VT_ERR_DECODE_ASYNC;
    }

    if (dec_st != noErr) {
        *out_os_status = (int32_t)dec_st;
        return zd_vt_map_dec_osstatus(dec_st);
    }

    if (!dec->has_output) {
        return ZD_VT_ERR_NO_OUTPUT;
    }
    *out_os_status = dec->out_os_status;
    return dec->out_status;
}

int32_t zd_vt_dec_decode_annexb_into(
    ZdVtDecoder *dec,
    const uint8_t *data,
    size_t len,
    uint8_t *dst_bgra,
    size_t dst_bgra_cap,
    ZdVtDecodedBgraFrame *out_frame
) {
    if (dec == NULL || data == NULL || len == 0u || out_frame == NULL) {
        return ZD_VT_ERR_INVALID_ARG;
    }
    memset(out_frame, 0, sizeof(*out_frame));

    int32_t os_status = 0;
    int32_t rc = zd_vt_dec_decode_annexb_common(
        dec, data, len, kCVPixelFormatType_32BGRA, dst_bgra, dst_bgra_cap, &os_status
    );
    out_frame->os_status = os_status;
    if (rc != ZD_VT_OK) {
        return rc;
    }

    out_frame->data = dec->out_bgra_ptr;
    out_frame->len = dec->bgra_len;
    out_frame->width = dec->out_width;
    out_frame->height = dec->out_height;
    out_frame->stride = dec->out_stride;
    return ZD_VT_OK;
}

int32_t zd_vt_dec_decode_annexb(
    ZdVtDecoder *dec,
    const uint8_t *data,
    size_t len,
    ZdVtDecodedBgraFrame *out_frame
) {
    return zd_vt_dec_decode_annexb_into(dec, data, len, NULL, 0u, out_frame);
}

int32_t zd_vt_dec_decode_annexb_nv12(
    ZdVtDecoder *dec,
    const uint8_t *data,
    size_t len,
    ZdVtDecodedNv12Frame *out_frame
) {
    if (dec == NULL || data == NULL || len == 0u || out_frame == NULL) {
        return ZD_VT_ERR_INVALID_ARG;
    }
    memset(out_frame, 0, sizeof(*out_frame));

    int32_t os_status = 0;
    int32_t rc = zd_vt_dec_decode_annexb_common(
        dec, data, len, kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange, NULL, 0u, &os_status
    );
    out_frame->os_status = os_status;
    if (rc != ZD_VT_OK) {
        return rc;
    }

    out_frame->y_data = dec->nv12_y_buf;
    out_frame->uv_data = dec->nv12_uv_buf;
    out_frame->width = dec->out_width;
    out_frame->height = dec->out_height;
    out_frame->y_stride = dec->out_stride;
    out_frame->uv_stride = dec->out_uv_stride;
    return ZD_VT_OK;
}

void zd_vt_dec_destroy(ZdVtDecoder *dec) {
    if (dec == NULL) {
        return;
    }
    zd_vt_dec_release_session(dec);
    free(dec->active_ps_blob);
    dec->active_ps_blob = NULL;
    free(dec->avcc_buf);
    dec->avcc_buf = NULL;
    free(dec->bgra_buf);
    dec->bgra_buf = NULL;
    free(dec->nv12_y_buf);
    dec->nv12_y_buf = NULL;
    free(dec->nv12_uv_buf);
    dec->nv12_uv_buf = NULL;
    free(dec);
}

void zd_vt_dec_invalidate_session_for_test(ZdVtDecoder *dec) {
    if (dec != NULL && dec->session != NULL) {
        VTDecompressionSessionInvalidate(dec->session);
    }
}

/* ============================================================================
 * Real 64x64 Hardware Capability Probe (Silent, Zero TCC Prompts)
 * ========================================================================== */

static bool zd_vt_probe_one_codec(uint32_t codec_id) {
    const uint32_t w = 64u;
    const uint32_t h = 64u;
    uint8_t y_plane[64u * 64u];
    uint8_t uv_plane[64u * 32u];

    for (uint32_t r = 0u; r < h; ++r) {
        for (uint32_t c = 0u; c < w; ++c) {
            y_plane[r * w + c] = (uint8_t)(32u + ((r + c) & 0x7Fu));
        }
    }
    memset(uv_plane, 128, sizeof(uv_plane));

    ZdVtEncoderConfig cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.codec_id = codec_id;
    cfg.width = w;
    cfg.height = h;
    cfg.fps = 30u;
    cfg.bitrate_bps = 500000u;
    cfg.max_keyframe_interval = 60u;

    ZdVtEncoder *enc = NULL;
    if (zd_vt_enc_create(&cfg, &enc) != ZD_VT_OK) {
        return false;
    }

    ZdVtEncodedFrame encoded;
    int32_t enc_rc = zd_vt_enc_encode_nv12(enc, y_plane, w, uv_plane, w, w, h, 0, 1u, &encoded);
    if (enc_rc != ZD_VT_OK || encoded.data == NULL || encoded.len == 0u || encoded.is_idr == 0u) {
        zd_vt_enc_destroy(enc);
        return false;
    }

    ZdVtDecoder *dec = NULL;
    if (zd_vt_dec_create(codec_id, &dec) != ZD_VT_OK) {
        zd_vt_enc_destroy(enc);
        return false;
    }

    ZdVtDecodedBgraFrame decoded;
    int32_t dec_rc = zd_vt_dec_decode_annexb(dec, encoded.data, encoded.len, &decoded);
    bool ok = (dec_rc == ZD_VT_OK && decoded.width == w && decoded.height == h &&
               decoded.data != NULL && decoded.len == (size_t)w * (size_t)h * 4u);

    zd_vt_dec_destroy(dec);
    zd_vt_enc_destroy(enc);
    return ok;
}

uint32_t zd_vt_probe_capabilities(void) {
    uint32_t caps = 0u;
    if (zd_vt_probe_one_codec(ZD_VT_CODEC_H264)) {
        caps |= ZD_VT_CAP_H264;
    }
    if (zd_vt_probe_one_codec(ZD_VT_CODEC_HEVC)) {
        caps |= ZD_VT_CAP_HEVC;
    }
    return caps;
}
