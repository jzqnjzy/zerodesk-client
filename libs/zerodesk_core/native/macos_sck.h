// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#ifndef ZERODESK_MACOS_SCK_H
#define ZERODESK_MACOS_SCK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZD_SCK_OK                   0
#define ZD_SCK_ERR_INVALID_ARG     -1
#define ZD_SCK_ERR_PERMISSION      -2
#define ZD_SCK_ERR_NO_DISPLAY      -3
#define ZD_SCK_ERR_START_FAILED    -4
#define ZD_SCK_ERR_STOP_TIMEOUT    -5
#define ZD_SCK_ERR_ALREADY_RUNNING -6
#define ZD_SCK_ERR_INTERNAL        -7

typedef struct ZdSckHandle ZdSckHandle;

typedef struct ZdSckConfig {
    uint32_t width;              /* 0 = derive from display (capped <= 1920, rounded even) */
    uint32_t height;             /* 0 = derive from display (capped <= 1080, rounded even) */
    uint32_t fps;                /* target fps (clamped 1..=120; 0 -> 30) */
    uint32_t display_index;      /* 0 = primary shareable display */
    uint8_t  capture_audio;      /* non-zero to capture system audio (48kHz/2ch) */
    uint8_t  exclude_self_audio; /* non-zero to set excludesCurrentProcessAudio = YES */
    uint8_t  _reserved[2];
} ZdSckConfig;

typedef struct ZdSckAudioBuffer {
    const uint8_t* data;
    uint32_t byte_len;
    uint32_t channels;
} ZdSckAudioBuffer;

typedef void (*ZdSckVideoCallback)(
    void* user_ctx,
    const uint8_t* bgra_base,
    uint32_t width,
    uint32_t height,
    uint32_t bytes_per_row,
    float scale_factor,
    int64_t pts_us
);

typedef void (*ZdSckAudioCallback)(
    void* user_ctx,
    double sample_rate,
    uint32_t channels,
    uint32_t format_flags,
    uint32_t bits_per_channel,
    uint32_t num_buffers,
    const ZdSckAudioBuffer* buffers,
    int64_t pts_us
);

typedef void (*ZdSckErrorCallback)(
    void* user_ctx,
    int32_t error_code,
    const char* message
);

/* Non-interactive permission check using CGPreflightScreenCaptureAccess() ONLY.
 * Returns 1 if granted, 0 if denied. NEVER calls CGRequestScreenCaptureAccess(). */
int32_t zd_sck_preflight_permission(void);

ZdSckHandle* zd_sck_create(
    const ZdSckConfig* cfg,
    ZdSckVideoCallback video_cb,
    ZdSckAudioCallback audio_cb,
    ZdSckErrorCallback err_cb,
    void* user_ctx
);

/* Starts capture. Threading contract:
 * - May block up to ~6 seconds (shareable content discovery + stream start); MUST NOT be
 *   invoked on the main thread.
 * - Callbacks (video_cb, audio_cb, err_cb) MUST be non-blocking and MUST NEVER invoke any
 *   zd_sck_* function synchronously. */
int32_t zd_sck_start(ZdSckHandle* h);

/* Stops capture with bounded timeout (default 2000ms when timeout_ms == 0).
 * Threading contract:
 * - MUST NOT be invoked synchronously from inside any video/audio/error callback; returns
 *   ZD_SCK_ERR_INVALID_ARG if called re-entrantly from a callback thread/queue. */
int32_t zd_sck_stop(ZdSckHandle* h, uint32_t timeout_ms);

/* Stops (if needed), detaches delegate under lock, drains queues, and frees handle.
 * MUST NOT be invoked from inside any video/audio/error callback. */
void zd_sck_destroy(ZdSckHandle* h);

int32_t zd_sck_get_dimensions(
    const ZdSckHandle* h,
    uint32_t* out_width,
    uint32_t* out_height
);

#ifdef __cplusplus
}
#endif

#endif /* ZERODESK_MACOS_SCK_H */
