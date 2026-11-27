// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#ifndef ZERODESK_V2_H
#define ZERODESK_V2_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZERODESK_V2_ABI_VERSION 1u

#define ZERODESK_OK 0
#define ZERODESK_ERR_INVALID_ARG (-1)
#define ZERODESK_ERR_INVALID_HANDLE (-2)
#define ZERODESK_ERR_INVALID_UTF8 (-3)
#define ZERODESK_ERR_BUFFER_TOO_SMALL (-4)
#define ZERODESK_ERR_TIMEOUT (-5)
#define ZERODESK_ERR_NO_EVENT (-6)
#define ZERODESK_ERR_NO_FRAME (-7)
#define ZERODESK_ERR_BUSY (-8)
#define ZERODESK_ERR_INTERNAL (-9)
#define ZERODESK_ERR_PANIC (-10)

#define ZERODESK_PIXEL_FORMAT_BGRA8 1u
#define ZERODESK_PIXEL_FORMAT_RGBA8 2u

typedef struct ZeroDeskOwnedBuffer {
    uint8_t *ptr;
    size_t len;
    size_t cap;
} ZeroDeskOwnedBuffer;

typedef struct ZeroDeskFrameInfo {
    uint64_t seq;
    uint32_t width;
    uint32_t height;
    uint32_t stride;
    uint32_t pixel_format;
    size_t byte_len;
    uint64_t pts_ms;
    uint64_t dropped_ui_frames;
} ZeroDeskFrameInfo;

uint32_t zerodesk_v2_abi_version(void);
int32_t zerodesk_v2_create(uint64_t *out_handle);
int32_t zerodesk_v2_destroy(uint64_t handle);
void zerodesk_v2_buffer_free(ZeroDeskOwnedBuffer buf);

int32_t zerodesk_v2_exec_json(
    uint64_t handle,
    const uint8_t *cmd_ptr,
    size_t cmd_len,
    ZeroDeskOwnedBuffer *out_reply_json);

int32_t zerodesk_v2_snapshot_json(
    uint64_t handle,
    ZeroDeskOwnedBuffer *out_snapshot_json);

int32_t zerodesk_v2_poll_event_json(
    uint64_t handle,
    ZeroDeskOwnedBuffer *out_event_json);

int32_t zerodesk_v2_poll_event_json_timeout(
    uint64_t handle,
    uint32_t timeout_ms,
    ZeroDeskOwnedBuffer *out_event_json);

int32_t zerodesk_v2_send_clipboard_png(
    uint64_t handle,
    const uint8_t *data_ptr,
    size_t data_len,
    ZeroDeskOwnedBuffer *out_reply_json);

int32_t zerodesk_v2_send_file(
    uint64_t handle,
    const uint8_t *path_ptr,
    size_t path_len,
    ZeroDeskOwnedBuffer *out_reply_json);

int32_t zerodesk_v2_frame_info(
    uint64_t handle,
    ZeroDeskFrameInfo *out_info);

int32_t zerodesk_v2_take_latest_frame(
    uint64_t handle,
    uint8_t *out_buf,
    size_t out_cap,
    ZeroDeskFrameInfo *out_info);

int32_t zerodesk_v2_os_selftest_json(
    ZeroDeskOwnedBuffer *out_report_json);

#ifdef __cplusplus
}
#endif

#endif /* ZERODESK_V2_H */
