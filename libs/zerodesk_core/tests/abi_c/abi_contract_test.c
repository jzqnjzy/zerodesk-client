// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#include "zerodesk_v2.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Compile-time ABI layout & constant assertions (C11 _Static_assert). */
_Static_assert(ZERODESK_V2_ABI_VERSION == 1u, "ABI version must be 1");
_Static_assert(ZERODESK_OK == 0, "ZERODESK_OK == 0");
_Static_assert(ZERODESK_ERR_INVALID_ARG == -1, "ZERODESK_ERR_INVALID_ARG == -1");
_Static_assert(ZERODESK_ERR_INVALID_HANDLE == -2, "ZERODESK_ERR_INVALID_HANDLE == -2");
_Static_assert(ZERODESK_ERR_INVALID_UTF8 == -3, "ZERODESK_ERR_INVALID_UTF8 == -3");
_Static_assert(ZERODESK_ERR_BUFFER_TOO_SMALL == -4, "ZERODESK_ERR_BUFFER_TOO_SMALL == -4");
_Static_assert(ZERODESK_ERR_TIMEOUT == -5, "ZERODESK_ERR_TIMEOUT == -5");
_Static_assert(ZERODESK_ERR_NO_EVENT == -6, "ZERODESK_ERR_NO_EVENT == -6");
_Static_assert(ZERODESK_ERR_NO_FRAME == -7, "ZERODESK_ERR_NO_FRAME == -7");
_Static_assert(ZERODESK_ERR_BUSY == -8, "ZERODESK_ERR_BUSY == -8");
_Static_assert(ZERODESK_ERR_INTERNAL == -9, "ZERODESK_ERR_INTERNAL == -9");
_Static_assert(ZERODESK_ERR_PANIC == -10, "ZERODESK_ERR_PANIC == -10");
_Static_assert(ZERODESK_PIXEL_FORMAT_BGRA8 == 1u, "BGRA8 == 1");
_Static_assert(ZERODESK_PIXEL_FORMAT_RGBA8 == 2u, "RGBA8 == 2");

#if defined(__LP64__) || defined(_LP64)
_Static_assert(sizeof(ZeroDeskOwnedBuffer) == 24, "ZeroDeskOwnedBuffer LP64 size == 24");
_Static_assert(offsetof(ZeroDeskOwnedBuffer, ptr) == 0, "ZeroDeskOwnedBuffer.ptr offset");
_Static_assert(offsetof(ZeroDeskOwnedBuffer, len) == 8, "ZeroDeskOwnedBuffer.len offset");
_Static_assert(offsetof(ZeroDeskOwnedBuffer, cap) == 16, "ZeroDeskOwnedBuffer.cap offset");

_Static_assert(sizeof(ZeroDeskFrameInfo) == 48, "ZeroDeskFrameInfo LP64 size == 48");
_Static_assert(offsetof(ZeroDeskFrameInfo, seq) == 0, "ZeroDeskFrameInfo.seq offset");
_Static_assert(offsetof(ZeroDeskFrameInfo, width) == 8, "ZeroDeskFrameInfo.width offset");
_Static_assert(offsetof(ZeroDeskFrameInfo, height) == 12, "ZeroDeskFrameInfo.height offset");
_Static_assert(offsetof(ZeroDeskFrameInfo, stride) == 16, "ZeroDeskFrameInfo.stride offset");
_Static_assert(offsetof(ZeroDeskFrameInfo, pixel_format) == 20, "ZeroDeskFrameInfo.pixel_format offset");
_Static_assert(offsetof(ZeroDeskFrameInfo, byte_len) == 24, "ZeroDeskFrameInfo.byte_len offset");
_Static_assert(offsetof(ZeroDeskFrameInfo, pts_ms) == 32, "ZeroDeskFrameInfo.pts_ms offset");
_Static_assert(offsetof(ZeroDeskFrameInfo, dropped_ui_frames) == 40, "ZeroDeskFrameInfo.dropped_ui_frames offset");
#endif

typedef int32_t (*fn_frame_info_t)(uint64_t, ZeroDeskFrameInfo *);
typedef int32_t (*fn_take_latest_frame_t)(uint64_t, uint8_t *, size_t, ZeroDeskFrameInfo *);
typedef int32_t (*fn_poll_event_json_t)(uint64_t, ZeroDeskOwnedBuffer *);
typedef void (*fn_buffer_free_t)(ZeroDeskOwnedBuffer);

#define CHECK(cond, msg)                                                                           \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "C-ABI CONTRACT FAIL at line %d: %s\n", __LINE__, (msg));              \
            return 1;                                                                              \
        }                                                                                          \
    } while (0)

static int buf_contains(ZeroDeskOwnedBuffer buf, const char *needle) {
    size_t nlen = strlen(needle);
    if (buf.ptr == NULL || buf.len < nlen) {
        return 0;
    }
    for (size_t i = 0; i + nlen <= buf.len; ++i) {
        if (memcmp(buf.ptr + i, needle, nlen) == 0) {
            return 1;
        }
    }
    return 0;
}

/* C-side verification of populated FrameMailbox two-phase copy, 0-cap size query,
 * canary buffer zero-overwrite on ZERODESK_ERR_BUFFER_TOO_SMALL, exact pixel copy,
 * and on-demand VideoFrameReady synthesis. */
int zerodesk_c_verify_seeded_frame(
    uint64_t handle,
    uint32_t expected_w,
    uint32_t expected_h,
    uint32_t expected_stride,
    uint32_t expected_fmt,
    const uint8_t *expected_pixels,
    size_t expected_len,
    fn_frame_info_t fn_info,
    fn_take_latest_frame_t fn_take,
    fn_poll_event_json_t fn_poll,
    fn_buffer_free_t fn_free) {
    /* 1. frame_info query */
    ZeroDeskFrameInfo info;
    memset(&info, 0xCC, sizeof(info));
    CHECK(fn_info(handle, &info) == ZERODESK_OK, "seeded frame_info == OK");
    CHECK(info.seq >= 1, "seeded frame seq >= 1");
    CHECK(info.width == expected_w, "seeded width matches");
    CHECK(info.height == expected_h, "seeded height matches");
    CHECK(info.stride == expected_stride, "seeded stride matches");
    CHECK(info.pixel_format == expected_fmt, "seeded pixel_format matches");
    CHECK(info.byte_len == expected_len, "seeded byte_len matches");

    /* 2. out_cap == 0 size query -> ZERODESK_ERR_BUFFER_TOO_SMALL + required byte_len */
    ZeroDeskFrameInfo q_info;
    memset(&q_info, 0, sizeof(q_info));
    CHECK(fn_take(handle, NULL, 0, &q_info) == ZERODESK_ERR_BUFFER_TOO_SMALL,
          "out_cap==0 -> BUFFER_TOO_SMALL");
    CHECK(q_info.byte_len == expected_len, "out_cap==0 writes required byte_len");

    /* 3. small non-empty buffer filled with canary 0xAA -> ZERO bytes overwritten! */
    uint8_t small_canary[16];
    memset(small_canary, 0xAA, sizeof(small_canary));
    ZeroDeskFrameInfo s_info;
    memset(&s_info, 0, sizeof(s_info));
    CHECK(fn_take(handle, small_canary, sizeof(small_canary), &s_info) ==
              ZERODESK_ERR_BUFFER_TOO_SMALL,
          "small buf -> BUFFER_TOO_SMALL");
    CHECK(s_info.byte_len == expected_len, "small buf writes required byte_len");
    for (size_t i = 0; i < sizeof(small_canary); ++i) {
        CHECK(small_canary[i] == 0xAA, "small canary buffer untouched on BUFFER_TOO_SMALL");
    }

    /* 4. full-size buffer copy -> ZERODESK_OK + exact metadata & pixel match */
    uint8_t *full = (uint8_t *)calloc(1, expected_len);
    CHECK(full != NULL, "alloc full buffer");
    ZeroDeskFrameInfo f_info;
    memset(&f_info, 0, sizeof(f_info));
    int32_t rc = fn_take(handle, full, expected_len, &f_info);
    CHECK(rc == ZERODESK_OK, "full buf -> OK");
    CHECK(f_info.seq == info.seq, "copied seq matches");
    CHECK(f_info.stride == expected_stride, "copied stride matches");
    CHECK(f_info.byte_len == expected_len, "copied byte_len matches");
    CHECK(memcmp(full, expected_pixels, expected_len) == 0, "copied pixels match exactly");
    free(full);

    /* 5. On-demand VideoFrameReady synthesized via poll_event_json */
    ZeroDeskOwnedBuffer ev = {NULL, 0, 0};
    CHECK(fn_poll(handle, &ev) == ZERODESK_OK, "poll_event_json returns VideoFrameReady");
    CHECK(buf_contains(ev, "\"kind\":\"VideoFrameReady\""), "event kind is VideoFrameReady");
    fn_free(ev);

    return 0;
}

#ifndef ZERODESK_NO_MAIN
/* Compile-time strict C function-pointer signature verification against zerodesk_v2.h.
 * Compiled with -Wall -Wextra -Werror -std=c11 so ANY signature drift fails the build. */
static int verify_strict_signatures(void) {
    uint32_t (*fn_abi_version)(void) = zerodesk_v2_abi_version;
    int32_t (*fn_create)(uint64_t *) = zerodesk_v2_create;
    int32_t (*fn_destroy)(uint64_t) = zerodesk_v2_destroy;
    fn_buffer_free_t fn_buffer_free = zerodesk_v2_buffer_free;
    int32_t (*fn_exec_json)(uint64_t, const uint8_t *, size_t, ZeroDeskOwnedBuffer *) =
        zerodesk_v2_exec_json;
    int32_t (*fn_snapshot_json)(uint64_t, ZeroDeskOwnedBuffer *) = zerodesk_v2_snapshot_json;
    fn_poll_event_json_t fn_poll_event_json = zerodesk_v2_poll_event_json;
    int32_t (*fn_poll_event_json_timeout)(uint64_t, uint32_t, ZeroDeskOwnedBuffer *) =
        zerodesk_v2_poll_event_json_timeout;
    int32_t (*fn_send_clipboard_png)(uint64_t, const uint8_t *, size_t, ZeroDeskOwnedBuffer *) =
        zerodesk_v2_send_clipboard_png;
    int32_t (*fn_send_file)(uint64_t, const uint8_t *, size_t, ZeroDeskOwnedBuffer *) =
        zerodesk_v2_send_file;
    fn_frame_info_t fn_frame_info = zerodesk_v2_frame_info;
    fn_take_latest_frame_t fn_take_latest_frame = zerodesk_v2_take_latest_frame;
    int32_t (*fn_os_selftest_json)(ZeroDeskOwnedBuffer *) = zerodesk_v2_os_selftest_json;

    CHECK(fn_abi_version != NULL, "fn_abi_version non-null");
    CHECK(fn_create != NULL, "fn_create non-null");
    CHECK(fn_destroy != NULL, "fn_destroy non-null");
    CHECK(fn_buffer_free != NULL, "fn_buffer_free non-null");
    CHECK(fn_exec_json != NULL, "fn_exec_json non-null");
    CHECK(fn_snapshot_json != NULL, "fn_snapshot_json non-null");
    CHECK(fn_poll_event_json != NULL, "fn_poll_event_json non-null");
    CHECK(fn_poll_event_json_timeout != NULL, "fn_poll_event_json_timeout non-null");
    CHECK(fn_send_clipboard_png != NULL, "fn_send_clipboard_png non-null");
    CHECK(fn_send_file != NULL, "fn_send_file non-null");
    CHECK(fn_frame_info != NULL, "fn_frame_info non-null");
    CHECK(fn_take_latest_frame != NULL, "fn_take_latest_frame non-null");
    CHECK(fn_os_selftest_json != NULL, "fn_os_selftest_json non-null");
    return 0;
}

int main(void) {
    if (verify_strict_signatures() != 0) {
        return 1;
    }

    /* 1. ABI version */
    CHECK(zerodesk_v2_abi_version() == ZERODESK_V2_ABI_VERSION, "abi version == 1");

    /* 2. Null args and invalid handles */
    CHECK(zerodesk_v2_create(NULL) == ZERODESK_ERR_INVALID_ARG, "create(NULL) -> INVALID_ARG");
    CHECK(zerodesk_v2_destroy(0) == ZERODESK_ERR_INVALID_HANDLE, "destroy(0) -> INVALID_HANDLE");
    CHECK(zerodesk_v2_destroy(9999999ULL) == ZERODESK_ERR_INVALID_HANDLE,
          "destroy(bogus) -> INVALID_HANDLE");

    ZeroDeskOwnedBuffer buf = {NULL, 0, 0};
    CHECK(zerodesk_v2_snapshot_json(0, &buf) == ZERODESK_ERR_INVALID_HANDLE,
          "snapshot(0) -> INVALID_HANDLE");
    CHECK(zerodesk_v2_snapshot_json(123456ULL, &buf) == ZERODESK_ERR_INVALID_HANDLE,
          "snapshot(bogus) -> INVALID_HANDLE");
    zerodesk_v2_buffer_free(buf);

    /* 3. Create live runtime handle */
    uint64_t handle = 0;
    CHECK(zerodesk_v2_create(&handle) == ZERODESK_OK, "create succeeded");
    CHECK(handle != 0, "handle is non-zero");

    /* 4. Snapshot JSON */
    CHECK(zerodesk_v2_snapshot_json(handle, &buf) == ZERODESK_OK, "snapshot_json succeeded");
    CHECK(buf_contains(buf, "\"state\":\"idle\""), "snapshot state is idle");
    zerodesk_v2_buffer_free(buf);

    /* 5. Invalid UTF-8 & embedded NUL in send_file rejected at FFI boundary */
    const uint8_t bad_utf8[3] = {0xFF, 0xFE, 0x80};
    CHECK(zerodesk_v2_exec_json(handle, bad_utf8, sizeof(bad_utf8), &buf) ==
              ZERODESK_ERR_INVALID_UTF8,
          "bad UTF-8 -> INVALID_UTF8");
    CHECK(zerodesk_v2_send_file(handle, bad_utf8, sizeof(bad_utf8), &buf) ==
              ZERODESK_ERR_INVALID_UTF8,
          "send_file bad UTF-8 -> INVALID_UTF8");
    const uint8_t nul_path[] = "/tmp/a\0b.txt";
    CHECK(zerodesk_v2_send_file(handle, nul_path, sizeof(nul_path) - 1, &buf) ==
              ZERODESK_ERR_INVALID_ARG,
          "send_file embedded NUL -> INVALID_ARG");

    /* 6. Embedded NUL byte in exec_json is NOT silently truncated */
    const uint8_t nul_cmd[] = "{\"v\":1,\0\"cmd\":\"snapshot\"}";
    CHECK(zerodesk_v2_exec_json(handle, nul_cmd, sizeof(nul_cmd) - 1, &buf) == ZERODESK_OK,
          "embedded NUL returns structured JSON error");
    CHECK(buf_contains(buf, "\"ok\":false"), "embedded NUL rejected in JSON reply");
    zerodesk_v2_buffer_free(buf);

    /* 7. Garbage JSON never panics */
    const char *garbage = "{{{not valid json!!!";
    CHECK(zerodesk_v2_exec_json(handle, (const uint8_t *)garbage, strlen(garbage), &buf) ==
              ZERODESK_OK,
          "garbage JSON returns structured error JSON");
    CHECK(buf_contains(buf, "\"error_code\":\"InvalidJson\""), "garbage JSON -> InvalidJson");
    zerodesk_v2_buffer_free(buf);

    /* 8. Valid exec_json command (idempotent stop_host when idle) */
    const char *stop_cmd = "{\"v\":1,\"cmd\":\"stop_host\"}";
    CHECK(zerodesk_v2_exec_json(handle, (const uint8_t *)stop_cmd, strlen(stop_cmd), &buf) ==
              ZERODESK_OK,
          "exec_json stop_host succeeded");
    CHECK(buf_contains(buf, "\"already_stopped\":true"), "stop_host already_stopped:true");
    zerodesk_v2_buffer_free(buf);

    /* 9. Poll event empty + timeout */
    CHECK(zerodesk_v2_poll_event_json(handle, &buf) == ZERODESK_ERR_NO_EVENT,
          "empty poll -> NO_EVENT");
    CHECK(zerodesk_v2_poll_event_json_timeout(handle, 25, &buf) == ZERODESK_ERR_TIMEOUT,
          "empty poll timeout -> TIMEOUT");

    /* 10. Binary clipboard PNG rejects invalid header cleanly */
    const uint8_t bad_png[16] = {'N', 'O', 'T', '_', 'P', 'N', 'G', 0};
    CHECK(zerodesk_v2_send_clipboard_png(handle, bad_png, sizeof(bad_png), &buf) == ZERODESK_OK,
          "bad PNG returns structured JSON reply");
    CHECK(buf_contains(buf, "\"ok\":false"), "bad PNG rejected");
    zerodesk_v2_buffer_free(buf);

    /* 11. Frame info & take_latest_frame when empty -> ZERODESK_ERR_NO_FRAME & out_info zeroed */
    ZeroDeskFrameInfo finfo;
    memset(&finfo, 0xFF, sizeof(finfo));
    CHECK(zerodesk_v2_frame_info(handle, &finfo) == ZERODESK_ERR_NO_FRAME,
          "frame_info empty -> NO_FRAME");
    CHECK(finfo.seq == 0 && finfo.byte_len == 0, "frame_info zero-initialized on error");
    uint8_t dummy_buf[16];
    CHECK(zerodesk_v2_take_latest_frame(handle, dummy_buf, sizeof(dummy_buf), &finfo) ==
              ZERODESK_ERR_NO_FRAME,
          "take_latest_frame empty -> NO_FRAME");

    /* 12. Zero-write os_selftest JSON */
    CHECK(zerodesk_v2_os_selftest_json(&buf) == ZERODESK_OK, "os_selftest_json succeeded");
    CHECK(buf_contains(buf, "\"zero_writes_enforced\":true"),
          "os_selftest has zero_writes_enforced:true");
    zerodesk_v2_buffer_free(buf);

    /* 13. Destroy, double-destroy, and use-after-destroy */
    CHECK(zerodesk_v2_destroy(handle) == ZERODESK_OK, "destroy succeeded");
    CHECK(zerodesk_v2_destroy(handle) == ZERODESK_ERR_INVALID_HANDLE,
          "double destroy -> INVALID_HANDLE");
    CHECK(zerodesk_v2_snapshot_json(handle, &buf) == ZERODESK_ERR_INVALID_HANDLE,
          "use-after-destroy snapshot -> INVALID_HANDLE");
    CHECK(zerodesk_v2_exec_json(handle, (const uint8_t *)stop_cmd, strlen(stop_cmd), &buf) ==
              ZERODESK_ERR_INVALID_HANDLE,
          "use-after-destroy exec -> INVALID_HANDLE");

    return 0;
}
#endif
