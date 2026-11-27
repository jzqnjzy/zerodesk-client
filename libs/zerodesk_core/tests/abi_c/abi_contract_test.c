// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#include "zerodesk_v2.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* Compile-time strict C function-pointer signature verification against zerodesk_v2.h.
 * Compiled with -Wall -Wextra -Werror -std=c11 so ANY signature drift fails the build. */
static int verify_strict_signatures(void) {
    uint32_t (*fn_abi_version)(void) = zerodesk_v2_abi_version;
    int32_t (*fn_create)(uint64_t *) = zerodesk_v2_create;
    int32_t (*fn_destroy)(uint64_t) = zerodesk_v2_destroy;
    void (*fn_buffer_free)(ZeroDeskOwnedBuffer) = zerodesk_v2_buffer_free;
    int32_t (*fn_exec_json)(uint64_t, const uint8_t *, size_t, ZeroDeskOwnedBuffer *) =
        zerodesk_v2_exec_json;
    int32_t (*fn_snapshot_json)(uint64_t, ZeroDeskOwnedBuffer *) = zerodesk_v2_snapshot_json;
    int32_t (*fn_poll_event_json)(uint64_t, ZeroDeskOwnedBuffer *) = zerodesk_v2_poll_event_json;
    int32_t (*fn_poll_event_json_timeout)(uint64_t, uint32_t, ZeroDeskOwnedBuffer *) =
        zerodesk_v2_poll_event_json_timeout;
    int32_t (*fn_send_clipboard_png)(uint64_t, const uint8_t *, size_t, ZeroDeskOwnedBuffer *) =
        zerodesk_v2_send_clipboard_png;
    int32_t (*fn_send_file)(uint64_t, const uint8_t *, size_t, ZeroDeskOwnedBuffer *) =
        zerodesk_v2_send_file;
    int32_t (*fn_frame_info)(uint64_t, ZeroDeskFrameInfo *) = zerodesk_v2_frame_info;
    int32_t (*fn_take_latest_frame)(uint64_t, uint8_t *, size_t, ZeroDeskFrameInfo *) =
        zerodesk_v2_take_latest_frame;
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
    /* Freeing empty buffer must be a safe no-op */
    zerodesk_v2_buffer_free(buf);

    /* 3. Create live runtime handle */
    uint64_t handle = 0;
    CHECK(zerodesk_v2_create(&handle) == ZERODESK_OK, "create succeeded");
    CHECK(handle != 0, "handle is non-zero");

    /* 4. Snapshot JSON */
    CHECK(zerodesk_v2_snapshot_json(handle, &buf) == ZERODESK_OK, "snapshot_json succeeded");
    CHECK(buf_contains(buf, "\"state\":\"idle\""), "snapshot state is idle");
    zerodesk_v2_buffer_free(buf);

    /* 5. Invalid UTF-8 rejected with ZERODESK_ERR_INVALID_UTF8 */
    const uint8_t bad_utf8[3] = {0xFF, 0xFE, 0x80};
    CHECK(zerodesk_v2_exec_json(handle, bad_utf8, sizeof(bad_utf8), &buf) ==
              ZERODESK_ERR_INVALID_UTF8,
          "bad UTF-8 -> INVALID_UTF8");
    CHECK(zerodesk_v2_send_file(handle, bad_utf8, sizeof(bad_utf8), &buf) ==
              ZERODESK_ERR_INVALID_UTF8,
          "send_file bad UTF-8 -> INVALID_UTF8");

    /* 6. Embedded NUL byte is NOT silently truncated */
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

    /* 11. Frame info & take_latest_frame when empty -> ZERODESK_ERR_NO_FRAME */
    ZeroDeskFrameInfo finfo;
    memset(&finfo, 0, sizeof(finfo));
    CHECK(zerodesk_v2_frame_info(handle, &finfo) == ZERODESK_ERR_NO_FRAME,
          "frame_info empty -> NO_FRAME");
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
