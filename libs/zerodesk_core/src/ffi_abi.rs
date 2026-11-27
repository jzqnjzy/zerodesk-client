// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Stable C-ABI surface for `zerodesk_core`.
//!
//! Safety invariants:
//! - Monotonic `u64` handle table (`0` is always invalid; double-destroy / use-after-destroy
//!   return `ZERODESK_ERR_INVALID_HANDLE`, never UB).
//! - Every `extern "C"` entrypoint is wrapped in `catch_unwind` returning `ZERODESK_ERR_PANIC`.
//! - All input strings are `(ptr, len)` UTF-8 validated (never C-string NUL-truncated).
//! - All output buffers are owned `ZeroDeskOwnedBuffer` freed exclusively via `zerodesk_v2_buffer_free`.

use crate::{
    bridge::V2BridgeRuntime,
    frame::{FrameError, FrameInfo},
    os::os_selftest,
};
use std::{
    collections::HashMap,
    panic::{catch_unwind, AssertUnwindSafe},
    slice,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, LazyLock, Mutex,
    },
    time::Duration,
};

pub const ZERODESK_V2_ABI_VERSION: u32 = 1;

pub const ZERODESK_OK: i32 = 0;
pub const ZERODESK_ERR_INVALID_ARG: i32 = -1;
pub const ZERODESK_ERR_INVALID_HANDLE: i32 = -2;
pub const ZERODESK_ERR_INVALID_UTF8: i32 = -3;
pub const ZERODESK_ERR_BUFFER_TOO_SMALL: i32 = -4;
pub const ZERODESK_ERR_TIMEOUT: i32 = -5;
pub const ZERODESK_ERR_NO_EVENT: i32 = -6;
pub const ZERODESK_ERR_NO_FRAME: i32 = -7;
pub const ZERODESK_ERR_BUSY: i32 = -8;
pub const ZERODESK_ERR_INTERNAL: i32 = -9;
pub const ZERODESK_ERR_PANIC: i32 = -10;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ZeroDeskOwnedBuffer {
    pub ptr: *mut u8,
    pub len: usize,
    pub cap: usize,
}

impl ZeroDeskOwnedBuffer {
    pub fn empty() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            cap: 0,
        }
    }

    pub fn from_vec(mut v: Vec<u8>) -> Self {
        let ptr = v.as_mut_ptr();
        let len = v.len();
        let cap = v.capacity();
        std::mem::forget(v);
        Self { ptr, len, cap }
    }

    pub fn from_string(s: String) -> Self {
        Self::from_vec(s.into_bytes())
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ZeroDeskFrameInfo {
    pub seq: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: u32,
    pub byte_len: usize,
    pub pts_ms: u64,
    pub dropped_ui_frames: u64,
}

impl From<FrameInfo> for ZeroDeskFrameInfo {
    fn from(info: FrameInfo) -> Self {
        Self {
            seq: info.seq,
            width: info.width,
            height: info.height,
            stride: info.stride,
            pixel_format: info.pixel_format.as_u32(),
            byte_len: info.byte_len,
            pts_ms: info.pts_ms,
            dropped_ui_frames: info.dropped_ui_frames,
        }
    }
}

static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);
static HANDLE_TABLE: LazyLock<Mutex<HashMap<u64, Arc<V2BridgeRuntime>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

macro_rules! ffi_catch_unwind {
    ($body:expr) => {
        match catch_unwind(AssertUnwindSafe(|| $body)) {
            Ok(code) => code,
            Err(_) => ZERODESK_ERR_PANIC,
        }
    };
}

/// Rust-side helper to register an existing `Arc<V2BridgeRuntime>` into the global handle table.
pub fn register_runtime(rt: Arc<V2BridgeRuntime>) -> u64 {
    let id = NEXT_HANDLE.fetch_add(1, Ordering::AcqRel);
    HANDLE_TABLE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .insert(id, rt);
    id
}

/// Rust-side helper to inspect a handle's runtime without removing it.
pub fn lookup_runtime(handle: u64) -> Option<Arc<V2BridgeRuntime>> {
    if handle == 0 {
        return None;
    }
    HANDLE_TABLE
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&handle)
        .map(Arc::clone)
}

unsafe fn slice_from_raw_checked<'a>(ptr: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if ptr.is_null() {
        return Err(ZERODESK_ERR_INVALID_ARG);
    }
    Ok(slice::from_raw_parts(ptr, len))
}

unsafe fn utf8_from_raw_checked<'a>(ptr: *const u8, len: usize) -> Result<&'a str, i32> {
    let bytes = slice_from_raw_checked(ptr, len)?;
    std::str::from_utf8(bytes).map_err(|_| ZERODESK_ERR_INVALID_UTF8)
}

#[no_mangle]
pub extern "C" fn zerodesk_v2_abi_version() -> u32 {
    ZERODESK_V2_ABI_VERSION
}

/// # Safety
/// `out_handle` must be a valid, non-null, aligned writable pointer to `u64`.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_create(out_handle: *mut u64) -> i32 {
    ffi_catch_unwind!({
        if out_handle.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        let rt = match V2BridgeRuntime::new() {
            Ok(r) => Arc::new(r),
            Err(_) => return ZERODESK_ERR_INTERNAL,
        };
        let id = register_runtime(rt);
        *out_handle = id;
        ZERODESK_OK
    })
}

#[no_mangle]
pub extern "C" fn zerodesk_v2_destroy(handle: u64) -> i32 {
    ffi_catch_unwind!({
        if handle == 0 {
            return ZERODESK_ERR_INVALID_HANDLE;
        }
        let removed = HANDLE_TABLE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&handle);
        let Some(rt) = removed else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        rt.destroy();
        ZERODESK_OK
    })
}

/// # Safety
/// `buf` must either be empty/null or a `ZeroDeskOwnedBuffer` previously allocated by this library
/// and not yet freed.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_buffer_free(buf: ZeroDeskOwnedBuffer) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if !buf.ptr.is_null() && buf.cap > 0 {
            drop(Vec::from_raw_parts(buf.ptr, buf.len, buf.cap));
        }
    }));
}

/// # Safety
/// `cmd_ptr` must be valid for `cmd_len` bytes (when `cmd_len > 0`); `out_reply_json` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_exec_json(
    handle: u64,
    cmd_ptr: *const u8,
    cmd_len: usize,
    out_reply_json: *mut ZeroDeskOwnedBuffer,
) -> i32 {
    ffi_catch_unwind!({
        if out_reply_json.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        *out_reply_json = ZeroDeskOwnedBuffer::empty();
        let Some(rt) = lookup_runtime(handle) else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        let cmd_str = match utf8_from_raw_checked(cmd_ptr, cmd_len) {
            Ok(s) => s,
            Err(code) => return code,
        };
        let reply = rt.exec_json(cmd_str);
        *out_reply_json = ZeroDeskOwnedBuffer::from_string(reply);
        ZERODESK_OK
    })
}

/// # Safety
/// `out_snapshot_json` must be a valid, non-null writable pointer.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_snapshot_json(
    handle: u64,
    out_snapshot_json: *mut ZeroDeskOwnedBuffer,
) -> i32 {
    ffi_catch_unwind!({
        if out_snapshot_json.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        *out_snapshot_json = ZeroDeskOwnedBuffer::empty();
        let Some(rt) = lookup_runtime(handle) else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        let snap = rt.snapshot_json();
        *out_snapshot_json = ZeroDeskOwnedBuffer::from_string(snap);
        ZERODESK_OK
    })
}

/// # Safety
/// `out_event_json` must be a valid, non-null writable pointer.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_poll_event_json(
    handle: u64,
    out_event_json: *mut ZeroDeskOwnedBuffer,
) -> i32 {
    ffi_catch_unwind!({
        if out_event_json.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        *out_event_json = ZeroDeskOwnedBuffer::empty();
        let Some(rt) = lookup_runtime(handle) else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        match rt.poll_event_json() {
            Some(ev) => {
                *out_event_json = ZeroDeskOwnedBuffer::from_string(ev);
                ZERODESK_OK
            }
            None => ZERODESK_ERR_NO_EVENT,
        }
    })
}

/// # Safety
/// `out_event_json` must be a valid, non-null writable pointer.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_poll_event_json_timeout(
    handle: u64,
    timeout_ms: u32,
    out_event_json: *mut ZeroDeskOwnedBuffer,
) -> i32 {
    ffi_catch_unwind!({
        if out_event_json.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        *out_event_json = ZeroDeskOwnedBuffer::empty();
        let Some(rt) = lookup_runtime(handle) else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        let timeout = Duration::from_millis(timeout_ms as u64);
        match rt.poll_event_json_timeout(timeout) {
            Some(ev) => {
                *out_event_json = ZeroDeskOwnedBuffer::from_string(ev);
                ZERODESK_OK
            }
            None => ZERODESK_ERR_TIMEOUT,
        }
    })
}

/// # Safety
/// `data_ptr` must be valid for `data_len` bytes (when `data_len > 0`); `out_reply_json` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_send_clipboard_png(
    handle: u64,
    data_ptr: *const u8,
    data_len: usize,
    out_reply_json: *mut ZeroDeskOwnedBuffer,
) -> i32 {
    ffi_catch_unwind!({
        if out_reply_json.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        *out_reply_json = ZeroDeskOwnedBuffer::empty();
        let Some(rt) = lookup_runtime(handle) else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        let bytes = match slice_from_raw_checked(data_ptr, data_len) {
            Ok(b) => b,
            Err(code) => return code,
        };
        let reply = rt.send_clipboard_png(bytes);
        *out_reply_json = ZeroDeskOwnedBuffer::from_string(reply);
        ZERODESK_OK
    })
}

/// # Safety
/// `path_ptr` must be valid for `path_len` bytes (when `path_len > 0`); `out_reply_json` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_send_file(
    handle: u64,
    path_ptr: *const u8,
    path_len: usize,
    out_reply_json: *mut ZeroDeskOwnedBuffer,
) -> i32 {
    ffi_catch_unwind!({
        if out_reply_json.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        *out_reply_json = ZeroDeskOwnedBuffer::empty();
        let Some(rt) = lookup_runtime(handle) else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        let path_str = match utf8_from_raw_checked(path_ptr, path_len) {
            Ok(s) => s,
            Err(code) => return code,
        };
        let reply = rt.send_file_path(path_str);
        *out_reply_json = ZeroDeskOwnedBuffer::from_string(reply);
        ZERODESK_OK
    })
}

/// # Safety
/// `out_info` must be a valid, non-null writable pointer.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_frame_info(
    handle: u64,
    out_info: *mut ZeroDeskFrameInfo,
) -> i32 {
    ffi_catch_unwind!({
        if out_info.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        let Some(rt) = lookup_runtime(handle) else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        match rt.frame_info() {
            Ok(info) => {
                *out_info = info.into();
                ZERODESK_OK
            }
            Err(FrameError::NoFrame) => ZERODESK_ERR_NO_FRAME,
            Err(_) => ZERODESK_ERR_INTERNAL,
        }
    })
}

/// # Safety
/// `out_buf` must be writable for `out_cap` bytes (when `out_cap > 0`); `out_info` must be non-null.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_take_latest_frame(
    handle: u64,
    out_buf: *mut u8,
    out_cap: usize,
    out_info: *mut ZeroDeskFrameInfo,
) -> i32 {
    ffi_catch_unwind!({
        if out_info.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        if out_cap > 0 && out_buf.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        let Some(rt) = lookup_runtime(handle) else {
            return ZERODESK_ERR_INVALID_HANDLE;
        };
        let buf = if out_cap == 0 {
            &mut []
        } else {
            slice::from_raw_parts_mut(out_buf, out_cap)
        };
        match rt.take_latest_frame(buf) {
            Ok(info) => {
                *out_info = info.into();
                ZERODESK_OK
            }
            Err((FrameError::BufferTooSmall { .. }, Some(info))) => {
                *out_info = info.into();
                ZERODESK_ERR_BUFFER_TOO_SMALL
            }
            Err((FrameError::NoFrame, _)) => ZERODESK_ERR_NO_FRAME,
            Err(_) => ZERODESK_ERR_INTERNAL,
        }
    })
}

/// # Safety
/// `out_report_json` must be a valid, non-null writable pointer.
#[no_mangle]
pub unsafe extern "C" fn zerodesk_v2_os_selftest_json(
    out_report_json: *mut ZeroDeskOwnedBuffer,
) -> i32 {
    ffi_catch_unwind!({
        if out_report_json.is_null() {
            return ZERODESK_ERR_INVALID_ARG;
        }
        *out_report_json = ZeroDeskOwnedBuffer::empty();
        let report = os_selftest();
        match serde_json::to_string(&report) {
            Ok(s) => {
                *out_report_json = ZeroDeskOwnedBuffer::from_string(s);
                ZERODESK_OK
            }
            Err(_) => ZERODESK_ERR_INTERNAL,
        }
    })
}
