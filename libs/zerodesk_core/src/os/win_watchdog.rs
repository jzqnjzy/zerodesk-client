// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(windows)]` HID watchdog supervisor using:
//! - `CreatePipe` with `SetHandleInformation` clearing `HANDLE_FLAG_INHERIT` on parent ends
//! - `STARTUPINFOEXW` + `InitializeProcThreadAttributeList` +
//!   `UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST)` +
//!   `CreateProcessW(..., EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, ...)` so ONLY
//!   the exact `[cmd_read, ack_write]` pipe handles are inherited (preventing grandchild
//!   handle leaks from blocking pipe EOF!)
//! - `GetProcessTimes` creation timestamp (`FILETIME` 100ns) passed to the watchdog for
//!   PID-reuse protection (`is_same_process_instance`)
//! - Session nonce transmitted strictly inside the `Hello` pipe frame (NEVER leaked in argv!).

#![cfg(windows)]

use super::{
    traits::{check_release_report, HidWatchdogBackend, InputPrivilegeStatus},
    watchdog_proto::{
        bitmap_clear_key, bitmap_set_key, WatchdogFrame, WatchdogMsgType, WATCHDOG_FRAME_LEN,
    },
    watchdog_supervisor::{HidGatePhase, HidWatchdogConfig, WATCHDOG_BIN_NAME},
    win_input::win_input_privilege_status,
    win_watchdog_logic::{quote_win_arg, ProcessIdentity, DEFAULT_WIN_HEARTBEAT_TIMEOUT_MS},
    EmergencyKeyReleaser, OsError, ReleaseReport,
};
use rand_core::{OsRng, RngCore};
use std::{
    ffi::OsStr,
    mem::size_of,
    num::NonZeroU32,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::Mutex,
    time::{Duration, Instant},
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CloseHandle, SetHandleInformation, BOOL, FILETIME, HANDLE, HANDLE_FLAGS,
            HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
        },
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{ReadFile, WriteFile},
        System::{
            Pipes::{CreatePipe, PeekNamedPipe},
            Threading::{
                CreateProcessW, DeleteProcThreadAttributeList, GetCurrentProcess, GetProcessTimes,
                InitializeProcThreadAttributeList, TerminateProcess, UpdateProcThreadAttribute,
                WaitForSingleObject, CREATE_NO_WINDOW, EXTENDED_STARTUPINFO_PRESENT,
                LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST, STARTUPINFOEXW,
            },
        },
    },
};

const WIN_WATCHDOG_PIPE_BUF_SIZE: u32 = 4096;

/// Queries a process handle's creation timestamp (`FILETIME` in 100-ns units)
/// via `GetProcessTimes` for PID-reuse validation.
pub fn query_process_creation_time(process_handle: HANDLE) -> Result<u64, OsError> {
    let mut creation = FILETIME::default();
    let mut exit_t = FILETIME::default();
    let mut kernel_t = FILETIME::default();
    let mut user_t = FILETIME::default();
    unsafe {
        GetProcessTimes(
            process_handle,
            &mut creation,
            &mut exit_t,
            &mut kernel_t,
            &mut user_t,
        )
    }
    .map_err(|e| OsError::CaptureFailed(format!("GetProcessTimes failed: {e}")))?;
    Ok((u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime))
}

/// Returns the current process's `(pid, creation_time_100ns)` identity.
pub fn current_process_identity() -> Result<ProcessIdentity, OsError> {
    let pid = std::process::id();
    let creation_time_100ns = query_process_creation_time(unsafe { GetCurrentProcess() })?;
    Ok(ProcessIdentity::new(pid, creation_time_100ns))
}

fn to_wide_nul(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

fn resolve_windows_watchdog_binary(explicit: Option<&Path>) -> Result<PathBuf, OsError> {
    let exe_name = format!("{WATCHDOG_BIN_NAME}.exe");
    let candidate = if let Some(p) = explicit {
        p.to_path_buf()
    } else {
        let exe = std::env::current_exe().map_err(|e| {
            OsError::CaptureFailed(format!("current_exe() failed locating watchdog: {e}"))
        })?;
        let parent = exe.parent().ok_or_else(|| {
            OsError::CaptureFailed("current_exe() has no parent directory".into())
        })?;
        let sibling = parent.join(&exe_name);
        if sibling.is_file() {
            sibling
        } else if parent.file_name().and_then(|n| n.to_str()) == Some("deps") {
            parent
                .parent()
                .map(|p| p.join(&exe_name))
                .unwrap_or(sibling)
        } else {
            sibling
        }
    };
    if !candidate.is_file() {
        return Err(OsError::CaptureFailed(format!(
            "Windows HID watchdog binary not found: {}",
            candidate.display()
        )));
    }
    Ok(candidate)
}

/// RAII wrapper around a Win32 `HANDLE` that closes it automatically on Drop.
struct OwnedHandle(HANDLE);

// SAFETY: Win32 kernel pipe/process handles are process-global and safe to transfer across threads.
unsafe impl Send for OwnedHandle {}

impl OwnedHandle {
    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() && self.0 .0 != 0 {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn create_inheritable_pipe() -> Result<(OwnedHandle, OwnedHandle), OsError> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: ptr::null_mut(),
        bInheritHandle: BOOL(1),
    };
    let mut read_h = HANDLE::default();
    let mut write_h = HANDLE::default();
    unsafe { CreatePipe(&mut read_h, &mut write_h, Some(&sa), WIN_WATCHDOG_PIPE_BUF_SIZE) }
        .map_err(|e| OsError::CaptureFailed(format!("CreatePipe failed: {e}")))?;
    Ok((OwnedHandle(read_h), OwnedHandle(write_h)))
}

fn clear_handle_inherit(handle: HANDLE) -> Result<(), OsError> {
    unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
        .map_err(|e| OsError::CaptureFailed(format!("SetHandleInformation failed: {e}")))
}

/// Checks pipe buffer occupancy via `PeekNamedPipe` before `WriteFile` so a
/// stalled watchdog cannot deadlock the host input thread under lock.
fn ensure_pipe_headroom(handle: HANDLE, needed: usize) -> Result<(), OsError> {
    let mut queued = 0u32;
    if unsafe { PeekNamedPipe(handle, None, 0, None, Some(&mut queued), None) }.is_ok() {
        let free = (WIN_WATCHDOG_PIPE_BUF_SIZE as usize).saturating_sub(queued as usize);
        if free < needed {
            return Err(OsError::CaptureFailed(format!(
                "watchdog pipe buffer saturated (queued={queued}, free={free}, needed={needed})"
            )));
        }
    }
    Ok(())
}

fn write_exact_handle(handle: HANDLE, bytes: &[u8]) -> Result<(), OsError> {
    ensure_pipe_headroom(handle, bytes.len())?;
    let mut written_total = 0usize;
    while written_total < bytes.len() {
        let mut written = 0u32;
        unsafe { WriteFile(handle, Some(&bytes[written_total..]), Some(&mut written), None) }
            .map_err(|e| OsError::CaptureFailed(format!("WriteFile(watchdog pipe) failed: {e}")))?;
        if written == 0 {
            return Err(OsError::CaptureFailed(
                "WriteFile(watchdog pipe) wrote 0 bytes".into(),
            ));
        }
        written_total += written as usize;
    }
    Ok(())
}

fn read_ready_frame_bounded(ack_read: HANDLE, timeout: Duration) -> Result<u8, OsError> {
    let deadline = Instant::now() + timeout;
    let mut buf = [0u8; WATCHDOG_FRAME_LEN];
    let mut filled = 0usize;

    while filled < WATCHDOG_FRAME_LEN {
        if Instant::now() >= deadline {
            return Err(OsError::Timeout);
        }
        let mut avail = 0u32;
        if unsafe { PeekNamedPipe(ack_read, None, 0, None, Some(&mut avail), None) }.is_err() {
            return Err(OsError::CaptureFailed(
                "watchdog closed ack pipe before sending Ready".into(),
            ));
        }
        if avail == 0 {
            std::thread::sleep(Duration::from_millis(5));
            continue;
        }
        let to_read = (WATCHDOG_FRAME_LEN - filled).min(avail as usize);
        let mut read_now = 0u32;
        unsafe {
            ReadFile(
                ack_read,
                Some(&mut buf[filled..filled + to_read]),
                Some(&mut read_now),
                None,
            )
        }
        .map_err(|e| OsError::CaptureFailed(format!("ReadFile(ack pipe) failed: {e}")))?;
        if read_now == 0 {
            return Err(OsError::CaptureFailed(
                "EOF reading Ready frame from Windows watchdog".into(),
            ));
        }
        filled += read_now as usize;
    }

    let frame = WatchdogFrame::decode(&buf)
        .map_err(|e| OsError::InvalidData(format!("invalid Ready frame from watchdog: {e}")))?;
    if frame.msg_type != WatchdogMsgType::Ready {
        return Err(OsError::InvalidData(format!(
            "expected Ready frame from watchdog, got {:?}",
            frame.msg_type
        )));
    }
    Ok(frame.flags)
}

/// Spawns `bin_path` with `STARTUPINFOEXW` + `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`
/// so ONLY `inherited_handles` (strictly `[cmd_read, ack_write]`) are inherited.
fn spawn_with_explicit_handle_list(
    bin_path: &Path,
    args: &[String],
    inherited_handles: &mut [HANDLE],
) -> Result<(OwnedHandle, NonZeroU32), OsError> {
    let mut attr_size: usize = 0;
    let _ = unsafe {
        InitializeProcThreadAttributeList(
            LPPROC_THREAD_ATTRIBUTE_LIST(ptr::null_mut()),
            1,
            0,
            &mut attr_size,
        )
    };
    if attr_size == 0 {
        return Err(OsError::CaptureFailed(
            "InitializeProcThreadAttributeList returned size 0".into(),
        ));
    }

    let word_count = attr_size.div_ceil(size_of::<u64>());
    let mut attr_buf = vec![0u64; word_count];
    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr().cast());
    unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) }.map_err(|e| {
        OsError::CaptureFailed(format!("InitializeProcThreadAttributeList failed: {e}"))
    })?;

    struct AttrListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
    impl Drop for AttrListGuard {
        fn drop(&mut self) {
            unsafe { DeleteProcThreadAttributeList(self.0) };
        }
    }
    let _attr_guard = AttrListGuard(attr_list);

    unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            Some(inherited_handles.as_ptr().cast()),
            std::mem::size_of_val(inherited_handles),
            None,
            None,
        )
    }
    .map_err(|e| {
        OsError::CaptureFailed(format!(
            "UpdateProcThreadAttribute(PROC_THREAD_ATTRIBUTE_HANDLE_LIST) failed: {e}"
        ))
    })?;

    let mut startup: STARTUPINFOEXW = unsafe { std::mem::zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attr_list;

    let mut cmd_line = quote_win_arg(&bin_path.to_string_lossy());
    for a in args {
        cmd_line.push(' ');
        cmd_line.push_str(&quote_win_arg(a));
    }
    let app_wide = to_wide_nul(bin_path.as_os_str());
    let mut cmd_wide = to_wide_nul(OsStr::new(&cmd_line));
    let mut proc_info = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            PCWSTR(app_wide.as_ptr()),
            PWSTR(cmd_wide.as_mut_ptr()),
            None,
            None,
            true,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW,
            None,
            PCWSTR::null(),
            &startup.StartupInfo,
            &mut proc_info,
        )
    }
    .map_err(|e| {
        OsError::CaptureFailed(format!(
            "CreateProcessW({}) with PROC_THREAD_ATTRIBUTE_HANDLE_LIST failed: {e}",
            bin_path.display()
        ))
    })?;

    if !proc_info.hThread.is_invalid() && proc_info.hThread.0 != 0 {
        unsafe {
            let _ = CloseHandle(proc_info.hThread);
        }
    }
    let proc_handle = OwnedHandle(proc_info.hProcess);
    let pid = NonZeroU32::new(proc_info.dwProcessId).ok_or_else(|| {
        OsError::CaptureFailed("CreateProcessW returned invalid PID 0".into())
    })?;
    Ok((proc_handle, pid))
}

struct WinGateState {
    phase: HidGatePhase,
    keys_bitmap: [u8; 32],
    buttons: u8,
    mods: u8,
    dirty: bool,
    next_seq: u64,
    cmd_write: Option<OwnedHandle>,
}

impl WinGateState {
    fn close_on_write_failure(&mut self) {
        self.phase = HidGatePhase::Closed;
        self.cmd_write = None;
    }
}

/// Windows supervisor for `zerodesk-hid-watchdog.exe` enforcing strict handle
/// inheritance isolation (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) and PID creation-time
/// binding (`GetProcessTimes`).
pub struct WinHidWatchdogSupervisor {
    gate: Mutex<WinGateState>,
    child_process: Mutex<Option<(OwnedHandle, NonZeroU32)>>,
    ack_read: Mutex<Option<OwnedHandle>>,
    shutdown_timeout: Duration,
}

impl WinHidWatchdogSupervisor {
    pub fn spawn(cfg: HidWatchdogConfig) -> Result<Self, OsError> {
        let bin_path = resolve_windows_watchdog_binary(cfg.binary_path.as_deref())?;
        let host_identity = current_process_identity()?;

        let (cmd_read, cmd_write) = create_inheritable_pipe()?;
        let (ack_read, ack_write) = create_inheritable_pipe()?;

        // Only child ends may be inherited; clear inherit flag on parent ends!
        clear_handle_inherit(cmd_write.raw())?;
        clear_handle_inherit(ack_read.raw())?;

        // Nonce travels strictly inside the `Hello` pipe frame (NEVER exposed in process argv!).
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);

        let mut args = vec![
            "--parent-pid".to_string(),
            host_identity.pid.to_string(),
            "--parent-creation-time".to_string(),
            host_identity.creation_time_100ns.to_string(),
            "--cmd-handle".to_string(),
            (cmd_read.raw().0 as usize).to_string(),
            "--ack-handle".to_string(),
            (ack_write.raw().0 as usize).to_string(),
            "--heartbeat-timeout-ms".to_string(),
            DEFAULT_WIN_HEARTBEAT_TIMEOUT_MS.to_string(),
        ];
        if let Some(report) = &cfg.dry_run_report_path {
            args.push("--dry-run-journal".to_string());
            args.push(report.to_string_lossy().into_owned());
        }
        if cfg.real_os_input {
            args.push("--real-os-input".to_string());
        }

        let mut inherited = [cmd_read.raw(), ack_write.raw()];
        let (child_handle, child_pid) =
            spawn_with_explicit_handle_list(&bin_path, &args, &mut inherited)?;

        // Immediately close child ends in parent so EOF triggers cleanly if child dies.
        drop(cmd_read);
        drop(ack_write);

        let sup = Self {
            gate: Mutex::new(WinGateState {
                phase: HidGatePhase::Open,
                keys_bitmap: [0u8; 32],
                buttons: 0,
                mods: 0,
                dirty: false,
                next_seq: 0,
                cmd_write: Some(cmd_write),
            }),
            child_process: Mutex::new(Some((child_handle, child_pid))),
            ack_read: Mutex::new(Some(ack_read)),
            shutdown_timeout: cfg.shutdown_timeout,
        };

        let hello = WatchdogFrame::hello(host_identity.pid, nonce).encode();
        {
            let mut g = sup.gate.lock().unwrap_or_else(|e| e.into_inner());
            let Some(raw_h) = g.cmd_write.as_ref().map(OwnedHandle::raw) else {
                return Err(OsError::Interlocked);
            };
            if let Err(e) = write_exact_handle(raw_h, &hello) {
                g.close_on_write_failure();
                drop(g);
                sup.force_terminate();
                return Err(e);
            }
        }

        let ack_raw = {
            let g = sup.ack_read.lock().unwrap_or_else(|e| e.into_inner());
            g.as_ref().map(OwnedHandle::raw)
        };
        let Some(ack_h) = ack_raw else {
            sup.force_terminate();
            return Err(OsError::Interlocked);
        };
        if let Err(e) = read_ready_frame_bounded(ack_h, cfg.handshake_timeout) {
            sup.force_terminate();
            return Err(e);
        }

        Ok(sup)
    }

    pub fn child_pid(&self) -> Option<NonZeroU32> {
        self.child_process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|(_, pid)| *pid)
    }

    pub fn is_open(&self) -> bool {
        self.gate.lock().unwrap_or_else(|e| e.into_inner()).phase == HidGatePhase::Open
    }

    /// Sends a live `StateSnapshot` heartbeat carrying the current pressed bitmap so
    /// the watchdog knows the host event loop is responsive.
    pub fn send_heartbeat(&self) -> Result<(), OsError> {
        let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if g.phase != HidGatePhase::Open {
            return Err(OsError::Interlocked);
        }
        let Some(raw_h) = g.cmd_write.as_ref().map(OwnedHandle::raw) else {
            g.close_on_write_failure();
            return Err(OsError::Interlocked);
        };
        let next_seq = g.next_seq.saturating_add(1);
        let frame = WatchdogFrame::state_snapshot(next_seq, g.keys_bitmap, g.buttons, g.mods)
            .encode();
        if let Err(e) = write_exact_handle(raw_h, &frame) {
            g.close_on_write_failure();
            return Err(e);
        }
        g.next_seq = next_seq;
        Ok(())
    }

    pub fn before_key_down(&self, usage: u16, modifiers: u8) -> Result<(), OsError> {
        let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if g.phase != HidGatePhase::Open {
            return Err(OsError::Interlocked);
        }
        let Some(raw_h) = g.cmd_write.as_ref().map(OwnedHandle::raw) else {
            g.close_on_write_failure();
            return Err(OsError::Interlocked);
        };
        let mut next_bm = g.keys_bitmap;
        bitmap_set_key(&mut next_bm, usage);
        let next_seq = g.next_seq.saturating_add(1);
        let frame = WatchdogFrame::state_snapshot(next_seq, next_bm, g.buttons, modifiers).encode();
        if let Err(e) = write_exact_handle(raw_h, &frame) {
            g.close_on_write_failure();
            return Err(e);
        }
        g.keys_bitmap = next_bm;
        g.mods = modifiers;
        g.dirty = true;
        g.next_seq = next_seq;
        Ok(())
    }

    pub fn after_key_up(&self, usage: u16, modifiers: u8) -> Result<(), OsError> {
        let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if g.phase != HidGatePhase::Open {
            return Ok(());
        }
        let Some(raw_h) = g.cmd_write.as_ref().map(OwnedHandle::raw) else {
            g.close_on_write_failure();
            return Ok(());
        };
        bitmap_clear_key(&mut g.keys_bitmap, usage);
        g.mods = modifiers;
        g.dirty = g.keys_bitmap.iter().any(|&b| b != 0) || g.buttons != 0;
        let next_seq = g.next_seq.saturating_add(1);
        let frame =
            WatchdogFrame::state_snapshot(next_seq, g.keys_bitmap, g.buttons, g.mods).encode();
        if let Err(e) = write_exact_handle(raw_h, &frame) {
            g.close_on_write_failure();
            return Err(e);
        }
        g.next_seq = next_seq;
        Ok(())
    }

    fn force_terminate(&self) {
        {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            g.close_on_write_failure();
        }
        *self.ack_read.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // Take child handle and drop MutexGuard BEFORE blocking Win32 WaitForSingleObject!
        let taken = self
            .child_process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some((proc_h, _)) = taken {
            unsafe {
                let _ = TerminateProcess(proc_h.raw(), 1);
                let _ = WaitForSingleObject(proc_h.raw(), 500);
            }
        }
    }

    pub fn shutdown(
        &self,
        local_releaser: Option<&dyn EmergencyKeyReleaser>,
    ) -> Option<ReleaseReport> {
        let (was_open, was_dirty) = {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            let open = g.phase == HidGatePhase::Open;
            let dirty = g.dirty;
            if open {
                g.phase = HidGatePhase::Quiescing;
            }
            (open, dirty)
        };
        let release_report = if was_open || was_dirty {
            local_releaser.map(EmergencyKeyReleaser::release_all_keys)
        } else {
            None
        };
        {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(h) = g.cmd_write.take() {
                if was_open {
                    g.next_seq = g.next_seq.saturating_add(1);
                    let exit_frame = WatchdogFrame::graceful_exit(g.next_seq).encode();
                    let _ = write_exact_handle(h.raw(), &exit_frame);
                }
                drop(h);
            }
            g.keys_bitmap = [0u8; 32];
            g.buttons = 0;
            g.mods = 0;
            g.dirty = false;
            g.phase = HidGatePhase::Closed;
        }
        *self.ack_read.lock().unwrap_or_else(|e| e.into_inner()) = None;

        // Take child handle and drop MutexGuard BEFORE blocking WaitForSingleObject!
        let taken = self
            .child_process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        if let Some((proc_h, _)) = taken {
            let wait_ms = self
                .shutdown_timeout
                .as_millis()
                .min(u32::MAX as u128) as u32;
            let wait_res = unsafe { WaitForSingleObject(proc_h.raw(), wait_ms) };
            if wait_res != WAIT_OBJECT_0 {
                unsafe {
                    let _ = TerminateProcess(proc_h.raw(), 1);
                    let _ = WaitForSingleObject(proc_h.raw(), 500);
                }
            }
        }
        release_report
    }
}

impl Drop for WinHidWatchdogSupervisor {
    fn drop(&mut self) {
        let _ = self.shutdown(None);
    }
}

/// Windows implementation of the cross-platform `HidWatchdogBackend` trait.
#[derive(Default)]
pub struct WinHidWatchdogBackend {
    supervisor: Option<WinHidWatchdogSupervisor>,
}

impl WinHidWatchdogBackend {
    pub fn new() -> Self {
        Self { supervisor: None }
    }
}

impl HidWatchdogBackend for WinHidWatchdogBackend {
    fn spawn(&mut self, cfg: HidWatchdogConfig) -> Result<Option<NonZeroU32>, OsError> {
        if let Some(old) = self.supervisor.take() {
            let _ = old.shutdown(None);
        }
        let sup = WinHidWatchdogSupervisor::spawn(cfg)?;
        let pid = sup.child_pid();
        self.supervisor = Some(sup);
        Ok(pid)
    }

    fn heartbeat(&self) -> Result<(), OsError> {
        let Some(sup) = &self.supervisor else {
            return Err(OsError::Interlocked);
        };
        sup.send_heartbeat()
    }

    fn release_all(
        &self,
        local_releaser: Option<&dyn EmergencyKeyReleaser>,
    ) -> Result<ReleaseReport, OsError> {
        let Some(releaser) = local_releaser else {
            return Err(OsError::InvalidData(
                "release_all requires a local EmergencyKeyReleaser".into(),
            ));
        };
        check_release_report(releaser.release_all_keys())
    }

    fn shutdown(
        &mut self,
        local_releaser: Option<&dyn EmergencyKeyReleaser>,
    ) -> Result<ReleaseReport, OsError> {
        let report = if let Some(sup) = self.supervisor.take() {
            sup.shutdown(local_releaser)
                .or_else(|| local_releaser.map(EmergencyKeyReleaser::release_all_keys))
        } else {
            local_releaser.map(EmergencyKeyReleaser::release_all_keys)
        };
        match report {
            Some(rep) => check_release_report(rep),
            None => Ok(ReleaseReport::default()),
        }
    }

    fn accessibility_or_uipi_status(&self) -> InputPrivilegeStatus {
        win_input_privilege_status()
    }
}
