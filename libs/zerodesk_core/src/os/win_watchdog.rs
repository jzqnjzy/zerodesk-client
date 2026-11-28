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
//!   PID-reuse protection (`is_same_process_instance`).

use super::{
    traits::{HidWatchdogBackend, InputPrivilegeStatus},
    watchdog_proto::{
        bitmap_clear_key, bitmap_set_key, WatchdogFrame, WatchdogMsgType, WATCHDOG_FRAME_LEN,
    },
    watchdog_supervisor::{HidGatePhase, HidWatchdogConfig, WATCHDOG_BIN_NAME},
    win_input::win_input_privilege_status,
    win_watchdog_logic::{ProcessIdentity, DEFAULT_WIN_HEARTBEAT_TIMEOUT_MS},
    EmergencyKeyReleaser, OsError,
};
use rand_core::{OsRng, RngCore};
use std::{
    ffi::OsStr,
    mem::size_of,
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

fn quote_win_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
        } else if ch == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            backslashes = 0;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..(backslashes * 2) {
        out.push('\\');
    }
    out.push('"');
    out
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
    unsafe { CreatePipe(&mut read_h, &mut write_h, Some(&sa), 4096) }
        .map_err(|e| OsError::CaptureFailed(format!("CreatePipe failed: {e}")))?;
    Ok((OwnedHandle(read_h), OwnedHandle(write_h)))
}

fn clear_handle_inherit(handle: HANDLE) -> Result<(), OsError> {
    unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)) }
        .map_err(|e| OsError::CaptureFailed(format!("SetHandleInformation failed: {e}")))
}

fn write_exact_handle(handle: HANDLE, bytes: &[u8]) -> Result<(), OsError> {
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
) -> Result<(OwnedHandle, u32), OsError> {
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

    // Align buffer for LPPROC_THREAD_ATTRIBUTE_LIST via Vec<u64>.
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
    Ok((OwnedHandle(proc_info.hProcess), proc_info.dwProcessId))
}

struct WinGateState {
    phase: HidGatePhase,
    keys_bitmap: [u8; 32],
    buttons: u8,
    mods: u8,
    next_seq: u64,
    cmd_write: Option<OwnedHandle>,
}

/// Windows supervisor for `zerodesk-hid-watchdog.exe` enforcing strict handle
/// inheritance isolation (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`) and PID creation-time
/// binding (`GetProcessTimes`).
pub struct WinHidWatchdogSupervisor {
    gate: Mutex<WinGateState>,
    child_process: Mutex<Option<(OwnedHandle, u32)>>,
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

        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let nonce_hex = hex::encode(nonce);

        let mut args = vec![
            "--parent-pid".to_string(),
            host_identity.pid.to_string(),
            "--parent-creation-time".to_string(),
            host_identity.creation_time_100ns.to_string(),
            "--nonce-hex".to_string(),
            nonce_hex,
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
                next_seq: 0,
                cmd_write: Some(cmd_write),
            }),
            child_process: Mutex::new(Some((child_handle, child_pid))),
            ack_read: Mutex::new(Some(ack_read)),
            shutdown_timeout: cfg.shutdown_timeout,
        };

        let hello = WatchdogFrame::hello(host_identity.pid, nonce).encode();
        {
            let g = sup.gate.lock().unwrap_or_else(|e| e.into_inner());
            let Some(h) = g.cmd_write.as_ref() else {
                return Err(OsError::Interlocked);
            };
            if let Err(e) = write_exact_handle(h.raw(), &hello) {
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

    pub fn child_pid(&self) -> Option<u32> {
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
            g.phase = HidGatePhase::Closed;
            return Err(OsError::Interlocked);
        };
        g.next_seq = g.next_seq.saturating_add(1);
        let frame = WatchdogFrame::state_snapshot(g.next_seq, g.keys_bitmap, g.buttons, g.mods)
            .encode();
        if let Err(e) = write_exact_handle(raw_h, &frame) {
            g.phase = HidGatePhase::Closed;
            g.cmd_write = None;
            return Err(e);
        }
        Ok(())
    }

    pub fn before_key_down(&self, usage: u16, modifiers: u8) -> Result<(), OsError> {
        let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if g.phase != HidGatePhase::Open {
            return Err(OsError::Interlocked);
        }
        let Some(raw_h) = g.cmd_write.as_ref().map(OwnedHandle::raw) else {
            g.phase = HidGatePhase::Closed;
            return Err(OsError::Interlocked);
        };
        let mut next_bm = g.keys_bitmap;
        bitmap_set_key(&mut next_bm, usage);
        let next_seq = g.next_seq.saturating_add(1);
        let frame = WatchdogFrame::state_snapshot(next_seq, next_bm, g.buttons, modifiers).encode();
        write_exact_handle(raw_h, &frame)?;
        g.keys_bitmap = next_bm;
        g.mods = modifiers;
        g.next_seq = next_seq;
        Ok(())
    }

    pub fn after_key_up(&self, usage: u16, modifiers: u8) -> Result<(), OsError> {
        let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
        if g.phase != HidGatePhase::Open {
            return Ok(());
        }
        let Some(raw_h) = g.cmd_write.as_ref().map(OwnedHandle::raw) else {
            return Ok(());
        };
        bitmap_clear_key(&mut g.keys_bitmap, usage);
        g.mods = modifiers;
        g.next_seq = g.next_seq.saturating_add(1);
        let frame = WatchdogFrame::state_snapshot(g.next_seq, g.keys_bitmap, g.buttons, g.mods)
            .encode();
        let _ = write_exact_handle(raw_h, &frame);
        Ok(())
    }

    fn force_terminate(&self) {
        {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            g.phase = HidGatePhase::Closed;
            g.cmd_write = None;
        }
        *self.ack_read.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some((proc_h, _)) = self
            .child_process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            unsafe {
                let _ = TerminateProcess(proc_h.raw(), 1);
                let _ = WaitForSingleObject(proc_h.raw(), 500);
            }
        }
    }

    pub fn shutdown(&self, local_releaser: Option<&dyn EmergencyKeyReleaser>) {
        let was_open = {
            let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
            if g.phase == HidGatePhase::Open {
                g.phase = HidGatePhase::Quiescing;
                true
            } else {
                false
            }
        };
        if was_open {
            if let Some(releaser) = local_releaser {
                let _ = releaser.release_all_keys();
            }
        }
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
            g.phase = HidGatePhase::Closed;
        }
        *self.ack_read.lock().unwrap_or_else(|e| e.into_inner()) = None;
        if let Some((proc_h, _)) = self
            .child_process
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
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
    }
}

impl Drop for WinHidWatchdogSupervisor {
    fn drop(&mut self) {
        self.shutdown(None);
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
    fn spawn(&mut self, cfg: HidWatchdogConfig) -> Result<u32, OsError> {
        if let Some(old) = self.supervisor.take() {
            old.shutdown(None);
        }
        let sup = WinHidWatchdogSupervisor::spawn(cfg)?;
        let pid = sup.child_pid().unwrap_or(0);
        self.supervisor = Some(sup);
        Ok(pid)
    }

    fn heartbeat(&self) -> Result<(), OsError> {
        let Some(sup) = &self.supervisor else {
            return Err(OsError::Interlocked);
        };
        sup.send_heartbeat()
    }

    fn release_all(&self, local_releaser: Option<&dyn EmergencyKeyReleaser>) -> Result<(), OsError> {
        if let Some(releaser) = local_releaser {
            let _ = releaser.release_all_keys();
        }
        Ok(())
    }

    fn shutdown(&mut self, local_releaser: Option<&dyn EmergencyKeyReleaser>) {
        if let Some(sup) = self.supervisor.take() {
            sup.shutdown(local_releaser);
        }
    }

    fn accessibility_or_uipi_status(&self) -> InputPrivilegeStatus {
        win_input_privilege_status()
    }
}
