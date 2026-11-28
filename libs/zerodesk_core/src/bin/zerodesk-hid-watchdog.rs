// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `zerodesk-hid-watchdog` — Independent OS-level HID watchdog subprocess.
//!
//! Tracks the Host's held keys/buttons/modifiers via atomic 56-byte pipe snapshots and
//! unconditionally releases all held keys + all 8 standard modifiers + held mouse buttons
//! if the Host dies (including `SIGKILL` / `kill -9`, process-group `kill -9 -pgid`, leaked
//! pipe write-end fd via `kqueue EVFILT_PROC NOTE_EXIT`, malformed frame, or signal).

// Standalone binary does not link `src/platform/macos.mm`, which provides `BackingScaleFactor`
// for `scrap::quartz::Display::scale()`.
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn BackingScaleFactor(display: u32) -> f32 {
    use std::ffi::c_void;
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGDisplayPixelsWide(display: u32) -> usize;
        fn CGDisplayCopyDisplayMode(display: u32) -> *const c_void;
        fn CGDisplayModeGetPixelWidth(mode: *const c_void) -> usize;
        fn CGDisplayModeRelease(mode: *const c_void);
    }
    unsafe {
        let mode = CGDisplayCopyDisplayMode(display);
        if mode.is_null() {
            return 1.0;
        }
        let pixel_w = CGDisplayModeGetPixelWidth(mode);
        CGDisplayModeRelease(mode);
        let point_w = CGDisplayPixelsWide(display);
        if point_w == 0 || pixel_w == 0 {
            1.0
        } else {
            (pixel_w as f32 / point_w as f32).max(1.0)
        }
    }
}

#[cfg(unix)]
use std::{path::Path, time::Duration};
use std::{
    env,
    path::PathBuf,
    process::ExitCode,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use zerodesk_core::os::{
    input::RealInputPermit,
    watchdog_proto::{
        WatchdogFrame, WatchdogReleaseReport, ALL_MODIFIER_HID_USAGES, WATCHDOG_FRAME_LEN,
        WATCHDOG_READY_FLAG_REAL_OS_INPUT, WATCHDOG_RELEASED_FLAG_EMERGENCY_FAILED,
        WATCHDOG_RELEASED_FLAG_EMERGENCY_OK, WATCHDOG_RELEASED_FLAG_GRACEFUL,
        WATCHDOG_REPORT_SCHEMA_VERSION,
    },
};
#[cfg(unix)]
use zerodesk_core::os::{
    input::{emergency_release_real_os_keys, is_accessibility_trusted},
    watchdog_proto::{bitmap_collect_keys, WatchdogMsgType, WATCHDOG_READY_FLAG_AX_TRUSTED},
};

#[cfg(unix)]
struct WatchdogArgs {
    parent_pid: u32,
    nonce: [u8; 8],
    cmd_fd: i32,
    ack_fd: i32,
    lock_file: PathBuf,
    dry_run_journal: Option<PathBuf>,
    real_os_input: bool,
}

#[cfg(unix)]
fn parse_args(args: &[String]) -> Result<WatchdogArgs, String> {
    let mut parent_pid: Option<u32> = None;
    let mut nonce: Option<[u8; 8]> = None;
    let mut cmd_fd: i32 = 0;
    let mut ack_fd: Option<i32> = None;
    let mut lock_file: Option<PathBuf> = None;
    let mut dry_run_journal: Option<PathBuf> = None;
    let mut real_os_input = false;

    let mut i = 0usize;
    while i < args.len() {
        let flag = args[i].as_str();
        let next_val = |idx: &mut usize, name: &str| -> Result<String, String> {
            if *idx + 1 >= args.len() {
                return Err(format!("{name} requires a value"));
            }
            *idx += 2;
            Ok(args[*idx - 1].clone())
        };
        match flag {
            "--parent-pid" => {
                let raw = next_val(&mut i, "--parent-pid")?;
                let pid: u32 = raw
                    .parse()
                    .map_err(|_| format!("invalid --parent-pid: {raw}"))?;
                if pid == 0 {
                    return Err("--parent-pid must be > 0".into());
                }
                parent_pid = Some(pid);
            }
            "--nonce-hex" => {
                let raw = next_val(&mut i, "--nonce-hex")?;
                let bytes = hex::decode(&raw).map_err(|_| "invalid --nonce-hex".to_string())?;
                if bytes.len() != 8 {
                    return Err("--nonce-hex must be 16 hex chars (8 bytes)".into());
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                nonce = Some(arr);
            }
            "--cmd-fd" => {
                let raw = next_val(&mut i, "--cmd-fd")?;
                cmd_fd = raw.parse().map_err(|_| format!("invalid --cmd-fd: {raw}"))?;
                if cmd_fd < 0 {
                    return Err("--cmd-fd must be >= 0".into());
                }
            }
            "--ack-fd" => {
                let raw = next_val(&mut i, "--ack-fd")?;
                let fd: i32 = raw.parse().map_err(|_| format!("invalid --ack-fd: {raw}"))?;
                if fd < 0 {
                    return Err("--ack-fd must be >= 0".into());
                }
                ack_fd = Some(fd);
            }
            "--lock-file" => {
                let raw = next_val(&mut i, "--lock-file")?;
                if raw.is_empty() {
                    return Err("--lock-file must be non-empty".into());
                }
                lock_file = Some(PathBuf::from(raw));
            }
            "--dry-run-journal" => {
                let raw = next_val(&mut i, "--dry-run-journal")?;
                if raw.is_empty() {
                    return Err("--dry-run-journal must be non-empty".into());
                }
                dry_run_journal = Some(PathBuf::from(raw));
            }
            "--real-os-input" => {
                real_os_input = true;
                i += 1;
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }

    let ack_fd = ack_fd.ok_or_else(|| "missing --ack-fd".to_string())?;
    if cmd_fd == ack_fd {
        return Err("--cmd-fd and --ack-fd must be distinct descriptors".into());
    }
    if real_os_input && dry_run_journal.is_some() {
        return Err("--real-os-input cannot be combined with --dry-run-journal".into());
    }

    Ok(WatchdogArgs {
        parent_pid: parent_pid.ok_or_else(|| "missing --parent-pid".to_string())?,
        nonce: nonce.ok_or_else(|| "missing --nonce-hex".to_string())?,
        cmd_fd,
        ack_fd,
        lock_file: lock_file.ok_or_else(|| "missing --lock-file".to_string())?,
        dry_run_journal,
        real_os_input,
    })
}

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::{ffi::CString, fs, os::unix::ffi::OsStrExt};

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
    #[cfg(not(target_os = "linux"))]
    const MAX_CLOSE_FD_CAP: i32 = 16_384;

    #[derive(Default)]
    struct TrackedState {
        keys_bitmap: [u8; 32],
        buttons: u8,
        mods: u8,
        last_seq: u64,
    }

    enum DrainOutcome {
        Continue,
        GracefulExit(u64),
        EmergencyRelease(&'static str),
    }

    fn validate_pipe_fd(fd: i32, name: &str) -> Result<(), String> {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(fd, &mut st) } != 0 {
            return Err(format!(
                "fstat({name}={fd}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        if (st.st_mode & libc::S_IFMT) != libc::S_IFIFO {
            return Err(format!("{name}={fd} is not a pipe/FIFO (S_ISFIFO required)"));
        }
        Ok(())
    }

    #[cfg(not(target_os = "linux"))]
    fn max_open_fd_bound() -> i32 {
        let mut rl = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0
            && rl.rlim_cur != libc::RLIM_INFINITY
            && rl.rlim_cur > 0
        {
            (rl.rlim_cur.min(MAX_CLOSE_FD_CAP as u64) as i32).max(256)
        } else {
            4096
        }
    }

    fn set_nonblock(fd: i32) -> Result<(), String> {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return Err(format!("fcntl(F_GETFL) failed on fd {fd}"));
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(format!("fcntl(F_SETFL, O_NONBLOCK) failed on fd {fd}"));
            }
        }
        Ok(())
    }

    fn write_all_best_effort(fd: i32, data: &[u8]) {
        let mut written = 0usize;
        while written < data.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    data[written..].as_ptr() as *const libc::c_void,
                    data.len() - written,
                )
            };
            if n > 0 {
                written += n as usize;
            } else if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                break;
            } else {
                break;
            }
        }
    }

    /// Startup hardening: verify cmd_fd/ack_fd are distinct pipes, ignore SIGPIPE, redirect stdio
    /// (except cmd_fd/ack_fd) to `/dev/null`, detach session via `setsid()`, acquire exclusive
    /// non-blocking `flock` on lock file, and close all unneeded fds >= 3 up to `RLIMIT_NOFILE`
    /// (clamped to 16384). Runs BEFORE any AX/XPC framework calls so closing fds never disrupts them.
    fn harden_process_and_lock(
        cmd_fd: i32,
        ack_fd: i32,
        lock_file: &Path,
    ) -> Result<i32, String> {
        validate_pipe_fd(cmd_fd, "cmd_fd")?;
        validate_pipe_fd(ack_fd, "ack_fd")?;

        unsafe {
            libc::signal(libc::SIGPIPE, libc::SIG_IGN);
        }

        // Redirect standard fds 0/1/2 that are not cmd_fd/ack_fd to /dev/null.
        let devnull_c = CString::new("/dev/null").map_err(|_| "invalid /dev/null path")?;
        let devnull_fd = unsafe { libc::open(devnull_c.as_ptr(), libc::O_RDWR) };
        if devnull_fd >= 0 {
            for std_fd in 0..=2 {
                if std_fd != cmd_fd && std_fd != ack_fd && std_fd != devnull_fd {
                    unsafe {
                        libc::dup2(devnull_fd, std_fd);
                    }
                }
            }
            if devnull_fd > 2 && devnull_fd != cmd_fd && devnull_fd != ack_fd {
                unsafe {
                    libc::close(devnull_fd);
                }
            }
        }

        // Detach from parent's process group / controlling terminal so `kill -9 -pgid`
        // cannot terminate the watchdog before it releases held keys.
        unsafe {
            let _ = libc::setsid();
        }

        // Open per-session lock file with O_NOFOLLOW + 0600 and acquire non-blocking exclusive flock.
        let lock_c = CString::new(lock_file.as_os_str().as_bytes())
            .map_err(|_| "lock file path contains NUL")?;
        let lock_fd = unsafe {
            libc::open(
                lock_c.as_ptr(),
                libc::O_CREAT | libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if lock_fd < 0 {
            return Err(format!(
                "open lock file failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let rc = unsafe { libc::flock(lock_fd, libc::LOCK_EX | libc::LOCK_NB) };
        if rc != 0 {
            unsafe {
                libc::close(lock_fd);
            }
            return Err("lock file already held by another watchdog instance".into());
        }

        // Close all unneeded fds >= 3.
        // On Linux, audit `/proc/self/fd` directly to guarantee zero leaked descriptors
        // outside `[0, 1, 2, cmd_fd, ack_fd, lock_fd]`.
        #[cfg(target_os = "linux")]
        {
            let _ = zerodesk_core::os::linux_watchdog::audit_and_close_leaked_fds(&[
                0, 1, 2, cmd_fd, ack_fd, lock_fd,
            ]);
        }
        #[cfg(not(target_os = "linux"))]
        {
            let max_fd = max_open_fd_bound();
            for fd in 3..max_fd {
                if fd != cmd_fd && fd != ack_fd && fd != lock_fd {
                    unsafe {
                        libc::close(fd);
                    }
                }
            }
        }

        set_nonblock(cmd_fd)?;
        Ok(lock_fd)
    }

    /// Atomically writes the dry-run release report JSON with `0600` permissions and `O_NOFOLLOW`.
    fn write_report_atomic_0600(path: &Path, report: &WatchdogReleaseReport) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(report)
            .map_err(|e| format!("serialize release report: {e}"))?;
        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("watchdog-report.json");
        let tmp_name = format!(
            ".{file_name}.tmp.{}.{}",
            std::process::id(),
            now_epoch_ms()
        );
        let tmp_path = parent.join(tmp_name);
        let tmp_c = CString::new(tmp_path.as_os_str().as_bytes())
            .map_err(|_| "tmp report path contains NUL")?;
        let fd = unsafe {
            libc::open(
                tmp_c.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600 as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(format!(
                "open temp report failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut off = 0usize;
        let mut write_err: Option<String> = None;
        while off < json.len() {
            let n = unsafe {
                libc::write(
                    fd,
                    json[off..].as_ptr() as *const libc::c_void,
                    json.len() - off,
                )
            };
            if n > 0 {
                off += n as usize;
            } else if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                write_err = Some(format!("write temp report failed: {err}"));
                break;
            } else {
                write_err = Some("short write on temp report".into());
                break;
            }
        }
        if write_err.is_none() {
            unsafe {
                let _ = libc::fsync(fd);
            }
        }
        unsafe {
            libc::close(fd);
        }
        if let Some(e) = write_err {
            let _ = fs::remove_file(&tmp_path);
            return Err(e);
        }
        if let Err(e) = fs::rename(&tmp_path, path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(format!("rename report failed: {e}"));
        }
        Ok(())
    }

    /// Executes emergency release and returns `true` iff release completed with zero residuals
    /// and zero errors.
    fn execute_emergency_release(
        trigger: &str,
        args: &WatchdogArgs,
        state: &TrackedState,
        real_permit: Option<&RealInputPermit>,
    ) -> bool {
        let start = Instant::now();
        let released_keys = bitmap_collect_keys(&state.keys_bitmap);
        let released_modifiers = ALL_MODIFIER_HID_USAGES.to_vec();

        let (release_ok, release_error) = if let Some(permit) = real_permit {
            match emergency_release_real_os_keys(permit, &released_keys, state.buttons) {
                Ok(rep) if rep.residual_keys == 0 && rep.residual_buttons == 0 => (true, None),
                Ok(rep) => (
                    false,
                    Some(format!(
                        "residual unreleased HID state: keys={} buttons={}",
                        rep.residual_keys, rep.residual_buttons
                    )),
                ),
                Err(e) => (false, Some(e.to_string())),
            }
        } else {
            (true, None)
        };

        let mut overall_ok = release_ok;
        if let Some(report_path) = &args.dry_run_journal {
            let report = WatchdogReleaseReport {
                schema_version: WATCHDOG_REPORT_SCHEMA_VERSION,
                trigger: trigger.to_string(),
                parent_pid: args.parent_pid,
                watchdog_pid: std::process::id(),
                released_keys,
                released_buttons: state.buttons,
                released_modifiers,
                release_ok,
                release_error,
                release_elapsed_ms: start.elapsed().as_millis() as u64,
                timestamp_epoch_ms: now_epoch_ms(),
            };
            if write_report_atomic_0600(report_path, &report).is_err() {
                overall_ok = false;
            }
        }

        let ack_flag = if overall_ok {
            WATCHDOG_RELEASED_FLAG_EMERGENCY_OK
        } else {
            WATCHDOG_RELEASED_FLAG_EMERGENCY_FAILED
        };
        let ack = WatchdogFrame::released(state.last_seq, ack_flag).encode();
        write_all_best_effort(args.ack_fd, &ack);
        overall_ok
    }

    fn drain_cmd_frames(
        cmd_fd: i32,
        acc: &mut [u8; WATCHDOG_FRAME_LEN],
        acc_len: &mut usize,
        state: &mut TrackedState,
    ) -> DrainOutcome {
        loop {
            let n = unsafe {
                libc::read(
                    cmd_fd,
                    acc[*acc_len..].as_mut_ptr() as *mut libc::c_void,
                    WATCHDOG_FRAME_LEN - *acc_len,
                )
            };
            if n > 0 {
                *acc_len += n as usize;
                if *acc_len == WATCHDOG_FRAME_LEN {
                    *acc_len = 0;
                    let frame = match WatchdogFrame::decode(acc) {
                        Ok(f) => f,
                        Err(_) => return DrainOutcome::EmergencyRelease("malformed_frame"),
                    };
                    match frame.msg_type {
                        WatchdogMsgType::StateSnapshot => {
                            if frame.seq < state.last_seq {
                                return DrainOutcome::EmergencyRelease("malformed_frame");
                            }
                            state.last_seq = frame.seq;
                            state.keys_bitmap = frame.payload;
                            state.buttons = frame.buttons;
                            state.mods = frame.mods;
                        }
                        WatchdogMsgType::GracefulExit => {
                            state.keys_bitmap = [0u8; 32];
                            state.buttons = 0;
                            state.mods = 0;
                            return DrainOutcome::GracefulExit(frame.seq);
                        }
                        WatchdogMsgType::Hello
                        | WatchdogMsgType::Ready
                        | WatchdogMsgType::Released
                        | WatchdogMsgType::AxStatus => {
                            return DrainOutcome::EmergencyRelease("malformed_frame");
                        }
                    }
                }
            } else if n == 0 {
                if *acc_len > 0 {
                    return DrainOutcome::EmergencyRelease("malformed_frame");
                }
                return DrainOutcome::EmergencyRelease("pipe_eof");
            } else {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => return DrainOutcome::Continue,
                    _ => return DrainOutcome::EmergencyRelease("pipe_eof"),
                }
            }
        }
    }

    fn wait_for_hello(cmd_fd: i32, expected_pid: u32, expected_nonce: [u8; 8]) -> Result<(), String> {
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let mut buf = [0u8; WATCHDOG_FRAME_LEN];
        let mut filled = 0usize;

        while filled < WATCHDOG_FRAME_LEN {
            let rem = match deadline.checked_duration_since(Instant::now()) {
                Some(d) if !d.is_zero() => d,
                _ => return Err("handshake timed out waiting for Hello".into()),
            };
            let timeout_ms = rem.as_millis().min(i32::MAX as u128) as i32;
            let mut pfd = libc::pollfd {
                fd: cmd_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if prc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(format!("poll failed during handshake: {err}"));
            }
            if prc == 0 {
                return Err("handshake timed out waiting for Hello".into());
            }
            let n = unsafe {
                libc::read(
                    cmd_fd,
                    buf[filled..].as_mut_ptr() as *mut libc::c_void,
                    WATCHDOG_FRAME_LEN - filled,
                )
            };
            if n > 0 {
                filled += n as usize;
            } else if n == 0 {
                return Err("EOF before Hello frame".into());
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR)
                    || err.raw_os_error() == Some(libc::EAGAIN)
                {
                    continue;
                }
                return Err(format!("read failed during handshake: {err}"));
            }
        }

        let frame = WatchdogFrame::decode(&buf).map_err(|e| format!("bad Hello frame: {e}"))?;
        let Some((pid, nonce)) = frame.parse_hello() else {
            return Err("first frame was not a valid Hello".into());
        };
        if pid != expected_pid || nonce != expected_nonce {
            return Err("Hello pid/nonce mismatch".into());
        }
        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn run_event_loop(
        args: &WatchdogArgs,
        state: &mut TrackedState,
        real_permit: Option<&RealInputPermit>,
        ready_flags: u8,
    ) -> bool {
        // Arm SIG_IGN + kqueue + EVFILT_READ + EVFILT_PROC + EVFILT_SIGNAL BEFORE sending Ready
        // so the parent never injects keys until all crash-detection filters are live!
        unsafe {
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            libc::signal(libc::SIGINT, libc::SIG_IGN);
        }

        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            return false;
        }

        let make_ev = |ident: usize, filter: i16, flags: u16, fflags: u32| -> libc::kevent {
            libc::kevent {
                ident,
                filter,
                flags,
                fflags,
                data: 0,
                udata: std::ptr::null_mut(),
            }
        };

        let base_changes = [
            make_ev(
                args.cmd_fd as usize,
                libc::EVFILT_READ,
                libc::EV_ADD | libc::EV_ENABLE,
                0,
            ),
            make_ev(
                libc::SIGHUP as usize,
                libc::EVFILT_SIGNAL,
                libc::EV_ADD | libc::EV_ENABLE,
                0,
            ),
            make_ev(
                libc::SIGTERM as usize,
                libc::EVFILT_SIGNAL,
                libc::EV_ADD | libc::EV_ENABLE,
                0,
            ),
            make_ev(
                libc::SIGINT as usize,
                libc::EVFILT_SIGNAL,
                libc::EV_ADD | libc::EV_ENABLE,
                0,
            ),
        ];

        let reg_rc = unsafe {
            libc::kevent(
                kq,
                base_changes.as_ptr(),
                base_changes.len() as i32,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if reg_rc < 0 {
            unsafe {
                libc::close(kq);
            }
            return false;
        }

        let mut acc = [0u8; WATCHDOG_FRAME_LEN];
        let mut acc_len = 0usize;

        // Register EVFILT_PROC NOTE_EXIT BEFORE sending Ready. If parent already died (ESRCH),
        // exit cleanly without sending Ready (parent never received Ready, so no keys were injected).
        let proc_change = make_ev(
            args.parent_pid as usize,
            libc::EVFILT_PROC,
            libc::EV_ADD | libc::EV_ENABLE | libc::EV_ONESHOT,
            libc::NOTE_EXIT,
        );
        let proc_rc = unsafe {
            libc::kevent(
                kq,
                &proc_change,
                1,
                std::ptr::null_mut(),
                0,
                std::ptr::null(),
            )
        };
        if proc_rc < 0 {
            unsafe {
                libc::close(kq);
            }
            return false;
        }

        // All kqueue filters are now armed: announce Ready (with capability flags) to supervisor!
        let ready = WatchdogFrame::ready_with_flags(0, ready_flags).encode();
        write_all_best_effort(args.ack_fd, &ready);
        let _ = set_nonblock(args.ack_fd);

        let mut exit_ok = true;
        let mut events = [make_ev(0, 0, 0, 0); 16];
        let mut last_ax_report = Instant::now();
        let mut last_ax_trusted = (ready_flags & WATCHDOG_READY_FLAG_AX_TRUSTED) != 0;
        let poll_timeout = libc::timespec {
            tv_sec: 1,
            tv_nsec: 0,
        };
        loop {
            let n = unsafe {
                libc::kevent(
                    kq,
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    &poll_timeout,
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                exit_ok = execute_emergency_release("malformed_frame", args, state, real_permit);
                break;
            }

            if n == 0 || last_ax_report.elapsed() >= Duration::from_secs(1) {
                last_ax_report = Instant::now();
                let ax_now = is_accessibility_trusted();
                let flags = if ax_now {
                    WATCHDOG_READY_FLAG_AX_TRUSTED
                } else {
                    0
                };
                if ax_now != last_ax_trusted || n == 0 {
                    last_ax_trusted = ax_now;
                    let hb = WatchdogFrame::ax_status(state.last_seq, flags).encode();
                    write_all_best_effort(args.ack_fd, &hb);
                }
            }

            let mut saw_read = false;
            let mut saw_proc_exit = false;
            let mut saw_signal = false;

            for ev in &events[..(n as usize)] {
                match ev.filter {
                    libc::EVFILT_READ => saw_read = true,
                    libc::EVFILT_PROC => {
                        if (ev.fflags & libc::NOTE_EXIT) != 0 {
                            saw_proc_exit = true;
                        }
                    }
                    libc::EVFILT_SIGNAL => saw_signal = true,
                    _ => {}
                }
            }

            // Always drain cmd_fd BEFORE handling NOTE_EXIT so a GracefulExit queued right before
            // parent exit is never misclassified as a crash.
            if saw_read || saw_proc_exit {
                match drain_cmd_frames(args.cmd_fd, &mut acc, &mut acc_len, state) {
                    DrainOutcome::Continue => {}
                    DrainOutcome::GracefulExit(seq) => {
                        let ack = WatchdogFrame::released(seq, WATCHDOG_RELEASED_FLAG_GRACEFUL)
                            .encode();
                        write_all_best_effort(args.ack_fd, &ack);
                        break;
                    }
                    DrainOutcome::EmergencyRelease(trigger) => {
                        exit_ok = execute_emergency_release(trigger, args, state, real_permit);
                        break;
                    }
                }
            }

            if saw_proc_exit {
                exit_ok =
                    execute_emergency_release("parent_exit_kqueue", args, state, real_permit);
                break;
            }

            if saw_signal {
                exit_ok = execute_emergency_release("signal", args, state, real_permit);
                break;
            }
        }

        unsafe {
            libc::close(kq);
        }
        exit_ok
    }

    #[cfg(target_os = "linux")]
    fn run_event_loop(
        args: &WatchdogArgs,
        state: &mut TrackedState,
        real_permit: Option<&RealInputPermit>,
        ready_flags: u8,
    ) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};
        use zerodesk_core::os::{
            linux_watchdog::{
                arm_pdeathsig_and_verify_parent, execute_watchdog_linux_release,
                LinuxParentMonitor,
            },
            linux_watchdog_logic::{
                LinuxWatchdogAction, LinuxWatchdogLoopCore, DEFAULT_LINUX_HEARTBEAT_TIMEOUT_MS,
            },
        };

        static SIG_FIRED: AtomicBool = AtomicBool::new(false);
        extern "C" fn on_sig(_sig: libc::c_int) {
            SIG_FIRED.store(true, Ordering::Release);
        }

        // 1. Arm PR_SET_PDEATHSIG + immediately verify getppid() == args.parent_pid
        //    (defeats fork->prctl race if parent died right after spawn).
        let _ = arm_pdeathsig_and_verify_parent(args.parent_pid);

        unsafe {
            libc::signal(libc::SIGHUP, on_sig as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, on_sig as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, on_sig as *const () as libc::sighandler_t);
        }

        // 2. Attach race-free parent monitor (`pidfd_open` preferred; `/proc/<pid>/stat`
        //    field 22 starttime fallback on pre-5.3 kernels).
        let monitor = match LinuxParentMonitor::attach(args.parent_pid) {
            Ok(m) => m,
            Err(_) => {
                return execute_emergency_release("parent_exit_pidfd", args, state, real_permit);
            }
        };

        let ready = WatchdogFrame::ready_with_flags(0, ready_flags).encode();
        write_all_best_effort(args.ack_fd, &ready);

        let loop_start = Instant::now();
        let mut core = LinuxWatchdogLoopCore::new(0, DEFAULT_LINUX_HEARTBEAT_TIMEOUT_MS, false);
        let mut exit_ok = true;
        let mut acc = [0u8; WATCHDOG_FRAME_LEN];
        let mut acc_len = 0usize;

        let run_linux_release = |trigger: &'static str,
                                 steps: &[zerodesk_core::os::linux_watchdog_logic::LinuxReleaseStep],
                                 st: &TrackedState|
         -> bool {
            let mut ok = true;
            if real_permit.is_some() && execute_watchdog_linux_release(None, steps).is_err() {
                ok = false;
            }
            execute_emergency_release(trigger, args, st, None) && ok
        };

        loop {
            let mut poll_fds = [
                libc::pollfd {
                    fd: args.cmd_fd,
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: monitor.pidfd().unwrap_or(-1),
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];
            let nfds: libc::nfds_t = if monitor.pidfd().is_some() { 2 } else { 1 };
            let prc = unsafe { libc::poll(poll_fds.as_mut_ptr(), nfds, 100) };
            let elapsed_ms = loop_start.elapsed().as_millis() as u64;

            if prc > 0 && (poll_fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0
            {
                match drain_cmd_frames(args.cmd_fd, &mut acc, &mut acc_len, state) {
                    DrainOutcome::Continue => {
                        let snap = WatchdogFrame::state_snapshot(
                            state.last_seq,
                            state.keys_bitmap,
                            state.buttons,
                            state.mods,
                        );
                        if let LinuxWatchdogAction::EmergencyRelease { trigger, steps } =
                            core.on_frame(&snap, elapsed_ms)
                        {
                            exit_ok = run_linux_release(trigger, &steps, state);
                            break;
                        }
                    }
                    DrainOutcome::GracefulExit(seq) => {
                        let ack = WatchdogFrame::released(seq, WATCHDOG_RELEASED_FLAG_GRACEFUL)
                            .encode();
                        write_all_best_effort(args.ack_fd, &ack);
                        break;
                    }
                    DrainOutcome::EmergencyRelease(trigger) => {
                        let action = core.on_parent_died(trigger);
                        if let LinuxWatchdogAction::EmergencyRelease { steps, .. } = action {
                            exit_ok = run_linux_release(trigger, &steps, state);
                        }
                        break;
                    }
                }
            }

            let pidfd_exited =
                monitor.pidfd().is_some() && (poll_fds[1].revents & (libc::POLLIN | libc::POLLHUP)) != 0;
            let parent_dead = pidfd_exited || !monitor.is_parent_alive();
            if parent_dead {
                // Drain any queued GracefulExit frame before treating parent death as a crash.
                match drain_cmd_frames(args.cmd_fd, &mut acc, &mut acc_len, state) {
                    DrainOutcome::GracefulExit(seq) => {
                        let ack = WatchdogFrame::released(seq, WATCHDOG_RELEASED_FLAG_GRACEFUL)
                            .encode();
                        write_all_best_effort(args.ack_fd, &ack);
                    }
                    DrainOutcome::EmergencyRelease(trigger) => {
                        let action = core.on_parent_died(trigger);
                        if let LinuxWatchdogAction::EmergencyRelease { steps, .. } = action {
                            exit_ok = run_linux_release(trigger, &steps, state);
                        }
                    }
                    DrainOutcome::Continue => {
                        let trigger = if monitor.pidfd().is_some() {
                            "parent_exit_pidfd"
                        } else {
                            "parent_exit_proc_stat"
                        };
                        let action = core.on_parent_died(trigger);
                        if let LinuxWatchdogAction::EmergencyRelease { steps, .. } = action {
                            exit_ok = run_linux_release(trigger, &steps, state);
                        }
                    }
                }
                break;
            }

            if SIG_FIRED.load(Ordering::Acquire) {
                let action = core.on_parent_died("signal");
                if let LinuxWatchdogAction::EmergencyRelease { steps, .. } = action {
                    exit_ok = run_linux_release("signal", &steps, state);
                }
                break;
            }

            if let LinuxWatchdogAction::EmergencyRelease { trigger, steps } =
                core.on_tick(elapsed_ms)
            {
                exit_ok = run_linux_release(trigger, &steps, state);
                break;
            }
        }
        exit_ok
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    fn run_event_loop(
        args: &WatchdogArgs,
        state: &mut TrackedState,
        real_permit: Option<&RealInputPermit>,
        ready_flags: u8,
    ) -> bool {
        use std::sync::atomic::{AtomicBool, Ordering};
        static SIG_FIRED: AtomicBool = AtomicBool::new(false);
        extern "C" fn on_sig(_sig: libc::c_int) {
            SIG_FIRED.store(true, Ordering::Release);
        }
        unsafe {
            libc::signal(libc::SIGHUP, on_sig as *const () as libc::sighandler_t);
            libc::signal(libc::SIGTERM, on_sig as *const () as libc::sighandler_t);
            libc::signal(libc::SIGINT, on_sig as *const () as libc::sighandler_t);
        }

        let ready = WatchdogFrame::ready_with_flags(0, ready_flags).encode();
        write_all_best_effort(args.ack_fd, &ready);

        let mut exit_ok = true;
        let mut acc = [0u8; WATCHDOG_FRAME_LEN];
        let mut acc_len = 0usize;
        loop {
            let mut pfd = libc::pollfd {
                fd: args.cmd_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, 100) };
            if prc > 0 && (pfd.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR)) != 0 {
                match drain_cmd_frames(args.cmd_fd, &mut acc, &mut acc_len, state) {
                    DrainOutcome::Continue => {}
                    DrainOutcome::GracefulExit(seq) => {
                        let ack = WatchdogFrame::released(seq, WATCHDOG_RELEASED_FLAG_GRACEFUL)
                            .encode();
                        write_all_best_effort(args.ack_fd, &ack);
                        break;
                    }
                    DrainOutcome::EmergencyRelease(trigger) => {
                        exit_ok = execute_emergency_release(trigger, args, state, real_permit);
                        break;
                    }
                }
            }
            if SIG_FIRED.load(Ordering::Acquire) {
                exit_ok = execute_emergency_release("signal", args, state, real_permit);
                break;
            }
            let alive = unsafe { libc::kill(args.parent_pid as libc::pid_t, 0) };
            if alive != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                match drain_cmd_frames(args.cmd_fd, &mut acc, &mut acc_len, state) {
                    DrainOutcome::GracefulExit(seq) => {
                        let ack = WatchdogFrame::released(seq, WATCHDOG_RELEASED_FLAG_GRACEFUL)
                            .encode();
                        write_all_best_effort(args.ack_fd, &ack);
                    }
                    DrainOutcome::EmergencyRelease(trigger) => {
                        exit_ok = execute_emergency_release(trigger, args, state, real_permit);
                    }
                    DrainOutcome::Continue => {
                        exit_ok = execute_emergency_release(
                            "parent_exit_kqueue",
                            args,
                            state,
                            real_permit,
                        );
                    }
                }
                break;
            }
        }
        exit_ok
    }

    pub fn run(args: WatchdogArgs) -> ExitCode {
        // 1. Harden fds & acquire flock FIRST so closing fds >= 3 never closes AX/XPC fds!
        let Ok(lock_fd) = harden_process_and_lock(args.cmd_fd, args.ack_fd, &args.lock_file)
        else {
            return ExitCode::FAILURE;
        };

        // 2. Validate real-input permit & AX trust AFTER fd hardening.
        let mut ready_flags = 0u8;
        let real_permit = if args.real_os_input {
            match RealInputPermit::from_explicit_opt_in(true) {
                Ok(p) => {
                    if !is_accessibility_trusted() {
                        unsafe {
                            libc::close(lock_fd);
                        }
                        return ExitCode::FAILURE;
                    }
                    ready_flags = WATCHDOG_READY_FLAG_REAL_OS_INPUT | WATCHDOG_READY_FLAG_AX_TRUSTED;
                    Some(p)
                }
                Err(_) => {
                    unsafe {
                        libc::close(lock_fd);
                    }
                    return ExitCode::FAILURE;
                }
            }
        } else {
            if is_accessibility_trusted() {
                ready_flags |= WATCHDOG_READY_FLAG_AX_TRUSTED;
            }
            None
        };

        // 3. Handshake: wait up to 5s for valid Hello matching (parent_pid, nonce).
        // If timeout or mismatch, exit cleanly WITHOUT releasing any keys!
        if wait_for_hello(args.cmd_fd, args.parent_pid, args.nonce).is_err() {
            unsafe {
                libc::close(lock_fd);
            }
            return ExitCode::FAILURE;
        }

        // 4. Arm kqueue/signals, send Ready (with capability flags), and enter event loop.
        let mut state = TrackedState::default();
        let ok = run_event_loop(&args, &mut state, real_permit.as_ref(), ready_flags);

        unsafe {
            libc::close(lock_fd);
        }
        if ok {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use std::{
        fs,
        sync::{
            atomic::{AtomicBool, Ordering},
            mpsc, Arc,
        },
        thread,
    };
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        Storage::FileSystem::{ReadFile, WriteFile},
        System::Threading::{
            CreateEventW, OpenProcess, SetEvent, WaitForMultipleObjects, WaitForSingleObject,
            PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
        },
    };
    use zerodesk_core::os::{
        win_input::execute_atomic_release_batch,
        win_watchdog::query_process_creation_time,
        win_watchdog_logic::{
            is_same_process_instance, ProcessIdentity, WinInputEventDesc, WinWatchdogAction,
            WinWatchdogLoopState, DEFAULT_WIN_HEARTBEAT_TIMEOUT_MS,
        },
    };

    const WAIT_OBJECT_PIPE: u32 = WAIT_OBJECT_0.0 + 1;
    const PARENT_EXIT_PIPE_DRAIN_MS: u32 = 50;

    struct WinWatchdogArgs {
        parent_pid: u32,
        parent_creation_time_100ns: u64,
        expected_nonce: Option<[u8; 8]>,
        cmd_handle: usize,
        ack_handle: usize,
        heartbeat_timeout_ms: u64,
        dry_run_journal: Option<PathBuf>,
        real_os_input: bool,
    }

    fn parse_win_args(args: &[String]) -> Result<WinWatchdogArgs, String> {
        let mut parent_pid: Option<u32> = None;
        let mut parent_creation_time_100ns: Option<u64> = None;
        let mut expected_nonce: Option<[u8; 8]> = None;
        let mut cmd_handle: Option<usize> = None;
        let mut ack_handle: Option<usize> = None;
        let mut heartbeat_timeout_ms = DEFAULT_WIN_HEARTBEAT_TIMEOUT_MS;
        let mut dry_run_journal: Option<PathBuf> = None;
        let mut real_os_input = false;

        let mut i = 0usize;
        while i < args.len() {
            let flag = args[i].as_str();
            let next_val = |idx: &mut usize, name: &str| -> Result<String, String> {
                if *idx + 1 >= args.len() {
                    return Err(format!("{name} requires a value"));
                }
                *idx += 2;
                Ok(args[*idx - 1].clone())
            };
            match flag {
                "--parent-pid" => {
                    let raw = next_val(&mut i, "--parent-pid")?;
                    let pid: u32 = raw
                        .parse()
                        .map_err(|_| format!("invalid --parent-pid: {raw}"))?;
                    if pid == 0 {
                        return Err("--parent-pid must be > 0".into());
                    }
                    parent_pid = Some(pid);
                }
                "--parent-creation-time" => {
                    let raw = next_val(&mut i, "--parent-creation-time")?;
                    let ct: u64 = raw
                        .parse()
                        .map_err(|_| format!("invalid --parent-creation-time: {raw}"))?;
                    if ct == 0 {
                        return Err("--parent-creation-time must be > 0".into());
                    }
                    parent_creation_time_100ns = Some(ct);
                }
                "--nonce-hex" => {
                    // Optional backward-compat flag; default supervisor sends nonce strictly over pipe Hello.
                    let raw = next_val(&mut i, "--nonce-hex")?;
                    let bytes = hex::decode(&raw).map_err(|_| "invalid --nonce-hex".to_string())?;
                    if bytes.len() != 8 {
                        return Err("--nonce-hex must be 16 hex chars (8 bytes)".into());
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(&bytes);
                    expected_nonce = Some(arr);
                }
                "--cmd-handle" => {
                    let raw = next_val(&mut i, "--cmd-handle")?;
                    let h: usize = raw
                        .parse()
                        .map_err(|_| format!("invalid --cmd-handle: {raw}"))?;
                    cmd_handle = Some(h);
                }
                "--ack-handle" => {
                    let raw = next_val(&mut i, "--ack-handle")?;
                    let h: usize = raw
                        .parse()
                        .map_err(|_| format!("invalid --ack-handle: {raw}"))?;
                    ack_handle = Some(h);
                }
                "--heartbeat-timeout-ms" => {
                    let raw = next_val(&mut i, "--heartbeat-timeout-ms")?;
                    heartbeat_timeout_ms = raw
                        .parse::<u64>()
                        .map_err(|_| format!("invalid --heartbeat-timeout-ms: {raw}"))?
                        .max(100);
                }
                "--dry-run-journal" => {
                    let raw = next_val(&mut i, "--dry-run-journal")?;
                    if raw.is_empty() {
                        return Err("--dry-run-journal must be non-empty".into());
                    }
                    dry_run_journal = Some(PathBuf::from(raw));
                }
                "--real-os-input" => {
                    real_os_input = true;
                    i += 1;
                }
                other => return Err(format!("unknown flag: {other}")),
            }
        }

        let cmd_handle = cmd_handle.ok_or_else(|| "missing --cmd-handle".to_string())?;
        let ack_handle = ack_handle.ok_or_else(|| "missing --ack-handle".to_string())?;
        if cmd_handle == 0 || ack_handle == 0 || cmd_handle == ack_handle {
            return Err("--cmd-handle and --ack-handle must be valid distinct handles".into());
        }
        if real_os_input && dry_run_journal.is_some() {
            return Err("--real-os-input cannot be combined with --dry-run-journal".into());
        }

        Ok(WinWatchdogArgs {
            parent_pid: parent_pid.ok_or_else(|| "missing --parent-pid".to_string())?,
            parent_creation_time_100ns: parent_creation_time_100ns
                .ok_or_else(|| "missing --parent-creation-time".to_string())?,
            expected_nonce,
            cmd_handle,
            ack_handle,
            heartbeat_timeout_ms,
            dry_run_journal,
            real_os_input,
        })
    }

    struct HandleGuard(HANDLE);
    impl Drop for HandleGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() && self.0 .0 != 0 {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }

    enum PipeEvent {
        Frame(WatchdogFrame),
        Malformed,
        Eof,
    }

    fn write_best_effort(handle: HANDLE, data: &[u8]) {
        let mut written_total = 0usize;
        while written_total < data.len() {
            let mut written = 0u32;
            if unsafe { WriteFile(handle, Some(&data[written_total..]), Some(&mut written), None) }
                .is_err()
                || written == 0
            {
                break;
            }
            written_total += written as usize;
        }
    }

    fn read_exact_frame(handle: HANDLE) -> Result<WatchdogFrame, PipeEvent> {
        let mut buf = [0u8; WATCHDOG_FRAME_LEN];
        let mut filled = 0usize;
        while filled < WATCHDOG_FRAME_LEN {
            let mut n = 0u32;
            let res = unsafe { ReadFile(handle, Some(&mut buf[filled..]), Some(&mut n), None) };
            if res.is_err() || n == 0 {
                return Err(PipeEvent::Eof);
            }
            filled += n as usize;
        }
        WatchdogFrame::decode(&buf).map_err(|_| PipeEvent::Malformed)
    }

    struct WinReleaseRequest<'a> {
        trigger: &'a str,
        keys: &'a [u16],
        buttons: u8,
        batch: &'a [WinInputEventDesc],
        last_seq: u64,
    }

    fn execute_release(
        req: &WinReleaseRequest<'_>,
        args: &WinWatchdogArgs,
        real_permit: Option<&RealInputPermit>,
        ack_handle: HANDLE,
    ) -> bool {
        let start = Instant::now();
        let (release_ok, release_error) = if let Some(_permit) = real_permit {
            match execute_atomic_release_batch(req.batch) {
                Ok(rep) => {
                    if rep.residual_keys == 0 && rep.residual_buttons == 0 {
                        (true, None)
                    } else {
                        (
                            false,
                            Some(format!(
                                "SendInput residual keys={} buttons={} (UIPI/desktop restriction)",
                                rep.residual_keys, rep.residual_buttons
                            )),
                        )
                    }
                }
                Err(e) => (false, Some(e.to_string())),
            }
        } else {
            (true, None)
        };

        let elapsed_ms = start.elapsed().as_millis() as u64;
        if let Some(report_path) = &args.dry_run_journal {
            let report = WatchdogReleaseReport {
                schema_version: WATCHDOG_REPORT_SCHEMA_VERSION,
                trigger: req.trigger.to_string(),
                parent_pid: args.parent_pid,
                watchdog_pid: std::process::id(),
                released_keys: req.keys.to_vec(),
                released_buttons: req.buttons,
                released_modifiers: ALL_MODIFIER_HID_USAGES.to_vec(),
                release_ok,
                release_error,
                release_elapsed_ms: elapsed_ms,
                timestamp_epoch_ms: now_epoch_ms(),
            };
            if let Ok(json) = serde_json::to_vec_pretty(&report) {
                let _ = fs::write(report_path, json);
            }
        }

        let flag = if release_ok {
            WATCHDOG_RELEASED_FLAG_EMERGENCY_OK
        } else {
            WATCHDOG_RELEASED_FLAG_EMERGENCY_FAILED
        };
        let ack = WatchdogFrame::released(req.last_seq, flag).encode();
        write_best_effort(ack_handle, &ack);
        release_ok
    }

    fn drain_pipe_events(
        rx: &mpsc::Receiver<PipeEvent>,
        loop_state: &mut WinWatchdogLoopState,
        now_ms: u64,
    ) -> WinWatchdogAction {
        while let Ok(ev) = rx.try_recv() {
            let action = match ev {
                PipeEvent::Frame(frame) => loop_state.on_frame(frame, now_ms),
                PipeEvent::Malformed => loop_state.on_malformed_frame(),
                PipeEvent::Eof => loop_state.on_pipe_eof(),
            };
            if !matches!(action, WinWatchdogAction::Continue) {
                return action;
            }
        }
        WinWatchdogAction::Continue
    }

    pub fn run(raw_args: &[String]) -> ExitCode {
        let args = match parse_win_args(raw_args) {
            Ok(a) => a,
            Err(_) => return ExitCode::from(2),
        };
        let cmd_guard = HandleGuard(HANDLE(args.cmd_handle as isize));
        let ack_guard = HandleGuard(HANDLE(args.ack_handle as isize));

        // 1. Validate optional real-input permit.
        let mut ready_flags = 0u8;
        let real_permit = if args.real_os_input {
            match RealInputPermit::from_explicit_opt_in(true) {
                Ok(p) => {
                    ready_flags |= WATCHDOG_READY_FLAG_REAL_OS_INPUT;
                    Some(p)
                }
                Err(_) => return ExitCode::FAILURE,
            }
        } else {
            None
        };

        // 2. Open parent process handle & verify GetProcessTimes creation time against PID reuse!
        let parent_handle = match unsafe {
            OpenProcess(
                PROCESS_SYNCHRONIZE | PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                args.parent_pid,
            )
        } {
            Ok(h) => HandleGuard(h),
            Err(_) => return ExitCode::FAILURE,
        };
        let Ok(observed_ct) = query_process_creation_time(parent_handle.0) else {
            return ExitCode::FAILURE;
        };
        let expected_id = ProcessIdentity::new(args.parent_pid, args.parent_creation_time_100ns);
        let observed_id = ProcessIdentity::new(args.parent_pid, observed_ct);
        if !is_same_process_instance(expected_id, observed_id) {
            // PID was already reused by another process -> exit WITHOUT releasing keys!
            return ExitCode::FAILURE;
        }

        // 3. Handshake: read Hello from pipe and verify parent_pid (plus optional expected_nonce).
        let hello = match read_exact_frame(cmd_guard.0) {
            Ok(f) => f,
            Err(_) => return ExitCode::FAILURE,
        };
        let Some((hello_pid, hello_nonce)) = hello.parse_hello() else {
            return ExitCode::FAILURE;
        };
        if hello_pid != args.parent_pid {
            return ExitCode::FAILURE;
        }
        if let Some(exp_nonce) = args.expected_nonce {
            if hello_nonce != exp_nonce {
                return ExitCode::FAILURE;
            }
        }

        // 4. Create wakeup event and pipe reader thread so WaitForMultipleObjects monitors
        //    [parent_handle, pipe_event] simultaneously with bounded heartbeat timeout.
        let Ok(pipe_event_raw) = (unsafe { CreateEventW(None, false, false, None) }) else {
            return ExitCode::FAILURE;
        };
        let pipe_event = HandleGuard(pipe_event_raw);

        let ready = WatchdogFrame::ready_with_flags(0, ready_flags).encode();
        write_best_effort(ack_guard.0, &ready);

        let (tx, rx) = mpsc::channel::<PipeEvent>();
        let reader_done = Arc::new(AtomicBool::new(false));
        let reader_done_bg = Arc::clone(&reader_done);
        let cmd_raw = args.cmd_handle;
        let ev_raw = pipe_event.0 .0 as usize;
        if thread::Builder::new()
            .name("zd-win-wd-reader".into())
            .spawn(move || {
                let h_cmd = HANDLE(cmd_raw as isize);
                let h_ev = HANDLE(ev_raw as isize);
                loop {
                    match read_exact_frame(h_cmd) {
                        Ok(frame) => {
                            let _ = tx.send(PipeEvent::Frame(frame));
                            unsafe {
                                let _ = SetEvent(h_ev);
                            }
                        }
                        Err(ev) => {
                            let _ = tx.send(ev);
                            reader_done_bg.store(true, Ordering::Release);
                            unsafe {
                                let _ = SetEvent(h_ev);
                            }
                            break;
                        }
                    }
                }
            })
            .is_err()
        {
            return ExitCode::FAILURE;
        }

        let boot = Instant::now();
        let mut loop_state = WinWatchdogLoopState::new(0, args.heartbeat_timeout_ms);
        let handles = [parent_handle.0, pipe_event.0];

        loop {
            let now_ms = boot.elapsed().as_millis() as u64;
            let rem_ms = loop_state
                .heartbeat()
                .remaining_ms(now_ms)
                .clamp(1, u32::MAX as u64) as u32;

            let wait = unsafe { WaitForMultipleObjects(&handles, false, rem_ms) };
            let now_ms = boot.elapsed().as_millis() as u64;

            // Always drain pending pipe frames first so a GracefulExit sent right before
            // parent exit is never misclassified as a crash.
            let mut action = drain_pipe_events(&rx, &mut loop_state, now_ms);

            if matches!(action, WinWatchdogAction::Continue) {
                if wait == WAIT_OBJECT_0 {
                    // Parent exited: wait briefly (<= 50ms) for the reader thread to finish
                    // draining any final GracefulExit or StateSnapshot before deciding.
                    if !reader_done.load(Ordering::Acquire) {
                        unsafe {
                            let _ = WaitForSingleObject(pipe_event.0, PARENT_EXIT_PIPE_DRAIN_MS);
                        }
                    }
                    let post_now = boot.elapsed().as_millis() as u64;
                    action = drain_pipe_events(&rx, &mut loop_state, post_now);
                    if matches!(action, WinWatchdogAction::Continue) {
                        action = loop_state.on_parent_process_exit();
                    }
                } else if wait.0 == WAIT_OBJECT_PIPE {
                    // Always enforce heartbeat deadline on every iteration even under wakeups.
                    action = loop_state.on_tick(now_ms);
                } else if wait == WAIT_TIMEOUT {
                    action = loop_state.on_tick(now_ms);
                } else {
                    // WAIT_FAILED or unexpected return: fail closed immediately (never spin!).
                    action = loop_state.on_parent_process_exit();
                }
            }

            match action {
                WinWatchdogAction::Continue => continue,
                WinWatchdogAction::GracefulExit { seq } => {
                    let ack =
                        WatchdogFrame::released(seq, WATCHDOG_RELEASED_FLAG_GRACEFUL).encode();
                    write_best_effort(ack_guard.0, &ack);
                    return ExitCode::SUCCESS;
                }
                WinWatchdogAction::EmergencyRelease {
                    trigger,
                    keys,
                    buttons,
                    batch,
                    ..
                } => {
                    let ok = execute_release(
                        &WinReleaseRequest {
                            trigger,
                            keys: &keys,
                            buttons,
                            batch: &batch,
                            last_seq: loop_state.last_seq(),
                        },
                        &args,
                        real_permit.as_ref(),
                        ack_guard.0,
                    );
                    return if ok {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    };
                }
            }
        }
    }
}

fn main() -> ExitCode {
    let raw_args: Vec<String> = env::args().skip(1).collect();

    #[cfg(unix)]
    {
        let args = match parse_args(&raw_args) {
            Ok(a) => a,
            Err(_) => return ExitCode::from(2),
        };
        unix_impl::run(args)
    }
    #[cfg(windows)]
    {
        windows_impl::run(&raw_args)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = raw_args;
        ExitCode::FAILURE
    }
}
