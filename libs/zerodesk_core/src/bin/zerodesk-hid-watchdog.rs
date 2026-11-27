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

use std::{
    env,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zerodesk_core::os::{
    input::{emergency_release_real_os_keys, is_accessibility_trusted, RealInputPermit},
    watchdog_proto::{
        bitmap_collect_keys, WatchdogFrame, WatchdogMsgType, WatchdogReleaseReport,
        ALL_MODIFIER_HID_USAGES, WATCHDOG_FRAME_LEN, WATCHDOG_REPORT_SCHEMA_VERSION,
    },
};

struct WatchdogArgs {
    parent_pid: u32,
    nonce: [u8; 8],
    cmd_fd: i32,
    ack_fd: i32,
    lock_file: PathBuf,
    dry_run_journal: Option<PathBuf>,
    real_os_input: bool,
}

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

    Ok(WatchdogArgs {
        parent_pid: parent_pid.ok_or_else(|| "missing --parent-pid".to_string())?,
        nonce: nonce.ok_or_else(|| "missing --nonce-hex".to_string())?,
        cmd_fd,
        ack_fd: ack_fd.ok_or_else(|| "missing --ack-fd".to_string())?,
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
    use std::{
        ffi::CString,
        fs,
        os::unix::ffi::OsStrExt,
    };

    const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

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

    /// Startup hardening: ignore SIGPIPE, redirect stdio (except cmd_fd/ack_fd) to `/dev/null`,
    /// detach session via `setsid()`, acquire exclusive non-blocking `flock` on lock file, and
    /// close all unneeded fds >= 3.
    fn harden_process_and_lock(
        cmd_fd: i32,
        ack_fd: i32,
        lock_file: &Path,
    ) -> Result<i32, String> {
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

        // Close all unneeded fds >= 3 up to getdtablesize().clamp(256, 4096).
        let max_fd = unsafe { libc::getdtablesize() }.clamp(256, 4096);
        for fd in 3..max_fd {
            if fd != cmd_fd && fd != ack_fd && fd != lock_fd {
                unsafe {
                    libc::close(fd);
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

    fn execute_emergency_release(
        trigger: &str,
        args: &WatchdogArgs,
        state: &TrackedState,
        real_permit: Option<&RealInputPermit>,
    ) {
        let start = Instant::now();
        let released_keys = bitmap_collect_keys(&state.keys_bitmap);
        let released_modifiers = ALL_MODIFIER_HID_USAGES.to_vec();

        if let Some(permit) = real_permit {
            let _ = emergency_release_real_os_keys(permit, &released_keys, state.buttons);
        }

        if let Some(report_path) = &args.dry_run_journal {
            let report = WatchdogReleaseReport {
                schema_version: WATCHDOG_REPORT_SCHEMA_VERSION,
                trigger: trigger.to_string(),
                parent_pid: args.parent_pid,
                watchdog_pid: std::process::id(),
                released_keys,
                released_buttons: state.buttons,
                released_modifiers,
                release_elapsed_ms: start.elapsed().as_millis() as u64,
                timestamp_epoch_ms: now_epoch_ms(),
            };
            let _ = write_report_atomic_0600(report_path, &report);
        }

        let ack = WatchdogFrame::released(state.last_seq, 1).encode();
        write_all_best_effort(args.ack_fd, &ack);
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
                        | WatchdogMsgType::Released => {
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
    ) {
        // Ignore SIGHUP/SIGTERM/SIGINT so kqueue EVFILT_SIGNAL intercepts them cleanly without
        // killing the process before emergency release runs.
        unsafe {
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
            libc::signal(libc::SIGINT, libc::SIG_IGN);
        }

        let kq = unsafe { libc::kqueue() };
        if kq < 0 {
            execute_emergency_release("malformed_frame", args, state, real_permit);
            return;
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
            execute_emergency_release("malformed_frame", args, state, real_permit);
            return;
        }

        let mut acc = [0u8; WATCHDOG_FRAME_LEN];
        let mut acc_len = 0usize;

        // Register EVFILT_PROC NOTE_EXIT separately so ESRCH (parent already exited!) is
        // detected immediately and cleanly.
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
            // Drain any buffered GracefulExit/StateSnapshot before concluding parent crashed.
            match drain_cmd_frames(args.cmd_fd, &mut acc, &mut acc_len, state) {
                DrainOutcome::GracefulExit(seq) => {
                    let ack = WatchdogFrame::released(seq, 0).encode();
                    write_all_best_effort(args.ack_fd, &ack);
                }
                DrainOutcome::EmergencyRelease(trigger) => {
                    execute_emergency_release(trigger, args, state, real_permit);
                }
                DrainOutcome::Continue => {
                    execute_emergency_release("parent_exit_kqueue", args, state, real_permit);
                }
            }
            unsafe {
                libc::close(kq);
            }
            return;
        }

        let mut events = [make_ev(0, 0, 0, 0); 16];
        loop {
            let n = unsafe {
                libc::kevent(
                    kq,
                    std::ptr::null(),
                    0,
                    events.as_mut_ptr(),
                    events.len() as i32,
                    std::ptr::null(),
                )
            };
            if n < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                execute_emergency_release("malformed_frame", args, state, real_permit);
                break;
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
                        let ack = WatchdogFrame::released(seq, 0).encode();
                        write_all_best_effort(args.ack_fd, &ack);
                        break;
                    }
                    DrainOutcome::EmergencyRelease(trigger) => {
                        execute_emergency_release(trigger, args, state, real_permit);
                        break;
                    }
                }
            }

            if saw_proc_exit {
                execute_emergency_release("parent_exit_kqueue", args, state, real_permit);
                break;
            }

            if saw_signal {
                execute_emergency_release("signal", args, state, real_permit);
                break;
            }
        }

        unsafe {
            libc::close(kq);
        }
    }

    #[cfg(not(target_os = "macos"))]
    fn run_event_loop(
        args: &WatchdogArgs,
        state: &mut TrackedState,
        real_permit: Option<&RealInputPermit>,
    ) {
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
                        let ack = WatchdogFrame::released(seq, 0).encode();
                        write_all_best_effort(args.ack_fd, &ack);
                        break;
                    }
                    DrainOutcome::EmergencyRelease(trigger) => {
                        execute_emergency_release(trigger, args, state, real_permit);
                        break;
                    }
                }
            }
            if SIG_FIRED.load(Ordering::Acquire) {
                execute_emergency_release("signal", args, state, real_permit);
                break;
            }
            let alive = unsafe { libc::kill(args.parent_pid as libc::pid_t, 0) };
            if alive != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                match drain_cmd_frames(args.cmd_fd, &mut acc, &mut acc_len, state) {
                    DrainOutcome::GracefulExit(seq) => {
                        let ack = WatchdogFrame::released(seq, 0).encode();
                        write_all_best_effort(args.ack_fd, &ack);
                    }
                    DrainOutcome::EmergencyRelease(trigger) => {
                        execute_emergency_release(trigger, args, state, real_permit);
                    }
                    DrainOutcome::Continue => {
                        execute_emergency_release("parent_exit_kqueue", args, state, real_permit);
                    }
                }
                break;
            }
        }
    }

    pub fn run(args: WatchdogArgs) -> ExitCode {
        let real_permit = if args.real_os_input {
            match RealInputPermit::from_explicit_opt_in(true) {
                Ok(p) => {
                    if !is_accessibility_trusted() {
                        return ExitCode::FAILURE;
                    }
                    Some(p)
                }
                Err(_) => return ExitCode::FAILURE,
            }
        } else {
            None
        };

        let Ok(lock_fd) = harden_process_and_lock(args.cmd_fd, args.ack_fd, &args.lock_file)
        else {
            return ExitCode::FAILURE;
        };

        // Handshake: wait up to 5s for valid Hello matching (parent_pid, nonce).
        // If timeout or mismatch, exit cleanly WITHOUT releasing any keys!
        if wait_for_hello(args.cmd_fd, args.parent_pid, args.nonce).is_err() {
            unsafe {
                libc::close(lock_fd);
            }
            return ExitCode::FAILURE;
        }

        let ready = WatchdogFrame::ready(0).encode();
        write_all_best_effort(args.ack_fd, &ready);

        let mut state = TrackedState::default();
        run_event_loop(&args, &mut state, real_permit.as_ref());

        unsafe {
            libc::close(lock_fd);
        }
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let raw_args: Vec<String> = env::args().skip(1).collect();
    let args = match parse_args(&raw_args) {
        Ok(a) => a,
        Err(_) => return ExitCode::from(2),
    };

    #[cfg(unix)]
    {
        unix_impl::run(args)
    }
    #[cfg(not(unix))]
    {
        let _ = args;
        ExitCode::FAILURE
    }
}
