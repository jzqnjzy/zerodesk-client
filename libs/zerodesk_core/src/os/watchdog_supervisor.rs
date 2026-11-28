// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Host-side supervisor and `HidGate` state machine for the independent
//! `zerodesk-hid-watchdog` subprocess.
//!
//! Enforces the golden ordering invariant:
//! - On `KeyDown` / `MouseDown`: acquire `HidGate`, verify `Open`, write atomic 56-byte
//!   `StateSnapshot` (`O_NONBLOCK`) to watchdog pipe, and ONLY inject into `OsHidSink`
//!   after the pipe write succeeds. On `EAGAIN`, refuse injection, release local keys,
//!   report degradation, and permanently close after 5 consecutive failures. On `EPIPE`,
//!   release local keys, report degradation, and fail closed immediately.
//! - On `KeyUp` / `MouseUp`: inject into `OsHidSink` FIRST, then update snapshot.

use super::{EmergencyKeyReleaser, OsError, OsHidSink, ReleaseReport};
use crate::session::hid::{KeyEvent, MouseEvent, MouseKind};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

pub const MAX_CONSECUTIVE_EAGAIN_FAILURES: u32 = 5;
pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
pub const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(2);
pub const WATCHDOG_BIN_NAME: &str = "zerodesk-hid-watchdog";

static ACTIVE_WATCHDOG_CHILDREN: AtomicUsize = AtomicUsize::new(0);

/// Returns the number of currently live `zerodesk-hid-watchdog` child processes spawned
/// by `HidWatchdogSupervisor` in this process.
pub fn active_watchdog_children() -> usize {
    ACTIVE_WATCHDOG_CHILDREN.load(Ordering::Acquire)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidGatePhase {
    Open,
    Quiescing,
    Closed,
}

#[derive(Debug, Clone)]
pub struct HidWatchdogConfig {
    /// Optional explicit binary path; when `None`, resolves strictly relative to `current_exe()`
    /// (NEVER `PATH`).
    pub binary_path: Option<PathBuf>,
    /// Optional explicit per-session flock file path.
    pub lock_file_path: Option<PathBuf>,
    /// Optional dry-run release report JSON path (`0600` + `O_NOFOLLOW`).
    pub dry_run_report_path: Option<PathBuf>,
    /// Whether the watchdog should post real OS `CGEvent` key-ups (requires compile-time
    /// `real-input` feature + macOS Accessibility trust).
    pub real_os_input: bool,
    pub handshake_timeout: Duration,
    pub shutdown_timeout: Duration,
}

impl Default for HidWatchdogConfig {
    fn default() -> Self {
        Self {
            binary_path: None,
            lock_file_path: None,
            dry_run_report_path: None,
            real_os_input: false,
            handshake_timeout: DEFAULT_HANDSHAKE_TIMEOUT,
            shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
        }
    }
}

pub type DegradedCallback = Arc<dyn Fn(String) + Send + Sync>;

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use crate::os::{
        watchdog_proto::{
            bitmap_clear_key, bitmap_set_key, WatchdogFrame, WatchdogMsgType, WATCHDOG_FRAME_LEN,
            WATCHDOG_READY_FLAG_AX_TRUSTED, WATCHDOG_READY_FLAG_REAL_OS_INPUT,
        },
        OsPermission,
    };
    use rand_core::{OsRng, RngCore};
    use std::{
        ffi::CString,
        fs,
        os::unix::{ffi::OsStrExt, process::CommandExt},
        process::Command,
        sync::Mutex,
        thread,
        time::Instant,
    };

    struct HidGateState {
        phase: HidGatePhase,
        keys_bitmap: [u8; 32],
        buttons: u8,
        mods: u8,
        next_seq: u64,
        consecutive_eagain_failures: u32,
        cmd_write_fd: Option<i32>,
    }

    fn close_fd(fd: i32) {
        if fd >= 0 {
            unsafe {
                libc::close(fd);
            }
        }
    }

    fn set_cloexec(fd: i32) -> Result<(), OsError> {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFD);
            if flags < 0 {
                return Err(OsError::CaptureFailed(format!(
                    "fcntl(F_GETFD) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) < 0 {
                return Err(OsError::CaptureFailed(format!(
                    "fcntl(F_SETFD, FD_CLOEXEC) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
        }
        Ok(())
    }

    fn set_nonblock_and_nosigpipe(fd: i32) -> Result<(), OsError> {
        unsafe {
            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 {
                return Err(OsError::CaptureFailed(format!(
                    "fcntl(F_GETFL) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            if libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                return Err(OsError::CaptureFailed(format!(
                    "fcntl(F_SETFL, O_NONBLOCK) failed: {}",
                    std::io::Error::last_os_error()
                )));
            }
            #[cfg(target_os = "macos")]
            {
                // Darwin <sys/fcntl.h>: #define F_SETNOSIGPIPE 73 (absent in older libc 0.2.x).
                const F_SETNOSIGPIPE: libc::c_int = 73;
                if libc::fcntl(fd, F_SETNOSIGPIPE, 1) < 0 {
                    return Err(OsError::CaptureFailed(format!(
                        "fcntl(F_SETNOSIGPIPE) failed: {}",
                        std::io::Error::last_os_error()
                    )));
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                // Non-macOS Unix has no per-fd F_SETNOSIGPIPE; verify SIGPIPE is SIG_IGN (fail closed).
                let mut act: libc::sigaction = std::mem::zeroed();
                if libc::sigaction(libc::SIGPIPE, std::ptr::null(), &mut act) != 0
                    || act.sa_sigaction != libc::SIG_IGN
                {
                    return Err(OsError::CaptureFailed(
                        "SIGPIPE must be SIG_IGN on non-macOS Unix before supervising HID watchdog"
                            .into(),
                    ));
                }
            }
        }
        Ok(())
    }

    fn make_cloexec_pipe() -> Result<(i32, i32), OsError> {
        let mut fds = [-1i32; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(OsError::CaptureFailed(format!(
                "pipe() failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if let Err(e) = set_cloexec(fds[0]).and_then(|_| set_cloexec(fds[1])) {
            close_fd(fds[0]);
            close_fd(fds[1]);
            return Err(e);
        }
        Ok((fds[0], fds[1]))
    }

    /// Resolves the watchdog binary strictly relative to `current_exe()` (NEVER `PATH`),
    /// then validates it with `lstat` (regular file, not symlink, owner root or current euid,
    /// not group/world writable, executable).
    pub fn resolve_and_verify_watchdog_binary(
        explicit: Option<&Path>,
    ) -> Result<PathBuf, OsError> {
        let candidate = if let Some(p) = explicit {
            p.to_path_buf()
        } else {
            let exe = std::env::current_exe().map_err(|e| {
                OsError::CaptureFailed(format!("current_exe() failed locating watchdog: {e}"))
            })?;
            let parent = exe.parent().ok_or_else(|| {
                OsError::CaptureFailed("current_exe() has no parent directory".into())
            })?;
            let sibling = parent.join(WATCHDOG_BIN_NAME);
            if sibling.exists() {
                sibling
            } else if parent.file_name().and_then(|n| n.to_str()) == Some("deps") {
                // Cargo integration tests live in `target/<profile>/deps/<test-bin>` while
                // workspace binaries live in `target/<profile>/<bin>`.
                parent
                    .parent()
                    .map(|p| p.join(WATCHDOG_BIN_NAME))
                    .unwrap_or(sibling)
            } else {
                sibling
            }
        };
        verify_watchdog_binary(&candidate)?;
        Ok(candidate)
    }

    pub fn verify_watchdog_binary(path: &Path) -> Result<(), OsError> {
        let c_path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| OsError::InvalidData("watchdog binary path contains NUL".into()))?;
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::lstat(c_path.as_ptr(), &mut st) } != 0 {
            return Err(OsError::CaptureFailed(format!(
                "lstat({}) failed: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }
        let file_type = st.st_mode & libc::S_IFMT;
        if file_type != libc::S_IFREG {
            return Err(OsError::InvalidData(format!(
                "watchdog binary {} is not a regular file (symlink or special file rejected)",
                path.display()
            )));
        }
        let euid = unsafe { libc::geteuid() };
        if st.st_uid != 0 && st.st_uid != euid {
            return Err(OsError::InvalidData(format!(
                "watchdog binary {} owned by uid {} (expected root or euid {euid})",
                path.display(),
                st.st_uid
            )));
        }
        if (st.st_mode & 0o022) != 0 {
            return Err(OsError::InvalidData(format!(
                "watchdog binary {} has unsafe group/world write permissions ({:#o})",
                path.display(),
                st.st_mode & 0o777
            )));
        }
        if (st.st_mode & 0o111) == 0 {
            return Err(OsError::InvalidData(format!(
                "watchdog binary {} is not executable",
                path.display()
            )));
        }
        Ok(())
    }

    enum PipeWriteResult {
        Ok,
        WouldBlock,
        Broken(String),
    }

    fn write_frame_nonblock(fd: i32, frame: &[u8; WATCHDOG_FRAME_LEN]) -> PipeWriteResult {
        loop {
            let n = unsafe { libc::write(fd, frame.as_ptr() as *const libc::c_void, frame.len()) };
            if n == frame.len() as isize {
                return PipeWriteResult::Ok;
            }
            if n < 0 {
                let err = std::io::Error::last_os_error();
                match err.raw_os_error() {
                    Some(libc::EINTR) => continue,
                    Some(libc::EAGAIN) => return PipeWriteResult::WouldBlock,
                    Some(libc::EPIPE) => {
                        return PipeWriteResult::Broken("watchdog pipe EPIPE (child died)".into())
                    }
                    _ => return PipeWriteResult::Broken(format!("watchdog pipe write error: {err}")),
                }
            }
            return PipeWriteResult::Broken(format!(
                "unexpected partial atomic pipe write: {n}/{}",
                frame.len()
            ));
        }
    }

    fn wait_for_ready_frame(ack_fd: i32, timeout: Duration) -> Result<u8, OsError> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; WATCHDOG_FRAME_LEN];
        let mut filled = 0usize;
        while filled < WATCHDOG_FRAME_LEN {
            let rem = match deadline.checked_duration_since(Instant::now()) {
                Some(d) if !d.is_zero() => d,
                _ => return Err(OsError::Timeout),
            };
            let timeout_ms = rem.as_millis().min(i32::MAX as u128) as i32;
            let mut pfd = libc::pollfd {
                fd: ack_fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let prc = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
            if prc < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(OsError::CaptureFailed(format!(
                    "poll waiting for watchdog Ready failed: {err}"
                )));
            }
            if prc == 0 {
                return Err(OsError::Timeout);
            }
            let n = unsafe {
                libc::read(
                    ack_fd,
                    buf[filled..].as_mut_ptr() as *mut libc::c_void,
                    WATCHDOG_FRAME_LEN - filled,
                )
            };
            if n > 0 {
                filled += n as usize;
            } else if n == 0 {
                return Err(OsError::CaptureFailed(
                    "watchdog closed ack pipe before sending Ready".into(),
                ));
            } else {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                return Err(OsError::CaptureFailed(format!(
                    "read waiting for watchdog Ready failed: {err}"
                )));
            }
        }
        let frame = WatchdogFrame::decode(&buf).map_err(|e| {
            OsError::InvalidData(format!("invalid Ready frame from watchdog: {e}"))
        })?;
        if frame.msg_type != WatchdogMsgType::Ready {
            return Err(OsError::InvalidData(format!(
                "expected Ready frame from watchdog, got {:?}",
                frame.msg_type
            )));
        }
        Ok(frame.flags)
    }

    fn reap_child_bounded(pid: i32, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        let mut status: libc::c_int = 0;
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
            if r == pid {
                return;
            }
            if r < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                // ECHILD or already reaped.
                return;
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        // Bounded wait expired: escalate to SIGKILL and blocking reap so ZERO zombies ever remain.
        unsafe {
            let _ = libc::kill(pid, libc::SIGKILL);
        }
        loop {
            let r = unsafe { libc::waitpid(pid, &mut status, 0) };
            if r == pid {
                return;
            }
            if r < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return;
        }
    }

    struct AckReaderState {
        fd: Option<i32>,
        buf: [u8; WATCHDOG_FRAME_LEN],
        filled: usize,
    }

    pub struct HidWatchdogSupervisor {
        gate: Mutex<HidGateState>,
        child_pid: Mutex<Option<i32>>,
        ack_read: Mutex<AckReaderState>,
        lock_file_path: Option<PathBuf>,
        shutdown_timeout: Duration,
        owns_child: bool,
        watchdog_ax_trusted: Arc<std::sync::atomic::AtomicBool>,
    }

    impl HidWatchdogSupervisor {
        pub fn spawn(cfg: HidWatchdogConfig) -> Result<Self, OsError> {
            let bin_path = resolve_and_verify_watchdog_binary(cfg.binary_path.as_deref())?;
            let (cmd_read, cmd_write) = make_cloexec_pipe()?;
            let (ack_read, ack_write) = match make_cloexec_pipe() {
                Ok(p) => p,
                Err(e) => {
                    close_fd(cmd_read);
                    close_fd(cmd_write);
                    return Err(e);
                }
            };

            if let Err(e) = set_nonblock_and_nosigpipe(cmd_write) {
                close_fd(cmd_read);
                close_fd(cmd_write);
                close_fd(ack_read);
                close_fd(ack_write);
                return Err(e);
            }

            let mut nonce = [0u8; 8];
            OsRng.fill_bytes(&mut nonce);
            let nonce_hex = hex::encode(nonce);
            let parent_pid = std::process::id();

            let lock_file = match cfg.lock_file_path {
                Some(p) => p,
                None => {
                    let base_dir = cfg
                        .dry_run_report_path
                        .as_deref()
                        .and_then(|p| p.parent())
                        .unwrap_or_else(|| Path::new("/tmp"));
                    base_dir.join(format!("zerodesk-hid-wd-{parent_pid}-{nonce_hex}.lock"))
                }
            };

            let mut cmd = Command::new(&bin_path);
            cmd.env_clear()
                .arg("--parent-pid")
                .arg(parent_pid.to_string())
                .arg("--nonce-hex")
                .arg(&nonce_hex)
                .arg("--cmd-fd")
                .arg(cmd_read.to_string())
                .arg("--ack-fd")
                .arg(ack_write.to_string())
                .arg("--lock-file")
                .arg(&lock_file);
            if let Some(report) = &cfg.dry_run_report_path {
                cmd.arg("--dry-run-journal").arg(report);
            }
            if cfg.real_os_input {
                cmd.arg("--real-os-input");
            }

            // In pre_exec (async-signal-safe only):
            // 1. Clear FD_CLOEXEC ONLY on cmd_read and ack_write.
            // 2. Call setsid() (ignore EPERM) so child is detached even before exec().
            // 3. Close all inherited fds 3..rlim_cur.min(16384) except cmd_read and ack_write.
            unsafe {
                cmd.pre_exec(move || {
                    for fd in [cmd_read, ack_write] {
                        let flags = libc::fcntl(fd, libc::F_GETFD);
                        if flags < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        if libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                    }
                    let _ = libc::setsid();
                    let mut rl = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    let max_fd = if libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) == 0
                        && rl.rlim_cur != libc::RLIM_INFINITY
                        && rl.rlim_cur > 0
                    {
                        (rl.rlim_cur.min(16_384) as i32).max(256)
                    } else {
                        4096
                    };
                    for fd in 3..max_fd {
                        if fd != cmd_read && fd != ack_write {
                            let _ = libc::close(fd);
                        }
                    }
                    Ok(())
                });
            }

            let child = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => {
                    close_fd(cmd_read);
                    close_fd(cmd_write);
                    close_fd(ack_read);
                    close_fd(ack_write);
                    return Err(OsError::CaptureFailed(format!(
                        "spawn {} failed: {e}",
                        bin_path.display()
                    )));
                }
            };

            // Parent immediately closes the child ends of both pipes.
            close_fd(cmd_read);
            close_fd(ack_write);

            let child_pid = child.id() as i32;
            // Transfer ownership of child pid to our explicit waitpid reaper (no Drop leak in Child).
            std::mem::forget(child);
            ACTIVE_WATCHDOG_CHILDREN.fetch_add(1, Ordering::AcqRel);

            let sup = Self {
                gate: Mutex::new(HidGateState {
                    phase: HidGatePhase::Open,
                    keys_bitmap: [0u8; 32],
                    buttons: 0,
                    mods: 0,
                    next_seq: 0,
                    consecutive_eagain_failures: 0,
                    cmd_write_fd: Some(cmd_write),
                }),
                child_pid: Mutex::new(Some(child_pid)),
                ack_read: Mutex::new(AckReaderState {
                    fd: Some(ack_read),
                    buf: [0u8; WATCHDOG_FRAME_LEN],
                    filled: 0,
                }),
                lock_file_path: Some(lock_file),
                shutdown_timeout: cfg.shutdown_timeout,
                owns_child: true,
                watchdog_ax_trusted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            };

            // Handshake: send Hello(parent_pid, nonce) and wait for Ready within handshake_timeout.
            let hello = WatchdogFrame::hello(parent_pid, nonce).encode();
            match write_frame_nonblock(cmd_write, &hello) {
                PipeWriteResult::Ok => {}
                PipeWriteResult::WouldBlock => {
                    sup.force_kill_and_cleanup();
                    return Err(OsError::CaptureFailed(
                        "unexpected EAGAIN writing Hello to fresh watchdog pipe".into(),
                    ));
                }
                PipeWriteResult::Broken(msg) => {
                    sup.force_kill_and_cleanup();
                    return Err(OsError::CaptureFailed(msg));
                }
            }

            let ready_flags = match wait_for_ready_frame(ack_read, cfg.handshake_timeout) {
                Ok(f) => f,
                Err(e) => {
                    sup.force_kill_and_cleanup();
                    return Err(e);
                }
            };
            // Switch ack_read to non-blocking so live AxStatus heartbeats can be drained safely.
            unsafe {
                let flags = libc::fcntl(ack_read, libc::F_GETFL);
                if flags >= 0 {
                    let _ = libc::fcntl(ack_read, libc::F_SETFL, flags | libc::O_NONBLOCK);
                }
            }
            let ax_trusted = (ready_flags & WATCHDOG_READY_FLAG_AX_TRUSTED) != 0;
            sup.watchdog_ax_trusted
                .store(ax_trusted, Ordering::Release);
            if cfg.real_os_input {
                let required = WATCHDOG_READY_FLAG_REAL_OS_INPUT | WATCHDOG_READY_FLAG_AX_TRUSTED;
                if (ready_flags & required) != required {
                    sup.force_kill_and_cleanup();
                    return Err(OsError::PermissionDenied(OsPermission::Accessibility));
                }
            }

            Ok(sup)
        }

        /// Attaches a `HidWatchdogSupervisor` gate directly to an existing pipe write fd
        /// (taking ownership of `cmd_write_fd`). Sets `O_NONBLOCK` and `F_SETNOSIGPIPE`.
        pub fn from_raw_pipe_fd(cmd_write_fd: i32) -> Result<Self, OsError> {
            set_nonblock_and_nosigpipe(cmd_write_fd)?;
            Ok(Self {
                gate: Mutex::new(HidGateState {
                    phase: HidGatePhase::Open,
                    keys_bitmap: [0u8; 32],
                    buttons: 0,
                    mods: 0,
                    next_seq: 0,
                    consecutive_eagain_failures: 0,
                    cmd_write_fd: Some(cmd_write_fd),
                }),
                child_pid: Mutex::new(None),
                ack_read: Mutex::new(AckReaderState {
                    fd: None,
                    buf: [0u8; WATCHDOG_FRAME_LEN],
                    filled: 0,
                }),
                lock_file_path: None,
                shutdown_timeout: DEFAULT_SHUTDOWN_TIMEOUT,
                owns_child: false,
                watchdog_ax_trusted: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            })
        }

        /// Returns a shared atomic handle reflecting the watchdog child's live `AXIsProcessTrusted()`
        /// state (flipped to `false` immediately if the watchdog exits or revokes trust).
        pub fn accessibility_trusted_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
            Arc::clone(&self.watchdog_ax_trusted)
        }

        /// Drains any queued `AxStatus` IPC heartbeats from the watchdog ack pipe without blocking.
        /// Immediately stores `false` if the watchdog child exited (pipe EOF or error).
        pub fn poll_ax_status(&self) {
            let mut st = self.ack_read.lock().unwrap_or_else(|e| e.into_inner());
            let Some(fd) = st.fd else {
                if self.owns_child {
                    self.watchdog_ax_trusted.store(false, Ordering::Release);
                }
                return;
            };
            loop {
                let start = st.filled;
                let n = unsafe {
                    libc::read(
                        fd,
                        st.buf[start..].as_mut_ptr() as *mut libc::c_void,
                        WATCHDOG_FRAME_LEN - start,
                    )
                };
                if n > 0 {
                    st.filled += n as usize;
                    if st.filled == WATCHDOG_FRAME_LEN {
                        st.filled = 0;
                        if let Ok(frame) = WatchdogFrame::decode(&st.buf) {
                            match frame.msg_type {
                                WatchdogMsgType::AxStatus | WatchdogMsgType::Ready => {
                                    let trusted =
                                        (frame.flags & WATCHDOG_READY_FLAG_AX_TRUSTED) != 0;
                                    self.watchdog_ax_trusted.store(trusted, Ordering::Release);
                                }
                                WatchdogMsgType::Released => {
                                    self.watchdog_ax_trusted.store(false, Ordering::Release);
                                }
                                _ => {}
                            }
                        }
                    }
                } else if n == 0 {
                    // Watchdog closed ack pipe (exited) -> immediately fail closed!
                    self.watchdog_ax_trusted.store(false, Ordering::Release);
                    if let Some(dead_fd) = st.fd.take() {
                        close_fd(dead_fd);
                    }
                    break;
                } else {
                    let err = std::io::Error::last_os_error();
                    match err.raw_os_error() {
                        Some(libc::EINTR) => continue,
                        Some(libc::EAGAIN) => break,
                        _ => {
                            self.watchdog_ax_trusted.store(false, Ordering::Release);
                            if let Some(dead_fd) = st.fd.take() {
                                close_fd(dead_fd);
                            }
                            break;
                        }
                    }
                }
            }
        }

        /// Reports the watchdog child's live `AXIsProcessTrusted()` status after draining any
        /// pending heartbeat updates from the ack pipe.
        pub fn accessibility_trusted(&self) -> bool {
            self.poll_ax_status();
            self.watchdog_ax_trusted.load(Ordering::Acquire)
        }

        pub fn child_pid(&self) -> Option<u32> {
            self.child_pid
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .map(|p| p as u32)
        }

        pub fn phase(&self) -> HidGatePhase {
            self.gate.lock().unwrap_or_else(|e| e.into_inner()).phase
        }

        pub fn consecutive_eagain_failures(&self) -> u32 {
            self.gate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .consecutive_eagain_failures
        }

        pub fn is_open(&self) -> bool {
            self.phase() == HidGatePhase::Open
        }

        /// Returns the raw `cmd_write_fd` if currently open (for low-level diagnostics / tests).
        pub fn cmd_write_fd(&self) -> Option<i32> {
            self.gate
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .cmd_write_fd
        }

        fn force_kill_and_cleanup(&self) {
            self.watchdog_ax_trusted.store(false, Ordering::Release);
            {
                let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
                g.phase = HidGatePhase::Closed;
                if let Some(fd) = g.cmd_write_fd.take() {
                    close_fd(fd);
                }
            }
            if let Some(fd) = self
                .ack_read
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .fd
                .take()
            {
                close_fd(fd);
            }
            if let Some(pid) = self
                .child_pid
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                unsafe {
                    let _ = libc::kill(pid, libc::SIGKILL);
                }
                reap_child_bounded(pid, Duration::from_millis(500));
                if self.owns_child {
                    ACTIVE_WATCHDOG_CHILDREN.fetch_sub(1, Ordering::AcqRel);
                }
            }
            if let Some(lock_path) = &self.lock_file_path {
                let _ = fs::remove_file(lock_path);
            }
        }

        /// Non-blocking reap + resource cleanup invoked after detecting a broken pipe (`EPIPE`)
        /// so a dead watchdog never lingers as a zombie while the supervisor is still alive.
        fn try_reap_dead_child_nonblock(&self) {
            self.watchdog_ax_trusted.store(false, Ordering::Release);
            if let Some(fd) = self
                .ack_read
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .fd
                .take()
            {
                close_fd(fd);
            }
            let mut pid_guard = self.child_pid.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(pid) = *pid_guard {
                let mut status: libc::c_int = 0;
                let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if r == pid
                    || (r < 0
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
                {
                    *pid_guard = None;
                    if self.owns_child {
                        ACTIVE_WATCHDOG_CHILDREN.fetch_sub(1, Ordering::AcqRel);
                    }
                    if let Some(lock_path) = &self.lock_file_path {
                        let _ = fs::remove_file(lock_path);
                    }
                }
            }
        }

        /// Golden ordering for `KeyDown`:
        /// Acquire `HidGate` -> check `Open` -> build snapshot -> write 56B `O_NONBLOCK` ->
        /// commit & return `Ok(())` ONLY on full write.
        pub fn before_key_down(
            &self,
            usage: u16,
            modifiers: u8,
            local_releaser: &dyn EmergencyKeyReleaser,
            on_degraded: Option<&DegradedCallback>,
        ) -> Result<(), OsError> {
            if usage >= 256 {
                return Err(OsError::InvalidData(format!(
                    "USB HID usage {usage:#x} outside 0..255 watchdog bitmap"
                )));
            }
            let degraded_reason: Option<String>;
            let err_to_return: OsError;
            let mut is_broken = false;
            {
                let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
                if g.phase != HidGatePhase::Open {
                    return Err(OsError::Interlocked);
                }
                let Some(fd) = g.cmd_write_fd else {
                    g.phase = HidGatePhase::Closed;
                    return Err(OsError::Interlocked);
                };
                let mut next_bitmap = g.keys_bitmap;
                bitmap_set_key(&mut next_bitmap, usage);
                let next_seq = g.next_seq.saturating_add(1);
                let frame =
                    WatchdogFrame::state_snapshot(next_seq, next_bitmap, g.buttons, modifiers)
                        .encode();

                match write_frame_nonblock(fd, &frame) {
                    PipeWriteResult::Ok => {
                        g.keys_bitmap = next_bitmap;
                        g.mods = modifiers;
                        g.next_seq = next_seq;
                        g.consecutive_eagain_failures = 0;
                        return Ok(());
                    }
                    PipeWriteResult::WouldBlock => {
                        g.consecutive_eagain_failures =
                            g.consecutive_eagain_failures.saturating_add(1);
                        g.keys_bitmap = [0u8; 32];
                        g.buttons = 0;
                        g.mods = 0;
                        let count = g.consecutive_eagain_failures;
                        let closed_now = count >= MAX_CONSECUTIVE_EAGAIN_FAILURES;
                        if closed_now {
                            g.phase = HidGatePhase::Closed;
                            if let Some(wfd) = g.cmd_write_fd.take() {
                                close_fd(wfd);
                            }
                        }
                        degraded_reason = Some(format!(
                            "HID watchdog pipe full (EAGAIN {count}/{MAX_CONSECUTIVE_EAGAIN_FAILURES}{})",
                            if closed_now { ", permanently closed" } else { "" }
                        ));
                        err_to_return = if closed_now {
                            OsError::Interlocked
                        } else {
                            OsError::CaptureFailed("HID watchdog pipe full (EAGAIN)".into())
                        };
                    }
                    PipeWriteResult::Broken(msg) => {
                        g.phase = HidGatePhase::Closed;
                        g.keys_bitmap = [0u8; 32];
                        g.buttons = 0;
                        g.mods = 0;
                        if let Some(wfd) = g.cmd_write_fd.take() {
                            close_fd(wfd);
                        }
                        is_broken = true;
                        degraded_reason = Some(msg);
                        err_to_return = OsError::Interlocked;
                    }
                }
            }
            // Drop HidGate lock BEFORE calling local_releaser or degraded callback.
            let _ = local_releaser.release_all_keys();
            if is_broken {
                self.try_reap_dead_child_nonblock();
            }
            if let (Some(cb), Some(reason)) = (on_degraded, degraded_reason) {
                cb(reason);
            }
            Err(err_to_return)
        }

        /// Golden ordering for `KeyUp`: called AFTER injecting into `OsHidSink`.
        pub fn after_key_up(
            &self,
            usage: u16,
            modifiers: u8,
            local_releaser: &dyn EmergencyKeyReleaser,
            on_degraded: Option<&DegradedCallback>,
        ) {
            if usage >= 256 {
                return;
            }
            let broken_reason: Option<String> = {
                let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
                if g.phase != HidGatePhase::Open {
                    return;
                }
                let Some(fd) = g.cmd_write_fd else {
                    g.phase = HidGatePhase::Closed;
                    return;
                };
                bitmap_clear_key(&mut g.keys_bitmap, usage);
                g.mods = modifiers;
                g.next_seq = g.next_seq.saturating_add(1);
                let frame = WatchdogFrame::state_snapshot(
                    g.next_seq,
                    g.keys_bitmap,
                    g.buttons,
                    g.mods,
                )
                .encode();
                match write_frame_nonblock(fd, &frame) {
                    PipeWriteResult::Ok => {
                        g.consecutive_eagain_failures = 0;
                        None
                    }
                    PipeWriteResult::WouldBlock => {
                        // Safe direction on release: watchdog merely over-estimates held keys.
                        None
                    }
                    PipeWriteResult::Broken(msg) => {
                        g.phase = HidGatePhase::Closed;
                        g.keys_bitmap = [0u8; 32];
                        g.buttons = 0;
                        g.mods = 0;
                        if let Some(wfd) = g.cmd_write_fd.take() {
                            close_fd(wfd);
                        }
                        Some(msg)
                    }
                }
            };
            if let Some(reason) = broken_reason {
                let _ = local_releaser.release_all_keys();
                self.try_reap_dead_child_nonblock();
                if let Some(cb) = on_degraded {
                    cb(reason);
                }
            }
        }

        /// Golden ordering for `MouseDown`: write snapshot BEFORE injecting into `OsHidSink`.
        pub fn before_mouse_down(
            &self,
            buttons_mask: u8,
            local_releaser: &dyn EmergencyKeyReleaser,
            on_degraded: Option<&DegradedCallback>,
        ) -> Result<(), OsError> {
            let masked = buttons_mask & 0x1F;
            let degraded_reason: Option<String>;
            let err_to_return: OsError;
            let mut is_broken = false;
            {
                let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
                if g.phase != HidGatePhase::Open {
                    return Err(OsError::Interlocked);
                }
                let Some(fd) = g.cmd_write_fd else {
                    g.phase = HidGatePhase::Closed;
                    return Err(OsError::Interlocked);
                };
                let next_buttons = g.buttons | masked;
                let next_seq = g.next_seq.saturating_add(1);
                let frame = WatchdogFrame::state_snapshot(
                    next_seq,
                    g.keys_bitmap,
                    next_buttons,
                    g.mods,
                )
                .encode();
                match write_frame_nonblock(fd, &frame) {
                    PipeWriteResult::Ok => {
                        g.buttons = next_buttons;
                        g.next_seq = next_seq;
                        g.consecutive_eagain_failures = 0;
                        return Ok(());
                    }
                    PipeWriteResult::WouldBlock => {
                        g.consecutive_eagain_failures =
                            g.consecutive_eagain_failures.saturating_add(1);
                        g.keys_bitmap = [0u8; 32];
                        g.buttons = 0;
                        g.mods = 0;
                        let count = g.consecutive_eagain_failures;
                        let closed_now = count >= MAX_CONSECUTIVE_EAGAIN_FAILURES;
                        if closed_now {
                            g.phase = HidGatePhase::Closed;
                            if let Some(wfd) = g.cmd_write_fd.take() {
                                close_fd(wfd);
                            }
                        }
                        degraded_reason = Some(format!(
                            "HID watchdog pipe full on MouseDown (EAGAIN {count}/{MAX_CONSECUTIVE_EAGAIN_FAILURES}{})",
                            if closed_now { ", permanently closed" } else { "" }
                        ));
                        err_to_return = if closed_now {
                            OsError::Interlocked
                        } else {
                            OsError::CaptureFailed("HID watchdog pipe full (EAGAIN)".into())
                        };
                    }
                    PipeWriteResult::Broken(msg) => {
                        g.phase = HidGatePhase::Closed;
                        g.keys_bitmap = [0u8; 32];
                        g.buttons = 0;
                        g.mods = 0;
                        if let Some(wfd) = g.cmd_write_fd.take() {
                            close_fd(wfd);
                        }
                        is_broken = true;
                        degraded_reason = Some(msg);
                        err_to_return = OsError::Interlocked;
                    }
                }
            }
            let _ = local_releaser.release_all_keys();
            if is_broken {
                self.try_reap_dead_child_nonblock();
            }
            if let (Some(cb), Some(reason)) = (on_degraded, degraded_reason) {
                cb(reason);
            }
            Err(err_to_return)
        }

        /// Golden ordering for `MouseUp`: called AFTER injecting into `OsHidSink`.
        pub fn after_mouse_up(
            &self,
            buttons_mask: u8,
            local_releaser: &dyn EmergencyKeyReleaser,
            on_degraded: Option<&DegradedCallback>,
        ) {
            let masked = buttons_mask & 0x1F;
            let broken_reason: Option<String> = {
                let mut g = self.gate.lock().unwrap_or_else(|e| e.into_inner());
                if g.phase != HidGatePhase::Open {
                    return;
                }
                let Some(fd) = g.cmd_write_fd else {
                    g.phase = HidGatePhase::Closed;
                    return;
                };
                g.buttons &= !masked;
                g.next_seq = g.next_seq.saturating_add(1);
                let frame = WatchdogFrame::state_snapshot(
                    g.next_seq,
                    g.keys_bitmap,
                    g.buttons,
                    g.mods,
                )
                .encode();
                match write_frame_nonblock(fd, &frame) {
                    PipeWriteResult::Ok => {
                        g.consecutive_eagain_failures = 0;
                        None
                    }
                    PipeWriteResult::WouldBlock => None,
                    PipeWriteResult::Broken(msg) => {
                        g.phase = HidGatePhase::Closed;
                        g.keys_bitmap = [0u8; 32];
                        g.buttons = 0;
                        g.mods = 0;
                        if let Some(wfd) = g.cmd_write_fd.take() {
                            close_fd(wfd);
                        }
                        Some(msg)
                    }
                }
            };
            if let Some(reason) = broken_reason {
                let _ = local_releaser.release_all_keys();
                self.try_reap_dead_child_nonblock();
                if let Some(cb) = on_degraded {
                    cb(reason);
                }
            }
        }

        /// Graceful teardown:
        /// `Open -> Quiescing` -> release all local keys -> send `GracefulExit` -> close
        /// `cmd_write_fd` -> `waitpid` with bounded 2s timeout (escalating to `SIGKILL` + reap
        /// on timeout so zero zombies remain) -> `Closed`.
        ///
        /// Always closes pipes, reaps any spawned child process, and decrements
        /// `ACTIVE_WATCHDOG_CHILDREN` even if `HidGate` already transitioned to `Closed`
        /// via `EPIPE` or repeated `EAGAIN` (idempotent via `.take()`).
        pub fn shutdown(&self, local_releaser: Option<&dyn EmergencyKeyReleaser>) {
            self.watchdog_ax_trusted.store(false, Ordering::Release);
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
                if let Some(fd) = g.cmd_write_fd.take() {
                    if was_open {
                        g.next_seq = g.next_seq.saturating_add(1);
                        let exit_frame = WatchdogFrame::graceful_exit(g.next_seq).encode();
                        let _ = write_frame_nonblock(fd, &exit_frame);
                    }
                    close_fd(fd);
                }
                g.keys_bitmap = [0u8; 32];
                g.buttons = 0;
                g.mods = 0;
                g.phase = HidGatePhase::Closed;
            }

            if let Some(fd) = self
                .ack_read
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .fd
                .take()
            {
                close_fd(fd);
            }

            if let Some(pid) = self
                .child_pid
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                reap_child_bounded(pid, self.shutdown_timeout);
                if self.owns_child {
                    ACTIVE_WATCHDOG_CHILDREN.fetch_sub(1, Ordering::AcqRel);
                }
            }

            if let Some(lock_path) = &self.lock_file_path {
                let _ = fs::remove_file(lock_path);
            }
        }
    }

    impl Drop for HidWatchdogSupervisor {
        fn drop(&mut self) {
            self.shutdown(None);
        }
    }
}

#[cfg(not(unix))]
mod non_unix_stub {
    use super::*;

    pub fn verify_watchdog_binary(_path: &Path) -> Result<(), OsError> {
        Err(OsError::UnsupportedPlatform(
            "independent HID watchdog subprocess only supported on Unix",
        ))
    }

    pub struct HidWatchdogSupervisor;

    impl HidWatchdogSupervisor {
        pub fn spawn(_cfg: HidWatchdogConfig) -> Result<Self, OsError> {
            Err(OsError::UnsupportedPlatform(
                "independent HID watchdog subprocess only supported on Unix",
            ))
        }

        pub fn child_pid(&self) -> Option<u32> {
            None
        }

        pub fn phase(&self) -> HidGatePhase {
            HidGatePhase::Closed
        }

        pub fn consecutive_eagain_failures(&self) -> u32 {
            0
        }

        pub fn is_open(&self) -> bool {
            false
        }

        pub fn accessibility_trusted(&self) -> bool {
            false
        }

        pub fn accessibility_trusted_flag(&self) -> Arc<std::sync::atomic::AtomicBool> {
            Arc::new(std::sync::atomic::AtomicBool::new(false))
        }

        pub fn poll_ax_status(&self) {}

        pub fn before_key_down(
            &self,
            _usage: u16,
            _modifiers: u8,
            _local_releaser: &dyn EmergencyKeyReleaser,
            _on_degraded: Option<&DegradedCallback>,
        ) -> Result<(), OsError> {
            Err(OsError::UnsupportedPlatform("non-unix"))
        }

        pub fn after_key_up(
            &self,
            _usage: u16,
            _modifiers: u8,
            _local_releaser: &dyn EmergencyKeyReleaser,
            _on_degraded: Option<&DegradedCallback>,
        ) {
        }

        pub fn before_mouse_down(
            &self,
            _buttons_mask: u8,
            _local_releaser: &dyn EmergencyKeyReleaser,
            _on_degraded: Option<&DegradedCallback>,
        ) -> Result<(), OsError> {
            Err(OsError::UnsupportedPlatform("non-unix"))
        }

        pub fn after_mouse_up(
            &self,
            _buttons_mask: u8,
            _local_releaser: &dyn EmergencyKeyReleaser,
            _on_degraded: Option<&DegradedCallback>,
        ) {
        }

        pub fn shutdown(&self, _local_releaser: Option<&dyn EmergencyKeyReleaser>) {}
    }
}

#[cfg(unix)]
pub use unix_impl::{
    resolve_and_verify_watchdog_binary, verify_watchdog_binary, HidWatchdogSupervisor,
};
#[cfg(not(unix))]
pub use non_unix_stub::{verify_watchdog_binary, HidWatchdogSupervisor};

struct SupervisedEmergencyKeyReleaser {
    inner: Arc<dyn EmergencyKeyReleaser>,
    supervisor: Arc<HidWatchdogSupervisor>,
}

impl EmergencyKeyReleaser for SupervisedEmergencyKeyReleaser {
    fn release_all_keys(&self) -> ReleaseReport {
        // Quiesce & close HidGate FIRST so any concurrent send_key/send_mouse post-injection
        // check sees !is_open() immediately, then release local keys.
        self.supervisor.shutdown(None);
        self.inner.release_all_keys()
    }
}

/// `OsHidSink` decorator enforcing the `HidGate` golden ordering invariant with an attached
/// `HidWatchdogSupervisor` subprocess.
pub struct WatchdogSupervisedHidSink {
    inner: Box<dyn OsHidSink>,
    local_releaser: Arc<dyn EmergencyKeyReleaser>,
    supervisor: Arc<HidWatchdogSupervisor>,
    on_degraded: Option<DegradedCallback>,
}

impl WatchdogSupervisedHidSink {
    pub fn new(
        inner: Box<dyn OsHidSink>,
        supervisor: Arc<HidWatchdogSupervisor>,
        on_degraded: Option<DegradedCallback>,
    ) -> Self {
        let local_releaser = inner.emergency_releaser();
        Self {
            inner,
            local_releaser,
            supervisor,
            on_degraded,
        }
    }

    pub fn supervisor(&self) -> &Arc<HidWatchdogSupervisor> {
        &self.supervisor
    }
}

impl Drop for WatchdogSupervisedHidSink {
    fn drop(&mut self) {
        self.supervisor.shutdown(Some(self.local_releaser.as_ref()));
    }
}

impl OsHidSink for WatchdogSupervisedHidSink {
    fn send_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
        let Ok(usage) = u16::try_from(ev.usb_hid_usage) else {
            return Err(OsError::InvalidData(format!(
                "USB HID usage {:#x} exceeds u16 range",
                ev.usb_hid_usage
            )));
        };
        if ev.down {
            // Golden ordering: snapshot MUST reach watchdog pipe BEFORE injecting KeyDown.
            self.supervisor.before_key_down(
                usage,
                ev.modifiers,
                self.local_releaser.as_ref(),
                self.on_degraded.as_ref(),
            )?;
            let res = self.inner.send_key(ev);
            // Post-injection re-check: close microsecond race if concurrent shutdown/release
            // transitioned HidGate out of Open while `inner.send_key` was executing.
            if !self.supervisor.is_open() {
                let _ = self.local_releaser.release_all_keys();
                return Err(OsError::Interlocked);
            }
            res
        } else {
            // Golden ordering: inject KeyUp FIRST, then update watchdog snapshot.
            let res = self.inner.send_key(ev);
            if res.is_ok() {
                self.supervisor.after_key_up(
                    usage,
                    ev.modifiers,
                    self.local_releaser.as_ref(),
                    self.on_degraded.as_ref(),
                );
            }
            res
        }
    }

    fn send_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError> {
        match ev.kind {
            MouseKind::Down => {
                self.supervisor.before_mouse_down(
                    ev.buttons,
                    self.local_releaser.as_ref(),
                    self.on_degraded.as_ref(),
                )?;
                let res = self.inner.send_mouse(ev);
                if !self.supervisor.is_open() {
                    let _ = self.local_releaser.release_all_keys();
                    return Err(OsError::Interlocked);
                }
                res
            }
            MouseKind::Up => {
                let res = self.inner.send_mouse(ev);
                if res.is_ok() {
                    self.supervisor.after_mouse_up(
                        ev.buttons,
                        self.local_releaser.as_ref(),
                        self.on_degraded.as_ref(),
                    );
                }
                res
            }
            MouseKind::MoveAbs | MouseKind::MoveRel | MouseKind::Wheel => {
                if !self.supervisor.is_open() {
                    return Err(OsError::Interlocked);
                }
                self.inner.send_mouse(ev)
            }
        }
    }

    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
        Arc::new(SupervisedEmergencyKeyReleaser {
            inner: Arc::clone(&self.local_releaser),
            supervisor: Arc::clone(&self.supervisor),
        })
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::{fs::PermissionsExt, net::UnixDatagram},
        sync::Mutex,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn unique_tmp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-wd-sup-{tag}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn verify_watchdog_binary_rejects_symlinks_and_world_writable_files() {
        let dir = unique_tmp_dir("verify");
        let good = dir.join("wd-bin");
        fs::write(&good, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&good, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(verify_watchdog_binary(&good).is_ok());

        // Group/world-writable MUST fail closed.
        let writable = dir.join("wd-writable");
        fs::write(&writable, b"#!/bin/sh\n").unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(verify_watchdog_binary(&writable).is_err());

        // Symlink MUST fail closed via lstat.
        let link = dir.join("wd-symlink");
        std::os::unix::fs::symlink(&good, &link).unwrap();
        assert!(verify_watchdog_binary(&link).is_err());

        // Non-regular file (socket) MUST fail closed.
        let sock = dir.join("wd-sock");
        let _s = UnixDatagram::bind(&sock).unwrap();
        assert!(verify_watchdog_binary(&sock).is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn post_injection_gate_recheck_releases_key_on_concurrent_shutdown_race() {
        use std::sync::atomic::AtomicUsize;

        struct RacingState {
            held: Mutex<Vec<u16>>,
            release_calls: AtomicUsize,
        }

        struct RacingReleaser {
            state: Arc<RacingState>,
        }

        impl EmergencyKeyReleaser for RacingReleaser {
            fn release_all_keys(&self) -> ReleaseReport {
                self.state.release_calls.fetch_add(1, Ordering::AcqRel);
                let mut held = self.state.held.lock().unwrap();
                let count = held.len();
                held.clear();
                ReleaseReport {
                    released_keys: count,
                    released_buttons: 0,
                    residual_keys: 0,
                    residual_buttons: 0,
                }
            }
        }

        struct RacingHidSink {
            state: Arc<RacingState>,
            supervised_releaser: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>>,
        }

        impl OsHidSink for RacingHidSink {
            fn send_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
                // Simulate concurrent emergency_releaser().release_all_keys() from another thread
                // running right BEFORE this KeyDown lands in the inner sink!
                if let Some(rel) = self.supervised_releaser.lock().unwrap().clone() {
                    let h = std::thread::spawn(move || {
                        let _ = rel.release_all_keys();
                    });
                    h.join().unwrap();
                }
                if ev.down {
                    self.state.held.lock().unwrap().push(ev.usb_hid_usage as u16);
                }
                Ok(())
            }

            fn send_mouse(&mut self, _ev: &MouseEvent) -> Result<(), OsError> {
                Ok(())
            }

            fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
                Arc::new(RacingReleaser {
                    state: Arc::clone(&self.state),
                })
            }
        }

        let mut fds = [-1i32; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = fds[0];
        let write_fd = fds[1];
        struct ReadGuard(i32);
        impl Drop for ReadGuard {
            fn drop(&mut self) {
                unsafe {
                    libc::close(self.0);
                }
            }
        }
        let _r = ReadGuard(read_fd);

        let sup = Arc::new(HidWatchdogSupervisor::from_raw_pipe_fd(write_fd).unwrap());
        let state = Arc::new(RacingState {
            held: Mutex::new(Vec::new()),
            release_calls: AtomicUsize::new(0),
        });
        let rel_slot: Arc<Mutex<Option<Arc<dyn EmergencyKeyReleaser>>>> =
            Arc::new(Mutex::new(None));
        let mut sink = WatchdogSupervisedHidSink::new(
            Box::new(RacingHidSink {
                state: Arc::clone(&state),
                supervised_releaser: Arc::clone(&rel_slot),
            }),
            Arc::clone(&sup),
            None,
        );
        *rel_slot.lock().unwrap() = Some(sink.emergency_releaser());

        let res = sink.send_key(&KeyEvent {
            down: true,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 0,
            client_ts_ms: 1,
        });
        assert_eq!(res, Err(OsError::Interlocked));
        assert!(
            state.held.lock().unwrap().is_empty(),
            "post-injection re-check MUST release key pressed during concurrent shutdown race"
        );
        assert!(
            state.release_calls.load(Ordering::Acquire) >= 2,
            "both concurrent emergency release and post-injection re-check release must have run"
        );
    }
}
