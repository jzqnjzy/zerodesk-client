// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Real-OS integration tests for `zerodesk-hid-watchdog` and `HidWatchdogSupervisor`:
//! 1. Real `SIGKILL` (`kill -9`) of mock Host holding normal + modifier keys
//! 2. Process-group `SIGKILL` (`kill -9 -pgid`) verifying `setsid()` immunity
//! 3. Leaked write-end fd via `SCM_RIGHTS` verifying macOS `kqueue EVFILT_PROC NOTE_EXIT`
//! 4. Pipe full (`EAGAIN`) verifying no injection, local release, degraded event, permanent close after 5 failures
//! 5. External watchdog `SIGKILL` (`EPIPE`) verifying fail-closed & local release
//! 6. Malformed frame (bad CRC) verifying immediate emergency release & exit
//! 7. 100x start/stop stress test verifying zero zombies / leftover watchdog processes

#![cfg(unix)]

use std::{
    fs,
    io::{BufRead, BufReader},
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
        prelude::{AsRawFd, RawFd},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use zerodesk_core::{
    os::{
        dryrun::{DryRunHidJournal, DryRunHidSink},
        watchdog_proto::{
            WatchdogFrame, WatchdogReleaseReport, ALL_MODIFIER_HID_USAGES, WATCHDOG_FRAME_LEN,
            WATCHDOG_REPORT_SCHEMA_VERSION,
        },
        watchdog_supervisor::{
            active_watchdog_children, HidGatePhase, HidWatchdogConfig, HidWatchdogSupervisor,
            WatchdogSupervisedHidSink, MAX_CONSECUTIVE_EAGAIN_FAILURES,
        },
        OsError, OsHidSink,
    },
    session::hid::{KeyEvent, MouseEvent, MouseKind, MOD_CTRL, MOD_META, MOD_SHIFT},
};

const WATCHDOG_BIN: &str = env!("CARGO_BIN_EXE_zerodesk-hid-watchdog");

/// Serializes in-process watchdog spawn tests (tests 5, 6, 7) so `active_watchdog_children()`
/// assertions never race with a sibling test's live child inside the same test runner process.
static IN_PROCESS_WD_LOCK: Mutex<()> = Mutex::new(());

struct TempDirGuard(PathBuf);

impl TempDirGuard {
    fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "zd-wd-sigkill-{tag}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// RAII cleanup guard ensuring spawned child processes and any tracked watchdog PIDs are
/// always killed and reaped even if an assertion panics.
struct ChildCleanupGuard {
    child: Option<Child>,
    extra_pids: Vec<i32>,
}

impl ChildCleanupGuard {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            extra_pids: Vec::new(),
        }
    }

    fn track_pid(&mut self, pid: i32) {
        if pid > 0 {
            self.extra_pids.push(pid);
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().unwrap()
    }

    fn pid(&self) -> i32 {
        self.child.as_ref().unwrap().id() as i32
    }

    fn reap(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.wait();
        }
    }
}

impl Drop for ChildCleanupGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        for &pid in &self.extra_pids {
            unsafe {
                let _ = libc::kill(pid, libc::SIGKILL);
            }
        }
    }
}

fn key_ev(usage: u32, down: bool, modifiers: u8) -> KeyEvent {
    KeyEvent {
        down,
        modifiers,
        usb_hid_usage: usage,
        unicode_scalar: 0,
        client_ts_ms: 1,
    }
}

fn wait_for_report(path: &Path, timeout: Duration) -> (WatchdogReleaseReport, Duration) {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(bytes) = fs::read(path) {
            if let Ok(report) = serde_json::from_slice::<WatchdogReleaseReport>(&bytes) {
                return (report, start.elapsed());
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    panic!(
        "timed out after {:?} waiting for watchdog release report at {}",
        timeout,
        path.display()
    );
}

fn wait_pid_gone(pid: i32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let rc = unsafe { libc::kill(pid, 0) };
        if rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let rc = unsafe { libc::kill(pid, 0) };
    rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

fn assert_file_mode_0600(path: &Path) {
    let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "expected 0600 mode on {}", path.display());
}

fn send_fd_over_unix(sock: &UnixStream, fd: RawFd) {
    let mut data = [0x42u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut ctrl = vec![0u8; cmsg_space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null());
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const RawFd as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<RawFd>(),
        );
        let n = libc::sendmsg(sock.as_raw_fd(), &msg, 0);
        assert!(n > 0, "sendmsg(SCM_RIGHTS) failed: {}", std::io::Error::last_os_error());
    }
}

fn recv_fd_over_unix(sock: &UnixStream) -> RawFd {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    let cmsg_space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) } as usize;
    let mut ctrl = vec![0u8; cmsg_space];
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = ctrl.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cmsg_space as _;

    unsafe {
        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, 0);
        assert!(n > 0, "recvmsg(SCM_RIGHTS) failed: {}", std::io::Error::last_os_error());
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null());
        assert_eq!((*cmsg).cmsg_level, libc::SOL_SOCKET);
        assert_eq!((*cmsg).cmsg_type, libc::SCM_RIGHTS);
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(
            libc::CMSG_DATA(cmsg),
            &mut fd as *mut RawFd as *mut u8,
            std::mem::size_of::<RawFd>(),
        );
        assert!(fd >= 0);
        fd
    }
}

fn spawn_mock_host(mode: &str, report_path: &Path, sock_path: Option<&Path>, new_pgid: bool) -> (ChildCleanupGuard, i32) {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", "mock_host_child_entrypoint", "--nocapture"])
        .env("ZD_MOCK_HOST_MODE", mode)
        .env("ZD_MOCK_HOST_REPORT", report_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    if let Some(sp) = sock_path {
        cmd.env("ZD_MOCK_HOST_SOCK", sp);
    }
    if new_pgid {
        unsafe {
            cmd.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let child = cmd.spawn().expect("spawn mock host child");
    let mut guard = ChildCleanupGuard::new(child);
    let stdout = guard.child_mut().stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let wd_pid = loop {
        assert!(
            Instant::now() < deadline,
            "timed out waiting for mock host READY line"
        );
        line.clear();
        let n = reader.read_line(&mut line).unwrap();
        assert!(n > 0, "mock host exited before printing READY");
        if let Some(rest) = line.trim().strip_prefix("ZD_MOCK_READY ") {
            break rest.parse::<i32>().unwrap();
        }
    };
    guard.track_pid(wd_pid);
    (guard, wd_pid)
}

/// Helper entrypoint executed in child processes spawned by tests 1, 2, and 3.
/// Returns immediately when `ZD_MOCK_HOST_MODE` is not set.
#[test]
fn mock_host_child_entrypoint() {
    let Ok(mode) = std::env::var("ZD_MOCK_HOST_MODE") else {
        return;
    };
    let report_path = PathBuf::from(std::env::var("ZD_MOCK_HOST_REPORT").unwrap());
    let sup = Arc::new(
        HidWatchdogSupervisor::spawn(HidWatchdogConfig {
            binary_path: Some(PathBuf::from(WATCHDOG_BIN)),
            dry_run_report_path: Some(report_path),
            ..HidWatchdogConfig::default()
        })
        .expect("mock host failed to spawn watchdog"),
    );
    let wd_pid = sup.child_pid().expect("watchdog pid");
    let mut sink = WatchdogSupervisedHidSink::new(Box::new(DryRunHidSink::new()), Arc::clone(&sup), None);

    match mode.as_str() {
        "sigkill_basic" => {
            sink.send_key(&key_ev(0x04, true, 0)).unwrap(); // A
            sink.send_key(&key_ev(0x05, true, 0)).unwrap(); // B
            sink.send_key(&key_ev(0xE3, true, MOD_META)).unwrap(); // LeftMeta
            sink.send_mouse(&MouseEvent {
                kind: MouseKind::Down,
                buttons: 0x01,
                x_or_dx: 0,
                y_or_dy: 0,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: 1,
            })
            .unwrap();
        }
        "sigkill_pgid" => {
            sink.send_key(&key_ev(0x06, true, 0)).unwrap(); // C
            sink.send_key(&key_ev(0xE1, true, MOD_SHIFT)).unwrap(); // LeftShift
        }
        "sigkill_leaked_fd" => {
            sink.send_key(&key_ev(0x07, true, 0)).unwrap(); // D
            sink.send_key(&key_ev(0xE0, true, MOD_CTRL)).unwrap(); // LeftCtrl
            let sock_path = std::env::var("ZD_MOCK_HOST_SOCK").unwrap();
            let stream = UnixStream::connect(&sock_path).expect("connect scm_rights sock");
            let cmd_fd = sup.cmd_write_fd().expect("cmd_write_fd");
            send_fd_over_unix(&stream, cmd_fd);
        }
        other => panic!("unknown mock host mode: {other}"),
    }

    println!("ZD_MOCK_READY {wd_pid}");
    // Keep supervisor alive and wait to be terminated by SIGKILL.
    loop {
        thread::sleep(Duration::from_secs(60));
    }
}

#[test]
fn test1_real_sigkill_releases_held_keys_and_modifiers_under_1s() {
    let tmp = TempDirGuard::new("t1");
    let report_path = tmp.path().join("release-report.json");
    let (mut host, wd_pid) = spawn_mock_host("sigkill_basic", &report_path, None, false);
    let host_pid = host.pid();

    let kill_at = Instant::now();
    unsafe {
        assert_eq!(libc::kill(host_pid, libc::SIGKILL), 0);
    }
    host.reap();

    let (report, observed_elapsed) = wait_for_report(&report_path, Duration::from_millis(1000));
    eprintln!(
        "[SIGKILL basic] observed_ms={} report.release_elapsed_ms={} trigger={}",
        observed_elapsed.as_millis(),
        report.release_elapsed_ms,
        report.trigger
    );
    assert_file_mode_0600(&report_path);
    assert_eq!(report.schema_version, WATCHDOG_REPORT_SCHEMA_VERSION);
    assert!(report.release_ok);
    assert!(report.release_error.is_none());
    assert!(
        report.trigger == "pipe_eof" || report.trigger == "parent_exit_kqueue",
        "unexpected trigger: {}",
        report.trigger
    );
    assert_eq!(report.parent_pid, host_pid as u32);
    assert_eq!(report.released_keys, vec![0x04, 0x05, 0xE3]);
    assert_eq!(report.released_buttons, 0x01);
    assert_eq!(report.released_modifiers, ALL_MODIFIER_HID_USAGES.to_vec());
    assert!(
        kill_at.elapsed() <= Duration::from_millis(1000),
        "SIGKILL release exceeded 1000ms budget"
    );
    assert!(
        wait_pid_gone(wd_pid, Duration::from_secs(2)),
        "watchdog process {wd_pid} did not exit cleanly"
    );
}

#[test]
fn test2_process_group_sigkill_setsid_immunity_still_releases() {
    let tmp = TempDirGuard::new("t2");
    let report_path = tmp.path().join("pgid-report.json");
    let (mut host, wd_pid) = spawn_mock_host("sigkill_pgid", &report_path, None, true);
    let host_pid = host.pid();

    // Send SIGKILL to the ENTIRE process group `-pgid`!
    unsafe {
        assert_eq!(libc::kill(-host_pid, libc::SIGKILL), 0);
    }
    host.reap();

    let (report, observed_elapsed) = wait_for_report(&report_path, Duration::from_millis(1000));
    eprintln!(
        "[SIGKILL -pgid] observed_ms={} report.release_elapsed_ms={} trigger={}",
        observed_elapsed.as_millis(),
        report.release_elapsed_ms,
        report.trigger
    );
    assert_file_mode_0600(&report_path);
    assert_eq!(report.schema_version, WATCHDOG_REPORT_SCHEMA_VERSION);
    assert_eq!(report.released_keys, vec![0x06, 0xE1]);
    assert_eq!(report.released_modifiers, ALL_MODIFIER_HID_USAGES.to_vec());
    assert!(
        wait_pid_gone(wd_pid, Duration::from_secs(2)),
        "watchdog process {wd_pid} did not exit cleanly"
    );
}

#[test]
fn test3_leaked_write_fd_kqueue_note_exit_still_releases() {
    let tmp = TempDirGuard::new("t3");
    let report_path = tmp.path().join("leaked-fd-report.json");
    let sock_path = tmp.path().join("fd-leak.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();

    let (mut host, wd_pid) =
        spawn_mock_host("sigkill_leaked_fd", &report_path, Some(&sock_path), false);
    let host_pid = host.pid();

    // Accept the leaked write-end fd and intentionally KEEP IT OPEN across host SIGKILL!
    let (stream, _) = listener.accept().unwrap();
    let leaked_write_fd = recv_fd_over_unix(&stream);
    struct FdCloseGuard(RawFd);
    impl Drop for FdCloseGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let _leaked_guard = FdCloseGuard(leaked_write_fd);

    unsafe {
        assert_eq!(libc::kill(host_pid, libc::SIGKILL), 0);
    }
    host.reap();

    let (report, observed_elapsed) = wait_for_report(&report_path, Duration::from_millis(1000));
    eprintln!(
        "[SIGKILL leaked-fd] observed_ms={} report.release_elapsed_ms={} trigger={}",
        observed_elapsed.as_millis(),
        report.release_elapsed_ms,
        report.trigger
    );
    assert_file_mode_0600(&report_path);
    assert_eq!(report.schema_version, WATCHDOG_REPORT_SCHEMA_VERSION);
    assert_eq!(report.trigger, "parent_exit_kqueue");
    assert_eq!(report.released_keys, vec![0x07, 0xE0]);
    assert_eq!(report.released_modifiers, ALL_MODIFIER_HID_USAGES.to_vec());
    assert!(
        wait_pid_gone(wd_pid, Duration::from_secs(2)),
        "watchdog process {wd_pid} did not exit cleanly"
    );
}

#[test]
fn test4_pipe_full_eagain_blocks_injection_releases_local_and_closes_after_5() {
    let mut fds = [-1i32; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let read_fd = fds[0];
    let write_fd = fds[1];
    struct ReadFdGuard(i32);
    impl Drop for ReadFdGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
            }
        }
    }
    let _read_guard = ReadFdGuard(read_fd);

    let sup = Arc::new(HidWatchdogSupervisor::from_raw_pipe_fd(write_fd).unwrap());
    let journal = DryRunHidJournal::new();
    let degraded_events: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let deg_c = Arc::clone(&degraded_events);
    let mut sink = WatchdogSupervisedHidSink::new(
        Box::new(DryRunHidSink::with_journal(journal.clone())),
        Arc::clone(&sup),
        Some(Arc::new(move |reason| {
            deg_c.lock().unwrap().push(reason);
        })),
    );

    // 1. While pipe has space, KeyDown(0x04) succeeds and is injected.
    sink.send_key(&key_ev(0x04, true, 0)).unwrap();
    assert_eq!(journal.pressed_keys(), vec![0x04]);

    // 2. Fill the pipe kernel buffer until O_NONBLOCK write returns EAGAIN.
    let fill_chunk = [0u8; 4096];
    let raw_w = sup.cmd_write_fd().unwrap();
    loop {
        let n = unsafe {
            libc::write(
                raw_w,
                fill_chunk.as_ptr() as *const libc::c_void,
                fill_chunk.len(),
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error().raw_os_error();
            if err == Some(libc::EAGAIN) {
                break;
            }
            panic!("unexpected pipe fill error: {err:?}");
        }
    }

    // 3. Failures 1..=4: MUST NOT inject 0x05, MUST locally release 0x04, MUST report degraded.
    for attempt in 1..MAX_CONSECUTIVE_EAGAIN_FAILURES {
        let res = sink.send_key(&key_ev(0x05, true, 0));
        assert!(res.is_err(), "attempt {attempt} must fail on EAGAIN");
        assert!(
            !journal.pressed_keys().contains(&0x05),
            "0x05 must NEVER be injected on EAGAIN"
        );
        assert!(
            !journal
                .entries()
                .iter()
                .any(|e| e.kind == "key_down" && e.key_usage == Some(0x05)),
            "journal event history must prove 0x05 key_down NEVER reached inner sink"
        );
        assert!(
            journal.is_all_released(),
            "local release_all_keys() must release prior held key 0x04"
        );
        assert_eq!(sup.consecutive_eagain_failures(), attempt);
        assert_eq!(sup.phase(), HidGatePhase::Open);
    }

    // 4. 5th consecutive EAGAIN permanently transitions HidGate to Closed and closes cmd_write_fd!
    let fifth = sink.send_key(&key_ev(0x05, true, 0));
    assert_eq!(fifth, Err(OsError::Interlocked));
    assert_eq!(sup.consecutive_eagain_failures(), MAX_CONSECUTIVE_EAGAIN_FAILURES);
    assert_eq!(sup.phase(), HidGatePhase::Closed);
    assert!(sup.cmd_write_fd().is_none(), "cmd_write_fd must be closed immediately on permanent EAGAIN");
    assert!(
        !journal
            .entries()
            .iter()
            .any(|e| e.kind == "key_down" && e.key_usage == Some(0x05)),
        "0x05 key_down must never appear in journal history"
    );
    assert_eq!(
        degraded_events.lock().unwrap().len(),
        MAX_CONSECUTIVE_EAGAIN_FAILURES as usize
    );

    // 5. Even after draining the pipe and resuming dry-run journal, gate stays permanently Closed.
    let mut drain = [0u8; 4096];
    unsafe {
        let fl = libc::fcntl(read_fd, libc::F_GETFL);
        libc::fcntl(read_fd, libc::F_SETFL, fl | libc::O_NONBLOCK);
        while libc::read(read_fd, drain.as_mut_ptr() as *mut libc::c_void, drain.len()) > 0 {}
    }
    journal.resume_for_new_session();
    assert_eq!(sink.send_key(&key_ev(0x06, true, 0)), Err(OsError::Interlocked));
    assert!(journal.pressed_keys().is_empty());
    assert!(
        !journal
            .entries()
            .iter()
            .any(|e| e.kind == "key_down" && e.key_usage == Some(0x06)),
        "0x06 key_down must never reach inner sink after permanent close"
    );
}

#[test]
fn test5_external_watchdog_kill_epipe_triggers_local_release_and_fail_closed() {
    let _serial = IN_PROCESS_WD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDirGuard::new("t5");
    let sup = Arc::new(
        HidWatchdogSupervisor::spawn(HidWatchdogConfig {
            binary_path: Some(PathBuf::from(WATCHDOG_BIN)),
            dry_run_report_path: Some(tmp.path().join("epipe-report.json")),
            ..HidWatchdogConfig::default()
        })
        .unwrap(),
    );
    let wd_pid = sup.child_pid().unwrap() as i32;

    // P1-3: verify FD_CLOEXEC is set on parent's cmd_write_fd!
    let raw_w = sup.cmd_write_fd().unwrap();
    let fd_flags = unsafe { libc::fcntl(raw_w, libc::F_GETFD) };
    assert!(fd_flags >= 0, "fcntl(F_GETFD) on cmd_write_fd failed");
    assert_ne!(
        fd_flags & libc::FD_CLOEXEC,
        0,
        "cmd_write_fd MUST have FD_CLOEXEC set"
    );

    let journal = DryRunHidJournal::new();
    let degraded_count = Arc::new(AtomicUsize::new(0));
    let deg_c = Arc::clone(&degraded_count);
    let mut sink = WatchdogSupervisedHidSink::new(
        Box::new(DryRunHidSink::with_journal(journal.clone())),
        Arc::clone(&sup),
        Some(Arc::new(move |_| {
            deg_c.fetch_add(1, Ordering::AcqRel);
        })),
    );

    sink.send_key(&key_ev(0x08, true, 0)).unwrap();
    assert_eq!(journal.pressed_keys(), vec![0x08]);

    // Kill the watchdog externally with SIGKILL!
    unsafe {
        assert_eq!(libc::kill(wd_pid, libc::SIGKILL), 0);
    }

    // Wait briefly for the kernel to close the dead watchdog's pipe read end (POLLERR on write fd).
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        let mut pfd = libc::pollfd {
            fd: raw_w,
            events: libc::POLLOUT,
            revents: 0,
        };
        let rc = unsafe { libc::poll(&mut pfd, 1, 20) };
        if rc > 0 && (pfd.revents & (libc::POLLERR | libc::POLLHUP)) != 0 {
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }

    // P1-2: on macOS, temporarily restore SIGPIPE to SIG_DFL across the broken-pipe write to
    // genuinely prove F_SETNOSIGPIPE prevents SIGPIPE termination!
    #[cfg(target_os = "macos")]
    struct SigpipeRestoreGuard(libc::sighandler_t);
    #[cfg(target_os = "macos")]
    impl Drop for SigpipeRestoreGuard {
        fn drop(&mut self) {
            unsafe {
                libc::signal(libc::SIGPIPE, self.0);
            }
        }
    }
    #[cfg(target_os = "macos")]
    let _sigpipe_guard = {
        let prev = unsafe { libc::signal(libc::SIGPIPE, libc::SIG_DFL) };
        SigpipeRestoreGuard(prev)
    };

    let err = sink.send_key(&key_ev(0x09, true, 0)).unwrap_err();
    #[cfg(target_os = "macos")]
    drop(_sigpipe_guard);

    assert_eq!(err, OsError::Interlocked);
    assert!(journal.is_all_released());
    assert!(!journal.pressed_keys().contains(&0x09));
    // P1-1: verify journal event history proves 0x09 NEVER reached inner sink!
    assert!(
        !journal
            .entries()
            .iter()
            .any(|e| e.kind == "key_down" && e.key_usage == Some(0x09)),
        "0x09 key_down must NEVER appear in journal history on EPIPE"
    );
    assert_eq!(sup.phase(), HidGatePhase::Closed);
    assert!(sup.cmd_write_fd().is_none(), "cmd_write_fd must be closed immediately on EPIPE");
    assert!(degraded_count.load(Ordering::Acquire) >= 1);

    drop(sink);
    drop(sup);
    assert!(wait_pid_gone(wd_pid, Duration::from_secs(2)));
}

#[test]
fn test6_malformed_frame_bad_crc_triggers_immediate_watchdog_release() {
    let _serial = IN_PROCESS_WD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDirGuard::new("t6");
    let report_path = tmp.path().join("malformed-report.json");
    let sup = Arc::new(
        HidWatchdogSupervisor::spawn(HidWatchdogConfig {
            binary_path: Some(PathBuf::from(WATCHDOG_BIN)),
            dry_run_report_path: Some(report_path.clone()),
            ..HidWatchdogConfig::default()
        })
        .unwrap(),
    );
    let wd_pid = sup.child_pid().unwrap() as i32;
    let mut sink = WatchdogSupervisedHidSink::new(Box::new(DryRunHidSink::new()), Arc::clone(&sup), None);

    sink.send_key(&key_ev(0x0A, true, 0)).unwrap(); // G
    sink.send_key(&key_ev(0xE2, true, 0)).unwrap(); // LeftAlt

    // Inject a 56-byte frame with corrupted CRC directly onto the watchdog pipe!
    let mut bad = WatchdogFrame::state_snapshot(999, [0u8; 32], 0, 0).encode();
    bad[WATCHDOG_FRAME_LEN - 1] ^= 0xFF;
    let raw_w = sup.cmd_write_fd().unwrap();
    let written = unsafe { libc::write(raw_w, bad.as_ptr() as *const libc::c_void, bad.len()) };
    assert_eq!(written, WATCHDOG_FRAME_LEN as isize);

    let (report, _) = wait_for_report(&report_path, Duration::from_millis(1000));
    assert_file_mode_0600(&report_path);
    assert_eq!(report.trigger, "malformed_frame");
    assert_eq!(report.released_keys, vec![0x0A, 0xE2]);
    assert_eq!(report.released_modifiers, ALL_MODIFIER_HID_USAGES.to_vec());

    drop(sink);
    drop(sup);
    assert!(wait_pid_gone(wd_pid, Duration::from_secs(2)));
}

#[test]
fn test7_stress_100x_start_stop_zero_zombies_zero_leftovers() {
    let _serial = IN_PROCESS_WD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let tmp = TempDirGuard::new("t7-100x");
    let mut spawned_pids = Vec::with_capacity(100);
    let report_path = tmp.path().join("should-not-exist-on-graceful-exit.json");

    for i in 0..100u32 {
        let sup = Arc::new(
            HidWatchdogSupervisor::spawn(HidWatchdogConfig {
                binary_path: Some(PathBuf::from(WATCHDOG_BIN)),
                dry_run_report_path: Some(report_path.clone()),
                ..HidWatchdogConfig::default()
            })
            .unwrap_or_else(|e| panic!("iteration {i} spawn failed: {e}")),
        );
        let wd_pid = sup.child_pid().unwrap() as i32;
        spawned_pids.push(wd_pid);
        let mut sink =
            WatchdogSupervisedHidSink::new(Box::new(DryRunHidSink::new()), Arc::clone(&sup), None);
        sink.send_key(&key_ev(0x04, true, 0)).unwrap();
        sink.send_key(&key_ev(0x04, false, 0)).unwrap();
        drop(sink);
        drop(sup);
    }

    assert_eq!(
        active_watchdog_children(),
        0,
        "active_watchdog_children must be 0 after 100x clean cycles"
    );
    assert!(
        !report_path.exists(),
        "graceful exits must NOT emit emergency release reports"
    );
    for pid in spawned_pids {
        assert!(
            wait_pid_gone(pid, Duration::from_millis(200)),
            "leftover/zombie watchdog pid {pid} detected"
        );
    }
}

#[test]
fn test8_spawn_rejects_missing_symlink_and_world_writable_binary() {
    let tmp = TempDirGuard::new("t8-fail-closed");

    // 1. Non-existent binary path -> must fail closed.
    let missing = tmp.path().join("does-not-exist-watchdog");
    assert!(HidWatchdogSupervisor::spawn(HidWatchdogConfig {
        binary_path: Some(missing),
        ..HidWatchdogConfig::default()
    })
    .is_err());

    // 2. Symlink pointing to the real watchdog binary -> must fail closed via lstat.
    let symlink_path = tmp.path().join("watchdog-symlink");
    std::os::unix::fs::symlink(WATCHDOG_BIN, &symlink_path).unwrap();
    assert!(HidWatchdogSupervisor::spawn(HidWatchdogConfig {
        binary_path: Some(symlink_path),
        ..HidWatchdogConfig::default()
    })
    .is_err());

    // 3. World-writable copy -> must fail closed.
    let writable_path = tmp.path().join("watchdog-0777");
    fs::copy(WATCHDOG_BIN, &writable_path).unwrap();
    fs::set_permissions(&writable_path, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(HidWatchdogSupervisor::spawn(HidWatchdogConfig {
        binary_path: Some(writable_path),
        ..HidWatchdogConfig::default()
    })
    .is_err());
}
