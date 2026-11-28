// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(target_os = "linux")]` independent HID watchdog supervisor &
//! kernel primitives:
//! - `O_CLOEXEC` pipes + `prctl(PR_SET_PDEATHSIG, SIGTERM)` followed immediately
//!   by `getppid() == expected_ppid` race verification;
//! - `pidfd_open(parent_pid, 0)` + immediate `getppid() == parent_pid` PID-reuse
//!   verification + `poll(pidfd)` (falling back to `FallbackLegacyProcStat` ONLY
//!   when `pidfd_open` returns `ENOSYS` on pre-5.3 kernels);
//! - `/proc/self/fd` descriptor leak audit & cleanup;
//! - Implements `HidWatchdogBackend` (`LinuxHidWatchdogBackend`).

#![cfg(target_os = "linux")]

use super::{
    linux_input::{
        execute_uinput_dual_layer_release, execute_xtest_release, linux_input_privilege_status,
        UinputVirtualDevice,
    },
    linux_watchdog_logic::{
        audit_open_fds_for_close, is_same_linux_parent_instance, parse_proc_fd_entries,
        parse_proc_stat, ForkRaceGuardStateMachine, LinuxParentMonitorMode, LinuxProcStatIdentity,
        LinuxReleaseStep,
    },
    traits::{check_release_report, HidWatchdogBackend, InputPrivilegeStatus},
    watchdog_supervisor::{HidWatchdogConfig, HidWatchdogSupervisor},
    EmergencyKeyReleaser, OsError, ReleaseReport,
};
use std::{fs, num::NonZeroU32};

// Clean-room Linux UAPI constant (`PR_SET_PDEATHSIG = 1` across all Linux architectures).
pub const LINUX_PR_SET_PDEATHSIG: libc::c_int = 1;

/// Opens a race-free Linux `pidfd` for `pid` via `libc::syscall(libc::SYS_pidfd_open, pid, 0)`.
/// `pidfd_open` creates close-on-exec descriptors by default.
pub fn open_pidfd(pid: u32) -> Result<libc::c_int, std::io::Error> {
    if pid == 0 {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let fd = unsafe {
        libc::syscall(
            libc::SYS_pidfd_open,
            pid as libc::pid_t,
            0 as libc::c_uint,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(fd as libc::c_int)
    }
}

/// Probes whether the running Linux kernel supports `pidfd_open` by opening a
/// `pidfd` on the current process and closing it immediately.
pub fn probe_pidfd_supported() -> bool {
    match open_pidfd(std::process::id()) {
        Ok(fd) => {
            unsafe {
                libc::close(fd);
            }
            true
        }
        Err(_) => false,
    }
}

/// Reads and parses `/proc/<pid>/stat` into a `LinuxProcStatIdentity` (including
/// field 22 `starttime` for PID-reuse detection).
pub fn read_proc_stat_identity(pid: u32) -> Result<LinuxProcStatIdentity, String> {
    let path = format!("/proc/{pid}/stat");
    let raw = fs::read_to_string(&path).map_err(|e| format!("read {path} failed: {e}"))?;
    parse_proc_stat(&raw)
}

/// Arms `prctl(PR_SET_PDEATHSIG, SIGTERM)` and IMMEDIATELY verifies
/// `getppid() == expected_ppid` via `ForkRaceGuardStateMachine` to close the
/// `fork() -> prctl()` race window.
pub fn arm_pdeathsig_and_verify_parent(expected_ppid: u32) -> Result<(), String> {
    let mut guard = ForkRaceGuardStateMachine::new(expected_ppid)?;
    let prctl_ok = unsafe { libc::prctl(LINUX_PR_SET_PDEATHSIG, libc::SIGTERM, 0, 0, 0) == 0 };
    guard.on_pdeathsig_armed(prctl_ok)?;
    let observed_ppid = unsafe { libc::getppid() } as u32;
    guard.on_verify_ppid(observed_ppid)?;
    Ok(())
}

/// Snapshots all open non-negative file descriptors from `/proc/self/fd`, dropping
/// the `ReadDir` handle BEFORE returning so callers never close `ReadDir`'s own dirfd.
fn snapshot_open_fds() -> Vec<libc::c_int> {
    let Ok(read_dir) = fs::read_dir("/proc/self/fd") else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for entry in read_dir.flatten() {
        if let Some(s) = entry.file_name().to_str() {
            names.push(s.to_string());
        }
    }
    let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
    parse_proc_fd_entries(&name_refs)
}

/// Enumerates `/proc/self/fd`, identifies all open descriptors outside `keep_fds`
/// via `audit_open_fds_for_close`, and closes them deterministically.
/// Returns the number of leaked descriptors closed.
pub fn audit_and_close_leaked_fds(keep_fds: &[libc::c_int]) -> usize {
    let open_fds = snapshot_open_fds();
    let to_close = audit_open_fds_for_close(&open_fds, keep_fds);
    for &fd in &to_close {
        unsafe {
            libc::close(fd);
        }
    }
    to_close.len()
}

/// Read-only `/proc/self/fd` leak counter used by `zerodesk-linux-diag`.
pub fn count_unexpected_open_fds(keep_fds: &[libc::c_int]) -> usize {
    let open_fds = snapshot_open_fds();
    audit_open_fds_for_close(&open_fds, keep_fds).len()
}

/// Opens parent monitor handle for the Linux watchdog child:
/// - Prefers `pidfd_open(parent_pid, 0)` followed immediately by `getppid() == parent_pid`
///   verification (immune to PID reuse);
/// - Falls back explicitly to `FallbackLegacyProcStat` (`getppid()` + `/proc/<pid>/stat`
///   `starttime`) ONLY when `pidfd_open` fails with `ENOSYS` (Linux < 5.3). All other
///   errors (`EMFILE`, `EPERM`, `ENOMEM`, `ESRCH`) fail closed immediately!
pub struct LinuxParentMonitor {
    mode: LinuxParentMonitorMode,
    pidfd: Option<libc::c_int>,
    parent_pid: u32,
}

impl LinuxParentMonitor {
    pub fn attach(parent_pid: u32) -> Result<Self, String> {
        match open_pidfd(parent_pid) {
            Ok(fd) => {
                // Verify parent identity AFTER pidfd_open to rule out PID reuse right before attach.
                let observed_ppid = unsafe { libc::getppid() } as u32;
                if observed_ppid != parent_pid {
                    unsafe {
                        libc::close(fd);
                    }
                    return Err(format!(
                        "parent identity mismatch (pid reuse suspected): expected ppid {parent_pid}, observed {observed_ppid}"
                    ));
                }
                Ok(Self {
                    mode: LinuxParentMonitorMode::PidFd,
                    pidfd: Some(fd),
                    parent_pid,
                })
            }
            Err(err) if err.raw_os_error() == Some(libc::ENOSYS) => {
                let observed_ppid = unsafe { libc::getppid() } as u32;
                if observed_ppid != parent_pid {
                    return Err(format!(
                        "parent already exited before legacy proc/stat attach (expected {parent_pid}, observed {observed_ppid})"
                    ));
                }
                let id = read_proc_stat_identity(parent_pid)?;
                Ok(Self {
                    mode: LinuxParentMonitorMode::FallbackLegacyProcStat {
                        parent_pid,
                        start_time_ticks: id.start_time_ticks,
                    },
                    pidfd: None,
                    parent_pid,
                })
            }
            Err(err) => Err(format!("pidfd_open({parent_pid}) failed closed: {err}")),
        }
    }

    pub fn mode(&self) -> LinuxParentMonitorMode {
        self.mode
    }

    pub fn pidfd(&self) -> Option<libc::c_int> {
        self.pidfd
    }

    /// Checks whether the exact monitored parent instance is still alive (retries
    /// `poll` once on `EINTR` in `PidFd` mode; verifies both `getppid()` and
    /// `/proc/<pid>/stat` `starttime` in `FallbackLegacyProcStat` mode).
    pub fn is_parent_alive(&self) -> bool {
        match self.mode {
            LinuxParentMonitorMode::PidFd => {
                let Some(fd) = self.pidfd else {
                    return false;
                };
                for attempt in 0..2 {
                    let mut pfd = libc::pollfd {
                        fd,
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    let rc = unsafe { libc::poll(&mut pfd, 1, 0) };
                    if rc == 0 {
                        return true;
                    }
                    if rc < 0
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINTR)
                        && attempt == 0
                    {
                        continue;
                    }
                    return false;
                }
                false
            }
            LinuxParentMonitorMode::FallbackLegacyProcStat {
                parent_pid,
                start_time_ticks,
            } => {
                let observed_ppid = unsafe { libc::getppid() } as u32;
                if observed_ppid != self.parent_pid {
                    return false;
                }
                match read_proc_stat_identity(parent_pid) {
                    Ok(obs) => is_same_linux_parent_instance(parent_pid, start_time_ticks, &obs),
                    Err(_) => false,
                }
            }
        }
    }
}

impl Drop for LinuxParentMonitor {
    fn drop(&mut self) {
        if let Some(fd) = self.pidfd.take() {
            if fd >= 0 {
                unsafe {
                    libc::close(fd);
                }
            }
        }
    }
}

/// Executes emergency dual-layer release on Linux from inside the watchdog child:
/// - Tier 1 (explicit `/dev/uinput` opt-in): sends explicit `EV_KEY=0` +
///   `EV_SYN SYN_REPORT` FIRST, then closes the `uinput` fd. If tier 1 fails,
///   attempts best-effort Tier 2 X11 `XTest` release before returning error.
/// - Tier 2 (default / X11): executes explicit X11 `XTest` key/button-up + `XFlush`.
pub fn execute_watchdog_linux_release(
    uinput_dev: Option<&mut UinputVirtualDevice>,
    uinput_explicit_opt_in: bool,
    steps: &[LinuxReleaseStep],
) -> Result<ReleaseReport, OsError> {
    if let Some(dev) = uinput_dev {
        let rep = execute_uinput_dual_layer_release(dev, steps);
        if let Ok(ok_rep) = check_release_report(rep) {
            return Ok(ok_rep);
        }
        // Best-effort Tier-2 fallback if Tier-1 uinput release had residuals.
        if let Ok(xrep) = execute_xtest_release(steps) {
            if check_release_report(xrep).is_ok() {
                return Ok(xrep);
            }
        }
        return check_release_report(rep);
    }

    if uinput_explicit_opt_in {
        match UinputVirtualDevice::open_opt_in("/dev/uinput", true) {
            Ok(mut dev) => {
                let rep = execute_uinput_dual_layer_release(&mut dev, steps);
                if let Ok(ok_rep) = check_release_report(rep) {
                    return Ok(ok_rep);
                }
                if let Ok(xrep) = execute_xtest_release(steps) {
                    if check_release_report(xrep).is_ok() {
                        return Ok(xrep);
                    }
                }
                return check_release_report(rep);
            }
            Err(uinput_err) => {
                if let Ok(xrep) = execute_xtest_release(steps) {
                    if check_release_report(xrep).is_ok() {
                        return Ok(xrep);
                    }
                }
                return Err(uinput_err);
            }
        }
    }

    let rep = execute_xtest_release(steps)?;
    check_release_report(rep)
}

/// Linux `HidWatchdogBackend` wrapping `HidWatchdogSupervisor` with Linux
/// `InputPrivilegeStatus` reporting and `pidfd` / `proc/stat` introspection.
#[derive(Default)]
pub struct LinuxHidWatchdogBackend {
    supervisor: Option<HidWatchdogSupervisor>,
}

impl LinuxHidWatchdogBackend {
    pub fn new() -> Self {
        Self { supervisor: None }
    }

    pub fn supervisor(&self) -> Option<&HidWatchdogSupervisor> {
        self.supervisor.as_ref()
    }
}

impl HidWatchdogBackend for LinuxHidWatchdogBackend {
    fn spawn(&mut self, cfg: HidWatchdogConfig) -> Result<Option<NonZeroU32>, OsError> {
        if let Some(old) = self.supervisor.take() {
            old.shutdown(None);
        }
        let sup = HidWatchdogSupervisor::spawn(cfg)?;
        let pid = sup.child_pid().and_then(NonZeroU32::new);
        self.supervisor = Some(sup);
        Ok(pid)
    }

    fn heartbeat(&self) -> Result<(), OsError> {
        let Some(sup) = &self.supervisor else {
            return Err(OsError::Interlocked);
        };
        if !sup.is_open() {
            return Err(OsError::Interlocked);
        }
        Ok(())
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
        let report = local_releaser.map(EmergencyKeyReleaser::release_all_keys);
        if let Some(sup) = self.supervisor.take() {
            sup.shutdown(None);
        }
        match report {
            Some(rep) => check_release_report(rep),
            None => Ok(ReleaseReport::default()),
        }
    }

    fn accessibility_or_uipi_status(&self) -> InputPrivilegeStatus {
        linux_input_privilege_status()
    }
}
