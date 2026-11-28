// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic Linux input permission degradation chain, `/dev/uinput`
//! root-equivalent opt-in gate, dual-layer stuck-key release sequencer,
//! anti-PID-reuse (`pidfd_open` + legacy `/proc/<pid>/stat` starttime parser),
//! `/proc/self/fd` leak auditor, and `fork` + `PR_SET_PDEATHSIG` race guard.
//!
//! Compiled and unit-tested on ALL platforms (including macOS).

use super::{
    linux_capture_logic::LinuxSessionKind,
    linux_hid_keymap::{mouse_buttons_mask_to_linux, LinuxHidKeyMap},
    watchdog_proto::{
        bitmap_collect_keys, WatchdogFrame, WatchdogMsgType, ALL_MODIFIER_HID_USAGES,
    },
    win_watchdog_logic::{
        is_emergency_escape_hotkey, HeartbeatStatus, WatchdogHeartbeatTracker,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Default host-hang heartbeat timeout on Linux (ms).
pub const DEFAULT_LINUX_HEARTBEAT_TIMEOUT_MS: u64 = 3_000;

/// Target upper bound (ms) for full emergency key release on parent `SIGKILL` or
/// emergency hotkey.
pub const LINUX_EMERGENCY_RELEASE_SLA_MS: u64 = 500;

/// Explicit high-privilege warning emitted whenever `/dev/uinput` opt-in is active.
pub const UINPUT_ROOT_EQUIVALENT_WARNING: &str =
    "HIGH PRIVILEGE WARNING: /dev/uinput provides root-equivalent local input injection across all seats/sessions; keep disabled unless explicitly opted in with tightly scoped udev ACLs.";

// ============================================================================
// 3-Tier Input Access Degradation Chain & /dev/uinput Root-Equivalent Opt-In
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxInputBackendChoice {
    WaylandPortalRemoteDesktop {
        active_session_notice_required: bool,
        emergency_escape_shortcut: String,
    },
    X11XTest,
    UinputRootEquivalentOptIn {
        device_path: String,
    },
    ExplicitDeny {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UinputOptInStatus {
    DisabledByDefault,
    OptInRequestedPermissionDenied {
        device_path: String,
        detail: String,
    },
    OptInActiveHighPrivilegeWarning {
        device_path: String,
        warning: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxInputCapabilities {
    pub session_kind: LinuxSessionKind,
    pub portal_remote_desktop_available: bool,
    pub xtest_available: bool,
    /// Must be explicitly enabled by the user/admin; defaults to `false`.
    pub uinput_explicit_opt_in: bool,
    /// Whether `/dev/uinput` is currently writable by the process (udev rule / input group).
    pub uinput_writable: bool,
    pub uinput_device_path: String,
}

impl Default for LinuxInputCapabilities {
    fn default() -> Self {
        Self {
            session_kind: LinuxSessionKind::Headless,
            portal_remote_desktop_available: false,
            xtest_available: false,
            uinput_explicit_opt_in: false,
            uinput_writable: false,
            uinput_device_path: "/dev/uinput".into(),
        }
    }
}

/// Complete resolved input access decision with explicit degradation warnings
/// (NEVER silently downgrades or hides `/dev/uinput` privilege escalation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxInputAccessPlan {
    pub selected: LinuxInputBackendChoice,
    pub uinput_status: UinputOptInStatus,
    pub permitted: bool,
    pub warnings: Vec<String>,
}

/// Resolves the Linux input injection backend strictly following ZeroDesk's
/// 3-tier access chain:
/// - Default priority (no uinput opt-in):
///   1. `WaylandPortalRemoteDesktop` (Wayland + portal available; mandates active
///      session notification & emergency escape hotkey),
///   2. `X11XTest` (X11 + XTest extension available),
///   3. `ExplicitDeny` (never silent!).
/// - Explicit `/dev/uinput` opt-in (`uinput_explicit_opt_in == true`):
///   - When `/dev/uinput` is writable, selects `UinputRootEquivalentOptIn` AND
///     attaches mandatory `UINPUT_ROOT_EQUIVALENT_WARNING`.
///   - When `/dev/uinput` is NOT writable, records `OptInRequestedPermissionDenied`
///     warning and falls back explicitly to the standard chain (never pretending
///     uinput succeeded).
pub fn resolve_linux_input_access_plan(caps: &LinuxInputCapabilities) -> LinuxInputAccessPlan {
    let mut warnings = Vec::new();
    let dev_path = if caps.uinput_device_path.trim().is_empty() {
        "/dev/uinput".to_string()
    } else {
        caps.uinput_device_path.clone()
    };

    if caps.uinput_explicit_opt_in {
        if caps.uinput_writable {
            warnings.push(UINPUT_ROOT_EQUIVALENT_WARNING.to_string());
            return LinuxInputAccessPlan {
                selected: LinuxInputBackendChoice::UinputRootEquivalentOptIn {
                    device_path: dev_path.clone(),
                },
                uinput_status: UinputOptInStatus::OptInActiveHighPrivilegeWarning {
                    device_path: dev_path,
                    warning: UINPUT_ROOT_EQUIVALENT_WARNING.to_string(),
                },
                permitted: true,
                warnings,
            };
        }
        let detail = format!(
            "explicit /dev/uinput opt-in requested, but {dev_path} is not writable by current user/udev ACL"
        );
        warnings.push(detail.clone());
        let uinput_status = UinputOptInStatus::OptInRequestedPermissionDenied {
            device_path: dev_path,
            detail,
        };
        return resolve_standard_chain(caps, uinput_status, warnings);
    }

    resolve_standard_chain(caps, UinputOptInStatus::DisabledByDefault, warnings)
}

fn resolve_standard_chain(
    caps: &LinuxInputCapabilities,
    uinput_status: UinputOptInStatus,
    mut warnings: Vec<String>,
) -> LinuxInputAccessPlan {
    match caps.session_kind {
        LinuxSessionKind::Wayland => {
            if caps.portal_remote_desktop_available {
                LinuxInputAccessPlan {
                    selected: LinuxInputBackendChoice::WaylandPortalRemoteDesktop {
                        active_session_notice_required: true,
                        emergency_escape_shortcut: "Ctrl+Alt+Super+Escape".into(),
                    },
                    uinput_status,
                    permitted: true,
                    warnings,
                }
            } else {
                let reason = "Wayland session lacks org.freedesktop.portal.RemoteDesktop; input injection explicitly denied (XTest cannot inject native Wayland windows and /dev/uinput is disabled by default)".to_string();
                warnings.push(reason.clone());
                LinuxInputAccessPlan {
                    selected: LinuxInputBackendChoice::ExplicitDeny { reason },
                    uinput_status,
                    permitted: false,
                    warnings,
                }
            }
        }
        LinuxSessionKind::X11 => {
            if caps.xtest_available {
                LinuxInputAccessPlan {
                    selected: LinuxInputBackendChoice::X11XTest,
                    uinput_status,
                    permitted: true,
                    warnings,
                }
            } else {
                let reason = "X11 session lacks XTest extension (libXtst); input injection explicitly denied".to_string();
                warnings.push(reason.clone());
                LinuxInputAccessPlan {
                    selected: LinuxInputBackendChoice::ExplicitDeny { reason },
                    uinput_status,
                    permitted: false,
                    warnings,
                }
            }
        }
        LinuxSessionKind::Headless => {
            let reason = "Headless Linux session has neither Wayland RemoteDesktop portal nor X11 XTest; input injection explicitly denied unless /dev/uinput is explicitly opted in and writable".to_string();
            warnings.push(reason.clone());
            LinuxInputAccessPlan {
                selected: LinuxInputBackendChoice::ExplicitDeny { reason },
                uinput_status,
                permitted: false,
                warnings,
            }
        }
    }
}

// ============================================================================
// Dual-Layer Emergency Key Release Sequence (Explicit EV_KEY=0 + SYN_REPORT -> Close)
// ============================================================================

/// Single atomic operation in Linux's dual-layer emergency release plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum LinuxReleaseStep {
    /// Layer 1: explicit `EV_KEY` release (`value = 0`) for a mapped key.
    KeyRelease { hid_usage: u16, evdev_code: u16 },
    /// Layer 1: explicit `EV_KEY` release (`value = 0`) for a mouse button.
    MouseButtonRelease { button_bit: u8, evdev_code: u16 },
    /// Layer 1 commit: `EV_SYN / SYN_REPORT` flushing all explicit releases to the kernel.
    SynReport,
    /// Layer 2 backup: `close(uinput_fd)` (strictly AFTER `SynReport`; kernel auto-release
    /// on fd close serves ONLY as a secondary safety net).
    CloseUinputFd,
}

/// Authoritative pressed-state shadow set maintained by the Linux watchdog.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LinuxWatchdogShadowSet {
    pressed_hid_keys: BTreeSet<u16>,
    pressed_mouse_buttons: u8,
    pressed_modifiers: u8,
}

impl LinuxWatchdogShadowSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update_from_snapshot(&mut self, keys_bitmap: &[u8; 32], buttons: u8, mods: u8) {
        self.pressed_hid_keys.clear();
        for usage in bitmap_collect_keys(keys_bitmap) {
            self.pressed_hid_keys.insert(usage);
        }
        self.pressed_mouse_buttons = buttons & 0x1F;
        self.pressed_modifiers = mods;
    }

    pub fn set_pressed_keys(&mut self, hid_usages: &[u16], buttons: u8, mods: u8) {
        self.pressed_hid_keys = hid_usages.iter().copied().collect();
        self.pressed_mouse_buttons = buttons & 0x1F;
        self.pressed_modifiers = mods;
    }

    pub fn clear(&mut self) {
        self.pressed_hid_keys.clear();
        self.pressed_mouse_buttons = 0;
        self.pressed_modifiers = 0;
    }

    pub fn pressed_hid_keys(&self) -> Vec<u16> {
        self.pressed_hid_keys.iter().copied().collect()
    }

    pub fn pressed_mouse_buttons(&self) -> u8 {
        self.pressed_mouse_buttons
    }

    pub fn pressed_modifiers(&self) -> u8 {
        self.pressed_modifiers
    }

    /// Builds the mandatory **dual-layer** Linux release sequence:
    /// 1. Explicit `KeyRelease` (`EV_KEY value=0`) for every tracked pressed key +
    ///    all 8 standard modifiers (`0xE0..=0xE7`) as defense-in-depth,
    /// 2. Explicit `MouseButtonRelease` (`EV_KEY value=0`) for all 5 standard buttons,
    /// 3. Explicit `SynReport` (`EV_SYN / SYN_REPORT`),
    /// 4. If `has_uinput_fd`, appends `CloseUinputFd` strictly AFTER `SynReport`.
    pub fn build_dual_layer_release_plan(&self, has_uinput_fd: bool) -> Vec<LinuxReleaseStep> {
        let mut keys: BTreeSet<u16> = self.pressed_hid_keys.clone();
        for m in ALL_MODIFIER_HID_USAGES {
            keys.insert(m);
        }

        let mut plan = Vec::with_capacity(keys.len() + 7);
        for usage in keys {
            if let Some(m) = LinuxHidKeyMap::hid_to_linux(usage) {
                plan.push(LinuxReleaseStep::KeyRelease {
                    hid_usage: usage,
                    evdev_code: m.evdev_code,
                });
            }
        }
        let full_buttons = (self.pressed_mouse_buttons & 0x1F) | 0x1F;
        for btn in mouse_buttons_mask_to_linux(full_buttons) {
            plan.push(LinuxReleaseStep::MouseButtonRelease {
                button_bit: btn.button_bit,
                evdev_code: btn.evdev_code,
            });
        }
        plan.push(LinuxReleaseStep::SynReport);
        if has_uinput_fd {
            plan.push(LinuxReleaseStep::CloseUinputFd);
        }
        plan
    }
}

// ============================================================================
// Anti-PID-Reuse (`pidfd_open` preferred; `/proc/<pid>/stat` starttime fallback)
// ============================================================================

/// Parent liveness monitoring mechanism chosen at runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxParentMonitorMode {
    /// Preferred (Linux >= 5.3): `pidfd_open(parent_pid, 0)` + `poll(pidfd)` is
    /// completely immune to PID reuse races.
    PidFd,
    /// Legacy kernel fallback (`ENOSYS` / unsupported `pidfd_open`): verifies BOTH
    /// `getppid() == parent_pid` AND `/proc/<pid>/stat` field 22 (`starttime`).
    FallbackLegacyProcStat {
        parent_pid: u32,
        start_time_ticks: u64,
    },
}

/// Parsed identity tuple from `/proc/<pid>/stat`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxProcStatIdentity {
    pub pid: u32,
    pub comm: String,
    pub state: char,
    pub ppid: u32,
    /// Field 22 of `/proc/<pid>/stat`: process start time in clock ticks since boot.
    pub start_time_ticks: u64,
}

/// Parses `/proc/<pid>/stat` safely even when `comm` contains spaces, newlines, or
/// nested parentheses (e.g. `12345 (my (weird) app) S 100 ...`).
///
/// Per `proc(5)`:
/// - Field 1: `pid` (before first `(`)
/// - Field 2: `(comm)` delimited by the FIRST `(` and the LAST `)`
/// - Remaining fields after `)` start at Field 3 (`state`), Field 4 (`ppid`), ...,
///   Field 22 (`starttime` = zero-based index 19 after the closing `)`).
pub fn parse_proc_stat(content: &str) -> Result<LinuxProcStatIdentity, String> {
    let trimmed = content.trim();
    let open_paren = trimmed
        .find('(')
        .ok_or_else(|| "malformed /proc/<pid>/stat: missing '('".to_string())?;
    let close_paren = trimmed
        .rfind(')')
        .ok_or_else(|| "malformed /proc/<pid>/stat: missing ')'".to_string())?;
    if close_paren <= open_paren {
        return Err("malformed /proc/<pid>/stat: ')' precedes '('".into());
    }

    let pid_str = trimmed[..open_paren].trim();
    let pid: u32 = pid_str
        .parse()
        .map_err(|_| format!("invalid pid in /proc/<pid>/stat: '{pid_str}'"))?;
    if pid == 0 {
        return Err("pid in /proc/<pid>/stat must be non-zero".into());
    }

    let comm = trimmed[open_paren + 1..close_paren].to_string();
    let rest = trimmed[close_paren + 1..].trim();
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // Fields after `)` are field 3..=N, so field 22 (`starttime`) is index 22 - 3 = 19.
    if fields.len() <= 19 {
        return Err(format!(
            "truncated /proc/<pid>/stat: expected >= 20 post-comm fields, got {}",
            fields.len()
        ));
    }

    let state = fields[0]
        .chars()
        .next()
        .ok_or_else(|| "empty state field in /proc/<pid>/stat".to_string())?;
    let ppid: u32 = fields[1]
        .parse()
        .map_err(|_| format!("invalid ppid in /proc/<pid>/stat: '{}'", fields[1]))?;
    let start_time_ticks: u64 = fields[19]
        .parse()
        .map_err(|_| format!("invalid starttime (field 22) in /proc/<pid>/stat: '{}'", fields[19]))?;

    Ok(LinuxProcStatIdentity {
        pid,
        comm,
        state,
        ppid,
        start_time_ticks,
    })
}

/// Validates whether an observed `/proc/<pid>/stat` snapshot represents the exact
/// same live (non-zombie/non-dead) parent process instance.
pub fn is_same_linux_parent_instance(
    expected_pid: u32,
    expected_start_time_ticks: u64,
    observed: &LinuxProcStatIdentity,
) -> bool {
    expected_pid != 0
        && expected_start_time_ticks != 0
        && observed.pid == expected_pid
        && observed.start_time_ticks == expected_start_time_ticks
        && observed.state != 'Z'
        && observed.state != 'X'
        && observed.state != 'x'
}

// ============================================================================
// `/proc/self/fd` Leak Audit & `fork()` + `PR_SET_PDEATHSIG` Race Guard
// ============================================================================

/// Parses directory entry names from `/proc/self/fd` into sorted non-negative fd integers.
pub fn parse_proc_fd_entries(entries: &[&str]) -> Vec<i32> {
    let mut fds: BTreeSet<i32> = BTreeSet::new();
    for &entry in entries {
        if let Ok(fd) = entry.trim().parse::<i32>() {
            if fd >= 0 {
                fds.insert(fd);
            }
        }
    }
    fds.into_iter().collect()
}

/// Computes the exact sorted list of unexpected/leaked open file descriptors to close,
/// given all currently open fds (e.g. from `/proc/self/fd`) and the allowlisted keep set
/// (typically `[0, 1, 2, cmd_fd, ack_fd, lock_fd, uinput_fd, pidfd]`).
pub fn audit_open_fds_for_close(open_fds: &[i32], keep_fds: &[i32]) -> Vec<i32> {
    let keep: BTreeSet<i32> = keep_fds.iter().copied().filter(|&fd| fd >= 0).collect();
    let mut to_close: BTreeSet<i32> = BTreeSet::new();
    for &fd in open_fds {
        if fd >= 0 && !keep.contains(&fd) {
            to_close.insert(fd);
        }
    }
    to_close.into_iter().collect()
}

/// State machine modeling the Linux child startup sequence that eliminates the
/// classic `fork()` -> `prctl(PR_SET_PDEATHSIG)` race window:
/// 1. Child calls `prctl(PR_SET_PDEATHSIG, SIGTERM)` immediately after `fork()`.
/// 2. Child IMMEDIATELY checks `getppid() == expected_ppid` (if parent died between
///    `fork()` and `prctl()`, `getppid()` will be reparented to init/subreaper != expected!).
/// 3. Child completes the ready-pipe `Hello` / `Ready` handshake before allowing HID injection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForkPdeathsigPhase {
    PreFork,
    PdeathsigArmed,
    ParentVerified,
    ReadyPipeAcked,
    ParentDiedDuringForkRace {
        expected_ppid: u32,
        observed_ppid: u32,
    },
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone)]
pub struct ForkRaceGuardStateMachine {
    expected_ppid: u32,
    phase: ForkPdeathsigPhase,
}

impl ForkRaceGuardStateMachine {
    pub fn new(expected_ppid: u32) -> Result<Self, String> {
        if expected_ppid == 0 {
            return Err("expected_ppid must be non-zero".into());
        }
        Ok(Self {
            expected_ppid,
            phase: ForkPdeathsigPhase::PreFork,
        })
    }

    pub fn phase(&self) -> &ForkPdeathsigPhase {
        &self.phase
    }

    pub fn on_pdeathsig_armed(&mut self, prctl_ok: bool) -> Result<&ForkPdeathsigPhase, String> {
        if self.phase != ForkPdeathsigPhase::PreFork {
            return Err(format!("invalid phase for prctl: {:?}", self.phase));
        }
        if !prctl_ok {
            let reason = "prctl(PR_SET_PDEATHSIG) failed".to_string();
            self.phase = ForkPdeathsigPhase::Failed {
                reason: reason.clone(),
            };
            return Err(reason);
        }
        self.phase = ForkPdeathsigPhase::PdeathsigArmed;
        Ok(&self.phase)
    }

    /// Must be called strictly AFTER `on_pdeathsig_armed(true)` to detect a parent
    /// that died in the window between `fork()` and `prctl(PR_SET_PDEATHSIG)`.
    pub fn on_verify_ppid(&mut self, observed_ppid: u32) -> Result<&ForkPdeathsigPhase, String> {
        if self.phase != ForkPdeathsigPhase::PdeathsigArmed {
            return Err(format!(
                "getppid() verification must happen strictly after PR_SET_PDEATHSIG (phase={:?})",
                self.phase
            ));
        }
        if observed_ppid != self.expected_ppid {
            self.phase = ForkPdeathsigPhase::ParentDiedDuringForkRace {
                expected_ppid: self.expected_ppid,
                observed_ppid,
            };
            return Err(format!(
                "parent died during fork->prctl race: expected ppid {}, observed {}",
                self.expected_ppid, observed_ppid
            ));
        }
        self.phase = ForkPdeathsigPhase::ParentVerified;
        Ok(&self.phase)
    }

    pub fn on_ready_pipe_acked(&mut self) -> Result<&ForkPdeathsigPhase, String> {
        if self.phase != ForkPdeathsigPhase::ParentVerified {
            return Err(format!(
                "ready pipe handshake requires verified parent (phase={:?})",
                self.phase
            ));
        }
        self.phase = ForkPdeathsigPhase::ReadyPipeAcked;
        Ok(&self.phase)
    }
}

// ============================================================================
// Unified Linux Watchdog Event-Loop Core
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinuxWatchdogAction {
    Continue,
    GracefulExit {
        seq: u64,
    },
    EmergencyRelease {
        trigger: &'static str,
        steps: Vec<LinuxReleaseStep>,
    },
}

/// Platform-agnostic Linux watchdog loop core unifying `StateSnapshot`,
/// `GracefulExit`, emergency escape hotkey (`Ctrl+Alt+Super+Escape`),
/// parent `SIGKILL` (`pidfd` / `proc/stat` / `pipe_eof`), heartbeat timeout,
/// and POSIX signals onto ONE identical dual-layer release path.
#[derive(Debug, Clone)]
pub struct LinuxWatchdogLoopCore {
    shadow: LinuxWatchdogShadowSet,
    last_seq: u64,
    has_uinput_fd: bool,
    heartbeat: WatchdogHeartbeatTracker,
    emergency_latched: Option<&'static str>,
}

impl LinuxWatchdogLoopCore {
    pub fn new(start_ms: u64, heartbeat_timeout_ms: u64, has_uinput_fd: bool) -> Self {
        Self {
            shadow: LinuxWatchdogShadowSet::new(),
            last_seq: 0,
            has_uinput_fd,
            heartbeat: WatchdogHeartbeatTracker::new(start_ms, heartbeat_timeout_ms),
            emergency_latched: None,
        }
    }

    pub fn shadow(&self) -> &LinuxWatchdogShadowSet {
        &self.shadow
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn is_emergency_latched(&self) -> bool {
        self.emergency_latched.is_some()
    }

    pub fn on_frame(&mut self, frame: &WatchdogFrame, now_ms: u64) -> LinuxWatchdogAction {
        if let Some(latched) = self.emergency_latched {
            return LinuxWatchdogAction::EmergencyRelease {
                trigger: latched,
                steps: self.shadow.build_dual_layer_release_plan(self.has_uinput_fd),
            };
        }
        match frame.msg_type {
            WatchdogMsgType::StateSnapshot => {
                if frame.seq < self.last_seq {
                    return self.trigger_emergency("malformed_frame_seq_rollback");
                }
                self.last_seq = frame.seq;
                self.shadow
                    .update_from_snapshot(&frame.payload, frame.buttons, frame.mods);
                self.heartbeat.on_heartbeat(now_ms);
                // Check if the snapshot contains the emergency escape hotkey (`Ctrl+Alt+Super+Escape`).
                for usage in self.shadow.pressed_hid_keys() {
                    if is_emergency_escape_hotkey(usage, frame.mods) {
                        return self.trigger_emergency("emergency_hotkey");
                    }
                }
                LinuxWatchdogAction::Continue
            }
            WatchdogMsgType::GracefulExit => {
                if frame.seq < self.last_seq {
                    return self.trigger_emergency("malformed_frame_seq_rollback");
                }
                self.last_seq = frame.seq;
                self.shadow.clear();
                LinuxWatchdogAction::GracefulExit { seq: frame.seq }
            }
            WatchdogMsgType::Hello
            | WatchdogMsgType::Ready
            | WatchdogMsgType::Released
            | WatchdogMsgType::AxStatus => self.trigger_emergency("malformed_frame_type"),
        }
    }

    pub fn on_tick(&mut self, now_ms: u64) -> LinuxWatchdogAction {
        if let Some(latched) = self.emergency_latched {
            return LinuxWatchdogAction::EmergencyRelease {
                trigger: latched,
                steps: self.shadow.build_dual_layer_release_plan(self.has_uinput_fd),
            };
        }
        match self.heartbeat.check_timeout(now_ms) {
            HeartbeatStatus::Healthy { .. } => LinuxWatchdogAction::Continue,
            HeartbeatStatus::TimedOut { .. } => self.trigger_emergency("heartbeat_timeout"),
        }
    }

    pub fn on_parent_died(&mut self, trigger: &'static str) -> LinuxWatchdogAction {
        self.trigger_emergency(trigger)
    }

    pub fn on_emergency_hotkey(&mut self) -> LinuxWatchdogAction {
        self.trigger_emergency("emergency_hotkey")
    }

    fn trigger_emergency(&mut self, trigger: &'static str) -> LinuxWatchdogAction {
        let latched = *self.emergency_latched.get_or_insert(trigger);
        LinuxWatchdogAction::EmergencyRelease {
            trigger: latched,
            steps: self.shadow.build_dual_layer_release_plan(self.has_uinput_fd),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::{
        linux_hid_keymap::{BTN_LEFT, KEY_A, KEY_LEFTCTRL},
        watchdog_proto::bitmap_set_key,
    };
    use crate::session::hid::{MOD_ALT, MOD_CTRL, MOD_META};

    #[test]
    fn input_access_chain_enforces_priority_and_uinput_opt_in_default_off() {
        // Wayland with portal -> RemoteDesktop (uinput disabled by default).
        let plan = resolve_linux_input_access_plan(&LinuxInputCapabilities {
            session_kind: LinuxSessionKind::Wayland,
            portal_remote_desktop_available: true,
            xtest_available: true,
            uinput_explicit_opt_in: false,
            uinput_writable: true, // even if writable, MUST stay disabled unless explicitly opted in!
            uinput_device_path: "/dev/uinput".into(),
        });
        assert!(plan.permitted);
        assert_eq!(plan.uinput_status, UinputOptInStatus::DisabledByDefault);
        assert!(matches!(
            plan.selected,
            LinuxInputBackendChoice::WaylandPortalRemoteDesktop {
                active_session_notice_required: true,
                ..
            }
        ));

        // Wayland without portal -> ExplicitDeny (NEVER silently falls back to XTest or uinput).
        let denied = resolve_linux_input_access_plan(&LinuxInputCapabilities {
            session_kind: LinuxSessionKind::Wayland,
            portal_remote_desktop_available: false,
            xtest_available: true,
            uinput_explicit_opt_in: false,
            uinput_writable: true,
            uinput_device_path: "/dev/uinput".into(),
        });
        assert!(!denied.permitted);
        assert!(matches!(denied.selected, LinuxInputBackendChoice::ExplicitDeny { .. }));

        // X11 with XTest -> X11XTest.
        let x11_plan = resolve_linux_input_access_plan(&LinuxInputCapabilities {
            session_kind: LinuxSessionKind::X11,
            portal_remote_desktop_available: false,
            xtest_available: true,
            uinput_explicit_opt_in: false,
            uinput_writable: false,
            uinput_device_path: "/dev/uinput".into(),
        });
        assert!(x11_plan.permitted);
        assert_eq!(x11_plan.selected, LinuxInputBackendChoice::X11XTest);

        // Explicit /dev/uinput opt-in + writable -> active with high-privilege warning.
        let uinput_plan = resolve_linux_input_access_plan(&LinuxInputCapabilities {
            session_kind: LinuxSessionKind::Headless,
            portal_remote_desktop_available: false,
            xtest_available: false,
            uinput_explicit_opt_in: true,
            uinput_writable: true,
            uinput_device_path: "/dev/uinput".into(),
        });
        assert!(uinput_plan.permitted);
        assert!(matches!(
            uinput_plan.selected,
            LinuxInputBackendChoice::UinputRootEquivalentOptIn { .. }
        ));
        assert!(matches!(
            uinput_plan.uinput_status,
            UinputOptInStatus::OptInActiveHighPrivilegeWarning { .. }
        ));
        assert!(!uinput_plan.warnings.is_empty());

        // Explicit /dev/uinput opt-in requested but permission denied -> records denial and falls back cleanly.
        let uinput_denied = resolve_linux_input_access_plan(&LinuxInputCapabilities {
            session_kind: LinuxSessionKind::X11,
            portal_remote_desktop_available: false,
            xtest_available: true,
            uinput_explicit_opt_in: true,
            uinput_writable: false,
            uinput_device_path: "/dev/uinput".into(),
        });
        assert!(uinput_denied.permitted);
        assert_eq!(uinput_denied.selected, LinuxInputBackendChoice::X11XTest);
        assert!(matches!(
            uinput_denied.uinput_status,
            UinputOptInStatus::OptInRequestedPermissionDenied { .. }
        ));
    }

    #[test]
    fn dual_layer_release_plan_emits_explicit_keys_then_syn_report_then_close_uinput() {
        let mut shadow = LinuxWatchdogShadowSet::new();
        shadow.set_pressed_keys(&[0x04], 0x01, MOD_CTRL); // 'A' + Left mouse button
        let steps = shadow.build_dual_layer_release_plan(true);

        // Must contain explicit KeyRelease for 'A', LeftCtrl, MouseButtonRelease for BTN_LEFT.
        assert!(steps.contains(&LinuxReleaseStep::KeyRelease {
            hid_usage: 0x04,
            evdev_code: KEY_A,
        }));
        assert!(steps.contains(&LinuxReleaseStep::KeyRelease {
            hid_usage: 0xE0,
            evdev_code: KEY_LEFTCTRL,
        }));
        assert!(steps.contains(&LinuxReleaseStep::MouseButtonRelease {
            button_bit: 1,
            evdev_code: BTN_LEFT,
        }));

        // SynReport MUST immediately precede CloseUinputFd (Layer 1 before Layer 2!).
        let syn_idx = steps
            .iter()
            .position(|s| *s == LinuxReleaseStep::SynReport)
            .expect("SynReport present");
        let close_idx = steps
            .iter()
            .position(|s| *s == LinuxReleaseStep::CloseUinputFd)
            .expect("CloseUinputFd present");
        assert_eq!(syn_idx + 1, close_idx);
        assert_eq!(close_idx, steps.len() - 1);
    }

    #[test]
    fn parse_proc_stat_handles_spaces_and_nested_parentheses_in_comm() {
        // Synthetic /proc/4242/stat line with spaces & nested parens inside comm!
        // Post-comm fields: [0]=state(3), [1]=ppid(4), ..., [19]=starttime(22).
        let stat = "4242 (zero desk (worker 1)) S 1001 4242 1001 0 -1 4194304 100 0 0 0 5 2 0 0 20 0 4 0 987654321 1048576 256";
        let id = parse_proc_stat(stat).unwrap();
        assert_eq!(id.pid, 4242);
        assert_eq!(id.comm, "zero desk (worker 1)");
        assert_eq!(id.state, 'S');
        assert_eq!(id.ppid, 1001);
        assert_eq!(id.start_time_ticks, 987_654_321);

        assert!(is_same_linux_parent_instance(4242, 987_654_321, &id));
        // PID reused with different starttime -> rejected!
        assert!(!is_same_linux_parent_instance(4242, 111_111_111, &id));
        // Zombie process -> rejected!
        let mut zombie = id.clone();
        zombie.state = 'Z';
        assert!(!is_same_linux_parent_instance(4242, 987_654_321, &zombie));
    }

    #[test]
    fn proc_fd_audit_and_fork_pdeathsig_race_guard_work_deterministically() {
        let open = parse_proc_fd_entries(&[".", "..", "0", "1", "2", "3", "4", "5", "9", "42"]);
        let leaked = audit_open_fds_for_close(&open, &[0, 1, 2, 3, 4, 5]);
        assert_eq!(leaked, vec![9, 42]);

        // Happy path: PreFork -> PdeathsigArmed -> ParentVerified -> ReadyPipeAcked.
        let mut guard = ForkRaceGuardStateMachine::new(1234).unwrap();
        guard.on_pdeathsig_armed(true).unwrap();
        guard.on_verify_ppid(1234).unwrap();
        guard.on_ready_pipe_acked().unwrap();
        assert_eq!(guard.phase(), &ForkPdeathsigPhase::ReadyPipeAcked);

        // Parent died between fork() and prctl(PR_SET_PDEATHSIG) -> reparented to PID 1!
        let mut raced = ForkRaceGuardStateMachine::new(1234).unwrap();
        raced.on_pdeathsig_armed(true).unwrap();
        assert!(raced.on_verify_ppid(1).is_err());
        assert_eq!(
            raced.phase(),
            &ForkPdeathsigPhase::ParentDiedDuringForkRace {
                expected_ppid: 1234,
                observed_ppid: 1,
            }
        );
    }

    #[test]
    fn watchdog_loop_core_unifies_hotkey_and_parent_sigkill_onto_same_release_plan() {
        let mut core = LinuxWatchdogLoopCore::new(1_000, 3_000, true);
        let mut bitmap = [0u8; 32];
        bitmap_set_key(&mut bitmap, 0x04); // 'A'
        let snap = WatchdogFrame::state_snapshot(1, bitmap, 0x01, MOD_CTRL);
        assert_eq!(core.on_frame(&snap, 1_100), LinuxWatchdogAction::Continue);

        let mut core_hotkey = core.clone();
        let sigkill_action = core.on_parent_died("parent_exit_pidfd");
        let hotkey_action = core_hotkey.on_emergency_hotkey();
        match (sigkill_action, hotkey_action) {
            (
                LinuxWatchdogAction::EmergencyRelease { steps: s1, .. },
                LinuxWatchdogAction::EmergencyRelease { steps: s2, .. },
            ) => assert_eq!(s1, s2),
            other => panic!("expected matching EmergencyRelease plans, got {other:?}"),
        }

        // Sending Ctrl+Alt+Super+Escape inside a snapshot triggers immediate release and latches!
        let mut core_esc = LinuxWatchdogLoopCore::new(1_000, 3_000, true);
        assert_eq!(core_esc.on_frame(&snap, 1_100), LinuxWatchdogAction::Continue);
        bitmap_set_key(&mut bitmap, 0x29); // Escape
        let esc = WatchdogFrame::state_snapshot(2, bitmap, 0, MOD_CTRL | MOD_ALT | MOD_META);
        assert!(matches!(
            core_esc.on_frame(&esc, 1_200),
            LinuxWatchdogAction::EmergencyRelease {
                trigger: "emergency_hotkey",
                ..
            }
        ));
        assert!(core_esc.is_emergency_latched());
        // Once latched, subsequent snapshots/ticks NEVER return Continue!
        let benign = WatchdogFrame::state_snapshot(3, [0u8; 32], 0, 0);
        assert!(matches!(
            core_esc.on_frame(&benign, 1_300),
            LinuxWatchdogAction::EmergencyRelease {
                trigger: "emergency_hotkey",
                ..
            }
        ));
        assert!(matches!(
            core_esc.on_tick(1_400),
            LinuxWatchdogAction::EmergencyRelease {
                trigger: "emergency_hotkey",
                ..
            }
        ));
    }

    #[test]
    fn graceful_exit_rejects_seq_rollback_and_proc_stat_rejects_malformed_inputs() {
        let mut core = LinuxWatchdogLoopCore::new(1_000, 3_000, true);
        let mut bm = [0u8; 32];
        bitmap_set_key(&mut bm, 0x04);
        assert_eq!(
            core.on_frame(&WatchdogFrame::state_snapshot(5, bm, 0x01, 0), 1_100),
            LinuxWatchdogAction::Continue
        );
        // Replayed GracefulExit with seq < last_seq MUST fail closed via EmergencyRelease
        // without clearing the shadow set!
        assert!(matches!(
            core.on_frame(&WatchdogFrame::graceful_exit(4), 1_150),
            LinuxWatchdogAction::EmergencyRelease {
                trigger: "malformed_frame_seq_rollback",
                ..
            }
        ));
        assert_eq!(core.shadow().pressed_hid_keys(), vec![0x04]);

        // Malformed /proc/<pid>/stat inputs rejected cleanly.
        assert!(parse_proc_stat("").is_err());
        assert!(parse_proc_stat("123 no_parens S 1").is_err());
        assert!(parse_proc_stat("123 )inverted( S 1").is_err());
        assert!(parse_proc_stat("0 (zero) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 100").is_err());
        assert!(parse_proc_stat("42 (truncated) S 1 2 3").is_err());
        assert!(parse_proc_stat(
            "42 (bad_start) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 0 not_a_num"
        )
        .is_err());
    }
}
