// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic Windows HID watchdog state machine, single-batch `SendInput`
//! release plan builder, PID-reuse creation-time guard, heartbeat timeout detector,
//! and emergency escape hotkey detector.
//!
//! Compiled and unit-tested on ALL platforms (including macOS).

use super::{
    watchdog_proto::{
        bitmap_collect_keys, WatchdogFrame, WatchdogMsgType, ALL_MODIFIER_HID_USAGES,
    },
    win_hid_keymap::{
        mouse_buttons_mask_to_release_actions, WinHidKeyMap, ALL_MOUSE_BUTTON_BITS,
    },
};
use crate::session::hid::{MOD_ALT, MOD_CTRL, MOD_META};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Default host-hang heartbeat timeout on Windows (triggers emergency single-batch
/// release even when the host process is still alive but its event loop froze).
pub const DEFAULT_WIN_HEARTBEAT_TIMEOUT_MS: u64 = 3_000;

/// USB HID Usage ID for Escape (`0x29`).
pub const HID_USAGE_ESCAPE: u16 = 0x29;

/// Platform-agnostic description of one Win32 `INPUT` element inside an atomic
/// `SendInput` emergency release batch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum WinInputEventDesc {
    KeyboardScanUp {
        hid_usage: u16,
        scan_code: u16,
        extended: bool,
    },
    MouseButtonUp {
        button_bit: u8,
        flags: u32,
        mouse_data: u32,
    },
}

/// Builds ONE single atomic `SendInput` release batch covering:
/// 1. Every mapped tracked key in `pressed_hid_keys` (deduplicated, sorted),
/// 2. All 8 standard modifiers (`0xE0..=0xE7`: L/R Ctrl, Shift, Alt, Win) unconditionally
///    as defense-in-depth (even if `pressed_modifiers == 0`),
/// 3. All 5 standard mouse buttons (`Left`, `Right`, `Middle`, `X1`, `X2`) unconditionally
///    so no held button can ever survive a missed snapshot or crash.
pub fn build_release_batch(
    pressed_hid_keys: &[u16],
    _pressed_modifiers: u8,
    pressed_mouse_buttons: u8,
) -> Vec<WinInputEventDesc> {
    let mut keys_to_release: BTreeSet<u16> = pressed_hid_keys.iter().copied().collect();
    for mod_usage in ALL_MODIFIER_HID_USAGES {
        keys_to_release.insert(mod_usage);
    }

    let mut batch = Vec::with_capacity(keys_to_release.len() + ALL_MOUSE_BUTTON_BITS.len());
    for usage in keys_to_release {
        if let Some(m) = WinHidKeyMap::hid_to_win(usage) {
            batch.push(WinInputEventDesc::KeyboardScanUp {
                hid_usage: usage,
                scan_code: m.scan_code,
                extended: m.extended,
            });
        }
    }

    // Defense-in-depth: release every tracked mouse button bit plus all 5 standard buttons.
    let full_mouse_mask = (pressed_mouse_buttons & 0x1F) | 0x1F;
    for action in mouse_buttons_mask_to_release_actions(full_mouse_mask) {
        batch.push(WinInputEventDesc::MouseButtonUp {
            button_bit: action.button_bit,
            flags: action.flags,
            mouse_data: action.mouse_data,
        });
    }
    batch
}

/// Process identity tuple combining PID with Windows `GetProcessTimes` creation
/// timestamp (`FILETIME` in 100-nanosecond intervals since 1601-01-01 UTC) to
/// defeat OS PID reuse races.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub creation_time_100ns: u64,
}

impl ProcessIdentity {
    pub const fn new(pid: u32, creation_time_100ns: u64) -> Self {
        Self {
            pid,
            creation_time_100ns,
        }
    }
}

/// Returns `true` ONLY when both identities are valid (non-zero PID and non-zero
/// creation time) AND match identically in both `pid` and `creation_time_100ns`.
pub fn is_same_process_instance(expected: ProcessIdentity, observed: ProcessIdentity) -> bool {
    expected.pid != 0
        && expected.creation_time_100ns != 0
        && expected.pid == observed.pid
        && expected.creation_time_100ns == observed.creation_time_100ns
}

/// Monotonic heartbeat timeout tracker detecting a hung host whose process is
/// still alive (pipe open, no exit signal, but event loop stopped sending frames).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeartbeatStatus {
    Healthy { elapsed_ms: u64, remaining_ms: u64 },
    TimedOut { elapsed_ms: u64 },
}

#[derive(Debug, Clone)]
pub struct WatchdogHeartbeatTracker {
    timeout_ms: u64,
    last_activity_ms: u64,
    heartbeat_count: u64,
    timed_out: bool,
}

impl WatchdogHeartbeatTracker {
    pub fn new(start_ms: u64, timeout_ms: u64) -> Self {
        Self {
            timeout_ms: timeout_ms.max(1),
            last_activity_ms: start_ms,
            heartbeat_count: 0,
            timed_out: false,
        }
    }

    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms
    }

    pub fn heartbeat_count(&self) -> u64 {
        self.heartbeat_count
    }

    pub fn on_heartbeat(&mut self, now_ms: u64) {
        if now_ms >= self.last_activity_ms {
            self.last_activity_ms = now_ms;
        }
        self.heartbeat_count = self.heartbeat_count.saturating_add(1);
        self.timed_out = false;
    }

    pub fn check_timeout(&mut self, now_ms: u64) -> HeartbeatStatus {
        let elapsed_ms = now_ms.saturating_sub(self.last_activity_ms);
        if elapsed_ms >= self.timeout_ms {
            self.timed_out = true;
            HeartbeatStatus::TimedOut { elapsed_ms }
        } else {
            HeartbeatStatus::Healthy {
                elapsed_ms,
                remaining_ms: self.timeout_ms - elapsed_ms,
            }
        }
    }

    pub fn remaining_ms(&self, now_ms: u64) -> u64 {
        let elapsed_ms = now_ms.saturating_sub(self.last_activity_ms);
        self.timeout_ms.saturating_sub(elapsed_ms)
    }

    pub fn is_timed_out(&self) -> bool {
        self.timed_out
    }
}

/// Detects the cross-platform emergency escape hotkey:
/// - Windows: `Ctrl + Alt + Win + Escape`
/// - macOS: `Ctrl + Opt + Cmd + Escape`
///
/// Matches `Escape` (`0x29`) with `MOD_CTRL | MOD_ALT | MOD_META` all set (additional
/// `MOD_SHIFT` is permitted so holding Shift cannot defeat the escape hatch).
pub fn is_emergency_escape_hotkey(hid_usage: u16, modifiers_mask: u8) -> bool {
    if hid_usage != HID_USAGE_ESCAPE {
        return false;
    }
    let required = MOD_CTRL | MOD_ALT | MOD_META;
    (modifiers_mask & required) == required
}

/// Decision produced by the platform-agnostic Windows watchdog event-loop core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WinWatchdogAction {
    Continue,
    GracefulExit {
        seq: u64,
    },
    EmergencyRelease {
        trigger: &'static str,
        keys: Vec<u16>,
        buttons: u8,
        mods: u8,
        batch: Vec<WinInputEventDesc>,
    },
}

/// Platform-agnostic frame & heartbeat state machine shared by the Windows
/// `zerodesk-hid-watchdog` runtime and unit tests on macOS.
#[derive(Debug, Clone)]
pub struct WinWatchdogLoopState {
    keys_bitmap: [u8; 32],
    buttons: u8,
    mods: u8,
    last_seq: u64,
    heartbeat: WatchdogHeartbeatTracker,
}

impl WinWatchdogLoopState {
    pub fn new(start_ms: u64, heartbeat_timeout_ms: u64) -> Self {
        Self {
            keys_bitmap: [0u8; 32],
            buttons: 0,
            mods: 0,
            last_seq: 0,
            heartbeat: WatchdogHeartbeatTracker::new(start_ms, heartbeat_timeout_ms),
        }
    }

    pub fn heartbeat(&self) -> &WatchdogHeartbeatTracker {
        &self.heartbeat
    }

    pub fn tracked_keys(&self) -> Vec<u16> {
        bitmap_collect_keys(&self.keys_bitmap)
    }

    pub fn tracked_buttons(&self) -> u8 {
        self.buttons
    }

    pub fn tracked_mods(&self) -> u8 {
        self.mods
    }

    pub fn last_seq(&self) -> u64 {
        self.last_seq
    }

    pub fn build_emergency_action(&self, trigger: &'static str) -> WinWatchdogAction {
        let keys = bitmap_collect_keys(&self.keys_bitmap);
        let batch = build_release_batch(&keys, self.mods, self.buttons);
        WinWatchdogAction::EmergencyRelease {
            trigger,
            keys,
            buttons: self.buttons,
            mods: self.mods,
            batch,
        }
    }

    pub fn on_frame(&mut self, frame: WatchdogFrame, now_ms: u64) -> WinWatchdogAction {
        self.heartbeat.on_heartbeat(now_ms);
        match frame.msg_type {
            WatchdogMsgType::StateSnapshot => {
                self.keys_bitmap = frame.payload;
                self.buttons = frame.buttons & 0x1F;
                self.mods = frame.mods;
                self.last_seq = frame.seq;
                WinWatchdogAction::Continue
            }
            WatchdogMsgType::GracefulExit => {
                self.keys_bitmap = [0u8; 32];
                self.buttons = 0;
                self.mods = 0;
                self.last_seq = frame.seq;
                WinWatchdogAction::GracefulExit { seq: frame.seq }
            }
            WatchdogMsgType::Hello => {
                // Unexpected duplicate Hello after handshake -> fail closed.
                self.build_emergency_action("unexpected_hello")
            }
            WatchdogMsgType::Ready | WatchdogMsgType::Released | WatchdogMsgType::AxStatus => {
                self.build_emergency_action("unexpected_frame_type")
            }
        }
    }

    pub fn on_pipe_eof(&self) -> WinWatchdogAction {
        self.build_emergency_action("pipe_eof")
    }

    pub fn on_malformed_frame(&self) -> WinWatchdogAction {
        self.build_emergency_action("malformed_frame")
    }

    pub fn on_parent_process_exit(&self) -> WinWatchdogAction {
        self.build_emergency_action("parent_process_exit")
    }

    pub fn on_tick(&mut self, now_ms: u64) -> WinWatchdogAction {
        match self.heartbeat.check_timeout(now_ms) {
            HeartbeatStatus::Healthy { .. } => WinWatchdogAction::Continue,
            HeartbeatStatus::TimedOut { .. } => self.build_emergency_action("heartbeat_timeout"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::watchdog_proto::bitmap_set_key;
    use crate::session::hid::MOD_SHIFT;

    #[test]
    fn release_batch_covers_tracked_keys_all_8_modifiers_and_all_5_mouse_buttons() {
        // Track A (0x04), UpArrow (0x52, extended), and LeftCtrl (0xE0, also in modifiers)
        let batch = build_release_batch(&[0x04, 0x52, 0xE0, 0x04], 0, 0x01);

        // Expect: 2 non-modifier keys (0x04, 0x52) + 8 modifiers (0xE0..=0xE7) = 10 keyboard + 5 mouse = 15 events
        assert_eq!(batch.len(), 15);

        let kb_usages: Vec<u16> = batch
            .iter()
            .filter_map(|e| match e {
                WinInputEventDesc::KeyboardScanUp { hid_usage, .. } => Some(*hid_usage),
                WinInputEventDesc::MouseButtonUp { .. } => None,
            })
            .collect();
        assert_eq!(kb_usages.len(), 10);
        assert!(kb_usages.contains(&0x04));
        assert!(kb_usages.contains(&0x52));
        for mod_u in ALL_MODIFIER_HID_USAGES {
            assert!(kb_usages.contains(&mod_u), "missing modifier {mod_u:#04x}");
        }

        // Verify UpArrow carries extended=true
        let up_entry = batch
            .iter()
            .find(|e| matches!(e, WinInputEventDesc::KeyboardScanUp { hid_usage: 0x52, .. }))
            .unwrap();
        assert!(matches!(
            up_entry,
            WinInputEventDesc::KeyboardScanUp {
                scan_code: 0x48,
                extended: true,
                ..
            }
        ));

        // Verify all 5 mouse buttons are present
        let mouse_bits: Vec<u8> = batch
            .iter()
            .filter_map(|e| match e {
                WinInputEventDesc::MouseButtonUp { button_bit, .. } => Some(*button_bit),
                WinInputEventDesc::KeyboardScanUp { .. } => None,
            })
            .collect();
        assert_eq!(mouse_bits, ALL_MOUSE_BUTTON_BITS.to_vec());
    }

    #[test]
    fn pid_reuse_guard_rejects_creation_time_mismatch_and_zero_values() {
        let host = ProcessIdentity::new(4242, 133_500_000_000_000_000);
        assert!(is_same_process_instance(host, host));

        // Same PID, different creation time (OS recycled PID after host exited!) -> REJECT!
        let reused = ProcessIdentity::new(4242, 133_500_000_050_000_000);
        assert!(!is_same_process_instance(host, reused));

        // Different PID -> REJECT
        assert!(!is_same_process_instance(
            host,
            ProcessIdentity::new(4243, host.creation_time_100ns)
        ));

        // Zero PID or zero creation time -> REJECT (fail closed)
        assert!(!is_same_process_instance(
            ProcessIdentity::new(0, 12345),
            ProcessIdentity::new(0, 12345)
        ));
        assert!(!is_same_process_instance(
            ProcessIdentity::new(4242, 0),
            ProcessIdentity::new(4242, 0)
        ));
    }

    #[test]
    fn heartbeat_tracker_triggers_emergency_release_when_host_hangs() {
        let mut loop_state = WinWatchdogLoopState::new(1_000, 3_000);
        let mut bm = [0u8; 32];
        bitmap_set_key(&mut bm, 0x04); // A
        let snap = WatchdogFrame::state_snapshot(1, bm, 0x03, MOD_CTRL);
        assert_eq!(loop_state.on_frame(snap, 1_500), WinWatchdogAction::Continue);

        // Still healthy at 4_499ms (2_999ms elapsed)
        assert_eq!(loop_state.on_tick(4_499), WinWatchdogAction::Continue);

        // Heartbeat resets window at 4_499ms
        let hb = WatchdogFrame::state_snapshot(2, bm, 0x03, MOD_CTRL);
        assert_eq!(loop_state.on_frame(hb, 4_499), WinWatchdogAction::Continue);
        assert_eq!(loop_state.on_tick(6_000), WinWatchdogAction::Continue);

        // Host freezes -> at 7_500ms (>= 3_000ms since 4_499ms) triggers atomic emergency release!
        match loop_state.on_tick(7_500) {
            WinWatchdogAction::EmergencyRelease {
                trigger,
                keys,
                buttons,
                batch,
                ..
            } => {
                assert_eq!(trigger, "heartbeat_timeout");
                assert_eq!(keys, vec![0x04]);
                assert_eq!(buttons, 0x03);
                assert_eq!(batch.len(), 1 + 8 + 5);
            }
            other => panic!("expected EmergencyRelease(heartbeat_timeout), got {other:?}"),
        }
    }

    #[test]
    fn graceful_exit_clears_state_without_emergency_release() {
        let mut loop_state = WinWatchdogLoopState::new(0, 3_000);
        let mut bm = [0u8; 32];
        bitmap_set_key(&mut bm, 0x1A); // W
        assert_eq!(
            loop_state.on_frame(WatchdogFrame::state_snapshot(1, bm, 0x01, 0), 100),
            WinWatchdogAction::Continue
        );
        assert_eq!(
            loop_state.on_frame(WatchdogFrame::graceful_exit(2), 200),
            WinWatchdogAction::GracefulExit { seq: 2 }
        );
        assert!(loop_state.tracked_keys().is_empty());
        assert_eq!(loop_state.tracked_buttons(), 0);
    }

    #[test]
    fn emergency_escape_hotkey_matches_ctrl_alt_win_escape() {
        let combo = MOD_CTRL | MOD_ALT | MOD_META;
        assert!(is_emergency_escape_hotkey(HID_USAGE_ESCAPE, combo));
        assert!(is_emergency_escape_hotkey(
            HID_USAGE_ESCAPE,
            combo | MOD_SHIFT
        ));
        assert!(!is_emergency_escape_hotkey(
            HID_USAGE_ESCAPE,
            MOD_CTRL | MOD_ALT
        ));
        assert!(!is_emergency_escape_hotkey(0x04, combo));
    }
}
