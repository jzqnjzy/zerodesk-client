// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic bidirectional USB HID Usage Page `0x07` <-> Windows AT Set 1
//! Scan Code (with `KEYEVENTF_EXTENDEDKEY`) & Virtual Key (`VK_*`) mapping table,
//! plus Windows `SendInput` mouse button mask mapping for all 5 mouse buttons
//! (`Left`, `Right`, `Middle`, `X1`, `X2`).
//!
//! Compiled and unit-tested on ALL platforms (including macOS).

use crate::session::hid::{MOD_ALT, MOD_CTRL, MOD_META, MOD_SHIFT};
use serde::{Deserialize, Serialize};

/// Win32 `SendInput` keyboard flags (matching `<WinUser.h>`).
pub const WIN_KEYEVENTF_EXTENDEDKEY: u32 = 0x0001;
pub const WIN_KEYEVENTF_KEYUP: u32 = 0x0002;
pub const WIN_KEYEVENTF_SCANCODE: u32 = 0x0008;

/// Win32 `SendInput` mouse flags & `mouseData` constants (matching `<WinUser.h>`).
pub const WIN_MOUSEEVENTF_MOVE: u32 = 0x0001;
pub const WIN_MOUSEEVENTF_LEFTDOWN: u32 = 0x0002;
pub const WIN_MOUSEEVENTF_LEFTUP: u32 = 0x0004;
pub const WIN_MOUSEEVENTF_RIGHTDOWN: u32 = 0x0008;
pub const WIN_MOUSEEVENTF_RIGHTUP: u32 = 0x0010;
pub const WIN_MOUSEEVENTF_MIDDLEDOWN: u32 = 0x0020;
pub const WIN_MOUSEEVENTF_MIDDLEUP: u32 = 0x0040;
pub const WIN_MOUSEEVENTF_XDOWN: u32 = 0x0080;
pub const WIN_MOUSEEVENTF_XUP: u32 = 0x0100;
pub const WIN_MOUSEEVENTF_WHEEL: u32 = 0x0800;
pub const WIN_MOUSEEVENTF_HWHEEL: u32 = 0x1000;
pub const WIN_MOUSEEVENTF_VIRTUALDESK: u32 = 0x4000;
pub const WIN_MOUSEEVENTF_ABSOLUTE: u32 = 0x8000;

pub const WIN_XBUTTON1: u32 = 0x0001;
pub const WIN_XBUTTON2: u32 = 0x0002;

/// ZeroDesk `spec/04` mouse button mask bits (`0x1F`).
pub const HID_MOUSE_BIT_LEFT: u8 = 1 << 0;
pub const HID_MOUSE_BIT_RIGHT: u8 = 1 << 1;
pub const HID_MOUSE_BIT_MIDDLE: u8 = 1 << 2;
pub const HID_MOUSE_BIT_X1: u8 = 1 << 3;
pub const HID_MOUSE_BIT_X2: u8 = 1 << 4;
pub const ALL_MOUSE_BUTTON_BITS: [u8; 5] = [
    HID_MOUSE_BIT_LEFT,
    HID_MOUSE_BIT_RIGHT,
    HID_MOUSE_BIT_MIDDLE,
    HID_MOUSE_BIT_X1,
    HID_MOUSE_BIT_X2,
];

/// Single bidirectional entry between USB HID Usage Page `0x07`, Windows Set 1
/// hardware scan code (+ `extended` E0 flag), and Windows Virtual Key (`VK_*`).
///
/// `use_vk_mode` is `true` ONLY for Pause (`0x48`), because Windows scan code `0x45`
/// collides with NumLock unless injected via `wVk = VK_PAUSE` without `KEYEVENTF_SCANCODE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct WinKeyMapping {
    pub hid_usage: u16,
    pub scan_code: u16,
    pub extended: bool,
    pub vk_code: u16,
    pub use_vk_mode: bool,
}

impl WinKeyMapping {
    pub const fn new(hid_usage: u16, scan_code: u16, extended: bool, vk_code: u16) -> Self {
        Self {
            hid_usage,
            scan_code,
            extended,
            vk_code,
            use_vk_mode: false,
        }
    }

    pub const fn new_vk_only(hid_usage: u16, scan_code: u16, vk_code: u16) -> Self {
        Self {
            hid_usage,
            scan_code,
            extended: false,
            vk_code,
            use_vk_mode: true,
        }
    }

    /// Computes Win32 `KEYBDINPUT.dwFlags` for `SendInput`.
    /// Omits `WIN_KEYEVENTF_SCANCODE` when `use_vk_mode == true` (Pause `0x48`).
    pub const fn send_input_flags(self, down: bool) -> u32 {
        let mut flags = if self.use_vk_mode {
            0
        } else {
            WIN_KEYEVENTF_SCANCODE
        };
        if !self.use_vk_mode && self.extended {
            flags |= WIN_KEYEVENTF_EXTENDEDKEY;
        }
        if !down {
            flags |= WIN_KEYEVENTF_KEYUP;
        }
        flags
    }
}

/// Complete original USB HID Usage Page `0x07` <-> Windows Set 1 Scan Code & VK table.
/// Covers all ANSI/ISO keys, digits, punctuation, F1-F12, navigation cluster,
/// arrow keys, keypad cluster, and all 8 distinct left/right modifiers (`0xE0..=0xE7`).
const WIN_KEY_TABLE: &[WinKeyMapping] = &[
    // Letters A..Z (USB HID 0x04..=0x1D)
    WinKeyMapping::new(0x04, 0x1E, false, 0x41), // A
    WinKeyMapping::new(0x05, 0x30, false, 0x42), // B
    WinKeyMapping::new(0x06, 0x2E, false, 0x43), // C
    WinKeyMapping::new(0x07, 0x20, false, 0x44), // D
    WinKeyMapping::new(0x08, 0x12, false, 0x45), // E
    WinKeyMapping::new(0x09, 0x21, false, 0x46), // F
    WinKeyMapping::new(0x0A, 0x22, false, 0x47), // G
    WinKeyMapping::new(0x0B, 0x23, false, 0x48), // H
    WinKeyMapping::new(0x0C, 0x17, false, 0x49), // I
    WinKeyMapping::new(0x0D, 0x24, false, 0x4A), // J
    WinKeyMapping::new(0x0E, 0x25, false, 0x4B), // K
    WinKeyMapping::new(0x0F, 0x26, false, 0x4C), // L
    WinKeyMapping::new(0x10, 0x32, false, 0x4D), // M
    WinKeyMapping::new(0x11, 0x31, false, 0x4E), // N
    WinKeyMapping::new(0x12, 0x18, false, 0x4F), // O
    WinKeyMapping::new(0x13, 0x19, false, 0x50), // P
    WinKeyMapping::new(0x14, 0x10, false, 0x51), // Q
    WinKeyMapping::new(0x15, 0x13, false, 0x52), // R
    WinKeyMapping::new(0x16, 0x1F, false, 0x53), // S
    WinKeyMapping::new(0x17, 0x14, false, 0x54), // T
    WinKeyMapping::new(0x18, 0x16, false, 0x55), // U
    WinKeyMapping::new(0x19, 0x2F, false, 0x56), // V
    WinKeyMapping::new(0x1A, 0x11, false, 0x57), // W
    WinKeyMapping::new(0x1B, 0x2D, false, 0x58), // X
    WinKeyMapping::new(0x1C, 0x15, false, 0x59), // Y
    WinKeyMapping::new(0x1D, 0x2C, false, 0x5A), // Z
    // Top-row digits 1..9, 0 (USB HID 0x1E..=0x27)
    WinKeyMapping::new(0x1E, 0x02, false, 0x31), // 1
    WinKeyMapping::new(0x1F, 0x03, false, 0x32), // 2
    WinKeyMapping::new(0x20, 0x04, false, 0x33), // 3
    WinKeyMapping::new(0x21, 0x05, false, 0x34), // 4
    WinKeyMapping::new(0x22, 0x06, false, 0x35), // 5
    WinKeyMapping::new(0x23, 0x07, false, 0x36), // 6
    WinKeyMapping::new(0x24, 0x08, false, 0x37), // 7
    WinKeyMapping::new(0x25, 0x09, false, 0x38), // 8
    WinKeyMapping::new(0x26, 0x0A, false, 0x39), // 9
    WinKeyMapping::new(0x27, 0x0B, false, 0x30), // 0
    // Core control keys (USB HID 0x28..=0x2C)
    WinKeyMapping::new(0x28, 0x1C, false, 0x0D), // Enter / VK_RETURN
    WinKeyMapping::new(0x29, 0x01, false, 0x1B), // Escape / VK_ESCAPE
    WinKeyMapping::new(0x2A, 0x0E, false, 0x08), // Backspace / VK_BACK
    WinKeyMapping::new(0x2B, 0x0F, false, 0x09), // Tab / VK_TAB
    WinKeyMapping::new(0x2C, 0x39, false, 0x20), // Space / VK_SPACE
    // ANSI punctuation & CapsLock (USB HID 0x2D..=0x39)
    WinKeyMapping::new(0x2D, 0x0C, false, 0xBD), // Minus / VK_OEM_MINUS
    WinKeyMapping::new(0x2E, 0x0D, false, 0xBB), // Equal / VK_OEM_PLUS
    WinKeyMapping::new(0x2F, 0x1A, false, 0xDB), // LeftBracket / VK_OEM_4
    WinKeyMapping::new(0x30, 0x1B, false, 0xDD), // RightBracket / VK_OEM_6
    WinKeyMapping::new(0x31, 0x2B, false, 0xDC), // Backslash / VK_OEM_5
    WinKeyMapping::new(0x33, 0x27, false, 0xBA), // Semicolon / VK_OEM_1
    WinKeyMapping::new(0x34, 0x28, false, 0xDE), // Quote / VK_OEM_7
    WinKeyMapping::new(0x35, 0x29, false, 0xC0), // Grave / VK_OEM_3
    WinKeyMapping::new(0x36, 0x33, false, 0xBC), // Comma / VK_OEM_COMMA
    WinKeyMapping::new(0x37, 0x34, false, 0xBE), // Period / VK_OEM_PERIOD
    WinKeyMapping::new(0x38, 0x35, false, 0xBF), // Slash / VK_OEM_2
    WinKeyMapping::new(0x39, 0x3A, false, 0x14), // CapsLock / VK_CAPITAL
    // Function keys F1..F12 (USB HID 0x3A..=0x45)
    WinKeyMapping::new(0x3A, 0x3B, false, 0x70), // F1
    WinKeyMapping::new(0x3B, 0x3C, false, 0x71), // F2
    WinKeyMapping::new(0x3C, 0x3D, false, 0x72), // F3
    WinKeyMapping::new(0x3D, 0x3E, false, 0x73), // F4
    WinKeyMapping::new(0x3E, 0x3F, false, 0x74), // F5
    WinKeyMapping::new(0x3F, 0x40, false, 0x75), // F6
    WinKeyMapping::new(0x40, 0x41, false, 0x76), // F7
    WinKeyMapping::new(0x41, 0x42, false, 0x77), // F8
    WinKeyMapping::new(0x42, 0x43, false, 0x78), // F9
    WinKeyMapping::new(0x43, 0x44, false, 0x79), // F10
    WinKeyMapping::new(0x44, 0x57, false, 0x7A), // F11
    WinKeyMapping::new(0x45, 0x58, false, 0x7B), // F12
    // System / lock keys (USB HID 0x46..=0x48)
    WinKeyMapping::new(0x46, 0x37, true, 0x2C), // PrintScreen / VK_SNAPSHOT
    WinKeyMapping::new(0x47, 0x46, false, 0x91), // ScrollLock / VK_SCROLL
    // Pause MUST use VK_PAUSE without KEYEVENTF_SCANCODE so scan code 0x45 never toggles NumLock.
    WinKeyMapping::new_vk_only(0x48, 0x45, 0x13), // Pause / VK_PAUSE
    // Navigation & editing cluster (USB HID 0x49..=0x4E, all extended E0)
    WinKeyMapping::new(0x49, 0x52, true, 0x2D), // Insert / VK_INSERT
    WinKeyMapping::new(0x4A, 0x47, true, 0x24), // Home / VK_HOME
    WinKeyMapping::new(0x4B, 0x49, true, 0x21), // PageUp / VK_PRIOR
    WinKeyMapping::new(0x4C, 0x53, true, 0x2E), // ForwardDelete / VK_DELETE
    WinKeyMapping::new(0x4D, 0x4F, true, 0x23), // End / VK_END
    WinKeyMapping::new(0x4E, 0x51, true, 0x22), // PageDown / VK_NEXT
    // Arrow keys (USB HID 0x4F..=0x52, all extended E0)
    WinKeyMapping::new(0x4F, 0x4D, true, 0x27), // RightArrow / VK_RIGHT
    WinKeyMapping::new(0x50, 0x4B, true, 0x25), // LeftArrow / VK_LEFT
    WinKeyMapping::new(0x51, 0x50, true, 0x28), // DownArrow / VK_DOWN
    WinKeyMapping::new(0x52, 0x48, true, 0x26), // UpArrow / VK_UP
    // Keypad cluster (USB HID 0x53..=0x63, 0x67)
    WinKeyMapping::new(0x53, 0x45, true, 0x90), // NumLock / VK_NUMLOCK
    WinKeyMapping::new(0x54, 0x35, true, 0x6F), // KeypadDivide / VK_DIVIDE
    WinKeyMapping::new(0x55, 0x37, false, 0x6A), // KeypadMultiply / VK_MULTIPLY
    WinKeyMapping::new(0x56, 0x4A, false, 0x6D), // KeypadMinus / VK_SUBTRACT
    WinKeyMapping::new(0x57, 0x4E, false, 0x6B), // KeypadPlus / VK_ADD
    WinKeyMapping::new(0x58, 0x1C, true, 0x0D), // KeypadEnter (extended E0 + 0x1C)
    WinKeyMapping::new(0x59, 0x4F, false, 0x61), // Keypad1 / VK_NUMPAD1
    WinKeyMapping::new(0x5A, 0x50, false, 0x62), // Keypad2 / VK_NUMPAD2
    WinKeyMapping::new(0x5B, 0x51, false, 0x63), // Keypad3 / VK_NUMPAD3
    WinKeyMapping::new(0x5C, 0x4B, false, 0x64), // Keypad4 / VK_NUMPAD4
    WinKeyMapping::new(0x5D, 0x4C, false, 0x65), // Keypad5 / VK_NUMPAD5
    WinKeyMapping::new(0x5E, 0x4D, false, 0x66), // Keypad6 / VK_NUMPAD6
    WinKeyMapping::new(0x5F, 0x47, false, 0x67), // Keypad7 / VK_NUMPAD7
    WinKeyMapping::new(0x60, 0x48, false, 0x68), // Keypad8 / VK_NUMPAD8
    WinKeyMapping::new(0x61, 0x49, false, 0x69), // Keypad9 / VK_NUMPAD9
    WinKeyMapping::new(0x62, 0x52, false, 0x60), // Keypad0 / VK_NUMPAD0
    WinKeyMapping::new(0x63, 0x53, false, 0x6E), // KeypadDecimal / VK_DECIMAL
    // ISO non-US backslash / pipe & Application menu & Keypad Equals
    WinKeyMapping::new(0x64, 0x56, false, 0xE2), // ISO Backslash / VK_OEM_102
    WinKeyMapping::new(0x65, 0x5D, true, 0x5D), // Application / VK_APPS
    WinKeyMapping::new(0x67, 0x59, false, 0x92), // KeypadEquals / VK_OEM_NEC_EQUAL
    // Left & Right Modifiers (USB HID 0xE0..=0xE7, strictly distinct)
    WinKeyMapping::new(0xE0, 0x1D, false, 0xA2), // LeftControl / VK_LCONTROL
    WinKeyMapping::new(0xE1, 0x2A, false, 0xA0), // LeftShift / VK_LSHIFT
    WinKeyMapping::new(0xE2, 0x38, false, 0xA4), // LeftAlt / VK_LMENU
    WinKeyMapping::new(0xE3, 0x5B, true, 0x5B), // LeftWin / VK_LWIN
    WinKeyMapping::new(0xE4, 0x1D, true, 0xA3), // RightControl / VK_RCONTROL
    WinKeyMapping::new(0xE5, 0x36, false, 0xA1), // RightShift / VK_RSHIFT
    WinKeyMapping::new(0xE6, 0x38, true, 0xA5), // RightAlt / VK_RMENU
    WinKeyMapping::new(0xE7, 0x5C, true, 0x5C), // RightWin / VK_RWIN
];

/// Bidirectional USB HID <-> Windows Scan Code / Virtual Key mapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct WinHidKeyMap;

impl WinHidKeyMap {
    pub fn all_mappings() -> &'static [WinKeyMapping] {
        WIN_KEY_TABLE
    }

    /// Maps a USB HID Usage Page `0x07` usage ID to its Windows scan code + VK mapping.
    /// Unknown usages return `None` and are NEVER synthesized.
    pub fn hid_to_win(hid_usage: u16) -> Option<WinKeyMapping> {
        WIN_KEY_TABLE
            .iter()
            .copied()
            .find(|m| m.hid_usage == hid_usage)
    }

    /// Maps a Windows Set 1 `(scan_code, extended)` pair back to USB HID Usage Page `0x07`.
    pub fn scan_code_to_hid(scan_code: u16, extended: bool) -> Option<u16> {
        WIN_KEY_TABLE
            .iter()
            .find(|m| m.scan_code == scan_code && m.extended == extended)
            .map(|m| m.hid_usage)
    }

    /// Maps a Windows Virtual Key (`VK_*`) back to USB HID Usage Page `0x07`.
    /// For `VK_RETURN` (`0x0D`), prefers main Enter (`0x28`); use `scan_code_to_hid`
    /// whenever hardware scan codes are available to distinguish Keypad Enter (`0x58`).
    pub fn vk_to_hid(vk_code: u16) -> Option<u16> {
        WIN_KEY_TABLE
            .iter()
            .find(|m| m.vk_code == vk_code)
            .map(|m| m.hid_usage)
    }

    pub fn is_modifier_usage(hid_usage: u16) -> bool {
        (0xE0..=0xE7).contains(&hid_usage)
    }

    pub fn modifier_bit(hid_usage: u16) -> Option<u8> {
        match hid_usage {
            0xE0 | 0xE4 => Some(MOD_CTRL),
            0xE1 | 0xE5 => Some(MOD_SHIFT),
            0xE2 | 0xE6 => Some(MOD_ALT),
            0xE3 | 0xE7 => Some(MOD_META),
            _ => None,
        }
    }
}

/// Platform-agnostic descriptor of a single Windows `MOUSEINPUT` button action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WinMouseButtonAction {
    pub button_bit: u8,
    pub flags: u32,
    pub mouse_data: u32,
}

/// Maps a single ZeroDesk mouse button bit (`1<<0..=1<<4`) to its Windows
/// `SendInput` `MOUSEEVENTF_*` flag and `mouseData` (`XBUTTON1`/`XBUTTON2`).
pub fn mouse_button_bit_to_win(button_bit: u8, down: bool) -> Option<WinMouseButtonAction> {
    let (flags, mouse_data) = match (button_bit, down) {
        (HID_MOUSE_BIT_LEFT, true) => (WIN_MOUSEEVENTF_LEFTDOWN, 0),
        (HID_MOUSE_BIT_LEFT, false) => (WIN_MOUSEEVENTF_LEFTUP, 0),
        (HID_MOUSE_BIT_RIGHT, true) => (WIN_MOUSEEVENTF_RIGHTDOWN, 0),
        (HID_MOUSE_BIT_RIGHT, false) => (WIN_MOUSEEVENTF_RIGHTUP, 0),
        (HID_MOUSE_BIT_MIDDLE, true) => (WIN_MOUSEEVENTF_MIDDLEDOWN, 0),
        (HID_MOUSE_BIT_MIDDLE, false) => (WIN_MOUSEEVENTF_MIDDLEUP, 0),
        (HID_MOUSE_BIT_X1, true) => (WIN_MOUSEEVENTF_XDOWN, WIN_XBUTTON1),
        (HID_MOUSE_BIT_X1, false) => (WIN_MOUSEEVENTF_XUP, WIN_XBUTTON1),
        (HID_MOUSE_BIT_X2, true) => (WIN_MOUSEEVENTF_XDOWN, WIN_XBUTTON2),
        (HID_MOUSE_BIT_X2, false) => (WIN_MOUSEEVENTF_XUP, WIN_XBUTTON2),
        _ => return None,
    };
    Some(WinMouseButtonAction {
        button_bit,
        flags,
        mouse_data,
    })
}

/// Expands a 5-bit mouse button mask (`0x1F`) into Windows `MOUSEEVENTF_*UP` actions
/// in deterministic bit order (`Left`, `Right`, `Middle`, `X1`, `X2`).
pub fn mouse_buttons_mask_to_release_actions(buttons_mask: u8) -> Vec<WinMouseButtonAction> {
    let mut actions = Vec::with_capacity(5);
    for bit in ALL_MOUSE_BUTTON_BITS {
        if (buttons_mask & bit) != 0 {
            if let Some(action) = mouse_button_bit_to_win(bit, false) {
                actions.push(action);
            }
        }
    }
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeMap, BTreeSet};

    #[test]
    fn table_has_unique_hid_usages_and_unique_scan_code_pairs() {
        let mut seen_hid = BTreeSet::new();
        let mut seen_scan = BTreeSet::new();
        for m in WinHidKeyMap::all_mappings() {
            assert!(
                seen_hid.insert(m.hid_usage),
                "duplicate hid_usage {:#04x}",
                m.hid_usage
            );
            assert!(
                seen_scan.insert((m.scan_code, m.extended)),
                "duplicate (scan_code={:#04x}, extended={}) for hid {:#04x}",
                m.scan_code,
                m.extended,
                m.hid_usage
            );
            assert_eq!(WinHidKeyMap::hid_to_win(m.hid_usage), Some(*m));
            assert_eq!(
                WinHidKeyMap::scan_code_to_hid(m.scan_code, m.extended),
                Some(m.hid_usage)
            );
        }
    }

    #[test]
    fn pause_uses_vk_mode_without_scancode_flag_and_all_others_use_scancode() {
        let pause = WinHidKeyMap::hid_to_win(0x48).unwrap();
        assert!(pause.use_vk_mode);
        assert_eq!(pause.vk_code, 0x13);
        assert_eq!(pause.send_input_flags(true), 0);
        assert_eq!(pause.send_input_flags(false), WIN_KEYEVENTF_KEYUP);
        assert_eq!(pause.send_input_flags(true) & WIN_KEYEVENTF_SCANCODE, 0);
        assert_eq!(pause.send_input_flags(false) & WIN_KEYEVENTF_SCANCODE, 0);

        for m in WinHidKeyMap::all_mappings() {
            if m.hid_usage != 0x48 {
                assert!(!m.use_vk_mode, "only Pause 0x48 may set use_vk_mode");
                assert_ne!(m.send_input_flags(true) & WIN_KEYEVENTF_SCANCODE, 0);
                assert_ne!(m.send_input_flags(false) & WIN_KEYEVENTF_SCANCODE, 0);
            }
        }
    }

    #[test]
    fn vk_to_hid_round_trips_and_vk_return_is_sole_duplicate() {
        let mut vk_counts: BTreeMap<u16, Vec<u16>> = BTreeMap::new();
        for m in WinHidKeyMap::all_mappings() {
            vk_counts.entry(m.vk_code).or_default().push(m.hid_usage);
        }
        let dups: Vec<u16> = vk_counts
            .iter()
            .filter(|(_, hids)| hids.len() > 1)
            .map(|(&vk, _)| vk)
            .collect();
        assert_eq!(dups, vec![0x0D], "VK_RETURN (0x0D) must be the sole duplicate VK");
        assert_eq!(WinHidKeyMap::vk_to_hid(0x0D), Some(0x28));
        assert_eq!(WinHidKeyMap::scan_code_to_hid(0x1C, false), Some(0x28));
        assert_eq!(WinHidKeyMap::scan_code_to_hid(0x1C, true), Some(0x58));

        for m in WinHidKeyMap::all_mappings() {
            if m.hid_usage == 0x58 {
                assert_eq!(WinHidKeyMap::vk_to_hid(m.vk_code), Some(0x28));
            } else {
                assert_eq!(
                    WinHidKeyMap::vk_to_hid(m.vk_code),
                    Some(m.hid_usage),
                    "vk_to_hid mismatch for VK {:#04x}",
                    m.vk_code
                );
            }
        }
    }

    #[test]
    fn extended_keys_and_all_eight_modifiers_are_distinct() {
        let mut mod_scans = BTreeSet::new();
        let mut mod_vks = BTreeSet::new();
        for usage in 0xE0u16..=0xE7u16 {
            let m = WinHidKeyMap::hid_to_win(usage).unwrap();
            assert!(WinHidKeyMap::is_modifier_usage(usage));
            assert!(WinHidKeyMap::modifier_bit(usage).is_some());
            assert!(mod_scans.insert((m.scan_code, m.extended)));
            assert!(mod_vks.insert(m.vk_code));
        }
        for ext_usage in [
            0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x54, 0x58, 0xE3, 0xE4,
            0xE6, 0xE7,
        ] {
            let m = WinHidKeyMap::hid_to_win(ext_usage).unwrap();
            assert!(m.extended, "usage {ext_usage:#04x} must have extended=true");
            assert_ne!(m.send_input_flags(true) & WIN_KEYEVENTF_EXTENDEDKEY, 0);
            assert_ne!(m.send_input_flags(false) & WIN_KEYEVENTF_KEYUP, 0);
        }
    }

    #[test]
    fn mouse_button_mask_maps_all_five_buttons_with_xbutton_data() {
        let all = mouse_buttons_mask_to_release_actions(0x1F);
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].flags, WIN_MOUSEEVENTF_LEFTUP);
        assert_eq!(all[1].flags, WIN_MOUSEEVENTF_RIGHTUP);
        assert_eq!(all[2].flags, WIN_MOUSEEVENTF_MIDDLEUP);
        assert_eq!(all[3].flags, WIN_MOUSEEVENTF_XUP);
        assert_eq!(all[3].mouse_data, WIN_XBUTTON1);
        assert_eq!(all[4].flags, WIN_MOUSEEVENTF_XUP);
        assert_eq!(all[4].mouse_data, WIN_XBUTTON2);

        assert!(mouse_button_bit_to_win(1 << 5, false).is_none());
    }
}
