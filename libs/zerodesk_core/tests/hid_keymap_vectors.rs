// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Shared cross-platform USB HID Usage Page `0x07` keymap test vectors verifying:
//! 1. Full bidirectional round-trip integrity of `WinHidKeyMap` (`hid -> (scan, ext) -> hid`);
//! 2. 100% key coverage parity between `WinHidKeyMap` and Rust `hid_usage_to_macos_keycode`;
//! 3. 100% coverage of the canonical macOS `MacHidKeyMap` standard HID usage vector
//!    (letters, digits, control/punctuation, F1..F12, nav/arrows, numpad, and all 8 modifiers);
//! 4. Mouse button mask parity across all 5 standard buttons (`Left`, `Right`, `Middle`, `X1`, `X2`).

use std::collections::BTreeSet;
use zerodesk_core::os::{
    input::hid_usage_to_macos_keycode,
    watchdog_proto::ALL_MODIFIER_HID_USAGES,
    win_hid_keymap::{
        mouse_button_bit_to_win, mouse_buttons_mask_to_release_actions, WinHidKeyMap,
        ALL_MOUSE_BUTTON_BITS, WIN_KEYEVENTF_EXTENDEDKEY, WIN_KEYEVENTF_KEYUP,
        WIN_KEYEVENTF_SCANCODE, WIN_MOUSEEVENTF_LEFTDOWN, WIN_MOUSEEVENTF_LEFTUP,
        WIN_MOUSEEVENTF_MIDDLEDOWN, WIN_MOUSEEVENTF_MIDDLEUP, WIN_MOUSEEVENTF_RIGHTDOWN,
        WIN_MOUSEEVENTF_RIGHTUP, WIN_MOUSEEVENTF_XDOWN, WIN_MOUSEEVENTF_XUP, WIN_XBUTTON1,
        WIN_XBUTTON2,
    },
};

/// Canonical cross-platform USB HID Usage Page `0x07` vector mirroring every
/// entry mapped by macOS `MacHidKeyMap.keyCodeToHidUsage`.
const MAC_HID_KEYMAP_STANDARD_USAGES: &[u16] = &[
    // Letters A..Z (0x04..=0x1D)
    0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12,
    0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
    // Digits 1..9, 0 (0x1E..=0x27)
    0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    // Core control (0x28..=0x2C)
    0x28, 0x29, 0x2A, 0x2B, 0x2C,
    // Punctuation & CapsLock (0x2D..=0x39, skipping non-US 0x32)
    0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
    // Function keys F1..F12 (0x3A..=0x45)
    0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45,
    // Navigation & editing cluster (0x49..=0x4E)
    0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
    // Arrow keys (0x4F..=0x52)
    0x4F, 0x50, 0x51, 0x52,
    // Keypad cluster (0x53..=0x63, 0x67)
    0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61,
    0x62, 0x63, 0x67,
    // All 8 left/right modifiers (0xE0..=0xE7)
    0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7,
];

#[test]
fn win_hid_keymap_round_trips_every_entry_and_has_no_collisions() {
    let mut seen_scans = BTreeSet::new();
    for entry in WinHidKeyMap::all_mappings() {
        assert_eq!(
            WinHidKeyMap::hid_to_win(entry.hid_usage),
            Some(*entry),
            "forward lookup mismatch for HID {:#04x}",
            entry.hid_usage
        );
        assert_eq!(
            WinHidKeyMap::scan_code_to_hid(entry.scan_code, entry.extended),
            Some(entry.hid_usage),
            "reverse scan-code lookup mismatch for HID {:#04x}",
            entry.hid_usage
        );
        assert!(
            seen_scans.insert((entry.scan_code, entry.extended)),
            "scan-code collision for ({:#04x}, ext={})",
            entry.scan_code,
            entry.extended
        );
        // Verify SendInput scan-code flags carry SCANCODE + KEYUP/EXTENDEDKEY accurately
        let down_flags = entry.send_input_flags(true);
        let up_flags = entry.send_input_flags(false);
        assert_ne!(down_flags & WIN_KEYEVENTF_SCANCODE, 0);
        assert_eq!(down_flags & WIN_KEYEVENTF_KEYUP, 0);
        assert_ne!(up_flags & WIN_KEYEVENTF_KEYUP, 0);
        assert_eq!((down_flags & WIN_KEYEVENTF_EXTENDEDKEY) != 0, entry.extended);
    }
}

#[test]
fn win_hid_keymap_achieves_full_parity_with_macos_rust_allowlist_and_mac_hid_keymap() {
    // 1. Every USB HID usage mapped by Rust `hid_usage_to_macos_keycode` MUST be mapped by `WinHidKeyMap`.
    let mut mac_rust_count = 0usize;
    for usage in 0u16..=0xFFu16 {
        if hid_usage_to_macos_keycode(usage).is_some() {
            mac_rust_count += 1;
            assert!(
                WinHidKeyMap::hid_to_win(usage).is_some(),
                "WinHidKeyMap missing HID usage {usage:#04x} present in hid_usage_to_macos_keycode"
            );
        }
    }
    assert!(
        mac_rust_count >= 75,
        "expected >= 75 macOS Rust allowlist keys, got {mac_rust_count}"
    );

    // 2. Every canonical MacHidKeyMap usage (including full numpad & Insert) MUST be mapped by WinHidKeyMap.
    for &usage in MAC_HID_KEYMAP_STANDARD_USAGES {
        let win = WinHidKeyMap::hid_to_win(usage).unwrap_or_else(|| {
            panic!("WinHidKeyMap missing canonical MacHidKeyMap HID usage {usage:#04x}")
        });
        assert_eq!(
            WinHidKeyMap::scan_code_to_hid(win.scan_code, win.extended),
            Some(usage),
            "WinHidKeyMap failed reverse round-trip for MacHidKeyMap usage {usage:#04x}"
        );
    }

    // 3. All 8 modifiers must remain strictly distinct on BOTH macOS and Windows.
    let mut mac_mods = BTreeSet::new();
    let mut win_mods = BTreeSet::new();
    for &mod_usage in &ALL_MODIFIER_HID_USAGES {
        let mac_kc = hid_usage_to_macos_keycode(mod_usage).unwrap();
        let win_m = WinHidKeyMap::hid_to_win(mod_usage).unwrap();
        assert!(mac_mods.insert(mac_kc));
        assert!(win_mods.insert((win_m.scan_code, win_m.extended)));
    }
    assert_eq!(mac_mods.len(), 8);
    assert_eq!(win_mods.len(), 8);
}

#[test]
fn win_hid_keymap_rejects_unmapped_and_maps_all_five_mouse_buttons() {
    assert_eq!(WinHidKeyMap::hid_to_win(0x00), None);
    assert_eq!(WinHidKeyMap::hid_to_win(0x66), None); // Keyboard Power forbidden
    assert_eq!(WinHidKeyMap::hid_to_win(0xFF), None);
    assert_eq!(WinHidKeyMap::hid_to_win(0x9999), None);

    let expected_down = [
        (ALL_MOUSE_BUTTON_BITS[0], WIN_MOUSEEVENTF_LEFTDOWN, 0),
        (ALL_MOUSE_BUTTON_BITS[1], WIN_MOUSEEVENTF_RIGHTDOWN, 0),
        (ALL_MOUSE_BUTTON_BITS[2], WIN_MOUSEEVENTF_MIDDLEDOWN, 0),
        (ALL_MOUSE_BUTTON_BITS[3], WIN_MOUSEEVENTF_XDOWN, WIN_XBUTTON1),
        (ALL_MOUSE_BUTTON_BITS[4], WIN_MOUSEEVENTF_XDOWN, WIN_XBUTTON2),
    ];
    for (bit, flags, data) in expected_down {
        let act = mouse_button_bit_to_win(bit, true).unwrap();
        assert_eq!(act.flags, flags);
        assert_eq!(act.mouse_data, data);
    }

    let ups = mouse_buttons_mask_to_release_actions(0x1F);
    assert_eq!(ups.len(), 5);
    assert_eq!(ups[0].flags, WIN_MOUSEEVENTF_LEFTUP);
    assert_eq!(ups[1].flags, WIN_MOUSEEVENTF_RIGHTUP);
    assert_eq!(ups[2].flags, WIN_MOUSEEVENTF_MIDDLEUP);
    assert_eq!(ups[3].flags, WIN_MOUSEEVENTF_XUP);
    assert_eq!(ups[3].mouse_data, WIN_XBUTTON1);
    assert_eq!(ups[4].flags, WIN_MOUSEEVENTF_XUP);
    assert_eq!(ups[4].mouse_data, WIN_XBUTTON2);
}
