// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Shared cross-platform USB HID Usage Page `0x07` keymap test vectors verifying:
//! 1. Full bidirectional round-trip integrity of `WinHidKeyMap` (`hid -> (scan, ext) -> hid` & `vk_to_hid`);
//! 2. Hardcoded golden `HID -> (scan_code, extended)` vectors + exact Win32 constant values;
//! 3. Exact bidirectional parity between Rust `hid_usage_to_macos_keycode`, canonical
//!    `MAC_HID_KEYMAP_STANDARD_USAGES`, and `WinHidKeyMap` with explicit `WIN_EXTRA_ALLOWED`;
//! 4. Mouse button mask parity across all 5 standard buttons (`Left`, `Right`, `Middle`, `X1`, `X2`).

use std::collections::BTreeSet;
use zerodesk_core::os::{
    input::hid_usage_to_macos_keycode,
    watchdog_proto::ALL_MODIFIER_HID_USAGES,
    win_hid_keymap::{
        mouse_button_bit_to_win, mouse_buttons_mask_to_release_actions, WinHidKeyMap,
        ALL_MOUSE_BUTTON_BITS, WIN_KEYEVENTF_EXTENDEDKEY, WIN_KEYEVENTF_KEYUP,
        WIN_KEYEVENTF_SCANCODE, WIN_MOUSEEVENTF_ABSOLUTE, WIN_MOUSEEVENTF_HWHEEL,
        WIN_MOUSEEVENTF_LEFTDOWN, WIN_MOUSEEVENTF_LEFTUP, WIN_MOUSEEVENTF_MIDDLEDOWN,
        WIN_MOUSEEVENTF_MIDDLEUP, WIN_MOUSEEVENTF_MOVE, WIN_MOUSEEVENTF_RIGHTDOWN,
        WIN_MOUSEEVENTF_RIGHTUP, WIN_MOUSEEVENTF_VIRTUALDESK, WIN_MOUSEEVENTF_WHEEL,
        WIN_MOUSEEVENTF_XDOWN, WIN_MOUSEEVENTF_XUP, WIN_XBUTTON1, WIN_XBUTTON2,
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

/// Explicit allowlist of Windows-specific USB HID keys beyond macOS `MacHidKeyMap`:
/// PrintScreen (`0x46`), ScrollLock (`0x47`), Pause (`0x48`), ISO Backslash (`0x64`),
/// and Application/Menu (`0x65`).
const WIN_EXTRA_ALLOWED: &[u16] = &[0x46, 0x47, 0x48, 0x64, 0x65];

/// Hardcoded golden reference vectors `(hid_usage, scan_code, extended, vk_code)`
/// verifying AT Set 1 scan codes independent of the implementation table.
const GOLDEN_HID_TO_WIN_VECTORS: &[(u16, u16, bool, u16)] = &[
    (0x04, 0x1E, false, 0x41), // A
    (0x10, 0x32, false, 0x4D), // M
    (0x14, 0x10, false, 0x51), // Q
    (0x1A, 0x11, false, 0x57), // W
    (0x1D, 0x2C, false, 0x5A), // Z
    (0x1E, 0x02, false, 0x31), // 1
    (0x27, 0x0B, false, 0x30), // 0
    (0x28, 0x1C, false, 0x0D), // Enter
    (0x29, 0x01, false, 0x1B), // Escape
    (0x2A, 0x0E, false, 0x08), // Backspace
    (0x2B, 0x0F, false, 0x09), // Tab
    (0x2C, 0x39, false, 0x20), // Space
    (0x39, 0x3A, false, 0x14), // CapsLock
    (0x3A, 0x3B, false, 0x70), // F1
    (0x44, 0x57, false, 0x7A), // F11
    (0x45, 0x58, false, 0x7B), // F12
    (0x46, 0x37, true, 0x2C),  // PrintScreen
    (0x48, 0x45, false, 0x13), // Pause (VK-only)
    (0x49, 0x52, true, 0x2D),  // Insert
    (0x4A, 0x47, true, 0x24),  // Home
    (0x4B, 0x49, true, 0x21),  // PageUp
    (0x4C, 0x53, true, 0x2E),  // Delete
    (0x4D, 0x4F, true, 0x23),  // End
    (0x4E, 0x51, true, 0x22),  // PageDown
    (0x4F, 0x4D, true, 0x27),  // RightArrow
    (0x50, 0x4B, true, 0x25),  // LeftArrow
    (0x51, 0x50, true, 0x28),  // DownArrow
    (0x52, 0x48, true, 0x26),  // UpArrow
    (0x54, 0x35, true, 0x6F),  // KeypadDivide
    (0x58, 0x1C, true, 0x0D),  // KeypadEnter
    (0x64, 0x56, false, 0xE2), // ISO Backslash (VK_OEM_102)
    (0xE0, 0x1D, false, 0xA2), // LeftControl
    (0xE1, 0x2A, false, 0xA0), // LeftShift
    (0xE2, 0x38, false, 0xA4), // LeftAlt
    (0xE3, 0x5B, true, 0x5B),  // LeftWin
    (0xE4, 0x1D, true, 0xA3),  // RightControl
    (0xE5, 0x36, false, 0xA1), // RightShift
    (0xE6, 0x38, true, 0xA5),  // RightAlt
    (0xE7, 0x5C, true, 0x5C),  // RightWin
];

#[test]
fn win32_constants_and_hardcoded_golden_vectors_match_spec() {
    assert_eq!(WIN_KEYEVENTF_EXTENDEDKEY, 0x0001);
    assert_eq!(WIN_KEYEVENTF_KEYUP, 0x0002);
    assert_eq!(WIN_KEYEVENTF_SCANCODE, 0x0008);
    assert_eq!(WIN_MOUSEEVENTF_MOVE, 0x0001);
    assert_eq!(WIN_MOUSEEVENTF_LEFTDOWN, 0x0002);
    assert_eq!(WIN_MOUSEEVENTF_LEFTUP, 0x0004);
    assert_eq!(WIN_MOUSEEVENTF_RIGHTDOWN, 0x0008);
    assert_eq!(WIN_MOUSEEVENTF_RIGHTUP, 0x0010);
    assert_eq!(WIN_MOUSEEVENTF_MIDDLEDOWN, 0x0020);
    assert_eq!(WIN_MOUSEEVENTF_MIDDLEUP, 0x0040);
    assert_eq!(WIN_MOUSEEVENTF_XDOWN, 0x0080);
    assert_eq!(WIN_MOUSEEVENTF_XUP, 0x0100);
    assert_eq!(WIN_MOUSEEVENTF_WHEEL, 0x0800);
    assert_eq!(WIN_MOUSEEVENTF_HWHEEL, 0x1000);
    assert_eq!(WIN_MOUSEEVENTF_VIRTUALDESK, 0x4000);
    assert_eq!(WIN_MOUSEEVENTF_ABSOLUTE, 0x8000);
    assert_eq!(WIN_XBUTTON1, 0x0001);
    assert_eq!(WIN_XBUTTON2, 0x0002);
    assert_eq!(ALL_MOUSE_BUTTON_BITS, [1, 2, 4, 8, 16]);
    assert_eq!(
        ALL_MODIFIER_HID_USAGES,
        [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7]
    );

    assert!(GOLDEN_HID_TO_WIN_VECTORS.len() >= 30);
    for &(hid, scan, ext, vk) in GOLDEN_HID_TO_WIN_VECTORS {
        let m = WinHidKeyMap::hid_to_win(hid)
            .unwrap_or_else(|| panic!("missing golden HID {hid:#04x}"));
        assert_eq!(
            (m.scan_code, m.extended, m.vk_code),
            (scan, ext, vk),
            "golden mismatch for HID {hid:#04x}"
        );
    }
}

#[test]
fn win_hid_keymap_round_trips_every_entry_and_verifies_exact_flags() {
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

        let expected_down = if entry.use_vk_mode {
            0
        } else {
            WIN_KEYEVENTF_SCANCODE | if entry.extended { WIN_KEYEVENTF_EXTENDEDKEY } else { 0 }
        };
        let expected_up = expected_down | WIN_KEYEVENTF_KEYUP;
        assert_eq!(
            entry.send_input_flags(true),
            expected_down,
            "exact down_flags mismatch for HID {:#04x}",
            entry.hid_usage
        );
        assert_eq!(
            entry.send_input_flags(false),
            expected_up,
            "exact up_flags mismatch for HID {:#04x}",
            entry.hid_usage
        );
    }
}

#[test]
fn win_hid_keymap_achieves_bidirectional_parity_with_macos_tables() {
    // 1. Every USB HID usage mapped by Rust `hid_usage_to_macos_keycode` MUST be mapped by
    //    BOTH `MAC_HID_KEYMAP_STANDARD_USAGES` and `WinHidKeyMap`.
    let mac_std_set: BTreeSet<u16> = MAC_HID_KEYMAP_STANDARD_USAGES.iter().copied().collect();
    let extra_set: BTreeSet<u16> = WIN_EXTRA_ALLOWED.iter().copied().collect();
    let win_set: BTreeSet<u16> = WinHidKeyMap::all_mappings()
        .iter()
        .map(|m| m.hid_usage)
        .collect();

    let mut mac_rust_count = 0usize;
    for usage in 0u16..=0xFFu16 {
        if hid_usage_to_macos_keycode(usage).is_some() {
            mac_rust_count += 1;
            assert!(
                mac_std_set.contains(&usage),
                "MAC_HID_KEYMAP_STANDARD_USAGES missing Rust macOS allowlist usage {usage:#04x}"
            );
            assert!(
                win_set.contains(&usage),
                "WinHidKeyMap missing HID usage {usage:#04x} present in hid_usage_to_macos_keycode"
            );
        }
    }
    assert!(
        mac_rust_count >= 75,
        "expected >= 75 macOS Rust allowlist keys, got {mac_rust_count}"
    );

    // 2. Exact bidirectional parity: WinHidKeyMap == MAC_HID_KEYMAP_STANDARD_USAGES ∪ WIN_EXTRA_ALLOWED.
    let expected_win: BTreeSet<u16> = mac_std_set.union(&extra_set).copied().collect();
    assert_eq!(
        win_set, expected_win,
        "WinHidKeyMap must match MAC_HID_KEYMAP_STANDARD_USAGES ∪ WIN_EXTRA_ALLOWED exactly"
    );

    // 3. All 8 modifiers remain strictly distinct on BOTH macOS and Windows.
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

    for (bit, flags, data) in [
        (ALL_MOUSE_BUTTON_BITS[0], WIN_MOUSEEVENTF_LEFTDOWN, 0),
        (ALL_MOUSE_BUTTON_BITS[1], WIN_MOUSEEVENTF_RIGHTDOWN, 0),
        (ALL_MOUSE_BUTTON_BITS[2], WIN_MOUSEEVENTF_MIDDLEDOWN, 0),
        (ALL_MOUSE_BUTTON_BITS[3], WIN_MOUSEEVENTF_XDOWN, WIN_XBUTTON1),
        (ALL_MOUSE_BUTTON_BITS[4], WIN_MOUSEEVENTF_XDOWN, WIN_XBUTTON2),
    ] {
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

// ============================================================================
// Phase 9B: Linux evdev / X11 shared USB HID Usage Page 0x07 Golden Vectors
// (Existing macOS & Windows assertions above remain strictly untouched.)
// ============================================================================

/// Hardcoded golden reference vectors `(hid_usage, evdev_code, x11_keycode)`
/// verifying Linux `evdev` and XKB `evdev + 8` codes independent of the table.
const GOLDEN_HID_TO_LINUX_VECTORS: &[(u16, u16, u8)] = &[
    (0x04, 30, 38),   // A -> KEY_A
    (0x10, 50, 58),   // M -> KEY_M
    (0x14, 16, 24),   // Q -> KEY_Q
    (0x1A, 17, 25),   // W -> KEY_W
    (0x1D, 44, 52),   // Z -> KEY_Z
    (0x1E, 2, 10),    // 1 -> KEY_1
    (0x27, 11, 19),   // 0 -> KEY_0
    (0x28, 28, 36),   // Enter -> KEY_ENTER
    (0x29, 1, 9),     // Escape -> KEY_ESC
    (0x2A, 14, 22),   // Backspace -> KEY_BACKSPACE
    (0x2B, 15, 23),   // Tab -> KEY_TAB
    (0x2C, 57, 65),   // Space -> KEY_SPACE
    (0x39, 58, 66),   // CapsLock -> KEY_CAPSLOCK
    (0x3A, 59, 67),   // F1 -> KEY_F1
    (0x44, 87, 95),   // F11 -> KEY_F11
    (0x45, 88, 96),   // F12 -> KEY_F12
    (0x46, 99, 107),  // PrintScreen -> KEY_SYSRQ
    (0x47, 70, 78),   // ScrollLock -> KEY_SCROLLLOCK
    (0x48, 119, 127), // Pause -> KEY_PAUSE
    (0x49, 110, 118), // Insert -> KEY_INSERT
    (0x4A, 102, 110), // Home -> KEY_HOME
    (0x4B, 104, 112), // PageUp -> KEY_PAGEUP
    (0x4C, 111, 119), // Delete -> KEY_DELETE
    (0x4D, 107, 115), // End -> KEY_END
    (0x4E, 109, 117), // PageDown -> KEY_PAGEDOWN
    (0x4F, 106, 114), // RightArrow -> KEY_RIGHT
    (0x50, 105, 113), // LeftArrow -> KEY_LEFT
    (0x51, 108, 116), // DownArrow -> KEY_DOWN
    (0x52, 103, 111), // UpArrow -> KEY_UP
    (0x54, 98, 106),  // KeypadDivide -> KEY_KPSLASH
    (0x58, 96, 104),  // KeypadEnter -> KEY_KPENTER
    (0x64, 86, 94),   // ISO Backslash -> KEY_102ND
    (0x65, 127, 135), // Application/Menu -> KEY_COMPOSE
    (0xE0, 29, 37),   // LeftControl -> KEY_LEFTCTRL
    (0xE1, 42, 50),   // LeftShift -> KEY_LEFTSHIFT
    (0xE2, 56, 64),   // LeftAlt -> KEY_LEFTALT
    (0xE3, 125, 133), // LeftMeta -> KEY_LEFTMETA
    (0xE4, 97, 105),  // RightControl -> KEY_RIGHTCTRL
    (0xE5, 54, 62),   // RightShift -> KEY_RIGHTSHIFT
    (0xE6, 100, 108), // RightAlt -> KEY_RIGHTALT
    (0xE7, 126, 134), // RightMeta -> KEY_RIGHTMETA
];

#[test]
fn linux_hid_keymap_matches_golden_vectors_and_round_trips_bidirectionally() {
    use zerodesk_core::os::linux_hid_keymap::{
        mouse_button_bit_to_linux, mouse_buttons_mask_to_linux, LinuxHidKeyMap, BTN_EXTRA,
        BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_SIDE, X11_EVDEV_KEYCODE_OFFSET,
    };

    assert!(GOLDEN_HID_TO_LINUX_VECTORS.len() >= 40);
    for &(hid, evdev, x11) in GOLDEN_HID_TO_LINUX_VECTORS {
        let m = LinuxHidKeyMap::hid_to_linux(hid)
            .unwrap_or_else(|| panic!("missing Linux golden HID {hid:#04x}"));
        assert_eq!(
            (m.evdev_code, m.x11_keycode),
            (evdev, x11),
            "Linux golden mismatch for HID {hid:#04x}"
        );
        assert_eq!(u16::from(m.x11_keycode), m.evdev_code + X11_EVDEV_KEYCODE_OFFSET);
        assert_eq!(LinuxHidKeyMap::evdev_to_hid(evdev), Some(hid));
        assert_eq!(LinuxHidKeyMap::x11_keycode_to_hid(x11), Some(hid));
    }

    let mut seen_evdev = BTreeSet::new();
    for entry in LinuxHidKeyMap::all_mappings() {
        assert_eq!(LinuxHidKeyMap::hid_to_linux(entry.hid_usage), Some(*entry));
        assert_eq!(LinuxHidKeyMap::evdev_to_hid(entry.evdev_code), Some(entry.hid_usage));
        assert_eq!(
            LinuxHidKeyMap::x11_keycode_to_hid(entry.x11_keycode),
            Some(entry.hid_usage)
        );
        assert!(seen_evdev.insert(entry.evdev_code));
    }

    // All 5 standard mouse buttons map cleanly to Linux evdev BTN_* & X11 button indices.
    let all_btns = mouse_buttons_mask_to_linux(0x1F);
    assert_eq!(all_btns.len(), 5);
    assert_eq!(
        all_btns.iter().map(|b| (b.evdev_code, b.x11_button)).collect::<Vec<_>>(),
        vec![
            (BTN_LEFT, 1),
            (BTN_RIGHT, 3),
            (BTN_MIDDLE, 2),
            (BTN_SIDE, 8),
            (BTN_EXTRA, 9),
        ]
    );
    for bit in ALL_MOUSE_BUTTON_BITS {
        assert!(mouse_button_bit_to_linux(bit).is_some());
    }
}

#[test]
fn three_platform_hid_keymap_contract_parity_macos_windows_linux() {
    use zerodesk_core::os::linux_hid_keymap::LinuxHidKeyMap;

    let mac_std_set: BTreeSet<u16> = MAC_HID_KEYMAP_STANDARD_USAGES.iter().copied().collect();
    let win_set: BTreeSet<u16> = WinHidKeyMap::all_mappings()
        .iter()
        .map(|m| m.hid_usage)
        .collect();
    let linux_set: BTreeSet<u16> = LinuxHidKeyMap::all_mappings()
        .iter()
        .map(|m| m.hid_usage)
        .collect();

    // 1. Linux covers 100% of macOS standard usages AND matches Windows' full 106-key set identically!
    assert!(mac_std_set.is_subset(&linux_set));
    assert_eq!(
        linux_set, win_set,
        "LinuxHidKeyMap and WinHidKeyMap must cover the exact same 106 USB HID Usage Page 0x07 keys"
    );

    // 2. Every Rust macOS allowlist usage maps cleanly across all 3 platforms.
    for usage in 0u16..=0xFFu16 {
        if hid_usage_to_macos_keycode(usage).is_some() {
            assert!(WinHidKeyMap::hid_to_win(usage).is_some());
            assert!(LinuxHidKeyMap::hid_to_linux(usage).is_some());
        }
    }

    // 3. All 8 left/right modifiers remain strictly distinct on macOS, Windows, AND Linux.
    let mut linux_mods = BTreeSet::new();
    for &mod_usage in &ALL_MODIFIER_HID_USAGES {
        let m = LinuxHidKeyMap::hid_to_linux(mod_usage).unwrap();
        assert!(linux_mods.insert(m.evdev_code));
    }
    assert_eq!(linux_mods.len(), 8);
}
