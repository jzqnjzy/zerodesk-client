// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Clean-room platform-agnostic bidirectional USB HID Usage Page `0x07` <-> Linux
//! `evdev` (`KEY_*` / `BTN_*`) & X11 XKB `evdev` keycode (`evdev + 8`) mapping table,
//! plus all 5 standard mouse button bits (`Left`, `Right`, `Middle`, `X1`, `X2`).
//!
//! All numeric `evdev` ABI constants are hand-defined clean-room (zero copied kernel
//! headers) and compiled/unit-tested on ALL platforms including macOS.

use super::win_hid_keymap::{
    ALL_MOUSE_BUTTON_BITS, HID_MOUSE_BIT_LEFT, HID_MOUSE_BIT_MIDDLE, HID_MOUSE_BIT_RIGHT,
    HID_MOUSE_BIT_X1, HID_MOUSE_BIT_X2,
};
use serde::{Deserialize, Serialize};

// Clean-room Linux input event subsystem ABI constants.
pub const EV_SYN: u16 = 0x00;
pub const EV_KEY: u16 = 0x01;
pub const EV_REL: u16 = 0x02;
pub const EV_ABS: u16 = 0x03;

pub const SYN_REPORT: u16 = 0x00;

pub const REL_X: u16 = 0x00;
pub const REL_Y: u16 = 0x01;
pub const REL_HWHEEL: u16 = 0x06;
pub const REL_WHEEL: u16 = 0x08;

pub const ABS_X: u16 = 0x00;
pub const ABS_Y: u16 = 0x01;

pub const BTN_LEFT: u16 = 0x0110;
pub const BTN_RIGHT: u16 = 0x0111;
pub const BTN_MIDDLE: u16 = 0x0112;
pub const BTN_SIDE: u16 = 0x0113;
pub const BTN_EXTRA: u16 = 0x0114;

/// Standard XKB `evdev` keycode offset (`x11_keycode = evdev_code + 8`).
pub const X11_EVDEV_KEYCODE_OFFSET: u16 = 8;
/// Maximum Linux `evdev` code representable in an 8-bit X11 XKB keycode (`247 + 8 = 255`).
pub const MAX_X11_EVDEV_CODE: u16 = 247;

/// Converts a Linux `evdev` keycode to an X11 XKB keycode (`evdev + 8`), returning
/// `None` if `evdev_code > 247` would overflow `u8`.
pub const fn evdev_to_x11_keycode(evdev_code: u16) -> Option<u8> {
    if evdev_code <= MAX_X11_EVDEV_CODE {
        Some((evdev_code + X11_EVDEV_KEYCODE_OFFSET) as u8)
    } else {
        None
    }
}

/// Clean-room Linux `evdev` keyboard constants (`KEY_*`).
pub const KEY_ESC: u16 = 1;
pub const KEY_1: u16 = 2;
pub const KEY_2: u16 = 3;
pub const KEY_3: u16 = 4;
pub const KEY_4: u16 = 5;
pub const KEY_5: u16 = 6;
pub const KEY_6: u16 = 7;
pub const KEY_7: u16 = 8;
pub const KEY_8: u16 = 9;
pub const KEY_9: u16 = 10;
pub const KEY_0: u16 = 11;
pub const KEY_MINUS: u16 = 12;
pub const KEY_EQUAL: u16 = 13;
pub const KEY_BACKSPACE: u16 = 14;
pub const KEY_TAB: u16 = 15;
pub const KEY_Q: u16 = 16;
pub const KEY_W: u16 = 17;
pub const KEY_E: u16 = 18;
pub const KEY_R: u16 = 19;
pub const KEY_T: u16 = 20;
pub const KEY_Y: u16 = 21;
pub const KEY_U: u16 = 22;
pub const KEY_I: u16 = 23;
pub const KEY_O: u16 = 24;
pub const KEY_P: u16 = 25;
pub const KEY_LEFTBRACE: u16 = 26;
pub const KEY_RIGHTBRACE: u16 = 27;
pub const KEY_ENTER: u16 = 28;
pub const KEY_LEFTCTRL: u16 = 29;
pub const KEY_A: u16 = 30;
pub const KEY_S: u16 = 31;
pub const KEY_D: u16 = 32;
pub const KEY_F: u16 = 33;
pub const KEY_G: u16 = 34;
pub const KEY_H: u16 = 35;
pub const KEY_J: u16 = 36;
pub const KEY_K: u16 = 37;
pub const KEY_L: u16 = 38;
pub const KEY_SEMICOLON: u16 = 39;
pub const KEY_APOSTROPHE: u16 = 40;
pub const KEY_GRAVE: u16 = 41;
pub const KEY_LEFTSHIFT: u16 = 42;
pub const KEY_BACKSLASH: u16 = 43;
pub const KEY_Z: u16 = 44;
pub const KEY_X: u16 = 45;
pub const KEY_C: u16 = 46;
pub const KEY_V: u16 = 47;
pub const KEY_B: u16 = 48;
pub const KEY_N: u16 = 49;
pub const KEY_M: u16 = 50;
pub const KEY_COMMA: u16 = 51;
pub const KEY_DOT: u16 = 52;
pub const KEY_SLASH: u16 = 53;
pub const KEY_RIGHTSHIFT: u16 = 54;
pub const KEY_KPASTERISK: u16 = 55;
pub const KEY_LEFTALT: u16 = 56;
pub const KEY_SPACE: u16 = 57;
pub const KEY_CAPSLOCK: u16 = 58;
pub const KEY_F1: u16 = 59;
pub const KEY_F2: u16 = 60;
pub const KEY_F3: u16 = 61;
pub const KEY_F4: u16 = 62;
pub const KEY_F5: u16 = 63;
pub const KEY_F6: u16 = 64;
pub const KEY_F7: u16 = 65;
pub const KEY_F8: u16 = 66;
pub const KEY_F9: u16 = 67;
pub const KEY_F10: u16 = 68;
pub const KEY_NUMLOCK: u16 = 69;
pub const KEY_SCROLLLOCK: u16 = 70;
pub const KEY_KP7: u16 = 71;
pub const KEY_KP8: u16 = 72;
pub const KEY_KP9: u16 = 73;
pub const KEY_KPMINUS: u16 = 74;
pub const KEY_KP4: u16 = 75;
pub const KEY_KP5: u16 = 76;
pub const KEY_KP6: u16 = 77;
pub const KEY_KPPLUS: u16 = 78;
pub const KEY_KP1: u16 = 79;
pub const KEY_KP2: u16 = 80;
pub const KEY_KP3: u16 = 81;
pub const KEY_KP0: u16 = 82;
pub const KEY_KPDOT: u16 = 83;
pub const KEY_102ND: u16 = 86;
pub const KEY_F11: u16 = 87;
pub const KEY_F12: u16 = 88;
pub const KEY_KPENTER: u16 = 96;
pub const KEY_RIGHTCTRL: u16 = 97;
pub const KEY_KPSLASH: u16 = 98;
pub const KEY_SYSRQ: u16 = 99;
pub const KEY_RIGHTALT: u16 = 100;
pub const KEY_HOME: u16 = 102;
pub const KEY_UP: u16 = 103;
pub const KEY_PAGEUP: u16 = 104;
pub const KEY_LEFT: u16 = 105;
pub const KEY_RIGHT: u16 = 106;
pub const KEY_END: u16 = 107;
pub const KEY_DOWN: u16 = 108;
pub const KEY_PAGEDOWN: u16 = 109;
pub const KEY_INSERT: u16 = 110;
pub const KEY_DELETE: u16 = 111;
pub const KEY_KPEQUAL: u16 = 117;
pub const KEY_PAUSE: u16 = 119;
pub const KEY_LEFTMETA: u16 = 125;
pub const KEY_RIGHTMETA: u16 = 126;
pub const KEY_COMPOSE: u16 = 127;

/// Single bidirectional entry between USB HID Usage Page `0x07`, Linux `evdev`
/// `KEY_*` code, and X11 XKB `evdev` keycode (`evdev_code + 8`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinuxKeyMapping {
    pub hid_usage: u16,
    pub evdev_code: u16,
    pub x11_keycode: u8,
}

impl LinuxKeyMapping {
    pub const fn new(hid_usage: u16, evdev_code: u16) -> Self {
        assert!(evdev_code <= MAX_X11_EVDEV_CODE);
        Self {
            hid_usage,
            evdev_code,
            x11_keycode: (evdev_code + X11_EVDEV_KEYCODE_OFFSET) as u8,
        }
    }
}

/// Complete original USB HID Usage Page `0x07` <-> Linux `evdev` table.
/// Covers ANSI/ISO letters, digits, punctuation, F1-F12, PrintScreen/ScrollLock/Pause,
/// navigation & editing cluster, arrow keys, keypad cluster, Application/Compose,
/// and all 8 distinct left/right modifiers (`0xE0..=0xE7`).
const LINUX_KEY_TABLE: &[LinuxKeyMapping] = &[
    // Letters A..Z (USB HID 0x04..=0x1D)
    LinuxKeyMapping::new(0x04, KEY_A),
    LinuxKeyMapping::new(0x05, KEY_B),
    LinuxKeyMapping::new(0x06, KEY_C),
    LinuxKeyMapping::new(0x07, KEY_D),
    LinuxKeyMapping::new(0x08, KEY_E),
    LinuxKeyMapping::new(0x09, KEY_F),
    LinuxKeyMapping::new(0x0A, KEY_G),
    LinuxKeyMapping::new(0x0B, KEY_H),
    LinuxKeyMapping::new(0x0C, KEY_I),
    LinuxKeyMapping::new(0x0D, KEY_J),
    LinuxKeyMapping::new(0x0E, KEY_K),
    LinuxKeyMapping::new(0x0F, KEY_L),
    LinuxKeyMapping::new(0x10, KEY_M),
    LinuxKeyMapping::new(0x11, KEY_N),
    LinuxKeyMapping::new(0x12, KEY_O),
    LinuxKeyMapping::new(0x13, KEY_P),
    LinuxKeyMapping::new(0x14, KEY_Q),
    LinuxKeyMapping::new(0x15, KEY_R),
    LinuxKeyMapping::new(0x16, KEY_S),
    LinuxKeyMapping::new(0x17, KEY_T),
    LinuxKeyMapping::new(0x18, KEY_U),
    LinuxKeyMapping::new(0x19, KEY_V),
    LinuxKeyMapping::new(0x1A, KEY_W),
    LinuxKeyMapping::new(0x1B, KEY_X),
    LinuxKeyMapping::new(0x1C, KEY_Y),
    LinuxKeyMapping::new(0x1D, KEY_Z),
    // Top-row digits 1..9, 0 (USB HID 0x1E..=0x27)
    LinuxKeyMapping::new(0x1E, KEY_1),
    LinuxKeyMapping::new(0x1F, KEY_2),
    LinuxKeyMapping::new(0x20, KEY_3),
    LinuxKeyMapping::new(0x21, KEY_4),
    LinuxKeyMapping::new(0x22, KEY_5),
    LinuxKeyMapping::new(0x23, KEY_6),
    LinuxKeyMapping::new(0x24, KEY_7),
    LinuxKeyMapping::new(0x25, KEY_8),
    LinuxKeyMapping::new(0x26, KEY_9),
    LinuxKeyMapping::new(0x27, KEY_0),
    // Core control keys (USB HID 0x28..=0x2C)
    LinuxKeyMapping::new(0x28, KEY_ENTER),
    LinuxKeyMapping::new(0x29, KEY_ESC),
    LinuxKeyMapping::new(0x2A, KEY_BACKSPACE),
    LinuxKeyMapping::new(0x2B, KEY_TAB),
    LinuxKeyMapping::new(0x2C, KEY_SPACE),
    // ANSI punctuation & CapsLock (USB HID 0x2D..=0x39, skipping non-US 0x32)
    LinuxKeyMapping::new(0x2D, KEY_MINUS),
    LinuxKeyMapping::new(0x2E, KEY_EQUAL),
    LinuxKeyMapping::new(0x2F, KEY_LEFTBRACE),
    LinuxKeyMapping::new(0x30, KEY_RIGHTBRACE),
    LinuxKeyMapping::new(0x31, KEY_BACKSLASH),
    LinuxKeyMapping::new(0x33, KEY_SEMICOLON),
    LinuxKeyMapping::new(0x34, KEY_APOSTROPHE),
    LinuxKeyMapping::new(0x35, KEY_GRAVE),
    LinuxKeyMapping::new(0x36, KEY_COMMA),
    LinuxKeyMapping::new(0x37, KEY_DOT),
    LinuxKeyMapping::new(0x38, KEY_SLASH),
    LinuxKeyMapping::new(0x39, KEY_CAPSLOCK),
    // Function keys F1..F12 (USB HID 0x3A..=0x45)
    LinuxKeyMapping::new(0x3A, KEY_F1),
    LinuxKeyMapping::new(0x3B, KEY_F2),
    LinuxKeyMapping::new(0x3C, KEY_F3),
    LinuxKeyMapping::new(0x3D, KEY_F4),
    LinuxKeyMapping::new(0x3E, KEY_F5),
    LinuxKeyMapping::new(0x3F, KEY_F6),
    LinuxKeyMapping::new(0x40, KEY_F7),
    LinuxKeyMapping::new(0x41, KEY_F8),
    LinuxKeyMapping::new(0x42, KEY_F9),
    LinuxKeyMapping::new(0x43, KEY_F10),
    LinuxKeyMapping::new(0x44, KEY_F11),
    LinuxKeyMapping::new(0x45, KEY_F12),
    // System / lock keys (USB HID 0x46..=0x48)
    LinuxKeyMapping::new(0x46, KEY_SYSRQ),
    LinuxKeyMapping::new(0x47, KEY_SCROLLLOCK),
    LinuxKeyMapping::new(0x48, KEY_PAUSE),
    // Navigation & editing cluster (USB HID 0x49..=0x4E)
    LinuxKeyMapping::new(0x49, KEY_INSERT),
    LinuxKeyMapping::new(0x4A, KEY_HOME),
    LinuxKeyMapping::new(0x4B, KEY_PAGEUP),
    LinuxKeyMapping::new(0x4C, KEY_DELETE),
    LinuxKeyMapping::new(0x4D, KEY_END),
    LinuxKeyMapping::new(0x4E, KEY_PAGEDOWN),
    // Arrow keys (USB HID 0x4F..=0x52)
    LinuxKeyMapping::new(0x4F, KEY_RIGHT),
    LinuxKeyMapping::new(0x50, KEY_LEFT),
    LinuxKeyMapping::new(0x51, KEY_DOWN),
    LinuxKeyMapping::new(0x52, KEY_UP),
    // Keypad cluster (USB HID 0x53..=0x63, 0x67)
    LinuxKeyMapping::new(0x53, KEY_NUMLOCK),
    LinuxKeyMapping::new(0x54, KEY_KPSLASH),
    LinuxKeyMapping::new(0x55, KEY_KPASTERISK),
    LinuxKeyMapping::new(0x56, KEY_KPMINUS),
    LinuxKeyMapping::new(0x57, KEY_KPPLUS),
    LinuxKeyMapping::new(0x58, KEY_KPENTER),
    LinuxKeyMapping::new(0x59, KEY_KP1),
    LinuxKeyMapping::new(0x5A, KEY_KP2),
    LinuxKeyMapping::new(0x5B, KEY_KP3),
    LinuxKeyMapping::new(0x5C, KEY_KP4),
    LinuxKeyMapping::new(0x5D, KEY_KP5),
    LinuxKeyMapping::new(0x5E, KEY_KP6),
    LinuxKeyMapping::new(0x5F, KEY_KP7),
    LinuxKeyMapping::new(0x60, KEY_KP8),
    LinuxKeyMapping::new(0x61, KEY_KP9),
    LinuxKeyMapping::new(0x62, KEY_KP0),
    LinuxKeyMapping::new(0x63, KEY_KPDOT),
    // ISO non-US backslash, Application/Compose, Keypad Equals
    LinuxKeyMapping::new(0x64, KEY_102ND),
    LinuxKeyMapping::new(0x65, KEY_COMPOSE),
    LinuxKeyMapping::new(0x67, KEY_KPEQUAL),
    // Left & Right Modifiers (USB HID 0xE0..=0xE7, strictly distinct)
    LinuxKeyMapping::new(0xE0, KEY_LEFTCTRL),
    LinuxKeyMapping::new(0xE1, KEY_LEFTSHIFT),
    LinuxKeyMapping::new(0xE2, KEY_LEFTALT),
    LinuxKeyMapping::new(0xE3, KEY_LEFTMETA),
    LinuxKeyMapping::new(0xE4, KEY_RIGHTCTRL),
    LinuxKeyMapping::new(0xE5, KEY_RIGHTSHIFT),
    LinuxKeyMapping::new(0xE6, KEY_RIGHTALT),
    LinuxKeyMapping::new(0xE7, KEY_RIGHTMETA),
];

/// Bidirectional USB HID <-> Linux `evdev` / X11 keycode mapper.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinuxHidKeyMap;

impl LinuxHidKeyMap {
    pub fn all_mappings() -> &'static [LinuxKeyMapping] {
        LINUX_KEY_TABLE
    }

    /// Maps a USB HID Usage Page `0x07` usage ID to its Linux `evdev` / X11 mapping.
    /// Unknown usages return `None` and are NEVER synthesized.
    pub fn hid_to_linux(hid_usage: u16) -> Option<LinuxKeyMapping> {
        LINUX_KEY_TABLE
            .iter()
            .copied()
            .find(|m| m.hid_usage == hid_usage)
    }

    /// Reverse maps a Linux `evdev` `KEY_*` code back to USB HID Usage Page `0x07`.
    pub fn evdev_to_hid(evdev_code: u16) -> Option<u16> {
        LINUX_KEY_TABLE
            .iter()
            .find(|m| m.evdev_code == evdev_code)
            .map(|m| m.hid_usage)
    }

    /// Reverse maps an X11 XKB `evdev` keycode (`evdev + 8`) back to USB HID Usage Page `0x07`.
    pub fn x11_keycode_to_hid(x11_keycode: u8) -> Option<u16> {
        LINUX_KEY_TABLE
            .iter()
            .find(|m| m.x11_keycode == x11_keycode)
            .map(|m| m.hid_usage)
    }
}

/// Mouse button mapping for both Linux `evdev` (`BTN_*`) and X11 `XTest` button number (`1..=9`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxMouseButtonMapping {
    pub button_bit: u8,
    pub evdev_code: u16,
    pub x11_button: u32,
}

/// Maps one single ZeroDesk mouse button mask bit (`1<<0`..`1<<4`) to its Linux
/// `evdev` `BTN_*` code and X11 `XTestFakeButtonEvent` button index.
pub const fn mouse_button_bit_to_linux(button_bit: u8) -> Option<LinuxMouseButtonMapping> {
    match button_bit {
        HID_MOUSE_BIT_LEFT => Some(LinuxMouseButtonMapping {
            button_bit,
            evdev_code: BTN_LEFT,
            x11_button: 1,
        }),
        HID_MOUSE_BIT_RIGHT => Some(LinuxMouseButtonMapping {
            button_bit,
            evdev_code: BTN_RIGHT,
            x11_button: 3,
        }),
        HID_MOUSE_BIT_MIDDLE => Some(LinuxMouseButtonMapping {
            button_bit,
            evdev_code: BTN_MIDDLE,
            x11_button: 2,
        }),
        HID_MOUSE_BIT_X1 => Some(LinuxMouseButtonMapping {
            button_bit,
            evdev_code: BTN_SIDE,
            x11_button: 8,
        }),
        HID_MOUSE_BIT_X2 => Some(LinuxMouseButtonMapping {
            button_bit,
            evdev_code: BTN_EXTRA,
            x11_button: 9,
        }),
        _ => None,
    }
}

/// Expands a ZeroDesk mouse button bitmask into all matching Linux button mappings.
pub fn mouse_buttons_mask_to_linux(mask: u8) -> Vec<LinuxMouseButtonMapping> {
    let mut out = Vec::with_capacity(ALL_MOUSE_BUTTON_BITS.len());
    for bit in ALL_MOUSE_BUTTON_BITS {
        if (mask & bit) != 0 {
            if let Some(m) = mouse_button_bit_to_linux(bit) {
                out.push(m);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn linux_keymap_has_unique_bijection_for_hid_evdev_and_x11() {
        let mut hids = BTreeSet::new();
        let mut evdevs = BTreeSet::new();
        let mut x11s = BTreeSet::new();
        for entry in LinuxHidKeyMap::all_mappings() {
            assert!(hids.insert(entry.hid_usage), "duplicate HID {:#04x}", entry.hid_usage);
            assert!(evdevs.insert(entry.evdev_code), "duplicate evdev {}", entry.evdev_code);
            assert!(x11s.insert(entry.x11_keycode), "duplicate x11 {}", entry.x11_keycode);
            assert_eq!(LinuxHidKeyMap::hid_to_linux(entry.hid_usage), Some(*entry));
            assert_eq!(LinuxHidKeyMap::evdev_to_hid(entry.evdev_code), Some(entry.hid_usage));
            assert_eq!(LinuxHidKeyMap::x11_keycode_to_hid(entry.x11_keycode), Some(entry.hid_usage));
        }
        assert_eq!(LinuxHidKeyMap::all_mappings().len(), 106);
        assert_eq!(LinuxHidKeyMap::hid_to_linux(0x00), None);
        assert_eq!(LinuxHidKeyMap::hid_to_linux(0x66), None); // Power key forbidden
        assert_eq!(evdev_to_x11_keycode(MAX_X11_EVDEV_CODE), Some(255));
        assert_eq!(evdev_to_x11_keycode(MAX_X11_EVDEV_CODE + 1), None);
    }

    #[test]
    fn linux_mouse_buttons_cover_all_five_standard_bits() {
        let all = mouse_buttons_mask_to_linux(0x1F);
        assert_eq!(all.len(), 5);
        assert_eq!(all[0].evdev_code, BTN_LEFT);
        assert_eq!(all[0].x11_button, 1);
        assert_eq!(all[1].evdev_code, BTN_RIGHT);
        assert_eq!(all[1].x11_button, 3);
        assert_eq!(all[2].evdev_code, BTN_MIDDLE);
        assert_eq!(all[2].x11_button, 2);
        assert_eq!(all[3].evdev_code, BTN_SIDE);
        assert_eq!(all[3].x11_button, 8);
        assert_eq!(all[4].evdev_code, BTN_EXTRA);
        assert_eq!(all[4].x11_button, 9);
        assert_eq!(mouse_button_bit_to_linux(0x80), None);
    }
}
