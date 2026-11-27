// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#[cfg(all(target_os = "macos", feature = "real-input"))]
use super::{EmergencyKeyReleaser, ReleaseReport};
use super::{OsError, OsHidSink};
use std::{
    collections::BTreeSet,
    sync::{Arc, Mutex},
};

/// All 8 USB HID modifier usages (Left/Right Ctrl, Shift, Alt, Meta), released unconditionally
/// during emergency key release as defense-in-depth.
#[cfg(all(target_os = "macos", feature = "real-input"))]
const ALL_MODIFIER_HID_USAGES: [u16; 8] = [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7];

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> u8;
}

#[cfg(target_os = "macos")]
#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn IsSecureEventInputEnabled() -> u8;
}

/// Pure ANSI positional USB HID Usage Page `0x07` -> macOS virtual keycode (`CGKeyCode`) allowlist.
/// Unknown usages return `None` and are NEVER injected.
pub fn hid_usage_to_macos_keycode(usage: u16) -> Option<u16> {
    match usage {
        // Letters A..Z (USB HID 0x04..=0x1D)
        0x04 => Some(0x00), // A
        0x05 => Some(0x0B), // B
        0x06 => Some(0x08), // C
        0x07 => Some(0x02), // D
        0x08 => Some(0x0E), // E
        0x09 => Some(0x03), // F
        0x0A => Some(0x05), // G
        0x0B => Some(0x04), // H
        0x0C => Some(0x22), // I
        0x0D => Some(0x26), // J
        0x0E => Some(0x28), // K
        0x0F => Some(0x25), // L
        0x10 => Some(0x2E), // M
        0x11 => Some(0x2D), // N
        0x12 => Some(0x1F), // O
        0x13 => Some(0x23), // P
        0x14 => Some(0x0C), // Q
        0x15 => Some(0x0F), // R
        0x16 => Some(0x01), // S
        0x17 => Some(0x11), // T
        0x18 => Some(0x20), // U
        0x19 => Some(0x09), // V
        0x1A => Some(0x0D), // W
        0x1B => Some(0x07), // X
        0x1C => Some(0x10), // Y
        0x1D => Some(0x06), // Z
        // Digits 1..9, 0 (USB HID 0x1E..=0x27)
        0x1E => Some(0x12), // 1
        0x1F => Some(0x13), // 2
        0x20 => Some(0x14), // 3
        0x21 => Some(0x15), // 4
        0x22 => Some(0x17), // 5
        0x23 => Some(0x16), // 6
        0x24 => Some(0x1A), // 7
        0x25 => Some(0x1C), // 8
        0x26 => Some(0x19), // 9
        0x27 => Some(0x1D), // 0
        // Editing / navigation
        0x28 => Some(0x24), // Enter / Return
        0x29 => Some(0x35), // Escape
        0x2A => Some(0x33), // Backspace / Delete
        0x2B => Some(0x30), // Tab
        0x2C => Some(0x31), // Space
        0x2D => Some(0x1B), // Minus
        0x2E => Some(0x18), // Equal
        0x2F => Some(0x21), // LeftBracket
        0x30 => Some(0x1E), // RightBracket
        0x31 => Some(0x2A), // Backslash
        0x33 => Some(0x29), // Semicolon
        0x34 => Some(0x27), // Quote
        0x35 => Some(0x32), // Grave
        0x36 => Some(0x2B), // Comma
        0x37 => Some(0x2F), // Period
        0x38 => Some(0x2C), // Slash
        0x39 => Some(0x39), // CapsLock
        // Function keys F1..F12 (USB HID 0x3A..=0x45)
        0x3A => Some(0x7A), // F1
        0x3B => Some(0x78), // F2
        0x3C => Some(0x63), // F3
        0x3D => Some(0x76), // F4
        0x3E => Some(0x60), // F5
        0x3F => Some(0x61), // F6
        0x40 => Some(0x62), // F7
        0x41 => Some(0x64), // F8
        0x42 => Some(0x65), // F9
        0x43 => Some(0x6D), // F10
        0x44 => Some(0x67), // F11
        0x45 => Some(0x6F), // F12
        // Navigation cluster
        0x4A => Some(0x73), // Home
        0x4B => Some(0x74), // PageUp
        0x4C => Some(0x75), // ForwardDelete
        0x4D => Some(0x77), // End
        0x4E => Some(0x79), // PageDown
        0x4F => Some(0x7C), // RightArrow
        0x50 => Some(0x7B), // LeftArrow
        0x51 => Some(0x7D), // DownArrow
        0x52 => Some(0x7E), // UpArrow
        // Left & Right Modifiers (kept distinct!)
        0xE0 => Some(0x3B), // LeftControl
        0xE1 => Some(0x38), // LeftShift
        0xE2 => Some(0x3A), // LeftAlt / Option
        0xE3 => Some(0x37), // LeftMeta / Command
        0xE4 => Some(0x3E), // RightControl
        0xE5 => Some(0x3C), // RightShift
        0xE6 => Some(0x3D), // RightAlt / Option
        0xE7 => Some(0x36), // RightMeta / Command
        _ => None,
    }
}

/// Runtime opt-in token required (in addition to `cfg(target_os = "macos")`, `feature = "real-input"`,
/// and `AXIsProcessTrusted()`) before any real OS input sink can be constructed.
#[derive(Debug)]
pub struct RealInputPermit {
    _private: (),
}

impl RealInputPermit {
    /// Only succeeds when `explicit_opt_in` is true (e.g. CLI `--real-os-input`) AND the
    /// `real-input` compile-time Cargo feature is enabled.
    pub fn from_explicit_opt_in(explicit_opt_in: bool) -> Result<Self, OsError> {
        if !explicit_opt_in {
            return Err(OsError::UnsupportedPlatform(
                "real OS input requires explicit runtime opt-in (--real-os-input)",
            ));
        }
        #[cfg(feature = "real-input")]
        {
            Ok(Self { _private: () })
        }
        #[cfg(not(feature = "real-input"))]
        {
            Err(OsError::UnsupportedPlatform(
                "real OS input disabled at compile time (enable --features real-input)",
            ))
        }
    }
}

pub fn real_input_compiled_in() -> bool {
    cfg!(feature = "real-input")
}

/// Read-only Accessibility trust check (`AXIsProcessTrusted()` on macOS).
pub fn is_accessibility_trusted() -> bool {
    #[cfg(target_os = "macos")]
    {
        unsafe { AXIsProcessTrusted() != 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Read-only macOS Secure Event Input check (`IsSecureEventInputEnabled()` via Carbon).
pub fn is_secure_event_input_enabled() -> bool {
    #[cfg(target_os = "macos")]
    {
        unsafe { IsSecureEventInputEnabled() != 0 }
    }
    #[cfg(not(target_os = "macos"))]
    {
        false
    }
}

/// Tiny lock-minimal pressed-key/button state shared between an OS HID sink and its independent
/// stateless `EmergencyKeyReleaser`.
/// `interlocked` latches `true` upon emergency release so subsequent sends fail closed until
/// explicitly resumed.
#[derive(Debug, Default)]
pub struct PressedHidState {
    pub keys: BTreeSet<u16>,
    pub buttons: u8,
    pub interlocked: bool,
}

impl PressedHidState {
    pub fn new_shared() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self::default()))
    }
}

#[cfg(all(target_os = "macos", feature = "real-input"))]
mod macos_real_input {
    use super::*;
    use crate::{
        os::OsPermission,
        session::hid::{KeyEvent, MouseEvent, MouseKind, MOD_ALT, MOD_CTRL, MOD_META, MOD_SHIFT},
    };
    use std::{
        ffi::c_void,
        time::{Duration, Instant},
    };

    const K_CG_HID_EVENT_TAP: u32 = 0;
    const K_CG_EVENT_LEFT_MOUSE_DOWN: u32 = 1;
    const K_CG_EVENT_LEFT_MOUSE_UP: u32 = 2;
    const K_CG_EVENT_RIGHT_MOUSE_DOWN: u32 = 3;
    const K_CG_EVENT_RIGHT_MOUSE_UP: u32 = 4;
    const K_CG_EVENT_MOUSE_MOVED: u32 = 5;
    const K_CG_EVENT_OTHER_MOUSE_DOWN: u32 = 25;
    const K_CG_EVENT_OTHER_MOUSE_UP: u32 = 26;

    const K_CG_MOUSE_BUTTON_LEFT: u32 = 0;
    const K_CG_MOUSE_BUTTON_RIGHT: u32 = 1;
    const K_CG_MOUSE_BUTTON_CENTER: u32 = 2;

    const K_CG_EVENT_FLAG_MASK_SHIFT: u64 = 0x0002_0000;
    const K_CG_EVENT_FLAG_MASK_CONTROL: u64 = 0x0004_0000;
    const K_CG_EVENT_FLAG_MASK_ALTERNATE: u64 = 0x0008_0000;
    const K_CG_EVENT_FLAG_MASK_COMMAND: u64 = 0x0010_0000;
    const WHEEL_CLAMP: i32 = 1024;
    const AX_RECHECK_INTERVAL: Duration = Duration::from_secs(2);

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CGPoint {
        x: f64,
        y: f64,
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGMainDisplayID() -> u32;
        fn CGDisplayPixelsWide(display: u32) -> usize;
        fn CGDisplayPixelsHigh(display: u32) -> usize;
        fn CGEventCreateKeyboardEvent(
            source: *const c_void,
            virtual_key: u16,
            key_down: bool,
        ) -> *mut c_void;
        fn CGEventCreateMouseEvent(
            source: *const c_void,
            mouse_type: u32,
            mouse_cursor_position: CGPoint,
            mouse_button: u32,
        ) -> *mut c_void;
        // Fixed-arity non-variadic scroll wheel constructor (safe C ABI across arm64/x86_64).
        fn CGEventCreateScrollWheelEvent2(
            source: *const c_void,
            units: u32,
            wheel_count: u32,
            wheel1: i32,
            wheel2: i32,
            wheel3: i32,
        ) -> *mut c_void;
        fn CGEventSetFlags(event: *mut c_void, flags: u64);
        fn CGEventPost(tap: u32, event: *mut c_void);
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRelease(cf: *const c_void);
    }

    fn modifiers_to_cg_flags(modifiers: u8) -> u64 {
        let mut flags = 0u64;
        if (modifiers & MOD_SHIFT) != 0 {
            flags |= K_CG_EVENT_FLAG_MASK_SHIFT;
        }
        if (modifiers & MOD_CTRL) != 0 {
            flags |= K_CG_EVENT_FLAG_MASK_CONTROL;
        }
        if (modifiers & MOD_ALT) != 0 {
            flags |= K_CG_EVENT_FLAG_MASK_ALTERNATE;
        }
        if (modifiers & MOD_META) != 0 {
            flags |= K_CG_EVENT_FLAG_MASK_COMMAND;
        }
        flags
    }

    fn post_key_event(keycode: u16, down: bool, modifiers: u8) -> bool {
        unsafe {
            let ev = CGEventCreateKeyboardEvent(std::ptr::null(), keycode, down);
            if ev.is_null() {
                return false;
            }
            let flags = modifiers_to_cg_flags(modifiers);
            if flags != 0 {
                CGEventSetFlags(ev, flags);
            }
            CGEventPost(K_CG_HID_EVENT_TAP, ev);
            CFRelease(ev as *const c_void);
            true
        }
    }

    fn post_mouse_event(mouse_type: u32, pt: CGPoint, button: u32) -> bool {
        unsafe {
            let ev = CGEventCreateMouseEvent(std::ptr::null(), mouse_type, pt, button);
            if ev.is_null() {
                return false;
            }
            CGEventPost(K_CG_HID_EVENT_TAP, ev);
            CFRelease(ev as *const c_void);
            true
        }
    }

    /// Posts `keyUp` for every key in `keys`, unconditionally posts `keyUp` for all 8 standard
    /// modifier usages (`0xE0..=0xE7`), and posts `mouseUp` for all bits set in `buttons`.
    /// Requires `AXIsProcessTrusted()` (fail-closed).
    pub fn emergency_release_macos_keys_and_buttons(
        keys: &[u16],
        buttons: u8,
    ) -> Result<ReleaseReport, OsError> {
        if !is_accessibility_trusted() {
            return Err(OsError::PermissionDenied(OsPermission::Accessibility));
        }
        let mut released_keys = 0usize;
        let mut residual_keys = 0usize;
        let mut already_released = BTreeSet::new();
        for &usage in keys {
            if let Some(kc) = hid_usage_to_macos_keycode(usage) {
                if post_key_event(kc, false, 0) {
                    released_keys += 1;
                    already_released.insert(usage);
                } else {
                    residual_keys += 1;
                }
            }
        }
        for mod_usage in ALL_MODIFIER_HID_USAGES {
            if !already_released.contains(&mod_usage) {
                if let Some(kc) = hid_usage_to_macos_keycode(mod_usage) {
                    let _ = post_key_event(kc, false, 0);
                }
            }
        }
        let mut released_buttons = 0usize;
        let mut residual_buttons = 0usize;
        let origin = CGPoint { x: 0.0, y: 0.0 };
        for (mask, ev_type, btn) in [
            (1u8 << 0, K_CG_EVENT_LEFT_MOUSE_UP, K_CG_MOUSE_BUTTON_LEFT),
            (1u8 << 1, K_CG_EVENT_RIGHT_MOUSE_UP, K_CG_MOUSE_BUTTON_RIGHT),
            (1u8 << 2, K_CG_EVENT_OTHER_MOUSE_UP, K_CG_MOUSE_BUTTON_CENTER),
        ] {
            if (buttons & mask) != 0 {
                if post_mouse_event(ev_type, origin, btn) {
                    released_buttons += 1;
                } else {
                    residual_buttons += 1;
                }
            }
        }
        Ok(ReleaseReport {
            released_keys,
            released_buttons,
            residual_keys,
            residual_buttons,
        })
    }

    /// Stateless emergency releaser: sets `interlocked = true`, snapshots & clears pressed state
    /// under a tiny lock, drops lock, posts `keyUp`/`mouseUp` + all 8 modifier `keyUp`s directly
    /// to `CGEventPost` without borrowing `MacOsHidSink`.
    pub struct MacOsEmergencyKeyReleaser {
        pressed: Arc<Mutex<PressedHidState>>,
    }

    impl EmergencyKeyReleaser for MacOsEmergencyKeyReleaser {
        fn release_all_keys(&self) -> ReleaseReport {
            let (keys, buttons) = {
                let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                g.interlocked = true;
                let keys: Vec<u16> = g.keys.iter().copied().collect();
                let buttons = g.buttons;
                g.keys.clear();
                g.buttons = 0;
                (keys, buttons)
            };
            let mut released_keys = 0usize;
            let mut residual_keys = 0usize;
            let mut already_released = BTreeSet::new();
            for usage in keys {
                if let Some(kc) = hid_usage_to_macos_keycode(usage) {
                    if post_key_event(kc, false, 0) {
                        released_keys += 1;
                        already_released.insert(usage);
                    } else {
                        residual_keys += 1;
                    }
                }
            }
            // Defense-in-depth: unconditionally post keyUp for all 8 modifiers.
            for mod_usage in ALL_MODIFIER_HID_USAGES {
                if !already_released.contains(&mod_usage) {
                    if let Some(kc) = hid_usage_to_macos_keycode(mod_usage) {
                        let _ = post_key_event(kc, false, 0);
                    }
                }
            }
            let mut released_buttons = 0usize;
            let mut residual_buttons = 0usize;
            let origin = CGPoint { x: 0.0, y: 0.0 };
            for (mask, ev_type, btn) in [
                (1u8 << 0, K_CG_EVENT_LEFT_MOUSE_UP, K_CG_MOUSE_BUTTON_LEFT),
                (1u8 << 1, K_CG_EVENT_RIGHT_MOUSE_UP, K_CG_MOUSE_BUTTON_RIGHT),
                (1u8 << 2, K_CG_EVENT_OTHER_MOUSE_UP, K_CG_MOUSE_BUTTON_CENTER),
            ] {
                if (buttons & mask) != 0 {
                    if post_mouse_event(ev_type, origin, btn) {
                        released_buttons += 1;
                    } else {
                        residual_buttons += 1;
                    }
                }
            }
            ReleaseReport {
                released_keys,
                released_buttons,
                residual_keys,
                residual_buttons,
            }
        }
    }

    pub struct MacOsHidSink {
        pressed: Arc<Mutex<PressedHidState>>,
        cursor_pt: CGPoint,
        last_ax_check: Instant,
    }

    impl MacOsHidSink {
        /// Triple-gated constructor: requires `cfg(macos)`, `feature = "real-input"`,
        /// runtime `Arc<RealInputPermit>`, AND `AXIsProcessTrusted()`.
        pub fn new(_permit: Arc<RealInputPermit>) -> Result<Self, OsError> {
            if !is_accessibility_trusted() {
                return Err(OsError::PermissionDenied(OsPermission::Accessibility));
            }
            Ok(Self {
                pressed: PressedHidState::new_shared(),
                cursor_pt: CGPoint { x: 0.0, y: 0.0 },
                last_ax_check: Instant::now(),
            })
        }

        fn ensure_ax_trusted(&mut self) -> Result<(), OsError> {
            if self.last_ax_check.elapsed() >= AX_RECHECK_INTERVAL {
                if !is_accessibility_trusted() {
                    return Err(OsError::PermissionDenied(OsPermission::Accessibility));
                }
                self.last_ax_check = Instant::now();
            }
            Ok(())
        }

        fn display_point_bounds() -> (f64, f64) {
            unsafe {
                let disp = CGMainDisplayID();
                let w = CGDisplayPixelsWide(disp).max(1) as f64;
                let h = CGDisplayPixelsHigh(disp).max(1) as f64;
                (w, h)
            }
        }
    }

    impl OsHidSink for MacOsHidSink {
        fn send_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
            self.ensure_ax_trusted()?;
            let Ok(usage) = u16::try_from(ev.usb_hid_usage) else {
                return Err(OsError::InvalidData(format!(
                    "USB HID usage {:#x} exceeds u16 range",
                    ev.usb_hid_usage
                )));
            };
            let Some(kc) = hid_usage_to_macos_keycode(usage) else {
                // Unknown HID usage: never inject.
                return Ok(());
            };
            {
                let g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                if g.interlocked {
                    return Err(OsError::Interlocked);
                }
            }
            // Post FIRST; only update `pressed` on success so failed key-up stays tracked for EmergencyKeyReleaser!
            if !post_key_event(kc, ev.down, ev.modifiers) {
                return Err(OsError::CaptureFailed(
                    "CGEventCreateKeyboardEvent failed".into(),
                ));
            }
            let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
            if g.interlocked {
                // Emergency release raced while we were posting; post keyUp defensively if we pressed down.
                if ev.down {
                    drop(g);
                    let _ = post_key_event(kc, false, 0);
                }
                return Err(OsError::Interlocked);
            }
            if ev.down {
                g.keys.insert(usage);
            } else {
                g.keys.remove(&usage);
            }
            Ok(())
        }

        fn send_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError> {
            self.ensure_ax_trusted()?;
            {
                let g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                if g.interlocked {
                    return Err(OsError::Interlocked);
                }
            }
            let (pw, ph) = Self::display_point_bounds();
            let max_x = (pw.max(1.0) - 1.0).max(0.0);
            let max_y = (ph.max(1.0) - 1.0).max(0.0);
            let buttons = ev.buttons & 0x07;
            match ev.kind {
                MouseKind::MoveAbs => {
                    let x = ((ev.x_or_dx.max(0) as f64) / 65535.0).clamp(0.0, 1.0) * max_x;
                    let y = ((ev.y_or_dy.max(0) as f64) / 65535.0).clamp(0.0, 1.0) * max_y;
                    let next_pt = CGPoint { x, y };
                    if !post_mouse_event(K_CG_EVENT_MOUSE_MOVED, next_pt, K_CG_MOUSE_BUTTON_LEFT) {
                        return Err(OsError::CaptureFailed("CGEventCreateMouseEvent failed".into()));
                    }
                    self.cursor_pt = next_pt;
                }
                MouseKind::MoveRel => {
                    let next_pt = CGPoint {
                        x: (self.cursor_pt.x + ev.x_or_dx as f64).clamp(0.0, max_x),
                        y: (self.cursor_pt.y + ev.y_or_dy as f64).clamp(0.0, max_y),
                    };
                    if !post_mouse_event(K_CG_EVENT_MOUSE_MOVED, next_pt, K_CG_MOUSE_BUTTON_LEFT) {
                        return Err(OsError::CaptureFailed("CGEventCreateMouseEvent failed".into()));
                    }
                    self.cursor_pt = next_pt;
                }
                MouseKind::Down => {
                    for (mask, down_ev, up_ev, btn) in [
                        (
                            1u8 << 0,
                            K_CG_EVENT_LEFT_MOUSE_DOWN,
                            K_CG_EVENT_LEFT_MOUSE_UP,
                            K_CG_MOUSE_BUTTON_LEFT,
                        ),
                        (
                            1u8 << 1,
                            K_CG_EVENT_RIGHT_MOUSE_DOWN,
                            K_CG_EVENT_RIGHT_MOUSE_UP,
                            K_CG_MOUSE_BUTTON_RIGHT,
                        ),
                        (
                            1u8 << 2,
                            K_CG_EVENT_OTHER_MOUSE_DOWN,
                            K_CG_EVENT_OTHER_MOUSE_UP,
                            K_CG_MOUSE_BUTTON_CENTER,
                        ),
                    ] {
                        if (buttons & mask) != 0 {
                            {
                                let g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                                if g.interlocked {
                                    return Err(OsError::Interlocked);
                                }
                            }
                            if !post_mouse_event(down_ev, self.cursor_pt, btn) {
                                return Err(OsError::CaptureFailed(
                                    "CGEventCreateMouseEvent(down) failed".into(),
                                ));
                            }
                            let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                            if g.interlocked {
                                drop(g);
                                let _ = post_mouse_event(up_ev, self.cursor_pt, btn);
                                return Err(OsError::Interlocked);
                            }
                            g.buttons |= mask;
                        }
                    }
                }
                MouseKind::Up => {
                    for (mask, up_ev, btn) in [
                        (1u8 << 0, K_CG_EVENT_LEFT_MOUSE_UP, K_CG_MOUSE_BUTTON_LEFT),
                        (1u8 << 1, K_CG_EVENT_RIGHT_MOUSE_UP, K_CG_MOUSE_BUTTON_RIGHT),
                        (
                            1u8 << 2,
                            K_CG_EVENT_OTHER_MOUSE_UP,
                            K_CG_MOUSE_BUTTON_CENTER,
                        ),
                    ] {
                        if (buttons & mask) != 0 {
                            {
                                let g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                                if g.interlocked {
                                    return Err(OsError::Interlocked);
                                }
                            }
                            if !post_mouse_event(up_ev, self.cursor_pt, btn) {
                                return Err(OsError::CaptureFailed(
                                    "CGEventCreateMouseEvent(up) failed".into(),
                                ));
                            }
                            let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                            g.buttons &= !mask;
                        }
                    }
                }
                MouseKind::Wheel => {
                    {
                        let g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                        if g.interlocked {
                            return Err(OsError::Interlocked);
                        }
                    }
                    let wy = (ev.wheel_dy as i32).clamp(-WHEEL_CLAMP, WHEEL_CLAMP);
                    let wx = (ev.wheel_dx as i32).clamp(-WHEEL_CLAMP, WHEEL_CLAMP);
                    unsafe {
                        let scroll =
                            CGEventCreateScrollWheelEvent2(std::ptr::null(), 1, 2, wy, wx, 0);
                        if scroll.is_null() {
                            return Err(OsError::CaptureFailed(
                                "CGEventCreateScrollWheelEvent2 failed".into(),
                            ));
                        }
                        CGEventPost(K_CG_HID_EVENT_TAP, scroll);
                        CFRelease(scroll as *const c_void);
                    }
                }
            }
            Ok(())
        }

        fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
            Arc::new(MacOsEmergencyKeyReleaser {
                pressed: Arc::clone(&self.pressed),
            })
        }
    }
}

/// Attempts to create the platform's real OS HID sink. Triple-gated on macOS; returns
/// `UnsupportedPlatform` when `real-input` feature is off or on unsupported platforms.
pub fn create_real_os_hid_sink(permit: Arc<RealInputPermit>) -> Result<Box<dyn OsHidSink>, OsError> {
    #[cfg(all(target_os = "macos", feature = "real-input"))]
    {
        Ok(Box::new(macos_real_input::MacOsHidSink::new(permit)?))
    }
    #[cfg(not(all(target_os = "macos", feature = "real-input")))]
    {
        let _ = permit;
        Err(OsError::UnsupportedPlatform(
            "real OS HID sink unavailable on this platform/feature set",
        ))
    }
}

/// Releases all specified HID keys, all 8 standard modifiers, and mouse buttons directly via OS APIs.
/// Triple-gated: requires `cfg(target_os = "macos")`, `feature = "real-input"`, `RealInputPermit`,
/// and `AXIsProcessTrusted()`.
pub fn emergency_release_real_os_keys(
    permit: &RealInputPermit,
    keys: &[u16],
    buttons: u8,
) -> Result<super::ReleaseReport, OsError> {
    let _ = permit;
    #[cfg(all(target_os = "macos", feature = "real-input"))]
    {
        macos_real_input::emergency_release_macos_keys_and_buttons(keys, buttons)
    }
    #[cfg(not(all(target_os = "macos", feature = "real-input")))]
    {
        let _ = (keys, buttons);
        Err(OsError::UnsupportedPlatform(
            "real OS HID emergency release unavailable on this platform/feature set",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hid_usage_to_macos_keycode_pure_allowlist_mapping() {
        assert_eq!(hid_usage_to_macos_keycode(0x04), Some(0x00)); // A
        assert_eq!(hid_usage_to_macos_keycode(0x1D), Some(0x06)); // Z
        assert_eq!(hid_usage_to_macos_keycode(0x28), Some(0x24)); // Enter
        assert_eq!(hid_usage_to_macos_keycode(0x29), Some(0x35)); // Escape
        assert_eq!(hid_usage_to_macos_keycode(0x2C), Some(0x31)); // Space
        assert_eq!(hid_usage_to_macos_keycode(0x3A), Some(0x7A)); // F1
        assert_eq!(hid_usage_to_macos_keycode(0x45), Some(0x6F)); // F12
        assert_eq!(hid_usage_to_macos_keycode(0xE0), Some(0x3B)); // LCtrl
        assert_eq!(hid_usage_to_macos_keycode(0xE4), Some(0x3E)); // RCtrl
        assert_ne!(
            hid_usage_to_macos_keycode(0xE1),
            hid_usage_to_macos_keycode(0xE5)
        );
        assert_eq!(hid_usage_to_macos_keycode(0x00), None);
        assert_eq!(hid_usage_to_macos_keycode(0xFF), None);
        assert_eq!(hid_usage_to_macos_keycode(0x9999), None);
    }

    #[test]
    fn real_input_permit_requires_explicit_opt_in() {
        assert!(RealInputPermit::from_explicit_opt_in(false).is_err());
        #[cfg(not(feature = "real-input"))]
        assert!(RealInputPermit::from_explicit_opt_in(true).is_err());
        #[cfg(feature = "real-input")]
        assert!(RealInputPermit::from_explicit_opt_in(true).is_ok());
    }
}
