// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    capture::SharedVisualMarker,
    config::sync_parent_dir,
    hid::{
        HidBatchOutcome, HidPayload, KeyEvent, MouseEvent, MouseKind, HID_MOVEREL_COALESCE_MAX,
        MOD_ALT, MOD_CTRL, MOD_META, MOD_SHIFT, MOUSE_BUTTONS_VALID_MASK,
    },
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::{
    collections::{BTreeSet, VecDeque},
    fmt,
    fs::{self, OpenOptions},
    io::{BufWriter, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering},
        mpsc::{self, RecvTimeoutError},
        Arc, Mutex, TryLockError,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use v2_transport::HID_STALE_DROP_MS;

pub const MAX_HID_BATCH_SIZE: usize = 128;
pub const DEFAULT_HID_RATE_LIMIT_PER_SEC: u32 = 1000;
pub const DEFAULT_AUDIT_LOG_CAP: usize = 10_000;
pub const MOUSE_BUTTON_LEFT: u8 = 1 << 0;
pub const MOUSE_BUTTON_RIGHT: u8 = 1 << 1;
pub const MOUSE_BUTTON_MIDDLE: u8 = 1 << 2;
pub const MOUSE_BUTTON_BACK: u8 = 1 << 3;
pub const MOUSE_BUTTON_FORWARD: u8 = 1 << 4;

/// Normative `spec/04` §6.2.4 bounded `release_all` retry policy:
/// 1 initial pass + up to 5 retries with exponential backoff `[50, 100, 200, 400, 500]ms`.
pub const HID_RELEASE_ALL_MAX_RETRIES: usize = 5;
pub const HID_RELEASE_ALL_BACKOFF_MS: [u64; HID_RELEASE_ALL_MAX_RETRIES] =
    [50, 100, 200, 400, 500];
const _: () = assert!(HID_RELEASE_ALL_BACKOFF_MS.len() == HID_RELEASE_ALL_MAX_RETRIES);

/// Normative `spec/04` §6.2.4 watchdog bounds (`1s <= watchdog_timeout <= 10s`).
pub const HID_WATCHDOG_MIN_MS: u64 = 1_000;
pub const HID_WATCHDOG_MAX_MS: u64 = 10_000;
/// Floor for `spawn_independent_release_watchdog` so deterministic tests can use short timeouts
/// while production configs enforce `HID_WATCHDOG_MIN_MS` (`>= 1000ms`) in `V2ClientConfig::validate`.
pub const HID_WATCHDOG_FLOOR_MS: u64 = 20;
pub const WATCHDOG_JOIN_TIMEOUT: Duration = Duration::from_millis(2_000);

static AUDIT_TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputSinkError {
    Backend(String),
}

impl fmt::Display for InputSinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Backend(msg) => write!(f, "HID input sink backend error: {msg}"),
        }
    }
}

impl std::error::Error for InputSinkError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InputError {
    PermissionDenied(String),
    InvalidBounds(String),
    BatchTooLarge { len: usize, max: usize },
    SinkFailed(String),
    SessionTerminated,
    InputFaulted,
    InvalidFraming(String),
}

impl fmt::Display for InputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(msg) => write!(f, "HID input permission denied: {msg}"),
            Self::InvalidBounds(msg) => write!(f, "invalid HID screen bounds: {msg}"),
            Self::BatchTooLarge { len, max } => {
                write!(f, "HID batch size {len} exceeds maximum {max}")
            }
            Self::SinkFailed(msg) => write!(f, "HID sink failed (session must terminate): {msg}"),
            Self::SessionTerminated => write!(
                f,
                "HID input executor is terminated after a fatal sink failure"
            ),
            Self::InputFaulted => write!(
                f,
                "HID input subsystem is fault-latched after bounded release_all exhaustion (emit 0x04 SESSION_CLOSE 0x0103)"
            ),
            Self::InvalidFraming(msg) => write!(f, "HID framing error (0x0103): {msg}"),
        }
    }
}

impl std::error::Error for InputError {}

/// Strict USB HID Usage Page `0x07` key whitelist.
/// Left and right modifiers are distinct variants and are NEVER merged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SafeHidKey {
    KeyA,
    KeyB,
    KeyC,
    KeyD,
    KeyE,
    KeyF,
    KeyG,
    KeyH,
    KeyI,
    KeyJ,
    KeyK,
    KeyL,
    KeyM,
    KeyN,
    KeyO,
    KeyP,
    KeyQ,
    KeyR,
    KeyS,
    KeyT,
    KeyU,
    KeyV,
    KeyW,
    KeyX,
    KeyY,
    KeyZ,
    Digit1,
    Digit2,
    Digit3,
    Digit4,
    Digit5,
    Digit6,
    Digit7,
    Digit8,
    Digit9,
    Digit0,
    Enter,
    Escape,
    Backspace,
    Tab,
    Space,
    F1,
    F2,
    F3,
    F4,
    F5,
    F6,
    F7,
    F8,
    F9,
    F10,
    F11,
    F12,
    Delete,
    RightArrow,
    LeftArrow,
    DownArrow,
    UpArrow,
    LeftControl,
    LeftShift,
    LeftAlt,
    LeftMeta,
    RightControl,
    RightShift,
    RightAlt,
    RightMeta,
}

impl SafeHidKey {
    /// Parses a USB HID Usage Page `0x07` usage value (`0x0007_00xx` or bare `0x0000_00xx`).
    /// Performs zero fallback or bit-masking; any unknown usage page or usage ID returns `None`.
    pub fn from_usb_hid_usage(usage: u32) -> Option<Self> {
        let page = usage >> 16;
        if page != 0x0000 && page != 0x0007 {
            return None;
        }
        let code = usage & 0xFFFF;
        match code {
            0x04 => Some(Self::KeyA),
            0x05 => Some(Self::KeyB),
            0x06 => Some(Self::KeyC),
            0x07 => Some(Self::KeyD),
            0x08 => Some(Self::KeyE),
            0x09 => Some(Self::KeyF),
            0x0A => Some(Self::KeyG),
            0x0B => Some(Self::KeyH),
            0x0C => Some(Self::KeyI),
            0x0D => Some(Self::KeyJ),
            0x0E => Some(Self::KeyK),
            0x0F => Some(Self::KeyL),
            0x10 => Some(Self::KeyM),
            0x11 => Some(Self::KeyN),
            0x12 => Some(Self::KeyO),
            0x13 => Some(Self::KeyP),
            0x14 => Some(Self::KeyQ),
            0x15 => Some(Self::KeyR),
            0x16 => Some(Self::KeyS),
            0x17 => Some(Self::KeyT),
            0x18 => Some(Self::KeyU),
            0x19 => Some(Self::KeyV),
            0x1A => Some(Self::KeyW),
            0x1B => Some(Self::KeyX),
            0x1C => Some(Self::KeyY),
            0x1D => Some(Self::KeyZ),
            0x1E => Some(Self::Digit1),
            0x1F => Some(Self::Digit2),
            0x20 => Some(Self::Digit3),
            0x21 => Some(Self::Digit4),
            0x22 => Some(Self::Digit5),
            0x23 => Some(Self::Digit6),
            0x24 => Some(Self::Digit7),
            0x25 => Some(Self::Digit8),
            0x26 => Some(Self::Digit9),
            0x27 => Some(Self::Digit0),
            0x28 => Some(Self::Enter),
            0x29 => Some(Self::Escape),
            0x2A => Some(Self::Backspace),
            0x2B => Some(Self::Tab),
            0x2C => Some(Self::Space),
            0x3A => Some(Self::F1),
            0x3B => Some(Self::F2),
            0x3C => Some(Self::F3),
            0x3D => Some(Self::F4),
            0x3E => Some(Self::F5),
            0x3F => Some(Self::F6),
            0x40 => Some(Self::F7),
            0x41 => Some(Self::F8),
            0x42 => Some(Self::F9),
            0x43 => Some(Self::F10),
            0x44 => Some(Self::F11),
            0x45 => Some(Self::F12),
            0x4C => Some(Self::Delete),
            0x4F => Some(Self::RightArrow),
            0x50 => Some(Self::LeftArrow),
            0x51 => Some(Self::DownArrow),
            0x52 => Some(Self::UpArrow),
            0xE0 => Some(Self::LeftControl),
            0xE1 => Some(Self::LeftShift),
            0xE2 => Some(Self::LeftAlt),
            0xE3 => Some(Self::LeftMeta),
            0xE4 => Some(Self::RightControl),
            0xE5 => Some(Self::RightShift),
            0xE6 => Some(Self::RightAlt),
            0xE7 => Some(Self::RightMeta),
            _ => None,
        }
    }

    pub fn usb_hid_usage(self) -> u32 {
        match self {
            Self::KeyA => 0x04,
            Self::KeyB => 0x05,
            Self::KeyC => 0x06,
            Self::KeyD => 0x07,
            Self::KeyE => 0x08,
            Self::KeyF => 0x09,
            Self::KeyG => 0x0A,
            Self::KeyH => 0x0B,
            Self::KeyI => 0x0C,
            Self::KeyJ => 0x0D,
            Self::KeyK => 0x0E,
            Self::KeyL => 0x0F,
            Self::KeyM => 0x10,
            Self::KeyN => 0x11,
            Self::KeyO => 0x12,
            Self::KeyP => 0x13,
            Self::KeyQ => 0x14,
            Self::KeyR => 0x15,
            Self::KeyS => 0x16,
            Self::KeyT => 0x17,
            Self::KeyU => 0x18,
            Self::KeyV => 0x19,
            Self::KeyW => 0x1A,
            Self::KeyX => 0x1B,
            Self::KeyY => 0x1C,
            Self::KeyZ => 0x1D,
            Self::Digit1 => 0x1E,
            Self::Digit2 => 0x1F,
            Self::Digit3 => 0x20,
            Self::Digit4 => 0x21,
            Self::Digit5 => 0x22,
            Self::Digit6 => 0x23,
            Self::Digit7 => 0x24,
            Self::Digit8 => 0x25,
            Self::Digit9 => 0x26,
            Self::Digit0 => 0x27,
            Self::Enter => 0x28,
            Self::Escape => 0x29,
            Self::Backspace => 0x2A,
            Self::Tab => 0x2B,
            Self::Space => 0x2C,
            Self::F1 => 0x3A,
            Self::F2 => 0x3B,
            Self::F3 => 0x3C,
            Self::F4 => 0x3D,
            Self::F5 => 0x3E,
            Self::F6 => 0x3F,
            Self::F7 => 0x40,
            Self::F8 => 0x41,
            Self::F9 => 0x42,
            Self::F10 => 0x43,
            Self::F11 => 0x44,
            Self::F12 => 0x45,
            Self::Delete => 0x4C,
            Self::RightArrow => 0x4F,
            Self::LeftArrow => 0x50,
            Self::DownArrow => 0x51,
            Self::UpArrow => 0x52,
            Self::LeftControl => 0xE0,
            Self::LeftShift => 0xE1,
            Self::LeftAlt => 0xE2,
            Self::LeftMeta => 0xE3,
            Self::RightControl => 0xE4,
            Self::RightShift => 0xE5,
            Self::RightAlt => 0xE6,
            Self::RightMeta => 0xE7,
        }
    }
}

/// Key identifier recorded in audit logs: redacted by default to avoid logging typed secrets
/// unless explicitly opted in via `HidInputExecutor::with_audit_key_identity(true)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditKey {
    Key(SafeHidKey),
    Redacted,
}

impl Serialize for AuditKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Key(k) => k.serialize(serializer),
            Self::Redacted => serializer.serialize_str("redacted"),
        }
    }
}

impl<'de> Deserialize<'de> for AuditKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        if s == "redacted" {
            return Ok(Self::Redacted);
        }
        serde_json::from_value::<SafeHidKey>(serde_json::Value::String(s))
            .map(Self::Key)
            .map_err(serde::de::Error::custom)
    }
}

/// Outcome of `HidInputSink::release_all_best_effort`: reports any buttons or keys whose
/// release panicked or failed so `HidInputExecutor` retains them for bounded retry.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ReleaseAllResult {
    pub failed_buttons: u8,
    pub failed_keys: Vec<SafeHidKey>,
}

/// Pure side-effect sink trait. Sinks MUST NOT track pressed state; all state lives in
/// `HidInputExecutor` / `AtomicHeldState`.
pub trait HidInputSink: Send {
    /// Optional per-batch preflight hook (e.g. macOS Accessibility trust re-check).
    fn preflight_batch(&mut self) -> Result<(), InputSinkError> {
        Ok(())
    }

    fn move_abs(&mut self, x: i32, y: i32) -> Result<(), InputSinkError>;
    fn move_rel(&mut self, dx: i32, dy: i32) -> Result<(), InputSinkError>;
    fn mouse_down(&mut self, button_bit: u8) -> Result<(), InputSinkError>;
    fn mouse_up(&mut self, button_bit: u8) -> Result<(), InputSinkError>;
    fn wheel(&mut self, dx: i16, dy: i16) -> Result<(), InputSinkError>;
    fn key_down(&mut self, key: SafeHidKey) -> Result<(), InputSinkError>;
    fn key_up(&mut self, key: SafeHidKey) -> Result<(), InputSinkError>;

    /// Best-effort infallible release of all currently held buttons and keys.
    /// MUST isolate each item and MUST NEVER panic.
    fn release_all_best_effort(
        &mut self,
        pressed_buttons: u8,
        pressed_keys: &[SafeHidKey],
    ) -> ReleaseAllResult;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DryRunOp {
    MoveAbs { x: i32, y: i32 },
    MoveRel { dx: i32, dy: i32 },
    MouseDown { button_bit: u8 },
    MouseUp { button_bit: u8 },
    Wheel { dx: i16, dy: i16 },
    KeyDown { key: SafeHidKey },
    KeyUp { key: SafeHidKey },
}

/// Pure in-memory recording sink with zero OS side effects.
#[derive(Debug, Default)]
pub struct DryRunSink {
    pub ops: Vec<DryRunOp>,
}

impl DryRunSink {
    pub fn new() -> Self {
        Self::default()
    }
}

impl HidInputSink for DryRunSink {
    fn move_abs(&mut self, x: i32, y: i32) -> Result<(), InputSinkError> {
        self.ops.push(DryRunOp::MoveAbs { x, y });
        Ok(())
    }

    fn move_rel(&mut self, dx: i32, dy: i32) -> Result<(), InputSinkError> {
        self.ops.push(DryRunOp::MoveRel { dx, dy });
        Ok(())
    }

    fn mouse_down(&mut self, button_bit: u8) -> Result<(), InputSinkError> {
        self.ops.push(DryRunOp::MouseDown { button_bit });
        Ok(())
    }

    fn mouse_up(&mut self, button_bit: u8) -> Result<(), InputSinkError> {
        self.ops.push(DryRunOp::MouseUp { button_bit });
        Ok(())
    }

    fn wheel(&mut self, dx: i16, dy: i16) -> Result<(), InputSinkError> {
        self.ops.push(DryRunOp::Wheel { dx, dy });
        Ok(())
    }

    fn key_down(&mut self, key: SafeHidKey) -> Result<(), InputSinkError> {
        self.ops.push(DryRunOp::KeyDown { key });
        Ok(())
    }

    fn key_up(&mut self, key: SafeHidKey) -> Result<(), InputSinkError> {
        self.ops.push(DryRunOp::KeyUp { key });
        Ok(())
    }

    fn release_all_best_effort(
        &mut self,
        pressed_buttons: u8,
        pressed_keys: &[SafeHidKey],
    ) -> ReleaseAllResult {
        for bit_idx in 0..5u8 {
            let bit = 1u8 << bit_idx;
            if pressed_buttons & bit != 0 {
                self.ops.push(DryRunOp::MouseUp { button_bit: bit });
            }
        }
        for &key in pressed_keys {
            self.ops.push(DryRunOp::KeyUp { key });
        }
        ReleaseAllResult::default()
    }
}

#[cfg(all(
    feature = "os-input",
    not(any(target_os = "android", target_os = "ios"))
))]
mod os_sink {
    use super::{
        HidInputSink, InputError, InputSinkError, ReleaseAllResult, SafeHidKey, MOUSE_BUTTON_BACK,
        MOUSE_BUTTON_FORWARD, MOUSE_BUTTON_LEFT, MOUSE_BUTTON_MIDDLE, MOUSE_BUTTON_RIGHT,
    };
    use enigo::{Enigo, Key, KeyboardControllable, MouseButton, MouseControllable};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[cfg(target_os = "macos")]
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrusted() -> u8;
    }

    #[cfg(target_os = "macos")]
    fn is_macos_accessibility_trusted() -> bool {
        unsafe { AXIsProcessTrusted() != 0 }
    }

    fn map_safe_key_to_enigo(key: SafeHidKey) -> Key {
        match key {
            SafeHidKey::KeyA => Key::Layout('a'),
            SafeHidKey::KeyB => Key::Layout('b'),
            SafeHidKey::KeyC => Key::Layout('c'),
            SafeHidKey::KeyD => Key::Layout('d'),
            SafeHidKey::KeyE => Key::Layout('e'),
            SafeHidKey::KeyF => Key::Layout('f'),
            SafeHidKey::KeyG => Key::Layout('g'),
            SafeHidKey::KeyH => Key::Layout('h'),
            SafeHidKey::KeyI => Key::Layout('i'),
            SafeHidKey::KeyJ => Key::Layout('j'),
            SafeHidKey::KeyK => Key::Layout('k'),
            SafeHidKey::KeyL => Key::Layout('l'),
            SafeHidKey::KeyM => Key::Layout('m'),
            SafeHidKey::KeyN => Key::Layout('n'),
            SafeHidKey::KeyO => Key::Layout('o'),
            SafeHidKey::KeyP => Key::Layout('p'),
            SafeHidKey::KeyQ => Key::Layout('q'),
            SafeHidKey::KeyR => Key::Layout('r'),
            SafeHidKey::KeyS => Key::Layout('s'),
            SafeHidKey::KeyT => Key::Layout('t'),
            SafeHidKey::KeyU => Key::Layout('u'),
            SafeHidKey::KeyV => Key::Layout('v'),
            SafeHidKey::KeyW => Key::Layout('w'),
            SafeHidKey::KeyX => Key::Layout('x'),
            SafeHidKey::KeyY => Key::Layout('y'),
            SafeHidKey::KeyZ => Key::Layout('z'),
            SafeHidKey::Digit1 => Key::Layout('1'),
            SafeHidKey::Digit2 => Key::Layout('2'),
            SafeHidKey::Digit3 => Key::Layout('3'),
            SafeHidKey::Digit4 => Key::Layout('4'),
            SafeHidKey::Digit5 => Key::Layout('5'),
            SafeHidKey::Digit6 => Key::Layout('6'),
            SafeHidKey::Digit7 => Key::Layout('7'),
            SafeHidKey::Digit8 => Key::Layout('8'),
            SafeHidKey::Digit9 => Key::Layout('9'),
            SafeHidKey::Digit0 => Key::Layout('0'),
            SafeHidKey::Enter => Key::Return,
            SafeHidKey::Escape => Key::Escape,
            SafeHidKey::Backspace => Key::Backspace,
            SafeHidKey::Tab => Key::Tab,
            SafeHidKey::Space => Key::Space,
            SafeHidKey::F1 => Key::F1,
            SafeHidKey::F2 => Key::F2,
            SafeHidKey::F3 => Key::F3,
            SafeHidKey::F4 => Key::F4,
            SafeHidKey::F5 => Key::F5,
            SafeHidKey::F6 => Key::F6,
            SafeHidKey::F7 => Key::F7,
            SafeHidKey::F8 => Key::F8,
            SafeHidKey::F9 => Key::F9,
            SafeHidKey::F10 => Key::F10,
            SafeHidKey::F11 => Key::F11,
            SafeHidKey::F12 => Key::F12,
            SafeHidKey::Delete => Key::Delete,
            SafeHidKey::RightArrow => Key::RightArrow,
            SafeHidKey::LeftArrow => Key::LeftArrow,
            SafeHidKey::DownArrow => Key::DownArrow,
            SafeHidKey::UpArrow => Key::UpArrow,
            SafeHidKey::LeftControl => Key::Control,
            SafeHidKey::LeftShift => Key::Shift,
            SafeHidKey::LeftAlt => Key::Alt,
            SafeHidKey::LeftMeta => Key::Meta,
            SafeHidKey::RightControl => Key::RightControl,
            SafeHidKey::RightShift => Key::RightShift,
            SafeHidKey::RightAlt => Key::RightAlt,
            SafeHidKey::RightMeta => Key::RWin,
        }
    }

    fn map_button_bit(button_bit: u8) -> Result<MouseButton, InputSinkError> {
        match button_bit {
            MOUSE_BUTTON_LEFT => Ok(MouseButton::Left),
            MOUSE_BUTTON_RIGHT => Ok(MouseButton::Right),
            MOUSE_BUTTON_MIDDLE => Ok(MouseButton::Middle),
            MOUSE_BUTTON_BACK => Ok(MouseButton::Back),
            MOUSE_BUTTON_FORWARD => Ok(MouseButton::Forward),
            other => Err(InputSinkError::Backend(format!(
                "unsupported mouse button bit {other:#04x}"
            ))),
        }
    }

    /// Real OS synthetic input sink backed by `enigo::Enigo`.
    /// Gated behind `#[cfg(feature = "os-input")]` (never enabled by default).
    pub struct EnigoOsSink {
        enigo: Enigo,
    }

    impl EnigoOsSink {
        pub fn new() -> Result<Self, InputError> {
            #[cfg(target_os = "macos")]
            {
                if !is_macos_accessibility_trusted() {
                    return Err(InputError::PermissionDenied(
                        "macOS Accessibility permission not granted".into(),
                    ));
                }
            }
            let enigo = catch_unwind(AssertUnwindSafe(Enigo::new)).map_err(|_| {
                InputError::SinkFailed("Enigo::new panicked during initialization".into())
            })?;
            Ok(Self { enigo })
        }
    }

    impl HidInputSink for EnigoOsSink {
        fn preflight_batch(&mut self) -> Result<(), InputSinkError> {
            #[cfg(target_os = "macos")]
            {
                if !is_macos_accessibility_trusted() {
                    return Err(InputSinkError::Backend(
                        "macOS Accessibility permission revoked".into(),
                    ));
                }
            }
            Ok(())
        }

        fn move_abs(&mut self, x: i32, y: i32) -> Result<(), InputSinkError> {
            catch_unwind(AssertUnwindSafe(|| self.enigo.mouse_move_to(x, y)))
                .map_err(|_| InputSinkError::Backend("enigo mouse_move_to panicked".into()))
        }

        fn move_rel(&mut self, dx: i32, dy: i32) -> Result<(), InputSinkError> {
            catch_unwind(AssertUnwindSafe(|| self.enigo.mouse_move_relative(dx, dy)))
                .map_err(|_| InputSinkError::Backend("enigo mouse_move_relative panicked".into()))
        }

        fn mouse_down(&mut self, button_bit: u8) -> Result<(), InputSinkError> {
            let btn = map_button_bit(button_bit)?;
            match catch_unwind(AssertUnwindSafe(|| self.enigo.mouse_down(btn))) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(InputSinkError::Backend(e.to_string())),
                Err(_) => Err(InputSinkError::Backend("enigo mouse_down panicked".into())),
            }
        }

        fn mouse_up(&mut self, button_bit: u8) -> Result<(), InputSinkError> {
            let btn = map_button_bit(button_bit)?;
            catch_unwind(AssertUnwindSafe(|| self.enigo.mouse_up(btn)))
                .map_err(|_| InputSinkError::Backend("enigo mouse_up panicked".into()))
        }

        fn wheel(&mut self, dx: i16, dy: i16) -> Result<(), InputSinkError> {
            catch_unwind(AssertUnwindSafe(|| {
                if dx != 0 {
                    MouseControllable::mouse_scroll_x(&mut self.enigo, i32::from(dx));
                }
                if dy != 0 {
                    MouseControllable::mouse_scroll_y(&mut self.enigo, i32::from(dy));
                }
            }))
            .map_err(|_| InputSinkError::Backend("enigo wheel scroll panicked".into()))
        }

        fn key_down(&mut self, key: SafeHidKey) -> Result<(), InputSinkError> {
            let ek = map_safe_key_to_enigo(key);
            match catch_unwind(AssertUnwindSafe(|| self.enigo.key_down(ek))) {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(InputSinkError::Backend(e.to_string())),
                Err(_) => Err(InputSinkError::Backend("enigo key_down panicked".into())),
            }
        }

        fn key_up(&mut self, key: SafeHidKey) -> Result<(), InputSinkError> {
            let ek = map_safe_key_to_enigo(key);
            catch_unwind(AssertUnwindSafe(|| self.enigo.key_up(ek)))
                .map_err(|_| InputSinkError::Backend("enigo key_up panicked".into()))
        }

        fn release_all_best_effort(
            &mut self,
            pressed_buttons: u8,
            pressed_keys: &[SafeHidKey],
        ) -> ReleaseAllResult {
            let mut result = ReleaseAllResult::default();
            for bit_idx in 0..5u8 {
                let bit = 1u8 << bit_idx;
                if pressed_buttons & bit != 0 {
                    match map_button_bit(bit) {
                        Ok(btn) => {
                            if catch_unwind(AssertUnwindSafe(|| self.enigo.mouse_up(btn))).is_err()
                            {
                                result.failed_buttons |= bit;
                            }
                        }
                        Err(_) => {
                            result.failed_buttons |= bit;
                        }
                    }
                }
            }
            for &key in pressed_keys {
                let ek = map_safe_key_to_enigo(key);
                if catch_unwind(AssertUnwindSafe(|| self.enigo.key_up(ek))).is_err() {
                    result.failed_keys.push(key);
                }
            }
            result
        }
    }
}

#[cfg(all(
    feature = "os-input",
    not(any(target_os = "android", target_os = "ios"))
))]
pub use os_sink::EnigoOsSink;

/// Lock-free / short-lived pure-memory held input snapshot shared between `HidInputExecutor`
/// and the independent release watchdog.
///
/// The internal `pressed_keys` mutex is strictly pure-memory and NEVER held across any OS sink
/// call or sleep, ensuring the watchdog can always read held state and perform bounded
/// `[50, 100, 200, 400, 500]ms` releases even if the executor thread stalls inside an OS syscall.
pub struct AtomicHeldState {
    pressed_buttons: AtomicU8,
    pressed_keys: Mutex<BTreeSet<SafeHidKey>>,
    input_faulted: AtomicBool,
    releasing: AtomicBool,
    closed: AtomicBool,
    release_generation: AtomicU64,
    last_activity_mono_ms: AtomicU64,
    monotonic_origin: Instant,
    watchdog_release_count: AtomicU64,
}

impl Default for AtomicHeldState {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicHeldState {
    pub fn new() -> Self {
        Self {
            pressed_buttons: AtomicU8::new(0),
            pressed_keys: Mutex::new(BTreeSet::new()),
            input_faulted: AtomicBool::new(false),
            releasing: AtomicBool::new(false),
            closed: AtomicBool::new(false),
            release_generation: AtomicU64::new(0),
            last_activity_mono_ms: AtomicU64::new(0),
            monotonic_origin: Instant::now(),
            watchdog_release_count: AtomicU64::new(0),
        }
    }

    pub fn pressed_buttons(&self) -> u8 {
        self.pressed_buttons.load(Ordering::Acquire)
    }

    pub fn pressed_keys_snapshot(&self) -> Vec<SafeHidKey> {
        let guard = self
            .pressed_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.iter().copied().collect()
    }

    pub fn snapshot(&self) -> (u8, Vec<SafeHidKey>) {
        let buttons = self.pressed_buttons.load(Ordering::Acquire);
        let keys = self.pressed_keys_snapshot();
        (buttons, keys)
    }

    pub fn has_pressed_state(&self) -> bool {
        if self.pressed_buttons.load(Ordering::Acquire) != 0 {
            return true;
        }
        let guard = self
            .pressed_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        !guard.is_empty()
    }

    pub fn record_button_down(&self, bit: u8) {
        self.pressed_buttons
            .fetch_or(bit & MOUSE_BUTTONS_VALID_MASK, Ordering::AcqRel);
    }

    pub fn clear_button(&self, bit: u8) {
        self.pressed_buttons.fetch_and(!bit, Ordering::AcqRel);
    }

    pub fn set_buttons(&self, mask: u8) {
        self.pressed_buttons
            .store(mask & MOUSE_BUTTONS_VALID_MASK, Ordering::Release);
    }

    pub fn record_key_down(&self, key: SafeHidKey) {
        let mut guard = self
            .pressed_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(key);
    }

    pub fn clear_key(&self, key: SafeHidKey) {
        let mut guard = self
            .pressed_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.remove(&key);
    }

    pub fn replace_keys(&self, keys: &BTreeSet<SafeHidKey>) {
        let mut guard = self
            .pressed_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = keys.clone();
    }

    pub fn retain_only_failed(&self, failed_buttons: u8, failed_keys: &[SafeHidKey]) {
        self.pressed_buttons
            .store(failed_buttons & MOUSE_BUTTONS_VALID_MASK, Ordering::Release);
        let mut guard = self
            .pressed_keys
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clear();
        for &k in failed_keys {
            guard.insert(k);
        }
    }

    pub fn is_faulted(&self) -> bool {
        self.input_faulted.load(Ordering::Acquire)
    }

    pub fn latch_faulted(&self) {
        self.input_faulted.store(true, Ordering::Release);
        self.closed.store(true, Ordering::Release);
    }

    pub fn reset_fault(&self) {
        self.input_faulted.store(false, Ordering::Release);
        self.releasing.store(false, Ordering::Release);
        self.closed.store(false, Ordering::Release);
    }

    pub fn is_releasing(&self) -> bool {
        self.releasing.load(Ordering::Acquire)
    }

    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    pub fn is_releasing_or_closed(&self) -> bool {
        self.releasing.load(Ordering::Acquire) || self.closed.load(Ordering::Acquire)
    }

    pub fn is_faulted_or_releasing(&self) -> bool {
        self.input_faulted.load(Ordering::Acquire) || self.is_releasing_or_closed()
    }

    pub fn set_releasing(&self, val: bool) {
        self.releasing.store(val, Ordering::Release);
    }

    pub fn mark_closed(&self) {
        self.closed.store(true, Ordering::Release);
    }

    pub fn release_generation(&self) -> u64 {
        self.release_generation.load(Ordering::Acquire)
    }

    pub fn bump_release_generation(&self) -> u64 {
        self.release_generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1)
    }

    pub fn touch_activity(&self) {
        let now_mono = self.monotonic_origin.elapsed().as_millis() as u64;
        self.last_activity_mono_ms
            .store(now_mono, Ordering::Release);
    }

    pub fn elapsed_since_last_activity(&self) -> Duration {
        let now_mono = self.monotonic_origin.elapsed().as_millis() as u64;
        let last = self.last_activity_mono_ms.load(Ordering::Acquire);
        Duration::from_millis(now_mono.saturating_sub(last))
    }

    pub fn watchdog_release_count(&self) -> u64 {
        self.watchdog_release_count.load(Ordering::Acquire)
    }

    pub fn record_watchdog_release(&self) {
        self.watchdog_release_count.fetch_add(1, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum AuditRecord {
    MouseMoveAbs {
        seq: u32,
        x: i32,
        y: i32,
        ts_ms: u64,
    },
    MouseMoveRel {
        seq: u32,
        dx: i32,
        dy: i32,
        cur_x: i32,
        cur_y: i32,
        ts_ms: u64,
    },
    MouseDown {
        seq: u32,
        button_bit: u8,
        x: i32,
        y: i32,
        ts_ms: u64,
    },
    MouseUp {
        seq: u32,
        button_bit: u8,
        x: i32,
        y: i32,
        ts_ms: u64,
    },
    MouseWheel {
        seq: u32,
        dx: i16,
        dy: i16,
        ts_ms: u64,
    },
    KeyDown {
        seq: u32,
        key: AuditKey,
        ts_ms: u64,
    },
    KeyUp {
        seq: u32,
        key: AuditKey,
        ts_ms: u64,
    },
    Dropped {
        seq: u32,
        reason: String,
        ts_ms: u64,
    },
    ReleaseAll {
        reason: String,
        released_buttons: u8,
        released_keys: Vec<SafeHidKey>,
        #[serde(default)]
        failed_buttons: u8,
        #[serde(default)]
        failed_keys: Vec<SafeHidKey>,
        ts_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAllSummary {
    pub released_buttons: u8,
    pub released_keys: Vec<SafeHidKey>,
    pub failed_buttons: u8,
    pub failed_keys: Vec<SafeHidKey>,
    pub retries_executed: usize,
    pub input_faulted: bool,
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate_per_sec: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_per_sec: u32) -> Self {
        let cap = f64::from(rate_per_sec.max(1));
        Self {
            tokens: cap,
            capacity: cap,
            rate_per_sec: cap,
            last_refill: Instant::now(),
        }
    }

    fn try_consume(&mut self) -> bool {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        if !elapsed.is_zero() {
            self.tokens =
                (self.tokens + elapsed.as_secs_f64() * self.rate_per_sec).min(self.capacity);
            self.last_refill = now;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared HID input execution state machine aligned 100% with `protocol-spec` v1.2.3 + `V26`.
pub struct HidInputExecutor<S: HidInputSink> {
    sink: S,
    screen_width: i32,
    screen_height: i32,
    cur_x: i32,
    cur_y: i32,
    pressed_buttons: u8,
    pressed_keys: BTreeSet<SafeHidKey>,
    held_state: Arc<AtomicHeldState>,
    max_received_client_ts_ms: u64,
    pending_move_rel: Option<(u32, MouseEvent, usize)>,
    block_dangerous_shortcuts: bool,
    audit_key_identity: bool,
    terminated: bool,
    rate_limiter: TokenBucket,
    visual_marker: Option<SharedVisualMarker>,
    audit_log: VecDeque<AuditRecord>,
    audit_log_cap: usize,
    pub audit_log_dropped: u64,
    pub executed_events: u64,
    pub batch_too_large_drops: u64,
    pub invalid_button_drops: u64,
    pub unsupported_usage_drops: u64,
    pub blocked_shortcut_drops: u64,
    pub out_of_bounds_drops: u64,
    pub dropped_late: u64,
    pub spurious_up_bits_ignored: u64,
    pub oob_up_coords_ignored: u64,
    pub last_up_coords_applied: Option<bool>,
    pub rate_limited_drops: u64,
    pub release_all_count: u64,
    pub release_all_retries_executed: u64,
}

impl<S: HidInputSink> HidInputExecutor<S> {
    pub fn new(sink: S, screen_width: i32, screen_height: i32) -> Result<Self, InputError> {
        Self::with_options(
            sink,
            screen_width,
            screen_height,
            DEFAULT_HID_RATE_LIMIT_PER_SEC,
            None,
        )
    }

    pub fn with_options(
        sink: S,
        screen_width: i32,
        screen_height: i32,
        rate_limit_per_sec: u32,
        visual_marker: Option<SharedVisualMarker>,
    ) -> Result<Self, InputError> {
        if screen_width <= 0 || screen_height <= 0 {
            return Err(InputError::InvalidBounds(format!(
                "screen dimensions must be positive, got {screen_width}x{screen_height}"
            )));
        }
        Ok(Self {
            sink,
            screen_width,
            screen_height,
            cur_x: 0,
            cur_y: 0,
            pressed_buttons: 0,
            pressed_keys: BTreeSet::new(),
            held_state: Arc::new(AtomicHeldState::new()),
            max_received_client_ts_ms: 0,
            pending_move_rel: None,
            block_dangerous_shortcuts: true,
            audit_key_identity: false,
            terminated: false,
            rate_limiter: TokenBucket::new(rate_limit_per_sec),
            visual_marker,
            audit_log: VecDeque::new(),
            audit_log_cap: DEFAULT_AUDIT_LOG_CAP,
            audit_log_dropped: 0,
            executed_events: 0,
            batch_too_large_drops: 0,
            invalid_button_drops: 0,
            unsupported_usage_drops: 0,
            blocked_shortcut_drops: 0,
            out_of_bounds_drops: 0,
            dropped_late: 0,
            spurious_up_bits_ignored: 0,
            oob_up_coords_ignored: 0,
            last_up_coords_applied: None,
            rate_limited_drops: 0,
            release_all_count: 0,
            release_all_retries_executed: 0,
        })
    }

    /// Opts into recording exact `SafeHidKey` names in `AuditRecord::KeyDown`/`KeyUp`
    /// (defaults to `false`, redacting key identity as `"redacted"`).
    pub fn with_audit_key_identity(mut self, enabled: bool) -> Self {
        self.audit_key_identity = enabled;
        self
    }

    /// Configures the bounded in-memory audit ring capacity (minimum 1).
    pub fn with_audit_log_cap(mut self, cap: usize) -> Self {
        self.audit_log_cap = cap.max(1);
        while self.audit_log.len() > self.audit_log_cap {
            self.audit_log.pop_front();
            self.audit_log_dropped = self.audit_log_dropped.saturating_add(1);
        }
        self
    }

    /// Returns the shared lock-free held-input state for the independent watchdog.
    pub fn held_state(&self) -> Arc<AtomicHeldState> {
        Arc::clone(&self.held_state)
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub fn is_faulted(&self) -> bool {
        self.held_state.is_faulted()
    }

    pub fn max_received_client_ts_ms(&self) -> u64 {
        self.max_received_client_ts_ms
    }

    /// Permanently latches this executor as closed BEFORE releasing held keys during teardown,
    /// ensuring no concurrent/in-flight input can re-press a key or button after release.
    pub fn latch_closed(&mut self) {
        self.terminated = true;
        self.pending_move_rel = None;
        self.held_state.mark_closed();
    }

    /// Explicit operator reset after hardware/driver recovery from an `input_faulted` latch.
    pub fn reset_input_fault(&mut self) {
        self.held_state.reset_fault();
        self.terminated = false;
        self.pending_move_rel = None;
    }

    /// Runs preflight and an initial `release_all("startup_self_test")` before accepting first input.
    /// Fails closed on any backend error or fault latch.
    pub fn startup_self_test(&mut self) -> Result<(), InputError> {
        if let Err(e) = self.sink.preflight_batch() {
            return Err(self.fail_sink(e));
        }
        let summary = self.release_all("startup_self_test");
        if summary.input_faulted || summary.failed_buttons != 0 || !summary.failed_keys.is_empty() {
            return Err(InputError::InputFaulted);
        }
        Ok(())
    }

    pub fn pressed_buttons(&self) -> u8 {
        self.sync_from_held_state_if_released();
        self.pressed_buttons
    }

    pub fn pressed_keys(&self) -> &BTreeSet<SafeHidKey> {
        &self.pressed_keys
    }

    pub fn has_pressed_state(&self) -> bool {
        self.pressed_buttons != 0
            || !self.pressed_keys.is_empty()
            || self.held_state.has_pressed_state()
    }

    pub fn cursor_position(&self) -> (i32, i32) {
        (self.cur_x, self.cur_y)
    }

    pub fn audit_log(&self) -> &VecDeque<AuditRecord> {
        &self.audit_log
    }

    /// Reconciles local mirror with `AtomicHeldState` after an independent watchdog release.
    pub fn sync_from_held_state(&mut self) {
        let (btns, keys) = self.held_state.snapshot();
        self.pressed_buttons = btns;
        self.pressed_keys = keys.into_iter().collect();
    }

    fn sync_from_held_state_if_released(&self) {
        // Read-only accessor; `pressed_buttons()` reflects `self.pressed_buttons` which stays
        // synced on every mutable call or `sync_from_held_state()`.
    }

    /// Updates monotonic activity timestamp (immune to wall-clock jumps, lock-free).
    pub fn touch_activity(&self) {
        self.held_state.touch_activity();
    }

    pub fn elapsed_since_last_activity(&self) -> Duration {
        self.held_state.elapsed_since_last_activity()
    }

    fn push_audit(&mut self, rec: AuditRecord) {
        while self.audit_log.len() >= self.audit_log_cap {
            self.audit_log.pop_front();
            self.audit_log_dropped = self.audit_log_dropped.saturating_add(1);
        }
        self.audit_log.push_back(rec);
    }

    fn format_audit_key(&self, key: SafeHidKey) -> AuditKey {
        if self.audit_key_identity {
            AuditKey::Key(key)
        } else {
            AuditKey::Redacted
        }
    }

    fn update_visual_marker(&self, x: i32, y: i32) {
        if let Some(marker) = &self.visual_marker {
            if let Ok(mut guard) = marker.lock() {
                *guard = Some((x, y));
            }
        }
    }

    fn is_in_bounds(&self, x: i32, y: i32) -> bool {
        x >= 0 && y >= 0 && x < self.screen_width && y < self.screen_height
    }

    /// Order-independent dangerous shortcut check evaluated across the full candidate active set
    /// `self.pressed_keys ∪ {incoming_key}` plus wire modifier bits on every `KeyDown`.
    fn is_dangerous_shortcut(&self, incoming_key: SafeHidKey, ev_modifiers: u8) -> bool {
        if !self.block_dangerous_shortcuts {
            return false;
        }
        let has = |k: SafeHidKey| incoming_key == k || self.pressed_keys.contains(&k);
        let ctrl = has(SafeHidKey::LeftControl)
            || has(SafeHidKey::RightControl)
            || (ev_modifiers & MOD_CTRL) != 0;
        let alt = has(SafeHidKey::LeftAlt)
            || has(SafeHidKey::RightAlt)
            || (ev_modifiers & MOD_ALT) != 0;
        let meta = has(SafeHidKey::LeftMeta)
            || has(SafeHidKey::RightMeta)
            || (ev_modifiers & MOD_META) != 0;
        let shift = has(SafeHidKey::LeftShift)
            || has(SafeHidKey::RightShift)
            || (ev_modifiers & MOD_SHIFT) != 0;
        let has_fn_key = [
            SafeHidKey::F1,
            SafeHidKey::F2,
            SafeHidKey::F3,
            SafeHidKey::F4,
            SafeHidKey::F5,
            SafeHidKey::F6,
            SafeHidKey::F7,
            SafeHidKey::F8,
            SafeHidKey::F9,
            SafeHidKey::F10,
            SafeHidKey::F11,
            SafeHidKey::F12,
        ]
        .into_iter()
        .any(has);

        if ctrl && alt && (has(SafeHidKey::Delete) || has(SafeHidKey::Backspace) || has_fn_key) {
            return true;
        }
        (ctrl && has(SafeHidKey::KeyQ))
            || (alt && has(SafeHidKey::F4))
            || (meta && has(SafeHidKey::KeyQ))
            || (meta && has(SafeHidKey::KeyL))
            || (meta && shift && has(SafeHidKey::KeyQ))
            || (ctrl && meta && has(SafeHidKey::KeyQ))
            || (meta && alt && has(SafeHidKey::Escape))
    }

    fn fail_sink(&mut self, err: InputSinkError) -> InputError {
        self.latch_closed();
        let summary = self.release_all("sink_failed");
        if summary.input_faulted {
            InputError::InputFaulted
        } else {
            InputError::SinkFailed(err.to_string())
        }
    }

    /// Executes a single isolated pass of `release_all`, discarding any pending coalesced
    /// `MoveRel` and retaining any failed buttons/keys in the residual set.
    pub fn release_all_single_pass(&mut self, reason: &str) -> ReleaseAllSummary {
        self.pending_move_rel = None;
        self.sync_from_held_state();

        let had_buttons = self.pressed_buttons;
        let had_keys: Vec<SafeHidKey> = self.pressed_keys.iter().copied().collect();

        let result = if had_buttons != 0 || !had_keys.is_empty() {
            match catch_unwind(AssertUnwindSafe(|| {
                self.sink.release_all_best_effort(had_buttons, &had_keys)
            })) {
                Ok(res) => res,
                Err(_) => ReleaseAllResult {
                    failed_buttons: had_buttons,
                    failed_keys: had_keys.clone(),
                },
            }
        } else {
            ReleaseAllResult::default()
        };

        let retained_buttons = result.failed_buttons & had_buttons;
        let failed_key_set: BTreeSet<SafeHidKey> = result
            .failed_keys
            .into_iter()
            .filter(|k| self.pressed_keys.contains(k))
            .collect();

        let released_buttons = had_buttons & !retained_buttons;
        let released_keys: Vec<SafeHidKey> = had_keys
            .iter()
            .copied()
            .filter(|k| !failed_key_set.contains(k))
            .collect();
        let failed_keys: Vec<SafeHidKey> = failed_key_set.iter().copied().collect();

        self.pressed_buttons = retained_buttons;
        self.pressed_keys = failed_key_set;
        self.held_state
            .retain_only_failed(retained_buttons, &failed_keys);
        self.release_all_count = self.release_all_count.saturating_add(1);

        let ts_ms = now_epoch_ms();
        self.push_audit(AuditRecord::ReleaseAll {
            reason: reason.to_string(),
            released_buttons,
            released_keys: released_keys.clone(),
            failed_buttons: retained_buttons,
            failed_keys: failed_keys.clone(),
            ts_ms,
        });

        ReleaseAllSummary {
            released_buttons,
            released_keys,
            failed_buttons: retained_buttons,
            failed_keys,
            retries_executed: 0,
            input_faulted: self.held_state.is_faulted(),
        }
    }

    /// Executes normative `spec/04` §6.2.4 bounded `release_all`:
    /// 1 initial isolated pass + up to `HID_RELEASE_ALL_MAX_RETRIES` (5) retries of ONLY the
    /// residual failed buttons/keys using backoff `[50, 100, 200, 400, 500]ms`.
    /// If any residual remains after all 5 retries, latches `input_faulted = true` and refuses
    /// all subsequent HID events (`Err(InputError::InputFaulted)`).
    pub fn release_all_with_backoff<F: FnMut(Duration)>(
        &mut self,
        reason: &str,
        mut sleep_fn: F,
    ) -> ReleaseAllSummary {
        self.pending_move_rel = None;
        self.sync_from_held_state();

        let initial_buttons = self.pressed_buttons;
        let initial_keys: BTreeSet<SafeHidKey> = self.pressed_keys.clone();
        let mut total_released_buttons = 0u8;
        let mut total_released_keys: BTreeSet<SafeHidKey> = BTreeSet::new();

        self.held_state.set_releasing(true);
        self.held_state.bump_release_generation();

        let mut cur = self.release_all_single_pass(reason);
        total_released_buttons |= cur.released_buttons;
        for &k in &cur.released_keys {
            total_released_keys.insert(k);
        }

        let mut retries_executed = 0usize;
        if cur.failed_buttons != 0 || !cur.failed_keys.is_empty() {
            for &backoff_ms in &HID_RELEASE_ALL_BACKOFF_MS {
                sleep_fn(Duration::from_millis(backoff_ms));
                retries_executed += 1;
                self.release_all_retries_executed =
                    self.release_all_retries_executed.saturating_add(1);
                let retry_reason = format!("{reason}_retry_{retries_executed}");
                cur = self.release_all_single_pass(&retry_reason);
                total_released_buttons |= cur.released_buttons;
                for &k in &cur.released_keys {
                    total_released_keys.insert(k);
                }
                if cur.failed_buttons == 0 && cur.failed_keys.is_empty() {
                    break;
                }
            }
        }

        let faulted = cur.failed_buttons != 0 || !cur.failed_keys.is_empty();
        if faulted {
            self.held_state.latch_faulted();
            self.terminated = true;
            eprintln!(
                "[hid] FATAL: input_faulted latched after {retries_executed} retries (residual buttons={:#04x}, key_count={}); emit 0x04 SESSION_CLOSE(0x0103)",
                cur.failed_buttons,
                cur.failed_keys.len()
            );
        }
        // Always clear `releasing` (NEVER clears `closed`!).
        self.held_state.set_releasing(false);

        let released_keys: Vec<SafeHidKey> = initial_keys
            .iter()
            .copied()
            .filter(|k| total_released_keys.contains(k))
            .collect();

        ReleaseAllSummary {
            released_buttons: initial_buttons & total_released_buttons,
            released_keys,
            failed_buttons: cur.failed_buttons,
            failed_keys: cur.failed_keys,
            retries_executed,
            input_faulted: faulted,
        }
    }

    /// Executes normative `spec/04` §6.2.4 bounded `release_all` using `std::thread::sleep`
    /// for `[50, 100, 200, 400, 500]ms` backoff.
    pub fn release_all(&mut self, reason: &str) -> ReleaseAllSummary {
        self.release_all_with_backoff(reason, thread::sleep)
    }

    /// Coalesces and executes a batch of `(stream_seq, HidPayload, enqueue_ms)` under full v1.2.3
    /// anti-stuck-key and bounded streaming `MoveRel` coalescing rules.
    pub fn apply_batch(
        &mut self,
        events: &[(u32, HidPayload, u64)],
        now_ms: u64,
    ) -> Result<HidBatchOutcome, InputError> {
        if self.held_state.is_faulted() {
            return Err(InputError::InputFaulted);
        }
        if self.terminated || self.held_state.is_releasing_or_closed() {
            return Err(InputError::SessionTerminated);
        }
        if events.len() > MAX_HID_BATCH_SIZE {
            self.batch_too_large_drops = self.batch_too_large_drops.saturating_add(1);
            return Err(InputError::BatchTooLarge {
                len: events.len(),
                max: MAX_HID_BATCH_SIZE,
            });
        }
        if let Err(e) = self.sink.preflight_batch() {
            return Err(self.fail_sink(e));
        }

        self.sync_from_held_state();
        self.touch_activity();
        self.execute_events_v123(events, Some(now_ms), false)
    }

    /// Executes a non-blocking drained batch of L4 `(stream_seq, HidPayload)` events strictly
    /// under `spec/04` §6 (v1.2.3 + `V26`), using purely client monotonic `client_ts_ms` for 150ms
    /// late-drop filtering and rejecting `HidEchoAck` on the Host receive side (`0x0103`).
    pub fn apply_v123_stream_batch(
        &mut self,
        events: &[(u32, HidPayload)],
    ) -> Result<HidBatchOutcome, InputError> {
        if self.held_state.is_faulted() {
            return Err(InputError::InputFaulted);
        }
        if self.terminated || self.held_state.is_releasing_or_closed() {
            return Err(InputError::SessionTerminated);
        }
        if let Err(e) = self.sink.preflight_batch() {
            return Err(self.fail_sink(e));
        }
        self.sync_from_held_state();
        self.touch_activity();
        let adapted: Vec<(u32, HidPayload, u64)> =
            events.iter().map(|&(seq, p)| (seq, p, 0)).collect();
        self.execute_events_v123(&adapted, None, true)
    }

    fn flush_pending_move_rel(&mut self, out: &mut HidBatchOutcome) -> Result<(), InputError> {
        if let Some((rel_seq, rel_ev, _count)) = self.pending_move_rel.take() {
            if self.apply_mouse_move_rel(rel_seq, rel_ev)? {
                out.executed.push((rel_seq, HidPayload::Mouse(rel_ev)));
            }
        }
        Ok(())
    }

    fn execute_events_v123(
        &mut self,
        events: &[(u32, HidPayload, u64)],
        wall_now_ms: Option<u64>,
        strict_host_direction: bool,
    ) -> Result<HidBatchOutcome, InputError> {
        let mut out = HidBatchOutcome::default();

        for &(seq, payload, enqueue_ms) in events {
            out.acked_seqs.push(seq);
            match payload {
                HidPayload::Mouse(ev) if ev.kind == MouseKind::MoveRel => {
                    if ev.buttons & !MOUSE_BUTTONS_VALID_MASK != 0 {
                        self.flush_pending_move_rel(&mut out)?;
                        self.record_invalid_button_drop(seq, ev.buttons);
                        continue;
                    }
                    out.coalesced_rel_count += 1;
                    if let Some((_, _, count)) = self.pending_move_rel {
                        if count >= HID_MOVEREL_COALESCE_MAX {
                            self.flush_pending_move_rel(&mut out)?;
                        }
                    }
                    if let Some((last_seq, acc, count)) = &mut self.pending_move_rel {
                        *last_seq = seq;
                        acc.x_or_dx = acc.x_or_dx.saturating_add(ev.x_or_dx);
                        acc.y_or_dy = acc.y_or_dy.saturating_add(ev.y_or_dy);
                        acc.buttons = ev.buttons;
                        acc.client_ts_ms = ev.client_ts_ms;
                        *count += 1;
                    } else {
                        self.pending_move_rel = Some((seq, ev, 1));
                    }
                }
                HidPayload::Mouse(ev) => {
                    self.flush_pending_move_rel(&mut out)?;
                    let is_late = self.is_event_late(ev.client_ts_ms, wall_now_ms, enqueue_ms);
                    if self.apply_mouse_non_rel(seq, ev, is_late, &mut out)? {
                        out.executed.push((seq, HidPayload::Mouse(ev)));
                    }
                }
                HidPayload::Key(ev) => {
                    self.flush_pending_move_rel(&mut out)?;
                    let is_late = self.is_event_late(ev.client_ts_ms, wall_now_ms, enqueue_ms);
                    if self.apply_key(seq, ev, is_late, &mut out)? {
                        out.executed.push((seq, HidPayload::Key(ev)));
                    }
                }
                HidPayload::EchoAck(_) => {
                    self.flush_pending_move_rel(&mut out)?;
                    if strict_host_direction {
                        let _ = self.release_all("invalid_framing_echo_ack_direction");
                        return Err(InputError::InvalidFraming(
                            "Host received HidEchoAck (0x03) on Controller->Host direction".into(),
                        ));
                    }
                }
            }
        }

        self.flush_pending_move_rel(&mut out)?;
        Ok(out)
    }

    fn is_event_late(
        &self,
        client_ts_ms: u64,
        wall_now_ms: Option<u64>,
        enqueue_ms: u64,
    ) -> bool {
        if self
            .max_received_client_ts_ms
            .saturating_sub(client_ts_ms)
            > HID_STALE_DROP_MS
        {
            return true;
        }
        if let Some(now) = wall_now_ms {
            if now.saturating_sub(enqueue_ms) > HID_STALE_DROP_MS {
                return true;
            }
        }
        false
    }

    fn advance_high_water_mark(&mut self, client_ts_ms: u64) {
        if client_ts_ms > self.max_received_client_ts_ms {
            self.max_received_client_ts_ms = client_ts_ms;
        }
    }

    fn record_invalid_button_drop(&mut self, seq: u32, buttons: u8) {
        self.invalid_button_drops = self.invalid_button_drops.saturating_add(1);
        self.push_audit(AuditRecord::Dropped {
            seq,
            reason: format!("invalid_mouse_buttons:{buttons:#04x}"),
            ts_ms: now_epoch_ms(),
        });
    }

    /// Release-only helper (`pressed = prev & buttons`), releasing every bit in `prev & !buttons`
    /// on the sink without ever pressing any bit in `buttons & !prev`.
    fn release_cleared_buttons(
        &mut self,
        seq: u32,
        target_buttons: u8,
        ts_ms: u64,
        record_audit: bool,
    ) -> Result<(), InputError> {
        let to_release = self.pressed_buttons & !target_buttons;
        for bit_idx in 0..5u8 {
            let bit = 1u8 << bit_idx;
            if to_release & bit != 0 {
                if let Err(e) = self.sink.mouse_up(bit) {
                    return Err(self.fail_sink(e));
                }
                self.pressed_buttons &= !bit;
                self.held_state.clear_button(bit);
                if record_audit {
                    self.executed_events = self.executed_events.saturating_add(1);
                    self.push_audit(AuditRecord::MouseUp {
                        seq,
                        button_bit: bit,
                        x: self.cur_x,
                        y: self.cur_y,
                        ts_ms,
                    });
                }
            }
        }
        Ok(())
    }

    fn apply_mouse_move_rel(&mut self, seq: u32, ev: MouseEvent) -> Result<bool, InputError> {
        let ts_ms = now_epoch_ms();
        if ev.buttons & !MOUSE_BUTTONS_VALID_MASK != 0 {
            self.record_invalid_button_drop(seq, ev.buttons);
            return Ok(false);
        }
        // Release-only directionality for non-Down events (spec/04 §6.1.1)
        self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;

        if !self.rate_limiter.try_consume() {
            self.rate_limited_drops = self.rate_limited_drops.saturating_add(1);
            self.push_audit(AuditRecord::Dropped {
                seq,
                reason: "rate_limited".into(),
                ts_ms,
            });
            return Ok(false);
        }
        self.advance_high_water_mark(ev.client_ts_ms);
        let next_x = self
            .cur_x
            .saturating_add(ev.x_or_dx)
            .clamp(0, self.screen_width - 1);
        let next_y = self
            .cur_y
            .saturating_add(ev.y_or_dy)
            .clamp(0, self.screen_height - 1);
        let clamped_dx = next_x - self.cur_x;
        let clamped_dy = next_y - self.cur_y;
        if let Err(e) = self.sink.move_rel(clamped_dx, clamped_dy) {
            return Err(self.fail_sink(e));
        }
        self.cur_x = next_x;
        self.cur_y = next_y;
        self.update_visual_marker(self.cur_x, self.cur_y);
        self.executed_events = self.executed_events.saturating_add(1);
        self.push_audit(AuditRecord::MouseMoveRel {
            seq,
            dx: clamped_dx,
            dy: clamped_dy,
            cur_x: self.cur_x,
            cur_y: self.cur_y,
            ts_ms,
        });
        Ok(true)
    }

    fn apply_mouse_non_rel(
        &mut self,
        seq: u32,
        ev: MouseEvent,
        is_late: bool,
        out: &mut HidBatchOutcome,
    ) -> Result<bool, InputError> {
        let ts_ms = now_epoch_ms();
        if ev.buttons & !MOUSE_BUTTONS_VALID_MASK != 0 {
            self.record_invalid_button_drop(seq, ev.buttons);
            return Ok(false);
        }

        match ev.kind {
            MouseKind::MoveAbs => {
                if !self.is_in_bounds(ev.x_or_dx, ev.y_or_dy) {
                    self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                    self.out_of_bounds_drops = self.out_of_bounds_drops.saturating_add(1);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "out_of_bounds".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                if is_late {
                    self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                    self.dropped_late = self.dropped_late.saturating_add(1);
                    out.dropped_stale_seqs.push(seq);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "late_drop".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                if !self.rate_limiter.try_consume() {
                    self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                    self.rate_limited_drops = self.rate_limited_drops.saturating_add(1);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "rate_limited".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                self.advance_high_water_mark(ev.client_ts_ms);
                self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                if let Err(e) = self.sink.move_abs(ev.x_or_dx, ev.y_or_dy) {
                    return Err(self.fail_sink(e));
                }
                self.cur_x = ev.x_or_dx;
                self.cur_y = ev.y_or_dy;
                self.update_visual_marker(self.cur_x, self.cur_y);
                self.executed_events = self.executed_events.saturating_add(1);
                self.push_audit(AuditRecord::MouseMoveAbs {
                    seq,
                    x: self.cur_x,
                    y: self.cur_y,
                    ts_ms,
                });
                Ok(true)
            }
            MouseKind::MoveRel => unreachable!("MoveRel handled in coalescing path"),
            MouseKind::Down => {
                if !self.is_in_bounds(ev.x_or_dx, ev.y_or_dy) {
                    // spec/04 §6.1.1 & §6.2.2: even when Down is rejected OOB, preserve any
                    // implicit release (`prev & !buttons`) so previously held buttons never stick,
                    // while NEVER injecting new press bits or advancing max_received_client_ts_ms.
                    self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                    self.out_of_bounds_drops = self.out_of_bounds_drops.saturating_add(1);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "out_of_bounds".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                if is_late {
                    // Preserve implicit release on late-dropped Down as well.
                    self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                    self.dropped_late = self.dropped_late.saturating_add(1);
                    out.dropped_stale_seqs.push(seq);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "late_drop".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                if !self.rate_limiter.try_consume() {
                    self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                    self.rate_limited_drops = self.rate_limited_drops.saturating_add(1);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "rate_limited".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                self.advance_high_water_mark(ev.client_ts_ms);
                self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;

                if (self.cur_x, self.cur_y) != (ev.x_or_dx, ev.y_or_dy) {
                    if let Err(e) = self.sink.move_abs(ev.x_or_dx, ev.y_or_dy) {
                        return Err(self.fail_sink(e));
                    }
                    self.cur_x = ev.x_or_dx;
                    self.cur_y = ev.y_or_dy;
                }
                self.update_visual_marker(self.cur_x, self.cur_y);

                for bit_idx in 0..5u8 {
                    let bit = 1u8 << bit_idx;
                    if ev.buttons & bit != 0 && (self.pressed_buttons & bit) == 0 {
                        // Race closure with independent watchdog: capture release_generation and
                        // verify not releasing/closed BEFORE pressing, record bit BEFORE sink call,
                        // and re-check both generation and releasing/closed AFTER sink call.
                        let gen_before = self.held_state.release_generation();
                        if self.held_state.is_faulted_or_releasing() {
                            return Err(if self.held_state.is_faulted() {
                                InputError::InputFaulted
                            } else {
                                InputError::SessionTerminated
                            });
                        }
                        self.held_state.record_button_down(bit);
                        if let Err(e) = self.sink.mouse_down(bit) {
                            self.held_state.clear_button(bit);
                            return Err(self.fail_sink(e));
                        }
                        if self.held_state.release_generation() != gen_before
                            || self.held_state.is_faulted_or_releasing()
                        {
                            let _ = self.sink.mouse_up(bit);
                            self.held_state.clear_button(bit);
                            return Err(if self.held_state.is_faulted() {
                                InputError::InputFaulted
                            } else {
                                InputError::SessionTerminated
                            });
                        }
                        self.pressed_buttons |= bit;
                        self.executed_events = self.executed_events.saturating_add(1);
                        self.push_audit(AuditRecord::MouseDown {
                            seq,
                            button_bit: bit,
                            x: self.cur_x,
                            y: self.cur_y,
                            ts_ms,
                        });
                    }
                }
                Ok(true)
            }
            MouseKind::Up => {
                // UNCONDITIONALLY EXEMPT from 150ms late drop, OOB drop, and rate limiting.
                // Post-event bitmap semantics (spec/04 §6.1.1):
                //   released = prev & !buttons
                //   spurious = buttons & !prev  (ignored & counted, NEVER injected as Down)
                //   pressed  = prev & buttons
                let prev = self.pressed_buttons;
                let spurious = ev.buttons & !prev;
                if spurious != 0 {
                    self.spurious_up_bits_ignored = self
                        .spurious_up_bits_ignored
                        .saturating_add(u64::from(spurious.count_ones()));
                }

                if self.is_in_bounds(ev.x_or_dx, ev.y_or_dy) {
                    if (self.cur_x, self.cur_y) != (ev.x_or_dx, ev.y_or_dy) {
                        if let Err(e) = self.sink.move_abs(ev.x_or_dx, ev.y_or_dy) {
                            return Err(self.fail_sink(e));
                        }
                        self.cur_x = ev.x_or_dx;
                        self.cur_y = ev.y_or_dy;
                        self.update_visual_marker(self.cur_x, self.cur_y);
                        self.executed_events = self.executed_events.saturating_add(1);
                        self.push_audit(AuditRecord::MouseMoveAbs {
                            seq,
                            x: self.cur_x,
                            y: self.cur_y,
                            ts_ms,
                        });
                    }
                    self.last_up_coords_applied = Some(true);
                    self.advance_high_water_mark(ev.client_ts_ms);
                } else {
                    // OOB MouseKind::Up ignores coordinates and does NOT advance high-water mark.
                    self.oob_up_coords_ignored = self.oob_up_coords_ignored.saturating_add(1);
                    self.last_up_coords_applied = Some(false);
                }

                self.release_cleared_buttons(seq, ev.buttons, ts_ms, true)?;
                Ok(true)
            }
            MouseKind::Wheel => {
                // Wheel ignores x_or_dx / y_or_dy (no OOB check per spec/04 §6.1.1).
                if is_late {
                    self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                    self.dropped_late = self.dropped_late.saturating_add(1);
                    out.dropped_stale_seqs.push(seq);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "late_drop".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                if !self.rate_limiter.try_consume() {
                    self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                    self.rate_limited_drops = self.rate_limited_drops.saturating_add(1);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "rate_limited".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                self.advance_high_water_mark(ev.client_ts_ms);
                self.release_cleared_buttons(seq, ev.buttons, ts_ms, false)?;
                if let Err(e) = self.sink.wheel(ev.wheel_dx, ev.wheel_dy) {
                    return Err(self.fail_sink(e));
                }
                self.executed_events = self.executed_events.saturating_add(1);
                self.push_audit(AuditRecord::MouseWheel {
                    seq,
                    dx: ev.wheel_dx,
                    dy: ev.wheel_dy,
                    ts_ms,
                });
                Ok(true)
            }
        }
    }

    fn apply_key(
        &mut self,
        seq: u32,
        ev: KeyEvent,
        is_late: bool,
        out: &mut HidBatchOutcome,
    ) -> Result<bool, InputError> {
        let ts_ms = now_epoch_ms();
        let Some(key) = SafeHidKey::from_usb_hid_usage(ev.usb_hid_usage) else {
            // Unknown/non-whitelisted usage (including usage == 0): safe non-fatal drop,
            // NEVER advances max_received_client_ts_ms (spec/04 §6.2.1).
            self.unsupported_usage_drops = self.unsupported_usage_drops.saturating_add(1);
            self.push_audit(AuditRecord::Dropped {
                seq,
                reason: format!("unsupported_usage:{:#x}", ev.usb_hid_usage),
                ts_ms,
            });
            return Ok(false);
        };

        if ev.down {
            if is_late {
                self.dropped_late = self.dropped_late.saturating_add(1);
                out.dropped_stale_seqs.push(seq);
                self.push_audit(AuditRecord::Dropped {
                    seq,
                    reason: "late_drop".into(),
                    ts_ms,
                });
                return Ok(false);
            }
            if self.is_dangerous_shortcut(key, ev.modifiers) {
                self.blocked_shortcut_drops = self.blocked_shortcut_drops.saturating_add(1);
                let reason = if self.audit_key_identity {
                    format!("blocked_shortcut:{key:?}")
                } else {
                    "blocked_shortcut:redacted".into()
                };
                self.push_audit(AuditRecord::Dropped { seq, reason, ts_ms });
                return Ok(false);
            }
            self.advance_high_water_mark(ev.client_ts_ms);
            if !self.pressed_keys.contains(&key) {
                if !self.rate_limiter.try_consume() {
                    self.rate_limited_drops = self.rate_limited_drops.saturating_add(1);
                    self.push_audit(AuditRecord::Dropped {
                        seq,
                        reason: "rate_limited".into(),
                        ts_ms,
                    });
                    return Ok(false);
                }
                // Race closure: capture release_generation and check releasing/closed BEFORE
                // calling sink.key_down, record key in AtomicHeldState BEFORE sink call, and
                // re-check both generation and releasing/closed AFTER sink.key_down.
                let gen_before = self.held_state.release_generation();
                if self.held_state.is_faulted_or_releasing() {
                    return Err(if self.held_state.is_faulted() {
                        InputError::InputFaulted
                    } else {
                        InputError::SessionTerminated
                    });
                }
                self.held_state.record_key_down(key);
                if let Err(e) = self.sink.key_down(key) {
                    self.held_state.clear_key(key);
                    return Err(self.fail_sink(e));
                }
                if self.held_state.release_generation() != gen_before
                    || self.held_state.is_faulted_or_releasing()
                {
                    let _ = self.sink.key_up(key);
                    self.held_state.clear_key(key);
                    return Err(if self.held_state.is_faulted() {
                        InputError::InputFaulted
                    } else {
                        InputError::SessionTerminated
                    });
                }
                self.pressed_keys.insert(key);
                self.executed_events = self.executed_events.saturating_add(1);
                let audit_key = self.format_audit_key(key);
                self.push_audit(AuditRecord::KeyDown {
                    seq,
                    key: audit_key,
                    ts_ms,
                });
            }
            Ok(true)
        } else {
            // KeyUp (down == false) is UNCONDITIONALLY EXEMPT from 150ms late drop and rate limit.
            self.advance_high_water_mark(ev.client_ts_ms);
            if self.pressed_keys.contains(&key) {
                if let Err(e) = self.sink.key_up(key) {
                    return Err(self.fail_sink(e));
                }
                self.pressed_keys.remove(&key);
                self.held_state.clear_key(key);
                self.executed_events = self.executed_events.saturating_add(1);
                let audit_key = self.format_audit_key(key);
                self.push_audit(AuditRecord::KeyUp {
                    seq,
                    key: audit_key,
                    ts_ms,
                });
            }
            Ok(true)
        }
    }

    /// Writes the audit log as JSONL atomically using a unique nonce temp file
    /// (`0600`, `O_CREAT | O_EXCL | O_NOFOLLOW` on Unix), `sync_all()`, and `rename()`.
    pub fn flush_audit_jsonl(&self, path: &Path) -> std::io::Result<()> {
        write_audit_records_jsonl(self.audit_log.iter(), path)
    }
}

/// Atomically writes a slice/iterator of `AuditRecord` entries to `path` (`0600` on Unix).
pub fn write_audit_records_jsonl<'a, I>(records: I, path: &Path) -> std::io::Result<()>
where
    I: IntoIterator<Item = &'a AuditRecord>,
{
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    let nonce = AUDIT_TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!(
        ".{}.tmp.{}.{}.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("audit.jsonl"),
        std::process::id(),
        nonce,
        nanos
    );
    let tmp_path = path.with_file_name(tmp_name);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    let write_result = (|| -> std::io::Result<()> {
        let file = opts.open(&tmp_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))?;
        }
        let mut writer = BufWriter::new(file);
        for rec in records {
            let line = serde_json::to_string(rec).map_err(std::io::Error::other)?;
            writer.write_all(line.as_bytes())?;
            writer.write_all(b"\n")?;
        }
        let file = writer.into_inner().map_err(|e| e.into_error())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&tmp_path, path)?;
        sync_parent_dir(path)?;
        Ok(())
    })();

    if write_result.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_result
}

impl<S: HidInputSink> Drop for HidInputExecutor<S> {
    fn drop(&mut self) {
        if self.has_pressed_state() {
            let _ = self.release_all("drop");
        }
    }
}

struct WatchdogDoneGuard(mpsc::SyncSender<()>);

impl Drop for WatchdogDoneGuard {
    fn drop(&mut self) {
        let _ = self.0.try_send(());
    }
}

/// RAII handle for the independent HID release watchdog thread.
/// Joining is always bounded so a deadlocked OS HID sink can never hang teardown.
pub struct WatchdogHandle {
    stop: Arc<AtomicBool>,
    join_handle: Option<JoinHandle<()>>,
    done_rx: Option<mpsc::Receiver<()>>,
}

impl WatchdogHandle {
    pub fn stop_and_join_timeout(&mut self, timeout: Duration) -> Result<(), InputError> {
        self.stop.store(true, Ordering::Release);
        let Some(handle) = self.join_handle.take() else {
            return Ok(());
        };
        if let Some(done_rx) = self.done_rx.take() {
            match done_rx.recv_timeout(timeout) {
                Ok(()) | Err(RecvTimeoutError::Disconnected) => {}
                Err(RecvTimeoutError::Timeout) => {
                    // Detach stalled watchdog thread rather than deadlocking teardown.
                    drop(handle);
                    return Err(InputError::SinkFailed(format!(
                        "zd-v2-hid-watchdog did not exit within {timeout:?}"
                    )));
                }
            }
        }
        handle
            .join()
            .map_err(|_| InputError::SinkFailed("zd-v2-hid-watchdog thread panicked".into()))?;
        Ok(())
    }

    pub fn stop_and_join(&mut self) -> Result<(), InputError> {
        self.stop_and_join_timeout(WATCHDOG_JOIN_TIMEOUT)
    }
}

impl Drop for WatchdogHandle {
    fn drop(&mut self) {
        let _ = self.stop_and_join_timeout(Duration::from_millis(200));
    }
}

/// Runs a bounded 5-retry `[50, 100, 200, 400, 500]ms` isolated release directly against an
/// independent release-only sink using `AtomicHeldState` (ZERO executor mutex held!).
pub fn run_independent_release_all<S: HidInputSink, F: FnMut(Duration)>(
    held_state: &AtomicHeldState,
    release_sink: &mut S,
    reason: &str,
    sleep_fn: F,
) -> ReleaseAllSummary {
    run_independent_release_all_with_stop(held_state, release_sink, reason, None, sleep_fn)
}

fn run_independent_release_all_with_stop<S: HidInputSink, F: FnMut(Duration)>(
    held_state: &AtomicHeldState,
    release_sink: &mut S,
    reason: &str,
    stop: Option<&AtomicBool>,
    mut sleep_fn: F,
) -> ReleaseAllSummary {
    held_state.set_releasing(true);
    held_state.bump_release_generation();
    let (initial_buttons, initial_keys) = held_state.snapshot();
    if initial_buttons == 0 && initial_keys.is_empty() {
        // ONLY clear `releasing`, NEVER `closed`.
        held_state.set_releasing(false);
        return ReleaseAllSummary {
            released_buttons: 0,
            released_keys: Vec::new(),
            failed_buttons: 0,
            failed_keys: Vec::new(),
            retries_executed: 0,
            input_faulted: held_state.is_faulted(),
        };
    }

    let mut rem_buttons = initial_buttons;
    let mut rem_keys = initial_keys.clone();
    let mut retries_executed = 0usize;

    let run_pass = |sink: &mut S, btns: u8, keys: &[SafeHidKey]| -> (u8, Vec<SafeHidKey>) {
        let res = match catch_unwind(AssertUnwindSafe(|| {
            sink.release_all_best_effort(btns, keys)
        })) {
            Ok(r) => r,
            Err(_) => ReleaseAllResult {
                failed_buttons: btns,
                failed_keys: keys.to_vec(),
            },
        };
        let next_btns = res.failed_buttons & btns;
        let next_keys: Vec<SafeHidKey> = res
            .failed_keys
            .into_iter()
            .filter(|k| keys.contains(k))
            .collect();
        (next_btns, next_keys)
    };

    let (b, k) = run_pass(release_sink, rem_buttons, &rem_keys);
    rem_buttons = b;
    rem_keys = k;
    held_state.retain_only_failed(rem_buttons, &rem_keys);

    if rem_buttons != 0 || !rem_keys.is_empty() {
        for &backoff_ms in &HID_RELEASE_ALL_BACKOFF_MS {
            if stop.is_some_and(|s| s.load(Ordering::Acquire)) {
                break;
            }
            sleep_fn(Duration::from_millis(backoff_ms));
            retries_executed += 1;
            let (nb, nk) = run_pass(release_sink, rem_buttons, &rem_keys);
            rem_buttons = nb;
            rem_keys = nk;
            held_state.retain_only_failed(rem_buttons, &rem_keys);
            if rem_buttons == 0 && rem_keys.is_empty() {
                break;
            }
        }
    }

    let faulted = rem_buttons != 0 || !rem_keys.is_empty();
    if faulted {
        held_state.latch_faulted();
        eprintln!(
            "[hid-watchdog] FATAL: independent release_all ({reason}) exhausted {retries_executed} retries; residual buttons={rem_buttons:#04x}, key_count={}",
            rem_keys.len()
        );
    }
    // Always clear ONLY `releasing`, NEVER `closed`!
    held_state.set_releasing(false);

    let released_buttons = initial_buttons & !rem_buttons;
    let released_keys: Vec<SafeHidKey> = initial_keys
        .into_iter()
        .filter(|k| !rem_keys.contains(k))
        .collect();

    ReleaseAllSummary {
        released_buttons,
        released_keys,
        failed_buttons: rem_buttons,
        failed_keys: rem_keys,
        retries_executed,
        input_faulted: faulted,
    }
}

/// Spawns a non-blocking independent watchdog OS thread that owns its OWN release-only sink
/// and reads `Arc<AtomicHeldState>` directly without EVER locking `Mutex<HidInputExecutor>`.
///
/// Even if the executor thread is completely stalled inside an OS syscall, this watchdog still
/// fires within `watchdog_timeout` and executes the bounded `[50, 100, 200, 400, 500]ms`
/// isolated `release_all` loop.
///
/// `watchdog_timeout` is floored at `HID_WATCHDOG_FLOOR_MS` (20ms) for deterministic tests;
/// production configurations enforce `HID_WATCHDOG_MIN_MS..=HID_WATCHDOG_MAX_MS` (`1000..=10000ms`)
/// in `V2ClientConfig::validate()`.
pub fn spawn_independent_release_watchdog<S: HidInputSink + 'static>(
    held_state: Arc<AtomicHeldState>,
    mut release_sink: S,
    watchdog_timeout: Duration,
    stop: Arc<AtomicBool>,
    audit_records: Option<Arc<Mutex<Vec<AuditRecord>>>>,
) -> std::io::Result<WatchdogHandle> {
    let effective_timeout = watchdog_timeout.max(Duration::from_millis(HID_WATCHDOG_FLOOR_MS));
    let poll_interval =
        (effective_timeout / 4).clamp(Duration::from_millis(5), Duration::from_millis(25));
    let thread_stop = Arc::clone(&stop);
    let (done_tx, done_rx) = mpsc::sync_channel::<()>(1);

    let join_handle = thread::Builder::new()
        .name("zd-v2-hid-indep-watchdog".to_string())
        .spawn(move || {
            let _done_guard = WatchdogDoneGuard(done_tx);
            while !thread_stop.load(Ordering::Acquire) {
                thread::sleep(poll_interval);
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                // Once `input_faulted` is latched, the session enters teardown which explicitly
                // invokes a final `release_all` pass; avoid spin-retrying a permanently broken sink.
                if !held_state.is_faulted()
                    && held_state.has_pressed_state()
                    && held_state.elapsed_since_last_activity() >= effective_timeout
                {
                    let summary = run_independent_release_all_with_stop(
                        &held_state,
                        &mut release_sink,
                        "watchdog_timeout",
                        Some(&thread_stop),
                        thread::sleep,
                    );
                    held_state.record_watchdog_release();
                    if let Some(audit) = &audit_records {
                        let maybe_guard = match audit.try_lock() {
                            Ok(g) => Some(g),
                            Err(TryLockError::Poisoned(p)) => Some(p.into_inner()),
                            Err(TryLockError::WouldBlock) => None,
                        };
                        if let Some(mut guard) = maybe_guard {
                            if guard.len() >= DEFAULT_AUDIT_LOG_CAP {
                                let drain = guard.len() + 1 - DEFAULT_AUDIT_LOG_CAP;
                                guard.drain(0..drain);
                            }
                            guard.push(AuditRecord::ReleaseAll {
                                reason: "watchdog_timeout".into(),
                                released_buttons: summary.released_buttons,
                                released_keys: summary.released_keys,
                                failed_buttons: summary.failed_buttons,
                                failed_keys: summary.failed_keys,
                                ts_ms: now_epoch_ms(),
                            });
                        }
                    }
                }
            }
        })?;

    Ok(WatchdogHandle {
        stop,
        join_handle: Some(join_handle),
        done_rx: Some(done_rx),
    })
}

/// Legacy mutex-backed watchdog retained for Phase 3 CLI backward compatibility.
/// Prefer `spawn_independent_release_watchdog` for non-blocking independent sink release.
pub fn spawn_release_watchdog<S: HidInputSink + 'static>(
    executor: Arc<Mutex<HidInputExecutor<S>>>,
    watchdog_timeout: Duration,
    stop: Arc<AtomicBool>,
) -> std::io::Result<WatchdogHandle> {
    let effective_timeout = watchdog_timeout.max(Duration::from_millis(HID_WATCHDOG_FLOOR_MS));
    let poll_interval =
        (effective_timeout / 4).clamp(Duration::from_millis(5), Duration::from_millis(25));
    let thread_stop = Arc::clone(&stop);
    let (done_tx, done_rx) = mpsc::sync_channel::<()>(1);

    let join_handle = thread::Builder::new()
        .name("zd-v2-hid-watchdog".to_string())
        .spawn(move || {
            let _done_guard = WatchdogDoneGuard(done_tx);
            while !thread_stop.load(Ordering::Acquire) {
                thread::sleep(poll_interval);
                if thread_stop.load(Ordering::Acquire) {
                    break;
                }
                let (mut guard, was_poisoned) = match executor.try_lock() {
                    Ok(g) => (g, false),
                    Err(TryLockError::WouldBlock) => continue,
                    Err(TryLockError::Poisoned(e)) => (e.into_inner(), true),
                };
                if !guard.is_faulted() && guard.has_pressed_state() {
                    if guard.elapsed_since_last_activity() >= effective_timeout {
                        let _ = guard.release_all("watchdog_timeout");
                    } else if was_poisoned {
                        let _ = guard.release_all("watchdog_poison_recovery");
                    }
                }
            }
        })?;

    Ok(WatchdogHandle {
        stop,
        join_handle: Some(join_handle),
        done_rx: Some(done_rx),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::hid::decode_l4_hid_frame;
    use std::sync::atomic::AtomicUsize;

    struct FaultInjectingSink {
        ops: Vec<DryRunOp>,
        fail_after: usize,
        call_count: usize,
        release_all_calls: Arc<AtomicUsize>,
        released_buttons_seen: Arc<Mutex<u8>>,
        released_keys_seen: Arc<Mutex<Vec<SafeHidKey>>>,
    }

    impl FaultInjectingSink {
        fn new(fail_after: usize) -> Self {
            Self {
                ops: Vec::new(),
                fail_after,
                call_count: 0,
                release_all_calls: Arc::new(AtomicUsize::new(0)),
                released_buttons_seen: Arc::new(Mutex::new(0)),
                released_keys_seen: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn check_fault(&mut self) -> Result<(), InputSinkError> {
            self.call_count += 1;
            if self.call_count >= self.fail_after {
                return Err(InputSinkError::Backend(format!(
                    "injected fault at call {}",
                    self.call_count
                )));
            }
            Ok(())
        }
    }

    impl HidInputSink for FaultInjectingSink {
        fn move_abs(&mut self, x: i32, y: i32) -> Result<(), InputSinkError> {
            self.check_fault()?;
            self.ops.push(DryRunOp::MoveAbs { x, y });
            Ok(())
        }

        fn move_rel(&mut self, dx: i32, dy: i32) -> Result<(), InputSinkError> {
            self.check_fault()?;
            self.ops.push(DryRunOp::MoveRel { dx, dy });
            Ok(())
        }

        fn mouse_down(&mut self, button_bit: u8) -> Result<(), InputSinkError> {
            self.check_fault()?;
            self.ops.push(DryRunOp::MouseDown { button_bit });
            Ok(())
        }

        fn mouse_up(&mut self, button_bit: u8) -> Result<(), InputSinkError> {
            self.check_fault()?;
            self.ops.push(DryRunOp::MouseUp { button_bit });
            Ok(())
        }

        fn wheel(&mut self, dx: i16, dy: i16) -> Result<(), InputSinkError> {
            self.check_fault()?;
            self.ops.push(DryRunOp::Wheel { dx, dy });
            Ok(())
        }

        fn key_down(&mut self, key: SafeHidKey) -> Result<(), InputSinkError> {
            self.check_fault()?;
            self.ops.push(DryRunOp::KeyDown { key });
            Ok(())
        }

        fn key_up(&mut self, key: SafeHidKey) -> Result<(), InputSinkError> {
            self.check_fault()?;
            self.ops.push(DryRunOp::KeyUp { key });
            Ok(())
        }

        fn release_all_best_effort(
            &mut self,
            pressed_buttons: u8,
            pressed_keys: &[SafeHidKey],
        ) -> ReleaseAllResult {
            self.release_all_calls.fetch_add(1, Ordering::SeqCst);
            *self.released_buttons_seen.lock().unwrap() |= pressed_buttons;
            self.released_keys_seen
                .lock()
                .unwrap()
                .extend_from_slice(pressed_keys);
            ReleaseAllResult::default()
        }
    }

    struct PartialFailReleaseSink {
        fail_buttons_on_passes: Vec<u8>,
        fail_keys_on_passes: Vec<Vec<SafeHidKey>>,
        pass_index: usize,
        always_fail_keys: Vec<SafeHidKey>,
    }

    impl PartialFailReleaseSink {
        fn fail_once_key(key: SafeHidKey) -> Self {
            Self {
                fail_buttons_on_passes: vec![0],
                fail_keys_on_passes: vec![vec![key]],
                pass_index: 0,
                always_fail_keys: Vec::new(),
            }
        }

        fn always_fail_key(key: SafeHidKey) -> Self {
            Self {
                fail_buttons_on_passes: Vec::new(),
                fail_keys_on_passes: Vec::new(),
                pass_index: 0,
                always_fail_keys: vec![key],
            }
        }
    }

    impl HidInputSink for PartialFailReleaseSink {
        fn move_abs(&mut self, _x: i32, _y: i32) -> Result<(), InputSinkError> {
            Ok(())
        }
        fn move_rel(&mut self, _dx: i32, _dy: i32) -> Result<(), InputSinkError> {
            Ok(())
        }
        fn mouse_down(&mut self, _button_bit: u8) -> Result<(), InputSinkError> {
            Ok(())
        }
        fn mouse_up(&mut self, _button_bit: u8) -> Result<(), InputSinkError> {
            Ok(())
        }
        fn wheel(&mut self, _dx: i16, _dy: i16) -> Result<(), InputSinkError> {
            Ok(())
        }
        fn key_down(&mut self, _key: SafeHidKey) -> Result<(), InputSinkError> {
            Ok(())
        }
        fn key_up(&mut self, _key: SafeHidKey) -> Result<(), InputSinkError> {
            Ok(())
        }
        fn release_all_best_effort(
            &mut self,
            pressed_buttons: u8,
            pressed_keys: &[SafeHidKey],
        ) -> ReleaseAllResult {
            let idx = self.pass_index;
            self.pass_index += 1;
            let mut res = ReleaseAllResult::default();
            if let Some(&fail_b) = self.fail_buttons_on_passes.get(idx) {
                res.failed_buttons = pressed_buttons & fail_b;
            }
            if let Some(fail_k) = self.fail_keys_on_passes.get(idx) {
                for &k in pressed_keys {
                    if fail_k.contains(&k) {
                        res.failed_keys.push(k);
                    }
                }
            }
            for &k in pressed_keys {
                if self.always_fail_keys.contains(&k) && !res.failed_keys.contains(&k) {
                    res.failed_keys.push(k);
                }
            }
            res
        }
    }

    #[test]
    fn whitelist_rejects_unknown_usages_and_keeps_left_right_modifiers_distinct() {
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x04), Some(SafeHidKey::KeyA));
        assert_eq!(
            SafeHidKey::from_usb_hid_usage(0x0007_0004),
            Some(SafeHidKey::KeyA)
        );
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x000C_0004), None);
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x0001_0004), None);
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x00), None);
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x66), None);
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x0104), None);
        assert_eq!(SafeHidKey::from_usb_hid_usage(0xFFFF), None);

        assert_ne!(
            SafeHidKey::from_usb_hid_usage(0xE0),
            SafeHidKey::from_usb_hid_usage(0xE4)
        );
        assert_ne!(
            SafeHidKey::from_usb_hid_usage(0xE1),
            SafeHidKey::from_usb_hid_usage(0xE5)
        );
        assert_ne!(
            SafeHidKey::from_usb_hid_usage(0xE2),
            SafeHidKey::from_usb_hid_usage(0xE6)
        );
        assert_ne!(
            SafeHidKey::from_usb_hid_usage(0xE3),
            SafeHidKey::from_usb_hid_usage(0xE7)
        );

        let mut exec = HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap();
        let now = now_epoch_ms();
        exec.apply_batch(
            &[
                (
                    1,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: 0x000C_0004,
                        unicode_scalar: 'a' as u32,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    2,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: MOD_SHIFT,
                        usb_hid_usage: 0xE1,
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    3,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: MOD_SHIFT,
                        usb_hid_usage: 0xE5,
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
            ],
            now,
        )
        .unwrap();
        assert_eq!(exec.unsupported_usage_drops, 1);
        assert!(exec.pressed_keys().contains(&SafeHidKey::LeftShift));
        assert!(exec.pressed_keys().contains(&SafeHidKey::RightShift));
        assert_eq!(exec.pressed_keys().len(), 2);
    }

    #[test]
    fn rejects_out_of_bounds_abs_and_down_but_never_drops_oob_mouse_up() {
        let mut exec = HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap();
        let now = now_epoch_ms();
        exec.apply_batch(
            &[
                (
                    1,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveAbs,
                        buttons: 0,
                        x_or_dx: -1,
                        y_or_dy: 100,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    2,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveAbs,
                        buttons: 0,
                        x_or_dx: 1280,
                        y_or_dy: 720,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    3,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::Down,
                        buttons: MOUSE_BUTTON_LEFT,
                        x_or_dx: 2000,
                        y_or_dy: 50,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    4,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::Down,
                        buttons: MOUSE_BUTTON_LEFT,
                        x_or_dx: 100,
                        y_or_dy: 200,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                // Out-of-bounds Up with post-event bitmap `0` releases Left without moving cursor
                (
                    5,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::Up,
                        buttons: 0,
                        x_or_dx: -50,
                        y_or_dy: 9999,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    6,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::Down,
                        buttons: 0x20,
                        x_or_dx: 100,
                        y_or_dy: 200,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    7,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveAbs,
                        buttons: 0,
                        x_or_dx: 1270,
                        y_or_dy: 710,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    8,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveRel,
                        buttons: 0,
                        x_or_dx: 500,
                        y_or_dy: 500,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
            ],
            now,
        )
        .unwrap();
        assert_eq!(exec.out_of_bounds_drops, 3);
        assert_eq!(exec.invalid_button_drops, 1);
        assert_eq!(exec.pressed_buttons(), 0);
        assert_eq!(exec.last_up_coords_applied, Some(false));
        assert_eq!(exec.cursor_position(), (1279, 719));
        assert_eq!(
            exec.sink().ops,
            vec![
                DryRunOp::MoveAbs { x: 100, y: 200 },
                DryRunOp::MouseDown {
                    button_bit: MOUSE_BUTTON_LEFT
                },
                DryRunOp::MouseUp {
                    button_bit: MOUSE_BUTTON_LEFT
                },
                DryRunOp::MoveAbs { x: 1270, y: 710 },
                DryRunOp::MoveRel { dx: 9, dy: 9 },
            ]
        );
    }

    #[test]
    fn v26_stateful_invariants_full_conformance() {
        let v26_path = Path::new(
            "/Volumes/data/github/zerodesk/protocol-spec/vectors/v26_input_hid_wire.json",
        );
        if !v26_path.exists() {
            return;
        }
        let raw = std::fs::read_to_string(v26_path).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();
        let inv = &doc["stateful_invariants"];

        // 1. late_drop_exempts_release_events
        {
            let c = &inv["late_drop_exempts_release_events"];
            let w = c["screen_width"].as_i64().unwrap() as i32;
            let h = c["screen_height"].as_i64().unwrap() as i32;
            let mut exec = HidInputExecutor::new(DryRunSink::new(), w, h).unwrap();
            // Seed initial pressed state (button 1 + KeyA)
            exec.pressed_buttons = c["initial_pressed_buttons"].as_u64().unwrap() as u8;
            exec.held_state.set_buttons(exec.pressed_buttons);
            for k in c["initial_pressed_keys"].as_array().unwrap() {
                let key = SafeHidKey::from_usb_hid_usage(k.as_u64().unwrap() as u32).unwrap();
                exec.pressed_keys.insert(key);
                exec.held_state.record_key_down(key);
            }
            let frames: Vec<(u32, HidPayload)> = c["input_l4_frames_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| decode_l4_hid_frame(&hex::decode(s.as_str().unwrap()).unwrap()).unwrap())
                .collect();
            let out = exec.apply_v123_stream_batch(&frames).unwrap();
            let emitted_seqs: Vec<u32> = out.executed.iter().map(|(s, _)| *s).collect();
            let expected_emitted: Vec<u32> = c["expected_emitted_seqs"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(emitted_seqs, expected_emitted);
            assert_eq!(
                exec.pressed_buttons(),
                c["expected_final_pressed_buttons"].as_u64().unwrap() as u8
            );
            let final_keys: Vec<u32> = exec
                .pressed_keys()
                .iter()
                .map(|k| k.usb_hid_usage())
                .collect();
            let expected_keys: Vec<u32> = c["expected_final_pressed_keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_u64().unwrap() as u32)
                .collect();
            assert_eq!(final_keys, expected_keys);
            assert_eq!(
                exec.max_received_client_ts_ms(),
                c["expected_max_received_client_ts_ms"].as_u64().unwrap()
            );
            assert_eq!(
                exec.last_up_coords_applied,
                Some(c["expected_oob_up_coords_applied"].as_bool().unwrap())
            );
            assert_eq!(
                out.dropped_stale_seqs.len(),
                c["dropped_stale"].as_array().unwrap().len()
            );
            assert_eq!(
                exec.out_of_bounds_drops as usize,
                c["dropped_oob"].as_array().unwrap().len()
            );
            assert_eq!(
                exec.unsupported_usage_drops as usize,
                c["dropped_unknown_usage"].as_array().unwrap().len()
            );
        }

        // 2. oob_frame_does_not_poison_high_water_mark
        {
            let c = &inv["oob_frame_does_not_poison_high_water_mark"];
            let mut exec = HidInputExecutor::new(
                DryRunSink::new(),
                c["screen_width"].as_i64().unwrap() as i32,
                c["screen_height"].as_i64().unwrap() as i32,
            )
            .unwrap();
            let frames: Vec<(u32, HidPayload)> = c["input_l4_frames_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| decode_l4_hid_frame(&hex::decode(s.as_str().unwrap()).unwrap()).unwrap())
                .collect();
            let out = exec.apply_v123_stream_batch(&frames).unwrap();
            let emitted_seqs: Vec<u32> = out.executed.iter().map(|(s, _)| *s).collect();
            assert_eq!(emitted_seqs, vec![1, 4]);
            assert!(out.dropped_stale_seqs.is_empty());
            assert_eq!(exec.out_of_bounds_drops, 2);
            assert_eq!(
                exec.max_received_client_ts_ms(),
                c["expected_max_received_client_ts_ms"].as_u64().unwrap()
            );
        }

        // 3. up_frame_release_only_directionality (cases a, b, c)
        {
            let c = &inv["up_frame_release_only_directionality"];
            let w = c["screen_width"].as_i64().unwrap() as i32;
            let h = c["screen_height"].as_i64().unwrap() as i32;

            // Case A
            let ca = &c["case_a_prev_zero_up_sets_bit1"];
            let mut exec_a = HidInputExecutor::new(DryRunSink::new(), w, h).unwrap();
            let frames_a: Vec<(u32, HidPayload)> = ca["input_l4_frames_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| decode_l4_hid_frame(&hex::decode(s.as_str().unwrap()).unwrap()).unwrap())
                .collect();
            exec_a.apply_v123_stream_batch(&frames_a).unwrap();
            assert_eq!(exec_a.pressed_buttons(), 0);
            assert_eq!(
                exec_a.spurious_up_bits_ignored,
                ca["expected_spurious_up_bits_ignored"].as_u64().unwrap()
            );

            // Case B
            let cb = &c["case_b_late_up_stale_bitmask_cannot_press"];
            let mut exec_b = HidInputExecutor::new(DryRunSink::new(), w, h).unwrap();
            exec_b.max_received_client_ts_ms =
                cb["initial_max_received_client_ts_ms"].as_u64().unwrap();
            exec_b.pressed_buttons = cb["initial_pressed_buttons"].as_u64().unwrap() as u8;
            exec_b.held_state.set_buttons(exec_b.pressed_buttons);
            let frames_b: Vec<(u32, HidPayload)> = cb["input_l4_frames_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| decode_l4_hid_frame(&hex::decode(s.as_str().unwrap()).unwrap()).unwrap())
                .collect();
            exec_b.apply_v123_stream_batch(&frames_b).unwrap();
            assert_eq!(exec_b.pressed_buttons(), 0);
            assert_eq!(
                exec_b.spurious_up_bits_ignored,
                cb["expected_spurious_up_bits_ignored"].as_u64().unwrap()
            );

            // Case C
            let cc = &c["case_c_rejected_oob_down_preserves_implicit_release"];
            let mut exec_c = HidInputExecutor::new(DryRunSink::new(), w, h).unwrap();
            exec_c.pressed_buttons = cc["initial_pressed_buttons"].as_u64().unwrap() as u8;
            exec_c.held_state.set_buttons(exec_c.pressed_buttons);
            let frames_c: Vec<(u32, HidPayload)> = cc["input_l4_frames_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| decode_l4_hid_frame(&hex::decode(s.as_str().unwrap()).unwrap()).unwrap())
                .collect();
            let out_c = exec_c.apply_v123_stream_batch(&frames_c).unwrap();
            assert!(out_c.executed.is_empty());
            assert_eq!(exec_c.out_of_bounds_drops, 1);
            assert_eq!(exec_c.pressed_buttons(), 0);
            assert_eq!(
                exec_c.sink().ops,
                vec![DryRunOp::MouseUp {
                    button_bit: MOUSE_BUTTON_LEFT
                }]
            );
        }

        // 4. contiguous_move_rel_flushes_before_click + streaming saturation + 128 cap
        {
            let c = &inv["contiguous_move_rel_flushes_before_click"];
            let w = c["screen_width"].as_i64().unwrap() as i32;
            let h = c["screen_height"].as_i64().unwrap() as i32;
            let mut exec = HidInputExecutor::new(DryRunSink::new(), w, h).unwrap();
            let frames: Vec<(u32, HidPayload)> = c["input_l4_frames_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| decode_l4_hid_frame(&hex::decode(s.as_str().unwrap()).unwrap()).unwrap())
                .collect();
            let out = exec.apply_v123_stream_batch(&frames).unwrap();
            assert_eq!(out.executed.len(), 3);
            assert_eq!(out.executed[0].0, 11);
            assert_eq!(out.executed[1].0, 12);
            assert_eq!(out.executed[2].0, 13);
            match out.executed[0].1 {
                HidPayload::Mouse(ev) => {
                    assert_eq!(ev.x_or_dx, 14);
                    assert_eq!(ev.y_or_dy, 3);
                    assert_eq!(ev.client_ts_ms, 2005);
                }
                _ => panic!("expected MoveRel"),
            }

            // Streaming saturation
            let sat_frames: Vec<(u32, HidPayload)> = c["streaming_saturation_input_l4_frames_hex"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| decode_l4_hid_frame(&hex::decode(s.as_str().unwrap()).unwrap()).unwrap())
                .collect();
            let mut exec_sat = HidInputExecutor::new(DryRunSink::new(), w, h).unwrap();
            let sat_out = exec_sat.apply_v123_stream_batch(&sat_frames).unwrap();
            assert_eq!(sat_out.executed.len(), 1);
            assert_eq!(
                sat_out.executed[0].0,
                c["streaming_saturation_expected_echo_seq"]
                    .as_u64()
                    .unwrap() as u32
            );
            match sat_out.executed[0].1 {
                HidPayload::Mouse(ev) => {
                    assert_eq!(
                        ev.x_or_dx,
                        c["streaming_saturation_expected_dx"].as_i64().unwrap() as i32
                    );
                    assert_eq!(
                        ev.y_or_dy,
                        c["streaming_saturation_expected_dy"].as_i64().unwrap() as i32
                    );
                }
                _ => panic!("expected MoveRel"),
            }
        }

        // 5. release_all_isolated_partial_failure_retention + bounded 5-retry exhaustion
        {
            let c = &inv["release_all_isolated_partial_failure_retention"];
            let sink = PartialFailReleaseSink {
                fail_buttons_on_passes: vec![2, 0],
                fail_keys_on_passes: vec![vec![SafeHidKey::RightShift], vec![]],
                pass_index: 0,
                always_fail_keys: Vec::new(),
            };
            let mut exec = HidInputExecutor::new(sink, 1920, 1080).unwrap();
            exec.pressed_buttons = c["initial_pressed_buttons"].as_u64().unwrap() as u8;
            exec.held_state.set_buttons(exec.pressed_buttons);
            for k in c["initial_pressed_keys"].as_array().unwrap() {
                let key = SafeHidKey::from_usb_hid_usage(k.as_u64().unwrap() as u32).unwrap();
                exec.pressed_keys.insert(key);
                exec.held_state.record_key_down(key);
            }
            let p1 = exec.release_all_single_pass("v26_pass1");
            assert_eq!(p1.released_buttons, 1);
            assert_eq!(p1.failed_buttons, 2);
            assert_eq!(p1.released_keys, vec![SafeHidKey::KeyA, SafeHidKey::LeftShift]);
            assert_eq!(p1.failed_keys, vec![SafeHidKey::RightShift]);

            let p2 = exec.release_all_single_pass("v26_pass2");
            assert_eq!(p2.released_buttons, 2);
            assert_eq!(p2.failed_buttons, 0);
            assert_eq!(p2.released_keys, vec![SafeHidKey::RightShift]);
            assert!(p2.failed_keys.is_empty());

            // Bounded 5-retry exhaustion latches input_faulted
            let b = &c["bounded_retry_exhaustion"];
            let stuck_sink = PartialFailReleaseSink::always_fail_key(SafeHidKey::RightShift);
            let mut exec_ex = HidInputExecutor::new(stuck_sink, 1920, 1080).unwrap();
            exec_ex.pressed_buttons = 3;
            exec_ex.held_state.set_buttons(3);
            for key in [SafeHidKey::KeyA, SafeHidKey::LeftShift, SafeHidKey::RightShift] {
                exec_ex.pressed_keys.insert(key);
                exec_ex.held_state.record_key_down(key);
            }
            let mut recorded_sleeps = Vec::new();
            let summary = exec_ex.release_all_with_backoff("v26_exhaust", |d| {
                recorded_sleeps.push(d.as_millis() as u64);
            });
            assert_eq!(recorded_sleeps, HID_RELEASE_ALL_BACKOFF_MS.to_vec());
            assert_eq!(summary.retries_executed, HID_RELEASE_ALL_MAX_RETRIES);
            assert!(summary.input_faulted);
            assert!(exec_ex.is_faulted());
            assert_eq!(summary.failed_buttons, 0);
            assert_eq!(summary.failed_keys, vec![SafeHidKey::RightShift]);

            let probe_raw = hex::decode(b["probe_l4_frame_hex"].as_str().unwrap()).unwrap();
            let probe = decode_l4_hid_frame(&probe_raw).unwrap();
            assert_eq!(
                exec_ex.apply_v123_stream_batch(&[probe]),
                Err(InputError::InputFaulted)
            );

            // Explicit reset allows post-reset events again
            exec_ex.reset_input_fault();
            let post = exec_ex.apply_v123_stream_batch(&[probe]).unwrap();
            assert_eq!(post.executed.len(), 1);
        }
    }

    #[test]
    fn dangerous_shortcuts_blocked_in_forward_and_reversed_chord_order() {
        let now = now_epoch_ms();
        let key_ev = |down: bool, usage: u32, modifiers: u8| {
            HidPayload::Key(KeyEvent {
                down,
                modifiers,
                usb_hid_usage: usage,
                unicode_scalar: 0,
                client_ts_ms: now,
            })
        };

        let mut exec = HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap();
        exec.apply_batch(
            &[
                (1, key_ev(true, SafeHidKey::Delete.usb_hid_usage(), 0), now),
                (
                    2,
                    key_ev(true, SafeHidKey::LeftControl.usb_hid_usage(), MOD_CTRL),
                    now,
                ),
                (
                    3,
                    key_ev(
                        true,
                        SafeHidKey::LeftAlt.usb_hid_usage(),
                        MOD_CTRL | MOD_ALT,
                    ),
                    now,
                ),
            ],
            now,
        )
        .unwrap();
        assert_eq!(exec.blocked_shortcut_drops, 1);
        assert!(!exec.pressed_keys().contains(&SafeHidKey::LeftAlt));

        let mut exec2 = HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap();
        let blocked_chords: &[(u32, u8)] = &[
            (SafeHidKey::Backspace.usb_hid_usage(), MOD_CTRL | MOD_ALT),
            (SafeHidKey::F2.usb_hid_usage(), MOD_CTRL | MOD_ALT),
            (SafeHidKey::KeyQ.usb_hid_usage(), MOD_CTRL),
            (SafeHidKey::F4.usb_hid_usage(), MOD_ALT),
            (SafeHidKey::KeyQ.usb_hid_usage(), MOD_META),
            (SafeHidKey::KeyL.usb_hid_usage(), MOD_META),
            (SafeHidKey::KeyQ.usb_hid_usage(), MOD_META | MOD_SHIFT),
            (SafeHidKey::KeyQ.usb_hid_usage(), MOD_CTRL | MOD_META),
            (SafeHidKey::Escape.usb_hid_usage(), MOD_META | MOD_ALT),
        ];
        let batch: Vec<_> = blocked_chords
            .iter()
            .enumerate()
            .map(|(i, &(u, m))| (i as u32, key_ev(true, u, m), now))
            .collect();
        exec2.apply_batch(&batch, now).unwrap();
        assert_eq!(exec2.blocked_shortcut_drops, blocked_chords.len() as u64);
        assert!(exec2.pressed_keys().is_empty());
    }

    #[test]
    fn randomized_property_10000_sequences_zero_stuck_keys_or_buttons() {
        let mut seed: u64 = 0xD00D_F00D_1234_5678;
        let mut next_u32 = || -> u32 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 32) as u32
        };

        let sample_keys = [
            0x04u32, 0x05, 0x06, 0x1E, 0x28, 0xE0, 0xE1, 0xE4, 0xE5, 0x4F, 0x0104, 0x00,
        ];

        for trial in 0..10_000u32 {
            let mut exec =
                HidInputExecutor::with_options(DryRunSink::new(), 1920, 1080, 100_000, None)
                    .unwrap();
            let mut batch = Vec::with_capacity(12);
            let mut ts = 10_000u64;
            let len = (next_u32() % 10) + 1;
            for step in 0..len {
                let r = next_u32();
                // Mix fresh, late (-300ms), and OOB timestamps
                let ev_ts = match r % 4 {
                    0 => ts.saturating_sub(300),
                    1 => ts + 5,
                    2 => ts + 10_000,
                    _ => ts,
                };
                if r % 4 == 1 {
                    ts = ev_ts;
                }
                let x = if (r >> 3) % 5 == 0 {
                    3000
                } else {
                    ((r >> 4) % 1920) as i32
                };
                let y = if (r >> 5) % 5 == 0 {
                    -10
                } else {
                    ((r >> 8) % 1080) as i32
                };
                let payload = match r % 7 {
                    0 => HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveAbs,
                        buttons: ((r >> 12) as u8) & MOUSE_BUTTONS_VALID_MASK,
                        x_or_dx: x,
                        y_or_dy: y,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: ev_ts,
                    }),
                    1 => HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveRel,
                        buttons: ((r >> 12) as u8) & MOUSE_BUTTONS_VALID_MASK,
                        x_or_dx: ((r as i32) % 50) - 25,
                        y_or_dy: (((r >> 6) as i32) % 50) - 25,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: ev_ts,
                    }),
                    2 => HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::Down,
                        buttons: ((r >> 12) as u8) & MOUSE_BUTTONS_VALID_MASK,
                        x_or_dx: x,
                        y_or_dy: y,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: ev_ts,
                    }),
                    3 => HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::Up,
                        buttons: ((r >> 12) as u8) & MOUSE_BUTTONS_VALID_MASK,
                        x_or_dx: x,
                        y_or_dy: y,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: ev_ts,
                    }),
                    4 => HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::Wheel,
                        buttons: ((r >> 12) as u8) & MOUSE_BUTTONS_VALID_MASK,
                        x_or_dx: x,
                        y_or_dy: y,
                        wheel_dx: 0,
                        wheel_dy: 1,
                        client_ts_ms: ev_ts,
                    }),
                    5 => {
                        let usage = sample_keys[(r as usize) % sample_keys.len()];
                        let mods = match usage {
                            0xE0 | 0xE4 => MOD_CTRL,
                            0xE1 | 0xE5 => MOD_SHIFT,
                            _ => 0,
                        };
                        HidPayload::Key(KeyEvent {
                            down: true,
                            modifiers: mods,
                            usb_hid_usage: usage,
                            unicode_scalar: 0,
                            client_ts_ms: ev_ts,
                        })
                    }
                    _ => {
                        let usage = sample_keys[(r as usize) % sample_keys.len()];
                        HidPayload::Key(KeyEvent {
                            down: false,
                            modifiers: 0,
                            usb_hid_usage: usage,
                            unicode_scalar: 0,
                            client_ts_ms: ev_ts,
                        })
                    }
                };
                batch.push((step, payload));
            }
            let _ = exec.apply_v123_stream_batch(&batch);
            let _ = exec.release_all("property_end");

            // Invariant 1: Executor & AtomicHeldState have zero stuck buttons or keys
            assert_eq!(exec.pressed_buttons(), 0, "trial {trial}: stuck button");
            assert!(exec.pressed_keys().is_empty(), "trial {trial}: stuck key");
            assert!(
                !exec.held_state().has_pressed_state(),
                "trial {trial}: AtomicHeldState still has pressed state"
            );

            // Invariant 2: Net sink Down/Up count for every mouse button and key is balanced (0 held!)
            let mut sink_btns = 0u8;
            let mut sink_keys: BTreeSet<SafeHidKey> = BTreeSet::new();
            for op in &exec.sink().ops {
                match *op {
                    DryRunOp::MouseDown { button_bit } => sink_btns |= button_bit,
                    DryRunOp::MouseUp { button_bit } => sink_btns &= !button_bit,
                    DryRunOp::KeyDown { key } => {
                        sink_keys.insert(key);
                    }
                    DryRunOp::KeyUp { key } => {
                        sink_keys.remove(&key);
                    }
                    _ => {}
                }
            }
            assert_eq!(sink_btns, 0, "trial {trial}: sink button left down");
            assert!(sink_keys.is_empty(), "trial {trial}: sink key left down");
        }
    }

    #[test]
    fn randomized_hid_sequence_and_sink_failure_latch_terminated_and_release_all() {
        let mut seed: u64 = 0x5EED_CAFE_1234_ABCD;
        let mut next_u32 = || -> u32 {
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (seed >> 32) as u32
        };

        let sample_keys = [
            0x04u32, 0x05, 0x06, 0x1E, 0x28, 0xE0, 0xE1, 0xE4, 0xE5, 0x4F,
        ];

        for fail_at in [1usize, 3, 7, 15, 29, 64] {
            let sink = FaultInjectingSink::new(fail_at);
            let mut exec = HidInputExecutor::new(sink, 1280, 720).unwrap();
            let now = now_epoch_ms();
            let mut seq_base = 0u32;
            let mut failed = false;
            for _round in 0..4 {
                let mut batch = Vec::with_capacity(100);
                for offset in 0..100u32 {
                    let seq = seq_base + offset;
                    let r = next_u32();
                    let payload = match r % 5 {
                        0 => HidPayload::Mouse(MouseEvent {
                            kind: MouseKind::MoveAbs,
                            buttons: 0,
                            x_or_dx: (r % 1280) as i32,
                            y_or_dy: ((r >> 10) % 720) as i32,
                            wheel_dx: 0,
                            wheel_dy: 0,
                            client_ts_ms: now,
                        }),
                        1 => HidPayload::Mouse(MouseEvent {
                            kind: MouseKind::Down,
                            buttons: 1 << ((r % 3) as u8),
                            x_or_dx: (r % 1280) as i32,
                            y_or_dy: ((r >> 10) % 720) as i32,
                            wheel_dx: 0,
                            wheel_dy: 0,
                            client_ts_ms: now,
                        }),
                        2 => HidPayload::Mouse(MouseEvent {
                            kind: MouseKind::Up,
                            buttons: 0,
                            x_or_dx: (r % 1280) as i32,
                            y_or_dy: ((r >> 10) % 720) as i32,
                            wheel_dx: 0,
                            wheel_dy: 0,
                            client_ts_ms: now,
                        }),
                        3 => {
                            let usage = sample_keys[(r as usize) % sample_keys.len()];
                            let mods = match usage {
                                0xE0 | 0xE4 => MOD_CTRL,
                                0xE1 | 0xE5 => MOD_SHIFT,
                                _ => 0,
                            };
                            HidPayload::Key(KeyEvent {
                                down: true,
                                modifiers: mods,
                                usb_hid_usage: usage,
                                unicode_scalar: 0,
                                client_ts_ms: now,
                            })
                        }
                        _ => HidPayload::Key(KeyEvent {
                            down: false,
                            modifiers: 0,
                            usb_hid_usage: sample_keys[(r as usize) % sample_keys.len()],
                            unicode_scalar: 0,
                            client_ts_ms: now,
                        }),
                    };
                    batch.push((seq, payload, now));
                }
                seq_base += 100;
                if let Err(err) = exec.apply_batch(&batch, now) {
                    assert!(
                        matches!(err, InputError::SinkFailed(_)),
                        "expected SinkFailed for fail_at={fail_at}, got {err:?}"
                    );
                    failed = true;
                    break;
                }
            }
            assert!(failed, "expected SinkFailed for fail_at={fail_at}");
            assert!(exec.is_terminated());
            assert_eq!(exec.pressed_buttons(), 0);
            assert!(exec.pressed_keys().is_empty());
            assert_eq!(exec.apply_batch(&[], now), Err(InputError::SessionTerminated));
        }

        // Verify Drop releases any still-held state cleanly
        let sink = FaultInjectingSink::new(usize::MAX);
        let rel_calls = Arc::clone(&sink.release_all_calls);
        let rel_btns = Arc::clone(&sink.released_buttons_seen);
        let rel_keys = Arc::clone(&sink.released_keys_seen);
        {
            let mut exec = HidInputExecutor::new(sink, 1280, 720).unwrap();
            let now = now_epoch_ms();
            exec.apply_batch(
                &[
                    (
                        1,
                        HidPayload::Key(KeyEvent {
                            down: true,
                            modifiers: MOD_SHIFT,
                            usb_hid_usage: 0xE1,
                            unicode_scalar: 0,
                            client_ts_ms: now,
                        }),
                        now,
                    ),
                    (
                        2,
                        HidPayload::Mouse(MouseEvent {
                            kind: MouseKind::Down,
                            buttons: MOUSE_BUTTON_LEFT,
                            x_or_dx: 100,
                            y_or_dy: 100,
                            wheel_dx: 0,
                            wheel_dy: 0,
                            client_ts_ms: now,
                        }),
                        now,
                    ),
                ],
                now,
            )
            .unwrap();
        }
        assert_eq!(rel_calls.load(Ordering::SeqCst), 1);
        assert_eq!(*rel_btns.lock().unwrap(), MOUSE_BUTTON_LEFT);
        assert_eq!(*rel_keys.lock().unwrap(), vec![SafeHidKey::LeftShift]);
    }

    #[test]
    fn partial_release_all_failure_retains_failed_keys_and_bounded_5_retry_timing() {
        // Single-pass retention
        let sink = PartialFailReleaseSink::fail_once_key(SafeHidKey::KeyA);
        let mut exec = HidInputExecutor::new(sink, 1280, 720).unwrap();
        let now = now_epoch_ms();
        exec.apply_batch(
            &[
                (
                    1,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    2,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: MOD_SHIFT,
                        usb_hid_usage: SafeHidKey::LeftShift.usb_hid_usage(),
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
            ],
            now,
        )
        .unwrap();

        let first = exec.release_all_single_pass("first_try");
        assert_eq!(first.released_keys, vec![SafeHidKey::LeftShift]);
        assert_eq!(first.failed_keys, vec![SafeHidKey::KeyA]);
        assert!(exec.pressed_keys().contains(&SafeHidKey::KeyA));
        assert!(!exec.pressed_keys().contains(&SafeHidKey::LeftShift));

        let second = exec.release_all_single_pass("retry");
        assert_eq!(second.released_keys, vec![SafeHidKey::KeyA]);
        assert!(second.failed_keys.is_empty());
        assert!(exec.pressed_keys().is_empty());

        // Real-clock bounded 5-retry exhaustion timing check (sum of [50,100,200,400,500] = 1250ms)
        let always_fail = PartialFailReleaseSink::always_fail_key(SafeHidKey::KeyA);
        let mut exec2 = HidInputExecutor::new(always_fail, 1280, 720).unwrap();
        exec2.startup_self_test().unwrap();
        exec2
            .apply_batch(
                &[(
                    1,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                )],
                now,
            )
            .unwrap();
        let t0 = Instant::now();
        let sum = exec2.release_all("fault_timing");
        let elapsed = t0.elapsed();
        assert_eq!(sum.retries_executed, HID_RELEASE_ALL_MAX_RETRIES);
        assert!(sum.input_faulted);
        assert!(exec2.is_faulted());
        assert!(
            elapsed >= Duration::from_millis(1200),
            "expected >= 1200ms bounded backoff, got {elapsed:?}"
        );
        assert_eq!(exec2.apply_batch(&[], now), Err(InputError::InputFaulted));
    }

    #[test]
    fn independent_watchdog_releases_even_when_executor_mutex_is_stalled() {
        let exec = Arc::new(Mutex::new(
            HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap(),
        ));
        let held_state = exec.lock().unwrap().held_state();
        let audit_out = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));

        let mut indep_handle = spawn_independent_release_watchdog(
            Arc::clone(&held_state),
            DryRunSink::new(),
            Duration::from_millis(80),
            Arc::clone(&stop),
            Some(Arc::clone(&audit_out)),
        )
        .unwrap();

        // Hold executor mutex continuously (simulating an OS syscall stall!) while keys are held.
        {
            let mut guard = exec.lock().unwrap();
            let now = now_epoch_ms();
            guard
                .apply_batch(
                    &[
                        (
                            1,
                            HidPayload::Key(KeyEvent {
                                down: true,
                                modifiers: MOD_SHIFT,
                                usb_hid_usage: 0xE1,
                                unicode_scalar: 0,
                                client_ts_ms: now,
                            }),
                            now,
                        ),
                        (
                            2,
                            HidPayload::Mouse(MouseEvent {
                                kind: MouseKind::Down,
                                buttons: MOUSE_BUTTON_LEFT,
                                x_or_dx: 300,
                                y_or_dy: 300,
                                wheel_dx: 0,
                                wheel_dy: 0,
                                client_ts_ms: now,
                            }),
                            now,
                        ),
                    ],
                    now,
                )
                .unwrap();
            assert!(held_state.has_pressed_state());

            // Deliberately sleep WHILE STILL HOLDING `guard` (executor mutex locked!)
            thread::sleep(Duration::from_millis(220));

            // Independent watchdog MUST have released everything without waiting for `guard`!
            assert!(!held_state.has_pressed_state());
            assert_eq!(held_state.pressed_buttons(), 0);
            assert!(held_state.pressed_keys_snapshot().is_empty());
            assert!(held_state.watchdog_release_count() >= 1);
            guard.sync_from_held_state();
            assert_eq!(guard.pressed_buttons(), 0);
            assert!(guard.pressed_keys().is_empty());
        }

        indep_handle.stop_and_join().unwrap();
        let audits = audit_out.lock().unwrap();
        assert!(audits.iter().any(|r| matches!(
            r,
            AuditRecord::ReleaseAll {
                reason,
                released_buttons,
                released_keys,
                ..
            } if reason == "watchdog_timeout"
                && *released_buttons == MOUSE_BUTTON_LEFT
                && released_keys == &vec![SafeHidKey::LeftShift]
        )));
    }

    #[test]
    fn audit_redacts_key_identity_by_default_and_bounds_ring_and_writes_0600() {
        let mut exec = HidInputExecutor::new(DryRunSink::new(), 1280, 720)
            .unwrap()
            .with_audit_log_cap(3);
        let now = now_epoch_ms();
        exec.apply_batch(
            &[
                (
                    1,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                        unicode_scalar: 'a' as u32,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    2,
                    HidPayload::Key(KeyEvent {
                        down: false,
                        modifiers: 0,
                        usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                        unicode_scalar: 'a' as u32,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    3,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: SafeHidKey::KeyB.usb_hid_usage(),
                        unicode_scalar: 'b' as u32,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    4,
                    HidPayload::Key(KeyEvent {
                        down: false,
                        modifiers: 0,
                        usb_hid_usage: SafeHidKey::KeyB.usb_hid_usage(),
                        unicode_scalar: 'b' as u32,
                        client_ts_ms: now,
                    }),
                    now,
                ),
            ],
            now,
        )
        .unwrap();

        assert_eq!(exec.audit_log().len(), 3);
        assert_eq!(exec.audit_log_dropped, 1);
        for rec in exec.audit_log() {
            match rec {
                AuditRecord::KeyDown { key, .. } | AuditRecord::KeyUp { key, .. } => {
                    assert_eq!(*key, AuditKey::Redacted);
                }
                _ => panic!("expected redacted KeyDown/KeyUp, got {rec:?}"),
            }
        }

        let path = std::env::temp_dir().join(format!(
            "zd-audit-0600-test-{}-{}.jsonl",
            std::process::id(),
            now
        ));
        exec.flush_audit_jsonl(&path).unwrap();
        let raw = fs::read_to_string(&path).unwrap();
        assert!(raw.contains("\"key\":\"redacted\""));
        assert!(!raw.contains("\"KeyA\"") && !raw.contains("\"KeyB\""));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn batch_size_and_rate_limit_check_after_oob_validation_and_preserve_releases() {
        let mut exec =
            HidInputExecutor::with_options(DryRunSink::new(), 1280, 720, 2, None).unwrap();
        let now = now_epoch_ms();

        let huge: Vec<_> = (0..=(MAX_HID_BATCH_SIZE as u32))
            .map(|seq| {
                (
                    seq,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveAbs,
                        buttons: 0,
                        x_or_dx: 10,
                        y_or_dy: 10,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                )
            })
            .collect();
        assert!(matches!(
            exec.apply_batch(&huge, now),
            Err(InputError::BatchTooLarge { .. })
        ));
        assert_eq!(exec.batch_too_large_drops, 1);

        exec.apply_batch(
            &[
                (
                    0,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveAbs,
                        buttons: 0,
                        x_or_dx: 9999,
                        y_or_dy: 9999,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    1,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: 0x04,
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    2,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: 0x05,
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    3,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: 0x06,
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                (
                    4,
                    HidPayload::Key(KeyEvent {
                        down: false,
                        modifiers: 0,
                        usb_hid_usage: 0x04,
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
            ],
            now,
        )
        .unwrap();
        assert_eq!(exec.out_of_bounds_drops, 1);
        assert_eq!(exec.rate_limited_drops, 1);
        assert!(!exec.pressed_keys().contains(&SafeHidKey::KeyA));
        assert!(exec.pressed_keys().contains(&SafeHidKey::KeyB));
        assert!(!exec.pressed_keys().contains(&SafeHidKey::KeyC));
    }

    #[test]
    fn watchdog_releases_stuck_keys_and_recovers_poisoned_mutex() {
        let exec = Arc::new(Mutex::new(
            HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let mut handle =
            spawn_release_watchdog(Arc::clone(&exec), Duration::from_millis(80), Arc::clone(&stop))
                .unwrap();

        {
            let mut g = exec.lock().unwrap();
            let now = now_epoch_ms();
            g.apply_batch(
                &[
                    (
                        1,
                        HidPayload::Key(KeyEvent {
                            down: true,
                            modifiers: MOD_SHIFT,
                            usb_hid_usage: 0xE1,
                            unicode_scalar: 0,
                            client_ts_ms: now,
                        }),
                        now,
                    ),
                    (
                        2,
                        HidPayload::Key(KeyEvent {
                            down: true,
                            modifiers: MOD_SHIFT,
                            usb_hid_usage: 0x04,
                            unicode_scalar: 0,
                            client_ts_ms: now,
                        }),
                        now,
                    ),
                    (
                        3,
                        HidPayload::Mouse(MouseEvent {
                            kind: MouseKind::Down,
                            buttons: MOUSE_BUTTON_LEFT,
                            x_or_dx: 640,
                            y_or_dy: 360,
                            wheel_dx: 0,
                            wheel_dy: 0,
                            client_ts_ms: now,
                        }),
                        now,
                    ),
                ],
                now,
            )
            .unwrap();
            assert!(g.has_pressed_state());
        }

        thread::sleep(Duration::from_millis(200));
        handle.stop_and_join().unwrap();

        let g = exec.lock().unwrap();
        assert_eq!(g.pressed_buttons(), 0);
        assert!(g.pressed_keys().is_empty());
        assert!(g.audit_log().iter().any(|r| matches!(
            r,
            AuditRecord::ReleaseAll {
                reason,
                released_buttons,
                released_keys,
                ..
            } if reason == "watchdog_timeout"
                && *released_buttons == MOUSE_BUTTON_LEFT
                && released_keys == &vec![SafeHidKey::KeyA, SafeHidKey::LeftShift]
        )));

        let poisoned_exec = Arc::new(Mutex::new(
            HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap(),
        ));
        let p_clone = Arc::clone(&poisoned_exec);
        let _ = thread::spawn(move || {
            let mut g = p_clone.lock().unwrap();
            let now = now_epoch_ms();
            g.apply_batch(
                &[(
                    1,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                )],
                now,
            )
            .unwrap();
            panic!("simulated panic while holding executor mutex");
        })
        .join();
        assert!(poisoned_exec.is_poisoned());

        let stop2 = Arc::new(AtomicBool::new(false));
        let mut handle2 = spawn_release_watchdog(
            Arc::clone(&poisoned_exec),
            Duration::from_millis(500),
            stop2,
        )
        .unwrap();
        thread::sleep(Duration::from_millis(120));
        handle2.stop_and_join().unwrap();

        let g2 = poisoned_exec
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        assert_eq!(g2.pressed_buttons(), 0);
        assert!(g2.pressed_keys().is_empty());
        assert!(g2.audit_log().iter().any(|r| matches!(
            r,
            AuditRecord::ReleaseAll {
                reason,
                released_keys,
                ..
            } if reason == "watchdog_poison_recovery" && released_keys == &vec![SafeHidKey::KeyA]
        )));
    }

    #[test]
    fn atomic_held_state_separates_closed_from_releasing_and_generation_catches_race() {
        // 1. run_independent_release_all clears `releasing` but NEVER clears `closed`
        let state = AtomicHeldState::new();
        state.record_button_down(MOUSE_BUTTON_LEFT);
        state.record_key_down(SafeHidKey::KeyA);
        state.mark_closed();
        assert!(state.is_closed());
        assert!(state.is_releasing_or_closed());
        let gen0 = state.release_generation();
        let mut sink = DryRunSink::new();
        let summary = run_independent_release_all(&state, &mut sink, "teardown", |_| {});
        assert_eq!(summary.released_buttons, MOUSE_BUTTON_LEFT);
        assert_eq!(summary.released_keys, vec![SafeHidKey::KeyA]);
        assert!(!state.is_releasing());
        assert!(state.is_closed());
        assert!(state.is_releasing_or_closed());
        assert!(state.release_generation() > gen0);

        // 2. Stalled sink.key_down completing after concurrent release_generation bump issues
        //    immediate compensating key_up and never leaves an untracked stuck key!
        struct GenerationBumpingSink {
            held_state: Arc<AtomicHeldState>,
            ops: Vec<DryRunOp>,
        }
        impl HidInputSink for GenerationBumpingSink {
            fn move_abs(&mut self, x: i32, y: i32) -> Result<(), InputSinkError> {
                self.ops.push(DryRunOp::MoveAbs { x, y });
                Ok(())
            }
            fn move_rel(&mut self, dx: i32, dy: i32) -> Result<(), InputSinkError> {
                self.ops.push(DryRunOp::MoveRel { dx, dy });
                Ok(())
            }
            fn mouse_down(&mut self, button_bit: u8) -> Result<(), InputSinkError> {
                self.ops.push(DryRunOp::MouseDown { button_bit });
                Ok(())
            }
            fn mouse_up(&mut self, button_bit: u8) -> Result<(), InputSinkError> {
                self.ops.push(DryRunOp::MouseUp { button_bit });
                Ok(())
            }
            fn wheel(&mut self, dx: i16, dy: i16) -> Result<(), InputSinkError> {
                self.ops.push(DryRunOp::Wheel { dx, dy });
                Ok(())
            }
            fn key_down(&mut self, key: SafeHidKey) -> Result<(), InputSinkError> {
                self.ops.push(DryRunOp::KeyDown { key });
                // Simulate watchdog completing a full release cycle while sink.key_down was stalled
                self.held_state.bump_release_generation();
                Ok(())
            }
            fn key_up(&mut self, key: SafeHidKey) -> Result<(), InputSinkError> {
                self.ops.push(DryRunOp::KeyUp { key });
                Ok(())
            }
            fn release_all_best_effort(
                &mut self,
                _pressed_buttons: u8,
                _pressed_keys: &[SafeHidKey],
            ) -> ReleaseAllResult {
                ReleaseAllResult::default()
            }
        }

        let dummy_state = Arc::new(AtomicHeldState::new());
        let mut exec = HidInputExecutor::new(
            GenerationBumpingSink {
                held_state: dummy_state,
                ops: Vec::new(),
            },
            640,
            360,
        )
        .unwrap();
        exec.sink.held_state = exec.held_state();

        let res = exec.apply_v123_stream_batch(&[(
            1,
            HidPayload::Key(KeyEvent {
                down: true,
                modifiers: 0,
                usb_hid_usage: SafeHidKey::KeyZ.usb_hid_usage(),
                unicode_scalar: 0,
                client_ts_ms: 1000,
            }),
        )]);
        assert_eq!(res.unwrap_err(), InputError::SessionTerminated);
        assert!(exec.sink().ops.contains(&DryRunOp::KeyUp {
            key: SafeHidKey::KeyZ
        }));
        assert!(!exec.has_pressed_state());
    }

    #[test]
    fn move_abs_and_wheel_drops_preserve_implicit_button_release_and_up_move_is_audited() {
        let mut exec = HidInputExecutor::new(DryRunSink::new(), 640, 360).unwrap();
        // Press LEFT at (100, 100)
        exec.apply_v123_stream_batch(&[(
            1,
            HidPayload::Mouse(MouseEvent {
                kind: MouseKind::Down,
                buttons: MOUSE_BUTTON_LEFT,
                x_or_dx: 100,
                y_or_dy: 100,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: 1_000,
            }),
        )])
        .unwrap();
        assert_eq!(exec.pressed_buttons(), MOUSE_BUTTON_LEFT);

        // OOB MoveAbs with buttons = 0 MUST still release LEFT even though MoveAbs is dropped!
        exec.apply_v123_stream_batch(&[(
            2,
            HidPayload::Mouse(MouseEvent {
                kind: MouseKind::MoveAbs,
                buttons: 0,
                x_or_dx: 9999,
                y_or_dy: 9999,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: 1_010,
            }),
        )])
        .unwrap();
        assert_eq!(exec.pressed_buttons(), 0);

        // Press RIGHT at (100, 100), then send late Wheel with buttons = 0 -> MUST release RIGHT!
        exec.apply_v123_stream_batch(&[(
            3,
            HidPayload::Mouse(MouseEvent {
                kind: MouseKind::Down,
                buttons: MOUSE_BUTTON_RIGHT,
                x_or_dx: 100,
                y_or_dy: 100,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: 2_000,
            }),
        )])
        .unwrap();
        assert_eq!(exec.pressed_buttons(), MOUSE_BUTTON_RIGHT);
        exec.apply_v123_stream_batch(&[(
            4,
            HidPayload::Mouse(MouseEvent {
                kind: MouseKind::Wheel,
                buttons: 0,
                x_or_dx: 0,
                y_or_dy: 0,
                wheel_dx: 0,
                wheel_dy: 3,
                client_ts_ms: 1_000, // >150ms stale
            }),
        )])
        .unwrap();
        assert_eq!(exec.pressed_buttons(), 0);

        // MouseKind::Up at a new in-bounds coordinate MUST audit MouseMoveAbs + increment count
        let before_count = exec.executed_events;
        exec.apply_v123_stream_batch(&[(
            5,
            HidPayload::Mouse(MouseEvent {
                kind: MouseKind::Up,
                buttons: 0,
                x_or_dx: 222,
                y_or_dy: 111,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: 2_010,
            }),
        )])
        .unwrap();
        assert_eq!(exec.cursor_position(), (222, 111));
        assert!(exec.executed_events > before_count);
        assert!(exec.audit_log().iter().any(|r| matches!(
            r,
            AuditRecord::MouseMoveAbs {
                seq: 5,
                x: 222,
                y: 111,
                ..
            }
        )));
    }

    #[test]
    fn watchdog_stop_and_join_is_bounded_when_sink_stalls() {
        struct StallingReleaseSink {
            entered: Arc<AtomicBool>,
        }
        impl HidInputSink for StallingReleaseSink {
            fn move_abs(&mut self, _x: i32, _y: i32) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn move_rel(&mut self, _dx: i32, _dy: i32) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn mouse_down(&mut self, _button_bit: u8) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn mouse_up(&mut self, _button_bit: u8) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn wheel(&mut self, _dx: i16, _dy: i16) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn key_down(&mut self, _key: SafeHidKey) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn key_up(&mut self, _key: SafeHidKey) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn release_all_best_effort(
                &mut self,
                _pressed_buttons: u8,
                _pressed_keys: &[SafeHidKey],
            ) -> ReleaseAllResult {
                self.entered.store(true, Ordering::Release);
                thread::sleep(Duration::from_secs(2));
                ReleaseAllResult::default()
            }
        }

        let state = Arc::new(AtomicHeldState::new());
        state.record_key_down(SafeHidKey::KeyA);
        let entered = Arc::new(AtomicBool::new(false));
        let stop = Arc::new(AtomicBool::new(false));
        let mut handle = spawn_independent_release_watchdog(
            Arc::clone(&state),
            StallingReleaseSink {
                entered: Arc::clone(&entered),
            },
            Duration::from_millis(20),
            stop,
            None,
        )
        .unwrap();

        let deadline = Instant::now() + Duration::from_secs(1);
        while !entered.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(entered.load(Ordering::Acquire));

        let t0 = Instant::now();
        let res = handle.stop_and_join_timeout(Duration::from_millis(80));
        assert!(res.is_err());
        assert!(t0.elapsed() < Duration::from_millis(500));
    }
}
