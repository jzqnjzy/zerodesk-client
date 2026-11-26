use super::{
    capture::SharedVisualMarker,
    hid::{
        coalesce_hid_batch, HidBatchOutcome, HidPayload, KeyEvent, MouseEvent, MouseKind, MOD_ALT,
        MOD_CTRL, MOD_META, MOUSE_BUTTONS_VALID_MASK,
    },
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fmt,
    fs::{self, File},
    io::{BufWriter, Write},
    panic::{catch_unwind, AssertUnwindSafe},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAX_HID_BATCH_SIZE: usize = 128;
pub const DEFAULT_HID_RATE_LIMIT_PER_SEC: u32 = 1000;
pub const MOUSE_BUTTON_LEFT: u8 = 1 << 0;
pub const MOUSE_BUTTON_RIGHT: u8 = 1 << 1;
pub const MOUSE_BUTTON_MIDDLE: u8 = 1 << 2;
pub const MOUSE_BUTTON_BACK: u8 = 1 << 3;
pub const MOUSE_BUTTON_FORWARD: u8 = 1 << 4;

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

/// Pure side-effect sink trait. Sinks MUST NOT track pressed state; all state lives in
/// `HidInputExecutor`.
pub trait HidInputSink: Send {
    fn move_abs(&mut self, x: i32, y: i32) -> Result<(), InputSinkError>;
    fn move_rel(&mut self, dx: i32, dy: i32) -> Result<(), InputSinkError>;
    fn mouse_down(&mut self, button_bit: u8) -> Result<(), InputSinkError>;
    fn mouse_up(&mut self, button_bit: u8) -> Result<(), InputSinkError>;
    fn wheel(&mut self, dx: i16, dy: i16) -> Result<(), InputSinkError>;
    fn key_down(&mut self, key: SafeHidKey) -> Result<(), InputSinkError>;
    fn key_up(&mut self, key: SafeHidKey) -> Result<(), InputSinkError>;

    /// Best-effort infallible release of all currently held buttons and keys. MUST NEVER panic.
    fn release_all_best_effort(&mut self, pressed_buttons: u8, pressed_keys: &[SafeHidKey]);
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

    fn release_all_best_effort(&mut self, pressed_buttons: u8, pressed_keys: &[SafeHidKey]) {
        for bit_idx in 0..5u8 {
            let bit = 1u8 << bit_idx;
            if pressed_buttons & bit != 0 {
                self.ops.push(DryRunOp::MouseUp { button_bit: bit });
            }
        }
        for &key in pressed_keys {
            self.ops.push(DryRunOp::KeyUp { key });
        }
    }
}

#[cfg(all(
    feature = "os-input",
    not(any(target_os = "android", target_os = "ios"))
))]
mod os_sink {
    use super::{
        HidInputSink, InputError, InputSinkError, SafeHidKey, MOUSE_BUTTON_BACK,
        MOUSE_BUTTON_FORWARD, MOUSE_BUTTON_LEFT, MOUSE_BUTTON_MIDDLE, MOUSE_BUTTON_RIGHT,
    };
    use enigo::{Enigo, Key, KeyboardControllable, MouseButton, MouseControllable};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[cfg(target_os = "macos")]
    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrusted() -> bool;
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
                let trusted = unsafe { AXIsProcessTrusted() };
                if !trusted {
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

        fn release_all_best_effort(&mut self, pressed_buttons: u8, pressed_keys: &[SafeHidKey]) {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                for bit_idx in 0..5u8 {
                    let bit = 1u8 << bit_idx;
                    if pressed_buttons & bit != 0 {
                        if let Ok(btn) = map_button_bit(bit) {
                            self.enigo.mouse_up(btn);
                        }
                    }
                }
                for &key in pressed_keys {
                    self.enigo.key_up(map_safe_key_to_enigo(key));
                }
            }));
        }
    }
}

#[cfg(all(
    feature = "os-input",
    not(any(target_os = "android", target_os = "ios"))
))]
pub use os_sink::EnigoOsSink;

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
        key: SafeHidKey,
        ts_ms: u64,
    },
    KeyUp {
        seq: u32,
        key: SafeHidKey,
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
        ts_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseAllSummary {
    pub released_buttons: u8,
    pub released_keys: Vec<SafeHidKey>,
}

struct TokenBucket {
    tokens: f64,
    capacity: f64,
    rate_per_sec: f64,
    last_ms: u64,
}

impl TokenBucket {
    fn new(rate_per_sec: u32, now_ms: u64) -> Self {
        let cap = f64::from(rate_per_sec.max(1));
        Self {
            tokens: cap,
            capacity: cap,
            rate_per_sec: cap,
            last_ms: now_ms,
        }
    }

    fn try_consume(&mut self, now_ms: u64) -> bool {
        if now_ms > self.last_ms {
            let dt_secs = ((now_ms - self.last_ms) as f64) / 1000.0;
            self.tokens = (self.tokens + dt_secs * self.rate_per_sec).min(self.capacity);
            self.last_ms = now_ms;
        }
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Shared HID input execution state machine used identically by DryRun and OS sinks.
pub struct HidInputExecutor<S: HidInputSink> {
    sink: S,
    screen_width: i32,
    screen_height: i32,
    cur_x: i32,
    cur_y: i32,
    pressed_buttons: u8,
    pressed_keys: BTreeSet<SafeHidKey>,
    block_dangerous_shortcuts: bool,
    rate_limiter: TokenBucket,
    visual_marker: Option<SharedVisualMarker>,
    last_activity_ms: Arc<AtomicU64>,
    audit_log: Vec<AuditRecord>,
    pub executed_events: u64,
    pub unsupported_usage_drops: u64,
    pub blocked_shortcut_drops: u64,
    pub out_of_bounds_drops: u64,
    pub rate_limited_drops: u64,
    pub release_all_count: u64,
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
        let now = now_epoch_ms();
        Ok(Self {
            sink,
            screen_width,
            screen_height,
            cur_x: 0,
            cur_y: 0,
            pressed_buttons: 0,
            pressed_keys: BTreeSet::new(),
            block_dangerous_shortcuts: true,
            rate_limiter: TokenBucket::new(rate_limit_per_sec, now),
            visual_marker,
            last_activity_ms: Arc::new(AtomicU64::new(now)),
            audit_log: Vec::new(),
            executed_events: 0,
            unsupported_usage_drops: 0,
            blocked_shortcut_drops: 0,
            out_of_bounds_drops: 0,
            rate_limited_drops: 0,
            release_all_count: 0,
        })
    }

    pub fn sink(&self) -> &S {
        &self.sink
    }

    pub fn sink_mut(&mut self) -> &mut S {
        &mut self.sink
    }

    pub fn pressed_buttons(&self) -> u8 {
        self.pressed_buttons
    }

    pub fn pressed_keys(&self) -> &BTreeSet<SafeHidKey> {
        &self.pressed_keys
    }

    pub fn has_pressed_state(&self) -> bool {
        self.pressed_buttons != 0 || !self.pressed_keys.is_empty()
    }

    pub fn cursor_position(&self) -> (i32, i32) {
        (self.cur_x, self.cur_y)
    }

    pub fn audit_log(&self) -> &[AuditRecord] {
        &self.audit_log
    }

    pub fn last_activity_ms_handle(&self) -> Arc<AtomicU64> {
        Arc::clone(&self.last_activity_ms)
    }

    pub fn touch_activity(&self, now_ms: u64) {
        self.last_activity_ms.store(now_ms, Ordering::Release);
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

    fn is_dangerous_shortcut(&self, key: SafeHidKey, ev_modifiers: u8) -> bool {
        if !self.block_dangerous_shortcuts {
            return false;
        }
        let ctrl_active = self.pressed_keys.contains(&SafeHidKey::LeftControl)
            || self.pressed_keys.contains(&SafeHidKey::RightControl)
            || (ev_modifiers & MOD_CTRL) != 0;
        let alt_active = self.pressed_keys.contains(&SafeHidKey::LeftAlt)
            || self.pressed_keys.contains(&SafeHidKey::RightAlt)
            || (ev_modifiers & MOD_ALT) != 0;
        let meta_active = self.pressed_keys.contains(&SafeHidKey::LeftMeta)
            || self.pressed_keys.contains(&SafeHidKey::RightMeta)
            || (ev_modifiers & MOD_META) != 0;

        matches!(
            (key, ctrl_active, alt_active, meta_active),
            (SafeHidKey::Delete, true, true, _)
                | (SafeHidKey::KeyQ, _, _, true)
                | (SafeHidKey::F4, _, true, _)
        )
    }

    /// Idempotent, infallible release of all currently held buttons and keys.
    /// Clears both pressed sets and records `AuditRecord::ReleaseAll`.
    pub fn release_all(&mut self, reason: &str) -> ReleaseAllSummary {
        let released_buttons = self.pressed_buttons;
        let released_keys: Vec<SafeHidKey> = self.pressed_keys.iter().copied().collect();

        if released_buttons != 0 || !released_keys.is_empty() {
            let _ = catch_unwind(AssertUnwindSafe(|| {
                self.sink
                    .release_all_best_effort(released_buttons, &released_keys);
            }));
        }

        self.pressed_buttons = 0;
        self.pressed_keys.clear();
        self.release_all_count = self.release_all_count.saturating_add(1);

        let ts_ms = now_epoch_ms();
        self.audit_log.push(AuditRecord::ReleaseAll {
            reason: reason.to_string(),
            released_buttons,
            released_keys: released_keys.clone(),
            ts_ms,
        });

        ReleaseAllSummary {
            released_buttons,
            released_keys,
        }
    }

    /// Coalesces and executes a batch of `(stream_seq, HidPayload, enqueue_ms)` strictly consuming
    /// ONLY `outcome.executed`. If any sink call fails mid-batch, immediately calls `release_all`
    /// and returns `Err(InputError::SinkFailed(...))`.
    pub fn apply_batch(
        &mut self,
        events: &[(u32, HidPayload, u64)],
        now_ms: u64,
    ) -> Result<HidBatchOutcome, InputError> {
        if events.len() > MAX_HID_BATCH_SIZE {
            return Err(InputError::BatchTooLarge {
                len: events.len(),
                max: MAX_HID_BATCH_SIZE,
            });
        }
        self.touch_activity(now_ms);
        let outcome = coalesce_hid_batch(events, now_ms);

        for &(seq, payload) in &outcome.executed {
            match payload {
                HidPayload::Mouse(ev) => self.apply_mouse(seq, ev, now_ms)?,
                HidPayload::Key(ev) => self.apply_key(seq, ev, now_ms)?,
                HidPayload::EchoAck(_) => {}
            }
        }
        Ok(outcome)
    }

    fn apply_mouse(&mut self, seq: u32, ev: MouseEvent, now_ms: u64) -> Result<(), InputError> {
        let is_release = ev.kind == MouseKind::Up;
        if !is_release && !self.rate_limiter.try_consume(now_ms) {
            self.rate_limited_drops = self.rate_limited_drops.saturating_add(1);
            self.audit_log.push(AuditRecord::Dropped {
                seq,
                reason: "rate_limited".into(),
                ts_ms: now_ms,
            });
            return Ok(());
        }

        match ev.kind {
            MouseKind::MoveAbs => {
                if !self.is_in_bounds(ev.x_or_dx, ev.y_or_dy) {
                    self.out_of_bounds_drops = self.out_of_bounds_drops.saturating_add(1);
                    self.audit_log.push(AuditRecord::Dropped {
                        seq,
                        reason: "out_of_bounds".into(),
                        ts_ms: now_ms,
                    });
                    return Ok(());
                }
                if let Err(e) = self.sink.move_abs(ev.x_or_dx, ev.y_or_dy) {
                    self.release_all("sink_failed");
                    return Err(InputError::SinkFailed(e.to_string()));
                }
                self.cur_x = ev.x_or_dx;
                self.cur_y = ev.y_or_dy;
                self.update_visual_marker(self.cur_x, self.cur_y);
                self.executed_events = self.executed_events.saturating_add(1);
                self.audit_log.push(AuditRecord::MouseMoveAbs {
                    seq,
                    x: self.cur_x,
                    y: self.cur_y,
                    ts_ms: now_ms,
                });
            }
            MouseKind::MoveRel => {
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
                    self.release_all("sink_failed");
                    return Err(InputError::SinkFailed(e.to_string()));
                }
                self.cur_x = next_x;
                self.cur_y = next_y;
                self.update_visual_marker(self.cur_x, self.cur_y);
                self.executed_events = self.executed_events.saturating_add(1);
                self.audit_log.push(AuditRecord::MouseMoveRel {
                    seq,
                    dx: clamped_dx,
                    dy: clamped_dy,
                    cur_x: self.cur_x,
                    cur_y: self.cur_y,
                    ts_ms: now_ms,
                });
            }
            MouseKind::Down => {
                if !self.is_in_bounds(ev.x_or_dx, ev.y_or_dy) {
                    self.out_of_bounds_drops = self.out_of_bounds_drops.saturating_add(1);
                    self.audit_log.push(AuditRecord::Dropped {
                        seq,
                        reason: "out_of_bounds".into(),
                        ts_ms: now_ms,
                    });
                    return Ok(());
                }
                self.cur_x = ev.x_or_dx;
                self.cur_y = ev.y_or_dy;
                self.update_visual_marker(self.cur_x, self.cur_y);
                let mask = ev.buttons & MOUSE_BUTTONS_VALID_MASK;
                for bit_idx in 0..5u8 {
                    let bit = 1u8 << bit_idx;
                    if mask & bit != 0 && (self.pressed_buttons & bit) == 0 {
                        if let Err(e) = self.sink.mouse_down(bit) {
                            self.release_all("sink_failed");
                            return Err(InputError::SinkFailed(e.to_string()));
                        }
                        self.pressed_buttons |= bit;
                        self.executed_events = self.executed_events.saturating_add(1);
                        self.audit_log.push(AuditRecord::MouseDown {
                            seq,
                            button_bit: bit,
                            x: self.cur_x,
                            y: self.cur_y,
                            ts_ms: now_ms,
                        });
                    }
                }
            }
            MouseKind::Up => {
                if !self.is_in_bounds(ev.x_or_dx, ev.y_or_dy) {
                    self.out_of_bounds_drops = self.out_of_bounds_drops.saturating_add(1);
                    self.audit_log.push(AuditRecord::Dropped {
                        seq,
                        reason: "out_of_bounds".into(),
                        ts_ms: now_ms,
                    });
                    return Ok(());
                }
                self.cur_x = ev.x_or_dx;
                self.cur_y = ev.y_or_dy;
                let mask = ev.buttons & MOUSE_BUTTONS_VALID_MASK;
                let to_release = if mask == 0 {
                    self.pressed_buttons
                } else {
                    self.pressed_buttons & mask
                };
                for bit_idx in 0..5u8 {
                    let bit = 1u8 << bit_idx;
                    if to_release & bit != 0 {
                        if let Err(e) = self.sink.mouse_up(bit) {
                            self.release_all("sink_failed");
                            return Err(InputError::SinkFailed(e.to_string()));
                        }
                        self.pressed_buttons &= !bit;
                        self.executed_events = self.executed_events.saturating_add(1);
                        self.audit_log.push(AuditRecord::MouseUp {
                            seq,
                            button_bit: bit,
                            x: self.cur_x,
                            y: self.cur_y,
                            ts_ms: now_ms,
                        });
                    }
                }
            }
            MouseKind::Wheel => {
                if let Err(e) = self.sink.wheel(ev.wheel_dx, ev.wheel_dy) {
                    self.release_all("sink_failed");
                    return Err(InputError::SinkFailed(e.to_string()));
                }
                self.executed_events = self.executed_events.saturating_add(1);
                self.audit_log.push(AuditRecord::MouseWheel {
                    seq,
                    dx: ev.wheel_dx,
                    dy: ev.wheel_dy,
                    ts_ms: now_ms,
                });
            }
        }
        Ok(())
    }

    fn apply_key(&mut self, seq: u32, ev: KeyEvent, now_ms: u64) -> Result<(), InputError> {
        let Some(key) = SafeHidKey::from_usb_hid_usage(ev.usb_hid_usage) else {
            self.unsupported_usage_drops = self.unsupported_usage_drops.saturating_add(1);
            self.audit_log.push(AuditRecord::Dropped {
                seq,
                reason: format!("unsupported_usage:{:#x}", ev.usb_hid_usage),
                ts_ms: now_ms,
            });
            return Ok(());
        };

        if ev.down {
            if !self.rate_limiter.try_consume(now_ms) {
                self.rate_limited_drops = self.rate_limited_drops.saturating_add(1);
                self.audit_log.push(AuditRecord::Dropped {
                    seq,
                    reason: "rate_limited".into(),
                    ts_ms: now_ms,
                });
                return Ok(());
            }
            if self.is_dangerous_shortcut(key, ev.modifiers) {
                self.blocked_shortcut_drops = self.blocked_shortcut_drops.saturating_add(1);
                self.audit_log.push(AuditRecord::Dropped {
                    seq,
                    reason: format!("blocked_shortcut:{key:?}"),
                    ts_ms: now_ms,
                });
                return Ok(());
            }
            if !self.pressed_keys.contains(&key) {
                if let Err(e) = self.sink.key_down(key) {
                    self.release_all("sink_failed");
                    return Err(InputError::SinkFailed(e.to_string()));
                }
                self.pressed_keys.insert(key);
                self.executed_events = self.executed_events.saturating_add(1);
                self.audit_log.push(AuditRecord::KeyDown {
                    seq,
                    key,
                    ts_ms: now_ms,
                });
            }
        } else if self.pressed_keys.contains(&key) {
            if let Err(e) = self.sink.key_up(key) {
                self.release_all("sink_failed");
                return Err(InputError::SinkFailed(e.to_string()));
            }
            self.pressed_keys.remove(&key);
            self.executed_events = self.executed_events.saturating_add(1);
            self.audit_log.push(AuditRecord::KeyUp {
                seq,
                key,
                ts_ms: now_ms,
            });
        }
        Ok(())
    }

    /// Writes the audit log as JSONL atomically via a sibling temporary file + rename.
    pub fn flush_audit_jsonl(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        let tmp_name = format!(
            ".{}.tmp.{}",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("audit.jsonl"),
            std::process::id()
        );
        let tmp_path = path.with_file_name(tmp_name);
        {
            let file = File::create(&tmp_path)?;
            let mut writer = BufWriter::new(file);
            for rec in &self.audit_log {
                let line = serde_json::to_string(rec).map_err(std::io::Error::other)?;
                writer.write_all(line.as_bytes())?;
                writer.write_all(b"\n")?;
            }
            writer.flush()?;
        }
        fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

impl<S: HidInputSink> Drop for HidInputExecutor<S> {
    fn drop(&mut self) {
        if self.has_pressed_state() {
            let _ = self.release_all("drop");
        }
    }
}

/// Spawns an independent watchdog OS thread that invokes `release_all("watchdog_timeout")`
/// whenever any key or mouse button remains pressed and Controller activity exceeds
/// `watchdog_timeout`, even if the session async task is stalled or Controller was `SIGKILL`ed.
pub fn spawn_release_watchdog<S: HidInputSink + 'static>(
    executor: Arc<Mutex<HidInputExecutor<S>>>,
    watchdog_timeout: Duration,
    stop: Arc<AtomicBool>,
) -> std::io::Result<JoinHandle<()>> {
    let timeout_ms = watchdog_timeout.as_millis().max(1) as u64;
    let poll_interval = (watchdog_timeout / 4).clamp(Duration::from_millis(10), Duration::from_millis(50));

    thread::Builder::new()
        .name("zd-v2-hid-watchdog".to_string())
        .spawn(move || {
            while !stop.load(Ordering::Acquire) {
                thread::sleep(poll_interval);
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let Ok(mut guard) = executor.lock() else {
                    break;
                };
                if guard.has_pressed_state() {
                    let last = guard.last_activity_ms.load(Ordering::Acquire);
                    let now = now_epoch_ms();
                    if now.saturating_sub(last) >= timeout_ms {
                        let _ = guard.release_all("watchdog_timeout");
                    }
                }
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;
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

        fn release_all_best_effort(&mut self, pressed_buttons: u8, pressed_keys: &[SafeHidKey]) {
            self.release_all_calls.fetch_add(1, Ordering::SeqCst);
            *self.released_buttons_seen.lock().unwrap() |= pressed_buttons;
            self.released_keys_seen
                .lock()
                .unwrap()
                .extend_from_slice(pressed_keys);
            for bit_idx in 0..5u8 {
                let bit = 1u8 << bit_idx;
                if pressed_buttons & bit != 0 {
                    self.ops.push(DryRunOp::MouseUp { button_bit: bit });
                }
            }
            for &k in pressed_keys {
                self.ops.push(DryRunOp::KeyUp { key: k });
            }
        }
    }

    #[test]
    fn whitelist_rejects_unknown_usages_and_keeps_left_right_modifiers_distinct() {
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x04), Some(SafeHidKey::KeyA));
        assert_eq!(
            SafeHidKey::from_usb_hid_usage(0x0007_0004),
            Some(SafeHidKey::KeyA)
        );
        // Non-0x07 usage page must NEVER alias via `& 0xFF`
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x000C_0004), None);
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x0001_0004), None);
        // Unknown usage IDs in page 0x07 must be rejected
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x00), None);
        assert_eq!(SafeHidKey::from_usb_hid_usage(0x66), None); // Power
        assert_eq!(SafeHidKey::from_usb_hid_usage(0xFFFF), None);

        // Left & right modifiers remain distinct
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
                        modifiers: 0,
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
                        modifiers: 0,
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
    fn rejects_out_of_bounds_absolute_coords_and_clamps_relative_only() {
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
                    5,
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
        assert_eq!(exec.pressed_buttons(), 0);
        assert_eq!(exec.cursor_position(), (1279, 719));
        assert_eq!(
            exec.sink().ops,
            vec![
                DryRunOp::MoveAbs { x: 1270, y: 710 },
                DryRunOp::MoveRel { dx: 9, dy: 9 },
            ]
        );
    }

    #[test]
    fn dangerous_kill_session_shortcuts_are_blocked() {
        let mut exec = HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap();
        let now = now_epoch_ms();
        exec.apply_batch(
            &[
                // Ctrl + Alt + Delete
                (
                    1,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: 0xE0,
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
                        usb_hid_usage: 0xE2,
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
                        usb_hid_usage: 0x4C,
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                // Alt + F4 (Alt is already held)
                (
                    4,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: 0,
                        usb_hid_usage: 0x3D,
                        unicode_scalar: 0,
                        client_ts_ms: now,
                    }),
                    now,
                ),
                // Cmd/Meta + Q
                (
                    5,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: MOD_META,
                        usb_hid_usage: 0x14,
                        unicode_scalar: 'q' as u32,
                        client_ts_ms: now,
                    }),
                    now,
                ),
            ],
            now,
        )
        .unwrap();
        assert_eq!(exec.blocked_shortcut_drops, 3);
        assert!(!exec.pressed_keys().contains(&SafeHidKey::Delete));
        assert!(!exec.pressed_keys().contains(&SafeHidKey::F4));
        assert!(!exec.pressed_keys().contains(&SafeHidKey::KeyQ));
    }

    #[test]
    fn randomized_hid_sequence_and_mid_batch_sink_failure_never_leave_stuck_inputs() {
        // Deterministic LCG PRNG for reproducible property testing
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
                            buttons: 1 << ((r % 3) as u8),
                            x_or_dx: (r % 1280) as i32,
                            y_or_dy: ((r >> 10) % 720) as i32,
                            wheel_dx: 0,
                            wheel_dy: 0,
                            client_ts_ms: now,
                        }),
                        3 => HidPayload::Key(KeyEvent {
                            down: true,
                            modifiers: 0,
                            usb_hid_usage: sample_keys[(r as usize) % sample_keys.len()],
                            unicode_scalar: 0,
                            client_ts_ms: now,
                        }),
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
            assert_eq!(exec.pressed_buttons(), 0);
            assert!(exec.pressed_keys().is_empty());
            assert!(exec.audit_log().iter().any(|r| matches!(
                r,
                AuditRecord::ReleaseAll { reason, .. } if reason == "sink_failed"
            )));
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
                            modifiers: 0,
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
    fn batch_size_and_rate_limit_enforced_while_preserving_releases() {
        let mut exec =
            HidInputExecutor::with_options(DryRunSink::new(), 1280, 720, 2, None).unwrap();
        let now = now_epoch_ms();

        // Batch > MAX_HID_BATCH_SIZE fails closed
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

        // Rate limit capacity 2: 2 key downs succeed, 3rd key down dropped, key up still executes!
        exec.apply_batch(
            &[
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
        assert_eq!(exec.rate_limited_drops, 1);
        assert!(!exec.pressed_keys().contains(&SafeHidKey::KeyA));
        assert!(exec.pressed_keys().contains(&SafeHidKey::KeyB));
        assert!(!exec.pressed_keys().contains(&SafeHidKey::KeyC));
    }

    #[test]
    fn watchdog_releases_stuck_keys_and_buttons_after_timeout() {
        let exec = Arc::new(Mutex::new(
            HidInputExecutor::new(DryRunSink::new(), 1280, 720).unwrap(),
        ));
        let stop = Arc::new(AtomicBool::new(false));
        let handle =
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
                            modifiers: 0,
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
                            modifiers: 0,
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
        stop.store(true, Ordering::Release);
        handle.join().unwrap();

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
    }
}
