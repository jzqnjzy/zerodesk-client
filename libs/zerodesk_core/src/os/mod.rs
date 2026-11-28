// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub mod audio;
pub mod capture;
pub mod clipboard;
pub mod dryrun;
pub mod input;
pub mod sck;
pub mod watchdog_proto;
pub mod watchdog_supervisor;

use crate::{
    frame::PixelFormat,
    session::hid::{KeyEvent, MouseEvent},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::{
        mpsc::{self, RecvTimeoutError},
        Arc,
    },
    thread,
    time::Duration,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OsPermission {
    ScreenRecording,
    Accessibility,
    Microphone,
    Clipboard,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsError {
    PermissionDenied(OsPermission),
    NotPermitted,
    CaptureFailed(String),
    AudioUnavailable(String),
    UnsupportedAudioFormat(String),
    ClipboardUnavailable(String),
    UnsupportedPlatform(&'static str),
    InvalidData(String),
    Interlocked,
    Timeout,
}

impl fmt::Display for OsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(p) => write!(f, "OS permission denied: {p:?}"),
            Self::NotPermitted => write!(f, "not_permitted"),
            Self::CaptureFailed(msg) => write!(f, "OS capture failed: {msg}"),
            Self::AudioUnavailable(msg) => write!(f, "OS audio unavailable: {msg}"),
            Self::UnsupportedAudioFormat(msg) => write!(f, "unsupported OS audio format: {msg}"),
            Self::ClipboardUnavailable(msg) => write!(f, "OS clipboard unavailable: {msg}"),
            Self::UnsupportedPlatform(msg) => write!(f, "unsupported platform/feature: {msg}"),
            Self::InvalidData(msg) => write!(f, "invalid OS adapter data: {msg}"),
            Self::Interlocked => {
                write!(f, "OS HID sink is interlocked after emergency key release")
            }
            Self::Timeout => write!(f, "OS adapter probe timed out"),
        }
    }
}

impl std::error::Error for OsError {}

#[derive(Clone)]
pub struct RawCapturedFrame {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: PixelFormat,
    pub data: Vec<u8>,
}

impl fmt::Debug for RawCapturedFrame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RawCapturedFrame")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("stride", &self.stride)
            .field("pixel_format", &self.pixel_format)
            .field("data_len", &self.data.len())
            .finish()
    }
}

pub trait OsScreenCapture: Send {
    fn dimensions(&self) -> (u32, u32);
    fn capture_frame(&mut self) -> Result<RawCapturedFrame, OsError>;
}

/// Pair of screen capture handle plus optional co-hosted system audio capture (e.g. ScreenCaptureKit).
pub type OsCapturePair = (Box<dyn OsScreenCapture>, Option<Box<dyn OsAudioCapture>>);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseReport {
    pub released_keys: usize,
    pub released_buttons: usize,
    pub residual_keys: usize,
    pub residual_buttons: usize,
}

pub trait EmergencyKeyReleaser: Send + Sync {
    fn release_all_keys(&self) -> ReleaseReport;
}

pub trait OsHidSink: Send {
    fn send_key(&mut self, ev: &KeyEvent) -> Result<(), OsError>;
    fn send_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError>;
    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser>;
}

pub trait OsAudioCapture: Send {
    fn read_frame(&mut self, out_pcm: &mut [f32]) -> Result<bool, OsError>;
    fn dropped_frames(&self) -> u64 {
        0
    }
    fn has_stream_error(&self) -> bool {
        false
    }
}

pub trait OsAudioPlayback: Send {
    /// Returns `Ok(true)` if the entire frame was queued, or `Ok(false)` if dropped cleanly.
    fn write_frame(&mut self, pcm: &[f32]) -> Result<bool, OsError>;
    fn dropped_frames(&self) -> u64 {
        0
    }
    fn has_stream_error(&self) -> bool {
        false
    }
}

pub trait OsClipboardBackend: Send {
    fn read_change_count(&mut self) -> Option<i64>;
    fn read_text(&mut self) -> Result<Option<String>, OsError>;
    fn write_text(&mut self, text: &str) -> Result<(), OsError>;
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeOutcome {
    pub status: String,
    pub granted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Strictly redacted, zero-write OS capability preflight report.
/// NEVER includes hostname, username, device serial number, or clipboard contents.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsSelftestReport {
    pub schema_version: u32,
    pub platform: String,
    pub zero_writes_enforced: bool,
    pub real_input_compiled_in: bool,
    pub screen_recording: ProbeOutcome,
    pub accessibility: ProbeOutcome,
    pub secure_event_input_enabled: Option<bool>,
    pub audio: audio::AudioDeviceProbe,
    pub clipboard_readonly_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BoundedProbeResult<T> {
    Ok(T),
    Timeout,
    Panicked,
}

fn run_bounded_probe<T: Send + 'static>(
    name: &str,
    timeout: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> BoundedProbeResult<T> {
    let (tx, rx) = mpsc::channel();
    let spawn_res = thread::Builder::new()
        .name(format!("zd-probe-{name}"))
        .spawn(move || {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            if let Ok(v) = res {
                let _ = tx.send(v);
            }
        });
    if spawn_res.is_err() {
        return BoundedProbeResult::Panicked;
    }
    match rx.recv_timeout(timeout) {
        Ok(v) => BoundedProbeResult::Ok(v),
        Err(RecvTimeoutError::Timeout) => BoundedProbeResult::Timeout,
        Err(RecvTimeoutError::Disconnected) => BoundedProbeResult::Panicked,
    }
}

/// Runs a strictly zero-write OS capability preflight (never writes clipboard, never injects HID,
/// never writes files, never pops interactive permission dialogs, bounded <= 2s per probe).
pub fn os_selftest() -> OsSelftestReport {
    let timeout = Duration::from_secs(2);

    let screen_recording = match run_bounded_probe("screen", timeout, || {
        match capture::preflight_screen_capture_permission() {
            Ok(true) => ProbeOutcome {
                status: "granted".into(),
                granted: true,
                note: None,
            },
            Ok(false) => ProbeOutcome {
                status: "denied".into(),
                granted: false,
                note: Some(
                    "Screen Recording permission not granted (non-interactive preflight)".into(),
                ),
            },
            Err(e) => ProbeOutcome {
                status: "unsupported".into(),
                granted: false,
                note: Some(e.to_string()),
            },
        }
    }) {
        BoundedProbeResult::Ok(o) => o,
        BoundedProbeResult::Timeout => ProbeOutcome {
            status: "timeout".into(),
            granted: false,
            note: Some("screen permission probe timed out".into()),
        },
        BoundedProbeResult::Panicked => ProbeOutcome {
            status: "panic".into(),
            granted: false,
            note: Some("screen permission probe panicked".into()),
        },
    };

    let accessibility = match run_bounded_probe("ax", timeout, || {
        let trusted = input::is_accessibility_trusted();
        ProbeOutcome {
            status: if trusted { "granted" } else { "denied" }.into(),
            granted: trusted,
            note: if trusted {
                None
            } else {
                Some("Accessibility trust not granted; dry-run HID sink remains available".into())
            },
        }
    }) {
        BoundedProbeResult::Ok(o) => o,
        BoundedProbeResult::Timeout => ProbeOutcome {
            status: "timeout".into(),
            granted: false,
            note: Some("accessibility probe timed out".into()),
        },
        BoundedProbeResult::Panicked => ProbeOutcome {
            status: "panic".into(),
            granted: false,
            note: Some("accessibility probe panicked".into()),
        },
    };

    let secure_event_input_enabled =
        match run_bounded_probe("secure-input", timeout, input::is_secure_event_input_enabled) {
            BoundedProbeResult::Ok(v) => Some(v),
            BoundedProbeResult::Timeout | BoundedProbeResult::Panicked => None,
        };

    let audio = match run_bounded_probe("audio", timeout, audio::probe_audio_devices) {
        BoundedProbeResult::Ok(p) => p,
        BoundedProbeResult::Timeout => audio::AudioDeviceProbe {
            available: false,
            input_device_count: 0,
            output_device_count: 0,
            note: Some("audio device probe timed out".into()),
        },
        BoundedProbeResult::Panicked => audio::AudioDeviceProbe {
            available: false,
            input_device_count: 0,
            output_device_count: 0,
            note: Some("audio device probe panicked".into()),
        },
    };

    let clipboard_readonly_available =
        match run_bounded_probe("clipboard", timeout, clipboard::probe_clipboard_readonly) {
            BoundedProbeResult::Ok(v) => v,
            BoundedProbeResult::Timeout | BoundedProbeResult::Panicked => false,
        };

    OsSelftestReport {
        schema_version: 1,
        platform: std::env::consts::OS.to_string(),
        zero_writes_enforced: true,
        real_input_compiled_in: input::real_input_compiled_in(),
        screen_recording,
        accessibility,
        secure_event_input_enabled,
        audio,
        clipboard_readonly_available,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_selftest_is_redacted_and_zero_write() {
        let report = os_selftest();
        assert_eq!(report.schema_version, 1);
        assert!(report.zero_writes_enforced);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("hostname"));
        assert!(!json.contains("username"));
        assert!(!json.contains("serial"));
        assert!(!json.contains("clipboard_text"));
    }

    #[test]
    fn bounded_probe_distinguishes_panic_from_timeout() {
        let panicked: BoundedProbeResult<()> =
            run_bounded_probe("panic-test", Duration::from_secs(1), || {
                panic!("simulated probe panic");
            });
        assert_eq!(panicked, BoundedProbeResult::Panicked);

        let timed_out: BoundedProbeResult<()> =
            run_bounded_probe("timeout-test", Duration::from_millis(20), || {
                thread::sleep(Duration::from_millis(200));
            });
        assert_eq!(timed_out, BoundedProbeResult::Timeout);
    }

    #[test]
    fn raw_captured_frame_debug_redacts_pixel_bytes() {
        let frame = RawCapturedFrame {
            width: 4,
            height: 4,
            stride: 16,
            pixel_format: PixelFormat::Bgra8,
            data: vec![0xDE; 64],
        };
        let dbg = format!("{frame:?}");
        assert!(dbg.contains("data_len: 64"));
        assert!(!dbg.contains("222, 222"));
    }
}
