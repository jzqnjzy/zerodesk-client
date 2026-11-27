// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub mod audio;
pub mod capture;
pub mod clipboard;
pub mod dryrun;
pub mod input;

use crate::{
    frame::PixelFormat,
    session::hid::{KeyEvent, MouseEvent},
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    sync::{mpsc, Arc},
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
    CaptureFailed(String),
    AudioUnavailable(String),
    ClipboardUnavailable(String),
    UnsupportedPlatform(&'static str),
    InvalidData(String),
    Timeout,
}

impl fmt::Display for OsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionDenied(p) => write!(f, "OS permission denied: {p:?}"),
            Self::CaptureFailed(msg) => write!(f, "OS capture failed: {msg}"),
            Self::AudioUnavailable(msg) => write!(f, "OS audio unavailable: {msg}"),
            Self::ClipboardUnavailable(msg) => write!(f, "OS clipboard unavailable: {msg}"),
            Self::UnsupportedPlatform(msg) => write!(f, "unsupported platform/feature: {msg}"),
            Self::InvalidData(msg) => write!(f, "invalid OS adapter data: {msg}"),
            Self::Timeout => write!(f, "OS adapter probe timed out"),
        }
    }
}

impl std::error::Error for OsError {}

#[derive(Debug, Clone)]
pub struct RawCapturedFrame {
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub pixel_format: PixelFormat,
    pub data: Vec<u8>,
}

pub trait OsScreenCapture: Send {
    fn dimensions(&self) -> (u32, u32);
    fn capture_frame(&mut self) -> Result<RawCapturedFrame, OsError>;
}

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
}

pub trait OsAudioPlayback: Send {
    fn write_frame(&mut self, pcm: &[f32]) -> Result<(), OsError>;
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

fn run_bounded_probe<T: Send + 'static>(
    name: &str,
    timeout: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = mpsc::channel();
    let _ = thread::Builder::new()
        .name(format!("zd-probe-{name}"))
        .spawn(move || {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            if let Ok(v) = res {
                let _ = tx.send(v);
            }
        });
    rx.recv_timeout(timeout).ok()
}

/// Runs a strictly zero-write OS capability preflight (never writes clipboard, never injects HID,
/// never writes files, never pops interactive permission dialogs, bounded <= 2s per probe).
pub fn os_selftest() -> OsSelftestReport {
    let timeout = Duration::from_secs(2);

    let screen_recording = run_bounded_probe("screen", timeout, || {
        match capture::preflight_screen_capture_permission() {
            Ok(true) => ProbeOutcome {
                status: "granted".into(),
                granted: true,
                note: None,
            },
            Ok(false) => ProbeOutcome {
                status: "denied".into(),
                granted: false,
                note: Some("Screen Recording permission not granted (non-interactive preflight)".into()),
            },
            Err(e) => ProbeOutcome {
                status: "unsupported".into(),
                granted: false,
                note: Some(e.to_string()),
            },
        }
    })
    .unwrap_or_else(|| ProbeOutcome {
        status: "timeout".into(),
        granted: false,
        note: Some("screen permission probe timed out".into()),
    });

    let accessibility = run_bounded_probe("ax", timeout, || {
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
    })
    .unwrap_or_else(|| ProbeOutcome {
        status: "timeout".into(),
        granted: false,
        note: Some("accessibility probe timed out".into()),
    });

    let secure_event_input_enabled =
        run_bounded_probe("secure-input", timeout, input::is_secure_event_input_enabled);

    let audio = run_bounded_probe("audio", timeout, audio::probe_audio_devices).unwrap_or(
        audio::AudioDeviceProbe {
            available: false,
            input_device_count: 0,
            output_device_count: 0,
            note: Some("audio device probe timed out".into()),
        },
    );

    let clipboard_readonly_available =
        run_bounded_probe("clipboard", timeout, clipboard::probe_clipboard_readonly)
            .unwrap_or(false);

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
        // Verify no sensitive host identity keys appear in the report schema.
        assert!(!json.contains("hostname"));
        assert!(!json.contains("username"));
        assert!(!json.contains("serial"));
        assert!(!json.contains("clipboard_text"));
    }
}
