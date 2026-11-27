// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    EmergencyKeyReleaser, OsAudioCapture, OsAudioPlayback, OsClipboardBackend, OsError, OsHidSink,
    OsScreenCapture, RawCapturedFrame, ReleaseReport,
};
use crate::{
    frame::PixelFormat,
    session::{
        capture::bgra_to_i420_bt601,
        hid::{KeyEvent, MouseEvent, MouseKind},
        video::{generate_animated_i420, I420Frame},
    },
};
use scrap::I420ToARGB;
use std::{
    collections::BTreeSet,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
    time::{SystemTime, UNIX_EPOCH},
};

fn now_epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Deterministic moving test-pattern screen source (zero OS permissions required).
pub struct SyntheticScreenSource {
    width: u32,
    height: u32,
    frame_idx: u32,
}

impl SyntheticScreenSource {
    pub fn new(width: u32, height: u32) -> Self {
        Self {
            width: (width & !1).max(32),
            height: (height & !1).max(32),
            frame_idx: 0,
        }
    }

    pub fn next_i420(&mut self) -> I420Frame {
        let frame = generate_animated_i420(self.width as usize, self.height as usize, self.frame_idx);
        self.frame_idx = self.frame_idx.wrapping_add(1);
        frame
    }
}

impl OsScreenCapture for SyntheticScreenSource {
    fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    fn capture_frame(&mut self) -> Result<RawCapturedFrame, OsError> {
        let i420 = self.next_i420();
        let stride = self.width * 4;
        let mut bgra = vec![0u8; (stride as usize) * (self.height as usize)];
        let uv_w = (self.width / 2) as i32;
        let rc = unsafe {
            I420ToARGB(
                i420.y.as_ptr(),
                self.width as i32,
                i420.u.as_ptr(),
                uv_w,
                i420.v.as_ptr(),
                uv_w,
                bgra.as_mut_ptr(),
                stride as i32,
                self.width as i32,
                self.height as i32,
            )
        };
        if rc != 0 {
            return Err(OsError::CaptureFailed(format!(
                "synthetic I420ToARGB failed: {rc}"
            )));
        }
        Ok(RawCapturedFrame {
            width: self.width,
            height: self.height,
            stride,
            pixel_format: PixelFormat::Bgra8,
            data: bgra,
        })
    }
}

/// Helper to convert a `RawCapturedFrame` (BGRA8/RGBA8) into `I420Frame`.
pub fn raw_captured_to_i420(frame: &RawCapturedFrame) -> Result<I420Frame, OsError> {
    bgra_to_i420_bt601(
        &frame.data,
        frame.stride as usize,
        frame.width as usize,
        frame.height as usize,
    )
    .map_err(|e| OsError::CaptureFailed(e.to_string()))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRunHidJournalEntry {
    pub kind: String,
    pub key_usage: Option<u16>,
    pub buttons: u8,
    pub pressed_keys_snapshot: Vec<u16>,
    pub timestamp_ms: u64,
}

#[derive(Debug, Default)]
struct DryRunPressedState {
    keys: BTreeSet<u16>,
    buttons: u8,
}

#[derive(Clone, Default)]
pub struct DryRunHidJournal {
    entries: Arc<Mutex<Vec<DryRunHidJournalEntry>>>,
    pressed: Arc<Mutex<DryRunPressedState>>,
}

impl DryRunHidJournal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> Vec<DryRunHidJournalEntry> {
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn pressed_keys(&self) -> Vec<u16> {
        self.pressed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys
            .iter()
            .copied()
            .collect()
    }

    pub fn pressed_buttons(&self) -> u8 {
        self.pressed
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .buttons
    }

    pub fn is_all_released(&self) -> bool {
        let g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
        g.keys.is_empty() && g.buttons == 0
    }

    pub fn record_key_public(&self, ev: &KeyEvent) {
        self.record_key(ev);
    }

    pub fn record_mouse_public(&self, ev: &MouseEvent) {
        self.record_mouse(ev);
    }

    pub fn emergency_release_all(&self) -> ReleaseReport {
        let releaser = DryRunEmergencyKeyReleaser {
            journal: self.clone(),
        };
        releaser.release_all_keys()
    }

    fn record_key(&self, ev: &KeyEvent) {
        let usage = (ev.usb_hid_usage & 0xFFFF) as u16;
        let (buttons, snapshot) = {
            let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
            if ev.down {
                g.keys.insert(usage);
            } else {
                g.keys.remove(&usage);
            }
            (g.buttons, g.keys.iter().copied().collect::<Vec<_>>())
        };
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(DryRunHidJournalEntry {
                kind: if ev.down {
                    "key_down".into()
                } else {
                    "key_up".into()
                },
                key_usage: Some(usage),
                buttons,
                pressed_keys_snapshot: snapshot,
                timestamp_ms: now_epoch_ms(),
            });
    }

    fn record_mouse(&self, ev: &MouseEvent) {
        let (buttons, snapshot) = {
            let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
            match ev.kind {
                MouseKind::Down => g.buttons |= ev.buttons,
                MouseKind::Up => g.buttons &= !ev.buttons,
                MouseKind::MoveAbs | MouseKind::MoveRel => g.buttons = ev.buttons,
                MouseKind::Wheel => {}
            }
            (g.buttons, g.keys.iter().copied().collect::<Vec<_>>())
        };
        self.entries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(DryRunHidJournalEntry {
                kind: format!("mouse_{:?}", ev.kind).to_ascii_lowercase(),
                key_usage: None,
                buttons,
                pressed_keys_snapshot: snapshot,
                timestamp_ms: now_epoch_ms(),
            });
    }
}

/// Independent stateless emergency releaser for `DryRunHidSink`.
/// Reads the pressed-key set under a tiny lock, drops the lock immediately, and appends
/// synthetic release entries without borrowing `DryRunHidSink`.
#[derive(Clone)]
pub struct DryRunEmergencyKeyReleaser {
    journal: DryRunHidJournal,
}

impl EmergencyKeyReleaser for DryRunEmergencyKeyReleaser {
    fn release_all_keys(&self) -> ReleaseReport {
        let (keys_to_release, buttons_to_release) = {
            let mut g = self
                .journal
                .pressed
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let keys: Vec<u16> = g.keys.iter().copied().collect();
            let buttons = g.buttons;
            g.keys.clear();
            g.buttons = 0;
            (keys, buttons)
        };
        let ts = now_epoch_ms();
        let mut released_keys = 0usize;
        let mut released_buttons = 0usize;
        {
            let mut log = self
                .journal
                .entries
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            for usage in &keys_to_release {
                released_keys += 1;
                log.push(DryRunHidJournalEntry {
                    kind: "emergency_key_up".into(),
                    key_usage: Some(*usage),
                    buttons: 0,
                    pressed_keys_snapshot: Vec::new(),
                    timestamp_ms: ts,
                });
            }
            if buttons_to_release != 0 {
                released_buttons = buttons_to_release.count_ones() as usize;
                log.push(DryRunHidJournalEntry {
                    kind: "emergency_mouse_up".into(),
                    key_usage: None,
                    buttons: 0,
                    pressed_keys_snapshot: Vec::new(),
                    timestamp_ms: ts,
                });
            }
        }
        ReleaseReport {
            released_keys,
            released_buttons,
            residual_keys: 0,
            residual_buttons: 0,
        }
    }
}

/// Zero-OS-injection HID sink with full journal + independent `EmergencyKeyReleaser`.
#[derive(Clone, Default)]
pub struct DryRunHidSink {
    journal: DryRunHidJournal,
}

impl DryRunHidSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn journal(&self) -> &DryRunHidJournal {
        &self.journal
    }
}

impl OsHidSink for DryRunHidSink {
    fn send_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
        self.journal.record_key(ev);
        Ok(())
    }

    fn send_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError> {
        self.journal.record_mouse(ev);
        Ok(())
    }

    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
        Arc::new(DryRunEmergencyKeyReleaser {
            journal: self.journal.clone(),
        })
    }
}

/// Silent audio capture (returns zeroed 48kHz/2ch/20ms frames).
#[derive(Debug, Default)]
pub struct SilentAudioCapture;

impl OsAudioCapture for SilentAudioCapture {
    fn read_frame(&mut self, out_pcm: &mut [f32]) -> Result<bool, OsError> {
        out_pcm.fill(0.0);
        Ok(true)
    }
}

/// Silent audio playback sink (discards PCM frames without touching OS audio devices).
#[derive(Debug, Default)]
pub struct SilentAudioPlayback {
    pub frames_played: u64,
}

impl OsAudioPlayback for SilentAudioPlayback {
    fn write_frame(&mut self, _pcm: &[f32]) -> Result<(), OsError> {
        self.frames_played = self.frames_played.saturating_add(1);
        Ok(())
    }
}

/// Pure in-memory clipboard backend with simulated `change_count` (never touches OS clipboard).
#[derive(Clone, Default)]
pub struct MemoryClipboardBackend {
    text: Arc<Mutex<Option<String>>>,
    change_count: Arc<AtomicI64>,
}

impl MemoryClipboardBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_local_text(&self, text: impl Into<String>) {
        *self.text.lock().unwrap_or_else(|e| e.into_inner()) = Some(text.into());
        self.change_count.fetch_add(1, Ordering::AcqRel);
    }

    pub fn current_text(&self) -> Option<String> {
        self.text.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl OsClipboardBackend for MemoryClipboardBackend {
    fn read_change_count(&mut self) -> Option<i64> {
        Some(self.change_count.load(Ordering::Acquire))
    }

    fn read_text(&mut self) -> Result<Option<String>, OsError> {
        Ok(self.text.lock().unwrap_or_else(|e| e.into_inner()).clone())
    }

    fn write_text(&mut self, text: &str) -> Result<(), OsError> {
        *self.text.lock().unwrap_or_else(|e| e.into_inner()) = Some(text.to_string());
        self.change_count.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }
}
