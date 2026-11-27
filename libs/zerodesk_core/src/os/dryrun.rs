// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    EmergencyKeyReleaser, OsAudioCapture, OsAudioPlayback, OsClipboardBackend, OsError, OsHidSink,
    OsScreenCapture, RawCapturedFrame, ReleaseReport,
};
use crate::{
    frame::PixelFormat,
    os::audio::OS_AUDIO_FRAME_SAMPLES,
    session::{
        hid::{KeyEvent, MouseEvent, MouseKind},
        video::{generate_animated_i420, I420Frame},
    },
};
use scrap::I420ToARGB;
use std::{
    collections::{BTreeSet, VecDeque},
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_JOURNAL_ENTRIES: usize = 10_000;

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
        let frame =
            generate_animated_i420(self.width as usize, self.height as usize, self.frame_idx);
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

/// Converts a `RawCapturedFrame` (BGRA8 or RGBA8) into `I420Frame` with full bounds & stride validation.
pub fn raw_captured_to_i420(frame: &RawCapturedFrame) -> Result<I420Frame, OsError> {
    super::capture::convert_captured_stride_to_i420(frame)
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
struct DryRunJournalState {
    entries: VecDeque<DryRunHidJournalEntry>,
    dropped_entries: u64,
    keys: BTreeSet<u16>,
    buttons: u8,
    interlocked: bool,
}

impl DryRunJournalState {
    fn push_entry(&mut self, entry: DryRunHidJournalEntry) {
        if self.entries.len() >= MAX_JOURNAL_ENTRIES {
            self.entries.pop_front();
            self.dropped_entries = self.dropped_entries.saturating_add(1);
        }
        self.entries.push_back(entry);
    }
}

/// Thread-safe, bounded HID journal storing pressed-key state and recorded events under ONE mutex
/// so emergency releases and in-flight events are strictly ordered and atomic.
#[derive(Clone, Default)]
pub struct DryRunHidJournal {
    state: Arc<Mutex<DryRunJournalState>>,
}

impl DryRunHidJournal {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn entries(&self) -> Vec<DryRunHidJournalEntry> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entries
            .iter()
            .cloned()
            .collect()
    }

    pub fn dropped_entries(&self) -> u64 {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .dropped_entries
    }

    pub fn pressed_keys(&self) -> Vec<u16> {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys
            .iter()
            .copied()
            .collect()
    }

    pub fn pressed_buttons(&self) -> u8 {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .buttons
    }

    pub fn is_all_released(&self) -> bool {
        let g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        g.keys.is_empty() && g.buttons == 0
    }

    pub fn is_interlocked(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .interlocked
    }

    /// Resumes acceptance of new dry-run HID events for a fresh session after emergency release.
    pub fn resume_for_new_session(&self) {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        g.interlocked = false;
    }

    fn record_key(&self, ev: &KeyEvent) -> Result<(), OsError> {
        let Ok(usage) = u16::try_from(ev.usb_hid_usage) else {
            return Err(OsError::InvalidData(format!(
                "USB HID usage {:#x} exceeds u16 range",
                ev.usb_hid_usage
            )));
        };
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if g.interlocked {
            return Err(OsError::Interlocked);
        }
        if ev.down {
            g.keys.insert(usage);
        } else {
            g.keys.remove(&usage);
        }
        let buttons = g.buttons;
        let snapshot: Vec<u16> = g.keys.iter().copied().collect();
        g.push_entry(DryRunHidJournalEntry {
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
        Ok(())
    }

    fn record_mouse(&self, ev: &MouseEvent) -> Result<(), OsError> {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if g.interlocked {
            return Err(OsError::Interlocked);
        }
        let masked_buttons = ev.buttons & 0x1F;
        match ev.kind {
            MouseKind::Down => g.buttons |= masked_buttons,
            MouseKind::Up => g.buttons &= !masked_buttons,
            MouseKind::MoveAbs | MouseKind::MoveRel => g.buttons = masked_buttons,
            MouseKind::Wheel => {}
        }
        let buttons = g.buttons;
        let snapshot: Vec<u16> = g.keys.iter().copied().collect();
        g.push_entry(DryRunHidJournalEntry {
            kind: format!("mouse_{:?}", ev.kind).to_ascii_lowercase(),
            key_usage: None,
            buttons,
            pressed_keys_snapshot: snapshot,
            timestamp_ms: now_epoch_ms(),
        });
        Ok(())
    }

    pub fn emergency_release_all(&self) -> ReleaseReport {
        let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
        g.interlocked = true;
        let keys_to_release: Vec<u16> = g.keys.iter().copied().collect();
        let buttons_to_release = g.buttons;
        g.keys.clear();
        g.buttons = 0;

        let ts = now_epoch_ms();
        let mut released_keys = 0usize;
        let mut released_buttons = 0usize;
        for usage in &keys_to_release {
            released_keys += 1;
            g.push_entry(DryRunHidJournalEntry {
                kind: "emergency_key_up".into(),
                key_usage: Some(*usage),
                buttons: 0,
                pressed_keys_snapshot: Vec::new(),
                timestamp_ms: ts,
            });
        }
        if buttons_to_release != 0 {
            released_buttons = buttons_to_release.count_ones() as usize;
            g.push_entry(DryRunHidJournalEntry {
                kind: "emergency_mouse_up".into(),
                key_usage: None,
                buttons: 0,
                pressed_keys_snapshot: Vec::new(),
                timestamp_ms: ts,
            });
        }
        ReleaseReport {
            released_keys,
            released_buttons,
            residual_keys: 0,
            residual_buttons: 0,
        }
    }
}

/// Independent stateless emergency releaser for `DryRunHidSink`.
#[derive(Clone)]
pub struct DryRunEmergencyKeyReleaser {
    journal: DryRunHidJournal,
}

impl EmergencyKeyReleaser for DryRunEmergencyKeyReleaser {
    fn release_all_keys(&self) -> ReleaseReport {
        self.journal.emergency_release_all()
    }
}

/// Zero-OS-injection HID sink with bounded journal + independent `EmergencyKeyReleaser`.
#[derive(Clone, Default)]
pub struct DryRunHidSink {
    journal: DryRunHidJournal,
}

impl DryRunHidSink {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_journal(journal: DryRunHidJournal) -> Self {
        journal.resume_for_new_session();
        Self { journal }
    }

    pub fn journal(&self) -> &DryRunHidJournal {
        &self.journal
    }
}

impl OsHidSink for DryRunHidSink {
    fn send_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
        self.journal.record_key(ev)
    }

    fn send_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError> {
        self.journal.record_mouse(ev)
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
        if out_pcm.len() != OS_AUDIO_FRAME_SAMPLES {
            return Err(OsError::InvalidData(format!(
                "expected {OS_AUDIO_FRAME_SAMPLES} PCM samples, got {}",
                out_pcm.len()
            )));
        }
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
    fn write_frame(&mut self, pcm: &[f32]) -> Result<bool, OsError> {
        if pcm.len() != OS_AUDIO_FRAME_SAMPLES {
            return Err(OsError::InvalidData(format!(
                "expected {OS_AUDIO_FRAME_SAMPLES} PCM samples, got {}",
                pcm.len()
            )));
        }
        self.frames_played = self.frames_played.saturating_add(1);
        Ok(true)
    }
}

#[derive(Debug, Default)]
struct MemoryClipboardInner {
    text: Option<String>,
    change_count: i64,
}

/// Pure in-memory clipboard backend with atomic `(text, change_count)` updates
/// (never touches OS clipboard).
#[derive(Clone, Default)]
pub struct MemoryClipboardBackend {
    inner: Arc<Mutex<MemoryClipboardInner>>,
}

impl MemoryClipboardBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_local_text(&self, text: impl Into<String>) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.text = Some(text.into());
        g.change_count = g.change_count.saturating_add(1);
    }

    pub fn current_text(&self) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .text
            .clone()
    }

    /// Zeroizes and clears stored clipboard text on shutdown.
    pub fn clear(&self) {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(mut s) = g.text.take() {
            // SAFETY: wiping bytes to 0 produces valid UTF-8 NUL bytes before drop.
            for b in unsafe { s.as_bytes_mut() } {
                unsafe { std::ptr::write_volatile(b, 0) };
            }
        }
    }
}

impl OsClipboardBackend for MemoryClipboardBackend {
    fn read_change_count(&mut self) -> Option<i64> {
        Some(
            self.inner
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .change_count,
        )
    }

    fn read_text(&mut self) -> Result<Option<String>, OsError> {
        Ok(self
            .inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .text
            .clone())
    }

    fn write_text(&mut self, text: &str) -> Result<(), OsError> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.text = Some(text.to_string());
        g.change_count = g.change_count.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dryrun_journal_is_bounded_and_interlocked_after_emergency_release() {
        let mut sink = DryRunHidSink::new();
        let releaser = sink.emergency_releaser();
        for i in 0..(MAX_JOURNAL_ENTRIES + 50) {
            sink.send_key(&KeyEvent {
                down: i % 2 == 0,
                modifiers: 0,
                usb_hid_usage: 0x04,
                unicode_scalar: 0,
                client_ts_ms: i as u64,
            })
            .unwrap();
        }
        assert_eq!(sink.journal().entries().len(), MAX_JOURNAL_ENTRIES);
        assert_eq!(sink.journal().dropped_entries(), 50);

        // Out-of-u16 usage MUST fail closed (never masked to valid usage!)
        assert!(sink
            .send_key(&KeyEvent {
                down: true,
                modifiers: 0,
                usb_hid_usage: 0x0001_0004,
                unicode_scalar: 0,
                client_ts_ms: 999,
            })
            .is_err());

        let _ = releaser.release_all_keys();
        assert!(sink.journal().is_interlocked());
        assert_eq!(
            sink.send_key(&KeyEvent {
                down: true,
                modifiers: 0,
                usb_hid_usage: 0x04,
                unicode_scalar: 0,
                client_ts_ms: 1000,
            }),
            Err(OsError::Interlocked)
        );
    }
}
