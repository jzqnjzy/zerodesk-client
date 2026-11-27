// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{OsClipboardBackend, OsError};
use crate::session::clipboard::{validate_png_ihdr, CLIP_HARD_MAX_BYTES};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

/// Validates raw PNG clipboard bytes WITHOUT decoding pixels:
/// checks 8-byte PNG signature, IHDR width/height caps, and `CLIP_HARD_MAX_BYTES`.
pub fn validate_clipboard_png_bytes(bytes: &[u8]) -> Result<(u32, u32), OsError> {
    if bytes.is_empty() || bytes.len() > CLIP_HARD_MAX_BYTES as usize {
        return Err(OsError::InvalidData(format!(
            "PNG clipboard payload size {} outside 1..={CLIP_HARD_MAX_BYTES}",
            bytes.len()
        )));
    }
    validate_png_ihdr(bytes).map_err(|e| OsError::InvalidData(e.to_string()))
}

/// One-shot anti-echo suppression guard supporting `A -> B -> A` re-copy.
/// When remote clipboard content `H` is written locally, `arm(H)` records it ONCE.
/// The next local observation matching `H` is suppressed AND immediately clears the guard,
/// so a subsequent user copy of `A` after `B` transmits normally!
#[derive(Debug, Default)]
pub struct OneShotAntiEcho {
    suppressed_sha256: Option<[u8; 32]>,
}

impl OneShotAntiEcho {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn arm(&mut self, sha256: [u8; 32]) {
        self.suppressed_sha256 = Some(sha256);
    }

    /// Returns `true` if `sha256` matches the pending one-shot remote echo (and consumes it).
    pub fn check_and_consume(&mut self, sha256: [u8; 32]) -> bool {
        if self.suppressed_sha256 == Some(sha256) {
            self.suppressed_sha256 = None;
            true
        } else {
            false
        }
    }

    pub fn clear(&mut self) {
        self.suppressed_sha256 = None;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutboundClipboardItem {
    pub text: String,
    pub sha256: [u8; 32],
}

/// Single-threaded clipboard poller owning the sole `OsClipboardBackend` instance.
/// Uses SHA-256 primary dedup + optional OS `change_count` pre-filter + one-shot anti-echo
/// (`A -> B -> A`) + live `allow_clipboard` policy gate that purges pending outbound items when disabled.
pub struct ClipboardPoller {
    backend: Box<dyn OsClipboardBackend>,
    allow_clipboard: Arc<AtomicBool>,
    last_change_count: Option<i64>,
    last_seen_sha256: Option<[u8; 32]>,
    anti_echo: OneShotAntiEcho,
    outbound_queue: Arc<Mutex<VecDeque<OutboundClipboardItem>>>,
    max_queue_len: usize,
}

impl ClipboardPoller {
    pub fn new(backend: Box<dyn OsClipboardBackend>, allow_clipboard: Arc<AtomicBool>) -> Self {
        Self {
            backend,
            allow_clipboard,
            last_change_count: None,
            last_seen_sha256: None,
            anti_echo: OneShotAntiEcho::new(),
            outbound_queue: Arc::new(Mutex::new(VecDeque::new())),
            max_queue_len: 16,
        }
    }

    pub fn outbound_queue_handle(&self) -> Arc<Mutex<VecDeque<OutboundClipboardItem>>> {
        Arc::clone(&self.outbound_queue)
    }

    /// Applies remote clipboard text locally and arms one-shot anti-echo suppression.
    pub fn apply_remote_text(&mut self, text: &str) -> Result<(), OsError> {
        if !self.allow_clipboard.load(Ordering::Acquire) {
            self.clear_outbound_queue();
            return Ok(());
        }
        let hash: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        self.anti_echo.arm(hash);
        self.backend.write_text(text)?;
        // Sync pre-filter state without suppressing subsequent distinct user copies.
        self.last_seen_sha256 = Some(hash);
        Ok(())
    }

    /// Runs a single poll tick on the owning thread.
    /// Returns `Ok(Some(item))` if a new user-initiated clipboard change should be sent to the peer.
    pub fn poll_once(&mut self) -> Result<Option<OutboundClipboardItem>, OsError> {
        if !self.allow_clipboard.load(Ordering::Acquire) {
            self.clear_outbound_queue();
            return Ok(None);
        }

        // Cheap OS change_count pre-filter (e.g. macOS NSPasteboard changeCount).
        if let Some(cc) = self.backend.read_change_count() {
            if self.last_change_count == Some(cc) {
                return Ok(None);
            }
            self.last_change_count = Some(cc);
        }

        let Some(text) = self.backend.read_text()? else {
            return Ok(None);
        };
        if text.is_empty() || text.len() > CLIP_HARD_MAX_BYTES as usize {
            return Ok(None);
        }

        let hash: [u8; 32] = Sha256::digest(text.as_bytes()).into();

        // One-shot anti-echo check FIRST so remote write does not bounce back.
        if self.anti_echo.check_and_consume(hash) {
            self.last_seen_sha256 = Some(hash);
            return Ok(None);
        }

        // Primary SHA-256 deduplication against last seen content.
        if self.last_seen_sha256 == Some(hash) {
            return Ok(None);
        }
        self.last_seen_sha256 = Some(hash);

        let item = OutboundClipboardItem { text, sha256: hash };
        {
            let mut q = self.outbound_queue.lock().unwrap_or_else(|e| e.into_inner());
            while q.len() >= self.max_queue_len {
                q.pop_front();
            }
            q.push_back(item.clone());
        }
        Ok(Some(item))
    }

    pub fn clear_outbound_queue(&self) {
        self.outbound_queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }
}

/// Read-only macOS `NSPasteboard.generalPasteboard.changeCount` probe (NEVER reads clipboard text
/// or writes to clipboard).
#[cfg(target_os = "macos")]
pub fn macos_pasteboard_change_count_readonly() -> Option<i64> {
    use std::ffi::{c_char, c_void};

    #[link(name = "objc")]
    extern "C" {
        fn objc_getClass(name: *const c_char) -> *const c_void;
        fn sel_registerName(name: *const c_char) -> *const c_void;
        fn objc_msgSend();
    }

    unsafe {
        let cls = objc_getClass(c"NSPasteboard".as_ptr());
        if cls.is_null() {
            return None;
        }
        let sel_general = sel_registerName(c"generalPasteboard".as_ptr());
        let sel_change_count = sel_registerName(c"changeCount".as_ptr());
        let msg_get_pb: extern "C" fn(*const c_void, *const c_void) -> *const c_void =
            std::mem::transmute(objc_msgSend as *const ());
        let pb = msg_get_pb(cls, sel_general);
        if pb.is_null() {
            return None;
        }
        let msg_change_count: extern "C" fn(*const c_void, *const c_void) -> isize =
            std::mem::transmute(objc_msgSend as *const ());
        Some(msg_change_count(pb, sel_change_count) as i64)
    }
}

#[cfg(not(target_os = "macos"))]
pub fn macos_pasteboard_change_count_readonly() -> Option<i64> {
    None
}

/// Read-only clipboard capability probe for `os-selftest` (ZERO writes, ZERO clipboard text read!).
pub fn probe_clipboard_readonly() -> bool {
    #[cfg(target_os = "macos")]
    {
        macos_pasteboard_change_count_readonly().is_some()
    }
    #[cfg(not(target_os = "macos"))]
    {
        cfg!(feature = "os-clipboard")
    }
}

#[cfg(feature = "os-clipboard")]
mod arboard_impl {
    use super::*;

    pub struct ArboardClipboardBackend {
        inner: arboard::Clipboard,
    }

    impl ArboardClipboardBackend {
        pub fn new() -> Result<Self, OsError> {
            let inner = arboard::Clipboard::new()
                .map_err(|e| OsError::ClipboardUnavailable(e.to_string()))?;
            Ok(Self { inner })
        }
    }

    impl OsClipboardBackend for ArboardClipboardBackend {
        fn read_change_count(&mut self) -> Option<i64> {
            macos_pasteboard_change_count_readonly()
        }

        fn read_text(&mut self) -> Result<Option<String>, OsError> {
            match self.inner.get_text() {
                Ok(text) => Ok(Some(text)),
                Err(arboard::Error::ContentNotAvailable) => Ok(None),
                Err(e) => Err(OsError::ClipboardUnavailable(e.to_string())),
            }
        }

        fn write_text(&mut self, text: &str) -> Result<(), OsError> {
            self.inner
                .set_text(text.to_string())
                .map_err(|e| OsError::ClipboardUnavailable(e.to_string()))
        }
    }
}

pub fn create_os_clipboard_backend() -> Result<Box<dyn OsClipboardBackend>, OsError> {
    #[cfg(feature = "os-clipboard")]
    {
        arboard_impl::ArboardClipboardBackend::new()
            .map(|b| Box::new(b) as Box<dyn OsClipboardBackend>)
    }
    #[cfg(not(feature = "os-clipboard"))]
    {
        Err(OsError::UnsupportedPlatform(
            "os-clipboard feature disabled at compile time",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::dryrun::MemoryClipboardBackend;

    #[test]
    fn clipboard_poller_one_shot_anti_echo_a_b_a_and_policy_purge() {
        let mem = MemoryClipboardBackend::new();
        let allow = Arc::new(AtomicBool::new(true));
        let mut poller = ClipboardPoller::new(Box::new(mem.clone()), Arc::clone(&allow));
        let q = poller.outbound_queue_handle();

        // 1. Remote writes "A" -> armed one-shot anti-echo -> poll suppresses echo
        poller.apply_remote_text("A").unwrap();
        assert!(poller.poll_once().unwrap().is_none());

        // 2. Local user copies "B" -> transmitted!
        mem.set_local_text("B");
        let item_b = poller.poll_once().unwrap().expect("B should transmit");
        assert_eq!(item_b.text, "B");

        // 3. Local user copies "A" again (A -> B -> A) -> MUST transmit (one-shot was cleared!)
        mem.set_local_text("A");
        let item_a2 = poller.poll_once().unwrap().expect("A->B->A must transmit");
        assert_eq!(item_a2.text, "A");
        assert_eq!(q.lock().unwrap().len(), 2);

        // 4. Policy disables clipboard -> poll immediately purges outbound queue
        allow.store(false, Ordering::Release);
        mem.set_local_text("C");
        assert!(poller.poll_once().unwrap().is_none());
        assert!(q.lock().unwrap().is_empty());
    }

    #[test]
    fn clipboard_png_header_validation_without_decoding_pixels() {
        // Valid minimal 1x1 PNG header (8-byte sig + IHDR chunk)
        let mut png = Vec::new();
        png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&640u32.to_be_bytes());
        png.extend_from_slice(&480u32.to_be_bytes());
        png.extend_from_slice(&[8, 6, 0, 0, 0]);
        png.extend_from_slice(&[0u8; 4]); // CRC placeholder
        assert_eq!(validate_clipboard_png_bytes(&png).unwrap(), (640, 480));

        // Bad magic rejected
        assert!(validate_clipboard_png_bytes(b"NOT_A_PNG_HEADER_1234567890").is_err());
    }
}
