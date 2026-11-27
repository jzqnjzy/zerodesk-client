// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{OsClipboardBackend, OsError};
use crate::session::clipboard::{validate_png_ihdr, CLIP_HARD_MAX_BYTES};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
};

/// Atomically updates the live `allow_clipboard` flag and bumps `policy_gen` whenever the
/// policy transitions so `ClipboardPoller` always forces a baseline resync even if policy
/// toggles `true -> false -> true` between two polling ticks.
pub fn set_clipboard_policy_allowed(flag: &AtomicBool, policy_gen: &AtomicU64, allowed: bool) {
    let prev = flag.swap(allowed, Ordering::AcqRel);
    if prev != allowed {
        policy_gen.fetch_add(1, Ordering::AcqRel);
    }
}

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

#[derive(Clone, PartialEq, Eq)]
pub struct OutboundClipboardItem {
    pub text: String,
    pub sha256: [u8; 32],
}

impl fmt::Debug for OutboundClipboardItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OutboundClipboardItem")
            .field("len", &self.text.len())
            .field(
                "sha256_prefix",
                &format!("{:02x}{:02x}..", self.sha256[0], self.sha256[1]),
            )
            .finish()
    }
}

/// Controlled read-only consumer handle for queued outbound clipboard changes.
/// Binds the live `allow_clipboard` policy flag at construction so consumers cannot bypass policy.
#[derive(Clone)]
pub struct ClipboardOutboundHandle {
    queue: Arc<Mutex<VecDeque<OutboundClipboardItem>>>,
    allow_clipboard: Arc<AtomicBool>,
}

impl ClipboardOutboundHandle {
    pub fn pop_front(&self) -> Option<OutboundClipboardItem> {
        let mut q = self.queue.lock().unwrap_or_else(|e| e.into_inner());
        if !self.allow_clipboard.load(Ordering::Acquire) {
            q.clear();
            return None;
        }
        q.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Single-threaded clipboard poller owning the sole `OsClipboardBackend` instance.
/// Uses SHA-256 primary dedup + optional OS `change_count` pre-filter + one-shot anti-echo
/// (`A -> B -> A`) + initial/policy-reenable baseline resync tracked via monotonic `policy_gen`
/// (never leaks pre-existing clipboard contents even across fast `true -> false -> true` toggles!).
pub struct ClipboardPoller {
    backend: Box<dyn OsClipboardBackend>,
    allow_clipboard: Arc<AtomicBool>,
    policy_gen: Arc<AtomicU64>,
    last_seen_policy_gen: u64,
    last_change_count: Option<i64>,
    last_seen_sha256: Option<[u8; 32]>,
    needs_resync: bool,
    anti_echo: OneShotAntiEcho,
    outbound_queue: Arc<Mutex<VecDeque<OutboundClipboardItem>>>,
    max_queue_len: usize,
}

impl ClipboardPoller {
    pub fn new(backend: Box<dyn OsClipboardBackend>, allow_clipboard: Arc<AtomicBool>) -> Self {
        Self::with_policy_gen(backend, allow_clipboard, Arc::new(AtomicU64::new(0)))
    }

    pub fn with_policy_gen(
        backend: Box<dyn OsClipboardBackend>,
        allow_clipboard: Arc<AtomicBool>,
        policy_gen: Arc<AtomicU64>,
    ) -> Self {
        let init_gen = policy_gen.load(Ordering::Acquire);
        Self {
            backend,
            allow_clipboard,
            policy_gen,
            last_seen_policy_gen: init_gen,
            last_change_count: None,
            last_seen_sha256: None,
            needs_resync: true,
            anti_echo: OneShotAntiEcho::new(),
            outbound_queue: Arc::new(Mutex::new(VecDeque::new())),
            max_queue_len: 16,
        }
    }

    /// Updates the clipboard policy flag and bumps `policy_gen` on any transition.
    pub fn set_policy_allowed(&self, allowed: bool) {
        set_clipboard_policy_allowed(&self.allow_clipboard, &self.policy_gen, allowed);
    }

    pub fn outbound_handle(&self) -> ClipboardOutboundHandle {
        ClipboardOutboundHandle {
            queue: Arc::clone(&self.outbound_queue),
            allow_clipboard: Arc::clone(&self.allow_clipboard),
        }
    }

    fn sync_policy_gen(&mut self) {
        let cur_gen = self.policy_gen.load(Ordering::Acquire);
        if cur_gen != self.last_seen_policy_gen {
            self.last_seen_policy_gen = cur_gen;
            self.needs_resync = true;
            self.anti_echo.clear();
            self.clear_outbound_queue();
        }
    }

    /// Applies remote clipboard text locally and arms one-shot anti-echo suppression ONLY on success.
    /// Returns `Ok(true)` if applied, `Ok(false)` if blocked by policy.
    pub fn apply_remote_text(&mut self, text: &str) -> Result<bool, OsError> {
        self.sync_policy_gen();
        if text.is_empty() || text.len() > CLIP_HARD_MAX_BYTES as usize {
            return Err(OsError::InvalidData(format!(
                "remote clipboard text len {} outside 1..={CLIP_HARD_MAX_BYTES}",
                text.len()
            )));
        }
        if !self.allow_clipboard.load(Ordering::Acquire) {
            self.needs_resync = true;
            self.clear_outbound_queue();
            return Ok(false);
        }
        // Write FIRST, arm anti-echo ONLY if write_text succeeds!
        self.backend.write_text(text)?;
        let hash: [u8; 32] = Sha256::digest(text.as_bytes()).into();
        self.anti_echo.arm(hash);
        self.last_seen_sha256 = Some(hash);
        self.needs_resync = false;
        Ok(true)
    }

    /// Runs a single poll tick on the owning thread without duplicating into `outbound_queue`.
    /// Returns `Ok(Some(item))` if a new user-initiated clipboard change should be sent to the peer.
    pub fn poll_once(&mut self) -> Result<Option<OutboundClipboardItem>, OsError> {
        self.sync_policy_gen();
        if !self.allow_clipboard.load(Ordering::Acquire) {
            self.needs_resync = true;
            self.anti_echo.clear();
            self.clear_outbound_queue();
            return Ok(None);
        }

        let current_cc = self.backend.read_change_count();
        if !self.needs_resync {
            if let Some(cc) = current_cc {
                if self.last_change_count == Some(cc) {
                    return Ok(None);
                }
            }
        }

        // Do NOT commit `last_change_count` if `read_text()` errors, so transient errors retry.
        let text_opt = self.backend.read_text()?;
        if let Some(cc) = current_cc {
            self.last_change_count = Some(cc);
        }

        if self.needs_resync {
            self.needs_resync = false;
            self.last_seen_sha256 = text_opt
                .as_deref()
                .filter(|t| !t.is_empty())
                .map(|t| Sha256::digest(t.as_bytes()).into());
            return Ok(None);
        }

        let Some(text) = text_opt else {
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

        Ok(Some(OutboundClipboardItem { text, sha256: hash }))
    }

    /// Polls once and enqueues any new outbound item into the bounded `ClipboardOutboundHandle`
    /// queue (single consumption contract with no duplicate return).
    pub fn poll_into_queue(&mut self) -> Result<bool, OsError> {
        let Some(item) = self.poll_once()? else {
            return Ok(false);
        };
        let mut q = self.outbound_queue.lock().unwrap_or_else(|e| e.into_inner());
        while q.len() >= self.max_queue_len {
            q.pop_front();
        }
        q.push_back(item);
        Ok(true)
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
    fn clipboard_poller_resyncs_baseline_one_shot_aba_redacts_debug_and_policy_purges() {
        let mem = MemoryClipboardBackend::new();
        mem.set_local_text("PRE_EXISTING_SECRET_MUST_NOT_SEND");
        let allow = Arc::new(AtomicBool::new(true));
        let mut poller = ClipboardPoller::new(Box::new(mem.clone()), Arc::clone(&allow));
        let handle = poller.outbound_handle();

        // 0. Initial baseline resync MUST NOT transmit pre-existing clipboard contents!
        assert!(poller.poll_once().unwrap().is_none());

        // 1. Remote writes "A" -> armed one-shot anti-echo -> poll suppresses echo
        assert!(poller.apply_remote_text("A").unwrap());
        assert!(poller.poll_once().unwrap().is_none());

        // Empty remote text fails closed
        assert!(poller.apply_remote_text("").is_err());

        // 2. Local user copies "B" -> transmitted via poll_into_queue!
        mem.set_local_text("B");
        assert!(poller.poll_into_queue().unwrap());
        let item_b = handle.pop_front().expect("B should dequeue");
        assert_eq!(item_b.text, "B");
        let dbg_str = format!("{item_b:?}");
        assert!(!dbg_str.contains("\"B\""));
        assert!(dbg_str.contains("len: 1"));

        // 3. Local user copies "A" again (A -> B -> A) -> MUST transmit (one-shot was cleared!)
        mem.set_local_text("A");
        assert!(poller.poll_into_queue().unwrap());
        assert_eq!(handle.len(), 1);

        // 4. Policy disables clipboard -> poll immediately purges outbound queue & sets needs_resync
        poller.set_policy_allowed(false);
        mem.set_local_text("SECRET_WHILE_DISABLED");
        assert!(poller.poll_once().unwrap().is_none());
        assert!(handle.is_empty());

        // 5. Policy re-enabled -> first poll resyncs baseline WITHOUT leaking SECRET_WHILE_DISABLED!
        poller.set_policy_allowed(true);
        assert!(poller.poll_once().unwrap().is_none());
        // Next user copy AFTER re-enable transmits normally
        mem.set_local_text("AFTER_REENABLE");
        let after = poller.poll_once().unwrap().expect("after reenable sends");
        assert_eq!(after.text, "AFTER_REENABLE");
    }

    #[test]
    fn clipboard_poller_resyncs_across_fast_false_true_toggle_without_intermediate_poll() {
        let mem = MemoryClipboardBackend::new();
        let allow = Arc::new(AtomicBool::new(true));
        let pgen = Arc::new(AtomicU64::new(0));
        let mut poller =
            ClipboardPoller::with_policy_gen(Box::new(mem.clone()), Arc::clone(&allow), Arc::clone(&pgen));
        let handle = poller.outbound_handle();

        // Initial baseline resync.
        assert!(poller.poll_once().unwrap().is_none());

        // Queue one item while allowed, then toggle false -> copy secret -> toggle true WITHOUT
        // calling poll_once while disabled!
        mem.set_local_text("BEFORE_TOGGLE");
        assert!(poller.poll_into_queue().unwrap());
        assert_eq!(handle.len(), 1);

        set_clipboard_policy_allowed(&allow, &pgen, false);
        mem.set_local_text("COPIED_DURING_DISABLED_WINDOW");
        set_clipboard_policy_allowed(&allow, &pgen, true);

        // First poll MUST observe policy_gen bump, purge stale queue, and resync baseline without emitting!
        assert!(poller.poll_once().unwrap().is_none());
        assert!(handle.is_empty());

        // Subsequent copy after resync transmits normally.
        mem.set_local_text("FRESH_AFTER_RESYNC");
        let item = poller.poll_once().unwrap().expect("fresh copy sends");
        assert_eq!(item.text, "FRESH_AFTER_RESYNC");
    }

    #[test]
    fn clipboard_png_header_validation_without_decoding_pixels() {
        let mut png = Vec::new();
        png.extend_from_slice(&[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        png.extend_from_slice(&13u32.to_be_bytes());
        png.extend_from_slice(b"IHDR");
        png.extend_from_slice(&640u32.to_be_bytes());
        png.extend_from_slice(&480u32.to_be_bytes());
        png.extend_from_slice(&[8, 6, 0, 0, 0]);
        png.extend_from_slice(&[0u8; 4]);
        assert_eq!(validate_clipboard_png_bytes(&png).unwrap(), (640, 480));
        assert!(validate_clipboard_png_bytes(b"NOT_A_PNG_HEADER_1234567890").is_err());
    }
}
