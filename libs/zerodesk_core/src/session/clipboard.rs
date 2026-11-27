// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `0x04 Clipboard` (`p3` reliable ordered) normative binary wire protocol (`spec/04` §7, `v1.2.4`
//! & `V27`), dual-end policy gate, UTF-8 / PNG IHDR bomb guard, and `A -> B -> A` anti-echo state machine.

use super::policy::EffectiveTenantPolicy;
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{Duration, Instant},
};
use v2_transport::L4Header;

pub const CLIP_MSG_SYNC: u8 = 0x01;
pub const CLIP_MSG_ACK: u8 = 0x02;
pub const CLIP_MSG_CHUNK: u8 = 0x03;

pub const CLIP_SYNC_WIRE_LEN: usize = 57;
pub const CLIP_ACK_WIRE_LEN: usize = 9;
pub const CLIP_CHUNK_HDR_LEN: usize = 12;
pub const CLIP_CHUNK_MAX_PAYLOAD: usize = 1_024;
pub const CLIP_CHUNK_MIN_WIRE_LEN: usize = CLIP_CHUNK_HDR_LEN + 1;
pub const CLIP_CHUNK_MAX_WIRE_LEN: usize = CLIP_CHUNK_HDR_LEN + CLIP_CHUNK_MAX_PAYLOAD;

pub const CLIP_MIME_TEXT_UTF8: u8 = 1;
pub const CLIP_MIME_IMAGE_PNG: u8 = 2;
pub const CLIP_MIME_FILE_URI_LIST: u8 = 3;

pub const CLIP_ACK_OK: u8 = 0;
pub const CLIP_ACK_POLICY_DENIED: u8 = 1;
pub const CLIP_ACK_TOO_LARGE: u8 = 2;
pub const CLIP_ACK_HASH_MISMATCH: u8 = 3;
pub const CLIP_ACK_RATE_LIMITED: u8 = 4;
pub const CLIP_ACK_UNSUPPORTED: u8 = 5;
pub const CLIP_ACK_TIMEOUT: u8 = 6;

pub const CLIP_HARD_MAX_BYTES: u32 = 262_144;
pub const CLIP_REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);
pub const CLIP_PNG_MAX_DIM: u32 = 8_192;
pub const CLIP_PNG_MAX_PIXELS: u64 = 33_554_432;
pub const CLIP_ERROR_INVALID_FRAMING: u16 = 0x0103;
pub const CHANNEL_CONSECUTIVE_FRAMING_ERROR_LIMIT: u32 = 3;

/// Shared per-session consecutive `0x0103` channel framing error counter across `0x04 Clipboard`
/// and `0x05 FileTransfer` (`spec/04` §8.4).
/// - Incremented ONLY on transfer/chunk-level `0x0103 INVALID_FRAMING` violations.
/// - NEVER incremented on `POLICY_DENIED`, `RATE_LIMITED`, or `0x04 Clipboard` unknown `msg_type`.
/// - Reset to `0` immediately upon any valid accepted `0x04` or `0x05` frame.
/// - Reaching `>= 3` requires immediate `SESSION_CLOSE(0x0103)`.
#[derive(Debug, Clone, Default)]
pub struct ChannelFramingErrorCounter {
    consecutive: u32,
}

impl ChannelFramingErrorCounter {
    pub fn new() -> Self {
        Self { consecutive: 0 }
    }

    pub fn consecutive(&self) -> u32 {
        self.consecutive
    }

    pub fn reset(&mut self) {
        self.consecutive = 0;
    }

    /// Records a channel-level `0x0103` framing violation. Returns `true` if `>= 3` consecutive
    /// violations have been reached (caller MUST close session with `SESSION_CLOSE(0x0103)`).
    pub fn record_framing_error(&mut self) -> bool {
        self.consecutive = self.consecutive.saturating_add(1);
        self.consecutive >= CHANNEL_CONSECUTIVE_FRAMING_ERROR_LIMIT
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardError {
    InvalidFraming { error_code: u16, reason: String },
    PolicyDenied(String),
    TooLarge { size: usize, limit: u64 },
    UnsupportedMime(u8),
    BulkPaused,
    RateLimited,
    InvalidContent(String),
}

impl fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFraming { error_code, reason } => {
                write!(f, "clipboard framing error ({error_code:#06x}): {reason}")
            }
            Self::PolicyDenied(msg) => write!(f, "clipboard denied by tenant policy: {msg}"),
            Self::TooLarge { size, limit } => {
                write!(f, "clipboard payload {size}B exceeds limit {limit}B")
            }
            Self::UnsupportedMime(m) => write!(f, "clipboard mime_kind={m} unsupported"),
            Self::BulkPaused => write!(f, "clipboard paused by Survival Mode / PAUSE_FILE_CHUNK"),
            Self::RateLimited => write!(f, "clipboard rate-limited / transfer already in flight"),
            Self::InvalidContent(msg) => write!(f, "clipboard content validation failed: {msg}"),
        }
    }
}

impl std::error::Error for ClipboardError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipSync {
    pub mime_kind: u8,
    pub clip_id: u64,
    pub origin_nonce: u64,
    pub total_len: u32,
    pub total_chunks: u32,
    pub sha256: [u8; 32],
}

impl ClipSync {
    pub fn encode(&self) -> Result<[u8; CLIP_SYNC_WIRE_LEN], ClipboardError> {
        Self::validate_fields(
            self.mime_kind,
            self.clip_id,
            self.total_len,
            self.total_chunks,
        )?;
        let mut out = [0u8; CLIP_SYNC_WIRE_LEN];
        out[0] = self.mime_kind;
        out[1..9].copy_from_slice(&self.clip_id.to_be_bytes());
        out[9..17].copy_from_slice(&self.origin_nonce.to_be_bytes());
        out[17..21].copy_from_slice(&self.total_len.to_be_bytes());
        out[21..25].copy_from_slice(&self.total_chunks.to_be_bytes());
        out[25..57].copy_from_slice(&self.sha256);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ClipboardError> {
        if bytes.len() != CLIP_SYNC_WIRE_LEN {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: format!(
                    "CLIP_SYNC must be exact {CLIP_SYNC_WIRE_LEN}B, got {}B",
                    bytes.len()
                ),
            });
        }
        let mime_kind = bytes[0];
        let clip_id = u64::from_be_bytes([
            bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        ]);
        let origin_nonce = u64::from_be_bytes([
            bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16],
        ]);
        let total_len = u32::from_be_bytes([bytes[17], bytes[18], bytes[19], bytes[20]]);
        let total_chunks = u32::from_be_bytes([bytes[21], bytes[22], bytes[23], bytes[24]]);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&bytes[25..57]);
        Self::validate_fields(mime_kind, clip_id, total_len, total_chunks)?;
        Ok(Self {
            mime_kind,
            clip_id,
            origin_nonce,
            total_len,
            total_chunks,
            sha256,
        })
    }

    fn validate_fields(
        mime_kind: u8,
        clip_id: u64,
        total_len: u32,
        total_chunks: u32,
    ) -> Result<(), ClipboardError> {
        if !(CLIP_MIME_TEXT_UTF8..=CLIP_MIME_FILE_URI_LIST).contains(&mime_kind) {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: format!("invalid CLIP_SYNC mime_kind={mime_kind}"),
            });
        }
        if clip_id == 0 {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: "CLIP_SYNC clip_id must be non-zero".into(),
            });
        }
        if total_len == 0 {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: "CLIP_SYNC total_len must be >= 1".into(),
            });
        }
        if total_chunks == 0 {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: "CLIP_SYNC total_chunks must be >= 1".into(),
            });
        }
        let max_for_chunks = u64::from(total_chunks).saturating_mul(CLIP_CHUNK_MAX_PAYLOAD as u64);
        if total_chunks > total_len || u64::from(total_len) > max_for_chunks {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: format!(
                    "CLIP_SYNC total_len={total_len} inconsistent with total_chunks={total_chunks}"
                ),
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipChunk {
    pub clip_id: u64,
    pub chunk_seq: u32,
    pub payload: Vec<u8>,
}

impl ClipChunk {
    pub fn encode(&self) -> Result<Vec<u8>, ClipboardError> {
        if self.clip_id == 0 {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: "CLIP_CHUNK clip_id must be non-zero".into(),
            });
        }
        if self.payload.is_empty() || self.payload.len() > CLIP_CHUNK_MAX_PAYLOAD {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: format!(
                    "CLIP_CHUNK payload {}B outside 1..={CLIP_CHUNK_MAX_PAYLOAD}B",
                    self.payload.len()
                ),
            });
        }
        let mut out = Vec::with_capacity(CLIP_CHUNK_HDR_LEN + self.payload.len());
        out.extend_from_slice(&self.clip_id.to_be_bytes());
        out.extend_from_slice(&self.chunk_seq.to_be_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ClipboardError> {
        if !(CLIP_CHUNK_MIN_WIRE_LEN..=CLIP_CHUNK_MAX_WIRE_LEN).contains(&bytes.len()) {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: format!(
                    "CLIP_CHUNK wire length {}B outside {CLIP_CHUNK_MIN_WIRE_LEN}..={CLIP_CHUNK_MAX_WIRE_LEN}B",
                    bytes.len()
                ),
            });
        }
        let clip_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        if clip_id == 0 {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: "CLIP_CHUNK clip_id must be non-zero".into(),
            });
        }
        let chunk_seq = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        Ok(Self {
            clip_id,
            chunk_seq,
            payload: bytes[CLIP_CHUNK_HDR_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClipAck {
    pub clip_id: u64,
    pub status: u8,
}

impl ClipAck {
    pub fn encode(&self) -> Result<[u8; CLIP_ACK_WIRE_LEN], ClipboardError> {
        if self.status > CLIP_ACK_TIMEOUT {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: format!("invalid CLIP_ACK status={}", self.status),
            });
        }
        let mut out = [0u8; CLIP_ACK_WIRE_LEN];
        out[0..8].copy_from_slice(&self.clip_id.to_be_bytes());
        out[8] = self.status;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ClipboardError> {
        if bytes.len() != CLIP_ACK_WIRE_LEN {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: format!(
                    "CLIP_ACK must be exact {CLIP_ACK_WIRE_LEN}B, got {}B",
                    bytes.len()
                ),
            });
        }
        let clip_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let status = bytes[8];
        if status > CLIP_ACK_TIMEOUT {
            return Err(ClipboardError::InvalidFraming {
                error_code: CLIP_ERROR_INVALID_FRAMING,
                reason: format!("invalid CLIP_ACK status={status} (allowed 0..=6)"),
            });
        }
        Ok(Self { clip_id, status })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipMessage {
    Sync(ClipSync),
    Ack(ClipAck),
    Chunk(ClipChunk),
    UnknownMsgType(u8),
}

/// Decodes a `0x04 Clipboard` L4 frame strictly checking `L4Header.flags == 0` and exact `body_len`.
/// Unknown `msg_type` returns `Ok(ClipMessage::UnknownMsgType(t))` so the receiver replies
/// `CLIP_ACK(0, 5 UNSUPPORTED)` without closing the session (`spec/04` §7.1).
pub fn decode_clipboard_l4(l4_hdr: &L4Header, body: &[u8]) -> Result<ClipMessage, ClipboardError> {
    if l4_hdr.flags != 0 {
        return Err(ClipboardError::InvalidFraming {
            error_code: CLIP_ERROR_INVALID_FRAMING,
            reason: format!("0x04 Clipboard L4Header.flags must be 0, got {:#x}", l4_hdr.flags),
        });
    }
    if usize::from(l4_hdr.body_len) != body.len() {
        return Err(ClipboardError::InvalidFraming {
            error_code: CLIP_ERROR_INVALID_FRAMING,
            reason: format!(
                "0x04 Clipboard L4Header.body_len={} != actual body len {}",
                l4_hdr.body_len,
                body.len()
            ),
        });
    }
    match l4_hdr.msg_type {
        CLIP_MSG_SYNC => Ok(ClipMessage::Sync(ClipSync::decode(body)?)),
        CLIP_MSG_ACK => Ok(ClipMessage::Ack(ClipAck::decode(body)?)),
        CLIP_MSG_CHUNK => Ok(ClipMessage::Chunk(ClipChunk::decode(body)?)),
        other => Ok(ClipMessage::UnknownMsgType(other)),
    }
}

/// Validates PNG 8-byte magic + leading 13-byte `IHDR` chunk dimensions BEFORE any full image
/// decode (`spec/04` §7.3.3): `1 <= width <= 8192`, `1 <= height <= 8192`,
/// `(width as u64) * (height as u64) <= 33_554_432`.
pub fn validate_png_ihdr(bytes: &[u8]) -> Result<(u32, u32), ClipboardError> {
    const PNG_MAGIC: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    if bytes.len() < 33 {
        return Err(ClipboardError::InvalidContent(
            "PNG payload shorter than 33B magic+IHDR header".into(),
        ));
    }
    if bytes[0..8] != PNG_MAGIC {
        return Err(ClipboardError::InvalidContent(
            "PNG magic signature mismatch".into(),
        ));
    }
    let ihdr_len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    if ihdr_len != 13 || &bytes[12..16] != b"IHDR" {
        return Err(ClipboardError::InvalidContent(
            "PNG first chunk is not a valid 13-byte IHDR".into(),
        ));
    }
    let width = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let height = u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    if width == 0 || height == 0 || width > CLIP_PNG_MAX_DIM || height > CLIP_PNG_MAX_DIM {
        return Err(ClipboardError::InvalidContent(format!(
            "PNG IHDR dimensions {width}x{height} out of 1..={CLIP_PNG_MAX_DIM} guard"
        )));
    }
    let pixels = u64::from(width).saturating_mul(u64::from(height));
    if pixels > CLIP_PNG_MAX_PIXELS {
        return Err(ClipboardError::InvalidContent(format!(
            "PNG IHDR pixel count {pixels} exceeds {CLIP_PNG_MAX_PIXELS} decompression bomb guard"
        )));
    }
    Ok((width, height))
}

/// Validates clipboard payload content for the given `mime_kind`.
pub fn validate_clipboard_content(mime_kind: u8, payload: &[u8]) -> Result<(), ClipboardError> {
    match mime_kind {
        CLIP_MIME_TEXT_UTF8 => {
            std::str::from_utf8(payload)
                .map_err(|e| ClipboardError::InvalidContent(format!("invalid UTF-8 text: {e}")))?;
            Ok(())
        }
        CLIP_MIME_IMAGE_PNG => {
            let _ = validate_png_ihdr(payload)?;
            Ok(())
        }
        CLIP_MIME_FILE_URI_LIST => Err(ClipboardError::UnsupportedMime(mime_kind)),
        other => Err(ClipboardError::InvalidFraming {
            error_code: CLIP_ERROR_INVALID_FRAMING,
            reason: format!("invalid mime_kind={other}"),
        }),
    }
}

/// Evaluates `spec/04` §7.2.1 deterministic policy-before-unsupported gate for a `CLIP_SYNC`.
/// Returns `Ok(())` if permitted, or `Err(ack_status)` (`CLIP_ACK_POLICY_DENIED`,
/// `CLIP_ACK_UNSUPPORTED`, or `CLIP_ACK_TOO_LARGE`).
pub fn check_clipboard_policy_for_sync(
    policy: &EffectiveTenantPolicy,
    mime_kind: u8,
    total_len: u32,
) -> Result<(), u8> {
    if mime_kind == CLIP_MIME_FILE_URI_LIST {
        // Deterministic evaluation order MUST: check policy FIRST before returning UNSUPPORTED!
        if !(policy.allow_clipboard() && policy.allow_file_clipboard()) {
            return Err(CLIP_ACK_POLICY_DENIED);
        }
        return Err(CLIP_ACK_UNSUPPORTED);
    }
    if !policy.allow_clipboard() || policy.max_clipboard_bytes() == 0 {
        return Err(CLIP_ACK_POLICY_DENIED);
    }
    let max_bytes = policy.max_clipboard_bytes().min(u64::from(CLIP_HARD_MAX_BYTES));
    if u64::from(total_len) > max_bytes {
        return Err(CLIP_ACK_TOO_LARGE);
    }
    Ok(())
}

/// State-machine anti-echo loop guard (`spec/04` §7.3.4).
/// Suppresses local echo ONLY while the local clipboard still reflects the last remote-applied
/// hash before any new local change, so `A -> B -> A` is NEVER falsely suppressed.
#[derive(Debug, Clone, Default)]
pub struct ClipboardAntiEchoGuard {
    last_remote_applied_hash: Option<[u8; 32]>,
    suppress_echo: bool,
}

impl ClipboardAntiEchoGuard {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn on_remote_applied(&mut self, payload_sha256: [u8; 32]) {
        self.last_remote_applied_hash = Some(payload_sha256);
        self.suppress_echo = true;
    }

    /// Returns `true` if a local clipboard change with `local_sha256` should be synced to the
    /// remote peer; returns `false` if it is an echo of the most recent remote-applied content.
    pub fn should_sync_local(&mut self, local_sha256: [u8; 32]) -> bool {
        if self.suppress_echo && self.last_remote_applied_hash == Some(local_sha256) {
            return false;
        }
        self.suppress_echo = false;
        self.last_remote_applied_hash = None;
        true
    }

    pub fn is_suppressing(&self) -> bool {
        self.suppress_echo
    }
}

/// Prepared outbound clipboard transfer (1 `CLIP_SYNC` + `>= 1` `CLIP_CHUNK`s).
#[derive(Debug, Clone)]
pub struct OutboundClipboardTransfer {
    pub sync: ClipSync,
    pub chunks: Vec<ClipChunk>,
}

/// Validates sender-side policy & content and chunks `payload` into `CLIP_SYNC` + `CLIP_CHUNK`s
/// (`<= 1024B`/chunk, always `>= 1` chunk).
pub fn prepare_outbound_clipboard(
    policy: &EffectiveTenantPolicy,
    mime_kind: u8,
    payload: &[u8],
    clip_id: u64,
    origin_nonce: u64,
    bulk_paused: bool,
) -> Result<OutboundClipboardTransfer, ClipboardError> {
    if bulk_paused {
        return Err(ClipboardError::BulkPaused);
    }
    if clip_id == 0 {
        return Err(ClipboardError::InvalidFraming {
            error_code: CLIP_ERROR_INVALID_FRAMING,
            reason: "clip_id must be non-zero".into(),
        });
    }
    if payload.is_empty() {
        return Err(ClipboardError::InvalidContent(
            "clipboard payload must not be empty".into(),
        ));
    }
    let total_len = u32::try_from(payload.len()).map_err(|_| ClipboardError::TooLarge {
        size: payload.len(),
        limit: u64::from(CLIP_HARD_MAX_BYTES),
    })?;
    if let Err(status) = check_clipboard_policy_for_sync(policy, mime_kind, total_len) {
        return match status {
            CLIP_ACK_POLICY_DENIED => Err(ClipboardError::PolicyDenied(
                "local verified policy denies clipboard operation".into(),
            )),
            CLIP_ACK_TOO_LARGE => Err(ClipboardError::TooLarge {
                size: payload.len(),
                limit: policy.max_clipboard_bytes().min(u64::from(CLIP_HARD_MAX_BYTES)),
            }),
            _ => Err(ClipboardError::UnsupportedMime(mime_kind)),
        };
    }
    validate_clipboard_content(mime_kind, payload)?;

    let sha256: [u8; 32] = Sha256::digest(payload).into();
    let mut chunks = Vec::new();
    for (idx, part) in payload.chunks(CLIP_CHUNK_MAX_PAYLOAD).enumerate() {
        chunks.push(ClipChunk {
            clip_id,
            chunk_seq: idx as u32,
            payload: part.to_vec(),
        });
    }
    let sync = ClipSync {
        mime_kind,
        clip_id,
        origin_nonce,
        total_len,
        total_chunks: chunks.len() as u32,
        sha256,
    };
    Ok(OutboundClipboardTransfer { sync, chunks })
}

struct InboundClipState {
    sync: ClipSync,
    started_at: Instant,
    next_chunk_seq: u32,
    buf: Vec<u8>,
}

/// Completed remote clipboard payload ready to be applied to local OS clipboard.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveredClipboard {
    pub clip_id: u64,
    pub mime_kind: u8,
    pub origin_nonce: u64,
    pub sha256: [u8; 32],
    pub payload: Vec<u8>,
}

/// Action returned by `ClipboardReceiver::on_frame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClipboardRecvAction {
    /// No wire reply needed yet (e.g., accepted intermediate chunk).
    None,
    /// Send a `CLIP_ACK` reply on `0x04 Clipboard` (keep session alive).
    SendAck(ClipAck),
    /// Completed, SHA-256 & content verified; apply to clipboard and send `CLIP_ACK(id, 0 OK)`.
    DeliverAndAck {
        delivered: DeliveredClipboard,
        ack: ClipAck,
    },
    /// Session-fatal `0x0103 INVALID_FRAMING` — caller MUST send `SESSION_CLOSE(0x0103)` and close.
    SessionFatal(String),
}

/// Receiver state machine for `0x04 Clipboard` (max 1 in-flight per direction, 10s timeout,
/// dual-end policy enforcement, UTF-8 / PNG IHDR validation, anti-echo integration).
pub struct ClipboardReceiver {
    policy: EffectiveTenantPolicy,
    in_flight: Option<InboundClipState>,
    pub anti_echo: ClipboardAntiEchoGuard,
    last_completed_at: Option<Instant>,
    min_interval: Duration,
}

impl ClipboardReceiver {
    pub fn new(policy: EffectiveTenantPolicy) -> Self {
        Self {
            policy,
            in_flight: None,
            anti_echo: ClipboardAntiEchoGuard::new(),
            last_completed_at: None,
            min_interval: Duration::ZERO,
        }
    }

    pub fn with_rate_limit(mut self, min_interval: Duration) -> Self {
        self.min_interval = min_interval;
        self
    }

    pub fn has_in_flight(&self) -> bool {
        self.in_flight.is_some()
    }

    pub fn update_policy(&mut self, policy: EffectiveTenantPolicy) {
        self.policy = policy;
    }

    /// Checks 10-second reassembly timeout; if expired, drops in-flight buffer and returns
    /// `Some(ClipAck { clip_id, status: CLIP_ACK_TIMEOUT })`.
    pub fn poll_timeout(&mut self, now: Instant) -> Option<ClipAck> {
        let expired_id = self.in_flight.as_ref().and_then(|st| {
            if now.saturating_duration_since(st.started_at) >= CLIP_REASSEMBLY_TIMEOUT {
                Some(st.sync.clip_id)
            } else {
                None
            }
        })?;
        self.in_flight = None;
        Some(ClipAck {
            clip_id: expired_id,
            status: CLIP_ACK_TIMEOUT,
        })
    }

    /// Handles one incoming `0x04 Clipboard` L4 frame.
    pub fn on_l4_frame(
        &mut self,
        l4_hdr: &L4Header,
        body: &[u8],
        now: Instant,
        err_counter: &mut ChannelFramingErrorCounter,
    ) -> ClipboardRecvAction {
        let msg = match decode_clipboard_l4(l4_hdr, body) {
            Ok(m) => m,
            Err(e) => {
                // Spec/04 §8.4: malformed known msg_type / L4 header mismatch / invalid enum is Session-Fatal!
                let _ = err_counter.record_framing_error();
                return ClipboardRecvAction::SessionFatal(e.to_string());
            }
        };

        match msg {
            ClipMessage::UnknownMsgType(_) => {
                // Spec/04 §7.1 & §8.4: MUST reply CLIP_ACK(0, 5 UNSUPPORTED), NEVER close session,
                // and NEVER increment consecutive 0x0103 framing error counter.
                ClipboardRecvAction::SendAck(ClipAck {
                    clip_id: 0,
                    status: CLIP_ACK_UNSUPPORTED,
                })
            }
            ClipMessage::Ack(_) => {
                err_counter.reset();
                ClipboardRecvAction::None
            }
            ClipMessage::Sync(sync) => {
                // First expire any timed-out stale in-flight transfer
                let _ = self.poll_timeout(now);

                // Policy check FIRST (also enforces mime_kind=3 policy-before-unsupported)
                if let Err(status) = check_clipboard_policy_for_sync(
                    &self.policy,
                    sync.mime_kind,
                    sync.total_len,
                ) {
                    return ClipboardRecvAction::SendAck(ClipAck {
                        clip_id: sync.clip_id,
                        status,
                    });
                }

                // Max 1 in-flight per direction & rate limit
                if self.in_flight.is_some() {
                    return ClipboardRecvAction::SendAck(ClipAck {
                        clip_id: sync.clip_id,
                        status: CLIP_ACK_RATE_LIMITED,
                    });
                }
                if !self.min_interval.is_zero() {
                    if let Some(last) = self.last_completed_at {
                        if now.saturating_duration_since(last) < self.min_interval {
                            return ClipboardRecvAction::SendAck(ClipAck {
                                clip_id: sync.clip_id,
                                status: CLIP_ACK_RATE_LIMITED,
                            });
                        }
                    }
                }

                err_counter.reset();
                self.in_flight = Some(InboundClipState {
                    buf: Vec::with_capacity(sync.total_len as usize),
                    sync,
                    started_at: now,
                    next_chunk_seq: 0,
                });
                ClipboardRecvAction::None
            }
            ClipMessage::Chunk(chunk) => {
                let Some(st) = self.in_flight.as_mut() else {
                    if err_counter.record_framing_error() {
                        return ClipboardRecvAction::SessionFatal(
                            "consecutive 0x0103 framing errors >= 3 (orphan CLIP_CHUNK)".into(),
                        );
                    }
                    return ClipboardRecvAction::None;
                };
                if chunk.clip_id != st.sync.clip_id || chunk.chunk_seq != st.next_chunk_seq {
                    self.in_flight = None;
                    if err_counter.record_framing_error() {
                        return ClipboardRecvAction::SessionFatal(
                            "consecutive 0x0103 framing errors >= 3 (out-of-order CLIP_CHUNK)"
                                .into(),
                        );
                    }
                    return ClipboardRecvAction::SendAck(ClipAck {
                        clip_id: chunk.clip_id,
                        status: CLIP_ACK_HASH_MISMATCH,
                    });
                }
                let new_len = st.buf.len().saturating_add(chunk.payload.len());
                if new_len > st.sync.total_len as usize {
                    let cid = st.sync.clip_id;
                    self.in_flight = None;
                    if err_counter.record_framing_error() {
                        return ClipboardRecvAction::SessionFatal(
                            "consecutive 0x0103 framing errors >= 3 (CLIP_CHUNK overflow)".into(),
                        );
                    }
                    return ClipboardRecvAction::SendAck(ClipAck {
                        clip_id: cid,
                        status: CLIP_ACK_HASH_MISMATCH,
                    });
                }
                st.buf.extend_from_slice(&chunk.payload);
                st.next_chunk_seq = st.next_chunk_seq.saturating_add(1);
                err_counter.reset();

                if st.next_chunk_seq < st.sync.total_chunks {
                    return ClipboardRecvAction::None;
                }

                // Final chunk received: verify exact length, SHA-256, and content guard
                let Some(done) = self.in_flight.take() else {
                    return ClipboardRecvAction::None;
                };
                if done.buf.len() != done.sync.total_len as usize {
                    return ClipboardRecvAction::SendAck(ClipAck {
                        clip_id: done.sync.clip_id,
                        status: CLIP_ACK_HASH_MISMATCH,
                    });
                }
                let digest: [u8; 32] = Sha256::digest(&done.buf).into();
                if digest != done.sync.sha256 {
                    return ClipboardRecvAction::SendAck(ClipAck {
                        clip_id: done.sync.clip_id,
                        status: CLIP_ACK_HASH_MISMATCH,
                    });
                }
                if validate_clipboard_content(done.sync.mime_kind, &done.buf).is_err() {
                    return ClipboardRecvAction::SendAck(ClipAck {
                        clip_id: done.sync.clip_id,
                        status: CLIP_ACK_HASH_MISMATCH,
                    });
                }

                self.last_completed_at = Some(now);
                self.anti_echo.on_remote_applied(digest);
                ClipboardRecvAction::DeliverAndAck {
                    delivered: DeliveredClipboard {
                        clip_id: done.sync.clip_id,
                        mime_kind: done.sync.mime_kind,
                        origin_nonce: done.sync.origin_nonce,
                        sha256: digest,
                        payload: done.buf,
                    },
                    ack: ClipAck {
                        clip_id: done.sync.clip_id,
                        status: CLIP_ACK_OK,
                    },
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::policy::{
        TenantPolicyBody, POLICY_FLAG_ALLOW_CLIPBOARD, POLICY_FLAG_ALLOW_FILE_CLIPBOARD,
    };
    use serde_json::Value;
    use v2_transport::{decode_l4_frame, encode_l4_frame};

    const V27_PATH: &str =
        "/Volumes/data/github/zerodesk/protocol-spec/vectors/v27_policy_clipboard_file.json";

    fn policy_with(flags: u32, max_clipboard_kb: u32) -> EffectiveTenantPolicy {
        EffectiveTenantPolicy {
            tenant_id: [0x11; 16],
            version: 1,
            exp_unix: u64::MAX,
            policy_hash: [0x22; 32],
            body: TenantPolicyBody {
                schema_ver: 1,
                flags,
                max_bw_kbps: 20_000,
                max_file_mb: 256,
                max_clipboard_kb,
            },
            degraded: false,
            degraded_reason: None,
        }
    }

    #[test]
    fn clipboard_matches_v27_golden_frames_negative_cases_and_png_ihdr_guard() {
        let raw_json = std::fs::read_to_string(V27_PATH).unwrap();
        let v: Value = serde_json::from_str(&raw_json).unwrap();
        let cb = &v["clipboard"];

        // CLIP_SYNC exact bytes + L4 frame
        let sync_bytes = hex::decode(cb["clip_sync"]["body_hex"].as_str().unwrap()).unwrap();
        let sync = ClipSync::decode(&sync_bytes).unwrap();
        assert_eq!(sync.clip_id, 42);
        assert_eq!(sync.mime_kind, CLIP_MIME_TEXT_UTF8);
        assert_eq!(sync.origin_nonce, 1234605616436508552);
        assert_eq!(sync.total_len, 26);
        assert_eq!(sync.total_chunks, 1);
        assert_eq!(sync.encode().unwrap().as_slice(), sync_bytes.as_slice());
        let l4_sync = encode_l4_frame(
            &L4Header {
                msg_type: CLIP_MSG_SYNC,
                flags: 0,
                body_len: sync_bytes.len() as u16,
                stream_seq: 1,
            },
            &sync_bytes,
        )
        .unwrap();
        assert_eq!(hex::encode(&l4_sync), cb["clip_sync"]["l4_frame_hex"].as_str().unwrap());

        // CLIP_CHUNK exact bytes + L4 frame
        let chunk_bytes = hex::decode(cb["clip_chunk"]["body_hex"].as_str().unwrap()).unwrap();
        let chunk = ClipChunk::decode(&chunk_bytes).unwrap();
        assert_eq!(chunk.clip_id, 42);
        assert_eq!(chunk.chunk_seq, 0);
        assert_eq!(chunk.payload, cb["payload_utf8"].as_str().unwrap().as_bytes());
        assert_eq!(chunk.encode().unwrap(), chunk_bytes);
        let l4_chunk = encode_l4_frame(
            &L4Header {
                msg_type: CLIP_MSG_CHUNK,
                flags: 0,
                body_len: chunk_bytes.len() as u16,
                stream_seq: 2,
            },
            &chunk_bytes,
        )
        .unwrap();
        assert_eq!(hex::encode(&l4_chunk), cb["clip_chunk"]["l4_frame_hex"].as_str().unwrap());

        // CLIP_ACK exact bytes + L4 frame
        let ack_bytes = hex::decode(cb["clip_ack"]["body_hex"].as_str().unwrap()).unwrap();
        let ack = ClipAck::decode(&ack_bytes).unwrap();
        assert_eq!(ack.clip_id, 42);
        assert_eq!(ack.status, CLIP_ACK_OK);
        assert_eq!(ack.encode().unwrap().as_slice(), ack_bytes.as_slice());
        let l4_ack = encode_l4_frame(
            &L4Header {
                msg_type: CLIP_MSG_ACK,
                flags: 0,
                body_len: ack_bytes.len() as u16,
                stream_seq: 3,
            },
            &ack_bytes,
        )
        .unwrap();
        assert_eq!(hex::encode(&l4_ack), cb["clip_ack"]["l4_frame_hex"].as_str().unwrap());

        // All V27 negative wire cases -> 0x0103 INVALID_FRAMING
        for case in cb["negative_wire_cases"].as_array().unwrap() {
            let name = case["case"].as_str().unwrap();
            let msg_type = case["msg_type"].as_u64().unwrap() as u8;
            let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            let hdr = L4Header {
                msg_type,
                flags: 0,
                body_len: body.len() as u16,
                stream_seq: 1,
            };
            let err = decode_clipboard_l4(&hdr, &body).unwrap_err();
            assert!(
                matches!(
                    err,
                    ClipboardError::InvalidFraming {
                        error_code: CLIP_ERROR_INVALID_FRAMING,
                        ..
                    }
                ),
                "case '{name}' expected 0x0103, got {err:?}"
            );
        }

        // Unknown msg_type -> CLIP_ACK(0, 5 UNSUPPORTED), NO session close, NO error counter bump!
        let unk_l4 = hex::decode(cb["unknown_msg_type_l4_hex"].as_str().unwrap()).unwrap();
        let (unk_hdr, unk_body) = decode_l4_frame(&unk_l4).unwrap();
        let mut rx = ClipboardReceiver::new(policy_with(POLICY_FLAG_ALLOW_CLIPBOARD, 256));
        let mut err_cnt = ChannelFramingErrorCounter::new();
        let act = rx.on_l4_frame(&unk_hdr, unk_body, Instant::now(), &mut err_cnt);
        assert_eq!(
            act,
            ClipboardRecvAction::SendAck(ClipAck {
                clip_id: 0,
                status: CLIP_ACK_UNSUPPORTED
            })
        );
        assert_eq!(
            hex::encode(
                ClipAck {
                    clip_id: 0,
                    status: CLIP_ACK_UNSUPPORTED
                }
                .encode()
                .unwrap()
            ),
            cb["expected_unsupported_ack_hex"].as_str().unwrap()
        );
        assert_eq!(err_cnt.consecutive(), 0);

        // PNG IHDR bomb guard
        let png = &cb["png_ihdr_cases"];
        assert_eq!(
            validate_png_ihdr(&hex::decode(png["valid_1920x1080_hex"].as_str().unwrap()).unwrap())
                .unwrap(),
            (1920, 1080)
        );
        assert!(validate_png_ihdr(
            &hex::decode(png["invalid_dim_8193x100_hex"].as_str().unwrap()).unwrap()
        )
        .is_err());
        assert!(validate_png_ihdr(
            &hex::decode(png["invalid_pixels_6000x6000_hex"].as_str().unwrap()).unwrap()
        )
        .is_err());
    }

    #[test]
    fn clipboard_multi_chunk_policy_gate_mime3_order_timeout_and_aba_anti_echo() {
        // 1. Multi-chunk UTF-8 transfer (> 1024B) succeeds end-to-end
        let pol_allow = policy_with(POLICY_FLAG_ALLOW_CLIPBOARD, 256);
        let payload = "ZeroDesk-v1.2.4-UTF8-中文-".repeat(120);
        let outbound =
            prepare_outbound_clipboard(&pol_allow, CLIP_MIME_TEXT_UTF8, payload.as_bytes(), 7, 99, false)
                .unwrap();
        assert!(outbound.chunks.len() >= 3);

        let mut rx = ClipboardReceiver::new(pol_allow.clone());
        let mut err_cnt = ChannelFramingErrorCounter::new();
        let now = Instant::now();
        let sync_wire = outbound.sync.encode().unwrap();
        let sync_act = rx.on_l4_frame(
            &L4Header {
                msg_type: CLIP_MSG_SYNC,
                flags: 0,
                body_len: sync_wire.len() as u16,
                stream_seq: 1,
            },
            &sync_wire,
            now,
            &mut err_cnt,
        );
        assert_eq!(sync_act, ClipboardRecvAction::None);

        // Concurrent second CLIP_SYNC while in-flight -> RATE_LIMITED (status 4)
        let mut sync2 = outbound.sync.clone();
        sync2.clip_id = 8;
        let sync2_wire = sync2.encode().unwrap();
        assert_eq!(
            rx.on_l4_frame(
                &L4Header {
                    msg_type: CLIP_MSG_SYNC,
                    flags: 0,
                    body_len: sync2_wire.len() as u16,
                    stream_seq: 2,
                },
                &sync2_wire,
                now,
                &mut err_cnt,
            ),
            ClipboardRecvAction::SendAck(ClipAck {
                clip_id: 8,
                status: CLIP_ACK_RATE_LIMITED
            })
        );

        let mut delivered = None;
        for (i, ch) in outbound.chunks.iter().enumerate() {
            let cw = ch.encode().unwrap();
            let act = rx.on_l4_frame(
                &L4Header {
                    msg_type: CLIP_MSG_CHUNK,
                    flags: 0,
                    body_len: cw.len() as u16,
                    stream_seq: (i + 3) as u32,
                },
                &cw,
                now,
                &mut err_cnt,
            );
            if i + 1 < outbound.chunks.len() {
                assert_eq!(act, ClipboardRecvAction::None);
            } else if let ClipboardRecvAction::DeliverAndAck { delivered: d, ack } = act {
                assert_eq!(ack.status, CLIP_ACK_OK);
                delivered = Some(d);
            } else {
                panic!("expected DeliverAndAck on final chunk, got {act:?}");
            }
        }
        let d = delivered.unwrap();
        assert_eq!(d.payload, payload.as_bytes());

        // 2. Anti-echo state machine: A -> B -> A MUST NOT suppress second A
        let hash_a: [u8; 32] = Sha256::digest(b"content-A").into();
        let hash_b: [u8; 32] = Sha256::digest(b"content-B").into();
        let mut guard = ClipboardAntiEchoGuard::new();
        guard.on_remote_applied(hash_a);
        assert!(!guard.should_sync_local(hash_a)); // echo suppressed
        assert!(guard.should_sync_local(hash_b));  // local change B clears guard
        assert!(guard.should_sync_local(hash_a));  // A -> B -> A is NOT suppressed!

        // 3. mime_kind=3 deterministic order: policy checked FIRST, then UNSUPPORTED
        let pol_no_file_clip = policy_with(POLICY_FLAG_ALLOW_CLIPBOARD, 256);
        assert_eq!(
            check_clipboard_policy_for_sync(&pol_no_file_clip, CLIP_MIME_FILE_URI_LIST, 32),
            Err(CLIP_ACK_POLICY_DENIED)
        );
        let pol_with_file_clip =
            policy_with(POLICY_FLAG_ALLOW_CLIPBOARD | POLICY_FLAG_ALLOW_FILE_CLIPBOARD, 256);
        assert_eq!(
            check_clipboard_policy_for_sync(&pol_with_file_clip, CLIP_MIME_FILE_URI_LIST, 32),
            Err(CLIP_ACK_UNSUPPORTED)
        );

        // 4. 10s reassembly timeout clears in-flight and returns CLIP_ACK_TIMEOUT
        let mut rx_to = ClipboardReceiver::new(pol_allow);
        let _ = rx_to.on_l4_frame(
            &L4Header {
                msg_type: CLIP_MSG_SYNC,
                flags: 0,
                body_len: sync_wire.len() as u16,
                stream_seq: 1,
            },
            &sync_wire,
            now,
            &mut err_cnt,
        );
        assert!(rx_to.has_in_flight());
        assert_eq!(
            rx_to.poll_timeout(now + Duration::from_secs(10)),
            Some(ClipAck {
                clip_id: 7,
                status: CLIP_ACK_TIMEOUT
            })
        );
        assert!(!rx_to.has_in_flight());

        // 5. Paused on Survival Mode / PAUSE_FILE_CHUNK
        let pol_ok = policy_with(POLICY_FLAG_ALLOW_CLIPBOARD, 256);
        assert_eq!(
            prepare_outbound_clipboard(&pol_ok, CLIP_MIME_TEXT_UTF8, b"hi", 1, 1, true).unwrap_err(),
            ClipboardError::BulkPaused
        );
    }
}
