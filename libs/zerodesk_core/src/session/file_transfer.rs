// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `0x05 FileTransfer` (`p3` reliable ordered, push-only) normative binary wire protocol
//! (`spec/04` §8, `v1.2.4` & `V27`), strict filename sanitization, Unix `statvfs` disk pre-check,
//! non-overwriting atomic save (`O_NOFOLLOW | O_CREAT | O_EXCL` `0600` -> `sync_all` ->
//! `hard_link` + `unlink` with `(1)..(999)` collision suffix `<= 255B` -> parent-dir `fsync`),
//! streaming SHA-256 verification, absolute credit window sender, and audit logging.

use super::{
    clipboard::ChannelFramingErrorCounter,
    config::sync_parent_dir,
    policy::EffectiveTenantPolicy,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fmt,
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use v2_transport::L4Header;

pub const FILE_MSG_OFFER: u8 = 0x01;
pub const FILE_MSG_ACCEPT: u8 = 0x02;
pub const FILE_MSG_CHUNK: u8 = 0x03;
pub const FILE_MSG_ACK: u8 = 0x04;
pub const FILE_MSG_COMPLETE: u8 = 0x05;
pub const FILE_MSG_ABORT: u8 = 0x06;
pub const FILE_MSG_COMPLETE_ACK: u8 = 0x07;

pub const FILE_COMPLETE_ACK_OK: u8 = 0;
pub const FILE_COMPLETE_ACK_HASH_MISMATCH: u8 = 1;
pub const FILE_COMPLETE_ACK_IO_ERROR: u8 = 2;

pub const FILE_OFFER_FIXED_LEN: usize = 54;
pub const FILE_ACCEPT_WIRE_LEN: usize = 24;
pub const FILE_CHUNK_HDR_LEN: usize = 16;
pub const FILE_ACK_WIRE_LEN: usize = 24;
pub const FILE_COMPLETE_WIRE_LEN: usize = 40;
pub const FILE_ABORT_WIRE_LEN: usize = 10;
pub const FILE_COMPLETE_ACK_WIRE_LEN: usize = 9;

pub const FILE_CHUNK_MIN_SIZE: u32 = 1;
pub const FILE_CHUNK_MAX_SIZE: u32 = 32_768;
pub const FILE_RECOMMENDED_CHUNK_SIZE: u32 = 1_024;
pub const FILE_DEFAULT_WINDOW_BYTES: u64 = 262_144;
pub const FILE_MAX_CONCURRENT_PER_DIR: usize = 2;
pub const FILE_STALL_TIMEOUT: Duration = Duration::from_secs(30);
pub const FILE_NAME_MAX_BYTES: usize = 255;
pub const FILE_COLLISION_MAX_RETRIES: u32 = 999;

pub const FILE_ERR_OK: u16 = 0x0000;
pub const FILE_ERR_INVALID_FRAMING: u16 = 0x0103;
pub const FILE_ERR_POLICY_DENIED: u16 = 0x0401;
pub const FILE_ERR_AUDIT_UNAVAILABLE: u16 = 0x0402;
pub const FILE_ERR_PATH_FAILED: u16 = 0x0502;
pub const FILE_ERR_RATE_LIMITED: u16 = 0x0503;

static TMP_FILE_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileTransferError {
    InvalidFraming { error_code: u16, reason: String },
    PolicyDenied(String),
    RateLimited,
    InvalidFilename(String),
    InsufficientDiskSpace { required: u64, available: u64 },
    Io(String),
    BulkPaused,
}

impl fmt::Display for FileTransferError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFraming { error_code, reason } => {
                write!(f, "file transfer framing error ({error_code:#06x}): {reason}")
            }
            Self::PolicyDenied(msg) => write!(f, "file transfer denied by policy: {msg}"),
            Self::RateLimited => {
                write!(f, "file transfer concurrency limit ({FILE_MAX_CONCURRENT_PER_DIR}) exceeded")
            }
            Self::InvalidFilename(msg) => write!(f, "unsafe filename rejected: {msg}"),
            Self::InsufficientDiskSpace {
                required,
                available,
            } => write!(
                f,
                "insufficient disk space: need {required} bytes, available {available} bytes"
            ),
            Self::Io(msg) => write!(f, "file transfer I/O error: {msg}"),
            Self::BulkPaused => write!(f, "file transfer paused by Survival Mode / PAUSE_FILE_CHUNK"),
        }
    }
}

impl std::error::Error for FileTransferError {}

/// Strict `spec/04` §8.3 filename sanitizer (Fail-Closed).
pub fn validate_safe_filename(name_bytes: &[u8]) -> Result<String, FileTransferError> {
    if name_bytes.is_empty() || name_bytes.len() > FILE_NAME_MAX_BYTES {
        return Err(FileTransferError::InvalidFilename(format!(
            "filename byte length {} outside 1..={FILE_NAME_MAX_BYTES}",
            name_bytes.len()
        )));
    }
    let name = std::str::from_utf8(name_bytes)
        .map_err(|_| FileTransferError::InvalidFilename("filename is not valid UTF-8".into()))?;

    if name.starts_with('.') {
        return Err(FileTransferError::InvalidFilename(
            "filename must not start with '.'".into(),
        ));
    }
    if name.ends_with('.') || name.ends_with(' ') {
        return Err(FileTransferError::InvalidFilename(
            "filename must not end with '.' or space".into(),
        ));
    }
    if name.contains("..") {
        return Err(FileTransferError::InvalidFilename(
            "filename must not contain '..'".into(),
        ));
    }

    for ch in name.chars() {
        let cp = ch as u32;
        if cp < 0x20 || cp == 0x7F {
            return Err(FileTransferError::InvalidFilename(format!(
                "filename contains control character U+{cp:04X}"
            )));
        }
        if matches!(ch, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|') {
            return Err(FileTransferError::InvalidFilename(format!(
                "filename contains forbidden character '{ch}'"
            )));
        }
        // BiDi override & isolate controls + zero-width / BOM characters
        if (0x202A..=0x202E).contains(&cp)
            || (0x2066..=0x2069).contains(&cp)
            || (0x200B..=0x200D).contains(&cp)
            || cp == 0xFEFF
        {
            return Err(FileTransferError::InvalidFilename(format!(
                "filename contains forbidden BiDi/zero-width character U+{cp:04X}"
            )));
        }
    }

    // Windows reserved device names (stem before first '.', trimming trailing spaces, ASCII CI)
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    let upper = stem.to_ascii_uppercase();
    let is_windows_reserved = matches!(
        upper.as_str(),
        "CON"
            | "PRN"
            | "AUX"
            | "NUL"
            | "CONIN$"
            | "CONOUT$"
            | "COM1"
            | "COM2"
            | "COM3"
            | "COM4"
            | "COM5"
            | "COM6"
            | "COM7"
            | "COM8"
            | "COM9"
            | "LPT1"
            | "LPT2"
            | "LPT3"
            | "LPT4"
            | "LPT5"
            | "LPT6"
            | "LPT7"
            | "LPT8"
            | "LPT9"
    );
    if is_windows_reserved {
        return Err(FileTransferError::InvalidFilename(format!(
            "filename stem '{stem}' is a Windows reserved device name"
        )));
    }

    Ok(name.to_string())
}

/// Builds collision-suffixed filename inserting `({attempt})` before the extension while
/// keeping total UTF-8 byte length strictly `<= 255` on valid UTF-8 character boundaries.
pub fn build_collision_filename(base_name: &str, attempt: u32) -> String {
    let suffix = format!("({attempt})");
    let (stem, ext) = match base_name.rfind('.') {
        Some(dot) if dot > 0 => (&base_name[..dot], &base_name[dot..]),
        _ => (base_name, ""),
    };
    let reserved = suffix.len().saturating_add(ext.len());
    if reserved >= FILE_NAME_MAX_BYTES {
        // Pathological extension alone >= 255B cannot occur after validate_safe_filename,
        // fallback cleanly by truncating the whole base_name before suffix.
        let max_stem = FILE_NAME_MAX_BYTES.saturating_sub(suffix.len());
        let trunc = truncate_utf8_bytes(base_name, max_stem);
        return format!("{trunc}{suffix}");
    }
    let max_stem = FILE_NAME_MAX_BYTES - reserved;
    let trunc_stem = truncate_utf8_bytes(stem, max_stem);
    format!("{trunc_stem}{suffix}{ext}")
}

fn truncate_utf8_bytes(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

/// Checks free disk space on Unix via `statvfs` before accepting a non-empty file.
pub fn check_disk_space_for_file(dir: &Path, file_size: u64) -> Result<(), FileTransferError> {
    if file_size == 0 {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;
        let c_path = CString::new(dir.as_os_str().as_bytes()).map_err(|_| {
            FileTransferError::Io("download directory path contains interior NUL".into())
        })?;
        let mut st: libc::statvfs = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::statvfs(c_path.as_ptr(), &mut st) };
        if rc != 0 {
            return Err(FileTransferError::Io(format!(
                "statvfs('{}') failed: {}",
                dir.display(),
                io::Error::last_os_error()
            )));
        }
        let block_size = if st.f_frsize > 0 {
            st.f_frsize as u64
        } else {
            st.f_bsize as u64
        };
        let available = (st.f_bavail as u64).saturating_mul(block_size);
        if available < file_size {
            return Err(FileTransferError::InsufficientDiskSpace {
                required: file_size,
                available,
            });
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = (dir, file_size);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOffer {
    pub transfer_id: u64,
    pub file_size: u64,
    pub chunk_size: u32,
    pub sha256: [u8; 32],
    pub rel_name: String,
}

impl FileOffer {
    pub fn encode(&self) -> Result<Vec<u8>, FileTransferError> {
        if !(FILE_CHUNK_MIN_SIZE..=FILE_CHUNK_MAX_SIZE).contains(&self.chunk_size) {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!("FILE_OFFER chunk_size={} outside 1..=32768", self.chunk_size),
            });
        }
        let _ = validate_safe_filename(self.rel_name.as_bytes())?;
        let name_bytes = self.rel_name.as_bytes();
        let name_len = u16::try_from(name_bytes.len()).map_err(|_| {
            FileTransferError::InvalidFilename("filename exceeds u16::MAX".into())
        })?;
        let mut out = Vec::with_capacity(FILE_OFFER_FIXED_LEN + name_bytes.len());
        out.extend_from_slice(&self.transfer_id.to_be_bytes());
        out.extend_from_slice(&self.file_size.to_be_bytes());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        out.extend_from_slice(&self.sha256);
        out.extend_from_slice(&name_len.to_be_bytes());
        out.extend_from_slice(name_bytes);
        Ok(out)
    }

    /// Decodes wire bytes strictly validating framing length. Note: invalid `chunk_size` or
    /// unsafe filename returns `FileOfferDecodeOutcome::TransferInvalid` so the receiver can
    /// emit single-transfer `FILE_ABORT(transfer_id, 0x0103)` per `spec/04` §8.4, while
    /// truncated/trailing framing returns `Err(InvalidFraming)` (session-fatal).
    pub fn decode_raw(bytes: &[u8]) -> Result<FileOfferRaw, FileTransferError> {
        if bytes.len() < FILE_OFFER_FIXED_LEN {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_OFFER truncated: {}B < {FILE_OFFER_FIXED_LEN}B",
                    bytes.len()
                ),
            });
        }
        let transfer_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let file_size = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let chunk_size = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&bytes[20..52]);
        let name_len = u16::from_be_bytes([bytes[52], bytes[53]]) as usize;
        if bytes.len() != FILE_OFFER_FIXED_LEN + name_len {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_OFFER body len {} != 54 + name_len({})",
                    bytes.len(),
                    name_len
                ),
            });
        }
        Ok(FileOfferRaw {
            transfer_id,
            file_size,
            chunk_size,
            sha256,
            raw_name: bytes[FILE_OFFER_FIXED_LEN..].to_vec(),
        })
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FileTransferError> {
        let raw = Self::decode_raw(bytes)?;
        raw.validate()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileOfferRaw {
    pub transfer_id: u64,
    pub file_size: u64,
    pub chunk_size: u32,
    pub sha256: [u8; 32],
    pub raw_name: Vec<u8>,
}

impl FileOfferRaw {
    pub fn validate(self) -> Result<FileOffer, FileTransferError> {
        if !(FILE_CHUNK_MIN_SIZE..=FILE_CHUNK_MAX_SIZE).contains(&self.chunk_size) {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!("FILE_OFFER chunk_size={} outside 1..=32768", self.chunk_size),
            });
        }
        let rel_name = validate_safe_filename(&self.raw_name)?;
        Ok(FileOffer {
            transfer_id: self.transfer_id,
            file_size: self.file_size,
            chunk_size: self.chunk_size,
            sha256: self.sha256,
            rel_name,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAccept {
    pub transfer_id: u64,
    pub resume_offset: u64,
    pub initial_window_end_offset: u64,
}

impl FileAccept {
    pub fn encode(&self) -> Result<[u8; FILE_ACCEPT_WIRE_LEN], FileTransferError> {
        if self.resume_offset != 0 {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: "v1.2.4 FILE_ACCEPT resume_offset must be 0".into(),
            });
        }
        let mut out = [0u8; FILE_ACCEPT_WIRE_LEN];
        out[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        out[8..16].copy_from_slice(&self.resume_offset.to_be_bytes());
        out[16..24].copy_from_slice(&self.initial_window_end_offset.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FileTransferError> {
        if bytes.len() != FILE_ACCEPT_WIRE_LEN {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ACCEPT must be exact {FILE_ACCEPT_WIRE_LEN}B, got {}B",
                    bytes.len()
                ),
            });
        }
        let transfer_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let resume_offset = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        if resume_offset != 0 {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!("FILE_ACCEPT resume_offset={resume_offset} must be 0 in v1.2.4"),
            });
        }
        let initial_window_end_offset = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        Ok(Self {
            transfer_id,
            resume_offset,
            initial_window_end_offset,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileChunk {
    pub transfer_id: u64,
    pub offset: u64,
    pub data: Vec<u8>,
}

impl FileChunk {
    pub fn encode(&self) -> Result<Vec<u8>, FileTransferError> {
        if self.data.is_empty() || self.data.len() > FILE_CHUNK_MAX_SIZE as usize {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_CHUNK data len {} outside 1..={FILE_CHUNK_MAX_SIZE}",
                    self.data.len()
                ),
            });
        }
        let mut out = Vec::with_capacity(FILE_CHUNK_HDR_LEN + self.data.len());
        out.extend_from_slice(&self.transfer_id.to_be_bytes());
        out.extend_from_slice(&self.offset.to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FileTransferError> {
        if bytes.len() <= FILE_CHUNK_HDR_LEN
            || bytes.len() > FILE_CHUNK_HDR_LEN + FILE_CHUNK_MAX_SIZE as usize
        {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!("FILE_CHUNK wire len {} out of bounds", bytes.len()),
            });
        }
        let transfer_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let offset = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        Ok(Self {
            transfer_id,
            offset,
            data: bytes[FILE_CHUNK_HDR_LEN..].to_vec(),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAck {
    pub transfer_id: u64,
    pub next_expected_offset: u64,
    pub window_end_offset: u64,
}

impl FileAck {
    pub fn encode(&self) -> Result<[u8; FILE_ACK_WIRE_LEN], FileTransferError> {
        if self.window_end_offset < self.next_expected_offset {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ACK window_end_offset({}) < next_expected_offset({})",
                    self.window_end_offset, self.next_expected_offset
                ),
            });
        }
        let mut out = [0u8; FILE_ACK_WIRE_LEN];
        out[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        out[8..16].copy_from_slice(&self.next_expected_offset.to_be_bytes());
        out[16..24].copy_from_slice(&self.window_end_offset.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FileTransferError> {
        if bytes.len() != FILE_ACK_WIRE_LEN {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ACK must be exact {FILE_ACK_WIRE_LEN}B, got {}B",
                    bytes.len()
                ),
            });
        }
        let transfer_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let next_expected_offset = u64::from_be_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let window_end_offset = u64::from_be_bytes([
            bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        ]);
        if window_end_offset < next_expected_offset {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ACK window_end_offset({window_end_offset}) < next_expected_offset({next_expected_offset})"
                ),
            });
        }
        Ok(Self {
            transfer_id,
            next_expected_offset,
            window_end_offset,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileComplete {
    pub transfer_id: u64,
    pub sha256: [u8; 32],
}

impl FileComplete {
    pub fn encode(&self) -> [u8; FILE_COMPLETE_WIRE_LEN] {
        let mut out = [0u8; FILE_COMPLETE_WIRE_LEN];
        out[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        out[8..40].copy_from_slice(&self.sha256);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FileTransferError> {
        if bytes.len() != FILE_COMPLETE_WIRE_LEN {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_COMPLETE must be exact {FILE_COMPLETE_WIRE_LEN}B, got {}B",
                    bytes.len()
                ),
            });
        }
        let transfer_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&bytes[8..40]);
        Ok(Self {
            transfer_id,
            sha256,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileAbort {
    pub transfer_id: u64,
    pub error_code: u16,
}

impl FileAbort {
    pub fn encode(&self) -> [u8; FILE_ABORT_WIRE_LEN] {
        let mut out = [0u8; FILE_ABORT_WIRE_LEN];
        out[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        out[8..10].copy_from_slice(&self.error_code.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FileTransferError> {
        if bytes.len() != FILE_ABORT_WIRE_LEN {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ABORT must be exact {FILE_ABORT_WIRE_LEN}B, got {}B",
                    bytes.len()
                ),
            });
        }
        let transfer_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let error_code = u16::from_be_bytes([bytes[8], bytes[9]]);
        Ok(Self {
            transfer_id,
            error_code,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileCompleteAck {
    pub transfer_id: u64,
    pub status: u8,
}

impl FileCompleteAck {
    pub fn encode(&self) -> Result<[u8; FILE_COMPLETE_ACK_WIRE_LEN], FileTransferError> {
        if self.status > FILE_COMPLETE_ACK_IO_ERROR {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!("invalid FILE_COMPLETE_ACK status={}", self.status),
            });
        }
        let mut out = [0u8; FILE_COMPLETE_ACK_WIRE_LEN];
        out[0..8].copy_from_slice(&self.transfer_id.to_be_bytes());
        out[8] = self.status;
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, FileTransferError> {
        if bytes.len() != FILE_COMPLETE_ACK_WIRE_LEN {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_COMPLETE_ACK must be exact {FILE_COMPLETE_ACK_WIRE_LEN}B, got {}B",
                    bytes.len()
                ),
            });
        }
        let transfer_id = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        let status = bytes[8];
        if status > FILE_COMPLETE_ACK_IO_ERROR {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!("invalid FILE_COMPLETE_ACK status={status} (allowed 0..=2)"),
            });
        }
        Ok(Self {
            transfer_id,
            status,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileMessage {
    OfferRaw(FileOfferRaw),
    Accept(FileAccept),
    Chunk(FileChunk),
    Ack(FileAck),
    Complete(FileComplete),
    Abort(FileAbort),
    CompleteAck(FileCompleteAck),
}

/// Decodes a `0x05 FileTransfer` L4 frame strictly checking `L4Header.flags == 0`, exact `body_len`,
/// and rejecting any unknown `msg_type` (`spec/04` §8.1 & §8.4).
pub fn decode_file_l4(l4_hdr: &L4Header, body: &[u8]) -> Result<FileMessage, FileTransferError> {
    if l4_hdr.flags != 0 {
        return Err(FileTransferError::InvalidFraming {
            error_code: FILE_ERR_INVALID_FRAMING,
            reason: format!(
                "0x05 FileTransfer L4Header.flags must be 0, got {:#x}",
                l4_hdr.flags
            ),
        });
    }
    if usize::from(l4_hdr.body_len) != body.len() {
        return Err(FileTransferError::InvalidFraming {
            error_code: FILE_ERR_INVALID_FRAMING,
            reason: format!(
                "0x05 FileTransfer L4Header.body_len={} != actual body len {}",
                l4_hdr.body_len,
                body.len()
            ),
        });
    }
    match l4_hdr.msg_type {
        FILE_MSG_OFFER => Ok(FileMessage::OfferRaw(FileOffer::decode_raw(body)?)),
        FILE_MSG_ACCEPT => Ok(FileMessage::Accept(FileAccept::decode(body)?)),
        FILE_MSG_CHUNK => Ok(FileMessage::Chunk(FileChunk::decode(body)?)),
        FILE_MSG_ACK => Ok(FileMessage::Ack(FileAck::decode(body)?)),
        FILE_MSG_COMPLETE => Ok(FileMessage::Complete(FileComplete::decode(body)?)),
        FILE_MSG_ABORT => Ok(FileMessage::Abort(FileAbort::decode(body)?)),
        FILE_MSG_COMPLETE_ACK => Ok(FileMessage::CompleteAck(FileCompleteAck::decode(body)?)),
        other => Err(FileTransferError::InvalidFraming {
            error_code: FILE_ERR_INVALID_FRAMING,
            reason: format!("unknown 0x05 FileTransfer msg_type={other:#04x}"),
        }),
    }
}

/// Checks local verified tenant policy for `0x05 FileTransfer` (`spec/04` §8.1).
pub fn check_file_policy(
    policy: &EffectiveTenantPolicy,
    file_size: u64,
) -> Result<(), FileTransferError> {
    if !policy.allow_file_transfer() || policy.max_file_bytes() == 0 {
        return Err(FileTransferError::PolicyDenied(
            "tenant policy disables 0x05 FileTransfer (or max_file_mb == 0)".into(),
        ));
    }
    let limit = policy.max_file_bytes();
    if file_size > limit {
        return Err(FileTransferError::PolicyDenied(format!(
            "file_size {file_size}B exceeds tenant max_file_bytes {limit}B"
        )));
    }
    Ok(())
}

/// Audit record emitted for completed/aborted file transfers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileTransferAuditRecord {
    pub direction: String,
    pub transfer_id: u64,
    pub rel_name: String,
    pub file_size: u64,
    pub sha256_hex: String,
    pub final_path: Option<String>,
    pub outcome: String,
    pub error_code: u16,
}

/// Sender-side absolute credit window state machine (`spec/04` §8.2.4).
#[derive(Debug, Clone)]
pub struct FileSenderWindow {
    pub transfer_id: u64,
    pub file_size: u64,
    pub chunk_size: u32,
    pub sha256: [u8; 32],
    pub rel_name: String,
    accepted: bool,
    max_sent_offset: u64,
    next_expected_offset: u64,
    window_end_offset: u64,
    last_progress_at: Instant,
    complete_sent: bool,
}

impl FileSenderWindow {
    pub fn new(
        policy: &EffectiveTenantPolicy,
        transfer_id: u64,
        rel_name: &str,
        file_size: u64,
        chunk_size: u32,
        sha256: [u8; 32],
        now: Instant,
    ) -> Result<(Self, FileOffer), FileTransferError> {
        check_file_policy(policy, file_size)?;
        let safe_name = validate_safe_filename(rel_name.as_bytes())?;
        if !(FILE_CHUNK_MIN_SIZE..=FILE_CHUNK_MAX_SIZE).contains(&chunk_size) {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!("chunk_size {chunk_size} outside 1..=32768"),
            });
        }
        let offer = FileOffer {
            transfer_id,
            file_size,
            chunk_size,
            sha256,
            rel_name: safe_name.clone(),
        };
        Ok((
            Self {
                transfer_id,
                file_size,
                chunk_size,
                sha256,
                rel_name: safe_name,
                accepted: false,
                max_sent_offset: 0,
                next_expected_offset: 0,
                window_end_offset: 0,
                last_progress_at: now,
                complete_sent: false,
            },
            offer,
        ))
    }

    pub fn on_accept(
        &mut self,
        accept: &FileAccept,
        now: Instant,
    ) -> Result<(), FileTransferError> {
        if self.accepted {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: "duplicate FILE_ACCEPT rejected".into(),
            });
        }
        if accept.transfer_id != self.transfer_id {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: "FILE_ACCEPT transfer_id mismatch".into(),
            });
        }
        if accept.resume_offset > self.file_size {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ACCEPT resume_offset({}) > file_size({})",
                    accept.resume_offset, self.file_size
                ),
            });
        }
        if accept.initial_window_end_offset > self.file_size
            || accept.initial_window_end_offset < accept.resume_offset
            || (accept.resume_offset < self.file_size
                && accept.initial_window_end_offset == accept.resume_offset)
        {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ACCEPT initial_window_end_offset={} invalid for resume_offset={} file_size={}",
                    accept.initial_window_end_offset, accept.resume_offset, self.file_size
                ),
            });
        }
        self.accepted = true;
        self.max_sent_offset = accept.resume_offset;
        self.next_expected_offset = accept.resume_offset;
        self.window_end_offset = accept.initial_window_end_offset;
        self.last_progress_at = now;
        Ok(())
    }

    /// Processes an incoming `FILE_ACK`, enforcing:
    /// - `transfer_id` match
    /// - `next_expected_offset <= max_sent_offset`
    /// - `window_end_offset <= file_size`
    /// - monotonic non-decreasing `next_expected_offset` and `window_end_offset`
    /// - idempotency on duplicate identical `FILE_ACK` (zero window inflation!).
    pub fn on_ack(&mut self, ack: &FileAck, now: Instant) -> Result<(), FileTransferError> {
        if !self.accepted || ack.transfer_id != self.transfer_id {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: "FILE_ACK transfer_id mismatch or transfer not accepted".into(),
            });
        }
        if ack.next_expected_offset > self.max_sent_offset {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ACK next_expected_offset({}) > max_sent_offset({})",
                    ack.next_expected_offset, self.max_sent_offset
                ),
            });
        }
        if ack.window_end_offset > self.file_size {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: format!(
                    "FILE_ACK window_end_offset({}) > file_size({})",
                    ack.window_end_offset, self.file_size
                ),
            });
        }
        if ack.window_end_offset < ack.next_expected_offset {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: "FILE_ACK window_end_offset < next_expected_offset".into(),
            });
        }
        if ack.next_expected_offset < self.next_expected_offset
            || ack.window_end_offset < self.window_end_offset
        {
            return Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                reason: "FILE_ACK offset/window regression detected".into(),
            });
        }
        if ack.next_expected_offset > self.next_expected_offset
            || ack.window_end_offset > self.window_end_offset
        {
            self.last_progress_at = now;
        }
        self.next_expected_offset = ack.next_expected_offset;
        self.window_end_offset = ack.window_end_offset;
        Ok(())
    }

    /// Returns the next `(offset, len)` byte slice permitted to send under the current absolute
    /// credit window, or `None` when paused (`bulk_paused == true`), unaccepted, or window full.
    pub fn next_chunk_range(&self, bulk_paused: bool) -> Option<(u64, usize)> {
        if bulk_paused || !self.accepted || self.max_sent_offset >= self.file_size {
            return None;
        }
        if self.max_sent_offset >= self.window_end_offset {
            return None;
        }
        let avail = self
            .window_end_offset
            .saturating_sub(self.max_sent_offset)
            .min(u64::from(self.chunk_size));
        if avail == 0 {
            None
        } else {
            Some((self.max_sent_offset, avail as usize))
        }
    }

    pub fn mark_chunk_sent(&mut self, offset: u64, len: usize, now: Instant) {
        let end = offset.saturating_add(len as u64);
        if end > self.max_sent_offset {
            self.max_sent_offset = end;
            self.last_progress_at = now;
        }
    }

    pub fn ready_for_complete(&self) -> bool {
        self.accepted && !self.complete_sent && self.next_expected_offset == self.file_size
    }

    pub fn peek_complete(&self) -> FileComplete {
        FileComplete {
            transfer_id: self.transfer_id,
            sha256: self.sha256,
        }
    }

    pub fn commit_complete(&mut self, now: Instant) {
        self.complete_sent = true;
        self.last_progress_at = now;
    }

    pub fn build_complete(&mut self, now: Instant) -> FileComplete {
        self.commit_complete(now);
        self.peek_complete()
    }

    pub fn is_stalled(&self, now: Instant) -> bool {
        now.saturating_duration_since(self.last_progress_at) >= FILE_STALL_TIMEOUT
    }

    pub fn window_end_offset(&self) -> u64 {
        self.window_end_offset
    }

    pub fn max_sent_offset(&self) -> u64 {
        self.max_sent_offset
    }

    pub fn next_expected_offset(&self) -> u64 {
        self.next_expected_offset
    }
}

struct ActiveInboundTransfer {
    offer: FileOffer,
    tmp_path: PathBuf,
    tmp_file: Option<File>,
    hasher: Sha256,
    next_expected_offset: u64,
    window_end_offset: u64,
    last_progress_at: Instant,
}

impl Drop for ActiveInboundTransfer {
    fn drop(&mut self) {
        self.tmp_file = None;
        if self.tmp_path.exists() {
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

/// Wire reply / control action produced by `FileTransferReceiver`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileRecvAction {
    None,
    SendAccept(FileAccept),
    SendAck(FileAck),
    SendAbort(FileAbort),
    SendCompleteAck {
        ack: FileCompleteAck,
        saved_path: Option<PathBuf>,
        audit: FileTransferAuditRecord,
    },
    SessionFatal(String),
}

pub const FILE_AUDIT_LOG_CAP: usize = 1_024;

/// Push-only `0x05 FileTransfer` receiver enforcing policy, max 2 concurrent transfers,
/// 30s stall timeout, `statvfs` disk space pre-check, streaming SHA-256, and non-overwriting
/// atomic save with `(1)..(999)` collision suffix retries.
pub struct FileTransferReceiver {
    policy: EffectiveTenantPolicy,
    download_dir: PathBuf,
    window_size: u64,
    active: HashMap<u64, ActiveInboundTransfer>,
    pub audit_records: VecDeque<FileTransferAuditRecord>,
}

impl FileTransferReceiver {
    pub fn new(policy: EffectiveTenantPolicy, download_dir: PathBuf) -> Self {
        Self {
            policy,
            download_dir,
            window_size: FILE_DEFAULT_WINDOW_BYTES,
            active: HashMap::new(),
            audit_records: VecDeque::new(),
        }
    }

    fn push_audit(&mut self, record: FileTransferAuditRecord) {
        if self.audit_records.len() >= FILE_AUDIT_LOG_CAP {
            let _ = self.audit_records.pop_front();
        }
        self.audit_records.push_back(record);
    }

    pub fn with_window_size(mut self, window_size: u64) -> Self {
        self.window_size = window_size.max(1024);
        self
    }

    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    pub fn update_policy(&mut self, policy: EffectiveTenantPolicy) {
        self.policy = policy;
    }

    /// Checks 30s stall timeout across active transfers, cleaning up temp files and returning
    /// `FILE_ABORT(tid, 0x0502 PATH_FAILED)` for each stalled transfer.
    pub fn poll_stalls(&mut self, now: Instant) -> Vec<FileAbort> {
        let stalled_ids: Vec<u64> = self
            .active
            .iter()
            .filter_map(|(&tid, st)| {
                if now.saturating_duration_since(st.last_progress_at) >= FILE_STALL_TIMEOUT {
                    Some(tid)
                } else {
                    None
                }
            })
            .collect();
        let mut aborts = Vec::with_capacity(stalled_ids.len());
        for tid in stalled_ids {
            if let Some(st) = self.active.remove(&tid) {
                self.push_audit(FileTransferAuditRecord {
                    direction: "inbound".into(),
                    transfer_id: tid,
                    rel_name: st.offer.rel_name.clone(),
                    file_size: st.offer.file_size,
                    sha256_hex: hex::encode(st.offer.sha256),
                    final_path: None,
                    outcome: "stalled".into(),
                    error_code: FILE_ERR_PATH_FAILED,
                });
            }
            aborts.push(FileAbort {
                transfer_id: tid,
                error_code: FILE_ERR_PATH_FAILED,
            });
        }
        aborts
    }

    fn create_temp_file(&self, transfer_id: u64) -> Result<(PathBuf, File), FileTransferError> {
        fs::create_dir_all(&self.download_dir).map_err(|e| {
            FileTransferError::Io(format!(
                "create download dir '{}': {e}",
                self.download_dir.display()
            ))
        })?;
        let nonce = TMP_FILE_NONCE.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmp_name = format!(
            ".zd_ft_{transfer_id:016x}_{}_{nonce}_{nanos}.tmp",
            std::process::id()
        );
        let tmp_path = self.download_dir.join(tmp_name);
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
        }
        let file = opts.open(&tmp_path).map_err(|e| {
            FileTransferError::Io(format!("create temp file '{}': {e}", tmp_path.display()))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    FileTransferError::Io(format!(
                        "fchmod 0600 temp file '{}': {e}",
                        tmp_path.display()
                    ))
                })?;
        }
        Ok((tmp_path, file))
    }

    /// Non-overwriting atomic save: `sync_all` -> `hard_link` (with bounded `(1)..(999)` collision
    /// retries `<= 255B`) -> `unlink(tmp)` -> parent-dir `fsync`.
    fn finalize_atomic_non_overwriting(
        &self,
        mut st: ActiveInboundTransfer,
    ) -> Result<PathBuf, FileTransferError> {
        if let Some(mut f) = st.tmp_file.take() {
            f.flush()
                .map_err(|e| FileTransferError::Io(format!("flush temp file: {e}")))?;
            f.sync_all()
                .map_err(|e| FileTransferError::Io(format!("sync_all temp file: {e}")))?;
        }

        let mut linked_path: Option<PathBuf> = None;
        for attempt in 0..=FILE_COLLISION_MAX_RETRIES {
            let candidate_name = if attempt == 0 {
                st.offer.rel_name.clone()
            } else {
                build_collision_filename(&st.offer.rel_name, attempt)
            };
            let candidate_path = self.download_dir.join(&candidate_name);
            match fs::hard_link(&st.tmp_path, &candidate_path) {
                Ok(()) => {
                    linked_path = Some(candidate_path);
                    break;
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(FileTransferError::Io(format!(
                        "hard_link '{}' -> '{}': {e}",
                        st.tmp_path.display(),
                        candidate_path.display()
                    )));
                }
            }
        }

        let Some(final_path) = linked_path else {
            return Err(FileTransferError::Io(format!(
                "non-overwriting save exhausted {FILE_COLLISION_MAX_RETRIES} collision retries for '{}'",
                st.offer.rel_name
            )));
        };

        let _ = fs::remove_file(&st.tmp_path);
        if let Err(e) = sync_parent_dir(&final_path) {
            let unsupported_dir_sync = {
                #[cfg(unix)]
                {
                    matches!(e.raw_os_error(), Some(libc::EINVAL | libc::ENOSYS))
                        || matches!(
                            e.kind(),
                            io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
                        )
                }
                #[cfg(not(unix))]
                {
                    matches!(
                        e.kind(),
                        io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
                    )
                }
            };
            if !unsupported_dir_sync {
                let _ = fs::remove_file(&final_path);
                return Err(FileTransferError::Io(format!("fsync parent dir: {e}")));
            }
        }
        Ok(final_path)
    }

    pub fn on_l4_frame(
        &mut self,
        l4_hdr: &L4Header,
        body: &[u8],
        now: Instant,
        err_counter: &mut ChannelFramingErrorCounter,
    ) -> FileRecvAction {
        let msg = match decode_file_l4(l4_hdr, body) {
            Ok(m) => m,
            Err(e) => {
                let _ = err_counter.record_framing_error();
                return FileRecvAction::SessionFatal(e.to_string());
            }
        };

        match msg {
            FileMessage::OfferRaw(raw) => {
                let tid = raw.transfer_id;
                let file_size = raw.file_size;

                // Validate chunk_size and safe filename (transfer-level 0x0103 per spec/04 §8.4)
                let offer = match raw.validate() {
                    Ok(o) => o,
                    Err(e) => {
                        if err_counter.record_framing_error() {
                            return FileRecvAction::SessionFatal(format!(
                                "consecutive 0x0103 channel framing errors >= 3: {e}"
                            ));
                        }
                        return FileRecvAction::SendAbort(FileAbort {
                            transfer_id: tid,
                            error_code: FILE_ERR_INVALID_FRAMING,
                        });
                    }
                };

                // Policy gate (NOT counted toward consecutive 0x0103 counter!)
                if let Err(e) = check_file_policy(&self.policy, file_size) {
                    self.push_audit(FileTransferAuditRecord {
                        direction: "inbound".into(),
                        transfer_id: tid,
                        rel_name: offer.rel_name,
                        file_size,
                        sha256_hex: hex::encode(offer.sha256),
                        final_path: None,
                        outcome: format!("policy_denied: {e}"),
                        error_code: FILE_ERR_POLICY_DENIED,
                    });
                    return FileRecvAction::SendAbort(FileAbort {
                        transfer_id: tid,
                        error_code: FILE_ERR_POLICY_DENIED,
                    });
                }

                // Duplicate transfer_id or concurrency limit (> 2)
                if self.active.contains_key(&tid) {
                    if err_counter.record_framing_error() {
                        return FileRecvAction::SessionFatal(
                            "consecutive 0x0103 errors >= 3 (duplicate transfer_id)".into(),
                        );
                    }
                    return FileRecvAction::SendAbort(FileAbort {
                        transfer_id: tid,
                        error_code: FILE_ERR_INVALID_FRAMING,
                    });
                }
                if self.active.len() >= FILE_MAX_CONCURRENT_PER_DIR {
                    return FileRecvAction::SendAbort(FileAbort {
                        transfer_id: tid,
                        error_code: FILE_ERR_RATE_LIMITED,
                    });
                }

                // Ensure download dir exists & check disk space via statvfs before accepting
                if fs::create_dir_all(&self.download_dir).is_err() {
                    return FileRecvAction::SendAbort(FileAbort {
                        transfer_id: tid,
                        error_code: FILE_ERR_PATH_FAILED,
                    });
                }
                if check_disk_space_for_file(&self.download_dir, file_size).is_err() {
                    return FileRecvAction::SendAbort(FileAbort {
                        transfer_id: tid,
                        error_code: FILE_ERR_PATH_FAILED,
                    });
                }

                let (tmp_path, tmp_file) = match self.create_temp_file(tid) {
                    Ok(v) => v,
                    Err(_) => {
                        return FileRecvAction::SendAbort(FileAbort {
                            transfer_id: tid,
                            error_code: FILE_ERR_PATH_FAILED,
                        });
                    }
                };

                let init_window = self.window_size.min(file_size);
                self.active.insert(
                    tid,
                    ActiveInboundTransfer {
                        offer,
                        tmp_path,
                        tmp_file: Some(tmp_file),
                        hasher: Sha256::new(),
                        next_expected_offset: 0,
                        window_end_offset: init_window,
                        last_progress_at: now,
                    },
                );
                err_counter.reset();
                FileRecvAction::SendAccept(FileAccept {
                    transfer_id: tid,
                    resume_offset: 0,
                    initial_window_end_offset: init_window,
                })
            }
            FileMessage::Chunk(chunk) => {
                let tid = chunk.transfer_id;
                let Some(st) = self.active.get_mut(&tid) else {
                    if err_counter.record_framing_error() {
                        return FileRecvAction::SessionFatal(
                            "consecutive 0x0103 errors >= 3 (unknown FILE_CHUNK transfer_id)"
                                .into(),
                        );
                    }
                    return FileRecvAction::SendAbort(FileAbort {
                        transfer_id: tid,
                        error_code: FILE_ERR_INVALID_FRAMING,
                    });
                };
                let data_len = chunk.data.len() as u64;
                let end_off = chunk.offset.checked_add(data_len);
                let chunk_valid = data_len > 0
                    && chunk.offset == st.next_expected_offset
                    && data_len <= u64::from(st.offer.chunk_size)
                    && end_off.is_some_and(|e| e <= st.window_end_offset && e <= st.offer.file_size);
                if !chunk_valid {
                    if let Some(removed) = self.active.remove(&tid) {
                        self.push_audit(FileTransferAuditRecord {
                            direction: "inbound".into(),
                            transfer_id: tid,
                            rel_name: removed.offer.rel_name.clone(),
                            file_size: removed.offer.file_size,
                            sha256_hex: hex::encode(removed.offer.sha256),
                            final_path: None,
                            outcome: "chunk_invalid".into(),
                            error_code: FILE_ERR_INVALID_FRAMING,
                        });
                    }
                    if err_counter.record_framing_error() {
                        return FileRecvAction::SessionFatal(
                            "consecutive 0x0103 errors >= 3 (out-of-order/over-window FILE_CHUNK)"
                                .into(),
                        );
                    }
                    return FileRecvAction::SendAbort(FileAbort {
                        transfer_id: tid,
                        error_code: FILE_ERR_INVALID_FRAMING,
                    });
                }

                if let Some(f) = st.tmp_file.as_mut() {
                    if f.write_all(&chunk.data).is_err() {
                        if let Some(removed) = self.active.remove(&tid) {
                            self.push_audit(FileTransferAuditRecord {
                                direction: "inbound".into(),
                                transfer_id: tid,
                                rel_name: removed.offer.rel_name.clone(),
                                file_size: removed.offer.file_size,
                                sha256_hex: hex::encode(removed.offer.sha256),
                                final_path: None,
                                outcome: "write_failed".into(),
                                error_code: FILE_ERR_PATH_FAILED,
                            });
                        }
                        return FileRecvAction::SendAbort(FileAbort {
                            transfer_id: tid,
                            error_code: FILE_ERR_PATH_FAILED,
                        });
                    }
                }
                st.hasher.update(&chunk.data);
                st.next_expected_offset = st.next_expected_offset.saturating_add(data_len);
                st.window_end_offset = st
                    .next_expected_offset
                    .saturating_add(self.window_size)
                    .min(st.offer.file_size);
                st.last_progress_at = now;
                err_counter.reset();

                FileRecvAction::SendAck(FileAck {
                    transfer_id: tid,
                    next_expected_offset: st.next_expected_offset,
                    window_end_offset: st.window_end_offset,
                })
            }
            FileMessage::Complete(comp) => {
                let tid = comp.transfer_id;
                let Some(st) = self.active.remove(&tid) else {
                    if err_counter.record_framing_error() {
                        return FileRecvAction::SessionFatal(
                            "consecutive 0x0103 errors >= 3 (unknown FILE_COMPLETE transfer_id)"
                                .into(),
                        );
                    }
                    return FileRecvAction::SendAbort(FileAbort {
                        transfer_id: tid,
                        error_code: FILE_ERR_INVALID_FRAMING,
                    });
                };

                let rel_name = st.offer.rel_name.clone();
                let file_size = st.offer.file_size;
                let offer_sha = st.offer.sha256;
                let computed: [u8; 32] = st.hasher.clone().finalize().into();

                if st.next_expected_offset != file_size
                    || computed != offer_sha
                    || computed != comp.sha256
                {
                    drop(st);
                    let audit = FileTransferAuditRecord {
                        direction: "inbound".into(),
                        transfer_id: tid,
                        rel_name,
                        file_size,
                        sha256_hex: hex::encode(computed),
                        final_path: None,
                        outcome: "hash_mismatch".into(),
                        error_code: FILE_ERR_INVALID_FRAMING,
                    };
                    self.push_audit(audit.clone());
                    err_counter.reset();
                    return FileRecvAction::SendCompleteAck {
                        ack: FileCompleteAck {
                            transfer_id: tid,
                            status: FILE_COMPLETE_ACK_HASH_MISMATCH,
                        },
                        saved_path: None,
                        audit,
                    };
                }

                match self.finalize_atomic_non_overwriting(st) {
                    Ok(saved_path) => {
                        let audit = FileTransferAuditRecord {
                            direction: "inbound".into(),
                            transfer_id: tid,
                            rel_name,
                            file_size,
                            sha256_hex: hex::encode(computed),
                            final_path: Some(saved_path.display().to_string()),
                            outcome: "ok".into(),
                            error_code: FILE_ERR_OK,
                        };
                        self.push_audit(audit.clone());
                        err_counter.reset();
                        FileRecvAction::SendCompleteAck {
                            ack: FileCompleteAck {
                                transfer_id: tid,
                                status: FILE_COMPLETE_ACK_OK,
                            },
                            saved_path: Some(saved_path),
                            audit,
                        }
                    }
                    Err(e) => {
                        let audit = FileTransferAuditRecord {
                            direction: "inbound".into(),
                            transfer_id: tid,
                            rel_name,
                            file_size,
                            sha256_hex: hex::encode(computed),
                            final_path: None,
                            outcome: format!("io_error: {e}"),
                            error_code: FILE_ERR_PATH_FAILED,
                        };
                        self.push_audit(audit.clone());
                        FileRecvAction::SendCompleteAck {
                            ack: FileCompleteAck {
                                transfer_id: tid,
                                status: FILE_COMPLETE_ACK_IO_ERROR,
                            },
                            saved_path: None,
                            audit,
                        }
                    }
                }
            }
            FileMessage::Abort(ab) => {
                if let Some(st) = self.active.remove(&ab.transfer_id) {
                    self.push_audit(FileTransferAuditRecord {
                        direction: "inbound".into(),
                        transfer_id: ab.transfer_id,
                        rel_name: st.offer.rel_name.clone(),
                        file_size: st.offer.file_size,
                        sha256_hex: hex::encode(st.offer.sha256),
                        final_path: None,
                        outcome: "peer_aborted".into(),
                        error_code: ab.error_code,
                    });
                    err_counter.reset();
                }
                // Unknown transfer_id Abort is ignored WITHOUT resetting err_counter!
                FileRecvAction::None
            }
            FileMessage::Accept(_) | FileMessage::Ack(_) | FileMessage::CompleteAck(_) => {
                // Role-violation: receiver-only message received on receiver side!
                if err_counter.record_framing_error() {
                    return FileRecvAction::SessionFatal(
                        "consecutive 0x0103 errors >= 3 (receiver-only frame role violation)"
                            .into(),
                    );
                }
                FileRecvAction::None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::policy::{TenantPolicyBody, POLICY_FLAG_ALLOW_FILE_TRANSFER};
    use serde_json::Value;
    use v2_transport::encode_l4_frame;

    const V27_PATH: &str =
        "/Volumes/data/github/zerodesk/protocol-spec/vectors/v27_policy_clipboard_file.json";

    fn allow_file_policy(max_file_mb: u32) -> EffectiveTenantPolicy {
        EffectiveTenantPolicy {
            tenant_id: [0x11; 16],
            version: 1,
            exp_unix: u64::MAX,
            policy_hash: [0x22; 32],
            body: TenantPolicyBody {
                schema_ver: 1,
                flags: POLICY_FLAG_ALLOW_FILE_TRANSFER,
                max_bw_kbps: 20_000,
                max_file_mb,
                max_clipboard_kb: 256,
            },
            degraded: false,
            degraded_reason: None,
        }
    }

    #[test]
    fn file_transfer_matches_v27_golden_frames_filename_matrix_and_negative_cases() {
        let raw_json = std::fs::read_to_string(V27_PATH).unwrap();
        let v: Value = serde_json::from_str(&raw_json).unwrap();
        let ft = &v["file_transfer"];

        // FILE_OFFER
        let offer_bytes = hex::decode(ft["file_offer"]["body_hex"].as_str().unwrap()).unwrap();
        let offer = FileOffer::decode(&offer_bytes).unwrap();
        assert_eq!(offer.transfer_id, 72623859790382856);
        assert_eq!(offer.file_size, 57);
        assert_eq!(offer.chunk_size, 1024);
        assert_eq!(offer.rel_name, "report_2026.pdf");
        assert_eq!(offer.encode().unwrap(), offer_bytes);
        let l4_offer = encode_l4_frame(
            &L4Header {
                msg_type: FILE_MSG_OFFER,
                flags: 0,
                body_len: offer_bytes.len() as u16,
                stream_seq: 10,
            },
            &offer_bytes,
        )
        .unwrap();
        assert_eq!(hex::encode(&l4_offer), ft["file_offer"]["l4_frame_hex"].as_str().unwrap());

        // FILE_ACCEPT
        let acc_bytes = hex::decode(ft["file_accept"]["body_hex"].as_str().unwrap()).unwrap();
        let acc = FileAccept::decode(&acc_bytes).unwrap();
        assert_eq!(acc.resume_offset, 0);
        assert_eq!(acc.initial_window_end_offset, 57);
        assert_eq!(acc.encode().unwrap().as_slice(), acc_bytes.as_slice());

        // FILE_CHUNK
        let chk_bytes = hex::decode(ft["file_chunk"]["body_hex"].as_str().unwrap()).unwrap();
        let chk = FileChunk::decode(&chk_bytes).unwrap();
        assert_eq!(chk.offset, 0);
        assert_eq!(chk.encode().unwrap(), chk_bytes);

        // FILE_ACK
        let ack_bytes = hex::decode(ft["file_ack"]["body_hex"].as_str().unwrap()).unwrap();
        let ack = FileAck::decode(&ack_bytes).unwrap();
        assert_eq!(ack.next_expected_offset, 57);
        assert_eq!(ack.window_end_offset, 57);
        assert_eq!(ack.encode().unwrap().as_slice(), ack_bytes.as_slice());

        // FILE_COMPLETE
        let comp_bytes = hex::decode(ft["file_complete"]["body_hex"].as_str().unwrap()).unwrap();
        let comp = FileComplete::decode(&comp_bytes).unwrap();
        assert_eq!(comp.encode().as_slice(), comp_bytes.as_slice());

        // FILE_ABORT
        let ab_bytes = hex::decode(ft["file_abort"]["body_hex"].as_str().unwrap()).unwrap();
        let ab = FileAbort::decode(&ab_bytes).unwrap();
        assert_eq!(ab.error_code, FILE_ERR_POLICY_DENIED);
        assert_eq!(ab.encode().as_slice(), ab_bytes.as_slice());

        // FILE_COMPLETE_ACK
        let cack_bytes =
            hex::decode(ft["file_complete_ack"]["body_hex"].as_str().unwrap()).unwrap();
        let cack = FileCompleteAck::decode(&cack_bytes).unwrap();
        assert_eq!(cack.status, FILE_COMPLETE_ACK_OK);
        assert_eq!(cack.encode().unwrap().as_slice(), cack_bytes.as_slice());

        // All 29 V27 filename rejection cases MUST fail
        for case in ft["filename_rejection_matrix"].as_array().unwrap() {
            let name_tag = case["case"].as_str().unwrap();
            let raw_name = hex::decode(case["name_hex"].as_str().unwrap()).unwrap();
            assert!(
                validate_safe_filename(&raw_name).is_err(),
                "unsafe filename case '{name_tag}' was unexpectedly accepted"
            );
        }

        // All 5 V27 valid filenames MUST pass
        for valid in ft["filename_valid_cases"].as_array().unwrap() {
            let s = valid.as_str().unwrap();
            assert_eq!(validate_safe_filename(s.as_bytes()).unwrap(), s);
        }

        // All 11 V27 negative wire cases -> 0x0103 INVALID_FRAMING
        for case in ft["negative_wire_cases"].as_array().unwrap() {
            let name = case["case"].as_str().unwrap();
            let msg_type = case["msg_type"].as_u64().unwrap() as u8;
            let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            let hdr = L4Header {
                msg_type,
                flags: 0,
                body_len: body.len() as u16,
                stream_seq: 1,
            };
            let decoded = decode_file_l4(&hdr, &body);
            let is_0103 = match decoded {
                Err(FileTransferError::InvalidFraming {
                    error_code: FILE_ERR_INVALID_FRAMING,
                    ..
                }) => true,
                Ok(FileMessage::OfferRaw(raw)) => matches!(
                    raw.validate(),
                    Err(FileTransferError::InvalidFraming {
                        error_code: FILE_ERR_INVALID_FRAMING,
                        ..
                    })
                ),
                _ => false,
            };
            assert!(is_0103, "negative wire case '{name}' did not trigger 0x0103");
        }
    }

    #[test]
    fn file_transfer_streaming_sha256_non_overwrite_collision_window_and_policy_gate() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-ft-test-{}-{uniq}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();

        let payload = b"ZeroDesk Phase 4B deterministic streaming SHA-256 payload! ".repeat(50);
        let sha: [u8; 32] = Sha256::digest(&payload).into();
        let policy = allow_file_policy(10);
        let now = Instant::now();

        let mut rx = FileTransferReceiver::new(policy.clone(), dir.clone()).with_window_size(1024);
        let mut err_cnt = ChannelFramingErrorCounter::new();

        // Run TWO transfers with the SAME filename "report.bin" to verify non-overwrite (1) suffix!
        let mut saved_paths = Vec::new();
        for tid in [100u64, 101u64] {
            let (mut sender, offer) = FileSenderWindow::new(
                &policy,
                tid,
                "report.bin",
                payload.len() as u64,
                512,
                sha,
                now,
            )
            .unwrap();
            let offer_wire = offer.encode().unwrap();
            let acc_act = rx.on_l4_frame(
                &L4Header {
                    msg_type: FILE_MSG_OFFER,
                    flags: 0,
                    body_len: offer_wire.len() as u16,
                    stream_seq: 1,
                },
                &offer_wire,
                now,
                &mut err_cnt,
            );
            let FileRecvAction::SendAccept(acc) = acc_act else {
                panic!("expected SendAccept, got {acc_act:?}");
            };
            sender.on_accept(&acc, now).unwrap();

            // Verify bulk pause freezes chunk emission
            assert!(sender.next_chunk_range(true).is_none());

            let mut seq = 2u32;
            while let Some((off, len)) = sender.next_chunk_range(false) {
                let slice = &payload[off as usize..(off as usize + len)];
                let chunk = FileChunk {
                    transfer_id: tid,
                    offset: off,
                    data: slice.to_vec(),
                };
                sender.mark_chunk_sent(off, len, now);
                let cw = chunk.encode().unwrap();
                let ack_act = rx.on_l4_frame(
                    &L4Header {
                        msg_type: FILE_MSG_CHUNK,
                        flags: 0,
                        body_len: cw.len() as u16,
                        stream_seq: seq,
                    },
                    &cw,
                    now,
                    &mut err_cnt,
                );
                seq += 1;
                let FileRecvAction::SendAck(ack) = ack_act else {
                    panic!("expected SendAck, got {ack_act:?}");
                };
                // Idempotent duplicate ACK must not inflate window!
                sender.on_ack(&ack, now).unwrap();
                let w_before = sender.window_end_offset();
                sender.on_ack(&ack, now).unwrap();
                assert_eq!(sender.window_end_offset(), w_before);
            }
            assert!(sender.ready_for_complete());
            let comp = sender.build_complete(now);
            let comp_wire = comp.encode();
            let done_act = rx.on_l4_frame(
                &L4Header {
                    msg_type: FILE_MSG_COMPLETE,
                    flags: 0,
                    body_len: comp_wire.len() as u16,
                    stream_seq: seq,
                },
                &comp_wire,
                now,
                &mut err_cnt,
            );
            match done_act {
                FileRecvAction::SendCompleteAck {
                    ack,
                    saved_path: Some(p),
                    ..
                } => {
                    assert_eq!(ack.status, FILE_COMPLETE_ACK_OK);
                    assert_eq!(fs::read(&p).unwrap(), payload);
                    saved_paths.push(p);
                }
                other => panic!("expected SendCompleteAck OK, got {other:?}"),
            }
        }
        assert_eq!(saved_paths[0].file_name().unwrap(), "report.bin");
        assert_eq!(saved_paths[1].file_name().unwrap(), "report(1).bin");
        assert_eq!(rx.audit_records.len(), 2);

        // Policy denied when allow_file_transfer=false or max_file_mb=0 -> FILE_ABORT(tid, 0x0401)
        let denied_pol = EffectiveTenantPolicy::degraded([0x11; 16], [0x22; 32], "degraded");
        assert!(FileSenderWindow::new(&denied_pol, 200, "a.bin", 10, 512, sha, now).is_err());
        let mut rx_denied = FileTransferReceiver::new(denied_pol, dir.clone());
        let offer_ok = FileOffer {
            transfer_id: 200,
            file_size: 10,
            chunk_size: 512,
            sha256: sha,
            rel_name: "a.bin".into(),
        };
        let ow = offer_ok.encode().unwrap();
        assert_eq!(
            rx_denied.on_l4_frame(
                &L4Header {
                    msg_type: FILE_MSG_OFFER,
                    flags: 0,
                    body_len: ow.len() as u16,
                    stream_seq: 1,
                },
                &ow,
                now,
                &mut err_cnt,
            ),
            FileRecvAction::SendAbort(FileAbort {
                transfer_id: 200,
                error_code: FILE_ERR_POLICY_DENIED
            })
        );
        // Policy denial must NEVER bump consecutive 0x0103 error counter!
        assert_eq!(err_cnt.consecutive(), 0);

        // Collision filename keeps <= 255B on UTF-8 boundary
        let long_name = format!("{}.txt", "中".repeat(83)); // 249 + 4 = 253B
        let suffixed = build_collision_filename(&long_name, 999);
        assert!(suffixed.len() <= FILE_NAME_MAX_BYTES);
        assert!(suffixed.ends_with("(999).txt"));

        // Sender window rejects regression and next_expected > max_sent_offset
        let (mut sw, _) =
            FileSenderWindow::new(&policy, 300, "w.bin", 1000, 500, sha, now).unwrap();
        sw.on_accept(
            &FileAccept {
                transfer_id: 300,
                resume_offset: 0,
                initial_window_end_offset: 500,
            },
            now,
        )
        .unwrap();
        assert!(sw
            .on_ack(
                &FileAck {
                    transfer_id: 300,
                    next_expected_offset: 100, // > max_sent_offset (0)!
                    window_end_offset: 500,
                },
                now,
            )
            .is_err());
        sw.mark_chunk_sent(0, 500, now);
        assert!(sw
            .on_ack(
                &FileAck {
                    transfer_id: 300,
                    next_expected_offset: 500,
                    window_end_offset: 1001, // > file_size (1000)!
                },
                now,
            )
            .is_err());

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn file_transfer_duplicate_accept_role_violation_counter_and_bounded_audit() {
        let now = Instant::now();
        let policy = allow_file_policy(16);
        let sha = [0x44u8; 32];

        // 1. Duplicate FILE_ACCEPT MUST fail closed with InvalidFraming
        let (mut sw, _) =
            FileSenderWindow::new(&policy, 400, "dup.bin", 1024, 512, sha, now).unwrap();
        let acc = FileAccept {
            transfer_id: 400,
            resume_offset: 0,
            initial_window_end_offset: 1024,
        };
        sw.on_accept(&acc, now).unwrap();
        assert!(matches!(
            sw.on_accept(&acc, now),
            Err(FileTransferError::InvalidFraming {
                error_code: FILE_ERR_INVALID_FRAMING,
                ..
            })
        ));

        // 2. Role-violation frames (Accept/Ack/CompleteAck) & unknown Abort MUST NOT bypass err_counter
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-ft-p1-{}-{uniq}", std::process::id()));
        let mut rx = FileTransferReceiver::new(policy.clone(), dir.clone());
        let mut err_cnt = ChannelFramingErrorCounter::new();

        let acc_body = acc.encode().unwrap();
        let acc_hdr = L4Header {
            msg_type: FILE_MSG_ACCEPT,
            flags: 0,
            body_len: acc_body.len() as u16,
            stream_seq: 1,
        };
        assert_eq!(
            rx.on_l4_frame(&acc_hdr, &acc_body, now, &mut err_cnt),
            FileRecvAction::None
        );
        assert_eq!(err_cnt.consecutive(), 1);

        // Unknown transfer_id Abort MUST NOT reset err_cnt
        let unk_ab = FileAbort {
            transfer_id: 999_999,
            error_code: FILE_ERR_PATH_FAILED,
        }
        .encode();
        let ab_hdr = L4Header {
            msg_type: FILE_MSG_ABORT,
            flags: 0,
            body_len: unk_ab.len() as u16,
            stream_seq: 2,
        };
        assert_eq!(
            rx.on_l4_frame(&ab_hdr, &unk_ab, now, &mut err_cnt),
            FileRecvAction::None
        );
        assert_eq!(err_cnt.consecutive(), 1);

        // 2nd & 3rd receiver-only role-violation frames MUST escalate to SessionFatal!
        assert_eq!(
            rx.on_l4_frame(&acc_hdr, &acc_body, now, &mut err_cnt),
            FileRecvAction::None
        );
        assert!(matches!(
            rx.on_l4_frame(&acc_hdr, &acc_body, now, &mut err_cnt),
            FileRecvAction::SessionFatal(_)
        ));

        // 3. Policy-denied Offer flood MUST remain bounded at FILE_AUDIT_LOG_CAP (1024)
        let denied = EffectiveTenantPolicy::degraded([1; 16], [2; 32], "denied");
        let mut denied_rx = FileTransferReceiver::new(denied, dir.clone());
        let mut err_cnt2 = ChannelFramingErrorCounter::new();
        for tid in 1..=(FILE_AUDIT_LOG_CAP as u64 + 64) {
            let offer_body = FileOffer {
                transfer_id: tid,
                file_size: 16,
                chunk_size: 1024,
                sha256: sha,
                rel_name: "flood.bin".into(),
            }
            .encode()
            .unwrap();
            let offer_hdr = L4Header {
                msg_type: FILE_MSG_OFFER,
                flags: 0,
                body_len: offer_body.len() as u16,
                stream_seq: tid as u32,
            };
            let _ = denied_rx.on_l4_frame(&offer_hdr, &offer_body, now, &mut err_cnt2);
        }
        assert_eq!(denied_rx.audit_records.len(), FILE_AUDIT_LOG_CAP);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sender_window_waits_for_final_ack_before_complete_and_allows_zero_byte_file() {
        let now = Instant::now();
        let pol = allow_file_policy(16);
        let payload = vec![0xABu8; 2048];
        let sha: [u8; 32] = Sha256::digest(&payload).into();
        let (mut sender, _offer) =
            FileSenderWindow::new(&pol, 7, "wait_ack.bin", payload.len() as u64, 1024, sha, now)
                .unwrap();
        sender
            .on_accept(
                &FileAccept {
                    transfer_id: 7,
                    resume_offset: 0,
                    initial_window_end_offset: payload.len() as u64,
                },
                now,
            )
            .unwrap();

        // Send all bytes without receiving FILE_ACK yet: MUST NOT be ready_for_complete.
        while let Some((off, len)) = sender.next_chunk_range(false) {
            sender.mark_chunk_sent(off, len, now);
        }
        assert_eq!(sender.max_sent_offset(), payload.len() as u64);
        assert_eq!(sender.next_expected_offset(), 0);
        assert!(!sender.ready_for_complete());

        // Partial ACK still blocks FILE_COMPLETE.
        sender
            .on_ack(
                &FileAck {
                    transfer_id: 7,
                    next_expected_offset: 1024,
                    window_end_offset: 2048,
                },
                now,
            )
            .unwrap();
        assert!(!sender.ready_for_complete());

        // Final ACK reaching file_size unlocks FILE_COMPLETE.
        sender
            .on_ack(
                &FileAck {
                    transfer_id: 7,
                    next_expected_offset: 2048,
                    window_end_offset: 2048,
                },
                now,
            )
            .unwrap();
        assert!(sender.ready_for_complete());

        // 0-byte file: ready_for_complete immediately after FILE_ACCEPT (resume_offset == file_size).
        let empty_sha: [u8; 32] = Sha256::digest(b"").into();
        let (mut zero_sender, zero_offer) =
            FileSenderWindow::new(&pol, 8, "empty.bin", 0, 1024, empty_sha, now).unwrap();
        let dir = std::env::temp_dir().join(format!("zd_ft_zero_{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let mut rx = FileTransferReceiver::new(pol, dir.clone());
        let mut err_cnt = ChannelFramingErrorCounter::new();
        let offer_wire = zero_offer.encode().unwrap();
        let acc_act = rx.on_l4_frame(
            &L4Header {
                msg_type: FILE_MSG_OFFER,
                flags: 0,
                body_len: offer_wire.len() as u16,
                stream_seq: 1,
            },
            &offer_wire,
            now,
            &mut err_cnt,
        );
        let FileRecvAction::SendAccept(acc) = acc_act else {
            panic!("expected SendAccept for 0-byte file, got {acc_act:?}");
        };
        assert_eq!(acc.resume_offset, 0);
        assert_eq!(acc.initial_window_end_offset, 0);

        zero_sender.on_accept(&acc, now).unwrap();
        assert!(zero_sender.next_chunk_range(false).is_none());
        assert!(zero_sender.ready_for_complete());

        let comp_wire = zero_sender.build_complete(now).encode();
        let done_act = rx.on_l4_frame(
            &L4Header {
                msg_type: FILE_MSG_COMPLETE,
                flags: 0,
                body_len: comp_wire.len() as u16,
                stream_seq: 2,
            },
            &comp_wire,
            now,
            &mut err_cnt,
        );
        match done_act {
            FileRecvAction::SendCompleteAck {
                ack,
                saved_path: Some(p),
                ..
            } => {
                assert_eq!(ack.status, FILE_COMPLETE_ACK_OK);
                assert_eq!(fs::read(&p).unwrap().len(), 0);
            }
            other => panic!("expected SendCompleteAck for 0-byte file, got {other:?}"),
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn sender_window_resume_offset_full_and_partial_boundaries() {
        let now = Instant::now();
        let pol = allow_file_policy(16);
        let payload = vec![0xCDu8; 2048];
        let sha: [u8; 32] = Sha256::digest(&payload).into();

        // 1. resume_offset == file_size (2048) -> immediately ready_for_complete without chunks!
        let (mut full_resume, _) =
            FileSenderWindow::new(&pol, 21, "resumed_full.bin", 2048, 1024, sha, now).unwrap();
        full_resume
            .on_accept(
                &FileAccept {
                    transfer_id: 21,
                    resume_offset: 2048,
                    initial_window_end_offset: 2048,
                },
                now,
            )
            .unwrap();
        assert_eq!(full_resume.next_expected_offset(), 2048);
        assert_eq!(full_resume.max_sent_offset(), 2048);
        assert!(full_resume.next_chunk_range(false).is_none());
        assert!(full_resume.ready_for_complete());
        let peeked = full_resume.peek_complete();
        assert_eq!(peeked.transfer_id, 21);
        assert_eq!(peeked.sha256, sha);
        assert!(full_resume.ready_for_complete(), "peek_complete must not mark complete_sent");
        full_resume.commit_complete(now);
        assert!(!full_resume.ready_for_complete());

        // 2. partial resume_offset = 1024 < 2048 -> NOT ready until remaining 1024B sent AND ACKed!
        let (mut partial_resume, _) =
            FileSenderWindow::new(&pol, 22, "resumed_partial.bin", 2048, 1024, sha, now).unwrap();
        partial_resume
            .on_accept(
                &FileAccept {
                    transfer_id: 22,
                    resume_offset: 1024,
                    initial_window_end_offset: 2048,
                },
                now,
            )
            .unwrap();
        assert_eq!(partial_resume.next_expected_offset(), 1024);
        assert!(!partial_resume.ready_for_complete());
        assert_eq!(partial_resume.next_chunk_range(false), Some((1024, 1024)));
        partial_resume.mark_chunk_sent(1024, 1024, now);
        assert!(!partial_resume.ready_for_complete());
        partial_resume
            .on_ack(
                &FileAck {
                    transfer_id: 22,
                    next_expected_offset: 2048,
                    window_end_offset: 2048,
                },
                now,
            )
            .unwrap();
        assert!(partial_resume.ready_for_complete());
    }
}
