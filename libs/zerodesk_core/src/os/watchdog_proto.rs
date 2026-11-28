// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Fixed-size 56-byte idempotent wire protocol between the Host supervisor and the
//! independent `zerodesk-hid-watchdog` subprocess (`56 << PIPE_BUF=512`, atomic writes
//! under `O_NONBLOCK`, zero heap allocation on encode/decode).

use serde::{Deserialize, Serialize};
use std::fmt;

pub const WATCHDOG_MAGIC: [u8; 4] = *b"ZDWD";
pub const WATCHDOG_PROTO_VERSION: u8 = 1;
pub const WATCHDOG_FRAME_LEN: usize = 56;
pub const WATCHDOG_REPORT_SCHEMA_VERSION: u32 = 1;

/// Capability bits carried in `WatchdogMsgType::Ready` frame `flags`.
pub const WATCHDOG_READY_FLAG_REAL_OS_INPUT: u8 = 0x01;
pub const WATCHDOG_READY_FLAG_AX_TRUSTED: u8 = 0x02;

/// Outcome flags carried in `WatchdogMsgType::Released` frame `flags`.
pub const WATCHDOG_RELEASED_FLAG_GRACEFUL: u8 = 0x00;
pub const WATCHDOG_RELEASED_FLAG_EMERGENCY_OK: u8 = 0x01;
pub const WATCHDOG_RELEASED_FLAG_EMERGENCY_FAILED: u8 = 0x02;

/// All 8 USB HID modifier usages (Left/Right Ctrl, Shift, Alt, Meta), released
/// unconditionally during emergency release as defense-in-depth.
pub const ALL_MODIFIER_HID_USAGES: [u16; 8] = [0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7];

// Compile-time guarantee: fixed 56-byte frame strictly smaller than POSIX/macOS PIPE_BUF (512).
const _: () = assert!(WATCHDOG_FRAME_LEN == 56 && WATCHDOG_FRAME_LEN < 512);

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogMsgType {
    Hello = 1,
    StateSnapshot = 2,
    GracefulExit = 3,
    Ready = 4,
    Released = 5,
    AxStatus = 6,
}

impl WatchdogMsgType {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Self::Hello),
            2 => Some(Self::StateSnapshot),
            3 => Some(Self::GracefulExit),
            4 => Some(Self::Ready),
            5 => Some(Self::Released),
            6 => Some(Self::AxStatus),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogProtoError {
    InvalidLength(usize),
    BadMagic([u8; 4]),
    UnsupportedVersion(u8),
    UnknownMsgType(u8),
    NonZeroReserved,
    CrcMismatch { expected: u32, actual: u32 },
}

impl fmt::Display for WatchdogProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength(n) => {
                write!(f, "invalid watchdog frame len {n} (expected {WATCHDOG_FRAME_LEN})")
            }
            Self::BadMagic(m) => write!(f, "bad watchdog frame magic: {m:02x?}"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported watchdog proto version: {v}"),
            Self::UnknownMsgType(t) => write!(f, "unknown watchdog message type: {t}"),
            Self::NonZeroReserved => write!(f, "non-zero reserved bytes in watchdog frame"),
            Self::CrcMismatch { expected, actual } => {
                write!(f, "watchdog frame CRC32 mismatch: expected {expected:#010x}, actual {actual:#010x}")
            }
        }
    }
}

impl std::error::Error for WatchdogProtoError {}

/// Fixed-size 56-byte frame layout (all multi-byte integers little-endian):
/// - `[0..4]`   magic (`b"ZDWD"`)
/// - `[4]`      version (`1`)
/// - `[5]`      msg_type (`1..=5`)
/// - `[6]`      flags
/// - `[7]`      reserved (`0`)
/// - `[8..16]`  seq (`u64` LE)
/// - `[16..48]` payload (`[u8; 32]`: 256-bit key bitmap for `StateSnapshot`; `parent_pid (u64 LE) || nonce ([u8; 8]) || 0[16]` for `Hello`)
/// - `[48]`     buttons (`u8`)
/// - `[49]`     mods (`u8`)
/// - `[50..52]` reserved2 (`[0, 0]`)
/// - `[52..56]` crc32 (`u32` LE, IEEE 802.3 over `[0..52]`)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WatchdogFrame {
    pub msg_type: WatchdogMsgType,
    pub flags: u8,
    pub seq: u64,
    pub payload: [u8; 32],
    pub buttons: u8,
    pub mods: u8,
}

impl WatchdogFrame {
    pub fn hello(parent_pid: u32, nonce: [u8; 8]) -> Self {
        let mut payload = [0u8; 32];
        payload[0..8].copy_from_slice(&u64::from(parent_pid).to_le_bytes());
        payload[8..16].copy_from_slice(&nonce);
        Self {
            msg_type: WatchdogMsgType::Hello,
            flags: 0,
            seq: 0,
            payload,
            buttons: 0,
            mods: 0,
        }
    }

    pub fn parse_hello(&self) -> Option<(u32, [u8; 8])> {
        if self.msg_type != WatchdogMsgType::Hello {
            return None;
        }
        if self.payload[16..32].iter().any(|&b| b != 0) {
            return None;
        }
        let pid_u64 = u64::from_le_bytes(self.payload[0..8].try_into().ok()?);
        let pid = u32::try_from(pid_u64).ok()?;
        if pid == 0 {
            return None;
        }
        let nonce: [u8; 8] = self.payload[8..16].try_into().ok()?;
        Some((pid, nonce))
    }

    pub fn state_snapshot(seq: u64, keys_bitmap: [u8; 32], buttons: u8, mods: u8) -> Self {
        Self {
            msg_type: WatchdogMsgType::StateSnapshot,
            flags: 0,
            seq,
            payload: keys_bitmap,
            buttons,
            mods,
        }
    }

    pub fn graceful_exit(seq: u64) -> Self {
        Self {
            msg_type: WatchdogMsgType::GracefulExit,
            flags: 0,
            seq,
            payload: [0u8; 32],
            buttons: 0,
            mods: 0,
        }
    }

    pub fn ready(seq: u64) -> Self {
        Self::ready_with_flags(seq, 0)
    }

    pub fn ready_with_flags(seq: u64, flags: u8) -> Self {
        Self {
            msg_type: WatchdogMsgType::Ready,
            flags,
            seq,
            payload: [0u8; 32],
            buttons: 0,
            mods: 0,
        }
    }

    pub fn released(seq: u64, flags: u8) -> Self {
        Self {
            msg_type: WatchdogMsgType::Released,
            flags,
            seq,
            payload: [0u8; 32],
            buttons: 0,
            mods: 0,
        }
    }

    pub fn ax_status(seq: u64, flags: u8) -> Self {
        Self {
            msg_type: WatchdogMsgType::AxStatus,
            flags,
            seq,
            payload: [0u8; 32],
            buttons: 0,
            mods: 0,
        }
    }

    /// Encodes into a stack-allocated 56-byte buffer (zero heap allocation).
    pub fn encode(&self) -> [u8; WATCHDOG_FRAME_LEN] {
        let mut buf = [0u8; WATCHDOG_FRAME_LEN];
        buf[0..4].copy_from_slice(&WATCHDOG_MAGIC);
        buf[4] = WATCHDOG_PROTO_VERSION;
        buf[5] = self.msg_type as u8;
        buf[6] = self.flags;
        buf[7] = 0;
        buf[8..16].copy_from_slice(&self.seq.to_le_bytes());
        buf[16..48].copy_from_slice(&self.payload);
        buf[48] = self.buttons;
        buf[49] = self.mods;
        buf[50] = 0;
        buf[51] = 0;
        let crc = crc32_ieee(&buf[0..52]);
        buf[52..56].copy_from_slice(&crc.to_le_bytes());
        buf
    }

    /// Decodes strictly from a 56-byte slice (zero heap allocation).
    pub fn decode(bytes: &[u8]) -> Result<Self, WatchdogProtoError> {
        if bytes.len() != WATCHDOG_FRAME_LEN {
            return Err(WatchdogProtoError::InvalidLength(bytes.len()));
        }
        let magic: [u8; 4] = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if magic != WATCHDOG_MAGIC {
            return Err(WatchdogProtoError::BadMagic(magic));
        }
        if bytes[4] != WATCHDOG_PROTO_VERSION {
            return Err(WatchdogProtoError::UnsupportedVersion(bytes[4]));
        }
        let msg_type = WatchdogMsgType::from_u8(bytes[5])
            .ok_or(WatchdogProtoError::UnknownMsgType(bytes[5]))?;
        if bytes[7] != 0 || bytes[50] != 0 || bytes[51] != 0 {
            return Err(WatchdogProtoError::NonZeroReserved);
        }
        let expected_crc = u32::from_le_bytes([bytes[52], bytes[53], bytes[54], bytes[55]]);
        let actual_crc = crc32_ieee(&bytes[0..52]);
        if expected_crc != actual_crc {
            return Err(WatchdogProtoError::CrcMismatch {
                expected: expected_crc,
                actual: actual_crc,
            });
        }
        let seq = u64::from_le_bytes([
            bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
        ]);
        let mut payload = [0u8; 32];
        payload.copy_from_slice(&bytes[16..48]);
        Ok(Self {
            msg_type,
            flags: bytes[6],
            seq,
            payload,
            buttons: bytes[48],
            mods: bytes[49],
        })
    }
}

/// Sets the bit for USB HID usage `0..=255`. Returns `false` if out of range.
pub fn bitmap_set_key(bitmap: &mut [u8; 32], usage: u16) -> bool {
    if usage >= 256 {
        return false;
    }
    let idx = (usage / 8) as usize;
    let bit = (usage % 8) as u8;
    bitmap[idx] |= 1u8 << bit;
    true
}

/// Clears the bit for USB HID usage `0..=255`. Returns `false` if out of range.
pub fn bitmap_clear_key(bitmap: &mut [u8; 32], usage: u16) -> bool {
    if usage >= 256 {
        return false;
    }
    let idx = (usage / 8) as usize;
    let bit = (usage % 8) as u8;
    bitmap[idx] &= !(1u8 << bit);
    true
}

/// Checks whether the bit for USB HID usage `0..=255` is set.
pub fn bitmap_contains_key(bitmap: &[u8; 32], usage: u16) -> bool {
    if usage >= 256 {
        return false;
    }
    let idx = (usage / 8) as usize;
    let bit = (usage % 8) as u8;
    (bitmap[idx] & (1u8 << bit)) != 0
}

/// Collects all set USB HID usages (`0..=255`) in sorted ascending order.
pub fn bitmap_collect_keys(bitmap: &[u8; 32]) -> Vec<u16> {
    let mut keys = Vec::new();
    for (byte_idx, &byte) in bitmap.iter().enumerate() {
        if byte == 0 {
            continue;
        }
        for bit in 0..8u16 {
            if (byte & (1u8 << bit)) != 0 {
                keys.push((byte_idx as u16) * 8 + bit);
            }
        }
    }
    keys
}

/// Pure-Rust IEEE 802.3 CRC32 (no external crate dependency).
const fn build_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0usize;
    while i < 256 {
        let mut c = i as u32;
        let mut j = 0;
        while j < 8 {
            if (c & 1) != 0 {
                c = 0xEDB8_8320 ^ (c >> 1);
            } else {
                c >>= 1;
            }
            j += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

const CRC32_TABLE: [u32; 256] = build_crc32_table();

pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        let idx = ((crc ^ u32::from(b)) & 0xFF) as usize;
        crc = CRC32_TABLE[idx] ^ (crc >> 8);
    }
    !crc
}

fn default_true() -> bool {
    true
}

/// Versioned (`schema_version = 1`) atomic release report written by `zerodesk-hid-watchdog`
/// in dry-run mode on emergency release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchdogReleaseReport {
    pub schema_version: u32,
    pub trigger: String,
    pub parent_pid: u32,
    pub watchdog_pid: u32,
    pub released_keys: Vec<u16>,
    pub released_buttons: u8,
    pub released_modifiers: Vec<u16>,
    #[serde(default = "default_true")]
    pub release_ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_error: Option<String>,
    pub release_elapsed_ms: u64,
    pub timestamp_epoch_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_ieee_matches_standard_check_vector() {
        // Standard IEEE 802.3 CRC32 check vector for ASCII "123456789" is 0xCBF43926.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_ieee(b""), 0x0000_0000);
    }

    #[test]
    fn round_trip_all_message_types() {
        let nonce = [0x11, 0x22, 0x33, 0x44, 0xAA, 0xBB, 0xCC, 0xDD];
        let hello = WatchdogFrame::hello(42_424, nonce);
        let decoded_hello = WatchdogFrame::decode(&hello.encode()).unwrap();
        assert_eq!(decoded_hello, hello);
        assert_eq!(decoded_hello.parse_hello(), Some((42_424, nonce)));

        let mut bitmap = [0u8; 32];
        assert!(bitmap_set_key(&mut bitmap, 0x04));
        assert!(bitmap_set_key(&mut bitmap, 0xE0));
        let snap = WatchdogFrame::state_snapshot(99, bitmap, 0x05, 0x03);
        let decoded_snap = WatchdogFrame::decode(&snap.encode()).unwrap();
        assert_eq!(decoded_snap, snap);
        assert_eq!(decoded_snap.buttons, 0x05);
        assert_eq!(decoded_snap.mods, 0x03);

        let exit = WatchdogFrame::graceful_exit(100);
        assert_eq!(WatchdogFrame::decode(&exit.encode()).unwrap(), exit);

        let ready = WatchdogFrame::ready(0);
        assert_eq!(WatchdogFrame::decode(&ready.encode()).unwrap(), ready);

        let released = WatchdogFrame::released(101, 0x01);
        assert_eq!(WatchdogFrame::decode(&released.encode()).unwrap(), released);
    }

    #[test]
    fn rejects_bit_flip_crc_bad_magic_version_type_and_lengths() {
        let base = WatchdogFrame::state_snapshot(7, [0x5A; 32], 0x03, 0x0F).encode();
        assert_eq!(base.len(), WATCHDOG_FRAME_LEN);

        // Every single bit flip across the entire 56-byte frame MUST be rejected.
        for byte_idx in 0..WATCHDOG_FRAME_LEN {
            for bit in 0..8 {
                let mut mutated = base;
                mutated[byte_idx] ^= 1u8 << bit;
                assert!(
                    WatchdogFrame::decode(&mutated).is_err(),
                    "bit flip at byte={byte_idx} bit={bit} was not rejected"
                );
            }
        }

        // Truncated and oversized slices MUST be rejected.
        assert_eq!(
            WatchdogFrame::decode(&base[..WATCHDOG_FRAME_LEN - 1]),
            Err(WatchdogProtoError::InvalidLength(WATCHDOG_FRAME_LEN - 1))
        );
        let mut oversized = base.to_vec();
        oversized.push(0);
        assert_eq!(
            WatchdogFrame::decode(&oversized),
            Err(WatchdogProtoError::InvalidLength(WATCHDOG_FRAME_LEN + 1))
        );

        // Explicit bad magic / bad version / bad msg_type / non-zero reserved with recomputed CRC.
        let mut bad_magic = base;
        bad_magic[0] = b'X';
        assert!(matches!(
            WatchdogFrame::decode(&bad_magic),
            Err(WatchdogProtoError::BadMagic(_))
        ));

        let mut bad_ver = base;
        bad_ver[4] = 2;
        let crc = crc32_ieee(&bad_ver[0..52]);
        bad_ver[52..56].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            WatchdogFrame::decode(&bad_ver),
            Err(WatchdogProtoError::UnsupportedVersion(2))
        );

        let mut bad_type = base;
        bad_type[5] = 99;
        let crc = crc32_ieee(&bad_type[0..52]);
        bad_type[52..56].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            WatchdogFrame::decode(&bad_type),
            Err(WatchdogProtoError::UnknownMsgType(99))
        );

        let mut bad_res = base;
        bad_res[7] = 1;
        let crc = crc32_ieee(&bad_res[0..52]);
        bad_res[52..56].copy_from_slice(&crc.to_le_bytes());
        assert_eq!(
            WatchdogFrame::decode(&bad_res),
            Err(WatchdogProtoError::NonZeroReserved)
        );
    }

    #[test]
    fn bitmap_edge_bits_0_1_modifiers_and_255() {
        let mut bm = [0u8; 32];
        let edges: Vec<u16> = vec![0, 1, 7, 8, 224, 225, 226, 227, 228, 229, 230, 231, 255];
        for &u in &edges {
            assert!(bitmap_set_key(&mut bm, u));
            assert!(bitmap_contains_key(&bm, u));
        }
        assert!(!bitmap_set_key(&mut bm, 256));
        assert!(!bitmap_contains_key(&bm, 256));
        assert_eq!(bitmap_collect_keys(&bm), edges);

        assert!(bitmap_clear_key(&mut bm, 0));
        assert!(bitmap_clear_key(&mut bm, 255));
        assert!(!bitmap_contains_key(&bm, 0));
        assert!(!bitmap_contains_key(&bm, 255));
        assert_eq!(
            bitmap_collect_keys(&bm),
            vec![1, 7, 8, 224, 225, 226, 227, 228, 229, 230, 231]
        );
    }
}
