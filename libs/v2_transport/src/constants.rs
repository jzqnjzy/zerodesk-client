// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub const MAGIC_VER: u16 = 0x5632;
pub const VER_MAJOR: u8 = 2;
pub const VER_MINOR: u8 = 1;
pub const VER_MAJOR_MINOR: u16 = ((VER_MAJOR as u16) << 8) | (VER_MINOR as u16);

pub const ACCESS_HDR_V11_LEN: usize = 28;
pub const ACCESS_HDR_V10_LEN: usize = 24;
pub const UDP_MIN_LEN: usize = 30;
pub const UDP_MAX_LEN: usize = 1228;
pub const UDP_L3_MIN_LEN: usize = 60;
pub const UDP_CTRL_MAX_LEN: usize = 285;
pub const STREAM_FRAME_MIN_LEN: usize = 34;
pub const STREAM_FRAME_MAX_LEN: usize = 1232;
pub const STREAM_QUEUE_CAP_BYTES: usize = 256 * 1024;
pub const BACKBONE_MAX_WIRE_BYTES: usize = 1289;

pub const L3_HDR_LEN: usize = 16;
pub const AEAD_TAG_LEN: usize = 16;
pub const L3_MTU_DEFAULT: usize = 1200;
pub const L3_MTU_WEBTRANSPORT: usize = 1000;
pub const L4_HDR_LEN: usize = 8;
pub const REPLAY_WINDOW_BITS: usize = 2048;

pub const ZERO_RTT_LRU_CAPACITY: usize = 10_000;
pub const LEG_CACHE_TTL_MS: u64 = 150;
pub const LEG_CACHE_MAX_BYTES: usize = 512 * 1024;
pub const LEG_NACK_VIDEO_MAX_AGE_MS: u64 = 100;
pub const LEG_REKEY_GRACE_MS: u64 = 150;

pub const ACTUATOR_MAX_TTL_MS: u16 = 150;
pub const MAX_FUTURE_SKEW_MS: u64 = 50;
pub const HID_STALE_DROP_MS: u64 = 150;
pub const ARQ_MAX_RETRIES: u8 = 8;
pub const ARQ_MIN_RTO_MS: u64 = 200;
pub const ARQ_MAX_RTO_MS: u64 = 3_000;
pub const IDR_MIN_INTERVAL_MS: u64 = 500;
pub const QUOTA_THROTTLE_KBPS: u32 = 256;

pub const CAP_CODEC_AV1: u64 = 1 << 0;
pub const CAP_CODEC_VP9: u64 = 1 << 1;
pub const CAP_CODEC_H264: u64 = 1 << 2;
pub const CAP_CODEC_HEVC_OS_HW: u64 = 1 << 3;
pub const CAP_AUDIO_OPUS_DTX: u64 = 1 << 4;
pub const CAP_TRANSPORT_P2P_IPV6: u64 = 1 << 5;
pub const CAP_TRANSPORT_TCP443_DUAL: u64 = 1 << 6;
pub const CAP_TRANSPORT_WEBTRANSPORT: u64 = 1 << 7;
pub const CAP_VIDEO_TEMPORAL_SVC: u64 = 1 << 8;
pub const CAP_VIDEO_INTRA_REFRESH: u64 = 1 << 9;
pub const CAP_CIPHER_CHACHA_PREF: u64 = 1 << 10;
pub const CAP_ENTERPRISE_AUDIT_DUAL: u64 = 1 << 11;
pub const CAP_VIDEO_LTR: u64 = 1 << 12;
pub const CAP_ACCESS_LEG_SEQ_V11: u64 = 1 << 13;
pub const CAP_SURVIVAL_MODE: u64 = 1 << 14;
pub const CAP_MULTIPATH_ACTIVE_ACTIVE: u64 = 1 << 15;
pub const CAP_REALTIME_ACTUATOR_CH: u64 = 1 << 16;
pub const CAP_CLIPBOARD: u64 = 1 << 17;
pub const CAP_FILE_TRANSFER: u64 = 1 << 18;

pub const CHAN_TRANSPORT_CTRL: u8 = 0x00;
pub const CHAN_INPUT_HID: u8 = 0x01;
pub const CHAN_AUDIO: u8 = 0x02;
pub const CHAN_VIDEO: u8 = 0x03;
pub const CHAN_CLIPBOARD: u8 = 0x04;
pub const CHAN_FILE_TRANSFER: u8 = 0x05;
pub const CHAN_DIAGNOSTICS: u8 = 0x06;
pub const CHAN_REALTIME_ACTUATOR: u8 = 0x07;
pub const CHAN_TELEMETRY: u8 = 0x08;

pub const EDGE_CTRL_PING: u8 = 0x01;
pub const EDGE_CTRL_PONG: u8 = 0x02;
pub const EDGE_CTRL_REKEY_ACCESS: u8 = 0x04;
pub const EDGE_CTRL_TICKET_EXPIRING: u8 = 0x05;
pub const EDGE_CTRL_MTU_HINT: u8 = 0x06;
pub const EDGE_CTRL_LEG_NACK: u8 = 0x07;
pub const EDGE_CTRL_BW_HINT: u8 = 0x08;

pub const BW_EVENT_DROP_ACTIVE: u8 = 1 << 0;
pub const BW_EVENT_PAUSE_FILE_CHUNK: u8 = 1 << 1;
pub const BW_EVENT_SURVIVAL_MODE: u8 = 1 << 2;

pub const PATTERN_IK: u8 = 1;
pub const PATTERN_XX: u8 = 2;

pub const CIPHER_AESGCM: u16 = 0x0001;
pub const CIPHER_CHACHAPOLY: u16 = 0x0002;

pub const TRANSPORT_MODE_P2P: u8 = 1;
pub const TRANSPORT_MODE_RELAY_UDP: u8 = 2;
pub const TRANSPORT_MODE_TCP443: u8 = 3;
pub const TRANSPORT_MODE_WEBTRANSPORT: u8 = 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum ErrorCode {
    Ok = 0x0000,
    UnsupportedVersion = 0x0101,
    NoCommonCodec = 0x0102,
    InvalidFraming = 0x0103,
    CertExpired = 0x0201,
    CertRevoked = 0x0202,
    DelegationRollback = 0x0203,
    TranscriptMismatch = 0x0204,
    TicketInvalid = 0x0301,
    TicketExpired = 0x0302,
    LeaseFenced = 0x0303,
    QuotaExhausted = 0x0304,
    PolicyDenied = 0x0401,
    AuditChannelUnavailable = 0x0402,
    PopDraining = 0x0501,
    PathFailed = 0x0502,
    RateLimited = 0x0503,
}

impl ErrorCode {
    pub fn as_u16(self) -> u16 {
        self as u16
    }
}

pub fn default_channel_priority(chan_id: u8) -> Option<u8> {
    match chan_id {
        CHAN_TRANSPORT_CTRL | CHAN_INPUT_HID | CHAN_REALTIME_ACTUATOR => Some(0),
        CHAN_AUDIO | CHAN_TELEMETRY => Some(1),
        CHAN_VIDEO => Some(2),
        CHAN_CLIPBOARD | CHAN_FILE_TRANSFER | CHAN_DIAGNOSTICS => Some(3),
        _ => None,
    }
}

pub fn channel_priority_matches(chan_id: u8, pp: u8) -> bool {
    match chan_id {
        CHAN_TRANSPORT_CTRL | CHAN_INPUT_HID | CHAN_REALTIME_ACTUATOR => pp == 0,
        CHAN_AUDIO => pp == 1,
        CHAN_VIDEO => pp == 2,
        CHAN_CLIPBOARD | CHAN_FILE_TRANSFER | CHAN_DIAGNOSTICS => pp == 3,
        CHAN_TELEMETRY => pp == 0 || pp == 1,
        _ => false,
    }
}

/// RFC 1982 modular 32-bit sequence comparison (`a > b`).
pub fn seq_u32_gt(a: u32, b: u32) -> bool {
    let diff = a.wrapping_sub(b);
    diff != 0 && diff < 0x8000_0000
}
