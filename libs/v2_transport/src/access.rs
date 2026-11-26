// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use crate::{
    constants::{
        seq_u32_gt, ACCESS_HDR_V10_LEN, ACCESS_HDR_V11_LEN, BW_EVENT_DROP_ACTIVE,
        BW_EVENT_PAUSE_FILE_CHUNK, EDGE_CTRL_BW_HINT, EDGE_CTRL_LEG_NACK, EDGE_CTRL_MTU_HINT,
        EDGE_CTRL_PING, EDGE_CTRL_PONG, EDGE_CTRL_REKEY_ACCESS, EDGE_CTRL_TICKET_EXPIRING,
        LEG_CACHE_MAX_BYTES, LEG_CACHE_TTL_MS, LEG_NACK_VIDEO_MAX_AGE_MS, LEG_REKEY_GRACE_MS,
        MAGIC_VER, STREAM_FRAME_MAX_LEN, STREAM_FRAME_MIN_LEN, UDP_CTRL_MAX_LEN, UDP_L3_MIN_LEN,
        UDP_MAX_LEN, UDP_MIN_LEN,
    },
    error::TransportError,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::{BTreeMap, VecDeque};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

type HmacSha256 = Hmac<Sha256>;

pub const ACCESS_HKDF_LABEL: &[u8; 8] = b"v2mac-v1";
pub const TRANSPORT_DATAGRAM: u8 = 0;
pub const TRANSPORT_STREAM: u8 = 1;
pub const DIR_CLIENT_TO_EDGE: u8 = 0;
pub const DIR_EDGE_TO_CLIENT: u8 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessFlags {
    pub pp: u8,
    pub discardable: bool,
    pub frame_end: bool,
    pub is_ctrl_edge: bool,
    pub dir_edge_to_client: bool,
    pub rtx: bool,
}

impl AccessFlags {
    pub fn to_u16(self) -> u16 {
        let mut v: u16 = ((self.pp & 0x03) as u16) << 14;
        if self.discardable {
            v |= 1 << 13;
        }
        if self.frame_end {
            v |= 1 << 12;
        }
        if self.is_ctrl_edge {
            v |= 1 << 11;
        }
        if self.dir_edge_to_client {
            v |= 1 << 10;
        }
        if self.rtx {
            v |= 1 << 9;
        }
        v
    }

    pub fn from_u16(raw: u16) -> Result<Self, TransportError> {
        if raw & 0x01FF != 0 {
            return Err(TransportError::InvalidFraming(
                "access header reserved bits must be zero".into(),
            ));
        }
        Ok(Self {
            pp: ((raw >> 14) & 0x03) as u8,
            discardable: (raw >> 13) & 1 != 0,
            frame_end: (raw >> 12) & 1 != 0,
            is_ctrl_edge: (raw >> 11) & 1 != 0,
            dir_edge_to_client: (raw >> 10) & 1 != 0,
            rtx: (raw >> 9) & 1 != 0,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessHeaderV11 {
    pub flags: AccessFlags,
    pub route_cid: [u8; 8],
    pub access_epoch: u32,
    pub leg_seq: u32,
    pub mac_64: [u8; 8],
}

impl AccessHeaderV11 {
    pub fn encode_mac_zero(&self) -> [u8; ACCESS_HDR_V11_LEN] {
        let mut buf = [0u8; ACCESS_HDR_V11_LEN];
        buf[0..2].copy_from_slice(&MAGIC_VER.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_u16().to_be_bytes());
        buf[4..12].copy_from_slice(&self.route_cid);
        buf[12..16].copy_from_slice(&self.access_epoch.to_be_bytes());
        buf[16..20].copy_from_slice(&self.leg_seq.to_be_bytes());
        buf
    }

    pub fn encode(&self) -> [u8; ACCESS_HDR_V11_LEN] {
        let mut buf = self.encode_mac_zero();
        buf[20..28].copy_from_slice(&self.mac_64);
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < ACCESS_HDR_V11_LEN {
            return Err(TransportError::InvalidFraming(
                "truncated v1.1 access header".into(),
            ));
        }
        let magic_ver = u16::from_be_bytes([bytes[0], bytes[1]]);
        if magic_ver != MAGIC_VER {
            if (magic_ver >> 4) == (MAGIC_VER >> 4) {
                return Err(TransportError::UnsupportedVersion);
            }
            return Err(TransportError::InvalidFraming("invalid magic_ver".into()));
        }
        let flags_raw = u16::from_be_bytes([bytes[2], bytes[3]]);
        let flags = AccessFlags::from_u16(flags_raw)?;
        let mut route_cid = [0u8; 8];
        route_cid.copy_from_slice(&bytes[4..12]);
        let access_epoch = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let leg_seq = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
        let mut mac_64 = [0u8; 8];
        mac_64.copy_from_slice(&bytes[20..28]);
        Ok(Self {
            flags,
            route_cid,
            access_epoch,
            leg_seq,
            mac_64,
        })
    }

    pub fn validate_udp_ingress(&self, total_len: usize) -> Result<(), TransportError> {
        if !(UDP_MIN_LEN..=UDP_MAX_LEN).contains(&total_len) {
            return Err(TransportError::InvalidFraming(
                "udp packet length out of [30, 1228]".into(),
            ));
        }
        if self.flags.frame_end {
            return Err(TransportError::InvalidFraming(
                "udp access header must have e=0".into(),
            ));
        }
        if self.flags.dir_edge_to_client {
            return Err(TransportError::InvalidFraming(
                "ingress udp access header must have r=0".into(),
            ));
        }
        if self.flags.is_ctrl_edge {
            if total_len > UDP_CTRL_MAX_LEN || self.leg_seq != 0 {
                return Err(TransportError::InvalidFraming(
                    "invalid edge control frame length or non-zero leg_seq".into(),
                ));
            }
        } else if total_len < UDP_L3_MIN_LEN {
            return Err(TransportError::InvalidFraming(
                "udp L3 packet shorter than 60 bytes".into(),
            ));
        }
        Ok(())
    }

    /// RTT sampling MUST ignore packets with `rtx == true` (`x = 1`).
    pub fn eligible_for_rtt_sample(&self) -> bool {
        !self.flags.rtx
    }
}

/// Legacy v1.0 24-byte UDP access header (for mixed Leg 1 v1.0 <-> Leg 3 v1.1 interop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessHeaderV10 {
    pub flags: AccessFlags,
    pub route_cid: [u8; 8],
    pub access_epoch: u32,
    pub mac_64: [u8; 8],
}

impl AccessHeaderV10 {
    pub fn encode_mac_zero(&self) -> [u8; ACCESS_HDR_V10_LEN] {
        let mut buf = [0u8; ACCESS_HDR_V10_LEN];
        buf[0..2].copy_from_slice(&MAGIC_VER.to_be_bytes());
        buf[2..4].copy_from_slice(&self.flags.to_u16().to_be_bytes());
        buf[4..12].copy_from_slice(&self.route_cid);
        buf[12..16].copy_from_slice(&self.access_epoch.to_be_bytes());
        buf
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < ACCESS_HDR_V10_LEN {
            return Err(TransportError::InvalidFraming(
                "truncated v1.0 access header".into(),
            ));
        }
        let magic_ver = u16::from_be_bytes([bytes[0], bytes[1]]);
        if magic_ver != MAGIC_VER {
            return Err(TransportError::UnsupportedVersion);
        }
        let flags = AccessFlags::from_u16(u16::from_be_bytes([bytes[2], bytes[3]]))?;
        let mut route_cid = [0u8; 8];
        route_cid.copy_from_slice(&bytes[4..12]);
        let access_epoch = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
        let mut mac_64 = [0u8; 8];
        mac_64.copy_from_slice(&bytes[16..24]);
        Ok(Self {
            flags,
            route_cid,
            access_epoch,
            mac_64,
        })
    }
}

/// Derives `(prk, key_dir)` using V2 spec §2.1 HKDF-SHA256 `v2mac-v1`.
pub fn derive_access_key_with_prk(
    route_cid: &[u8; 8],
    hs_hash: &[u8; 32],
    transport: u8,
    dir: u8,
    access_epoch: u32,
) -> Result<([u8; 32], [u8; 32]), TransportError> {
    let (prk_ga, hkdf) = Hkdf::<Sha256>::extract(Some(route_cid), hs_hash);
    let mut prk = [0u8; 32];
    prk.copy_from_slice(&prk_ga);

    let mut info = [0u8; 14];
    info[0..8].copy_from_slice(ACCESS_HKDF_LABEL);
    info[8] = transport;
    info[9] = dir;
    info[10..14].copy_from_slice(&access_epoch.to_be_bytes());

    let mut key_dir = [0u8; 32];
    hkdf.expand(&info, &mut key_dir)
        .map_err(|_| TransportError::InvalidFraming("hkdf expand failed".into()))?;
    Ok((prk, key_dir))
}

pub fn derive_access_key(
    route_cid: &[u8; 8],
    hs_hash: &[u8; 32],
    transport: u8,
    dir: u8,
    access_epoch: u32,
) -> Result<[u8; 32], TransportError> {
    Ok(derive_access_key_with_prk(route_cid, hs_hash, transport, dir, access_epoch)?.1)
}

/// Derives a role-isolated L2c TLS-443 stream directional MAC key (`transport = 1`, `stream_role = 1|2`):
/// `info (15B) = "v2mac-v1" || u8(1) || u8(dir) || u32_be(access_epoch) || u8(stream_role)`.
pub fn derive_stream_role_key(
    route_cid: &[u8; 8],
    hs_hash: &[u8; 32],
    dir: u8,
    access_epoch: u32,
    stream_role: u8,
) -> Result<[u8; 32], TransportError> {
    let (_, hkdf) = Hkdf::<Sha256>::extract(Some(route_cid), hs_hash);
    let mut info = [0u8; 15];
    info[0..8].copy_from_slice(ACCESS_HKDF_LABEL);
    info[8] = TRANSPORT_STREAM;
    info[9] = dir;
    info[10..14].copy_from_slice(&access_epoch.to_be_bytes());
    info[14] = stream_role;

    let mut key_dir = [0u8; 32];
    hkdf.expand(&info, &mut key_dir)
        .map_err(|_| TransportError::InvalidFraming("hkdf expand failed".into()))?;
    Ok(key_dir)
}

pub fn compute_udp_mac64(
    key_dir: &[u8; 32],
    hdr_mac_zero: &[u8],
    payload: &[u8],
) -> Result<[u8; 8], TransportError> {
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| TransportError::InvalidFraming("payload exceeds u16::MAX".into()))?;
    let mut mac = HmacSha256::new_from_slice(key_dir)
        .map_err(|_| TransportError::InvalidFraming("invalid hmac key".into()))?;
    mac.update(hdr_mac_zero);
    mac.update(&payload_len.to_be_bytes());
    mac.update(payload);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[0..8]);
    Ok(out)
}

pub fn compute_stream_mac64(
    key_dir: &[u8; 32],
    hdr_mac_zero: &[u8; ACCESS_HDR_V11_LEN],
    frame_id: u32,
    payload: &[u8],
) -> Result<[u8; 8], TransportError> {
    let payload_len = u16::try_from(payload.len())
        .map_err(|_| TransportError::InvalidFraming("payload exceeds u16::MAX".into()))?;
    let mut mac = HmacSha256::new_from_slice(key_dir)
        .map_err(|_| TransportError::InvalidFraming("invalid hmac key".into()))?;
    mac.update(hdr_mac_zero);
    mac.update(&frame_id.to_be_bytes());
    mac.update(&payload_len.to_be_bytes());
    mac.update(payload);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; 8];
    out.copy_from_slice(&full[0..8]);
    Ok(out)
}

pub fn verify_mac64_ct(expected: &[u8; 8], received: &[u8; 8]) -> Result<(), TransportError> {
    if bool::from(expected.ct_eq(received)) {
        Ok(())
    } else {
        Err(TransportError::InvalidMac)
    }
}

pub fn seal_udp_v11(
    key_dir: &[u8; 32],
    mut hdr: AccessHeaderV11,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let hdr_zero = hdr.encode_mac_zero();
    hdr.mac_64 = compute_udp_mac64(key_dir, &hdr_zero, payload)?;
    let mut out = Vec::with_capacity(ACCESS_HDR_V11_LEN + payload.len());
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn seal_stream_v11(
    key_dir: &[u8; 32],
    mut hdr: AccessHeaderV11,
    frame_id: u32,
    payload: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let frame_len = ACCESS_HDR_V11_LEN + 4 + payload.len();
    if !(STREAM_FRAME_MIN_LEN..=STREAM_FRAME_MAX_LEN).contains(&frame_len) {
        return Err(TransportError::InvalidFraming(
            "stream frame_len out of [34, 1232]".into(),
        ));
    }
    let hdr_zero = hdr.encode_mac_zero();
    hdr.mac_64 = compute_stream_mac64(key_dir, &hdr_zero, frame_id, payload)?;
    let mut out = Vec::with_capacity(4 + frame_len);
    out.extend_from_slice(&(frame_len as u32).to_be_bytes());
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(&frame_id.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedStreamFrame {
    pub header: AccessHeaderV11,
    pub frame_id: u32,
    pub payload: Vec<u8>,
}

/// Incremental TCP/WebSocket stream parser that strictly enforces
/// `34 <= frame_len <= 1232` before allocation and fails immediately on bad length.
#[derive(Debug, Default)]
pub struct StreamFrameParser {
    buf: Vec<u8>,
}

impl StreamFrameParser {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn feed(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    pub fn next_frame(&mut self) -> Result<Option<DecodedStreamFrame>, TransportError> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let frame_len =
            u32::from_be_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if !(STREAM_FRAME_MIN_LEN..=STREAM_FRAME_MAX_LEN).contains(&frame_len) {
            return Err(TransportError::InvalidFraming(format!(
                "illegal stream frame_len {frame_len}"
            )));
        }
        if self.buf.len() < 4 + frame_len {
            return Ok(None);
        }
        let frame_bytes: Vec<u8> = self.buf.drain(0..4 + frame_len).collect();
        let header = AccessHeaderV11::decode(&frame_bytes[4..4 + ACCESS_HDR_V11_LEN])?;
        let fid_off = 4 + ACCESS_HDR_V11_LEN;
        let frame_id = u32::from_be_bytes([
            frame_bytes[fid_off],
            frame_bytes[fid_off + 1],
            frame_bytes[fid_off + 2],
            frame_bytes[fid_off + 3],
        ]);
        let payload = frame_bytes[fid_off + 4..].to_vec();
        Ok(Some(DecodedStreamFrame {
            header,
            frame_id,
            payload,
        }))
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct PrecomputedEpochKey {
    #[zeroize(skip)]
    epoch: u32,
    key: [u8; 32],
}

/// Precomputed per-session directional MAC key state implementing V2 §2.1
/// `{cur-1, cur, cur+1}` `access_epoch` promotion and `grace = max(2s, 4*RTT)`.
pub struct AccessEpochState {
    route_cid: [u8; 8],
    hs_hash: Zeroizing<[u8; 32]>,
    transport: u8,
    dir: u8,
    cur_epoch: u32,
    cur_key: PrecomputedEpochKey,
    prev_key: Option<PrecomputedEpochKey>,
    prev_expire_ms: Option<u64>,
    grace_ms: u64,
}

impl AccessEpochState {
    pub fn new(
        route_cid: [u8; 8],
        hs_hash: [u8; 32],
        transport: u8,
        dir: u8,
        initial_epoch: u32,
        rtt_ms: u64,
    ) -> Result<Self, TransportError> {
        let hs_hash = Zeroizing::new(hs_hash);
        let key = derive_access_key(&route_cid, &hs_hash, transport, dir, initial_epoch)?;
        let prev_key = if initial_epoch > 0 {
            let pk = derive_access_key(&route_cid, &hs_hash, transport, dir, initial_epoch - 1)?;
            Some(PrecomputedEpochKey {
                epoch: initial_epoch - 1,
                key: pk,
            })
        } else {
            None
        };
        Ok(Self {
            route_cid,
            hs_hash,
            transport,
            dir,
            cur_epoch: initial_epoch,
            cur_key: PrecomputedEpochKey {
                epoch: initial_epoch,
                key,
            },
            prev_key,
            prev_expire_ms: None,
            grace_ms: 2_000u64.max(rtt_ms.saturating_mul(4)),
        })
    }

    pub fn cur_epoch(&self) -> u32 {
        self.cur_epoch
    }

    pub fn cur_key(&self) -> &[u8; 32] {
        &self.cur_key.key
    }

    /// Returns the precomputed directional MAC key for `epoch` (`cur` or `cur-1`).
    pub fn key_for_epoch(&self, epoch: u32) -> Option<&[u8; 32]> {
        if epoch == self.cur_key.epoch {
            return Some(&self.cur_key.key);
        }
        if let Some(prev) = &self.prev_key {
            if epoch == prev.epoch {
                return Some(&prev.key);
            }
        }
        None
    }

    /// Advances sender-side directional key to `new_epoch`, keeping the old key
    /// in `prev_key` for `grace_ms` so in-flight `LEG_NACK` retransmissions can
    /// still compute valid old-epoch MACs.
    pub fn advance_epoch(&mut self, new_epoch: u32, now_ms: u64) -> Result<(), TransportError> {
        if new_epoch <= self.cur_epoch {
            return Err(TransportError::AccessEpochRejected);
        }
        let next_key =
            derive_access_key(&self.route_cid, &self.hs_hash, self.transport, self.dir, new_epoch)?;
        let old_cur = std::mem::replace(
            &mut self.cur_key,
            PrecomputedEpochKey {
                epoch: new_epoch,
                key: next_key,
            },
        );
        self.prev_key = Some(old_cur);
        self.prev_expire_ms = Some(now_ms.saturating_add(self.grace_ms));
        self.cur_epoch = new_epoch;
        Ok(())
    }

    /// Verifies a v1.1 UDP packet's `mac_64`.
    /// - Rejects `epoch < cur-1` and `epoch > cur+1`.
    /// - Rejects `cur-1` once grace window has expired.
    /// - On valid `cur+1`, promotes `cur <- cur+1` and sets grace deadline for old `cur`.
    /// - Forged `cur+1` fails MAC verification and NEVER promotes `cur`.
    pub fn verify_udp_packet<'a>(
        &mut self,
        packet: &'a [u8],
        now_ms: u64,
    ) -> Result<(AccessHeaderV11, &'a [u8]), TransportError> {
        if packet.len() < ACCESS_HDR_V11_LEN {
            return Err(TransportError::InvalidFraming("packet too short".into()));
        }
        let hdr = AccessHeaderV11::decode(&packet[..ACCESS_HDR_V11_LEN])?;
        if hdr.route_cid != self.route_cid {
            return Err(TransportError::InvalidFraming("route_cid mismatch".into()));
        }
        let payload = &packet[ACCESS_HDR_V11_LEN..];
        let hdr_zero = hdr.encode_mac_zero();

        if hdr.access_epoch == self.cur_epoch {
            let expected = compute_udp_mac64(&self.cur_key.key, &hdr_zero, payload)?;
            verify_mac64_ct(&expected, &hdr.mac_64)?;
            return Ok((hdr, payload));
        }

        if let Some(prev) = &self.prev_key {
            if hdr.access_epoch == prev.epoch {
                if let Some(deadline) = self.prev_expire_ms {
                    if now_ms > deadline {
                        self.prev_key = None;
                        self.prev_expire_ms = None;
                        return Err(TransportError::AccessEpochRejected);
                    }
                }
                let expected = compute_udp_mac64(&prev.key, &hdr_zero, payload)?;
                verify_mac64_ct(&expected, &hdr.mac_64)?;
                return Ok((hdr, payload));
            }
        }

        if let Some(next_epoch) = self.cur_epoch.checked_add(1) {
            if hdr.access_epoch == next_epoch {
                let candidate_key = derive_access_key(
                    &self.route_cid,
                    &self.hs_hash,
                    self.transport,
                    self.dir,
                    next_epoch,
                )?;
                let expected = compute_udp_mac64(&candidate_key, &hdr_zero, payload)?;
                verify_mac64_ct(&expected, &hdr.mac_64)?;
                let old_cur = std::mem::replace(
                    &mut self.cur_key,
                    PrecomputedEpochKey {
                        epoch: next_epoch,
                        key: candidate_key,
                    },
                );
                self.prev_key = Some(old_cur);
                self.prev_expire_ms = Some(now_ms.saturating_add(self.grace_ms));
                self.cur_epoch = next_epoch;
                return Ok((hdr, payload));
            }
        }

        Err(TransportError::AccessEpochRejected)
    }
}

/// Per-leg 256-entry modular `u32` deduplication window for `leg_seq`.
#[derive(Debug, Clone)]
pub struct LegSeqDedupWindow {
    initialized: bool,
    highest: u32,
    bitmap: [u64; 4], // 256 bits
}

impl Default for LegSeqDedupWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl LegSeqDedupWindow {
    pub fn new() -> Self {
        Self {
            initialized: false,
            highest: 0,
            bitmap: [0; 4],
        }
    }

    /// Returns `true` if `leg_seq` is new and recorded; `false` if duplicate or too old.
    pub fn check_and_mark(&mut self, leg_seq: u32) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = leg_seq;
            self.bitmap = [0; 4];
            self.set_bit(0);
            return true;
        }
        if leg_seq == self.highest {
            return false;
        }
        if seq_u32_gt(leg_seq, self.highest) {
            let shift = leg_seq.wrapping_sub(self.highest) as usize;
            self.shift_left(shift);
            self.highest = leg_seq;
            self.set_bit(0);
            true
        } else {
            let delta = self.highest.wrapping_sub(leg_seq) as usize;
            if delta >= 256 {
                return false;
            }
            if self.get_bit(delta) {
                return false;
            }
            self.set_bit(delta);
            true
        }
    }

    fn get_bit(&self, idx: usize) -> bool {
        (self.bitmap[idx / 64] >> (idx % 64)) & 1 != 0
    }

    fn set_bit(&mut self, idx: usize) {
        self.bitmap[idx / 64] |= 1u64 << (idx % 64);
    }

    fn shift_left(&mut self, shift: usize) {
        if shift >= 256 {
            self.bitmap = [0; 4];
            return;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut next = [0u64; 4];
        for (i, slot) in next.iter_mut().enumerate() {
            if i >= word_shift {
                let src = i - word_shift;
                *slot |= self.bitmap[src] << bit_shift;
                if bit_shift > 0 && src > 0 {
                    *slot |= self.bitmap[src - 1] >> (64 - bit_shift);
                }
            }
        }
        self.bitmap = next;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeCtrlFrame {
    Ping {
        ts_us: u64,
    },
    Pong {
        ts_us: u64,
    },
    RekeyAccess {
        new_access_epoch: u32,
    },
    TicketExpiring {
        remain_sec: u32,
    },
    MtuHint {
        suggested_l3_mtu: u16,
    },
    LegNack {
        base_leg_seq: u32,
        loss_bitmap: u64,
    },
    BwHint {
        cap_kbps: u32,
        queue_delay_ms: u16,
        report_age_ms: u16,
        bottleneck_leg: u8,
        event_flags: u8,
    },
}

impl EdgeCtrlFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match *self {
            Self::Ping { ts_us } => {
                out.push(EDGE_CTRL_PING);
                out.push(8);
                out.extend_from_slice(&ts_us.to_be_bytes());
            }
            Self::Pong { ts_us } => {
                out.push(EDGE_CTRL_PONG);
                out.push(8);
                out.extend_from_slice(&ts_us.to_be_bytes());
            }
            Self::RekeyAccess { new_access_epoch } => {
                out.push(EDGE_CTRL_REKEY_ACCESS);
                out.push(4);
                out.extend_from_slice(&new_access_epoch.to_be_bytes());
            }
            Self::TicketExpiring { remain_sec } => {
                out.push(EDGE_CTRL_TICKET_EXPIRING);
                out.push(4);
                out.extend_from_slice(&remain_sec.to_be_bytes());
            }
            Self::MtuHint { suggested_l3_mtu } => {
                out.push(EDGE_CTRL_MTU_HINT);
                out.push(2);
                out.extend_from_slice(&suggested_l3_mtu.to_be_bytes());
            }
            Self::LegNack {
                base_leg_seq,
                loss_bitmap,
            } => {
                out.push(EDGE_CTRL_LEG_NACK);
                out.push(12);
                out.extend_from_slice(&base_leg_seq.to_be_bytes());
                out.extend_from_slice(&loss_bitmap.to_be_bytes());
            }
            Self::BwHint {
                cap_kbps,
                queue_delay_ms,
                report_age_ms,
                bottleneck_leg,
                event_flags,
            } => {
                out.push(EDGE_CTRL_BW_HINT);
                out.push(10);
                out.extend_from_slice(&cap_kbps.to_be_bytes());
                out.extend_from_slice(&queue_delay_ms.to_be_bytes());
                out.extend_from_slice(&report_age_ms.to_be_bytes());
                out.push(bottleneck_leg);
                out.push(event_flags);
            }
        }
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < 2 {
            return Err(TransportError::InvalidFraming(
                "edge control frame shorter than 2 bytes".into(),
            ));
        }
        let msg_type = bytes[0];
        let body_len = bytes[1] as usize;
        if bytes.len() != 2 + body_len {
            return Err(TransportError::InvalidFraming(
                "edge control body_len mismatch".into(),
            ));
        }
        let b = &bytes[2..];
        match (msg_type, body_len) {
            (EDGE_CTRL_PING, 8) => Ok(Self::Ping {
                ts_us: u64::from_be_bytes(b.try_into().map_err(|_| {
                    TransportError::InvalidFraming("ping slice".into())
                })?),
            }),
            (EDGE_CTRL_PONG, 8) => Ok(Self::Pong {
                ts_us: u64::from_be_bytes(b.try_into().map_err(|_| {
                    TransportError::InvalidFraming("pong slice".into())
                })?),
            }),
            (EDGE_CTRL_REKEY_ACCESS, 4) => Ok(Self::RekeyAccess {
                new_access_epoch: u32::from_be_bytes(b.try_into().map_err(|_| {
                    TransportError::InvalidFraming("rekey slice".into())
                })?),
            }),
            (EDGE_CTRL_TICKET_EXPIRING, 4) => Ok(Self::TicketExpiring {
                remain_sec: u32::from_be_bytes(b.try_into().map_err(|_| {
                    TransportError::InvalidFraming("ticket_expiring slice".into())
                })?),
            }),
            (EDGE_CTRL_MTU_HINT, 2) => Ok(Self::MtuHint {
                suggested_l3_mtu: u16::from_be_bytes(b.try_into().map_err(|_| {
                    TransportError::InvalidFraming("mtu_hint slice".into())
                })?),
            }),
            (EDGE_CTRL_LEG_NACK, 12) => Ok(Self::LegNack {
                base_leg_seq: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                loss_bitmap: u64::from_be_bytes([
                    b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11],
                ]),
            }),
            (EDGE_CTRL_BW_HINT, 10) => Ok(Self::BwHint {
                cap_kbps: u32::from_be_bytes([b[0], b[1], b[2], b[3]]),
                queue_delay_ms: u16::from_be_bytes([b[4], b[5]]),
                report_age_ms: u16::from_be_bytes([b[6], b[7]]),
                bottleneck_leg: b[8],
                event_flags: b[9],
            }),
            _ => Err(TransportError::InvalidFraming(format!(
                "unknown or malformed edge ctrl msg_type={msg_type:#x}, body_len={body_len}"
            ))),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CachedLegPacket {
    pub header: AccessHeaderV11,
    pub l3_payload: Vec<u8>,
    pub inserted_ms: u64,
    pub last_rtx_ms: Option<u64>,
    pub rtx_count: u8,
}

impl CachedLegPacket {
    pub fn wire_len(&self) -> usize {
        ACCESS_HDR_V11_LEN + self.l3_payload.len()
    }
}

/// 150ms / 512KB per-session ciphertext cache for `LEG_NACK` local recovery.
///
/// Enforces every anti-amplification invariant of V2 §2.2:
/// - `d=1` discardable packets are never cached (0 RTX).
/// - `p0/p1/p2` max 2 retransmissions (total <= 3 wire emissions); `p3` max 1 RTX.
/// - 2nd RTX spaced by `>= 1 * rtt_ms`.
/// - Video (`p2`) entries older than 100ms are never retransmitted; all entries older than 150ms evicted.
/// - Old-epoch entries honored only within 150ms grace; hard rekey clears cache immediately.
/// - Every `LEG_NACK` retransmission sets `flags.rtx = true` (`x = 1`) and recomputes `mac_64`
///   with the precomputed directional key for `entry.header.access_epoch`.
/// - When the 512KB cache is full, lower-priority packets (larger `pp`) NEVER evict higher-priority packets.
/// - 100% of original + retransmitted bytes counted in `billed_bytes`.
#[derive(Debug)]
pub struct LegCiphertextCache {
    entries: BTreeMap<u32, CachedLegPacket>,
    order: VecDeque<u32>,
    total_bytes: usize,
    pub billed_bytes: u64,
    pub rtx_emitted_bytes: u64,
    pub orig_emitted_bytes: u64,
    cur_epoch: u32,
    rekey_at_ms: Option<u64>,
}

impl LegCiphertextCache {
    pub fn new(initial_epoch: u32) -> Self {
        Self {
            entries: BTreeMap::new(),
            order: VecDeque::new(),
            total_bytes: 0,
            billed_bytes: 0,
            rtx_emitted_bytes: 0,
            orig_emitted_bytes: 0,
            cur_epoch: initial_epoch,
            rekey_at_ms: None,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes
    }

    pub fn contains_seq(&self, leg_seq: u32) -> bool {
        self.entries.contains_key(&leg_seq)
    }

    pub fn record_original(
        &mut self,
        hdr: &AccessHeaderV11,
        l3_payload: Vec<u8>,
        now_ms: u64,
    ) {
        let wire_len = ACCESS_HDR_V11_LEN + l3_payload.len();
        let len = wire_len as u64;
        self.billed_bytes = self.billed_bytes.saturating_add(len);
        self.orig_emitted_bytes = self.orig_emitted_bytes.saturating_add(len);
        if hdr.flags.is_ctrl_edge || hdr.flags.discardable {
            return;
        }
        self.evict_expired(now_ms);
        if wire_len > LEG_CACHE_MAX_BYTES {
            return;
        }
        let existing_len = self
            .entries
            .get(&hdr.leg_seq)
            .map(CachedLegPacket::wire_len)
            .unwrap_or(0);
        let projected = self.total_bytes.saturating_sub(existing_len) + wire_len;
        if projected > LEG_CACHE_MAX_BYTES {
            let needed = projected - LEG_CACHE_MAX_BYTES;
            // Lower priority (larger pp) MUST NEVER evict higher priority (smaller pp).
            let evictable_bytes: usize = self
                .entries
                .values()
                .filter(|e| e.header.leg_seq != hdr.leg_seq && e.header.flags.pp >= hdr.flags.pp)
                .map(CachedLegPacket::wire_len)
                .sum();
            if evictable_bytes < needed {
                return;
            }
            while self.total_bytes.saturating_sub(existing_len) + wire_len > LEG_CACHE_MAX_BYTES {
                if !self.evict_lowest_priority(hdr.flags.pp, hdr.leg_seq) {
                    break;
                }
            }
        }
        if self.total_bytes.saturating_sub(existing_len) + wire_len > LEG_CACHE_MAX_BYTES {
            return;
        }
        if let Some(old) = self.entries.remove(&hdr.leg_seq) {
            self.total_bytes = self.total_bytes.saturating_sub(old.wire_len());
            if let Some(pos) = self.order.iter().position(|&s| s == hdr.leg_seq) {
                self.order.remove(pos);
            }
        }
        self.total_bytes += wire_len;
        self.order.push_back(hdr.leg_seq);
        self.entries.insert(
            hdr.leg_seq,
            CachedLegPacket {
                header: *hdr,
                l3_payload,
                inserted_ms: now_ms,
                last_rtx_ms: None,
                rtx_count: 0,
            },
        );
    }

    pub fn on_soft_rekey(&mut self, new_epoch: u32, now_ms: u64) {
        self.cur_epoch = new_epoch;
        self.rekey_at_ms = Some(now_ms);
    }

    pub fn on_hard_rekey_clear(&mut self, new_epoch: u32) {
        self.cur_epoch = new_epoch;
        self.rekey_at_ms = None;
        self.entries.clear();
        self.order.clear();
        self.total_bytes = 0;
    }

    pub fn handle_leg_nack(
        &mut self,
        base_leg_seq: u32,
        loss_bitmap: u64,
        now_ms: u64,
        rtt_ms: u64,
        rtx_budget_bytes: Option<usize>,
        epoch_state: &AccessEpochState,
    ) -> Vec<Vec<u8>> {
        self.evict_expired(now_ms);
        let mut candidates = Vec::new();
        for bit in 0..64u32 {
            if (loss_bitmap >> bit) & 1 == 0 {
                continue;
            }
            let seq = base_leg_seq.wrapping_add(bit);
            if let Some(entry) = self.entries.get(&seq) {
                if !self.is_eligible_for_rtx(entry, now_ms, rtt_ms) {
                    continue;
                }
                candidates.push((entry.header.flags.pp, seq));
            }
        }
        // Serve highest priority (smallest pp) first when token bucket is tight.
        candidates.sort_by_key(|&(pp, seq)| (pp, seq));

        let mut remaining_budget = rtx_budget_bytes.unwrap_or(usize::MAX);
        let mut out = Vec::new();
        for (_, seq) in candidates {
            if let Some(entry) = self.entries.get_mut(&seq) {
                let wire_len = entry.wire_len();
                if wire_len > remaining_budget {
                    continue;
                }
                let Some(key_dir) = epoch_state.key_for_epoch(entry.header.access_epoch) else {
                    continue;
                };
                let mut rtx_hdr = entry.header;
                rtx_hdr.flags.rtx = true;
                rtx_hdr.mac_64 = [0; 8];
                let Ok(pkt) = seal_udp_v11(key_dir, rtx_hdr, &entry.l3_payload) else {
                    continue;
                };
                remaining_budget -= wire_len;
                entry.rtx_count += 1;
                entry.last_rtx_ms = Some(now_ms);
                let len = pkt.len() as u64;
                self.billed_bytes = self.billed_bytes.saturating_add(len);
                self.rtx_emitted_bytes = self.rtx_emitted_bytes.saturating_add(len);
                out.push(pkt);
            }
        }
        out
    }

    fn is_eligible_for_rtx(&self, entry: &CachedLegPacket, now_ms: u64, rtt_ms: u64) -> bool {
        if entry.header.access_epoch != self.cur_epoch {
            match self.rekey_at_ms {
                Some(t) if now_ms.saturating_sub(t) <= LEG_REKEY_GRACE_MS => {}
                _ => return false,
            }
        }
        let max_age_ms = if entry.header.flags.pp == 2 {
            LEG_NACK_VIDEO_MAX_AGE_MS
        } else {
            LEG_CACHE_TTL_MS
        };
        if now_ms.saturating_sub(entry.inserted_ms) > max_age_ms {
            return false;
        }
        let max_rtx = if entry.header.flags.pp == 3 { 1 } else { 2 };
        if entry.rtx_count >= max_rtx {
            return false;
        }
        if let Some(last) = entry.last_rtx_ms {
            if now_ms.saturating_sub(last) < rtt_ms {
                return false;
            }
        }
        true
    }

    fn evict_expired(&mut self, now_ms: u64) {
        while let Some(&front) = self.order.front() {
            let expired = self
                .entries
                .get(&front)
                .map(|e| now_ms.saturating_sub(e.inserted_ms) > LEG_CACHE_TTL_MS)
                .unwrap_or(true);
            if expired {
                self.order.pop_front();
                if let Some(removed) = self.entries.remove(&front) {
                    self.total_bytes = self.total_bytes.saturating_sub(removed.wire_len());
                }
            } else {
                break;
            }
        }
    }

    fn evict_lowest_priority(&mut self, incoming_pp: u8, exclude_seq: u32) -> bool {
        let victim = self
            .entries
            .values()
            .filter(|e| e.header.leg_seq != exclude_seq && e.header.flags.pp >= incoming_pp)
            .max_by_key(|e| (e.header.flags.pp, std::cmp::Reverse(e.inserted_ms)))
            .map(|e| e.header.leg_seq);
        if let Some(seq) = victim {
            if let Some(removed) = self.entries.remove(&seq) {
                self.total_bytes = self.total_bytes.saturating_sub(removed.wire_len());
                if let Some(pos) = self.order.iter().position(|&s| s == seq) {
                    self.order.remove(pos);
                }
                return true;
            }
        }
        false
    }
}

/// Stateful three-leg `BW_HINT` controller matching V2 §2.2 & golden vector V20.
#[derive(Debug, Clone)]
pub struct BwHintController {
    lease_bw_cap_kbps: u32,
    current_bw_kbps: u32,
    last_drop_ms: Option<u64>,
    last_ramp_ms: Option<u64>,
    pub gcc_loss_backoff_disabled: bool,
    pub survival_mode: bool,
}

impl BwHintController {
    pub fn new(initial_e2e_gcc_kbps: u32, lease_bw_cap_kbps: u32) -> Self {
        Self {
            lease_bw_cap_kbps,
            current_bw_kbps: initial_e2e_gcc_kbps.min(lease_bw_cap_kbps),
            last_drop_ms: None,
            last_ramp_ms: None,
            gcc_loss_backoff_disabled: false,
            survival_mode: false,
        }
    }

    pub fn effective_bw_kbps(&self) -> u32 {
        self.current_bw_kbps
    }

    pub fn on_bw_hint(
        &mut self,
        e2e_gcc_kbps: u32,
        cap_kbps: u32,
        report_age_ms: u16,
        bottleneck_leg: u8,
        event_flags: u8,
        now_ms: u64,
    ) -> u32 {
        self.survival_mode = (event_flags & crate::constants::BW_EVENT_SURVIVAL_MODE) != 0;
        let e2e_cap = e2e_gcc_kbps.min(self.lease_bw_cap_kbps);

        // Stale report (> 500ms) reverts immediately to pure E2E GCC.
        if report_age_ms > 500 {
            self.gcc_loss_backoff_disabled = false;
            self.current_bw_kbps = e2e_cap;
            return self.current_bw_kbps;
        }

        // Random loss without queuing congestion (bottleneck_leg == 0):
        // disable GCC loss-based backoff and never reduce due to low cap_kbps.
        if bottleneck_leg == 0 {
            self.gcc_loss_backoff_disabled = true;
            let ceiling = e2e_cap.min(((cap_kbps as u64) * 9 / 10) as u32);
            let target = if cap_kbps >= e2e_cap { e2e_cap } else { e2e_cap.max(ceiling) };
            if target > self.current_bw_kbps {
                let hold_ok = self
                    .last_drop_ms
                    .map(|d| now_ms.saturating_sub(d) >= 1_000)
                    .unwrap_or(true);
                let ramp_ok = self
                    .last_ramp_ms
                    .map(|r| now_ms.saturating_sub(r) >= 500)
                    .unwrap_or(true);
                if hold_ok && ramp_ok {
                    let ramped = ((self.current_bw_kbps as u64) * 110 / 100) as u32;
                    self.current_bw_kbps = ramped.min(target);
                    self.last_ramp_ms = Some(now_ms);
                }
            }
            return self.current_bw_kbps;
        }

        self.gcc_loss_backoff_disabled = false;
        let hint_cap = ((cap_kbps as u64) * 9 / 10) as u32;
        let target = e2e_cap.min(hint_cap);

        if target < self.current_bw_kbps {
            // 10% deadband suppresses oscillation.
            let diff = self.current_bw_kbps - target;
            if (diff as u64) * 100 >= (self.current_bw_kbps as u64) * 10 {
                self.current_bw_kbps = target;
                self.last_drop_ms = Some(now_ms);
                self.last_ramp_ms = None;
            }
        }
        self.current_bw_kbps
    }
}

#[derive(Debug, Clone)]
pub struct QueuedStreamSlice {
    pub enqueue_ms: u64,
    pub frame_id: u32,
    pub flags: AccessFlags,
    pub wire_bytes: Vec<u8>,
}

/// TCP-443 stream queue implementing V2 §2.3 80ms HOL discard of complete
/// (`flags.e == 1`), discardable (`flags.d == 1`), non-zero `frame_id` video frames.
#[derive(Debug, Default)]
pub struct TcpStreamSendQueue {
    items: Vec<QueuedStreamSlice>,
}

impl TcpStreamSendQueue {
    pub fn push(&mut self, item: QueuedStreamSlice) {
        self.items.push(item);
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.items.iter().map(|i| i.wire_bytes.len()).sum()
    }

    pub fn pop_front(&mut self) -> Option<QueuedStreamSlice> {
        if self.items.is_empty() {
            None
        } else {
            Some(self.items.remove(0))
        }
    }

    pub fn drain_all(&mut self) -> Vec<QueuedStreamSlice> {
        std::mem::take(&mut self.items)
    }

    pub fn prune_hol_expired(
        &mut self,
        now_ms: u64,
        hol_threshold_ms: u64,
    ) -> (Vec<u32>, Option<EdgeCtrlFrame>) {
        let Some(head_age) = self
            .items
            .first()
            .map(|first| now_ms.saturating_sub(first.enqueue_ms))
        else {
            return (Vec::new(), None);
        };
        if head_age <= hol_threshold_ms {
            return (Vec::new(), None);
        }

        // Identify complete discardable non-zero frame_ids.
        let mut complete_discardable = std::collections::BTreeSet::new();
        for item in &self.items {
            if item.frame_id != 0 && item.flags.discardable && item.flags.frame_end {
                complete_discardable.insert(item.frame_id);
            }
        }
        if complete_discardable.is_empty() {
            return (Vec::new(), None);
        }

        let mut dropped = Vec::new();
        self.items.retain(|item| {
            if item.frame_id != 0 && complete_discardable.contains(&item.frame_id) {
                if !dropped.contains(&item.frame_id) {
                    dropped.push(item.frame_id);
                }
                false
            } else {
                true
            }
        });

        let bw_hint = EdgeCtrlFrame::BwHint {
            cap_kbps: 4_000,
            queue_delay_ms: head_age.min(u16::MAX as u64) as u16,
            report_age_ms: 0,
            bottleneck_leg: 1,
            event_flags: BW_EVENT_DROP_ACTIVE | BW_EVENT_PAUSE_FILE_CHUNK,
        };
        (dropped, Some(bw_hint))
    }

    pub fn surviving_frame_ids(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        for item in &self.items {
            if !ids.contains(&item.frame_id) {
                ids.push(item.frame_id);
            }
        }
        ids
    }
}
