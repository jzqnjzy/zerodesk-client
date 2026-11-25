use crate::{
    constants::{
        ACTUATOR_MAX_TTL_MS, ARQ_MAX_RETRIES, ARQ_MAX_RTO_MS, ARQ_MIN_RTO_MS, HID_STALE_DROP_MS,
        IDR_MIN_INTERVAL_MS, L3_HDR_LEN, L4_HDR_LEN, MAX_FUTURE_SKEW_MS, AEAD_TAG_LEN,
    },
    error::TransportError,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use v2_identity::ControlPreemptToken;

pub const STREAM_SEQ_DEDUP_CAPACITY: usize = 4096;
pub const VIDEO_REASSEMBLER_MAX_PARTIALS: usize = 64;
pub const VIDEO_REASSEMBLER_MAX_AGE_MS: u16 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L4Header {
    pub msg_type: u8,
    pub flags: u8,
    pub body_len: u16,
    pub stream_seq: u32,
}

impl L4Header {
    pub fn encode(&self) -> [u8; L4_HDR_LEN] {
        let mut out = [0u8; L4_HDR_LEN];
        out[0] = self.msg_type;
        out[1] = self.flags;
        out[2..4].copy_from_slice(&self.body_len.to_be_bytes());
        out[4..8].copy_from_slice(&self.stream_seq.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < L4_HDR_LEN {
            return Err(TransportError::InvalidFraming("L4 header truncated".into()));
        }
        Ok(Self {
            msg_type: bytes[0],
            flags: bytes[1],
            body_len: u16::from_be_bytes([bytes[2], bytes[3]]),
            stream_seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        })
    }
}

pub fn encode_l4_frame(header: &L4Header, body: &[u8]) -> Result<Vec<u8>, TransportError> {
    if body.len() != header.body_len as usize {
        return Err(TransportError::InvalidFraming(
            "L4 body_len does not match payload".into(),
        ));
    }
    let mut out = Vec::with_capacity(L4_HDR_LEN + body.len());
    out.extend_from_slice(&header.encode());
    out.extend_from_slice(body);
    Ok(out)
}

pub fn decode_l4_frame(bytes: &[u8]) -> Result<(L4Header, &[u8]), TransportError> {
    let hdr = L4Header::decode(bytes)?;
    let body = &bytes[L4_HDR_LEN..];
    if body.len() != hdr.body_len as usize {
        return Err(TransportError::InvalidFraming(
            "L4 frame payload length mismatch".into(),
        ));
    }
    Ok((hdr, body))
}

/// Computes the 64-bit SACK bitmap for sequences in `(cum_ack + 1)..=(cum_ack + 64)`.
pub fn build_sack_bitmap(cum_ack: u32, received_seqs: &[u32]) -> u64 {
    let mut bitmap = 0u64;
    for &seq in received_seqs {
        let delta = seq.wrapping_sub(cum_ack);
        if (1..=64).contains(&delta) {
            bitmap |= 1u64 << (delta - 1);
        }
    }
    bitmap
}

/// Computes ARQ RTO per V2 §5.2: `max(200ms, SRTT + 4*RTTVAR) * 2^retry`, capped at `3000ms`.
pub fn compute_rto_ms(srtt_ms: u64, rttvar_ms: u64, retry_count: u8) -> u64 {
    let base = ARQ_MIN_RTO_MS.max(srtt_ms.saturating_add(rttvar_ms.saturating_mul(4)));
    let mult = 1u64.checked_shl(retry_count.min(16) as u32).unwrap_or(u64::MAX);
    base.saturating_mul(mult).min(ARQ_MAX_RTO_MS)
}

/// Evaluates whether an ARQ retry count has breached the 8-retry path failure limit.
pub fn check_arq_retry_limit(retries: u8) -> Result<(), TransportError> {
    if retries >= ARQ_MAX_RETRIES {
        Err(TransportError::PathFailed)
    } else {
        Ok(())
    }
}

/// Computes effective `p3` flow-control credit window: `min(rwnd, cwnd)`.
pub fn effective_p3_credit(rwnd_bytes: u32, cwnd_bytes: u32) -> u32 {
    rwnd_bytes.min(cwnd_bytes)
}

/// Tracks `(chan_id, stream_seq)` deduplication across ARQ retransmits & 5ms dual-send
/// with a hard bounded entry cap (`STREAM_SEQ_DEDUP_CAPACITY`).
#[derive(Debug)]
pub struct StreamSeqDedup {
    max_entries: usize,
    seen: BTreeSet<(u8, u32)>,
    order: VecDeque<(u8, u32)>,
}

impl Default for StreamSeqDedup {
    fn default() -> Self {
        Self::with_capacity(STREAM_SEQ_DEDUP_CAPACITY)
    }
}

impl StreamSeqDedup {
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            max_entries: max_entries.max(1),
            seen: BTreeSet::new(),
            order: VecDeque::new(),
        }
    }

    pub fn len(&self) -> usize {
        self.seen.len()
    }

    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }

    pub fn mark_if_new(&mut self, chan_id: u8, stream_seq: u32) -> bool {
        let key = (chan_id, stream_seq);
        if self.seen.contains(&key) {
            return false;
        }
        while self.seen.len() >= self.max_entries {
            if let Some(oldest) = self.order.pop_front() {
                self.seen.remove(&oldest);
            } else {
                break;
            }
        }
        self.seen.insert(key);
        self.order.push_back(key);
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidEvent {
    Key { seq: u32, code: u16, enqueue_ms: u64 },
    MouseRel { seq: u32, dx: i32, dy: i32, enqueue_ms: u64 },
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HidBatchResult {
    pub acked_seqs: Vec<u32>,
    pub executed_keys: Vec<u32>,
    pub dropped_keys: Vec<u32>,
    pub accumulated_mouse_dx: i32,
    pub accumulated_mouse_dy: i32,
}

/// Processes queued `0x01 InputHID` events per V2 §5.2:
/// - Key events queued `> 150ms` are dropped without execution, but STILL ACKed.
/// - Relative mouse deltas are NEVER dropped; they are vector-accumulated even if stale.
pub fn process_hid_queue(events: &[HidEvent], now_ms: u64) -> HidBatchResult {
    let mut res = HidBatchResult::default();
    for ev in events {
        match *ev {
            HidEvent::Key {
                seq,
                code: _,
                enqueue_ms,
            } => {
                res.acked_seqs.push(seq);
                if now_ms.saturating_sub(enqueue_ms) > HID_STALE_DROP_MS {
                    res.dropped_keys.push(seq);
                } else {
                    res.executed_keys.push(seq);
                }
            }
            HidEvent::MouseRel {
                seq,
                dx,
                dy,
                enqueue_ms: _,
            } => {
                res.acked_seqs.push(seq);
                res.accumulated_mouse_dx = res.accumulated_mouse_dx.saturating_add(dx);
                res.accumulated_mouse_dy = res.accumulated_mouse_dy.saturating_add(dy);
            }
        }
    }
    res
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoSlice {
    pub codec_id: u8,
    pub frame_id: u32,
    pub ref_frame_id: u32,
    pub ltr_slot: u8,
    pub is_idr: bool,
    pub is_ref: bool,
    pub max_age_ms: u16,
    pub slice_idx: u16,
    pub slice_cnt: u16,
    pub data: Vec<u8>,
}

pub const VIDEO_SLICE_META_LEN: usize = 1 + 4 + 4 + 1 + 1 + 1 + 2 + 2 + 2; // 18 bytes

impl VideoSlice {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(VIDEO_SLICE_META_LEN + self.data.len());
        out.push(self.codec_id);
        out.extend_from_slice(&self.frame_id.to_be_bytes());
        out.extend_from_slice(&self.ref_frame_id.to_be_bytes());
        out.push(self.ltr_slot);
        out.push(u8::from(self.is_idr));
        out.push(u8::from(self.is_ref));
        out.extend_from_slice(&self.max_age_ms.to_be_bytes());
        out.extend_from_slice(&self.slice_idx.to_be_bytes());
        out.extend_from_slice(&self.slice_cnt.to_be_bytes());
        out.extend_from_slice(&self.data);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < VIDEO_SLICE_META_LEN {
            return Err(TransportError::InvalidFraming("VIDEO_SLICE truncated".into()));
        }
        let slice_idx = u16::from_be_bytes([bytes[14], bytes[15]]);
        let slice_cnt = u16::from_be_bytes([bytes[16], bytes[17]]);
        if slice_cnt == 0 || slice_idx >= slice_cnt {
            return Err(TransportError::InvalidFraming(
                "invalid VIDEO_SLICE index/count".into(),
            ));
        }
        Ok(Self {
            codec_id: bytes[0],
            frame_id: u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
            ref_frame_id: u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]),
            ltr_slot: bytes[9],
            is_idr: bytes[10] != 0,
            is_ref: bytes[11] != 0,
            max_age_ms: u16::from_be_bytes([bytes[12], bytes[13]]),
            slice_idx,
            slice_cnt,
            data: bytes[VIDEO_SLICE_META_LEN..].to_vec(),
        })
    }

    /// Slices an encoded frame so each L3 packet fits within `l3_mtu` (default `<= 1200B`).
    #[allow(clippy::too_many_arguments)]
    pub fn slice_frame(
        codec_id: u8,
        frame_id: u32,
        ref_frame_id: u32,
        ltr_slot: u8,
        is_idr: bool,
        is_ref: bool,
        max_age_ms: u16,
        frame_data: &[u8],
        l3_mtu: usize,
    ) -> Result<Vec<Self>, TransportError> {
        let overhead = L3_HDR_LEN + AEAD_TAG_LEN + L4_HDR_LEN + VIDEO_SLICE_META_LEN;
        if l3_mtu <= overhead {
            return Err(TransportError::InvalidFraming("l3_mtu too small".into()));
        }
        let max_chunk = l3_mtu - overhead;
        if frame_data.is_empty() {
            return Ok(vec![Self {
                codec_id,
                frame_id,
                ref_frame_id,
                ltr_slot,
                is_idr,
                is_ref,
                max_age_ms,
                slice_idx: 0,
                slice_cnt: 1,
                data: Vec::new(),
            }]);
        }
        let chunks: Vec<&[u8]> = frame_data.chunks(max_chunk).collect();
        let slice_cnt = u16::try_from(chunks.len())
            .map_err(|_| TransportError::InvalidFraming("frame exceeds u16 slices".into()))?;
        Ok(chunks
            .into_iter()
            .enumerate()
            .map(|(i, chunk)| Self {
                codec_id,
                frame_id,
                ref_frame_id,
                ltr_slot,
                is_idr,
                is_ref,
                max_age_ms,
                slice_idx: i as u16,
                slice_cnt,
                data: chunk.to_vec(),
            })
            .collect())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReassembledVideoFrame {
    pub codec_id: u8,
    pub frame_id: u32,
    pub ref_frame_id: u32,
    pub ltr_slot: u8,
    pub is_idr: bool,
    pub is_ref: bool,
    pub data: Vec<u8>,
}

struct PartialFrame {
    codec_id: u8,
    ref_frame_id: u32,
    ltr_slot: u8,
    is_idr: bool,
    is_ref: bool,
    max_age_ms: u16,
    first_recv_ms: u64,
    slice_cnt: u16,
    slices: BTreeMap<u16, Vec<u8>>,
}

/// Receive-side video slice reassembler with bounded partial-frame capacity
/// (`VIDEO_REASSEMBLER_MAX_PARTIALS = 64`) and clamped `max_age_ms <= 500ms`.
#[derive(Default)]
pub struct VideoReassembler {
    partials: BTreeMap<u32, PartialFrame>,
    pub expired_frames: u64,
}

impl VideoReassembler {
    pub fn partial_count(&self) -> usize {
        self.partials.len()
    }

    pub fn push_slice(&mut self, slice: VideoSlice, now_ms: u64) -> Option<ReassembledVideoFrame> {
        self.evict_expired(now_ms);
        if !self.partials.contains_key(&slice.frame_id) {
            while self.partials.len() >= VIDEO_REASSEMBLER_MAX_PARTIALS {
                let oldest_fid = self
                    .partials
                    .iter()
                    .min_by_key(|(&fid, pf)| (pf.first_recv_ms, fid))
                    .map(|(&fid, _)| fid);
                if let Some(fid) = oldest_fid {
                    self.partials.remove(&fid);
                    self.expired_frames = self.expired_frames.saturating_add(1);
                } else {
                    break;
                }
            }
        }
        let clamped_max_age_ms = slice.max_age_ms.min(VIDEO_REASSEMBLER_MAX_AGE_MS);
        let entry = self
            .partials
            .entry(slice.frame_id)
            .or_insert_with(|| PartialFrame {
                codec_id: slice.codec_id,
                ref_frame_id: slice.ref_frame_id,
                ltr_slot: slice.ltr_slot,
                is_idr: slice.is_idr,
                is_ref: slice.is_ref,
                max_age_ms: clamped_max_age_ms,
                first_recv_ms: now_ms,
                slice_cnt: slice.slice_cnt,
                slices: BTreeMap::new(),
            });
        if slice.slice_cnt != entry.slice_cnt {
            return None;
        }
        entry.slices.insert(slice.slice_idx, slice.data);
        if entry.slices.len() == entry.slice_cnt as usize {
            if let Some(done) = self.partials.remove(&slice.frame_id) {
                let mut data = Vec::new();
                for idx in 0..done.slice_cnt {
                    if let Some(part) = done.slices.get(&idx) {
                        data.extend_from_slice(part);
                    }
                }
                return Some(ReassembledVideoFrame {
                    codec_id: done.codec_id,
                    frame_id: slice.frame_id,
                    ref_frame_id: done.ref_frame_id,
                    ltr_slot: done.ltr_slot,
                    is_idr: done.is_idr,
                    is_ref: done.is_ref,
                    data,
                });
            }
        }
        None
    }

    pub fn evict_expired(&mut self, now_ms: u64) -> Vec<(u32, bool)> {
        let mut expired = Vec::new();
        self.partials.retain(|&fid, pf| {
            if now_ms.saturating_sub(pf.first_recv_ms) > pf.max_age_ms as u64 {
                expired.push((fid, pf.is_ref));
                false
            } else {
                true
            }
        });
        self.expired_frames = self.expired_frames.saturating_add(expired.len() as u64);
        expired
    }
}

pub const LTR_REASON_SLICE_LOST_TIMEOUT: u8 = 1;
pub const LTR_REASON_DECODE_ERROR: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LtrRecoveryReq {
    pub last_good_ref_frame_id: u32,
    pub broken_frame_id: u32,
    pub reason: u8,
}

impl LtrRecoveryReq {
    pub fn encode(&self) -> [u8; 9] {
        let mut out = [0u8; 9];
        out[0..4].copy_from_slice(&self.last_good_ref_frame_id.to_be_bytes());
        out[4..8].copy_from_slice(&self.broken_frame_id.to_be_bytes());
        out[8] = self.reason;
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() != 9 {
            return Err(TransportError::InvalidFraming(
                "LTR_RECOVERY_REQ must be 9 bytes".into(),
            ));
        }
        Ok(Self {
            last_good_ref_frame_id: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            broken_frame_id: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            reason: bytes[8],
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    ForceRefLtr(u32),
    IntraRefresh,
    ForceIdr,
    RateLimitedSkip,
}

#[derive(Debug, Clone, Copy)]
struct LtrSlotState {
    frame_id: u32,
    confirmed: bool,
}

/// Dual-slot LTR recovery ladder matching V2 §5.3 and golden vector V21.
#[derive(Debug, Clone)]
pub struct LtrRecoveryController {
    pub cap_ltr: bool,
    pub cap_intra_refresh: bool,
    slots: [Option<LtrSlotState>; 2],
    last_idr_ms: Option<u64>,
}

impl LtrRecoveryController {
    pub fn new(cap_ltr: bool, cap_intra_refresh: bool) -> Self {
        Self {
            cap_ltr,
            cap_intra_refresh,
            slots: [None, None],
            last_idr_ms: None,
        }
    }

    /// Attempts to mark a frame into `slot_idx` (`0` or `1`).
    /// Never overwrites an existing unconfirmed slot (V2 §5.3).
    pub fn try_mark_ltr(&mut self, slot_idx: usize, frame_id: u32) -> bool {
        if slot_idx >= 2 {
            return false;
        }
        if let Some(existing) = self.slots[slot_idx] {
            if !existing.confirmed {
                return false;
            }
        }
        self.slots[slot_idx] = Some(LtrSlotState {
            frame_id,
            confirmed: false,
        });
        true
    }

    pub fn confirm_ltr(&mut self, frame_id: u32) {
        for slot in self.slots.iter_mut().flatten() {
            if slot.frame_id == frame_id {
                slot.confirmed = true;
            }
        }
    }

    pub fn handle_recovery_req(&mut self, req: LtrRecoveryReq, now_ms: u64) -> RecoveryAction {
        if req.reason != LTR_REASON_DECODE_ERROR && self.cap_ltr {
            let slot_hit = self
                .slots
                .iter()
                .flatten()
                .any(|s| s.confirmed && s.frame_id == req.last_good_ref_frame_id);
            if slot_hit {
                return RecoveryAction::ForceRefLtr(req.last_good_ref_frame_id);
            }
        }
        if req.reason != LTR_REASON_DECODE_ERROR && self.cap_intra_refresh {
            return RecoveryAction::IntraRefresh;
        }
        if let Some(last) = self.last_idr_ms {
            if now_ms.saturating_sub(last) < IDR_MIN_INTERVAL_MS {
                return RecoveryAction::RateLimitedSkip;
            }
        }
        self.last_idr_ms = Some(now_ms);
        RecoveryAction::ForceIdr
    }
}

/// Computes `0x04 ANCHOR_RELIABLE_RS` parity count: `ceil(k * max(0.25, 3 * leg2_loss))`.
pub fn anchor_rs_parity_count(k: usize, leg2_loss: f64) -> usize {
    let ratio = 0.25f64.max(3.0 * leg2_loss);
    ((k as f64) * ratio).ceil() as usize
}

/// `0x07 RealtimeActuator` frame (v1.2): strict latest-overwrite, never retransmitted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActuatorCmd {
    pub control_epoch: u32,
    pub cmd_seq: u32,
    pub send_ts_ms: u64,
    pub ttl_ms: u16,
    pub payload: Vec<u8>,
}

pub const ACTUATOR_HDR_LEN: usize = 4 + 4 + 8 + 2; // 18 bytes

impl ActuatorCmd {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ACTUATOR_HDR_LEN + self.payload.len());
        out.extend_from_slice(&self.control_epoch.to_be_bytes());
        out.extend_from_slice(&self.cmd_seq.to_be_bytes());
        out.extend_from_slice(&self.send_ts_ms.to_be_bytes());
        out.extend_from_slice(&self.ttl_ms.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < ACTUATOR_HDR_LEN {
            return Err(TransportError::InvalidFraming(
                "ACTUATOR_CMD truncated".into(),
            ));
        }
        Ok(Self {
            control_epoch: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            cmd_seq: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
            send_ts_ms: u64::from_be_bytes([
                bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14],
                bytes[15],
            ]),
            ttl_ms: u16::from_be_bytes([bytes[16], bytes[17]]),
            payload: bytes[ACTUATOR_HDR_LEN..].to_vec(),
        })
    }
}

/// Enforces `0x07 RealtimeActuator` timing, monotonic `cmd_seq`, and CA-signed
/// `ControlPreemptToken` safety-officer preemption (V2 §5.3 & V24).
#[derive(Debug, Clone)]
pub struct ActuatorReceiver {
    tenant_id: [u8; 16],
    drone_device_id: [u8; 16],
    current_control_epoch: u32,
    last_cmd_seq: Option<u32>,
}

impl ActuatorReceiver {
    pub fn new(tenant_id: [u8; 16], drone_device_id: [u8; 16], initial_epoch: u32) -> Self {
        Self {
            tenant_id,
            drone_device_id,
            current_control_epoch: initial_epoch,
            last_cmd_seq: None,
        }
    }

    pub fn current_control_epoch(&self) -> u32 {
        self.current_control_epoch
    }

    /// Raises `control_epoch` ONLY after verifying a CA-signed `ControlPreemptToken`.
    pub fn apply_preempt_token(
        &mut self,
        token: &ControlPreemptToken,
        ca_spki_der: &[u8],
        now_unix: u64,
    ) -> Result<u32, TransportError> {
        token.verify(ca_spki_der, &self.tenant_id, &self.drone_device_id, now_unix)?;
        if token.new_control_epoch <= self.current_control_epoch {
            return Err(TransportError::InvalidFraming(
                "preempt token control_epoch is not strictly newer".into(),
            ));
        }
        self.current_control_epoch = token.new_control_epoch;
        self.last_cmd_seq = None;
        Ok(self.current_control_epoch)
    }

    /// Validates an incoming `0x07 RealtimeActuator` command.
    /// Rejects:
    /// - `ttl_ms == 0` or `ttl_ms > 150`
    /// - `send_ts_ms > now_ms + 50ms` (future timestamp skew)
    /// - `now_ms > send_ts_ms + ttl_ms` (expired)
    /// - `control_epoch != current_control_epoch` (stale pilot or unilateral bump)
    /// - `cmd_seq <= last_cmd_seq` within the same `control_epoch`
    pub fn accept_cmd(&mut self, cmd: &ActuatorCmd, now_ms: u64) -> bool {
        if cmd.ttl_ms == 0 || cmd.ttl_ms > ACTUATOR_MAX_TTL_MS {
            return false;
        }
        if cmd.send_ts_ms > now_ms.saturating_add(MAX_FUTURE_SKEW_MS) {
            return false;
        }
        if now_ms > cmd.send_ts_ms.saturating_add(cmd.ttl_ms as u64) {
            return false;
        }
        if cmd.control_epoch != self.current_control_epoch {
            return false;
        }
        if let Some(last) = self.last_cmd_seq {
            if cmd.cmd_seq <= last {
                return false;
            }
        }
        self.last_cmd_seq = Some(cmd.cmd_seq);
        true
    }
}

/// `0x08 Telemetry` high-frequency downlink frame (v1.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryFrame {
    pub telem_seq: u32,
    pub sample_ts_ms: u64,
    pub mask: u16,
    pub payload: Vec<u8>,
}

pub const TELEMETRY_HDR_LEN: usize = 4 + 8 + 2; // 14 bytes

impl TelemetryFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TELEMETRY_HDR_LEN + self.payload.len());
        out.extend_from_slice(&self.telem_seq.to_be_bytes());
        out.extend_from_slice(&self.sample_ts_ms.to_be_bytes());
        out.extend_from_slice(&self.mask.to_be_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < TELEMETRY_HDR_LEN {
            return Err(TransportError::InvalidFraming(
                "TELEMETRY_FRAME truncated".into(),
            ));
        }
        Ok(Self {
            telem_seq: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            sample_ts_ms: u64::from_be_bytes([
                bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
            ]),
            mask: u16::from_be_bytes([bytes[12], bytes[13]]),
            payload: bytes[TELEMETRY_HDR_LEN..].to_vec(),
        })
    }
}
