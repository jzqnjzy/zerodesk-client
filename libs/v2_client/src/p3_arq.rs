// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! End-to-end L4 `p3` (`0x04 Clipboard`, `0x05 FileTransfer`, `0x06 Diag`) reliable ordered ARQ
//! engine (`spec/04` §1.1, §2, §3.2).
//!
//! Decoupled from local `ActiveTransportMode` (runs identically over UDP, Dual TLS-443, and
//! asymmetric mixed-transport paths). Uses wrapping `u32` half-space sequence arithmetic,
//! per-channel 64-pkt / 256 KiB send windows, 2 MiB hard-capped receive reorder buffers,
//! `0x00 TransportCtrl` `0x01 ACK_SACK` (13 B), SACK-hole & 3-dup-ACK fast retransmit, and
//! RFC 6298 RTT estimation with `v2_transport` RTO/retry helpers.

use crate::error::ClientError;
use bytes::Bytes;
use std::{
    collections::{HashMap, VecDeque},
    time::Duration,
};
use tokio::time::Instant;
use v2_transport::{
    build_sack_bitmap, check_arq_retry_limit, compute_rto_ms, L4Header, CHAN_CLIPBOARD,
    CHAN_DIAGNOSTICS, CHAN_FILE_TRANSFER, L4_HDR_LEN,
};

pub const CTRL_MSG_ACK_SACK: u8 = 0x01;
pub const ACK_SACK_WIRE_LEN: usize = 13;
pub const ACK_SACK_STREAM_SEQ: u32 = 0;

pub const P3_MAX_INFLIGHT_PKTS: usize = 64;
pub const P3_MAX_INFLIGHT_BYTES: usize = 256 * 1024;
pub const P3_RECV_BUF_MAX_BYTES: usize = 2 * 1024 * 1024;
pub const P3_DELAYED_ACK_MS: u64 = 10;
pub const P3_ACK_PKT_THRESHOLD: u32 = 32;
pub const P3_INITIAL_SRTT_MS: u64 = 200;
pub const P3_INITIAL_RTTVAR_MS: u64 = 100;
pub const P3_FAST_RTX_MIN_GAP_MS: u64 = 50;
pub const P3_DUP_ACK_THRESHOLD: u32 = 3;
pub const P3_PROBE_STREAM_SEQ: u32 = u32::MAX;

/// RFC 1982 signed 32-bit wrapping sequence comparisons (half-space arithmetic).
#[inline]
pub const fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[inline]
pub const fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

#[inline]
pub const fn seq_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

#[inline]
pub const fn seq_ge(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) >= 0
}

/// Returns `true` if `chan_id` is a `p3` reliable ordered channel (`0x04`, `0x05`, `0x06`).
#[inline]
pub const fn is_p3_channel(chan_id: u8) -> bool {
    matches!(
        chan_id,
        CHAN_CLIPBOARD | CHAN_FILE_TRANSFER | CHAN_DIAGNOSTICS
    )
}

#[inline]
const fn p3_slot_idx(chan_id: u8) -> Option<usize> {
    match chan_id {
        CHAN_CLIPBOARD => Some(0),
        CHAN_FILE_TRANSFER => Some(1),
        CHAN_DIAGNOSTICS => Some(2),
        _ => None,
    }
}

/// `0x00 TransportCtrl` `0x01 ACK_SACK` frame (`spec/04` §3.2):
/// `[u8 target_chan][u32_be cum_ack_seq][u64_be sack_bitmap]` (13 bytes exact).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AckSackFrame {
    pub target_chan: u8,
    pub cum_ack_seq: u32,
    pub sack_bitmap: u64,
}

impl AckSackFrame {
    pub fn encode(&self) -> [u8; ACK_SACK_WIRE_LEN] {
        let mut out = [0u8; ACK_SACK_WIRE_LEN];
        out[0] = self.target_chan;
        out[1..5].copy_from_slice(&self.cum_ack_seq.to_be_bytes());
        out[5..13].copy_from_slice(&self.sack_bitmap.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() != ACK_SACK_WIRE_LEN {
            return Err(ClientError::Protocol(format!(
                "ACK_SACK must be {ACK_SACK_WIRE_LEN}B, got {}B",
                bytes.len()
            )));
        }
        Ok(Self {
            target_chan: bytes[0],
            cum_ack_seq: u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]),
            sack_bitmap: u64::from_be_bytes([
                bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12],
            ]),
        })
    }
}

/// Outbound L4 frame to transmit (or retransmit with a fresh L3 `unified_seq` and identical
/// `L4Header.stream_seq`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P3TxFrame {
    pub chan_id: u8,
    pub msg_type: u8,
    pub flags: u8,
    pub stream_seq: u32,
    pub body: Vec<u8>,
}

/// Ordered inbound L4 frame ready for upper-layer delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct P3ReadyFrame {
    pub chan_id: u8,
    pub header: L4Header,
    pub body: Bytes,
}

/// Actions produced by `P3ArqEngine::poll_due`.
#[derive(Debug, Default)]
pub struct P3PollActions {
    pub acks: Vec<AckSackFrame>,
    pub retransmits: Vec<P3TxFrame>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum P3RecvOutcome {
    Delivered(usize),
    BufferedOutOfOrder,
    Duplicate,
    DroppedProbe,
}

struct P3InflightEntry {
    msg_type: u8,
    flags: u8,
    stream_seq: u32,
    body: Vec<u8>,
    frame_bytes: usize,
    first_sent_at: Instant,
    last_sent_at: Instant,
    rto_deadline: Instant,
    retries: u8,
    sacked: bool,
    last_fast_rtx_at: Option<Instant>,
}

struct P3SendState {
    chan_id: u8,
    next_tx_seq: u32,
    send_base: u32,
    inflight: HashMap<u32, P3InflightEntry>,
    inflight_bytes: usize,
    srtt_ms: u64,
    rttvar_ms: u64,
    rtt_initialized: bool,
    dup_ack_count: u32,
    pending_rtx: VecDeque<u32>,
    rtx_sent_total: u64,
}

impl P3SendState {
    fn new(chan_id: u8) -> Self {
        Self {
            chan_id,
            next_tx_seq: 0,
            send_base: 0,
            inflight: HashMap::new(),
            inflight_bytes: 0,
            srtt_ms: P3_INITIAL_SRTT_MS,
            rttvar_ms: P3_INITIAL_RTTVAR_MS,
            rtt_initialized: false,
            dup_ack_count: 0,
            pending_rtx: VecDeque::new(),
            rtx_sent_total: 0,
        }
    }

    fn current_rto(&self, retries: u8) -> Duration {
        Duration::from_millis(compute_rto_ms(self.srtt_ms, self.rttvar_ms, retries))
    }

    fn update_rtt(&mut self, sample_ms: u64) {
        let sample = sample_ms.max(1);
        if !self.rtt_initialized {
            self.rtt_initialized = true;
            self.srtt_ms = sample;
            self.rttvar_ms = (sample / 2).max(1);
        } else {
            let diff = self.srtt_ms.abs_diff(sample);
            self.rttvar_ms = (3 * self.rttvar_ms + diff) / 4;
            self.srtt_ms = (7 * self.srtt_ms + sample) / 8;
        }
    }

    fn enqueue_send(
        &mut self,
        msg_type: u8,
        flags: u8,
        body: &[u8],
        now: Instant,
    ) -> Result<P3TxFrame, ClientError> {
        let frame_bytes = L4_HDR_LEN.saturating_add(body.len());
        if self.inflight.len() >= P3_MAX_INFLIGHT_PKTS
            || self.inflight_bytes.saturating_add(frame_bytes) > P3_MAX_INFLIGHT_BYTES
        {
            return Err(ClientError::P3Backpressure {
                chan_id: self.chan_id,
            });
        }
        let seq = self.next_tx_seq;
        self.next_tx_seq = seq.wrapping_add(1);
        let rto = self.current_rto(0);
        let entry = P3InflightEntry {
            msg_type,
            flags,
            stream_seq: seq,
            body: body.to_vec(),
            frame_bytes,
            first_sent_at: now,
            last_sent_at: now,
            rto_deadline: now + rto,
            retries: 0,
            sacked: false,
            last_fast_rtx_at: None,
        };
        self.inflight_bytes = self.inflight_bytes.saturating_add(frame_bytes);
        self.inflight.insert(seq, entry);
        Ok(P3TxFrame {
            chan_id: self.chan_id,
            msg_type,
            flags,
            stream_seq: seq,
            body: body.to_vec(),
        })
    }

    fn queue_fast_rtx(&mut self, seq: u32, now: Instant) {
        let min_gap = Duration::from_millis((self.srtt_ms / 2).max(P3_FAST_RTX_MIN_GAP_MS));
        let rto = self
            .inflight
            .get(&seq)
            .map(|e| self.current_rto(e.retries))
            .unwrap_or_else(|| self.current_rto(0));
        if let Some(entry) = self.inflight.get_mut(&seq) {
            if entry.sacked {
                return;
            }
            if let Some(last_fast) = entry.last_fast_rtx_at {
                if now.saturating_duration_since(last_fast) < min_gap {
                    return;
                }
            }
            entry.last_fast_rtx_at = Some(now);
            entry.last_sent_at = now;
            entry.rto_deadline = now + rto;
            if !self.pending_rtx.contains(&seq) {
                self.pending_rtx.push_back(seq);
            }
        }
    }

    fn on_ack(&mut self, cum_ack_seq: u32, sack_bitmap: u64, now: Instant) {
        if self.inflight.is_empty() {
            return;
        }
        let cum_advances =
            seq_ge(cum_ack_seq, self.send_base) && seq_lt(cum_ack_seq, self.next_tx_seq);
        if cum_advances {
            let mut cur = self.send_base;
            let mut rtt_sample: Option<u64> = None;
            loop {
                if let Some(entry) = self.inflight.remove(&cur) {
                    self.inflight_bytes = self.inflight_bytes.saturating_sub(entry.frame_bytes);
                    if entry.retries == 0 && entry.last_fast_rtx_at.is_none() {
                        rtt_sample =
                            Some(now.saturating_duration_since(entry.first_sent_at).as_millis() as u64);
                    }
                }
                if cur == cum_ack_seq {
                    break;
                }
                cur = cur.wrapping_add(1);
            }
            self.send_base = cum_ack_seq.wrapping_add(1);
            self.dup_ack_count = 0;
            if let Some(sample) = rtt_sample {
                self.update_rtt(sample);
            }
        }

        if self.inflight.is_empty() {
            self.pending_rtx.clear();
            return;
        }

        // Only apply SACK/dup-ACK logic when `cum_ack_seq` aligns with `send_base - 1`
        // (ignores stale out-of-order ACKs from behind `send_base - 1` without regressing state).
        if cum_ack_seq != self.send_base.wrapping_sub(1) {
            return;
        }

        let mut highest_sacked: Option<u32> = None;
        let mut sack_rtt_sample: Option<u64> = None;
        for bit in 0..64u32 {
            if (sack_bitmap >> bit) & 1 == 0 {
                continue;
            }
            let seq = cum_ack_seq.wrapping_add(1 + bit);
            if let Some(entry) = self.inflight.get_mut(&seq) {
                if !entry.sacked {
                    entry.sacked = true;
                    if entry.retries == 0 && entry.last_fast_rtx_at.is_none() {
                        sack_rtt_sample =
                            Some(now.saturating_duration_since(entry.first_sent_at).as_millis() as u64);
                    }
                }
                highest_sacked = Some(match highest_sacked {
                    Some(prev) if seq_gt(prev, seq) => prev,
                    _ => seq,
                });
            }
        }
        if let Some(sample) = sack_rtt_sample {
            self.update_rtt(sample);
        }

        if let Some(max_sacked) = highest_sacked {
            let mut holes = Vec::new();
            let mut cur = self.send_base;
            while seq_lt(cur, max_sacked) {
                if let Some(entry) = self.inflight.get(&cur) {
                    if !entry.sacked {
                        holes.push(cur);
                    }
                }
                cur = cur.wrapping_add(1);
            }
            for seq in holes {
                self.queue_fast_rtx(seq, now);
            }
        } else if !cum_advances && sack_bitmap == 0 {
            self.dup_ack_count = self.dup_ack_count.saturating_add(1);
            if self.dup_ack_count >= P3_DUP_ACK_THRESHOLD {
                self.dup_ack_count = 0;
                self.queue_fast_rtx(self.send_base, now);
            }
        }
    }

    fn poll_retransmits(&mut self, now: Instant) -> Result<Vec<P3TxFrame>, ClientError> {
        let mut out = Vec::new();
        while let Some(seq) = self.pending_rtx.pop_front() {
            if let Some(entry) = self.inflight.get(&seq) {
                if !entry.sacked {
                    self.rtx_sent_total = self.rtx_sent_total.saturating_add(1);
                    out.push(P3TxFrame {
                        chan_id: self.chan_id,
                        msg_type: entry.msg_type,
                        flags: entry.flags,
                        stream_seq: entry.stream_seq,
                        body: entry.body.clone(),
                    });
                }
            }
        }

        // Collect RTO-expired un-SACKed entries in wrapping stream_seq order.
        let mut due_seqs: Vec<u32> = self
            .inflight
            .values()
            .filter(|e| !e.sacked && now >= e.rto_deadline)
            .map(|e| e.stream_seq)
            .collect();
        due_seqs.sort_by_key(|&s| s.wrapping_sub(self.send_base));

        for seq in due_seqs {
            let next_retries = match self.inflight.get(&seq) {
                Some(e) => e.retries.saturating_add(1),
                None => continue,
            };
            if check_arq_retry_limit(next_retries).is_err() {
                return Err(ClientError::PathFailed(format!(
                    "p3 ARQ chan {:#04x} stream_seq {} exceeded 8 retries",
                    self.chan_id, seq
                )));
            }
            let next_rto = self.current_rto(next_retries);
            if let Some(entry) = self.inflight.get_mut(&seq) {
                entry.retries = next_retries;
                entry.last_sent_at = now;
                entry.rto_deadline = now + next_rto;
                self.rtx_sent_total = self.rtx_sent_total.saturating_add(1);
                out.push(P3TxFrame {
                    chan_id: self.chan_id,
                    msg_type: entry.msg_type,
                    flags: entry.flags,
                    stream_seq: entry.stream_seq,
                    body: entry.body.clone(),
                });
            }
        }
        Ok(out)
    }

    fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if !self.pending_rtx.is_empty() {
            return Some(now);
        }
        self.inflight
            .values()
            .filter(|e| !e.sacked)
            .map(|e| e.rto_deadline)
            .min()
    }
}

struct P3BufferedFrame {
    header: L4Header,
    body: Bytes,
    frame_bytes: usize,
}

struct P3RecvState {
    chan_id: u8,
    cum_ack_seq: u32,
    has_received_any: bool,
    ooo_buf: HashMap<u32, P3BufferedFrame>,
    ooo_bytes: usize,
    unacked_pkts: u32,
    ack_deadline: Option<Instant>,
    ack_immediate: bool,
}

impl P3RecvState {
    fn new(chan_id: u8) -> Self {
        Self {
            chan_id,
            cum_ack_seq: u32::MAX,
            has_received_any: false,
            ooo_buf: HashMap::new(),
            ooo_bytes: 0,
            unacked_pkts: 0,
            ack_deadline: None,
            ack_immediate: false,
        }
    }

    fn on_recv(
        &mut self,
        header: L4Header,
        body: Bytes,
        now: Instant,
        ready_queue: &mut VecDeque<P3ReadyFrame>,
    ) -> Result<P3RecvOutcome, ClientError> {
        let seq = header.stream_seq;

        // Defense against negative policy probes (`stream_seq == u32::MAX`) unless the stream has
        // genuinely wrapped to `u32::MAX - 1`.
        if seq == P3_PROBE_STREAM_SEQ && self.cum_ack_seq != u32::MAX - 1 {
            return Ok(P3RecvOutcome::DroppedProbe);
        }

        // Duplicate / already-delivered check (wrapping half-space).
        if seq_le(seq, self.cum_ack_seq) {
            if self.has_received_any {
                self.ack_immediate = true;
            }
            return Ok(P3RecvOutcome::Duplicate);
        }
        if self.ooo_buf.contains_key(&seq) {
            self.ack_immediate = true;
            return Ok(P3RecvOutcome::Duplicate);
        }

        self.has_received_any = true;
        let expected = self.cum_ack_seq.wrapping_add(1);
        if seq == expected {
            self.cum_ack_seq = seq;
            ready_queue.push_back(P3ReadyFrame {
                chan_id: self.chan_id,
                header,
                body,
            });
            let mut delivered = 1usize;
            let mut drained_ooo = 0usize;
            loop {
                let next_seq = self.cum_ack_seq.wrapping_add(1);
                let Some(buffered) = self.ooo_buf.remove(&next_seq) else {
                    break;
                };
                self.ooo_bytes = self.ooo_bytes.saturating_sub(buffered.frame_bytes);
                self.cum_ack_seq = next_seq;
                ready_queue.push_back(P3ReadyFrame {
                    chan_id: self.chan_id,
                    header: buffered.header,
                    body: buffered.body,
                });
                delivered = delivered.saturating_add(1);
                drained_ooo = drained_ooo.saturating_add(1);
            }
            self.unacked_pkts = self.unacked_pkts.saturating_add(delivered as u32);
            if drained_ooo > 0 || self.unacked_pkts >= P3_ACK_PKT_THRESHOLD {
                self.ack_immediate = true;
            } else if self.ack_deadline.is_none() {
                self.ack_deadline = Some(now + Duration::from_millis(P3_DELAYED_ACK_MS));
            }
            Ok(P3RecvOutcome::Delivered(delivered))
        } else {
            let frame_bytes = L4_HDR_LEN.saturating_add(body.len());
            if self.ooo_bytes.saturating_add(frame_bytes) > P3_RECV_BUF_MAX_BYTES {
                return Err(ClientError::Protocol(format!(
                    "p3 recv reorder buffer exceeded {P3_RECV_BUF_MAX_BYTES}B cap on chan {:#04x}",
                    self.chan_id
                )));
            }
            self.ooo_bytes = self.ooo_bytes.saturating_add(frame_bytes);
            self.ooo_buf.insert(
                seq,
                P3BufferedFrame {
                    header,
                    body,
                    frame_bytes,
                },
            );
            self.ack_immediate = true;
            Ok(P3RecvOutcome::BufferedOutOfOrder)
        }
    }

    fn build_ack(&self) -> AckSackFrame {
        let keys: Vec<u32> = self.ooo_buf.keys().copied().collect();
        let bitmap = build_sack_bitmap(self.cum_ack_seq, &keys);
        AckSackFrame {
            target_chan: self.chan_id,
            cum_ack_seq: self.cum_ack_seq,
            sack_bitmap: bitmap,
        }
    }

    fn take_due_ack(&mut self, now: Instant) -> Option<AckSackFrame> {
        let due = self.ack_immediate || self.ack_deadline.is_some_and(|dl| now >= dl);
        if !due {
            return None;
        }
        self.ack_immediate = false;
        self.ack_deadline = None;
        self.unacked_pkts = 0;
        Some(self.build_ack())
    }

    fn next_deadline(&self, now: Instant) -> Option<Instant> {
        if self.ack_immediate {
            Some(now)
        } else {
            self.ack_deadline
        }
    }
}

/// Session-scoped L4 `p3` ARQ engine managing independent send/recv state per `p3` channel
/// (`0x04 Clipboard`, `0x05 FileTransfer`, `0x06 Diag`).
pub struct P3ArqEngine {
    send: [P3SendState; 3],
    recv: [P3RecvState; 3],
    ready_queue: VecDeque<P3ReadyFrame>,
}

impl Default for P3ArqEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl P3ArqEngine {
    pub fn new() -> Self {
        Self {
            send: [
                P3SendState::new(CHAN_CLIPBOARD),
                P3SendState::new(CHAN_FILE_TRANSFER),
                P3SendState::new(CHAN_DIAGNOSTICS),
            ],
            recv: [
                P3RecvState::new(CHAN_CLIPBOARD),
                P3RecvState::new(CHAN_FILE_TRANSFER),
                P3RecvState::new(CHAN_DIAGNOSTICS),
            ],
            ready_queue: VecDeque::new(),
        }
    }

    pub fn enqueue_send(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        flags: u8,
        body: &[u8],
        now: Instant,
    ) -> Result<P3TxFrame, ClientError> {
        let idx = p3_slot_idx(chan_id).ok_or_else(|| {
            ClientError::Protocol(format!("chan_id {chan_id:#04x} is not a p3 ARQ channel"))
        })?;
        self.send[idx].enqueue_send(msg_type, flags, body, now)
    }

    pub fn on_recv_data(
        &mut self,
        chan_id: u8,
        header: L4Header,
        body: Bytes,
        now: Instant,
    ) -> Result<P3RecvOutcome, ClientError> {
        let idx = p3_slot_idx(chan_id).ok_or_else(|| {
            ClientError::Protocol(format!("chan_id {chan_id:#04x} is not a p3 ARQ channel"))
        })?;
        self.recv[idx].on_recv(header, body, now, &mut self.ready_queue)
    }

    pub fn on_recv_ack(&mut self, ack: &AckSackFrame, now: Instant) {
        if let Some(idx) = p3_slot_idx(ack.target_chan) {
            self.send[idx].on_ack(ack.cum_ack_seq, ack.sack_bitmap, now);
        }
    }

    pub fn pop_ready(&mut self) -> Option<P3ReadyFrame> {
        self.ready_queue.pop_front()
    }

    pub fn has_ready(&self) -> bool {
        !self.ready_queue.is_empty()
    }

    pub fn poll_due(&mut self, now: Instant) -> Result<P3PollActions, ClientError> {
        let mut actions = P3PollActions::default();
        for rx in &mut self.recv {
            if let Some(ack) = rx.take_due_ack(now) {
                actions.acks.push(ack);
            }
        }
        for tx in &mut self.send {
            let rtx = tx.poll_retransmits(now)?;
            actions.retransmits.extend(rtx);
        }
        Ok(actions)
    }

    pub fn next_deadline(&self, now: Instant) -> Option<Instant> {
        let mut earliest: Option<Instant> = None;
        for rx in &self.recv {
            if let Some(dl) = rx.next_deadline(now) {
                earliest = Some(earliest.map_or(dl, |e| e.min(dl)));
            }
        }
        for tx in &self.send {
            if let Some(dl) = tx.next_deadline(now) {
                earliest = Some(earliest.map_or(dl, |e| e.min(dl)));
            }
        }
        earliest
    }

    pub fn inflight_pkts(&self, chan_id: u8) -> usize {
        p3_slot_idx(chan_id).map_or(0, |i| self.send[i].inflight.len())
    }

    pub fn inflight_bytes(&self, chan_id: u8) -> usize {
        p3_slot_idx(chan_id).map_or(0, |i| self.send[i].inflight_bytes)
    }

    pub fn rtx_sent_total(&self, chan_id: u8) -> u64 {
        p3_slot_idx(chan_id).map_or(0, |i| self.send[i].rtx_sent_total)
    }

    pub fn recv_cum_ack(&self, chan_id: u8) -> u32 {
        p3_slot_idx(chan_id).map_or(u32::MAX, |i| self.recv[i].cum_ack_seq)
    }

    pub fn recv_ooo_bytes(&self, chan_id: u8) -> usize {
        p3_slot_idx(chan_id).map_or(0, |i| self.recv[i].ooo_bytes)
    }

    #[cfg(test)]
    pub fn set_seq_state_for_test(&mut self, chan_id: u8, next_tx: u32, recv_cum: u32) {
        if let Some(i) = p3_slot_idx(chan_id) {
            self.send[i].next_tx_seq = next_tx;
            self.send[i].send_base = next_tx;
            self.recv[i].cum_ack_seq = recv_cum;
            self.recv[i].has_received_any = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_hdr(seq: u32, len: usize) -> L4Header {
        L4Header {
            msg_type: 0x03,
            flags: 0,
            body_len: len as u16,
            stream_seq: seq,
        }
    }

    #[test]
    fn initial_seq1_before_seq0_yields_cum_u32_max_and_bitmap_0b10() {
        let now = Instant::now();
        let mut rx = P3ArqEngine::new();
        assert_eq!(rx.recv_cum_ack(CHAN_FILE_TRANSFER), u32::MAX);

        let out = rx
            .on_recv_data(
                CHAN_FILE_TRANSFER,
                mk_hdr(1, 4),
                Bytes::from_static(b"pkt1"),
                now,
            )
            .unwrap();
        assert_eq!(out, P3RecvOutcome::BufferedOutOfOrder);
        assert!(rx.pop_ready().is_none());

        let actions = rx.poll_due(now).unwrap();
        assert_eq!(actions.acks.len(), 1);
        assert_eq!(
            actions.acks[0],
            AckSackFrame {
                target_chan: CHAN_FILE_TRANSFER,
                cum_ack_seq: u32::MAX,
                sack_bitmap: 0b10,
            }
        );

        // Now deliver seq 0 -> delivers 0 then 1 strictly in order!
        let out0 = rx
            .on_recv_data(
                CHAN_FILE_TRANSFER,
                mk_hdr(0, 4),
                Bytes::from_static(b"pkt0"),
                now,
            )
            .unwrap();
        assert_eq!(out0, P3RecvOutcome::Delivered(2));
        let f0 = rx.pop_ready().unwrap();
        let f1 = rx.pop_ready().unwrap();
        assert_eq!(f0.header.stream_seq, 0);
        assert_eq!(&f0.body[..], b"pkt0");
        assert_eq!(f1.header.stream_seq, 1);
        assert_eq!(&f1.body[..], b"pkt1");
        assert!(rx.pop_ready().is_none());

        let actions2 = rx.poll_due(now).unwrap();
        assert_eq!(actions2.acks.len(), 1);
        assert_eq!(actions2.acks[0].cum_ack_seq, 1);
        assert_eq!(actions2.acks[0].sack_bitmap, 0);
    }

    #[test]
    fn sequence_wraparound_across_u32_max_to_zero_and_one() {
        let now = Instant::now();
        let mut tx = P3ArqEngine::new();
        let mut rx = P3ArqEngine::new();
        tx.set_seq_state_for_test(CHAN_FILE_TRANSFER, u32::MAX - 1, u32::MAX - 2);
        rx.set_seq_state_for_test(CHAN_FILE_TRANSFER, u32::MAX - 1, u32::MAX - 2);

        let f_prev = tx
            .enqueue_send(CHAN_FILE_TRANSFER, 0x03, 0, b"m1", now)
            .unwrap();
        let f_max = tx
            .enqueue_send(CHAN_FILE_TRANSFER, 0x03, 0, b"max", now)
            .unwrap();
        let f_zero = tx
            .enqueue_send(CHAN_FILE_TRANSFER, 0x03, 0, b"zero", now)
            .unwrap();
        let f_one = tx
            .enqueue_send(CHAN_FILE_TRANSFER, 0x03, 0, b"one", now)
            .unwrap();
        assert_eq!(f_prev.stream_seq, u32::MAX - 1);
        assert_eq!(f_max.stream_seq, u32::MAX);
        assert_eq!(f_zero.stream_seq, 0);
        assert_eq!(f_one.stream_seq, 1);

        // Deliver u32::MAX-1 first so cum_ack reaches u32::MAX-1, then deliver 1, 0, u32::MAX out of order!
        rx.on_recv_data(
            CHAN_FILE_TRANSFER,
            mk_hdr(f_prev.stream_seq, f_prev.body.len()),
            Bytes::from(f_prev.body.clone()),
            now,
        )
        .unwrap();
        rx.on_recv_data(
            CHAN_FILE_TRANSFER,
            mk_hdr(f_one.stream_seq, f_one.body.len()),
            Bytes::from(f_one.body.clone()),
            now,
        )
        .unwrap();
        rx.on_recv_data(
            CHAN_FILE_TRANSFER,
            mk_hdr(f_zero.stream_seq, f_zero.body.len()),
            Bytes::from(f_zero.body.clone()),
            now,
        )
        .unwrap();
        let ack1 = rx.poll_due(now).unwrap().acks.pop().unwrap();
        assert_eq!(ack1.cum_ack_seq, u32::MAX - 1);
        // bit 0 = u32::MAX (missing), bit 1 = 0 (present), bit 2 = 1 (present) => 0b110
        assert_eq!(ack1.sack_bitmap, 0b110);

        // Feed SACK to sender -> fast-retransmits u32::MAX immediately!
        tx.on_recv_ack(&ack1, now + Duration::from_millis(20));
        let rtx = tx.poll_due(now + Duration::from_millis(20)).unwrap().retransmits;
        assert_eq!(rtx.len(), 1);
        assert_eq!(rtx[0].stream_seq, u32::MAX);

        // Deliver retransmitted u32::MAX -> drains u32::MAX, 0, 1 in strict order!
        rx.on_recv_data(
            CHAN_FILE_TRANSFER,
            mk_hdr(rtx[0].stream_seq, rtx[0].body.len()),
            Bytes::from(rtx[0].body.clone()),
            now + Duration::from_millis(40),
        )
        .unwrap();
        let delivered: Vec<u32> = std::iter::from_fn(|| rx.pop_ready())
            .map(|f| f.header.stream_seq)
            .collect();
        assert_eq!(delivered, vec![u32::MAX - 1, u32::MAX, 0, 1]);

        let ack2 = rx.poll_due(now + Duration::from_millis(40)).unwrap().acks.pop().unwrap();
        assert_eq!(ack2.cum_ack_seq, 1);
        assert_eq!(ack2.sack_bitmap, 0);
        tx.on_recv_ack(&ack2, now + Duration::from_millis(60));
        assert_eq!(tx.inflight_pkts(CHAN_FILE_TRANSFER), 0);
        assert_eq!(tx.inflight_bytes(CHAN_FILE_TRANSFER), 0);
    }

    #[test]
    fn probe_u32_max_silently_dropped_when_cum_not_u32_max_minus_1() {
        let now = Instant::now();
        let mut rx = P3ArqEngine::new();
        let out = rx
            .on_recv_data(
                CHAN_FILE_TRANSFER,
                mk_hdr(P3_PROBE_STREAM_SEQ, 5),
                Bytes::from_static(b"probe"),
                now,
            )
            .unwrap();
        assert_eq!(out, P3RecvOutcome::DroppedProbe);
        assert_eq!(rx.recv_cum_ack(CHAN_FILE_TRANSFER), u32::MAX);
        assert_eq!(rx.recv_ooo_bytes(CHAN_FILE_TRANSFER), 0);
        assert!(rx.pop_ready().is_none());
        assert!(rx.poll_due(now).unwrap().acks.is_empty());
    }

    #[test]
    fn rto_exponential_backoff_and_8_retries_path_failed() {
        let mut now = Instant::now();
        let mut tx = P3ArqEngine::new();
        let _ = tx
            .enqueue_send(CHAN_FILE_TRANSFER, 0x01, 0, b"offer", now)
            .unwrap();

        // Retries 1..=7 succeed with exponential backoff capped at 3000ms.
        let mut rtx_count = 0usize;
        for expected_retry in 1..=7u8 {
            let dl = tx.next_deadline(now).unwrap();
            assert!(dl > now);
            now = dl;
            let actions = tx.poll_due(now).unwrap();
            assert_eq!(actions.retransmits.len(), 1);
            assert_eq!(actions.retransmits[0].stream_seq, 0);
            rtx_count += 1;
            let expected_next_rto = compute_rto_ms(P3_INITIAL_SRTT_MS, P3_INITIAL_RTTVAR_MS, expected_retry);
            assert_eq!(
                tx.next_deadline(now).unwrap().saturating_duration_since(now),
                Duration::from_millis(expected_next_rto)
            );
        }
        assert_eq!(rtx_count, 7);

        // 8th timeout triggers PathFailed!
        now = tx.next_deadline(now).unwrap();
        let err = tx.poll_due(now).unwrap_err();
        assert!(matches!(err, ClientError::PathFailed(_)));
    }

    #[test]
    fn per_channel_window_backpressure_isolates_file_from_clipboard() {
        let now = Instant::now();
        let mut tx = P3ArqEngine::new();

        // Fill 0x05 FileTransfer to 64 inflight packets -> 65th returns P3Backpressure!
        for _ in 0..P3_MAX_INFLIGHT_PKTS {
            tx.enqueue_send(CHAN_FILE_TRANSFER, 0x03, 0, &[0xAB; 1024], now)
                .unwrap();
        }
        let bp = tx.enqueue_send(CHAN_FILE_TRANSFER, 0x03, 0, &[0xAB; 1024], now);
        assert!(matches!(
            bp,
            Err(ClientError::P3Backpressure {
                chan_id: CHAN_FILE_TRANSFER
            })
        ));

        // 0x04 Clipboard MUST remain completely unblocked!
        let clip = tx
            .enqueue_send(CHAN_CLIPBOARD, 0x01, 0, b"clipboard-still-flows", now)
            .unwrap();
        assert_eq!(clip.stream_seq, 0);
        assert_eq!(tx.inflight_pkts(CHAN_CLIPBOARD), 1);
    }

    #[test]
    fn recv_reorder_buffer_enforces_2_mib_hard_cap() {
        let now = Instant::now();
        let mut rx = P3ArqEngine::new();
        // Leave seq 0 missing so every subsequent 16 KiB frame buffers in ooo_buf.
        let payload = vec![0x55u8; 16 * 1024];
        let mut seq = 1u32;
        let mut hit_cap = false;
        for _ in 0..200 {
            match rx.on_recv_data(
                CHAN_FILE_TRANSFER,
                mk_hdr(seq, payload.len()),
                Bytes::from(payload.clone()),
                now,
            ) {
                Ok(P3RecvOutcome::BufferedOutOfOrder) => seq += 1,
                Err(ClientError::Protocol(_)) => {
                    hit_cap = true;
                    break;
                }
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
        assert!(hit_cap, "expected 2 MiB hard cap error");
        assert!(rx.recv_ooo_bytes(CHAN_FILE_TRANSFER) <= P3_RECV_BUF_MAX_BYTES);
    }
}
