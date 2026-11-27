// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#[cfg(any(test, feature = "test-utils"))]
use crate::p3_arq::P3_PROBE_STREAM_SEQ;
use crate::{
    access_ctrl::AccessKeys,
    error::ClientError,
    p3_arq::{
        is_p3_channel, AckSackFrame, P3ArqEngine, ACK_SACK_STREAM_SEQ, ACK_SACK_WIRE_LEN,
        CTRL_MSG_ACK_SACK,
    },
    tls443::{DualTls443Client, StreamRecvEvent},
};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeSet, VecDeque},
    net::SocketAddr,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::UdpSocket, time::Instant};
use v2_identity::{ControlPreemptToken, DelegationStatement};
#[cfg(any(test, feature = "test-utils"))]
use v2_transport::CIPHER_AESGCM;
use v2_transport::{
    default_channel_priority, decode_l4_frame, encode_l4_frame, rs64_decode_block,
    rs64_encode_block, seal_udp_v11, seq_u32_gt, AccessEpochState, AccessFlags, AccessHeaderV11,
    ActuatorCmd, ActuatorReceiver, AssembledVideoFrame, AudioPacket, BwHintController,
    ClipboardFrame, ControlFrame, E2eeHandshakeOutput, E2eeNoiseHandshake, EdgeCtrlFrame,
    FileFrame, HidFrame, L3Receiver, L3Sender, L4Header, LegCiphertextCache, LegSeqDedupWindow,
    PrologueInput, StreamSeqDedup, TelemetryFrame, TransportError, TransportEvent,
    VerifiedTenantPolicy, VideoFrameMeta, VideoReassembler, VideoSlice, ACCESS_HDR_V11_LEN,
    BW_EVENT_DROP_ACTIVE, BW_EVENT_PAUSE_FILE_CHUNK, BW_EVENT_SURVIVAL_MODE, CHAN_AUDIO,
    CHAN_CLIPBOARD, CHAN_DIAGNOSTICS, CHAN_FILE_TRANSFER, CHAN_INPUT_HID,
    CHAN_REALTIME_ACTUATOR, CHAN_TELEMETRY, CHAN_TRANSPORT_CTRL, CHAN_VIDEO,
    DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT, L3_MTU_DEFAULT, SURVIVAL_RS_K, SURVIVAL_RS_M,
    TRANSPORT_DATAGRAM, UDP_MAX_LEN,
};

pub const SURVIVAL_SHARD_MAGIC: u8 = 0x52;
pub const SURVIVAL_SHARD_HDR_LEN: usize = 6; // [magic:1][block_id:4][shard_idx:1]

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn now_us() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Binds `127.0.0.1:0` when talking to a loopback Edge, or `0.0.0.0:0` for WAN Edge.
pub fn bind_addr_for_edge(edge_udp_addr: &SocketAddr) -> &'static str {
    if edge_udp_addr.ip().is_loopback() {
        if edge_udp_addr.is_ipv6() {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        }
    } else if edge_udp_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    }
}

/// Maximum number of missing `leg_seq` entries retained by `LegGapTracker`.
pub const MAX_LEG_GAP_MISSING: usize = 512;

/// Tracks incoming `leg_seq` gaps on a single access leg to emit `EdgeCtrl::LegNack`
/// for missing sequences without amplifying on discardable (`d=1`) drops.
#[derive(Debug, Default)]
pub struct LegGapTracker {
    initialized: bool,
    highest_seq: u32,
    missing: BTreeSet<u32>,
}

impl LegGapTracker {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an arriving `leg_seq`. Returns `Some((base_leg_seq, loss_bitmap))`
    /// whenever new `leg_seq` gaps are opened on non-discardable traffic.
    pub fn on_recv(&mut self, leg_seq: u32, discardable: bool) -> Option<(u32, u64)> {
        if !self.initialized {
            self.initialized = true;
            self.highest_seq = leg_seq;
            return None;
        }
        if leg_seq == self.highest_seq {
            return None;
        }
        if seq_u32_gt(leg_seq, self.highest_seq) {
            let delta = leg_seq.wrapping_sub(self.highest_seq);
            let mut opened = false;
            if delta > 1 && delta <= 64 {
                for step in 1..delta {
                    self.missing.insert(self.highest_seq.wrapping_add(step));
                    opened = true;
                }
            } else if delta > 64 {
                self.missing.clear();
            }
            self.highest_seq = leg_seq;
            while self.missing.len() > MAX_LEG_GAP_MISSING {
                let oldest = self
                    .missing
                    .iter()
                    .copied()
                    .max_by_key(|&s| self.highest_seq.wrapping_sub(s));
                if let Some(seq) = oldest {
                    self.missing.remove(&seq);
                } else {
                    break;
                }
            }
            if opened && !discardable {
                return self.build_nack();
            }
            None
        } else {
            self.missing.remove(&leg_seq);
            None
        }
    }

    pub fn build_nack(&self) -> Option<(u32, u64)> {
        let base = self
            .missing
            .iter()
            .copied()
            .max_by_key(|&s| self.highest_seq.wrapping_sub(s))?;
        let mut bitmap = 0u64;
        for &seq in &self.missing {
            let off = seq.wrapping_sub(base);
            if off < 64 {
                bitmap |= 1u64 << off;
            }
        }
        if bitmap == 0 {
            None
        } else {
            Some((base, bitmap))
        }
    }

    pub fn missing_count(&self) -> usize {
        self.missing.len()
    }
}

#[derive(Debug, Clone)]
pub enum UdpRecvEvent {
    EdgeCtrl(EdgeCtrlFrame),
    L3Data {
        header: AccessHeaderV11,
        payload: Vec<u8>,
    },
}

#[derive(Debug, Clone, Default)]
pub struct UdpLinkStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub leg_nacks_sent: u64,
    pub leg_nacks_recv: u64,
    pub rtx_packets_sent: u64,
    pub rtx_packets_recv: u64,
    pub dup_packets_dropped: u64,
    pub p3_dropped: u64,
}

/// Active data-plane transport mode selected for a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActiveTransportMode {
    Udp,
    DualTls443,
}

impl ActiveTransportMode {
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Udp => v2_transport::TRANSPORT_MODE_RELAY_UDP,
            Self::DualTls443 => v2_transport::TRANSPORT_MODE_TCP443,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Udp => "udp",
            Self::DualTls443 => "dual_tls443",
        }
    }
}

const UDP_PENDING_RX_CAP: usize = 512;
const MAX_HANDSHAKE_RESPONDER_ATTEMPTS: usize = 16;
const MAX_HANDSHAKE_INITIATOR_BAD_MSG2: usize = 8;
const MAX_CONSECUTIVE_BAD_L3_FRAMES: u32 = 32;

/// Layer 2 UDP 28B Access Transport link to a single `v2-edge` PoP.
pub struct UdpAccessLink {
    socket: UdpSocket,
    edge_addr: SocketAddr,
    route_cid: [u8; 8],
    tx_epoch: AccessEpochState,
    rx_epoch: AccessEpochState,
    next_leg_seq: u32,
    dedup: LegSeqDedupWindow,
    gap_tracker: LegGapTracker,
    rtx_cache: LegCiphertextCache,
    bw_hint: BwHintController,
    pending: VecDeque<UdpRecvEvent>,
    bulk_paused: bool,
    rtt_ms: u64,
    pub auto_leg_nack: bool,
    pub stats: UdpLinkStats,
}

impl UdpAccessLink {
    pub async fn connect(
        edge_udp_addr: &str,
        keys: &AccessKeys,
        lease_bw_cap_kbps: u32,
    ) -> Result<Self, ClientError> {
        let edge_addr: SocketAddr = edge_udp_addr
            .parse()
            .map_err(|e| ClientError::Config(format!("invalid edge UDP addr '{edge_udp_addr}': {e}")))?;
        let bind_addr = bind_addr_for_edge(&edge_addr);
        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(edge_addr).await?;

        let tx_epoch = AccessEpochState::new(
            keys.route_cid,
            *keys.hs_hash,
            TRANSPORT_DATAGRAM,
            DIR_CLIENT_TO_EDGE,
            keys.access_epoch,
            20,
        )?;
        let rx_epoch = AccessEpochState::new(
            keys.route_cid,
            *keys.hs_hash,
            TRANSPORT_DATAGRAM,
            DIR_EDGE_TO_CLIENT,
            keys.access_epoch,
            20,
        )?;

        Ok(Self {
            socket,
            edge_addr,
            route_cid: keys.route_cid,
            tx_epoch,
            rx_epoch,
            next_leg_seq: 1,
            dedup: LegSeqDedupWindow::new(),
            gap_tracker: LegGapTracker::new(),
            rtx_cache: LegCiphertextCache::new(keys.access_epoch),
            bw_hint: BwHintController::new(lease_bw_cap_kbps, lease_bw_cap_kbps),
            pending: VecDeque::new(),
            bulk_paused: false,
            rtt_ms: 20,
            auto_leg_nack: true,
            stats: UdpLinkStats::default(),
        })
    }

    pub fn is_bulk_paused(&self) -> bool {
        self.bulk_paused || self.bw_hint.survival_mode
    }

    pub fn p3_dropped(&self) -> u64 {
        self.stats.p3_dropped
    }

    pub fn local_addr(&self) -> Result<SocketAddr, ClientError> {
        Ok(self.socket.local_addr()?)
    }

    pub fn edge_addr(&self) -> SocketAddr {
        self.edge_addr
    }

    pub fn route_cid(&self) -> [u8; 8] {
        self.route_cid
    }

    pub fn bw_controller(&self) -> &BwHintController {
        &self.bw_hint
    }

    pub fn rtx_cache(&self) -> &LegCiphertextCache {
        &self.rtx_cache
    }

    pub async fn send_edge_ctrl(&mut self, frame: &EdgeCtrlFrame) -> Result<(), ClientError> {
        let body = frame.encode();
        let hdr = AccessHeaderV11 {
            flags: AccessFlags {
                pp: 0,
                discardable: false,
                frame_end: false,
                is_ctrl_edge: true,
                dir_edge_to_client: false,
                rtx: false,
            },
            route_cid: self.route_cid,
            access_epoch: self.tx_epoch.cur_epoch(),
            leg_seq: 0,
            mac_64: [0; 8],
        };
        let wire = seal_udp_v11(self.tx_epoch.cur_key(), hdr, &body)?;
        self.socket.send(&wire).await?;
        self.stats.tx_packets = self.stats.tx_packets.saturating_add(1);
        self.stats.tx_bytes = self.stats.tx_bytes.saturating_add(wire.len() as u64);
        Ok(())
    }

    pub async fn send_leg_nack(
        &mut self,
        base_leg_seq: u32,
        loss_bitmap: u64,
    ) -> Result<(), ClientError> {
        self.stats.leg_nacks_sent = self.stats.leg_nacks_sent.saturating_add(1);
        self.send_edge_ctrl(&EdgeCtrlFrame::LegNack {
            base_leg_seq,
            loss_bitmap,
        })
        .await
    }

    /// Sends an L3 datagram wrapped in the 28B v1.1 UDP access header + HMAC-SHA256-64,
    /// caching non-discardable (`d=0`) packets for `LEG_NACK` retransmission.
    pub async fn send_l3_packet(
        &mut self,
        pp: u8,
        discardable: bool,
        l3_payload: &[u8],
    ) -> Result<u32, ClientError> {
        let seq = self.next_leg_seq;
        self.next_leg_seq = self.next_leg_seq.wrapping_add(1);
        // p3 (Bulk) frames are NEVER discardable (p3_dropped == 0 invariant).
        let eff_discardable = if pp == 3 { false } else { discardable };
        let hdr = AccessHeaderV11 {
            flags: AccessFlags {
                pp,
                discardable: eff_discardable,
                frame_end: false,
                is_ctrl_edge: false,
                dir_edge_to_client: false,
                rtx: false,
            },
            route_cid: self.route_cid,
            access_epoch: self.tx_epoch.cur_epoch(),
            leg_seq: seq,
            mac_64: [0; 8],
        };
        let wire = seal_udp_v11(self.tx_epoch.cur_key(), hdr, l3_payload)?;
        self.rtx_cache
            .record_original(&hdr, l3_payload.to_vec(), now_ms());
        self.socket.send(&wire).await?;
        self.stats.tx_packets = self.stats.tx_packets.saturating_add(1);
        self.stats.tx_bytes = self.stats.tx_bytes.saturating_add(wire.len() as u64);
        Ok(seq)
    }

    fn push_pending(&mut self, ev: UdpRecvEvent) -> Result<(), ClientError> {
        if self.pending.len() >= UDP_PENDING_RX_CAP {
            return Err(ClientError::Timeout(
                "UDP pending buffer cap exceeded during ping wait".into(),
            ));
        }
        self.pending.push_back(ev);
        Ok(())
    }

    /// Sends an `EdgeCtrl::Ping` and waits for the matching `EdgeCtrl::Pong`, retrying on loss.
    /// Buffers non-matching `L3Data`/`EdgeCtrl` events in `self.pending` so packets already marked
    /// in `dedup` are never lost. Returns measured RTT in microseconds.
    pub async fn ping_with_retry(
        &mut self,
        max_attempts: usize,
        per_attempt_timeout: Duration,
    ) -> Result<u64, ClientError> {
        let attempts = max_attempts.max(1);
        for _ in 0..attempts {
            let ts_us = now_us();
            let sent = Instant::now();
            self.send_edge_ctrl(&EdgeCtrlFrame::Ping { ts_us }).await?;

            let deadline = Instant::now()
                .checked_add(per_attempt_timeout)
                .ok_or_else(|| {
                    ClientError::Protocol("UDP ping timeout overflows monotonic clock".into())
                })?;
            loop {
                let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                match self.recv_packet_raw(rem).await {
                    Ok(UdpRecvEvent::EdgeCtrl(EdgeCtrlFrame::Pong { ts_us: echo }))
                        if echo == ts_us =>
                    {
                        let rtt_us = sent.elapsed().as_micros() as u64;
                        self.rtt_ms = (rtt_us / 1000).max(1);
                        return Ok(rtt_us);
                    }
                    Ok(ev) => {
                        self.push_pending(ev)?;
                        continue;
                    }
                    Err(ClientError::Timeout(_)) => break,
                    Err(e) => return Err(e),
                }
            }
        }
        Err(ClientError::Timeout(format!(
            "UDP EdgeCtrl::Ping to {} failed after {attempts} attempts",
            self.edge_addr
        )))
    }

    /// Probes UDP reachability with 2 `EdgeCtrl::Ping` packets (at `0ms` and `600ms`)
    /// bounded by a single shared wall-clock deadline (`total_timeout`, default `1500ms`).
    pub async fn probe_udp_two_pings(
        &mut self,
        total_timeout: Duration,
    ) -> Result<u64, ClientError> {
        let started = Instant::now();
        let deadline = started.checked_add(total_timeout).ok_or_else(|| {
            ClientError::Protocol("UDP probe timeout overflows monotonic clock".into())
        })?;
        let second_ping_at = started
            .checked_add(Duration::from_millis(600))
            .unwrap_or(deadline);
        let ts1 = now_us();
        self.send_edge_ctrl(&EdgeCtrlFrame::Ping { ts_us: ts1 }).await?;
        let mut ts2: Option<u64> = None;

        loop {
            let now = Instant::now();
            let Some(rem) = deadline.checked_duration_since(now).filter(|d| !d.is_zero()) else {
                return Err(ClientError::Timeout(format!(
                    "UDP probe to {} exceeded {:?} deadline",
                    self.edge_addr, total_timeout
                )));
            };
            let wait = if ts2.is_none() {
                match second_ping_at.checked_duration_since(now).filter(|d| !d.is_zero()) {
                    Some(until_second) => rem.min(until_second),
                    None => {
                        let t = now_us();
                        self.send_edge_ctrl(&EdgeCtrlFrame::Ping { ts_us: t }).await?;
                        ts2 = Some(t);
                        rem
                    }
                }
            } else {
                rem
            };

            match self.recv_packet_raw(wait).await {
                Ok(UdpRecvEvent::EdgeCtrl(EdgeCtrlFrame::Pong { ts_us: echo }))
                    if echo == ts1 || ts2 == Some(echo) =>
                {
                    let rtt_us = started.elapsed().as_micros() as u64;
                    self.rtt_ms = (rtt_us / 1000).max(1);
                    return Ok(rtt_us);
                }
                Ok(ev) => {
                    self.push_pending(ev)?;
                    continue;
                }
                Err(ClientError::Timeout(_)) => {
                    if ts2.is_none() && Instant::now() >= second_ping_at && Instant::now() < deadline
                    {
                        let t = now_us();
                        self.send_edge_ctrl(&EdgeCtrlFrame::Ping { ts_us: t }).await?;
                        ts2 = Some(t);
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }

    /// Receives and authenticates the next UDP packet from Edge, draining any events buffered
    /// during an earlier ping wait first.
    /// Automatically honors incoming `EdgeCtrl::LegNack` (emitting `rtx=1` packets),
    /// `EdgeCtrl::Ping` (replying `Pong`), and `EdgeCtrl::BwHint`.
    pub async fn recv_packet(&mut self, timeout: Duration) -> Result<UdpRecvEvent, ClientError> {
        if let Some(ev) = self.pending.pop_front() {
            return Ok(ev);
        }
        self.recv_packet_raw(timeout).await
    }

    async fn recv_packet_raw(&mut self, timeout: Duration) -> Result<UdpRecvEvent, ClientError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            ClientError::Protocol("UDP recv timeout overflows monotonic clock".into())
        })?;
        let mut buf = [0u8; UDP_MAX_LEN + 64];
        loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("UDP recv timed out".into()));
            };
            let n = tokio::time::timeout(rem, self.socket.recv(&mut buf))
                .await
                .map_err(|_| ClientError::Timeout("UDP recv timed out".into()))??;
            if n < ACCESS_HDR_V11_LEN {
                continue;
            }
            let now = now_ms();
            let (hdr, payload_slice) = match self.rx_epoch.verify_udp_packet(&buf[..n], now) {
                Ok(v) => v,
                Err(_) => continue,
            };
            if !hdr.flags.dir_edge_to_client {
                continue;
            }
            let payload = payload_slice.to_vec();
            self.stats.rx_packets = self.stats.rx_packets.saturating_add(1);
            self.stats.rx_bytes = self.stats.rx_bytes.saturating_add(n as u64);

            if hdr.flags.is_ctrl_edge {
                let ctrl = EdgeCtrlFrame::decode(&payload)?;
                match ctrl {
                    EdgeCtrlFrame::Ping { ts_us } => {
                        let _ = self.send_edge_ctrl(&EdgeCtrlFrame::Pong { ts_us }).await;
                    }
                    EdgeCtrlFrame::LegNack {
                        base_leg_seq,
                        loss_bitmap,
                    } => {
                        self.stats.leg_nacks_recv = self.stats.leg_nacks_recv.saturating_add(1);
                        let rtx_pkts = self.rtx_cache.handle_leg_nack(
                            base_leg_seq,
                            loss_bitmap,
                            now,
                            self.rtt_ms,
                            None,
                            &self.tx_epoch,
                        );
                        for pkt in rtx_pkts {
                            let _ = self.socket.send(&pkt).await;
                            self.stats.rtx_packets_sent =
                                self.stats.rtx_packets_sent.saturating_add(1);
                        }
                    }
                    EdgeCtrlFrame::BwHint {
                        cap_kbps,
                        report_age_ms,
                        bottleneck_leg,
                        event_flags,
                        ..
                    } => {
                        let cur_bw = self.bw_hint.effective_bw_kbps();
                        self.bw_hint.on_bw_hint(
                            cur_bw,
                            cap_kbps,
                            report_age_ms,
                            bottleneck_leg,
                            event_flags,
                            now,
                        );
                        self.bulk_paused = (event_flags
                            & (BW_EVENT_PAUSE_FILE_CHUNK
                                | BW_EVENT_DROP_ACTIVE
                                | BW_EVENT_SURVIVAL_MODE))
                            != 0;
                    }
                    _ => {}
                }
                return Ok(UdpRecvEvent::EdgeCtrl(ctrl));
            }

            if hdr.flags.rtx {
                self.stats.rtx_packets_recv = self.stats.rtx_packets_recv.saturating_add(1);
            }
            if !self.dedup.check_and_mark(hdr.leg_seq) {
                self.stats.dup_packets_dropped = self.stats.dup_packets_dropped.saturating_add(1);
                continue;
            }
            if let Some((base_leg_seq, loss_bitmap)) =
                self.gap_tracker.on_recv(hdr.leg_seq, hdr.flags.discardable)
            {
                if self.auto_leg_nack {
                    let _ = self.send_leg_nack(base_leg_seq, loss_bitmap).await;
                }
            }
            return Ok(UdpRecvEvent::L3Data {
                header: hdr,
                payload,
            });
        }
    }

    /// Manually handles a `LEG_NACK` request against this link's ciphertext cache and returns
    /// the generated `rtx=1` wire packets (also useful for deterministic verification).
    pub fn handle_local_leg_nack(
        &mut self,
        base_leg_seq: u32,
        loss_bitmap: u64,
    ) -> Vec<Vec<u8>> {
        self.rtx_cache.handle_leg_nack(
            base_leg_seq,
            loss_bitmap,
            now_ms(),
            self.rtt_ms,
            None,
            &self.tx_epoch,
        )
    }
}

/// Encodes 6 unequal-length payloads into 10 Survival Mode `RS(6,4)` wire shards via `v2_transport`.
pub fn encode_survival_rs64_shards(
    block_id: u32,
    data_shards: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, ClientError> {
    let raw_shards = rs64_encode_block(data_shards)?;
    let mut out = Vec::with_capacity(SURVIVAL_RS_K + SURVIVAL_RS_M);
    for (idx, shard) in raw_shards.into_iter().enumerate() {
        let mut frame = Vec::with_capacity(SURVIVAL_SHARD_HDR_LEN + shard.len());
        frame.push(SURVIVAL_SHARD_MAGIC);
        frame.extend_from_slice(&block_id.to_be_bytes());
        frame.push(idx as u8);
        frame.extend_from_slice(&shard);
        out.push(frame);
    }
    Ok(out)
}

/// Decodes any `>= 6` surviving Survival Mode `RS(6,4)` wire shards into the original 6 payloads.
pub fn decode_survival_rs64_shards(
    expected_block_id: u32,
    received_frames: &[Vec<u8>],
) -> Result<Vec<Vec<u8>>, ClientError> {
    let mut slots: Vec<Option<Vec<u8>>> = vec![None; SURVIVAL_RS_K + SURVIVAL_RS_M];
    for frame in received_frames {
        if frame.len() < SURVIVAL_SHARD_HDR_LEN || frame[0] != SURVIVAL_SHARD_MAGIC {
            return Err(ClientError::Protocol("malformed RS(6,4) survival shard".into()));
        }
        let bid = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]);
        if bid != expected_block_id {
            continue;
        }
        let idx = frame[5] as usize;
        if idx >= SURVIVAL_RS_K + SURVIVAL_RS_M {
            return Err(ClientError::Protocol("RS(6,4) shard index out of range".into()));
        }
        slots[idx] = Some(frame[SURVIVAL_SHARD_HDR_LEN..].to_vec());
    }
    Ok(rs64_decode_block(&slots)?)
}

const HANDSHAKE_RTX_INITIAL_INTERVAL: Duration = Duration::from_millis(600);
const HANDSHAKE_RTX_MAX_INTERVAL: Duration = Duration::from_millis(2_400);
const HANDSHAKE_REPLAY_TTL: Duration = Duration::from_secs(5);

fn next_handshake_rtx_interval(current: Duration) -> Duration {
    current.saturating_mul(2).min(HANDSHAKE_RTX_MAX_INTERVAL)
}

enum HandshakeReplayCache {
    Initiator {
        msg2: Vec<u8>,
        created: Instant,
    },
    Responder {
        msg1: Vec<u8>,
        msg2: Vec<u8>,
        created: Instant,
    },
}

/// Unified Layer 2 data-plane transport supporting both UDP 28B and Dual TLS-443 fallback.
pub enum AccessDataPlane {
    Udp(Box<UdpAccessLink>),
    DualTls443(Box<DualTls443Client>),
}

impl From<UdpAccessLink> for AccessDataPlane {
    fn from(link: UdpAccessLink) -> Self {
        Self::Udp(Box::new(link))
    }
}

impl From<DualTls443Client> for AccessDataPlane {
    fn from(client: DualTls443Client) -> Self {
        Self::DualTls443(Box::new(client))
    }
}

impl AccessDataPlane {
    pub fn active_mode(&self) -> ActiveTransportMode {
        match self {
            Self::Udp(_) => ActiveTransportMode::Udp,
            Self::DualTls443(_) => ActiveTransportMode::DualTls443,
        }
    }

    pub fn route_cid(&self) -> [u8; 8] {
        match self {
            Self::Udp(u) => u.route_cid(),
            Self::DualTls443(t) => t.route_cid(),
        }
    }

    pub fn is_bulk_paused(&self) -> bool {
        match self {
            Self::Udp(u) => u.is_bulk_paused(),
            Self::DualTls443(t) => t.is_bulk_paused(),
        }
    }

    pub fn p3_dropped(&self) -> u64 {
        match self {
            Self::Udp(u) => u.p3_dropped(),
            Self::DualTls443(t) => t.p3_dropped(),
        }
    }

    pub fn stats(&self) -> UdpLinkStats {
        match self {
            Self::Udp(u) => u.stats.clone(),
            Self::DualTls443(t) => UdpLinkStats {
                tx_packets: t.realtime.tx_packets.saturating_add(t.bulk.tx_packets),
                rx_packets: t.realtime.rx_packets.saturating_add(t.bulk.rx_packets),
                tx_bytes: t.realtime.tx_bytes.saturating_add(t.bulk.tx_bytes),
                rx_bytes: t.realtime.rx_bytes.saturating_add(t.bulk.rx_bytes),
                leg_nacks_sent: 0,
                leg_nacks_recv: 0,
                rtx_packets_sent: 0,
                rtx_packets_recv: 0,
                dup_packets_dropped: 0,
                p3_dropped: t.p3_dropped(),
            },
        }
    }

    pub fn as_udp(&self) -> Option<&UdpAccessLink> {
        match self {
            Self::Udp(u) => Some(u),
            Self::DualTls443(_) => None,
        }
    }

    pub fn as_udp_mut(&mut self) -> Option<&mut UdpAccessLink> {
        match self {
            Self::Udp(u) => Some(u),
            Self::DualTls443(_) => None,
        }
    }

    pub fn as_tls443(&self) -> Option<&DualTls443Client> {
        match self {
            Self::Udp(_) => None,
            Self::DualTls443(t) => Some(t),
        }
    }

    pub fn as_tls443_mut(&mut self) -> Option<&mut DualTls443Client> {
        match self {
            Self::Udp(_) => None,
            Self::DualTls443(t) => Some(t),
        }
    }

    pub async fn send_edge_ctrl(&mut self, ctrl: &EdgeCtrlFrame) -> Result<(), ClientError> {
        match self {
            Self::Udp(u) => u.send_edge_ctrl(ctrl).await,
            Self::DualTls443(t) => t.send_edge_ctrl(ctrl).await,
        }
    }

    /// Application-layer keepalive/dead-link ping across either UDP or Dual TLS-443.
    pub async fn ping(&mut self, timeout: Duration) -> Result<u64, ClientError> {
        match self {
            Self::Udp(u) => u.ping_with_retry(1, timeout).await,
            Self::DualTls443(t) => t.ping(timeout).await,
        }
    }

    pub async fn send_l3_packet(
        &mut self,
        pp: u8,
        discardable: bool,
        frame_end: bool,
        frame_id: u32,
        l3_payload: &[u8],
    ) -> Result<u32, ClientError> {
        // Invariant: p3 (Bulk) frames are NEVER discardable and NEVER dropped by HoL logic.
        let (eff_discardable, eff_frame_end, eff_frame_id) = if pp == 3 {
            (false, true, 0)
        } else if frame_id == 0 {
            (false, frame_end, 0)
        } else {
            (discardable, frame_end, frame_id)
        };
        match self {
            Self::Udp(u) => u.send_l3_packet(pp, eff_discardable, l3_payload).await,
            Self::DualTls443(t) => {
                t.send_l3(pp, eff_discardable, eff_frame_end, eff_frame_id, l3_payload)
                    .await
            }
        }
    }

    pub async fn recv_packet(&mut self, timeout: Duration) -> Result<UdpRecvEvent, ClientError> {
        match self {
            Self::Udp(u) => u.recv_packet(timeout).await,
            Self::DualTls443(t) => match t.recv_frame(timeout).await? {
                StreamRecvEvent::EdgeCtrl(ctrl) => Ok(UdpRecvEvent::EdgeCtrl(ctrl)),
                StreamRecvEvent::L3Data {
                    header, payload, ..
                } => Ok(UdpRecvEvent::L3Data { header, payload }),
            },
        }
    }
}

/// Raw decrypted L4 frame preserving exact `L4Header` (`msg_type`, `flags`, `body_len`,
/// `stream_seq`) for v1.2.4 `0x02 Audio`, `0x04 Clipboard`, and `0x05 FileTransfer` state machines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawL4Frame {
    pub chan_id: u8,
    pub header: L4Header,
    pub body: Bytes,
}

/// Unified v1.2.4 receive event returned by `V2E2eeSession::recv_v124_event`.
#[derive(Debug, Clone, PartialEq)]
pub enum V2RecvEvent {
    Transport(TransportEvent),
    AudioRaw(RawL4Frame),
    ClipboardRaw(RawL4Frame),
    FileTransferRaw(RawL4Frame),
}

/// Type alias highlighting transport-agnostic `AccessDataPlane` support (UDP or Dual TLS-443)
/// while keeping the `UdpE2eeSession` name 100% backward-compatible.
pub type V2E2eeSession = UdpE2eeSession;

/// Complete client ↔ client E2EE session running identically over `AccessDataPlane` (UDP or
/// Dual TLS-443) with:
/// - `Noise_IK` handshake + 204B anti-downgrade prologue + P-256 `DelegationStatement` verification
/// - L3 AEAD + 2048-bit replay window + `chan_id <-> pp` validation
/// - L4 9-channel multiplexer (`0x00..0x08`, including `0x07 RealtimeActuator` policy + `ActuatorReceiver` gate)
pub struct UdpE2eeSession {
    link: AccessDataPlane,
    policy: VerifiedTenantPolicy,
    l3_mtu: usize,
    sender: L3Sender,
    receiver: L3Receiver,
    reassembler: VideoReassembler,
    actuator_receiver: ActuatorReceiver,
    stream_dedup: StreamSeqDedup,
    next_stream_seq: [u32; 9],
    p3_arq: P3ArqEngine,
    hs_replay: Option<HandshakeReplayCache>,
    invalid_l3_frames_dropped: u64,
}

impl UdpE2eeSession {
    #[allow(clippy::too_many_arguments)]
    pub async fn handshake_initiator(
        link: impl Into<AccessDataPlane>,
        prologue_input: &PrologueInput,
        local_x25519_priv: &[u8; 32],
        remote_x25519_pub: &[u8; 32],
        peer_delegation: &DelegationStatement,
        expected_peer_device_id: &[u8; 16],
        peer_device_spki_der: &[u8],
        peer_device_cert_exp_unix: u64,
        now_unix: u64,
        policy: VerifiedTenantPolicy,
        local_device_id: [u8; 16],
        l3_mtu: usize,
        timeout: Duration,
    ) -> Result<(Self, E2eeHandshakeOutput), ClientError> {
        let mut link = link.into();
        let prologue = prologue_input.compute_prologue();
        let mut hs = E2eeNoiseHandshake::build_ik_initiator(
            prologue_input.cipher_suite,
            local_x25519_priv,
            remote_x25519_pub,
            &prologue,
        )?;
        let msg1 = hs.write_message(b"V2-SESSION-OPEN")?;
        link.send_l3_packet(0, false, true, 0, &msg1).await?;

        let is_udp = link.active_mode() == ActiveTransportMode::Udp;
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            ClientError::Protocol("E2EE handshake timeout overflows monotonic clock".into())
        })?;
        let mut rtx_interval = HANDSHAKE_RTX_INITIAL_INTERVAL;
        let mut next_rtx = Instant::now().checked_add(rtx_interval).unwrap_or(deadline);
        let mut bad_msg2_attempts = 0usize;
        let msg2 = loop {
            let now = Instant::now();
            let Some(rem) = deadline
                .checked_duration_since(now)
                .filter(|d| !d.is_zero())
            else {
                return Err(ClientError::Timeout("E2EE Noise_IK msg2 timed out".into()));
            };
            let slice = if is_udp {
                match next_rtx
                    .checked_duration_since(now)
                    .filter(|d| !d.is_zero())
                {
                    Some(until_rtx) => rem.min(until_rtx),
                    None => {
                        link.send_l3_packet(0, false, true, 0, &msg1).await?;
                        rtx_interval = next_handshake_rtx_interval(rtx_interval);
                        next_rtx = Instant::now() + rtx_interval;
                        continue;
                    }
                }
            } else {
                rem
            };
            match link.recv_packet(slice).await {
                Ok(UdpRecvEvent::L3Data { header, payload }) => {
                    // Responder always sends Noise_IK msg2 on pp=0; silently discard early
                    // pp=1/2/3 media/bulk packets that overtook a delayed or dropped msg2.
                    if header.flags.pp != 0 {
                        continue;
                    }
                    match hs.read_message(&payload) {
                        Ok(_) => break payload,
                        Err(e) => {
                            bad_msg2_attempts = bad_msg2_attempts.saturating_add(1);
                            if bad_msg2_attempts >= MAX_HANDSHAKE_INITIATOR_BAD_MSG2 {
                                return Err(e.into());
                            }
                            continue;
                        }
                    }
                }
                Ok(UdpRecvEvent::EdgeCtrl(_)) => continue,
                Err(ClientError::Timeout(_)) => {
                    let now = Instant::now();
                    if deadline.checked_duration_since(now).is_none() {
                        return Err(ClientError::Timeout("E2EE Noise_IK msg2 timed out".into()));
                    }
                    if is_udp && next_rtx.checked_duration_since(now).is_none() {
                        link.send_l3_packet(0, false, true, 0, &msg1).await?;
                        rtx_interval = next_handshake_rtx_interval(rtx_interval);
                        next_rtx = Instant::now() + rtx_interval;
                    }
                }
                Err(e) => return Err(e),
            }
        };
        let out = hs.finish_split(
            Some(peer_delegation),
            expected_peer_device_id,
            peer_device_spki_der,
            peer_device_cert_exp_unix,
            now_unix,
        )?;
        let mut session = Self::from_handshake(link, &out, policy, local_device_id, l3_mtu);
        session.hs_replay = Some(HandshakeReplayCache::Initiator {
            msg2,
            created: Instant::now(),
        });
        Ok((session, out))
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn handshake_responder(
        link: impl Into<AccessDataPlane>,
        prologue_input: &PrologueInput,
        local_x25519_priv: &[u8; 32],
        peer_delegation: &DelegationStatement,
        expected_peer_device_id: &[u8; 16],
        peer_device_spki_der: &[u8],
        peer_device_cert_exp_unix: u64,
        now_unix: u64,
        policy: VerifiedTenantPolicy,
        local_device_id: [u8; 16],
        l3_mtu: usize,
        timeout: Duration,
    ) -> Result<(Self, E2eeHandshakeOutput), ClientError> {
        let mut link = link.into();
        let prologue = prologue_input.compute_prologue();
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            ClientError::Protocol("E2EE handshake timeout overflows monotonic clock".into())
        })?;
        let mut attempts = 0usize;
        let mut last_err: Option<ClientError> = None;

        let (msg1, msg2, out) = loop {
            if attempts >= MAX_HANDSHAKE_RESPONDER_ATTEMPTS {
                return Err(last_err.unwrap_or_else(|| {
                    ClientError::Protocol(
                        "E2EE Noise_IK responder exceeded max invalid msg1 attempts".into(),
                    )
                }));
            }
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("E2EE Noise_IK msg1 timed out".into()));
            };
            let candidate_msg1 = match link.recv_packet(rem).await? {
                UdpRecvEvent::L3Data { payload, .. } => payload,
                UdpRecvEvent::EdgeCtrl(_) => continue,
            };
            attempts += 1;

            let mut hs = E2eeNoiseHandshake::build_ik_responder(
                prologue_input.cipher_suite,
                local_x25519_priv,
                &prologue,
            )?;
            if let Err(e) = hs.read_message(&candidate_msg1) {
                last_err = Some(e.into());
                continue;
            }
            let msg2 = match hs.write_message(b"V2-SESSION-ACCEPT") {
                Ok(m) => m,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };
            let out = match hs.finish_split(
                Some(peer_delegation),
                expected_peer_device_id,
                peer_device_spki_der,
                peer_device_cert_exp_unix,
                now_unix,
            ) {
                Ok(o) => o,
                Err(e) => {
                    last_err = Some(e.into());
                    continue;
                }
            };
            link.send_l3_packet(0, false, true, 0, &msg2).await?;
            break (candidate_msg1, msg2, out);
        };
        let mut session = Self::from_handshake(link, &out, policy, local_device_id, l3_mtu);
        session.hs_replay = Some(HandshakeReplayCache::Responder {
            msg1,
            msg2,
            created: Instant::now(),
        });
        Ok((session, out))
    }

    pub fn from_handshake(
        link: impl Into<AccessDataPlane>,
        hs_out: &E2eeHandshakeOutput,
        policy: VerifiedTenantPolicy,
        local_device_id: [u8; 16],
        l3_mtu: usize,
    ) -> Self {
        let tenant_id = policy.tenant_id;
        Self {
            link: link.into(),
            policy,
            l3_mtu: l3_mtu.min(L3_MTU_DEFAULT),
            sender: L3Sender::new(hs_out.cipher_suite, 1, *hs_out.tx_key),
            receiver: L3Receiver::new(hs_out.cipher_suite, 1, *hs_out.rx_key),
            reassembler: VideoReassembler::default(),
            actuator_receiver: ActuatorReceiver::new(tenant_id, local_device_id, 1),
            stream_dedup: StreamSeqDedup::default(),
            next_stream_seq: [0; 9],
            p3_arq: P3ArqEngine::new(),
            hs_replay: None,
            invalid_l3_frames_dropped: 0,
        }
    }

    /// Creates a session directly from pre-shared keys (gated behind `test` / `test-utils`).
    #[cfg(any(test, feature = "test-utils"))]
    pub fn from_keys(
        link: impl Into<AccessDataPlane>,
        tx_key: [u8; 32],
        rx_key: [u8; 32],
        policy: VerifiedTenantPolicy,
        local_device_id: [u8; 16],
    ) -> Self {
        let tenant_id = policy.tenant_id;
        Self {
            link: link.into(),
            policy,
            l3_mtu: L3_MTU_DEFAULT,
            sender: L3Sender::new(CIPHER_AESGCM, 1, tx_key),
            receiver: L3Receiver::new(CIPHER_AESGCM, 1, rx_key),
            reassembler: VideoReassembler::default(),
            actuator_receiver: ActuatorReceiver::new(tenant_id, local_device_id, 1),
            stream_dedup: StreamSeqDedup::default(),
            next_stream_seq: [0; 9],
            p3_arq: P3ArqEngine::new(),
            hs_replay: None,
            invalid_l3_frames_dropped: 0,
        }
    }

    pub fn invalid_l3_frames_dropped(&self) -> u64 {
        self.invalid_l3_frames_dropped
    }

    pub fn data_plane(&self) -> &AccessDataPlane {
        &self.link
    }

    pub fn data_plane_mut(&mut self) -> &mut AccessDataPlane {
        &mut self.link
    }

    pub fn udp_link(&self) -> Option<&UdpAccessLink> {
        self.link.as_udp()
    }

    pub fn udp_link_mut(&mut self) -> Option<&mut UdpAccessLink> {
        self.link.as_udp_mut()
    }

    pub fn active_transport_mode(&self) -> ActiveTransportMode {
        self.link.active_mode()
    }

    pub fn p3_dropped(&self) -> u64 {
        self.link.p3_dropped()
    }

    pub fn is_bulk_paused(&self) -> bool {
        self.link.is_bulk_paused()
    }

    pub async fn ping_keepalive(&mut self, timeout: Duration) -> Result<u64, ClientError> {
        self.link.ping(timeout).await
    }

    pub fn policy(&self) -> &VerifiedTenantPolicy {
        &self.policy
    }

    pub fn apply_actuator_preempt(
        &mut self,
        token: &ControlPreemptToken,
        ca_spki_der: &[u8],
        now_unix: u64,
    ) -> Result<u32, ClientError> {
        Ok(self
            .actuator_receiver
            .apply_preempt_token(token, ca_spki_der, now_unix)?)
    }

    pub fn next_arq_deadline(&self) -> Option<Instant> {
        self.p3_arq.next_deadline(Instant::now())
    }

    pub async fn poll_arq(&mut self) -> Result<(), ClientError> {
        let actions = self.p3_arq.poll_due(Instant::now())?;
        for ack in actions.acks {
            self.send_ack_sack(&ack).await?;
        }
        for rtx in actions.retransmits {
            self.send_l4_with_seq(
                rtx.chan_id,
                rtx.msg_type,
                rtx.flags,
                rtx.stream_seq,
                false,
                true,
                0,
                &rtx.body,
            )
            .await?;
        }
        Ok(())
    }

    pub fn p3_arq_inflight_pkts(&self, chan_id: u8) -> usize {
        self.p3_arq.inflight_pkts(chan_id)
    }

    pub fn p3_arq_inflight_bytes(&self, chan_id: u8) -> usize {
        self.p3_arq.inflight_bytes(chan_id)
    }

    pub fn p3_arq_rtx_sent(&self, chan_id: u8) -> u64 {
        self.p3_arq.rtx_sent_total(chan_id)
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_l4_with_seq(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        flags: u8,
        stream_seq: u32,
        discardable: bool,
        frame_end: bool,
        frame_id: u32,
        body: &[u8],
    ) -> Result<u32, ClientError> {
        let pp = default_channel_priority(chan_id)
            .ok_or_else(|| TransportError::InvalidFraming(format!("unknown chan_id {chan_id}")))?;
        let body_len = u16::try_from(body.len())
            .map_err(|_| TransportError::InvalidFraming("L4 body exceeds u16::MAX".into()))?;
        let l4_hdr = L4Header {
            msg_type,
            flags,
            body_len,
            stream_seq,
        };
        let l4_wire = encode_l4_frame(&l4_hdr, body)?;
        let ts_mod = (now_us() & 0xFFFF_FFFF) as u32;
        let (_, l3_wire) = self.sender.encrypt(chan_id, 0, ts_mod, &l4_wire)?;
        self.link
            .send_l3_packet(pp, discardable, frame_end, frame_id, &l3_wire)
            .await
    }

    async fn send_ack_sack(&mut self, ack: &AckSackFrame) -> Result<(), ClientError> {
        let payload = ack.encode();
        let _ = self
            .send_l4_with_seq(
                CHAN_TRANSPORT_CTRL,
                CTRL_MSG_ACK_SACK,
                0,
                ACK_SACK_STREAM_SEQ,
                false,
                true,
                0,
                &payload,
            )
            .await?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_l4_internal(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        flags: u8,
        discardable: bool,
        frame_end: bool,
        frame_id: u32,
        body: &[u8],
    ) -> Result<u32, ClientError> {
        if is_p3_channel(chan_id) {
            self.poll_arq().await?;
            let tx = self
                .p3_arq
                .enqueue_send(chan_id, msg_type, flags, body, Instant::now())?;
            return self
                .send_l4_with_seq(
                    chan_id,
                    tx.msg_type,
                    tx.flags,
                    tx.stream_seq,
                    false,
                    true,
                    0,
                    &tx.body,
                )
                .await;
        }
        let idx = chan_id as usize;
        let stream_seq = self.next_stream_seq[idx];
        self.next_stream_seq[idx] = stream_seq.wrapping_add(1);
        self.send_l4_with_seq(
            chan_id,
            msg_type,
            flags,
            stream_seq,
            discardable,
            frame_end,
            frame_id,
            body,
        )
        .await
    }

    pub async fn send_channel_frame(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        flags: u8,
        discardable: bool,
        body: &[u8],
    ) -> Result<u32, ClientError> {
        let is_file_clipboard = chan_id == CHAN_CLIPBOARD && flags != 0;
        self.policy.enforce_channel(chan_id, is_file_clipboard)?;
        self.send_l4_internal(chan_id, msg_type, flags, discardable, true, 0, body)
            .await
    }

    /// Sends a v1.2.4 channel-protocol L4 frame strictly limited to `0x02 Audio`, `0x04 Clipboard`,
    /// or `0x05 FileTransfer`. Enforces `self.policy.enforce_channel(...)` on all data frames,
    /// exempting ONLY rejection/control reply frames (`CLIP_ACK` = `0x02`, `FILE_ABORT` = `0x06`,
    /// `FILE_COMPLETE_ACK` = `0x07`) so a policy-denied receiver can always emit `POLICY_DENIED` /
    /// `UNSUPPORTED` replies while `CHAN_INPUT_HID` / `CHAN_REALTIME_ACTUATOR` can NEVER bypass policy.
    pub async fn send_l4_raw(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        flags: u8,
        discardable: bool,
        body: &[u8],
    ) -> Result<u32, ClientError> {
        let is_reply_exempt = matches!(
            (chan_id, msg_type),
            (CHAN_CLIPBOARD, 0x02) | (CHAN_FILE_TRANSFER, 0x06 | 0x07)
        );
        match chan_id {
            CHAN_AUDIO | CHAN_CLIPBOARD | CHAN_FILE_TRANSFER => {
                if !is_reply_exempt {
                    let is_file_clipboard = chan_id == CHAN_CLIPBOARD && flags != 0;
                    self.policy.enforce_channel(chan_id, is_file_clipboard)?;
                }
                self.send_l4_internal(chan_id, msg_type, flags, discardable, true, 0, body)
                    .await
            }
            _ => Err(TransportError::InvalidFraming(format!(
                "send_l4_raw only permits Audio/Clipboard/FileTransfer, got chan_id={chan_id:#04x}"
            ))
            .into()),
        }
    }

    /// Sends a raw negative-test wire probe expected to be dropped at Edge L2 (`AllDenied`),
    /// bypassing both local policy and `p3` ARQ (`stream_seq = u32::MAX`) so Edge-dropped probes
    /// create zero ARQ retries or sequence holes. Never permits `CHAN_INPUT_HID` or
    /// `CHAN_REALTIME_ACTUATOR`.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn send_negative_policy_probe(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        body: &[u8],
    ) -> Result<u32, ClientError> {
        match chan_id {
            CHAN_CLIPBOARD | CHAN_FILE_TRANSFER => {
                self.send_l4_with_seq(
                    chan_id,
                    msg_type,
                    0,
                    P3_PROBE_STREAM_SEQ,
                    false,
                    true,
                    0,
                    body,
                )
                .await
            }
            CHAN_AUDIO => {
                self.send_l4_internal(chan_id, msg_type, 0, false, true, 0, body)
                    .await
            }
            _ => Err(TransportError::InvalidFraming(format!(
                "send_negative_policy_probe only permits Audio/Clipboard/FileTransfer, got {chan_id:#04x}"
            ))
            .into()),
        }
    }

    /// Sends a raw wire frame bypassing only the local policy check while retaining full `p3` ARQ
    /// reliability so partial-deny tests (where Edge forwards `p3` and remote Host must reply
    /// `POLICY_DENIED` / `FILE_ABORT(0x0401)`) remain reliable under WAN loss.
    #[cfg(any(test, feature = "test-utils"))]
    pub async fn send_l4_bypass_local_policy(
        &mut self,
        chan_id: u8,
        msg_type: u8,
        body: &[u8],
    ) -> Result<u32, ClientError> {
        match chan_id {
            CHAN_AUDIO | CHAN_CLIPBOARD | CHAN_FILE_TRANSFER => {
                self.send_l4_internal(chan_id, msg_type, 0, false, true, 0, body)
                    .await
            }
            _ => Err(TransportError::InvalidFraming(format!(
                "send_l4_bypass_local_policy only permits Audio/Clipboard/FileTransfer, got {chan_id:#04x}"
            ))
            .into()),
        }
    }

    pub async fn send_hid(&mut self, frame: &HidFrame) -> Result<u32, ClientError> {
        self.send_channel_frame(CHAN_INPUT_HID, frame.msg_type, 0, false, &frame.payload)
            .await
    }

    pub async fn send_audio(&mut self, pkt: &AudioPacket) -> Result<u32, ClientError> {
        let mut body = Vec::with_capacity(5 + pkt.payload.len());
        body.extend_from_slice(&pkt.ts.to_be_bytes());
        body.push(u8::from(pkt.dtx));
        body.extend_from_slice(&pkt.payload);
        self.send_channel_frame(CHAN_AUDIO, 0x01, 0, false, &body)
            .await
    }

    pub async fn send_video_frame(
        &mut self,
        meta: &VideoFrameMeta,
        frame_data: &[u8],
    ) -> Result<usize, ClientError> {
        self.policy.enforce_channel(CHAN_VIDEO, false)?;
        let slices = VideoSlice::slice_frame(
            meta.codec_id,
            meta.frame_id,
            meta.ref_frame_id,
            meta.ltr_slot,
            meta.is_idr,
            meta.is_ref,
            meta.max_age_ms,
            frame_data,
            self.l3_mtu,
        )?;
        let count = slices.len();
        let discardable = !meta.is_ref && meta.frame_id != 0;
        for (idx, slice) in slices.into_iter().enumerate() {
            let encoded = slice.encode();
            let frame_end = idx + 1 == count;
            self.send_l4_internal(
                CHAN_VIDEO,
                0x01,
                0,
                discardable,
                frame_end,
                meta.frame_id,
                &encoded,
            )
            .await?;
        }
        Ok(count)
    }

    pub async fn send_clipboard(&mut self, frame: &ClipboardFrame) -> Result<u32, ClientError> {
        self.policy
            .enforce_channel(CHAN_CLIPBOARD, frame.is_file_clipboard)?;
        self.send_channel_frame(
            CHAN_CLIPBOARD,
            0x01,
            u8::from(frame.is_file_clipboard),
            false,
            &frame.payload,
        )
        .await
    }

    pub async fn send_file_chunk(&mut self, frame: &FileFrame) -> Result<u32, ClientError> {
        self.policy.enforce_channel(CHAN_FILE_TRANSFER, false)?;
        self.send_channel_frame(CHAN_FILE_TRANSFER, frame.msg_type, 0, false, &frame.payload)
            .await
    }

    pub async fn send_actuator(&mut self, cmd: &ActuatorCmd) -> Result<u32, ClientError> {
        self.policy
            .enforce_channel(CHAN_REALTIME_ACTUATOR, false)?;
        let body = cmd.encode();
        self.send_channel_frame(CHAN_REALTIME_ACTUATOR, 0x01, 0, false, &body)
            .await
    }

    pub async fn send_telemetry(&mut self, frame: &TelemetryFrame) -> Result<u32, ClientError> {
        let body = frame.encode();
        self.send_channel_frame(CHAN_TELEMETRY, 0x01, 0, true, &body)
            .await
    }

    pub async fn send_control(&mut self, msg_type: u8, payload: &[u8]) -> Result<u32, ClientError> {
        self.send_channel_frame(CHAN_TRANSPORT_CTRL, msg_type, 0, false, payload)
            .await
    }

    async fn recv_decrypted_l4(
        &mut self,
        deadline: Instant,
    ) -> Result<(u8, L4Header, Vec<u8>, u64), ClientError> {
        self.poll_arq().await?;
        let mut consecutive_bad_l3 = 0u32;
        loop {
            if let Some(ready) = self.p3_arq.pop_ready() {
                return Ok((ready.chan_id, ready.header, ready.body.to_vec(), now_ms()));
            }
            let now_inst = Instant::now();
            let Some(rem) = deadline.checked_duration_since(now_inst) else {
                return Err(ClientError::Timeout("E2EE recv_event timed out".into()));
            };
            let wait = if let Some(arq_dl) = self.p3_arq.next_deadline(now_inst) {
                match arq_dl.checked_duration_since(now_inst) {
                    Some(until_arq) if !until_arq.is_zero() => rem.min(until_arq),
                    _ => {
                        self.poll_arq().await?;
                        continue;
                    }
                }
            } else {
                rem
            };
            let (hdr, l3_bytes) = match self.link.recv_packet(wait).await {
                Ok(UdpRecvEvent::EdgeCtrl(_)) => {
                    self.poll_arq().await?;
                    continue;
                }
                Ok(UdpRecvEvent::L3Data { header, payload }) => (header, payload),
                Err(ClientError::Timeout(_)) => {
                    self.poll_arq().await?;
                    if self.p3_arq.has_ready() {
                        continue;
                    }
                    if Instant::now() >= deadline {
                        return Err(ClientError::Timeout("E2EE recv_event timed out".into()));
                    }
                    continue;
                }
                Err(e) => return Err(e),
            };
            if let Some(cache) = &self.hs_replay {
                let expired = match cache {
                    HandshakeReplayCache::Responder { created, .. }
                    | HandshakeReplayCache::Initiator { created, .. } => {
                        created.elapsed() >= HANDSHAKE_REPLAY_TTL
                    }
                };
                if expired {
                    self.hs_replay = None;
                } else {
                    match cache {
                        HandshakeReplayCache::Responder { msg1, msg2, .. }
                            if l3_bytes == *msg1 =>
                        {
                            self.link.send_l3_packet(0, false, true, 0, msg2).await?;
                            continue;
                        }
                        HandshakeReplayCache::Initiator { msg2, .. } if l3_bytes == *msg2 => {
                            continue;
                        }
                        _ => {}
                    }
                }
            }
            let now = now_ms();
            let (l3_hdr, pt) = match self.receiver.decrypt_and_verify(
                &l3_bytes,
                Some(hdr.flags.pp),
                now,
            ) {
                Ok(v) => {
                    consecutive_bad_l3 = 0;
                    v
                }
                Err(TransportError::ReplayDetected) => continue,
                Err(e) => {
                    self.invalid_l3_frames_dropped =
                        self.invalid_l3_frames_dropped.saturating_add(1);
                    consecutive_bad_l3 = consecutive_bad_l3.saturating_add(1);
                    if consecutive_bad_l3 >= MAX_CONSECUTIVE_BAD_L3_FRAMES {
                        return Err(e.into());
                    }
                    continue;
                }
            };
            let (l4_hdr, body) = decode_l4_frame(&pt)?;
            if l3_hdr.chan_id == CHAN_TRANSPORT_CTRL
                && l4_hdr.msg_type == CTRL_MSG_ACK_SACK
                && body.len() == ACK_SACK_WIRE_LEN
                && is_p3_channel(body[0])
            {
                let ack = AckSackFrame::decode(body)?;
                self.p3_arq.on_recv_ack(&ack, Instant::now());
                self.poll_arq().await?;
                continue;
            }
            if is_p3_channel(l3_hdr.chan_id) {
                self.p3_arq.on_recv_data(
                    l3_hdr.chan_id,
                    l4_hdr,
                    Bytes::copy_from_slice(body),
                    Instant::now(),
                )?;
                self.poll_arq().await?;
                continue;
            }
            if !self.stream_dedup.mark_if_new(l3_hdr.chan_id, l4_hdr.stream_seq) {
                continue;
            }
            return Ok((l3_hdr.chan_id, l4_hdr, body.to_vec(), now));
        }
    }

    /// Receives the next v1.2.4 session event, preserving raw `L4Header` + body for `0x02 Audio`,
    /// `0x04 Clipboard`, and `0x05 FileTransfer` so their v1.2.4 state machines can enforce
    /// exact framing, policy replies (`POLICY_DENIED`), and unknown `msg_type` handling.
    pub async fn recv_v124_event(&mut self, timeout: Duration) -> Result<V2RecvEvent, ClientError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            ClientError::Protocol("E2EE recv_v124_event timeout overflows monotonic clock".into())
        })?;
        loop {
            let (chan_id, l4_hdr, body, now) = self.recv_decrypted_l4(deadline).await?;
            match chan_id {
                CHAN_AUDIO => {
                    return Ok(V2RecvEvent::AudioRaw(RawL4Frame {
                        chan_id,
                        header: l4_hdr,
                        body: Bytes::from(body),
                    }));
                }
                CHAN_CLIPBOARD => {
                    return Ok(V2RecvEvent::ClipboardRaw(RawL4Frame {
                        chan_id,
                        header: l4_hdr,
                        body: Bytes::from(body),
                    }));
                }
                CHAN_FILE_TRANSFER => {
                    return Ok(V2RecvEvent::FileTransferRaw(RawL4Frame {
                        chan_id,
                        header: l4_hdr,
                        body: Bytes::from(body),
                    }));
                }
                _ => {
                    if let Some(ev) = self.dispatch_standard_channel(chan_id, l4_hdr, &body, now)? {
                        return Ok(V2RecvEvent::Transport(ev));
                    }
                }
            }
        }
    }

    fn dispatch_standard_channel(
        &mut self,
        chan_id: u8,
        l4_hdr: L4Header,
        body: &[u8],
        now: u64,
    ) -> Result<Option<TransportEvent>, ClientError> {
        match chan_id {
            CHAN_TRANSPORT_CTRL => Ok(Some(TransportEvent::Control(ControlFrame {
                msg_type: l4_hdr.msg_type,
                stream_seq: l4_hdr.stream_seq,
                payload: Bytes::copy_from_slice(body),
            }))),
            CHAN_INPUT_HID => Ok(Some(TransportEvent::Hid(HidFrame {
                msg_type: l4_hdr.msg_type,
                payload: Bytes::copy_from_slice(body),
            }))),
            CHAN_AUDIO => {
                if body.len() < 5 {
                    return Err(
                        TransportError::InvalidFraming("audio packet too short".into()).into(),
                    );
                }
                if body[4] >= 2 {
                    return Err(TransportError::InvalidFraming(format!(
                        "invalid audio dtx_u8 {}",
                        body[4]
                    ))
                    .into());
                }
                let ts = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                let dtx = body[4] == 1;
                Ok(Some(TransportEvent::Audio(AudioPacket {
                    ts,
                    dtx,
                    payload: Bytes::copy_from_slice(&body[5..]),
                })))
            }
            CHAN_VIDEO => {
                let slice = VideoSlice::decode(body)?;
                if let Some(frame) = self.reassembler.push_slice(slice, now) {
                    Ok(Some(TransportEvent::VideoFrame(AssembledVideoFrame {
                        codec_id: frame.codec_id,
                        frame_id: frame.frame_id,
                        ref_frame_id: frame.ref_frame_id,
                        ltr_slot: frame.ltr_slot,
                        is_idr: frame.is_idr,
                        is_ref: frame.is_ref,
                        data: Bytes::from(frame.data),
                    })))
                } else {
                    Ok(None)
                }
            }
            CHAN_CLIPBOARD => {
                let is_file_clipboard = l4_hdr.flags != 0;
                self.policy
                    .enforce_channel(CHAN_CLIPBOARD, is_file_clipboard)?;
                Ok(Some(TransportEvent::Clipboard(ClipboardFrame {
                    is_file_clipboard,
                    payload: Bytes::copy_from_slice(body),
                })))
            }
            CHAN_FILE_TRANSFER => {
                self.policy.enforce_channel(CHAN_FILE_TRANSFER, false)?;
                Ok(Some(TransportEvent::FileTransfer(FileFrame {
                    msg_type: l4_hdr.msg_type,
                    payload: Bytes::copy_from_slice(body),
                })))
            }
            CHAN_DIAGNOSTICS => {
                let snap = serde_json::from_slice(body)?;
                Ok(Some(TransportEvent::Diagnostics(snap)))
            }
            CHAN_REALTIME_ACTUATOR => {
                self.policy
                    .enforce_channel(CHAN_REALTIME_ACTUATOR, false)?;
                let cmd = ActuatorCmd::decode(body)?;
                if !self.actuator_receiver.accept_cmd(&cmd, now) {
                    return Err(TransportError::InvalidFraming(
                        "0x07 RealtimeActuator command rejected by safety validator".into(),
                    )
                    .into());
                }
                Ok(Some(TransportEvent::RealtimeActuator(cmd)))
            }
            CHAN_TELEMETRY => {
                let frame = TelemetryFrame::decode(body)?;
                Ok(Some(TransportEvent::Telemetry(frame)))
            }
            other => Err(TransportError::InvalidFraming(format!(
                "unsupported chan_id {other:#04x}"
            ))
            .into()),
        }
    }

    /// Receives and dispatches the next L4 `TransportEvent`, verifying L3 AEAD, 2048-bit
    /// replay window, `chan_id <-> pp`, `VerifiedTenantPolicy`, and `0x07 ActuatorReceiver`.
    pub async fn recv_event(&mut self, timeout: Duration) -> Result<TransportEvent, ClientError> {
        let deadline = Instant::now().checked_add(timeout).ok_or_else(|| {
            ClientError::Protocol("E2EE recv_event timeout overflows monotonic clock".into())
        })?;
        loop {
            let (chan_id, l4_hdr, body, now) = self.recv_decrypted_l4(deadline).await?;
            if let Some(ev) = self.dispatch_standard_channel(chan_id, l4_hdr, &body, now)? {
                return Ok(ev);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::sync::mpsc;
    use v2_identity::{
        DeviceCert, DeviceKeyStore, SoftwareDeviceKeyStore, TenantPolicyBlob,
        X25519StaticKeyRotator,
    };
    use v2_transport::{
        QuotaExhaustPolicy, TenantPolicyRules, PATTERN_IK, TRANSPORT_MODE_RELAY_UDP,
        VER_MAJOR_MINOR,
    };

    struct RelayFixture {
        link_a: UdpAccessLink,
        link_b: UdpAccessLink,
        stop_tx: mpsc::Sender<()>,
        relay_task: tokio::task::JoinHandle<()>,
        a2b_seen: Arc<AtomicUsize>,
        b2a_seen: Arc<AtomicUsize>,
    }

    async fn spawn_lossy_udp_relay_pair(
        drop_first_a2b: usize,
        drop_first_b2a: usize,
        dup_first_delivered_b2a: bool,
    ) -> RelayFixture {
        let relay_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = relay_a.local_addr().unwrap();
        let addr_b = relay_b.local_addr().unwrap();

        let cid_a = [0x11; 8];
        let cid_b = [0x22; 8];
        let hs_a = [0x33; 32];
        let hs_b = [0x44; 32];
        let keys_a = AccessKeys::derive(cid_a, hs_a, 0).unwrap();
        let keys_b = AccessKeys::derive(cid_b, hs_b, 0).unwrap();

        let a2b_seen = Arc::new(AtomicUsize::new(0));
        let b2a_seen = Arc::new(AtomicUsize::new(0));
        let a2b_cnt = Arc::clone(&a2b_seen);
        let b2a_cnt = Arc::clone(&b2a_seen);

        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let ka = keys_a.clone();
        let kb = keys_b.clone();
        let relay_task = tokio::spawn(async move {
            let mut rx_a =
                AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                    .unwrap();
            let mut rx_b =
                AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                    .unwrap();
            let mut peer_a: Option<SocketAddr> = None;
            let mut peer_b: Option<SocketAddr> = None;
            let mut seq_to_a = 1u32;
            let mut seq_to_b = 1u32;
            let mut b2a_delivered = 0usize;
            let mut ba = [0u8; 2048];
            let mut bb = [0u8; 2048];

            loop {
                tokio::select! {
                    _ = stop_rx.recv() => break,
                    Ok((n, src)) = relay_a.recv_from(&mut ba) => {
                        peer_a = Some(src);
                        if let Ok((hdr, body)) = rx_a.verify_udp_packet(&ba[..n], 100) {
                            if hdr.flags.is_ctrl_edge {
                                if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                    let ph = AccessHeaderV11 {
                                        flags: AccessFlags {
                                            pp: 0,
                                            discardable: false,
                                            frame_end: false,
                                            is_ctrl_edge: true,
                                            dir_edge_to_client: true,
                                            rtx: false,
                                        },
                                        route_cid: cid_a,
                                        access_epoch: 0,
                                        leg_seq: 0,
                                        mac_64: [0; 8],
                                    };
                                    let w = seal_udp_v11(
                                        &ka.udp_key_e2c,
                                        ph,
                                        &EdgeCtrlFrame::Pong { ts_us }.encode(),
                                    )
                                    .unwrap();
                                    let _ = relay_a.send_to(&w, src).await;
                                }
                            } else if let Some(dst) = peer_b {
                                let idx = a2b_cnt.fetch_add(1, Ordering::SeqCst) + 1;
                                if idx <= drop_first_a2b {
                                    continue;
                                }
                                let fh = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: hdr.flags.pp,
                                        discardable: hdr.flags.discardable,
                                        frame_end: false,
                                        is_ctrl_edge: false,
                                        dir_edge_to_client: true,
                                        rtx: false,
                                    },
                                    route_cid: cid_b,
                                    access_epoch: 0,
                                    leg_seq: seq_to_b,
                                    mac_64: [0; 8],
                                };
                                seq_to_b = seq_to_b.wrapping_add(1);
                                let w = seal_udp_v11(&kb.udp_key_e2c, fh, body).unwrap();
                                let _ = relay_b.send_to(&w, dst).await;
                            }
                        }
                    }
                    Ok((n, src)) = relay_b.recv_from(&mut bb) => {
                        peer_b = Some(src);
                        if let Ok((hdr, body)) = rx_b.verify_udp_packet(&bb[..n], 100) {
                            if hdr.flags.is_ctrl_edge {
                                if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                    let ph = AccessHeaderV11 {
                                        flags: AccessFlags {
                                            pp: 0,
                                            discardable: false,
                                            frame_end: false,
                                            is_ctrl_edge: true,
                                            dir_edge_to_client: true,
                                            rtx: false,
                                        },
                                        route_cid: cid_b,
                                        access_epoch: 0,
                                        leg_seq: 0,
                                        mac_64: [0; 8],
                                    };
                                    let w = seal_udp_v11(
                                        &kb.udp_key_e2c,
                                        ph,
                                        &EdgeCtrlFrame::Pong { ts_us }.encode(),
                                    )
                                    .unwrap();
                                    let _ = relay_b.send_to(&w, src).await;
                                }
                            } else if let Some(dst) = peer_a {
                                let idx = b2a_cnt.fetch_add(1, Ordering::SeqCst) + 1;
                                if idx <= drop_first_b2a {
                                    continue;
                                }
                                b2a_delivered += 1;
                                let copies = if dup_first_delivered_b2a && b2a_delivered == 1 {
                                    2
                                } else {
                                    1
                                };
                                for _ in 0..copies {
                                    let fh = AccessHeaderV11 {
                                        flags: AccessFlags {
                                            pp: hdr.flags.pp,
                                            discardable: hdr.flags.discardable,
                                            frame_end: false,
                                            is_ctrl_edge: false,
                                            dir_edge_to_client: true,
                                            rtx: false,
                                        },
                                        route_cid: cid_a,
                                        access_epoch: 0,
                                        leg_seq: seq_to_a,
                                        mac_64: [0; 8],
                                    };
                                    seq_to_a = seq_to_a.wrapping_add(1);
                                    let w = seal_udp_v11(&ka.udp_key_e2c, fh, body).unwrap();
                                    let _ = relay_a.send_to(&w, dst).await;
                                }
                            }
                        }
                    }
                }
            }
        });

        let mut link_a = UdpAccessLink::connect(&addr_a.to_string(), &keys_a, 10_000)
            .await
            .unwrap();
        let mut link_b = UdpAccessLink::connect(&addr_b.to_string(), &keys_b, 10_000)
            .await
            .unwrap();
        link_a
            .ping_with_retry(2, Duration::from_secs(1))
            .await
            .unwrap();
        link_b
            .ping_with_retry(2, Duration::from_secs(1))
            .await
            .unwrap();

        RelayFixture {
            link_a,
            link_b,
            stop_tx,
            relay_task,
            a2b_seen,
            b2a_seen,
        }
    }

    struct HandshakeFixture {
        prologue: PrologueInput,
        priv_a: [u8; 32],
        priv_b: [u8; 32],
        pub_b: [u8; 32],
        deleg_a: DelegationStatement,
        deleg_b: DelegationStatement,
        dev_a: [u8; 16],
        dev_b: [u8; 16],
        spki_a: Vec<u8>,
        spki_b: Vec<u8>,
        policy_a: VerifiedTenantPolicy,
        policy_b: VerifiedTenantPolicy,
        now_u: u64,
        exp_u: u64,
    }

    fn make_signed_policy(
        ca: &SoftwareDeviceKeyStore,
        dev_spki: &[u8],
        tenant_id: [u8; 16],
        dev_id: [u8; 16],
        now_u: u64,
        rules: TenantPolicyRules,
    ) -> VerifiedTenantPolicy {
        let ca_spki = ca.public_key_spki_der().unwrap();
        let mut cert = DeviceCert {
            version: 1,
            cert_id: dev_id,
            device_id: dev_id,
            tenant_id,
            p256_pub_der: dev_spki.to_vec(),
            key_epoch: 1,
            policy_hash: rules.canonical_hash(),
            cap_bits: 0x1_7FFF,
            iat_unix: now_u - 10,
            exp_unix: now_u + 3600,
            hardware_backed: false,
            sig_der: Vec::new(),
        };
        cert.sig_der = ca.sign_p256_low_s(&cert.tbs_bytes().unwrap()).unwrap();
        let mut blob = TenantPolicyBlob {
            tenant_id,
            version: 1,
            policy_hash: rules.canonical_hash(),
            iat_unix: now_u - 10,
            exp_unix: now_u + 3600,
            sig_der: Vec::new(),
        };
        blob.sig_der = ca.sign_p256_low_s(&blob.tbs_bytes()).unwrap();
        VerifiedTenantPolicy::from_verified_blob(&blob, &cert, &rules, &ca_spki, now_u).unwrap()
    }

    fn build_handshake_fixture() -> HandshakeFixture {
        let ca = SoftwareDeviceKeyStore::generate();
        let ks_a = SoftwareDeviceKeyStore::generate();
        let ks_b = SoftwareDeviceKeyStore::generate();
        let spki_a = ks_a.public_key_spki_der().unwrap();
        let spki_b = ks_b.public_key_spki_der().unwrap();
        let tenant_id = [0x71; 16];
        let dev_a = [0xA0; 16];
        let dev_b = [0xB0; 16];
        let now_u = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp_u = now_u + 3600;

        let mut rot_a = X25519StaticKeyRotator::new(dev_a, false, 0);
        let mut rot_b = X25519StaticKeyRotator::new(dev_b, false, 0);
        let gen_a = rot_a.ensure_current(&ks_a, now_u, exp_u).unwrap();
        let gen_b = rot_b.ensure_current(&ks_b, now_u, exp_u).unwrap();
        let priv_a = *gen_a.secret_bytes();
        let priv_b = *gen_b.secret_bytes();
        let pub_b = gen_b.public_key;
        let deleg_a = gen_a.delegation.clone();
        let deleg_b = gen_b.delegation.clone();

        let rules = TenantPolicyRules {
            allow_file_transfer: true,
            allow_clipboard: true,
            allow_file_clipboard: true,
            allow_tcp_tunnel: true,
            allow_terminal: true,
            allow_realtime_actuator: false,
            bw_cap_kbps: 20_000,
            exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
        };
        let policy_a = make_signed_policy(&ca, &spki_a, tenant_id, dev_a, now_u, rules.clone());
        let policy_b = make_signed_policy(&ca, &spki_b, tenant_id, dev_b, now_u, rules);

        let prologue = PrologueInput {
            ver_major_minor: VER_MAJOR_MINOR,
            handshake_pattern: PATTERN_IK,
            cipher_suite: CIPHER_AESGCM,
            transport_mode: TRANSPORT_MODE_RELAY_UDP,
            device_id_ctrl: dev_a,
            device_id_host: dev_b,
            ctrl_devcert_tbs_sha256: Sha256::digest(&spki_a).into(),
            host_devcert_tbs_sha256: Sha256::digest(&spki_b).into(),
            policy_hash: policy_a.policy_hash,
            edge_cert_tbs_sha256_or_zero: [0xEE; 32],
            negotiated_cap_bits: 0x1_7FFF,
            session_id: [0x99; 16],
        };

        HandshakeFixture {
            prologue,
            priv_a,
            priv_b,
            pub_b,
            deleg_a,
            deleg_b,
            dev_a,
            dev_b,
            spki_a,
            spki_b,
            policy_a,
            policy_b,
            now_u,
            exp_u,
        }
    }

    #[tokio::test]
    async fn noise_ik_handshake_recovers_when_first_msg1_is_dropped() {
        let relay = spawn_lossy_udp_relay_pair(1, 0, false).await;
        let fx = build_handshake_fixture();

        let hs_a = UdpE2eeSession::handshake_initiator(
            relay.link_a,
            &fx.prologue,
            &fx.priv_a,
            &fx.pub_b,
            &fx.deleg_b,
            &fx.dev_b,
            &fx.spki_b,
            fx.exp_u,
            fx.now_u,
            fx.policy_a,
            fx.dev_a,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        );
        let hs_b = UdpE2eeSession::handshake_responder(
            relay.link_b,
            &fx.prologue,
            &fx.priv_b,
            &fx.deleg_a,
            &fx.dev_a,
            &fx.spki_a,
            fx.exp_u,
            fx.now_u,
            fx.policy_b,
            fx.dev_b,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        );
        let ((mut sess_a, out_a), (mut sess_b, out_b)) = tokio::try_join!(hs_a, hs_b).unwrap();
        assert_eq!(out_a.hs_hash, out_b.hs_hash);
        assert!(relay.a2b_seen.load(Ordering::SeqCst) >= 2);

        sess_a
            .send_hid(&HidFrame {
                msg_type: 0x01,
                payload: Bytes::from_static(b"MSG1-DROP-RECOVERED"),
            })
            .await
            .unwrap();
        let ev_b = sess_b.recv_event(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            ev_b,
            TransportEvent::Hid(ref f) if f.payload.as_ref() == b"MSG1-DROP-RECOVERED"
        ));

        let _ = relay.stop_tx.send(()).await;
        let _ = relay.relay_task.await;
    }

    #[tokio::test]
    async fn noise_ik_handshake_recovers_when_first_msg2_is_dropped_while_responder_in_recv_event()
    {
        let relay = spawn_lossy_udp_relay_pair(0, 1, false).await;
        let fx = build_handshake_fixture();

        let prologue_b = fx.prologue.clone();
        let priv_b = fx.priv_b;
        let deleg_a = fx.deleg_a;
        let dev_a = fx.dev_a;
        let dev_b = fx.dev_b;
        let spki_a = fx.spki_a;
        let exp_u = fx.exp_u;
        let now_u = fx.now_u;
        let policy_b = fx.policy_b;

        let responder_task = tokio::spawn(async move {
            let (mut sess_b, out_b) = UdpE2eeSession::handshake_responder(
                relay.link_b,
                &prologue_b,
                &priv_b,
                &deleg_a,
                &dev_a,
                &spki_a,
                exp_u,
                now_u,
                policy_b,
                dev_b,
                L3_MTU_DEFAULT,
                Duration::from_secs(3),
            )
            .await?;
            let ev_b = sess_b.recv_event(Duration::from_secs(3)).await?;
            sess_b.send_control(0x05, b"MSG2-DROP-CTRL-OK").await?;
            Ok::<(E2eeHandshakeOutput, TransportEvent), ClientError>((out_b, ev_b))
        });

        let (mut sess_a, out_a) = UdpE2eeSession::handshake_initiator(
            relay.link_a,
            &fx.prologue,
            &fx.priv_a,
            &fx.pub_b,
            &fx.deleg_b,
            &fx.dev_b,
            &fx.spki_b,
            fx.exp_u,
            fx.now_u,
            fx.policy_a,
            fx.dev_a,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        )
        .await
        .unwrap();

        sess_a
            .send_hid(&HidFrame {
                msg_type: 0x01,
                payload: Bytes::from_static(b"MSG2-DROP-HID-OK"),
            })
            .await
            .unwrap();
        let ev_a = sess_a.recv_event(Duration::from_secs(2)).await.unwrap();
        let (out_b, ev_b) = responder_task.await.unwrap().unwrap();

        assert_eq!(out_a.hs_hash, out_b.hs_hash);
        assert!(relay.a2b_seen.load(Ordering::SeqCst) >= 3);
        assert!(relay.b2a_seen.load(Ordering::SeqCst) >= 3);
        assert!(matches!(
            ev_b,
            TransportEvent::Hid(ref f) if f.payload.as_ref() == b"MSG2-DROP-HID-OK"
        ));
        assert!(matches!(
            ev_a,
            TransportEvent::Control(ref f)
                if f.msg_type == 0x05 && f.payload.as_ref() == b"MSG2-DROP-CTRL-OK"
        ));

        let _ = relay.stop_tx.send(()).await;
        let _ = relay.relay_task.await;
    }

    #[tokio::test]
    async fn noise_ik_initiator_ignores_duplicate_msg2_in_recv_event() {
        let relay = spawn_lossy_udp_relay_pair(0, 0, true).await;
        let fx = build_handshake_fixture();

        let hs_a = UdpE2eeSession::handshake_initiator(
            relay.link_a,
            &fx.prologue,
            &fx.priv_a,
            &fx.pub_b,
            &fx.deleg_b,
            &fx.dev_b,
            &fx.spki_b,
            fx.exp_u,
            fx.now_u,
            fx.policy_a,
            fx.dev_a,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        );
        let hs_b = UdpE2eeSession::handshake_responder(
            relay.link_b,
            &fx.prologue,
            &fx.priv_b,
            &fx.deleg_a,
            &fx.dev_a,
            &fx.spki_a,
            fx.exp_u,
            fx.now_u,
            fx.policy_b,
            fx.dev_b,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        );
        let ((mut sess_a, out_a), (mut sess_b, out_b)) = tokio::try_join!(hs_a, hs_b).unwrap();
        assert_eq!(out_a.hs_hash, out_b.hs_hash);

        sess_b
            .send_control(0x06, b"DUP-MSG2-IGNORED-OK")
            .await
            .unwrap();
        let ev_a = sess_a.recv_event(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            ev_a,
            TransportEvent::Control(ref f)
                if f.msg_type == 0x06 && f.payload.as_ref() == b"DUP-MSG2-IGNORED-OK"
        ));

        let _ = relay.stop_tx.send(()).await;
        let _ = relay.relay_task.await;
    }

    #[test]
    fn handshake_rtx_exponential_backoff_schedule() {
        let i0 = HANDSHAKE_RTX_INITIAL_INTERVAL;
        assert_eq!(i0, Duration::from_millis(600));
        let i1 = next_handshake_rtx_interval(i0);
        assert_eq!(i1, Duration::from_millis(1_200));
        let i2 = next_handshake_rtx_interval(i1);
        assert_eq!(i2, Duration::from_millis(2_400));
        let i3 = next_handshake_rtx_interval(i2);
        assert_eq!(i3, Duration::from_millis(2_400));
    }

    #[tokio::test]
    async fn noise_ik_initiator_ignores_late_duplicate_msg2_after_valid_l3_frame() {
        let relay = spawn_lossy_udp_relay_pair(0, 0, false).await;
        let fx = build_handshake_fixture();

        let hs_a = UdpE2eeSession::handshake_initiator(
            relay.link_a,
            &fx.prologue,
            &fx.priv_a,
            &fx.pub_b,
            &fx.deleg_b,
            &fx.dev_b,
            &fx.spki_b,
            fx.exp_u,
            fx.now_u,
            fx.policy_a,
            fx.dev_a,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        );
        let hs_b = UdpE2eeSession::handshake_responder(
            relay.link_b,
            &fx.prologue,
            &fx.priv_b,
            &fx.deleg_a,
            &fx.dev_a,
            &fx.spki_a,
            fx.exp_u,
            fx.now_u,
            fx.policy_b,
            fx.dev_b,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        );
        let ((mut sess_a, out_a), (mut sess_b, out_b)) = tokio::try_join!(hs_a, hs_b).unwrap();
        assert_eq!(out_a.hs_hash, out_b.hs_hash);

        let cached_msg1 = match &sess_b.hs_replay {
            Some(HandshakeReplayCache::Responder { msg1, .. }) => msg1.clone(),
            _ => panic!("responder missing HandshakeReplayCache"),
        };

        // 1. Responder sends a valid L3 video frame immediately after msg2 #1, and initiator
        //    decrypts it before any late duplicate msg2 #2 arrives (trans-Pacific race).
        let meta = VideoFrameMeta {
            display_idx: 0,
            codec_id: 2,
            frame_id: 1,
            ref_frame_id: 1,
            ltr_slot: 0,
            is_idr: true,
            is_ref: true,
            max_age_ms: 200,
        };
        sess_b
            .send_video_frame(&meta, b"FIRST-VALID-L3-VIDEO-FRAME")
            .await
            .unwrap();
        let ev_a1 = sess_a.recv_event(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            ev_a1,
            TransportEvent::VideoFrame(ref f)
                if f.frame_id == 1 && f.data.as_ref() == b"FIRST-VALID-L3-VIDEO-FRAME"
        ));

        // 2. Initiator also sends a valid L3 HID frame and responder decrypts it — responder's
        //    replay cache must likewise remain active for the full 5s TTL.
        sess_a
            .send_hid(&HidFrame {
                msg_type: 0x01,
                payload: Bytes::from_static(b"VALID-L3-HID-BEFORE-LATE-MSG1"),
            })
            .await
            .unwrap();
        let ev_b1 = sess_b.recv_event(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            ev_b1,
            TransportEvent::Hid(ref f) if f.payload.as_ref() == b"VALID-L3-HID-BEFORE-LATE-MSG1"
        ));

        // 3. Late retransmitted msg1 #2 arrives at responder after valid L3 traffic, triggering
        //    duplicate msg2 #2 back to initiator (followed by another valid L3 frame).
        sess_a
            .data_plane_mut()
            .send_l3_packet(0, false, true, 0, &cached_msg1)
            .await
            .unwrap();
        sess_a
            .send_hid(&HidFrame {
                msg_type: 0x01,
                payload: Bytes::from_static(b"HID-AFTER-LATE-MSG1"),
            })
            .await
            .unwrap();
        let ev_b2 = sess_b.recv_event(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            ev_b2,
            TransportEvent::Hid(ref f) if f.payload.as_ref() == b"HID-AFTER-LATE-MSG1"
        ));

        sess_b
            .send_control(0x07, b"CTRL-AFTER-LATE-DUP-MSG2")
            .await
            .unwrap();

        // 4. Initiator receives late duplicate msg2 #2 (within 5s TTL) AFTER having already
        //    decrypted a valid L3 frame; it must silently ignore msg2 #2 without failing with
        //    'L3 reserved field must be zero' and deliver the subsequent valid L3 frame.
        let ev_a2 = sess_a.recv_event(Duration::from_secs(2)).await.unwrap();
        assert!(matches!(
            ev_a2,
            TransportEvent::Control(ref f)
                if f.msg_type == 0x07 && f.payload.as_ref() == b"CTRL-AFTER-LATE-DUP-MSG2"
        ));

        let _ = relay.stop_tx.send(()).await;
        let _ = relay.relay_task.await;
    }

    #[tokio::test]
    async fn udp_probe_two_pings_times_out_cleanly_when_udp_blackholed() {
        // Bind a UDP socket that never replies (simulating UDP firewall drop)
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = blackhole.local_addr().unwrap();
        let keys = AccessKeys::derive([0x11; 8], [0x22; 32], 0).unwrap();
        let mut link = UdpAccessLink::connect(&addr.to_string(), &keys, 10_000)
            .await
            .unwrap();
        let t0 = Instant::now();
        let res = link.probe_udp_two_pings(Duration::from_millis(800)).await;
        let elapsed = t0.elapsed();
        assert!(matches!(res, Err(ClientError::Timeout(_))));
        assert!(elapsed >= Duration::from_millis(750));
        assert!(elapsed < Duration::from_millis(1500));
        assert_eq!(link.stats.tx_packets, 2);
        assert_eq!(link.p3_dropped(), 0);
    }

    #[tokio::test]
    async fn access_data_plane_dual_tls443_e2ee_realtime_and_bulk_p3_zero_drop() {
        use rcgen::generate_simple_self_signed;
        use rustls::ServerConfig;
        use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::sync::Arc;
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::TcpListener,
        };
        use tokio_rustls::TlsAcceptor;
        use v2_transport::{
            compute_stream_mac64, derive_stream_role_key, seal_stream_v11, verify_mac64_ct,
            StreamFrameParser,
        };

        let cert = generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
        let cert_der = cert.cert.der().to_vec();
        let key_der = cert.key_pair.serialize_der();

        let tmp_ca = std::env::temp_dir().join(format!(
            "zd-tls443-dp-ca-{}-{}.der",
            std::process::id(),
            now_us()
        ));
        std::fs::write(&tmp_ca, &cert_der).unwrap();

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let srv_cfg = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert_der)],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(srv_cfg));

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tls_addr = listener.local_addr().unwrap();

        let cid_a = [0xA1; 8];
        let cid_b = [0xB2; 8];
        let hs_a = [0x33; 32];
        let hs_b = [0x44; 32];
        let keys_a = AccessKeys::derive(cid_a, hs_a, 0).unwrap();
        let keys_b = AccessKeys::derive(cid_b, hs_b, 0).unwrap();

        // Channel pair per role (Realtime=1, Bulk=2) forwarding L3 payloads A <-> B
        let (a_rt_tx, a_rt_rx) = mpsc::channel::<(AccessFlags, u32, Vec<u8>)>(64);
        let (b_rt_tx, b_rt_rx) = mpsc::channel::<(AccessFlags, u32, Vec<u8>)>(64);
        let (a_bk_tx, a_bk_rx) = mpsc::channel::<(AccessFlags, u32, Vec<u8>)>(64);
        let (b_bk_tx, b_bk_rx) = mpsc::channel::<(AccessFlags, u32, Vec<u8>)>(64);

        let srv_task = tokio::spawn(async move {
            let mut a_rt_rx_opt = Some(a_rt_rx);
            let mut b_rt_rx_opt = Some(b_rt_rx);
            let mut a_bk_rx_opt = Some(a_bk_rx);
            let mut b_bk_rx_opt = Some(b_bk_rx);
            let mut handles = Vec::new();
            for _ in 0..4 {
                let (tcp, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(tcp).await.unwrap();
                let mut preface = [0u8; 9];
                tls.read_exact(&mut preface).await.unwrap();
                let role = preface[0];
                let mut cid = [0u8; 8];
                cid.copy_from_slice(&preface[1..9]);
                let (hs, fwd_tx, rx_opt) = if cid == cid_a {
                    if role == 1 {
                        (hs_a, b_rt_tx.clone(), a_rt_rx_opt.take().unwrap())
                    } else {
                        (hs_a, b_bk_tx.clone(), a_bk_rx_opt.take().unwrap())
                    }
                } else if role == 1 {
                    (hs_b, a_rt_tx.clone(), b_rt_rx_opt.take().unwrap())
                } else {
                    (hs_b, a_bk_tx.clone(), b_bk_rx_opt.take().unwrap())
                };
                let c2e_key =
                    derive_stream_role_key(&cid, &hs, DIR_CLIENT_TO_EDGE, 0, role).unwrap();
                let e2c_key =
                    derive_stream_role_key(&cid, &hs, DIR_EDGE_TO_CLIENT, 0, role).unwrap();
                handles.push(tokio::spawn(async move {
                    let mut parser = StreamFrameParser::new();
                    let mut rx_chan = rx_opt;
                    let mut buf = [0u8; 4096];
                    let mut tx_seq = 1u32;
                    loop {
                        while let Ok(Some(frame)) = parser.next_frame() {
                            let hdr_zero = frame.header.encode_mac_zero();
                            let mac = compute_stream_mac64(
                                &c2e_key,
                                &hdr_zero,
                                frame.frame_id,
                                &frame.payload,
                            )
                            .unwrap();
                            verify_mac64_ct(&mac, &frame.header.mac_64).unwrap();
                            if frame.header.flags.is_ctrl_edge {
                                if let Ok(EdgeCtrlFrame::Ping { ts_us }) =
                                    EdgeCtrlFrame::decode(&frame.payload)
                                {
                                    let pong = AccessHeaderV11 {
                                        flags: AccessFlags {
                                            pp: 0,
                                            discardable: false,
                                            frame_end: true,
                                            is_ctrl_edge: true,
                                            dir_edge_to_client: true,
                                            rtx: false,
                                        },
                                        route_cid: cid,
                                        access_epoch: 0,
                                        leg_seq: 0,
                                        mac_64: [0; 8],
                                    };
                                    let wire = seal_stream_v11(
                                        &e2c_key,
                                        pong,
                                        0,
                                        &EdgeCtrlFrame::Pong { ts_us }.encode(),
                                    )
                                    .unwrap();
                                    let _ = tls.write_all(&wire).await;
                                    let _ = tls.flush().await;
                                }
                            } else {
                                let _ = fwd_tx
                                    .send((frame.header.flags, frame.frame_id, frame.payload))
                                    .await;
                            }
                        }
                        tokio::select! {
                            r = tls.read(&mut buf) => match r {
                                Ok(0) | Err(_) => break,
                                Ok(n) => parser.feed(&buf[..n]),
                            },
                            Some((flags, fid, payload)) = rx_chan.recv() => {
                                let out_hdr = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: flags.pp,
                                        discardable: flags.discardable,
                                        frame_end: flags.frame_end,
                                        is_ctrl_edge: false,
                                        dir_edge_to_client: true,
                                        rtx: false,
                                    },
                                    route_cid: cid,
                                    access_epoch: 0,
                                    leg_seq: tx_seq,
                                    mac_64: [0; 8],
                                };
                                tx_seq = tx_seq.wrapping_add(1);
                                let wire = seal_stream_v11(&e2c_key, out_hdr, fid, &payload).unwrap();
                                if tls.write_all(&wire).await.is_err() {
                                    break;
                                }
                                let _ = tls.flush().await;
                            }
                        }
                    }
                }));
            }
            handles
        });

        let tls_addr_str = tls_addr.to_string();
        let c_a = DualTls443Client::connect(&tls_addr_str, &keys_a, Some(&tmp_ca), 20_000);
        let c_b = DualTls443Client::connect(&tls_addr_str, &keys_b, Some(&tmp_ca), 20_000);
        let (dual_a, dual_b) = tokio::try_join!(c_a, c_b).unwrap();
        let handles = srv_task.await.unwrap();

        let fx = build_handshake_fixture();
        let hs_a_fut = V2E2eeSession::handshake_initiator(
            dual_a,
            &fx.prologue,
            &fx.priv_a,
            &fx.pub_b,
            &fx.deleg_b,
            &fx.dev_b,
            &fx.spki_b,
            fx.exp_u,
            fx.now_u,
            fx.policy_a,
            fx.dev_a,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        );
        let hs_b_fut = V2E2eeSession::handshake_responder(
            dual_b,
            &fx.prologue,
            &fx.priv_b,
            &fx.deleg_a,
            &fx.dev_a,
            &fx.spki_a,
            fx.exp_u,
            fx.now_u,
            fx.policy_b,
            fx.dev_b,
            L3_MTU_DEFAULT,
            Duration::from_secs(3),
        );
        let ((mut sess_a, out_a), (mut sess_b, out_b)) =
            tokio::try_join!(hs_a_fut, hs_b_fut).unwrap();
        assert_eq!(out_a.hs_hash, out_b.hs_hash);
        assert_eq!(sess_a.active_transport_mode(), ActiveTransportMode::DualTls443);
        assert_eq!(sess_b.active_transport_mode(), ActiveTransportMode::DualTls443);

        // Send Realtime (HID p0) + Bulk (Clipboard p3 + FileTransfer p3) simultaneously
        sess_a
            .send_hid(&HidFrame {
                msg_type: 0x01,
                payload: Bytes::from_static(b"TLS443-RT-HID"),
            })
            .await
            .unwrap();
        sess_a
            .send_l4_raw(CHAN_CLIPBOARD, 0x01, 0, false, b"TLS443-BULK-CLIP")
            .await
            .unwrap();
        sess_a
            .send_l4_raw(CHAN_FILE_TRANSFER, 0x01, 0, false, b"TLS443-BULK-FILE")
            .await
            .unwrap();

        let mut got_hid = false;
        let mut got_clip = false;
        let mut got_file = false;
        for _ in 0..3 {
            match sess_b.recv_v124_event(Duration::from_secs(2)).await.unwrap() {
                V2RecvEvent::Transport(TransportEvent::Hid(f)) => {
                    assert_eq!(f.payload.as_ref(), b"TLS443-RT-HID");
                    got_hid = true;
                }
                V2RecvEvent::ClipboardRaw(f) => {
                    assert_eq!(f.body.as_ref(), b"TLS443-BULK-CLIP");
                    got_clip = true;
                }
                V2RecvEvent::FileTransferRaw(f) => {
                    assert_eq!(f.body.as_ref(), b"TLS443-BULK-FILE");
                    got_file = true;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert!(got_hid && got_clip && got_file);
        assert_eq!(sess_a.p3_dropped(), 0);
        assert_eq!(sess_b.p3_dropped(), 0);

        // Verify Bulk HoL prune NEVER drops p3 frames (p3_dropped == 0 invariant)
        {
            let bulk = &mut sess_a.data_plane_mut().as_tls443_mut().unwrap().bulk;
            let l3_stub = vec![0xABu8; 64];
            bulk.enqueue_l3_slice(3, true, true, 99, &l3_stub, 1000)
                .unwrap();
            let (dropped, hint) = bulk.prune_hol_queue(1500);
            assert!(dropped.is_empty());
            assert!(hint.is_none());
            assert_eq!(bulk.p3_dropped(), 0);
            let _ = bulk.drain_send_queue();
        }

        // Verify keepalive ping succeeds over Dual TLS-443
        let rtt_us = sess_a.ping_keepalive(Duration::from_secs(2)).await.unwrap();
        assert!(rtt_us < 2_000_000);

        for h in handles {
            h.abort();
        }
        let _ = std::fs::remove_file(&tmp_ca);
    }

    #[tokio::test]
    async fn udp_ping_buffers_interleaved_l3_data_without_loss() {
        let edge_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let edge_addr = edge_sock.local_addr().unwrap();
        let cid = [0x61; 8];
        let hs = [0x62; 32];
        let keys = AccessKeys::derive(cid, hs, 0).unwrap();

        let mut link = UdpAccessLink::connect(&edge_addr.to_string(), &keys, 10_000)
            .await
            .unwrap();

        let edge_task = tokio::spawn(async move {
            let mut rx_ep =
                AccessEpochState::new(cid, hs, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                    .unwrap();
            let tx_ep =
                AccessEpochState::new(cid, hs, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 0, 10)
                    .unwrap();
            let mut buf = [0u8; 2048];
            let (n, peer) = edge_sock.recv_from(&mut buf).await.unwrap();
            let (hdr, body) = rx_ep.verify_udp_packet(&buf[..n], now_ms()).unwrap();
            assert!(hdr.flags.is_ctrl_edge);
            let EdgeCtrlFrame::Ping { ts_us } = EdgeCtrlFrame::decode(body).unwrap() else {
                panic!("expected Ping");
            };

            // Send an L3Data packet BEFORE Pong so ping_with_retry receives it while awaiting Pong!
            let data_hdr = AccessHeaderV11 {
                flags: AccessFlags {
                    pp: 0,
                    discardable: false,
                    frame_end: true,
                    is_ctrl_edge: false,
                    dir_edge_to_client: true,
                    rtx: false,
                },
                route_cid: cid,
                access_epoch: 0,
                leg_seq: 1,
                mac_64: [0; 8],
            };
            let data_wire = seal_udp_v11(tx_ep.cur_key(), data_hdr, b"PRESERVED-L3-DATA").unwrap();
            edge_sock.send_to(&data_wire, peer).await.unwrap();

            // Then send the matching Pong
            let pong_hdr = AccessHeaderV11 {
                flags: AccessFlags {
                    pp: 0,
                    discardable: false,
                    frame_end: false,
                    is_ctrl_edge: true,
                    dir_edge_to_client: true,
                    rtx: false,
                },
                route_cid: cid,
                access_epoch: 0,
                leg_seq: 0,
                mac_64: [0; 8],
            };
            let pong_wire = seal_udp_v11(
                tx_ep.cur_key(),
                pong_hdr,
                &EdgeCtrlFrame::Pong { ts_us }.encode(),
            )
            .unwrap();
            edge_sock.send_to(&pong_wire, peer).await.unwrap();
        });

        let rtt = link
            .ping_with_retry(1, Duration::from_secs(2))
            .await
            .unwrap();
        assert!(rtt < 2_000_000);
        // The interleaved L3Data packet MUST be delivered by the next recv_packet call!
        match link.recv_packet(Duration::from_millis(200)).await.unwrap() {
            UdpRecvEvent::L3Data { payload, .. } => assert_eq!(payload, b"PRESERVED-L3-DATA"),
            other => panic!("expected buffered L3Data, got {other:?}"),
        }
        edge_task.await.unwrap();
    }

    #[tokio::test]
    async fn recv_decrypted_l4_drops_stray_bad_aead_and_send_l4_raw_enforces_policy() {
        let fixture = spawn_lossy_udp_relay_pair(0, 0, false).await;
        let denied_policy = VerifiedTenantPolicy {
            tenant_id: [0x11; 16],
            policy_version: 1,
            policy_hash: [0x22; 32],
            allow_file_transfer: false,
            allow_clipboard: false,
            allow_file_clipboard: false,
            allow_tcp_tunnel: false,
            allow_terminal: false,
            allow_realtime_actuator: false,
            bw_cap_kbps: 10_000,
            exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
        };
        let mut sess_a = UdpE2eeSession::from_keys(
            fixture.link_a,
            [0xA1; 32],
            [0xB2; 32],
            denied_policy.clone(),
            [0x01; 16],
        );
        let mut sess_b = UdpE2eeSession::from_keys(
            fixture.link_b,
            [0xB2; 32],
            [0xA1; 32],
            denied_policy,
            [0x02; 16],
        );

        // 1. send_l4_raw MUST reject CHAN_INPUT_HID / CHAN_REALTIME_ACTUATOR and denied CLIP_SYNC / FILE_OFFER
        assert!(sess_a
            .send_l4_raw(CHAN_INPUT_HID, 0x01, 0, false, b"hid")
            .await
            .is_err());
        assert!(sess_a
            .send_l4_raw(CHAN_REALTIME_ACTUATOR, 0x01, 0, false, b"act")
            .await
            .is_err());
        assert!(sess_a
            .send_l4_raw(CHAN_CLIPBOARD, 0x01, 0, false, b"denied-sync")
            .await
            .is_err());
        assert!(sess_a
            .send_l4_raw(CHAN_FILE_TRANSFER, 0x01, 0, false, b"denied-offer")
            .await
            .is_err());
        // Rejection replies CLIP_ACK(0x02) & FILE_ABORT(0x06) remain allowed even when channel is denied
        assert!(sess_a
            .send_l4_raw(CHAN_CLIPBOARD, 0x02, 0, false, &[0u8; 9])
            .await
            .is_ok());

        // 2. Inject 2 stray/corrupted L3 packets directly on link_a, followed by a valid HID frame.
        sess_a
            .data_plane_mut()
            .send_l3_packet(0, false, true, 0, &[0xFFu8; 48])
            .await
            .unwrap();
        sess_a
            .data_plane_mut()
            .send_l3_packet(0, false, true, 0, &[0xEEu8; 48])
            .await
            .unwrap();
        sess_a
            .send_hid(&HidFrame {
                msg_type: 0x01,
                payload: Bytes::from_static(b"VALID-AFTER-STRAY"),
            })
            .await
            .unwrap();

        // Drain the CLIP_ACK first, then verify sess_b drops the 2 corrupt L3 packets and delivers the valid HID!
        let mut got_hid = false;
        for _ in 0..3 {
            match sess_b.recv_v124_event(Duration::from_secs(2)).await.unwrap() {
                V2RecvEvent::ClipboardRaw(_) => {}
                V2RecvEvent::Transport(TransportEvent::Hid(f)) => {
                    assert_eq!(f.payload.as_ref(), b"VALID-AFTER-STRAY");
                    got_hid = true;
                    break;
                }
                other => panic!("unexpected event: {other:?}"),
            }
        }
        assert!(got_hid);
        assert_eq!(sess_b.invalid_l3_frames_dropped(), 2);

        let _ = fixture.stop_tx.send(()).await;
        fixture.relay_task.abort();
    }

    #[tokio::test]
    async fn p3_arq_sack_hole_rtx_uses_fresh_l3_unified_seq_and_same_stream_seq() {
        let relay_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = relay_a.local_addr().unwrap();
        let addr_b = relay_b.local_addr().unwrap();

        let cid_a = [0x51; 8];
        let cid_b = [0x52; 8];
        let hs_a = [0x53; 32];
        let hs_b = [0x54; 32];
        let keys_a = AccessKeys::derive(cid_a, hs_a, 0).unwrap();
        let keys_b = AccessKeys::derive(cid_b, hs_b, 0).unwrap();

        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let seen_p3_l3_seqs = Arc::new(tokio::sync::Mutex::new(Vec::<u64>::new()));
        let seen_clone = Arc::clone(&seen_p3_l3_seqs);
        let ka = keys_a.clone();
        let kb = keys_b.clone();
        let relay_task = tokio::spawn(async move {
            let mut rx_a =
                AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                    .unwrap();
            let mut rx_b =
                AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                    .unwrap();
            let mut peer_a: Option<SocketAddr> = None;
            let mut peer_b: Option<SocketAddr> = None;
            let mut seq_to_a = 1u32;
            let mut seq_to_b = 1u32;
            let mut a2b_p3_idx = 0usize;
            let mut ba = [0u8; 2048];
            let mut bb = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = stop_rx.recv() => break,
                    Ok((n, src)) = relay_a.recv_from(&mut ba) => {
                        peer_a = Some(src);
                        if let Ok((hdr, body)) = rx_a.verify_udp_packet(&ba[..n], 100) {
                            if hdr.flags.is_ctrl_edge {
                                if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                    let ph = AccessHeaderV11 {
                                        flags: AccessFlags {
                                            pp: 0, discardable: false, frame_end: false,
                                            is_ctrl_edge: true, dir_edge_to_client: true, rtx: false,
                                        },
                                        route_cid: cid_a, access_epoch: 0, leg_seq: 0, mac_64: [0; 8],
                                    };
                                    let w = seal_udp_v11(&ka.udp_key_e2c, ph, &EdgeCtrlFrame::Pong { ts_us }.encode()).unwrap();
                                    let _ = relay_a.send_to(&w, src).await;
                                }
                            } else if let Some(dst) = peer_b {
                                if hdr.flags.pp == 3 {
                                    // L3 header unified_seq is big-endian u64 in bytes 1..9 of the plaintext L3 header.
                                    if body.len() >= 9 {
                                        let u_seq = u64::from_be_bytes([
                                            body[1], body[2], body[3], body[4],
                                            body[5], body[6], body[7], body[8],
                                        ]);
                                        seen_clone.lock().await.push(u_seq);
                                    }
                                    a2b_p3_idx += 1;
                                    // Drop ONLY the 2nd p3 packet (stream_seq=1) once!
                                    if a2b_p3_idx == 2 {
                                        continue;
                                    }
                                }
                                let fh = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: hdr.flags.pp, discardable: hdr.flags.discardable, frame_end: false,
                                        is_ctrl_edge: false, dir_edge_to_client: true, rtx: false,
                                    },
                                    route_cid: cid_b, access_epoch: 0, leg_seq: seq_to_b, mac_64: [0; 8],
                                };
                                seq_to_b = seq_to_b.wrapping_add(1);
                                let w = seal_udp_v11(&kb.udp_key_e2c, fh, body).unwrap();
                                let _ = relay_b.send_to(&w, dst).await;
                            }
                        }
                    }
                    Ok((n, src)) = relay_b.recv_from(&mut bb) => {
                        peer_b = Some(src);
                        if let Ok((hdr, body)) = rx_b.verify_udp_packet(&bb[..n], 100) {
                            if hdr.flags.is_ctrl_edge {
                                if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                    let ph = AccessHeaderV11 {
                                        flags: AccessFlags {
                                            pp: 0, discardable: false, frame_end: false,
                                            is_ctrl_edge: true, dir_edge_to_client: true, rtx: false,
                                        },
                                        route_cid: cid_b, access_epoch: 0, leg_seq: 0, mac_64: [0; 8],
                                    };
                                    let w = seal_udp_v11(&kb.udp_key_e2c, ph, &EdgeCtrlFrame::Pong { ts_us }.encode()).unwrap();
                                    let _ = relay_b.send_to(&w, src).await;
                                }
                            } else if let Some(dst) = peer_a {
                                let fh = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: hdr.flags.pp, discardable: hdr.flags.discardable, frame_end: false,
                                        is_ctrl_edge: false, dir_edge_to_client: true, rtx: false,
                                    },
                                    route_cid: cid_a, access_epoch: 0, leg_seq: seq_to_a, mac_64: [0; 8],
                                };
                                seq_to_a = seq_to_a.wrapping_add(1);
                                let w = seal_udp_v11(&ka.udp_key_e2c, fh, body).unwrap();
                                let _ = relay_a.send_to(&w, dst).await;
                            }
                        }
                    }
                }
            }
        });

        let mut link_a = UdpAccessLink::connect(&addr_a.to_string(), &keys_a, 10_000)
            .await
            .unwrap();
        let mut link_b = UdpAccessLink::connect(&addr_b.to_string(), &keys_b, 10_000)
            .await
            .unwrap();
        link_a.auto_leg_nack = false;
        link_b.auto_leg_nack = false;
        link_a.ping_with_retry(1, Duration::from_secs(1)).await.unwrap();
        link_b.ping_with_retry(1, Duration::from_secs(1)).await.unwrap();

        let allow_pol = VerifiedTenantPolicy {
            tenant_id: [0x11; 16],
            policy_version: 1,
            policy_hash: [0x22; 32],
            allow_file_transfer: true,
            allow_clipboard: true,
            allow_file_clipboard: true,
            allow_tcp_tunnel: false,
            allow_terminal: false,
            allow_realtime_actuator: false,
            bw_cap_kbps: 20_000,
            exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
        };
        let mut sess_a = UdpE2eeSession::from_keys(link_a, [0xA1; 32], [0xB2; 32], allow_pol.clone(), [0x01; 16]);
        let mut sess_b = UdpE2eeSession::from_keys(link_b, [0xB2; 32], [0xA1; 32], allow_pol, [0x02; 16]);

        // Send 4 p3 frames: seq 0, 1 (dropped!), 2, 3
        for idx in 0u8..4 {
            sess_a
                .send_l4_raw(CHAN_FILE_TRANSFER, 0x03, 0, false, &[idx, 0xCC, 0xDD])
                .await
                .unwrap();
        }

        // Drive both endpoints concurrently so sess_b emits ACK_SACK(cum=0, bitmap=0b110) and
        // sess_a fast-retransmits seq 1 with a FRESH L3 unified_seq!
        let recv_task = tokio::spawn(async move {
            let mut got = Vec::new();
            while got.len() < 4 {
                match sess_b.recv_v124_event(Duration::from_secs(2)).await.unwrap() {
                    V2RecvEvent::FileTransferRaw(raw) => got.push((raw.header.stream_seq, raw.body.to_vec())),
                    other => panic!("unexpected event on sess_b: {other:?}"),
                }
            }
            // Wait briefly so final ACK reaches sess_a
            let _ = sess_b.recv_v124_event(Duration::from_millis(40)).await;
            (sess_b, got)
        });

        let ack_deadline = Instant::now() + Duration::from_secs(2);
        while sess_a.p3_arq_inflight_pkts(CHAN_FILE_TRANSFER) > 0 && Instant::now() < ack_deadline {
            let _ = sess_a.recv_v124_event(Duration::from_millis(20)).await;
        }
        let (_sess_b, got) = recv_task.await.unwrap();

        assert_eq!(
            got,
            vec![
                (0, vec![0, 0xCC, 0xDD]),
                (1, vec![1, 0xCC, 0xDD]),
                (2, vec![2, 0xCC, 0xDD]),
                (3, vec![3, 0xCC, 0xDD]),
            ]
        );
        assert!(sess_a.p3_arq_rtx_sent(CHAN_FILE_TRANSFER) >= 1);
        assert_eq!(sess_a.p3_arq_inflight_pkts(CHAN_FILE_TRANSFER), 0);

        let l3_seqs = seen_p3_l3_seqs.lock().await;
        assert!(l3_seqs.len() >= 5, "expected original 4 + >=1 rtx, got {l3_seqs:?}");
        // Every transmitted L3 packet (including RTX of stream_seq=1) MUST have a strictly distinct L3 unified_seq!
        let unique: BTreeSet<u64> = l3_seqs.iter().copied().collect();
        assert_eq!(unique.len(), l3_seqs.len());

        let _ = stop_tx.send(()).await;
        relay_task.abort();
    }

    #[tokio::test]
    async fn p3_negative_policy_probe_leaves_zero_arq_state_and_stray_u32_max_dropped() {
        // 1. Dropped probe creates zero ARQ inflight / timers
        let fx_drop = spawn_lossy_udp_relay_pair(1, 0, false).await;
        let allow_pol = VerifiedTenantPolicy {
            tenant_id: [0x11; 16],
            policy_version: 1,
            policy_hash: [0x22; 32],
            allow_file_transfer: true,
            allow_clipboard: true,
            allow_file_clipboard: true,
            allow_tcp_tunnel: false,
            allow_terminal: false,
            allow_realtime_actuator: false,
            bw_cap_kbps: 20_000,
            exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
        };
        let mut sess_a =
            UdpE2eeSession::from_keys(fx_drop.link_a, [0xA1; 32], [0xB2; 32], allow_pol.clone(), [0x01; 16]);
        let mut sess_b =
            UdpE2eeSession::from_keys(fx_drop.link_b, [0xB2; 32], [0xA1; 32], allow_pol.clone(), [0x02; 16]);

        sess_a
            .send_negative_policy_probe(CHAN_FILE_TRANSFER, 0x01, b"dropped-probe")
            .await
            .unwrap();
        assert_eq!(sess_a.p3_arq_inflight_pkts(CHAN_FILE_TRANSFER), 0);
        assert!(sess_a.next_arq_deadline().is_none());

        // Subsequent real frame MUST start cleanly at stream_seq=0 and deliver without holes!
        sess_a
            .send_l4_raw(CHAN_FILE_TRANSFER, 0x01, 0, false, b"real-seq-0")
            .await
            .unwrap();
        match sess_b.recv_v124_event(Duration::from_secs(1)).await.unwrap() {
            V2RecvEvent::FileTransferRaw(raw) => {
                assert_eq!(raw.header.stream_seq, 0);
                assert_eq!(raw.body.as_ref(), b"real-seq-0");
            }
            other => panic!("expected real-seq-0, got {other:?}"),
        }
        let _ = fx_drop.stop_tx.send(()).await;
        fx_drop.relay_task.abort();

        // 2. Undropped stray u32::MAX probe arriving at receiver is silently dropped without polluting ARQ
        let fx_pass = spawn_lossy_udp_relay_pair(0, 0, false).await;
        let mut sess_a2 =
            UdpE2eeSession::from_keys(fx_pass.link_a, [0xA1; 32], [0xB2; 32], allow_pol.clone(), [0x01; 16]);
        let mut sess_b2 =
            UdpE2eeSession::from_keys(fx_pass.link_b, [0xB2; 32], [0xA1; 32], allow_pol, [0x02; 16]);

        sess_a2
            .send_negative_policy_probe(CHAN_CLIPBOARD, 0x01, b"stray-probe")
            .await
            .unwrap();
        sess_a2
            .send_l4_raw(CHAN_CLIPBOARD, 0x01, 0, false, b"valid-clip-0")
            .await
            .unwrap();
        match sess_b2.recv_v124_event(Duration::from_secs(1)).await.unwrap() {
            V2RecvEvent::ClipboardRaw(raw) => {
                assert_eq!(raw.header.stream_seq, 0);
                assert_eq!(raw.body.as_ref(), b"valid-clip-0");
            }
            other => panic!("expected valid-clip-0, got {other:?}"),
        }
        let _ = fx_pass.stop_tx.send(()).await;
        fx_pass.relay_task.abort();
    }

    #[tokio::test]
    async fn handshake_initiator_tolerates_early_media_and_corrupt_pp0_before_delayed_msg2() {
        let relay_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = relay_a.local_addr().unwrap();
        let addr_b = relay_b.local_addr().unwrap();

        let cid_a = [0x71; 8];
        let cid_b = [0x72; 8];
        let hs_a = [0x73; 32];
        let hs_b = [0x74; 32];
        let keys_a = AccessKeys::derive(cid_a, hs_a, 0).unwrap();
        let keys_b = AccessKeys::derive(cid_b, hs_b, 0).unwrap();

        let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
        let ka = keys_a.clone();
        let kb = keys_b.clone();
        let relay_task = tokio::spawn(async move {
            let mut rx_a =
                AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                    .unwrap();
            let mut rx_b =
                AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                    .unwrap();
            let mut peer_a: Option<SocketAddr> = None;
            let mut peer_b: Option<SocketAddr> = None;
            let mut seq_to_a = 1u32;
            let mut seq_to_b = 1u32;
            let mut b2a_pp0_seen = 0usize;
            let mut ba = [0u8; 2048];
            let mut bb = [0u8; 2048];
            loop {
                tokio::select! {
                    _ = stop_rx.recv() => break,
                    Ok((n, src)) = relay_a.recv_from(&mut ba) => {
                        peer_a = Some(src);
                        if let Ok((hdr, body)) = rx_a.verify_udp_packet(&ba[..n], 100) {
                            if hdr.flags.is_ctrl_edge {
                                if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                    let ph = AccessHeaderV11 {
                                        flags: AccessFlags {
                                            pp: 0, discardable: false, frame_end: false,
                                            is_ctrl_edge: true, dir_edge_to_client: true, rtx: false,
                                        },
                                        route_cid: cid_a, access_epoch: 0, leg_seq: 0, mac_64: [0; 8],
                                    };
                                    let w = seal_udp_v11(&ka.udp_key_e2c, ph, &EdgeCtrlFrame::Pong { ts_us }.encode()).unwrap();
                                    let _ = relay_a.send_to(&w, src).await;
                                }
                            } else if let Some(dst) = peer_b {
                                let fh = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: hdr.flags.pp, discardable: hdr.flags.discardable, frame_end: false,
                                        is_ctrl_edge: false, dir_edge_to_client: true, rtx: false,
                                    },
                                    route_cid: cid_b, access_epoch: 0, leg_seq: seq_to_b, mac_64: [0; 8],
                                };
                                seq_to_b = seq_to_b.wrapping_add(1);
                                let w = seal_udp_v11(&kb.udp_key_e2c, fh, body).unwrap();
                                let _ = relay_b.send_to(&w, dst).await;
                            }
                        }
                    }
                    Ok((n, src)) = relay_b.recv_from(&mut bb) => {
                        peer_b = Some(src);
                        if let Ok((hdr, body)) = rx_b.verify_udp_packet(&bb[..n], 100) {
                            if hdr.flags.is_ctrl_edge {
                                if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                    let ph = AccessHeaderV11 {
                                        flags: AccessFlags {
                                            pp: 0, discardable: false, frame_end: false,
                                            is_ctrl_edge: true, dir_edge_to_client: true, rtx: false,
                                        },
                                        route_cid: cid_b, access_epoch: 0, leg_seq: 0, mac_64: [0; 8],
                                    };
                                    let w = seal_udp_v11(&kb.udp_key_e2c, ph, &EdgeCtrlFrame::Pong { ts_us }.encode()).unwrap();
                                    let _ = relay_b.send_to(&w, src).await;
                                }
                            } else if let Some(dst) = peer_a {
                                if hdr.flags.pp == 0 {
                                    b2a_pp0_seen += 1;
                                    // Drop the FIRST msg2 and inject early pp=1 Audio, pp=2 Video, AND 2 corrupt pp=0 packets!
                                    if b2a_pp0_seen == 1 {
                                        for (pp, payload) in [
                                            (1u8, b"early-audio-before-msg2".as_slice()),
                                            (2u8, b"early-video-before-msg2".as_slice()),
                                            (0u8, b"corrupt-pp0-packet-1".as_slice()),
                                            (0u8, b"corrupt-pp0-packet-2".as_slice()),
                                        ] {
                                            let inj = AccessHeaderV11 {
                                                flags: AccessFlags {
                                                    pp, discardable: false, frame_end: false,
                                                    is_ctrl_edge: false, dir_edge_to_client: true, rtx: false,
                                                },
                                                route_cid: cid_a, access_epoch: 0, leg_seq: seq_to_a, mac_64: [0; 8],
                                            };
                                            seq_to_a = seq_to_a.wrapping_add(1);
                                            let w = seal_udp_v11(&ka.udp_key_e2c, inj, payload).unwrap();
                                            let _ = relay_a.send_to(&w, dst).await;
                                        }
                                        continue;
                                    }
                                }
                                let fh = AccessHeaderV11 {
                                    flags: AccessFlags {
                                        pp: hdr.flags.pp, discardable: hdr.flags.discardable, frame_end: false,
                                        is_ctrl_edge: false, dir_edge_to_client: true, rtx: false,
                                    },
                                    route_cid: cid_a, access_epoch: 0, leg_seq: seq_to_a, mac_64: [0; 8],
                                };
                                seq_to_a = seq_to_a.wrapping_add(1);
                                let w = seal_udp_v11(&ka.udp_key_e2c, fh, body).unwrap();
                                let _ = relay_a.send_to(&w, dst).await;
                            }
                        }
                    }
                }
            }
        });

        let mut link_a = UdpAccessLink::connect(&addr_a.to_string(), &keys_a, 10_000)
            .await
            .unwrap();
        let mut link_b = UdpAccessLink::connect(&addr_b.to_string(), &keys_b, 10_000)
            .await
            .unwrap();
        link_a.auto_leg_nack = false;
        link_b.auto_leg_nack = false;
        link_a.ping_with_retry(1, Duration::from_secs(1)).await.unwrap();
        link_b.ping_with_retry(1, Duration::from_secs(1)).await.unwrap();

        let fx = build_handshake_fixture();
        let prologue_b = fx.prologue.clone();
        let priv_b = fx.priv_b;
        let deleg_a = fx.deleg_a.clone();
        let dev_a = fx.dev_a;
        let spki_a = fx.spki_a.clone();
        let exp_u = fx.exp_u;
        let now_u = fx.now_u;
        let policy_b = fx.policy_b.clone();
        let dev_b = fx.dev_b;

        let resp_task = tokio::spawn(async move {
            let (mut sess_b, out_b) = UdpE2eeSession::handshake_responder(
                link_b,
                &prologue_b,
                &priv_b,
                &deleg_a,
                &dev_a,
                &spki_a,
                exp_u,
                now_u,
                policy_b,
                dev_b,
                L3_MTU_DEFAULT,
                Duration::from_secs(4),
            )
            .await
            .unwrap();
            // Responder immediately sends early pp=1 Audio before receiving retransmitted msg1,
            // then enters recv_event (which replays cached msg2 when initiator retransmits msg1!).
            sess_b
                .send_audio(&AudioPacket {
                    ts: 1,
                    dtx: false,
                    payload: Bytes::from_static(b"host-early-audio"),
                })
                .await
                .unwrap();
            let ev = sess_b.recv_event(Duration::from_secs(4)).await.unwrap();
            (sess_b, out_b, ev)
        });

        let (mut sess_a, out_a) = UdpE2eeSession::handshake_initiator(
            link_a,
            &fx.prologue,
            &fx.priv_a,
            &fx.pub_b,
            &fx.deleg_b,
            &fx.dev_b,
            &fx.spki_b,
            fx.exp_u,
            fx.now_u,
            fx.policy_a,
            fx.dev_a,
            L3_MTU_DEFAULT,
            Duration::from_secs(4),
        )
        .await
        .unwrap();
        sess_a
            .send_control(0x09, b"AFTER-EARLY-MEDIA-OK")
            .await
            .unwrap();
        let (_sess_b, out_b, ev_b) = resp_task.await.unwrap();
        assert_eq!(out_a.hs_hash, out_b.hs_hash);
        assert!(matches!(
            ev_b,
            TransportEvent::Control(ref f) if f.msg_type == 0x09 && f.payload.as_ref() == b"AFTER-EARLY-MEDIA-OK"
        ));

        let _ = stop_tx.send(()).await;
        relay_task.abort();
    }
}
