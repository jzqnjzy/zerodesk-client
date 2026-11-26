use crate::{access_ctrl::AccessKeys, error::ClientError};
use bytes::Bytes;
use std::{
    collections::BTreeSet,
    net::SocketAddr,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::net::UdpSocket;
use v2_identity::{ControlPreemptToken, DelegationStatement};
use v2_transport::{
    default_channel_priority, decode_l4_frame, encode_l4_frame, rs64_decode_block,
    rs64_encode_block, seal_udp_v11, seq_u32_gt, AccessEpochState, AccessFlags, AccessHeaderV11,
    ActuatorCmd, ActuatorReceiver, AssembledVideoFrame, AudioPacket, BwHintController,
    ClipboardFrame, ControlFrame, E2eeHandshakeOutput, E2eeNoiseHandshake, EdgeCtrlFrame,
    FileFrame, HidFrame, L3Receiver, L3Sender, L4Header, LegCiphertextCache, LegSeqDedupWindow,
    PrologueInput, StreamSeqDedup, TelemetryFrame, TransportError, TransportEvent,
    VerifiedTenantPolicy, VideoFrameMeta, VideoReassembler, VideoSlice, ACCESS_HDR_V11_LEN,
    CHAN_AUDIO, CHAN_CLIPBOARD, CHAN_DIAGNOSTICS, CHAN_FILE_TRANSFER, CHAN_INPUT_HID,
    CHAN_REALTIME_ACTUATOR, CHAN_TELEMETRY, CHAN_TRANSPORT_CTRL, CHAN_VIDEO, CIPHER_AESGCM,
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
}

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
            rtt_ms: 20,
            auto_leg_nack: true,
            stats: UdpLinkStats::default(),
        })
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
        let hdr = AccessHeaderV11 {
            flags: AccessFlags {
                pp,
                discardable,
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

    /// Sends an `EdgeCtrl::Ping` and waits for the matching `EdgeCtrl::Pong`, retrying on loss.
    /// Returns measured RTT in microseconds.
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

            let deadline = Instant::now() + per_attempt_timeout;
            loop {
                let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                    break;
                };
                match self.recv_packet(rem).await {
                    Ok(UdpRecvEvent::EdgeCtrl(EdgeCtrlFrame::Pong { ts_us: echo }))
                        if echo == ts_us =>
                    {
                        let rtt_us = sent.elapsed().as_micros() as u64;
                        self.rtt_ms = (rtt_us / 1000).max(1);
                        return Ok(rtt_us);
                    }
                    Ok(_) => continue,
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

    /// Receives and authenticates the next UDP packet from Edge.
    /// Automatically honors incoming `EdgeCtrl::LegNack` (emitting `rtx=1` packets),
    /// `EdgeCtrl::Ping` (replying `Pong`), and `EdgeCtrl::BwHint`.
    pub async fn recv_packet(&mut self, timeout: Duration) -> Result<UdpRecvEvent, ClientError> {
        let deadline = Instant::now() + timeout;
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

const HANDSHAKE_RTX_INTERVAL: Duration = Duration::from_millis(400);
const HANDSHAKE_REPLAY_TTL: Duration = Duration::from_secs(5);

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

/// Complete client ↔ client E2EE session running over `UdpAccessLink` with:
/// - `Noise_IK` handshake + 204B anti-downgrade prologue + P-256 `DelegationStatement` verification
/// - L3 AEAD + 2048-bit replay window + `chan_id <-> pp` validation
/// - L4 9-channel multiplexer (`0x00..0x08`, including `0x07 RealtimeActuator` policy + `ActuatorReceiver` gate)
pub struct UdpE2eeSession {
    link: UdpAccessLink,
    policy: VerifiedTenantPolicy,
    l3_mtu: usize,
    sender: L3Sender,
    receiver: L3Receiver,
    reassembler: VideoReassembler,
    actuator_receiver: ActuatorReceiver,
    stream_dedup: StreamSeqDedup,
    next_stream_seq: [u32; 9],
    hs_replay: Option<HandshakeReplayCache>,
}

impl UdpE2eeSession {
    #[allow(clippy::too_many_arguments)]
    pub async fn handshake_initiator(
        mut link: UdpAccessLink,
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
        let prologue = prologue_input.compute_prologue();
        let mut hs = E2eeNoiseHandshake::build_ik_initiator(
            prologue_input.cipher_suite,
            local_x25519_priv,
            remote_x25519_pub,
            &prologue,
        )?;
        let msg1 = hs.write_message(b"V2-SESSION-OPEN")?;
        link.send_l3_packet(0, false, &msg1).await?;

        let deadline = Instant::now() + timeout;
        let mut next_rtx = Instant::now() + HANDSHAKE_RTX_INTERVAL;
        let msg2 = loop {
            let now = Instant::now();
            let Some(rem) = deadline
                .checked_duration_since(now)
                .filter(|d| !d.is_zero())
            else {
                return Err(ClientError::Timeout("E2EE Noise_IK msg2 timed out".into()));
            };
            let slice = match next_rtx
                .checked_duration_since(now)
                .filter(|d| !d.is_zero())
            {
                Some(until_rtx) => rem.min(until_rtx),
                None => {
                    link.send_l3_packet(0, false, &msg1).await?;
                    next_rtx = Instant::now() + HANDSHAKE_RTX_INTERVAL;
                    continue;
                }
            };
            match link.recv_packet(slice).await {
                Ok(UdpRecvEvent::L3Data { payload, .. }) => break payload,
                Ok(UdpRecvEvent::EdgeCtrl(_)) => continue,
                Err(ClientError::Timeout(_)) => {
                    let now = Instant::now();
                    if deadline.checked_duration_since(now).is_none() {
                        return Err(ClientError::Timeout("E2EE Noise_IK msg2 timed out".into()));
                    }
                    if next_rtx.checked_duration_since(now).is_none() {
                        link.send_l3_packet(0, false, &msg1).await?;
                        next_rtx = Instant::now() + HANDSHAKE_RTX_INTERVAL;
                    }
                }
                Err(e) => return Err(e),
            }
        };
        let _ = hs.read_message(&msg2)?;
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
        mut link: UdpAccessLink,
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
        let prologue = prologue_input.compute_prologue();
        let mut hs = E2eeNoiseHandshake::build_ik_responder(
            prologue_input.cipher_suite,
            local_x25519_priv,
            &prologue,
        )?;

        let deadline = Instant::now() + timeout;
        let msg1 = loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("E2EE Noise_IK msg1 timed out".into()));
            };
            match link.recv_packet(rem).await? {
                UdpRecvEvent::L3Data { payload, .. } => break payload,
                UdpRecvEvent::EdgeCtrl(_) => continue,
            }
        };
        let _ = hs.read_message(&msg1)?;
        let msg2 = hs.write_message(b"V2-SESSION-ACCEPT")?;
        link.send_l3_packet(0, false, &msg2).await?;

        let out = hs.finish_split(
            Some(peer_delegation),
            expected_peer_device_id,
            peer_device_spki_der,
            peer_device_cert_exp_unix,
            now_unix,
        )?;
        let mut session = Self::from_handshake(link, &out, policy, local_device_id, l3_mtu);
        session.hs_replay = Some(HandshakeReplayCache::Responder {
            msg1,
            msg2,
            created: Instant::now(),
        });
        Ok((session, out))
    }

    pub fn from_handshake(
        link: UdpAccessLink,
        hs_out: &E2eeHandshakeOutput,
        policy: VerifiedTenantPolicy,
        local_device_id: [u8; 16],
        l3_mtu: usize,
    ) -> Self {
        let tenant_id = policy.tenant_id;
        Self {
            link,
            policy,
            l3_mtu: l3_mtu.min(L3_MTU_DEFAULT),
            sender: L3Sender::new(hs_out.cipher_suite, 1, *hs_out.tx_key),
            receiver: L3Receiver::new(hs_out.cipher_suite, 1, *hs_out.rx_key),
            reassembler: VideoReassembler::default(),
            actuator_receiver: ActuatorReceiver::new(tenant_id, local_device_id, 1),
            stream_dedup: StreamSeqDedup::default(),
            next_stream_seq: [0; 9],
            hs_replay: None,
        }
    }

    /// Creates a session directly from pre-shared keys (convenience for local tests).
    pub fn from_keys(
        link: UdpAccessLink,
        tx_key: [u8; 32],
        rx_key: [u8; 32],
        policy: VerifiedTenantPolicy,
        local_device_id: [u8; 16],
    ) -> Self {
        let tenant_id = policy.tenant_id;
        Self {
            link,
            policy,
            l3_mtu: L3_MTU_DEFAULT,
            sender: L3Sender::new(CIPHER_AESGCM, 1, tx_key),
            receiver: L3Receiver::new(CIPHER_AESGCM, 1, rx_key),
            reassembler: VideoReassembler::default(),
            actuator_receiver: ActuatorReceiver::new(tenant_id, local_device_id, 1),
            stream_dedup: StreamSeqDedup::default(),
            next_stream_seq: [0; 9],
            hs_replay: None,
        }
    }

    pub fn link(&self) -> &UdpAccessLink {
        &self.link
    }

    pub fn link_mut(&mut self) -> &mut UdpAccessLink {
        &mut self.link
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
        let pp = default_channel_priority(chan_id)
            .ok_or_else(|| TransportError::InvalidFraming(format!("unknown chan_id {chan_id}")))?;
        let body_len = u16::try_from(body.len())
            .map_err(|_| TransportError::InvalidFraming("L4 body exceeds u16::MAX".into()))?;
        let idx = chan_id as usize;
        let stream_seq = self.next_stream_seq[idx];
        self.next_stream_seq[idx] = stream_seq.wrapping_add(1);

        let l4_hdr = L4Header {
            msg_type,
            flags,
            body_len,
            stream_seq,
        };
        let l4_wire = encode_l4_frame(&l4_hdr, body)?;
        let ts_mod = (now_us() & 0xFFFF_FFFF) as u32;
        let (_, l3_wire) = self.sender.encrypt(chan_id, 0, ts_mod, &l4_wire)?;
        self.link.send_l3_packet(pp, discardable, &l3_wire).await
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
        let discardable = !meta.is_ref;
        for slice in slices {
            let encoded = slice.encode();
            self.send_channel_frame(CHAN_VIDEO, 0x01, 0, discardable, &encoded)
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

    /// Receives and dispatches the next L4 `TransportEvent`, verifying L3 AEAD, 2048-bit
    /// replay window, `chan_id <-> pp`, `VerifiedTenantPolicy`, and `0x07 ActuatorReceiver`.
    pub async fn recv_event(&mut self, timeout: Duration) -> Result<TransportEvent, ClientError> {
        let deadline = Instant::now() + timeout;
        loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("E2EE recv_event timed out".into()));
            };
            let (hdr, l3_bytes) = match self.link.recv_packet(rem).await? {
                UdpRecvEvent::EdgeCtrl(_) => continue,
                UdpRecvEvent::L3Data { header, payload } => (header, payload),
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
                            self.link.send_l3_packet(0, false, msg2).await?;
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
                    self.hs_replay = None;
                    v
                }
                Err(TransportError::ReplayDetected) => continue,
                Err(e) => return Err(e.into()),
            };
            let (l4_hdr, body) = decode_l4_frame(&pt)?;
            if !self.stream_dedup.mark_if_new(l3_hdr.chan_id, l4_hdr.stream_seq) {
                continue;
            }
            match l3_hdr.chan_id {
                CHAN_TRANSPORT_CTRL => {
                    return Ok(TransportEvent::Control(ControlFrame {
                        msg_type: l4_hdr.msg_type,
                        stream_seq: l4_hdr.stream_seq,
                        payload: Bytes::copy_from_slice(body),
                    }));
                }
                CHAN_INPUT_HID => {
                    return Ok(TransportEvent::Hid(HidFrame {
                        msg_type: l4_hdr.msg_type,
                        payload: Bytes::copy_from_slice(body),
                    }));
                }
                CHAN_AUDIO => {
                    if body.len() < 5 {
                        return Err(TransportError::InvalidFraming("audio packet too short".into()).into());
                    }
                    let ts = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    let dtx = body[4] != 0;
                    return Ok(TransportEvent::Audio(AudioPacket {
                        ts,
                        dtx,
                        payload: Bytes::copy_from_slice(&body[5..]),
                    }));
                }
                CHAN_VIDEO => {
                    let slice = VideoSlice::decode(body)?;
                    if let Some(frame) = self.reassembler.push_slice(slice, now) {
                        return Ok(TransportEvent::VideoFrame(AssembledVideoFrame {
                            codec_id: frame.codec_id,
                            frame_id: frame.frame_id,
                            ref_frame_id: frame.ref_frame_id,
                            ltr_slot: frame.ltr_slot,
                            is_idr: frame.is_idr,
                            is_ref: frame.is_ref,
                            data: Bytes::from(frame.data),
                        }));
                    }
                }
                CHAN_CLIPBOARD => {
                    let is_file_clipboard = l4_hdr.flags != 0;
                    self.policy
                        .enforce_channel(CHAN_CLIPBOARD, is_file_clipboard)?;
                    return Ok(TransportEvent::Clipboard(ClipboardFrame {
                        is_file_clipboard,
                        payload: Bytes::copy_from_slice(body),
                    }));
                }
                CHAN_FILE_TRANSFER => {
                    self.policy.enforce_channel(CHAN_FILE_TRANSFER, false)?;
                    return Ok(TransportEvent::FileTransfer(FileFrame {
                        msg_type: l4_hdr.msg_type,
                        payload: Bytes::copy_from_slice(body),
                    }));
                }
                CHAN_DIAGNOSTICS => {
                    let snap = serde_json::from_slice(body)?;
                    return Ok(TransportEvent::Diagnostics(snap));
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
                    return Ok(TransportEvent::RealtimeActuator(cmd));
                }
                CHAN_TELEMETRY => {
                    let frame = TelemetryFrame::decode(body)?;
                    return Ok(TransportEvent::Telemetry(frame));
                }
                other => {
                    return Err(TransportError::InvalidFraming(format!(
                        "unsupported chan_id {other:#04x}"
                    ))
                    .into());
                }
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
}
