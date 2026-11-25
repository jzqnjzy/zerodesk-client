use crate::{
    constants::{
        default_channel_priority, CHAN_AUDIO, CHAN_CLIPBOARD, CHAN_DIAGNOSTICS, CHAN_FILE_TRANSFER,
        CHAN_INPUT_HID, CHAN_REALTIME_ACTUATOR, CHAN_TELEMETRY, CHAN_TRANSPORT_CTRL, CHAN_VIDEO,
        L3_MTU_DEFAULT,
    },
    diagnostics::QoeSnapshot,
    error::TransportError,
    l3::{L3Receiver, L3Sender},
    l4::{
        decode_l4_frame, encode_l4_frame, ActuatorCmd, ActuatorReceiver, L4Header, TelemetryFrame,
        VideoReassembler, VideoSlice,
    },
    path::TransportMode,
    policy::VerifiedTenantPolicy,
};
use async_trait::async_trait;
use bytes::Bytes;
use std::sync::{
    atomic::{AtomicU32, AtomicU64, Ordering},
    Mutex,
};
use tokio::sync::mpsc;
use v2_identity::ControlPreemptToken;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VideoFrameMeta {
    pub display_idx: u8,
    pub codec_id: u8, // 1=AV1, 2=VP9, 3=H264, 4=HEVC_OS_HW_ONLY
    pub frame_id: u32,
    pub ref_frame_id: u32,
    pub ltr_slot: u8,
    pub is_idr: bool,
    pub is_ref: bool, // false => access header flags.d = 1 (discardable)
    pub max_age_ms: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFrame {
    pub msg_type: u8,
    pub stream_seq: u32,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HidFrame {
    pub msg_type: u8,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AudioPacket {
    pub ts: u32,
    pub dtx: bool,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssembledVideoFrame {
    pub codec_id: u8,
    pub frame_id: u32,
    pub ref_frame_id: u32,
    pub ltr_slot: u8,
    pub is_idr: bool,
    pub is_ref: bool,
    pub data: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardFrame {
    pub is_file_clipboard: bool,
    pub payload: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileFrame {
    pub msg_type: u8,
    pub payload: Bytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdrReason {
    SliceLostTimeout,
    DecodeError,
    NewViewer,
}

#[derive(Debug, Clone, PartialEq)]
pub enum TransportEvent {
    Control(ControlFrame),
    Hid(HidFrame),
    Audio(AudioPacket),
    VideoFrame(AssembledVideoFrame),
    Clipboard(ClipboardFrame),
    FileTransfer(FileFrame),
    Diagnostics(QoeSnapshot),
    RealtimeActuator(ActuatorCmd),
    Telemetry(TelemetryFrame),
    TransportModeChanged(TransportMode),
    BandwidthEstimate {
        target_kbps: u32,
        rtt_ms: u32,
        loss_pct: f32,
    },
    RequestIdr {
        display_idx: u8,
        reason: IdrReason,
    },
    PolicyUpdated(VerifiedTenantPolicy),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TransportStats {
    pub tx_packets: u64,
    pub rx_packets: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub policy_denied_drops: u64,
}

/// Channel-aware ZeroDesk V2 transport trait (replaces V1 `hbb_common::Stream`).
#[async_trait]
pub trait TransportV2: Send + Sync {
    async fn send_hid(&self, frame: HidFrame) -> Result<(), TransportError>;
    async fn send_audio(&self, pkt: AudioPacket) -> Result<(), TransportError>;
    async fn send_video(&self, meta: VideoFrameMeta, data: Bytes) -> Result<(), TransportError>;
    async fn send_reliable(&self, chan_id: u8, payload: Bytes) -> Result<(), TransportError>;
    async fn send_clipboard(&self, frame: ClipboardFrame) -> Result<(), TransportError>;
    async fn send_diagnostics(&self, snap: QoeSnapshot) -> Result<(), TransportError>;
    async fn send_actuator(&self, cmd: ActuatorCmd) -> Result<(), TransportError>;
    async fn send_telemetry(&self, frame: TelemetryFrame) -> Result<(), TransportError>;
    async fn recv(&mut self) -> Result<TransportEvent, TransportError>;
    fn verified_policy(&self) -> &VerifiedTenantPolicy;
    fn session_stats(&self) -> TransportStats;
}

struct WireEnvelope {
    outer_pp: u8,
    l3_packet: Vec<u8>,
}

/// In-memory L3-encrypted `TransportV2` endpoint pair for local/CI verification
/// of channel dispatch, video MTU slicing/reassembly, actuator safety checks,
/// and `VerifiedTenantPolicy` enforcement.
pub struct LoopbackTransportV2 {
    policy: VerifiedTenantPolicy,
    l3_mtu: usize,
    sender: Mutex<L3Sender>,
    receiver: Mutex<L3Receiver>,
    reassembler: Mutex<VideoReassembler>,
    actuator_receiver: Mutex<ActuatorReceiver>,
    now_ms: AtomicU64,
    tx_wire: mpsc::UnboundedSender<WireEnvelope>,
    rx_wire: mpsc::UnboundedReceiver<WireEnvelope>,
    stream_seq: AtomicU32,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    policy_denied_drops: AtomicU64,
}

impl LoopbackTransportV2 {
    pub fn pair(
        cipher_suite: u16,
        key_a2b: [u8; 32],
        key_b2a: [u8; 32],
        policy: VerifiedTenantPolicy,
    ) -> (Self, Self) {
        Self::pair_with_device_ids(
            cipher_suite,
            key_a2b,
            key_b2a,
            policy,
            [0x01; 16],
            [0x02; 16],
        )
    }

    pub fn pair_with_device_ids(
        cipher_suite: u16,
        key_a2b: [u8; 32],
        key_b2a: [u8; 32],
        policy: VerifiedTenantPolicy,
        device_id_a: [u8; 16],
        device_id_b: [u8; 16],
    ) -> (Self, Self) {
        let (tx_a2b, rx_a2b) = mpsc::unbounded_channel();
        let (tx_b2a, rx_b2a) = mpsc::unbounded_channel();
        let tenant_id = policy.tenant_id;
        let a = Self {
            policy: policy.clone(),
            l3_mtu: L3_MTU_DEFAULT,
            sender: Mutex::new(L3Sender::new(cipher_suite, 1, key_a2b)),
            receiver: Mutex::new(L3Receiver::new(cipher_suite, 1, key_b2a)),
            reassembler: Mutex::new(VideoReassembler::default()),
            actuator_receiver: Mutex::new(ActuatorReceiver::new(tenant_id, device_id_a, 1)),
            now_ms: AtomicU64::new(0),
            tx_wire: tx_a2b,
            rx_wire: rx_b2a,
            stream_seq: AtomicU32::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            policy_denied_drops: AtomicU64::new(0),
        };
        let b = Self {
            policy,
            l3_mtu: L3_MTU_DEFAULT,
            sender: Mutex::new(L3Sender::new(cipher_suite, 1, key_b2a)),
            receiver: Mutex::new(L3Receiver::new(cipher_suite, 1, key_a2b)),
            reassembler: Mutex::new(VideoReassembler::default()),
            actuator_receiver: Mutex::new(ActuatorReceiver::new(tenant_id, device_id_b, 1)),
            now_ms: AtomicU64::new(0),
            tx_wire: tx_b2a,
            rx_wire: rx_a2b,
            stream_seq: AtomicU32::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            policy_denied_drops: AtomicU64::new(0),
        };
        (a, b)
    }

    pub fn set_now_ms(&self, now_ms: u64) {
        self.now_ms.store(now_ms, Ordering::Relaxed);
    }

    pub fn now_ms(&self) -> u64 {
        self.now_ms.load(Ordering::Relaxed)
    }

    pub fn apply_actuator_preempt(
        &self,
        token: &ControlPreemptToken,
        ca_spki_der: &[u8],
        now_unix: u64,
    ) -> Result<u32, TransportError> {
        self.actuator_receiver
            .lock()
            .unwrap()
            .apply_preempt_token(token, ca_spki_der, now_unix)
    }

    fn send_l4(
        &self,
        chan_id: u8,
        msg_type: u8,
        flags: u8,
        body: &[u8],
    ) -> Result<(), TransportError> {
        let outer_pp = default_channel_priority(chan_id)
            .ok_or_else(|| TransportError::InvalidFraming(format!("unknown chan {chan_id}")))?;
        let body_len = u16::try_from(body.len())
            .map_err(|_| TransportError::InvalidFraming("L4 body exceeds u16::MAX".into()))?;
        let seq = self.stream_seq.fetch_add(1, Ordering::Relaxed);
        let l4_hdr = L4Header {
            msg_type,
            flags,
            body_len,
            stream_seq: seq,
        };
        let l4_bytes = encode_l4_frame(&l4_hdr, body)?;
        let (_, l3_packet) = self
            .sender
            .lock()
            .unwrap()
            .encrypt(chan_id, 0, 0, &l4_bytes)?;
        let wire_len = l3_packet.len() as u64;
        self.tx_wire
            .send(WireEnvelope {
                outer_pp,
                l3_packet,
            })
            .map_err(|_| TransportError::Closed)?;
        self.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.tx_bytes.fetch_add(wire_len, Ordering::Relaxed);
        Ok(())
    }
}

#[async_trait]
impl TransportV2 for LoopbackTransportV2 {
    async fn send_hid(&self, frame: HidFrame) -> Result<(), TransportError> {
        self.send_l4(CHAN_INPUT_HID, frame.msg_type, 0, &frame.payload)
    }

    async fn send_audio(&self, pkt: AudioPacket) -> Result<(), TransportError> {
        let mut body = Vec::with_capacity(5 + pkt.payload.len());
        body.extend_from_slice(&pkt.ts.to_be_bytes());
        body.push(u8::from(pkt.dtx));
        body.extend_from_slice(&pkt.payload);
        self.send_l4(CHAN_AUDIO, 0x01, 0, &body)
    }

    async fn send_video(&self, meta: VideoFrameMeta, data: Bytes) -> Result<(), TransportError> {
        let slices = VideoSlice::slice_frame(
            meta.codec_id,
            meta.frame_id,
            meta.ref_frame_id,
            meta.ltr_slot,
            meta.is_idr,
            meta.is_ref,
            meta.max_age_ms,
            &data,
            self.l3_mtu,
        )?;
        for slice in slices {
            let encoded = slice.encode();
            self.send_l4(CHAN_VIDEO, 0x01, 0, &encoded)?;
        }
        Ok(())
    }

    async fn send_reliable(&self, chan_id: u8, payload: Bytes) -> Result<(), TransportError> {
        if let Err(e) = self.policy.enforce_channel(chan_id, false) {
            self.policy_denied_drops.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        self.send_l4(chan_id, 0x01, 0, &payload)
    }

    async fn send_clipboard(&self, frame: ClipboardFrame) -> Result<(), TransportError> {
        if let Err(e) = self
            .policy
            .enforce_channel(CHAN_CLIPBOARD, frame.is_file_clipboard)
        {
            self.policy_denied_drops.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        let flags = u8::from(frame.is_file_clipboard);
        self.send_l4(CHAN_CLIPBOARD, 0x01, flags, &frame.payload)
    }

    async fn send_diagnostics(&self, snap: QoeSnapshot) -> Result<(), TransportError> {
        let body = serde_json::to_vec(&snap)
            .map_err(|e| TransportError::InvalidFraming(e.to_string()))?;
        self.send_l4(CHAN_DIAGNOSTICS, 0x01, 0, &body)
    }

    async fn send_actuator(&self, cmd: ActuatorCmd) -> Result<(), TransportError> {
        if let Err(e) = self.policy.enforce_channel(CHAN_REALTIME_ACTUATOR, false) {
            self.policy_denied_drops.fetch_add(1, Ordering::Relaxed);
            return Err(e);
        }
        let body = cmd.encode();
        self.send_l4(CHAN_REALTIME_ACTUATOR, 0x01, 0, &body)
    }

    async fn send_telemetry(&self, frame: TelemetryFrame) -> Result<(), TransportError> {
        let body = frame.encode();
        self.send_l4(CHAN_TELEMETRY, 0x01, 0, &body)
    }

    async fn recv(&mut self) -> Result<TransportEvent, TransportError> {
        loop {
            let env = self.rx_wire.recv().await.ok_or(TransportError::Closed)?;
            let now_ms = self.now_ms.load(Ordering::Relaxed);
            let wire_len = env.l3_packet.len() as u64;
            let (l3_hdr, pt) = self.receiver.lock().unwrap().decrypt_and_verify(
                &env.l3_packet,
                Some(env.outer_pp),
                now_ms,
            )?;
            self.rx_packets.fetch_add(1, Ordering::Relaxed);
            self.rx_bytes.fetch_add(wire_len, Ordering::Relaxed);
            let (l4_hdr, body) = decode_l4_frame(&pt)?;
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
                        return Err(TransportError::InvalidFraming("audio packet too short".into()));
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
                    if let Some(frame) = self.reassembler.lock().unwrap().push_slice(slice, now_ms) {
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
                    if let Err(e) = self
                        .policy
                        .enforce_channel(CHAN_CLIPBOARD, is_file_clipboard)
                    {
                        self.policy_denied_drops.fetch_add(1, Ordering::Relaxed);
                        return Err(e);
                    }
                    return Ok(TransportEvent::Clipboard(ClipboardFrame {
                        is_file_clipboard,
                        payload: Bytes::copy_from_slice(body),
                    }));
                }
                CHAN_FILE_TRANSFER => {
                    if let Err(e) = self.policy.enforce_channel(CHAN_FILE_TRANSFER, false) {
                        self.policy_denied_drops.fetch_add(1, Ordering::Relaxed);
                        return Err(e);
                    }
                    return Ok(TransportEvent::FileTransfer(FileFrame {
                        msg_type: l4_hdr.msg_type,
                        payload: Bytes::copy_from_slice(body),
                    }));
                }
                CHAN_DIAGNOSTICS => {
                    let snap: QoeSnapshot = serde_json::from_slice(body)
                        .map_err(|e| TransportError::InvalidFraming(e.to_string()))?;
                    return Ok(TransportEvent::Diagnostics(snap));
                }
                CHAN_REALTIME_ACTUATOR => {
                    if let Err(e) = self.policy.enforce_channel(CHAN_REALTIME_ACTUATOR, false) {
                        self.policy_denied_drops.fetch_add(1, Ordering::Relaxed);
                        return Err(e);
                    }
                    let cmd = ActuatorCmd::decode(body)?;
                    if !self
                        .actuator_receiver
                        .lock()
                        .unwrap()
                        .accept_cmd(&cmd, now_ms)
                    {
                        return Err(TransportError::InvalidFraming(
                            "0x07 RealtimeActuator command rejected by safety validator".into(),
                        ));
                    }
                    return Ok(TransportEvent::RealtimeActuator(cmd));
                }
                CHAN_TELEMETRY => {
                    let frame = TelemetryFrame::decode(body)?;
                    return Ok(TransportEvent::Telemetry(frame));
                }
                other => {
                    return Err(TransportError::InvalidFraming(format!(
                        "unsupported chan_id {other:#x}"
                    )));
                }
            }
        }
    }

    fn verified_policy(&self) -> &VerifiedTenantPolicy {
        &self.policy
    }

    fn session_stats(&self) -> TransportStats {
        TransportStats {
            tx_packets: self.tx_packets.load(Ordering::Relaxed),
            rx_packets: self.rx_packets.load(Ordering::Relaxed),
            tx_bytes: self.tx_bytes.load(Ordering::Relaxed),
            rx_bytes: self.rx_bytes.load(Ordering::Relaxed),
            policy_denied_drops: self.policy_denied_drops.load(Ordering::Relaxed),
        }
    }
}
