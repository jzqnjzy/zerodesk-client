use crate::{control_plane::RelayTicketWire, error::ClientError};
use std::time::{Duration, Instant};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use v2_identity::{DelegationStatement, DeviceCert};

pub const MAX_SIGNALING_FRAME_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum PresenceState {
    Unspecified = 0,
    Online = 1,
    Sleep = 2,
    Offline = 3,
}

impl PresenceState {
    pub fn from_u32(v: u32) -> Self {
        match v {
            1 => Self::Online,
            2 => Self::Sleep,
            3 => Self::Offline,
            _ => Self::Unspecified,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedRedirect {
    pub target_home_region: String,
    pub target_pop_id: [u8; 8],
    pub routing_cas_ver: u64,
    pub retry_after_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeartbeatMsg {
    pub device_id: [u8; 16],
    pub presence: PresenceState,
    pub client_unix: u64,
    pub active_pop_id: Option<[u8; 8]>,
    pub rtt_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingConnectReq {
    pub session_id: [u8; 16],
    pub controller_device_id: [u8; 16],
    pub controlled_device_id: [u8; 16],
    pub proposed_l3_mtu: u32,
    pub cap_bits: u64,
    pub preferred_cipher_suite: u32,
    pub requested_exhaust_policy: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingConnectOffer {
    pub session_id: [u8; 16],
    pub controller_cert: Option<DeviceCert>,
    pub controller_delegation: Option<DelegationStatement>,
    pub relay_ticket: Option<RelayTicketWire>,
    pub proposed_l3_mtu: u32,
    pub controller_cap_bits: u64,
    pub ice_candidates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingConnectAccept {
    pub session_id: [u8; 16],
    pub error_code: u32,
    pub negotiated_l3_mtu: u32,
    pub negotiated_cap_bits: u64,
    pub negotiated_cipher_suite: u32,
    pub ice_candidates: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SignalingMsgKind {
    RegisterReq = 0x01,
    RegisterResp = 0x02,
    Heartbeat = 0x03,
    ConnectReq = 0x04,
    ConnectOffer = 0x05,
    ConnectAccept = 0x06,
    StaticKeyHint = 0x07,
}

impl SignalingMsgKind {
    pub fn from_u8(v: u8) -> Result<Self, ClientError> {
        match v {
            0x01 => Ok(Self::RegisterReq),
            0x02 => Ok(Self::RegisterResp),
            0x03 => Ok(Self::Heartbeat),
            0x04 => Ok(Self::ConnectReq),
            0x05 => Ok(Self::ConnectOffer),
            0x06 => Ok(Self::ConnectAccept),
            0x07 => Ok(Self::StaticKeyHint),
            other => Err(ClientError::Protocol(format!(
                "unknown signaling message kind {other:#04x}"
            ))),
        }
    }
}

/// Minimal clean-room Protobuf3 varint/field primitives matching `proto/v2/signaling.proto`.
fn encode_varint(mut v: u64, out: &mut Vec<u8>) {
    loop {
        let mut b = (v & 0x7F) as u8;
        v >>= 7;
        if v != 0 {
            b |= 0x80;
        }
        out.push(b);
        if v == 0 {
            break;
        }
    }
}

fn decode_varint(bytes: &[u8], pos: &mut usize) -> Result<u64, ClientError> {
    let mut val = 0u64;
    let mut shift = 0u32;
    loop {
        if *pos >= bytes.len() || shift >= 64 {
            return Err(ClientError::Protocol("truncated or overflowed protobuf varint".into()));
        }
        let b = bytes[*pos];
        *pos += 1;
        val |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok(val);
        }
        shift += 7;
    }
}

fn encode_pb_bytes(field_no: u32, data: &[u8], out: &mut Vec<u8>) {
    if data.is_empty() {
        return;
    }
    encode_varint(((field_no as u64) << 3) | 2, out);
    encode_varint(data.len() as u64, out);
    out.extend_from_slice(data);
}

fn encode_pb_varint(field_no: u32, val: u64, out: &mut Vec<u8>) {
    if val == 0 {
        return;
    }
    encode_varint((field_no as u64) << 3, out);
    encode_varint(val, out);
}

fn read_pb_bytes<'a>(bytes: &'a [u8], pos: &mut usize) -> Result<&'a [u8], ClientError> {
    let len = decode_varint(bytes, pos)? as usize;
    if *pos + len > bytes.len() {
        return Err(ClientError::Protocol("truncated protobuf bytes field".into()));
    }
    let slice = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

fn skip_pb_field(wire_type: u64, bytes: &[u8], pos: &mut usize) -> Result<(), ClientError> {
    match wire_type {
        0 => {
            let _ = decode_varint(bytes, pos)?;
            Ok(())
        }
        1 => {
            if *pos + 8 > bytes.len() {
                return Err(ClientError::Protocol("truncated fixed64 field".into()));
            }
            *pos += 8;
            Ok(())
        }
        2 => {
            let _ = read_pb_bytes(bytes, pos)?;
            Ok(())
        }
        5 => {
            if *pos + 4 > bytes.len() {
                return Err(ClientError::Protocol("truncated fixed32 field".into()));
            }
            *pos += 4;
            Ok(())
        }
        _ => Err(ClientError::Protocol(format!(
            "unsupported protobuf wire_type {wire_type}"
        ))),
    }
}

impl HeartbeatMsg {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48);
        encode_pb_bytes(1, &self.device_id, &mut out);
        encode_pb_varint(2, self.presence as u64, &mut out);
        encode_pb_varint(3, self.client_unix, &mut out);
        if let Some(pop) = &self.active_pop_id {
            encode_pb_bytes(4, pop, &mut out);
        }
        encode_pb_varint(5, self.rtt_ms as u64, &mut out);
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut device_id = [0u8; 16];
        let mut presence = PresenceState::Unspecified;
        let mut client_unix = 0u64;
        let mut active_pop_id = None;
        let mut rtt_ms = 0u32;
        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    if b.len() != 16 {
                        return Err(ClientError::Protocol("Heartbeat.device_id must be 16B".into()));
                    }
                    device_id.copy_from_slice(b);
                }
                (2, 0) => presence = PresenceState::from_u32(decode_varint(bytes, &mut pos)? as u32),
                (3, 0) => client_unix = decode_varint(bytes, &mut pos)?,
                (4, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    if b.len() != 8 {
                        return Err(ClientError::Protocol("Heartbeat.active_pop_id must be 8B".into()));
                    }
                    let mut arr = [0u8; 8];
                    arr.copy_from_slice(b);
                    active_pop_id = Some(arr);
                }
                (5, 0) => rtt_ms = decode_varint(bytes, &mut pos)? as u32,
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            device_id,
            presence,
            client_unix,
            active_pop_id,
            rtt_ms,
        })
    }
}

impl SignalingConnectReq {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(96);
        encode_pb_bytes(1, &self.session_id, &mut out);
        encode_pb_bytes(2, &self.controller_device_id, &mut out);
        encode_pb_bytes(3, &self.controlled_device_id, &mut out);
        encode_pb_varint(6, self.proposed_l3_mtu as u64, &mut out);
        encode_pb_varint(7, self.cap_bits, &mut out);
        encode_pb_varint(8, self.preferred_cipher_suite as u64, &mut out);
        encode_pb_varint(9, self.requested_exhaust_policy as u64, &mut out);
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut session_id = [0u8; 16];
        let mut controller_device_id = [0u8; 16];
        let mut controlled_device_id = [0u8; 16];
        let mut proposed_l3_mtu = 0u32;
        let mut cap_bits = 0u64;
        let mut preferred_cipher_suite = 0u32;
        let mut requested_exhaust_policy = 0u32;

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    if b.len() != 16 {
                        return Err(ClientError::Protocol("ConnectReq.session_id must be 16B".into()));
                    }
                    session_id.copy_from_slice(b);
                }
                (2, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    if b.len() != 16 {
                        return Err(ClientError::Protocol("ConnectReq.controller_device_id must be 16B".into()));
                    }
                    controller_device_id.copy_from_slice(b);
                }
                (3, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    if b.len() != 16 {
                        return Err(ClientError::Protocol("ConnectReq.controlled_device_id must be 16B".into()));
                    }
                    controlled_device_id.copy_from_slice(b);
                }
                (6, 0) => proposed_l3_mtu = decode_varint(bytes, &mut pos)? as u32,
                (7, 0) => cap_bits = decode_varint(bytes, &mut pos)?,
                (8, 0) => preferred_cipher_suite = decode_varint(bytes, &mut pos)? as u32,
                (9, 0) => requested_exhaust_policy = decode_varint(bytes, &mut pos)? as u32,
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            session_id,
            controller_device_id,
            controlled_device_id,
            proposed_l3_mtu,
            cap_bits,
            preferred_cipher_suite,
            requested_exhaust_policy,
        })
    }
}

impl SignalingConnectAccept {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        encode_pb_bytes(1, &self.session_id, &mut out);
        encode_pb_varint(2, self.error_code as u64, &mut out);
        encode_pb_varint(5, self.negotiated_l3_mtu as u64, &mut out);
        encode_pb_varint(6, self.negotiated_cap_bits, &mut out);
        encode_pb_varint(7, self.negotiated_cipher_suite as u64, &mut out);
        for cand in &self.ice_candidates {
            encode_pb_bytes(8, cand.as_bytes(), &mut out);
        }
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut session_id = [0u8; 16];
        let mut error_code = 0u32;
        let mut negotiated_l3_mtu = 0u32;
        let mut negotiated_cap_bits = 0u64;
        let mut negotiated_cipher_suite = 0u32;
        let mut ice_candidates = Vec::new();
        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    if b.len() != 16 {
                        return Err(ClientError::Protocol("ConnectAccept.session_id must be 16B".into()));
                    }
                    session_id.copy_from_slice(b);
                }
                (2, 0) => error_code = decode_varint(bytes, &mut pos)? as u32,
                (5, 0) => negotiated_l3_mtu = decode_varint(bytes, &mut pos)? as u32,
                (6, 0) => negotiated_cap_bits = decode_varint(bytes, &mut pos)?,
                (7, 0) => negotiated_cipher_suite = decode_varint(bytes, &mut pos)? as u32,
                (8, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    let s = std::str::from_utf8(b)
                        .map_err(|_| ClientError::Protocol("non-UTF8 ICE candidate".into()))?;
                    ice_candidates.push(s.to_string());
                }
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            session_id,
            error_code,
            negotiated_l3_mtu,
            negotiated_cap_bits,
            negotiated_cipher_suite,
            ice_candidates,
        })
    }
}

pub fn encode_signaling_frame(kind: SignalingMsgKind, payload: &[u8]) -> Result<Vec<u8>, ClientError> {
    let total = 1usize.saturating_add(payload.len());
    if total > MAX_SIGNALING_FRAME_BYTES {
        return Err(ClientError::Protocol(
            "signaling frame exceeds 64 KiB cap".into(),
        ));
    }
    let mut out = Vec::with_capacity(4 + total);
    out.extend_from_slice(&(total as u32).to_be_bytes());
    out.push(kind as u8);
    out.extend_from_slice(payload);
    Ok(out)
}

pub fn decode_signaling_frame(bytes: &[u8]) -> Result<(SignalingMsgKind, Vec<u8>), ClientError> {
    if bytes.len() < 5 {
        return Err(ClientError::Protocol("signaling frame truncated".into()));
    }
    let total = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    if total == 0 || total > MAX_SIGNALING_FRAME_BYTES || bytes.len() != 4 + total {
        return Err(ClientError::Protocol("invalid signaling frame length".into()));
    }
    let kind = SignalingMsgKind::from_u8(bytes[4])?;
    Ok((kind, bytes[5..].to_vec()))
}

#[derive(Debug, Clone)]
pub struct SignalingProbeResult {
    pub addr: String,
    pub connect_rtt_us: u64,
}

#[derive(Debug, Clone)]
pub struct SignalingClient {
    addr: String,
    timeout: Duration,
}

impl SignalingClient {
    pub fn new(addr: impl Into<String>) -> Self {
        Self {
            addr: addr.into(),
            timeout: Duration::from_secs(5),
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Performs a real TCP reachability/connect probe against `v2-signaling`.
    pub async fn probe_tcp(&self) -> Result<SignalingProbeResult, ClientError> {
        let start = Instant::now();
        let stream = tokio::time::timeout(self.timeout, TcpStream::connect(&self.addr))
            .await
            .map_err(|_| {
                ClientError::Timeout(format!("signaling TCP connect to {} timed out", self.addr))
            })??;
        let _ = stream.set_nodelay(true);
        let connect_rtt_us = start.elapsed().as_micros() as u64;
        drop(stream);
        Ok(SignalingProbeResult {
            addr: self.addr.clone(),
            connect_rtt_us,
        })
    }

    /// Sends a length-prefixed signaling frame and reads one response frame (Phase 2 gateway RPC seam).
    pub async fn exchange_frame(
        &self,
        kind: SignalingMsgKind,
        payload: &[u8],
    ) -> Result<(SignalingMsgKind, Vec<u8>), ClientError> {
        let frame = encode_signaling_frame(kind, payload)?;
        let fut = async {
            let mut stream = TcpStream::connect(&self.addr).await?;
            let _ = stream.set_nodelay(true);
            stream.write_all(&frame).await?;
            stream.flush().await?;
            let mut len_buf = [0u8; 4];
            stream.read_exact(&mut len_buf).await?;
            let total = u32::from_be_bytes(len_buf) as usize;
            if total == 0 || total > MAX_SIGNALING_FRAME_BYTES {
                return Err(ClientError::Protocol("invalid signaling response frame length".into()));
            }
            let mut body = vec![0u8; total];
            stream.read_exact(&mut body).await?;
            let resp_kind = SignalingMsgKind::from_u8(body[0])?;
            Ok((resp_kind, body[1..].to_vec()))
        };
        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ClientError::Timeout("signaling frame exchange timed out".into()))?
    }
}
