// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use crate::{
    control_plane::{RegisterDeviceResp, RelayTicketWire},
    error::ClientError,
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};
use v2_identity::{DelegationStatement, DeviceCert, DEVCERT_DOMAIN};

pub const MAX_SIGNALING_FRAME_BYTES: usize = 64 * 1024;
pub const SIGNALING_BACKOFF_INITIAL_MS: u64 = 500;
pub const SIGNALING_BACKOFF_MAX_MS: u64 = 30_000;
const PEER_ROUTE_PREFIX: &str = "v2-peer:";

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

/// Wire representation of `v2.control.DeviceCert` matching `proto/v2/identity.proto` fields `1..=12`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingDeviceCert {
    pub version: u32,
    pub cert_id: [u8; 16],
    pub device_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub p256_pub_der: Vec<u8>,
    pub key_epoch: u64,
    pub policy_hash: [u8; 32],
    pub cap_bits: u64,
    pub iat_unix: u64,
    pub exp_unix: u64,
    pub ca_key_id: u32,
    pub ca_sig: Vec<u8>,
}

impl SignalingDeviceCert {
    /// Parses a `SignalingDeviceCert` from canonical `"V2-DEVCERT-v1"` TBS bytes and its CA signature.
    pub fn from_tbs_and_sig(
        tbs: &[u8],
        ca_sig: Vec<u8>,
        ca_key_id: u32,
    ) -> Result<Self, ClientError> {
        const PREFIX_LEN: usize = 13 + 4 + 16 + 16 + 16 + 2;
        const SUFFIX_LEN: usize = 8 + 32 + 8 + 8 + 8;
        if tbs.len() < PREFIX_LEN + SUFFIX_LEN {
            return Err(ClientError::Protocol(format!(
                "DEVCERT_TBS truncated: {} bytes",
                tbs.len()
            )));
        }
        if &tbs[0..13] != DEVCERT_DOMAIN {
            return Err(ClientError::Protocol(
                "DEVCERT_TBS domain separator mismatch".into(),
            ));
        }
        let version = u32::from_be_bytes([tbs[13], tbs[14], tbs[15], tbs[16]]);
        let mut cert_id = [0u8; 16];
        cert_id.copy_from_slice(&tbs[17..33]);
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&tbs[33..49]);
        let mut tenant_id = [0u8; 16];
        tenant_id.copy_from_slice(&tbs[49..65]);
        let pub_len = u16::from_be_bytes([tbs[65], tbs[66]]) as usize;
        if tbs.len() != PREFIX_LEN + pub_len + SUFFIX_LEN {
            return Err(ClientError::Protocol(format!(
                "DEVCERT_TBS length {} does not match p256_pub_der length {pub_len}",
                tbs.len()
            )));
        }
        let p256_pub_der = tbs[67..67 + pub_len].to_vec();
        let off = 67 + pub_len;
        let key_epoch = read_u64_be(&tbs[off..off + 8]);
        let mut policy_hash = [0u8; 32];
        policy_hash.copy_from_slice(&tbs[off + 8..off + 40]);
        let cap_bits = read_u64_be(&tbs[off + 40..off + 48]);
        let iat_unix = read_u64_be(&tbs[off + 48..off + 56]);
        let exp_unix = read_u64_be(&tbs[off + 56..off + 64]);

        Ok(Self {
            version,
            cert_id,
            device_id,
            tenant_id,
            p256_pub_der,
            key_epoch,
            policy_hash,
            cap_bits,
            iat_unix,
            exp_unix,
            ca_key_id,
            ca_sig,
        })
    }

    /// Constructs a `SignalingDeviceCert` from a Control Plane `POST /v2/devices/register` response,
    /// cross-checking the JSON metadata against the canonical `"V2-DEVCERT-v1"` TBS bytes.
    pub fn from_register_resp(resp: &RegisterDeviceResp) -> Result<Self, ClientError> {
        let tbs = resp.tbs_bytes()?;
        let sig = resp.sig_der()?;
        let cert = Self::from_tbs_and_sig(&tbs, sig, 1)?;

        let expected_cert_id = hex::decode(&resp.cert_id_hex)?;
        if expected_cert_id.as_slice() != cert.cert_id {
            return Err(ClientError::Protocol(
                "RegisterDeviceResp.cert_id_hex does not match DEVCERT_TBS".into(),
            ));
        }
        if cert.key_epoch != resp.key_epoch
            || cert.iat_unix != resp.iat_unix
            || cert.exp_unix != resp.exp_unix
        {
            return Err(ClientError::Protocol(
                "RegisterDeviceResp timestamps/key_epoch do not match DEVCERT_TBS".into(),
            ));
        }
        Ok(cert)
    }

    pub fn from_identity_cert(cert: &DeviceCert, ca_key_id: u32) -> Self {
        Self {
            version: cert.version,
            cert_id: cert.cert_id,
            device_id: cert.device_id,
            tenant_id: cert.tenant_id,
            p256_pub_der: cert.p256_pub_der.clone(),
            key_epoch: cert.key_epoch,
            policy_hash: cert.policy_hash,
            cap_bits: cert.cap_bits,
            iat_unix: cert.iat_unix,
            exp_unix: cert.exp_unix,
            ca_key_id,
            ca_sig: cert.sig_der.clone(),
        }
    }

    pub fn to_identity_cert(&self) -> DeviceCert {
        DeviceCert {
            version: self.version,
            cert_id: self.cert_id,
            device_id: self.device_id,
            tenant_id: self.tenant_id,
            p256_pub_der: self.p256_pub_der.clone(),
            key_epoch: self.key_epoch,
            policy_hash: self.policy_hash,
            cap_bits: self.cap_bits,
            iat_unix: self.iat_unix,
            exp_unix: self.exp_unix,
            hardware_backed: false,
            sig_der: self.ca_sig.clone(),
        }
    }

    /// Produces canonical `"V2-DEVCERT-v1"` TBS bytes matching `proto/v2/identity.proto`.
    pub fn to_tbs_bytes(&self) -> Result<Vec<u8>, ClientError> {
        Ok(self.to_identity_cert().tbs_bytes()?)
    }

    pub fn to_tbs_sha256(&self) -> Result<[u8; 32], ClientError> {
        let tbs = self.to_tbs_bytes()?;
        Ok(Sha256::digest(&tbs).into())
    }

    pub fn verify(&self, ca_spki_der: &[u8], now_unix: u64) -> Result<(), ClientError> {
        Ok(self.to_identity_cert().verify(ca_spki_der, now_unix)?)
    }

    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        encode_pb_varint(1, self.version as u64, &mut out);
        encode_pb_bytes(2, &self.cert_id, &mut out);
        encode_pb_bytes(3, &self.device_id, &mut out);
        encode_pb_bytes(4, &self.tenant_id, &mut out);
        encode_pb_bytes(5, &self.p256_pub_der, &mut out);
        encode_pb_varint(6, self.key_epoch, &mut out);
        encode_pb_bytes(7, &self.policy_hash, &mut out);
        encode_pb_varint(8, self.cap_bits, &mut out);
        encode_pb_varint(9, self.iat_unix, &mut out);
        encode_pb_varint(10, self.exp_unix, &mut out);
        encode_pb_varint(11, self.ca_key_id as u64, &mut out);
        encode_pb_bytes(12, &self.ca_sig, &mut out);
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut version = 0u32;
        let mut cert_id = [0u8; 16];
        let mut device_id = [0u8; 16];
        let mut tenant_id = [0u8; 16];
        let mut p256_pub_der = Vec::new();
        let mut key_epoch = 0u64;
        let mut policy_hash = [0u8; 32];
        let mut cap_bits = 0u64;
        let mut iat_unix = 0u64;
        let mut exp_unix = 0u64;
        let mut ca_key_id = 0u32;
        let mut ca_sig = Vec::new();

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 0) => version = decode_u32_varint(bytes, &mut pos, "DeviceCert.version")?,
                (2, 2) => {
                    cert_id = read_fixed_bytes::<16>(bytes, &mut pos, "DeviceCert.cert_id")?;
                }
                (3, 2) => {
                    device_id = read_fixed_bytes::<16>(bytes, &mut pos, "DeviceCert.device_id")?;
                }
                (4, 2) => {
                    tenant_id = read_fixed_bytes::<16>(bytes, &mut pos, "DeviceCert.tenant_id")?;
                }
                (5, 2) => p256_pub_der = read_pb_bytes(bytes, &mut pos)?.to_vec(),
                (6, 0) => key_epoch = decode_varint(bytes, &mut pos)?,
                (7, 2) => {
                    policy_hash =
                        read_fixed_bytes::<32>(bytes, &mut pos, "DeviceCert.policy_hash")?;
                }
                (8, 0) => cap_bits = decode_varint(bytes, &mut pos)?,
                (9, 0) => iat_unix = decode_varint(bytes, &mut pos)?,
                (10, 0) => exp_unix = decode_varint(bytes, &mut pos)?,
                (11, 0) => {
                    ca_key_id = decode_u32_varint(bytes, &mut pos, "DeviceCert.ca_key_id")?;
                }
                (12, 2) => ca_sig = read_pb_bytes(bytes, &mut pos)?.to_vec(),
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            version,
            cert_id,
            device_id,
            tenant_id,
            p256_pub_der,
            key_epoch,
            policy_hash,
            cap_bits,
            iat_unix,
            exp_unix,
            ca_key_id,
            ca_sig,
        })
    }
}

/// Encodes `v2.control.DelegationStatement` per `proto/v2/identity.proto` fields `1..=6`.
pub fn encode_delegation_pb(stmt: &DelegationStatement) -> Vec<u8> {
    let mut out = Vec::with_capacity(144);
    encode_pb_bytes(1, &stmt.device_id, &mut out);
    encode_pb_bytes(2, &stmt.x25519_pub, &mut out);
    encode_pb_varint(3, u64::from(stmt.prefer_chacha), &mut out);
    encode_pb_varint(4, stmt.delegation_seq, &mut out);
    encode_pb_varint(5, stmt.exp_unix, &mut out);
    encode_pb_bytes(6, &stmt.sig_der, &mut out);
    out
}

/// Decodes `v2.control.DelegationStatement` per `proto/v2/identity.proto` fields `1..=6`.
pub fn decode_delegation_pb(bytes: &[u8]) -> Result<DelegationStatement, ClientError> {
    let mut pos = 0;
    let mut device_id = [0u8; 16];
    let mut x25519_pub = [0u8; 32];
    let mut prefer_chacha = false;
    let mut delegation_seq = 0u64;
    let mut exp_unix = 0u64;
    let mut sig_der = Vec::new();

    while pos < bytes.len() {
        let tag = decode_varint(bytes, &mut pos)?;
        let field_no = (tag >> 3) as u32;
        let wire_type = tag & 0x07;
        match (field_no, wire_type) {
            (1, 2) => {
                device_id =
                    read_fixed_bytes::<16>(bytes, &mut pos, "DelegationStatement.device_id")?;
            }
            (2, 2) => {
                x25519_pub =
                    read_fixed_bytes::<32>(bytes, &mut pos, "DelegationStatement.x25519_pub")?;
            }
            (3, 0) => {
                let raw = decode_varint(bytes, &mut pos)?;
                prefer_chacha = match raw {
                    0 => false,
                    1 => true,
                    _ => {
                        return Err(ClientError::Protocol(format!(
                            "DelegationStatement.prefer_chacha invalid bool {raw}"
                        )));
                    }
                };
            }
            (4, 0) => delegation_seq = decode_varint(bytes, &mut pos)?,
            (5, 0) => exp_unix = decode_varint(bytes, &mut pos)?,
            (6, 2) => sig_der = read_pb_bytes(bytes, &mut pos)?.to_vec(),
            _ => skip_pb_field(wire_type, bytes, &mut pos)?,
        }
    }
    Ok(DelegationStatement {
        device_id,
        x25519_pub,
        prefer_chacha,
        delegation_seq,
        exp_unix,
        sig_der,
    })
}

impl RelayTicketWire {
    /// Encodes `v2.control.RelayTicket` per `proto/v2/relay_lease.proto` fields `1..=3`.
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(48 + self.body.len());
        encode_pb_varint(1, self.key_id as u64, &mut out);
        encode_pb_bytes(2, &self.body, &mut out);
        encode_pb_bytes(3, &self.mac, &mut out);
        out
    }

    /// Decodes `v2.control.RelayTicket` per `proto/v2/relay_lease.proto` fields `1..=3`.
    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut key_id = 0u32;
        let mut body = Vec::new();
        let mut mac = [0u8; 32];
        let mut has_mac = false;

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 0) => key_id = decode_u32_varint(bytes, &mut pos, "RelayTicket.key_id")?,
                (2, 2) => body = read_pb_bytes(bytes, &mut pos)?.to_vec(),
                (3, 2) => {
                    mac = read_fixed_bytes::<32>(bytes, &mut pos, "RelayTicket.mac")?;
                    has_mac = true;
                }
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        if !has_mac || body.is_empty() {
            return Err(ClientError::Protocol(
                "RelayTicket missing required body or 32B mac".into(),
            ));
        }
        Ok(Self { key_id, body, mac })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MovedRedirect {
    pub target_home_region: String,
    pub target_pop_id: [u8; 8],
    pub routing_cas_ver: u64,
    pub retry_after_ms: u32,
}

impl MovedRedirect {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.target_home_region.len());
        encode_pb_bytes(1, self.target_home_region.as_bytes(), &mut out);
        encode_pb_bytes(2, &self.target_pop_id, &mut out);
        encode_pb_varint(3, self.routing_cas_ver, &mut out);
        encode_pb_varint(4, self.retry_after_ms as u64, &mut out);
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut target_home_region = String::new();
        let mut target_pop_id = [0u8; 8];
        let mut routing_cas_ver = 0u64;
        let mut retry_after_ms = 0u32;

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    target_home_region = std::str::from_utf8(b)
                        .map_err(|_| {
                            ClientError::Protocol("MovedRedirect.target_home_region non-UTF8".into())
                        })?
                        .to_string();
                }
                (2, 2) => {
                    target_pop_id =
                        read_fixed_bytes::<8>(bytes, &mut pos, "MovedRedirect.target_pop_id")?;
                }
                (3, 0) => routing_cas_ver = decode_varint(bytes, &mut pos)?,
                (4, 0) => {
                    retry_after_ms =
                        decode_u32_varint(bytes, &mut pos, "MovedRedirect.retry_after_ms")?;
                }
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            target_home_region,
            target_pop_id,
            routing_cas_ver,
            retry_after_ms,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingRegisterReq {
    pub device_cert: SignalingDeviceCert,
    pub delegation: DelegationStatement,
    pub presence: PresenceState,
    pub cap_bits: u64,
    pub home_region: String,
    pub ver_major: u32,
    pub ver_minor: u32,
}

impl SignalingRegisterReq {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(420);
        let cert_pb = self.device_cert.encode_pb();
        encode_pb_bytes(1, &cert_pb, &mut out);
        let deleg_pb = encode_delegation_pb(&self.delegation);
        encode_pb_bytes(2, &deleg_pb, &mut out);
        encode_pb_varint(3, self.presence as u64, &mut out);
        encode_pb_varint(4, self.cap_bits, &mut out);
        encode_pb_bytes(5, self.home_region.as_bytes(), &mut out);
        encode_pb_varint(6, self.ver_major as u64, &mut out);
        encode_pb_varint(7, self.ver_minor as u64, &mut out);
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut device_cert: Option<SignalingDeviceCert> = None;
        let mut delegation: Option<DelegationStatement> = None;
        let mut presence = PresenceState::Unspecified;
        let mut cap_bits = 0u64;
        let mut home_region = String::new();
        let mut ver_major = 0u32;
        let mut ver_minor = 0u32;

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    device_cert = Some(SignalingDeviceCert::decode_pb(b)?);
                }
                (2, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    delegation = Some(decode_delegation_pb(b)?);
                }
                (3, 0) => {
                    let raw = decode_u32_varint(bytes, &mut pos, "RegisterReq.presence")?;
                    presence = PresenceState::from_u32(raw);
                }
                (4, 0) => cap_bits = decode_varint(bytes, &mut pos)?,
                (5, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    home_region = std::str::from_utf8(b)
                        .map_err(|_| {
                            ClientError::Protocol("RegisterReq.home_region non-UTF8".into())
                        })?
                        .to_string();
                }
                (6, 0) => ver_major = decode_u32_varint(bytes, &mut pos, "RegisterReq.ver_major")?,
                (7, 0) => ver_minor = decode_u32_varint(bytes, &mut pos, "RegisterReq.ver_minor")?,
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            device_cert: device_cert.ok_or_else(|| {
                ClientError::Protocol("RegisterReq missing device_cert".into())
            })?,
            delegation: delegation.ok_or_else(|| {
                ClientError::Protocol("RegisterReq missing delegation".into())
            })?,
            presence,
            cap_bits,
            home_region,
            ver_major,
            ver_minor,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingRegisterResp {
    pub error_code: u32,
    pub server_unix: u64,
    pub redirect: Option<MovedRedirect>,
    pub heartbeat_interval_sec: u32,
}

impl SignalingRegisterResp {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        encode_pb_varint(1, self.error_code as u64, &mut out);
        encode_pb_varint(2, self.server_unix, &mut out);
        if let Some(redir) = &self.redirect {
            let redir_pb = redir.encode_pb();
            encode_pb_bytes(3, &redir_pb, &mut out);
        }
        encode_pb_varint(6, self.heartbeat_interval_sec as u64, &mut out);
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut error_code = 0u32;
        let mut server_unix = 0u64;
        let mut redirect = None;
        let mut heartbeat_interval_sec = 0u32;

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 0) => {
                    error_code = decode_u32_varint(bytes, &mut pos, "RegisterResp.error_code")?;
                }
                (2, 0) => server_unix = decode_varint(bytes, &mut pos)?,
                (3, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    redirect = Some(MovedRedirect::decode_pb(b)?);
                }
                (6, 0) => {
                    heartbeat_interval_sec =
                        decode_u32_varint(bytes, &mut pos, "RegisterResp.heartbeat_interval_sec")?;
                }
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            error_code,
            server_unix,
            redirect,
            heartbeat_interval_sec,
        })
    }
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
    pub controller_cert: Option<SignalingDeviceCert>,
    pub controller_delegation: Option<DelegationStatement>,
    pub proposed_l3_mtu: u32,
    pub cap_bits: u64,
    pub preferred_cipher_suite: u32,
    pub requested_exhaust_policy: u32,
    pub relay_ticket: Option<RelayTicketWire>,
    pub ice_candidates: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingConnectOffer {
    pub session_id: [u8; 16],
    pub controller_cert: Option<SignalingDeviceCert>,
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
    pub controlled_cert: Option<SignalingDeviceCert>,
    pub controlled_delegation: Option<DelegationStatement>,
    pub negotiated_l3_mtu: u32,
    pub negotiated_cap_bits: u64,
    pub negotiated_cipher_suite: u32,
    pub ice_candidates: Vec<String>,
    pub redirect: Option<MovedRedirect>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalingStaticKeyHint {
    pub device_id: [u8; 16],
    pub latest_delegation: DelegationStatement,
    pub hint_unix: u64,
}

impl SignalingStaticKeyHint {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(176);
        encode_pb_bytes(1, &self.device_id, &mut out);
        let deleg_pb = encode_delegation_pb(&self.latest_delegation);
        encode_pb_bytes(2, &deleg_pb, &mut out);
        encode_pb_varint(3, self.hint_unix, &mut out);
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut device_id = [0u8; 16];
        let mut latest_delegation: Option<DelegationStatement> = None;
        let mut hint_unix = 0u64;

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    device_id =
                        read_fixed_bytes::<16>(bytes, &mut pos, "StaticKeyHint.device_id")?;
                }
                (2, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    latest_delegation = Some(decode_delegation_pb(b)?);
                }
                (3, 0) => hint_unix = decode_varint(bytes, &mut pos)?,
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            device_id,
            latest_delegation: latest_delegation.ok_or_else(|| {
                ClientError::Protocol("StaticKeyHint missing latest_delegation".into())
            })?,
            hint_unix,
        })
    }
}

/// Structured peer-route candidate carried inside `ice_candidates`:
/// `v2-peer:pop_a=<pop_a>;cid_a=<hex>;pop_b=<pop_b>;cid_b=<hex>;bw_cap_kbps=<n>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRouteCandidate {
    pub pop_a: [u8; 8],
    pub cid_a: [u8; 8],
    pub pop_b: [u8; 8],
    pub cid_b: [u8; 8],
    pub bw_cap_kbps: u32,
}

impl PeerRouteCandidate {
    fn validate_pop_id<'a>(pop: &'a [u8; 8], field: &str) -> Result<&'a str, ClientError> {
        let s = std::str::from_utf8(pop).map_err(|_| {
            ClientError::Protocol(format!("peer-route {field} must be valid ASCII"))
        })?;
        if !s
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b';' && b != b'=')
        {
            return Err(ClientError::Protocol(format!(
                "peer-route {field} contains invalid characters"
            )));
        }
        Ok(s)
    }

    pub fn encode(&self) -> Result<String, ClientError> {
        if self.bw_cap_kbps == 0 {
            return Err(ClientError::Protocol(
                "peer-route bw_cap_kbps must be > 0".into(),
            ));
        }
        let pop_a_str = Self::validate_pop_id(&self.pop_a, "pop_a")?;
        let pop_b_str = Self::validate_pop_id(&self.pop_b, "pop_b")?;
        Ok(format!(
            "{PEER_ROUTE_PREFIX}pop_a={pop_a_str};cid_a={};pop_b={pop_b_str};cid_b={};bw_cap_kbps={}",
            hex::encode(self.cid_a),
            hex::encode(self.cid_b),
            self.bw_cap_kbps
        ))
    }

    pub fn parse(candidate: &str) -> Result<Self, ClientError> {
        let Some(rest) = candidate.strip_prefix(PEER_ROUTE_PREFIX) else {
            return Err(ClientError::Protocol(
                "candidate does not start with 'v2-peer:'".into(),
            ));
        };
        if rest.is_empty() {
            return Err(ClientError::Protocol("empty v2-peer candidate".into()));
        }

        let mut pop_a: Option<[u8; 8]> = None;
        let mut cid_a: Option<[u8; 8]> = None;
        let mut pop_b: Option<[u8; 8]> = None;
        let mut cid_b: Option<[u8; 8]> = None;
        let mut bw_cap_kbps: Option<u32> = None;

        for part in rest.split(';') {
            let (k, v) = part.split_once('=').ok_or_else(|| {
                ClientError::Protocol(format!("malformed v2-peer key=value token '{part}'"))
            })?;
            match k {
                "pop_a" => {
                    if pop_a.is_some() {
                        return Err(ClientError::Protocol("duplicate pop_a in v2-peer".into()));
                    }
                    pop_a = Some(parse_pop_id_str(v, "pop_a")?);
                }
                "cid_a" => {
                    if cid_a.is_some() {
                        return Err(ClientError::Protocol("duplicate cid_a in v2-peer".into()));
                    }
                    cid_a = Some(parse_cid_hex(v, "cid_a")?);
                }
                "pop_b" => {
                    if pop_b.is_some() {
                        return Err(ClientError::Protocol("duplicate pop_b in v2-peer".into()));
                    }
                    pop_b = Some(parse_pop_id_str(v, "pop_b")?);
                }
                "cid_b" => {
                    if cid_b.is_some() {
                        return Err(ClientError::Protocol("duplicate cid_b in v2-peer".into()));
                    }
                    cid_b = Some(parse_cid_hex(v, "cid_b")?);
                }
                "bw_cap_kbps" => {
                    if bw_cap_kbps.is_some() {
                        return Err(ClientError::Protocol(
                            "duplicate bw_cap_kbps in v2-peer".into(),
                        ));
                    }
                    let val: u32 = v.parse().map_err(|_| {
                        ClientError::Protocol(format!("invalid bw_cap_kbps '{v}'"))
                    })?;
                    if val == 0 {
                        return Err(ClientError::Protocol(
                            "v2-peer bw_cap_kbps must be > 0".into(),
                        ));
                    }
                    bw_cap_kbps = Some(val);
                }
                other => {
                    return Err(ClientError::Protocol(format!(
                        "unknown key '{other}' in v2-peer candidate"
                    )));
                }
            }
        }

        Ok(Self {
            pop_a: pop_a.ok_or_else(|| ClientError::Protocol("missing pop_a in v2-peer".into()))?,
            cid_a: cid_a.ok_or_else(|| ClientError::Protocol("missing cid_a in v2-peer".into()))?,
            pop_b: pop_b.ok_or_else(|| ClientError::Protocol("missing pop_b in v2-peer".into()))?,
            cid_b: cid_b.ok_or_else(|| ClientError::Protocol("missing cid_b in v2-peer".into()))?,
            bw_cap_kbps: bw_cap_kbps
                .ok_or_else(|| ClientError::Protocol("missing bw_cap_kbps in v2-peer".into()))?,
        })
    }

    pub fn find_in_candidates(candidates: &[String]) -> Result<Self, ClientError> {
        let mut found: Option<Self> = None;
        for cand in candidates {
            if cand.starts_with(PEER_ROUTE_PREFIX) {
                let parsed = Self::parse(cand)?;
                if found.is_some() {
                    return Err(ClientError::Protocol(
                        "multiple v2-peer route candidates present".into(),
                    ));
                }
                found = Some(parsed);
            }
        }
        found.ok_or_else(|| {
            ClientError::Protocol("missing v2-peer route candidate in ice_candidates".into())
        })
    }
}

fn parse_pop_id_str(v: &str, field: &str) -> Result<[u8; 8], ClientError> {
    let raw = v.as_bytes();
    if raw.len() != 8
        || !raw
            .iter()
            .all(|&b| b.is_ascii_graphic() && b != b';' && b != b'=')
    {
        return Err(ClientError::Protocol(format!(
            "v2-peer {field} must be exactly 8 printable ASCII bytes"
        )));
    }
    let mut arr = [0u8; 8];
    arr.copy_from_slice(raw);
    Ok(arr)
}

fn parse_cid_hex(v: &str, field: &str) -> Result<[u8; 8], ClientError> {
    if v.len() != 16 {
        return Err(ClientError::Protocol(format!(
            "v2-peer {field} must be 16 hex characters"
        )));
    }
    let bytes = hex::decode(v)
        .map_err(|_| ClientError::Protocol(format!("v2-peer {field} invalid hex")))?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(&bytes);
    Ok(arr)
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

fn read_u64_be(slice: &[u8]) -> u64 {
    u64::from_be_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ])
}

/// Minimal clean-room Protobuf3 varint/field primitives matching `proto/v2/*.proto`.
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
            return Err(ClientError::Protocol(
                "truncated or overflowed protobuf varint".into(),
            ));
        }
        let b = bytes[*pos];
        *pos += 1;
        if shift == 63 && (b & 0xFE) != 0 {
            return Err(ClientError::Protocol("overflowed 64-bit protobuf varint".into()));
        }
        val |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Ok(val);
        }
        shift += 7;
    }
}

fn decode_u32_varint(bytes: &[u8], pos: &mut usize, field: &str) -> Result<u32, ClientError> {
    let v = decode_varint(bytes, pos)?;
    u32::try_from(v).map_err(|_| ClientError::Protocol(format!("{field} overflows uint32: {v}")))
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
    let len = usize::try_from(decode_varint(bytes, pos)?)
        .map_err(|_| ClientError::Protocol("protobuf bytes length overflows usize".into()))?;
    if len > bytes.len().saturating_sub(*pos) {
        return Err(ClientError::Protocol("truncated protobuf bytes field".into()));
    }
    let slice = &bytes[*pos..*pos + len];
    *pos += len;
    Ok(slice)
}

fn read_fixed_bytes<const N: usize>(
    bytes: &[u8],
    pos: &mut usize,
    field: &str,
) -> Result<[u8; N], ClientError> {
    let b = read_pb_bytes(bytes, pos)?;
    if b.len() != N {
        return Err(ClientError::Protocol(format!(
            "{field} must be {N}B, got {}B",
            b.len()
        )));
    }
    let mut arr = [0u8; N];
    arr.copy_from_slice(b);
    Ok(arr)
}

fn skip_pb_field(wire_type: u64, bytes: &[u8], pos: &mut usize) -> Result<(), ClientError> {
    match wire_type {
        0 => {
            let _ = decode_varint(bytes, pos)?;
            Ok(())
        }
        1 => {
            if bytes.len().saturating_sub(*pos) < 8 {
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
            if bytes.len().saturating_sub(*pos) < 4 {
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
                    device_id = read_fixed_bytes::<16>(bytes, &mut pos, "Heartbeat.device_id")?;
                }
                (2, 0) => {
                    let raw = decode_u32_varint(bytes, &mut pos, "Heartbeat.presence")?;
                    presence = PresenceState::from_u32(raw);
                }
                (3, 0) => client_unix = decode_varint(bytes, &mut pos)?,
                (4, 2) => {
                    active_pop_id = Some(read_fixed_bytes::<8>(
                        bytes,
                        &mut pos,
                        "Heartbeat.active_pop_id",
                    )?);
                }
                (5, 0) => rtt_ms = decode_u32_varint(bytes, &mut pos, "Heartbeat.rtt_ms")?,
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
        let mut out = Vec::with_capacity(512);
        encode_pb_bytes(1, &self.session_id, &mut out);
        encode_pb_bytes(2, &self.controller_device_id, &mut out);
        encode_pb_bytes(3, &self.controlled_device_id, &mut out);
        if let Some(cert) = &self.controller_cert {
            let pb = cert.encode_pb();
            encode_pb_bytes(4, &pb, &mut out);
        }
        if let Some(deleg) = &self.controller_delegation {
            let pb = encode_delegation_pb(deleg);
            encode_pb_bytes(5, &pb, &mut out);
        }
        encode_pb_varint(6, self.proposed_l3_mtu as u64, &mut out);
        encode_pb_varint(7, self.cap_bits, &mut out);
        encode_pb_varint(8, self.preferred_cipher_suite as u64, &mut out);
        encode_pb_varint(9, self.requested_exhaust_policy as u64, &mut out);
        if let Some(ticket) = &self.relay_ticket {
            let pb = ticket.encode_pb();
            encode_pb_bytes(10, &pb, &mut out);
        }
        for cand in &self.ice_candidates {
            encode_pb_bytes(11, cand.as_bytes(), &mut out);
        }
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut session_id = [0u8; 16];
        let mut controller_device_id = [0u8; 16];
        let mut controlled_device_id = [0u8; 16];
        let mut controller_cert = None;
        let mut controller_delegation = None;
        let mut proposed_l3_mtu = 0u32;
        let mut cap_bits = 0u64;
        let mut preferred_cipher_suite = 0u32;
        let mut requested_exhaust_policy = 0u32;
        let mut relay_ticket = None;
        let mut ice_candidates = Vec::new();

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    session_id = read_fixed_bytes::<16>(bytes, &mut pos, "ConnectReq.session_id")?;
                }
                (2, 2) => {
                    controller_device_id = read_fixed_bytes::<16>(
                        bytes,
                        &mut pos,
                        "ConnectReq.controller_device_id",
                    )?;
                }
                (3, 2) => {
                    controlled_device_id = read_fixed_bytes::<16>(
                        bytes,
                        &mut pos,
                        "ConnectReq.controlled_device_id",
                    )?;
                }
                (4, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    controller_cert = Some(SignalingDeviceCert::decode_pb(b)?);
                }
                (5, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    controller_delegation = Some(decode_delegation_pb(b)?);
                }
                (6, 0) => {
                    proposed_l3_mtu =
                        decode_u32_varint(bytes, &mut pos, "ConnectReq.proposed_l3_mtu")?;
                }
                (7, 0) => cap_bits = decode_varint(bytes, &mut pos)?,
                (8, 0) => {
                    preferred_cipher_suite =
                        decode_u32_varint(bytes, &mut pos, "ConnectReq.preferred_cipher_suite")?;
                }
                (9, 0) => {
                    requested_exhaust_policy =
                        decode_u32_varint(bytes, &mut pos, "ConnectReq.requested_exhaust_policy")?;
                }
                (10, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    relay_ticket = Some(RelayTicketWire::decode_pb(b)?);
                }
                (11, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    let s = std::str::from_utf8(b).map_err(|_| {
                        ClientError::Protocol("ConnectReq non-UTF8 ICE candidate".into())
                    })?;
                    ice_candidates.push(s.to_string());
                }
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            session_id,
            controller_device_id,
            controlled_device_id,
            controller_cert,
            controller_delegation,
            proposed_l3_mtu,
            cap_bits,
            preferred_cipher_suite,
            requested_exhaust_policy,
            relay_ticket,
            ice_candidates,
        })
    }
}

impl SignalingConnectOffer {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(512);
        encode_pb_bytes(1, &self.session_id, &mut out);
        if let Some(cert) = &self.controller_cert {
            let pb = cert.encode_pb();
            encode_pb_bytes(2, &pb, &mut out);
        }
        if let Some(deleg) = &self.controller_delegation {
            let pb = encode_delegation_pb(deleg);
            encode_pb_bytes(3, &pb, &mut out);
        }
        if let Some(ticket) = &self.relay_ticket {
            let pb = ticket.encode_pb();
            encode_pb_bytes(4, &pb, &mut out);
        }
        encode_pb_varint(6, self.proposed_l3_mtu as u64, &mut out);
        encode_pb_varint(7, self.controller_cap_bits, &mut out);
        for cand in &self.ice_candidates {
            encode_pb_bytes(8, cand.as_bytes(), &mut out);
        }
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut session_id = [0u8; 16];
        let mut controller_cert = None;
        let mut controller_delegation = None;
        let mut relay_ticket = None;
        let mut proposed_l3_mtu = 0u32;
        let mut controller_cap_bits = 0u64;
        let mut ice_candidates = Vec::new();

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    session_id =
                        read_fixed_bytes::<16>(bytes, &mut pos, "ConnectOffer.session_id")?;
                }
                (2, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    controller_cert = Some(SignalingDeviceCert::decode_pb(b)?);
                }
                (3, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    controller_delegation = Some(decode_delegation_pb(b)?);
                }
                (4, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    relay_ticket = Some(RelayTicketWire::decode_pb(b)?);
                }
                (6, 0) => {
                    proposed_l3_mtu =
                        decode_u32_varint(bytes, &mut pos, "ConnectOffer.proposed_l3_mtu")?;
                }
                (7, 0) => controller_cap_bits = decode_varint(bytes, &mut pos)?,
                (8, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    let s = std::str::from_utf8(b).map_err(|_| {
                        ClientError::Protocol("ConnectOffer non-UTF8 ICE candidate".into())
                    })?;
                    ice_candidates.push(s.to_string());
                }
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            session_id,
            controller_cert,
            controller_delegation,
            relay_ticket,
            proposed_l3_mtu,
            controller_cap_bits,
            ice_candidates,
        })
    }
}

impl SignalingConnectAccept {
    pub fn encode_pb(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(420);
        encode_pb_bytes(1, &self.session_id, &mut out);
        encode_pb_varint(2, self.error_code as u64, &mut out);
        if let Some(cert) = &self.controlled_cert {
            let pb = cert.encode_pb();
            encode_pb_bytes(3, &pb, &mut out);
        }
        if let Some(deleg) = &self.controlled_delegation {
            let pb = encode_delegation_pb(deleg);
            encode_pb_bytes(4, &pb, &mut out);
        }
        encode_pb_varint(5, self.negotiated_l3_mtu as u64, &mut out);
        encode_pb_varint(6, self.negotiated_cap_bits, &mut out);
        encode_pb_varint(7, self.negotiated_cipher_suite as u64, &mut out);
        for cand in &self.ice_candidates {
            encode_pb_bytes(8, cand.as_bytes(), &mut out);
        }
        if let Some(redir) = &self.redirect {
            let pb = redir.encode_pb();
            encode_pb_bytes(9, &pb, &mut out);
        }
        out
    }

    pub fn decode_pb(bytes: &[u8]) -> Result<Self, ClientError> {
        let mut pos = 0;
        let mut session_id = [0u8; 16];
        let mut error_code = 0u32;
        let mut controlled_cert = None;
        let mut controlled_delegation = None;
        let mut negotiated_l3_mtu = 0u32;
        let mut negotiated_cap_bits = 0u64;
        let mut negotiated_cipher_suite = 0u32;
        let mut ice_candidates = Vec::new();
        let mut redirect = None;

        while pos < bytes.len() {
            let tag = decode_varint(bytes, &mut pos)?;
            let field_no = (tag >> 3) as u32;
            let wire_type = tag & 0x07;
            match (field_no, wire_type) {
                (1, 2) => {
                    session_id =
                        read_fixed_bytes::<16>(bytes, &mut pos, "ConnectAccept.session_id")?;
                }
                (2, 0) => {
                    error_code = decode_u32_varint(bytes, &mut pos, "ConnectAccept.error_code")?;
                }
                (3, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    controlled_cert = Some(SignalingDeviceCert::decode_pb(b)?);
                }
                (4, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    controlled_delegation = Some(decode_delegation_pb(b)?);
                }
                (5, 0) => {
                    negotiated_l3_mtu =
                        decode_u32_varint(bytes, &mut pos, "ConnectAccept.negotiated_l3_mtu")?;
                }
                (6, 0) => negotiated_cap_bits = decode_varint(bytes, &mut pos)?,
                (7, 0) => {
                    negotiated_cipher_suite = decode_u32_varint(
                        bytes,
                        &mut pos,
                        "ConnectAccept.negotiated_cipher_suite",
                    )?;
                }
                (8, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    let s = std::str::from_utf8(b)
                        .map_err(|_| ClientError::Protocol("non-UTF8 ICE candidate".into()))?;
                    ice_candidates.push(s.to_string());
                }
                (9, 2) => {
                    let b = read_pb_bytes(bytes, &mut pos)?;
                    redirect = Some(MovedRedirect::decode_pb(b)?);
                }
                _ => skip_pb_field(wire_type, bytes, &mut pos)?,
            }
        }
        Ok(Self {
            session_id,
            error_code,
            controlled_cert,
            controlled_delegation,
            negotiated_l3_mtu,
            negotiated_cap_bits,
            negotiated_cipher_suite,
            ice_candidates,
            redirect,
        })
    }
}

pub fn encode_signaling_frame(
    kind: SignalingMsgKind,
    payload: &[u8],
) -> Result<Vec<u8>, ClientError> {
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

/// Exponential reconnect backoff starting at 500ms, doubling with jitter, capped at 30s.
#[derive(Debug, Clone)]
pub struct SignalingReconnectBackoff {
    attempt: u32,
    initial_ms: u64,
    max_ms: u64,
}

impl Default for SignalingReconnectBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl SignalingReconnectBackoff {
    pub fn new() -> Self {
        Self {
            attempt: 0,
            initial_ms: SIGNALING_BACKOFF_INITIAL_MS,
            max_ms: SIGNALING_BACKOFF_MAX_MS,
        }
    }

    pub fn reset(&mut self) {
        self.attempt = 0;
    }

    pub fn attempts(&self) -> u32 {
        self.attempt
    }

    pub fn next_delay(&mut self) -> Duration {
        let sample = OsRng.next_u64();
        self.next_delay_deterministic(sample)
    }

    /// Computes the next delay using a caller-provided jitter sample (`[0.8x, 1.2x]` bounded by `max_ms`).
    pub fn next_delay_deterministic(&mut self, jitter_sample: u64) -> Duration {
        let shift = self.attempt.min(16);
        let base_ms = self
            .initial_ms
            .saturating_mul(1u64 << shift)
            .min(self.max_ms);
        self.attempt = self.attempt.saturating_add(1);
        // Apply +/-20% jitter centered on base_ms, clamped to [initial_ms/2, max_ms].
        let jitter_span = (base_ms / 5).max(1);
        let offset = jitter_sample % (jitter_span.saturating_mul(2).saturating_add(1));
        let jittered = base_ms
            .saturating_sub(jitter_span)
            .saturating_add(offset)
            .clamp(self.initial_ms / 2, self.max_ms);
        Duration::from_millis(jittered)
    }
}

/// Persistent async framed signaling session over a single live TCP connection.
/// Uses an internal receive buffer so `recv_frame(timeout)` is cancel-safe across timeouts.
pub struct SignalingSession {
    reader: OwnedReadHalf,
    writer: OwnedWriteHalf,
    read_buf: Vec<u8>,
    peer_addr: SocketAddr,
}

impl SignalingSession {
    pub async fn connect_and_register(
        addr: &str,
        req: &SignalingRegisterReq,
        timeout: Duration,
    ) -> Result<(Self, SignalingRegisterResp), ClientError> {
        let deadline = Instant::now() + timeout;
        let stream = tokio::time::timeout(timeout, TcpStream::connect(addr))
            .await
            .map_err(|_| {
                ClientError::Timeout(format!("signaling TCP connect to {addr} timed out"))
            })??;
        let _ = stream.set_nodelay(true);
        let peer_addr = stream.peer_addr()?;
        let (reader, writer) = stream.into_split();
        let mut session = Self {
            reader,
            writer,
            read_buf: Vec::with_capacity(4096),
            peer_addr,
        };

        let reg_payload = req.encode_pb();
        let write_rem = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| ClientError::Timeout("signaling RegisterReq timed out".into()))?;
        tokio::time::timeout(
            write_rem,
            session.send_frame(SignalingMsgKind::RegisterReq, &reg_payload),
        )
        .await
        .map_err(|_| ClientError::Timeout("signaling RegisterReq write timed out".into()))??;

        let read_rem = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| ClientError::Timeout("signaling RegisterResp timed out".into()))?;
        let (kind, payload) = session.recv_frame(read_rem).await?;
        if kind != SignalingMsgKind::RegisterResp {
            return Err(ClientError::Protocol(format!(
                "expected RegisterResp (0x02), got {kind:?}"
            )));
        }
        let resp = SignalingRegisterResp::decode_pb(&payload)?;
        if resp.error_code != 0 && resp.redirect.is_none() {
            return Err(ClientError::Protocol(format!(
                "signaling registration rejected with error_code={:#06x}",
                resp.error_code
            )));
        }
        Ok((session, resp))
    }

    pub fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }

    pub async fn send_frame(
        &mut self,
        kind: SignalingMsgKind,
        payload: &[u8],
    ) -> Result<(), ClientError> {
        let frame = encode_signaling_frame(kind, payload)?;
        self.writer.write_all(&frame).await?;
        self.writer.flush().await?;
        Ok(())
    }

    pub async fn send_heartbeat(&mut self, hb: &HeartbeatMsg) -> Result<(), ClientError> {
        self.send_frame(SignalingMsgKind::Heartbeat, &hb.encode_pb())
            .await
    }

    pub async fn send_connect_req(&mut self, req: &SignalingConnectReq) -> Result<(), ClientError> {
        self.send_frame(SignalingMsgKind::ConnectReq, &req.encode_pb())
            .await
    }

    pub async fn send_connect_accept(
        &mut self,
        acc: &SignalingConnectAccept,
    ) -> Result<(), ClientError> {
        self.send_frame(SignalingMsgKind::ConnectAccept, &acc.encode_pb())
            .await
    }

    pub async fn send_static_key_hint(
        &mut self,
        hint: &SignalingStaticKeyHint,
    ) -> Result<(), ClientError> {
        self.send_frame(SignalingMsgKind::StaticKeyHint, &hint.encode_pb())
            .await
    }

    fn try_pop_buffered_frame(&mut self) -> Result<Option<(SignalingMsgKind, Vec<u8>)>, ClientError> {
        if self.read_buf.len() < 4 {
            return Ok(None);
        }
        let total = u32::from_be_bytes([
            self.read_buf[0],
            self.read_buf[1],
            self.read_buf[2],
            self.read_buf[3],
        ]) as usize;
        if total == 0 || total > MAX_SIGNALING_FRAME_BYTES {
            self.read_buf.clear();
            return Err(ClientError::Protocol(format!(
                "invalid signaling frame length {total} (must be 1..={MAX_SIGNALING_FRAME_BYTES})"
            )));
        }
        let full_len = 4 + total;
        if self.read_buf.len() < full_len {
            return Ok(None);
        }
        let kind = SignalingMsgKind::from_u8(self.read_buf[4])?;
        let payload = self.read_buf[5..full_len].to_vec();
        self.read_buf.drain(..full_len);
        Ok(Some((kind, payload)))
    }

    /// Reads the next length-prefixed signaling frame within `timeout`.
    /// Cancel-safe: partial reads remain buffered in `self.read_buf` on timeout.
    pub async fn recv_frame(
        &mut self,
        timeout: Duration,
    ) -> Result<(SignalingMsgKind, Vec<u8>), ClientError> {
        if let Some(frame) = self.try_pop_buffered_frame()? {
            return Ok(frame);
        }
        let deadline = Instant::now() + timeout;
        let mut tmp = [0u8; 4096];
        loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("signaling recv_frame timed out".into()));
            };
            let n = tokio::time::timeout(rem, self.reader.read(&mut tmp))
                .await
                .map_err(|_| ClientError::Timeout("signaling recv_frame timed out".into()))??;
            if n == 0 {
                return Err(ClientError::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "signaling server closed connection",
                )));
            }
            if self.read_buf.len() + n > (MAX_SIGNALING_FRAME_BYTES + 4) * 2 {
                self.read_buf.clear();
                return Err(ClientError::Protocol(
                    "signaling receive buffer overflow".into(),
                ));
            }
            self.read_buf.extend_from_slice(&tmp[..n]);
            if let Some(frame) = self.try_pop_buffered_frame()? {
                return Ok(frame);
            }
        }
    }

    pub async fn shutdown(&mut self) -> Result<(), ClientError> {
        self.writer.shutdown().await?;
        Ok(())
    }
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

    pub fn addr(&self) -> &str {
        &self.addr
    }

    pub async fn connect_and_register(
        &self,
        req: &SignalingRegisterReq,
    ) -> Result<(SignalingSession, SignalingRegisterResp), ClientError> {
        SignalingSession::connect_and_register(&self.addr, req, self.timeout).await
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

    /// Sends a length-prefixed signaling frame and reads one response frame.
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
                return Err(ClientError::Protocol(
                    "invalid signaling response frame length".into(),
                ));
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use tokio::net::TcpListener;
    use v2_identity::{DeviceKeyStore, SoftwareDeviceKeyStore, X25519StaticKeyRotator};

    fn make_signed_cert_and_deleg() -> (
        SoftwareDeviceKeyStore,
        SignalingDeviceCert,
        DelegationStatement,
        Vec<u8>,
    ) {
        let ca = SoftwareDeviceKeyStore::generate();
        let ca_spki = ca.public_key_spki_der().unwrap();
        let dev = SoftwareDeviceKeyStore::generate();
        let dev_spki = dev.public_key_spki_der().unwrap();
        let device_id = [0x11u8; 16];
        let tenant_id = [0x22u8; 16];
        let cert_id = [0x33u8; 16];
        let mut cert = SignalingDeviceCert {
            version: 1,
            cert_id,
            device_id,
            tenant_id,
            p256_pub_der: dev_spki,
            key_epoch: 2,
            policy_hash: [0x44u8; 32],
            cap_bits: 0x3FFF,
            iat_unix: 1_700_000_000,
            exp_unix: 1_700_021_600,
            ca_key_id: 7,
            ca_sig: Vec::new(),
        };
        let tbs = cert.to_tbs_bytes().unwrap();
        cert.ca_sig = ca.sign_p256_low_s(&tbs).unwrap();
        let mut rot = X25519StaticKeyRotator::new(device_id, true, 5);
        let gen = rot
            .ensure_current(&dev, 1_700_000_100, cert.exp_unix)
            .unwrap();
        (dev, cert, gen.delegation.clone(), ca_spki)
    }

    #[test]
    fn device_cert_delegation_ticket_redirect_and_signaling_pb_roundtrips() {
        let (_dev, cert, deleg, ca_spki) = make_signed_cert_and_deleg();

        // DeviceCert roundtrip + verify + from_register_resp
        let cert_pb = cert.encode_pb();
        let cert_dec = SignalingDeviceCert::decode_pb(&cert_pb).unwrap();
        assert_eq!(cert_dec, cert);
        cert_dec.verify(&ca_spki, 1_700_000_100).unwrap();

        let tbs = cert.to_tbs_bytes().unwrap();
        let reg_resp = RegisterDeviceResp {
            cert_id_hex: hex::encode(cert.cert_id),
            key_epoch: cert.key_epoch,
            iat_unix: cert.iat_unix,
            exp_unix: cert.exp_unix,
            tbs_b64: B64.encode(&tbs),
            sig_der_b64: B64.encode(&cert.ca_sig),
        };
        let cert_from_resp = SignalingDeviceCert::from_register_resp(&reg_resp).unwrap();
        assert_eq!(cert_from_resp.to_tbs_bytes().unwrap(), tbs);
        assert_eq!(cert_from_resp.device_id, cert.device_id);
        assert_eq!(cert_from_resp.tenant_id, cert.tenant_id);
        cert_from_resp.verify(&ca_spki, 1_700_000_100).unwrap();

        // DelegationStatement roundtrip
        let deleg_dec = decode_delegation_pb(&encode_delegation_pb(&deleg)).unwrap();
        assert_eq!(deleg_dec, deleg);

        // RelayTicketWire roundtrip
        let ticket = RelayTicketWire {
            key_id: 3,
            body: vec![0x01, 0x02, 0x03, 0x04],
            mac: [0xABu8; 32],
        };
        assert_eq!(
            RelayTicketWire::decode_pb(&ticket.encode_pb()).unwrap(),
            ticket
        );

        // MovedRedirect roundtrip
        let redirect = MovedRedirect {
            target_home_region: "ap-east-1".into(),
            target_pop_id: *b"edge-b02",
            routing_cas_ver: 99,
            retry_after_ms: 2500,
        };
        assert_eq!(
            MovedRedirect::decode_pb(&redirect.encode_pb()).unwrap(),
            redirect
        );

        // RegisterReq / RegisterResp roundtrip
        let reg_req = SignalingRegisterReq {
            device_cert: cert.clone(),
            delegation: deleg.clone(),
            presence: PresenceState::Online,
            cap_bits: 0x1_2345,
            home_region: "local".into(),
            ver_major: 2,
            ver_minor: 1,
        };
        assert_eq!(
            SignalingRegisterReq::decode_pb(&reg_req.encode_pb()).unwrap(),
            reg_req
        );

        let sig_reg_resp = SignalingRegisterResp {
            error_code: 0,
            server_unix: 1_700_000_123,
            redirect: Some(redirect.clone()),
            heartbeat_interval_sec: 15,
        };
        assert_eq!(
            SignalingRegisterResp::decode_pb(&sig_reg_resp.encode_pb()).unwrap(),
            sig_reg_resp
        );

        // PeerRouteCandidate strict encode/decode
        let peer_route = PeerRouteCandidate {
            pop_a: *b"edge-a01",
            cid_a: [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef],
            pop_b: *b"edge-b02",
            cid_b: [0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10],
            bw_cap_kbps: 50_000,
        };
        let encoded_route = peer_route.encode().unwrap();
        assert_eq!(
            encoded_route,
            "v2-peer:pop_a=edge-a01;cid_a=0123456789abcdef;pop_b=edge-b02;cid_b=fedcba9876543210;bw_cap_kbps=50000"
        );
        assert_eq!(PeerRouteCandidate::parse(&encoded_route).unwrap(), peer_route);

        // ConnectReq / ConnectOffer / ConnectAccept / StaticKeyHint roundtrips
        let conn_req = SignalingConnectReq {
            session_id: [0x77; 16],
            controller_device_id: [0x11; 16],
            controlled_device_id: [0x22; 16],
            controller_cert: Some(cert.clone()),
            controller_delegation: Some(deleg.clone()),
            proposed_l3_mtu: 1200,
            cap_bits: 0x3FFF,
            preferred_cipher_suite: 1,
            requested_exhaust_policy: 0,
            relay_ticket: Some(ticket.clone()),
            ice_candidates: vec![encoded_route.clone()],
        };
        assert_eq!(
            SignalingConnectReq::decode_pb(&conn_req.encode_pb()).unwrap(),
            conn_req
        );

        let offer = SignalingConnectOffer {
            session_id: [0x77; 16],
            controller_cert: Some(cert.clone()),
            controller_delegation: Some(deleg.clone()),
            relay_ticket: Some(ticket),
            proposed_l3_mtu: 1200,
            controller_cap_bits: 0x3FFF,
            ice_candidates: vec![encoded_route.clone()],
        };
        assert_eq!(
            SignalingConnectOffer::decode_pb(&offer.encode_pb()).unwrap(),
            offer
        );

        let accept = SignalingConnectAccept {
            session_id: [0x77; 16],
            error_code: 0,
            controlled_cert: Some(cert),
            controlled_delegation: Some(deleg.clone()),
            negotiated_l3_mtu: 1200,
            negotiated_cap_bits: 0x3FFF,
            negotiated_cipher_suite: 1,
            ice_candidates: vec![encoded_route],
            redirect: Some(redirect),
        };
        assert_eq!(
            SignalingConnectAccept::decode_pb(&accept.encode_pb()).unwrap(),
            accept
        );

        let hint = SignalingStaticKeyHint {
            device_id: [0x11; 16],
            latest_delegation: deleg,
            hint_unix: 1_700_000_200,
        };
        assert_eq!(
            SignalingStaticKeyHint::decode_pb(&hint.encode_pb()).unwrap(),
            hint
        );
    }

    #[test]
    fn malformed_frames_and_peer_route_candidates_fail_closed() {
        // Frame bounds and truncation
        assert!(decode_signaling_frame(&[]).is_err());
        assert!(decode_signaling_frame(&[0, 0, 0, 0, 1]).is_err());
        assert!(decode_signaling_frame(&[0, 1, 0, 1, 1]).is_err()); // > 65536
        assert!(decode_signaling_frame(&[0, 0, 0, 2, 0xFF, 0x00]).is_err()); // unknown kind
        assert!(encode_signaling_frame(SignalingMsgKind::Heartbeat, &vec![0u8; 65536]).is_err());

        // Truncated protobufs
        assert!(SignalingDeviceCert::decode_pb(&[0x12, 0x10, 0x01, 0x02]).is_err());
        assert!(SignalingDeviceCert::decode_pb(&[0x12, 0x04, 1, 2, 3, 4]).is_err()); // cert_id != 16B
        assert!(decode_delegation_pb(&[0x18, 0x02]).is_err()); // bool = 2
        assert!(RelayTicketWire::decode_pb(&[0x08, 0x01]).is_err()); // missing body & mac
        assert!(SignalingRegisterReq::decode_pb(&[]).is_err()); // missing cert & deleg

        // Invalid peer-route candidates
        for bad in [
            "wrong:pop_a=edge-a01;cid_a=0123456789abcdef;pop_b=edge-b02;cid_b=fedcba9876543210;bw_cap_kbps=100",
            "v2-peer:pop_a=short;cid_a=0123456789abcdef;pop_b=edge-b02;cid_b=fedcba9876543210;bw_cap_kbps=100",
            "v2-peer:pop_a=edge-a01;cid_a=0123;pop_b=edge-b02;cid_b=fedcba9876543210;bw_cap_kbps=100",
            "v2-peer:pop_a=edge-a01;cid_a=0123456789abcdef;pop_b=edge-b02;cid_b=fedcba9876543210;bw_cap_kbps=0",
            "v2-peer:pop_a=edge-a01;cid_a=0123456789abcdef;pop_b=edge-b02;cid_b=fedcba9876543210;bw_cap_kbps=100;extra=1",
            "v2-peer:pop_a=edge-a01;pop_a=edge-a01;cid_a=0123456789abcdef;pop_b=edge-b02;cid_b=fedcba9876543210;bw_cap_kbps=100",
        ] {
            assert!(
                PeerRouteCandidate::parse(bad).is_err(),
                "expected error for malformed candidate: {bad}"
            );
        }
    }

    #[test]
    fn signaling_reconnect_backoff_doubles_with_jitter_and_caps_at_30s() {
        let mut backoff = SignalingReconnectBackoff::new();
        let d0 = backoff.next_delay_deterministic(0);
        assert!(d0 >= Duration::from_millis(400) && d0 <= Duration::from_millis(600));
        let d1 = backoff.next_delay_deterministic(u64::MAX);
        assert!(d1 >= Duration::from_millis(800) && d1 <= Duration::from_millis(1200));
        for _ in 0..10 {
            let d = backoff.next_delay_deterministic(12345);
            assert!(d <= Duration::from_millis(SIGNALING_BACKOFF_MAX_MS));
        }
        assert!(backoff.attempts() >= 12);
        backoff.reset();
        assert_eq!(backoff.attempts(), 0);
    }

    #[tokio::test]
    async fn signaling_session_register_heartbeat_offer_accept_and_error_reject() {
        let (_dev, cert, deleg, _ca_spki) = make_signed_cert_and_deleg();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let srv = tokio::spawn(async move {
            // Conn 1: succeeds and exchanges Heartbeat -> ConnectOffer -> ConnectAccept
            let (mut s1, _) = listener.accept().await.unwrap();
            let mut len_buf = [0u8; 4];
            s1.read_exact(&mut len_buf).await.unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total];
            s1.read_exact(&mut body).await.unwrap();
            assert_eq!(body[0], SignalingMsgKind::RegisterReq as u8);
            let reg_req = SignalingRegisterReq::decode_pb(&body[1..]).unwrap();

            let resp = SignalingRegisterResp {
                error_code: 0,
                server_unix: 1_700_000_200,
                redirect: None,
                heartbeat_interval_sec: 15,
            };
            let f = encode_signaling_frame(SignalingMsgKind::RegisterResp, &resp.encode_pb())
                .unwrap();
            s1.write_all(&f).await.unwrap();

            // Read Heartbeat
            s1.read_exact(&mut len_buf).await.unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut hb_body = vec![0u8; total];
            s1.read_exact(&mut hb_body).await.unwrap();
            assert_eq!(hb_body[0], SignalingMsgKind::Heartbeat as u8);

            // Send ConnectOffer in 2 split TCP chunks to test cancel-safe buffering
            let offer = SignalingConnectOffer {
                session_id: [0x99; 16],
                controller_cert: Some(reg_req.device_cert),
                controller_delegation: Some(reg_req.delegation),
                relay_ticket: None,
                proposed_l3_mtu: 1200,
                controller_cap_bits: 0x3FFF,
                ice_candidates: vec![],
            };
            let offer_wire =
                encode_signaling_frame(SignalingMsgKind::ConnectOffer, &offer.encode_pb()).unwrap();
            s1.write_all(&offer_wire[..7]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(20)).await;
            s1.write_all(&offer_wire[7..]).await.unwrap();
            s1.flush().await.unwrap();

            // Read ConnectAccept
            s1.read_exact(&mut len_buf).await.unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut acc_body = vec![0u8; total];
            s1.read_exact(&mut acc_body).await.unwrap();
            assert_eq!(acc_body[0], SignalingMsgKind::ConnectAccept as u8);
            let acc = SignalingConnectAccept::decode_pb(&acc_body[1..]).unwrap();
            assert_eq!(acc.session_id, [0x99; 16]);

            // Conn 2: non-zero error_code without redirect MUST be rejected by connect_and_register
            let (mut s2, _) = listener.accept().await.unwrap();
            s2.read_exact(&mut len_buf).await.unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut b2 = vec![0u8; total];
            s2.read_exact(&mut b2).await.unwrap();
            let err_resp = SignalingRegisterResp {
                error_code: 0x0401,
                server_unix: 1_700_000_201,
                redirect: None,
                heartbeat_interval_sec: 15,
            };
            let f2 = encode_signaling_frame(SignalingMsgKind::RegisterResp, &err_resp.encode_pb())
                .unwrap();
            s2.write_all(&f2).await.unwrap();
        });

        let reg_req = SignalingRegisterReq {
            device_cert: cert.clone(),
            delegation: deleg.clone(),
            presence: PresenceState::Online,
            cap_bits: 0x3FFF,
            home_region: "local".into(),
            ver_major: 2,
            ver_minor: 1,
        };

        let (mut sess, resp) =
            SignalingSession::connect_and_register(&addr.to_string(), &reg_req, Duration::from_secs(2))
                .await
                .unwrap();
        assert_eq!(resp.error_code, 0);
        assert_eq!(resp.heartbeat_interval_sec, 15);

        sess.send_heartbeat(&HeartbeatMsg {
            device_id: cert.device_id,
            presence: PresenceState::Online,
            client_unix: 1_700_000_200,
            active_pop_id: None,
            rtt_ms: 1,
        })
        .await
        .unwrap();

        // First call with tiny timeout may time out mid-chunk; second call MUST still assemble cleanly!
        let (kind, payload) = match sess.recv_frame(Duration::from_millis(5)).await {
            Ok(v) => v,
            Err(ClientError::Timeout(_)) => sess.recv_frame(Duration::from_secs(2)).await.unwrap(),
            Err(e) => panic!("unexpected recv_frame error: {e}"),
        };
        assert_eq!(kind, SignalingMsgKind::ConnectOffer);
        let offer = SignalingConnectOffer::decode_pb(&payload).unwrap();
        assert_eq!(offer.session_id, [0x99; 16]);

        sess.send_connect_accept(&SignalingConnectAccept {
            session_id: offer.session_id,
            error_code: 0,
            controlled_cert: Some(cert),
            controlled_delegation: Some(deleg),
            negotiated_l3_mtu: 1200,
            negotiated_cap_bits: 0x3FFF,
            negotiated_cipher_suite: 1,
            ice_candidates: vec![],
            redirect: None,
        })
        .await
        .unwrap();

        // Conn 2 must fail closed on non-zero error_code without redirect
        let rej = SignalingSession::connect_and_register(
            &addr.to_string(),
            &reg_req,
            Duration::from_secs(2),
        )
        .await;
        assert!(rej.is_err());

        srv.await.unwrap();
    }
}
