use crate::{control_plane::RelayTicketWire, error::ClientError};
use snow::{params::NoiseParams, Builder, TransportState};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use v2_transport::{
    derive_access_key, DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT, TRANSPORT_DATAGRAM, TRANSPORT_STREAM,
};
use zeroize::Zeroizing;

pub const ACCESS_IK_PATTERN: &str = "Noise_IK_25519_AESGCM_SHA256";
pub const ACCESS_PROLOGUE_PREFIX: &[u8; 15] = b"V2-ACCESS-IK-v1";
pub const ACCESS_PROLOGUE_LEN: usize = 15 + 8 + 32; // 55 bytes
pub const MAX_CTRL_FRAME_LEN: usize = 16_384;

pub const CTRL_OP_RELAY_BIND_REQ: u8 = 0x01;
pub const CTRL_OP_RELAY_BIND_RESP: u8 = 0x81;
pub const CTRL_OP_LEASE_RENEW_REQ: u8 = 0x02;
pub const CTRL_OP_LEASE_RENEW_RESP: u8 = 0x82;
pub const CTRL_OP_REBIND_REQ: u8 = 0x03;
pub const CTRL_OP_REBIND_RESP: u8 = 0x83;

/// Builds the exact 55-byte Noise_IK access prologue:
/// `b"V2-ACCESS-IK-v1" || pop_id[8] || edge_cert_hash[32]`.
pub fn build_access_prologue(
    pop_id: &[u8; 8],
    edge_cert_hash: &[u8; 32],
) -> [u8; ACCESS_PROLOGUE_LEN] {
    let mut out = [0u8; ACCESS_PROLOGUE_LEN];
    out[0..15].copy_from_slice(ACCESS_PROLOGUE_PREFIX);
    out[15..23].copy_from_slice(pop_id);
    out[23..55].copy_from_slice(edge_cert_hash);
    out
}

pub fn encode_ticket_wire(ticket: &RelayTicketWire) -> Result<Vec<u8>, ClientError> {
    let body_len = u16::try_from(ticket.body.len())
        .map_err(|_| ClientError::Protocol("RelayTicket body exceeds u16::MAX".into()))?;
    let mut out = Vec::with_capacity(4 + 2 + ticket.body.len() + 32);
    out.extend_from_slice(&ticket.key_id.to_be_bytes());
    out.extend_from_slice(&body_len.to_be_bytes());
    out.extend_from_slice(&ticket.body);
    out.extend_from_slice(&ticket.mac);
    Ok(out)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayBindResp {
    pub status: u16,
    pub route_cid: [u8; 8],
    pub session_start_unix: u64,
    pub access_epoch: u32,
    pub grace_ms: u32,
    pub egress_mtu: u16,
}

impl RelayBindResp {
    pub fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() != 29 || bytes[0] != CTRL_OP_RELAY_BIND_RESP {
            return Err(ClientError::Protocol(format!(
                "invalid RelayBindResp (len={}, tag={:#04x})",
                bytes.len(),
                bytes.first().copied().unwrap_or(0)
            )));
        }
        let status = u16::from_be_bytes([bytes[1], bytes[2]]);
        let mut route_cid = [0u8; 8];
        route_cid.copy_from_slice(&bytes[3..11]);
        let session_start_unix = u64::from_be_bytes([
            bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
        ]);
        let access_epoch = u32::from_be_bytes([bytes[19], bytes[20], bytes[21], bytes[22]]);
        let grace_ms = u32::from_be_bytes([bytes[23], bytes[24], bytes[25], bytes[26]]);
        let egress_mtu = u16::from_be_bytes([bytes[27], bytes[28]]);
        Ok(Self {
            status,
            route_cid,
            session_start_unix,
            access_epoch,
            grace_ms,
            egress_mtu,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeLeaseRenewResp {
    pub status: u16,
    pub route_cid: [u8; 8],
    pub session_start_unix: u64,
}

impl EdgeLeaseRenewResp {
    pub fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() != 19 || bytes[0] != CTRL_OP_LEASE_RENEW_RESP {
            return Err(ClientError::Protocol(format!(
                "invalid LeaseRenewResp (len={}, tag={:#04x})",
                bytes.len(),
                bytes.first().copied().unwrap_or(0)
            )));
        }
        let status = u16::from_be_bytes([bytes[1], bytes[2]]);
        let mut route_cid = [0u8; 8];
        route_cid.copy_from_slice(&bytes[3..11]);
        let session_start_unix = u64::from_be_bytes([
            bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16], bytes[17], bytes[18],
        ]);
        Ok(Self {
            status,
            route_cid,
            session_start_unix,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeRebindResp {
    pub status: u16,
    pub route_cid: [u8; 8],
}

impl EdgeRebindResp {
    pub fn decode(bytes: &[u8]) -> Result<Self, ClientError> {
        if bytes.len() != 11 || bytes[0] != CTRL_OP_REBIND_RESP {
            return Err(ClientError::Protocol(format!(
                "invalid RebindResp (len={}, tag={:#04x})",
                bytes.len(),
                bytes.first().copied().unwrap_or(0)
            )));
        }
        let status = u16::from_be_bytes([bytes[1], bytes[2]]);
        let mut route_cid = [0u8; 8];
        route_cid.copy_from_slice(&bytes[3..11]);
        Ok(Self { status, route_cid })
    }
}

/// Directional L2 access MAC keys derived from `session_access_secret` (`hs_hash`) via `v2_transport`.
#[derive(Clone)]
pub struct AccessKeys {
    pub route_cid: [u8; 8],
    pub hs_hash: Zeroizing<[u8; 32]>,
    pub access_epoch: u32,
    pub udp_key_c2e: Zeroizing<[u8; 32]>,
    pub udp_key_e2c: Zeroizing<[u8; 32]>,
    pub stream_key_c2e: Zeroizing<[u8; 32]>,
    pub stream_key_e2c: Zeroizing<[u8; 32]>,
}

impl AccessKeys {
    pub fn derive(
        route_cid: [u8; 8],
        hs_hash: [u8; 32],
        access_epoch: u32,
    ) -> Result<Self, ClientError> {
        let udp_c2e = derive_access_key(
            &route_cid,
            &hs_hash,
            TRANSPORT_DATAGRAM,
            DIR_CLIENT_TO_EDGE,
            access_epoch,
        )?;
        let udp_e2c = derive_access_key(
            &route_cid,
            &hs_hash,
            TRANSPORT_DATAGRAM,
            DIR_EDGE_TO_CLIENT,
            access_epoch,
        )?;
        let stream_c2e = derive_access_key(
            &route_cid,
            &hs_hash,
            TRANSPORT_STREAM,
            DIR_CLIENT_TO_EDGE,
            access_epoch,
        )?;
        let stream_e2c = derive_access_key(
            &route_cid,
            &hs_hash,
            TRANSPORT_STREAM,
            DIR_EDGE_TO_CLIENT,
            access_epoch,
        )?;
        Ok(Self {
            route_cid,
            hs_hash: Zeroizing::new(hs_hash),
            access_epoch,
            udp_key_c2e: Zeroizing::new(udp_c2e),
            udp_key_e2c: Zeroizing::new(udp_e2c),
            stream_key_c2e: Zeroizing::new(stream_c2e),
            stream_key_e2c: Zeroizing::new(stream_e2c),
        })
    }
}

/// Authenticated `Noise_IK_25519_AESGCM_SHA256` TCP control tunnel to `v2-edge --bind-ctrl-tcp`.
pub struct AccessControlTunnel {
    stream: TcpStream,
    transport: TransportState,
    session_access_secret: Zeroizing<[u8; 32]>,
    timeout: Duration,
}

impl AccessControlTunnel {
    pub async fn connect(
        ctrl_addr: &str,
        local_x25519_priv: &[u8; 32],
        edge_x25519_pub: &[u8; 32],
        pop_id: &[u8; 8],
        edge_cert_hash: &[u8; 32],
        timeout: Duration,
    ) -> Result<Self, ClientError> {
        let prologue = build_access_prologue(pop_id, edge_cert_hash);
        let params: NoiseParams = ACCESS_IK_PATTERN
            .parse()
            .map_err(|e: snow::Error| ClientError::Noise(e.to_string()))?;
        let mut hs = Builder::new(params)
            .local_private_key(local_x25519_priv)
            .map_err(|e| ClientError::Noise(e.to_string()))?
            .remote_public_key(edge_x25519_pub)
            .map_err(|e| ClientError::Noise(e.to_string()))?
            .prologue(&prologue)
            .map_err(|e| ClientError::Noise(e.to_string()))?
            .build_initiator()
            .map_err(|e| ClientError::Noise(e.to_string()))?;

        let fut = async {
            let mut stream = TcpStream::connect(ctrl_addr).await?;
            let _ = stream.set_nodelay(true);

            let mut msg1 = vec![0u8; 256];
            let n1 = hs
                .write_message(&[], &mut msg1)
                .map_err(|e| ClientError::Noise(e.to_string()))?;
            write_ctrl_frame(&mut stream, &msg1[..n1]).await?;

            let msg2 = read_ctrl_frame(&mut stream).await?;
            let mut resp_payload = vec![0u8; msg2.len() + 64];
            let _ = hs
                .read_message(&msg2, &mut resp_payload)
                .map_err(|e| ClientError::Noise(e.to_string()))?;

            if !hs.is_handshake_finished() {
                return Err(ClientError::Noise(
                    "Noise_IK access handshake did not complete after msg2".into(),
                ));
            }
            let raw_hash = hs.get_handshake_hash();
            if raw_hash.len() != 32 {
                return Err(ClientError::Noise(format!(
                    "unexpected Noise handshake hash length {}",
                    raw_hash.len()
                )));
            }
            let mut secret = Zeroizing::new([0u8; 32]);
            secret.copy_from_slice(raw_hash);

            let transport = hs
                .into_transport_mode()
                .map_err(|e| ClientError::Noise(e.to_string()))?;

            Ok(Self {
                stream,
                transport,
                session_access_secret: secret,
                timeout,
            })
        };

        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ClientError::Timeout(format!("Noise_IK connect to {ctrl_addr} timed out")))?
    }

    pub fn session_access_secret(&self) -> &[u8; 32] {
        &self.session_access_secret
    }

    pub async fn relay_bind(
        &mut self,
        ticket: &RelayTicketWire,
        peer_route_cid: &[u8; 8],
        peer_pop_id: &[u8; 8],
    ) -> Result<(RelayBindResp, AccessKeys), ClientError> {
        let ticket_bytes = encode_ticket_wire(ticket)?;
        let mut req = Vec::with_capacity(1 + ticket_bytes.len() + 8 + 8);
        req.push(CTRL_OP_RELAY_BIND_REQ);
        req.extend_from_slice(&ticket_bytes);
        req.extend_from_slice(peer_route_cid);
        req.extend_from_slice(peer_pop_id);

        let resp_bytes = self.rpc(&req).await?;
        let resp = RelayBindResp::decode(&resp_bytes)?;
        if resp.status != 0 {
            return Err(ClientError::EdgeStatus {
                status: resp.status,
                context: "RelayBindReq".into(),
            });
        }
        let keys = AccessKeys::derive(
            resp.route_cid,
            *self.session_access_secret,
            resp.access_epoch,
        )?;
        Ok((resp, keys))
    }

    pub async fn lease_renew(
        &mut self,
        ticket: &RelayTicketWire,
    ) -> Result<EdgeLeaseRenewResp, ClientError> {
        let ticket_bytes = encode_ticket_wire(ticket)?;
        let mut req = Vec::with_capacity(1 + ticket_bytes.len());
        req.push(CTRL_OP_LEASE_RENEW_REQ);
        req.extend_from_slice(&ticket_bytes);

        let resp_bytes = self.rpc(&req).await?;
        let resp = EdgeLeaseRenewResp::decode(&resp_bytes)?;
        if resp.status != 0 {
            return Err(ClientError::EdgeStatus {
                status: resp.status,
                context: "LeaseRenewReq".into(),
            });
        }
        Ok(resp)
    }

    pub async fn rebind(&mut self, route_cid: &[u8; 8]) -> Result<EdgeRebindResp, ClientError> {
        let mut req = [0u8; 9];
        req[0] = CTRL_OP_REBIND_REQ;
        req[1..9].copy_from_slice(route_cid);

        let resp_bytes = self.rpc(&req).await?;
        let resp = EdgeRebindResp::decode(&resp_bytes)?;
        if resp.status != 0 {
            return Err(ClientError::EdgeStatus {
                status: resp.status,
                context: "RebindReq".into(),
            });
        }
        Ok(resp)
    }

    async fn rpc(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ClientError> {
        let timeout = self.timeout;
        let fut = async {
            let mut ct = vec![0u8; plaintext.len() + 64];
            let n = self
                .transport
                .write_message(plaintext, &mut ct)
                .map_err(|e| ClientError::Noise(e.to_string()))?;
            write_ctrl_frame(&mut self.stream, &ct[..n]).await?;

            let resp_ct = read_ctrl_frame(&mut self.stream).await?;
            let mut pt = vec![0u8; resp_ct.len() + 64];
            let m = self
                .transport
                .read_message(&resp_ct, &mut pt)
                .map_err(|e| ClientError::Noise(e.to_string()))?;
            pt.truncate(m);
            Ok(pt)
        };
        tokio::time::timeout(timeout, fut)
            .await
            .map_err(|_| ClientError::Timeout("Noise_IK access control RPC timed out".into()))?
    }
}

pub async fn write_ctrl_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), ClientError> {
    if payload.is_empty() || payload.len() > MAX_CTRL_FRAME_LEN {
        return Err(ClientError::Protocol(format!(
            "control frame length {} out of [1, {MAX_CTRL_FRAME_LEN}]",
            payload.len()
        )));
    }
    let len = u16::try_from(payload.len())
        .map_err(|_| ClientError::Protocol("control frame exceeds u16::MAX".into()))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read_ctrl_frame<R: AsyncReadExt + Unpin>(
    reader: &mut R,
) -> Result<Vec<u8>, ClientError> {
    let mut len_buf = [0u8; 2];
    reader.read_exact(&mut len_buf).await?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_CTRL_FRAME_LEN {
        return Err(ClientError::Protocol(format!(
            "invalid incoming control frame length {len}"
        )));
    }
    let mut buf = vec![0u8; len];
    reader.read_exact(&mut buf).await?;
    Ok(buf)
}
