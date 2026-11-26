use crate::{
    access_ctrl::AccessKeys,
    control_plane::{build_tls_client_config, tls_server_name_for_host},
    error::ClientError,
};
use rustls::ClientConfig;
use std::{
    path::Path,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::{client::TlsStream, TlsConnector};
use v2_transport::{
    compute_stream_mac64, derive_stream_role_key, seal_stream_v11, verify_mac64_ct, AccessFlags,
    AccessHeaderV11, BwHintController, DecodedStreamFrame, EdgeCtrlFrame, QueuedStreamSlice,
    StreamFrameParser, TcpStreamSendQueue, BW_EVENT_DROP_ACTIVE, BW_EVENT_PAUSE_FILE_CHUNK,
    DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT, STREAM_FRAME_MAX_LEN, STREAM_FRAME_MIN_LEN,
    STREAM_QUEUE_CAP_BYTES,
};
use zeroize::Zeroizing;

pub const TLS443_PREFACE_LEN: usize = 9;
pub const TLS443_AUTH_DEADLINE: Duration = Duration::from_secs(5);
pub const TLS443_HOL_THRESHOLD_MS: u64 = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tls443StreamRole {
    Realtime = 1,
    Bulk = 2,
}

impl Tls443StreamRole {
    pub fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Encodes the exact 9-byte TLS-443 stream preface: `[role: u8][route_cid: u64_be]`.
pub fn encode_stream_preface(role: Tls443StreamRole, route_cid: &[u8; 8]) -> [u8; TLS443_PREFACE_LEN] {
    let mut out = [0u8; TLS443_PREFACE_LEN];
    out[0] = role.as_u8();
    out[1..9].copy_from_slice(route_cid);
    out
}

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

fn extract_host(addr: &str) -> &str {
    if let Some(bracket_end) = addr.find(']') {
        &addr[..=bracket_end]
    } else if let Some((h, _)) = addr.rsplit_once(':') {
        h
    } else {
        addr
    }
}

#[derive(Debug, Clone)]
pub enum StreamRecvEvent {
    EdgeCtrl(EdgeCtrlFrame),
    L3Data {
        header: AccessHeaderV11,
        frame_id: u32,
        payload: Vec<u8>,
    },
}

/// Single authenticated TLS 1.3 fallback stream (`Realtime` or `Bulk`) to `v2-edge --bind-tls443`.
pub struct Tls443Stream {
    role: Tls443StreamRole,
    stream: TlsStream<TcpStream>,
    route_cid: [u8; 8],
    access_epoch: u32,
    tx_key: Zeroizing<[u8; 32]>,
    rx_key: Zeroizing<[u8; 32]>,
    next_leg_seq: u32,
    parser: StreamFrameParser,
    send_queue: TcpStreamSendQueue,
    queued_bytes: usize,
    pub bw_hint: BwHintController,
    pub bulk_paused: bool,
    pub hol_dropped_frames: u64,
}

impl Tls443Stream {
    /// Connects TLS 1.3, writes the 9B preface, and completes the mandatory first-frame
    /// authenticated `EdgeCtrl::Ping` -> `Pong` exchange within the 5-second deadline.
    pub async fn connect_and_authenticate(
        tls443_addr: &str,
        role: Tls443StreamRole,
        keys: &AccessKeys,
        tls_config: Arc<ClientConfig>,
        lease_bw_cap_kbps: u32,
    ) -> Result<(Self, u64), ClientError> {
        let host = extract_host(tls443_addr);
        let server_name = tls_server_name_for_host(host)?;

        let tx_key = Zeroizing::new(derive_stream_role_key(
            &keys.route_cid,
            &keys.hs_hash,
            DIR_CLIENT_TO_EDGE,
            keys.access_epoch,
            role.as_u8(),
        )?);
        let rx_key = Zeroizing::new(derive_stream_role_key(
            &keys.route_cid,
            &keys.hs_hash,
            DIR_EDGE_TO_CLIENT,
            keys.access_epoch,
            role.as_u8(),
        )?);

        let fut = async {
            let tcp = TcpStream::connect(tls443_addr).await?;
            let _ = tcp.set_nodelay(true);
            let connector = TlsConnector::from(tls_config);
            let mut tls = connector
                .connect(server_name, tcp)
                .await
                .map_err(|e| ClientError::Tls(e.to_string()))?;

            let preface = encode_stream_preface(role, &keys.route_cid);
            tls.write_all(&preface).await?;
            tls.flush().await?;

            let mut conn = Self {
                role,
                stream: tls,
                route_cid: keys.route_cid,
                access_epoch: keys.access_epoch,
                tx_key,
                rx_key,
                next_leg_seq: 1,
                parser: StreamFrameParser::new(),
                send_queue: TcpStreamSendQueue::default(),
                queued_bytes: 0,
                bw_hint: BwHintController::new(lease_bw_cap_kbps, lease_bw_cap_kbps),
                bulk_paused: false,
                hol_dropped_frames: 0,
            };

            let rtt_us = conn.ping(TLS443_AUTH_DEADLINE).await?;
            Ok((conn, rtt_us))
        };

        tokio::time::timeout(TLS443_AUTH_DEADLINE, fut)
            .await
            .map_err(|_| {
                ClientError::Timeout(format!(
                    "TLS-443 {role:?} connect+auth exceeded 5s deadline"
                ))
            })?
    }

    pub fn role(&self) -> Tls443StreamRole {
        self.role
    }

    pub async fn send_edge_ctrl(&mut self, ctrl: &EdgeCtrlFrame) -> Result<(), ClientError> {
        let body = ctrl.encode();
        let hdr = AccessHeaderV11 {
            flags: AccessFlags {
                pp: 0,
                discardable: false,
                frame_end: true,
                is_ctrl_edge: true,
                dir_edge_to_client: false,
                rtx: false,
            },
            route_cid: self.route_cid,
            access_epoch: self.access_epoch,
            leg_seq: 0,
            mac_64: [0; 8],
        };
        let wire = seal_stream_v11(&self.tx_key, hdr, 0, &body)?;
        self.stream.write_all(&wire).await?;
        self.stream.flush().await?;
        Ok(())
    }

    pub async fn ping(&mut self, timeout: Duration) -> Result<u64, ClientError> {
        let ts_us = now_us();
        let start = Instant::now();
        self.send_edge_ctrl(&EdgeCtrlFrame::Ping { ts_us }).await?;
        let deadline = Instant::now() + timeout;
        loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("TLS-443 Ping timed out".into()));
            };
            match self.recv_frame(rem).await? {
                StreamRecvEvent::EdgeCtrl(EdgeCtrlFrame::Pong { ts_us: echo }) if echo == ts_us => {
                    return Ok(start.elapsed().as_micros() as u64);
                }
                StreamRecvEvent::EdgeCtrl(_) | StreamRecvEvent::L3Data { .. } => continue,
            }
        }
    }

    /// Enqueues a stream slice into the bounded 256 KB send queue for HoL monitoring.
    /// Non-reference (`discardable == true`) complete frames (`frame_end == true`, `frame_id != 0`)
    /// are dropped whole when head-of-line delay exceeds 80ms.
    pub fn enqueue_l3_slice(
        &mut self,
        pp: u8,
        discardable: bool,
        frame_end: bool,
        frame_id: u32,
        l3_payload: &[u8],
        enqueue_ms: u64,
    ) -> Result<Vec<u8>, ClientError> {
        let seq = self.next_leg_seq;
        self.next_leg_seq = self.next_leg_seq.wrapping_add(1);
        let flags = AccessFlags {
            pp,
            discardable,
            frame_end,
            is_ctrl_edge: false,
            dir_edge_to_client: false,
            rtx: false,
        };
        let hdr = AccessHeaderV11 {
            flags,
            route_cid: self.route_cid,
            access_epoch: self.access_epoch,
            leg_seq: seq,
            mac_64: [0; 8],
        };
        let wire = seal_stream_v11(&self.tx_key, hdr, frame_id, l3_payload)?;
        if self.queued_bytes.saturating_add(wire.len()) > STREAM_QUEUE_CAP_BYTES {
            let (dropped, _) = self.prune_hol_queue(enqueue_ms);
            if dropped.is_empty()
                && self.queued_bytes.saturating_add(wire.len()) > STREAM_QUEUE_CAP_BYTES
            {
                return Err(ClientError::Protocol(
                    "TLS-443 send queue exceeded 256 KB hard cap".into(),
                ));
            }
        }
        self.queued_bytes = self.queued_bytes.saturating_add(wire.len());
        self.send_queue.push(QueuedStreamSlice {
            enqueue_ms,
            frame_id,
            flags,
            wire_bytes: wire.clone(),
        });
        Ok(wire)
    }

    /// Runs the 80ms head-of-line non-reference frame discard rule on the Realtime send queue.
    pub fn prune_hol_queue(&mut self, now_ms_val: u64) -> (Vec<u32>, Option<EdgeCtrlFrame>) {
        let (dropped, hint) = self
            .send_queue
            .prune_hol_expired(now_ms_val, TLS443_HOL_THRESHOLD_MS);
        self.hol_dropped_frames = self.hol_dropped_frames.saturating_add(dropped.len() as u64);
        (dropped, hint)
    }

    /// Sends a single L3 payload immediately over this TLS-443 stream (checking HoL rules first).
    pub async fn send_l3_frame(
        &mut self,
        pp: u8,
        discardable: bool,
        frame_end: bool,
        frame_id: u32,
        l3_payload: &[u8],
    ) -> Result<(), ClientError> {
        let seq = self.next_leg_seq;
        self.next_leg_seq = self.next_leg_seq.wrapping_add(1);
        let hdr = AccessHeaderV11 {
            flags: AccessFlags {
                pp,
                discardable,
                frame_end,
                is_ctrl_edge: false,
                dir_edge_to_client: false,
                rtx: false,
            },
            route_cid: self.route_cid,
            access_epoch: self.access_epoch,
            leg_seq: seq,
            mac_64: [0; 8],
        };
        let wire = seal_stream_v11(&self.tx_key, hdr, frame_id, l3_payload)?;
        self.stream.write_all(&wire).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receives and authenticates the next stream frame. Enforces strict `34..=1232` length gate
    /// and updates `BwHintController` / `bulk_paused` on `EdgeCtrl::BwHint`.
    pub async fn recv_frame(&mut self, timeout: Duration) -> Result<StreamRecvEvent, ClientError> {
        let deadline = Instant::now() + timeout;
        let mut buf = [0u8; 4096];
        loop {
            if let Some(frame) = self.parser.next_frame()? {
                return self.verify_and_dispatch(frame).await;
            }
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("TLS-443 recv_frame timed out".into()));
            };
            let n = tokio::time::timeout(rem, self.stream.read(&mut buf))
                .await
                .map_err(|_| ClientError::Timeout("TLS-443 recv_frame timed out".into()))??;
            if n == 0 {
                return Err(ClientError::Protocol("TLS-443 stream closed by peer".into()));
            }
            self.parser.feed(&buf[..n]);
        }
    }

    async fn verify_and_dispatch(
        &mut self,
        frame: DecodedStreamFrame,
    ) -> Result<StreamRecvEvent, ClientError> {
        let frame_len = 28 + 4 + frame.payload.len();
        if !(STREAM_FRAME_MIN_LEN..=STREAM_FRAME_MAX_LEN).contains(&frame_len) {
            return Err(ClientError::Protocol(format!(
                "illegal TLS-443 frame_len {frame_len}"
            )));
        }
        if frame.header.route_cid != self.route_cid {
            return Err(ClientError::Protocol("TLS-443 route_cid mismatch".into()));
        }
        if !frame.header.flags.dir_edge_to_client {
            return Err(ClientError::Protocol(
                "TLS-443 incoming frame missing Edge->Client direction bit".into(),
            ));
        }
        let hdr_zero = frame.header.encode_mac_zero();
        let expected_mac =
            compute_stream_mac64(&self.rx_key, &hdr_zero, frame.frame_id, &frame.payload)?;
        verify_mac64_ct(&expected_mac, &frame.header.mac_64)?;

        if frame.header.flags.is_ctrl_edge {
            let ctrl = EdgeCtrlFrame::decode(&frame.payload)?;
            match ctrl {
                EdgeCtrlFrame::Ping { ts_us } => {
                    let _ = self.send_edge_ctrl(&EdgeCtrlFrame::Pong { ts_us }).await;
                }
                EdgeCtrlFrame::BwHint {
                    cap_kbps,
                    report_age_ms,
                    bottleneck_leg,
                    event_flags,
                    ..
                } => {
                    let cur = self.bw_hint.effective_bw_kbps();
                    self.bw_hint.on_bw_hint(
                        cur,
                        cap_kbps,
                        report_age_ms,
                        bottleneck_leg,
                        event_flags,
                        now_ms(),
                    );
                    self.bulk_paused =
                        (event_flags & (BW_EVENT_PAUSE_FILE_CHUNK | BW_EVENT_DROP_ACTIVE)) != 0;
                }
                _ => {}
            }
            return Ok(StreamRecvEvent::EdgeCtrl(ctrl));
        }

        Ok(StreamRecvEvent::L3Data {
            header: frame.header,
            frame_id: frame.frame_id,
            payload: frame.payload,
        })
    }
}

/// Dual TLS-443 fallback client managing independent `Realtime` (`p0/p1/p2`)
/// and `Bulk` (`p3`) TLS 1.3 connections to eliminate HoL blocking.
pub struct DualTls443Client {
    pub realtime: Tls443Stream,
    pub bulk: Tls443Stream,
    pub realtime_ping_rtt_us: u64,
    pub bulk_ping_rtt_us: u64,
}

impl DualTls443Client {
    pub async fn connect(
        tls443_addr: &str,
        keys: &AccessKeys,
        ca_der_path: Option<&Path>,
        lease_bw_cap_kbps: u32,
    ) -> Result<Self, ClientError> {
        let tls_cfg = build_tls_client_config(ca_der_path)?;
        let (realtime, realtime_ping_rtt_us) = Tls443Stream::connect_and_authenticate(
            tls443_addr,
            Tls443StreamRole::Realtime,
            keys,
            Arc::clone(&tls_cfg),
            lease_bw_cap_kbps,
        )
        .await?;
        let (bulk, bulk_ping_rtt_us) = Tls443Stream::connect_and_authenticate(
            tls443_addr,
            Tls443StreamRole::Bulk,
            keys,
            tls_cfg,
            lease_bw_cap_kbps,
        )
        .await?;
        Ok(Self {
            realtime,
            bulk,
            realtime_ping_rtt_us,
            bulk_ping_rtt_us,
        })
    }

    pub async fn send_l3(&mut self, pp: u8, discardable: bool, frame_end: bool, frame_id: u32, payload: &[u8]) -> Result<(), ClientError> {
        if pp == 3 {
            if self.realtime.bulk_paused || self.bulk.bulk_paused {
                return Err(ClientError::Protocol(
                    "Bulk TLS-443 stream paused by EdgeCtrl::BwHint".into(),
                ));
            }
            self.bulk
                .send_l3_frame(pp, false, true, 0, payload)
                .await
        } else {
            self.realtime
                .send_l3_frame(pp, discardable, frame_end, frame_id, payload)
                .await
        }
    }
}
