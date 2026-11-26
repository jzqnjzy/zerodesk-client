use super::{
    hid::{decode_hid_frame, encode_hid_frame, HidCodecError, HidEchoAck, HidPayload},
    video::{EncodedV2Frame, I420Frame, V2VideoDecoder, V2VideoEncoder, VideoCodec, VideoError},
};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use v2_client::{ClientError, UdpE2eeSession};
use v2_transport::{
    AssembledVideoFrame, ControlFrame, TransportEvent, VideoFrameMeta, IDR_MIN_INTERVAL_MS,
};

pub const PENDING_VIDEO_QUEUE_CAP: usize = 8;
pub const CTRL_MSG_SESSION_CLOSE: u8 = 0x04;
pub const CTRL_MSG_REQUEST_IDR: u8 = 0x10;

pub fn parse_session_close(ctrl: &ControlFrame) -> Option<u16> {
    if ctrl.msg_type != CTRL_MSG_SESSION_CLOSE {
        return None;
    }
    if ctrl.payload.len() == 2 {
        Some(u16::from_be_bytes([ctrl.payload[0], ctrl.payload[1]]))
    } else {
        None
    }
}

pub fn parse_request_idr(ctrl: &ControlFrame) -> Option<u32> {
    if ctrl.msg_type != CTRL_MSG_REQUEST_IDR {
        return None;
    }
    if ctrl.payload.len() == 4 {
        Some(u32::from_be_bytes([
            ctrl.payload[0],
            ctrl.payload[1],
            ctrl.payload[2],
            ctrl.payload[3],
        ]))
    } else {
        None
    }
}

#[derive(Debug)]
pub enum SessionError {
    Client(ClientError),
    Hid(HidCodecError),
    Video(VideoError),
    SessionClosed { error_code: u16 },
    Protocol(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(e) => write!(f, "v2 client error: {e}"),
            Self::Hid(e) => write!(f, "v2 HID codec error: {e}"),
            Self::Video(e) => write!(f, "v2 video error: {e}"),
            Self::SessionClosed { error_code } => {
                write!(f, "v2 session closed by peer (error_code={error_code:#06x})")
            }
            Self::Protocol(msg) => write!(f, "v2 session protocol error: {msg}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<ClientError> for SessionError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

impl From<HidCodecError> for SessionError {
    fn from(e: HidCodecError) -> Self {
        Self::Hid(e)
    }
}

impl From<VideoError> for SessionError {
    fn from(e: VideoError) -> Self {
        Self::Video(e)
    }
}

#[derive(Debug, Clone)]
pub struct PublishedFrameInfo {
    pub meta: VideoFrameMeta,
    pub raw_bytes: usize,
    pub slices_sent: usize,
    pub sha256: [u8; 32],
    pub encode_us: u64,
}

#[derive(Debug, Clone)]
pub struct DecodedVideoDelivery {
    pub frame: AssembledVideoFrame,
    pub sha256: [u8; 32],
    pub i420: I420Frame,
}

/// Native V2 Host desktop session controller.
/// Routes Video (`0x03`), InputHID (`0x01`), and TransportCtrl (`0x00`) directly over
/// `UdpE2eeSession` (never through `V2LoopbackBridge` / `V2ServiceStream`).
pub struct DesktopHostSession {
    session: UdpE2eeSession,
    encoder: Arc<Mutex<V2VideoEncoder>>,
    encoder_codec: VideoCodec,
    pub video_frames_sent: u64,
    pub video_slices_sent: u64,
    pub video_bytes_sent: u64,
    pub hid_frames_received: u64,
    pub malformed_hid_frames_dropped: u64,
    pub skipped_non_hid_events: u64,
}

impl DesktopHostSession {
    pub fn new(session: UdpE2eeSession, encoder: V2VideoEncoder) -> Self {
        let encoder_codec = encoder.codec();
        Self {
            session,
            encoder: Arc::new(Mutex::new(encoder)),
            encoder_codec,
            video_frames_sent: 0,
            video_slices_sent: 0,
            video_bytes_sent: 0,
            hid_frames_received: 0,
            malformed_hid_frames_dropped: 0,
            skipped_non_hid_events: 0,
        }
    }

    pub fn session(&self) -> &UdpE2eeSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut UdpE2eeSession {
        &mut self.session
    }

    pub fn encoder_codec(&self) -> VideoCodec {
        self.encoder_codec
    }

    /// Replaces the active encoder while keeping `frame_id` strictly monotonic across codec switches.
    pub fn replace_encoder(&mut self, mut encoder: V2VideoEncoder) {
        if let Ok(prev) = self.encoder.lock() {
            encoder.advance_next_frame_id_at_least(prev.next_frame_id());
        }
        self.encoder_codec = encoder.codec();
        self.encoder = Arc::new(Mutex::new(encoder));
    }

    pub fn into_inner(self) -> (UdpE2eeSession, Arc<Mutex<V2VideoEncoder>>) {
        (self.session, self.encoder)
    }

    /// Encodes an I420 frame via `scrap` and computes SHA-256 on Tokio's blocking pool so the
    /// async worker never stalls P0 HID or packet I/O, then transmits the raw bitstream over
    /// `UdpE2eeSession::send_video_frame` (`0x03 Video`). Accepts `Arc<I420Frame>` to avoid
    /// copying multi-megabyte raw planes on the async worker thread.
    pub async fn publish_i420_frame(
        &mut self,
        frame: Arc<I420Frame>,
        pts_ms: i64,
    ) -> Result<PublishedFrameInfo, SessionError> {
        let enc = Arc::clone(&self.encoder);
        let (encoded, sha256, encode_us) = tokio::task::spawn_blocking(
            move || -> Result<(EncodedV2Frame, [u8; 32], u64), SessionError> {
                let mut guard = enc
                    .lock()
                    .map_err(|_| SessionError::Protocol("video encoder mutex poisoned".into()))?;
                let enc_started = Instant::now();
                let encoded = guard.encode_i420(&frame, pts_ms)?;
                let encode_us = enc_started.elapsed().as_micros() as u64;
                let sha256: [u8; 32] = Sha256::digest(&encoded.data).into();
                Ok((encoded, sha256, encode_us))
            },
        )
        .await
        .map_err(|e| SessionError::Protocol(format!("video encode blocking task failed: {e}")))??;

        let raw_bytes = encoded.data.len();
        let slices_sent = self
            .session
            .send_video_frame(&encoded.meta, &encoded.data)
            .await?;
        self.video_frames_sent = self.video_frames_sent.saturating_add(1);
        self.video_slices_sent = self.video_slices_sent.saturating_add(slices_sent as u64);
        self.video_bytes_sent = self.video_bytes_sent.saturating_add(raw_bytes as u64);
        Ok(PublishedFrameInfo {
            meta: encoded.meta,
            raw_bytes,
            slices_sent,
            sha256,
            encode_us,
        })
    }

    pub async fn send_session_close(&mut self, error_code: u16) -> Result<u32, SessionError> {
        let seq = self
            .session
            .send_control(CTRL_MSG_SESSION_CLOSE, &error_code.to_be_bytes())
            .await?;
        Ok(seq)
    }

    /// Transmits a pre-encoded raw video frame directly over `0x03 Video`.
    pub async fn publish_raw_video(
        &mut self,
        meta: &VideoFrameMeta,
        data: &[u8],
    ) -> Result<usize, SessionError> {
        let slices_sent = self.session.send_video_frame(meta, data).await?;
        self.video_frames_sent = self.video_frames_sent.saturating_add(1);
        self.video_slices_sent = self.video_slices_sent.saturating_add(slices_sent as u64);
        self.video_bytes_sent = self.video_bytes_sent.saturating_add(data.len() as u64);
        Ok(slices_sent)
    }

    /// Receives the next valid `0x01 InputHID` frame, strictly decodes it without injecting any OS
    /// synthetic input, and echoes a `HidEchoAck` back on P0. Malformed HID frames and
    /// unexpected non-HID events are counted and skipped without aborting the receive loop;
    /// `0x04 SESSION_CLOSE` returns `Err(SessionError::SessionClosed { error_code })`.
    pub async fn recv_hid_and_echo(
        &mut self,
        echo_seq: u32,
        timeout: Duration,
    ) -> Result<HidPayload, SessionError> {
        let deadline = Instant::now() + timeout;
        loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("host HID recv timed out".into()).into());
            };
            match self.session.recv_event(rem).await? {
                TransportEvent::Hid(frame) => {
                    let payload = match decode_hid_frame(&frame) {
                        Ok(p) => p,
                        Err(_) => {
                            self.malformed_hid_frames_dropped =
                                self.malformed_hid_frames_dropped.saturating_add(1);
                            continue;
                        }
                    };
                    self.hid_frames_received = self.hid_frames_received.saturating_add(1);
                    let ack = HidPayload::EchoAck(HidEchoAck {
                        echo_seq,
                        client_ts_ms: payload.client_ts_ms(),
                    });
                    let ack_frame = encode_hid_frame(&ack)?;
                    self.session.send_hid(&ack_frame).await?;
                    return Ok(payload);
                }
                TransportEvent::Control(ctrl) => {
                    if let Some(error_code) = parse_session_close(&ctrl) {
                        return Err(SessionError::SessionClosed { error_code });
                    }
                    self.skipped_non_hid_events = self.skipped_non_hid_events.saturating_add(1);
                    continue;
                }
                TransportEvent::Audio(_)
                | TransportEvent::VideoFrame(_)
                | TransportEvent::Clipboard(_)
                | TransportEvent::FileTransfer(_)
                | TransportEvent::Diagnostics(_)
                | TransportEvent::RealtimeActuator(_)
                | TransportEvent::Telemetry(_)
                | TransportEvent::TransportModeChanged(_)
                | TransportEvent::BandwidthEstimate { .. }
                | TransportEvent::RequestIdr { .. }
                | TransportEvent::PolicyUpdated(_) => {
                    self.skipped_non_hid_events = self.skipped_non_hid_events.saturating_add(1);
                    continue;
                }
            }
        }
    }
}

/// Native V2 Controller desktop session controller.
/// Receives and decodes raw `0x03 Video` bitstreams and transmits `0x01 InputHID` on P0 directly
/// over `UdpE2eeSession`.
pub struct DesktopControllerSession {
    session: UdpE2eeSession,
    decoder: Arc<Mutex<V2VideoDecoder>>,
    decoder_codec: VideoCodec,
    pending_video: VecDeque<AssembledVideoFrame>,
    last_delivered_frame_id: Option<u32>,
    need_idr: bool,
    last_idr_request_at: Option<Instant>,
    pub video_frames_received: u64,
    pub pending_video_dropped: u64,
    pub stale_video_frames_dropped: u64,
    pub resync_non_idr_frames_skipped: u64,
    pub idr_requests_sent: u64,
    pub decode_errors: u64,
    pub decoder_flushed_frames: u64,
    pub hid_frames_sent: u64,
    pub skipped_hid_events: u64,
    pub skipped_stale_echo_acks: u64,
    pub skipped_control_events: u64,
    pub skipped_other_events: u64,
}

impl DesktopControllerSession {
    pub fn new(session: UdpE2eeSession, decoder: V2VideoDecoder) -> Self {
        let decoder_codec = decoder.codec();
        Self {
            session,
            decoder: Arc::new(Mutex::new(decoder)),
            decoder_codec,
            pending_video: VecDeque::with_capacity(PENDING_VIDEO_QUEUE_CAP),
            last_delivered_frame_id: None,
            need_idr: true,
            last_idr_request_at: None,
            video_frames_received: 0,
            pending_video_dropped: 0,
            stale_video_frames_dropped: 0,
            resync_non_idr_frames_skipped: 0,
            idr_requests_sent: 0,
            decode_errors: 0,
            decoder_flushed_frames: 0,
            hid_frames_sent: 0,
            skipped_hid_events: 0,
            skipped_stale_echo_acks: 0,
            skipped_control_events: 0,
            skipped_other_events: 0,
        }
    }

    pub fn session(&self) -> &UdpE2eeSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut UdpE2eeSession {
        &mut self.session
    }

    pub fn decoder_codec(&self) -> VideoCodec {
        self.decoder_codec
    }

    pub fn pending_video_len(&self) -> usize {
        self.pending_video.len()
    }

    pub fn clear_pending_video(&mut self) {
        self.pending_video.clear();
    }

    pub fn replace_decoder(&mut self, decoder: V2VideoDecoder) {
        self.decoder_codec = decoder.codec();
        self.decoder = Arc::new(Mutex::new(decoder));
        self.pending_video.clear();
        self.last_delivered_frame_id = None;
        self.need_idr = true;
        self.last_idr_request_at = None;
    }

    pub fn into_inner(self) -> (UdpE2eeSession, Arc<Mutex<V2VideoDecoder>>) {
        (self.session, self.decoder)
    }

    pub fn flush_decoder(&mut self) -> Result<Vec<I420Frame>, SessionError> {
        let mut guard = self
            .decoder
            .lock()
            .map_err(|_| SessionError::Protocol("video decoder mutex poisoned".into()))?;
        let flushed = match guard.flush_pending() {
            Ok(frames) => frames,
            Err(e) => {
                self.decode_errors = self.decode_errors.saturating_add(1);
                return Err(SessionError::Video(e));
            }
        };
        self.decoder_flushed_frames = self
            .decoder_flushed_frames
            .saturating_add(flushed.len() as u64);
        Ok(flushed)
    }

    pub async fn send_session_close(&mut self, error_code: u16) -> Result<u32, SessionError> {
        let seq = self
            .session
            .send_control(CTRL_MSG_SESSION_CLOSE, &error_code.to_be_bytes())
            .await?;
        Ok(seq)
    }

    fn push_pending_video(&mut self, frame: AssembledVideoFrame) {
        while self.pending_video.len() >= PENDING_VIDEO_QUEUE_CAP {
            self.pending_video.pop_front();
            self.pending_video_dropped = self.pending_video_dropped.saturating_add(1);
            self.need_idr = true;
        }
        self.pending_video.push_back(frame);
    }

    async fn decode_video_frame(
        &mut self,
        frame: AssembledVideoFrame,
    ) -> Result<DecodedVideoDelivery, SessionError> {
        let dec = Arc::clone(&self.decoder);
        let decoded = tokio::task::spawn_blocking(
            move || -> Result<(AssembledVideoFrame, [u8; 32], I420Frame), SessionError> {
                let sha256: [u8; 32] = Sha256::digest(&frame.data).into();
                let mut guard = dec
                    .lock()
                    .map_err(|_| SessionError::Protocol("video decoder mutex poisoned".into()))?;
                let i420 = guard.decode_assembled(&frame)?;
                Ok((frame, sha256, i420))
            },
        )
        .await
        .map_err(|e| SessionError::Protocol(format!("video decode blocking task failed: {e}")))?;

        let (frame, sha256, i420) = match decoded {
            Ok(v) => v,
            Err(e) => {
                if matches!(e, SessionError::Video(_)) {
                    self.decode_errors = self.decode_errors.saturating_add(1);
                }
                return Err(e);
            }
        };

        self.video_frames_received = self.video_frames_received.saturating_add(1);
        self.last_delivered_frame_id = Some(frame.frame_id);
        Ok(DecodedVideoDelivery {
            frame,
            sha256,
            i420,
        })
    }

    fn is_stale_video_frame(&self, frame_id: u32) -> bool {
        self.last_delivered_frame_id
            .is_some_and(|last| frame_id <= last)
    }

    fn should_skip_for_idr_resync(&mut self, frame: &AssembledVideoFrame) -> bool {
        if frame.is_idr {
            self.need_idr = false;
            return false;
        }
        if self.need_idr {
            self.resync_non_idr_frames_skipped =
                self.resync_non_idr_frames_skipped.saturating_add(1);
            return true;
        }
        if self
            .last_delivered_frame_id
            .is_some_and(|last| frame.frame_id > last.saturating_add(1))
        {
            self.need_idr = true;
            self.resync_non_idr_frames_skipped =
                self.resync_non_idr_frames_skipped.saturating_add(1);
            return true;
        }
        false
    }

    async fn maybe_send_idr_request(&mut self, frame_id: u32) {
        if self
            .last_idr_request_at
            .is_none_or(|t| t.elapsed() >= Duration::from_millis(IDR_MIN_INTERVAL_MS))
            && self
                .session
                .send_control(CTRL_MSG_REQUEST_IDR, &frame_id.to_be_bytes())
                .await
                .is_ok()
        {
            self.last_idr_request_at = Some(Instant::now());
            self.idr_requests_sent = self.idr_requests_sent.saturating_add(1);
        }
    }

    /// Receives the next assembled `0x03 Video` frame (draining any buffered frames from
    /// `pending_video` first), computes its SHA-256, and decodes it to I420 on Tokio's blocking
    /// pool. Out-of-order stale frames (`frame_id <= last_delivered_frame_id`), orphan non-IDR
    /// frames awaiting IDR resync, and late/unexpected HID or Control events are skipped and
    /// counted; `0x04 SESSION_CLOSE` returns `Err(SessionError::SessionClosed { error_code })`.
    pub async fn recv_and_decode_video(
        &mut self,
        timeout: Duration,
    ) -> Result<DecodedVideoDelivery, SessionError> {
        while let Some(frame) = self.pending_video.pop_front() {
            if self.is_stale_video_frame(frame.frame_id) {
                self.stale_video_frames_dropped =
                    self.stale_video_frames_dropped.saturating_add(1);
                continue;
            }
            if self.should_skip_for_idr_resync(&frame) {
                self.maybe_send_idr_request(frame.frame_id).await;
                continue;
            }
            return self.decode_video_frame(frame).await;
        }
        let deadline = Instant::now() + timeout;
        let frame = loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("controller video recv timed out".into()).into());
            };
            match self.session.recv_event(rem).await? {
                TransportEvent::VideoFrame(frame) => {
                    if self.is_stale_video_frame(frame.frame_id) {
                        self.stale_video_frames_dropped =
                            self.stale_video_frames_dropped.saturating_add(1);
                        continue;
                    }
                    if self.should_skip_for_idr_resync(&frame) {
                        self.maybe_send_idr_request(frame.frame_id).await;
                        continue;
                    }
                    break frame;
                }
                TransportEvent::Control(ctrl) => {
                    if let Some(error_code) = parse_session_close(&ctrl) {
                        return Err(SessionError::SessionClosed { error_code });
                    }
                    self.skipped_control_events = self.skipped_control_events.saturating_add(1);
                    continue;
                }
                TransportEvent::Hid(_) => {
                    self.skipped_hid_events = self.skipped_hid_events.saturating_add(1);
                    continue;
                }
                TransportEvent::Audio(_)
                | TransportEvent::Clipboard(_)
                | TransportEvent::FileTransfer(_)
                | TransportEvent::Diagnostics(_)
                | TransportEvent::RealtimeActuator(_)
                | TransportEvent::Telemetry(_)
                | TransportEvent::TransportModeChanged(_)
                | TransportEvent::BandwidthEstimate { .. }
                | TransportEvent::RequestIdr { .. }
                | TransportEvent::PolicyUpdated(_) => {
                    self.skipped_other_events = self.skipped_other_events.saturating_add(1);
                    continue;
                }
            }
        };
        self.decode_video_frame(frame).await
    }

    /// Sends a typed V2 HID payload over P0 (`0x01 InputHID`).
    pub async fn send_hid_payload(&mut self, payload: &HidPayload) -> Result<u32, SessionError> {
        let frame = encode_hid_frame(payload)?;
        let leg_seq = self.session.send_hid(&frame).await?;
        self.hid_frames_sent = self.hid_frames_sent.saturating_add(1);
        Ok(leg_seq)
    }

    /// Sends a typed P0 HID event and awaits the matching `HidEchoAck` on P0 while buffering any
    /// interleaved P2 video frames into `pending_video` (without incrementing
    /// `video_frames_received` until decoded) and skipping stale `echo_seq < expected_echo_seq`.
    /// Returns `Err(SessionError::SessionClosed { error_code })` on `0x04 SESSION_CLOSE`.
    pub async fn send_hid_and_await_echo(
        &mut self,
        payload: &HidPayload,
        expected_echo_seq: u32,
        timeout: Duration,
    ) -> Result<(HidEchoAck, u64, u64), SessionError> {
        let sent = Instant::now();
        self.send_hid_payload(payload).await?;
        let deadline = Instant::now() + timeout;
        let mut interleaved_video_frames = 0u64;
        loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("controller HidEchoAck timed out".into()).into());
            };
            match self.session.recv_event(rem).await? {
                TransportEvent::Hid(frame) => match decode_hid_frame(&frame) {
                    Ok(HidPayload::EchoAck(ack)) if ack.echo_seq == expected_echo_seq => {
                        let rtt_us = sent.elapsed().as_micros() as u64;
                        return Ok((ack, rtt_us, interleaved_video_frames));
                    }
                    Ok(HidPayload::EchoAck(ack)) if ack.echo_seq < expected_echo_seq => {
                        self.skipped_stale_echo_acks =
                            self.skipped_stale_echo_acks.saturating_add(1);
                        continue;
                    }
                    Ok(other) => {
                        return Err(SessionError::Protocol(format!(
                            "unexpected HID frame while awaiting echo_seq {expected_echo_seq}: {other:?}"
                        )));
                    }
                    Err(_) => {
                        self.skipped_hid_events = self.skipped_hid_events.saturating_add(1);
                        continue;
                    }
                },
                TransportEvent::VideoFrame(frame) => {
                    interleaved_video_frames = interleaved_video_frames.saturating_add(1);
                    self.push_pending_video(frame);
                }
                TransportEvent::Control(ctrl) => {
                    if let Some(error_code) = parse_session_close(&ctrl) {
                        return Err(SessionError::SessionClosed { error_code });
                    }
                    self.skipped_control_events = self.skipped_control_events.saturating_add(1);
                    continue;
                }
                TransportEvent::Audio(_)
                | TransportEvent::Clipboard(_)
                | TransportEvent::FileTransfer(_)
                | TransportEvent::Diagnostics(_)
                | TransportEvent::RealtimeActuator(_)
                | TransportEvent::Telemetry(_)
                | TransportEvent::TransportModeChanged(_)
                | TransportEvent::BandwidthEstimate { .. }
                | TransportEvent::RequestIdr { .. }
                | TransportEvent::PolicyUpdated(_) => {
                    self.skipped_other_events = self.skipped_other_events.saturating_add(1);
                    continue;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2_session::{
        hid::{KeyEvent, MouseEvent, MouseKind},
        video::generate_animated_i420,
    };
    use bytes::Bytes;
    use tokio::{net::UdpSocket, task::JoinHandle};
    use v2_client::{AccessKeys, UdpAccessLink};
    use v2_transport::{
        seal_udp_v11, AccessEpochState, AccessFlags, AccessHeaderV11, HidFrame,
        VerifiedTenantPolicy, DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT, TRANSPORT_DATAGRAM,
        UDP_MAX_LEN,
    };

    struct LoopbackPair {
        host: DesktopHostSession,
        controller: DesktopControllerSession,
        _relay: JoinHandle<()>,
    }

    async fn spawn_loopback_pair() -> LoopbackPair {
        let edge_a_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let edge_b_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let edge_a_addr = edge_a_sock.local_addr().unwrap();
        let edge_b_addr = edge_b_sock.local_addr().unwrap();

        let cid_a = [0xA1; 8];
        let cid_b = [0xB2; 8];
        let hs_a = [0x33; 32];
        let hs_b = [0x44; 32];
        let keys_a = AccessKeys::derive(cid_a, hs_a, 1).unwrap();
        let keys_b = AccessKeys::derive(cid_b, hs_b, 1).unwrap();

        let link_ctrl = UdpAccessLink::connect(&edge_a_addr.to_string(), &keys_a, 50_000)
            .await
            .unwrap();
        let link_host = UdpAccessLink::connect(&edge_b_addr.to_string(), &keys_b, 50_000)
            .await
            .unwrap();
        let ctrl_local = link_ctrl.local_addr().unwrap();
        let host_local = link_host.local_addr().unwrap();

        let mut rx_a =
            AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 1, 20)
                .unwrap();
        let tx_a =
            AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 1, 20)
                .unwrap();
        let mut rx_b =
            AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 1, 20)
                .unwrap();
        let tx_b =
            AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 1, 20)
                .unwrap();

        let relay = tokio::spawn(async move {
            let mut buf_a = [0u8; UDP_MAX_LEN + 64];
            let mut buf_b = [0u8; UDP_MAX_LEN + 64];
            let mut seq_to_host = 1u32;
            let mut seq_to_ctrl = 1u32;
            loop {
                tokio::select! {
                    res = edge_a_sock.recv(&mut buf_a) => {
                        let Ok(n) = res else { break; };
                        let Ok((hdr, payload)) = rx_a.verify_udp_packet(&buf_a[..n], 0) else { continue; };
                        let fwd_hdr = AccessHeaderV11 {
                            flags: AccessFlags {
                                pp: hdr.flags.pp,
                                discardable: hdr.flags.discardable,
                                frame_end: hdr.flags.frame_end,
                                is_ctrl_edge: false,
                                dir_edge_to_client: true,
                                rtx: false,
                            },
                            route_cid: cid_b,
                            access_epoch: tx_b.cur_epoch(),
                            leg_seq: seq_to_host,
                            mac_64: [0; 8],
                        };
                        seq_to_host = seq_to_host.wrapping_add(1);
                        if let Ok(wire) = seal_udp_v11(tx_b.cur_key(), fwd_hdr, payload) {
                            let _ = edge_b_sock.send_to(&wire, host_local).await;
                        }
                    }
                    res = edge_b_sock.recv(&mut buf_b) => {
                        let Ok(n) = res else { break; };
                        let Ok((hdr, payload)) = rx_b.verify_udp_packet(&buf_b[..n], 0) else { continue; };
                        let fwd_hdr = AccessHeaderV11 {
                            flags: AccessFlags {
                                pp: hdr.flags.pp,
                                discardable: hdr.flags.discardable,
                                frame_end: hdr.flags.frame_end,
                                is_ctrl_edge: false,
                                dir_edge_to_client: true,
                                rtx: false,
                            },
                            route_cid: cid_a,
                            access_epoch: tx_a.cur_epoch(),
                            leg_seq: seq_to_ctrl,
                            mac_64: [0; 8],
                        };
                        seq_to_ctrl = seq_to_ctrl.wrapping_add(1);
                        if let Ok(wire) = seal_udp_v11(tx_a.cur_key(), fwd_hdr, payload) {
                            let _ = edge_a_sock.send_to(&wire, ctrl_local).await;
                        }
                    }
                }
            }
        });

        let policy = VerifiedTenantPolicy::free_tier([0x11; 16]);
        let key_c2h = [0x55; 32];
        let key_h2c = [0x66; 32];
        let ctrl_sess =
            UdpE2eeSession::from_keys(link_ctrl, key_c2h, key_h2c, policy.clone(), [0x01; 16]);
        let host_sess =
            UdpE2eeSession::from_keys(link_host, key_h2c, key_c2h, policy, [0x02; 16]);

        let enc = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(30)).unwrap();
        let dec = V2VideoDecoder::new(VideoCodec::Vp9).unwrap();

        LoopbackPair {
            host: DesktopHostSession::new(host_sess, enc),
            controller: DesktopControllerSession::new(ctrl_sess, dec),
            _relay: relay,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recv_video_skips_late_hid_echo_and_control_frames() {
        let mut pair = spawn_loopback_pair().await;

        let late_ack = encode_hid_frame(&HidPayload::EchoAck(HidEchoAck {
            echo_seq: 99,
            client_ts_ms: 1234,
        }))
        .unwrap();
        pair.host.session_mut().send_hid(&late_ack).await.unwrap();
        pair.host
            .session_mut()
            .send_control(0x01, b"ping")
            .await
            .unwrap();

        let src = Arc::new(generate_animated_i420(64, 64, 0));
        let pub_info = pair.host.publish_i420_frame(src, 0).await.unwrap();

        let delivered = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(delivered.frame.frame_id, pub_info.meta.frame_id);
        assert_eq!(delivered.sha256, pub_info.sha256);
        assert_eq!(pair.controller.skipped_hid_events, 1);
        assert_eq!(pair.controller.skipped_control_events, 1);
        assert_eq!(pair.controller.video_frames_received, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn send_hid_skips_stale_echo_seq_and_buffers_video_until_decoded() {
        let mut pair = spawn_loopback_pair().await;

        // Host queues: stale echo_seq=2, two real VP9 video frames, then matching echo_seq=5.
        let stale_ack = encode_hid_frame(&HidPayload::EchoAck(HidEchoAck {
            echo_seq: 2,
            client_ts_ms: 100,
        }))
        .unwrap();
        pair.host.session_mut().send_hid(&stale_ack).await.unwrap();

        let f0 = Arc::new(generate_animated_i420(64, 64, 0));
        let f1 = Arc::new(generate_animated_i420(64, 64, 1));
        let info0 = pair.host.publish_i420_frame(f0, 0).await.unwrap();
        let info1 = pair.host.publish_i420_frame(f1, 33).await.unwrap();

        let good_ack = encode_hid_frame(&HidPayload::EchoAck(HidEchoAck {
            echo_seq: 5,
            client_ts_ms: 555,
        }))
        .unwrap();
        pair.host.session_mut().send_hid(&good_ack).await.unwrap();

        let probe = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveAbs,
            buttons: 0,
            x_or_dx: 10,
            y_or_dy: 20,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 555,
        });
        let (ack, _rtt, interleaved) = pair
            .controller
            .send_hid_and_await_echo(&probe, 5, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(ack.echo_seq, 5);
        assert_eq!(ack.client_ts_ms, 555);
        assert_eq!(interleaved, 2);
        assert_eq!(pair.controller.skipped_stale_echo_acks, 1);
        assert_eq!(pair.controller.pending_video_len(), 2);
        assert_eq!(pair.controller.video_frames_received, 0);

        let d0 = pair
            .controller
            .recv_and_decode_video(Duration::from_millis(200))
            .await
            .unwrap();
        let d1 = pair
            .controller
            .recv_and_decode_video(Duration::from_millis(200))
            .await
            .unwrap();
        assert_eq!(d0.frame.frame_id, info0.meta.frame_id);
        assert_eq!(d0.sha256, info0.sha256);
        assert_eq!(d1.frame.frame_id, info1.meta.frame_id);
        assert_eq!(d1.sha256, info1.sha256);
        assert_eq!(pair.controller.pending_video_len(), 0);
        assert_eq!(pair.controller.video_frames_received, 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn pending_video_queue_caps_at_bound_and_drops_oldest() {
        let mut pair = spawn_loopback_pair().await;

        let total = PENDING_VIDEO_QUEUE_CAP + 2;
        for idx in 0..total {
            let src = Arc::new(generate_animated_i420(64, 64, idx as u32));
            let _ = pair
                .host
                .publish_i420_frame(src, (idx as i64) * 33)
                .await
                .unwrap();
        }
        let ack = encode_hid_frame(&HidPayload::EchoAck(HidEchoAck {
            echo_seq: 1,
            client_ts_ms: 777,
        }))
        .unwrap();
        pair.host.session_mut().send_hid(&ack).await.unwrap();

        let probe = HidPayload::Key(KeyEvent {
            down: true,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 'a' as u32,
            client_ts_ms: 777,
        });
        let (_, _, interleaved) = pair
            .controller
            .send_hid_and_await_echo(&probe, 1, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(interleaved, total as u64);
        assert_eq!(pair.controller.pending_video_len(), PENDING_VIDEO_QUEUE_CAP);
        assert_eq!(pair.controller.pending_video_dropped, 2);
        assert_eq!(pair.controller.video_frames_received, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn host_recv_hid_drops_malformed_and_non_hid_events_gracefully() {
        let mut pair = spawn_loopback_pair().await;

        // Controller sends malformed HID frame, unexpected Control frame, then valid KeyEvent.
        let malformed = HidFrame {
            msg_type: 0xFF,
            payload: Bytes::from_static(&[1, 2, 3]),
        };
        pair.controller
            .session_mut()
            .send_hid(&malformed)
            .await
            .unwrap();
        pair.controller
            .session_mut()
            .send_control(0x02, b"ctrl")
            .await
            .unwrap();
        let valid = HidPayload::Key(KeyEvent {
            down: false,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 'a' as u32,
            client_ts_ms: 888,
        });
        pair.controller.send_hid_payload(&valid).await.unwrap();

        let got = pair
            .host
            .recv_hid_and_echo(7, Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(got, valid);
        assert_eq!(pair.host.malformed_hid_frames_dropped, 1);
        assert_eq!(pair.host.skipped_non_hid_events, 1);
        assert_eq!(pair.host.hid_frames_received, 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn replace_encoder_keeps_frame_id_monotonic() {
        let mut pair = spawn_loopback_pair().await;

        let f0 = Arc::new(generate_animated_i420(64, 64, 0));
        let f1 = Arc::new(generate_animated_i420(64, 64, 1));
        let p0 = pair.host.publish_i420_frame(Arc::clone(&f0), 0).await.unwrap();
        let p1 = pair.host.publish_i420_frame(f1, 33).await.unwrap();
        assert_eq!(p0.meta.frame_id, 1);
        assert_eq!(p1.meta.frame_id, 2);

        let av1 = V2VideoEncoder::new(VideoCodec::Av1, 64, 64, 2.0, Some(30)).unwrap();
        pair.host.replace_encoder(av1);
        let p2 = pair.host.publish_i420_frame(f0, 66).await.unwrap();
        assert_eq!(p2.meta.frame_id, 3);
        assert_eq!(p2.meta.ref_frame_id, 3);
        assert_eq!(p2.meta.ltr_slot, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn session_close_control_frame_breaks_receive_loops_cleanly() {
        let mut pair = spawn_loopback_pair().await;

        pair.controller.send_session_close(0x0000).await.unwrap();
        let host_res = pair.host.recv_hid_and_echo(1, Duration::from_secs(2)).await;
        assert!(matches!(
            host_res,
            Err(SessionError::SessionClosed { error_code: 0 })
        ));

        pair.host.send_session_close(0x0401).await.unwrap();
        let ctrl_res = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await;
        assert!(matches!(
            ctrl_res,
            Err(SessionError::SessionClosed { error_code: 0x0401 })
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn controller_counts_decode_errors_and_flushes_decoder() {
        let mut pair = spawn_loopback_pair().await;

        let f0 = Arc::new(generate_animated_i420(64, 64, 0));
        let _ = pair.host.publish_i420_frame(f0, 0).await.unwrap();
        let _ = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();

        let bad_meta = VideoFrameMeta {
            display_idx: 0,
            codec_id: VideoCodec::Vp9.codec_id(),
            frame_id: 99,
            ref_frame_id: 99,
            ltr_slot: 0,
            is_idr: true,
            is_ref: true,
            max_age_ms: 200,
        };
        pair.host
            .publish_raw_video(&bad_meta, &[0xFF, 0x00, 0x13, 0x37])
            .await
            .unwrap();
        let err = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await;
        assert!(matches!(err, Err(SessionError::Video(_))));
        assert_eq!(pair.controller.decode_errors, 1);

        let flushed = pair.controller.flush_decoder().unwrap();
        assert_eq!(pair.controller.decoder_flushed_frames, flushed.len() as u64);
    }

    #[test]
    fn parse_session_close_requires_exact_two_byte_payload() {
        let ok_frame = ControlFrame {
            msg_type: CTRL_MSG_SESSION_CLOSE,
            stream_seq: 1,
            payload: Bytes::from_static(&[0x04, 0x01]),
        };
        assert_eq!(parse_session_close(&ok_frame), Some(0x0401));

        for bad in [&[][..], &[0x01][..], &[0x00, 0x01, 0x02][..]] {
            let malformed = ControlFrame {
                msg_type: CTRL_MSG_SESSION_CLOSE,
                stream_seq: 2,
                payload: Bytes::copy_from_slice(bad),
            };
            assert_eq!(parse_session_close(&malformed), None);
        }

        let other = ControlFrame {
            msg_type: 0x03,
            stream_seq: 3,
            payload: Bytes::from_static(&[0x00, 0x00]),
        };
        assert_eq!(parse_session_close(&other), None);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn recv_video_drops_out_of_order_stale_frames_and_decodes_monotonically() {
        let mut pair = spawn_loopback_pair().await;

        let mut enc = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(1)).unwrap();
        let f1 = enc.encode_i420(&generate_animated_i420(64, 64, 0), 0).unwrap();
        let f2 = enc.encode_i420(&generate_animated_i420(64, 64, 1), 33).unwrap();
        let f3 = enc.encode_i420(&generate_animated_i420(64, 64, 2), 66).unwrap();
        let f4 = enc.encode_i420(&generate_animated_i420(64, 64, 3), 99).unwrap();
        let f5 = enc.encode_i420(&generate_animated_i420(64, 64, 4), 132).unwrap();
        assert_eq!(
            (
                f1.meta.frame_id,
                f2.meta.frame_id,
                f3.meta.frame_id,
                f4.meta.frame_id,
                f5.meta.frame_id
            ),
            (1, 2, 3, 4, 5)
        );

        // Deliver frame 1, then frame 3 ahead of frame 2 (simulating trans-Pacific UDP reorder).
        pair.host.publish_raw_video(&f1.meta, &f1.data).await.unwrap();
        let d1 = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d1.frame.frame_id, 1);

        pair.host.publish_raw_video(&f3.meta, &f3.data).await.unwrap();
        let d3 = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d3.frame.frame_id, 3);

        // Late older frame 2 and duplicate frame 3 arrive on UDP before frame 4 -> both dropped.
        pair.host.publish_raw_video(&f2.meta, &f2.data).await.unwrap();
        pair.host.publish_raw_video(&f3.meta, &f3.data).await.unwrap();
        pair.host.publish_raw_video(&f4.meta, &f4.data).await.unwrap();
        let d4 = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d4.frame.frame_id, 4);
        assert_eq!(pair.controller.stale_video_frames_dropped, 2);
        assert_eq!(pair.controller.decode_errors, 0);
        assert_eq!(pair.controller.video_frames_received, 3);

        // Stale frame buffered into `pending_video` during HID echo is also dropped before decode.
        pair.host.publish_raw_video(&f2.meta, &f2.data).await.unwrap();
        pair.host.publish_raw_video(&f5.meta, &f5.data).await.unwrap();
        let ack = encode_hid_frame(&HidPayload::EchoAck(HidEchoAck {
            echo_seq: 1,
            client_ts_ms: 42,
        }))
        .unwrap();
        pair.host.session_mut().send_hid(&ack).await.unwrap();
        let probe = HidPayload::Key(KeyEvent {
            down: true,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 'a' as u32,
            client_ts_ms: 42,
        });
        let (_, _, interleaved) = pair
            .controller
            .send_hid_and_await_echo(&probe, 1, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(interleaved, 2);
        assert_eq!(pair.controller.pending_video_len(), 2);

        let d5 = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d5.frame.frame_id, 5);
        assert_eq!(pair.controller.stale_video_frames_dropped, 3);
        assert_eq!(pair.controller.decode_errors, 0);

        // Replacing decoder resets `last_delivered_frame_id` so frame_id=1 is accepted again.
        pair.controller
            .replace_decoder(V2VideoDecoder::new(VideoCodec::Vp9).unwrap());
        pair.host.publish_raw_video(&f1.meta, &f1.data).await.unwrap();
        let d_reset = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d_reset.frame.frame_id, 1);
        assert_eq!(pair.controller.stale_video_frames_dropped, 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn controller_resyncs_to_next_idr_after_gap_or_pending_overflow() {
        let mut pair = spawn_loopback_pair().await;

        // (a) Direct frame-id gap with non-IDR P-frames: skip orphan P-frames until next IDR.
        let mut enc1 = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap();
        let f1 = enc1.encode_i420(&generate_animated_i420(64, 64, 0), 0).unwrap();
        let _f2_lost = enc1.encode_i420(&generate_animated_i420(64, 64, 1), 33).unwrap();
        let f3 = enc1.encode_i420(&generate_animated_i420(64, 64, 2), 66).unwrap();
        let f4 = enc1.encode_i420(&generate_animated_i420(64, 64, 3), 99).unwrap();
        assert!(f1.meta.is_idr && !f3.meta.is_idr && !f4.meta.is_idr);

        let mut enc2 = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap();
        enc2.advance_next_frame_id_at_least(5);
        let f5_idr = enc2.encode_i420(&generate_animated_i420(64, 64, 4), 0).unwrap();
        let f6_p = enc2.encode_i420(&generate_animated_i420(64, 64, 5), 33).unwrap();
        assert!(f5_idr.meta.is_idr && !f6_p.meta.is_idr);

        pair.host.publish_raw_video(&f1.meta, &f1.data).await.unwrap();
        let d1 = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d1.frame.frame_id, 1);

        // Drop f2; transmit orphan P-frames f3, f4 followed by fresh IDR f5 and P-frame f6.
        pair.host.publish_raw_video(&f3.meta, &f3.data).await.unwrap();
        pair.host.publish_raw_video(&f4.meta, &f4.data).await.unwrap();
        pair.host
            .publish_raw_video(&f5_idr.meta, &f5_idr.data)
            .await
            .unwrap();
        pair.host
            .publish_raw_video(&f6_p.meta, &f6_p.data)
            .await
            .unwrap();

        let d5 = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d5.frame.frame_id, 5);
        assert_eq!(pair.controller.resync_non_idr_frames_skipped, 2);
        assert_eq!(pair.controller.decode_errors, 0);

        let d6 = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d6.frame.frame_id, 6);
        assert_eq!(pair.controller.resync_non_idr_frames_skipped, 2);
        assert_eq!(pair.controller.decode_errors, 0);

        // (b) pending_video overflow evicts older IDR/frames, sets need_idr=true, and skips
        //     all buffered orphan P-frames until the next IDR arrives.
        let mut enc3 = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap();
        enc3.advance_next_frame_id_at_least(7);
        let overflow_total = PENDING_VIDEO_QUEUE_CAP + 2;
        for i in 0..overflow_total {
            let f = enc3
                .encode_i420(&generate_animated_i420(64, 64, i as u32), (i as i64) * 33)
                .unwrap();
            if i == 0 {
                assert!(f.meta.is_idr);
            } else {
                assert!(!f.meta.is_idr);
            }
            pair.host.publish_raw_video(&f.meta, &f.data).await.unwrap();
        }
        let ack = encode_hid_frame(&HidPayload::EchoAck(HidEchoAck {
            echo_seq: 1,
            client_ts_ms: 999,
        }))
        .unwrap();
        pair.host.session_mut().send_hid(&ack).await.unwrap();
        let probe = HidPayload::Key(KeyEvent {
            down: true,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 'a' as u32,
            client_ts_ms: 999,
        });
        let (_, _, interleaved) = pair
            .controller
            .send_hid_and_await_echo(&probe, 1, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(interleaved, overflow_total as u64);
        assert_eq!(pair.controller.pending_video_len(), PENDING_VIDEO_QUEUE_CAP);
        assert_eq!(pair.controller.pending_video_dropped, 2);
        assert!(pair.controller.need_idr);

        let next_id = 7 + (overflow_total as u32);
        let mut enc4 = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap();
        enc4.advance_next_frame_id_at_least(next_id);
        let recovery_idr = enc4
            .encode_i420(&generate_animated_i420(64, 64, 30), 0)
            .unwrap();
        let recovery_p = enc4
            .encode_i420(&generate_animated_i420(64, 64, 31), 33)
            .unwrap();
        assert!(recovery_idr.meta.is_idr && !recovery_p.meta.is_idr);
        pair.host
            .publish_raw_video(&recovery_idr.meta, &recovery_idr.data)
            .await
            .unwrap();
        pair.host
            .publish_raw_video(&recovery_p.meta, &recovery_p.data)
            .await
            .unwrap();

        let d_idr = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d_idr.frame.frame_id, recovery_idr.meta.frame_id);
        assert!(!pair.controller.need_idr);
        assert_eq!(
            pair.controller.resync_non_idr_frames_skipped,
            2 + (PENDING_VIDEO_QUEUE_CAP as u64)
        );
        assert_eq!(pair.controller.decode_errors, 0);

        let d_p = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d_p.frame.frame_id, recovery_p.meta.frame_id);
        assert_eq!(pair.controller.decode_errors, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn controller_skips_initial_orphan_pframe_when_first_idr_lost() {
        let mut pair = spawn_loopback_pair().await;

        let mut enc1 = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap();
        let _f1_lost_idr = enc1.encode_i420(&generate_animated_i420(64, 64, 0), 0).unwrap();
        let f2_orphan_p = enc1.encode_i420(&generate_animated_i420(64, 64, 1), 33).unwrap();
        assert!(!f2_orphan_p.meta.is_idr);

        let mut enc2 = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap();
        enc2.advance_next_frame_id_at_least(3);
        let f3_idr = enc2.encode_i420(&generate_animated_i420(64, 64, 2), 0).unwrap();
        assert!(f3_idr.meta.is_idr);

        // First IDR (frame_id=1) is never delivered; publish orphan P-frame (frame_id=2) then IDR (frame_id=3).
        pair.host
            .publish_raw_video(&f2_orphan_p.meta, &f2_orphan_p.data)
            .await
            .unwrap();
        pair.host
            .publish_raw_video(&f3_idr.meta, &f3_idr.data)
            .await
            .unwrap();

        let delivered = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(delivered.frame.frame_id, 3);
        assert_eq!(pair.controller.resync_non_idr_frames_skipped, 1);
        assert_eq!(pair.controller.decode_errors, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn controller_emits_rate_limited_idr_request_and_host_recovers_monotonically() {
        let mut pair = spawn_loopback_pair().await;

        // Publish initial IDR via host's real encoder (frame_id = 1) and decode on controller.
        let p1 = pair
            .host
            .publish_i420_frame(Arc::new(generate_animated_i420(64, 64, 0)), 0)
            .await
            .unwrap();
        assert!(p1.meta.is_idr && p1.meta.frame_id == 1);
        let d1 = pair
            .controller
            .recv_and_decode_video(Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(d1.frame.frame_id, 1);

        // Simulate frame_id=2 lost on WAN, while orphan P-frames 3 and 4 arrive at controller.
        let mut gap_enc = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap();
        let _ = gap_enc.encode_i420(&generate_animated_i420(64, 64, 0), 0).unwrap();
        let _ = gap_enc.encode_i420(&generate_animated_i420(64, 64, 1), 33).unwrap();
        let f3 = gap_enc.encode_i420(&generate_animated_i420(64, 64, 2), 66).unwrap();
        let f4 = gap_enc.encode_i420(&generate_animated_i420(64, 64, 3), 99).unwrap();
        assert!(!f3.meta.is_idr && !f4.meta.is_idr);
        assert_eq!((f3.meta.frame_id, f4.meta.frame_id), (3, 4));
        let max_prior_frame_id = f4.meta.frame_id;

        // Advance host's encoder to match prior sent frame_ids before sending orphan P-frames.
        let mut synced_enc = V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap();
        synced_enc.advance_next_frame_id_at_least(max_prior_frame_id + 1);
        pair.host.replace_encoder(synced_enc);

        pair.host.publish_raw_video(&f3.meta, &f3.data).await.unwrap();
        pair.host.publish_raw_video(&f4.meta, &f4.data).await.unwrap();

        let mut host = pair.host;
        let mut controller = pair.controller;

        let ctrl_task = async { controller.recv_and_decode_video(Duration::from_secs(3)).await };
        let host_task = async {
            let req_frame_id = loop {
                match host.session_mut().recv_event(Duration::from_secs(2)).await? {
                    TransportEvent::Control(ctrl) => {
                        if let Some(fid) = parse_request_idr(&ctrl) {
                            break fid;
                        }
                    }
                    _ => continue,
                }
            };
            host.replace_encoder(
                V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(60)).unwrap(),
            );
            let forced = host
                .publish_i420_frame(Arc::new(generate_animated_i420(64, 64, 10)), 0)
                .await?;
            Ok::<(u32, PublishedFrameInfo), SessionError>((req_frame_id, forced))
        };

        let (delivered, (req_frame_id, forced)) = tokio::try_join!(ctrl_task, host_task).unwrap();
        assert_eq!(req_frame_id, 3);
        assert!(forced.meta.is_idr);
        assert!(
            forced.meta.frame_id > max_prior_frame_id,
            "forced IDR frame_id {} must be > max prior {}",
            forced.meta.frame_id,
            max_prior_frame_id
        );
        assert_eq!(delivered.frame.frame_id, forced.meta.frame_id);
        assert_eq!(controller.idr_requests_sent, 1);
        assert_eq!(controller.resync_non_idr_frames_skipped, 2);
        assert_eq!(controller.decode_errors, 0);
    }
}
