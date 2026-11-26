use super::{
    hid::{decode_hid_frame, encode_hid_frame, HidCodecError, HidEchoAck, HidPayload},
    video::{I420Frame, V2VideoDecoder, V2VideoEncoder, VideoError},
};
use sha2::{Digest, Sha256};
use std::{
    fmt,
    time::{Duration, Instant},
};
use v2_client::{ClientError, UdpE2eeSession};
use v2_transport::{AssembledVideoFrame, TransportEvent, VideoFrameMeta};

#[derive(Debug)]
pub enum SessionError {
    Client(ClientError),
    Hid(HidCodecError),
    Video(VideoError),
    Protocol(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Client(e) => write!(f, "v2 client error: {e}"),
            Self::Hid(e) => write!(f, "v2 HID codec error: {e}"),
            Self::Video(e) => write!(f, "v2 video error: {e}"),
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
    encoder: V2VideoEncoder,
    pub video_frames_sent: u64,
    pub video_slices_sent: u64,
    pub video_bytes_sent: u64,
    pub hid_frames_received: u64,
}

impl DesktopHostSession {
    pub fn new(session: UdpE2eeSession, encoder: V2VideoEncoder) -> Self {
        Self {
            session,
            encoder,
            video_frames_sent: 0,
            video_slices_sent: 0,
            video_bytes_sent: 0,
            hid_frames_received: 0,
        }
    }

    pub fn session(&self) -> &UdpE2eeSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut UdpE2eeSession {
        &mut self.session
    }

    pub fn encoder(&self) -> &V2VideoEncoder {
        &self.encoder
    }

    pub fn replace_encoder(&mut self, encoder: V2VideoEncoder) {
        self.encoder = encoder;
    }

    pub fn into_inner(self) -> (UdpE2eeSession, V2VideoEncoder) {
        (self.session, self.encoder)
    }

    /// Encodes an I420 frame via `scrap` and transmits the raw compressed bitstream over
    /// `UdpE2eeSession::send_video_frame` (`0x03 Video`).
    pub async fn publish_i420_frame(
        &mut self,
        frame: &I420Frame,
        pts_ms: i64,
    ) -> Result<PublishedFrameInfo, SessionError> {
        let encoded = self.encoder.encode_i420(frame, pts_ms)?;
        let sha256: [u8; 32] = Sha256::digest(&encoded.data).into();
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
        })
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

    /// Receives the next `0x01 InputHID` frame, strictly decodes it without injecting any OS
    /// synthetic input, and echoes a `HidEchoAck` back on P0.
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
                    let payload = decode_hid_frame(&frame)?;
                    self.hid_frames_received = self.hid_frames_received.saturating_add(1);
                    let ack = HidPayload::EchoAck(HidEchoAck {
                        echo_seq,
                        client_ts_ms: payload.client_ts_ms(),
                    });
                    let ack_frame = encode_hid_frame(&ack)?;
                    self.session.send_hid(&ack_frame).await?;
                    return Ok(payload);
                }
                TransportEvent::Control(_) => continue,
                other => {
                    return Err(SessionError::Protocol(format!(
                        "host expected Hid event, got {other:?}"
                    )));
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
    decoder: V2VideoDecoder,
    pub video_frames_received: u64,
    pub hid_frames_sent: u64,
}

impl DesktopControllerSession {
    pub fn new(session: UdpE2eeSession, decoder: V2VideoDecoder) -> Self {
        Self {
            session,
            decoder,
            video_frames_received: 0,
            hid_frames_sent: 0,
        }
    }

    pub fn session(&self) -> &UdpE2eeSession {
        &self.session
    }

    pub fn session_mut(&mut self) -> &mut UdpE2eeSession {
        &mut self.session
    }

    pub fn decoder(&self) -> &V2VideoDecoder {
        &self.decoder
    }

    pub fn replace_decoder(&mut self, decoder: V2VideoDecoder) {
        self.decoder = decoder;
    }

    pub fn into_inner(self) -> (UdpE2eeSession, V2VideoDecoder) {
        (self.session, self.decoder)
    }

    /// Receives the next assembled `0x03 Video` frame, computes its SHA-256, and decodes it to I420.
    pub async fn recv_and_decode_video(
        &mut self,
        timeout: Duration,
    ) -> Result<DecodedVideoDelivery, SessionError> {
        let deadline = Instant::now() + timeout;
        loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("controller video recv timed out".into()).into());
            };
            match self.session.recv_event(rem).await? {
                TransportEvent::VideoFrame(frame) => {
                    let sha256: [u8; 32] = Sha256::digest(&frame.data).into();
                    let i420 = self.decoder.decode_assembled(&frame)?;
                    self.video_frames_received = self.video_frames_received.saturating_add(1);
                    return Ok(DecodedVideoDelivery {
                        frame,
                        sha256,
                        i420,
                    });
                }
                TransportEvent::Control(_) => continue,
                other => {
                    return Err(SessionError::Protocol(format!(
                        "controller expected VideoFrame event, got {other:?}"
                    )));
                }
            }
        }
    }

    /// Sends a typed V2 HID payload over P0 (`0x01 InputHID`).
    pub async fn send_hid_payload(&mut self, payload: &HidPayload) -> Result<u32, SessionError> {
        let frame = encode_hid_frame(payload)?;
        let leg_seq = self.session.send_hid(&frame).await?;
        self.hid_frames_sent = self.hid_frames_sent.saturating_add(1);
        Ok(leg_seq)
    }

    /// Sends a typed P0 HID event and awaits the matching `HidEchoAck` on P0 while draining any
    /// interleaved P2 video frames so loaded preemption tests accurately measure P0 RTT.
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
                TransportEvent::Hid(frame) => match decode_hid_frame(&frame)? {
                    HidPayload::EchoAck(ack) if ack.echo_seq == expected_echo_seq => {
                        let rtt_us = sent.elapsed().as_micros() as u64;
                        return Ok((ack, rtt_us, interleaved_video_frames));
                    }
                    other => {
                        return Err(SessionError::Protocol(format!(
                            "unexpected HID frame while awaiting echo_seq {expected_echo_seq}: {other:?}"
                        )));
                    }
                },
                TransportEvent::VideoFrame(_) => {
                    interleaved_video_frames = interleaved_video_frames.saturating_add(1);
                    self.video_frames_received = self.video_frames_received.saturating_add(1);
                }
                TransportEvent::Control(_) => continue,
                other => {
                    return Err(SessionError::Protocol(format!(
                        "unexpected event while awaiting HidEchoAck: {other:?}"
                    )));
                }
            }
        }
    }
}
