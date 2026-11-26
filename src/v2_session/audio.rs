// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `0x02 Audio` — Real `libopus` FFI wrappers, `spec/04` §3.1 (`v1.2.4`) DTX/PLC framing,
//! modular `ts_u32` jitter buffer with 5-frame PLC cap & `decoder_silenced` latch, policy gate,
//! `AudioSource` / `AudioSink` traits, and deterministic multi-tone SNR/correlation verifier.

use super::policy::EffectiveTenantPolicy;
use std::{
    collections::BTreeMap,
    f32::consts::TAU,
    ffi::c_int,
    fmt,
    ptr::NonNull,
};

pub const AUDIO_SAMPLE_RATE_HZ: u32 = 48_000;
pub const AUDIO_FRAME_MS: u32 = 20;
pub const AUDIO_FRAME_SAMPLES_PER_CH: usize = 960;
pub const AUDIO_WIRE_HDR_LEN: usize = 5;
pub const AUDIO_MAX_OPUS_PACKET_BYTES: usize = 1_100;
pub const AUDIO_JITTER_MIN_FRAMES: usize = 2;
pub const AUDIO_JITTER_MAX_FRAMES: usize = 8;
pub const AUDIO_LATE_DROP_MS: u32 = 80;
pub const AUDIO_MAX_CONSECUTIVE_PLC: u32 = 5;

pub const AUDIO_DEFAULT_BITRATE_BPS: u32 = 48_000;
pub const AUDIO_MIN_NORMAL_BITRATE_BPS: u32 = 24_000;
pub const AUDIO_MAX_NORMAL_BITRATE_BPS: u32 = 64_000;
pub const AUDIO_SURVIVAL_BITRATE_BPS: u32 = 20_000;
pub const AUDIO_SURVIVAL_MIN_BITRATE_BPS: u32 = 16_000;
pub const AUDIO_SURVIVAL_MAX_BITRATE_BPS: u32 = 24_000;

pub const AUDIO_ERROR_INVALID_FRAMING: u16 = 0x0103;
pub const AUDIO_ERROR_POLICY_DENIED: u16 = 0x0401;

// Exact libopus C ABI constants from <opus/opus_defines.h>
const OPUS_OK: c_int = 0;
const OPUS_APPLICATION_VOIP: c_int = 2048;
const OPUS_SET_BITRATE_REQUEST: c_int = 4002;
const OPUS_SET_INBAND_FEC_REQUEST: c_int = 4012;
const OPUS_SET_PACKET_LOSS_PERC_REQUEST: c_int = 4014;
const OPUS_SET_DTX_REQUEST: c_int = 4016;
const OPUS_RESET_STATE: c_int = 4028;
const OPUS_GET_IN_DTX_REQUEST: c_int = 4049;

#[repr(C)]
struct OpusEncoderOpaque {
    _private: [u8; 0],
}

#[repr(C)]
struct OpusDecoderOpaque {
    _private: [u8; 0],
}

extern "C" {
    fn opus_encoder_create(
        fs: i32,
        channels: c_int,
        application: c_int,
        error: *mut c_int,
    ) -> *mut OpusEncoderOpaque;
    fn opus_encoder_destroy(st: *mut OpusEncoderOpaque);
    fn opus_encode_float(
        st: *mut OpusEncoderOpaque,
        pcm: *const f32,
        frame_size: c_int,
        data: *mut u8,
        max_data_bytes: i32,
    ) -> i32;
    fn opus_encoder_ctl(st: *mut OpusEncoderOpaque, request: c_int, ...) -> c_int;

    fn opus_decoder_create(
        fs: i32,
        channels: c_int,
        error: *mut c_int,
    ) -> *mut OpusDecoderOpaque;
    fn opus_decoder_destroy(st: *mut OpusDecoderOpaque);
    fn opus_decode_float(
        st: *mut OpusDecoderOpaque,
        data: *const u8,
        len: i32,
        pcm: *mut f32,
        frame_size: c_int,
        decode_fec: c_int,
    ) -> c_int;
    fn opus_decoder_ctl(st: *mut OpusDecoderOpaque, request: c_int, ...) -> c_int;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AudioError {
    InvalidChannels(u8),
    InvalidFrameLen { expected: usize, actual: usize },
    InvalidBitrate(u32),
    InvalidFraming { error_code: u16, reason: String },
    PolicyDenied(String),
    OpusError { op: &'static str, code: i32 },
}

impl fmt::Display for AudioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChannels(ch) => {
                write!(f, "invalid audio channel count {ch} (supported: 1 or 2)")
            }
            Self::InvalidFrameLen { expected, actual } => {
                write!(f, "invalid PCM frame len: expected {expected} samples, got {actual}")
            }
            Self::InvalidBitrate(bps) => write!(f, "invalid Opus bitrate {bps} bps"),
            Self::InvalidFraming { error_code, reason } => {
                write!(f, "audio framing error ({error_code:#06x}): {reason}")
            }
            Self::PolicyDenied(msg) => write!(f, "audio denied by tenant policy: {msg}"),
            Self::OpusError { op, code } => write!(f, "libopus {op} failed with code {code}"),
        }
    }
}

impl std::error::Error for AudioError {}

/// RFC 1982 signed 32-bit modular wrap-around comparison (`spec/04` §3.1).
pub const fn audio_ts_gt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) > 0
}

/// Signed 32-bit modular timestamp delta `a - b` in 48 kHz samples.
pub const fn audio_ts_delta(a: u32, b: u32) -> i32 {
    a.wrapping_sub(b) as i32
}

/// Decoded `0x02 Audio` wire frame: `[u32_be ts_u32][u8 dtx_u8][opus_payload...]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpusWireFrame {
    pub ts_u32: u32,
    pub dtx: bool,
    pub payload: Vec<u8>,
}

impl OpusWireFrame {
    pub fn encode(&self) -> Result<Vec<u8>, AudioError> {
        if !self.dtx && self.payload.is_empty() {
            return Err(AudioError::InvalidFraming {
                error_code: AUDIO_ERROR_INVALID_FRAMING,
                reason: "active audio frame (dtx_u8=0) must carry non-empty Opus payload".into(),
            });
        }
        if self.payload.len() > AUDIO_MAX_OPUS_PACKET_BYTES {
            return Err(AudioError::InvalidFraming {
                error_code: AUDIO_ERROR_INVALID_FRAMING,
                reason: format!(
                    "Opus payload {} exceeds {}B L3 MTU budget",
                    self.payload.len(),
                    AUDIO_MAX_OPUS_PACKET_BYTES
                ),
            });
        }
        let mut out = Vec::with_capacity(AUDIO_WIRE_HDR_LEN + self.payload.len());
        out.extend_from_slice(&self.ts_u32.to_be_bytes());
        out.push(u8::from(self.dtx));
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, AudioError> {
        if bytes.len() < AUDIO_WIRE_HDR_LEN {
            return Err(AudioError::InvalidFraming {
                error_code: AUDIO_ERROR_INVALID_FRAMING,
                reason: format!(
                    "audio frame truncated: {} bytes < {AUDIO_WIRE_HDR_LEN}B minimum",
                    bytes.len()
                ),
            });
        }
        let ts_u32 = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        let dtx_u8 = bytes[4];
        let payload = &bytes[AUDIO_WIRE_HDR_LEN..];
        match dtx_u8 {
            0 => {
                if payload.is_empty() {
                    return Err(AudioError::InvalidFraming {
                        error_code: AUDIO_ERROR_INVALID_FRAMING,
                        reason: "active audio frame (dtx_u8=0) has empty Opus payload".into(),
                    });
                }
                Ok(Self {
                    ts_u32,
                    dtx: false,
                    payload: payload.to_vec(),
                })
            }
            1 => Ok(Self {
                ts_u32,
                dtx: true,
                payload: payload.to_vec(),
            }),
            other => Err(AudioError::InvalidFraming {
                error_code: AUDIO_ERROR_INVALID_FRAMING,
                reason: format!("invalid audio dtx_u8={other} (allowed 0 or 1)"),
            }),
        }
    }
}

/// Encoded output from `V2AudioEncoder::encode_frame`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedAudioFrame {
    pub dtx: bool,
    pub payload: Vec<u8>,
}

/// Safe RAII wrapper around `libopus` `OpusEncoder` (`48 kHz`, `20ms = 960 samples/ch`,
/// mono or stereo, `opus_encode_float`, DTX + in-band FEC + normal/Survival bitrate modes).
pub struct V2AudioEncoder {
    raw: NonNull<OpusEncoderOpaque>,
    channels: u8,
    bitrate_bps: u32,
    survival_mode: bool,
}

// SAFETY: `OpusEncoder` is exclusively owned by this struct and only accessed via `&mut self`.
unsafe impl Send for V2AudioEncoder {}

impl Drop for V2AudioEncoder {
    fn drop(&mut self) {
        unsafe {
            opus_encoder_destroy(self.raw.as_ptr());
        }
    }
}

impl V2AudioEncoder {
    pub fn new(channels: u8, bitrate_bps: u32) -> Result<Self, AudioError> {
        if channels != 1 && channels != 2 {
            return Err(AudioError::InvalidChannels(channels));
        }
        if !(AUDIO_SURVIVAL_MIN_BITRATE_BPS..=AUDIO_MAX_NORMAL_BITRATE_BPS).contains(&bitrate_bps) {
            return Err(AudioError::InvalidBitrate(bitrate_bps));
        }
        let mut err: c_int = OPUS_OK;
        let ptr = unsafe {
            opus_encoder_create(
                AUDIO_SAMPLE_RATE_HZ as i32,
                c_int::from(channels),
                OPUS_APPLICATION_VOIP,
                &mut err,
            )
        };
        if err != OPUS_OK || ptr.is_null() {
            if !ptr.is_null() {
                unsafe { opus_encoder_destroy(ptr) };
            }
            return Err(AudioError::OpusError {
                op: "opus_encoder_create",
                code: err,
            });
        }
        let Some(raw) = NonNull::new(ptr) else {
            return Err(AudioError::OpusError {
                op: "opus_encoder_create",
                code: -7,
            });
        };
        let mut enc = Self {
            raw,
            channels,
            bitrate_bps,
            survival_mode: bitrate_bps < AUDIO_MIN_NORMAL_BITRATE_BPS,
        };
        enc.apply_ctl_int("OPUS_SET_BITRATE", OPUS_SET_BITRATE_REQUEST, bitrate_bps as c_int)?;
        enc.apply_ctl_int("OPUS_SET_DTX", OPUS_SET_DTX_REQUEST, 1)?;
        enc.apply_ctl_int("OPUS_SET_INBAND_FEC", OPUS_SET_INBAND_FEC_REQUEST, 1)?;
        enc.apply_ctl_int(
            "OPUS_SET_PACKET_LOSS_PERC",
            OPUS_SET_PACKET_LOSS_PERC_REQUEST,
            10,
        )?;
        Ok(enc)
    }

    fn apply_ctl_int(
        &mut self,
        op: &'static str,
        request: c_int,
        val: c_int,
    ) -> Result<(), AudioError> {
        let rc = unsafe { opus_encoder_ctl(self.raw.as_ptr(), request, val) };
        if rc != OPUS_OK {
            return Err(AudioError::OpusError { op, code: rc });
        }
        Ok(())
    }

    pub fn channels(&self) -> u8 {
        self.channels
    }

    pub fn bitrate_bps(&self) -> u32 {
        self.bitrate_bps
    }

    pub fn survival_mode(&self) -> bool {
        self.survival_mode
    }

    /// Switches between normal bitrate (`24..=64 kbps`) and Survival Mode (`16..=24 kbps`,
    /// higher packet-loss FEC hint per `spec/04` §1.2).
    pub fn set_survival_mode(&mut self, enabled: bool) -> Result<(), AudioError> {
        let target = if enabled {
            AUDIO_SURVIVAL_BITRATE_BPS
        } else {
            AUDIO_DEFAULT_BITRATE_BPS
        };
        self.apply_ctl_int(
            "OPUS_SET_BITRATE",
            OPUS_SET_BITRATE_REQUEST,
            target as c_int,
        )?;
        self.apply_ctl_int(
            "OPUS_SET_PACKET_LOSS_PERC",
            OPUS_SET_PACKET_LOSS_PERC_REQUEST,
            if enabled { 25 } else { 10 },
        )?;
        self.bitrate_bps = target;
        self.survival_mode = enabled;
        Ok(())
    }

    pub fn set_bitrate_bps(&mut self, bps: u32) -> Result<(), AudioError> {
        if !(AUDIO_SURVIVAL_MIN_BITRATE_BPS..=AUDIO_MAX_NORMAL_BITRATE_BPS).contains(&bps) {
            return Err(AudioError::InvalidBitrate(bps));
        }
        self.apply_ctl_int("OPUS_SET_BITRATE", OPUS_SET_BITRATE_REQUEST, bps as c_int)?;
        self.bitrate_bps = bps;
        Ok(())
    }

    /// Encodes one 20ms (`960 * channels` interleaved `f32`) frame via `opus_encode_float`.
    /// Pure-silence frames or frames where `libopus` enters DTX (`OPUS_GET_IN_DTX == 1` or
    /// `<= 2B` TOC-only DTX packet) are tagged `dtx = true`.
    pub fn encode_frame(&mut self, pcm: &[f32]) -> Result<EncodedAudioFrame, AudioError> {
        let expected = AUDIO_FRAME_SAMPLES_PER_CH * usize::from(self.channels);
        if pcm.len() != expected {
            return Err(AudioError::InvalidFrameLen {
                expected,
                actual: pcm.len(),
            });
        }
        let is_digital_silence = pcm.iter().all(|&s| s.abs() < 1e-6);
        let mut out = vec![0u8; AUDIO_MAX_OPUS_PACKET_BYTES];
        let written = unsafe {
            opus_encode_float(
                self.raw.as_ptr(),
                pcm.as_ptr(),
                AUDIO_FRAME_SAMPLES_PER_CH as c_int,
                out.as_mut_ptr(),
                out.len() as i32,
            )
        };
        if written < 0 {
            return Err(AudioError::OpusError {
                op: "opus_encode_float",
                code: written,
            });
        }
        let n = written as usize;
        let mut in_dtx: c_int = 0;
        let _ = unsafe {
            opus_encoder_ctl(self.raw.as_ptr(), OPUS_GET_IN_DTX_REQUEST, &mut in_dtx)
        };
        if is_digital_silence && (in_dtx != 0 || n <= 2) {
            return Ok(EncodedAudioFrame {
                dtx: true,
                payload: Vec::new(),
            });
        }
        if in_dtx != 0 || n <= 2 {
            out.truncate(n);
            return Ok(EncodedAudioFrame {
                dtx: true,
                payload: out,
            });
        }
        out.truncate(n);
        Ok(EncodedAudioFrame {
            dtx: false,
            payload: out,
        })
    }
}

/// Safe RAII wrapper around `libopus` `OpusDecoder` (`48 kHz`, `20ms = 960 samples/ch`).
pub struct V2AudioDecoder {
    raw: NonNull<OpusDecoderOpaque>,
    channels: u8,
    pub plc_decode_calls: u64,
    pub active_decode_calls: u64,
    pub reset_calls: u64,
}

// SAFETY: `OpusDecoder` is exclusively owned by this struct and only accessed via `&mut self`.
unsafe impl Send for V2AudioDecoder {}

impl Drop for V2AudioDecoder {
    fn drop(&mut self) {
        unsafe {
            opus_decoder_destroy(self.raw.as_ptr());
        }
    }
}

impl V2AudioDecoder {
    pub fn new(channels: u8) -> Result<Self, AudioError> {
        if channels != 1 && channels != 2 {
            return Err(AudioError::InvalidChannels(channels));
        }
        let mut err: c_int = OPUS_OK;
        let ptr = unsafe {
            opus_decoder_create(AUDIO_SAMPLE_RATE_HZ as i32, c_int::from(channels), &mut err)
        };
        if err != OPUS_OK || ptr.is_null() {
            if !ptr.is_null() {
                unsafe { opus_decoder_destroy(ptr) };
            }
            return Err(AudioError::OpusError {
                op: "opus_decoder_create",
                code: err,
            });
        }
        let Some(raw) = NonNull::new(ptr) else {
            return Err(AudioError::OpusError {
                op: "opus_decoder_create",
                code: -7,
            });
        };
        Ok(Self {
            raw,
            channels,
            plc_decode_calls: 0,
            active_decode_calls: 0,
            reset_calls: 0,
        })
    }

    pub fn channels(&self) -> u8 {
        self.channels
    }

    pub fn silence_frame(&self) -> Vec<f32> {
        vec![0.0f32; AUDIO_FRAME_SAMPLES_PER_CH * usize::from(self.channels)]
    }

    /// Decodes a non-empty Opus payload via `opus_decode_float`.
    pub fn decode_active(&mut self, payload: &[u8]) -> Result<Vec<f32>, AudioError> {
        if payload.is_empty() {
            return Err(AudioError::InvalidFraming {
                error_code: AUDIO_ERROR_INVALID_FRAMING,
                reason: "decode_active called with empty payload (use DTX silence path instead)"
                    .into(),
            });
        }
        let mut pcm = vec![0.0f32; AUDIO_FRAME_SAMPLES_PER_CH * usize::from(self.channels)];
        let decoded = unsafe {
            opus_decode_float(
                self.raw.as_ptr(),
                payload.as_ptr(),
                payload.len() as i32,
                pcm.as_mut_ptr(),
                AUDIO_FRAME_SAMPLES_PER_CH as c_int,
                0,
            )
        };
        if decoded < 0 {
            return Err(AudioError::OpusError {
                op: "opus_decode_float",
                code: decoded,
            });
        }
        self.active_decode_calls = self.active_decode_calls.saturating_add(1);
        pcm.truncate((decoded as usize) * usize::from(self.channels));
        Ok(pcm)
    }

    /// Runs `libopus` packet-loss concealment (`data = NULL, len = 0`).
    pub fn decode_plc(&mut self) -> Result<Vec<f32>, AudioError> {
        let mut pcm = vec![0.0f32; AUDIO_FRAME_SAMPLES_PER_CH * usize::from(self.channels)];
        let decoded = unsafe {
            opus_decode_float(
                self.raw.as_ptr(),
                std::ptr::null(),
                0,
                pcm.as_mut_ptr(),
                AUDIO_FRAME_SAMPLES_PER_CH as c_int,
                0,
            )
        };
        if decoded < 0 {
            return Err(AudioError::OpusError {
                op: "opus_decode_float(PLC)",
                code: decoded,
            });
        }
        self.plc_decode_calls = self.plc_decode_calls.saturating_add(1);
        pcm.truncate((decoded as usize) * usize::from(self.channels));
        Ok(pcm)
    }

    /// Resets internal Opus decoder state (`OPUS_RESET_STATE`) when latching silence after 5 PLC frames.
    pub fn reset(&mut self) -> Result<(), AudioError> {
        let rc = unsafe { opus_decoder_ctl(self.raw.as_ptr(), OPUS_RESET_STATE) };
        if rc != OPUS_OK {
            return Err(AudioError::OpusError {
                op: "opus_decoder_ctl(OPUS_RESET_STATE)",
                code: rc,
            });
        }
        self.reset_calls = self.reset_calls.saturating_add(1);
        Ok(())
    }

    /// Executes a `JitterPlayoutAction` adhering strictly to `spec/04` §3.1:
    /// - Zero-length `dtx_u8 = 1` outputs 960 silence samples directly WITHOUT calling `opus_decode(len = 0)`.
    /// - `SilenceAndResetDecoder` resets decoder state and outputs silence.
    pub fn execute_playout(&mut self, action: JitterPlayoutAction) -> Result<Vec<f32>, AudioError> {
        match action {
            JitterPlayoutAction::DecodeActive(payload)
            | JitterPlayoutAction::DecodeCng(payload) => self.decode_active(&payload),
            JitterPlayoutAction::DtxSilence
            | JitterPlayoutAction::LatchedSilence
            | JitterPlayoutAction::WaitingPrime => Ok(self.silence_frame()),
            JitterPlayoutAction::ConcealPlc => self.decode_plc(),
            JitterPlayoutAction::SilenceAndResetDecoder => {
                self.reset()?;
                Ok(self.silence_frame())
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JitterPushOutcome {
    Accepted,
    DroppedLate,
    DroppedMisaligned,
    DroppedFarFuture,
    DroppedBufferFull,
    DroppedDuplicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JitterPlayoutAction {
    WaitingPrime,
    DecodeActive(Vec<u8>),
    DecodeCng(Vec<u8>),
    DtxSilence,
    ConcealPlc,
    SilenceAndResetDecoder,
    LatchedSilence,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AudioJitterStats {
    pub active_frames_played: u64,
    pub dtx_frames_played: u64,
    pub plc_frames: u64,
    pub silence_after_plc_cap: u64,
    pub decoder_resets: u64,
    pub late_dropped: u64,
    pub far_future_dropped: u64,
    pub misaligned_dropped: u64,
    pub duplicate_dropped: u64,
    pub loss_events: u64,
}

/// Normative `spec/04` §3.1 audio jitter buffer (`2..=8` frames = `40..=160ms`) with:
/// - RFC 1982 modular 32-bit `ts_u32` wrap-around arithmetic,
/// - Strict rejection of `delta < 0`, `delta % 960 != 0`, and `delta >= 8*960` / full buffer
///   WITHOUT evicting the oldest imminent slot,
/// - DTX silence/CNG handling with zero packet-loss inflation,
/// - Hard 5-frame (100ms) consecutive PLC cap latching `decoder_silenced = true` + decoder reset
///   until the next active (`dtx_u8 = 0`) frame arrives.
#[derive(Debug, Clone)]
pub struct AudioJitterBuffer {
    min_frames: usize,
    max_frames: usize,
    playout_ts: Option<u32>,
    primed: bool,
    slots: BTreeMap<u32, OpusWireFrame>,
    consecutive_plc: u32,
    decoder_silenced: bool,
    pub stats: AudioJitterStats,
}

impl AudioJitterBuffer {
    pub fn new(min_frames: usize, max_frames: usize) -> Self {
        let min_f = min_frames.clamp(AUDIO_JITTER_MIN_FRAMES, AUDIO_JITTER_MAX_FRAMES);
        let max_f = max_frames.clamp(min_f, AUDIO_JITTER_MAX_FRAMES);
        Self {
            min_frames: min_f,
            max_frames: max_f,
            playout_ts: None,
            primed: false,
            slots: BTreeMap::new(),
            consecutive_plc: 0,
            decoder_silenced: false,
            stats: AudioJitterStats::default(),
        }
    }

    pub fn buffered_len(&self) -> usize {
        self.slots.len()
    }

    pub fn playout_ts(&self) -> Option<u32> {
        self.playout_ts
    }

    pub fn consecutive_plc(&self) -> u32 {
        self.consecutive_plc
    }

    pub fn is_decoder_silenced(&self) -> bool {
        self.decoder_silenced
    }

    pub fn is_primed(&self) -> bool {
        self.primed
    }

    pub fn push(&mut self, frame: OpusWireFrame) -> JitterPushOutcome {
        let base_ts = match self.playout_ts {
            Some(ts) => ts,
            None => {
                self.playout_ts = Some(frame.ts_u32);
                frame.ts_u32
            }
        };

        let delta = audio_ts_delta(frame.ts_u32, base_ts);
        if delta < 0 {
            self.stats.late_dropped = self.stats.late_dropped.saturating_add(1);
            return JitterPushOutcome::DroppedLate;
        }
        let step = AUDIO_FRAME_SAMPLES_PER_CH as i32;
        if delta % step != 0 {
            self.stats.misaligned_dropped = self.stats.misaligned_dropped.saturating_add(1);
            return JitterPushOutcome::DroppedMisaligned;
        }
        let slot_offset = (delta / step) as usize;
        if slot_offset >= self.max_frames {
            self.stats.far_future_dropped = self.stats.far_future_dropped.saturating_add(1);
            return JitterPushOutcome::DroppedFarFuture;
        }
        if self.slots.contains_key(&frame.ts_u32) {
            self.stats.duplicate_dropped = self.stats.duplicate_dropped.saturating_add(1);
            return JitterPushOutcome::DroppedDuplicate;
        }
        if self.slots.len() >= self.max_frames {
            self.stats.far_future_dropped = self.stats.far_future_dropped.saturating_add(1);
            return JitterPushOutcome::DroppedBufferFull;
        }

        self.slots.insert(frame.ts_u32, frame);
        if !self.primed && self.slots.len() >= self.min_frames {
            self.primed = true;
        }
        JitterPushOutcome::Accepted
    }

    /// Advances the playout cursor by one 20ms (960-sample) slot and returns the action to run.
    pub fn pop_playout(&mut self) -> JitterPlayoutAction {
        if !self.primed {
            return JitterPlayoutAction::WaitingPrime;
        }
        let Some(cur_ts) = self.playout_ts else {
            return JitterPlayoutAction::WaitingPrime;
        };
        self.playout_ts = Some(cur_ts.wrapping_add(AUDIO_FRAME_SAMPLES_PER_CH as u32));

        if let Some(frame) = self.slots.remove(&cur_ts) {
            if frame.dtx {
                self.stats.dtx_frames_played = self.stats.dtx_frames_played.saturating_add(1);
                // DTX is NOT packet loss: do not increment loss_events or consecutive_plc.
                self.consecutive_plc = 0;
                if frame.payload.is_empty() {
                    JitterPlayoutAction::DtxSilence
                } else {
                    JitterPlayoutAction::DecodeCng(frame.payload)
                }
            } else {
                self.stats.active_frames_played = self.stats.active_frames_played.saturating_add(1);
                self.consecutive_plc = 0;
                self.decoder_silenced = false;
                JitterPlayoutAction::DecodeActive(frame.payload)
            }
        } else if self.decoder_silenced {
            self.stats.silence_after_plc_cap = self.stats.silence_after_plc_cap.saturating_add(1);
            self.stats.loss_events = self.stats.loss_events.saturating_add(1);
            JitterPlayoutAction::LatchedSilence
        } else if self.consecutive_plc < AUDIO_MAX_CONSECUTIVE_PLC {
            self.consecutive_plc = self.consecutive_plc.saturating_add(1);
            self.stats.plc_frames = self.stats.plc_frames.saturating_add(1);
            self.stats.loss_events = self.stats.loss_events.saturating_add(1);
            JitterPlayoutAction::ConcealPlc
        } else {
            self.decoder_silenced = true;
            self.stats.decoder_resets = self.stats.decoder_resets.saturating_add(1);
            self.stats.silence_after_plc_cap = self.stats.silence_after_plc_cap.saturating_add(1);
            self.stats.loss_events = self.stats.loss_events.saturating_add(1);
            JitterPlayoutAction::SilenceAndResetDecoder
        }
    }
}

/// Policy and mute gate enforced on BOTH sender and receiver (`spec/04` §3.1 + `spec/06` §3.8).
#[derive(Debug, Clone)]
pub struct AudioChannelGate {
    policy_allow_audio: bool,
    muted: bool,
}

impl AudioChannelGate {
    pub fn from_policy(policy: &EffectiveTenantPolicy) -> Self {
        Self {
            policy_allow_audio: policy.allow_audio(),
            muted: false,
        }
    }

    pub fn set_muted(&mut self, muted: bool) {
        self.muted = muted;
    }

    pub fn is_muted(&self) -> bool {
        self.muted
    }

    pub fn policy_allows_audio(&self) -> bool {
        self.policy_allow_audio
    }

    /// Returns `Ok(true)` when audio may be transmitted/played, `Ok(false)` when muted locally,
    /// or `Err(AudioError::PolicyDenied)` when the tenant policy disables audio.
    pub fn check_allowed(&self) -> Result<bool, AudioError> {
        if !self.policy_allow_audio {
            return Err(AudioError::PolicyDenied(
                "tenant policy flags.allow_audio is disabled".into(),
            ));
        }
        Ok(!self.muted)
    }
}

/// Abstract audio capture source producing 20ms (`960 * channels`) 48 kHz float PCM frames.
pub trait AudioSource: Send {
    fn channels(&self) -> u8;
    fn next_frame(&mut self) -> Option<Vec<f32>>;
}

/// Abstract audio playback sink consuming 20ms (`960 * channels`) 48 kHz float PCM frames.
pub trait AudioSink: Send {
    fn channels(&self) -> u8;
    fn write_frame(&mut self, pcm: &[f32]) -> Result<(), AudioError>;
}

/// Deterministic synthetic audio generator emitting multi-tone (`440 Hz + 880 Hz`) active
/// frames followed by pure-silence DTX frames and optional trailing active frames.
#[derive(Debug, Clone)]
pub struct SyntheticMultiToneSource {
    channels: u8,
    active_lead_frames: usize,
    silence_frames: usize,
    active_tail_frames: usize,
    frame_idx: usize,
}

impl SyntheticMultiToneSource {
    pub fn new(
        channels: u8,
        active_lead_frames: usize,
        silence_frames: usize,
        active_tail_frames: usize,
    ) -> Result<Self, AudioError> {
        if channels != 1 && channels != 2 {
            return Err(AudioError::InvalidChannels(channels));
        }
        Ok(Self {
            channels,
            active_lead_frames,
            silence_frames,
            active_tail_frames,
            frame_idx: 0,
        })
    }

    pub fn total_frames(&self) -> usize {
        self.active_lead_frames + self.silence_frames + self.active_tail_frames
    }

    pub fn frame_pcm(channels: u8, frame_idx: usize, is_silence: bool) -> Vec<f32> {
        let ch = usize::from(channels);
        let mut out = vec![0.0f32; AUDIO_FRAME_SAMPLES_PER_CH * ch];
        if is_silence {
            return out;
        }
        let base_sample = frame_idx * AUDIO_FRAME_SAMPLES_PER_CH;
        let sr = AUDIO_SAMPLE_RATE_HZ as f32;
        for s in 0..AUDIO_FRAME_SAMPLES_PER_CH {
            let t = ((base_sample + s) as f32) / sr;
            let sample = 0.35 * (TAU * 440.0 * t).sin() + 0.25 * (TAU * 880.0 * t).sin();
            for c in 0..ch {
                out[s * ch + c] = sample;
            }
        }
        out
    }
}

impl AudioSource for SyntheticMultiToneSource {
    fn channels(&self) -> u8 {
        self.channels
    }

    fn next_frame(&mut self) -> Option<Vec<f32>> {
        let total = self.total_frames();
        if self.frame_idx >= total {
            return None;
        }
        let is_silence = self.frame_idx >= self.active_lead_frames
            && self.frame_idx < self.active_lead_frames + self.silence_frames;
        let pcm = Self::frame_pcm(self.channels, self.frame_idx, is_silence);
        self.frame_idx += 1;
        Some(pcm)
    }
}

/// Headless recording sink capturing decoded float PCM samples for SNR/correlation verification.
#[derive(Debug, Clone)]
pub struct RecordingAudioSink {
    channels: u8,
    pub frames: Vec<Vec<f32>>,
}

impl RecordingAudioSink {
    pub fn new(channels: u8) -> Result<Self, AudioError> {
        if channels != 1 && channels != 2 {
            return Err(AudioError::InvalidChannels(channels));
        }
        Ok(Self {
            channels,
            frames: Vec::new(),
        })
    }

    pub fn all_samples(&self) -> Vec<f32> {
        let mut out = Vec::new();
        for f in &self.frames {
            out.extend_from_slice(f);
        }
        out
    }
}

impl AudioSink for RecordingAudioSink {
    fn channels(&self) -> u8 {
        self.channels
    }

    fn write_frame(&mut self, pcm: &[f32]) -> Result<(), AudioError> {
        self.frames.push(pcm.to_vec());
        Ok(())
    }
}

/// Audio fidelity metrics between reference and decoded PCM (lag-aligned for Opus algorithmic
/// lookahead delay).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AudioQualityMetrics {
    pub best_lag_samples: usize,
    pub correlation: f64,
    pub snr_db: f64,
    pub rms_ref: f64,
    pub rms_decoded: f64,
}

/// Computes lag-aligned Pearson correlation and SNR (dB) between `reference` and `decoded` mono
/// (or interleaved) PCM, searching lags `0..=max_lag_samples` (typically `<= 960`) to compensate
/// for `libopus` encoder lookahead (~312 samples at 48 kHz).
pub fn measure_audio_quality(
    reference: &[f32],
    decoded: &[f32],
    max_lag_samples: usize,
) -> AudioQualityMetrics {
    let n = reference.len().min(decoded.len());
    if n < 64 {
        return AudioQualityMetrics {
            best_lag_samples: 0,
            correlation: 0.0,
            snr_db: -100.0,
            rms_ref: 0.0,
            rms_decoded: 0.0,
        };
    }

    let max_lag = max_lag_samples.min(n / 2);
    let mut best_lag = 0usize;
    let mut best_corr = -2.0f64;
    let mut best_snr = -100.0f64;
    let mut best_rms_ref = 0.0f64;
    let mut best_rms_dec = 0.0f64;

    for lag in 0..=max_lag {
        let len = n - lag;
        let r_slice = &reference[..len];
        let d_slice = &decoded[lag..lag + len];
        let mut dot = 0.0f64;
        let mut e_ref = 0.0f64;
        let mut e_dec = 0.0f64;
        let mut e_err = 0.0f64;
        for (&r, &d) in r_slice.iter().zip(d_slice.iter()) {
            let rf = f64::from(r);
            let df = f64::from(d);
            dot += rf * df;
            e_ref += rf * rf;
            e_dec += df * df;
            let diff = rf - df;
            e_err += diff * diff;
        }
        let denom = (e_ref * e_dec).sqrt();
        let corr = if denom > 1e-12 { dot / denom } else { 0.0 };
        if corr > best_corr {
            best_corr = corr;
            best_lag = lag;
            best_rms_ref = (e_ref / (len as f64)).sqrt();
            best_rms_dec = (e_dec / (len as f64)).sqrt();
            best_snr = if e_err <= 1e-12 {
                100.0
            } else if e_ref <= 1e-12 {
                -100.0
            } else {
                10.0 * (e_ref / e_err).log10()
            };
        }
    }

    AudioQualityMetrics {
        best_lag_samples: best_lag,
        correlation: best_corr,
        snr_db: best_snr,
        rms_ref: best_rms_ref,
        rms_decoded: best_rms_dec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2_session::policy::{
        EffectiveTenantPolicy, TenantPolicyBody, POLICY_FLAG_ALLOW_AUDIO,
    };
    use serde_json::Value;

    const V27_PATH: &str =
        "/Volumes/data/github/zerodesk/protocol-spec/vectors/v27_policy_clipboard_file.json";

    #[test]
    fn audio_wire_framing_matches_v27_golden_vectors() {
        let raw_json = std::fs::read_to_string(V27_PATH).unwrap();
        let v: Value = serde_json::from_str(&raw_json).unwrap();
        let a = &v["audio_dtx_plc"];

        let active_bytes = hex::decode(a["active_frame_hex"].as_str().unwrap()).unwrap();
        let active = OpusWireFrame::decode(&active_bytes).unwrap();
        assert!(!active.dtx);
        assert_eq!(active.ts_u32, 4294966336);
        assert_eq!(active.encode().unwrap(), active_bytes);

        let cng_bytes = hex::decode(a["dtx_cng_frame_hex"].as_str().unwrap()).unwrap();
        let cng = OpusWireFrame::decode(&cng_bytes).unwrap();
        assert!(cng.dtx);
        assert_eq!(cng.ts_u32, 960);
        assert_eq!(cng.encode().unwrap(), cng_bytes);

        let sil_bytes = hex::decode(a["dtx_silence_frame_hex"].as_str().unwrap()).unwrap();
        let sil = OpusWireFrame::decode(&sil_bytes).unwrap();
        assert!(sil.dtx);
        assert!(sil.payload.is_empty());
        assert_eq!(sil.ts_u32, 0);
        assert_eq!(sil.encode().unwrap(), sil_bytes);

        // Negative wire cases -> 0x0103 INVALID_FRAMING
        for key in [
            "invalid_active_empty_hex",
            "invalid_dtx_2_hex",
            "invalid_truncated_4b_hex",
        ] {
            let bad = hex::decode(a[key].as_str().unwrap()).unwrap();
            let err = OpusWireFrame::decode(&bad).unwrap_err();
            assert!(
                matches!(
                    err,
                    AudioError::InvalidFraming {
                        error_code: AUDIO_ERROR_INVALID_FRAMING,
                        ..
                    }
                ),
                "case {key} expected 0x0103, got {err:?}"
            );
        }

        // Wrap-around modular comparison
        let older = a["wrap_around_ts_older"].as_u64().unwrap() as u32;
        let newer = a["wrap_around_ts_newer"].as_u64().unwrap() as u32;
        assert!(audio_ts_gt(newer, older));
        assert!(!audio_ts_gt(older, newer));
        assert_eq!(audio_ts_delta(newer, older), 960);
    }

    #[test]
    fn real_libopus_multitone_snr_dtx_and_survival_mode() {
        let mut enc = V2AudioEncoder::new(1, AUDIO_DEFAULT_BITRATE_BPS).unwrap();
        let mut dec = V2AudioDecoder::new(1).unwrap();
        let mut src = SyntheticMultiToneSource::new(1, 30, 15, 10).unwrap();
        let mut sink = RecordingAudioSink::new(1).unwrap();

        let mut ref_lead = Vec::new();
        let mut dtx_count = 0usize;
        let mut active_count = 0usize;
        let mut ts: u32 = u32::MAX - (960 * 3) + 1; // Exercise u32 wrap-around!
        let mut jb = AudioJitterBuffer::new(2, 8);

        for idx in 0..src.total_frames() {
            let pcm = src.next_frame().unwrap();
            if idx < 30 {
                ref_lead.extend_from_slice(&pcm);
            }
            let encoded = enc.encode_frame(&pcm).unwrap();
            let wire = OpusWireFrame {
                ts_u32: ts,
                dtx: encoded.dtx,
                payload: encoded.payload,
            };
            if wire.dtx {
                dtx_count += 1;
            } else {
                active_count += 1;
            }
            let bytes = wire.encode().unwrap();
            let decoded_wire = OpusWireFrame::decode(&bytes).unwrap();
            assert_eq!(jb.push(decoded_wire), JitterPushOutcome::Accepted);
            if jb.is_primed() {
                let act = jb.pop_playout();
                let out_pcm = dec.execute_playout(act).unwrap();
                sink.write_frame(&out_pcm).unwrap();
            }
            ts = ts.wrapping_add(AUDIO_FRAME_SAMPLES_PER_CH as u32);
        }
        // Drain remaining buffered frames
        while jb.buffered_len() > 0 {
            let act = jb.pop_playout();
            let out_pcm = dec.execute_playout(act).unwrap();
            sink.write_frame(&out_pcm).unwrap();
        }

        assert!(active_count >= 30, "expected active frames, got {active_count}");
        assert!(dtx_count >= 1, "expected DTX silence frames during 15-frame silence");
        assert_eq!(jb.stats.loss_events, 0, "DTX must never count as packet loss");

        // Verify real multi-tone SNR & correlation on lead active segment (skip first 2 warmup frames)
        let decoded_all = sink.all_samples();
        let skip = AUDIO_FRAME_SAMPLES_PER_CH * 2;
        let ref_seg = &ref_lead[skip..AUDIO_FRAME_SAMPLES_PER_CH * 28];
        let dec_seg = &decoded_all[skip..AUDIO_FRAME_SAMPLES_PER_CH * 28];
        let q = measure_audio_quality(ref_seg, dec_seg, 960);
        assert!(
            q.correlation >= 0.90,
            "Opus 440+880Hz correlation too low: {:?}",
            q
        );
        assert!(
            q.snr_db >= 10.0,
            "Opus 440+880Hz SNR too low: {:?}",
            q
        );

        // Survival mode switches cleanly to 16..24 kbps and still encodes valid frames
        enc.set_survival_mode(true).unwrap();
        assert!(enc.survival_mode());
        assert!(
            (AUDIO_SURVIVAL_MIN_BITRATE_BPS..=AUDIO_SURVIVAL_MAX_BITRATE_BPS)
                .contains(&enc.bitrate_bps())
        );
        let surv_pcm = SyntheticMultiToneSource::frame_pcm(1, 0, false);
        let surv_enc = enc.encode_frame(&surv_pcm).unwrap();
        assert!(!surv_enc.payload.is_empty());
        let _ = dec.decode_active(&surv_enc.payload).unwrap();
    }

    #[test]
    fn jitter_buffer_12_slot_plc_cap_latches_silence_and_dtx_zero_len_skips_opus_decode() {
        let mut enc = V2AudioEncoder::new(1, AUDIO_DEFAULT_BITRATE_BPS).unwrap();
        let mut dec = V2AudioDecoder::new(1).unwrap();
        let mut jb = AudioJitterBuffer::new(2, 8);

        let active_pcm = SyntheticMultiToneSource::frame_pcm(1, 0, false);
        let active_payload = enc.encode_frame(&active_pcm).unwrap().payload;

        // Prime with 2 active frames at ts=0, 960
        assert_eq!(
            jb.push(OpusWireFrame {
                ts_u32: 0,
                dtx: false,
                payload: active_payload.clone(),
            }),
            JitterPushOutcome::Accepted
        );
        assert_eq!(
            jb.push(OpusWireFrame {
                ts_u32: 960,
                dtx: false,
                payload: active_payload.clone(),
            }),
            JitterPushOutcome::Accepted
        );
        // Far-future frame (delta = 8 * 960) MUST be rejected without evicting ts=0
        assert_eq!(
            jb.push(OpusWireFrame {
                ts_u32: 8 * 960,
                dtx: false,
                payload: active_payload.clone(),
            }),
            JitterPushOutcome::DroppedFarFuture
        );
        // Misaligned timestamp MUST be rejected
        assert_eq!(
            jb.push(OpusWireFrame {
                ts_u32: 1000,
                dtx: false,
                payload: active_payload.clone(),
            }),
            JitterPushOutcome::DroppedMisaligned
        );

        // Zero-length DTX frame at ts=1920 outputs 960 silence samples WITHOUT calling opus_decode
        assert_eq!(
            jb.push(OpusWireFrame {
                ts_u32: 1920,
                dtx: true,
                payload: Vec::new(),
            }),
            JitterPushOutcome::Accepted
        );

        let a0 = jb.pop_playout();
        assert!(matches!(a0, JitterPlayoutAction::DecodeActive(_)));
        let _ = dec.execute_playout(a0).unwrap();
        let a1 = jb.pop_playout();
        assert!(matches!(a1, JitterPlayoutAction::DecodeActive(_)));
        let _ = dec.execute_playout(a1).unwrap();

        let active_calls_before_dtx = dec.active_decode_calls;
        let plc_calls_before_dtx = dec.plc_decode_calls;
        let a2 = jb.pop_playout();
        assert_eq!(a2, JitterPlayoutAction::DtxSilence);
        let sil_pcm = dec.execute_playout(a2).unwrap();
        assert_eq!(sil_pcm.len(), 960);
        assert!(sil_pcm.iter().all(|&s| s == 0.0));
        assert_eq!(dec.active_decode_calls, active_calls_before_dtx);
        assert_eq!(dec.plc_decode_calls, plc_calls_before_dtx);
        assert_eq!(jb.stats.loss_events, 0);

        // Late frame (delta < 0) rejected
        assert_eq!(
            jb.push(OpusWireFrame {
                ts_u32: 0,
                dtx: false,
                payload: active_payload.clone(),
            }),
            JitterPushOutcome::DroppedLate
        );

        // 12 consecutive missing slots:
        // slots 1..=5 -> ConcealPlc (5 PLC calls)
        // slot 6 -> SilenceAndResetDecoder (latches decoder_silenced = true, calls opus_decoder_ctl(RESET))
        // slots 7..=12 -> LatchedSilence (ZERO additional PLC calls!)
        for slot in 1..=12 {
            let act = jb.pop_playout();
            match slot {
                1..=5 => assert_eq!(act, JitterPlayoutAction::ConcealPlc),
                6 => assert_eq!(act, JitterPlayoutAction::SilenceAndResetDecoder),
                7..=12 => assert_eq!(act, JitterPlayoutAction::LatchedSilence),
                _ => unreachable!(),
            }
            let out = dec.execute_playout(act).unwrap();
            assert_eq!(out.len(), 960);
            if slot >= 6 {
                assert!(out.iter().all(|&s| s == 0.0));
                assert!(jb.is_decoder_silenced());
            }
        }
        assert_eq!(dec.plc_decode_calls, 5);
        assert_eq!(dec.reset_calls, 1);

        // Next valid active frame clears decoder_silenced
        let cur = jb.playout_ts().unwrap();
        assert_eq!(
            jb.push(OpusWireFrame {
                ts_u32: cur,
                dtx: false,
                payload: active_payload,
            }),
            JitterPushOutcome::Accepted
        );
        let recovered = jb.pop_playout();
        assert!(matches!(recovered, JitterPlayoutAction::DecodeActive(_)));
        assert!(!jb.is_decoder_silenced());
        assert_eq!(jb.consecutive_plc(), 0);
    }

    #[test]
    fn audio_policy_gate_enforces_allow_audio_and_mute() {
        let allowed = EffectiveTenantPolicy {
            tenant_id: [1; 16],
            version: 1,
            policy_hash: [2; 32],
            body: TenantPolicyBody {
                schema_ver: 1,
                flags: POLICY_FLAG_ALLOW_AUDIO,
                max_bw_kbps: 20_000,
                max_file_mb: 0,
                max_clipboard_kb: 0,
            },
            degraded: false,
            degraded_reason: None,
        };
        let mut gate = AudioChannelGate::from_policy(&allowed);
        assert_eq!(gate.check_allowed(), Ok(true));
        gate.set_muted(true);
        assert_eq!(gate.check_allowed(), Ok(false));

        let denied = EffectiveTenantPolicy::degraded([1; 16], [2; 32], "degraded");
        let denied_gate = AudioChannelGate::from_policy(&denied);
        assert!(matches!(
            denied_gate.check_allowed(),
            Err(AudioError::PolicyDenied(_))
        ));
    }
}
