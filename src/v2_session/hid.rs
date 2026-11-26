// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use bytes::Bytes;
use std::fmt;
use v2_transport::{HidFrame, L4Header, HID_STALE_DROP_MS, L4_HDR_LEN};

pub const HID_MSG_MOUSE: u8 = 0x01;
pub const HID_MSG_KEY: u8 = 0x02;
pub const HID_MSG_ECHO_ACK: u8 = 0x03;

/// Fixed big-endian wire length for `MouseEvent`:
/// `kind(1) + buttons(1) + x_or_dx(4) + y_or_dy(4) + wheel_dx(2) + wheel_dy(2) + client_ts_ms(8) = 22`.
pub const MOUSE_EVENT_WIRE_LEN: usize = 22;
/// Fixed big-endian wire length for `KeyEvent`:
/// `down(1) + modifiers(1) + usb_hid_usage(4) + unicode_scalar(4) + client_ts_ms(8) = 18`.
pub const KEY_EVENT_WIRE_LEN: usize = 18;
/// Fixed big-endian wire length for `HidEchoAck`:
/// `echo_seq(4) + client_ts_ms(8) = 12`.
pub const HID_ECHO_ACK_WIRE_LEN: usize = 12;

/// Hard upper bound on contiguous `MoveRel` events coalesced into a single emission (spec/04 §6.2.3).
pub const HID_MOVEREL_COALESCE_MAX: usize = 128;
/// Zero hold time: coalesced `MoveRel` runs flush immediately at end of batch or non-`MoveRel` boundary.
pub const HID_MAX_COALESCE_HOLD_MS: u64 = 0;
/// Session-fatal `ErrorCode::InvalidFraming` (`0x0103` = 259) per spec/04 §5 & §6.
pub const ERROR_CODE_INVALID_FRAMING: u16 = 0x0103;

pub const MOD_SHIFT: u8 = 1 << 0;
pub const MOD_CTRL: u8 = 1 << 1;
pub const MOD_ALT: u8 = 1 << 2;
pub const MOD_META: u8 = 1 << 3;
const MOD_VALID_MASK: u8 = MOD_SHIFT | MOD_CTRL | MOD_ALT | MOD_META;
pub const MOUSE_BUTTONS_VALID_MASK: u8 = 0x1F;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidCodecError {
    /// Any `0x01 InputHID` wire/framing violation corresponding to session-fatal `0x0103 INVALID_FRAMING`.
    InvalidFraming(String),
}

impl HidCodecError {
    pub fn error_code(&self) -> u16 {
        ERROR_CODE_INVALID_FRAMING
    }
}

impl fmt::Display for HidCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFraming(msg) => write!(f, "INVALID_FRAMING (0x0103): {msg}"),
        }
    }
}

impl std::error::Error for HidCodecError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MouseKind {
    MoveAbs = 0,
    MoveRel = 1,
    Down = 2,
    Up = 3,
    Wheel = 4,
}

impl MouseKind {
    pub fn from_u8(v: u8) -> Result<Self, HidCodecError> {
        match v {
            0 => Ok(Self::MoveAbs),
            1 => Ok(Self::MoveRel),
            2 => Ok(Self::Down),
            3 => Ok(Self::Up),
            4 => Ok(Self::Wheel),
            other => Err(HidCodecError::InvalidFraming(format!(
                "invalid mouse event kind discriminant {other}"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEvent {
    pub kind: MouseKind,
    pub buttons: u8,
    pub x_or_dx: i32,
    pub y_or_dy: i32,
    pub wheel_dx: i16,
    pub wheel_dy: i16,
    pub client_ts_ms: u64,
}

impl MouseEvent {
    pub fn validate(&self) -> Result<(), HidCodecError> {
        if self.buttons & !MOUSE_BUTTONS_VALID_MASK != 0 {
            return Err(HidCodecError::InvalidFraming(format!(
                "reserved mouse button bits set: {:#04x}",
                self.buttons
            )));
        }
        if self.kind != MouseKind::Wheel && (self.wheel_dx != 0 || self.wheel_dy != 0) {
            return Err(HidCodecError::InvalidFraming(format!(
                "non-zero wheel delta ({}, {}) on non-Wheel mouse event {:?}",
                self.wheel_dx, self.wheel_dy, self.kind
            )));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; MOUSE_EVENT_WIRE_LEN], HidCodecError> {
        self.validate()?;
        let mut out = [0u8; MOUSE_EVENT_WIRE_LEN];
        out[0] = self.kind as u8;
        out[1] = self.buttons;
        out[2..6].copy_from_slice(&self.x_or_dx.to_be_bytes());
        out[6..10].copy_from_slice(&self.y_or_dy.to_be_bytes());
        out[10..12].copy_from_slice(&self.wheel_dx.to_be_bytes());
        out[12..14].copy_from_slice(&self.wheel_dy.to_be_bytes());
        out[14..22].copy_from_slice(&self.client_ts_ms.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HidCodecError> {
        if bytes.len() != MOUSE_EVENT_WIRE_LEN {
            return Err(HidCodecError::InvalidFraming(format!(
                "invalid MouseEvent payload length: expected {MOUSE_EVENT_WIRE_LEN}, got {}",
                bytes.len()
            )));
        }
        let kind = MouseKind::from_u8(bytes[0])?;
        let ev = Self {
            kind,
            buttons: bytes[1],
            x_or_dx: i32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            y_or_dy: i32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
            wheel_dx: i16::from_be_bytes([bytes[10], bytes[11]]),
            wheel_dy: i16::from_be_bytes([bytes[12], bytes[13]]),
            client_ts_ms: u64::from_be_bytes([
                bytes[14], bytes[15], bytes[16], bytes[17], bytes[18], bytes[19], bytes[20],
                bytes[21],
            ]),
        };
        ev.validate()?;
        Ok(ev)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    pub down: bool,
    pub modifiers: u8,
    pub usb_hid_usage: u32,
    pub unicode_scalar: u32,
    pub client_ts_ms: u64,
}

/// Returns the required `modifiers` bitmap bit when pressing (`down == true`) a USB HID modifier
/// key (`0xE0..=0xE7`, with or without Usage Page `0x07` prefix) per `spec/04` §6.1.2.
pub fn required_modifier_bit_for_usage(usb_hid_usage: u32) -> Option<u8> {
    match usb_hid_usage {
        0xE0 | 0xE4 | 0x0007_00E0 | 0x0007_00E4 => Some(MOD_CTRL),
        0xE1 | 0xE5 | 0x0007_00E1 | 0x0007_00E5 => Some(MOD_SHIFT),
        0xE2 | 0xE6 | 0x0007_00E2 | 0x0007_00E6 => Some(MOD_ALT),
        0xE3 | 0xE7 | 0x0007_00E3 | 0x0007_00E7 => Some(MOD_META),
        _ => None,
    }
}

impl KeyEvent {
    pub fn validate(&self) -> Result<(), HidCodecError> {
        if self.modifiers & !MOD_VALID_MASK != 0 {
            return Err(HidCodecError::InvalidFraming(format!(
                "reserved key modifier bits set: {:#04x}",
                self.modifiers
            )));
        }
        if self.unicode_scalar != 0 && char::from_u32(self.unicode_scalar).is_none() {
            return Err(HidCodecError::InvalidFraming(format!(
                "invalid unicode scalar {:#010x}",
                self.unicode_scalar
            )));
        }
        if self.down {
            if let Some(required_bit) = required_modifier_bit_for_usage(self.usb_hid_usage) {
                if (self.modifiers & required_bit) == 0 {
                    return Err(HidCodecError::InvalidFraming(format!(
                        "modifier key down usage {:#x} missing required modifier bit {required_bit:#04x} (got {:#04x})",
                        self.usb_hid_usage, self.modifiers
                    )));
                }
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; KEY_EVENT_WIRE_LEN], HidCodecError> {
        self.validate()?;
        let mut out = [0u8; KEY_EVENT_WIRE_LEN];
        out[0] = u8::from(self.down);
        out[1] = self.modifiers;
        out[2..6].copy_from_slice(&self.usb_hid_usage.to_be_bytes());
        out[6..10].copy_from_slice(&self.unicode_scalar.to_be_bytes());
        out[10..18].copy_from_slice(&self.client_ts_ms.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HidCodecError> {
        if bytes.len() != KEY_EVENT_WIRE_LEN {
            return Err(HidCodecError::InvalidFraming(format!(
                "invalid KeyEvent payload length: expected {KEY_EVENT_WIRE_LEN}, got {}",
                bytes.len()
            )));
        }
        let down = match bytes[0] {
            0 => false,
            1 => true,
            other => {
                return Err(HidCodecError::InvalidFraming(format!(
                    "invalid KeyEvent.down flag {other} (expected 0 or 1)"
                )));
            }
        };
        let ev = Self {
            down,
            modifiers: bytes[1],
            usb_hid_usage: u32::from_be_bytes([bytes[2], bytes[3], bytes[4], bytes[5]]),
            unicode_scalar: u32::from_be_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]),
            client_ts_ms: u64::from_be_bytes([
                bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[16],
                bytes[17],
            ]),
        };
        ev.validate()?;
        Ok(ev)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidEchoAck {
    pub echo_seq: u32,
    pub client_ts_ms: u64,
}

impl HidEchoAck {
    pub fn encode(&self) -> [u8; HID_ECHO_ACK_WIRE_LEN] {
        let mut out = [0u8; HID_ECHO_ACK_WIRE_LEN];
        out[0..4].copy_from_slice(&self.echo_seq.to_be_bytes());
        out[4..12].copy_from_slice(&self.client_ts_ms.to_be_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HidCodecError> {
        if bytes.len() != HID_ECHO_ACK_WIRE_LEN {
            return Err(HidCodecError::InvalidFraming(format!(
                "invalid HidEchoAck payload length: expected {HID_ECHO_ACK_WIRE_LEN}, got {}",
                bytes.len()
            )));
        }
        Ok(Self {
            echo_seq: u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
            client_ts_ms: u64::from_be_bytes([
                bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
            ]),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidPayload {
    Mouse(MouseEvent),
    Key(KeyEvent),
    EchoAck(HidEchoAck),
}

impl HidPayload {
    pub fn client_ts_ms(&self) -> u64 {
        match self {
            Self::Mouse(m) => m.client_ts_ms,
            Self::Key(k) => k.client_ts_ms,
            Self::EchoAck(a) => a.client_ts_ms,
        }
    }
}

pub fn encode_hid_frame(payload: &HidPayload) -> Result<HidFrame, HidCodecError> {
    match payload {
        HidPayload::Mouse(ev) => Ok(HidFrame {
            msg_type: HID_MSG_MOUSE,
            payload: Bytes::copy_from_slice(&ev.encode()?),
        }),
        HidPayload::Key(ev) => Ok(HidFrame {
            msg_type: HID_MSG_KEY,
            payload: Bytes::copy_from_slice(&ev.encode()?),
        }),
        HidPayload::EchoAck(ack) => Ok(HidFrame {
            msg_type: HID_MSG_ECHO_ACK,
            payload: Bytes::copy_from_slice(&ack.encode()),
        }),
    }
}

pub fn decode_hid_frame(frame: &HidFrame) -> Result<HidPayload, HidCodecError> {
    match frame.msg_type {
        HID_MSG_MOUSE => Ok(HidPayload::Mouse(MouseEvent::decode(&frame.payload)?)),
        HID_MSG_KEY => Ok(HidPayload::Key(KeyEvent::decode(&frame.payload)?)),
        HID_MSG_ECHO_ACK => Ok(HidPayload::EchoAck(HidEchoAck::decode(&frame.payload)?)),
        other => Err(HidCodecError::InvalidFraming(format!(
            "unknown InputHID msg_type {other:#04x}"
        ))),
    }
}

/// Encodes an L4-framed `0x01 InputHID` packet (`8B L4Header + exact body`, `flags = 0`).
pub fn encode_l4_hid_frame(
    stream_seq: u32,
    payload: &HidPayload,
) -> Result<Vec<u8>, HidCodecError> {
    let frame = encode_hid_frame(payload)?;
    let body_len = u16::try_from(frame.payload.len()).map_err(|_| {
        HidCodecError::InvalidFraming("InputHID payload exceeds u16::MAX".into())
    })?;
    let hdr = L4Header {
        msg_type: frame.msg_type,
        flags: 0,
        body_len,
        stream_seq,
    };
    let mut out = Vec::with_capacity(L4_HDR_LEN + frame.payload.len());
    out.extend_from_slice(&hdr.encode());
    out.extend_from_slice(&frame.payload);
    Ok(out)
}

/// Decodes and strictly validates an L4-framed `0x01 InputHID` packet per `spec/04` §6.
/// Any truncated header, non-zero `L4Header.flags`, `body_len` mismatch, trailing bytes,
/// unknown `msg_type`, or invalid inner field returns `Err(HidCodecError::InvalidFraming(_))`.
pub fn decode_l4_hid_frame(bytes: &[u8]) -> Result<(u32, HidPayload), HidCodecError> {
    if bytes.len() < L4_HDR_LEN {
        return Err(HidCodecError::InvalidFraming(format!(
            "L4 InputHID frame truncated: {} bytes < {L4_HDR_LEN}",
            bytes.len()
        )));
    }
    let hdr = L4Header::decode(bytes)
        .map_err(|e| HidCodecError::InvalidFraming(e.to_string()))?;
    if hdr.flags != 0 {
        return Err(HidCodecError::InvalidFraming(format!(
            "L4 InputHID reserved flags non-zero: {:#04x}",
            hdr.flags
        )));
    }
    let body = &bytes[L4_HDR_LEN..];
    if body.len() != hdr.body_len as usize {
        return Err(HidCodecError::InvalidFraming(format!(
            "L4 InputHID body_len {} != actual payload length {}",
            hdr.body_len,
            body.len()
        )));
    }
    let frame = HidFrame {
        msg_type: hdr.msg_type,
        payload: Bytes::copy_from_slice(body),
    };
    let payload = decode_hid_frame(&frame)?;
    Ok((hdr.stream_seq, payload))
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HidBatchOutcome {
    pub acked_seqs: Vec<u32>,
    pub executed: Vec<(u32, HidPayload)>,
    pub dropped_stale_seqs: Vec<u32>,
    pub coalesced_rel_count: usize,
}

impl HidBatchOutcome {
    pub fn total_rel_dx(&self) -> i32 {
        self.executed
            .iter()
            .filter_map(|(_, payload)| match payload {
                HidPayload::Mouse(ev) if ev.kind == MouseKind::MoveRel => Some(ev.x_or_dx),
                _ => None,
            })
            .fold(0i32, i32::saturating_add)
    }

    pub fn total_rel_dy(&self) -> i32 {
        self.executed
            .iter()
            .filter_map(|(_, payload)| match payload {
                HidPayload::Mouse(ev) if ev.kind == MouseKind::MoveRel => Some(ev.y_or_dy),
                _ => None,
            })
            .fold(0i32, i32::saturating_add)
    }
}

/// Applies `protocol-spec/spec/04-inner-channels.md` §2 & §6.2.3 stale-drop and bounded
/// contiguous relative-mouse vector coalescing over a batch of `(stream_seq, payload, enqueue_ms)`:
/// - Every event is ACKed regardless of staleness.
/// - `MouseKind::MoveRel` deltas are NEVER dropped; contiguous runs coalesce left-to-right via
///   `i32::saturating_add`, capped at `HID_MOVEREL_COALESCE_MAX = 128`, and flush before any
///   non-`MoveRel` boundary to preserve spatial order.
/// - Release events (`MouseKind::Up` and `KeyEvent { down: false }`) are NEVER dropped so
///   network jitter cannot leave buttons or keys stuck.
/// - Other non-relative mouse events and key-down events queued `> 150ms` are dropped without
///   execution.
pub fn coalesce_hid_batch(
    events: &[(u32, HidPayload, u64)],
    now_ms: u64,
) -> HidBatchOutcome {
    let mut out = HidBatchOutcome::default();
    let mut pending_rel: Option<(u32, MouseEvent, usize)> = None;
    let flush_rel = |pending: &mut Option<(u32, MouseEvent, usize)>, out: &mut HidBatchOutcome| {
        if let Some((rel_seq, rel_ev, _)) = pending.take() {
            out.executed.push((rel_seq, HidPayload::Mouse(rel_ev)));
        }
    };

    for &(seq, payload, enqueue_ms) in events {
        out.acked_seqs.push(seq);
        match payload {
            HidPayload::Mouse(ev) if ev.kind == MouseKind::MoveRel => {
                out.coalesced_rel_count += 1;
                if let Some((_, _, count)) = pending_rel {
                    if count >= HID_MOVEREL_COALESCE_MAX {
                        flush_rel(&mut pending_rel, &mut out);
                    }
                }
                if let Some((last_seq, acc, count)) = &mut pending_rel {
                    *last_seq = seq;
                    acc.x_or_dx = acc.x_or_dx.saturating_add(ev.x_or_dx);
                    acc.y_or_dy = acc.y_or_dy.saturating_add(ev.y_or_dy);
                    acc.buttons = ev.buttons;
                    acc.client_ts_ms = ev.client_ts_ms;
                    *count += 1;
                } else {
                    pending_rel = Some((seq, ev, 1));
                }
            }
            HidPayload::Mouse(ev) if ev.kind == MouseKind::Up => {
                flush_rel(&mut pending_rel, &mut out);
                out.executed.push((seq, payload));
            }
            HidPayload::Key(ev) if !ev.down => {
                flush_rel(&mut pending_rel, &mut out);
                out.executed.push((seq, payload));
            }
            HidPayload::Mouse(_) | HidPayload::Key(_) => {
                flush_rel(&mut pending_rel, &mut out);
                if now_ms.saturating_sub(enqueue_ms) > HID_STALE_DROP_MS {
                    out.dropped_stale_seqs.push(seq);
                } else {
                    out.executed.push((seq, payload));
                }
            }
            HidPayload::EchoAck(_) => {
                flush_rel(&mut pending_rel, &mut out);
                out.executed.push((seq, payload));
            }
        }
    }
    flush_rel(&mut pending_rel, &mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn mouse_key_echo_wire_roundtrip_and_strict_validation() {
        let mouse = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::Wheel,
            buttons: 0x05,
            x_or_dx: -320,
            y_or_dy: 640,
            wheel_dx: -12,
            wheel_dy: 24,
            client_ts_ms: 1_700_000_123_456,
        });
        let m_frame = encode_hid_frame(&mouse).unwrap();
        assert_eq!(m_frame.msg_type, HID_MSG_MOUSE);
        assert_eq!(m_frame.payload.len(), MOUSE_EVENT_WIRE_LEN);
        assert_eq!(decode_hid_frame(&m_frame).unwrap(), mouse);

        let key = HidPayload::Key(KeyEvent {
            down: true,
            modifiers: MOD_SHIFT | MOD_CTRL,
            usb_hid_usage: 0x0007_0004,
            unicode_scalar: 'A' as u32,
            client_ts_ms: 1_700_000_123_457,
        });
        let k_frame = encode_hid_frame(&key).unwrap();
        assert_eq!(k_frame.msg_type, HID_MSG_KEY);
        assert_eq!(k_frame.payload.len(), KEY_EVENT_WIRE_LEN);
        assert_eq!(decode_hid_frame(&k_frame).unwrap(), key);

        let ack = HidPayload::EchoAck(HidEchoAck {
            echo_seq: 42,
            client_ts_ms: 1_700_000_123_458,
        });
        let a_frame = encode_hid_frame(&ack).unwrap();
        assert_eq!(a_frame.msg_type, HID_MSG_ECHO_ACK);
        assert_eq!(a_frame.payload.len(), HID_ECHO_ACK_WIRE_LEN);
        assert_eq!(decode_hid_frame(&a_frame).unwrap(), ack);

        // Strict discriminant, reserved bits, wheel-delta, length, and modifier-consistency rejections
        let mut bad_mouse = m_frame.payload.to_vec();
        bad_mouse[0] = 9;
        assert!(matches!(
            MouseEvent::decode(&bad_mouse),
            Err(HidCodecError::InvalidFraming(_))
        ));
        assert!(matches!(
            MouseEvent::decode(&bad_mouse[..20]),
            Err(HidCodecError::InvalidFraming(_))
        ));
        bad_mouse[0] = MouseKind::Wheel as u8;
        bad_mouse[1] = 0x20;
        assert!(matches!(
            MouseEvent::decode(&bad_mouse),
            Err(HidCodecError::InvalidFraming(_))
        ));
        bad_mouse[0] = MouseKind::MoveAbs as u8;
        bad_mouse[1] = 0x01;
        assert!(matches!(
            MouseEvent::decode(&bad_mouse),
            Err(HidCodecError::InvalidFraming(_))
        ));
        assert!(matches!(
            encode_hid_frame(&HidPayload::Mouse(MouseEvent {
                kind: MouseKind::Down,
                buttons: 0x40,
                x_or_dx: 0,
                y_or_dy: 0,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: 1,
            })),
            Err(HidCodecError::InvalidFraming(_))
        ));
        assert!(matches!(
            encode_hid_frame(&HidPayload::Mouse(MouseEvent {
                kind: MouseKind::MoveRel,
                buttons: 0,
                x_or_dx: 1,
                y_or_dy: 2,
                wheel_dx: 0,
                wheel_dy: 3,
                client_ts_ms: 1,
            })),
            Err(HidCodecError::InvalidFraming(_))
        ));

        let mut bad_key = k_frame.payload.to_vec();
        bad_key[0] = 2;
        assert!(matches!(
            KeyEvent::decode(&bad_key),
            Err(HidCodecError::InvalidFraming(_))
        ));
        bad_key[0] = 1;
        bad_key[1] = 0x80;
        assert!(matches!(
            KeyEvent::decode(&bad_key),
            Err(HidCodecError::InvalidFraming(_))
        ));
        bad_key[1] = 0;
        bad_key[6..10].copy_from_slice(&0xD800u32.to_be_bytes());
        assert!(matches!(
            KeyEvent::decode(&bad_key),
            Err(HidCodecError::InvalidFraming(_))
        ));

        // Modifier consistency: pressing LeftShift (0xE1) with modifiers=0 MUST fail with 0x0103
        for (usage, bad_mods, good_mods) in [
            (0xE0u32, 0u8, MOD_CTRL),
            (0xE4, MOD_SHIFT, MOD_CTRL),
            (0xE1, 0, MOD_SHIFT),
            (0xE5, MOD_ALT, MOD_SHIFT),
            (0xE2, 0, MOD_ALT),
            (0xE6, MOD_META, MOD_ALT),
            (0xE3, 0, MOD_META),
            (0xE7, MOD_ALT, MOD_META),
        ] {
            let err = KeyEvent {
                down: true,
                modifiers: bad_mods,
                usb_hid_usage: usage,
                unicode_scalar: 0,
                client_ts_ms: 1000,
            }
            .encode()
            .unwrap_err();
            assert_eq!(err.error_code(), ERROR_CODE_INVALID_FRAMING);

            assert!(KeyEvent {
                down: true,
                modifiers: good_mods,
                usb_hid_usage: usage,
                unicode_scalar: 0,
                client_ts_ms: 1000,
            }
            .encode()
            .is_ok());

            // KeyUp (down == false) allows modifier bit to remain 1 (opposite side held) or 0
            assert!(KeyEvent {
                down: false,
                modifiers: good_mods,
                usb_hid_usage: usage,
                unicode_scalar: 0,
                client_ts_ms: 1001,
            }
            .encode()
            .is_ok());
            assert!(KeyEvent {
                down: false,
                modifiers: 0,
                usb_hid_usage: usage,
                unicode_scalar: 0,
                client_ts_ms: 1001,
            }
            .encode()
            .is_ok());
        }
    }

    #[test]
    fn v26_wire_vectors_and_l4_negative_cases() {
        // Inline V26 spot checks (run everywhere)
        let mouse_abs_hex = "0100001600000001000000000780000004380000000000000000000f4241";
        let (seq, payload) = decode_l4_hid_frame(&hex::decode(mouse_abs_hex).unwrap()).unwrap();
        assert_eq!(seq, 1);
        assert_eq!(
            hex::encode(encode_l4_hid_frame(seq, &payload).unwrap()),
            mouse_abs_hex
        );
        // L4 non-zero flags rejected with 0x0103
        let bad_flags = hex::decode("0301000c000000640000002a00000000000f42a3").unwrap();
        assert_eq!(
            decode_l4_hid_frame(&bad_flags).unwrap_err().error_code(),
            0x0103
        );

        // Full V26 JSON golden vector verification when protocol-spec is present
        let v26_path = Path::new("/Volumes/data/github/zerodesk/protocol-spec/vectors/v26_input_hid_wire.json");
        if !v26_path.exists() {
            return;
        }
        let raw = std::fs::read_to_string(v26_path).unwrap();
        let doc: serde_json::Value = serde_json::from_str(&raw).unwrap();

        for case in doc["valid_wire_cases"].as_array().unwrap() {
            let name = case["case"].as_str().unwrap();
            let l4_hex = case["l4_frame_hex"].as_str().unwrap();
            let body_hex = case["body_hex"].as_str().unwrap();
            let expected_seq = case["stream_seq"].as_u64().unwrap() as u32;
            let raw_l4 = hex::decode(l4_hex).unwrap();
            let (seq, payload) = decode_l4_hid_frame(&raw_l4)
                .unwrap_or_else(|e| panic!("V26 valid case '{name}' failed decode: {e}"));
            assert_eq!(seq, expected_seq, "case {name}");
            let reencoded = encode_l4_hid_frame(seq, &payload).unwrap();
            assert_eq!(hex::encode(&reencoded), l4_hex, "case {name} l4 re-encode");
            let frame = encode_hid_frame(&payload).unwrap();
            assert_eq!(hex::encode(&frame.payload), body_hex, "case {name} body re-encode");
        }

        for case in doc["negative_wire_cases"].as_array().unwrap() {
            let name = case["case"].as_str().unwrap();
            let msg_type = case["msg_type"].as_u64().unwrap() as u8;
            let expected_err = case["expected_err"].as_u64().unwrap() as u16;
            let body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            let frame = HidFrame {
                msg_type,
                payload: Bytes::from(body),
            };
            let err = decode_hid_frame(&frame)
                .expect_err(&format!("V26 negative wire case '{name}' unexpectedly passed"));
            assert_eq!(err.error_code(), expected_err, "case {name}");
        }

        for case in doc["l4_negative_cases"].as_array().unwrap() {
            let name = case["case"].as_str().unwrap();
            let expected_err = case["expected_err"].as_u64().unwrap() as u16;
            let raw_l4 = hex::decode(case["l4_frame_hex"].as_str().unwrap()).unwrap();
            let err = decode_l4_hid_frame(&raw_l4)
                .expect_err(&format!("V26 L4 negative case '{name}' unexpectedly passed"));
            assert_eq!(err.error_code(), expected_err, "case {name}");
        }
    }

    #[test]
    fn coalescer_caps_at_128_and_uses_streaming_left_to_right_saturation() {
        let mut events = Vec::new();
        for seq in 1..=129u32 {
            events.push((
                seq,
                HidPayload::Mouse(MouseEvent {
                    kind: MouseKind::MoveRel,
                    buttons: 0,
                    x_or_dx: 1,
                    y_or_dy: 2,
                    wheel_dx: 0,
                    wheel_dy: 0,
                    client_ts_ms: 4000 + u64::from(seq),
                }),
                4000 + u64::from(seq),
            ));
        }
        let out = coalesce_hid_batch(&events, 4200);
        assert_eq!(out.executed.len(), 2);
        assert_eq!(out.executed[0].0, 128);
        assert_eq!(out.executed[1].0, 129);
        assert_eq!(
            out.executed[0].1,
            HidPayload::Mouse(MouseEvent {
                kind: MouseKind::MoveRel,
                buttons: 0,
                x_or_dx: 128,
                y_or_dy: 256,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: 4128,
            })
        );
        assert_eq!(
            out.executed[1].1,
            HidPayload::Mouse(MouseEvent {
                kind: MouseKind::MoveRel,
                buttons: 0,
                x_or_dx: 1,
                y_or_dy: 2,
                wheel_dx: 0,
                wheel_dy: 0,
                client_ts_ms: 4129,
            })
        );

        // Streaming saturation: [i32::MAX, +10, -10] -> 2147483637 (NOT i32::MAX!)
        let sat = coalesce_hid_batch(
            &[
                (
                    20,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveRel,
                        buttons: 0,
                        x_or_dx: i32::MAX,
                        y_or_dy: i32::MIN,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: 3000,
                    }),
                    3000,
                ),
                (
                    21,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveRel,
                        buttons: 0,
                        x_or_dx: 10,
                        y_or_dy: -10,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: 3005,
                    }),
                    3005,
                ),
                (
                    22,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveRel,
                        buttons: 0,
                        x_or_dx: -10,
                        y_or_dy: 10,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: 3010,
                    }),
                    3010,
                ),
            ],
            3010,
        );
        assert_eq!(sat.executed.len(), 1);
        assert_eq!(sat.executed[0].0, 22);
        assert_eq!(sat.total_rel_dx(), 2_147_483_637);
        assert_eq!(sat.total_rel_dy(), -2_147_483_638);
    }

    #[test]
    fn coalescer_drops_stale_abs_and_keys_but_accumulates_relative_mouse() {
        let now_ms = 1_000;
        let stale_key = HidPayload::Key(KeyEvent {
            down: true,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 'a' as u32,
            client_ts_ms: 800,
        });
        let fresh_abs = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveAbs,
            buttons: 0,
            x_or_dx: 500,
            y_or_dy: 300,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 950,
        });
        let stale_abs = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveAbs,
            buttons: 0,
            x_or_dx: 100,
            y_or_dy: 100,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 700,
        });
        let stale_rel_1 = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveRel,
            buttons: 0,
            x_or_dx: 15,
            y_or_dy: -10,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 700,
        });
        let fresh_rel_2 = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveRel,
            buttons: 0,
            x_or_dx: -5,
            y_or_dy: 22,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 990,
        });

        let out = coalesce_hid_batch(
            &[
                (1, stale_key, 800),
                (2, stale_abs, 700),
                (3, stale_rel_1, 700),
                (4, fresh_abs, 950),
                (5, fresh_rel_2, 990),
            ],
            now_ms,
        );
        assert_eq!(out.acked_seqs, vec![1, 2, 3, 4, 5]);
        assert_eq!(out.dropped_stale_seqs, vec![1, 2]);
        assert_eq!(
            out.executed,
            vec![(3, stale_rel_1), (4, fresh_abs), (5, fresh_rel_2)]
        );
        assert_eq!(out.total_rel_dx(), 10);
        assert_eq!(out.total_rel_dy(), 12);
        assert_eq!(out.coalesced_rel_count, 2);
    }

    #[test]
    fn coalescer_never_drops_stale_release_events() {
        let now_ms = 2_000;
        let stale_ts = now_ms - HID_STALE_DROP_MS - 50;

        let stale_mouse_down = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::Down,
            buttons: 0x01,
            x_or_dx: 100,
            y_or_dy: 200,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: stale_ts,
        });
        let stale_mouse_abs = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveAbs,
            buttons: 0x01,
            x_or_dx: 120,
            y_or_dy: 210,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: stale_ts,
        });
        let stale_mouse_up = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::Up,
            buttons: 0x00,
            x_or_dx: 120,
            y_or_dy: 210,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: stale_ts,
        });
        let stale_key_down = HidPayload::Key(KeyEvent {
            down: true,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 'a' as u32,
            client_ts_ms: stale_ts,
        });
        let stale_key_up = HidPayload::Key(KeyEvent {
            down: false,
            modifiers: 0,
            usb_hid_usage: 0x04,
            unicode_scalar: 'a' as u32,
            client_ts_ms: stale_ts,
        });

        let out = coalesce_hid_batch(
            &[
                (1, stale_mouse_down, stale_ts),
                (2, stale_mouse_abs, stale_ts),
                (3, stale_mouse_up, stale_ts),
                (4, stale_key_down, stale_ts),
                (5, stale_key_up, stale_ts),
            ],
            now_ms,
        );
        assert_eq!(out.acked_seqs, vec![1, 2, 3, 4, 5]);
        assert_eq!(out.dropped_stale_seqs, vec![1, 2, 4]);
        assert_eq!(out.executed, vec![(3, stale_mouse_up), (5, stale_key_up)]);
    }

    #[test]
    fn coalescer_preserves_spatial_order_across_non_rel_boundaries() {
        let now_ms = 1_000;
        let rel_a = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveRel,
            buttons: 0,
            x_or_dx: 10,
            y_or_dy: -4,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 950,
        });
        let rel_b = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveRel,
            buttons: 0,
            x_or_dx: 6,
            y_or_dy: 9,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 955,
        });
        let down = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::Down,
            buttons: 0x01,
            x_or_dx: 0,
            y_or_dy: 0,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 960,
        });
        let rel_c = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveRel,
            buttons: 0x01,
            x_or_dx: -3,
            y_or_dy: 12,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 965,
        });
        let rel_d = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveRel,
            buttons: 0x01,
            x_or_dx: 8,
            y_or_dy: -2,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 970,
        });

        let out = coalesce_hid_batch(
            &[
                (1, rel_a, 950),
                (2, rel_b, 955),
                (3, down, 960),
                (4, rel_c, 965),
                (5, rel_d, 970),
            ],
            now_ms,
        );
        assert_eq!(out.acked_seqs, vec![1, 2, 3, 4, 5]);
        assert!(out.dropped_stale_seqs.is_empty());
        assert_eq!(
            out.executed,
            vec![
                (
                    2,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveRel,
                        buttons: 0,
                        x_or_dx: 16,
                        y_or_dy: 5,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: 955,
                    }),
                ),
                (3, down),
                (
                    5,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::MoveRel,
                        buttons: 0x01,
                        x_or_dx: 5,
                        y_or_dy: 10,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: 970,
                    }),
                ),
            ]
        );
        assert_eq!(out.total_rel_dx(), 21);
        assert_eq!(out.total_rel_dy(), 15);
        assert_eq!(out.coalesced_rel_count, 4);
    }
}
