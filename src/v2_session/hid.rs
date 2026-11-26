use bytes::Bytes;
use std::fmt;
use v2_transport::{HidFrame, HID_STALE_DROP_MS};

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

pub const MOD_SHIFT: u8 = 1 << 0;
pub const MOD_CTRL: u8 = 1 << 1;
pub const MOD_ALT: u8 = 1 << 2;
pub const MOD_META: u8 = 1 << 3;
const MOD_VALID_MASK: u8 = MOD_SHIFT | MOD_CTRL | MOD_ALT | MOD_META;
pub const MOUSE_BUTTONS_VALID_MASK: u8 = 0x1F;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidCodecError {
    UnknownMsgType(u8),
    InvalidLength {
        msg_type: u8,
        expected: usize,
        actual: usize,
    },
    InvalidMouseKind(u8),
    InvalidMouseButtons(u8),
    UnexpectedWheelDelta {
        kind: MouseKind,
        wheel_dx: i16,
        wheel_dy: i16,
    },
    InvalidBoolFlag(u8),
    InvalidModifiers(u8),
    InvalidUnicodeScalar(u32),
}

impl fmt::Display for HidCodecError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownMsgType(t) => write!(f, "unknown HID msg_type {t:#04x}"),
            Self::InvalidLength {
                msg_type,
                expected,
                actual,
            } => write!(
                f,
                "invalid HID payload length for msg_type {msg_type:#04x}: expected {expected}, got {actual}"
            ),
            Self::InvalidMouseKind(k) => write!(f, "invalid mouse event kind discriminant {k}"),
            Self::InvalidMouseButtons(b) => write!(f, "reserved mouse button bits set: {b:#04x}"),
            Self::UnexpectedWheelDelta {
                kind,
                wheel_dx,
                wheel_dy,
            } => write!(
                f,
                "non-zero wheel delta ({wheel_dx}, {wheel_dy}) on non-Wheel mouse event {kind:?}"
            ),
            Self::InvalidBoolFlag(v) => write!(f, "invalid boolean flag value {v} (expected 0 or 1)"),
            Self::InvalidModifiers(m) => write!(f, "reserved key modifier bits set: {m:#04x}"),
            Self::InvalidUnicodeScalar(u) => write!(f, "invalid unicode scalar {u:#010x}"),
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
            other => Err(HidCodecError::InvalidMouseKind(other)),
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
            return Err(HidCodecError::InvalidMouseButtons(self.buttons));
        }
        if self.kind != MouseKind::Wheel && (self.wheel_dx != 0 || self.wheel_dy != 0) {
            return Err(HidCodecError::UnexpectedWheelDelta {
                kind: self.kind,
                wheel_dx: self.wheel_dx,
                wheel_dy: self.wheel_dy,
            });
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
            return Err(HidCodecError::InvalidLength {
                msg_type: HID_MSG_MOUSE,
                expected: MOUSE_EVENT_WIRE_LEN,
                actual: bytes.len(),
            });
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

impl KeyEvent {
    pub fn validate(&self) -> Result<(), HidCodecError> {
        if self.modifiers & !MOD_VALID_MASK != 0 {
            return Err(HidCodecError::InvalidModifiers(self.modifiers));
        }
        if self.unicode_scalar != 0 && char::from_u32(self.unicode_scalar).is_none() {
            return Err(HidCodecError::InvalidUnicodeScalar(self.unicode_scalar));
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
            return Err(HidCodecError::InvalidLength {
                msg_type: HID_MSG_KEY,
                expected: KEY_EVENT_WIRE_LEN,
                actual: bytes.len(),
            });
        }
        let down = match bytes[0] {
            0 => false,
            1 => true,
            other => return Err(HidCodecError::InvalidBoolFlag(other)),
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
            return Err(HidCodecError::InvalidLength {
                msg_type: HID_MSG_ECHO_ACK,
                expected: HID_ECHO_ACK_WIRE_LEN,
                actual: bytes.len(),
            });
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
        other => Err(HidCodecError::UnknownMsgType(other)),
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct HidBatchOutcome {
    pub acked_seqs: Vec<u32>,
    pub executed: Vec<(u32, HidPayload)>,
    pub dropped_stale_seqs: Vec<u32>,
    pub accumulated_rel_dx: i32,
    pub accumulated_rel_dy: i32,
    pub coalesced_rel_count: usize,
}

/// Applies `protocol-spec/spec/04-inner-channels.md` §2 stale-drop and relative mouse
/// vector coalescing rules over a batch of `(stream_seq, payload, enqueue_ms)`:
/// - Every event is ACKed regardless of staleness.
/// - `MouseKind::MoveRel` deltas are NEVER dropped; contiguous runs coalesce into a single
///   `(dx, dy)` vector and flush before any non-`MoveRel` boundary to preserve spatial order.
/// - Release events (`MouseKind::Up` and `KeyEvent { down: false }`) are NEVER dropped so
///   network jitter cannot leave buttons or keys stuck.
/// - Other non-relative mouse events and key-down events queued `> 150ms` are dropped without
///   execution.
pub fn coalesce_hid_batch(
    events: &[(u32, HidPayload, u64)],
    now_ms: u64,
) -> HidBatchOutcome {
    let mut out = HidBatchOutcome::default();
    let mut pending_rel: Option<(u32, MouseEvent)> = None;
    let flush_rel = |pending: &mut Option<(u32, MouseEvent)>, out: &mut HidBatchOutcome| {
        if let Some((rel_seq, rel_ev)) = pending.take() {
            out.executed.push((rel_seq, HidPayload::Mouse(rel_ev)));
        }
    };

    for &(seq, payload, enqueue_ms) in events {
        out.acked_seqs.push(seq);
        match payload {
            HidPayload::Mouse(ev) if ev.kind == MouseKind::MoveRel => {
                out.accumulated_rel_dx = out.accumulated_rel_dx.saturating_add(ev.x_or_dx);
                out.accumulated_rel_dy = out.accumulated_rel_dy.saturating_add(ev.y_or_dy);
                out.coalesced_rel_count += 1;
                if let Some((last_seq, acc)) = &mut pending_rel {
                    *last_seq = seq;
                    acc.x_or_dx = acc.x_or_dx.saturating_add(ev.x_or_dx);
                    acc.y_or_dy = acc.y_or_dy.saturating_add(ev.y_or_dy);
                    acc.buttons = ev.buttons;
                    acc.client_ts_ms = ev.client_ts_ms;
                } else {
                    pending_rel = Some((seq, ev));
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

        // Strict discriminant, reserved bits, wheel-delta, and length rejections
        let mut bad_mouse = m_frame.payload.to_vec();
        bad_mouse[0] = 9;
        assert!(matches!(
            MouseEvent::decode(&bad_mouse),
            Err(HidCodecError::InvalidMouseKind(9))
        ));
        assert!(matches!(
            MouseEvent::decode(&bad_mouse[..20]),
            Err(HidCodecError::InvalidLength { .. })
        ));
        bad_mouse[0] = MouseKind::Wheel as u8;
        bad_mouse[1] = 0x20;
        assert!(matches!(
            MouseEvent::decode(&bad_mouse),
            Err(HidCodecError::InvalidMouseButtons(0x20))
        ));
        bad_mouse[0] = MouseKind::MoveAbs as u8;
        bad_mouse[1] = 0x01;
        assert!(matches!(
            MouseEvent::decode(&bad_mouse),
            Err(HidCodecError::UnexpectedWheelDelta {
                kind: MouseKind::MoveAbs,
                wheel_dx: -12,
                wheel_dy: 24,
            })
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
            Err(HidCodecError::InvalidMouseButtons(0x40))
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
            Err(HidCodecError::UnexpectedWheelDelta {
                kind: MouseKind::MoveRel,
                wheel_dx: 0,
                wheel_dy: 3,
            })
        ));

        let mut bad_key = k_frame.payload.to_vec();
        bad_key[0] = 2;
        assert!(matches!(
            KeyEvent::decode(&bad_key),
            Err(HidCodecError::InvalidBoolFlag(2))
        ));
        bad_key[0] = 1;
        bad_key[1] = 0x80;
        assert!(matches!(
            KeyEvent::decode(&bad_key),
            Err(HidCodecError::InvalidModifiers(0x80))
        ));
        bad_key[1] = 0;
        bad_key[6..10].copy_from_slice(&0xD800u32.to_be_bytes());
        assert!(matches!(
            KeyEvent::decode(&bad_key),
            Err(HidCodecError::InvalidUnicodeScalar(0xD800))
        ));
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
        assert_eq!(out.accumulated_rel_dx, 10);
        assert_eq!(out.accumulated_rel_dy, 12);
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
        assert_eq!(out.accumulated_rel_dx, 21);
        assert_eq!(out.accumulated_rel_dy, 15);
        assert_eq!(out.coalesced_rel_count, 4);
    }
}
