use crate::{
    constants::{
        channel_priority_matches, AEAD_TAG_LEN, CIPHER_AESGCM, CIPHER_CHACHAPOLY, L3_HDR_LEN,
        REPLAY_WINDOW_BITS,
    },
    error::TransportError,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce as AesNonce,
};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const PKT_SEQ_MAX: u64 = (1u64 << 48) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct L3Header {
    pub e2ee_epoch: u16,
    pub pkt_seq: u64, // 48-bit unsigned
    pub send_ts_us_mod: u32,
    pub chan_id: u8,
    pub frame_flags: u8,
}

impl L3Header {
    pub fn unified_seq(&self) -> u64 {
        ((self.e2ee_epoch as u64) << 48) | (self.pkt_seq & PKT_SEQ_MAX)
    }

    pub fn nonce_96(&self) -> [u8; 12] {
        let mut nonce = [0u8; 12];
        nonce[4..12].copy_from_slice(&self.unified_seq().to_be_bytes());
        nonce
    }

    pub fn encode(&self) -> Result<[u8; L3_HDR_LEN], TransportError> {
        if self.pkt_seq > PKT_SEQ_MAX {
            return Err(TransportError::SequenceExhausted);
        }
        if self.frame_flags & !0x03 != 0 {
            return Err(TransportError::InvalidFraming(
                "L3 frame_flags reserved bits must be zero".into(),
            ));
        }
        let mut out = [0u8; L3_HDR_LEN];
        out[0..8].copy_from_slice(&self.unified_seq().to_be_bytes());
        out[8..12].copy_from_slice(&self.send_ts_us_mod.to_be_bytes());
        out[12] = self.chan_id;
        out[13] = self.frame_flags;
        // bytes 14..16 reserved = 0
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, TransportError> {
        if bytes.len() < L3_HDR_LEN {
            return Err(TransportError::InvalidFraming("L3 header truncated".into()));
        }
        let reserved = u16::from_be_bytes([bytes[14], bytes[15]]);
        if reserved != 0 {
            return Err(TransportError::InvalidFraming(
                "L3 reserved field must be zero".into(),
            ));
        }
        let frame_flags = bytes[13];
        if frame_flags & !0x03 != 0 {
            return Err(TransportError::InvalidFraming(
                "L3 frame_flags reserved bits must be zero".into(),
            ));
        }
        let unified = u64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]);
        Ok(Self {
            e2ee_epoch: (unified >> 48) as u16,
            pkt_seq: unified & PKT_SEQ_MAX,
            send_ts_us_mod: u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
            chan_id: bytes[12],
            frame_flags,
        })
    }
}

pub fn seal_l3(
    cipher_suite: u16,
    key: &[u8; 32],
    header: &L3Header,
    plaintext: &[u8],
) -> Result<Vec<u8>, TransportError> {
    let aad = header.encode()?;
    let nonce = header.nonce_96();
    let ciphertext = match cipher_suite {
        CIPHER_AESGCM => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| TransportError::AeadFailed)?;
            cipher
                .encrypt(
                    AesNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| TransportError::AeadFailed)?
        }
        CIPHER_CHACHAPOLY => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| TransportError::AeadFailed)?;
            cipher
                .encrypt(
                    ChaChaNonce::from_slice(&nonce),
                    Payload {
                        msg: plaintext,
                        aad: &aad,
                    },
                )
                .map_err(|_| TransportError::AeadFailed)?
        }
        _ => return Err(TransportError::AeadFailed),
    };
    let mut out = Vec::with_capacity(L3_HDR_LEN + ciphertext.len());
    out.extend_from_slice(&aad);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn open_l3(
    cipher_suite: u16,
    key: &[u8; 32],
    packet: &[u8],
) -> Result<(L3Header, Vec<u8>), TransportError> {
    if packet.len() < L3_HDR_LEN + AEAD_TAG_LEN {
        return Err(TransportError::InvalidFraming(
            "L3 packet shorter than header + tag".into(),
        ));
    }
    let aad = &packet[0..L3_HDR_LEN];
    let header = L3Header::decode(aad)?;
    let nonce = header.nonce_96();
    let ct = &packet[L3_HDR_LEN..];
    let pt = match cipher_suite {
        CIPHER_AESGCM => {
            let cipher = Aes256Gcm::new_from_slice(key)
                .map_err(|_| TransportError::AeadFailed)?;
            cipher
                .decrypt(
                    AesNonce::from_slice(&nonce),
                    Payload { msg: ct, aad },
                )
                .map_err(|_| TransportError::AeadFailed)?
        }
        CIPHER_CHACHAPOLY => {
            let cipher = ChaCha20Poly1305::new_from_slice(key)
                .map_err(|_| TransportError::AeadFailed)?;
            cipher
                .decrypt(
                    ChaChaNonce::from_slice(&nonce),
                    Payload { msg: ct, aad },
                )
                .map_err(|_| TransportError::AeadFailed)?
        }
        _ => return Err(TransportError::AeadFailed),
    };
    Ok((header, pt))
}

/// 2048-bit sliding anti-replay and dual-send deduplication window per `e2ee_epoch`.
#[derive(Debug, Clone)]
pub struct ReplayWindow2048 {
    initialized: bool,
    highest: u64,
    bits: [u64; REPLAY_WINDOW_BITS / 64],
}

impl Default for ReplayWindow2048 {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow2048 {
    pub fn new() -> Self {
        Self {
            initialized: false,
            highest: 0,
            bits: [0u64; REPLAY_WINDOW_BITS / 64],
        }
    }

    pub fn would_accept(&self, pkt_seq: u64) -> bool {
        if !self.initialized {
            return true;
        }
        if pkt_seq > self.highest {
            return true;
        }
        let delta = self.highest - pkt_seq;
        if delta >= REPLAY_WINDOW_BITS as u64 {
            return false;
        }
        !self.get_bit(delta as usize)
    }

    pub fn check_and_mark(&mut self, pkt_seq: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.highest = pkt_seq;
            self.bits = [0u64; REPLAY_WINDOW_BITS / 64];
            self.set_bit(0);
            return true;
        }
        if pkt_seq > self.highest {
            let shift = (pkt_seq - self.highest) as usize;
            self.shift_left(shift);
            self.highest = pkt_seq;
            self.set_bit(0);
            return true;
        }
        let delta = (self.highest - pkt_seq) as usize;
        if delta >= REPLAY_WINDOW_BITS {
            return false;
        }
        if self.get_bit(delta) {
            return false;
        }
        self.set_bit(delta);
        true
    }

    fn get_bit(&self, idx: usize) -> bool {
        (self.bits[idx / 64] >> (idx % 64)) & 1 != 0
    }

    fn set_bit(&mut self, idx: usize) {
        self.bits[idx / 64] |= 1u64 << (idx % 64);
    }

    fn shift_left(&mut self, shift: usize) {
        if shift >= REPLAY_WINDOW_BITS {
            self.bits = [0u64; REPLAY_WINDOW_BITS / 64];
            return;
        }
        let words = REPLAY_WINDOW_BITS / 64;
        let word_shift = shift / 64;
        let bit_shift = shift % 64;
        let mut next = [0u64; REPLAY_WINDOW_BITS / 64];
        for i in word_shift..words {
            let src = i - word_shift;
            next[i] |= self.bits[src] << bit_shift;
            if bit_shift > 0 && src > 0 {
                next[i] |= self.bits[src - 1] >> (64 - bit_shift);
            }
        }
        self.bits = next;
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
struct EpochSlot {
    #[zeroize(skip)]
    epoch: u16,
    key: [u8; 32],
    #[zeroize(skip)]
    window: ReplayWindow2048,
    #[zeroize(skip)]
    expire_ms: Option<u64>,
}

/// Stateful L3 sender enforcing strict `+1` per-direction `pkt_seq` with zero skips.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct L3Sender {
    #[zeroize(skip)]
    cipher_suite: u16,
    #[zeroize(skip)]
    e2ee_epoch: u16,
    #[zeroize(skip)]
    next_pkt_seq: u64,
    key: [u8; 32],
}

impl L3Sender {
    pub fn new(cipher_suite: u16, e2ee_epoch: u16, key: [u8; 32]) -> Self {
        Self {
            cipher_suite,
            e2ee_epoch,
            next_pkt_seq: 0,
            key,
        }
    }

    pub fn rekey(&mut self, new_epoch: u16, new_key: [u8; 32]) {
        self.e2ee_epoch = new_epoch;
        self.key = new_key;
        self.next_pkt_seq = 0;
    }

    pub fn encrypt(
        &mut self,
        chan_id: u8,
        frame_flags: u8,
        send_ts_us_mod: u32,
        plaintext: &[u8],
    ) -> Result<(L3Header, Vec<u8>), TransportError> {
        if self.next_pkt_seq > PKT_SEQ_MAX {
            return Err(TransportError::SequenceExhausted);
        }
        let header = L3Header {
            e2ee_epoch: self.e2ee_epoch,
            pkt_seq: self.next_pkt_seq,
            send_ts_us_mod,
            chan_id,
            frame_flags,
        };
        let wire = seal_l3(self.cipher_suite, &self.key, &header, plaintext)?;
        self.next_pkt_seq += 1;
        Ok((header, wire))
    }
}

/// Stateful L3 receiver maintaining `[e2ee_epoch-1, e2ee_epoch]` dual 2048-bit
/// replay/dedup windows, `grace = max(2s, 4*RTT)` expiry, and `chan_id <-> pp` check.
pub struct L3Receiver {
    cipher_suite: u16,
    current: EpochSlot,
    previous: Option<EpochSlot>,
    pub priority_mismatch_count: u64,
}

impl L3Receiver {
    pub fn new(cipher_suite: u16, initial_epoch: u16, key: [u8; 32]) -> Self {
        Self {
            cipher_suite,
            current: EpochSlot {
                epoch: initial_epoch,
                key,
                window: ReplayWindow2048::new(),
                expire_ms: None,
            },
            previous: None,
            priority_mismatch_count: 0,
        }
    }

    pub fn install_next_epoch(&mut self, new_epoch: u16, new_key: [u8; 32], now_ms: u64, rtt_ms: u64) {
        let grace_ms = 2_000u64.max(rtt_ms.saturating_mul(4));
        let mut old = std::mem::replace(
            &mut self.current,
            EpochSlot {
                epoch: new_epoch,
                key: new_key,
                window: ReplayWindow2048::new(),
                expire_ms: None,
            },
        );
        old.expire_ms = Some(now_ms.saturating_add(grace_ms));
        self.previous = Some(old);
    }

    pub fn decrypt_and_verify(
        &mut self,
        packet: &[u8],
        outer_pp: Option<u8>,
        now_ms: u64,
    ) -> Result<(L3Header, Vec<u8>), TransportError> {
        if packet.len() < L3_HDR_LEN + AEAD_TAG_LEN {
            return Err(TransportError::InvalidFraming("L3 packet too short".into()));
        }
        let peek = L3Header::decode(&packet[0..L3_HDR_LEN])?;

        // Drop expired previous epoch key cleanly.
        if let Some(prev) = &self.previous {
            if let Some(deadline) = prev.expire_ms {
                if now_ms > deadline {
                    self.previous = None;
                }
            }
        }

        let slot = if peek.e2ee_epoch == self.current.epoch {
            &mut self.current
        } else if let Some(prev) = self.previous.as_mut() {
            if peek.e2ee_epoch == prev.epoch {
                prev
            } else {
                return Err(TransportError::AeadFailed);
            }
        } else {
            return Err(TransportError::AeadFailed);
        };

        if !slot.window.would_accept(peek.pkt_seq) {
            return Err(TransportError::ReplayDetected);
        }

        // Authenticate BEFORE mutating replay state.
        let (header, plaintext) = open_l3(self.cipher_suite, &slot.key, packet)?;

        if let Some(pp) = outer_pp {
            if !channel_priority_matches(header.chan_id, pp) {
                self.priority_mismatch_count = self.priority_mismatch_count.saturating_add(1);
                return Err(TransportError::PriorityMismatch {
                    chan_id: header.chan_id,
                    pp,
                });
            }
        }

        if !slot.window.check_and_mark(header.pkt_seq) {
            return Err(TransportError::ReplayDetected);
        }

        Ok((header, plaintext))
    }
}
