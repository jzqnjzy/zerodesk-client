use crate::{
    constants::{
        CHAN_TRANSPORT_CTRL, CIPHER_AESGCM, CIPHER_CHACHAPOLY, PATTERN_IK, PATTERN_XX,
        ZERO_RTT_LRU_CAPACITY,
    },
    error::TransportError,
};
use sha2::{Digest, Sha256};
use snow::{params::NoiseParams, Builder, HandshakeState};
use std::collections::{BTreeMap, HashMap};
use v2_identity::{DelegationStatement, EdgeCert, IdentityError};
use zeroize::Zeroizing;

pub const PROLOGUE_DOMAIN: &[u8; 14] = b"V2-PROLOGUE-v1";
pub const PROLOGUE_PREIMAGE_LEN: usize = 204;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrologueInput {
    pub ver_major_minor: u16,
    pub handshake_pattern: u8,
    pub cipher_suite: u16,
    pub transport_mode: u8,
    pub device_id_ctrl: [u8; 16],
    pub device_id_host: [u8; 16],
    pub ctrl_devcert_tbs_sha256: [u8; 32],
    pub host_devcert_tbs_sha256: [u8; 32],
    pub policy_hash: [u8; 32],
    pub edge_cert_tbs_sha256_or_zero: [u8; 32],
    pub negotiated_cap_bits: u64,
    pub session_id: [u8; 16],
}

impl PrologueInput {
    pub fn preimage_bytes(&self) -> [u8; PROLOGUE_PREIMAGE_LEN] {
        let mut out = [0u8; PROLOGUE_PREIMAGE_LEN];
        let mut pos = 0;
        let mut push = |slice: &[u8]| {
            out[pos..pos + slice.len()].copy_from_slice(slice);
            pos += slice.len();
        };
        push(PROLOGUE_DOMAIN);
        push(&self.ver_major_minor.to_be_bytes());
        push(&[self.handshake_pattern]);
        push(&self.cipher_suite.to_be_bytes());
        push(&[self.transport_mode]);
        push(&self.device_id_ctrl);
        push(&self.device_id_host);
        push(&self.ctrl_devcert_tbs_sha256);
        push(&self.host_devcert_tbs_sha256);
        push(&self.policy_hash);
        push(&self.edge_cert_tbs_sha256_or_zero);
        push(&self.negotiated_cap_bits.to_be_bytes());
        push(&self.session_id);
        debug_assert_eq!(pos, PROLOGUE_PREIMAGE_LEN);
        out
    }

    pub fn compute_prologue(&self) -> [u8; 32] {
        Sha256::digest(self.preimage_bytes()).into()
    }
}

pub struct E2eeHandshakeOutput {
    pub tx_key: Zeroizing<[u8; 32]>,
    pub rx_key: Zeroizing<[u8; 32]>,
    pub hs_hash: Zeroizing<[u8; 32]>,
    pub cipher_suite: u16,
    pub remote_static_x25519: [u8; 32],
    pub peer_delegation: DelegationStatement,
}

pub struct AccessHandshakeOutput {
    pub hs_hash: Zeroizing<[u8; 32]>,
}

fn noise_params_str(pattern: u8, cipher_suite: u16) -> Result<&'static str, TransportError> {
    match (pattern, cipher_suite) {
        (PATTERN_IK, CIPHER_AESGCM) => Ok("Noise_IK_25519_AESGCM_SHA256"),
        (PATTERN_IK, CIPHER_CHACHAPOLY) => Ok("Noise_IK_25519_ChaChaPoly_SHA256"),
        (PATTERN_XX, CIPHER_AESGCM) => Ok("Noise_XX_25519_AESGCM_SHA256"),
        (PATTERN_XX, CIPHER_CHACHAPOLY) => Ok("Noise_XX_25519_ChaChaPoly_SHA256"),
        _ => Err(TransportError::Noise(format!(
            "unsupported pattern={pattern} cipher_suite={cipher_suite:#x}"
        ))),
    }
}

/// Device <-> Edge access-layer `Noise_IK_25519_AESGCM_SHA256` handshake wrapper.
///
/// Verifies the Edge's `EdgeCert` against the pinned control-plane CA before
/// initiating, binds `edge_cert_hash || pop_id` as prologue, and returns `hs_hash`
/// used as IKM for L2 `v2mac-v1` directional MAC keys.
pub struct AccessNoiseHandshake {
    state: HandshakeState,
}

impl AccessNoiseHandshake {
    pub fn build_initiator(
        local_x25519_priv: &[u8; 32],
        edge_cert: &EdgeCert,
        ca_spki_der: &[u8],
        now_unix: u64,
    ) -> Result<Self, TransportError> {
        edge_cert.verify(ca_spki_der, now_unix)?;
        let mut prologue = [0u8; 40];
        prologue[0..32].copy_from_slice(&edge_cert.tbs_sha256());
        prologue[32..40].copy_from_slice(&edge_cert.pop_id);
        let params: NoiseParams = "Noise_IK_25519_AESGCM_SHA256"
            .parse()
            .map_err(|e: snow::Error| TransportError::Noise(e.to_string()))?;
        let state = Builder::new(params)
            .local_private_key(local_x25519_priv)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .remote_public_key(&edge_cert.x25519_pub)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .prologue(&prologue)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .build_initiator()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        Ok(Self { state })
    }

    pub fn build_responder(
        edge_x25519_priv: &[u8; 32],
        edge_cert: &EdgeCert,
    ) -> Result<Self, TransportError> {
        let mut prologue = [0u8; 40];
        prologue[0..32].copy_from_slice(&edge_cert.tbs_sha256());
        prologue[32..40].copy_from_slice(&edge_cert.pop_id);
        let params: NoiseParams = "Noise_IK_25519_AESGCM_SHA256"
            .parse()
            .map_err(|e: snow::Error| TransportError::Noise(e.to_string()))?;
        let state = Builder::new(params)
            .local_private_key(edge_x25519_priv)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .prologue(&prologue)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .build_responder()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        Ok(Self { state })
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; payload.len() + 128];
        let len = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; message.len() + 64];
        let len = self
            .state
            .read_message(message, &mut buf)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn finish(self) -> Result<AccessHandshakeOutput, TransportError> {
        if !self.state.is_handshake_finished() {
            return Err(TransportError::Noise("access handshake not finished".into()));
        }
        let mut hs_hash = Zeroizing::new([0u8; 32]);
        let raw = self.state.get_handshake_hash();
        if raw.len() != 32 {
            return Err(TransportError::Noise("unexpected handshake hash len".into()));
        }
        hs_hash.copy_from_slice(raw);
        Ok(AccessHandshakeOutput { hs_hash })
    }
}

/// End-to-end Controller <-> Controlled `Noise_IK` / `Noise_XX` handshake wrapper
/// using `snow`, binding the 32B SHA-256 anti-downgrade `prologue`, verifying the
/// peer's P-256 `DelegationStatement` bound to `remote_static_x25519`, and extracting
/// raw `Split()` directional keys before discarding Noise's `CipherState`.
pub struct E2eeNoiseHandshake {
    state: HandshakeState,
    pattern: u8,
    cipher_suite: u16,
    is_initiator: bool,
    rx_count: u8,
    received_peer_delegation: Option<DelegationStatement>,
}

impl E2eeNoiseHandshake {
    pub fn build_ik_initiator(
        cipher_suite: u16,
        local_x25519_priv: &[u8; 32],
        remote_x25519_pub: &[u8; 32],
        prologue: &[u8; 32],
    ) -> Result<Self, TransportError> {
        let params: NoiseParams = noise_params_str(PATTERN_IK, cipher_suite)?
            .parse()
            .map_err(|e: snow::Error| TransportError::Noise(e.to_string()))?;
        let state = Builder::new(params)
            .local_private_key(local_x25519_priv)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .remote_public_key(remote_x25519_pub)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .prologue(prologue)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .build_initiator()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        Ok(Self {
            state,
            pattern: PATTERN_IK,
            cipher_suite,
            is_initiator: true,
            rx_count: 0,
            received_peer_delegation: None,
        })
    }

    pub fn build_ik_responder(
        cipher_suite: u16,
        local_x25519_priv: &[u8; 32],
        prologue: &[u8; 32],
    ) -> Result<Self, TransportError> {
        let params: NoiseParams = noise_params_str(PATTERN_IK, cipher_suite)?
            .parse()
            .map_err(|e: snow::Error| TransportError::Noise(e.to_string()))?;
        let state = Builder::new(params)
            .local_private_key(local_x25519_priv)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .prologue(prologue)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .build_responder()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        Ok(Self {
            state,
            pattern: PATTERN_IK,
            cipher_suite,
            is_initiator: false,
            rx_count: 0,
            received_peer_delegation: None,
        })
    }

    pub fn build_xx_initiator(
        cipher_suite: u16,
        local_x25519_priv: &[u8; 32],
        prologue: &[u8; 32],
    ) -> Result<Self, TransportError> {
        let params: NoiseParams = noise_params_str(PATTERN_XX, cipher_suite)?
            .parse()
            .map_err(|e: snow::Error| TransportError::Noise(e.to_string()))?;
        let state = Builder::new(params)
            .local_private_key(local_x25519_priv)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .prologue(prologue)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .build_initiator()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        Ok(Self {
            state,
            pattern: PATTERN_XX,
            cipher_suite,
            is_initiator: true,
            rx_count: 0,
            received_peer_delegation: None,
        })
    }

    pub fn build_xx_responder(
        cipher_suite: u16,
        local_x25519_priv: &[u8; 32],
        prologue: &[u8; 32],
    ) -> Result<Self, TransportError> {
        let params: NoiseParams = noise_params_str(PATTERN_XX, cipher_suite)?
            .parse()
            .map_err(|e: snow::Error| TransportError::Noise(e.to_string()))?;
        let state = Builder::new(params)
            .local_private_key(local_x25519_priv)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .prologue(prologue)
            .map_err(|e| TransportError::Noise(e.to_string()))?
            .build_responder()
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        Ok(Self {
            state,
            pattern: PATTERN_XX,
            cipher_suite,
            is_initiator: false,
            rx_count: 0,
            received_peer_delegation: None,
        })
    }

    pub fn write_message(&mut self, payload: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; payload.len() + 128];
        let len = self
            .state
            .write_message(payload, &mut buf)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        buf.truncate(len);
        Ok(buf)
    }

    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, TransportError> {
        let mut buf = vec![0u8; message.len() + 64];
        let len = self
            .state
            .read_message(message, &mut buf)
            .map_err(|e| TransportError::Noise(e.to_string()))?;
        buf.truncate(len);
        if self.pattern == PATTERN_XX {
            let expects_delegation = (self.is_initiator && self.rx_count == 0)
                || (!self.is_initiator && self.rx_count == 1);
            if expects_delegation {
                let deleg = DelegationStatement::decode_wire(&buf)?;
                self.received_peer_delegation = Some(deleg);
            }
        }
        self.rx_count = self.rx_count.saturating_add(1);
        Ok(buf)
    }

    pub fn is_finished(&self) -> bool {
        self.state.is_handshake_finished()
    }

    /// Verifies the peer's P-256 `DelegationStatement` (binding `x25519_pub == remote_static_x25519`,
    /// `device_id`, low-S signature, and expiry), then extracts Noise `Split()` directional keys
    /// (`tx_key`, `rx_key`) and drops `HandshakeState` per V2 spec §4.3.
    ///
    /// - For `Noise_XX`, the peer's `DelegationStatement` MUST have been parsed from `msg2`
    ///   (initiator) / `msg3` (responder).
    /// - For `Noise_IK`, `peer_delegation` MUST be supplied as `Some(...)`.
    pub fn finish_split(
        mut self,
        peer_delegation: Option<&DelegationStatement>,
        expected_peer_device_id: &[u8; 16],
        peer_device_spki_der: &[u8],
        peer_device_cert_exp_unix: u64,
        now_unix: u64,
    ) -> Result<E2eeHandshakeOutput, TransportError> {
        if !self.state.is_handshake_finished() {
            return Err(TransportError::Noise("e2ee handshake not finished".into()));
        }

        let mut remote_static_x25519 = [0u8; 32];
        let remote = self
            .state
            .get_remote_static()
            .ok_or_else(|| TransportError::Noise("missing remote static key".into()))?;
        if remote.len() != 32 {
            return Err(TransportError::Noise("unexpected remote static len".into()));
        }
        remote_static_x25519.copy_from_slice(remote);

        let deleg = match self.pattern {
            PATTERN_XX => {
                let wire_deleg = self
                    .received_peer_delegation
                    .take()
                    .ok_or(IdentityError::InvalidSignature)?;
                if let Some(ext) = peer_delegation {
                    if ext != &wire_deleg {
                        return Err(IdentityError::BindingMismatch.into());
                    }
                }
                wire_deleg
            }
            PATTERN_IK => peer_delegation
                .cloned()
                .ok_or(IdentityError::InvalidSignature)?,
            _ => return Err(TransportError::Noise("unknown handshake pattern".into())),
        };

        if &deleg.device_id != expected_peer_device_id {
            return Err(IdentityError::BindingMismatch.into());
        }
        if deleg.x25519_pub != remote_static_x25519 {
            return Err(IdentityError::BindingMismatch.into());
        }
        deleg.verify(peer_device_spki_der, peer_device_cert_exp_unix, now_unix)?;

        let mut hs_hash = Zeroizing::new([0u8; 32]);
        let raw_hash = self.state.get_handshake_hash();
        if raw_hash.len() != 32 {
            return Err(TransportError::Noise("unexpected handshake hash len".into()));
        }
        hs_hash.copy_from_slice(raw_hash);

        let (k_i2r, k_r2i) = self.state.dangerously_get_raw_split();
        let (tx_key, rx_key) = if self.is_initiator {
            (Zeroizing::new(k_i2r), Zeroizing::new(k_r2i))
        } else {
            (Zeroizing::new(k_r2i), Zeroizing::new(k_i2r))
        };
        Ok(E2eeHandshakeOutput {
            tx_key,
            rx_key,
            hs_hash,
            cipher_suite: self.cipher_suite,
            remote_static_x25519,
            peer_delegation: deleg,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ZeroRttDecision {
    pub accepted: bool,
    pub handshake_continue: bool,
    pub diag_drop_incremented: bool,
}

/// 10,000-entry bounded `session_id` true-LRU idempotency cache and 0-RTT frame gate
/// matching V2 §4.2 and golden vector V05.
///
/// - Only `0x00 TransportCtrl` (`SessionOpenReq`) is allowed in 0-RTT; piggybacked
///   `0x01 InputHID` / `0x05 FileTransfer` are silently dropped (`diag_drop_count += 1`)
///   without aborting the handshake.
/// - Replayed `session_id` refreshes its LRU recency and is rejected (`diag_drop_count += 1`)
///   while handshake continues.
/// - `purge_expired` removes all expired entries regardless of insertion order.
/// - When cache reaches capacity (10,000) of unexpired entries, new 0-RTT falls back cleanly
///   to 1-RTT without incrementing drop counter or aborting handshake.
#[derive(Debug)]
pub struct ZeroRttGuard {
    capacity: usize,
    entries: HashMap<[u8; 16], (u64, u64)>, // session_id -> (expire_unix, access_tick)
    by_recency: BTreeMap<u64, [u8; 16]>,    // access_tick -> session_id (front = LRU, back = MRU)
    next_tick: u64,
    min_exp_unix: u64,
    pub diag_drop_count: u64,
}

impl Default for ZeroRttGuard {
    fn default() -> Self {
        Self::new(ZERO_RTT_LRU_CAPACITY)
    }
}

impl ZeroRttGuard {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            entries: HashMap::with_capacity(capacity.min(1024)),
            by_recency: BTreeMap::new(),
            next_tick: 0,
            min_exp_unix: u64::MAX,
            diag_drop_count: 0,
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn lru_session_id(&self) -> Option<[u8; 16]> {
        self.by_recency.values().next().copied()
    }

    pub fn touch(&mut self, session_id: &[u8; 16]) -> bool {
        let Some((exp, old_tick)) = self.entries.get_mut(session_id) else {
            return false;
        };
        let _ = exp;
        let prev = *old_tick;
        self.by_recency.remove(&prev);
        let tick = self.next_tick;
        self.next_tick = self.next_tick.wrapping_add(1);
        *old_tick = tick;
        self.by_recency.insert(tick, *session_id);
        true
    }

    pub fn evict_lru(&mut self) -> Option<[u8; 16]> {
        let (&tick, &sid) = self.by_recency.iter().next()?;
        self.by_recency.remove(&tick);
        self.entries.remove(&sid);
        self.recompute_min_exp();
        Some(sid)
    }

    pub fn purge_expired(&mut self, now_unix: u64) {
        if self.entries.is_empty() || now_unix <= self.min_exp_unix {
            return;
        }
        let mut removed_ticks = Vec::new();
        self.entries.retain(|_, (exp, tick)| {
            if now_unix > *exp {
                removed_ticks.push(*tick);
                false
            } else {
                true
            }
        });
        for tick in removed_ticks {
            self.by_recency.remove(&tick);
        }
        self.recompute_min_exp();
    }

    fn recompute_min_exp(&mut self) {
        self.min_exp_unix = self
            .entries
            .values()
            .map(|(exp, _)| *exp)
            .min()
            .unwrap_or(u64::MAX);
    }

    pub fn evaluate_0rtt(
        &mut self,
        initiator_delegation: &DelegationStatement,
        initiator_spki_der: &[u8],
        initiator_cert_exp_unix: u64,
        session_id: [u8; 16],
        chan_id: u8,
        static_key_exp_unix: u64,
        now_unix: u64,
    ) -> Result<ZeroRttDecision, TransportError> {
        initiator_delegation.verify(initiator_spki_der, initiator_cert_exp_unix, now_unix)?;
        self.purge_expired(now_unix);

        if chan_id != CHAN_TRANSPORT_CTRL {
            self.diag_drop_count = self.diag_drop_count.saturating_add(1);
            return Ok(ZeroRttDecision {
                accepted: false,
                handshake_continue: true,
                diag_drop_incremented: true,
            });
        }

        if self.touch(&session_id) {
            self.diag_drop_count = self.diag_drop_count.saturating_add(1);
            return Ok(ZeroRttDecision {
                accepted: false,
                handshake_continue: true,
                diag_drop_incremented: true,
            });
        }

        if self.entries.len() >= self.capacity {
            return Ok(ZeroRttDecision {
                accepted: false,
                handshake_continue: true,
                diag_drop_incremented: false,
            });
        }

        let tick = self.next_tick;
        self.next_tick = self.next_tick.wrapping_add(1);
        self.entries.insert(session_id, (static_key_exp_unix, tick));
        self.by_recency.insert(tick, session_id);
        if static_key_exp_unix < self.min_exp_unix {
            self.min_exp_unix = static_key_exp_unix;
        }
        Ok(ZeroRttDecision {
            accepted: true,
            handshake_continue: true,
            diag_drop_incremented: false,
        })
    }
}
