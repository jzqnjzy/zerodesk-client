use crate::{certs::DelegationStatement, error::IdentityError, keystore::DeviceKeyStore};
use rand_core::OsRng;
use std::collections::{HashMap, VecDeque};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// 12-hour static key rotation slice per V2 spec §4.1.
pub const X25519_SLICE_SECS: u64 = 12 * 3600;
/// Retain at least the latest 2 generations covering >= 48 hours.
pub const X25519_MIN_RETENTION_SECS: u64 = 48 * 3600;
pub const X25519_RETAINED_GENERATIONS: usize = 2;
pub const STATIC_KEY_HINT_MAX_RETRIES: u8 = 1;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct X25519KeyGeneration {
    secret_bytes: [u8; 32],
    #[zeroize(skip)]
    pub public_key: [u8; 32],
    #[zeroize(skip)]
    pub slice_index: u64,
    #[zeroize(skip)]
    pub delegation_seq: u64,
    #[zeroize(skip)]
    pub created_unix: u64,
    #[zeroize(skip)]
    pub retain_until_unix: u64,
    #[zeroize(skip)]
    pub delegation: DelegationStatement,
}

impl X25519KeyGeneration {
    pub fn secret_bytes(&self) -> &[u8; 32] {
        &self.secret_bytes
    }

    pub fn diffie_hellman(&self, peer_public: [u8; 32]) -> [u8; 32] {
        let secret = StaticSecret::from(self.secret_bytes);
        let peer = PublicKey::from(peer_public);
        *secret.diffie_hellman(&peer).as_bytes()
    }
}

/// Manages 12-hour time-slice X25519 static keys in memory (`ZeroizeOnDrop`).
///
/// Retains the latest 2 generations (`>= 48h` retention window) so the
/// responder can attempt decryption against the current and previous static
/// keys during slice rollover.
pub struct X25519StaticKeyRotator {
    device_id: [u8; 16],
    prefer_chacha: bool,
    last_delegation_seq: u64,
    generations: VecDeque<X25519KeyGeneration>,
}

impl X25519StaticKeyRotator {
    pub fn new(device_id: [u8; 16], prefer_chacha: bool, initial_delegation_seq: u64) -> Self {
        Self {
            device_id,
            prefer_chacha,
            last_delegation_seq: initial_delegation_seq,
            generations: VecDeque::with_capacity(X25519_RETAINED_GENERATIONS),
        }
    }

    pub fn slice_for(now_unix: u64) -> u64 {
        now_unix / X25519_SLICE_SECS
    }

    /// Ensures a key exists for the current 12-hour time slice, rotating when
    /// `now_unix / 43200` advances. `delegation.exp_unix` is clamped to
    /// `<= device_cert_exp_unix` per V2 spec §4.1.
    pub fn ensure_current(
        &mut self,
        store: &dyn DeviceKeyStore,
        now_unix: u64,
        device_cert_exp_unix: u64,
    ) -> Result<&X25519KeyGeneration, IdentityError> {
        if now_unix > device_cert_exp_unix {
            return Err(IdentityError::CertExpired);
        }
        let slice = Self::slice_for(now_unix);
        let need_rotate = match self.generations.front() {
            Some(cur) => cur.slice_index != slice || now_unix > cur.delegation.exp_unix,
            None => true,
        };
        if need_rotate {
            self.rotate_now(store, now_unix, device_cert_exp_unix)?;
        }
        self.generations
            .front()
            .ok_or_else(|| IdentityError::Storage("missing active x25519 key".into()))
    }

    pub fn rotate_now(
        &mut self,
        store: &dyn DeviceKeyStore,
        now_unix: u64,
        device_cert_exp_unix: u64,
    ) -> Result<&X25519KeyGeneration, IdentityError> {
        if now_unix > device_cert_exp_unix {
            return Err(IdentityError::CertExpired);
        }
        let slice = Self::slice_for(now_unix);
        let next_seq = self.last_delegation_seq.saturating_add(1);
        let static_secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&static_secret).to_bytes();
        let secret_bytes = static_secret.to_bytes();

        let slice_end = (slice + 1).saturating_mul(X25519_SLICE_SECS);
        let exp_unix = slice_end.min(device_cert_exp_unix);
        let mut delegation = DelegationStatement {
            device_id: self.device_id,
            x25519_pub: public_key,
            prefer_chacha: self.prefer_chacha,
            delegation_seq: next_seq,
            exp_unix,
            sig_der: Vec::new(),
        };
        let tbs = delegation.tbs_bytes();
        delegation.sig_der = store.sign_p256_low_s(&tbs)?;

        let generation = X25519KeyGeneration {
            secret_bytes,
            public_key,
            slice_index: slice,
            delegation_seq: next_seq,
            created_unix: now_unix,
            retain_until_unix: now_unix.saturating_add(X25519_MIN_RETENTION_SECS),
            delegation,
        };

        self.last_delegation_seq = next_seq;
        self.generations.push_front(generation);
        while self.generations.len() > X25519_RETAINED_GENERATIONS {
            let expired_tail = self
                .generations
                .back()
                .map(|g| now_unix >= g.retain_until_unix)
                .unwrap_or(true);
            if expired_tail || self.generations.len() > X25519_RETAINED_GENERATIONS {
                self.generations.pop_back();
            }
        }
        self.generations
            .front()
            .ok_or_else(|| IdentityError::Storage("rotation failed".into()))
    }

    pub fn current(&self) -> Option<&X25519KeyGeneration> {
        self.generations.front()
    }

    /// Returns retained generations (newest first) for sequential IK `msg1` decryption attempts.
    pub fn retained_generations(&self) -> impl Iterator<Item = &X25519KeyGeneration> {
        self.generations.iter()
    }

    /// Removes generations past their `>= 48h` retention window while always
    /// keeping the active generation if present.
    pub fn prune_expired(&mut self, now_unix: u64) {
        while self.generations.len() > 1 {
            let should_drop = self
                .generations
                .back()
                .map(|g| now_unix > g.retain_until_unix)
                .unwrap_or(false);
            if should_drop {
                self.generations.pop_back();
            } else {
                break;
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedDelegation {
    pub delegation_seq: u64,
    pub x25519_pub: [u8; 32],
}

/// Anti-rollback and anti-substitution cache: `device_id -> (delegation_seq, x25519_pub)`.
///
/// Rejects any lower `delegation_seq` OR same `delegation_seq` bound to a different
/// `x25519_pub` with `IdentityError::DelegationRollback` (`0x0203`).
#[derive(Debug, Default)]
pub struct DelegationCache {
    entries: HashMap<[u8; 16], CachedDelegation>,
}

impl DelegationCache {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, device_id: &[u8; 16]) -> Option<&CachedDelegation> {
        self.entries.get(device_id)
    }

    pub fn verify_and_record(
        &mut self,
        stmt: &DelegationStatement,
        device_spki_der: &[u8],
        device_cert_exp_unix: u64,
        now_unix: u64,
    ) -> Result<(), IdentityError> {
        stmt.verify(device_spki_der, device_cert_exp_unix, now_unix)?;
        if let Some(prev) = self.entries.get(&stmt.device_id) {
            if stmt.delegation_seq < prev.delegation_seq {
                return Err(IdentityError::DelegationRollback);
            }
            if stmt.delegation_seq == prev.delegation_seq && stmt.x25519_pub != prev.x25519_pub {
                return Err(IdentityError::DelegationRollback);
            }
        }
        self.entries.insert(
            stmt.device_id,
            CachedDelegation {
                delegation_seq: stmt.delegation_seq,
                x25519_pub: stmt.x25519_pub,
            },
        );
        Ok(())
    }
}

/// Validates a responder `StaticKeyHint{latest DelegationStatement}` after an
/// expired-static-key `Noise_IK` failure: verifies P-256 signature, requires
/// strictly increasing `delegation_seq`, and allows at most 1 retry.
#[derive(Debug, Default)]
pub struct StaticKeyHintRetry {
    retries_used: u8,
}

impl StaticKeyHintRetry {
    pub fn new() -> Self {
        Self { retries_used: 0 }
    }

    pub fn retries_used(&self) -> u8 {
        self.retries_used
    }

    pub fn accept_hint(
        &mut self,
        cache: &mut DelegationCache,
        hint: &DelegationStatement,
        device_spki_der: &[u8],
        device_cert_exp_unix: u64,
        now_unix: u64,
    ) -> Result<(), IdentityError> {
        if self.retries_used >= STATIC_KEY_HINT_MAX_RETRIES {
            return Err(IdentityError::RetryLimitExceeded);
        }
        if let Some(prev) = cache.get(&hint.device_id) {
            if hint.delegation_seq <= prev.delegation_seq {
                return Err(IdentityError::DelegationRollback);
            }
        }
        cache.verify_and_record(hint, device_spki_der, device_cert_exp_unix, now_unix)?;
        self.retries_used += 1;
        Ok(())
    }
}
