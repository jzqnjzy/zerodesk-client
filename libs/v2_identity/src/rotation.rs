use crate::{certs::DelegationStatement, error::IdentityError, keystore::DeviceKeyStore};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// 12-hour static key rotation slice per V2 spec §4.1.
pub const X25519_SLICE_SECS: u64 = 12 * 3600;
/// Retain at least the latest 2 generations covering >= 48 hours.
pub const X25519_MIN_RETENTION_SECS: u64 = 48 * 3600;
pub const X25519_RETAINED_GENERATIONS: usize = 2;
pub const STATIC_KEY_HINT_MAX_RETRIES: u8 = 1;
pub const STATIC_KEY_HINT_MAX_SESSIONS: usize = 4096;

const ROTATOR_STATE_MAGIC: &[u8; 6] = b"ZDROT1";
const ROTATOR_STATE_VERSION: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetainedKeyMetadata {
    pub public_key: [u8; 32],
    pub slice_index: u64,
    pub delegation_seq: u64,
    pub created_unix: u64,
    pub retain_until_unix: u64,
    pub delegation: DelegationStatement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotatorPersistedState {
    pub device_id: [u8; 16],
    pub prefer_chacha: bool,
    pub last_delegation_seq: u64,
    pub retained_metadata: Vec<RetainedKeyMetadata>,
}

impl RotatorPersistedState {
    pub fn encode_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let count = u8::try_from(self.retained_metadata.len())
            .map_err(|_| IdentityError::InvalidFraming("too many retained metadata items".into()))?;
        let mut out = Vec::with_capacity(6 + 1 + 16 + 1 + 8 + 1 + self.retained_metadata.len() * 192);
        out.extend_from_slice(ROTATOR_STATE_MAGIC);
        out.push(ROTATOR_STATE_VERSION);
        out.extend_from_slice(&self.device_id);
        out.push(u8::from(self.prefer_chacha));
        out.extend_from_slice(&self.last_delegation_seq.to_be_bytes());
        out.push(count);
        for meta in &self.retained_metadata {
            let deleg_wire = meta.delegation.encode_wire()?;
            let deleg_len = u16::try_from(deleg_wire.len())
                .map_err(|_| IdentityError::InvalidFraming("delegation exceeds u16::MAX".into()))?;
            out.extend_from_slice(&meta.public_key);
            out.extend_from_slice(&meta.slice_index.to_be_bytes());
            out.extend_from_slice(&meta.delegation_seq.to_be_bytes());
            out.extend_from_slice(&meta.created_unix.to_be_bytes());
            out.extend_from_slice(&meta.retain_until_unix.to_be_bytes());
            out.extend_from_slice(&deleg_len.to_be_bytes());
            out.extend_from_slice(&deleg_wire);
        }
        Ok(out)
    }

    pub fn decode_bytes(bytes: &[u8]) -> Result<Self, IdentityError> {
        const HDR_LEN: usize = 6 + 1 + 16 + 1 + 8 + 1;
        if bytes.len() < HDR_LEN {
            return Err(IdentityError::InvalidFraming(
                "persisted rotator state truncated".into(),
            ));
        }
        if &bytes[0..6] != ROTATOR_STATE_MAGIC || bytes[6] != ROTATOR_STATE_VERSION {
            return Err(IdentityError::InvalidFraming(
                "invalid persisted rotator state magic or version".into(),
            ));
        }
        let mut device_id = [0u8; 16];
        device_id.copy_from_slice(&bytes[7..23]);
        let prefer_chacha = match bytes[23] {
            0 => false,
            1 => true,
            _ => {
                return Err(IdentityError::InvalidFraming(
                    "invalid prefer_chacha byte in rotator state".into(),
                ));
            }
        };
        let last_delegation_seq = u64::from_be_bytes([
            bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
        ]);
        let count = bytes[32] as usize;
        if count > X25519_RETAINED_GENERATIONS {
            return Err(IdentityError::InvalidFraming(
                "retained metadata count exceeds maximum".into(),
            ));
        }
        let mut pos = HDR_LEN;
        let mut retained_metadata = Vec::with_capacity(count);
        for _ in 0..count {
            if pos + 32 + 8 * 4 + 2 > bytes.len() {
                return Err(IdentityError::InvalidFraming(
                    "persisted rotator metadata truncated".into(),
                ));
            }
            let mut public_key = [0u8; 32];
            public_key.copy_from_slice(&bytes[pos..pos + 32]);
            pos += 32;
            let read_u64 = |slice: &[u8]| -> u64 {
                u64::from_be_bytes([
                    slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
                ])
            };
            let slice_index = read_u64(&bytes[pos..pos + 8]);
            pos += 8;
            let delegation_seq = read_u64(&bytes[pos..pos + 8]);
            pos += 8;
            let created_unix = read_u64(&bytes[pos..pos + 8]);
            pos += 8;
            let retain_until_unix = read_u64(&bytes[pos..pos + 8]);
            pos += 8;
            let deleg_len = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]) as usize;
            pos += 2;
            if pos + deleg_len > bytes.len() {
                return Err(IdentityError::InvalidFraming(
                    "persisted delegation truncated".into(),
                ));
            }
            let delegation = DelegationStatement::decode_wire(&bytes[pos..pos + deleg_len])?;
            pos += deleg_len;
            retained_metadata.push(RetainedKeyMetadata {
                public_key,
                slice_index,
                delegation_seq,
                created_unix,
                retain_until_unix,
                delegation,
            });
        }
        if pos != bytes.len() {
            return Err(IdentityError::InvalidFraming(
                "trailing bytes in persisted rotator state".into(),
            ));
        }
        let max_meta_seq = retained_metadata
            .iter()
            .map(|m| m.delegation_seq)
            .max()
            .unwrap_or(0);
        Ok(Self {
            device_id,
            prefer_chacha,
            last_delegation_seq: last_delegation_seq.max(max_meta_seq),
            retained_metadata,
        })
    }
}

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

    pub fn metadata(&self) -> RetainedKeyMetadata {
        RetainedKeyMetadata {
            public_key: self.public_key,
            slice_index: self.slice_index,
            delegation_seq: self.delegation_seq,
            created_unix: self.created_unix,
            retain_until_unix: self.retain_until_unix,
            delegation: self.delegation.clone(),
        }
    }

    pub fn diffie_hellman(&self, peer_public: [u8; 32]) -> Zeroizing<[u8; 32]> {
        let mut secret = StaticSecret::from(self.secret_bytes);
        let peer = PublicKey::from(peer_public);
        let mut shared = secret.diffie_hellman(&peer);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(shared.as_bytes());
        shared.zeroize();
        secret.zeroize();
        out
    }
}

/// Manages 12-hour time-slice X25519 static keys in memory (`ZeroizeOnDrop`).
///
/// Retains the latest 2 generations (`>= 48h` retention window) so the
/// responder can attempt decryption against the current and previous static
/// keys during slice rollover. Non-secret metadata (`last_delegation_seq` and
/// generation metadata) can be persisted across restarts so `delegation_seq`
/// remains strictly monotonic without writing X25519 private keys to disk.
pub struct X25519StaticKeyRotator {
    device_id: [u8; 16],
    prefer_chacha: bool,
    last_delegation_seq: u64,
    generations: VecDeque<X25519KeyGeneration>,
    prior_metadata: Vec<RetainedKeyMetadata>,
}

impl X25519StaticKeyRotator {
    pub fn new(device_id: [u8; 16], prefer_chacha: bool, initial_delegation_seq: u64) -> Self {
        Self {
            device_id,
            prefer_chacha,
            last_delegation_seq: initial_delegation_seq,
            generations: VecDeque::with_capacity(X25519_RETAINED_GENERATIONS),
            prior_metadata: Vec::new(),
        }
    }

    pub fn last_delegation_seq(&self) -> u64 {
        self.last_delegation_seq
    }

    pub fn retained_metadata(&self) -> Vec<RetainedKeyMetadata> {
        let mut out: Vec<RetainedKeyMetadata> =
            self.generations.iter().map(X25519KeyGeneration::metadata).collect();
        for meta in &self.prior_metadata {
            if out.len() >= X25519_RETAINED_GENERATIONS {
                break;
            }
            if !out.iter().any(|m| m.delegation_seq == meta.delegation_seq) {
                out.push(meta.clone());
            }
        }
        out
    }

    pub fn to_persisted_state(&self) -> RotatorPersistedState {
        RotatorPersistedState {
            device_id: self.device_id,
            prefer_chacha: self.prefer_chacha,
            last_delegation_seq: self.last_delegation_seq,
            retained_metadata: self.retained_metadata(),
        }
    }

    pub fn from_persisted_state(state: RotatorPersistedState) -> Self {
        let max_meta_seq = state
            .retained_metadata
            .iter()
            .map(|m| m.delegation_seq)
            .max()
            .unwrap_or(0);
        Self {
            device_id: state.device_id,
            prefer_chacha: state.prefer_chacha,
            last_delegation_seq: state.last_delegation_seq.max(max_meta_seq),
            generations: VecDeque::with_capacity(X25519_RETAINED_GENERATIONS),
            prior_metadata: state
                .retained_metadata
                .into_iter()
                .take(X25519_RETAINED_GENERATIONS)
                .collect(),
        }
    }

    pub fn save_state(&self, path: &Path) -> Result<(), IdentityError> {
        static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

        let bytes = self.to_persisted_state().encode_bytes()?;
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let base_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("rotator_state");
        let nonce = TMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let tmp_path: PathBuf = parent.join(format!(
            ".{base_name}.tmp.{}.{nonce}",
            std::process::id()
        ));

        let write_result: Result<(), IdentityError> = (|| {
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            let mut file = opts
                .open(&tmp_path)
                .map_err(|e| IdentityError::Storage(e.to_string()))?;
            file.write_all(&bytes)
                .map_err(|e| IdentityError::Storage(e.to_string()))?;
            file.sync_all()
                .map_err(|e| IdentityError::Storage(e.to_string()))?;
            #[cfg(unix)]
            {
                use std::{fs::Permissions, os::unix::fs::PermissionsExt};
                std::fs::set_permissions(&tmp_path, Permissions::from_mode(0o600))
                    .map_err(|e| IdentityError::Storage(e.to_string()))?;
            }
            drop(file);
            std::fs::rename(&tmp_path, path)
                .map_err(|e| IdentityError::Storage(e.to_string()))?;
            #[cfg(unix)]
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
            Ok(())
        })();

        if write_result.is_err() {
            let _ = std::fs::remove_file(&tmp_path);
        }
        write_result
    }

    pub fn load_state(path: &Path) -> Result<Self, IdentityError> {
        let bytes = std::fs::read(path).map_err(|e| IdentityError::Storage(e.to_string()))?;
        let state = RotatorPersistedState::decode_bytes(&bytes)?;
        Ok(Self::from_persisted_state(state))
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
        let mut static_secret = StaticSecret::random_from_rng(OsRng);
        let public_key = PublicKey::from(&static_secret).to_bytes();
        let secret_bytes = static_secret.to_bytes();
        static_secret.zeroize();

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
/// strictly increasing `delegation_seq`, and allows at most 1 retry per
/// handshake session (`handshake_id` / `session_id`).
#[derive(Debug, Default)]
pub struct StaticKeyHintRetry {
    per_session: HashMap<[u8; 16], u8>,
    order: VecDeque<[u8; 16]>,
}

impl StaticKeyHintRetry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn retries_used(&self, handshake_id: &[u8; 16]) -> u8 {
        self.per_session.get(handshake_id).copied().unwrap_or(0)
    }

    pub fn clear_session(&mut self, handshake_id: &[u8; 16]) {
        if self.per_session.remove(handshake_id).is_some() {
            if let Some(pos) = self.order.iter().position(|id| id == handshake_id) {
                self.order.remove(pos);
            }
        }
    }

    pub fn accept_hint(
        &mut self,
        handshake_id: [u8; 16],
        cache: &mut DelegationCache,
        hint: &DelegationStatement,
        device_spki_der: &[u8],
        device_cert_exp_unix: u64,
        now_unix: u64,
    ) -> Result<(), IdentityError> {
        let used = self.retries_used(&handshake_id);
        if used >= STATIC_KEY_HINT_MAX_RETRIES {
            return Err(IdentityError::RetryLimitExceeded);
        }
        if let Some(prev) = cache.get(&hint.device_id) {
            if hint.delegation_seq <= prev.delegation_seq {
                return Err(IdentityError::DelegationRollback);
            }
        }
        cache.verify_and_record(hint, device_spki_der, device_cert_exp_unix, now_unix)?;
        if !self.per_session.contains_key(&handshake_id) {
            while self.per_session.len() >= STATIC_KEY_HINT_MAX_SESSIONS {
                if let Some(oldest) = self.order.pop_front() {
                    self.per_session.remove(&oldest);
                } else {
                    break;
                }
            }
            self.order.push_back(handshake_id);
        }
        self.per_session.insert(handshake_id, used + 1);
        Ok(())
    }
}
