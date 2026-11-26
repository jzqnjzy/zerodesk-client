// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::config::{
    ensure_dir_0700, verify_file_permissions_0600, write_file_atomic_0600, V2ConfigError,
    DELEGATION_FILE_NAME, IDENTITY_FILE_NAME,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};
use v2_client::{
    decode_hex_array, now_unix_secs, ClientError, ControlPlaneClient, SignalingDeviceCert,
};
use v2_identity::{
    DelegationStatement, DeviceKeyStore, IdentityError, RotatorPersistedState,
    SoftwareDeviceKeyStore, X25519StaticKeyRotator,
};

const CERT_REFRESH_MARGIN_SECS: u64 = 300;

#[derive(Debug)]
pub enum IdentityStoreError {
    Config(V2ConfigError),
    Identity(IdentityError),
    Client(ClientError),
    Storage(String),
    EnrollmentRequired(String),
}

impl fmt::Display for IdentityStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Identity(e) => write!(f, "identity error: {e}"),
            Self::Client(e) => write!(f, "control-plane error: {e}"),
            Self::Storage(msg) => write!(f, "identity storage error: {msg}"),
            Self::EnrollmentRequired(msg) => write!(f, "enrollment required: {msg}"),
        }
    }
}

impl std::error::Error for IdentityStoreError {}

impl From<V2ConfigError> for IdentityStoreError {
    fn from(e: V2ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<IdentityError> for IdentityStoreError {
    fn from(e: IdentityError) -> Self {
        Self::Identity(e)
    }
}

impl From<ClientError> for IdentityStoreError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedIdentityFile {
    version: u32,
    device_id_hex: String,
    p256_pkcs8_der_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_cert_pb_b64: Option<String>,
}

/// Persistent ZeroDesk V2 device identity backed by atomic `0600` files in `identity_dir`:
/// - `identity_v2.json`: `device_id`, P-256 `SoftwareDeviceKeyStore` PKCS#8 DER, cached `tenant_id` & CA-signed `DeviceCert`.
/// - `delegation_v2.json`: `X25519StaticKeyRotator` non-secret monotonic state (`delegation_seq`).
pub struct PersistentV2Identity {
    identity_dir: PathBuf,
    device_id: [u8; 16],
    tenant_id: Option<[u8; 16]>,
    keystore: SoftwareDeviceKeyStore,
    device_cert: Option<SignalingDeviceCert>,
    rotator: X25519StaticKeyRotator,
}

impl PersistentV2Identity {
    /// Loads existing `identity_v2.json` + `delegation_v2.json` from `identity_dir` (refusing
    /// overly permissive permissions on Unix), or creates and atomically persists a fresh identity.
    pub fn load_or_create(identity_dir: &Path) -> Result<Self, IdentityStoreError> {
        ensure_dir_0700(identity_dir)?;
        let id_path = identity_dir.join(IDENTITY_FILE_NAME);
        let deleg_path = identity_dir.join(DELEGATION_FILE_NAME);

        if id_path.exists() {
            verify_file_permissions_0600(&id_path)?;
            let raw = fs::read_to_string(&id_path).map_err(|e| {
                IdentityStoreError::Storage(format!("read '{}': {e}", id_path.display()))
            })?;
            let persisted: PersistedIdentityFile = serde_json::from_str(&raw).map_err(|e| {
                IdentityStoreError::Storage(format!("parse '{}': {e}", id_path.display()))
            })?;
            let device_id = decode_hex_array::<16>(&persisted.device_id_hex, "device_id_hex")?;
            let pkcs8 = B64
                .decode(&persisted.p256_pkcs8_der_b64)
                .map_err(|e| IdentityStoreError::Storage(format!("decode p256_pkcs8_der: {e}")))?;
            let keystore = SoftwareDeviceKeyStore::from_pkcs8_der(&pkcs8)?;
            let tenant_id = match &persisted.tenant_id_hex {
                Some(h) if !h.is_empty() => Some(decode_hex_array::<16>(h, "tenant_id_hex")?),
                _ => None,
            };
            let device_cert = match &persisted.device_cert_pb_b64 {
                Some(b64) if !b64.is_empty() => {
                    let pb = B64.decode(b64).map_err(|e| {
                        IdentityStoreError::Storage(format!("decode device_cert_pb_b64: {e}"))
                    })?;
                    Some(SignalingDeviceCert::decode_pb(&pb)?)
                }
                _ => None,
            };

            let rotator = if deleg_path.exists() {
                verify_file_permissions_0600(&deleg_path)?;
                let deleg_raw = fs::read_to_string(&deleg_path).map_err(|e| {
                    IdentityStoreError::Storage(format!("read '{}': {e}", deleg_path.display()))
                })?;
                let state: RotatorPersistedState =
                    serde_json::from_str(&deleg_raw).map_err(|e| {
                        IdentityStoreError::Storage(format!(
                            "parse '{}': {e}",
                            deleg_path.display()
                        ))
                    })?;
                if state.device_id != device_id {
                    return Err(IdentityStoreError::Storage(
                        "delegation_v2.json device_id does not match identity_v2.json".into(),
                    ));
                }
                X25519StaticKeyRotator::from_persisted_state(state)
            } else {
                X25519StaticKeyRotator::new(device_id, false, 0)
            };

            Ok(Self {
                identity_dir: identity_dir.to_path_buf(),
                device_id,
                tenant_id,
                keystore,
                device_cert,
                rotator,
            })
        } else {
            let mut device_id = [0u8; 16];
            OsRng.fill_bytes(&mut device_id);
            let keystore = SoftwareDeviceKeyStore::generate();
            let rotator = X25519StaticKeyRotator::new(device_id, false, 0);
            let me = Self {
                identity_dir: identity_dir.to_path_buf(),
                device_id,
                tenant_id: None,
                keystore,
                device_cert: None,
                rotator,
            };
            me.persist_identity()?;
            me.persist_delegation()?;
            Ok(me)
        }
    }

    pub fn identity_dir(&self) -> &Path {
        &self.identity_dir
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.device_id
    }

    pub fn tenant_id(&self) -> Option<[u8; 16]> {
        self.tenant_id
    }

    pub fn keystore(&self) -> &SoftwareDeviceKeyStore {
        &self.keystore
    }

    pub fn device_cert(&self) -> Option<&SignalingDeviceCert> {
        self.device_cert.as_ref()
    }

    pub fn public_spki_der(&self) -> Result<Vec<u8>, IdentityStoreError> {
        Ok(self.keystore.public_key_spki_der()?)
    }

    fn persist_identity(&self) -> Result<(), IdentityStoreError> {
        let pkcs8 = self.keystore.to_pkcs8_der()?;
        let cert_pb_b64 = self
            .device_cert
            .as_ref()
            .map(|c| B64.encode(c.encode_pb()));
        let file = PersistedIdentityFile {
            version: 1,
            device_id_hex: hex::encode(self.device_id),
            p256_pkcs8_der_b64: B64.encode(pkcs8.as_slice()),
            tenant_id_hex: self.tenant_id.map(hex::encode),
            device_cert_pb_b64: cert_pb_b64,
        };
        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| IdentityStoreError::Storage(format!("serialize identity_v2.json: {e}")))?;
        write_file_atomic_0600(&self.identity_dir.join(IDENTITY_FILE_NAME), &bytes)?;
        Ok(())
    }

    fn persist_delegation(&self) -> Result<(), IdentityStoreError> {
        let state = self.rotator.to_persisted_state();
        let bytes = serde_json::to_vec_pretty(&state)
            .map_err(|e| IdentityStoreError::Storage(format!("serialize delegation_v2.json: {e}")))?;
        write_file_atomic_0600(&self.identity_dir.join(DELEGATION_FILE_NAME), &bytes)?;
        Ok(())
    }

    /// Ensures this device holds a valid CA-verified `SignalingDeviceCert`.
    /// Reuses a valid cached certificate (with `> 5min` TTL remaining) if present so
    /// `enrollment_token` is optional after initial registration; otherwise registers with the
    /// Control Plane, verifies the returned `DeviceCert` against `ca_spki_der`, and persists it.
    pub async fn ensure_registered(
        &mut self,
        cp: &ControlPlaneClient,
        ca_spki_der: &[u8],
        enrollment_token: Option<&str>,
        cap_bits: u64,
        home_region: &str,
    ) -> Result<SignalingDeviceCert, IdentityStoreError> {
        let now_unix = now_unix_secs();
        if let Some(cached) = &self.device_cert {
            if cached.device_id == self.device_id
                && cached.exp_unix > now_unix.saturating_add(CERT_REFRESH_MARGIN_SECS)
                && cached.verify(ca_spki_der, now_unix).is_ok()
            {
                self.tenant_id = Some(cached.tenant_id);
                return Ok(cached.clone());
            }
        }

        let token = enrollment_token
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                IdentityStoreError::EnrollmentRequired(
                    "no valid cached DeviceCert and no enrollment_token supplied".into(),
                )
            })?;

        let reg = cp
            .register_device(
                &self.keystore,
                &self.device_id,
                token,
                cap_bits,
                home_region,
                None,
                None,
            )
            .await?;
        let cert = SignalingDeviceCert::from_register_resp(&reg)?;
        if cert.device_id != self.device_id {
            return Err(IdentityStoreError::Storage(
                "Control Plane returned DeviceCert with mismatched device_id".into(),
            ));
        }
        let local_spki = self.keystore.public_key_spki_der()?;
        if cert.p256_pub_der != local_spki {
            return Err(IdentityStoreError::Storage(
                "Control Plane returned DeviceCert with mismatched p256_pub_der".into(),
            ));
        }
        cert.verify(ca_spki_der, now_unix_secs())?;

        self.tenant_id = Some(cert.tenant_id);
        self.device_cert = Some(cert.clone());
        self.persist_identity()?;
        Ok(cert)
    }

    /// Ensures a current 12-hour X25519 static key generation & signed `DelegationStatement`,
    /// atomically persisting updated monotonic `delegation_seq` state (`0600`).
    pub fn ensure_delegation(
        &mut self,
        now_unix: u64,
    ) -> Result<([u8; 32], DelegationStatement), IdentityStoreError> {
        let cert = self.device_cert.as_ref().ok_or_else(|| {
            IdentityStoreError::EnrollmentRequired(
                "cannot create X25519 delegation before DeviceCert registration".into(),
            )
        })?;
        let gen = self
            .rotator
            .ensure_current(&self.keystore, now_unix, cert.exp_unix)?;
        let secret = *gen.secret_bytes();
        let deleg = gen.delegation.clone();
        self.persist_delegation()?;
        Ok((secret, deleg))
    }

    /// Returns all currently retained X25519 private keys (newest first) for responder fallback.
    pub fn retained_x25519_secrets(&self) -> Vec<[u8; 32]> {
        self.rotator
            .retained_generations()
            .map(|g| *g.secret_bytes())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn persistent_identity_atomic_0600_reload_and_monotonic_delegation_seq() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-id-test-{}-{uniq}", std::process::id()));

        let mut id1 = PersistentV2Identity::load_or_create(&dir).unwrap();
        let dev_id = id1.device_id();
        let spki1 = id1.public_spki_der().unwrap();

        // Seed a synthetic CA-signed DeviceCert and generate a delegation
        let ca = SoftwareDeviceKeyStore::generate();
        let now = now_unix_secs();
        let mut cert = SignalingDeviceCert {
            version: 1,
            cert_id: [0x11; 16],
            device_id: dev_id,
            tenant_id: [0x22; 16],
            p256_pub_der: spki1.clone(),
            key_epoch: 1,
            policy_hash: [0x33; 32],
            cap_bits: 0x3FFF,
            iat_unix: now.saturating_sub(10),
            exp_unix: now.saturating_add(3600),
            ca_key_id: 1,
            ca_sig: Vec::new(),
        };
        cert.ca_sig = ca.sign_p256_low_s(&cert.to_tbs_bytes().unwrap()).unwrap();
        id1.device_cert = Some(cert.clone());
        id1.tenant_id = Some(cert.tenant_id);
        id1.persist_identity().unwrap();

        let (_sec1, deleg1) = id1.ensure_delegation(now).unwrap();
        assert_eq!(deleg1.delegation_seq, 1);

        // Reload in a "new process" -> same device_id, same SPKI, delegation_seq advances monotonically!
        let mut id2 = PersistentV2Identity::load_or_create(&dir).unwrap();
        assert_eq!(id2.device_id(), dev_id);
        assert_eq!(id2.public_spki_der().unwrap(), spki1);
        assert_eq!(id2.tenant_id(), Some([0x22; 16]));
        assert_eq!(id2.device_cert(), Some(&cert));

        let (_sec2, deleg2) = id2.ensure_delegation(now).unwrap();
        assert_eq!(deleg2.delegation_seq, 2);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let id_file = dir.join(IDENTITY_FILE_NAME);
            assert_eq!(fs::metadata(&id_file).unwrap().permissions().mode() & 0o777, 0o600);
            fs::set_permissions(&id_file, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(PersistentV2Identity::load_or_create(&dir).is_err());
            fs::set_permissions(&id_file, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
