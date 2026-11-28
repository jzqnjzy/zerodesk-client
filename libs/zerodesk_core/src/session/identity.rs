// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::config::{
    ensure_dir_0700, read_file_0600_to_string, write_file_atomic_0600, write_file_create_new_0600,
    V2ConfigError, DELEGATION_FILE_NAME, IDENTITY_FILE_NAME,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
#[cfg(any(unix, test))]
use std::fs;
use std::{
    fmt,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
};
use v2_client::{
    decode_hex_array, now_unix_secs, ClientError, ControlPlaneClient, PolicyBlobJson,
    SignalingDeviceCert,
};
use v2_identity::{
    DelegationStatement, DeviceKeyStore, IdentityError, RotatorPersistedState,
    SoftwareDeviceKeyStore, X25519StaticKeyRotator,
};

const CERT_REFRESH_MARGIN_SECS: u64 = 300;
const IDENTITY_LOCK_FILE_NAME: &str = ".lock";
const PERSISTED_IDENTITY_VERSION: u32 = 1;
const PERSISTED_POLICY_VERSION_SCHEMA: u32 = 1;
pub const POLICY_VERSION_FILE_NAME: &str = "policy_version_v2.json";

/// Cross-process exclusive lock (`flock(LOCK_EX)` on Unix, `LockFileEx(LOCKFILE_EXCLUSIVE_LOCK)`
/// on Windows) on `identity_dir/.lock`. Never held across `.await`.
struct IdentityDirLock {
    #[cfg(any(unix, windows))]
    file: File,
}

impl IdentityDirLock {
    fn acquire(identity_dir: &Path) -> Result<Self, IdentityStoreError> {
        ensure_dir_0700(identity_dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::{
                fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
                io::AsRawFd,
            };
            let lock_path = identity_dir.join(IDENTITY_LOCK_FILE_NAME);
            let mut opts = OpenOptions::new();
            opts.read(true)
                .write(true)
                .create(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW);
            let file = opts.open(&lock_path).map_err(|e| {
                IdentityStoreError::Storage(format!("open lock '{}': {e}", lock_path.display()))
            })?;
            let meta = file.metadata().map_err(|e| {
                IdentityStoreError::Storage(format!("fstat lock '{}': {e}", lock_path.display()))
            })?;
            let expected_uid = unsafe { libc::geteuid() };
            if !meta.is_file() || meta.uid() != expected_uid {
                return Err(V2ConfigError::InsecurePermissions(format!(
                    "lock file '{}' must be a regular file owned by uid {expected_uid}",
                    lock_path.display()
                ))
                .into());
            }
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| {
                    IdentityStoreError::Storage(format!(
                        "fchmod 0600 lock '{}': {e}",
                        lock_path.display()
                    ))
                })?;
            loop {
                let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
                if rc == 0 {
                    break;
                }
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(IdentityStoreError::Storage(format!(
                    "flock(LOCK_EX) '{}': {err}",
                    lock_path.display()
                )));
            }
            Ok(Self { file })
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows::Win32::{
                Foundation::HANDLE,
                Storage::FileSystem::{LockFileEx, LOCKFILE_EXCLUSIVE_LOCK},
                System::IO::OVERLAPPED,
            };
            let lock_path = identity_dir.join(IDENTITY_LOCK_FILE_NAME);
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&lock_path)
                .map_err(|e| {
                    IdentityStoreError::Storage(format!("open lock '{}': {e}", lock_path.display()))
                })?;
            let mut overlapped = OVERLAPPED::default();
            unsafe {
                LockFileEx(
                    HANDLE(file.as_raw_handle() as isize),
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            }
            .map_err(|e| {
                IdentityStoreError::Storage(format!(
                    "LockFileEx(LOCKFILE_EXCLUSIVE_LOCK) '{}': {e}",
                    lock_path.display()
                ))
            })?;
            Ok(Self { file })
        }
        #[cfg(not(any(unix, windows)))]
        {
            let _ = (File::open::<&Path>, OpenOptions::new, IDENTITY_LOCK_FILE_NAME);
            Ok(Self {})
        }
    }
}

#[cfg(unix)]
impl Drop for IdentityDirLock {
    fn drop(&mut self) {
        use std::os::unix::io::AsRawFd;
        unsafe {
            let _ = libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

#[cfg(windows)]
impl Drop for IdentityDirLock {
    fn drop(&mut self) {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::{
            Foundation::HANDLE, Storage::FileSystem::UnlockFileEx, System::IO::OVERLAPPED,
        };
        let mut overlapped = OVERLAPPED::default();
        unsafe {
            let _ = UnlockFileEx(
                HANDLE(self.file.as_raw_handle() as isize),
                0,
                u32::MAX,
                u32::MAX,
                &mut overlapped,
            );
        }
    }
}

#[derive(Debug)]
pub enum IdentityStoreError {
    Config(V2ConfigError),
    Identity(IdentityError),
    Client(ClientError),
    Storage(String),
    EnrollmentRequired(String),
    PolicyRollback { attempted: u64, persisted: u64 },
}

impl fmt::Display for IdentityStoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Identity(e) => write!(f, "identity error: {e}"),
            Self::Client(e) => write!(f, "control-plane error: {e}"),
            Self::Storage(msg) => write!(f, "identity storage error: {msg}"),
            Self::EnrollmentRequired(msg) => write!(f, "enrollment required: {msg}"),
            Self::PolicyRollback {
                attempted,
                persisted,
            } => write!(
                f,
                "policy version rollback refused: attempted={attempted} < persisted={persisted}"
            ),
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
struct PersistedPolicyVersionFile {
    version: u32,
    last_policy_version: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedIdentityFile {
    version: u32,
    device_id_hex: String,
    p256_pkcs8_der_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant_id_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    device_cert_pb_b64: Option<String>,
    // Legacy field read for backward compatibility only; authoritative high-water mark lives in
    // dedicated `policy_version_v2.json` so `persist_identity()` can never overwrite it.
    #[serde(default, skip_serializing)]
    last_policy_version: u64,
}

impl fmt::Debug for PersistedIdentityFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PersistedIdentityFile")
            .field("version", &self.version)
            .field("device_id_hex", &self.device_id_hex)
            .field("p256_pkcs8_der_b64", &"<redacted>")
            .field("tenant_id_hex", &self.tenant_id_hex)
            .field(
                "device_cert_pb_b64_present",
                &self.device_cert_pb_b64.is_some(),
            )
            .field("last_policy_version", &self.last_policy_version)
            .finish()
    }
}

/// Persistent ZeroDesk V2 device identity backed by atomic `0600` files in `identity_dir`:
/// - `identity_v2.json`: `device_id`, P-256 `SoftwareDeviceKeyStore` PKCS#8 DER, cached `tenant_id`,
///   CA-signed `DeviceCert`, and monotonic anti-rollback `last_policy_version`.
/// - `delegation_v2.json`: `X25519StaticKeyRotator` non-secret monotonic state (`delegation_seq`).
pub struct PersistentV2Identity {
    identity_dir: PathBuf,
    device_id: [u8; 16],
    tenant_id: Option<[u8; 16]>,
    keystore: SoftwareDeviceKeyStore,
    device_cert: Option<SignalingDeviceCert>,
    last_policy_version: u64,
    rotator: X25519StaticKeyRotator,
}

impl PersistentV2Identity {
    fn load_locked(
        identity_dir: &Path,
        id_path: &Path,
        deleg_path: &Path,
    ) -> Result<Self, IdentityStoreError> {
        let raw = read_file_0600_to_string(id_path)?;
        let persisted: PersistedIdentityFile = serde_json::from_str(&raw).map_err(|e| {
            IdentityStoreError::Storage(format!("parse '{}': {e}", id_path.display()))
        })?;
        if persisted.version != PERSISTED_IDENTITY_VERSION {
            return Err(IdentityStoreError::Storage(format!(
                "unsupported identity_v2.json version {} (expected {PERSISTED_IDENTITY_VERSION})",
                persisted.version
            )));
        }
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
            let deleg_raw = read_file_0600_to_string(deleg_path)?;
            let state: RotatorPersistedState = serde_json::from_str(&deleg_raw).map_err(|e| {
                IdentityStoreError::Storage(format!("parse '{}': {e}", deleg_path.display()))
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

        let policy_ver_path = identity_dir.join(POLICY_VERSION_FILE_NAME);
        let disk_policy_version = Self::read_policy_version_locked(&policy_ver_path)?;
        let last_policy_version = disk_policy_version.max(persisted.last_policy_version);
        if !policy_ver_path.exists() && persisted.last_policy_version > 0 {
            let file = PersistedPolicyVersionFile {
                version: PERSISTED_POLICY_VERSION_SCHEMA,
                last_policy_version: persisted.last_policy_version,
            };
            let bytes = serde_json::to_vec_pretty(&file).map_err(|e| {
                IdentityStoreError::Storage(format!("serialize {POLICY_VERSION_FILE_NAME}: {e}"))
            })?;
            write_file_atomic_0600(&policy_ver_path, &bytes)?;
        }

        Ok(Self {
            identity_dir: identity_dir.to_path_buf(),
            device_id,
            tenant_id,
            keystore,
            device_cert,
            last_policy_version,
            rotator,
        })
    }

    fn read_policy_version_locked(path: &Path) -> Result<u64, IdentityStoreError> {
        if !path.exists() {
            return Ok(0);
        }
        let raw = read_file_0600_to_string(path)?;
        let parsed: PersistedPolicyVersionFile = serde_json::from_str(&raw).map_err(|e| {
            IdentityStoreError::Storage(format!("parse '{}': {e}", path.display()))
        })?;
        if parsed.version != PERSISTED_POLICY_VERSION_SCHEMA {
            return Err(IdentityStoreError::Storage(format!(
                "unsupported {POLICY_VERSION_FILE_NAME} version {} (expected {PERSISTED_POLICY_VERSION_SCHEMA})",
                parsed.version
            )));
        }
        Ok(parsed.last_policy_version)
    }

    /// Loads existing `identity_v2.json` + `delegation_v2.json` from `identity_dir` under an
    /// exclusive cross-process `flock` (refusing overly permissive permissions or mismatched UID
    /// on Unix), or creates and atomically persists a fresh identity with `create_new`.
    pub fn load_or_create(identity_dir: &Path) -> Result<Self, IdentityStoreError> {
        let _lock = IdentityDirLock::acquire(identity_dir)?;
        let id_path = identity_dir.join(IDENTITY_FILE_NAME);
        let deleg_path = identity_dir.join(DELEGATION_FILE_NAME);

        if id_path.exists() {
            Self::load_locked(identity_dir, &id_path, &deleg_path)
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
                last_policy_version: 0,
                rotator,
            };
            let bytes = me.serialize_identity_bytes()?;
            write_file_create_new_0600(&id_path, &bytes)?;
            me.persist_delegation_locked()?;
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

    pub fn last_policy_version(&self) -> u64 {
        self.last_policy_version
    }

    /// Atomically verifies `version >= persisted last_policy_version` under `identity_dir/.lock`
    /// and persists the monotonic high-water mark in dedicated `policy_version_v2.json` (`0600` +
    /// parent-dir fsync). No-op on disk when `version == disk_last` without rewriting identity keys.
    pub fn advance_policy_version(&mut self, version: u64) -> Result<u64, IdentityStoreError> {
        let _lock = IdentityDirLock::acquire(&self.identity_dir)?;
        let pv_path = self.identity_dir.join(POLICY_VERSION_FILE_NAME);
        let disk_last = Self::read_policy_version_locked(&pv_path)?;
        let high_water = disk_last.max(self.last_policy_version);
        if version < high_water {
            self.last_policy_version = high_water;
            return Err(IdentityStoreError::PolicyRollback {
                attempted: version,
                persisted: high_water,
            });
        }
        self.last_policy_version = version;
        if version > disk_last {
            let file = PersistedPolicyVersionFile {
                version: PERSISTED_POLICY_VERSION_SCHEMA,
                last_policy_version: version,
            };
            let bytes = serde_json::to_vec_pretty(&file).map_err(|e| {
                IdentityStoreError::Storage(format!("serialize {POLICY_VERSION_FILE_NAME}: {e}"))
            })?;
            write_file_atomic_0600(&pv_path, &bytes)?;
        }
        Ok(self.last_policy_version)
    }

    pub fn public_spki_der(&self) -> Result<Vec<u8>, IdentityStoreError> {
        Ok(self.keystore.public_key_spki_der()?)
    }

    fn serialize_identity_bytes(&self) -> Result<Vec<u8>, IdentityStoreError> {
        let pkcs8 = self.keystore.to_pkcs8_der()?;
        let cert_pb_b64 = self
            .device_cert
            .as_ref()
            .map(|c| B64.encode(c.encode_pb()));
        let file = PersistedIdentityFile {
            version: PERSISTED_IDENTITY_VERSION,
            device_id_hex: hex::encode(self.device_id),
            p256_pkcs8_der_b64: B64.encode(pkcs8.as_slice()),
            tenant_id_hex: self.tenant_id.map(hex::encode),
            device_cert_pb_b64: cert_pb_b64,
            last_policy_version: self.last_policy_version,
        };
        serde_json::to_vec_pretty(&file)
            .map_err(|e| IdentityStoreError::Storage(format!("serialize identity_v2.json: {e}")))
    }

    fn persist_identity(&self) -> Result<(), IdentityStoreError> {
        let _lock = IdentityDirLock::acquire(&self.identity_dir)?;
        let bytes = self.serialize_identity_bytes()?;
        write_file_atomic_0600(&self.identity_dir.join(IDENTITY_FILE_NAME), &bytes)?;
        Ok(())
    }

    fn persist_delegation_locked(&self) -> Result<(), IdentityStoreError> {
        let state = self.rotator.to_persisted_state();
        let bytes = serde_json::to_vec_pretty(&state)
            .map_err(|e| IdentityStoreError::Storage(format!("serialize delegation_v2.json: {e}")))?;
        write_file_atomic_0600(&self.identity_dir.join(DELEGATION_FILE_NAME), &bytes)?;
        Ok(())
    }

    /// Ensures this device holds a valid CA-verified `SignalingDeviceCert`.
    pub async fn ensure_registered(
        &mut self,
        cp: &ControlPlaneClient,
        ca_spki_der: &[u8],
        enrollment_token: Option<&str>,
        cap_bits: u64,
        home_region: &str,
    ) -> Result<SignalingDeviceCert, IdentityStoreError> {
        let (cert, _blob) = self
            .ensure_registered_with_policy(cp, ca_spki_der, enrollment_token, cap_bits, home_region)
            .await?;
        Ok(cert)
    }

    /// Ensures this device holds a valid CA-verified `SignalingDeviceCert` and also returns any
    /// optional `PolicyBlobJson` returned inline by `POST /v2/devices/register`.
    pub async fn ensure_registered_with_policy(
        &mut self,
        cp: &ControlPlaneClient,
        ca_spki_der: &[u8],
        enrollment_token: Option<&str>,
        cap_bits: u64,
        home_region: &str,
    ) -> Result<(SignalingDeviceCert, Option<PolicyBlobJson>), IdentityStoreError> {
        let now_unix = now_unix_secs();
        if let Some(cached) = &self.device_cert {
            if cached.device_id == self.device_id
                && cached.exp_unix > now_unix.saturating_add(CERT_REFRESH_MARGIN_SECS)
                && cached.verify(ca_spki_der, now_unix).is_ok()
            {
                self.tenant_id = Some(cached.tenant_id);
                return Ok((cached.clone(), None));
            }
        }
        self.force_reregister_with_policy(cp, ca_spki_der, enrollment_token, cap_bits, home_region)
            .await
    }

    /// Forces a fresh `POST /v2/devices/register` call (used for initial registration, expired
    /// cert refresh, or the ONE bounded re-register refresh on valid-sig `policy_hash` mismatch).
    pub async fn force_reregister_with_policy(
        &mut self,
        cp: &ControlPlaneClient,
        ca_spki_der: &[u8],
        enrollment_token: Option<&str>,
        cap_bits: u64,
        home_region: &str,
    ) -> Result<(SignalingDeviceCert, Option<PolicyBlobJson>), IdentityStoreError> {
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
        Ok((cert, reg.policy_blob))
    }

    /// Ensures a current 12-hour X25519 static key generation & signed `DelegationStatement`,
    /// holding `identity_dir/.lock` while refreshing from disk and atomically persisting updated
    /// monotonic `delegation_seq` state (`0600` + parent-dir fsync).
    pub fn ensure_delegation(
        &mut self,
        now_unix: u64,
    ) -> Result<([u8; 32], DelegationStatement), IdentityStoreError> {
        let cert_exp = self
            .device_cert
            .as_ref()
            .ok_or_else(|| {
                IdentityStoreError::EnrollmentRequired(
                    "cannot create X25519 delegation before DeviceCert registration".into(),
                )
            })?
            .exp_unix;
        let _lock = IdentityDirLock::acquire(&self.identity_dir)?;
        let deleg_path = self.identity_dir.join(DELEGATION_FILE_NAME);
        if deleg_path.exists() {
            let deleg_raw = read_file_0600_to_string(&deleg_path)?;
            let disk_state: RotatorPersistedState =
                serde_json::from_str(&deleg_raw).map_err(|e| {
                    IdentityStoreError::Storage(format!("parse '{}': {e}", deleg_path.display()))
                })?;
            if disk_state.device_id != self.device_id {
                return Err(IdentityStoreError::Storage(
                    "delegation_v2.json device_id does not match identity_v2.json".into(),
                ));
            }
            let local_state = self.rotator.to_persisted_state();
            if disk_state.last_delegation_seq > local_state.last_delegation_seq {
                self.rotator = X25519StaticKeyRotator::from_persisted_state(disk_state);
            }
        }
        let gen = self
            .rotator
            .ensure_current(&self.keystore, now_unix, cert_exp)?;
        let secret = *gen.secret_bytes();
        let deleg = gen.delegation.clone();
        self.persist_delegation_locked()?;
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

        // Monotonic last_policy_version persists atomically and rejects rollback
        assert_eq!(id2.last_policy_version(), 0);
        assert_eq!(id2.advance_policy_version(7).unwrap(), 7);
        let mut id3 = PersistentV2Identity::load_or_create(&dir).unwrap();
        assert_eq!(id3.last_policy_version(), 7);
        assert!(id3.advance_policy_version(6).is_err());
        assert_eq!(id3.advance_policy_version(7).unwrap(), 7);
        assert_eq!(id3.advance_policy_version(8).unwrap(), 8);

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

    #[test]
    fn persisted_identity_debug_redacts_key_and_rejects_bad_version_and_concurrent_create() {
        let f = PersistedIdentityFile {
            version: 1,
            device_id_hex: "00".repeat(16),
            p256_pkcs8_der_b64: "SECRET_PKCS8_KEY_MATERIAL".into(),
            tenant_id_hex: None,
            device_cert_pb_b64: None,
            last_policy_version: 0,
        };
        let dbg = format!("{f:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("SECRET_PKCS8_KEY_MATERIAL"));

        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-id-ver-{}-{uniq}", std::process::id()));
        ensure_dir_0700(&dir).unwrap();

        // Concurrent load_or_create under flock MUST converge on a single identical device_id
        let d1 = dir.clone();
        let d2 = dir.clone();
        let t1 = std::thread::spawn(move || PersistentV2Identity::load_or_create(&d1).unwrap().device_id());
        let t2 = std::thread::spawn(move || PersistentV2Identity::load_or_create(&d2).unwrap().device_id());
        assert_eq!(t1.join().unwrap(), t2.join().unwrap());

        // Unsupported version != 1 MUST be rejected
        let id_path = dir.join(IDENTITY_FILE_NAME);
        let raw = read_file_0600_to_string(&id_path).unwrap();
        let mut parsed: PersistedIdentityFile = serde_json::from_str(&raw).unwrap();
        parsed.version = 99;
        write_file_atomic_0600(&id_path, &serde_json::to_vec(&parsed).unwrap()).unwrap();
        assert!(PersistentV2Identity::load_or_create(&dir).is_err());

        // Symlink read via read_file_0600_to_string MUST fail closed (O_NOFOLLOW)
        #[cfg(unix)]
        {
            let link = dir.join("sym_id.json");
            std::os::unix::fs::symlink(&id_path, &link).unwrap();
            assert!(read_file_0600_to_string(&link).is_err());
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn policy_version_v2_isolated_from_stale_persist_identity_and_refuses_rollback() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-pv-iso-{}-{uniq}", std::process::id()));
        ensure_dir_0700(&dir).unwrap();

        let mut inst_a = PersistentV2Identity::load_or_create(&dir).unwrap();
        assert_eq!(inst_a.advance_policy_version(7).unwrap(), 7);
        // Load instance B at version 7
        let mut inst_b = PersistentV2Identity::load_or_create(&dir).unwrap();
        assert_eq!(inst_b.last_policy_version(), 7);

        // Instance A advances to 8 (persisted into isolated policy_version_v2.json)
        assert_eq!(inst_a.advance_policy_version(8).unwrap(), 8);
        assert!(dir.join(POLICY_VERSION_FILE_NAME).exists());

        // Stale instance B rewrites identity_v2.json via persist_identity()
        inst_b.persist_identity().unwrap();

        // Disk high-water mark MUST remain 8, and instance B attempting version 7 MUST fail with PolicyRollback
        let reloaded = PersistentV2Identity::load_or_create(&dir).unwrap();
        assert_eq!(reloaded.last_policy_version(), 8);
        match inst_b.advance_policy_version(7) {
            Err(IdentityStoreError::PolicyRollback {
                attempted: 7,
                persisted: 8,
            }) => {}
            other => panic!("expected PolicyRollback(7 < 8), got {other:?}"),
        }
        // Idempotent repeat of 8 succeeds without error
        assert_eq!(inst_b.advance_policy_version(8).unwrap(), 8);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_identity_v2_migrates_last_policy_version_before_persist_identity() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-pv-leg-{}-{uniq}", std::process::id()));
        ensure_dir_0700(&dir).unwrap();

        // Seed a legacy identity_v2.json with last_policy_version = 7 and NO policy_version_v2.json
        let ks = SoftwareDeviceKeyStore::generate();
        let pkcs8 = ks.to_pkcs8_der().unwrap();
        let legacy_json = serde_json::json!({
            "version": 1,
            "device_id_hex": "11".repeat(16),
            "p256_pkcs8_der_b64": B64.encode(pkcs8.as_slice()),
            "last_policy_version": 7
        });
        write_file_atomic_0600(
            &dir.join(IDENTITY_FILE_NAME),
            &serde_json::to_vec_pretty(&legacy_json).unwrap(),
        )
        .unwrap();
        assert!(!dir.join(POLICY_VERSION_FILE_NAME).exists());

        // load_or_create MUST migrate 7 -> policy_version_v2.json immediately under flock
        let loaded = PersistentV2Identity::load_or_create(&dir).unwrap();
        assert_eq!(loaded.last_policy_version(), 7);
        assert!(dir.join(POLICY_VERSION_FILE_NAME).exists());

        // Calling persist_identity() BEFORE any advance_policy_version() MUST preserve 7 on disk
        loaded.persist_identity().unwrap();

        let mut reloaded = PersistentV2Identity::load_or_create(&dir).unwrap();
        assert_eq!(reloaded.last_policy_version(), 7);
        match reloaded.advance_policy_version(6) {
            Err(IdentityStoreError::PolicyRollback {
                attempted: 6,
                persisted: 7,
            }) => {}
            other => panic!("expected PolicyRollback(6 < 7), got {other:?}"),
        }

        let _ = fs::remove_dir_all(&dir);
    }
}
