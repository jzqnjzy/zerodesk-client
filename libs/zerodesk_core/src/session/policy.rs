// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `v1.2.4` CA-signed `TenantPolicyBlob` verification, 17-byte canonical `TenantPolicyBody`
//! codec (`spec/06` §3.8 & `V27`), and Fail-Closed Privilege Degrade (no unattended lockout).

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use v2_client::PolicyBlobJson;
use v2_identity::{verify_p256_low_s, TENANT_POLICY_DOMAIN};
use v2_transport::{QuotaExhaustPolicy, VerifiedTenantPolicy};

pub const TENANT_POLICY_BODY_LEN: usize = 17;
pub const TENANT_POLICY_SCHEMA_VER: u8 = 1;
pub const TENANT_POLICY_TBS_LEN: usize = 91;
pub const POLICY_CLOCK_SKEW_SECS: u64 = 300;
pub const DEGRADED_BASELINE_BW_KBPS: u32 = 2_000;
pub const MAX_CLIPBOARD_HARD_CAP_BYTES: u64 = 262_144;

pub const POLICY_FLAG_ALLOW_FILE_TRANSFER: u32 = 1 << 0;
pub const POLICY_FLAG_ALLOW_CLIPBOARD: u32 = 1 << 1;
pub const POLICY_FLAG_ALLOW_FILE_CLIPBOARD: u32 = 1 << 2;
pub const POLICY_FLAG_ALLOW_TCP_TUNNEL: u32 = 1 << 3;
pub const POLICY_FLAG_ALLOW_TERMINAL: u32 = 1 << 4;
pub const POLICY_FLAG_ALLOW_AUDIO: u32 = 1 << 5;
pub const POLICY_FLAGS_VALID_MASK: u32 = 0x0000_003F;
pub const POLICY_FLAGS_RESERVED_MASK: u32 = 0xFFFF_FFC0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    InvalidLength { expected: usize, actual: usize },
    UnsupportedSchemaVersion(u8),
    ReservedFlagsNonZero(u32),
    InvalidVersion(u64),
    InvalidTimeWindow { iat_unix: u64, exp_unix: u64 },
    ExpiredOrNotYetValid { now_unix: u64, iat_unix: u64, exp_unix: u64 },
    TenantMismatch,
    VersionRollback { version: u64, last_version: u64 },
    BodyHashMismatch,
    InvalidSignature(String),
    CertPolicyHashMismatch,
    MalformedBlob(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { expected, actual } => {
                write!(f, "TenantPolicyBody length mismatch: expected {expected}, got {actual}")
            }
            Self::UnsupportedSchemaVersion(v) => {
                write!(f, "unsupported TenantPolicyBody schema_ver={v} (expected {TENANT_POLICY_SCHEMA_VER})")
            }
            Self::ReservedFlagsNonZero(bits) => {
                write!(f, "TenantPolicyBody reserved flag bits non-zero: {bits:#010x}")
            }
            Self::InvalidVersion(v) => write!(f, "invalid TenantPolicyBlob version={v} (must be >= 1)"),
            Self::InvalidTimeWindow { iat_unix, exp_unix } => {
                write!(f, "invalid TenantPolicyBlob window: exp_unix({exp_unix}) <= iat_unix({iat_unix})")
            }
            Self::ExpiredOrNotYetValid {
                now_unix,
                iat_unix,
                exp_unix,
            } => write!(
                f,
                "TenantPolicyBlob outside validity window: now={now_unix}, iat={iat_unix}, exp={exp_unix}"
            ),
            Self::TenantMismatch => write!(f, "TenantPolicyBlob tenant_id does not match DeviceCert"),
            Self::VersionRollback {
                version,
                last_version,
            } => write!(
                f,
                "TenantPolicyBlob version rollback detected: version={version} < last_policy_version={last_version}"
            ),
            Self::BodyHashMismatch => {
                write!(f, "SHA-256(TenantPolicyBody) does not match policy_blob.policy_hash")
            }
            Self::InvalidSignature(msg) => write!(f, "TenantPolicyBlob CA signature invalid: {msg}"),
            Self::CertPolicyHashMismatch => {
                write!(f, "TenantPolicyBlob policy_hash does not match DeviceCert.policy_hash")
            }
            Self::MalformedBlob(msg) => write!(f, "malformed TenantPolicyBlob: {msg}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Exact 17-byte canonical big-endian `TenantPolicyBody` (`spec/06` §3.8.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantPolicyBody {
    pub schema_ver: u8,
    pub flags: u32,
    pub max_bw_kbps: u32,
    pub max_file_mb: u32,
    pub max_clipboard_kb: u32,
}

impl TenantPolicyBody {
    /// Fail-Closed Privilege Degrade baseline (`spec/06` §3.8.3):
    /// all 6 privilege flags disabled, `max_file_mb = 0`, `max_clipboard_kb = 0`,
    /// `max_bw_kbps = 2000` (`DEGRADED_BASELINE_BW_KBPS`) so Video + InputHID never lock out
    /// an unattended host.
    pub const fn degraded_baseline() -> Self {
        Self {
            schema_ver: TENANT_POLICY_SCHEMA_VER,
            flags: 0,
            max_bw_kbps: DEGRADED_BASELINE_BW_KBPS,
            max_file_mb: 0,
            max_clipboard_kb: 0,
        }
    }

    pub fn encode(&self) -> Result<[u8; TENANT_POLICY_BODY_LEN], PolicyError> {
        if self.schema_ver != TENANT_POLICY_SCHEMA_VER {
            return Err(PolicyError::UnsupportedSchemaVersion(self.schema_ver));
        }
        let reserved = self.flags & POLICY_FLAGS_RESERVED_MASK;
        if reserved != 0 {
            return Err(PolicyError::ReservedFlagsNonZero(reserved));
        }
        let mut out = [0u8; TENANT_POLICY_BODY_LEN];
        out[0] = self.schema_ver;
        out[1..5].copy_from_slice(&self.flags.to_be_bytes());
        out[5..9].copy_from_slice(&self.max_bw_kbps.to_be_bytes());
        out[9..13].copy_from_slice(&self.max_file_mb.to_be_bytes());
        out[13..17].copy_from_slice(&self.max_clipboard_kb.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.len() != TENANT_POLICY_BODY_LEN {
            return Err(PolicyError::InvalidLength {
                expected: TENANT_POLICY_BODY_LEN,
                actual: bytes.len(),
            });
        }
        let schema_ver = bytes[0];
        if schema_ver != TENANT_POLICY_SCHEMA_VER {
            return Err(PolicyError::UnsupportedSchemaVersion(schema_ver));
        }
        let flags = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
        let reserved = flags & POLICY_FLAGS_RESERVED_MASK;
        if reserved != 0 {
            return Err(PolicyError::ReservedFlagsNonZero(reserved));
        }
        let max_bw_kbps = u32::from_be_bytes([bytes[5], bytes[6], bytes[7], bytes[8]]);
        let max_file_mb = u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]);
        let max_clipboard_kb = u32::from_be_bytes([bytes[13], bytes[14], bytes[15], bytes[16]]);
        Ok(Self {
            schema_ver,
            flags,
            max_bw_kbps,
            max_file_mb,
            max_clipboard_kb,
        })
    }

    pub fn sha256(&self) -> Result<[u8; 32], PolicyError> {
        let encoded = self.encode()?;
        Ok(Sha256::digest(encoded).into())
    }

    pub const fn allow_file_transfer(&self) -> bool {
        (self.flags & POLICY_FLAG_ALLOW_FILE_TRANSFER) != 0 && self.max_file_mb > 0
    }

    pub const fn allow_clipboard(&self) -> bool {
        (self.flags & POLICY_FLAG_ALLOW_CLIPBOARD) != 0 && self.max_clipboard_kb > 0
    }

    /// `allow_file_clipboard` is effective ONLY when `allow_clipboard` is also 1 and
    /// `max_clipboard_kb > 0` (`spec/06` §3.8.1).
    pub const fn allow_file_clipboard(&self) -> bool {
        self.allow_clipboard() && (self.flags & POLICY_FLAG_ALLOW_FILE_CLIPBOARD) != 0
    }

    pub const fn allow_tcp_tunnel(&self) -> bool {
        (self.flags & POLICY_FLAG_ALLOW_TCP_TUNNEL) != 0
    }

    pub const fn allow_terminal(&self) -> bool {
        (self.flags & POLICY_FLAG_ALLOW_TERMINAL) != 0
    }

    pub const fn allow_audio(&self) -> bool {
        (self.flags & POLICY_FLAG_ALLOW_AUDIO) != 0
    }

    /// Checked u64 file size limit (`max_file_mb == 0` means disabled/0, NEVER unlimited).
    pub fn max_file_bytes(&self) -> u64 {
        u64::from(self.max_file_mb).saturating_mul(1024 * 1024)
    }

    /// Checked u64 clipboard limit capped at 256 KiB (`max_clipboard_kb == 0` means disabled/0).
    pub fn max_clipboard_bytes(&self) -> u64 {
        u64::from(self.max_clipboard_kb)
            .checked_mul(1024)
            .map(|v| v.min(MAX_CLIPBOARD_HARD_CAP_BYTES))
            .unwrap_or(MAX_CLIPBOARD_HARD_CAP_BYTES)
    }
}

/// Builds the exact 91-byte `TENANT_POLICY_TBS` preimage (`spec/06` §3.8.2):
/// `"V2-TENANT-POLICY-v1" (19B) || tenant_id(16B) || u64_be(version) || policy_hash(32B) || u64_be(iat_unix) || u64_be(exp_unix)`.
pub fn build_tenant_policy_tbs(
    tenant_id: &[u8; 16],
    version: u64,
    policy_hash: &[u8; 32],
    iat_unix: u64,
    exp_unix: u64,
) -> [u8; TENANT_POLICY_TBS_LEN] {
    let mut out = [0u8; TENANT_POLICY_TBS_LEN];
    out[0..19].copy_from_slice(TENANT_POLICY_DOMAIN);
    out[19..35].copy_from_slice(tenant_id);
    out[35..43].copy_from_slice(&version.to_be_bytes());
    out[43..75].copy_from_slice(policy_hash);
    out[75..83].copy_from_slice(&iat_unix.to_be_bytes());
    out[83..91].copy_from_slice(&exp_unix.to_be_bytes());
    out
}

/// Strict ASN.1 DER length check rejecting any trailing garbage bytes after the SEQUENCE.
fn validate_strict_der_ecdsa_sig_len(sig_der: &[u8]) -> Result<(), PolicyError> {
    if sig_der.len() < 8 || sig_der.len() > 72 {
        return Err(PolicyError::InvalidSignature(format!(
            "DER signature length {} out of bounds",
            sig_der.len()
        )));
    }
    if sig_der[0] != 0x30 {
        return Err(PolicyError::InvalidSignature(
            "DER signature missing SEQUENCE tag 0x30".into(),
        ));
    }
    let declared_len = sig_der[1] as usize;
    if declared_len >= 0x80 || 2 + declared_len != sig_der.len() {
        return Err(PolicyError::InvalidSignature(
            "DER signature length mismatch or trailing bytes present".into(),
        ));
    }
    Ok(())
}

/// Decoded & cryptographically verified (or fail-closed degraded) tenant policy used by both
/// Host and Controller at runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveTenantPolicy {
    pub tenant_id: [u8; 16],
    pub version: u64,
    #[serde(default)]
    pub exp_unix: u64,
    pub policy_hash: [u8; 32],
    pub body: TenantPolicyBody,
    pub degraded: bool,
    pub degraded_reason: Option<String>,
}

impl EffectiveTenantPolicy {
    /// Fail-Closed Privilege Degrade baseline anchored to `tenant_id` & `policy_hash`.
    pub fn degraded(tenant_id: [u8; 16], policy_hash: [u8; 32], reason: impl Into<String>) -> Self {
        Self {
            tenant_id,
            version: 0,
            exp_unix: 0,
            policy_hash,
            body: TenantPolicyBody::degraded_baseline(),
            degraded: true,
            degraded_reason: Some(reason.into()),
        }
    }

    pub fn allow_file_transfer(&self) -> bool {
        !self.degraded && self.body.allow_file_transfer()
    }

    pub fn allow_clipboard(&self) -> bool {
        !self.degraded && self.body.allow_clipboard()
    }

    pub fn allow_file_clipboard(&self) -> bool {
        !self.degraded && self.body.allow_file_clipboard()
    }

    pub fn allow_tcp_tunnel(&self) -> bool {
        !self.degraded && self.body.allow_tcp_tunnel()
    }

    pub fn allow_terminal(&self) -> bool {
        !self.degraded && self.body.allow_terminal()
    }

    pub fn allow_audio(&self) -> bool {
        !self.degraded && self.body.allow_audio()
    }

    pub fn max_bw_kbps(&self) -> u32 {
        if self.degraded {
            DEGRADED_BASELINE_BW_KBPS
        } else {
            self.body.max_bw_kbps
        }
    }

    pub fn max_file_bytes(&self) -> u64 {
        if self.degraded {
            0
        } else {
            self.body.max_file_bytes()
        }
    }

    pub fn max_clipboard_bytes(&self) -> u64 {
        if self.degraded {
            0
        } else {
            self.body.max_clipboard_bytes()
        }
    }

    /// Converts to `v2_transport::VerifiedTenantPolicy` for L3/L4 transport session enforcement.
    pub fn to_transport_policy(&self, effective_bw_cap_kbps: u32) -> VerifiedTenantPolicy {
        let bw = if self.degraded {
            effective_bw_cap_kbps.clamp(256, DEGRADED_BASELINE_BW_KBPS)
        } else if self.body.max_bw_kbps > 0 {
            effective_bw_cap_kbps.min(self.body.max_bw_kbps).max(256)
        } else {
            effective_bw_cap_kbps.max(256)
        };
        VerifiedTenantPolicy {
            tenant_id: self.tenant_id,
            policy_version: self.version.max(1),
            policy_hash: self.policy_hash,
            allow_file_transfer: self.allow_file_transfer(),
            allow_clipboard: self.allow_clipboard(),
            allow_file_clipboard: self.allow_file_clipboard(),
            allow_tcp_tunnel: self.allow_tcp_tunnel(),
            allow_terminal: self.allow_terminal(),
            allow_realtime_actuator: false,
            bw_cap_kbps: bw,
            exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
        }
    }
}

/// Outcome of verifying a `TenantPolicyBlob` against CA pubkey, local `DeviceCert`, clock,
/// and persisted anti-rollback `last_policy_version`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerifyOutcome {
    Verified(EffectiveTenantPolicy),
    Degraded {
        policy: EffectiveTenantPolicy,
        error: PolicyError,
        /// `true` ONLY when the CA signature, format, time window, tenant_id, version, and
        /// `SHA-256(body) == blob.policy_hash` are all valid, and ONLY `blob.policy_hash !=
        /// cert.policy_hash` failed (allows ONE bounded re-register refresh per `spec/06` §3.8.3).
        should_reregister: bool,
    },
}

impl PolicyVerifyOutcome {
    pub fn policy(&self) -> &EffectiveTenantPolicy {
        match self {
            Self::Verified(p) => p,
            Self::Degraded { policy, .. } => policy,
        }
    }

    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }

    pub fn should_reregister(&self) -> bool {
        matches!(
            self,
            Self::Degraded {
                should_reregister: true,
                ..
            }
        )
    }
}

/// Raw binary inputs for verifying a CA-signed `TenantPolicyBlob`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawTenantPolicyBlob<'a> {
    pub tenant_id: [u8; 16],
    pub version: u64,
    pub iat_unix: u64,
    pub exp_unix: u64,
    pub body: &'a [u8],
    pub policy_hash: [u8; 32],
    pub sig_der: &'a [u8],
}

/// Full normative `spec/06` §3.8.2 + §3.8.3 verifier for raw binary `TenantPolicyBlob` inputs.
pub fn verify_raw_tenant_policy_blob(
    blob: &RawTenantPolicyBlob<'_>,
    ca_spki_der: &[u8],
    cert_tenant_id: &[u8; 16],
    cert_policy_hash: &[u8; 32],
    last_policy_version: u64,
    now_unix: u64,
) -> PolicyVerifyOutcome {
    let degrade = |error: PolicyError, should_reregister: bool| PolicyVerifyOutcome::Degraded {
        policy: EffectiveTenantPolicy::degraded(*cert_tenant_id, *cert_policy_hash, error.to_string()),
        error,
        should_reregister,
    };

    // 1. Canonical 17B body (schema_ver == 1, reserved flag bits 6..31 == 0).
    let body = match TenantPolicyBody::decode(blob.body) {
        Ok(b) => b,
        Err(e) => return degrade(e, false),
    };

    // 2. Version >= 1.
    if blob.version < 1 {
        return degrade(PolicyError::InvalidVersion(blob.version), false);
    }

    // 3. Valid window: exp_unix > iat_unix.
    if blob.exp_unix <= blob.iat_unix {
        return degrade(
            PolicyError::InvalidTimeWindow {
                iat_unix: blob.iat_unix,
                exp_unix: blob.exp_unix,
            },
            false,
        );
    }

    // 4. Current clock within [iat_unix - 300, exp_unix].
    let earliest = blob.iat_unix.saturating_sub(POLICY_CLOCK_SKEW_SECS);
    if now_unix < earliest || now_unix > blob.exp_unix {
        return degrade(
            PolicyError::ExpiredOrNotYetValid {
                now_unix,
                iat_unix: blob.iat_unix,
                exp_unix: blob.exp_unix,
            },
            false,
        );
    }

    // 5. Tenant binding.
    if &blob.tenant_id != cert_tenant_id {
        return degrade(PolicyError::TenantMismatch, false);
    }

    // 6. Monotonic anti-rollback version check.
    if blob.version < last_policy_version {
        return degrade(
            PolicyError::VersionRollback {
                version: blob.version,
                last_version: last_policy_version,
            },
            false,
        );
    }

    // 7. Body digest binding: SHA-256(body) == blob.policy_hash.
    let computed_hash: [u8; 32] = Sha256::digest(blob.body).into();
    if computed_hash != blob.policy_hash {
        return degrade(PolicyError::BodyHashMismatch, false);
    }

    // 8. Strict DER (zero trailing bytes) + low-S ECDSA-P256 CA verification over 91B TBS.
    if let Err(e) = validate_strict_der_ecdsa_sig_len(blob.sig_der) {
        return degrade(e, false);
    }
    let tbs = build_tenant_policy_tbs(
        &blob.tenant_id,
        blob.version,
        &blob.policy_hash,
        blob.iat_unix,
        blob.exp_unix,
    );
    if let Err(e) = verify_p256_low_s(ca_spki_der, &tbs, blob.sig_der) {
        return degrade(PolicyError::InvalidSignature(e.to_string()), false);
    }

    // 9. Certificate policy_hash binding: valid CA signature + cert hash mismatch triggers ONE
    //    bounded re-register refresh (`spec/06` §3.8.3).
    if &blob.policy_hash != cert_policy_hash {
        return degrade(PolicyError::CertPolicyHashMismatch, true);
    }

    PolicyVerifyOutcome::Verified(EffectiveTenantPolicy {
        tenant_id: blob.tenant_id,
        version: blob.version,
        exp_unix: blob.exp_unix,
        policy_hash: blob.policy_hash,
        body,
        degraded: false,
        degraded_reason: None,
    })
}

/// Verifies an optional JSON `PolicyBlobJson` received from `POST /v2/devices/register` or
/// `GET /v2/tenants/policy`, returning Fail-Closed Privilege Degrade on missing or invalid blobs.
pub fn verify_tenant_policy_blob(
    blob_opt: Option<&PolicyBlobJson>,
    ca_spki_der: &[u8],
    cert_tenant_id: &[u8; 16],
    cert_policy_hash: &[u8; 32],
    last_policy_version: u64,
    now_unix: u64,
) -> PolicyVerifyOutcome {
    let Some(blob) = blob_opt else {
        let err = PolicyError::MalformedBlob("policy_blob missing from control plane".into());
        return PolicyVerifyOutcome::Degraded {
            policy: EffectiveTenantPolicy::degraded(
                *cert_tenant_id,
                *cert_policy_hash,
                err.to_string(),
            ),
            error: err,
            should_reregister: false,
        };
    };

    let tenant_id = match blob.tenant_id() {
        Ok(v) => v,
        Err(e) => {
            let err = PolicyError::MalformedBlob(e.to_string());
            return PolicyVerifyOutcome::Degraded {
                policy: EffectiveTenantPolicy::degraded(
                    *cert_tenant_id,
                    *cert_policy_hash,
                    err.to_string(),
                ),
                error: err,
                should_reregister: false,
            };
        }
    };
    let policy_hash = match blob.policy_hash() {
        Ok(v) => v,
        Err(e) => {
            let err = PolicyError::MalformedBlob(e.to_string());
            return PolicyVerifyOutcome::Degraded {
                policy: EffectiveTenantPolicy::degraded(
                    *cert_tenant_id,
                    *cert_policy_hash,
                    err.to_string(),
                ),
                error: err,
                should_reregister: false,
            };
        }
    };
    let body = match blob.body_bytes() {
        Ok(v) => v,
        Err(e) => {
            let err = PolicyError::MalformedBlob(e.to_string());
            return PolicyVerifyOutcome::Degraded {
                policy: EffectiveTenantPolicy::degraded(
                    *cert_tenant_id,
                    *cert_policy_hash,
                    err.to_string(),
                ),
                error: err,
                should_reregister: false,
            };
        }
    };
    let sig_der = match blob.sig_der() {
        Ok(v) => v,
        Err(e) => {
            let err = PolicyError::MalformedBlob(e.to_string());
            return PolicyVerifyOutcome::Degraded {
                policy: EffectiveTenantPolicy::degraded(
                    *cert_tenant_id,
                    *cert_policy_hash,
                    err.to_string(),
                ),
                error: err,
                should_reregister: false,
            };
        }
    };

    let raw = RawTenantPolicyBlob {
        tenant_id,
        version: blob.version,
        iat_unix: blob.iat_unix,
        exp_unix: blob.exp_unix,
        body: &body,
        policy_hash,
        sig_der: &sig_der,
    };
    verify_raw_tenant_policy_blob(
        &raw,
        ca_spki_der,
        cert_tenant_id,
        cert_policy_hash,
        last_policy_version,
        now_unix,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde_json::Value;

    const V27_PATH: &str = "/Volumes/data/github/zerodesk/protocol-spec/vectors/v27_policy_clipboard_file.json";

    #[test]
    fn tenant_policy_conformance_matches_v27_positive_and_all_negative_cases() {
        let raw_json = std::fs::read_to_string(V27_PATH).unwrap();
        let v: Value = serde_json::from_str(&raw_json).unwrap();
        let tp = &v["tenant_policy"];

        let ca_spki = hex::decode(tp["ca_pub_spki_der_hex"].as_str().unwrap()).unwrap();
        let tenant_id: [u8; 16] = hex::decode(tp["tenant_id_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let version = tp["version"].as_u64().unwrap();
        let iat_unix = tp["iat_unix"].as_u64().unwrap();
        let exp_unix = tp["exp_unix"].as_u64().unwrap();
        let now_unix = tp["now_unix"].as_u64().unwrap();
        let body_bytes = hex::decode(tp["body_hex"].as_str().unwrap()).unwrap();
        let policy_hash: [u8; 32] = hex::decode(tp["policy_hash_hex"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sig_der = hex::decode(tp["sig_der_hex"].as_str().unwrap()).unwrap();

        // Canonical 17B codec & 91B TBS exact byte match
        let body = TenantPolicyBody::decode(&body_bytes).unwrap();
        assert_eq!(body.schema_ver, 1);
        assert_eq!(body.flags, 63);
        assert_eq!(body.max_bw_kbps, 20000);
        assert_eq!(body.max_file_mb, 256);
        assert_eq!(body.max_clipboard_kb, 256);
        assert_eq!(body.encode().unwrap().as_slice(), body_bytes.as_slice());
        assert_eq!(body.sha256().unwrap(), policy_hash);

        let tbs = build_tenant_policy_tbs(&tenant_id, version, &policy_hash, iat_unix, exp_unix);
        assert_eq!(tbs.len(), tp["tbs_len"].as_u64().unwrap() as usize);
        assert_eq!(hex::encode(tbs), tp["tbs_hex"].as_str().unwrap());

        // Positive verification
        let blob_json = PolicyBlobJson {
            tenant_id_hex: tp["tenant_id_hex"].as_str().unwrap().into(),
            version,
            iat_unix,
            exp_unix,
            body_b64: B64.encode(&body_bytes),
            policy_hash_hex: tp["policy_hash_hex"].as_str().unwrap().into(),
            sig_der_b64: B64.encode(&sig_der),
        };
        let ok = verify_tenant_policy_blob(
            Some(&blob_json),
            &ca_spki,
            &tenant_id,
            &policy_hash,
            version,
            now_unix,
        );
        match ok {
            PolicyVerifyOutcome::Verified(pol) => {
                assert!(!pol.degraded);
                assert!(pol.allow_file_transfer());
                assert!(pol.allow_clipboard());
                assert!(pol.allow_file_clipboard());
                assert!(pol.allow_tcp_tunnel());
                assert!(pol.allow_terminal());
                assert!(pol.allow_audio());
                assert_eq!(pol.max_bw_kbps(), 20_000);
                assert_eq!(pol.max_file_bytes(), 256 * 1024 * 1024);
                assert_eq!(pol.max_clipboard_bytes(), 256 * 1024);
            }
            other => panic!("expected Verified, got {other:?}"),
        }

        // All 11 V27 negative cases
        let neg_cases = tp["negative_cases"].as_array().unwrap();
        assert_eq!(neg_cases.len(), 11);
        for case in neg_cases {
            let name = case["case"].as_str().unwrap();
            let neg_tid: [u8; 16] = hex::decode(case["tenant_id_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let neg_body = hex::decode(case["body_hex"].as_str().unwrap()).unwrap();
            let neg_hash: [u8; 32] = hex::decode(case["policy_hash_hex"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let neg_sig = hex::decode(case["sig_der_hex"].as_str().unwrap()).unwrap();
            let neg_ver = case["version"].as_u64().unwrap();
            let neg_last = case["last_policy_version"].as_u64().unwrap();
            let neg_iat = case["iat_unix"].as_u64().unwrap();
            let neg_exp = case["exp_unix"].as_u64().unwrap();
            let expect_rereg = case["expected_should_reregister"].as_bool().unwrap();

            let raw = RawTenantPolicyBlob {
                tenant_id: neg_tid,
                version: neg_ver,
                iat_unix: neg_iat,
                exp_unix: neg_exp,
                body: &neg_body,
                policy_hash: neg_hash,
                sig_der: &neg_sig,
            };
            let out = verify_raw_tenant_policy_blob(
                &raw,
                &ca_spki,
                &tenant_id,
                &policy_hash,
                neg_last,
                now_unix,
            );
            match out {
                PolicyVerifyOutcome::Degraded {
                    policy,
                    should_reregister,
                    ..
                } => {
                    assert_eq!(
                        should_reregister, expect_rereg,
                        "case '{name}' should_reregister mismatch"
                    );
                    assert!(policy.degraded, "case '{name}' must degrade");
                    assert!(!policy.allow_file_transfer(), "case '{name}'");
                    assert!(!policy.allow_clipboard(), "case '{name}'");
                    assert!(!policy.allow_file_clipboard(), "case '{name}'");
                    assert!(!policy.allow_tcp_tunnel(), "case '{name}'");
                    assert!(!policy.allow_terminal(), "case '{name}'");
                    assert!(!policy.allow_audio(), "case '{name}'");
                    assert_eq!(policy.max_file_bytes(), 0, "case '{name}'");
                    assert_eq!(policy.max_clipboard_bytes(), 0, "case '{name}'");
                    assert_eq!(
                        policy.max_bw_kbps(),
                        DEGRADED_BASELINE_BW_KBPS,
                        "case '{name}' degraded baseline bw must be 2000 kbps"
                    );
                }
                PolicyVerifyOutcome::Verified(_) => {
                    panic!("negative case '{name}' unexpectedly verified");
                }
            }
        }

        // Expired & missing blob degrade to 2000 kbps with all privileges false
        let expired = verify_tenant_policy_blob(
            Some(&blob_json),
            &ca_spki,
            &tenant_id,
            &policy_hash,
            version,
            exp_unix + 1,
        );
        assert!(!expired.is_verified());
        assert!(!expired.should_reregister());
        assert_eq!(expired.policy().max_bw_kbps(), 2000);

        let missing = verify_tenant_policy_blob(
            None,
            &ca_spki,
            &tenant_id,
            &policy_hash,
            version,
            now_unix,
        );
        assert!(!missing.is_verified());
        assert_eq!(missing.policy().max_bw_kbps(), 2000);
        assert!(!missing.policy().allow_audio());

        // Zero limits mean disabled (NEVER unlimited), checked u64 arithmetic handles u32::MAX
        let zero_limits = TenantPolicyBody {
            schema_ver: 1,
            flags: POLICY_FLAGS_VALID_MASK,
            max_bw_kbps: 0,
            max_file_mb: 0,
            max_clipboard_kb: 0,
        };
        assert!(!zero_limits.allow_file_transfer());
        assert!(!zero_limits.allow_clipboard());
        assert_eq!(zero_limits.max_file_bytes(), 0);
        assert_eq!(zero_limits.max_clipboard_bytes(), 0);

        let max_limits = TenantPolicyBody {
            schema_ver: 1,
            flags: POLICY_FLAGS_VALID_MASK,
            max_bw_kbps: u32::MAX,
            max_file_mb: u32::MAX,
            max_clipboard_kb: u32::MAX,
        };
        assert_eq!(
            max_limits.max_file_bytes(),
            u64::from(u32::MAX) * 1024 * 1024
        );
        assert_eq!(max_limits.max_clipboard_bytes(), MAX_CLIPBOARD_HARD_CAP_BYTES);
    }
}
