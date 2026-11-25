use crate::{error::IdentityError, keystore::verify_p256_low_s};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEVCERT_DOMAIN: &[u8; 13] = b"V2-DEVCERT-v1";
pub const EDGECERT_DOMAIN: &[u8; 14] = b"V2-EDGECERT-v1";
pub const DELEG_DOMAIN: &[u8; 18] = b"V2-X25519-DELEGATE";
pub const TENANT_POLICY_DOMAIN: &[u8; 19] = b"V2-TENANT-POLICY-v1";
pub const REVOCATION_DOMAIN: &[u8; 16] = b"V2-REVOCATION-v1";
pub const PREEMPT_DOMAIN: &[u8; 13] = b"V2-PREEMPT-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCert {
    pub version: u32,
    pub cert_id: [u8; 16],
    pub device_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub p256_pub_der: Vec<u8>,
    pub key_epoch: u64,
    pub policy_hash: [u8; 32],
    pub cap_bits: u64,
    pub iat_unix: u64,
    pub exp_unix: u64,
    pub hardware_backed: bool,
    pub sig_der: Vec<u8>,
}

impl DeviceCert {
    pub fn tbs_bytes(&self) -> Result<Vec<u8>, IdentityError> {
        let pub_len = u16::try_from(self.p256_pub_der.len())
            .map_err(|_| IdentityError::InvalidFraming("p256_pub_der exceeds u16::MAX".into()))?;
        let mut out = Vec::with_capacity(13 + 4 + 16 * 3 + 2 + self.p256_pub_der.len() + 8 + 32 + 24);
        out.extend_from_slice(DEVCERT_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.cert_id);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.tenant_id);
        out.extend_from_slice(&pub_len.to_be_bytes());
        out.extend_from_slice(&self.p256_pub_der);
        out.extend_from_slice(&self.key_epoch.to_be_bytes());
        out.extend_from_slice(&self.policy_hash);
        out.extend_from_slice(&self.cap_bits.to_be_bytes());
        out.extend_from_slice(&self.iat_unix.to_be_bytes());
        out.extend_from_slice(&self.exp_unix.to_be_bytes());
        Ok(out)
    }

    pub fn tbs_sha256(&self) -> Result<[u8; 32], IdentityError> {
        let tbs = self.tbs_bytes()?;
        Ok(Sha256::digest(&tbs).into())
    }

    pub fn verify(&self, ca_spki_der: &[u8], now_unix: u64) -> Result<(), IdentityError> {
        if now_unix > self.exp_unix {
            return Err(IdentityError::CertExpired);
        }
        let tbs = self.tbs_bytes()?;
        verify_p256_low_s(ca_spki_der, &tbs, &self.sig_der)
    }

    pub fn check_revocation(
        &self,
        notice: &RevocationNotice,
        ca_spki_der: &[u8],
    ) -> Result<(), IdentityError> {
        notice.verify(ca_spki_der)?;
        if notice.device_id == self.device_id && self.key_epoch < notice.min_key_epoch {
            return Err(IdentityError::CertRevoked);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeCert {
    pub version: u32,
    pub pop_id: [u8; 8],
    pub x25519_pub: [u8; 32],
    pub iat_unix: u64,
    pub exp_unix: u64,
    pub sig_der: Vec<u8>,
}

impl EdgeCert {
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(14 + 4 + 8 + 32 + 16);
        out.extend_from_slice(EDGECERT_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.pop_id);
        out.extend_from_slice(&self.x25519_pub);
        out.extend_from_slice(&self.iat_unix.to_be_bytes());
        out.extend_from_slice(&self.exp_unix.to_be_bytes());
        out
    }

    pub fn tbs_sha256(&self) -> [u8; 32] {
        Sha256::digest(self.tbs_bytes()).into()
    }

    pub fn verify(&self, ca_spki_der: &[u8], now_unix: u64) -> Result<(), IdentityError> {
        if now_unix > self.exp_unix {
            return Err(IdentityError::CertExpired);
        }
        let tbs = self.tbs_bytes();
        verify_p256_low_s(ca_spki_der, &tbs, &self.sig_der)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationStatement {
    pub device_id: [u8; 16],
    pub x25519_pub: [u8; 32],
    pub prefer_chacha: bool,
    pub delegation_seq: u64,
    pub exp_unix: u64,
    pub sig_der: Vec<u8>,
}

impl DelegationStatement {
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(18 + 16 + 32 + 1 + 8 + 8);
        out.extend_from_slice(DELEG_DOMAIN);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.x25519_pub);
        out.push(u8::from(self.prefer_chacha));
        out.extend_from_slice(&self.delegation_seq.to_be_bytes());
        out.extend_from_slice(&self.exp_unix.to_be_bytes());
        out
    }

    pub fn verify(
        &self,
        device_spki_der: &[u8],
        device_cert_exp_unix: u64,
        now_unix: u64,
    ) -> Result<(), IdentityError> {
        if self.exp_unix > device_cert_exp_unix || now_unix > self.exp_unix {
            return Err(IdentityError::CertExpired);
        }
        let tbs = self.tbs_bytes();
        verify_p256_low_s(device_spki_der, &tbs, &self.sig_der)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantPolicyBlob {
    pub tenant_id: [u8; 16],
    pub version: u64,
    pub policy_hash: [u8; 32],
    pub iat_unix: u64,
    pub exp_unix: u64,
    pub sig_der: Vec<u8>,
}

impl TenantPolicyBlob {
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(19 + 16 + 8 + 32 + 16);
        out.extend_from_slice(TENANT_POLICY_DOMAIN);
        out.extend_from_slice(&self.tenant_id);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.extend_from_slice(&self.policy_hash);
        out.extend_from_slice(&self.iat_unix.to_be_bytes());
        out.extend_from_slice(&self.exp_unix.to_be_bytes());
        out
    }

    pub fn verify(
        &self,
        ca_spki_der: &[u8],
        expected_tenant_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<(), IdentityError> {
        if &self.tenant_id != expected_tenant_id {
            return Err(IdentityError::BindingMismatch);
        }
        if now_unix > self.exp_unix {
            return Err(IdentityError::CertExpired);
        }
        let tbs = self.tbs_bytes();
        verify_p256_low_s(ca_spki_der, &tbs, &self.sig_der)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationNotice {
    pub device_id: [u8; 16],
    pub min_key_epoch: u64,
    pub iat_unix: u64,
    pub sig_der: Vec<u8>,
}

impl RevocationNotice {
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16 + 16 + 8 + 8);
        out.extend_from_slice(REVOCATION_DOMAIN);
        out.extend_from_slice(&self.device_id);
        out.extend_from_slice(&self.min_key_epoch.to_be_bytes());
        out.extend_from_slice(&self.iat_unix.to_be_bytes());
        out
    }

    pub fn verify(&self, ca_spki_der: &[u8]) -> Result<(), IdentityError> {
        let tbs = self.tbs_bytes();
        verify_p256_low_s(ca_spki_der, &tbs, &self.sig_der)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlPreemptToken {
    pub tenant_id: [u8; 16],
    pub drone_device_id: [u8; 16],
    pub operator_id: [u8; 16],
    pub new_control_epoch: u32,
    pub iat_unix: u64,
    pub exp_unix: u64,
    pub sig_der: Vec<u8>,
}

impl ControlPreemptToken {
    pub fn tbs_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(13 + 16 * 3 + 4 + 16);
        out.extend_from_slice(PREEMPT_DOMAIN);
        out.extend_from_slice(&self.tenant_id);
        out.extend_from_slice(&self.drone_device_id);
        out.extend_from_slice(&self.operator_id);
        out.extend_from_slice(&self.new_control_epoch.to_be_bytes());
        out.extend_from_slice(&self.iat_unix.to_be_bytes());
        out.extend_from_slice(&self.exp_unix.to_be_bytes());
        out
    }

    pub fn verify(
        &self,
        ca_spki_der: &[u8],
        expected_tenant_id: &[u8; 16],
        expected_drone_device_id: &[u8; 16],
        now_unix: u64,
    ) -> Result<(), IdentityError> {
        if &self.tenant_id != expected_tenant_id
            || &self.drone_device_id != expected_drone_device_id
        {
            return Err(IdentityError::BindingMismatch);
        }
        if now_unix > self.exp_unix {
            return Err(IdentityError::CertExpired);
        }
        let tbs = self.tbs_bytes();
        verify_p256_low_s(ca_spki_der, &tbs, &self.sig_der)
    }
}
