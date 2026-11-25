use crate::error::IdentityError;
use p256::{
    ecdsa::{
        signature::{Signer, Verifier},
        DerSignature, Signature, SigningKey, VerifyingKey,
    },
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use rand_core::OsRng;
use std::path::Path;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtectionLevel {
    HardwareBacked,
    SoftwareFallback,
}

/// Long-term P-256 device identity key store abstraction.
///
/// Implementations backed by Apple Secure Enclave, Windows TPM 2.0 (CNG),
/// Android StrongBox, or Linux TPM2-TSS return `hardware_backed() == true`.
/// Software fallback stores MUST return `hardware_backed() == false` so
/// registration and diagnostics never misrepresent hardware E2EE assurance.
pub trait DeviceKeyStore: Send + Sync {
    fn hardware_backed(&self) -> bool;

    fn protection_level(&self) -> KeyProtectionLevel {
        if self.hardware_backed() {
            KeyProtectionLevel::HardwareBacked
        } else {
            KeyProtectionLevel::SoftwareFallback
        }
    }

    fn public_key_spki_der(&self) -> Result<Vec<u8>, IdentityError>;

    fn sign_p256_low_s(&self, tbs: &[u8]) -> Result<Vec<u8>, IdentityError>;
}

/// Local software fallback P-256 key store.
///
/// Explicitly reports `hardware_backed() == false`. Secret key material is held
/// in a `SigningKey` (zeroized on drop via `p256`/`elliptic-curve`).
pub struct SoftwareDeviceKeyStore {
    signing_key: SigningKey,
}

impl SoftwareDeviceKeyStore {
    pub fn generate() -> Self {
        let signing_key = SigningKey::random(&mut OsRng);
        Self { signing_key }
    }

    pub fn from_scalar_bytes(bytes: &[u8; 32]) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_slice(bytes)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self, IdentityError> {
        let signing_key = SigningKey::from_pkcs8_der(der)
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
        Ok(Self { signing_key })
    }

    pub fn to_pkcs8_der(&self) -> Result<Zeroizing<Vec<u8>>, IdentityError> {
        let doc = self
            .signing_key
            .to_pkcs8_der()
            .map_err(|e| IdentityError::Storage(e.to_string()))?;
        Ok(Zeroizing::new(doc.as_bytes().to_vec()))
    }

    pub fn save_pkcs8_der(&self, path: &Path) -> Result<(), IdentityError> {
        let der = self.to_pkcs8_der()?;
        std::fs::write(path, der.as_slice())
            .map_err(|e| IdentityError::Storage(e.to_string()))
    }

    pub fn load_pkcs8_der(path: &Path) -> Result<Self, IdentityError> {
        let bytes = Zeroizing::new(
            std::fs::read(path).map_err(|e| IdentityError::Storage(e.to_string()))?,
        );
        Self::from_pkcs8_der(&bytes)
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        *self.signing_key.verifying_key()
    }
}

impl DeviceKeyStore for SoftwareDeviceKeyStore {
    fn hardware_backed(&self) -> bool {
        false
    }

    fn public_key_spki_der(&self) -> Result<Vec<u8>, IdentityError> {
        let doc = self
            .signing_key
            .verifying_key()
            .to_public_key_der()
            .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
        Ok(doc.as_bytes().to_vec())
    }

    fn sign_p256_low_s(&self, tbs: &[u8]) -> Result<Vec<u8>, IdentityError> {
        let sig: Signature = self.signing_key.sign(tbs);
        let low_s = sig.normalize_s().unwrap_or(sig);
        Ok(low_s.to_der().as_bytes().to_vec())
    }
}

/// Verifies an ECDSA-P256 DER signature over deterministic TBS bytes and
/// enforces strict low-S canonical form to eliminate signature malleability.
pub fn verify_p256_low_s(
    spki_der: &[u8],
    tbs: &[u8],
    sig_der: &[u8],
) -> Result<(), IdentityError> {
    let vk = VerifyingKey::from_public_key_der(spki_der)
        .map_err(|e| IdentityError::InvalidKey(e.to_string()))?;
    let der_sig = DerSignature::from_bytes(sig_der).map_err(|_| IdentityError::InvalidSignature)?;
    let sig = Signature::from_der(der_sig.as_bytes()).map_err(|_| IdentityError::InvalidSignature)?;
    if sig.normalize_s().is_some() {
        return Err(IdentityError::InvalidSignature);
    }
    vk.verify(tbs, &sig)
        .map_err(|_| IdentityError::InvalidSignature)
}
