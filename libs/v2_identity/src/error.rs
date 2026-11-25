use thiserror::Error;

pub const ERR_INVALID_FRAMING: u16 = 0x0103;
pub const ERR_CERT_EXPIRED: u16 = 0x0201;
pub const ERR_CERT_REVOKED: u16 = 0x0202;
pub const ERR_DELEGATION_ROLLBACK: u16 = 0x0203;
pub const ERR_TRANSCRIPT_MISMATCH: u16 = 0x0204;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IdentityError {
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("invalid signature encoding or non-canonical high-S signature")]
    InvalidSignature,
    #[error("certificate or delegation expired or exceeds parent expiry")]
    CertExpired,
    #[error("certificate revoked (key_epoch below min_key_epoch)")]
    CertRevoked,
    #[error("delegation rollback or key substitution detected")]
    DelegationRollback,
    #[error("cross-tenant or cross-device binding mismatch")]
    BindingMismatch,
    #[error("static key hint retry limit exceeded")]
    RetryLimitExceeded,
    #[error("invalid framing or length: {0}")]
    InvalidFraming(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl IdentityError {
    pub fn error_code(&self) -> u16 {
        match self {
            Self::CertExpired => ERR_CERT_EXPIRED,
            Self::CertRevoked => ERR_CERT_REVOKED,
            Self::DelegationRollback => ERR_DELEGATION_ROLLBACK,
            Self::InvalidSignature | Self::BindingMismatch => ERR_TRANSCRIPT_MISMATCH,
            Self::InvalidFraming(_) | Self::InvalidKey(_) | Self::RetryLimitExceeded | Self::Storage(_) => {
                ERR_INVALID_FRAMING
            }
        }
    }
}
