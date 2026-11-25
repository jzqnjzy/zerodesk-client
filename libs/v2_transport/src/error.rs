use crate::constants::ErrorCode;
use thiserror::Error;
use v2_identity::IdentityError;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransportError {
    #[error("unsupported protocol version")]
    UnsupportedVersion,
    #[error("invalid framing: {0}")]
    InvalidFraming(String),
    #[error("mac verification failed")]
    InvalidMac,
    #[error("access epoch out of window or grace expired")]
    AccessEpochRejected,
    #[error("aead authentication failed")]
    AeadFailed,
    #[error("replay or duplicate packet detected")]
    ReplayDetected,
    #[error("channel priority mismatch (chan={chan_id:#04x}, pp={pp})")]
    PriorityMismatch { chan_id: u8, pp: u8 },
    #[error("packet sequence exhausted; session rekey/recreate required")]
    SequenceExhausted,
    #[error("noise handshake error: {0}")]
    Noise(String),
    #[error("identity verification error: {0}")]
    Identity(#[from] IdentityError),
    #[error("tenant policy denied operation: {0}")]
    PolicyDenied(String),
    #[error("path failure after max retries")]
    PathFailed,
    #[error("0-rtt frame rejected before 1-rtt completion")]
    ZeroRttDisallowed,
    #[error("channel closed")]
    Closed,
}

impl TransportError {
    pub fn error_code(&self) -> ErrorCode {
        match self {
            Self::UnsupportedVersion => ErrorCode::UnsupportedVersion,
            Self::InvalidFraming(_)
            | Self::InvalidMac
            | Self::AccessEpochRejected
            | Self::PriorityMismatch { .. }
            | Self::ReplayDetected
            | Self::SequenceExhausted
            | Self::ZeroRttDisallowed
            | Self::Closed => ErrorCode::InvalidFraming,
            Self::AeadFailed | Self::Noise(_) => ErrorCode::TranscriptMismatch,
            Self::Identity(e) => match e.error_code() {
                0x0201 => ErrorCode::CertExpired,
                0x0202 => ErrorCode::CertRevoked,
                0x0203 => ErrorCode::DelegationRollback,
                0x0204 => ErrorCode::TranscriptMismatch,
                _ => ErrorCode::InvalidFraming,
            },
            Self::PolicyDenied(_) => ErrorCode::PolicyDenied,
            Self::PathFailed => ErrorCode::PathFailed,
        }
    }
}
