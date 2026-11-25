pub mod certs;
pub mod error;
pub mod keystore;
pub mod rotation;

pub use certs::{
    ControlPreemptToken, DelegationStatement, DeviceCert, EdgeCert, RevocationNotice,
    TenantPolicyBlob, DELEG_DOMAIN, DEVCERT_DOMAIN, EDGECERT_DOMAIN, MAX_DEVICE_CERT_TTL_SECS,
    MAX_EDGE_CERT_TTL_SECS, MAX_PREEMPT_TOKEN_TTL_SECS, MAX_TENANT_POLICY_TTL_SECS, PREEMPT_DOMAIN,
    REVOCATION_DOMAIN, TENANT_POLICY_DOMAIN,
};
pub use error::{
    IdentityError, ERR_CERT_EXPIRED, ERR_CERT_REVOKED, ERR_DELEGATION_ROLLBACK,
    ERR_INVALID_FRAMING, ERR_TRANSCRIPT_MISMATCH,
};
pub use keystore::{
    verify_p256_low_s, DeviceKeyStore, KeyProtectionLevel, SoftwareDeviceKeyStore,
};
pub use rotation::{
    CachedDelegation, DelegationCache, RetainedKeyMetadata, RotatorPersistedState,
    StaticKeyHintRetry, X25519KeyGeneration, X25519StaticKeyRotator, STATIC_KEY_HINT_MAX_RETRIES,
    STATIC_KEY_HINT_MAX_SESSIONS, X25519_MIN_RETENTION_SECS, X25519_RETAINED_GENERATIONS,
    X25519_SLICE_SECS,
};
