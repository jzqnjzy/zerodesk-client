// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use crate::{
    constants::{
        CHAN_CLIPBOARD, CHAN_FILE_TRANSFER, CHAN_REALTIME_ACTUATOR, QUOTA_THROTTLE_KBPS,
    },
    error::TransportError,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use v2_identity::{DeviceCert, TenantPolicyBlob};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum QuotaExhaustPolicy {
    /// ZeroDesk default: smoothly throttle to 256 kbps without disconnecting.
    Throttle256Kbps = 0,
    /// UAV / industrial safety mode: lock mission bandwidth, never throttle mid-flight; emit RTH alert.
    MissionLockedAlert = 1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantPolicyRules {
    pub allow_file_transfer: bool,
    pub allow_clipboard: bool,
    pub allow_file_clipboard: bool,
    pub allow_tcp_tunnel: bool,
    pub allow_terminal: bool,
    pub allow_realtime_actuator: bool,
    pub bw_cap_kbps: u32,
    pub exhaust_policy: QuotaExhaustPolicy,
}

impl TenantPolicyRules {
    pub fn free_tier_default() -> Self {
        Self {
            allow_file_transfer: false,
            allow_clipboard: true,
            allow_file_clipboard: false,
            allow_tcp_tunnel: false,
            allow_terminal: false,
            allow_realtime_actuator: false,
            bw_cap_kbps: 4_000,
            exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
        }
    }

    pub fn canonical_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(b"V2-POLICY-RULES-v1");
        h.update([
            u8::from(self.allow_file_transfer),
            u8::from(self.allow_clipboard),
            u8::from(self.allow_file_clipboard && self.allow_file_transfer),
            u8::from(self.allow_tcp_tunnel),
            u8::from(self.allow_terminal),
            u8::from(self.allow_realtime_actuator),
            self.exhaust_policy as u8,
        ]);
        h.update(self.bw_cap_kbps.to_be_bytes());
        h.finalize().into()
    }
}

/// Cryptographically verified tenant policy hard ceiling.
///
/// Local UI switches or CM `SwitchPermission` commands can ONLY narrow permissions
/// below this ceiling; they can NEVER enable a feature denied by the tenant policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedTenantPolicy {
    pub tenant_id: [u8; 16],
    pub policy_version: u64,
    pub policy_hash: [u8; 32],
    pub allow_file_transfer: bool,
    pub allow_clipboard: bool,
    pub allow_file_clipboard: bool,
    pub allow_tcp_tunnel: bool,
    pub allow_terminal: bool,
    pub allow_realtime_actuator: bool,
    pub bw_cap_kbps: u32,
    pub exhaust_policy: QuotaExhaustPolicy,
}

impl VerifiedTenantPolicy {
    pub fn from_verified_blob(
        blob: &TenantPolicyBlob,
        device_cert: &DeviceCert,
        rules: &TenantPolicyRules,
        ca_spki_der: &[u8],
        now_unix: u64,
    ) -> Result<Self, TransportError> {
        blob.verify(ca_spki_der, &device_cert.tenant_id, now_unix)?;
        if blob.policy_hash != device_cert.policy_hash {
            return Err(TransportError::PolicyDenied(
                "policy_hash mismatch between TenantPolicyBlob and DeviceCert".into(),
            ));
        }
        if rules.canonical_hash() != blob.policy_hash {
            return Err(TransportError::PolicyDenied(
                "policy rules digest does not match signed policy_hash".into(),
            ));
        }
        Ok(Self::from_rules_internal(
            device_cert.tenant_id,
            blob.version,
            blob.policy_hash,
            rules,
        ))
    }

    pub fn free_tier(tenant_id: [u8; 16]) -> Self {
        let rules = TenantPolicyRules::free_tier_default();
        let hash = rules.canonical_hash();
        Self::from_rules_internal(tenant_id, 1, hash, &rules)
    }

    fn from_rules_internal(
        tenant_id: [u8; 16],
        policy_version: u64,
        policy_hash: [u8; 32],
        rules: &TenantPolicyRules,
    ) -> Self {
        // Hard invariant: disabling file transfer MUST also block file-clipboard (Cliprdr) bypass.
        let allow_file_clipboard = rules.allow_file_transfer && rules.allow_file_clipboard;
        Self {
            tenant_id,
            policy_version,
            policy_hash,
            allow_file_transfer: rules.allow_file_transfer,
            allow_clipboard: rules.allow_clipboard,
            allow_file_clipboard,
            allow_tcp_tunnel: rules.allow_tcp_tunnel,
            allow_terminal: rules.allow_terminal,
            allow_realtime_actuator: rules.allow_realtime_actuator,
            bw_cap_kbps: rules.bw_cap_kbps,
            exhaust_policy: rules.exhaust_policy,
        }
    }

    #[cfg(test)]
    pub fn from_rules_unchecked(
        tenant_id: [u8; 16],
        policy_version: u64,
        policy_hash: [u8; 32],
        rules: &TenantPolicyRules,
    ) -> Self {
        Self::from_rules_internal(tenant_id, policy_version, policy_hash, rules)
    }

    pub fn enforce_channel(
        &self,
        chan_id: u8,
        is_file_clipboard: bool,
    ) -> Result<(), TransportError> {
        match chan_id {
            CHAN_FILE_TRANSFER if !self.allow_file_transfer => Err(TransportError::PolicyDenied(
                "0x05 FileTransfer blocked by tenant policy".into(),
            )),
            CHAN_CLIPBOARD if !self.allow_clipboard => Err(TransportError::PolicyDenied(
                "0x04 Clipboard blocked by tenant policy".into(),
            )),
            CHAN_CLIPBOARD if is_file_clipboard && !self.allow_file_clipboard => {
                Err(TransportError::PolicyDenied(
                    "file clipboard (Cliprdr) blocked when file transfer is disabled".into(),
                ))
            }
            CHAN_REALTIME_ACTUATOR if !self.allow_realtime_actuator => {
                Err(TransportError::PolicyDenied(
                    "0x07 RealtimeActuator blocked by tenant policy".into(),
                ))
            }
            _ => Ok(()),
        }
    }

    pub fn enforce_tcp_tunnel(&self) -> Result<(), TransportError> {
        if !self.allow_tcp_tunnel {
            return Err(TransportError::PolicyDenied(
                "TCP tunnel / port forwarding blocked by tenant policy".into(),
            ));
        }
        Ok(())
    }

    /// Computes effective bandwidth cap on quota exhaustion.
    /// Returns `(effective_cap_kbps, should_emit_rth_alert)`.
    pub fn on_quota_exhausted(&self) -> (u32, bool) {
        match self.exhaust_policy {
            QuotaExhaustPolicy::Throttle256Kbps => {
                (self.bw_cap_kbps.min(QUOTA_THROTTLE_KBPS), false)
            }
            QuotaExhaustPolicy::MissionLockedAlert => (self.bw_cap_kbps, true),
        }
    }
}
