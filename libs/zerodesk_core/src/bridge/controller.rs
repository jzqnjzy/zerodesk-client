// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Pure Rust JSON-ABI Bridge Controller (`V2BridgeController`) with zero Flutter SDK dependency.
//!
//! Provides a versioned (`"v": 1`) JSON command & snapshot envelope, an explicit fail-closed
//! state machine, a pollable bounded event queue (zero re-entrant callbacks while holding locks),
//! CA-verified caller display info, secret-redacted snapshots, and atomic `0600` config save/load.

use crate::session::{
    clipboard::{check_clipboard_policy_for_sync, CLIP_HARD_MAX_BYTES},
    config::{
        read_file_0600_to_string, write_file_atomic_0600, TransportMode, V2ConfigError,
        DEFAULT_BW_CAP_KBPS, DEFAULT_FPS, DEFAULT_KEEPALIVE_INTERVAL_MS,
        DEFAULT_LEASE_RENEW_INTERVAL_SEC, DEFAULT_UDP_PROBE_TIMEOUT_MS,
        DEFAULT_WATCHDOG_TIMEOUT_MS, MAX_LEASE_RENEW_INTERVAL_SEC, MAX_UDP_PROBE_TIMEOUT_MS,
        MIN_UDP_PROBE_TIMEOUT_MS,
    },
    file_transfer::{check_file_policy, validate_safe_filename},
    policy::EffectiveTenantPolicy,
    runtime::QoeSnapshot,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::sync::Notify;
use v2_client::{ActiveTransportMode, EdgeEndpointConfig, SignalingDeviceCert};

pub const BRIDGE_ABI_VERSION: u32 = 1;
pub const BRIDGE_EVENT_QUEUE_CAP: usize = 256;
pub const BRIDGE_MAX_CMD_JSON_BYTES: usize = 512 * 1024;
pub const BRIDGE_MAX_CLIP_B64_BYTES: usize = 360 * 1024;

/// Explicit lifecycle state machine for `V2BridgeController`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BridgeState {
    Idle,
    Bootstrapping,
    Ready,
    Listening,
    Dialing,
    Incoming,
    Streaming,
    Closing,
    Faulted,
}

/// Caller identity derived SOLELY from a CA-verified `DeviceCert` (never untrusted strings).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedCallerDisplay {
    pub device_id_hex: String,
    pub tenant_id_hex: String,
    pub cert_id_hex: String,
    pub key_epoch: u64,
    pub verified_by_ca: bool,
}

impl VerifiedCallerDisplay {
    pub fn from_verified_cert(cert: &SignalingDeviceCert) -> Self {
        Self {
            device_id_hex: hex::encode(cert.device_id),
            tenant_id_hex: hex::encode(cert.tenant_id),
            cert_id_hex: hex::encode(cert.cert_id),
            key_epoch: cert.key_epoch,
            verified_by_ca: true,
        }
    }
}

/// Persisted on-disk client config saved atomically at `0600`.
/// NEVER serialized directly into UI snapshots (use `RedactedConfigView` for snapshots).
#[derive(Clone, Serialize, Deserialize)]
pub struct BridgePersistedConfig {
    #[serde(default = "default_abi_v")]
    pub v: u32,
    pub control_plane_endpoint: String,
    pub signaling_addr: String,
    #[serde(default)]
    pub signaling_tls: Option<bool>,
    #[serde(default)]
    pub edge_a: Option<EdgeEndpointConfig>,
    #[serde(default)]
    pub edge_b: Option<EdgeEndpointConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enrollment_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_der_path: Option<String>,
    pub identity_dir: String,
    #[serde(default = "default_home_region")]
    pub home_region: String,
    #[serde(default = "default_codec_name")]
    pub codec: String,
    #[serde(default = "default_fps")]
    pub fps: u32,
    #[serde(default = "default_watchdog_ms")]
    pub watchdog_timeout_ms: u64,
    #[serde(default = "default_keepalive_ms")]
    pub keepalive_interval_ms: u64,
    #[serde(default = "default_lease_sec")]
    pub lease_renew_interval_sec: u64,
    #[serde(default = "default_bw_kbps")]
    pub bw_cap_kbps: u32,
    #[serde(default)]
    pub transport_mode: TransportMode,
    #[serde(default = "default_udp_probe_ms")]
    pub udp_probe_timeout_ms: u64,
}

fn default_abi_v() -> u32 {
    BRIDGE_ABI_VERSION
}
fn default_home_region() -> String {
    "local".into()
}
fn default_codec_name() -> String {
    "vp9".into()
}
fn default_fps() -> u32 {
    DEFAULT_FPS
}
fn default_watchdog_ms() -> u64 {
    DEFAULT_WATCHDOG_TIMEOUT_MS
}
fn default_keepalive_ms() -> u64 {
    DEFAULT_KEEPALIVE_INTERVAL_MS
}
fn default_lease_sec() -> u64 {
    DEFAULT_LEASE_RENEW_INTERVAL_SEC
}
fn default_bw_kbps() -> u32 {
    DEFAULT_BW_CAP_KBPS
}
fn default_udp_probe_ms() -> u64 {
    DEFAULT_UDP_PROBE_TIMEOUT_MS
}

impl std::fmt::Debug for BridgePersistedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BridgePersistedConfig")
            .field("v", &self.v)
            .field("control_plane_endpoint", &self.control_plane_endpoint)
            .field("signaling_addr", &self.signaling_addr)
            .field(
                "enrollment_token",
                &self.enrollment_token.as_ref().map(|_| "<redacted>"),
            )
            .field("identity_dir", &self.identity_dir)
            .field("transport_mode", &self.transport_mode)
            .finish()
    }
}

/// Redacted view of configuration safe for UI snapshots (ZERO secrets/tokens/keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactedConfigView {
    pub control_plane_endpoint: String,
    pub signaling_addr: String,
    pub identity_dir: String,
    pub home_region: String,
    pub codec: String,
    pub fps: u32,
    pub transport_mode: TransportMode,
    pub udp_probe_timeout_ms: u64,
    pub has_enrollment_token: bool,
}

impl From<&BridgePersistedConfig> for RedactedConfigView {
    fn from(c: &BridgePersistedConfig) -> Self {
        Self {
            control_plane_endpoint: c.control_plane_endpoint.clone(),
            signaling_addr: c.signaling_addr.clone(),
            identity_dir: c.identity_dir.clone(),
            home_region: c.home_region.clone(),
            codec: c.codec.clone(),
            fps: c.fps,
            transport_mode: c.transport_mode,
            udp_probe_timeout_ms: c.udp_probe_timeout_ms,
            has_enrollment_token: c
                .enrollment_token
                .as_deref()
                .is_some_and(|t| !t.is_empty()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicySummary {
    pub version: u64,
    pub degraded: bool,
    pub degraded_reason: Option<String>,
    pub allow_file_transfer: bool,
    pub allow_clipboard: bool,
    pub allow_file_clipboard: bool,
    pub allow_tcp_tunnel: bool,
    pub allow_terminal: bool,
    pub allow_audio: bool,
    pub max_bw_kbps: u32,
    pub max_file_bytes: u64,
    pub max_clipboard_bytes: u64,
}

impl From<&EffectiveTenantPolicy> for PolicySummary {
    fn from(p: &EffectiveTenantPolicy) -> Self {
        Self {
            version: p.version,
            degraded: p.degraded,
            degraded_reason: p.degraded_reason.clone(),
            allow_file_transfer: p.allow_file_transfer(),
            allow_clipboard: p.allow_clipboard(),
            allow_file_clipboard: p.allow_file_clipboard(),
            allow_tcp_tunnel: p.allow_tcp_tunnel(),
            allow_terminal: p.allow_terminal(),
            allow_audio: p.allow_audio(),
            max_bw_kbps: p.max_bw_kbps(),
            max_file_bytes: p.max_file_bytes(),
            max_clipboard_bytes: p.max_clipboard_bytes(),
        }
    }
}

/// Versioned redacted state snapshot (`"v": 1`) returned by `snapshot` command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeSnapshot {
    pub v: u32,
    pub state: BridgeState,
    pub transport_mode: TransportMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_transport_mode: Option<ActiveTransportMode>,
    pub audio_muted: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_device_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_tenant_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_session_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending_incoming_session_id_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verified_caller: Option<VerifiedCallerDisplay>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicySummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<RedactedConfigView>,
    pub active_file_transfers: Vec<u64>,
    pub qoe: QoeSnapshot,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fault_reason: Option<String>,
}

/// Versioned event emitted onto the bounded pollable queue (never delivered via re-entrant lock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BridgeEvent {
    pub v: u32,
    pub seq: u64,
    pub kind: String,
    pub payload: serde_json::Value,
}

/// Versioned command envelope (`"v": 1`, unknown fields ignored on deserialize).
#[derive(Debug, Deserialize)]
struct BridgeCommandEnvelope {
    pub v: u32,
    pub cmd: String,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub config: Option<BridgePersistedConfig>,
    #[serde(default)]
    pub target_device_id_hex: Option<String>,
    #[serde(default)]
    pub session_id_hex: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub muted: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub mime_kind: Option<u8>,
    #[serde(default)]
    pub payload_b64: Option<String>,
    #[serde(default)]
    pub rel_name: Option<String>,
    #[serde(default)]
    pub file_size: Option<u64>,
    #[serde(default)]
    pub transfer_id: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BridgeResponseEnvelope {
    pub v: u32,
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl BridgeResponseEnvelope {
    fn ok(data: serde_json::Value) -> Self {
        Self {
            v: BRIDGE_ABI_VERSION,
            ok: true,
            error_code: None,
            error: None,
            data: Some(data),
        }
    }

    fn err(code: &str, msg: impl Into<String>) -> Self {
        Self {
            v: BRIDGE_ABI_VERSION,
            ok: false,
            error_code: Some(code.to_string()),
            error: Some(msg.into()),
            data: None,
        }
    }

    fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            r#"{"v":1,"ok":false,"error_code":"serialize_error","error":"failed to encode bridge response"}"#
                .to_string()
        })
    }
}

impl BridgePersistedConfig {
    pub fn validate(&self) -> Result<(), V2ConfigError> {
        if self.v != BRIDGE_ABI_VERSION {
            return Err(V2ConfigError::InvalidValue(format!(
                "unsupported config ABI version {} (expected {BRIDGE_ABI_VERSION})",
                self.v
            )));
        }
        if self.control_plane_endpoint.trim().is_empty() {
            return Err(V2ConfigError::InvalidValue(
                "control_plane_endpoint must not be empty".into(),
            ));
        }
        if self.signaling_addr.trim().is_empty() {
            return Err(V2ConfigError::InvalidValue(
                "signaling_addr must not be empty".into(),
            ));
        }
        if self.identity_dir.trim().is_empty() {
            return Err(V2ConfigError::InvalidValue(
                "identity_dir must not be empty".into(),
            ));
        }
        if self.fps == 0 || self.fps > 120 {
            return Err(V2ConfigError::InvalidValue(format!(
                "fps {} outside 1..=120",
                self.fps
            )));
        }
        if self.watchdog_timeout_ms == 0 || self.keepalive_interval_ms == 0 {
            return Err(V2ConfigError::InvalidValue(
                "watchdog_timeout_ms and keepalive_interval_ms must be > 0".into(),
            ));
        }
        if self.keepalive_interval_ms >= self.watchdog_timeout_ms {
            return Err(V2ConfigError::InvalidValue(
                "keepalive_interval_ms must be < watchdog_timeout_ms".into(),
            ));
        }
        if self.lease_renew_interval_sec == 0
            || self.lease_renew_interval_sec > MAX_LEASE_RENEW_INTERVAL_SEC
        {
            return Err(V2ConfigError::InvalidValue(format!(
                "lease_renew_interval_sec {} outside 1..={MAX_LEASE_RENEW_INTERVAL_SEC}",
                self.lease_renew_interval_sec
            )));
        }
        if !(MIN_UDP_PROBE_TIMEOUT_MS..=MAX_UDP_PROBE_TIMEOUT_MS)
            .contains(&self.udp_probe_timeout_ms)
        {
            return Err(V2ConfigError::InvalidValue(format!(
                "udp_probe_timeout_ms {} outside {MIN_UDP_PROBE_TIMEOUT_MS}..={MAX_UDP_PROBE_TIMEOUT_MS}",
                self.udp_probe_timeout_ms
            )));
        }
        Ok(())
    }
}

/// Atomically saves a `BridgePersistedConfig` JSON file at strict `0600` (`O_NOFOLLOW | O_CREAT | O_EXCL`
/// temp -> `sync_all` -> `rename` -> parent-dir `fsync`).
pub fn save_config_json(path: &Path, cfg: &BridgePersistedConfig) -> Result<(), V2ConfigError> {
    cfg.validate()?;
    let bytes = serde_json::to_vec_pretty(cfg)
        .map_err(|e| V2ConfigError::InvalidValue(format!("serialize config JSON: {e}")))?;
    write_file_atomic_0600(path, &bytes)
}

/// Loads a `BridgePersistedConfig` JSON file verifying strict `0600` & `O_NOFOLLOW` on Unix.
pub fn load_config_json(path: &Path) -> Result<BridgePersistedConfig, V2ConfigError> {
    let raw = read_file_0600_to_string(path)?;
    let cfg: BridgePersistedConfig = serde_json::from_str(&raw)
        .map_err(|e| V2ConfigError::InvalidValue(format!("parse config JSON: {e}")))?;
    cfg.validate()?;
    Ok(cfg)
}

struct BridgeInner {
    state: BridgeState,
    config: Option<BridgePersistedConfig>,
    transport_mode: TransportMode,
    active_transport_mode: Option<ActiveTransportMode>,
    audio_muted: bool,
    local_device_id_hex: Option<String>,
    local_tenant_id_hex: Option<String>,
    active_session_id_hex: Option<String>,
    pending_incoming_session_id_hex: Option<String>,
    incoming_accepted: bool,
    verified_caller: Option<VerifiedCallerDisplay>,
    policy: Option<EffectiveTenantPolicy>,
    active_file_transfers: BTreeMap<u64, String>,
    next_transfer_id: u64,
    next_clip_id: u64,
    qoe: QoeSnapshot,
    fault_reason: Option<String>,
    event_seq: u64,
    events: VecDeque<BridgeEvent>,
}

impl BridgeInner {
    fn new() -> Self {
        Self {
            state: BridgeState::Idle,
            config: None,
            transport_mode: TransportMode::Auto,
            active_transport_mode: None,
            audio_muted: false,
            local_device_id_hex: None,
            local_tenant_id_hex: None,
            active_session_id_hex: None,
            pending_incoming_session_id_hex: None,
            incoming_accepted: false,
            verified_caller: None,
            policy: None,
            active_file_transfers: BTreeMap::new(),
            next_transfer_id: 1,
            next_clip_id: 1,
            qoe: QoeSnapshot::default(),
            fault_reason: None,
            event_seq: 0,
            events: VecDeque::with_capacity(64),
        }
    }

    fn allows_config_mutation(&self) -> bool {
        matches!(
            self.state,
            BridgeState::Idle | BridgeState::Ready | BridgeState::Listening | BridgeState::Faulted
        )
    }

    fn push_event(&mut self, kind: &str, payload: serde_json::Value) {
        self.event_seq = self.event_seq.saturating_add(1);
        while self.events.len() >= BRIDGE_EVENT_QUEUE_CAP {
            self.events.pop_front();
        }
        self.events.push_back(BridgeEvent {
            v: BRIDGE_ABI_VERSION,
            seq: self.event_seq,
            kind: kind.to_string(),
            payload,
        });
    }

    fn snapshot(&self) -> BridgeSnapshot {
        BridgeSnapshot {
            v: BRIDGE_ABI_VERSION,
            state: self.state,
            transport_mode: self.transport_mode,
            active_transport_mode: self.active_transport_mode,
            audio_muted: self.audio_muted,
            local_device_id_hex: self.local_device_id_hex.clone(),
            local_tenant_id_hex: self.local_tenant_id_hex.clone(),
            active_session_id_hex: self.active_session_id_hex.clone(),
            pending_incoming_session_id_hex: self.pending_incoming_session_id_hex.clone(),
            verified_caller: self.verified_caller.clone(),
            policy: self.policy.as_ref().map(PolicySummary::from),
            config: self.config.as_ref().map(RedactedConfigView::from),
            active_file_transfers: self.active_file_transfers.keys().copied().collect(),
            qoe: self.qoe.clone(),
            fault_reason: self.fault_reason.clone(),
        }
    }
}

/// Pure Rust JSON-ABI controller for ZeroDesk V2 sessions (zero Flutter SDK dependency).
#[derive(Clone)]
pub struct V2BridgeController {
    inner: Arc<Mutex<BridgeInner>>,
    event_notify: Arc<Notify>,
}

impl Default for V2BridgeController {
    fn default() -> Self {
        Self::new()
    }
}

impl V2BridgeController {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BridgeInner::new())),
            event_notify: Arc::new(Notify::new()),
        }
    }

    pub fn state(&self) -> BridgeState {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .state
    }

    pub fn allows_config_mutation(&self) -> bool {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .allows_config_mutation()
    }

    pub fn snapshot(&self) -> BridgeSnapshot {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshot()
    }

    /// Drains all queued bridge events without holding the lock across caller handling.
    pub fn drain_events(&self) -> Vec<BridgeEvent> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.events.drain(..).collect()
    }

    /// Pops the next queued event immediately (non-blocking).
    pub fn recv_event(&self) -> Option<BridgeEvent> {
        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        g.events.pop_front()
    }

    /// Awaits the next queued event up to `timeout` without holding any internal mutex across `.await`.
    /// Registers & enables the `Notify` waiter BEFORE checking the queue to eliminate lost wakeups.
    pub async fn recv_event_timeout(&self, timeout: Duration) -> Option<BridgeEvent> {
        let notified = self.event_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if let Some(ev) = self.recv_event() {
            return Some(ev);
        }
        let _ = tokio::time::timeout(timeout, notified).await;
        self.recv_event()
    }

    /// Runtime hook: called when device bootstrap/policy refresh completes with CA-verified cert &
    /// policy. Enforces explicit source-state guards: rejects ONLY `BridgeState::Idle`; during
    /// active/transition states (`Dialing | Incoming | Streaming | Closing`), updates cert & policy
    /// in-place WITHOUT changing `state`, `pending_incoming_session_id_hex`, `incoming_accepted`,
    /// or `active_session_id_hex`.
    pub fn on_bootstrap_complete(
        &self,
        local_cert: &SignalingDeviceCert,
        policy: EffectiveTenantPolicy,
        listening: bool,
    ) -> Result<(), String> {
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            match g.state {
                BridgeState::Idle => {
                    return Err("on_bootstrap_complete forbidden in state Idle".into());
                }
                BridgeState::Dialing
                | BridgeState::Incoming
                | BridgeState::Streaming
                | BridgeState::Closing => {
                    let st = g.state;
                    g.local_device_id_hex = Some(hex::encode(local_cert.device_id));
                    g.local_tenant_id_hex = Some(hex::encode(local_cert.tenant_id));
                    g.policy = Some(policy.clone());
                    g.push_event(
                        "policy_refreshed",
                        serde_json::json!({
                            "state": st,
                            "policy_degraded": policy.degraded,
                        }),
                    );
                }
                BridgeState::Bootstrapping
                | BridgeState::Ready
                | BridgeState::Listening
                | BridgeState::Faulted => {
                    g.local_device_id_hex = Some(hex::encode(local_cert.device_id));
                    g.local_tenant_id_hex = Some(hex::encode(local_cert.tenant_id));
                    g.policy = Some(policy.clone());
                    g.state = if listening {
                        BridgeState::Listening
                    } else {
                        BridgeState::Ready
                    };
                    g.fault_reason = None;
                    let st = g.state;
                    g.push_event(
                        "state_changed",
                        serde_json::json!({
                            "state": st,
                            "policy_degraded": policy.degraded,
                        }),
                    );
                }
            }
        }
        self.event_notify.notify_waiters();
        Ok(())
    }

    /// Runtime hook: updates the effective tenant policy in-place during an active or ready
    /// session without mutating `state` or requiring a `SignalingDeviceCert`.
    /// Fails closed if an existing unexpired verified policy would be downgraded or degraded.
    pub fn on_policy_updated(&self, policy: EffectiveTenantPolicy) -> Result<(), String> {
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.state == BridgeState::Idle {
                return Err("on_policy_updated forbidden in state Idle".into());
            }
            if let Some(cur) = &g.policy {
                let now = v2_client::now_unix_secs();
                if !cur.degraded && cur.exp_unix > now {
                    if policy.degraded {
                        return Err(
                            "refusing to overwrite unexpired verified policy with degraded policy"
                                .into(),
                        );
                    }
                    if policy.version < cur.version {
                        return Err(format!(
                            "refusing policy version downgrade ({} < {})",
                            policy.version, cur.version
                        ));
                    }
                }
            }
            let st = g.state;
            g.policy = Some(policy.clone());
            g.push_event(
                "policy_refreshed",
                serde_json::json!({
                    "state": st,
                    "policy_degraded": policy.degraded,
                }),
            );
        }
        self.event_notify.notify_waiters();
        Ok(())
    }

    /// Runtime hook: called when an incoming call has passed CA `DeviceCert` verification.
    /// Caller display info is derived SOLELY from the CA-verified `DeviceCert`.
    pub fn on_incoming_verified_call(
        &self,
        session_id: [u8; 16],
        caller_cert: &SignalingDeviceCert,
    ) -> Result<(), String> {
        let caller = VerifiedCallerDisplay::from_verified_cert(caller_cert);
        let sid_hex = hex::encode(session_id);
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if g.state != BridgeState::Listening {
                return Err(format!(
                    "cannot accept incoming call in state {:?}",
                    g.state
                ));
            }
            g.state = BridgeState::Incoming;
            g.pending_incoming_session_id_hex = Some(sid_hex.clone());
            g.incoming_accepted = false;
            g.verified_caller = Some(caller.clone());
            g.push_event(
                "incoming_call",
                serde_json::json!({
                    "session_id_hex": sid_hex,
                    "verified_caller": caller,
                }),
            );
        }
        self.event_notify.notify_waiters();
        Ok(())
    }

    /// Runtime hook: transitions `Dialing` or `Incoming` into `Streaming` once Noise IK completes.
    pub fn on_streaming_started(
        &self,
        session_id: [u8; 16],
        peer_cert: &SignalingDeviceCert,
        active_mode: ActiveTransportMode,
    ) -> Result<(), String> {
        let sid_hex = hex::encode(session_id);
        let peer_display = VerifiedCallerDisplay::from_verified_cert(peer_cert);
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if !matches!(g.state, BridgeState::Dialing | BridgeState::Incoming) {
                return Err(format!(
                    "cannot transition to Streaming from state {:?}",
                    g.state
                ));
            }
            g.state = BridgeState::Streaming;
            g.active_session_id_hex = Some(sid_hex.clone());
            g.pending_incoming_session_id_hex = None;
            g.incoming_accepted = false;
            g.verified_caller = Some(peer_display.clone());
            g.active_transport_mode = Some(active_mode);
            g.qoe.active_transport_mode = Some(active_mode);
            g.qoe.transport_mode = active_mode.as_u8();
            g.push_event(
                "streaming_started",
                serde_json::json!({
                    "session_id_hex": sid_hex,
                    "active_transport_mode": active_mode,
                    "verified_peer": peer_display,
                }),
            );
        }
        self.event_notify.notify_waiters();
        Ok(())
    }

    /// Runtime hook: transitions from an active/closing/faulted state back to `Listening`/`Ready`/
    /// `Idle` after ordered teardown, always clearing `fault_reason` and `active_file_transfers`.
    /// Rejects `Idle` and `Bootstrapping`.
    pub fn on_closed(&self, return_to_listening: bool) -> Result<(), String> {
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            if matches!(g.state, BridgeState::Idle | BridgeState::Bootstrapping) {
                return Err(format!("on_closed forbidden in state {:?}", g.state));
            }
            g.state = if return_to_listening {
                BridgeState::Listening
            } else if g.config.is_some() {
                BridgeState::Ready
            } else {
                BridgeState::Idle
            };
            g.active_session_id_hex = None;
            g.pending_incoming_session_id_hex = None;
            g.incoming_accepted = false;
            g.verified_caller = None;
            g.active_transport_mode = None;
            g.fault_reason = None;
            g.active_file_transfers.clear();
            let st = g.state;
            g.push_event("state_changed", serde_json::json!({ "state": st }));
        }
        self.event_notify.notify_waiters();
        Ok(())
    }

    /// Runtime hook: transitions into `Faulted` with structured diagnostic reason.
    pub fn on_faulted(&self, reason: impl Into<String>) {
        let reason_s = reason.into();
        {
            let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            g.state = BridgeState::Faulted;
            g.fault_reason = Some(reason_s.clone());
            g.push_event("faulted", serde_json::json!({ "reason": reason_s }));
        }
        self.event_notify.notify_waiters();
    }

    /// Executes a versioned (`"v": 1`) JSON command string and returns a versioned JSON response.
    /// Unknown JSON fields are ignored on deserialize. Illegal state transitions return structured
    /// `{"v":1,"ok":false,"error_code":"illegal_state_transition",...}` JSON without panicking.
    pub fn execute_command_json(&self, cmd_json: &str) -> String {
        if cmd_json.len() > BRIDGE_MAX_CMD_JSON_BYTES {
            return BridgeResponseEnvelope::err(
                "too_large",
                format!(
                    "command JSON size {}B exceeds {BRIDGE_MAX_CMD_JSON_BYTES}B cap",
                    cmd_json.len()
                ),
            )
            .to_json_string();
        }
        let env: BridgeCommandEnvelope = match serde_json::from_str(cmd_json) {
            Ok(e) => e,
            Err(e) => {
                return BridgeResponseEnvelope::err(
                    "invalid_json",
                    format!("malformed command envelope: {e}"),
                )
                .to_json_string();
            }
        };
        if env.v != BRIDGE_ABI_VERSION {
            return BridgeResponseEnvelope::err(
                "unsupported_abi_version",
                format!(
                    "unsupported bridge ABI version {} (expected {BRIDGE_ABI_VERSION})",
                    env.v
                ),
            )
            .to_json_string();
        }

        let (resp, notify) = self.dispatch_command(env);
        if notify {
            self.event_notify.notify_waiters();
        }
        resp.to_json_string()
    }

    fn dispatch_command(&self, env: BridgeCommandEnvelope) -> (BridgeResponseEnvelope, bool) {
        match env.cmd.as_str() {
            "snapshot" => {
                let snap = self.snapshot();
                match serde_json::to_value(&snap) {
                    Ok(v) => (BridgeResponseEnvelope::ok(v), false),
                    Err(e) => (
                        BridgeResponseEnvelope::err("serialize_error", e.to_string()),
                        false,
                    ),
                }
            }
            "load_config" => {
                let Some(path) = env.path.as_deref().filter(|s| !s.is_empty()) else {
                    return (
                        BridgeResponseEnvelope::err("missing_field", "load_config requires 'path'"),
                        false,
                    );
                };
                {
                    let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if !g.allows_config_mutation() {
                        return (
                            BridgeResponseEnvelope::err(
                                "illegal_state_transition",
                                format!("load_config forbidden in state {:?}", g.state),
                            ),
                            false,
                        );
                    }
                }
                match load_config_json(Path::new(path)) {
                    Ok(cfg) => {
                        let redacted = RedactedConfigView::from(&cfg);
                        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                        if !g.allows_config_mutation() {
                            return (
                                BridgeResponseEnvelope::err(
                                    "illegal_state_transition",
                                    format!("load_config forbidden in state {:?}", g.state),
                                ),
                                false,
                            );
                        }
                        g.transport_mode = cfg.transport_mode;
                        g.config = Some(cfg);
                        if g.state == BridgeState::Idle {
                            g.state = BridgeState::Ready;
                        }
                        g.push_event(
                            "config_loaded",
                            serde_json::json!({ "config": redacted }),
                        );
                        let out = serde_json::json!({ "config": redacted, "state": g.state });
                        (BridgeResponseEnvelope::ok(out), true)
                    }
                    Err(e) => (BridgeResponseEnvelope::err("config_error", e.to_string()), false),
                }
            }
            "save_config" => {
                let Some(path) = env.path.as_deref().filter(|s| !s.is_empty()) else {
                    return (
                        BridgeResponseEnvelope::err("missing_field", "save_config requires 'path'"),
                        false,
                    );
                };
                let Some(cfg) = env.config else {
                    return (
                        BridgeResponseEnvelope::err(
                            "missing_field",
                            "save_config requires 'config'",
                        ),
                        false,
                    );
                };
                {
                    let g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                    if !g.allows_config_mutation() {
                        return (
                            BridgeResponseEnvelope::err(
                                "illegal_state_transition",
                                format!("save_config forbidden in state {:?}", g.state),
                            ),
                            false,
                        );
                    }
                }
                match save_config_json(Path::new(path), &cfg) {
                    Ok(()) => {
                        let redacted = RedactedConfigView::from(&cfg);
                        let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                        if !g.allows_config_mutation() {
                            return (
                                BridgeResponseEnvelope::err(
                                    "illegal_state_transition",
                                    format!("save_config forbidden in state {:?}", g.state),
                                ),
                                false,
                            );
                        }
                        g.transport_mode = cfg.transport_mode;
                        g.config = Some(cfg);
                        g.push_event(
                            "config_saved",
                            serde_json::json!({ "config": redacted }),
                        );
                        (
                            BridgeResponseEnvelope::ok(serde_json::json!({ "config": redacted })),
                            true,
                        )
                    }
                    Err(e) => (BridgeResponseEnvelope::err("config_error", e.to_string()), false),
                }
            }
            "start_host" => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if !matches!(g.state, BridgeState::Idle | BridgeState::Ready) {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!("start_host forbidden in state {:?}", g.state),
                        ),
                        false,
                    );
                }
                if g.config.is_none() {
                    return (
                        BridgeResponseEnvelope::err(
                            "missing_config",
                            "load_config or save_config must succeed before start_host",
                        ),
                        false,
                    );
                }
                g.state = BridgeState::Bootstrapping;
                g.push_event(
                    "state_changed",
                    serde_json::json!({ "state": BridgeState::Bootstrapping, "role": "host" }),
                );
                (
                    BridgeResponseEnvelope::ok(
                        serde_json::json!({ "state": BridgeState::Bootstrapping }),
                    ),
                    true,
                )
            }
            "stop_host" => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if !matches!(
                    g.state,
                    BridgeState::Listening
                        | BridgeState::Bootstrapping
                        | BridgeState::Incoming
                        | BridgeState::Streaming
                ) {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!("stop_host forbidden in state {:?}", g.state),
                        ),
                        false,
                    );
                }
                g.state = BridgeState::Closing;
                g.incoming_accepted = false;
                g.active_file_transfers.clear();
                g.push_event(
                    "state_changed",
                    serde_json::json!({ "state": BridgeState::Closing, "reason": "stop_host" }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({ "state": BridgeState::Closing })),
                    true,
                )
            }
            "dial" => {
                let Some(target) = env.target_device_id_hex.as_deref() else {
                    return (
                        BridgeResponseEnvelope::err(
                            "missing_field",
                            "dial requires 'target_device_id_hex'",
                        ),
                        false,
                    );
                };
                if hex::decode(target).map(|b| b.len()).unwrap_or(0) != 16 {
                    return (
                        BridgeResponseEnvelope::err(
                            "invalid_argument",
                            "target_device_id_hex must be 32 hex chars (16 bytes)",
                        ),
                        false,
                    );
                }
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if !matches!(g.state, BridgeState::Ready | BridgeState::Listening) {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!("dial forbidden in state {:?}", g.state),
                        ),
                        false,
                    );
                }
                let transport_mode = g.transport_mode;
                g.state = BridgeState::Dialing;
                g.push_event(
                    "dial_requested",
                    serde_json::json!({
                        "target_device_id_hex": target,
                        "transport_mode": transport_mode,
                    }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({
                        "state": BridgeState::Dialing,
                        "target_device_id_hex": target,
                    })),
                    true,
                )
            }
            "disconnect" => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if !matches!(
                    g.state,
                    BridgeState::Dialing | BridgeState::Incoming | BridgeState::Streaming
                ) {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!("disconnect forbidden in state {:?}", g.state),
                        ),
                        false,
                    );
                }
                let reason = env.reason.unwrap_or_else(|| "user_disconnect".into());
                g.state = BridgeState::Closing;
                g.incoming_accepted = false;
                g.active_file_transfers.clear();
                g.push_event(
                    "disconnect_requested",
                    serde_json::json!({ "state": BridgeState::Closing, "reason": reason }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({ "state": BridgeState::Closing })),
                    true,
                )
            }
            "accept_incoming" => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.state != BridgeState::Incoming || g.incoming_accepted {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!(
                                "accept_incoming forbidden in state {:?} (accepted={})",
                                g.state, g.incoming_accepted
                            ),
                        ),
                        false,
                    );
                }
                if let Some(req_sid) = env.session_id_hex.as_deref() {
                    if g.pending_incoming_session_id_hex.as_deref() != Some(req_sid) {
                        return (
                            BridgeResponseEnvelope::err(
                                "session_mismatch",
                                "accept_incoming session_id_hex does not match pending call",
                            ),
                            false,
                        );
                    }
                }
                g.incoming_accepted = true;
                let sid = g.pending_incoming_session_id_hex.clone().unwrap_or_default();
                g.push_event(
                    "incoming_call_accepted",
                    serde_json::json!({ "session_id_hex": sid }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({
                        "decision": "accept",
                        "session_id_hex": sid,
                    })),
                    true,
                )
            }
            "reject_incoming" => {
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.state != BridgeState::Incoming || g.incoming_accepted {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!(
                                "reject_incoming forbidden in state {:?} (accepted={})",
                                g.state, g.incoming_accepted
                            ),
                        ),
                        false,
                    );
                }
                if let Some(req_sid) = env.session_id_hex.as_deref() {
                    if g.pending_incoming_session_id_hex.as_deref() != Some(req_sid) {
                        return (
                            BridgeResponseEnvelope::err(
                                "session_mismatch",
                                "reject_incoming session_id_hex does not match pending call",
                            ),
                            false,
                        );
                    }
                }
                let sid = g.pending_incoming_session_id_hex.take().unwrap_or_default();
                let reason = env.reason.unwrap_or_else(|| "user_rejected".into());
                g.incoming_accepted = false;
                g.verified_caller = None;
                g.state = BridgeState::Listening;
                g.push_event(
                    "incoming_call_rejected",
                    serde_json::json!({ "session_id_hex": sid, "reason": reason }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({
                        "decision": "reject",
                        "state": BridgeState::Listening,
                    })),
                    true,
                )
            }
            "set_audio_mute" => {
                let Some(muted) = env.muted else {
                    return (
                        BridgeResponseEnvelope::err(
                            "missing_field",
                            "set_audio_mute requires boolean 'muted'",
                        ),
                        false,
                    );
                };
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                g.audio_muted = muted;
                g.push_event("audio_mute_changed", serde_json::json!({ "muted": muted }));
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({ "audio_muted": muted })),
                    true,
                )
            }
            "set_transport_mode" => {
                let Some(mode_str) = env.mode.as_deref() else {
                    return (
                        BridgeResponseEnvelope::err(
                            "missing_field",
                            "set_transport_mode requires 'mode' (auto|udp|tls443)",
                        ),
                        false,
                    );
                };
                let mode = match TransportMode::parse_name(mode_str) {
                    Ok(m) => m,
                    Err(e) => {
                        return (
                            BridgeResponseEnvelope::err("invalid_argument", e.to_string()),
                            false,
                        );
                    }
                };
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if !g.allows_config_mutation() {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!("set_transport_mode forbidden in state {:?}", g.state),
                        ),
                        false,
                    );
                }
                g.transport_mode = mode;
                if let Some(cfg) = g.config.as_mut() {
                    cfg.transport_mode = mode;
                }
                g.push_event(
                    "transport_mode_changed",
                    serde_json::json!({ "transport_mode": mode }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({ "transport_mode": mode })),
                    true,
                )
            }
            "send_clipboard" => {
                let Some(mime_kind) = env.mime_kind else {
                    return (
                        BridgeResponseEnvelope::err(
                            "missing_field",
                            "send_clipboard requires 'mime_kind'",
                        ),
                        false,
                    );
                };
                let Some(payload_b64) = env.payload_b64.as_deref() else {
                    return (
                        BridgeResponseEnvelope::err(
                            "missing_field",
                            "send_clipboard requires 'payload_b64'",
                        ),
                        false,
                    );
                };
                if payload_b64.len() > BRIDGE_MAX_CLIP_B64_BYTES {
                    return (
                        BridgeResponseEnvelope::err(
                            "too_large",
                            format!(
                                "payload_b64 length {}B exceeds {BRIDGE_MAX_CLIP_B64_BYTES}B pre-decode cap",
                                payload_b64.len()
                            ),
                        ),
                        false,
                    );
                }
                let payload = match B64.decode(payload_b64) {
                    Ok(p) if !p.is_empty() => p,
                    Ok(_) => {
                        return (
                            BridgeResponseEnvelope::err(
                                "invalid_argument",
                                "clipboard payload must not be empty",
                            ),
                            false,
                        );
                    }
                    Err(e) => {
                        return (
                            BridgeResponseEnvelope::err(
                                "invalid_argument",
                                format!("invalid payload_b64: {e}"),
                            ),
                            false,
                        );
                    }
                };
                let total_len = match u32::try_from(payload.len()) {
                    Ok(n) if n <= CLIP_HARD_MAX_BYTES => n,
                    _ => {
                        return (
                            BridgeResponseEnvelope::err(
                                "too_large",
                                "clipboard payload exceeds 256 KiB hard limit",
                            ),
                            false,
                        );
                    }
                };
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.state != BridgeState::Streaming {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!("send_clipboard requires Streaming state, got {:?}", g.state),
                        ),
                        false,
                    );
                }
                if let Some(pol) = &g.policy {
                    if let Err(status) = check_clipboard_policy_for_sync(pol, mime_kind, total_len)
                    {
                        return (
                            BridgeResponseEnvelope::err(
                                "policy_denied",
                                format!("clipboard blocked by verified policy (status={status})"),
                            ),
                            false,
                        );
                    }
                } else {
                    return (
                        BridgeResponseEnvelope::err(
                            "policy_denied",
                            "verified tenant policy unavailable (fail-closed)",
                        ),
                        false,
                    );
                }
                let clip_id = g.next_clip_id;
                g.next_clip_id = g.next_clip_id.saturating_add(1);
                g.push_event(
                    "clipboard_queued",
                    serde_json::json!({
                        "clip_id": clip_id,
                        "mime_kind": mime_kind,
                        "bytes": total_len,
                    }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({
                        "clip_id": clip_id,
                        "bytes": total_len,
                    })),
                    true,
                )
            }
            "send_file" => {
                let Some(rel_name) = env.rel_name.as_deref() else {
                    return (
                        BridgeResponseEnvelope::err("missing_field", "send_file requires 'rel_name'"),
                        false,
                    );
                };
                let Some(file_size) = env.file_size else {
                    return (
                        BridgeResponseEnvelope::err("missing_field", "send_file requires 'file_size'"),
                        false,
                    );
                };
                if let Err(e) = validate_safe_filename(rel_name.as_bytes()) {
                    return (
                        BridgeResponseEnvelope::err("invalid_filename", e.to_string()),
                        false,
                    );
                }
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.state != BridgeState::Streaming {
                    return (
                        BridgeResponseEnvelope::err(
                            "illegal_state_transition",
                            format!("send_file requires Streaming state, got {:?}", g.state),
                        ),
                        false,
                    );
                }
                if let Some(pol) = &g.policy {
                    if let Err(e) = check_file_policy(pol, file_size) {
                        return (
                            BridgeResponseEnvelope::err("policy_denied", e.to_string()),
                            false,
                        );
                    }
                } else {
                    return (
                        BridgeResponseEnvelope::err(
                            "policy_denied",
                            "verified tenant policy unavailable (fail-closed)",
                        ),
                        false,
                    );
                }
                if g.active_file_transfers.len() >= 2 {
                    return (
                        BridgeResponseEnvelope::err(
                            "rate_limited",
                            "maximum 2 concurrent outbound file transfers reached",
                        ),
                        false,
                    );
                }
                let tid = g.next_transfer_id;
                g.next_transfer_id = g.next_transfer_id.saturating_add(1);
                g.active_file_transfers.insert(tid, rel_name.to_string());
                g.push_event(
                    "file_transfer_queued",
                    serde_json::json!({
                        "transfer_id": tid,
                        "rel_name": rel_name,
                        "file_size": file_size,
                    }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({
                        "transfer_id": tid,
                        "rel_name": rel_name,
                    })),
                    true,
                )
            }
            "cancel_file" => {
                let Some(tid) = env.transfer_id else {
                    return (
                        BridgeResponseEnvelope::err(
                            "missing_field",
                            "cancel_file requires 'transfer_id'",
                        ),
                        false,
                    );
                };
                let mut g = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if g.active_file_transfers.remove(&tid).is_none() {
                    return (
                        BridgeResponseEnvelope::err(
                            "not_found",
                            format!("no active file transfer with transfer_id={tid}"),
                        ),
                        false,
                    );
                }
                g.push_event(
                    "file_transfer_cancelled",
                    serde_json::json!({ "transfer_id": tid }),
                );
                (
                    BridgeResponseEnvelope::ok(serde_json::json!({
                        "transfer_id": tid,
                        "cancelled": true,
                    })),
                    true,
                )
            }
            other => (
                BridgeResponseEnvelope::err("unknown_command", format!("unknown command '{other}'")),
                false,
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::session::policy::{TenantPolicyBody, POLICY_FLAGS_VALID_MASK};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn sample_cert(dev_id: [u8; 16], tid: [u8; 16]) -> SignalingDeviceCert {
        SignalingDeviceCert {
            version: 1,
            cert_id: [0xCC; 16],
            device_id: dev_id,
            tenant_id: tid,
            p256_pub_der: vec![0x30, 0x59],
            key_epoch: 3,
            policy_hash: [0x55; 32],
            cap_bits: 0x6_7FFF,
            iat_unix: 100,
            exp_unix: 200,
            ca_key_id: 1,
            ca_sig: vec![0x30, 0x06],
        }
    }

    fn full_policy(tid: [u8; 16]) -> EffectiveTenantPolicy {
        EffectiveTenantPolicy {
            tenant_id: tid,
            version: 2,
            exp_unix: u64::MAX,
            policy_hash: [0x55; 32],
            body: TenantPolicyBody {
                schema_ver: 1,
                flags: POLICY_FLAGS_VALID_MASK,
                max_bw_kbps: 20_000,
                max_file_mb: 100,
                max_clipboard_kb: 256,
            },
            degraded: false,
            degraded_reason: None,
        }
    }

    #[test]
    fn bridge_state_machine_redaction_atomic_0600_config_and_all_commands() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-bridge-test-{}-{uniq}", std::process::id()));
        let cfg_path = dir.join("client_cfg.json");

        let ctrl = V2BridgeController::new();
        assert_eq!(ctrl.state(), BridgeState::Idle);

        // Illegal transition: dial in Idle -> structured error JSON
        let err_dial: BridgeResponseEnvelope = serde_json::from_str(&ctrl.execute_command_json(
            r#"{"v":1,"cmd":"dial","target_device_id_hex":"0102030405060708090a0b0c0d0e0f10","unknown_future_field":123}"#,
        ))
        .unwrap();
        assert!(!err_dial.ok);
        assert_eq!(
            err_dial.error_code.as_deref(),
            Some("illegal_state_transition")
        );

        // save_config atomic 0600 & load_config (with unknown field ignored)
        let secret_token = "SUPER_SECRET_ENROLLMENT_TOKEN_NEVER_LEAK";
        let save_cmd = serde_json::json!({
            "v": 1,
            "cmd": "save_config",
            "extra_ignored": true,
            "path": cfg_path.display().to_string(),
            "config": {
                "v": 1,
                "control_plane_endpoint": "https://cp.example:443",
                "signaling_addr": "sig.example:443",
                "enrollment_token": secret_token,
                "identity_dir": dir.join("id").display().to_string(),
                "transport_mode": "auto"
            }
        });
        let save_resp_str = ctrl.execute_command_json(&save_cmd.to_string());
        assert!(!save_resp_str.contains(secret_token));
        let save_resp: BridgeResponseEnvelope = serde_json::from_str(&save_resp_str).unwrap();
        assert!(save_resp.ok);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&cfg_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }

        let load_cmd = serde_json::json!({
            "v": 1,
            "cmd": "load_config",
            "path": cfg_path.display().to_string(),
        });
        let load_resp_str = ctrl.execute_command_json(&load_cmd.to_string());
        assert!(!load_resp_str.contains(secret_token));
        assert_eq!(ctrl.state(), BridgeState::Ready);

        // Snapshot MUST NEVER contain enrollment_token or any private key material
        let snap_str = ctrl.execute_command_json(r#"{"v":1,"cmd":"snapshot"}"#);
        assert!(!snap_str.contains(secret_token));
        assert!(snap_str.contains("\"has_enrollment_token\":true"));

        // start_host -> Bootstrapping -> Listening -> Incoming (verified CA cert) -> accept -> Streaming
        let start_resp: BridgeResponseEnvelope =
            serde_json::from_str(&ctrl.execute_command_json(r#"{"v":1,"cmd":"start_host"}"#))
                .unwrap();
        assert!(start_resp.ok);
        assert_eq!(ctrl.state(), BridgeState::Bootstrapping);

        let tid = [0x77; 16];
        let local_cert = sample_cert([0x11; 16], tid);
        let peer_cert = sample_cert([0x22; 16], tid);
        ctrl.on_bootstrap_complete(&local_cert, full_policy(tid), true)
            .unwrap();
        assert_eq!(ctrl.state(), BridgeState::Listening);

        assert!(serde_json::from_str::<BridgeResponseEnvelope>(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"set_transport_mode","mode":"tls443"}"#)
        )
        .unwrap()
        .ok);
        assert_eq!(ctrl.snapshot().transport_mode, TransportMode::Tls443Only);

        let sid = [0xAA; 16];
        ctrl.on_incoming_verified_call(sid, &peer_cert).unwrap();
        assert_eq!(ctrl.state(), BridgeState::Incoming);
        let snap = ctrl.snapshot();
        assert_eq!(
            snap.verified_caller.as_ref().map(|c| c.device_id_hex.as_str()),
            Some(hex::encode([0x22u8; 16]).as_str())
        );
        assert!(snap.verified_caller.unwrap().verified_by_ca);

        let acc_resp: BridgeResponseEnvelope = serde_json::from_str(
            &ctrl.execute_command_json(&format!(
                r#"{{"v":1,"cmd":"accept_incoming","session_id_hex":"{}"}}"#,
                hex::encode(sid)
            )),
        )
        .unwrap();
        assert!(acc_resp.ok);

        ctrl.on_streaming_started(sid, &peer_cert, ActiveTransportMode::DualTls443)
            .unwrap();
        assert_eq!(ctrl.state(), BridgeState::Streaming);
        assert_eq!(
            ctrl.snapshot().active_transport_mode,
            Some(ActiveTransportMode::DualTls443)
        );

        // set_audio_mute + send_clipboard + send_file + cancel_file (set_transport_mode rejected during Streaming)
        assert!(serde_json::from_str::<BridgeResponseEnvelope>(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"set_audio_mute","muted":true}"#)
        )
        .unwrap()
        .ok);
        assert!(ctrl.snapshot().audio_muted);

        assert!(!serde_json::from_str::<BridgeResponseEnvelope>(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"set_transport_mode","mode":"udp"}"#)
        )
        .unwrap()
        .ok);

        let clip_resp: BridgeResponseEnvelope = serde_json::from_str(&ctrl.execute_command_json(
            &format!(
                r#"{{"v":1,"cmd":"send_clipboard","mime_kind":1,"payload_b64":"{}"}}"#,
                B64.encode(b"hello")
            ),
        ))
        .unwrap();
        assert!(clip_resp.ok);

        let file_resp: BridgeResponseEnvelope = serde_json::from_str(&ctrl.execute_command_json(
            r#"{"v":1,"cmd":"send_file","rel_name":"demo.txt","file_size":1024}"#,
        ))
        .unwrap();
        assert!(file_resp.ok);
        let tid_out = file_resp.data.unwrap()["transfer_id"].as_u64().unwrap();

        let cancel_resp: BridgeResponseEnvelope = serde_json::from_str(
            &ctrl.execute_command_json(&format!(
                r#"{{"v":1,"cmd":"cancel_file","transfer_id":{tid_out}}}"#
            )),
        )
        .unwrap();
        assert!(cancel_resp.ok);

        // disconnect -> Closing -> on_closed -> Listening -> stop_host -> Closing
        assert!(serde_json::from_str::<BridgeResponseEnvelope>(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"disconnect"}"#)
        )
        .unwrap()
        .ok);
        assert_eq!(ctrl.state(), BridgeState::Closing);
        ctrl.on_closed(true).unwrap();
        assert_eq!(ctrl.state(), BridgeState::Listening);

        // Verify reject_incoming path
        ctrl.on_incoming_verified_call([0xBB; 16], &peer_cert).unwrap();
        assert!(serde_json::from_str::<BridgeResponseEnvelope>(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"reject_incoming"}"#)
        )
        .unwrap()
        .ok);
        assert_eq!(ctrl.state(), BridgeState::Listening);

        // Bounded event queue drained cleanly
        let events = ctrl.drain_events();
        assert!(!events.is_empty());
        assert!(ctrl.recv_event().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bridge_p1_state_guards_anti_double_accept_size_caps_and_recv_timeout() {
        let ctrl = V2BridgeController::new();
        let tid = [0x22; 16];
        let local_cert = sample_cert([0xA1; 16], tid);
        let peer_cert = sample_cert([0xB2; 16], tid);

        // 1. on_bootstrap_complete & on_closed reject Idle
        assert!(ctrl
            .on_bootstrap_complete(&local_cert, full_policy(tid), true)
            .is_err());
        assert!(ctrl.on_closed(false).is_err());

        // 2. Oversized command JSON (> 512 KiB) & oversized payload_b64 (> 360 KiB) rejected before decode
        let huge_cmd = " ".repeat(BRIDGE_MAX_CMD_JSON_BYTES + 1);
        let huge_resp: BridgeResponseEnvelope =
            serde_json::from_str(&ctrl.execute_command_json(&huge_cmd)).unwrap();
        assert!(!huge_resp.ok);
        assert_eq!(huge_resp.error_code.as_deref(), Some("too_large"));

        let huge_b64 = "A".repeat(BRIDGE_MAX_CLIP_B64_BYTES + 4);
        let clip_cap_resp: BridgeResponseEnvelope = serde_json::from_str(
            &ctrl.execute_command_json(&format!(
                r#"{{"v":1,"cmd":"send_clipboard","mime_kind":1,"payload_b64":"{huge_b64}"}}"#
            )),
        )
        .unwrap();
        assert!(!clip_cap_resp.ok);
        assert_eq!(clip_cap_resp.error_code.as_deref(), Some("too_large"));

        // 3. Save valid config -> start_host -> Listening -> Incoming -> accept_incoming
        let uniq = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-br-p1-{}-{uniq}", std::process::id()));
        crate::session::config::ensure_dir_0700(&dir).unwrap();
        let cfg_path = dir.join("cfg.json");

        // Invalid config (empty endpoint) rejected by save_config BEFORE writing to disk
        let bad_save: BridgeResponseEnvelope = serde_json::from_str(&ctrl.execute_command_json(
            &format!(
                r#"{{"v":1,"cmd":"save_config","path":"{}","config":{{"v":1,"control_plane_endpoint":"","signaling_addr":"127.0.0.1:9001","identity_dir":"{}"}}}}"#,
                cfg_path.display(),
                dir.display()
            ),
        ))
        .unwrap();
        assert!(!bad_save.ok);
        assert!(!cfg_path.exists());

        let good_save: BridgeResponseEnvelope = serde_json::from_str(&ctrl.execute_command_json(
            &format!(
                r#"{{"v":1,"cmd":"save_config","path":"{}","config":{{"v":1,"control_plane_endpoint":"https://127.0.0.1:8443","signaling_addr":"127.0.0.1:9001","identity_dir":"{}"}}}}"#,
                cfg_path.display(),
                dir.display()
            ),
        ))
        .unwrap();
        assert!(good_save.ok);

        assert!(serde_json::from_str::<BridgeResponseEnvelope>(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"start_host"}"#)
        )
        .unwrap()
        .ok);
        // Active Bootstrapping rejects set_transport_mode / load_config / save_config
        let mut_during_boot: BridgeResponseEnvelope = serde_json::from_str(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"set_transport_mode","mode":"udp"}"#),
        )
        .unwrap();
        assert!(!mut_during_boot.ok);
        assert_eq!(
            mut_during_boot.error_code.as_deref(),
            Some("illegal_state_transition")
        );

        ctrl.on_bootstrap_complete(&local_cert, full_policy(tid), true)
            .unwrap();
        ctrl.on_incoming_verified_call([0xCC; 16], &peer_cert)
            .unwrap();

        // First accept_incoming succeeds; second accept_incoming & subsequent reject_incoming MUST fail!
        assert!(serde_json::from_str::<BridgeResponseEnvelope>(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"accept_incoming"}"#)
        )
        .unwrap()
        .ok);
        let dup_accept: BridgeResponseEnvelope = serde_json::from_str(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"accept_incoming"}"#),
        )
        .unwrap();
        assert!(!dup_accept.ok);
        assert_eq!(
            dup_accept.error_code.as_deref(),
            Some("illegal_state_transition")
        );
        let contra_reject: BridgeResponseEnvelope = serde_json::from_str(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"reject_incoming"}"#),
        )
        .unwrap();
        assert!(!contra_reject.ok);
        assert_eq!(
            contra_reject.error_code.as_deref(),
            Some("illegal_state_transition")
        );

        // on_bootstrap_complete during Incoming MUST return Ok, update policy, and preserve
        // state == Incoming + incoming_accepted + pending_incoming_session_id_hex!
        let mut incoming_refreshed = full_policy(tid);
        incoming_refreshed.version = 5;
        ctrl.on_bootstrap_complete(&local_cert, incoming_refreshed, true)
            .unwrap();
        assert_eq!(ctrl.state(), BridgeState::Incoming);
        let inc_snap = ctrl.snapshot();
        assert_eq!(inc_snap.policy.unwrap().version, 5);
        assert_eq!(
            inc_snap.pending_incoming_session_id_hex.as_deref(),
            Some(hex::encode([0xCCu8; 16]).as_str())
        );
        // incoming_accepted must still be true (a subsequent reject_incoming still fails!)
        let still_accepted: BridgeResponseEnvelope = serde_json::from_str(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"reject_incoming"}"#),
        )
        .unwrap();
        assert!(!still_accepted.ok);
        assert_eq!(
            still_accepted.error_code.as_deref(),
            Some("illegal_state_transition")
        );

        // Transition to Streaming -> on_bootstrap_complete updates policy ONLY without overwriting Streaming!
        ctrl.on_streaming_started([0xCC; 16], &peer_cert, ActiveTransportMode::DualTls443)
            .unwrap();
        let mut refreshed = full_policy(tid);
        refreshed.version = 9;
        ctrl.on_bootstrap_complete(&local_cert, refreshed, true)
            .unwrap();
        assert_eq!(ctrl.state(), BridgeState::Streaming);
        assert_eq!(ctrl.snapshot().policy.unwrap().version, 9);

        // set_transport_mode forbidden during Streaming
        let tm_stream: BridgeResponseEnvelope = serde_json::from_str(
            &ctrl.execute_command_json(r#"{"v":1,"cmd":"set_transport_mode","mode":"tls443"}"#),
        )
        .unwrap();
        assert!(!tm_stream.ok);
        assert_eq!(
            tm_stream.error_code.as_deref(),
            Some("illegal_state_transition")
        );

        // Faulted -> on_closed clears fault_reason
        ctrl.on_faulted("test fault");
        assert_eq!(ctrl.state(), BridgeState::Faulted);
        assert!(ctrl.snapshot().fault_reason.is_some());
        ctrl.on_closed(false).unwrap();
        assert_eq!(ctrl.state(), BridgeState::Ready);
        assert!(ctrl.snapshot().fault_reason.is_none());

        // 4. recv_event_timeout wakes reliably without lost wakeup
        let _ = ctrl.drain_events();
        let ctrl_c = ctrl.clone();
        let wake_task = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let _ = ctrl_c.execute_command_json(r#"{"v":1,"cmd":"set_audio_mute","muted":true}"#);
        });
        let ev = ctrl
            .recv_event_timeout(Duration::from_secs(2))
            .await
            .expect("recv_event_timeout should receive event");
        assert_eq!(ev.kind, "audio_mute_changed");
        wake_task.await.unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }
}
