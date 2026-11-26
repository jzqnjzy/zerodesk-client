// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    config::{V2ClientConfig, V2ConfigError},
    identity::{IdentityStoreError, PersistentV2Identity},
    input::SafeHidKey,
    runtime::{CloseReason, LeaseRenewalConfig, LeaseRenewalLeg, LeaseRenewalTask, QoeSnapshot},
    video::I420Frame,
};
use rand_core::{OsRng, RngCore};
use std::{
    collections::{HashSet, VecDeque},
    fmt,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use v2_client::{
    now_unix_secs, AccessControlTunnel, ClientError, ControlPlaneClient, HeartbeatMsg,
    PeerRouteCandidate, PresenceState, SignalingConnectAccept, SignalingConnectOffer,
    SignalingConnectReq, SignalingDeviceCert, SignalingMsgKind, SignalingReconnectBackoff,
    SignalingRegisterReq, SignalingSession, UdpAccessLink, UdpE2eeSession,
};
use v2_identity::{DelegationCache, DeviceKeyStore, SoftwareDeviceKeyStore};
use v2_transport::{
    PrologueInput, QuotaExhaustPolicy, VerifiedTenantPolicy, CAP_ACCESS_LEG_SEQ_V11,
    CAP_CODEC_AV1, CAP_CODEC_VP9, CAP_SURVIVAL_MODE, CAP_TRANSPORT_TCP443_DUAL, CIPHER_AESGCM,
    L3_MTU_DEFAULT, PATTERN_IK, TRANSPORT_MODE_RELAY_UDP, VER_MAJOR, VER_MAJOR_MINOR, VER_MINOR,
};

pub const DEFAULT_V2_CAP_BITS: u64 = CAP_CODEC_AV1
    | CAP_CODEC_VP9
    | CAP_TRANSPORT_TCP443_DUAL
    | CAP_ACCESS_LEG_SEQ_V11
    | CAP_SURVIVAL_MODE;
pub const SEEN_SESSION_CACHE_CAP: usize = 4096;
const UI_DISPATCH_CHANNEL_CAP: usize = 64;
const INCOMING_CALL_DECISION_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug)]
pub enum ManagerError {
    Config(V2ConfigError),
    Identity(IdentityStoreError),
    Client(ClientError),
    Protocol(String),
    Rejected { error_code: u16, reason: String },
    Stopped,
}

impl fmt::Display for ManagerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => write!(f, "{e}"),
            Self::Identity(e) => write!(f, "{e}"),
            Self::Client(e) => write!(f, "{e}"),
            Self::Protocol(msg) => write!(f, "V2 manager protocol error: {msg}"),
            Self::Rejected { error_code, reason } => {
                write!(f, "call rejected ({error_code:#06x}): {reason}")
            }
            Self::Stopped => write!(f, "V2 manager stopped"),
        }
    }
}

impl std::error::Error for ManagerError {}

impl From<V2ConfigError> for ManagerError {
    fn from(e: V2ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<IdentityStoreError> for ManagerError {
    fn from(e: IdentityStoreError) -> Self {
        Self::Identity(e)
    }
}

impl From<ClientError> for ManagerError {
    fn from(e: ClientError) -> Self {
        Self::Client(e)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2SessionState {
    Idle,
    Registering,
    Online,
    Connecting,
    Handshaking,
    Streaming,
    Closing(CloseReason),
    Closed(CloseReason),
    Faulted(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingCall {
    pub session_id: [u8; 16],
    pub controller_device_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub proposed_l3_mtu: u32,
    pub controller_cap_bits: u64,
    pub peer_route: PeerRouteCandidate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallDecision {
    Accept,
    Reject { error_code: u16, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityEvent {
    CertVerified {
        peer_device_id: [u8; 16],
    },
    CertRejected {
        reason: String,
    },
    TenantMismatch {
        expected: [u8; 16],
        actual: [u8; 16],
    },
    ReplaySessionRejected {
        session_id: [u8; 16],
    },
    InvalidHidFraming {
        reason: String,
    },
    InputFaulted {
        residual_buttons: u8,
        residual_keys: Vec<SafeHidKey>,
    },
    WatchdogTriggered,
    LeaseRenewalFailed {
        consecutive: u32,
        reason: String,
    },
    SignalingDisconnected {
        reason: String,
    },
}

/// UI / FFI callback boundary (`Send + Sync`).
/// Dispatched asynchronously via `UiCallbackDispatcher` and NEVER invoked while holding locks.
pub trait V2UiCallback: Send + Sync + 'static {
    fn on_frame(&self, frame: Arc<I420Frame>);
    fn on_state(&self, state: V2SessionState);
    fn on_qoe(&self, snapshot: QoeSnapshot);
    fn on_capabilities(&self, caps: VerifiedTenantPolicy);
    fn on_incoming_call(
        &self,
        call: IncomingCall,
        reply: oneshot::Sender<CallDecision>,
    );
    fn on_security_event(&self, event: SecurityEvent);
}

/// Headless default callback that auto-accepts verified incoming calls and ignores UI media/QoE.
#[derive(Debug, Default)]
pub struct NoopUiCallback;

impl V2UiCallback for NoopUiCallback {
    fn on_frame(&self, _frame: Arc<I420Frame>) {}
    fn on_state(&self, _state: V2SessionState) {}
    fn on_qoe(&self, _snapshot: QoeSnapshot) {}
    fn on_capabilities(&self, _caps: VerifiedTenantPolicy) {}
    fn on_incoming_call(&self, _call: IncomingCall, reply: oneshot::Sender<CallDecision>) {
        let _ = reply.send(CallDecision::Accept);
    }
    fn on_security_event(&self, _event: SecurityEvent) {}
}

enum UiDispatchEvent {
    Frame(Arc<I420Frame>),
    State(V2SessionState),
    Qoe(QoeSnapshot),
    Capabilities(VerifiedTenantPolicy),
    IncomingCall {
        call: IncomingCall,
        reply: oneshot::Sender<CallDecision>,
    },
    SecurityEvent(SecurityEvent),
}

/// Non-blocking async dispatcher that runs `V2UiCallback` on its own dedicated Tokio task,
/// guaranteeing callbacks are never invoked while holding internal session locks.
#[derive(Clone)]
pub struct UiCallbackDispatcher {
    tx: mpsc::Sender<UiDispatchEvent>,
}

impl UiCallbackDispatcher {
    pub fn spawn(callback: Arc<dyn V2UiCallback>) -> Self {
        let (tx, mut rx) = mpsc::channel::<UiDispatchEvent>(UI_DISPATCH_CHANNEL_CAP);
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                match ev {
                    UiDispatchEvent::Frame(f) => callback.on_frame(f),
                    UiDispatchEvent::State(s) => callback.on_state(s),
                    UiDispatchEvent::Qoe(q) => callback.on_qoe(q),
                    UiDispatchEvent::Capabilities(c) => callback.on_capabilities(c),
                    UiDispatchEvent::IncomingCall { call, reply } => {
                        callback.on_incoming_call(call, reply);
                    }
                    UiDispatchEvent::SecurityEvent(e) => callback.on_security_event(e),
                }
            }
        });
        Self { tx }
    }

    pub fn emit_frame(&self, frame: Arc<I420Frame>) {
        let _ = self.tx.try_send(UiDispatchEvent::Frame(frame));
    }

    pub fn emit_state(&self, state: V2SessionState) {
        let _ = self.tx.try_send(UiDispatchEvent::State(state));
    }

    pub fn emit_qoe(&self, qoe: QoeSnapshot) {
        let _ = self.tx.try_send(UiDispatchEvent::Qoe(qoe));
    }

    pub fn emit_capabilities(&self, caps: VerifiedTenantPolicy) {
        let _ = self.tx.try_send(UiDispatchEvent::Capabilities(caps));
    }

    pub fn emit_security_event(&self, ev: SecurityEvent) {
        let _ = self.tx.try_send(UiDispatchEvent::SecurityEvent(ev));
    }

    pub async fn ask_incoming_call(
        &self,
        call: IncomingCall,
        timeout: Duration,
    ) -> CallDecision {
        let (reply_tx, reply_rx) = oneshot::channel();
        if self
            .tx
            .send(UiDispatchEvent::IncomingCall {
                call,
                reply: reply_tx,
            })
            .await
            .is_err()
        {
            return CallDecision::Reject {
                error_code: 0x0401,
                reason: "UI callback channel closed".into(),
            };
        }
        match tokio::time::timeout(timeout, reply_rx).await {
            Ok(Ok(decision)) => decision,
            Ok(Err(_)) => CallDecision::Reject {
                error_code: 0x0401,
                reason: "UI dropped incoming call reply channel".into(),
            },
            Err(_) => CallDecision::Reject {
                error_code: 0x0401,
                reason: "incoming call approval timed out".into(),
            },
        }
    }
}

/// Bounded anti-replay `session_id` deduplication cache.
#[derive(Debug)]
pub struct SeenSessionCache {
    cap: usize,
    set: HashSet<[u8; 16]>,
    order: VecDeque<[u8; 16]>,
}

impl SeenSessionCache {
    pub fn new(cap: usize) -> Self {
        let cap = cap.max(1);
        Self {
            cap,
            set: HashSet::with_capacity(cap.min(256)),
            order: VecDeque::with_capacity(cap.min(256)),
        }
    }

    /// Returns `true` if `session_id` is new and recorded; `false` if it was already seen (replay).
    pub fn mark_if_new(&mut self, session_id: [u8; 16]) -> bool {
        if self.set.contains(&session_id) {
            return false;
        }
        while self.set.len() >= self.cap {
            if let Some(oldest) = self.order.pop_front() {
                self.set.remove(&oldest);
            } else {
                break;
            }
        }
        self.set.insert(session_id);
        self.order.push_back(session_id);
        true
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

/// Builds a `VerifiedTenantPolicy` anchored to mutually CA-verified `DeviceCert` fields.
pub fn build_verified_policy_from_cert(
    cert: &SignalingDeviceCert,
    bw_cap_kbps: u32,
) -> VerifiedTenantPolicy {
    VerifiedTenantPolicy {
        tenant_id: cert.tenant_id,
        policy_version: 1,
        policy_hash: cert.policy_hash,
        allow_file_transfer: true,
        allow_clipboard: true,
        allow_file_clipboard: true,
        allow_tcp_tunnel: true,
        allow_terminal: true,
        allow_realtime_actuator: false,
        bw_cap_kbps: bw_cap_kbps.max(256),
        exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
    }
}

#[allow(clippy::too_many_arguments)]
fn verify_peer_cert_and_delegation(
    peer_cert: &SignalingDeviceCert,
    peer_deleg: &v2_identity::DelegationStatement,
    local_cert: &SignalingDeviceCert,
    expected_peer_device_id: Option<[u8; 16]>,
    ca_spki_der: &[u8],
    delegation_cache: &mut DelegationCache,
    now_unix: u64,
    callbacks: &UiCallbackDispatcher,
) -> Result<(), (u16, String)> {
    if let Some(expected_dev) = expected_peer_device_id {
        if peer_cert.device_id != expected_dev {
            let reason = format!(
                "peer DeviceCert device_id {} != expected {}",
                hex::encode(peer_cert.device_id),
                hex::encode(expected_dev)
            );
            callbacks.emit_security_event(SecurityEvent::CertRejected {
                reason: reason.clone(),
            });
            return Err((0x0201, reason));
        }
    }
    if peer_cert.tenant_id != local_cert.tenant_id {
        callbacks.emit_security_event(SecurityEvent::TenantMismatch {
            expected: local_cert.tenant_id,
            actual: peer_cert.tenant_id,
        });
        return Err((
            0x0401,
            format!(
                "cross-tenant session denied (local={}, peer={})",
                hex::encode(local_cert.tenant_id),
                hex::encode(peer_cert.tenant_id)
            ),
        ));
    }
    if peer_cert.policy_hash != local_cert.policy_hash {
        let reason = "peer DeviceCert policy_hash does not match local tenant policy_hash".into();
        callbacks.emit_security_event(SecurityEvent::CertRejected { reason });
        return Err((
            0x0401,
            "peer DeviceCert policy_hash mismatch".into(),
        ));
    }
    if let Err(e) = peer_cert.verify(ca_spki_der, now_unix) {
        let reason = format!("peer DeviceCert CA verification failed: {e}");
        callbacks.emit_security_event(SecurityEvent::CertRejected {
            reason: reason.clone(),
        });
        return Err((0x0201, reason));
    }
    if peer_deleg.device_id != peer_cert.device_id {
        let reason = "peer DelegationStatement device_id != peer DeviceCert device_id".into();
        callbacks.emit_security_event(SecurityEvent::CertRejected { reason });
        return Err((0x0203, "delegation device_id mismatch".into()));
    }
    if let Err(e) = delegation_cache.verify_and_record(
        peer_deleg,
        &peer_cert.p256_pub_der,
        peer_cert.exp_unix,
        now_unix,
    ) {
        let reason = format!("peer DelegationStatement verify/anti-rollback failed: {e}");
        callbacks.emit_security_event(SecurityEvent::CertRejected {
            reason: reason.clone(),
        });
        return Err((0x0203, reason));
    }

    callbacks.emit_security_event(SecurityEvent::CertVerified {
        peer_device_id: peer_cert.device_id,
    });
    Ok(())
}

/// Active Host media/HID session returned by `DesktopHostDaemon::accept_next_session`.
/// Completely decoupled from `SignalingSession`: dropping signaling mid-session has ZERO effect.
pub struct AcceptedHostSession {
    pub session_id: [u8; 16],
    pub peer_device_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub e2ee_session: UdpE2eeSession,
    pub ctrl_tunnel_b: AccessControlTunnel,
    pub hs_hash: [u8; 32],
    pub policy: VerifiedTenantPolicy,
    pub peer_route: PeerRouteCandidate,
    pub negotiated_cap_bits: u64,
    pub negotiated_l3_mtu: usize,
}

/// Persistent Host signaling daemon: stays online via `SignalingSession` + periodic `Heartbeat`,
/// enforces anti-replay `session_id` dedup, mutual CA cert verification, same-tenant isolation,
/// and mandatory `Noise_IK` responder handshake.
pub struct DesktopHostDaemon {
    config: V2ClientConfig,
    identity: PersistentV2Identity,
    ca_spki_der: Vec<u8>,
    cap_bits: u64,
    callbacks: UiCallbackDispatcher,
    seen_sessions: SeenSessionCache,
    delegation_cache: DelegationCache,
    signaling: Option<SignalingSession>,
    heartbeat_interval: Duration,
    backoff: SignalingReconnectBackoff,
}

impl DesktopHostDaemon {
    pub async fn bootstrap(
        config: V2ClientConfig,
        callbacks: UiCallbackDispatcher,
    ) -> Result<Self, ManagerError> {
        config.validate()?;
        callbacks.emit_state(V2SessionState::Registering);

        let cp = ControlPlaneClient::new(
            &config.control_plane_endpoint,
            config.ca_der_path.as_deref(),
        )?;
        cp.healthz().await?;
        let ca_spki_der = cp.get_ca_pubkey().await?.spki_der()?;

        let mut identity = PersistentV2Identity::load_or_create(&config.identity_dir)?;
        let cert = identity
            .ensure_registered(
                &cp,
                &ca_spki_der,
                config.enrollment_token.as_deref(),
                DEFAULT_V2_CAP_BITS,
                &config.home_region,
            )
            .await?;
        let (_secret, deleg) = identity.ensure_delegation(now_unix_secs())?;

        let reg_req = SignalingRegisterReq {
            device_cert: cert,
            delegation: deleg,
            presence: PresenceState::Online,
            cap_bits: DEFAULT_V2_CAP_BITS,
            home_region: config.home_region.clone(),
            ver_major: u32::from(VER_MAJOR),
            ver_minor: u32::from(VER_MINOR),
        };
        let (sig, resp) = SignalingSession::connect_and_register(
            &config.signaling_addr,
            &reg_req,
            Duration::from_secs(10),
        )
        .await?;
        let hb_secs = u64::from(resp.heartbeat_interval_sec.clamp(5, 60));
        callbacks.emit_state(V2SessionState::Online);

        Ok(Self {
            config,
            identity,
            ca_spki_der,
            cap_bits: DEFAULT_V2_CAP_BITS,
            callbacks,
            seen_sessions: SeenSessionCache::new(SEEN_SESSION_CACHE_CAP),
            delegation_cache: DelegationCache::new(),
            signaling: Some(sig),
            heartbeat_interval: Duration::from_secs(hb_secs),
            backoff: SignalingReconnectBackoff::new(),
        })
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.identity.device_id()
    }

    pub fn tenant_id(&self) -> Option<[u8; 16]> {
        self.identity.tenant_id()
    }

    pub fn device_cert(&self) -> Option<&SignalingDeviceCert> {
        self.identity.device_cert()
    }

    pub fn config(&self) -> &V2ClientConfig {
        &self.config
    }

    /// Explicitly drops the signaling TCP connection (useful for clean shutdown or testing
    /// signaling-drop isolation while an active media session runs).
    pub async fn disconnect_signaling(&mut self) {
        if let Some(mut sig) = self.signaling.take() {
            let _ = sig.shutdown().await;
        }
    }

    async fn ensure_signaling_connected(&mut self) -> Result<(), ManagerError> {
        if self.signaling.is_some() {
            return Ok(());
        }
        let cert = self
            .identity
            .device_cert()
            .cloned()
            .ok_or_else(|| ManagerError::Protocol("host missing registered DeviceCert".into()))?;
        let (_sec, deleg) = self.identity.ensure_delegation(now_unix_secs())?;
        let reg_req = SignalingRegisterReq {
            device_cert: cert,
            delegation: deleg,
            presence: PresenceState::Online,
            cap_bits: self.cap_bits,
            home_region: self.config.home_region.clone(),
            ver_major: u32::from(VER_MAJOR),
            ver_minor: u32::from(VER_MINOR),
        };
        let (sig, resp) = SignalingSession::connect_and_register(
            &self.config.signaling_addr,
            &reg_req,
            Duration::from_secs(10),
        )
        .await?;
        self.heartbeat_interval = Duration::from_secs(u64::from(resp.heartbeat_interval_sec.clamp(5, 60)));
        self.backoff.reset();
        self.signaling = Some(sig);
        self.callbacks.emit_state(V2SessionState::Online);
        Ok(())
    }

    /// Waits online for the next verified `ConnectOffer`, binds Edge B, replies `ConnectAccept`,
    /// completes mandatory `Noise_IK` responder handshake, and returns an isolated
    /// `AcceptedHostSession`.
    pub async fn accept_next_session(
        &mut self,
        stop_flag: Arc<AtomicBool>,
        wait_timeout: Option<Duration>,
    ) -> Result<AcceptedHostSession, ManagerError> {
        let deadline = wait_timeout.and_then(|d| Instant::now().checked_add(d));
        let mut last_hb = Instant::now();

        loop {
            if stop_flag.load(Ordering::Acquire) {
                return Err(ManagerError::Stopped);
            }
            if let Some(dl) = deadline {
                if Instant::now() >= dl {
                    return Err(ClientError::Timeout("host waiting for ConnectOffer timed out".into()).into());
                }
            }

            if self.signaling.is_none() {
                let delay = self.backoff.next_delay();
                tokio::time::sleep(delay).await;
                if stop_flag.load(Ordering::Acquire) {
                    return Err(ManagerError::Stopped);
                }
                if let Err(e) = self.ensure_signaling_connected().await {
                    self.callbacks.emit_security_event(SecurityEvent::SignalingDisconnected {
                        reason: e.to_string(),
                    });
                    continue;
                }
                last_hb = Instant::now();
            }

            if last_hb.elapsed() >= self.heartbeat_interval {
                let hb = HeartbeatMsg {
                    device_id: self.identity.device_id(),
                    presence: PresenceState::Online,
                    client_unix: now_unix_secs(),
                    active_pop_id: self.config.edge_b.pop_id_bytes().ok(),
                    rtt_ms: 0,
                };
                if let Some(sig) = self.signaling.as_mut() {
                    if let Err(e) = sig.send_heartbeat(&hb).await {
                        self.callbacks.emit_security_event(SecurityEvent::SignalingDisconnected {
                            reason: format!("heartbeat send failed: {e}"),
                        });
                        self.signaling = None;
                        continue;
                    }
                }
                last_hb = Instant::now();
            }

            let poll_wait = Duration::from_millis(100);
            let recv_res = match self.signaling.as_mut() {
                Some(sig) => sig.recv_frame(poll_wait).await,
                None => continue,
            };

            match recv_res {
                Ok((SignalingMsgKind::ConnectOffer, payload)) => {
                    let offer = match SignalingConnectOffer::decode_pb(&payload) {
                        Ok(o) => o,
                        Err(e) => {
                            self.callbacks.emit_security_event(SecurityEvent::CertRejected {
                                reason: format!("malformed ConnectOffer: {e}"),
                            });
                            continue;
                        }
                    };
                    match self.handle_connect_offer(offer).await {
                        Ok(accepted) => return Ok(accepted),
                        Err(ManagerError::Rejected { .. }) => continue,
                        Err(e) => return Err(e),
                    }
                }
                Ok(_) => continue,
                Err(ClientError::Timeout(_)) => continue,
                Err(e) => {
                    self.callbacks.emit_security_event(SecurityEvent::SignalingDisconnected {
                        reason: format!("signaling recv failed: {e}"),
                    });
                    self.signaling = None;
                }
            }
        }
    }

    async fn send_reject(&mut self, session_id: [u8; 16], error_code: u16) {
        if let Some(sig) = self.signaling.as_mut() {
            let acc = SignalingConnectAccept {
                session_id,
                error_code: u32::from(error_code),
                controlled_cert: None,
                controlled_delegation: None,
                negotiated_l3_mtu: 0,
                negotiated_cap_bits: 0,
                negotiated_cipher_suite: 0,
                ice_candidates: Vec::new(),
                redirect: None,
            };
            let _ = sig.send_connect_accept(&acc).await;
        }
    }

    async fn handle_connect_offer(
        &mut self,
        offer: SignalingConnectOffer,
    ) -> Result<AcceptedHostSession, ManagerError> {
        if !self.seen_sessions.mark_if_new(offer.session_id) {
            self.callbacks.emit_security_event(SecurityEvent::ReplaySessionRejected {
                session_id: offer.session_id,
            });
            self.send_reject(offer.session_id, 0x0401).await;
            return Err(ManagerError::Rejected {
                error_code: 0x0401,
                reason: "duplicate session_id replay rejected".into(),
            });
        }

        let host_cert = self
            .identity
            .device_cert()
            .cloned()
            .ok_or_else(|| ManagerError::Protocol("host missing DeviceCert".into()))?;
        let Some(ctrl_cert) = offer.controller_cert else {
            self.send_reject(offer.session_id, 0x0201).await;
            return Err(ManagerError::Rejected {
                error_code: 0x0201,
                reason: "ConnectOffer missing controller_cert".into(),
            });
        };
        let Some(ctrl_deleg) = offer.controller_delegation else {
            self.send_reject(offer.session_id, 0x0203).await;
            return Err(ManagerError::Rejected {
                error_code: 0x0203,
                reason: "ConnectOffer missing controller_delegation".into(),
            });
        };
        let Some(ticket_b) = offer.relay_ticket else {
            self.send_reject(offer.session_id, 0x0301).await;
            return Err(ManagerError::Rejected {
                error_code: 0x0301,
                reason: "ConnectOffer missing relay_ticket".into(),
            });
        };

        let now_unix = now_unix_secs();
        if let Err((code, reason)) = verify_peer_cert_and_delegation(
            &ctrl_cert,
            &ctrl_deleg,
            &host_cert,
            None,
            &self.ca_spki_der,
            &mut self.delegation_cache,
            now_unix,
            &self.callbacks,
        ) {
            self.send_reject(offer.session_id, code).await;
            return Err(ManagerError::Rejected {
                error_code: code,
                reason,
            });
        }

        let peer_route = match PeerRouteCandidate::find_in_candidates(&offer.ice_candidates) {
            Ok(r) => r,
            Err(e) => {
                self.send_reject(offer.session_id, 0x0103).await;
                return Err(ManagerError::Rejected {
                    error_code: 0x0103,
                    reason: format!("invalid peer route candidate: {e}"),
                });
            }
        };

        let local_pop_b = self.config.edge_b.pop_id_bytes()?;
        if peer_route.pop_b != local_pop_b {
            self.send_reject(offer.session_id, 0x0502).await;
            return Err(ManagerError::Rejected {
                error_code: 0x0502,
                reason: "ConnectOffer pop_b does not match local edge_b".into(),
            });
        }

        let negotiated_cap_bits = offer.controller_cap_bits & self.cap_bits;
        if (negotiated_cap_bits & (CAP_CODEC_VP9 | CAP_CODEC_AV1)) == 0 {
            self.send_reject(offer.session_id, 0x0102).await;
            return Err(ManagerError::Rejected {
                error_code: 0x0102,
                reason: "no common video codec".into(),
            });
        }
        let negotiated_l3_mtu = if offer.proposed_l3_mtu == 0 {
            L3_MTU_DEFAULT
        } else {
            (offer.proposed_l3_mtu as usize).clamp(512, L3_MTU_DEFAULT)
        };

        let incoming = IncomingCall {
            session_id: offer.session_id,
            controller_device_id: ctrl_cert.device_id,
            tenant_id: ctrl_cert.tenant_id,
            proposed_l3_mtu: negotiated_l3_mtu as u32,
            controller_cap_bits: offer.controller_cap_bits,
            peer_route: peer_route.clone(),
        };
        match self
            .callbacks
            .ask_incoming_call(incoming, INCOMING_CALL_DECISION_TIMEOUT)
            .await
        {
            CallDecision::Accept => {}
            CallDecision::Reject { error_code, reason } => {
                self.send_reject(offer.session_id, error_code).await;
                return Err(ManagerError::Rejected { error_code, reason });
            }
        }

        self.callbacks.emit_state(V2SessionState::Handshaking);
        let (x25519_priv_host, host_deleg) = self.identity.ensure_delegation(now_unix_secs())?;

        let edge_b_pub = self.config.edge_b.x25519_pub()?;
        let edge_b_hash = self.config.edge_b.edge_cert_hash()?;
        let mut ctrl_b = AccessControlTunnel::connect(
            &self.config.edge_b.ctrl_addr,
            &x25519_priv_host,
            &edge_b_pub,
            &local_pop_b,
            &edge_b_hash,
            Duration::from_secs(5),
        )
        .await?;
        let (bind_b, keys_b) = ctrl_b
            .relay_bind(&ticket_b, &peer_route.cid_a, &peer_route.pop_a)
            .await?;
        if bind_b.route_cid != peer_route.cid_b {
            return Err(ManagerError::Protocol(
                "Edge B RelayBindResp route_cid mismatch".into(),
            ));
        }

        let mut udp_b =
            UdpAccessLink::connect(&self.config.edge_b.udp_addr, &keys_b, peer_route.bw_cap_kbps)
                .await?;
        let _ = udp_b.ping_with_retry(3, Duration::from_secs(1)).await?;

        // Send ConnectAccept over signaling BEFORE entering Noise_IK responder so Controller
        // immediately receives Host's CA-verified cert & delegation and sends IK msg1.
        let accept = SignalingConnectAccept {
            session_id: offer.session_id,
            error_code: 0,
            controlled_cert: Some(host_cert.clone()),
            controlled_delegation: Some(host_deleg),
            negotiated_l3_mtu: negotiated_l3_mtu as u32,
            negotiated_cap_bits,
            negotiated_cipher_suite: u32::from(CIPHER_AESGCM),
            ice_candidates: vec![peer_route.encode()?],
            redirect: None,
        };
        if let Some(sig) = self.signaling.as_mut() {
            sig.send_connect_accept(&accept).await?;
        } else {
            return Err(ManagerError::Protocol(
                "signaling disconnected before ConnectAccept could be sent".into(),
            ));
        }

        let edge_a_hash = self
            .config
            .edge_for_pop(&peer_route.pop_a)
            .map(|e| e.edge_cert_hash())
            .transpose()?
            .unwrap_or([0u8; 32]);
        let prologue_input = PrologueInput {
            ver_major_minor: VER_MAJOR_MINOR,
            handshake_pattern: PATTERN_IK,
            cipher_suite: CIPHER_AESGCM,
            transport_mode: TRANSPORT_MODE_RELAY_UDP,
            device_id_ctrl: ctrl_cert.device_id,
            device_id_host: host_cert.device_id,
            ctrl_devcert_tbs_sha256: ctrl_cert.to_tbs_sha256()?,
            host_devcert_tbs_sha256: host_cert.to_tbs_sha256()?,
            policy_hash: host_cert.policy_hash,
            edge_cert_tbs_sha256_or_zero: edge_a_hash,
            negotiated_cap_bits,
            session_id: offer.session_id,
        };
        let policy = build_verified_policy_from_cert(&host_cert, peer_route.bw_cap_kbps);

        let (e2ee_session, hs_out) = UdpE2eeSession::handshake_responder(
            udp_b,
            &prologue_input,
            &x25519_priv_host,
            &ctrl_deleg,
            &ctrl_cert.device_id,
            &ctrl_cert.p256_pub_der,
            ctrl_cert.exp_unix,
            now_unix_secs(),
            policy.clone(),
            host_cert.device_id,
            negotiated_l3_mtu,
            Duration::from_secs(10),
        )
        .await?;
        if hs_out.remote_static_x25519 != ctrl_deleg.x25519_pub {
            return Err(ManagerError::Protocol(
                "Noise_IK responder remote static X25519 mismatch".into(),
            ));
        }

        self.callbacks.emit_capabilities(policy.clone());
        self.callbacks.emit_state(V2SessionState::Streaming);

        Ok(AcceptedHostSession {
            session_id: offer.session_id,
            peer_device_id: ctrl_cert.device_id,
            tenant_id: host_cert.tenant_id,
            e2ee_session,
            ctrl_tunnel_b: ctrl_b,
            hs_hash: *hs_out.hs_hash,
            policy,
            peer_route,
            negotiated_cap_bits,
            negotiated_l3_mtu,
        })
    }
}

/// Active Controller session established via real `v2-signaling` + CA cert verification + `Noise_IK`
/// initiator + background `spec/06` (`<= 15s`) `LeaseRenewalTask`.
pub struct ConnectedControllerSession {
    pub session_id: [u8; 16],
    pub target_device_id: [u8; 16],
    pub tenant_id: [u8; 16],
    pub e2ee_session: UdpE2eeSession,
    pub lease_renewal: LeaseRenewalTask,
    pub hs_hash: [u8; 32],
    pub policy: VerifiedTenantPolicy,
    pub peer_route: PeerRouteCandidate,
    pub negotiated_cap_bits: u64,
    pub negotiated_l3_mtu: usize,
    pub keepalive_interval: Duration,
}

/// Production Controller client: registers with Control Plane + `v2-signaling`, acquires relay
/// leases, dials target device by `device_id` (ZERO `rendezvous.json`), verifies Host CA cert &
/// delegation, executes mandatory `Noise_IK` initiator handshake, and launches 15s `LeaseRenewalTask`.
pub struct DesktopControllerClient {
    config: V2ClientConfig,
    cp: ControlPlaneClient,
    identity: PersistentV2Identity,
    ca_spki_der: Vec<u8>,
    cap_bits: u64,
    callbacks: UiCallbackDispatcher,
    delegation_cache: DelegationCache,
    signaling: Option<SignalingSession>,
}

impl DesktopControllerClient {
    pub async fn bootstrap(
        config: V2ClientConfig,
        callbacks: UiCallbackDispatcher,
    ) -> Result<Self, ManagerError> {
        config.validate()?;
        callbacks.emit_state(V2SessionState::Registering);

        let cp = ControlPlaneClient::new(
            &config.control_plane_endpoint,
            config.ca_der_path.as_deref(),
        )?;
        cp.healthz().await?;
        let ca_spki_der = cp.get_ca_pubkey().await?.spki_der()?;

        let mut identity = PersistentV2Identity::load_or_create(&config.identity_dir)?;
        let cert = identity
            .ensure_registered(
                &cp,
                &ca_spki_der,
                config.enrollment_token.as_deref(),
                DEFAULT_V2_CAP_BITS,
                &config.home_region,
            )
            .await?;
        let (_sec, deleg) = identity.ensure_delegation(now_unix_secs())?;

        let reg_req = SignalingRegisterReq {
            device_cert: cert,
            delegation: deleg,
            presence: PresenceState::Online,
            cap_bits: DEFAULT_V2_CAP_BITS,
            home_region: config.home_region.clone(),
            ver_major: u32::from(VER_MAJOR),
            ver_minor: u32::from(VER_MINOR),
        };
        let (sig, _resp) = SignalingSession::connect_and_register(
            &config.signaling_addr,
            &reg_req,
            Duration::from_secs(10),
        )
        .await?;
        callbacks.emit_state(V2SessionState::Online);

        Ok(Self {
            config,
            cp,
            identity,
            ca_spki_der,
            cap_bits: DEFAULT_V2_CAP_BITS,
            callbacks,
            delegation_cache: DelegationCache::new(),
            signaling: Some(sig),
        })
    }

    pub fn device_id(&self) -> [u8; 16] {
        self.identity.device_id()
    }

    pub fn tenant_id(&self) -> Option<[u8; 16]> {
        self.identity.tenant_id()
    }

    pub fn take_signaling(&mut self) -> Option<SignalingSession> {
        self.signaling.take()
    }

    pub async fn dial(
        &mut self,
        target_device_id: [u8; 16],
        expected_tenant_id: Option<[u8; 16]>,
        connect_timeout: Duration,
    ) -> Result<ConnectedControllerSession, ManagerError> {
        self.callbacks.emit_state(V2SessionState::Connecting);
        let ctrl_cert = self
            .identity
            .device_cert()
            .cloned()
            .ok_or_else(|| ManagerError::Protocol("controller missing DeviceCert".into()))?;
        if let Some(expected_tid) = expected_tenant_id {
            if ctrl_cert.tenant_id != expected_tid {
                self.callbacks.emit_security_event(SecurityEvent::TenantMismatch {
                    expected: expected_tid,
                    actual: ctrl_cert.tenant_id,
                });
                return Err(ManagerError::Rejected {
                    error_code: 0x0401,
                    reason: "controller DeviceCert tenant_id does not match expected tenant_id"
                        .into(),
                });
            }
        }

        let (x25519_priv_ctrl, ctrl_deleg) = self.identity.ensure_delegation(now_unix_secs())?;
        let session_id = random_bytes::<16>();
        let cid_a = random_bytes::<8>();
        let cid_b = random_bytes::<8>();
        let pop_a = self.config.edge_a.pop_id_bytes()?;
        let pop_b = self.config.edge_b.pop_id_bytes()?;

        let lease_a = self
            .cp
            .issue_lease(
                self.identity.keystore(),
                Some(&ctrl_cert.tenant_id),
                &session_id,
                &cid_a,
                &pop_a,
                &ctrl_cert.device_id,
                &target_device_id,
                1,
            )
            .await?;
        let lease_b = self
            .cp
            .renew_lease(
                self.identity.keystore(),
                Some(&ctrl_cert.tenant_id),
                &session_id,
                &cid_b,
                &pop_b,
                &ctrl_cert.device_id,
                &target_device_id,
                lease_a.lease_seq,
                0,
                1,
            )
            .await?;
        let ticket_a = lease_a.to_relay_ticket()?;
        let ticket_b = lease_b.to_relay_ticket()?;

        let edge_a_pub = self.config.edge_a.x25519_pub()?;
        let edge_a_hash = self.config.edge_a.edge_cert_hash()?;
        let mut ctrl_a = AccessControlTunnel::connect(
            &self.config.edge_a.ctrl_addr,
            &x25519_priv_ctrl,
            &edge_a_pub,
            &pop_a,
            &edge_a_hash,
            Duration::from_secs(5),
        )
        .await?;
        let (bind_a, keys_a) = ctrl_a.relay_bind(&ticket_a, &cid_b, &pop_b).await?;
        if bind_a.route_cid != cid_a {
            return Err(ManagerError::Protocol(
                "Edge A RelayBindResp route_cid mismatch".into(),
            ));
        }

        let mut udp_a =
            UdpAccessLink::connect(&self.config.edge_a.udp_addr, &keys_a, lease_a.bw_cap_kbps)
                .await?;
        let _ = udp_a.ping_with_retry(3, Duration::from_secs(1)).await?;

        let peer_route = PeerRouteCandidate {
            pop_a,
            cid_a,
            pop_b,
            cid_b,
            bw_cap_kbps: lease_b.bw_cap_kbps.max(256),
        };
        let connect_req = SignalingConnectReq {
            session_id,
            controller_device_id: ctrl_cert.device_id,
            controlled_device_id: target_device_id,
            controller_cert: Some(ctrl_cert.clone()),
            controller_delegation: Some(ctrl_deleg),
            proposed_l3_mtu: L3_MTU_DEFAULT as u32,
            cap_bits: self.cap_bits,
            preferred_cipher_suite: u32::from(CIPHER_AESGCM),
            requested_exhaust_policy: 0,
            relay_ticket: Some(ticket_b),
            ice_candidates: vec![peer_route.encode()?],
        };

        let sig = self
            .signaling
            .as_mut()
            .ok_or_else(|| ManagerError::Protocol("controller signaling session not connected".into()))?;
        sig.send_connect_req(&connect_req).await?;

        let deadline = Instant::now() + connect_timeout;
        let accept = loop {
            let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                return Err(ClientError::Timeout("timed out awaiting ConnectAccept".into()).into());
            };
            let (kind, payload) = sig.recv_frame(rem).await?;
            if kind != SignalingMsgKind::ConnectAccept {
                continue;
            }
            let acc = SignalingConnectAccept::decode_pb(&payload)?;
            if acc.session_id != session_id {
                continue;
            }
            break acc;
        };

        if accept.error_code != 0 {
            return Err(ManagerError::Rejected {
                error_code: accept.error_code as u16,
                reason: format!(
                    "target rejected ConnectReq with error_code={:#06x}",
                    accept.error_code
                ),
            });
        }
        let host_cert = accept.controlled_cert.ok_or_else(|| {
            ManagerError::Protocol("ConnectAccept missing controlled_cert".into())
        })?;
        let host_deleg = accept.controlled_delegation.ok_or_else(|| {
            ManagerError::Protocol("ConnectAccept missing controlled_delegation".into())
        })?;

        let now_unix = now_unix_secs();
        if let Err((code, reason)) = verify_peer_cert_and_delegation(
            &host_cert,
            &host_deleg,
            &ctrl_cert,
            Some(target_device_id),
            &self.ca_spki_der,
            &mut self.delegation_cache,
            now_unix,
            &self.callbacks,
        ) {
            return Err(ManagerError::Rejected {
                error_code: code,
                reason,
            });
        }

        let negotiated_cap_bits = accept.negotiated_cap_bits;
        if (negotiated_cap_bits & !self.cap_bits) != 0
            || (negotiated_cap_bits & (CAP_CODEC_VP9 | CAP_CODEC_AV1)) == 0
        {
            return Err(ManagerError::Protocol(format!(
                "invalid negotiated_cap_bits={negotiated_cap_bits:#x}"
            )));
        }
        let negotiated_l3_mtu = if accept.negotiated_l3_mtu == 0 {
            L3_MTU_DEFAULT
        } else {
            (accept.negotiated_l3_mtu as usize).clamp(512, L3_MTU_DEFAULT)
        };

        self.callbacks.emit_state(V2SessionState::Handshaking);
        let prologue_input = PrologueInput {
            ver_major_minor: VER_MAJOR_MINOR,
            handshake_pattern: PATTERN_IK,
            cipher_suite: CIPHER_AESGCM,
            transport_mode: TRANSPORT_MODE_RELAY_UDP,
            device_id_ctrl: ctrl_cert.device_id,
            device_id_host: host_cert.device_id,
            ctrl_devcert_tbs_sha256: ctrl_cert.to_tbs_sha256()?,
            host_devcert_tbs_sha256: host_cert.to_tbs_sha256()?,
            policy_hash: host_cert.policy_hash,
            edge_cert_tbs_sha256_or_zero: edge_a_hash,
            negotiated_cap_bits,
            session_id,
        };
        let policy = build_verified_policy_from_cert(&host_cert, peer_route.bw_cap_kbps);

        let (e2ee_session, hs_out) = UdpE2eeSession::handshake_initiator(
            udp_a,
            &prologue_input,
            &x25519_priv_ctrl,
            &host_deleg.x25519_pub,
            &host_deleg,
            &host_cert.device_id,
            &host_cert.p256_pub_der,
            host_cert.exp_unix,
            now_unix_secs(),
            policy.clone(),
            ctrl_cert.device_id,
            negotiated_l3_mtu,
            Duration::from_secs(10),
        )
        .await?;
        if hs_out.remote_static_x25519 != host_deleg.x25519_pub {
            return Err(ManagerError::Protocol(
                "Noise_IK initiator remote static X25519 mismatch".into(),
            ));
        }

        // Clone P-256 signing key into Arc<dyn DeviceKeyStore> for background 15s LeaseRenewalTask.
        let pkcs8 = self.identity.keystore().to_pkcs8_der().map_err(IdentityStoreError::from)?;
        let renew_ks: Arc<dyn DeviceKeyStore> =
            Arc::new(SoftwareDeviceKeyStore::from_pkcs8_der(&pkcs8).map_err(IdentityStoreError::from)?);
        let lease_renewal = LeaseRenewalTask::spawn(
            LeaseRenewalConfig {
                cp: self.cp.clone(),
                keystore: renew_ks,
                tenant_id: Some(ctrl_cert.tenant_id),
                session_id,
                controller_device_id: ctrl_cert.device_id,
                controlled_device_id: host_cert.device_id,
                initial_lease_seq: lease_b.lease_seq,
                key_id: 1,
                renew_interval: Duration::from_secs(self.config.lease_renew_interval_sec),
            },
            vec![LeaseRenewalLeg {
                tunnel: ctrl_a,
                route_cid: cid_a,
                pop_id: pop_a,
            }],
        )?;

        self.callbacks.emit_capabilities(policy.clone());
        self.callbacks.emit_state(V2SessionState::Streaming);

        Ok(ConnectedControllerSession {
            session_id,
            target_device_id: host_cert.device_id,
            tenant_id: ctrl_cert.tenant_id,
            e2ee_session,
            lease_renewal,
            hs_hash: *hs_out.hs_hash,
            policy,
            peer_route,
            negotiated_cap_bits,
            negotiated_l3_mtu,
            keepalive_interval: Duration::from_millis(self.config.keepalive_interval_ms),
        })
    }
}

/// Unified UI/FFI-ready session manager facade exposing both Host Daemon and Controller Client.
pub struct V2SessionManager {
    config: V2ClientConfig,
    dispatcher: UiCallbackDispatcher,
    state: Arc<Mutex<V2SessionState>>,
    last_qoe: Arc<Mutex<QoeSnapshot>>,
}

impl V2SessionManager {
    pub fn new(
        config: V2ClientConfig,
        callback: Arc<dyn V2UiCallback>,
    ) -> Result<Self, ManagerError> {
        config.validate()?;
        Ok(Self {
            config,
            dispatcher: UiCallbackDispatcher::spawn(callback),
            state: Arc::new(Mutex::new(V2SessionState::Idle)),
            last_qoe: Arc::new(Mutex::new(QoeSnapshot::default())),
        })
    }

    pub fn config(&self) -> &V2ClientConfig {
        &self.config
    }

    pub fn dispatcher(&self) -> UiCallbackDispatcher {
        self.dispatcher.clone()
    }

    pub fn state(&self) -> V2SessionState {
        self.state
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn set_state(&self, state: V2SessionState) {
        {
            let mut g = self.state.lock().unwrap_or_else(|e| e.into_inner());
            *g = state.clone();
        }
        self.dispatcher.emit_state(state);
    }

    pub fn qoe(&self) -> QoeSnapshot {
        self.last_qoe
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub fn update_qoe(&self, snapshot: QoeSnapshot) {
        {
            let mut g = self.last_qoe.lock().unwrap_or_else(|e| e.into_inner());
            *g = snapshot.clone();
        }
        self.dispatcher.emit_qoe(snapshot);
    }

    pub async fn start_host_daemon(&self) -> Result<DesktopHostDaemon, ManagerError> {
        DesktopHostDaemon::bootstrap(self.config.clone(), self.dispatcher.clone()).await
    }

    pub async fn start_controller_client(&self) -> Result<DesktopControllerClient, ManagerError> {
        DesktopControllerClient::bootstrap(self.config.clone(), self.dispatcher.clone()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    struct RecordingCallback {
        states: Mutex<Vec<V2SessionState>>,
        security_events: Mutex<Vec<SecurityEvent>>,
        qoe_count: AtomicUsize,
        accept_calls: bool,
    }

    impl RecordingCallback {
        fn new(accept_calls: bool) -> Self {
            Self {
                states: Mutex::new(Vec::new()),
                security_events: Mutex::new(Vec::new()),
                qoe_count: AtomicUsize::new(0),
                accept_calls,
            }
        }
    }

    impl V2UiCallback for RecordingCallback {
        fn on_frame(&self, _frame: Arc<I420Frame>) {}
        fn on_state(&self, state: V2SessionState) {
            self.states.lock().unwrap().push(state);
        }
        fn on_qoe(&self, _snapshot: QoeSnapshot) {
            self.qoe_count.fetch_add(1, Ordering::SeqCst);
        }
        fn on_capabilities(&self, _caps: VerifiedTenantPolicy) {}
        fn on_incoming_call(&self, _call: IncomingCall, reply: oneshot::Sender<CallDecision>) {
            if self.accept_calls {
                let _ = reply.send(CallDecision::Accept);
            } else {
                let _ = reply.send(CallDecision::Reject {
                    error_code: 0x0401,
                    reason: "declined".into(),
                });
            }
        }
        fn on_security_event(&self, event: SecurityEvent) {
            self.security_events.lock().unwrap().push(event);
        }
    }

    #[test]
    fn seen_session_cache_dedups_replays_and_bounds_memory() {
        let mut cache = SeenSessionCache::new(3);
        let s1 = [1u8; 16];
        let s2 = [2u8; 16];
        let s3 = [3u8; 16];
        let s4 = [4u8; 16];
        assert!(cache.mark_if_new(s1));
        assert!(!cache.mark_if_new(s1));
        assert!(cache.mark_if_new(s2));
        assert!(cache.mark_if_new(s3));
        // Adding s4 evicts s1
        assert!(cache.mark_if_new(s4));
        assert!(!cache.mark_if_new(s2));
        assert!(cache.mark_if_new(s1));
    }

    #[tokio::test]
    async fn verify_peer_cert_enforces_ca_same_tenant_and_anti_rollback() {
        let cb = Arc::new(RecordingCallback::new(true));
        let disp = UiCallbackDispatcher::spawn(Arc::clone(&cb) as Arc<dyn V2UiCallback>);
        let ca = SoftwareDeviceKeyStore::generate();
        let ca_spki = ca.public_key_spki_der().unwrap();
        let dev_a = SoftwareDeviceKeyStore::generate();
        let dev_b = SoftwareDeviceKeyStore::generate();
        let now = now_unix_secs();

        let make_cert = |dev_id: [u8; 16], tid: [u8; 16], ks: &SoftwareDeviceKeyStore| {
            let mut c = SignalingDeviceCert {
                version: 1,
                cert_id: random_bytes::<16>(),
                device_id: dev_id,
                tenant_id: tid,
                p256_pub_der: ks.public_key_spki_der().unwrap(),
                key_epoch: 1,
                policy_hash: [0x55; 32],
                cap_bits: DEFAULT_V2_CAP_BITS,
                iat_unix: now.saturating_sub(10),
                exp_unix: now.saturating_add(3600),
                ca_key_id: 1,
                ca_sig: Vec::new(),
            };
            c.ca_sig = ca.sign_p256_low_s(&c.to_tbs_bytes().unwrap()).unwrap();
            c
        };

        let cert_a = make_cert([0xAA; 16], [0x11; 16], &dev_a);
        let cert_b_same = make_cert([0xBB; 16], [0x11; 16], &dev_b);
        let cert_b_cross = make_cert([0xBB; 16], [0x22; 16], &dev_b);

        let mut rot = v2_identity::X25519StaticKeyRotator::new([0xBB; 16], false, 0);
        let d1 = rot
            .rotate_now(&dev_b, now, cert_b_same.exp_unix)
            .unwrap()
            .delegation
            .clone();
        let d2 = rot
            .rotate_now(&dev_b, now, cert_b_same.exp_unix)
            .unwrap()
            .delegation
            .clone();

        let mut cache = DelegationCache::new();
        // Same tenant succeeds
        verify_peer_cert_and_delegation(
            &cert_b_same,
            &d2,
            &cert_a,
            Some([0xBB; 16]),
            &ca_spki,
            &mut cache,
            now,
            &disp,
        )
        .unwrap();

        // Rollback delegation_seq (d1 < d2) MUST fail closed with 0x0203
        let rb = verify_peer_cert_and_delegation(
            &cert_b_same,
            &d1,
            &cert_a,
            Some([0xBB; 16]),
            &ca_spki,
            &mut cache,
            now,
            &disp,
        );
        assert_eq!(rb.unwrap_err().0, 0x0203);

        // Cross-tenant MUST fail closed with 0x0401
        let xt = verify_peer_cert_and_delegation(
            &cert_b_cross,
            &d2,
            &cert_a,
            Some([0xBB; 16]),
            &ca_spki,
            &mut cache,
            now,
            &disp,
        );
        assert_eq!(xt.unwrap_err().0, 0x0401);

        // Dispatcher delivers security events & call decision asynchronously
        let decision = disp
            .ask_incoming_call(
                IncomingCall {
                    session_id: [0x99; 16],
                    controller_device_id: [0xAA; 16],
                    tenant_id: [0x11; 16],
                    proposed_l3_mtu: 1200,
                    controller_cap_bits: DEFAULT_V2_CAP_BITS,
                    peer_route: PeerRouteCandidate {
                        pop_a: *b"edge-a01",
                        cid_a: [1; 8],
                        pop_b: *b"edge-b02",
                        cid_b: [2; 8],
                        bw_cap_kbps: 10_000,
                    },
                },
                Duration::from_secs(1),
            )
            .await;
        assert_eq!(decision, CallDecision::Accept);
        assert!(cb
            .security_events
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, SecurityEvent::TenantMismatch { .. })));
    }

    #[tokio::test]
    async fn signaling_drop_mid_session_has_zero_effect_on_active_media_and_hid() {
        use crate::v2_session::{
            hid::{HidPayload, MouseEvent, MouseKind},
            session::{DesktopControllerSession, DesktopHostSession},
            video::{generate_animated_i420, V2VideoDecoder, V2VideoEncoder, VideoCodec},
        };
        use tokio::{
            io::{AsyncReadExt, AsyncWriteExt},
            net::{TcpListener, UdpSocket},
        };
        use v2_client::{
            encode_signaling_frame, AccessKeys, SignalingRegisterResp, UdpAccessLink,
        };
        use v2_transport::{
            seal_udp_v11, AccessEpochState, AccessFlags, AccessHeaderV11, DIR_CLIENT_TO_EDGE,
            DIR_EDGE_TO_CLIENT, TRANSPORT_DATAGRAM, UDP_MAX_LEN,
        };

        // 1. Establish a real SignalingSession and then drop it abruptly mid-session.
        let sig_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sig_addr = sig_listener.local_addr().unwrap();
        let ca = SoftwareDeviceKeyStore::generate();
        let dev = SoftwareDeviceKeyStore::generate();
        let now = now_unix_secs();
        let mut cert = SignalingDeviceCert {
            version: 1,
            cert_id: [1; 16],
            device_id: [2; 16],
            tenant_id: [3; 16],
            p256_pub_der: dev.public_key_spki_der().unwrap(),
            key_epoch: 1,
            policy_hash: [4; 32],
            cap_bits: DEFAULT_V2_CAP_BITS,
            iat_unix: now.saturating_sub(10),
            exp_unix: now.saturating_add(3600),
            ca_key_id: 1,
            ca_sig: Vec::new(),
        };
        cert.ca_sig = ca.sign_p256_low_s(&cert.to_tbs_bytes().unwrap()).unwrap();
        let mut rot = v2_identity::X25519StaticKeyRotator::new([2; 16], false, 0);
        let deleg = rot
            .ensure_current(&dev, now, cert.exp_unix)
            .unwrap()
            .delegation
            .clone();

        let sig_srv = tokio::spawn(async move {
            let (mut sock, _) = sig_listener.accept().await.unwrap();
            let mut len_buf = [0u8; 4];
            sock.read_exact(&mut len_buf).await.unwrap();
            let total = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; total];
            sock.read_exact(&mut body).await.unwrap();
            let resp = SignalingRegisterResp {
                error_code: 0,
                server_unix: now,
                redirect: None,
                heartbeat_interval_sec: 15,
            };
            let wire =
                encode_signaling_frame(SignalingMsgKind::RegisterResp, &resp.encode_pb()).unwrap();
            sock.write_all(&wire).await.unwrap();
            sock.flush().await.unwrap();
            // Abruptly close server-side signaling socket!
            drop(sock);
        });

        let reg_req = SignalingRegisterReq {
            device_cert: cert.clone(),
            delegation: deleg,
            presence: PresenceState::Online,
            cap_bits: DEFAULT_V2_CAP_BITS,
            home_region: "local".into(),
            ver_major: 2,
            ver_minor: 1,
        };
        let (mut sig_sess, _resp) = SignalingSession::connect_and_register(
            &sig_addr.to_string(),
            &reg_req,
            Duration::from_secs(2),
        )
        .await
        .unwrap();
        sig_srv.await.unwrap();
        // Verify signaling connection is genuinely dead (EOF).
        assert!(sig_sess.recv_frame(Duration::from_millis(200)).await.is_err());
        drop(sig_sess);

        // 2. Active UDP E2EE media/HID session continues unaffected!
        let edge_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let edge_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cid_a = [0xA1; 8];
        let cid_b = [0xB2; 8];
        let hs_a = [0x33; 32];
        let hs_b = [0x44; 32];
        let link_ctrl = UdpAccessLink::connect(
            &edge_a.local_addr().unwrap().to_string(),
            &AccessKeys::derive(cid_a, hs_a, 1).unwrap(),
            50_000,
        )
        .await
        .unwrap();
        let link_host = UdpAccessLink::connect(
            &edge_b.local_addr().unwrap().to_string(),
            &AccessKeys::derive(cid_b, hs_b, 1).unwrap(),
            50_000,
        )
        .await
        .unwrap();
        let ctrl_local = link_ctrl.local_addr().unwrap();
        let host_local = link_host.local_addr().unwrap();

        let mut rx_a =
            AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 1, 20)
                .unwrap();
        let tx_a =
            AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 1, 20)
                .unwrap();
        let mut rx_b =
            AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 1, 20)
                .unwrap();
        let tx_b =
            AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 1, 20)
                .unwrap();

        let relay = tokio::spawn(async move {
            let mut ba = [0u8; UDP_MAX_LEN + 64];
            let mut bb = [0u8; UDP_MAX_LEN + 64];
            let mut sh = 1u32;
            let mut sc = 1u32;
            loop {
                tokio::select! {
                    r = edge_a.recv(&mut ba) => {
                        let Ok(n) = r else { break; };
                        let Ok((hdr, payload)) = rx_a.verify_udp_packet(&ba[..n], 0) else { continue; };
                        let fh = AccessHeaderV11 {
                            flags: AccessFlags { pp: hdr.flags.pp, discardable: hdr.flags.discardable, frame_end: hdr.flags.frame_end, is_ctrl_edge: false, dir_edge_to_client: true, rtx: false },
                            route_cid: cid_b, access_epoch: tx_b.cur_epoch(), leg_seq: sh, mac_64: [0; 8],
                        };
                        sh = sh.wrapping_add(1);
                        if let Ok(w) = seal_udp_v11(tx_b.cur_key(), fh, payload) {
                            let _ = edge_b.send_to(&w, host_local).await;
                        }
                    }
                    r = edge_b.recv(&mut bb) => {
                        let Ok(n) = r else { break; };
                        let Ok((hdr, payload)) = rx_b.verify_udp_packet(&bb[..n], 0) else { continue; };
                        let fh = AccessHeaderV11 {
                            flags: AccessFlags { pp: hdr.flags.pp, discardable: hdr.flags.discardable, frame_end: hdr.flags.frame_end, is_ctrl_edge: false, dir_edge_to_client: true, rtx: false },
                            route_cid: cid_a, access_epoch: tx_a.cur_epoch(), leg_seq: sc, mac_64: [0; 8],
                        };
                        sc = sc.wrapping_add(1);
                        if let Ok(w) = seal_udp_v11(tx_a.cur_key(), fh, payload) {
                            let _ = edge_a.send_to(&w, ctrl_local).await;
                        }
                    }
                }
            }
        });

        let policy = build_verified_policy_from_cert(&cert, 50_000);
        let mut ctrl = DesktopControllerSession::new(
            UdpE2eeSession::from_keys(link_ctrl, [0x55; 32], [0x66; 32], policy.clone(), [1; 16]),
            V2VideoDecoder::new(VideoCodec::Vp9).unwrap(),
        );
        let mut host = DesktopHostSession::new(
            UdpE2eeSession::from_keys(link_host, [0x66; 32], [0x55; 32], policy, [2; 16]),
            V2VideoEncoder::new(VideoCodec::Vp9, 64, 64, 2.0, Some(30)).unwrap(),
        );

        let frame_pub = host
            .publish_i420_frame(Arc::new(generate_animated_i420(64, 64, 0)), 0)
            .await
            .unwrap();
        let delivered = ctrl
            .recv_and_decode_video(Duration::from_secs(3))
            .await
            .unwrap();
        assert_eq!(delivered.sha256, frame_pub.sha256);

        let mouse = HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveAbs,
            buttons: 0,
            x_or_dx: 32,
            y_or_dy: 32,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: 1000,
        });
        let (echo_res, host_res) = tokio::join!(
            ctrl.send_hid_and_await_echo(&mouse, 7, Duration::from_secs(3)),
            host.recv_hid_and_echo(7, Duration::from_secs(3)),
        );
        assert_eq!(echo_res.unwrap().0.echo_seq, 7);
        assert_eq!(host_res.unwrap(), mouse);
        relay.abort();
    }
}
