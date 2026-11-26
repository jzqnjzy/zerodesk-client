// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    capture::CapturePipelineHandle,
    config::{V2ConfigError, MAX_LEASE_RENEW_INTERVAL_SEC},
    input::{HidInputExecutor, HidInputSink},
    session::CTRL_MSG_SESSION_CLOSE,
};
use serde::{Deserialize, Serialize};
use std::{
    future::Future,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{sync::watch, task::JoinHandle};
use v2_client::{
    AccessControlTunnel, ClientError, ControlPlaneClient, SignalingSession, UdpE2eeSession,
};
use v2_identity::DeviceKeyStore;

pub const LEASE_RENEW_MAX_CONSECUTIVE_FAILURES: u32 = 3;
pub const LEASE_RENEW_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const SESSION_CLOSE_REDUNDANT_COUNT: usize = 3;
pub const SESSION_CLOSE_REDUNDANT_SPACING: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CloseReason {
    Normal,
    PeerClosed(u16),
    LeaseExpired,
    WatchdogTimeout,
    InputFaulted,
    InvalidFraming,
    Signal,
    IdleTimeout,
    ProtocolError(String),
}

impl CloseReason {
    pub fn wire_error_code(&self) -> u16 {
        match self {
            Self::Normal | Self::Signal | Self::IdleTimeout => 0x0000,
            Self::PeerClosed(code) => *code,
            Self::LeaseExpired => 0x0302,
            Self::WatchdogTimeout => 0x0502,
            Self::InputFaulted | Self::InvalidFraming => 0x0103,
            Self::ProtocolError(_) => 0x0103,
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Normal => "normal".into(),
            Self::PeerClosed(code) => format!("peer_closed:{code:#06x}"),
            Self::LeaseExpired => "lease_expired".into(),
            Self::WatchdogTimeout => "watchdog_timeout".into(),
            Self::InputFaulted => "input_faulted".into(),
            Self::InvalidFraming => "invalid_framing".into(),
            Self::Signal => "signal".into(),
            Self::IdleTimeout => "idle_timeout".into(),
            Self::ProtocolError(msg) => format!("protocol_error:{msg}"),
        }
    }
}

/// Real-time QoE and runtime telemetry snapshot delivered to UI callbacks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QoeSnapshot {
    pub fps: f64,
    pub decoded_frames: u64,
    pub dropped_frames: u64,
    pub stale_frames: u64,
    pub resync_frames: u64,
    pub idr_requests_sent: u64,
    pub encode_ms_p50: f64,
    pub encode_ms_p95: f64,
    pub lease_renewals_ok: u64,
    pub lease_renewals_err: u64,
    pub transport_mode: u8,
    pub rtt_ms: u64,
}

pub struct LeaseRenewalLeg {
    pub tunnel: AccessControlTunnel,
    pub route_cid: [u8; 8],
    pub pop_id: [u8; 8],
}

pub struct LeaseRenewalConfig {
    pub cp: ControlPlaneClient,
    pub keystore: Arc<dyn DeviceKeyStore>,
    pub tenant_id: Option<[u8; 16]>,
    pub session_id: [u8; 16],
    pub controller_device_id: [u8; 16],
    pub controlled_device_id: [u8; 16],
    pub initial_lease_seq: u64,
    pub key_id: u32,
    pub renew_interval: Duration,
}

/// Production `spec/06`-compliant (`<= 15s`) background `LeaseRenewReq` loop with
/// `MissedTickBehavior::Delay`, bounded 5s shutdown + abort, `(ok, err)` counters, and
/// 3-consecutive-failure fail-closed `CloseReason::LeaseExpired` shutdown trigger.
pub struct LeaseRenewalTask {
    stop_tx: watch::Sender<bool>,
    expired_rx: watch::Receiver<Option<CloseReason>>,
    task: Option<JoinHandle<()>>,
    renewals_ok: Arc<AtomicU64>,
    renewals_err: Arc<AtomicU64>,
}

impl LeaseRenewalTask {
    pub fn spawn(
        cfg: LeaseRenewalConfig,
        mut legs: Vec<LeaseRenewalLeg>,
    ) -> Result<Self, V2ConfigError> {
        let secs = cfg.renew_interval.as_secs();
        if cfg.renew_interval.is_zero() || secs > MAX_LEASE_RENEW_INTERVAL_SEC {
            return Err(V2ConfigError::InvalidValue(format!(
                "lease renewal interval {:?} must be in 1..={MAX_LEASE_RENEW_INTERVAL_SEC}s per spec/06",
                cfg.renew_interval
            )));
        }

        let (stop_tx, mut stop_rx) = watch::channel(false);
        let (expired_tx, expired_rx) = watch::channel(None);
        let renewals_ok = Arc::new(AtomicU64::new(0));
        let renewals_err = Arc::new(AtomicU64::new(0));
        let ok_task = Arc::clone(&renewals_ok);
        let err_task = Arc::clone(&renewals_err);

        let task = tokio::spawn(async move {
            let mut lease_seq = cfg.initial_lease_seq;
            let mut consecutive_failures = 0u32;
            let mut interval = tokio::time::interval(cfg.renew_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Consume immediate t=0 tick so first renewal runs after `renew_interval`.
            interval.tick().await;

            loop {
                tokio::select! {
                    biased;
                    res = stop_rx.changed() => {
                        if res.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        if legs.is_empty() {
                            break;
                        }
                        let mut tick_had_err = false;
                        for leg in &mut legs {
                            if *stop_rx.borrow() {
                                return;
                            }
                            let renew_res = cfg
                                .cp
                                .renew_lease(
                                    cfg.keystore.as_ref(),
                                    cfg.tenant_id.as_ref(),
                                    &cfg.session_id,
                                    &leg.route_cid,
                                    &leg.pop_id,
                                    &cfg.controller_device_id,
                                    &cfg.controlled_device_id,
                                    lease_seq,
                                    0,
                                    cfg.key_id,
                                )
                                .await;
                            match renew_res {
                                Ok(resp) => {
                                    lease_seq = resp.lease_seq;
                                    match resp.to_relay_ticket() {
                                        Ok(ticket) => match leg.tunnel.lease_renew(&ticket).await {
                                            Ok(_) => {
                                                ok_task.fetch_add(1, Ordering::Release);
                                            }
                                            Err(e) => {
                                                tick_had_err = true;
                                                err_task.fetch_add(1, Ordering::Release);
                                                eprintln!("[lease-renew] tunnel.lease_renew failed: {e}");
                                            }
                                        },
                                        Err(e) => {
                                            tick_had_err = true;
                                            err_task.fetch_add(1, Ordering::Release);
                                            eprintln!("[lease-renew] ticket decode failed: {e}");
                                        }
                                    }
                                }
                                Err(e) => {
                                    tick_had_err = true;
                                    err_task.fetch_add(1, Ordering::Release);
                                    eprintln!("[lease-renew] control-plane renew_lease failed: {e}");
                                }
                            }
                        }

                        if tick_had_err {
                            consecutive_failures = consecutive_failures.saturating_add(1);
                            if consecutive_failures >= LEASE_RENEW_MAX_CONSECUTIVE_FAILURES {
                                let _ = expired_tx.send(Some(CloseReason::LeaseExpired));
                                break;
                            }
                        } else {
                            consecutive_failures = 0;
                        }
                    }
                }
            }
        });

        Ok(Self {
            stop_tx,
            expired_rx,
            task: Some(task),
            renewals_ok,
            renewals_err,
        })
    }

    /// Generic async-driver constructor used by deterministic tests (and custom renewal hooks).
    pub fn spawn_with_fn<F, Fut>(renew_interval: Duration, mut renew_fn: F) -> Self
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send,
    {
        let (stop_tx, mut stop_rx) = watch::channel(false);
        let (expired_tx, expired_rx) = watch::channel(None);
        let renewals_ok = Arc::new(AtomicU64::new(0));
        let renewals_err = Arc::new(AtomicU64::new(0));
        let ok_task = Arc::clone(&renewals_ok);
        let err_task = Arc::clone(&renewals_err);

        let task = tokio::spawn(async move {
            let mut consecutive_failures = 0u32;
            let mut interval = tokio::time::interval(renew_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            interval.tick().await;

            loop {
                tokio::select! {
                    biased;
                    res = stop_rx.changed() => {
                        if res.is_err() || *stop_rx.borrow() {
                            break;
                        }
                    }
                    _ = interval.tick() => {
                        match renew_fn().await {
                            Ok(()) => {
                                consecutive_failures = 0;
                                ok_task.fetch_add(1, Ordering::Release);
                            }
                            Err(_) => {
                                err_task.fetch_add(1, Ordering::Release);
                                consecutive_failures = consecutive_failures.saturating_add(1);
                                if consecutive_failures >= LEASE_RENEW_MAX_CONSECUTIVE_FAILURES {
                                    let _ = expired_tx.send(Some(CloseReason::LeaseExpired));
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        Self {
            stop_tx,
            expired_rx,
            task: Some(task),
            renewals_ok,
            renewals_err,
        }
    }

    pub fn counts(&self) -> (u64, u64) {
        (
            self.renewals_ok.load(Ordering::Acquire),
            self.renewals_err.load(Ordering::Acquire),
        )
    }

    pub fn subscribe_expired(&self) -> watch::Receiver<Option<CloseReason>> {
        self.expired_rx.clone()
    }

    pub fn is_expired(&self) -> bool {
        self.expired_rx.borrow().is_some()
    }

    pub async fn shutdown(mut self) -> (u64, u64) {
        let _ = self.stop_tx.send(true);
        if let Some(mut handle) = self.task.take() {
            if tokio::time::timeout(LEASE_RENEW_SHUTDOWN_TIMEOUT, &mut handle)
                .await
                .is_err()
            {
                handle.abort();
                let _ = handle.await;
            }
        }
        self.counts()
    }
}

impl Drop for LeaseRenewalTask {
    fn drop(&mut self) {
        let _ = self.stop_tx.send(true);
        if let Some(handle) = self.task.take() {
            handle.abort();
        }
    }
}

/// Sends `0x04 SESSION_CLOSE(error_code)` 3× redundantly spaced by 20ms over P0 `TransportCtrl`.
pub async fn send_redundant_session_close_3x(
    session: &mut UdpE2eeSession,
    error_code: u16,
) -> Result<(), ClientError> {
    let mut first_err: Option<ClientError> = None;
    let mut sent_any = false;
    let payload = error_code.to_be_bytes();
    for attempt in 0..SESSION_CLOSE_REDUNDANT_COUNT {
        if attempt > 0 {
            tokio::time::sleep(SESSION_CLOSE_REDUNDANT_SPACING).await;
        }
        match session.send_control(CTRL_MSG_SESSION_CLOSE, &payload).await {
            Ok(_) => sent_any = true,
            Err(e) => {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
    }
    if sent_any {
        Ok(())
    } else if let Some(err) = first_err {
        Err(err)
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
pub struct OrderedTeardownReport {
    pub steps: Vec<&'static str>,
    pub lease_renewals_ok: u64,
    pub lease_renewals_err: u64,
    pub capture_joined: bool,
    pub session_close_sent: bool,
}

/// Strictly ordered production teardown sequence:
/// 1. `release_all` (HID safety first — zero stuck keys)
/// 2. Stop capture/encode pipeline
/// 3. 3× redundant `0x04 SESSION_CLOSE`
/// 4. Shutdown `LeaseRenewalTask` (bounded 5s + abort)
/// 5. Close data plane (`UdpE2eeSession`)
/// 6. Close signaling (`SignalingSession`, if owned by this teardown)
pub async fn ordered_session_teardown<S: HidInputSink>(
    mut executor: Option<&mut HidInputExecutor<S>>,
    mut capture: Option<CapturePipelineHandle>,
    mut data_plane: Option<UdpE2eeSession>,
    lease_renewal: Option<LeaseRenewalTask>,
    mut signaling: Option<SignalingSession>,
    reason: &CloseReason,
) -> OrderedTeardownReport {
    let mut report = OrderedTeardownReport::default();

    // 1. release_all
    if let Some(exec) = executor.as_mut() {
        let _ = exec.release_all(&reason.label());
        report.steps.push("release_all");
    }

    // 2. stop capture/encode
    if let Some(mut cap) = capture.take() {
        report.capture_joined = cap.stop_and_join().is_ok();
        report.steps.push("stop_capture");
    }

    // 3. 3x redundant 0x04 SESSION_CLOSE
    if let Some(sess) = data_plane.as_mut() {
        report.session_close_sent =
            send_redundant_session_close_3x(sess, reason.wire_error_code())
                .await
                .is_ok();
        report.steps.push("session_close_3x");
    }

    // 4. shutdown lease renewal
    if let Some(lr) = lease_renewal {
        let (ok, err) = lr.shutdown().await;
        report.lease_renewals_ok = ok;
        report.lease_renewals_err = err;
        report.steps.push("shutdown_lease_renewal");
    }

    // 5. close data plane
    if let Some(sess) = data_plane.take() {
        drop(sess);
        report.steps.push("close_data_plane");
    }

    // 6. close signaling
    if let Some(mut sig) = signaling.take() {
        let _ = sig.shutdown().await;
        drop(sig);
        report.steps.push("close_signaling");
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v2_session::input::DryRunSink;
    use std::sync::atomic::AtomicU32;

    #[tokio::test]
    async fn lease_renewal_triggers_fail_closed_after_3_consecutive_failures() {
        let attempt = Arc::new(AtomicU32::new(0));
        let attempt_c = Arc::clone(&attempt);
        // Sequence: Ok, Err, Ok (resets counter!), Err, Err, Err -> LeaseExpired!
        let task = LeaseRenewalTask::spawn_with_fn(Duration::from_millis(15), move || {
            let n = attempt_c.fetch_add(1, Ordering::SeqCst);
            async move {
                match n {
                    0 | 2 => Ok(()),
                    _ => Err("simulated lease failure".into()),
                }
            }
        });

        let mut exp_rx = task.subscribe_expired();
        tokio::time::timeout(Duration::from_secs(2), exp_rx.changed())
            .await
            .expect("lease renewal should trigger fail-closed LeaseExpired")
            .unwrap();
        assert_eq!(*exp_rx.borrow(), Some(CloseReason::LeaseExpired));
        let (ok, err) = task.shutdown().await;
        assert_eq!(ok, 2);
        assert_eq!(err, 4);
    }

    #[tokio::test]
    async fn ordered_teardown_executes_steps_in_strict_order() {
        let mut exec = HidInputExecutor::new(DryRunSink::new(), 640, 360).unwrap();
        let lr = LeaseRenewalTask::spawn_with_fn(Duration::from_secs(10), || async { Ok(()) });
        let report = ordered_session_teardown(
            Some(&mut exec),
            None,
            None,
            Some(lr),
            None,
            &CloseReason::Normal,
        )
        .await;
        assert_eq!(report.steps, vec!["release_all", "shutdown_lease_renewal"]);
    }
}
