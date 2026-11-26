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
    AccessControlTunnel, ActiveTransportMode, ClientError, ControlPlaneClient, SignalingSession,
    UdpE2eeSession,
};
use v2_identity::DeviceKeyStore;

pub const LEASE_RENEW_MAX_CONSECUTIVE_FAILURES: u32 = 3;
pub const LEASE_RENEW_CALL_TIMEOUT: Duration = Duration::from_secs(5);
pub const LEASE_RENEW_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);
pub const MAX_LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(MAX_LEASE_RENEW_INTERVAL_SEC);
pub const CAPTURE_JOIN_TIMEOUT: Duration = Duration::from_secs(2);
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_transport_mode: Option<ActiveTransportMode>,
    #[serde(default)]
    pub p3_dropped: u64,
    pub rtt_ms: u64,
}

pub struct LeaseRenewalLeg {
    pub tunnel: AccessControlTunnel,
    pub route_cid: [u8; 8],
    pub pop_id: [u8; 8],
    /// Independent monotonic `lease_seq` tracked per leg.
    pub lease_seq: u64,
}

pub struct LeaseRenewalConfig {
    pub cp: ControlPlaneClient,
    pub keystore: Arc<dyn DeviceKeyStore>,
    pub tenant_id: [u8; 16],
    pub session_id: [u8; 16],
    pub controller_device_id: [u8; 16],
    pub controlled_device_id: [u8; 16],
    pub key_id: u32,
    pub renew_interval: Duration,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeaseRenewalShutdown {
    pub renewals_ok: u64,
    pub renewals_err: u64,
    pub join_error: Option<String>,
}

fn validate_renew_interval(interval: Duration) -> Result<(), V2ConfigError> {
    if interval.is_zero() || interval > MAX_LEASE_RENEW_INTERVAL {
        return Err(V2ConfigError::InvalidValue(format!(
            "lease renewal interval {interval:?} must be in (0s, {MAX_LEASE_RENEW_INTERVAL_SEC}s] per spec/06"
        )));
    }
    Ok(())
}

/// Production `spec/06`-compliant (`<= 15s`) background `LeaseRenewReq` loop with
/// `MissedTickBehavior::Delay`, per-leg `lease_seq`, 5s per-call timeout, bounded 5s shutdown
/// with `JoinError` surfacing, `(ok, err)` counters, and 3-consecutive-failure fail-closed
/// `CloseReason::LeaseExpired` trigger.
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
        validate_renew_interval(cfg.renew_interval)?;
        if legs.is_empty() {
            return Err(V2ConfigError::InvalidValue(
                "lease renewal legs must not be empty".into(),
            ));
        }

        let (stop_tx, mut stop_rx) = watch::channel(false);
        let (expired_tx, expired_rx) = watch::channel(None);
        let renewals_ok = Arc::new(AtomicU64::new(0));
        let renewals_err = Arc::new(AtomicU64::new(0));
        let ok_task = Arc::clone(&renewals_ok);
        let err_task = Arc::clone(&renewals_err);

        let task = tokio::spawn(async move {
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
                        let mut tick_had_err = false;
                        for leg in &mut legs {
                            if *stop_rx.borrow() {
                                return;
                            }
                            let renew_res = tokio::time::timeout(
                                LEASE_RENEW_CALL_TIMEOUT,
                                cfg.cp.renew_lease(
                                    cfg.keystore.as_ref(),
                                    Some(&cfg.tenant_id),
                                    &cfg.session_id,
                                    &leg.route_cid,
                                    &leg.pop_id,
                                    &cfg.controller_device_id,
                                    &cfg.controlled_device_id,
                                    leg.lease_seq,
                                    0,
                                    cfg.key_id,
                                ),
                            )
                            .await;
                            match renew_res {
                                Ok(Ok(resp)) => {
                                    leg.lease_seq = resp.lease_seq;
                                    match resp.to_relay_ticket() {
                                        Ok(ticket) => match tokio::time::timeout(
                                            LEASE_RENEW_CALL_TIMEOUT,
                                            leg.tunnel.lease_renew(&ticket),
                                        )
                                        .await
                                        {
                                            Ok(Ok(_)) => {
                                                ok_task.fetch_add(1, Ordering::Release);
                                            }
                                            Ok(Err(e)) => {
                                                tick_had_err = true;
                                                err_task.fetch_add(1, Ordering::Release);
                                                eprintln!("[lease-renew] tunnel.lease_renew failed: {e}");
                                            }
                                            Err(_) => {
                                                tick_had_err = true;
                                                err_task.fetch_add(1, Ordering::Release);
                                                eprintln!("[lease-renew] tunnel.lease_renew timed out after {LEASE_RENEW_CALL_TIMEOUT:?}");
                                            }
                                        },
                                        Err(e) => {
                                            tick_had_err = true;
                                            err_task.fetch_add(1, Ordering::Release);
                                            eprintln!("[lease-renew] ticket decode failed: {e}");
                                        }
                                    }
                                }
                                Ok(Err(e)) => {
                                    tick_had_err = true;
                                    err_task.fetch_add(1, Ordering::Release);
                                    eprintln!("[lease-renew] control-plane renew_lease failed: {e}");
                                }
                                Err(_) => {
                                    tick_had_err = true;
                                    err_task.fetch_add(1, Ordering::Release);
                                    eprintln!("[lease-renew] control-plane renew_lease timed out after {LEASE_RENEW_CALL_TIMEOUT:?}");
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
    pub fn spawn_with_fn<F, Fut>(
        renew_interval: Duration,
        mut renew_fn: F,
    ) -> Result<Self, V2ConfigError>
    where
        F: FnMut() -> Fut + Send + 'static,
        Fut: Future<Output = Result<(), String>> + Send,
    {
        validate_renew_interval(renew_interval)?;
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
                        match tokio::time::timeout(LEASE_RENEW_CALL_TIMEOUT, renew_fn()).await {
                            Ok(Ok(())) => {
                                consecutive_failures = 0;
                                ok_task.fetch_add(1, Ordering::Release);
                            }
                            Ok(Err(_)) | Err(_) => {
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

        Ok(Self {
            stop_tx,
            expired_rx,
            task: Some(task),
            renewals_ok,
            renewals_err,
        })
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

    pub async fn shutdown(mut self) -> LeaseRenewalShutdown {
        let _ = self.stop_tx.send(true);
        let mut join_error = None;
        if let Some(mut handle) = self.task.take() {
            match tokio::time::timeout(LEASE_RENEW_SHUTDOWN_TIMEOUT, &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    join_error = Some(format!("lease renewal task failed: {e}"));
                }
                Err(_) => {
                    handle.abort();
                    let _ = handle.await;
                    join_error = Some(format!(
                        "lease renewal task shutdown timed out after {LEASE_RENEW_SHUTDOWN_TIMEOUT:?}"
                    ));
                }
            }
        }
        let (renewals_ok, renewals_err) = self.counts();
        LeaseRenewalShutdown {
            renewals_ok,
            renewals_err,
            join_error,
        }
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
    pub release_all_ok: bool,
    pub release_all_error: Option<String>,
    pub lease_renewals_ok: u64,
    pub lease_renewals_err: u64,
    pub lease_renewal_error: Option<String>,
    pub capture_joined: bool,
    pub capture_join_timed_out: bool,
    pub session_close_sent: bool,
}

/// Strictly ordered production teardown sequence:
/// 1. Permanently latch `HidInputExecutor` closed BEFORE releasing held inputs, then run
///    bounded `release_all` and record truthful success/failure (zero stuck keys).
/// 2. Stop capture/encode pipeline with bounded 2s join timeout (no teardown deadlock).
/// 3. 3× redundant `0x04 SESSION_CLOSE`.
/// 4. Shutdown `LeaseRenewalTask` (bounded 5s + abort + `JoinError` surfacing).
/// 5. Close data plane (`UdpE2eeSession`).
/// 6. Close signaling (`SignalingSession`, if owned by this teardown).
pub async fn ordered_session_teardown<S: HidInputSink>(
    mut executor: Option<&mut HidInputExecutor<S>>,
    mut capture: Option<CapturePipelineHandle>,
    mut data_plane: Option<UdpE2eeSession>,
    lease_renewal: Option<LeaseRenewalTask>,
    mut signaling: Option<SignalingSession>,
    reason: &CloseReason,
) -> OrderedTeardownReport {
    let mut report = OrderedTeardownReport::default();

    // 1. Latch executor closed FIRST, then release_all with truthful status recording
    if let Some(exec) = executor.as_mut() {
        exec.latch_closed();
        let summary = exec.release_all(&reason.label());
        if !summary.input_faulted && summary.failed_buttons == 0 && summary.failed_keys.is_empty() {
            report.release_all_ok = true;
            report.steps.push("release_all");
        } else {
            report.release_all_ok = false;
            report.release_all_error = Some(format!(
                "release_all incomplete: failed_buttons={:#04x}, failed_key_count={}, input_faulted={}",
                summary.failed_buttons,
                summary.failed_keys.len(),
                summary.input_faulted
            ));
            report.steps.push("release_all_failed");
        }
    }

    // 2. stop capture/encode (bounded 2s join via spawn_blocking)
    if let Some(mut cap) = capture.take() {
        let join_res = tokio::task::spawn_blocking(move || {
            cap.stop_and_join_timeout(CAPTURE_JOIN_TIMEOUT)
        })
        .await;
        match join_res {
            Ok(Ok(())) => {
                report.capture_joined = true;
                report.steps.push("stop_capture");
            }
            Ok(Err(e)) => {
                report.capture_joined = false;
                report.capture_join_timed_out = e.to_string().contains("did not exit within");
                eprintln!("[teardown] capture stop_and_join failed: {e}");
                report.steps.push(if report.capture_join_timed_out {
                    "stop_capture_timeout"
                } else {
                    "stop_capture_failed"
                });
            }
            Err(e) => {
                report.capture_joined = false;
                eprintln!("[teardown] capture join task panicked: {e}");
                report.steps.push("stop_capture_failed");
            }
        }
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
        let shut = lr.shutdown().await;
        report.lease_renewals_ok = shut.renewals_ok;
        report.lease_renewals_err = shut.renewals_err;
        report.lease_renewal_error = shut.join_error;
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
    use crate::v2_session::{
        hid::{HidPayload, KeyEvent},
        input::{DryRunSink, InputError, InputSinkError, ReleaseAllResult, SafeHidKey},
    };
    use std::sync::atomic::AtomicU32;
    use v2_identity::SoftwareDeviceKeyStore;

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
        })
        .unwrap();

        let mut exp_rx = task.subscribe_expired();
        tokio::time::timeout(Duration::from_secs(2), exp_rx.changed())
            .await
            .expect("lease renewal should trigger fail-closed LeaseExpired")
            .unwrap();
        assert_eq!(*exp_rx.borrow(), Some(CloseReason::LeaseExpired));
        let shut = task.shutdown().await;
        assert_eq!(shut.renewals_ok, 2);
        assert_eq!(shut.renewals_err, 4);
        assert!(shut.join_error.is_none());
    }

    #[tokio::test]
    async fn lease_renewal_rejects_empty_legs_and_invalid_duration_and_surfaces_panic() {
        // Duration > 15s (even 15.001s) and 0s MUST be rejected
        assert!(LeaseRenewalTask::spawn_with_fn(Duration::ZERO, || async { Ok(()) }).is_err());
        assert!(
            LeaseRenewalTask::spawn_with_fn(Duration::from_millis(15_001), || async { Ok(()) })
                .is_err()
        );
        assert!(
            LeaseRenewalTask::spawn_with_fn(Duration::from_millis(15_999), || async { Ok(()) })
                .is_err()
        );

        // Empty legs MUST be rejected
        let cp = ControlPlaneClient::new("http://127.0.0.1:18080", None).unwrap();
        let ks: Arc<dyn DeviceKeyStore> = Arc::new(SoftwareDeviceKeyStore::generate());
        let cfg = LeaseRenewalConfig {
            cp,
            keystore: ks,
            tenant_id: [0x11; 16],
            session_id: [0x22; 16],
            controller_device_id: [0x33; 16],
            controlled_device_id: [0x44; 16],
            key_id: 1,
            renew_interval: Duration::from_secs(15),
        };
        assert!(LeaseRenewalTask::spawn(cfg, Vec::new()).is_err());

        // Task panic MUST be surfaced in LeaseRenewalShutdown.join_error
        let panicking = LeaseRenewalTask::spawn_with_fn(Duration::from_millis(10), || async {
            panic!("simulated lease task panic");
        })
        .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        let shut = panicking.shutdown().await;
        assert!(shut.join_error.is_some());
    }

    #[tokio::test]
    async fn ordered_teardown_latches_closed_first_and_reports_release_all_truthfully() {
        // 1. Clean teardown latches executor closed BEFORE release and rejects post-teardown input
        let mut exec = HidInputExecutor::new(DryRunSink::new(), 640, 360).unwrap();
        exec.apply_v123_stream_batch(&[(
            1,
            HidPayload::Key(KeyEvent {
                down: true,
                modifiers: 0,
                usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                unicode_scalar: 0,
                client_ts_ms: 1000,
            }),
        )])
        .unwrap();
        let lr = LeaseRenewalTask::spawn_with_fn(Duration::from_secs(10), || async { Ok(()) })
            .unwrap();
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
        assert!(report.release_all_ok);
        assert!(report.release_all_error.is_none());
        assert!(exec.is_terminated());
        assert!(exec.held_state().is_closed());
        assert!(!exec.has_pressed_state());
        assert_eq!(
            exec.apply_v123_stream_batch(&[(
                2,
                HidPayload::Key(KeyEvent {
                    down: true,
                    modifiers: 0,
                    usb_hid_usage: SafeHidKey::KeyB.usb_hid_usage(),
                    unicode_scalar: 0,
                    client_ts_ms: 1010,
                }),
            )])
            .unwrap_err(),
            InputError::SessionTerminated
        );

        // 2. Failing release_all MUST be reported truthfully as release_all_failed (NEVER swallowed)
        struct AlwaysFailReleaseSink;
        impl HidInputSink for AlwaysFailReleaseSink {
            fn move_abs(&mut self, _x: i32, _y: i32) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn move_rel(&mut self, _dx: i32, _dy: i32) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn mouse_down(&mut self, _button_bit: u8) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn mouse_up(&mut self, _button_bit: u8) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn wheel(&mut self, _dx: i16, _dy: i16) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn key_down(&mut self, _key: SafeHidKey) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn key_up(&mut self, _key: SafeHidKey) -> Result<(), InputSinkError> {
                Ok(())
            }
            fn release_all_best_effort(
                &mut self,
                pressed_buttons: u8,
                pressed_keys: &[SafeHidKey],
            ) -> ReleaseAllResult {
                ReleaseAllResult {
                    failed_buttons: pressed_buttons,
                    failed_keys: pressed_keys.to_vec(),
                }
            }
        }
        let mut fail_exec = HidInputExecutor::new(AlwaysFailReleaseSink, 640, 360).unwrap();
        fail_exec
            .apply_v123_stream_batch(&[(
                1,
                HidPayload::Key(KeyEvent {
                    down: true,
                    modifiers: 0,
                    usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                    unicode_scalar: 0,
                    client_ts_ms: 1000,
                }),
            )])
            .unwrap();
        let fail_report = ordered_session_teardown(
            Some(&mut fail_exec),
            None,
            None,
            None,
            None,
            &CloseReason::Normal,
        )
        .await;
        assert_eq!(fail_report.steps, vec!["release_all_failed"]);
        assert!(!fail_report.release_all_ok);
        assert!(fail_report.release_all_error.is_some());
        assert!(fail_exec.is_faulted());
    }
}
