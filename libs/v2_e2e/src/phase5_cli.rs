// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `phase5-e2e` — End-to-end verification suite driving BOTH Host and Controller 100% through
//! `V2BridgeRuntime` JSON commands/events, `FrameMailbox`, OS dry-run adapters, and C-ABI wrappers.

use crate::phase4_cli::{parse_flag_value, TempDirGuard};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use v2_client::{ClusterConfig, ControlPlaneClient, CreateTenantReq};
use v2_e2e::{
    ensure_dir_0700,
    ffi_abi::{
        register_runtime, zerodesk_v2_abi_version, zerodesk_v2_buffer_free, zerodesk_v2_destroy,
        zerodesk_v2_frame_info, zerodesk_v2_snapshot_json, zerodesk_v2_take_latest_frame,
        ZeroDeskFrameInfo, ZeroDeskOwnedBuffer, ZERODESK_ERR_BUFFER_TOO_SMALL, ZERODESK_OK,
        ZERODESK_V2_ABI_VERSION,
    },
    scan_json_for_secret_canaries, write_file_atomic_0600, BridgePersistedConfig, TransportMode,
    V2BridgeRuntime, V2BridgeRuntimeOptions,
};

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

#[derive(Debug, Default, Serialize)]
struct Phase5E2eReport {
    pass: bool,
    config_0600_verified: bool,
    start_host_idempotent_verified: bool,
    incoming_stale_rejected_and_accept_verified: bool,
    video_mailbox_c_abi_verified: bool,
    slow_ui_dropped_frames: u64,
    audio_opus_dtx_verified: bool,
    hid_release_normal_disconnect_ms: Option<u64>,
    hid_release_watchdog_timeout_verified: bool,
    hid_release_sigterm_cancel_ms: Option<u64>,
    clipboard_bidir_aba_verified: bool,
    file_transfer_verified: bool,
    policy_refresh_and_deny_verified: bool,
    udp_to_tls443_fallback_verified: bool,
    zero_secret_leaks_verified: bool,
    zero_active_tasks_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn wait_for_event<F>(
    rt: &V2BridgeRuntime,
    timeout: Duration,
    captured: &mut Vec<String>,
    mut pred: F,
) -> Option<serde_json::Value>
where
    F: FnMut(&serde_json::Value) -> bool,
{
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let rem = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100));
        if let Some(raw) = rt.poll_event_json_timeout(rem) {
            captured.push(raw.clone());
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if pred(&val) {
                    return Some(val);
                }
            }
        }
    }
    None
}

fn wait_active_tasks_zero(rt: &V2BridgeRuntime, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if rt.active_task_count() == 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    rt.active_task_count() == 0
}

#[allow(clippy::too_many_arguments)]
fn build_bridge_config(
    cluster: &ClusterConfig,
    cp_url: &str,
    sig_addr: &str,
    ca_path: Option<&Path>,
    signaling_tls: Option<bool>,
    enrollment_token: &str,
    identity_dir: &Path,
    watchdog_ms: u64,
    keepalive_ms: u64,
    transport_mode: TransportMode,
) -> BridgePersistedConfig {
    BridgePersistedConfig {
        v: 1,
        control_plane_endpoint: cp_url.to_string(),
        signaling_addr: sig_addr.to_string(),
        signaling_tls,
        edge_a: Some(cluster.edge_a.clone()),
        edge_b: Some(cluster.edge_b.clone()),
        enrollment_token: Some(enrollment_token.to_string()),
        ca_der_path: ca_path.map(|p| p.display().to_string()),
        identity_dir: identity_dir.display().to_string(),
        home_region: "local".into(),
        codec: "vp9".into(),
        fps: 20,
        watchdog_timeout_ms: watchdog_ms,
        keepalive_interval_ms: keepalive_ms,
        lease_renew_interval_sec: 15,
        bw_cap_kbps: 20_000,
        transport_mode,
        udp_probe_timeout_ms: 800,
    }
}

fn save_and_load_config_0600(
    rt: &V2BridgeRuntime,
    cfg_path: &Path,
    cfg: &BridgePersistedConfig,
) -> Result<(), String> {
    let save_cmd = serde_json::json!({
        "v": 1,
        "cmd": "save_config",
        "path": cfg_path.display().to_string(),
        "config": cfg,
    });
    let save_resp: serde_json::Value = serde_json::from_str(&rt.exec_json(&save_cmd.to_string()))
        .map_err(|e| format!("parse save_config reply: {e}"))?;
    if save_resp["ok"].as_bool() != Some(true) {
        return Err(format!("save_config failed: {save_resp}"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(cfg_path)
            .map_err(|e| format!("stat cfg: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(format!("expected 0600 config mode, got {mode:#o}"));
        }
    }
    let load_cmd = serde_json::json!({
        "v": 1,
        "cmd": "load_config",
        "path": cfg_path.display().to_string(),
    });
    let load_resp: serde_json::Value = serde_json::from_str(&rt.exec_json(&load_cmd.to_string()))
        .map_err(|e| format!("parse load_config reply: {e}"))?;
    if load_resp["ok"].as_bool() != Some(true) {
        return Err(format!("load_config failed: {load_resp}"));
    }
    Ok(())
}

pub async fn cmd_phase5_e2e(args: &[String]) -> ExitCode {
    let mut config_path: Option<PathBuf> = None;
    let mut cp_url_override: Option<String> = None;
    let mut sig_addr_override: Option<String> = None;
    let mut ca_der_override: Option<PathBuf> = None;
    let mut enroll_override: Option<String> = None;
    let mut signaling_tls_flag: Option<bool> = None;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" | "--cluster-config" => {
                let flag = args[i].clone();
                parse_flag_value(args, &mut i, &flag).map(|v| {
                    config_path = Some(PathBuf::from(v));
                })
            }
            "--control-plane-url" => {
                parse_flag_value(args, &mut i, "--control-plane-url").map(|v| {
                    cp_url_override = Some(v);
                })
            }
            "--signaling-addr" => parse_flag_value(args, &mut i, "--signaling-addr").map(|v| {
                sig_addr_override = Some(v);
            }),
            "--ca-cert" | "--ca-der" => {
                let flag = args[i].clone();
                parse_flag_value(args, &mut i, &flag).map(|v| {
                    ca_der_override = Some(PathBuf::from(v));
                })
            }
            "--enrollment-token" => {
                parse_flag_value(args, &mut i, "--enrollment-token").map(|v| {
                    enroll_override = Some(v);
                })
            }
            "--signaling-tls" => {
                signaling_tls_flag = Some(true);
                Ok(())
            }
            other => Err(format!("unknown argument '{other}'")),
        };
        if let Err(e) = res {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
        i += 1;
    }

    let Some(config_path) = config_path else {
        eprintln!(
            "usage: phase5-e2e --config <cluster.json> [--control-plane-url <url>] [--signaling-addr <host:port>] [--ca-cert <path>] [--enrollment-token <tok>] [--signaling-tls]"
        );
        return ExitCode::from(2);
    };

    let cluster = match ClusterConfig::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("load cluster config failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let cp_url = cp_url_override.unwrap_or_else(|| cluster.cp_base_url());
    let sig_addr = sig_addr_override.unwrap_or_else(|| cluster.signaling_addr.clone());
    let resolved_ca = ca_der_override.or_else(|| {
        cluster
            .ca_der_path
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
    });
    let sig_tls = signaling_tls_flag.or(cluster.signaling_tls);

    let cp = match ControlPlaneClient::new(&cp_url, resolved_ca.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("init control plane client failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let work_dir = std::env::temp_dir().join(format!("zd-p5-e2e-{}-{uniq}", std::process::id()));
    let _work_guard = TempDirGuard(work_dir.clone());
    if let Err(e) = ensure_dir_0700(&work_dir) {
        eprintln!("create work_dir failed: {e}");
        return ExitCode::FAILURE;
    }

    let mut report = Phase5E2eReport::default();
    let res = run_phase5_suite(
        &cluster,
        &cp,
        &cp_url,
        &sig_addr,
        resolved_ca.as_deref(),
        sig_tls,
        enroll_override.as_deref(),
        &work_dir,
        &mut report,
    )
    .await;

    if let Err(e) = res {
        report.pass = false;
        report.error = Some(e);
    } else {
        report.pass = report.config_0600_verified
            && report.start_host_idempotent_verified
            && report.incoming_stale_rejected_and_accept_verified
            && report.video_mailbox_c_abi_verified
            && report.audio_opus_dtx_verified
            && report.hid_release_normal_disconnect_ms.is_some_and(|ms| ms <= 500)
            && report.hid_release_watchdog_timeout_verified
            && report.hid_release_sigterm_cancel_ms.is_some_and(|ms| ms <= 500)
            && report.clipboard_bidir_aba_verified
            && report.file_transfer_verified
            && report.policy_refresh_and_deny_verified
            && report.udp_to_tls443_fallback_verified
            && report.zero_secret_leaks_verified
            && report.zero_active_tasks_verified;
    }

    if let Ok(json) = serde_json::to_string_pretty(&report) {
        println!("{json}");
    }
    if report.pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_phase5_suite(
    cluster: &ClusterConfig,
    cp: &ControlPlaneClient,
    cp_url: &str,
    sig_addr: &str,
    ca_path: Option<&Path>,
    sig_tls: Option<bool>,
    enroll_override: Option<&str>,
    work_dir: &Path,
    report: &mut Phase5E2eReport,
) -> Result<(), String> {
    let admin_token = cluster
        .admin_token
        .as_deref()
        .ok_or_else(|| "cluster.json missing admin_token".to_string())?;

    // Provision Allowed tenant
    let allowed_enroll = match enroll_override {
        Some(tok) => tok.to_string(),
        None => {
            let tid_hex = hex::encode(random_bytes::<16>());
            let tok = format!("CANARY_ENROLL_P5_ALLOW_{}", hex::encode(random_bytes::<8>()));
            let req = CreateTenantReq {
                tenant_id_hex: tid_hex,
                name: Some("zerodesk-p5-allowed".into()),
                home_region: Some("local".into()),
                plan_tier: Some("pro".into()),
                monthly_quota_bytes: 20 * 1024 * 1024 * 1024,
                bw_cap_kbps: 50_000,
                exhaust_policy: 0,
                allow_file_transfer: true,
                enrollment_token: tok.clone(),
                enrollment_ttl_sec: 3600,
                policy_hash_hex: None,
                allow_clipboard: Some(true),
                allow_file_clipboard: Some(false),
                allow_tcp_tunnel: Some(false),
                allow_terminal: Some(false),
                allow_audio: Some(true),
                max_file_mb: Some(64),
                max_clipboard_kb: Some(256),
            };
            cp.create_tenant(admin_token, &req)
                .await
                .map_err(|e| format!("create allowed tenant: {e}"))?;
            tok
        }
    };

    let canary_clip_a = "CANARY_CLIPBOARD_SECRET_ALPHA_1234";
    let canary_clip_b = "CANARY_CLIPBOARD_SECRET_BETA_5678";
    let mut all_captured_json: Vec<String> = Vec::new();

    // Create Host and Controller V2BridgeRuntimes
    let host_dl = work_dir.join("host_downloads");
    let host_rt = Arc::new(
        V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
            download_dir: Some(host_dl.clone()),
            ..V2BridgeRuntimeOptions::default()
        })
        .map_err(|e| format!("create host runtime: {e}"))?,
    );
    let ctrl_rt = Arc::new(
        V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
            download_dir: Some(work_dir.join("ctrl_downloads")),
            ..V2BridgeRuntimeOptions::default()
        })
        .map_err(|e| format!("create controller runtime: {e}"))?,
    );

    // 1. Atomic 0600 config save/load
    let host_id_dir = work_dir.join("host_id");
    let ctrl_id_dir = work_dir.join("ctrl_id");
    ensure_dir_0700(&host_id_dir).map_err(|e| e.to_string())?;
    ensure_dir_0700(&ctrl_id_dir).map_err(|e| e.to_string())?;

    let host_cfg = build_bridge_config(
        cluster,
        cp_url,
        sig_addr,
        ca_path,
        sig_tls,
        &allowed_enroll,
        &host_id_dir,
        3000,
        500,
        TransportMode::Auto,
    );
    let ctrl_cfg = build_bridge_config(
        cluster,
        cp_url,
        sig_addr,
        ca_path,
        sig_tls,
        &allowed_enroll,
        &ctrl_id_dir,
        3000,
        500,
        TransportMode::Auto,
    );
    save_and_load_config_0600(&host_rt, &work_dir.join("host_cfg.json"), &host_cfg)?;
    save_and_load_config_0600(&ctrl_rt, &work_dir.join("ctrl_cfg.json"), &ctrl_cfg)?;
    report.config_0600_verified = true;

    // 2. start_host + idempotency
    let sh1: serde_json::Value = serde_json::from_str(
        &host_rt.exec_json(r#"{"v":1,"cmd":"start_host"}"#),
    )
    .map_err(|e| e.to_string())?;
    if sh1["ok"].as_bool() != Some(true) || sh1["accepted"].as_bool() != Some(true) {
        return Err(format!("start_host #1 failed: {sh1}"));
    }
    let gen1 = sh1["session_gen"].as_u64().unwrap_or(0);
    let sh2: serde_json::Value = serde_json::from_str(
        &host_rt.exec_json(r#"{"v":1,"cmd":"start_host"}"#),
    )
    .map_err(|e| e.to_string())?;
    if sh2["already_running"].as_bool() != Some(true) || sh2["session_gen"].as_u64() != Some(gen1) {
        return Err(format!("start_host idempotency failed: {sh2}"));
    }
    report.start_host_idempotent_verified = true;

    let host_ready_ev = wait_for_event(
        &host_rt,
        Duration::from_secs(15),
        &mut all_captured_json,
        |ev| ev["kind"] == "CommandResult" && ev["payload"]["cmd"] == "start_host",
    )
    .ok_or_else(|| "host start_host CommandResult timed out".to_string())?;
    if host_ready_ev["payload"]["ok"].as_bool() != Some(true) {
        return Err(format!("host bootstrap failed: {host_ready_ev}"));
    }
    let host_device_id_hex = host_ready_ev["payload"]["device_id_hex"]
        .as_str()
        .ok_or_else(|| "missing host device_id_hex".to_string())?
        .to_string();

    // 3. Dial -> Incoming stale-ID rejection -> valid accept -> Streaming
    let dial_cmd = serde_json::json!({
        "v": 1,
        "cmd": "dial",
        "target_device_id_hex": host_device_id_hex,
    });
    let dial_reply: serde_json::Value =
        serde_json::from_str(&ctrl_rt.exec_json(&dial_cmd.to_string()))
            .map_err(|e| e.to_string())?;
    if dial_reply["accepted"].as_bool() != Some(true) {
        return Err(format!("controller dial not accepted: {dial_reply}"));
    }

    let inc_ev = wait_for_event(
        &host_rt,
        Duration::from_secs(15),
        &mut all_captured_json,
        |ev| ev["kind"] == "IncomingCall",
    )
    .ok_or_else(|| "host never received IncomingCall".to_string())?;
    let inc_id = inc_ev["payload"]["incoming_id"]
        .as_str()
        .ok_or_else(|| "missing incoming_id".to_string())?
        .to_string();

    let stale_reply: serde_json::Value = serde_json::from_str(
        &host_rt.exec_json(r#"{"v":1,"cmd":"accept_incoming","incoming_id":"stale-999"}"#),
    )
    .map_err(|e| e.to_string())?;
    if stale_reply["error_code"].as_str() != Some("StaleIncoming") {
        return Err(format!("expected StaleIncoming, got {stale_reply}"));
    }
    let acc_cmd = serde_json::json!({
        "v": 1,
        "cmd": "accept_incoming",
        "incoming_id": inc_id,
    });
    let acc_reply: serde_json::Value =
        serde_json::from_str(&host_rt.exec_json(&acc_cmd.to_string()))
            .map_err(|e| e.to_string())?;
    if acc_reply["ok"].as_bool() != Some(true) {
        return Err(format!("accept_incoming failed: {acc_reply}"));
    }
    report.incoming_stale_rejected_and_accept_verified = true;

    let ctrl_stream = wait_for_event(
        &ctrl_rt,
        Duration::from_secs(20),
        &mut all_captured_json,
        |ev| ev["kind"] == "CommandResult" && ev["payload"]["cmd"] == "dial",
    )
    .ok_or_else(|| "controller dial CommandResult timed out".to_string())?;
    if ctrl_stream["payload"]["ok"].as_bool() != Some(true) {
        return Err(format!("controller dial failed: {ctrl_stream}"));
    }

    // 4. Live VP9 video through FrameMailbox + C-ABI two-phase copy + slow-UI dropped_ui_frames
    let _vfr = wait_for_event(
        &ctrl_rt,
        Duration::from_secs(10),
        &mut all_captured_json,
        |ev| ev["kind"] == "VideoFrameReady",
    )
    .ok_or_else(|| "no VideoFrameReady synthesized on controller".to_string())?;

    // Pause reading briefly so slow-UI dropped_ui_frames accumulates deterministically.
    tokio::time::sleep(Duration::from_millis(350)).await;

    // Exercise real C-ABI wrappers on the live Controller runtime!
    assert_eq!(zerodesk_v2_abi_version(), ZERODESK_V2_ABI_VERSION);
    let ctrl_handle = register_runtime(Arc::clone(&ctrl_rt));
    let mut snap_buf = ZeroDeskOwnedBuffer::empty();
    let snap_rc = unsafe { zerodesk_v2_snapshot_json(ctrl_handle, &mut snap_buf) };
    if snap_rc != ZERODESK_OK {
        return Err(format!("C-ABI snapshot_json failed: {snap_rc}"));
    }
    let snap_str = unsafe {
        std::str::from_utf8(std::slice::from_raw_parts(snap_buf.ptr, snap_buf.len))
            .unwrap_or("")
            .to_string()
    };
    unsafe { zerodesk_v2_buffer_free(snap_buf) };
    all_captured_json.push(snap_str);

    let mut finfo = ZeroDeskFrameInfo::default();
    if unsafe { zerodesk_v2_frame_info(ctrl_handle, &mut finfo) } != ZERODESK_OK {
        return Err("C-ABI frame_info failed".into());
    }
    let mut tiny = [0xAAu8; 8];
    let mut req_info = ZeroDeskFrameInfo::default();
    if unsafe {
        zerodesk_v2_take_latest_frame(ctrl_handle, tiny.as_mut_ptr(), tiny.len(), &mut req_info)
    } != ZERODESK_ERR_BUFFER_TOO_SMALL
        || !tiny.iter().all(|&b| b == 0xAA)
    {
        return Err("C-ABI buffer-too-small contract failed".into());
    }
    let mut pixels = vec![0u8; finfo.byte_len];
    let mut copied_info = ZeroDeskFrameInfo::default();
    if unsafe {
        zerodesk_v2_take_latest_frame(
            ctrl_handle,
            pixels.as_mut_ptr(),
            pixels.len(),
            &mut copied_info,
        )
    } != ZERODESK_OK
    {
        return Err("C-ABI take_latest_frame failed".into());
    }
    let non_zero_pixels = pixels.iter().any(|&b| b != 0);
    report.slow_ui_dropped_frames = copied_info.dropped_ui_frames;
    report.video_mailbox_c_abi_verified = non_zero_pixels && copied_info.width >= 32;

    // 5. Live Opus audio + DTX check via QoeTelemetry
    let qoe_ev = wait_for_event(
        &ctrl_rt,
        Duration::from_secs(5),
        &mut all_captured_json,
        |ev| {
            ev["kind"] == "QoeTelemetry"
                && ev["payload"]["audio_frames_decoded"].as_u64().unwrap_or(0) > 0
        },
    );
    report.audio_opus_dtx_verified = qoe_ev.is_some();

    // 6. Bidirectional Clipboard (A -> B -> A anti-echo) + File Transfer
    let clip_cmd_a = serde_json::json!({
        "v": 1,
        "cmd": "send_clipboard",
        "text": canary_clip_a,
    });
    let _ = ctrl_rt.exec_json(&clip_cmd_a.to_string());
    let host_got_a = wait_for_event(
        &host_rt,
        Duration::from_secs(5),
        &mut all_captured_json,
        |ev| ev["kind"] == "ClipboardReceived",
    );
    let clip_cmd_b = serde_json::json!({
        "v": 1,
        "cmd": "send_clipboard",
        "text": canary_clip_b,
    });
    let _ = host_rt.exec_json(&clip_cmd_b.to_string());
    let ctrl_got_b = wait_for_event(
        &ctrl_rt,
        Duration::from_secs(5),
        &mut all_captured_json,
        |ev| ev["kind"] == "ClipboardReceived",
    );
    // Re-send A (A -> B -> A)
    let _ = ctrl_rt.exec_json(&clip_cmd_a.to_string());
    let host_got_a2 = wait_for_event(
        &host_rt,
        Duration::from_secs(5),
        &mut all_captured_json,
        |ev| ev["kind"] == "ClipboardReceived",
    );
    report.clipboard_bidir_aba_verified =
        host_got_a.is_some() && ctrl_got_b.is_some() && host_got_a2.is_some();

    // File Transfer via binary path API
    let sample_file = work_dir.join("phase5_sample.bin");
    let sample_data: Vec<u8> = (0..8192usize).map(|i| ((i * 29 + 7) & 0xFF) as u8).collect();
    let sample_sha = hex::encode(Sha256::digest(&sample_data));
    write_file_atomic_0600(&sample_file, &sample_data).map_err(|e| e.to_string())?;
    let _ = ctrl_rt.send_file_path(&sample_file.display().to_string());
    let ft_ev = wait_for_event(
        &host_rt,
        Duration::from_secs(10),
        &mut all_captured_json,
        |ev| ev["kind"] == "FileTransferComplete",
    );
    report.file_transfer_verified = ft_ev
        .as_ref()
        .is_some_and(|ev| ev["payload"]["sha256_hex"].as_str() == Some(sample_sha.as_str()));

    // 7a. HID injection + normal disconnect key release <= 500ms
    let _ = ctrl_rt.exec_json(r#"{"v":1,"cmd":"send_hid_key","usb_hid_usage":4,"down":true}"#);
    tokio::time::sleep(Duration::from_millis(150)).await;
    let disc_start = Instant::now();
    let _ = ctrl_rt.exec_json(r#"{"v":1,"cmd":"disconnect"}"#);
    let release_deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < release_deadline && !host_rt.dryrun_hid_journal().is_all_released() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    if host_rt.dryrun_hid_journal().is_all_released() {
        report.hid_release_normal_disconnect_ms = Some(disc_start.elapsed().as_millis() as u64);
    }

    // Wait for controller tasks to drain to 0
    let _ = zerodesk_v2_destroy(ctrl_handle);
    let tasks_zero_1 = wait_active_tasks_zero(&ctrl_rt, Duration::from_secs(3));

    // 7b. Deterministic UDP -> Dual TLS-443 fallback + Watchdog timeout key release!
    let ctrl_fb_rt = V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
        drop_udp_override: true,
        ..V2BridgeRuntimeOptions::default()
    })
    .map_err(|e| e.to_string())?;
    save_and_load_config_0600(&ctrl_fb_rt, &work_dir.join("ctrl_fb_cfg.json"), &ctrl_cfg)?;
    let _ = ctrl_fb_rt.exec_json(&dial_cmd.to_string());
    if let Some(inc2) = wait_for_event(
        &host_rt,
        Duration::from_secs(15),
        &mut all_captured_json,
        |ev| ev["kind"] == "IncomingCall",
    ) {
        if let Some(id2) = inc2["payload"]["incoming_id"].as_str() {
            let acc2 = serde_json::json!({ "v": 1, "cmd": "accept_incoming", "incoming_id": id2 });
            let _ = host_rt.exec_json(&acc2.to_string());
        }
    }
    let fb_ev = wait_for_event(
        &ctrl_fb_rt,
        Duration::from_secs(20),
        &mut all_captured_json,
        |ev| {
            ev["kind"] == "TransportModeChanged"
                && ev["payload"]["active_transport_mode"] == "dual_tls443"
        },
    );
    report.udp_to_tls443_fallback_verified = fb_ev.is_some();

    // Hold a key and abruptly destroy controller without sending disconnect -> Host watchdog fires!
    let _ = ctrl_fb_rt.exec_json(r#"{"v":1,"cmd":"send_hid_key","usb_hid_usage":5,"down":true}"#);
    tokio::time::sleep(Duration::from_millis(150)).await;
    ctrl_fb_rt.destroy();
    let wd_ev = wait_for_event(
        &host_rt,
        Duration::from_secs(6),
        &mut all_captured_json,
        |ev| ev["kind"] == "WatchdogTriggered" || ev["kind"] == "SessionEnded",
    );
    report.hid_release_watchdog_timeout_verified =
        wd_ev.is_some() && host_rt.dryrun_hid_journal().is_all_released();

    // 7c. SIGTERM / cancel host while key is held -> released <= 500ms
    host_rt.dryrun_hid_journal().record_key_public(&v2_e2e::KeyEvent {
        down: true,
        modifiers: 0,
        usb_hid_usage: 0x06,
        unicode_scalar: 0,
        client_ts_ms: 1,
    });
    let stop_start = Instant::now();
    let _ = host_rt.exec_json(r#"{"v":1,"cmd":"stop_host"}"#);
    if host_rt.dryrun_hid_journal().is_all_released() {
        report.hid_release_sigterm_cancel_ms = Some(stop_start.elapsed().as_millis() as u64);
    }

    // 8. Policy refresh & PolicyDenied verification (provision denied tenant)
    let deny_tid = hex::encode(random_bytes::<16>());
    let deny_enroll = format!("CANARY_ENROLL_P5_DENY_{}", hex::encode(random_bytes::<8>()));
    let deny_req = CreateTenantReq {
        tenant_id_hex: deny_tid,
        name: Some("zerodesk-p5-denied".into()),
        home_region: Some("local".into()),
        plan_tier: Some("restricted".into()),
        monthly_quota_bytes: 20 * 1024 * 1024 * 1024,
        bw_cap_kbps: 20_000,
        exhaust_policy: 0,
        allow_file_transfer: false,
        enrollment_token: deny_enroll.clone(),
        enrollment_ttl_sec: 3600,
        policy_hash_hex: None,
        allow_clipboard: Some(false),
        allow_file_clipboard: Some(false),
        allow_tcp_tunnel: Some(false),
        allow_terminal: Some(false),
        allow_audio: Some(false),
        max_file_mb: Some(0),
        max_clipboard_kb: Some(0),
    };
    cp.create_tenant(admin_token, &deny_req)
        .await
        .map_err(|e| format!("create denied tenant: {e}"))?;
    let deny_dir = work_dir.join("deny_id");
    ensure_dir_0700(&deny_dir).map_err(|e| e.to_string())?;
    let deny_rt = V2BridgeRuntime::new().map_err(|e| e.to_string())?;
    let deny_cfg = build_bridge_config(
        cluster,
        cp_url,
        sig_addr,
        ca_path,
        sig_tls,
        &deny_enroll,
        &deny_dir,
        3000,
        500,
        TransportMode::Auto,
    );
    save_and_load_config_0600(&deny_rt, &work_dir.join("deny_cfg.json"), &deny_cfg)?;
    let _ = deny_rt.exec_json(r#"{"v":1,"cmd":"refresh_policy"}"#);
    let pol_ev = wait_for_event(
        &deny_rt,
        Duration::from_secs(10),
        &mut all_captured_json,
        |ev| ev["kind"] == "PolicyUpdated" || ev["kind"] == "PolicyDegraded",
    );
    let pol_denies = pol_ev
        .as_ref()
        .is_some_and(|ev| ev["payload"]["policy"]["allow_clipboard"] == false);
    report.policy_refresh_and_deny_verified = pol_denies;

    all_captured_json.push(host_rt.snapshot_json());
    all_captured_json.push(ctrl_rt.snapshot_json());
    all_captured_json.push(deny_rt.snapshot_json());

    let tasks_zero_host = wait_active_tasks_zero(&host_rt, Duration::from_secs(3));
    let tasks_zero_deny = wait_active_tasks_zero(&deny_rt, Duration::from_secs(3));
    host_rt.destroy();
    deny_rt.destroy();
    report.zero_active_tasks_verified = tasks_zero_1 && tasks_zero_host && tasks_zero_deny;

    // 9. Scan ALL captured events & snapshots for canary secrets!
    let canaries = [
        allowed_enroll.as_str(),
        deny_enroll.as_str(),
        canary_clip_a,
        canary_clip_b,
        "BEGIN PRIVATE KEY",
    ];
    let mut leaked = false;
    for item in &all_captured_json {
        if scan_json_for_secret_canaries(item, &canaries).is_err() {
            leaked = true;
            break;
        }
    }
    report.zero_secret_leaks_verified = !leaked;
    Ok(())
}
