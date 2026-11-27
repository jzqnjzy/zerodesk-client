// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `phase6-e2e` — Live-cluster verification of:
//! 1. Real child `zerodesk-desktop` Host supervised by independent `zerodesk-hid-watchdog`
//! 2. Live Controller (`V2BridgeRuntime`) video + HID KeyDown delivery (regular + modifier keys)
//! 3. Real `SIGKILL` (`kill -9`) of the Host process and independent watchdog release report
//!    within <= 1000ms (`0600` JSON, all held keys + all 8 modifiers released, zero leftovers)
//! 4. Non-interactive `os-sck` ScreenCaptureKit permission preflight (clean `PermissionDenied`
//!    without hanging or popping dialogs)

use crate::phase4_cli::{parse_flag_value, TempDirGuard};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use std::{
    fs,
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
    process::{Child, Command, ExitCode, Stdio},
    sync::mpsc,
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use v2_client::{ClusterConfig, ControlPlaneClient, CreateTenantReq};
use v2_e2e::{
    ensure_dir_0700,
    os::{
        sck::{
            enforce_sck_permission_preflight, open_sck_capture, preflight_sck_permission,
            SckCaptureConfig,
        },
        watchdog_proto::{
            WatchdogReleaseReport, ALL_MODIFIER_HID_USAGES, WATCHDOG_REPORT_SCHEMA_VERSION,
        },
        OsError, OsPermission,
    },
    BridgePersistedConfig, TransportMode, V2BridgeRuntime, V2BridgeRuntimeOptions, MOD_META,
};

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

#[derive(Debug, Default, Serialize)]
struct Phase6E2eReport {
    pass: bool,
    host_child_spawned: bool,
    live_video_frame_verified: bool,
    hid_keys_delivered: Vec<u16>,
    sigkill_sent_to_host_pid: Option<u32>,
    watchdog_pid: Option<u32>,
    watchdog_trigger: Option<String>,
    watchdog_report_mode_0600: bool,
    watchdog_released_keys: Vec<u16>,
    watchdog_released_modifiers: Vec<u16>,
    watchdog_release_elapsed_ms: Option<u64>,
    observed_sigkill_to_report_ms: Option<u64>,
    watchdog_zero_leftovers_verified: bool,
    sck_preflight_status: String,
    sck_preflight_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct ChildHostGuard {
    child: Option<Child>,
    watchdog_pid: Option<u32>,
}

impl ChildHostGuard {
    fn new(child: Child) -> Self {
        Self {
            child: Some(child),
            watchdog_pid: None,
        }
    }

    #[cfg(unix)]
    fn sigkill_and_reap(&mut self) -> Result<u32, String> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| "host child already exited".to_string())?;
        let pid = child.id();
        let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if rc != 0 {
            return Err(format!(
                "kill({pid}, SIGKILL) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        let _ = child.wait();
        Ok(pid)
    }

    #[cfg(not(unix))]
    fn sigkill_and_reap(&mut self) -> Result<u32, String> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| "host child already exited".to_string())?;
        let pid = child.id();
        let _ = child.kill();
        let _ = child.wait();
        Ok(pid)
    }
}

impl Drop for ChildHostGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
        #[cfg(unix)]
        if let Some(wd_pid) = self.watchdog_pid {
            unsafe {
                let _ = libc::kill(wd_pid as libc::pid_t, libc::SIGKILL);
            }
        }
    }
}

fn resolve_host_binary(explicit: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(p) = explicit {
        if p.is_file() {
            return Ok(p.to_path_buf());
        }
        return Err(format!("--host-bin does not exist: {}", p.display()));
    }
    let mut candidates = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            candidates.push(dir.join("zerodesk-desktop"));
        }
    }
    // Standard workspace build directories when zerodesk_core is built as a standalone workspace.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if let Some(libs_dir) = manifest_dir.parent() {
        let core_target = libs_dir.join("zerodesk_core").join("target");
        for profile in ["e2e", "release", "debug"] {
            candidates.push(core_target.join(profile).join("zerodesk-desktop"));
        }
    }
    for cand in &candidates {
        if cand.is_file() {
            let wd = cand
                .parent()
                .map(|p| p.join("zerodesk-hid-watchdog"))
                .unwrap_or_default();
            if wd.is_file() {
                return Ok(cand.clone());
            }
        }
    }
    Err(format!(
        "could not locate zerodesk-desktop alongside zerodesk-hid-watchdog (build with `cargo build --manifest-path libs/zerodesk_core/Cargo.toml --bins` or pass --host-bin); checked: {:?}",
        candidates
    ))
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
        watchdog_timeout_ms: 5000,
        keepalive_interval_ms: 500,
        lease_renew_interval_sec: 15,
        bw_cap_kbps: 20_000,
        transport_mode: TransportMode::Auto,
        udp_probe_timeout_ms: 800,
    }
}

fn wait_for_ctrl_event<F>(
    rt: &V2BridgeRuntime,
    timeout: Duration,
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
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&raw) {
                if pred(&val) {
                    return Some(val);
                }
            }
        }
    }
    None
}

fn wait_for_host_msg<F>(
    rx: &mpsc::Receiver<serde_json::Value>,
    timeout: Duration,
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
        match rx.recv_timeout(rem) {
            Ok(msg) => {
                if pred(&msg) {
                    return Some(msg);
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => continue,
            Err(mpsc::RecvTimeoutError::Disconnected) => return None,
        }
    }
    None
}

fn send_host_cmd(stdin: &mut impl Write, cmd: &serde_json::Value) -> Result<(), String> {
    writeln!(stdin, "{cmd}").map_err(|e| format!("write host stdin failed: {e}"))?;
    stdin
        .flush()
        .map_err(|e| format!("flush host stdin failed: {e}"))
}

fn wait_for_watchdog_report(
    path: &Path,
    timeout: Duration,
) -> Result<(WatchdogReleaseReport, Duration), String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(bytes) = fs::read(path) {
            if let Ok(report) = serde_json::from_slice::<WatchdogReleaseReport>(&bytes) {
                return Ok((report, start.elapsed()));
            }
        }
        thread::sleep(Duration::from_millis(5));
    }
    Err(format!(
        "timed out after {:?} waiting for watchdog release report at {}",
        timeout,
        path.display()
    ))
}

#[cfg(unix)]
fn wait_pid_gone(pid: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
        if rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
            return true;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    rc != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(not(unix))]
fn wait_pid_gone(_pid: u32, _timeout: Duration) -> bool {
    true
}

fn verify_sck_preflight_non_interactive() -> (String, bool) {
    // Always verify pure permission gate fails closed when ungranted.
    if enforce_sck_permission_preflight(false)
        != Err(OsError::PermissionDenied(OsPermission::ScreenRecording))
    {
        return ("pure_gate_failed".into(), false);
    }

    match preflight_sck_permission() {
        Ok(false) => match open_sck_capture(SckCaptureConfig::default()) {
            Err(OsError::PermissionDenied(OsPermission::ScreenRecording)) => {
                ("denied_clean_fail_closed".into(), true)
            }
            Err(other) => (format!("denied_unexpected_err:{other}"), false),
            Ok(_) => ("denied_unexpected_ok".into(), false),
        },
        Ok(true) => ("granted_non_interactive".into(), true),
        Err(OsError::UnsupportedPlatform(_)) => ("unsupported_platform".into(), true),
        Err(other) => (format!("preflight_err:{other}"), false),
    }
}

pub async fn cmd_phase6_e2e(args: &[String]) -> ExitCode {
    let mut config_path: Option<PathBuf> = None;
    let mut cp_url_override: Option<String> = None;
    let mut sig_addr_override: Option<String> = None;
    let mut ca_der_override: Option<PathBuf> = None;
    let mut enroll_override: Option<String> = None;
    let mut signaling_tls_flag: Option<bool> = None;
    let mut host_bin_override: Option<PathBuf> = None;

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
            "--host-bin" => parse_flag_value(args, &mut i, "--host-bin").map(|v| {
                host_bin_override = Some(PathBuf::from(v));
            }),
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
            "usage: phase6-e2e --config <cluster.json> [--host-bin <zerodesk-desktop>] [--control-plane-url <url>] [--signaling-addr <host:port>] [--ca-cert <path>] [--enrollment-token <tok>] [--signaling-tls]"
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
    let work_dir = std::env::temp_dir().join(format!("zd-p6-e2e-{}-{uniq}", std::process::id()));
    let _work_guard = TempDirGuard(work_dir.clone());
    if let Err(e) = ensure_dir_0700(&work_dir) {
        eprintln!("create work_dir failed: {e}");
        return ExitCode::FAILURE;
    }

    let mut report = Phase6E2eReport::default();
    let res = run_phase6_suite(
        &cluster,
        &cp,
        &cp_url,
        &sig_addr,
        resolved_ca.as_deref(),
        sig_tls,
        enroll_override.as_deref(),
        host_bin_override.as_deref(),
        &work_dir,
        &mut report,
    )
    .await;

    if let Err(e) = res {
        report.pass = false;
        report.error = Some(e);
    } else {
        report.pass = report.host_child_spawned
            && report.live_video_frame_verified
            && report.watchdog_report_mode_0600
            && report.observed_sigkill_to_report_ms.is_some_and(|ms| ms <= 1000)
            && report.watchdog_zero_leftovers_verified
            && report.sck_preflight_verified;
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
async fn run_phase6_suite(
    cluster: &ClusterConfig,
    cp: &ControlPlaneClient,
    cp_url: &str,
    sig_addr: &str,
    ca_path: Option<&Path>,
    sig_tls: Option<bool>,
    enroll_override: Option<&str>,
    host_bin_override: Option<&Path>,
    work_dir: &Path,
    report: &mut Phase6E2eReport,
) -> Result<(), String> {
    // Step 5 pre-check (non-interactive SCK preflight; zero dialogs, zero hangs).
    let (sck_status, sck_ok) = verify_sck_preflight_non_interactive();
    report.sck_preflight_status = sck_status;
    report.sck_preflight_verified = sck_ok;
    if !sck_ok {
        return Err(format!(
            "os-sck preflight verification failed: {}",
            report.sck_preflight_status
        ));
    }

    let host_bin = resolve_host_binary(host_bin_override)?;
    let admin_token = cluster
        .admin_token
        .as_deref()
        .ok_or_else(|| "cluster.json missing admin_token".to_string())?;

    let enroll_token = match enroll_override {
        Some(tok) => tok.to_string(),
        None => {
            let tid_hex = hex::encode(random_bytes::<16>());
            let tok = format!("CANARY_ENROLL_P6_{}", hex::encode(random_bytes::<8>()));
            let req = CreateTenantReq {
                tenant_id_hex: tid_hex,
                name: Some("zerodesk-p6-watchdog".into()),
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
                .map_err(|e| format!("create p6 tenant: {e}"))?;
            tok
        }
    };

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
        &enroll_token,
        &host_id_dir,
    );
    let ctrl_cfg = build_bridge_config(
        cluster,
        cp_url,
        sig_addr,
        ca_path,
        sig_tls,
        &enroll_token,
        &ctrl_id_dir,
    );

    let host_cfg_path = work_dir.join("host_cfg.json");
    let ctrl_cfg_path = work_dir.join("ctrl_cfg.json");
    let wd_report_path = work_dir.join("hid-watchdog-release.json");

    // Save Controller config and bootstrap Controller runtime.
    let ctrl_rt = V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
        download_dir: Some(work_dir.join("ctrl_downloads")),
        ..V2BridgeRuntimeOptions::default()
    })
    .map_err(|e| format!("create controller runtime: {e}"))?;

    for (path, cfg) in [(&host_cfg_path, &host_cfg), (&ctrl_cfg_path, &ctrl_cfg)] {
        let save_cmd = serde_json::json!({
            "v": 1,
            "cmd": "save_config",
            "path": path.display().to_string(),
            "config": cfg,
        });
        let resp: serde_json::Value = serde_json::from_str(&ctrl_rt.exec_json(&save_cmd.to_string()))
            .map_err(|e| format!("parse save_config reply: {e}"))?;
        if resp["ok"].as_bool() != Some(true) {
            return Err(format!("save_config failed: {resp}"));
        }
    }
    let load_ctrl = serde_json::json!({
        "v": 1,
        "cmd": "load_config",
        "path": ctrl_cfg_path.display().to_string(),
    });
    let load_ctrl_resp: serde_json::Value =
        serde_json::from_str(&ctrl_rt.exec_json(&load_ctrl.to_string()))
            .map_err(|e| e.to_string())?;
    if load_ctrl_resp["ok"].as_bool() != Some(true) {
        return Err(format!("controller load_config failed: {load_ctrl_resp}"));
    }

    // 1. Spawn real child `zerodesk-desktop bridge-stdio --hid-watchdog --watchdog-report <path>`.
    let mut child = Command::new(&host_bin)
        .args([
            "bridge-stdio",
            "--hid-watchdog",
            "--watchdog-report",
            &wd_report_path.display().to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| format!("spawn {} failed: {e}", host_bin.display()))?;

    let mut host_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "host child missing stdin".to_string())?;
    let host_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "host child missing stdout".to_string())?;
    let mut host_guard = ChildHostGuard::new(child);
    report.host_child_spawned = true;

    let (host_msg_tx, host_msg_rx) = mpsc::channel::<serde_json::Value>();
    let _reader_thread = thread::spawn(move || {
        let reader = BufReader::new(host_stdout);
        for line in reader.lines() {
            let Ok(line) = line else { break };
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&line) {
                if host_msg_tx.send(val).is_err() {
                    break;
                }
            }
        }
    });

    // Load config + start_host on child Host process.
    send_host_cmd(
        &mut host_stdin,
        &serde_json::json!({
            "v": 1,
            "cmd": "load_config",
            "path": host_cfg_path.display().to_string(),
        }),
    )?;
    let load_reply = wait_for_host_msg(&host_msg_rx, Duration::from_secs(5), |m| {
        m["stream"] == "reply"
    })
    .ok_or_else(|| "host child did not reply to load_config".to_string())?;
    if load_reply["body"]["ok"].as_bool() != Some(true) {
        return Err(format!("host child load_config failed: {load_reply}"));
    }

    send_host_cmd(&mut host_stdin, &serde_json::json!({"v": 1, "cmd": "start_host"}))?;
    let _host_ready = wait_for_host_msg(&host_msg_rx, Duration::from_secs(15), |m| {
        m["stream"] == "event"
            && m["body"]["kind"] == "CommandResult"
            && m["body"]["payload"]["cmd"] == "start_host"
            && m["body"]["payload"]["ok"].as_bool() == Some(true)
    })
    .ok_or_else(|| "host child did not complete start_host".to_string())?;

    // Query host device_id via get_snapshot.
    send_host_cmd(&mut host_stdin, &serde_json::json!({"v": 1, "cmd": "get_snapshot"}))?;
    let snap_reply = wait_for_host_msg(&host_msg_rx, Duration::from_secs(5), |m| {
        m["stream"] == "reply" && m["body"]["snapshot"]["local_device_id_hex"].is_string()
    })
    .ok_or_else(|| "host child did not return snapshot with local_device_id_hex".to_string())?;
    let host_device_id = snap_reply["body"]["snapshot"]["local_device_id_hex"]
        .as_str()
        .ok_or_else(|| "missing host local_device_id_hex".to_string())?
        .to_string();

    // 2. Dial from Controller and accept IncomingCall on Host child.
    let dial_cmd = serde_json::json!({
        "v": 1,
        "cmd": "dial",
        "target_device_id_hex": host_device_id,
    });
    let dial_reply: serde_json::Value =
        serde_json::from_str(&ctrl_rt.exec_json(&dial_cmd.to_string()))
            .map_err(|e| e.to_string())?;
    if dial_reply["ok"].as_bool() != Some(true) {
        return Err(format!("controller dial failed: {dial_reply}"));
    }

    let incoming = wait_for_host_msg(&host_msg_rx, Duration::from_secs(15), |m| {
        m["stream"] == "event" && m["body"]["kind"] == "IncomingCall"
    })
    .ok_or_else(|| "host child did not receive IncomingCall".to_string())?;
    let incoming_id = incoming["body"]["payload"]["incoming_id"]
        .as_str()
        .ok_or_else(|| "IncomingCall missing incoming_id".to_string())?
        .to_string();

    send_host_cmd(
        &mut host_stdin,
        &serde_json::json!({
            "v": 1,
            "cmd": "accept_incoming",
            "incoming_id": incoming_id,
        }),
    )?;

    // Wait for Controller to receive live video frame.
    let _video_ready = wait_for_ctrl_event(&ctrl_rt, Duration::from_secs(15), |ev| {
        ev["kind"] == "VideoFrameReady"
    })
    .ok_or_else(|| "controller never received VideoFrameReady from child host".to_string())?;
    let info = ctrl_rt
        .mailbox()
        .frame_info()
        .map_err(|e| format!("controller mailbox frame_info failed: {e}"))?;
    report.live_video_frame_verified = info.width >= 32 && info.height >= 32 && info.byte_len > 0;
    if !report.live_video_frame_verified {
        return Err(format!("invalid live frame info: {info:?}"));
    }

    // Send HID KeyDown for regular keys (0x04 'A', 0x05 'B') + modifier (0xE3 LeftMeta) and hold them!
    let held_keys: [(u16, u8); 3] = [(0x04, 0), (0x05, 0), (0xE3, MOD_META)];
    for &(usage, mods) in &held_keys {
        let key_cmd = serde_json::json!({
            "v": 1,
            "cmd": "send_hid_key",
            "down": true,
            "modifiers": mods,
            "usb_hid_usage": usage,
            "unicode_scalar": 0,
        });
        let resp: serde_json::Value =
            serde_json::from_str(&ctrl_rt.exec_json(&key_cmd.to_string()))
                .map_err(|e| e.to_string())?;
        if resp["ok"].as_bool() != Some(true) {
            return Err(format!("send_hid_key({usage:#x}) failed: {resp}"));
        }
    }
    report.hid_keys_delivered = held_keys.iter().map(|(u, _)| *u).collect();

    // Give UDP/TLS transport + Host HID loop brief settle time so all 3 KeyDown snapshots reach
    // the independent `zerodesk-hid-watchdog` pipe before we SIGKILL the Host!
    tokio::time::sleep(Duration::from_millis(350)).await;

    // 3. Send real SIGKILL (`kill -9`) to the live Host process!
    let kill_start = Instant::now();
    let killed_pid = host_guard.sigkill_and_reap()?;
    report.sigkill_sent_to_host_pid = Some(killed_pid);

    // 4. Verify independent watchdog writes 0600 release report within <= 1000ms!
    let (wd_report, observed_elapsed) =
        wait_for_watchdog_report(&wd_report_path, Duration::from_millis(1000))?;
    let total_observed_ms = kill_start.elapsed().as_millis() as u64;
    host_guard.watchdog_pid = Some(wd_report.watchdog_pid);

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&wd_report_path)
            .map_err(|e| format!("stat watchdog report: {e}"))?
            .permissions()
            .mode()
            & 0o777;
        report.watchdog_report_mode_0600 = mode == 0o600;
    }
    #[cfg(not(unix))]
    {
        report.watchdog_report_mode_0600 = true;
    }

    report.watchdog_pid = Some(wd_report.watchdog_pid);
    report.watchdog_trigger = Some(wd_report.trigger.clone());
    report.watchdog_released_keys = wd_report.released_keys.clone();
    report.watchdog_released_modifiers = wd_report.released_modifiers.clone();
    report.watchdog_release_elapsed_ms = Some(wd_report.release_elapsed_ms);
    report.observed_sigkill_to_report_ms = Some(total_observed_ms.max(observed_elapsed.as_millis() as u64));

    if wd_report.schema_version != WATCHDOG_REPORT_SCHEMA_VERSION {
        return Err(format!(
            "unexpected watchdog report schema_version={}",
            wd_report.schema_version
        ));
    }
    if wd_report.parent_pid != killed_pid {
        return Err(format!(
            "watchdog report parent_pid={} != killed host pid={killed_pid}",
            wd_report.parent_pid
        ));
    }
    for &(usage, _) in &held_keys {
        if !wd_report.released_keys.contains(&usage) {
            return Err(format!(
                "watchdog report missing held key {usage:#x}: {:?}",
                wd_report.released_keys
            ));
        }
    }
    if wd_report.released_modifiers != ALL_MODIFIER_HID_USAGES.to_vec() {
        return Err(format!(
            "watchdog report modifiers mismatch: {:?}",
            wd_report.released_modifiers
        ));
    }

    report.watchdog_zero_leftovers_verified =
        wait_pid_gone(wd_report.watchdog_pid, Duration::from_secs(2));
    if !report.watchdog_zero_leftovers_verified {
        return Err(format!(
            "watchdog pid {} still alive after emergency release",
            wd_report.watchdog_pid
        ));
    }

    ctrl_rt.destroy();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sck_preflight_verification_helper_never_hangs_or_prompts() {
        let (status, ok) = verify_sck_preflight_non_interactive();
        assert!(ok, "sck preflight failed: {status}");
        assert!(!status.is_empty());
    }
}
