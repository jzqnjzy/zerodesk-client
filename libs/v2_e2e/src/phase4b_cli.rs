// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use crate::phase4_cli::{
    audit_to_comparable, contains_rendezvous_file, parse_flag_value, read_audit_jsonl,
    wait_for_file, ChildGroupGuard, ControllerClientSummary, HostDaemonSummary, HostReadyFile,
    TempDirGuard,
};
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::process::Command;
use v2_client::{ClusterConfig, ControlPlaneClient, CreateTenantReq};
use v2_e2e::{ensure_dir_0700, write_file_atomic_0600, VideoCodec};

const AUTO_FALLBACK_MAX_MS: u64 = 3_000;
const MIN_AUDIO_SNR_DB: f64 = 12.0;

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScenarioFilter {
    All,
    A,
    B,
    C,
}

impl ScenarioFilter {
    fn parse(s: &str) -> Result<Self, String> {
        match s.trim().to_ascii_lowercase().as_str() {
            "all" => Ok(Self::All),
            "a" | "scenario_a" => Ok(Self::A),
            "b" | "scenario_b" => Ok(Self::B),
            "c" | "scenario_c" => Ok(Self::C),
            other => Err(format!(
                "invalid --scenario '{other}' (expected all|a|b|c)"
            )),
        }
    }

    fn run_a(self) -> bool {
        matches!(self, Self::All | Self::A)
    }

    fn run_b(self) -> bool {
        matches!(self, Self::All | Self::B)
    }

    fn run_c(self) -> bool {
        matches!(self, Self::All | Self::C)
    }
}

#[derive(Debug, Clone)]
struct Phase4bCaseSpec<'a> {
    name: &'a str,
    host_transport: &'a str,
    host_drop_udp: bool,
    ctl_transport: &'a str,
    ctl_drop_udp: bool,
    expected_host_mode: &'a str,
    expected_ctl_mode: &'a str,
    check_host_fallback_lt_3s: bool,
    check_ctl_fallback_lt_3s: bool,
    denied_mode: bool,
    send_file_twice: bool,
}

#[derive(Debug, Serialize)]
struct Phase4bCaseReport {
    name: String,
    pass: bool,
    handshake_hash_matched: bool,
    audit_events_matched: usize,
    audit_events_expected: usize,
    host_transport_mode: String,
    ctl_transport_mode: String,
    host_transport_attach_ms: u64,
    ctl_transport_attach_ms: u64,
    p3_dropped_host: u64,
    p3_dropped_ctl: u64,
    file_collision_verified: bool,
    host_summary: Option<HostDaemonSummary>,
    controller_summary: Option<ControllerClientSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct Phase4bE2eReport {
    pass: bool,
    zero_rendezvous_verified: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario_a_allowed_udp: Option<Phase4bCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario_b_denied_policy: Option<Phase4bCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario_c1_ctrl_drop_udp_fallback: Option<Phase4bCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario_c2_host_drop_udp_fallback: Option<Phase4bCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scenario_c3_tls443_only: Option<Phase4bCaseReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn build_sample_file_payload() -> (Vec<u8>, String) {
    // 16 KiB deterministic payload spanning 16 x 1024B FILE_CHUNK frames.
    let mut data = Vec::with_capacity(16 * 1024);
    for i in 0..(16 * 1024) {
        data.push(((i * 31 + 17) & 0xFF) as u8);
    }
    let sha_hex = hex::encode(Sha256::digest(&data));
    (data, sha_hex)
}

fn verify_saved_files_on_disk(
    saved_paths: &[String],
    expected_sha_hex: &str,
    expect_twice_collision: bool,
) -> Result<bool, String> {
    let expected_count = if expect_twice_collision { 2 } else { 1 };
    if saved_paths.len() != expected_count {
        return Err(format!(
            "expected {expected_count} saved files, got {}",
            saved_paths.len()
        ));
    }
    for path_str in saved_paths {
        let p = Path::new(path_str);
        let bytes =
            fs::read(p).map_err(|e| format!("read saved file '{}': {e}", p.display()))?;
        let actual_sha = hex::encode(Sha256::digest(&bytes));
        if actual_sha != expected_sha_hex {
            return Err(format!(
                "saved file '{}' SHA-256 mismatch (expected {expected_sha_hex}, got {actual_sha})",
                p.display()
            ));
        }
    }
    if expect_twice_collision {
        if saved_paths[0] == saved_paths[1] {
            return Err("second send overwrote first file instead of creating (1) collision copy".into());
        }
        let has_collision_suffix = saved_paths
            .iter()
            .any(|p| p.contains("(1)"));
        if !has_collision_suffix {
            return Err(format!(
                "expected '(1)' collision suffix in saved paths: {saved_paths:?}"
            ));
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

fn failed_case_report(name: &str, error: String) -> Phase4bCaseReport {
    Phase4bCaseReport {
        name: name.into(),
        pass: false,
        handshake_hash_matched: false,
        audit_events_matched: 0,
        audit_events_expected: 12,
        host_transport_mode: String::new(),
        ctl_transport_mode: String::new(),
        host_transport_attach_ms: 0,
        ctl_transport_attach_ms: 0,
        p3_dropped_host: 0,
        p3_dropped_ctl: 0,
        file_collision_verified: false,
        host_summary: None,
        controller_summary: None,
        error: Some(error),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_phase4b_case(
    exe: &Path,
    spec: &Phase4bCaseSpec<'_>,
    config_path: &Path,
    ca_der: Option<&Path>,
    signaling_tls: bool,
    host_id_dir: &Path,
    ctrl_id_dir: &Path,
    work_dir: &Path,
    tenant_id_hex: &str,
    enrollment_token: &str,
    codec: VideoCodec,
    frames: usize,
    sample_file_path: &Path,
    sample_file_sha_hex: &str,
) -> Phase4bCaseReport {
    let ready_file = work_dir.join(format!("{}_host_ready.json", spec.name));
    let host_audit = work_dir.join(format!("{}_host_audit.jsonl", spec.name));
    let ctrl_audit = work_dir.join(format!("{}_ctrl_audit.jsonl", spec.name));
    let download_dir = work_dir.join(format!("{}_downloads", spec.name));
    let _ = fs::remove_file(&ready_file);
    let _ = fs::remove_file(&host_audit);
    let _ = fs::remove_file(&ctrl_audit);
    let _ = fs::remove_dir_all(&download_dir);
    if let Err(e) = ensure_dir_0700(&download_dir) {
        return failed_case_report(spec.name, format!("create download_dir: {e}"));
    }

    let mut host_cmd = Command::new(exe);
    host_cmd
        .arg("v2-hostd")
        .arg("--config")
        .arg(config_path)
        .arg("--identity-dir")
        .arg(host_id_dir)
        .arg("--audit-out")
        .arg(&host_audit)
        .arg("--codec")
        .arg(codec.name())
        .arg("--fps")
        .arg("30")
        .arg("--watchdog-ms")
        .arg("2000")
        .arg("--idle-exit-ms")
        .arg("25000")
        .arg("--ready-file")
        .arg(&ready_file)
        .arg("--enrollment-token")
        .arg(enrollment_token)
        .arg("--audit-key-identity")
        .arg("--transport")
        .arg(spec.host_transport)
        .arg("--audio")
        .arg("--clipboard")
        .arg("--download-dir")
        .arg(&download_dir);
    if spec.host_drop_udp {
        host_cmd.arg("--drop-udp");
    }
    if let Some(ca) = ca_der {
        host_cmd.arg("--ca-der").arg(ca);
    }
    if signaling_tls {
        host_cmd.arg("--signaling-tls");
    }

    let mut host_child = match ChildGroupGuard::spawn_in_group(&mut host_cmd) {
        Ok(c) => c,
        Err(e) => return failed_case_report(spec.name, e),
    };

    let ready_bytes = match wait_for_file(&ready_file, Duration::from_secs(15)).await {
        Ok(b) => b,
        Err(e) => {
            host_child.sigkill_group();
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return failed_case_report(spec.name, e);
        }
    };
    let ready: HostReadyFile = match serde_json::from_slice(&ready_bytes) {
        Ok(r) => r,
        Err(e) => {
            host_child.sigkill_group();
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return failed_case_report(spec.name, format!("parse ready file: {e}"));
        }
    };

    let mut ctl_cmd = Command::new(exe);
    ctl_cmd
        .arg("v2-ctl")
        .arg("--config")
        .arg(config_path)
        .arg("--identity-dir")
        .arg(ctrl_id_dir)
        .arg("--target-device-id")
        .arg(&ready.device_id_hex)
        .arg("--tenant-id")
        .arg(tenant_id_hex)
        .arg("--enrollment-token")
        .arg(enrollment_token)
        .arg("--audit-out")
        .arg(&ctrl_audit)
        .arg("--codec")
        .arg(codec.name())
        .arg("--frames")
        .arg(frames.to_string())
        .arg("--audit-key-identity")
        .arg("--transport")
        .arg(spec.ctl_transport);
    if spec.ctl_drop_udp {
        ctl_cmd.arg("--drop-udp");
    }
    if spec.denied_mode {
        ctl_cmd.arg("--probe-denied-channels");
    } else {
        ctl_cmd
            .arg("--audio")
            .arg("--clipboard")
            .arg("--send-file")
            .arg(sample_file_path);
        if spec.send_file_twice {
            ctl_cmd.arg("--send-file-twice");
        }
    }
    if let Some(ca) = ca_der {
        ctl_cmd.arg("--ca-der").arg(ca);
    }
    if signaling_tls {
        ctl_cmd.arg("--signaling-tls");
    }

    let ctl_child = match ChildGroupGuard::spawn_in_group(&mut ctl_cmd) {
        Ok(c) => c,
        Err(e) => {
            host_child.sigkill_group();
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return failed_case_report(spec.name, e);
        }
    };

    let (ctl_res, host_res) = tokio::join!(
        ctl_child.wait_with_output(Duration::from_secs(60)),
        host_child.wait_with_output(Duration::from_secs(60)),
    );

    let (ctl_summary, host_summary, parse_err) = match (ctl_res, host_res) {
        (Ok((_cs, cout, cerr)), Ok((_hs, hout, herr))) => {
            let cs = serde_json::from_str::<ControllerClientSummary>(&cout).ok();
            let hs = serde_json::from_str::<HostDaemonSummary>(&hout).ok();
            let err = if cs.is_none() || hs.is_none() {
                Some(format!(
                    "failed to parse child summaries (ctl_err='{cerr}', host_err='{herr}')"
                ))
            } else {
                None
            };
            (cs, hs, err)
        }
        (Err(ce), Ok(_)) => (None, None, Some(format!("controller error: {ce}"))),
        (Ok(_), Err(he)) => (None, None, Some(format!("host error: {he}"))),
        (Err(ce), Err(he)) => (
            None,
            None,
            Some(format!("controller error: {ce}; host error: {he}")),
        ),
    };

    let mut matched = 0usize;
    let mut err = parse_err;
    if err.is_none() {
        match (read_audit_jsonl(&ctrl_audit), read_audit_jsonl(&host_audit)) {
            (Ok(c_recs), Ok(h_recs)) => {
                let c_cmp: Vec<_> = c_recs.iter().filter_map(audit_to_comparable).collect();
                let h_cmp: Vec<_> = h_recs.iter().filter_map(audit_to_comparable).collect();
                if c_cmp == h_cmp {
                    matched = c_cmp.len();
                } else {
                    err = Some(format!(
                        "audit mismatch: ctrl={} host={}",
                        c_cmp.len(),
                        h_cmp.len()
                    ));
                }
            }
            (Err(e), _) | (_, Err(e)) => err = Some(e),
        }
    }

    let (Some(h), Some(c)) = (host_summary.as_ref(), ctl_summary.as_ref()) else {
        return Phase4bCaseReport {
            name: spec.name.into(),
            pass: false,
            handshake_hash_matched: false,
            audit_events_matched: matched,
            audit_events_expected: 12,
            host_transport_mode: String::new(),
            ctl_transport_mode: String::new(),
            host_transport_attach_ms: 0,
            ctl_transport_attach_ms: 0,
            p3_dropped_host: 0,
            p3_dropped_ctl: 0,
            file_collision_verified: false,
            host_summary,
            controller_summary: ctl_summary,
            error: err,
        };
    };

    let hs_matched = !h.handshake_hash_hex.is_empty() && h.handshake_hash_hex == c.handshake_hash_hex;
    let clean_close = h.close_reason == "peer_closed:0x0000";
    let mut file_collision_verified = false;
    let mut checks = Vec::<String>::new();

    if !h.pass {
        checks.push(format!("host failed: {:?}", h.error));
    }
    if !c.pass {
        checks.push(format!("controller failed: {:?}", c.error));
    }
    if !hs_matched {
        checks.push("handshake hash mismatch".into());
    }
    if matched != 12 {
        checks.push(format!("HID audit matched {matched}/12"));
    }
    if !clean_close {
        checks.push(format!("unexpected host close_reason '{}'", h.close_reason));
    }
    if h.p3_dropped != 0 || c.p3_dropped != 0 {
        checks.push(format!(
            "p3_dropped invariant violated: host={}, ctl={}",
            h.p3_dropped, c.p3_dropped
        ));
    }
    if h.policy_version < 1 || h.policy_degraded || c.policy_version < 1 || c.policy_degraded {
        checks.push(format!(
            "verified policy missing or degraded: host(v={},deg={}) ctl(v={},deg={})",
            h.policy_version, h.policy_degraded, c.policy_version, c.policy_degraded
        ));
    }
    if h.active_transport_mode != spec.expected_host_mode {
        checks.push(format!(
            "host transport expected '{}', got '{}'",
            spec.expected_host_mode, h.active_transport_mode
        ));
    }
    if c.active_transport_mode != spec.expected_ctl_mode {
        checks.push(format!(
            "controller transport expected '{}', got '{}'",
            spec.expected_ctl_mode, c.active_transport_mode
        ));
    }
    if spec.check_host_fallback_lt_3s && h.transport_attach_ms >= AUTO_FALLBACK_MAX_MS {
        checks.push(format!(
            "host auto-fallback took {}ms (>= {}ms)",
            h.transport_attach_ms, AUTO_FALLBACK_MAX_MS
        ));
    }
    if spec.check_ctl_fallback_lt_3s && c.transport_attach_ms >= AUTO_FALLBACK_MAX_MS {
        checks.push(format!(
            "controller auto-fallback took {}ms (>= {}ms)",
            c.transport_attach_ms, AUTO_FALLBACK_MAX_MS
        ));
    }

    if spec.denied_mode {
        if !(c.audio_local_policy_denied
            && c.clipboard_local_policy_denied
            && c.file_local_policy_denied)
        {
            checks.push("controller local policy failed to deny audio/clipboard/file".into());
        }
        if c.clipboard_acks_denied < 1 || h.clipboard_acks_denied < 1 {
            checks.push("denied clipboard probe did not return CLIP_ACK POLICY_DENIED".into());
        }
        if c.file_transfers_aborted_policy < 1 || h.file_transfers_aborted_policy < 1 {
            checks.push("denied file probe did not return FILE_ABORT 0x0401".into());
        }
        if h.audio_policy_denied < 1 || h.audio_frames_sent != 0 {
            checks.push(format!(
                "denied audio policy gate mismatch: denied={}, sent={}",
                h.audio_policy_denied, h.audio_frames_sent
            ));
        }
        if h.file_transfers_completed != 0 || h.clipboard_received_text != 0 {
            checks.push("denied tenant unexpectedly delivered clipboard or file payload".into());
        }
    } else {
        if h.audio_frames_sent < 35 || c.audio_frames_received < 30 {
            checks.push(format!(
                "audio frames too low: sent={}, recv={}",
                h.audio_frames_sent, c.audio_frames_received
            ));
        }
        if c.audio_dtx_frames_received < 1 {
            checks.push("expected >= 1 Opus DTX silence frame received".into());
        }
        match c.audio_snr_db {
            Some(snr) if snr.is_finite() && snr >= MIN_AUDIO_SNR_DB => {}
            other => checks.push(format!(
                "audio SNR below gate ({MIN_AUDIO_SNR_DB} dB): {other:?}"
            )),
        }
        if c.clipboard_acks_ok < 3
            || h.clipboard_received_text < 2
            || h.clipboard_received_png < 1
        {
            checks.push(format!(
                "clipboard check failed: acks_ok={}, text={}, png={}",
                c.clipboard_acks_ok, h.clipboard_received_text, h.clipboard_received_png
            ));
        }
        if !h.clipboard_anti_echo_suppressed || !c.clipboard_anti_echo_preserved {
            checks.push(format!(
                "clipboard anti-echo check failed: host_suppressed={}, ctl_aba_preserved={}",
                h.clipboard_anti_echo_suppressed, c.clipboard_anti_echo_preserved
            ));
        }
        let expected_files = if spec.send_file_twice { 2 } else { 1 };
        if c.file_transfers_completed != expected_files
            || h.file_transfers_completed != expected_files
        {
            checks.push(format!(
                "file transfers completed mismatch: expected={expected_files}, ctl={}, host={}",
                c.file_transfers_completed, h.file_transfers_completed
            ));
        } else {
            match verify_saved_files_on_disk(
                &h.file_saved_paths,
                sample_file_sha_hex,
                spec.send_file_twice,
            ) {
                Ok(col_ok) => file_collision_verified = col_ok,
                Err(e) => checks.push(e),
            }
        }
    }

    let final_err = err.or_else(|| {
        if checks.is_empty() {
            None
        } else {
            Some(checks.join("; "))
        }
    });
    let pass = final_err.is_none();

    Phase4bCaseReport {
        name: spec.name.into(),
        pass,
        handshake_hash_matched: hs_matched,
        audit_events_matched: matched,
        audit_events_expected: 12,
        host_transport_mode: h.active_transport_mode.clone(),
        ctl_transport_mode: c.active_transport_mode.clone(),
        host_transport_attach_ms: h.transport_attach_ms,
        ctl_transport_attach_ms: c.transport_attach_ms,
        p3_dropped_host: h.p3_dropped,
        p3_dropped_ctl: c.p3_dropped,
        file_collision_verified,
        host_summary,
        controller_summary: ctl_summary,
        error: final_err,
    }
}

pub async fn cmd_phase4b_e2e(args: &[String]) -> ExitCode {
    let mut config_path: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut signaling_tls = false;
    let mut codec = VideoCodec::Vp9;
    let mut frames = 30usize;
    let mut filter = ScenarioFilter::All;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| {
                config_path = Some(PathBuf::from(v));
            }),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| {
                ca_der = Some(PathBuf::from(v));
            }),
            "--signaling-tls" => {
                signaling_tls = true;
                Ok(())
            }
            "--codec" => parse_flag_value(args, &mut i, "--codec")
                .and_then(|v| VideoCodec::parse_name(&v).map_err(|e| e.to_string()))
                .map(|c| codec = c),
            "--frames" => parse_flag_value(args, &mut i, "--frames")
                .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                .and_then(|n| {
                    if n == 0 {
                        Err("--frames must be >= 1".to_string())
                    } else {
                        Ok(n)
                    }
                })
                .map(|n| frames = n),
            "--scenario" => parse_flag_value(args, &mut i, "--scenario")
                .and_then(|v| ScenarioFilter::parse(&v))
                .map(|f| filter = f),
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
            "usage: phase4b-e2e --config <cluster.json> [--ca-der <path>] [--signaling-tls] [--codec vp9] [--frames 30] [--scenario all|a|b|c]"
        );
        return ExitCode::from(2);
    };

    let cluster = match ClusterConfig::from_file(&config_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("load cluster.json: {e}");
            return ExitCode::FAILURE;
        }
    };
    let resolved_ca = ca_der
        .clone()
        .or_else(|| cluster.ca_der_path.as_deref().filter(|s| !s.is_empty()).map(PathBuf::from));
    let cp = match ControlPlaneClient::new(&cluster.cp_base_url(), resolved_ca.as_deref()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("init control plane client: {e}");
            return ExitCode::FAILURE;
        }
    };
    let Some(admin_token) = cluster.admin_token.as_deref() else {
        eprintln!("cluster.json missing admin_token for phase4b-e2e tenant bootstrap");
        return ExitCode::FAILURE;
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let work_dir = std::env::temp_dir().join(format!(
        "zd-p4b-e2e-{}-{uniq}",
        std::process::id()
    ));
    let _work_dir_guard = TempDirGuard(work_dir.clone());
    if let Err(e) = ensure_dir_0700(&work_dir) {
        eprintln!("create temp work_dir: {e}");
        return ExitCode::FAILURE;
    }

    let (sample_bytes, sample_sha_hex) = build_sample_file_payload();
    let sample_file_path = work_dir.join("sample_p4b.bin");
    if let Err(e) = write_file_atomic_0600(&sample_file_path, &sample_bytes) {
        eprintln!("write sample file: {e}");
        return ExitCode::FAILURE;
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("resolve current_exe: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Provision Allowed tenant (for Scenario A and Scenario C) when needed.
    let mut allowed_tenant: Option<(String, String, PathBuf, PathBuf)> = None;
    if filter.run_a() || filter.run_c() {
        let tid_hex = hex::encode(random_bytes::<16>());
        let enroll = format!("v2-p4b-allow-{}", hex::encode(random_bytes::<8>()));
        let req = CreateTenantReq {
            tenant_id_hex: tid_hex.clone(),
            name: Some("zerodesk-p4b-allowed".into()),
            home_region: Some("local".into()),
            plan_tier: Some("pro".into()),
            monthly_quota_bytes: 20 * 1024 * 1024 * 1024,
            bw_cap_kbps: 50_000,
            exhaust_policy: 0,
            allow_file_transfer: true,
            enrollment_token: enroll.clone(),
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
        if let Err(e) = cp.create_tenant(admin_token, &req).await {
            eprintln!("create allowed tenant failed: {e}");
            return ExitCode::FAILURE;
        }
        let host_id = work_dir.join("allow_host_id");
        let ctrl_id = work_dir.join("allow_ctrl_id");
        if let Err(e) = ensure_dir_0700(&host_id).and_then(|_| ensure_dir_0700(&ctrl_id)) {
            eprintln!("create allowed identity dirs: {e}");
            return ExitCode::FAILURE;
        }
        allowed_tenant = Some((tid_hex, enroll, host_id, ctrl_id));
    }

    let scenario_a = if filter.run_a() {
        if let Some((ref tid, ref enroll, ref host_id, ref ctrl_id)) = allowed_tenant {
            let spec = Phase4bCaseSpec {
                name: "scenario_a_allowed_udp",
                host_transport: "udp",
                host_drop_udp: false,
                ctl_transport: "udp",
                ctl_drop_udp: false,
                expected_host_mode: "udp",
                expected_ctl_mode: "udp",
                check_host_fallback_lt_3s: false,
                check_ctl_fallback_lt_3s: false,
                denied_mode: false,
                send_file_twice: true,
            };
            Some(
                run_phase4b_case(
                    &exe,
                    &spec,
                    &config_path,
                    resolved_ca.as_deref(),
                    signaling_tls,
                    host_id,
                    ctrl_id,
                    &work_dir,
                    tid,
                    enroll,
                    codec,
                    frames,
                    &sample_file_path,
                    &sample_sha_hex,
                )
                .await,
            )
        } else {
            None
        }
    } else {
        None
    };

    let scenario_b = if filter.run_b() {
        let tid_hex = hex::encode(random_bytes::<16>());
        let enroll = format!("v2-p4b-deny-{}", hex::encode(random_bytes::<8>()));
        let req = CreateTenantReq {
            tenant_id_hex: tid_hex.clone(),
            name: Some("zerodesk-p4b-denied".into()),
            home_region: Some("local".into()),
            plan_tier: Some("restricted".into()),
            monthly_quota_bytes: 20 * 1024 * 1024 * 1024,
            bw_cap_kbps: 50_000,
            exhaust_policy: 0,
            allow_file_transfer: false,
            enrollment_token: enroll.clone(),
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
        if let Err(e) = cp.create_tenant(admin_token, &req).await {
            eprintln!("create denied tenant failed: {e}");
            return ExitCode::FAILURE;
        }
        let host_id = work_dir.join("deny_host_id");
        let ctrl_id = work_dir.join("deny_ctrl_id");
        if let Err(e) = ensure_dir_0700(&host_id).and_then(|_| ensure_dir_0700(&ctrl_id)) {
            eprintln!("create denied identity dirs: {e}");
            return ExitCode::FAILURE;
        }
        let spec = Phase4bCaseSpec {
            name: "scenario_b_denied_policy",
            host_transport: "udp",
            host_drop_udp: false,
            ctl_transport: "udp",
            ctl_drop_udp: false,
            expected_host_mode: "udp",
            expected_ctl_mode: "udp",
            check_host_fallback_lt_3s: false,
            check_ctl_fallback_lt_3s: false,
            denied_mode: true,
            send_file_twice: false,
        };
        Some(
            run_phase4b_case(
                &exe,
                &spec,
                &config_path,
                resolved_ca.as_deref(),
                signaling_tls,
                &host_id,
                &ctrl_id,
                &work_dir,
                &tid_hex,
                &enroll,
                codec,
                frames,
                &sample_file_path,
                &sample_sha_hex,
            )
            .await,
        )
    } else {
        None
    };

    let (scenario_c1, scenario_c2, scenario_c3) = if filter.run_c() {
        if let Some((ref tid, ref enroll, ref host_id, ref ctrl_id)) = allowed_tenant {
            let c1_spec = Phase4bCaseSpec {
                name: "scenario_c1_ctrl_drop_udp_fallback",
                host_transport: "auto",
                host_drop_udp: false,
                ctl_transport: "auto",
                ctl_drop_udp: true,
                expected_host_mode: "udp",
                expected_ctl_mode: "dual_tls443",
                check_host_fallback_lt_3s: false,
                check_ctl_fallback_lt_3s: true,
                denied_mode: false,
                send_file_twice: false,
            };
            let c1 = run_phase4b_case(
                &exe,
                &c1_spec,
                &config_path,
                resolved_ca.as_deref(),
                signaling_tls,
                host_id,
                ctrl_id,
                &work_dir,
                tid,
                enroll,
                codec,
                frames,
                &sample_file_path,
                &sample_sha_hex,
            )
            .await;

            let c2_spec = Phase4bCaseSpec {
                name: "scenario_c2_host_drop_udp_fallback",
                host_transport: "auto",
                host_drop_udp: true,
                ctl_transport: "auto",
                ctl_drop_udp: false,
                expected_host_mode: "dual_tls443",
                expected_ctl_mode: "udp",
                check_host_fallback_lt_3s: true,
                check_ctl_fallback_lt_3s: false,
                denied_mode: false,
                send_file_twice: false,
            };
            let c2 = run_phase4b_case(
                &exe,
                &c2_spec,
                &config_path,
                resolved_ca.as_deref(),
                signaling_tls,
                host_id,
                ctrl_id,
                &work_dir,
                tid,
                enroll,
                codec,
                frames,
                &sample_file_path,
                &sample_sha_hex,
            )
            .await;

            let c3_spec = Phase4bCaseSpec {
                name: "scenario_c3_tls443_only",
                host_transport: "tls443",
                host_drop_udp: false,
                ctl_transport: "tls443",
                ctl_drop_udp: false,
                expected_host_mode: "dual_tls443",
                expected_ctl_mode: "dual_tls443",
                check_host_fallback_lt_3s: false,
                check_ctl_fallback_lt_3s: false,
                denied_mode: false,
                send_file_twice: false,
            };
            let c3 = run_phase4b_case(
                &exe,
                &c3_spec,
                &config_path,
                resolved_ca.as_deref(),
                signaling_tls,
                host_id,
                ctrl_id,
                &work_dir,
                tid,
                enroll,
                codec,
                frames,
                &sample_file_path,
                &sample_sha_hex,
            )
            .await;
            (Some(c1), Some(c2), Some(c3))
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    let (zero_rendezvous_verified, rdv_err) = match contains_rendezvous_file(&work_dir) {
        Ok(None) => (true, None),
        Ok(Some(p)) => (
            false,
            Some(format!("unexpected rendezvous file found: {}", p.display())),
        ),
        Err(e) => (false, Some(format!("rendezvous scan failed: {e}"))),
    };

    let all_cases_ok = [&scenario_a, &scenario_b, &scenario_c1, &scenario_c2, &scenario_c3]
        .iter()
        .all(|opt| opt.as_ref().is_none_or(|r| r.pass));
    let pass = all_cases_ok && zero_rendezvous_verified;

    let report = Phase4bE2eReport {
        pass,
        zero_rendezvous_verified,
        scenario_a_allowed_udp: scenario_a,
        scenario_b_denied_policy: scenario_b,
        scenario_c1_ctrl_drop_udp_fallback: scenario_c1,
        scenario_c2_host_drop_udp_fallback: scenario_c2,
        scenario_c3_tls443_only: scenario_c3,
        error: rdv_err,
    };
    drop(_work_dir_guard);

    if let Ok(json) = serde_json::to_string_pretty(&report) {
        println!("{json}");
    }
    if pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scenario_filter_parses_all_variants_and_rejects_unknown() {
        assert_eq!(ScenarioFilter::parse("all"), Ok(ScenarioFilter::All));
        assert_eq!(ScenarioFilter::parse("A"), Ok(ScenarioFilter::A));
        assert_eq!(ScenarioFilter::parse("scenario_b"), Ok(ScenarioFilter::B));
        assert_eq!(ScenarioFilter::parse("c"), Ok(ScenarioFilter::C));
        assert!(ScenarioFilter::parse("d").is_err());
    }

    #[test]
    fn verify_saved_files_checks_sha256_and_collision_suffix() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-p4b-disk-{}-{uniq}", std::process::id()));
        ensure_dir_0700(&dir).unwrap();
        let (data, sha_hex) = build_sample_file_payload();
        let p1 = dir.join("sample_p4b.bin");
        let p2 = dir.join("sample_p4b (1).bin");
        write_file_atomic_0600(&p1, &data).unwrap();
        write_file_atomic_0600(&p2, &data).unwrap();

        let paths = vec![p1.display().to_string(), p2.display().to_string()];
        assert_eq!(verify_saved_files_on_disk(&paths, &sha_hex, true), Ok(true));
        // Duplicate identical path must fail collision check
        let dup = vec![p1.display().to_string(), p1.display().to_string()];
        assert!(verify_saved_files_on_disk(&dup, &sha_hex, true).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
