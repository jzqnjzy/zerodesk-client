// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{ExitCode, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
};
use v2_client::{
    decode_hex_array, ClusterConfig, ControlPlaneClient, CreateTenantReq,
};
use v2_e2e::{
    decode_hid_frame, detect_visual_marker, encode_hid_frame, ensure_dir_0700,
    ordered_session_teardown, parse_request_idr, parse_session_close,
    send_redundant_session_close_3x, spawn_capture_pipeline, spawn_independent_release_watchdog,
    write_audit_records_jsonl, write_file_atomic_0600, AuditKey, AuditRecord, CloseReason,
    DecodedVideoDelivery, DesktopControllerClient, DesktopControllerSession, DesktopHostDaemon,
    DesktopHostSession, DryRunSink, HidEchoAck, HidInputExecutor, HidPayload, InputError, KeyEvent,
    MouseEvent, MouseKind, NoopUiCallback, SafeHidKey, SessionError, SharedVisualMarker,
    SyntheticAnimatedSource, UiCallbackDispatcher, V2ClientConfig, V2VideoDecoder, V2VideoEncoder,
    VideoCodec, DEFAULT_HID_RATE_LIMIT_PER_SEC, DEFAULT_SYNTHETIC_HEIGHT, DEFAULT_SYNTHETIC_WIDTH,
    MOD_SHIFT, MOUSE_BUTTON_LEFT,
};
use v2_transport::{TransportEvent, IDR_MIN_INTERVAL_MS};

const ENCODER_QUALITY: f32 = 2.0;
const KEYFRAME_INTERVAL: usize = 30;
const MARKER_TARGET_X: i32 = 640;
const MARKER_TARGET_Y: i32 = 360;
const CTRL_MSG_KEEPALIVE: u8 = 0x03;

#[cfg(unix)]
extern "C" {
    fn setpgid(pid: i32, pgid: i32) -> i32;
    fn kill(pid: i32, sig: i32) -> i32;
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn parse_flag_value(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostReadyFile {
    device_id_hex: String,
    tenant_id_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostDaemonSummary {
    pass: bool,
    role: String,
    codec: String,
    device_id_hex: String,
    tenant_id_hex: String,
    handshake_hash_hex: String,
    width: usize,
    height: usize,
    frames_sent: u64,
    frames_captured: u64,
    frames_overwritten: u64,
    hid_executed: u64,
    release_all_count: u64,
    watchdog_release_count: u64,
    final_pressed_buttons: u8,
    final_pressed_keys: Vec<SafeHidKey>,
    input_faulted: bool,
    close_reason: String,
    capture_thread_joined: bool,
    watchdog_thread_joined: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControllerClientSummary {
    pass: bool,
    role: String,
    codec: String,
    device_id_hex: String,
    target_device_id_hex: String,
    tenant_id_hex: String,
    handshake_hash_hex: String,
    frames_decoded: u64,
    frame_id_monotonic: bool,
    decode_errors: u64,
    decoder_flushed_frames: u64,
    hid_events_sent: u64,
    visual_marker_before_hid: bool,
    visual_marker_detected_frames: u64,
    lease_renewals_ok: u64,
    lease_renewals_err: u64,
    leave_stuck: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ComparableHidEvent {
    MouseMoveAbs { x: i32, y: i32 },
    MouseMoveRel { dx: i32, dy: i32 },
    MouseDown { button_bit: u8, x: i32, y: i32 },
    MouseUp { button_bit: u8, x: i32, y: i32 },
    MouseWheel { dx: i16, dy: i16 },
    KeyDown { key: AuditKey },
    KeyUp { key: AuditKey },
}

fn audit_to_comparable(rec: &AuditRecord) -> Option<ComparableHidEvent> {
    match rec {
        AuditRecord::MouseMoveAbs { x, y, .. } => {
            Some(ComparableHidEvent::MouseMoveAbs { x: *x, y: *y })
        }
        AuditRecord::MouseMoveRel { dx, dy, .. } => {
            Some(ComparableHidEvent::MouseMoveRel { dx: *dx, dy: *dy })
        }
        AuditRecord::MouseDown {
            button_bit, x, y, ..
        } => Some(ComparableHidEvent::MouseDown {
            button_bit: *button_bit,
            x: *x,
            y: *y,
        }),
        AuditRecord::MouseUp {
            button_bit, x, y, ..
        } => Some(ComparableHidEvent::MouseUp {
            button_bit: *button_bit,
            x: *x,
            y: *y,
        }),
        AuditRecord::MouseWheel { dx, dy, .. } => {
            Some(ComparableHidEvent::MouseWheel { dx: *dx, dy: *dy })
        }
        AuditRecord::KeyDown { key, .. } => Some(ComparableHidEvent::KeyDown { key: *key }),
        AuditRecord::KeyUp { key, .. } => Some(ComparableHidEvent::KeyUp { key: *key }),
        AuditRecord::Dropped { .. } | AuditRecord::ReleaseAll { .. } => None,
    }
}

fn read_audit_jsonl(path: &Path) -> Result<Vec<AuditRecord>, String> {
    let f = File::open(path).map_err(|e| format!("open audit '{}': {e}", path.display()))?;
    let reader = BufReader::new(f);
    let mut records = Vec::new();
    for (idx, line_res) in reader.lines().enumerate() {
        let line = line_res.map_err(|e| format!("read audit line {}: {e}", idx + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rec: AuditRecord = serde_json::from_str(trimmed)
            .map_err(|e| format!("parse audit line {}: {e}", idx + 1))?;
        records.push(rec);
    }
    Ok(records)
}

/// Builds the deterministic 12-event v1.2.3-compliant HID verification sequence.
/// Uses post-event `buttons` on `MouseKind::Up` (`0`) and consistent `MOD_SHIFT` on `LeftShift`.
fn build_v123_hid_script(audit_key_identity: bool) -> Vec<(HidPayload, AuditRecord)> {
    let base_ts = now_ms();
    let mut items = Vec::with_capacity(12);
    let mut seq = 0u32;

    let mut push_mouse = |kind: MouseKind,
                          buttons: u8,
                          x: i32,
                          y: i32,
                          wdx: i16,
                          wdy: i16,
                          audit: AuditRecord| {
        let ev = MouseEvent {
            kind,
            buttons,
            x_or_dx: x,
            y_or_dy: y,
            wheel_dx: wdx,
            wheel_dy: wdy,
            client_ts_ms: base_ts + u64::from(seq),
        };
        items.push((HidPayload::Mouse(ev), audit));
        seq += 1;
    };

    push_mouse(
        MouseKind::MoveAbs,
        0,
        320,
        240,
        0,
        0,
        AuditRecord::MouseMoveAbs {
            seq: 0,
            x: 320,
            y: 240,
            ts_ms: base_ts,
        },
    );
    push_mouse(
        MouseKind::MoveRel,
        0,
        20,
        -10,
        0,
        0,
        AuditRecord::MouseMoveRel {
            seq: 1,
            dx: 20,
            dy: -10,
            cur_x: 340,
            cur_y: 230,
            ts_ms: base_ts + 1,
        },
    );
    push_mouse(
        MouseKind::Down,
        MOUSE_BUTTON_LEFT,
        340,
        230,
        0,
        0,
        AuditRecord::MouseDown {
            seq: 2,
            button_bit: MOUSE_BUTTON_LEFT,
            x: 340,
            y: 230,
            ts_ms: base_ts + 2,
        },
    );
    // v1.2.3 post-event bitmap: releasing Left sends `buttons = 0`
    push_mouse(
        MouseKind::Up,
        0,
        340,
        230,
        0,
        0,
        AuditRecord::MouseUp {
            seq: 3,
            button_bit: MOUSE_BUTTON_LEFT,
            x: 340,
            y: 230,
            ts_ms: base_ts + 3,
        },
    );
    push_mouse(
        MouseKind::Wheel,
        0,
        340,
        230,
        0,
        3,
        AuditRecord::MouseWheel {
            seq: 4,
            dx: 0,
            dy: 3,
            ts_ms: base_ts + 4,
        },
    );

    let key_steps: &[(bool, SafeHidKey)] = &[
        (true, SafeHidKey::KeyA),
        (false, SafeHidKey::KeyA),
        (true, SafeHidKey::LeftShift),
        (true, SafeHidKey::KeyB),
        (false, SafeHidKey::KeyB),
        (false, SafeHidKey::LeftShift),
    ];
    let mut active_mods = 0u8;
    for &(down, key) in key_steps {
        let ts = base_ts + u64::from(seq);
        if key == SafeHidKey::LeftShift {
            if down {
                active_mods |= MOD_SHIFT;
            } else {
                active_mods &= !MOD_SHIFT;
            }
        }
        let ev = KeyEvent {
            down,
            modifiers: active_mods,
            usb_hid_usage: key.usb_hid_usage(),
            unicode_scalar: 0,
            client_ts_ms: ts,
        };
        let audit_key = if audit_key_identity {
            AuditKey::Key(key)
        } else {
            AuditKey::Redacted
        };
        let rec = if down {
            AuditRecord::KeyDown {
                seq,
                key: audit_key,
                ts_ms: ts,
            }
        } else {
            AuditRecord::KeyUp {
                seq,
                key: audit_key,
                ts_ms: ts,
            }
        };
        items.push((HidPayload::Key(ev), rec));
        seq += 1;
    }

    let ts = base_ts + u64::from(seq);
    items.push((
        HidPayload::Mouse(MouseEvent {
            kind: MouseKind::MoveAbs,
            buttons: 0,
            x_or_dx: MARKER_TARGET_X,
            y_or_dy: MARKER_TARGET_Y,
            wheel_dx: 0,
            wheel_dy: 0,
            client_ts_ms: ts,
        }),
        AuditRecord::MouseMoveAbs {
            seq,
            x: MARKER_TARGET_X,
            y: MARKER_TARGET_Y,
            ts_ms: ts,
        },
    ));
    items
}

struct HostDaemonArgs {
    config: PathBuf,
    ca_der: Option<PathBuf>,
    identity_dir: PathBuf,
    audit_out: PathBuf,
    codec: VideoCodec,
    fps: u32,
    watchdog_ms: u64,
    idle_exit_ms: u64,
    ready_file: Option<PathBuf>,
    enrollment_token: Option<String>,
    audit_key_identity: bool,
}

async fn run_v2_hostd(args: &HostDaemonArgs) -> Result<HostDaemonSummary, String> {
    let cluster = ClusterConfig::from_file(&args.config).map_err(|e| e.to_string())?;
    let mut v2_cfg = V2ClientConfig::from_cluster_config(
        &cluster,
        args.identity_dir.clone(),
        args.ca_der.clone(),
        args.enrollment_token.clone(),
    );
    v2_cfg.codec = args.codec;
    v2_cfg.fps = args.fps;
    v2_cfg.watchdog_timeout_ms = args.watchdog_ms;
    v2_cfg.validate().map_err(|e| e.to_string())?;

    let dispatcher = UiCallbackDispatcher::spawn(Arc::new(NoopUiCallback));
    let mut daemon = DesktopHostDaemon::bootstrap(v2_cfg, dispatcher)
        .await
        .map_err(|e| e.to_string())?;

    let device_id_hex = hex::encode(daemon.device_id());
    let tenant_id_hex = daemon
        .tenant_id()
        .map(hex::encode)
        .ok_or_else(|| "host daemon missing tenant_id after registration".to_string())?;

    // Write ONLY public device_id_hex + tenant_id_hex to --ready-file (NO certs, NO tickets, NO rendezvous.json).
    if let Some(ready_path) = &args.ready_file {
        let ready = HostReadyFile {
            device_id_hex: device_id_hex.clone(),
            tenant_id_hex: tenant_id_hex.clone(),
        };
        let bytes = serde_json::to_vec_pretty(&ready).map_err(|e| e.to_string())?;
        write_file_atomic_0600(ready_path, &bytes).map_err(|e| e.to_string())?;
    }

    let sig_stop = Arc::new(AtomicBool::new(false));
    {
        let sig_flag = Arc::clone(&sig_stop);
        tokio::spawn(async move {
            #[cfg(unix)]
            {
                let mut sigterm =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).ok();
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {
                        sig_flag.store(true, Ordering::Release);
                    }
                    _ = async {
                        if let Some(ref mut s) = sigterm {
                            let _ = s.recv().await;
                        } else {
                            std::future::pending::<()>().await;
                        }
                    } => {
                        sig_flag.store(true, Ordering::Release);
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = tokio::signal::ctrl_c().await;
                sig_flag.store(true, Ordering::Release);
            }
        });
    }

    let accepted = daemon
        .accept_next_session(Arc::clone(&sig_stop), Some(Duration::from_secs(30)))
        .await
        .map_err(|e| e.to_string())?;
    let handshake_hash_hex = hex::encode(accepted.hs_hash);
    let _ctrl_tunnel_b = accepted.ctrl_tunnel_b;

    let visual_marker: SharedVisualMarker = Arc::new(Mutex::new(None));
    let capture_stop = Arc::new(AtomicBool::new(false));
    let width = DEFAULT_SYNTHETIC_WIDTH;
    let height = DEFAULT_SYNTHETIC_HEIGHT;
    let source = SyntheticAnimatedSource::new(
        width,
        height,
        args.fps,
        Some(Arc::clone(&visual_marker)),
    )
    .map_err(|e| e.to_string())?;
    let mut capture = spawn_capture_pipeline(source, Arc::clone(&capture_stop))
        .map_err(|e| format!("spawn capture pipeline: {e}"))?;

    let encoder = V2VideoEncoder::new(
        args.codec,
        width as u32,
        height as u32,
        ENCODER_QUALITY,
        Some(KEYFRAME_INTERVAL),
    )
    .map_err(|e| e.to_string())?;
    let mut host = DesktopHostSession::new(accepted.e2ee_session, encoder);

    let mut executor = HidInputExecutor::with_options(
        DryRunSink::new(),
        width as i32,
        height as i32,
        DEFAULT_HID_RATE_LIMIT_PER_SEC,
        Some(visual_marker),
    )
    .map_err(|e| e.to_string())?
    .with_audit_key_identity(args.audit_key_identity);
    executor.startup_self_test().map_err(|e| e.to_string())?;

    let held_state = executor.held_state();
    let watchdog_audit = Arc::new(Mutex::new(Vec::<AuditRecord>::new()));
    let watchdog_stop = Arc::new(AtomicBool::new(false));
    let mut watchdog_handle = spawn_independent_release_watchdog(
        Arc::clone(&held_state),
        DryRunSink::new(),
        Duration::from_millis(args.watchdog_ms),
        Arc::clone(&watchdog_stop),
        Some(Arc::clone(&watchdog_audit)),
    )
    .map_err(|e| format!("spawn independent release watchdog: {e}"))?;

    let frame_interval = Duration::from_nanos(1_000_000_000u64 / u64::from(args.fps.max(1)));
    let idle_exit = Duration::from_millis(args.idle_exit_ms);
    let session_start = Instant::now();
    let mut last_peer_activity = Instant::now();
    let mut next_frame_at = Instant::now();
    let mut next_hid_seq = 0u32;
    let mut last_forced_idr: Option<Instant> = None;
    let mut force_next_idr = false;
    let close_reason: CloseReason;
    let mut fatal_error: Option<String> = None;

    loop {
        if sig_stop.load(Ordering::Acquire) {
            close_reason = CloseReason::Signal;
            break;
        }
        if held_state.is_faulted() {
            close_reason = CloseReason::InputFaulted;
            break;
        }
        if held_state.watchdog_release_count() > 0 {
            close_reason = CloseReason::WatchdogTimeout;
            break;
        }
        if last_peer_activity.elapsed() >= idle_exit {
            close_reason = CloseReason::IdleTimeout;
            break;
        }

        let recv_wait = next_frame_at
            .saturating_duration_since(Instant::now())
            .clamp(Duration::from_millis(1), Duration::from_millis(10));
        match host.session_mut().recv_event(recv_wait).await {
            Ok(TransportEvent::Hid(frame)) => {
                last_peer_activity = Instant::now();
                executor.touch_activity();
                match decode_hid_frame(&frame) {
                    Ok(payload) => {
                        let seq = next_hid_seq;
                        next_hid_seq = next_hid_seq.wrapping_add(1);
                        match executor.apply_v123_stream_batch(&[(seq, payload)]) {
                            Ok(outcome) => {
                                for (exec_seq, exec_payload) in outcome.executed {
                                    let ack = HidPayload::EchoAck(HidEchoAck {
                                        echo_seq: exec_seq,
                                        client_ts_ms: exec_payload.client_ts_ms(),
                                    });
                                    if let Ok(ack_frame) = encode_hid_frame(&ack) {
                                        let _ = host.session_mut().send_hid(&ack_frame).await;
                                    }
                                }
                            }
                            Err(InputError::InputFaulted) => {
                                close_reason = CloseReason::InputFaulted;
                                fatal_error = Some("HID input_faulted latched".into());
                                break;
                            }
                            Err(InputError::InvalidFraming(msg)) => {
                                close_reason = CloseReason::InvalidFraming;
                                fatal_error = Some(msg);
                                break;
                            }
                            Err(e) => {
                                close_reason = CloseReason::ProtocolError(e.to_string());
                                fatal_error = Some(e.to_string());
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // spec/04 §6: any InputHID wire framing error is session-fatal 0x0103!
                        close_reason = CloseReason::InvalidFraming;
                        fatal_error = Some(e.to_string());
                        break;
                    }
                }
            }
            Ok(TransportEvent::Control(ctrl)) => {
                last_peer_activity = Instant::now();
                executor.touch_activity();
                if let Some(code) = parse_session_close(&ctrl) {
                    close_reason = CloseReason::PeerClosed(code);
                    break;
                }
                if parse_request_idr(&ctrl).is_some()
                    && last_forced_idr
                        .is_none_or(|t| t.elapsed() >= Duration::from_millis(IDR_MIN_INTERVAL_MS))
                {
                    force_next_idr = true;
                    last_forced_idr = Some(Instant::now());
                }
            }
            Ok(_) => {
                last_peer_activity = Instant::now();
                executor.touch_activity();
            }
            Err(v2_client::ClientError::Timeout(_)) => {}
            Err(e) => {
                close_reason = CloseReason::ProtocolError(e.to_string());
                fatal_error = Some(e.to_string());
                break;
            }
        }

        if Instant::now() >= next_frame_at {
            next_frame_at = Instant::now() + frame_interval;
            if let Some(captured) = capture.try_take_latest_or_keepalive(Duration::from_millis(500))
            {
                if force_next_idr {
                    force_next_idr = false;
                    let new_enc = V2VideoEncoder::new(
                        args.codec,
                        width as u32,
                        height as u32,
                        ENCODER_QUALITY,
                        Some(KEYFRAME_INTERVAL),
                    )
                    .map_err(|e| e.to_string())?;
                    host.replace_encoder(new_enc);
                }
                let pts_ms = session_start.elapsed().as_millis() as i64;
                let _ = host.publish_i420_frame(captured.frame, pts_ms).await;
            }
        }
    }

    let watchdog_joined = watchdog_handle.stop_and_join().is_ok();
    executor.sync_from_held_state();

    let frames_sent = host.video_frames_sent;
    let frames_captured = capture.stats().frames_captured.load(Ordering::Acquire);
    let frames_overwritten = capture.stats().frames_overwritten.load(Ordering::Acquire);
    let (e2ee_session, _enc) = host.into_inner();

    // Strict ordered teardown: release_all -> stop capture -> 3x SESSION_CLOSE -> close data plane
    let teardown = ordered_session_teardown(
        Some(&mut executor),
        Some(capture),
        Some(e2ee_session),
        None,
        None,
        &close_reason,
    )
    .await;
    daemon.disconnect_signaling().await;

    // Merge executor audit records + independent watchdog ReleaseAll records before flushing JSONL.
    let mut merged_audit: Vec<AuditRecord> = executor.audit_log().iter().cloned().collect();
    if let Ok(wd_recs) = watchdog_audit.lock() {
        merged_audit.extend(wd_recs.iter().cloned());
    }
    write_audit_records_jsonl(&merged_audit, &args.audit_out)
        .map_err(|e| format!("flush host audit JSONL: {e}"))?;

    let final_buttons = held_state.pressed_buttons();
    let final_keys = held_state.pressed_keys_snapshot();
    let wd_releases = held_state.watchdog_release_count();
    let total_releases = executor.release_all_count.saturating_add(wd_releases);
    let pass = fatal_error.is_none()
        && final_buttons == 0
        && final_keys.is_empty()
        && !held_state.is_faulted()
        && teardown.capture_joined
        && watchdog_joined;

    Ok(HostDaemonSummary {
        pass,
        role: "v2-hostd".into(),
        codec: args.codec.name().into(),
        device_id_hex,
        tenant_id_hex,
        handshake_hash_hex,
        width,
        height,
        frames_sent,
        frames_captured,
        frames_overwritten,
        hid_executed: executor.executed_events,
        release_all_count: total_releases,
        watchdog_release_count: wd_releases,
        final_pressed_buttons: final_buttons,
        final_pressed_keys: final_keys,
        input_faulted: held_state.is_faulted(),
        close_reason: close_reason.label(),
        capture_thread_joined: teardown.capture_joined,
        watchdog_thread_joined: watchdog_joined,
        error: fatal_error,
    })
}

pub async fn cmd_v2_hostd(args: &[String]) -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut identity_dir: Option<PathBuf> = None;
    let mut audit_out: Option<PathBuf> = None;
    let mut codec = VideoCodec::Vp9;
    let mut fps = 30u32;
    let mut watchdog_ms = 1200u64;
    let mut idle_exit_ms = 10_000u64;
    let mut ready_file: Option<PathBuf> = None;
    let mut enrollment_token: Option<String> = None;
    let mut audit_key_identity = false;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| {
                config = Some(PathBuf::from(v));
            }),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| {
                ca_der = Some(PathBuf::from(v));
            }),
            "--identity-dir" => parse_flag_value(args, &mut i, "--identity-dir").map(|v| {
                identity_dir = Some(PathBuf::from(v));
            }),
            "--audit-out" => parse_flag_value(args, &mut i, "--audit-out").map(|v| {
                audit_out = Some(PathBuf::from(v));
            }),
            "--codec" => parse_flag_value(args, &mut i, "--codec")
                .and_then(|v| VideoCodec::parse_name(&v).map_err(|e| e.to_string()))
                .map(|c| codec = c),
            "--fps" => parse_flag_value(args, &mut i, "--fps")
                .and_then(|v| v.parse::<u32>().map_err(|e| e.to_string()))
                .map(|n| fps = n),
            "--watchdog-ms" => parse_flag_value(args, &mut i, "--watchdog-ms")
                .and_then(|v| v.parse::<u64>().map_err(|e| e.to_string()))
                .map(|n| watchdog_ms = n),
            "--idle-exit-ms" => parse_flag_value(args, &mut i, "--idle-exit-ms")
                .and_then(|v| v.parse::<u64>().map_err(|e| e.to_string()))
                .map(|n| idle_exit_ms = n),
            "--ready-file" => parse_flag_value(args, &mut i, "--ready-file").map(|v| {
                ready_file = Some(PathBuf::from(v));
            }),
            "--enrollment-token" => {
                parse_flag_value(args, &mut i, "--enrollment-token").map(|v| {
                    enrollment_token = Some(v);
                })
            }
            "--audit-key-identity" => {
                audit_key_identity = true;
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

    let (Some(config), Some(identity_dir), Some(audit_out)) = (config, identity_dir, audit_out)
    else {
        eprintln!(
            "usage: v2-hostd --config <cluster.json> [--ca-der <path>] --identity-dir <dir> --audit-out <jsonl> [--codec vp9|av1] [--fps 30] [--watchdog-ms 1200] [--idle-exit-ms 10000] [--ready-file <path>] [--enrollment-token <tok>]"
        );
        return ExitCode::from(2);
    };

    let host_args = HostDaemonArgs {
        config,
        ca_der,
        identity_dir,
        audit_out,
        codec,
        fps,
        watchdog_ms,
        idle_exit_ms,
        ready_file,
        enrollment_token,
        audit_key_identity,
    };

    match run_v2_hostd(&host_args).await {
        Ok(summary) => {
            if let Ok(json) = serde_json::to_string_pretty(&summary) {
                println!("{json}");
            }
            if summary.pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            let err = serde_json::json!({
                "pass": false,
                "role": "v2-hostd",
                "error": e,
            });
            if let Ok(json) = serde_json::to_string_pretty(&err) {
                println!("{json}");
            }
            ExitCode::FAILURE
        }
    }
}

struct ControllerClientArgs {
    config: PathBuf,
    ca_der: Option<PathBuf>,
    identity_dir: PathBuf,
    target_device_id: [u8; 16],
    tenant_id: [u8; 16],
    enrollment_token: String,
    audit_out: PathBuf,
    codec: VideoCodec,
    frames: usize,
    leave_stuck: bool,
    hold_after_stuck_ms: u64,
    stuck_ready_file: Option<PathBuf>,
    audit_key_identity: bool,
}

async fn recv_video_with_keepalive(
    controller: &mut DesktopControllerSession,
    timeout: Duration,
    keepalive_interval: Duration,
    last_tx: &mut Instant,
) -> Result<DecodedVideoDelivery, SessionError> {
    let deadline = Instant::now() + timeout;
    loop {
        if last_tx.elapsed() >= keepalive_interval {
            controller
                .session_mut()
                .send_control(CTRL_MSG_KEEPALIVE, &now_ms().to_be_bytes())
                .await?;
            *last_tx = Instant::now();
        }
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            return Err(v2_client::ClientError::Timeout("controller video recv timed out".into()).into());
        };
        let until_ka = keepalive_interval
            .saturating_sub(last_tx.elapsed())
            .max(Duration::from_millis(1));
        match controller.recv_and_decode_video(rem.min(until_ka)).await {
            Ok(delivery) => {
                if last_tx.elapsed() >= keepalive_interval {
                    controller
                        .session_mut()
                        .send_control(CTRL_MSG_KEEPALIVE, &now_ms().to_be_bytes())
                        .await?;
                    *last_tx = Instant::now();
                }
                return Ok(delivery);
            }
            Err(SessionError::Client(v2_client::ClientError::Timeout(_))) => {
                if Instant::now() >= deadline {
                    return Err(
                        v2_client::ClientError::Timeout("controller video recv timed out".into())
                            .into(),
                    );
                }
            }
            Err(e) => return Err(e),
        }
    }
}

async fn run_v2_ctl(args: &ControllerClientArgs) -> Result<ControllerClientSummary, String> {
    let cluster = ClusterConfig::from_file(&args.config).map_err(|e| e.to_string())?;
    let mut v2_cfg = V2ClientConfig::from_cluster_config(
        &cluster,
        args.identity_dir.clone(),
        args.ca_der.clone(),
        Some(args.enrollment_token.clone()),
    );
    v2_cfg.codec = args.codec;
    v2_cfg.validate().map_err(|e| e.to_string())?;

    let dispatcher = UiCallbackDispatcher::spawn(Arc::new(NoopUiCallback));
    let mut client = DesktopControllerClient::bootstrap(v2_cfg, dispatcher)
        .await
        .map_err(|e| e.to_string())?;

    let device_id_hex = hex::encode(client.device_id());
    let connected = client
        .dial(
            args.target_device_id,
            Some(args.tenant_id),
            Duration::from_secs(20),
        )
        .await
        .map_err(|e| e.to_string())?;

    let handshake_hash_hex = hex::encode(connected.hs_hash);
    let keepalive_interval = connected.keepalive_interval;
    let lease_renewal = connected.lease_renewal;

    let decoder = V2VideoDecoder::new(args.codec).map_err(|e| e.to_string())?;
    let mut controller = DesktopControllerSession::new(connected.e2ee_session, decoder);

    let mut frames_decoded = 0u64;
    let mut last_frame_id: Option<u32> = None;
    let mut frame_id_monotonic = true;
    let mut hid_events_sent = 0u64;
    let mut visual_marker_before_hid = false;
    let mut visual_marker_detected_frames = 0u64;
    let mut sent_audit = Vec::<AuditRecord>::new();
    let mut last_tx = Instant::now();

    let run_res: Result<(), String> = if args.leave_stuck {
        async {
            let first = recv_video_with_keepalive(
                &mut controller,
                Duration::from_secs(10),
                keepalive_interval,
                &mut last_tx,
            )
            .await
            .map_err(|e| format!("initial video recv failed: {e}"))?;
            last_frame_id = Some(first.frame.frame_id);
            frames_decoded += 1;

            let base_ts = now_ms();
            let key_audit = |k: SafeHidKey| {
                if args.audit_key_identity {
                    AuditKey::Key(k)
                } else {
                    AuditKey::Redacted
                }
            };
            let stuck_events = [
                (
                    0u32,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: MOD_SHIFT,
                        usb_hid_usage: SafeHidKey::LeftShift.usb_hid_usage(),
                        unicode_scalar: 0,
                        client_ts_ms: base_ts,
                    }),
                    AuditRecord::KeyDown {
                        seq: 0,
                        key: key_audit(SafeHidKey::LeftShift),
                        ts_ms: base_ts,
                    },
                ),
                (
                    1u32,
                    HidPayload::Key(KeyEvent {
                        down: true,
                        modifiers: MOD_SHIFT,
                        usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                        unicode_scalar: 'A' as u32,
                        client_ts_ms: base_ts + 1,
                    }),
                    AuditRecord::KeyDown {
                        seq: 1,
                        key: key_audit(SafeHidKey::KeyA),
                        ts_ms: base_ts + 1,
                    },
                ),
                (
                    2u32,
                    HidPayload::Mouse(MouseEvent {
                        kind: MouseKind::Down,
                        buttons: MOUSE_BUTTON_LEFT,
                        x_or_dx: MARKER_TARGET_X,
                        y_or_dy: MARKER_TARGET_Y,
                        wheel_dx: 0,
                        wheel_dy: 0,
                        client_ts_ms: base_ts + 2,
                    }),
                    AuditRecord::MouseDown {
                        seq: 2,
                        button_bit: MOUSE_BUTTON_LEFT,
                        x: MARKER_TARGET_X,
                        y: MARKER_TARGET_Y,
                        ts_ms: base_ts + 2,
                    },
                ),
            ];
            for (expected_seq, payload, rec) in stuck_events {
                let _ = controller
                    .send_hid_and_await_echo(&payload, expected_seq, Duration::from_secs(5))
                    .await
                    .map_err(|e| format!("stuck HID seq {expected_seq} echo failed: {e}"))?;
                last_tx = Instant::now();
                hid_events_sent += 1;
                sent_audit.push(rec);
            }
            write_audit_records_jsonl(&sent_audit, &args.audit_out)
                .map_err(|e| format!("write controller audit: {e}"))?;
            if let Some(path) = &args.stuck_ready_file {
                write_file_atomic_0600(path, b"ready\n").map_err(|e| e.to_string())?;
            }
            eprintln!("[v2-ctl] stuck_ready");

            if args.hold_after_stuck_ms > 0 {
                tokio::time::sleep(Duration::from_millis(args.hold_after_stuck_ms)).await;
            }
            Ok(())
        }
        .await
    } else {
        async {
            let target_frames = args.frames.max(1);
            let pre_hid_frames = 2usize.min(target_frames);
            for _ in 0..pre_hid_frames {
                let d = recv_video_with_keepalive(
                    &mut controller,
                    Duration::from_secs(10),
                    keepalive_interval,
                    &mut last_tx,
                )
                .await
                .map_err(|e| format!("pre-HID video recv: {e}"))?;
                if let Some(prev) = last_frame_id {
                    if d.frame.frame_id <= prev {
                        frame_id_monotonic = false;
                    }
                }
                last_frame_id = Some(d.frame.frame_id);
                frames_decoded += 1;
                if detect_visual_marker(&d.i420, MARKER_TARGET_X, MARKER_TARGET_Y).detected {
                    visual_marker_before_hid = true;
                }
            }

            let script = build_v123_hid_script(args.audit_key_identity);
            for (idx, (payload, rec)) in script.into_iter().enumerate() {
                let _ = controller
                    .send_hid_and_await_echo(&payload, idx as u32, Duration::from_secs(5))
                    .await
                    .map_err(|e| format!("HID seq {idx} echo failed: {e}"))?;
                last_tx = Instant::now();
                hid_events_sent += 1;
                sent_audit.push(rec);
            }

            while (frames_decoded as usize) < target_frames {
                let d = recv_video_with_keepalive(
                    &mut controller,
                    Duration::from_secs(10),
                    keepalive_interval,
                    &mut last_tx,
                )
                .await
                .map_err(|e| format!("post-HID video recv: {e}"))?;
                if let Some(prev) = last_frame_id {
                    if d.frame.frame_id <= prev {
                        frame_id_monotonic = false;
                    }
                }
                last_frame_id = Some(d.frame.frame_id);
                frames_decoded += 1;
                if detect_visual_marker(&d.i420, MARKER_TARGET_X, MARKER_TARGET_Y).detected {
                    visual_marker_detected_frames += 1;
                }
            }

            let _ = controller.flush_decoder();
            write_audit_records_jsonl(&sent_audit, &args.audit_out)
                .map_err(|e| format!("write controller audit: {e}"))?;
            Ok(())
        }
        .await
    };

    let _ = send_redundant_session_close_3x(controller.session_mut(), 0x0000).await;
    let (lease_renewals_ok, lease_renewals_err) = lease_renewal.shutdown().await;
    if let Some(mut sig) = client.take_signaling() {
        let _ = sig.shutdown().await;
    }

    let decode_errors = controller.decode_errors;
    let decoder_flushed_frames = controller.decoder_flushed_frames;
    let pass = run_res.is_ok()
        && frame_id_monotonic
        && decode_errors == 0
        && (args.leave_stuck
            || (frames_decoded as usize >= args.frames.max(1)
                && !visual_marker_before_hid
                && visual_marker_detected_frames > 0));

    Ok(ControllerClientSummary {
        pass,
        role: "v2-ctl".into(),
        codec: args.codec.name().into(),
        device_id_hex,
        target_device_id_hex: hex::encode(args.target_device_id),
        tenant_id_hex: hex::encode(args.tenant_id),
        handshake_hash_hex,
        frames_decoded,
        frame_id_monotonic,
        decode_errors,
        decoder_flushed_frames,
        hid_events_sent,
        visual_marker_before_hid,
        visual_marker_detected_frames,
        lease_renewals_ok,
        lease_renewals_err,
        leave_stuck: args.leave_stuck,
        error: run_res.err(),
    })
}

pub async fn cmd_v2_ctl(args: &[String]) -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut identity_dir: Option<PathBuf> = None;
    let mut target_device_id_hex: Option<String> = None;
    let mut tenant_id_hex: Option<String> = None;
    let mut enrollment_token: Option<String> = None;
    let mut audit_out: Option<PathBuf> = None;
    let mut codec = VideoCodec::Vp9;
    let mut frames = 30usize;
    let mut leave_stuck = false;
    let mut hold_after_stuck_ms = 0u64;
    let mut stuck_ready_file: Option<PathBuf> = None;
    let mut audit_key_identity = false;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| {
                config = Some(PathBuf::from(v));
            }),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| {
                ca_der = Some(PathBuf::from(v));
            }),
            "--identity-dir" => parse_flag_value(args, &mut i, "--identity-dir").map(|v| {
                identity_dir = Some(PathBuf::from(v));
            }),
            "--target-device-id" => parse_flag_value(args, &mut i, "--target-device-id").map(|v| {
                target_device_id_hex = Some(v);
            }),
            "--tenant-id" => parse_flag_value(args, &mut i, "--tenant-id").map(|v| {
                tenant_id_hex = Some(v);
            }),
            "--enrollment-token" => parse_flag_value(args, &mut i, "--enrollment-token").map(|v| {
                enrollment_token = Some(v);
            }),
            "--audit-out" => parse_flag_value(args, &mut i, "--audit-out").map(|v| {
                audit_out = Some(PathBuf::from(v));
            }),
            "--codec" => parse_flag_value(args, &mut i, "--codec")
                .and_then(|v| VideoCodec::parse_name(&v).map_err(|e| e.to_string()))
                .map(|c| codec = c),
            "--frames" => parse_flag_value(args, &mut i, "--frames")
                .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                .map(|n| frames = n),
            "--leave-stuck" => {
                leave_stuck = true;
                Ok(())
            }
            "--hold-after-stuck-ms" => parse_flag_value(args, &mut i, "--hold-after-stuck-ms")
                .and_then(|v| v.parse::<u64>().map_err(|e| e.to_string()))
                .map(|n| hold_after_stuck_ms = n),
            "--stuck-ready-file" => parse_flag_value(args, &mut i, "--stuck-ready-file").map(|v| {
                stuck_ready_file = Some(PathBuf::from(v));
            }),
            "--audit-key-identity" => {
                audit_key_identity = true;
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

    let (
        Some(config),
        Some(identity_dir),
        Some(target_hex),
        Some(tenant_hex),
        Some(enrollment_token),
        Some(audit_out),
    ) = (
        config,
        identity_dir,
        target_device_id_hex,
        tenant_id_hex,
        enrollment_token,
        audit_out,
    )
    else {
        eprintln!(
            "usage: v2-ctl --config <cluster.json> [--ca-der <path>] --identity-dir <dir> --target-device-id <hex> --tenant-id <hex> --enrollment-token <tok> --audit-out <jsonl> [--codec vp9|av1] [--frames 30] [--leave-stuck] [--hold-after-stuck-ms <ms>]"
        );
        return ExitCode::from(2);
    };

    let target_device_id = match decode_hex_array::<16>(&target_hex, "target-device-id") {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };
    let tenant_id = match decode_hex_array::<16>(&tenant_hex, "tenant-id") {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::from(2);
        }
    };

    let ctl_args = ControllerClientArgs {
        config,
        ca_der,
        identity_dir,
        target_device_id,
        tenant_id,
        enrollment_token,
        audit_out,
        codec,
        frames,
        leave_stuck,
        hold_after_stuck_ms,
        stuck_ready_file,
        audit_key_identity,
    };

    match run_v2_ctl(&ctl_args).await {
        Ok(summary) => {
            if let Ok(json) = serde_json::to_string_pretty(&summary) {
                println!("{json}");
            }
            if summary.pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        Err(e) => {
            let err = serde_json::json!({
                "pass": false,
                "role": "v2-ctl",
                "error": e,
            });
            if let Ok(json) = serde_json::to_string_pretty(&err) {
                println!("{json}");
            }
            ExitCode::FAILURE
        }
    }
}

struct ChildGroupGuard {
    child: Option<Child>,
    pgid: Option<i32>,
}

impl ChildGroupGuard {
    fn spawn_in_group(cmd: &mut Command) -> Result<Self, String> {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(unix)]
        unsafe {
            cmd.pre_exec(|| {
                let _ = setpgid(0, 0);
                Ok(())
            });
        }
        let child = cmd.spawn().map_err(|e| format!("spawn child: {e}"))?;
        let pgid = child.id().map(|id| id as i32);
        Ok(Self {
            child: Some(child),
            pgid,
        })
    }

    fn sigkill_group(&mut self) {
        #[cfg(unix)]
        if let Some(pgid) = self.pgid {
            unsafe {
                let _ = kill(-pgid, 9);
            }
        }
        if let Some(child) = self.child.as_mut() {
            let _ = child.start_kill();
        }
    }

    async fn wait_with_output(
        mut self,
        timeout: Duration,
    ) -> Result<(std::process::ExitStatus, String, String), String> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| "child already consumed".to_string())?;
        let mut stdout = child.stdout.take();
        let mut stderr = child.stderr.take();
        let out_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut s) = stdout.take() {
                let _ = s.read_to_end(&mut buf).await;
            }
            String::from_utf8_lossy(&buf).into_owned()
        });
        let err_task = tokio::spawn(async move {
            let mut buf = Vec::new();
            if let Some(mut s) = stderr.take() {
                let _ = s.read_to_end(&mut buf).await;
            }
            String::from_utf8_lossy(&buf).into_owned()
        });

        let status = match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(st)) => st,
            Ok(Err(e)) => return Err(format!("wait child: {e}")),
            Err(_) => {
                #[cfg(unix)]
                if let Some(pgid) = self.pgid {
                    unsafe {
                        let _ = kill(-pgid, 9);
                    }
                }
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Err("child process timed out".into());
            }
        };
        let out_str = out_task.await.unwrap_or_default();
        let err_str = err_task.await.unwrap_or_default();
        Ok((status, out_str, err_str))
    }
}

impl Drop for ChildGroupGuard {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.sigkill_group();
        }
    }
}

async fn wait_for_file(path: &Path, timeout: Duration) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(bytes) = fs::read(path) {
            if !bytes.is_empty() {
                return Ok(bytes);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for '{}'", path.display()));
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

fn contains_rendezvous_file(root: &Path) -> Result<Option<PathBuf>, String> {
    let entries = fs::read_dir(root)
        .map_err(|e| format!("scan dir '{}': {e}", root.display()))?;
    for entry_res in entries {
        let entry = entry_res.map_err(|e| e.to_string())?;
        let p = entry.path();
        if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
            if name.to_ascii_lowercase().contains("rendezvous") {
                return Ok(Some(p));
            }
        }
        if p.is_dir() {
            if let Some(found) = contains_rendezvous_file(&p)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

#[derive(Debug, Serialize)]
struct ScenarioReport {
    name: String,
    codec: String,
    pass: bool,
    handshake_hash_matched: bool,
    audit_events_matched: usize,
    audit_events_expected: usize,
    host_summary: Option<HostDaemonSummary>,
    controller_summary: Option<ControllerClientSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct SignalingE2eReport {
    pass: bool,
    zero_rendezvous_verified: bool,
    scenario_1_vp9: ScenarioReport,
    scenario_2_av1: ScenarioReport,
    scenario_3_sigkill_watchdog: ScenarioReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
async fn run_signaling_normal_scenario(
    exe: &Path,
    name: &str,
    config_path: &Path,
    ca_der: Option<&Path>,
    host_id_dir: &Path,
    ctrl_id_dir: &Path,
    work_dir: &Path,
    tenant_id_hex: &str,
    enrollment_token: &str,
    codec: VideoCodec,
    frames: usize,
) -> ScenarioReport {
    let ready_file = work_dir.join(format!("{name}_host_ready.json"));
    let host_audit = work_dir.join(format!("{name}_host_audit.jsonl"));
    let ctrl_audit = work_dir.join(format!("{name}_ctrl_audit.jsonl"));

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
        .arg("1500")
        .arg("--idle-exit-ms")
        .arg("20000")
        .arg("--ready-file")
        .arg(&ready_file)
        .arg("--enrollment-token")
        .arg(enrollment_token)
        .arg("--audit-key-identity");
    if let Some(ca) = ca_der {
        host_cmd.arg("--ca-der").arg(ca);
    }

    let host_child = match ChildGroupGuard::spawn_in_group(&mut host_cmd) {
        Ok(c) => c,
        Err(e) => {
            return ScenarioReport {
                name: name.into(),
                codec: codec.name().into(),
                pass: false,
                handshake_hash_matched: false,
                audit_events_matched: 0,
                audit_events_expected: 12,
                host_summary: None,
                controller_summary: None,
                error: Some(e),
            };
        }
    };

    let ready_bytes = match wait_for_file(&ready_file, Duration::from_secs(15)).await {
        Ok(b) => b,
        Err(e) => {
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return ScenarioReport {
                name: name.into(),
                codec: codec.name().into(),
                pass: false,
                handshake_hash_matched: false,
                audit_events_matched: 0,
                audit_events_expected: 12,
                host_summary: None,
                controller_summary: None,
                error: Some(e),
            };
        }
    };
    let ready: HostReadyFile = match serde_json::from_slice(&ready_bytes) {
        Ok(r) => r,
        Err(e) => {
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return ScenarioReport {
                name: name.into(),
                codec: codec.name().into(),
                pass: false,
                handshake_hash_matched: false,
                audit_events_matched: 0,
                audit_events_expected: 12,
                host_summary: None,
                controller_summary: None,
                error: Some(format!("parse ready file: {e}")),
            };
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
        .arg("--audit-key-identity");
    if let Some(ca) = ca_der {
        ctl_cmd.arg("--ca-der").arg(ca);
    }

    let ctl_child = match ChildGroupGuard::spawn_in_group(&mut ctl_cmd) {
        Ok(c) => c,
        Err(e) => {
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return ScenarioReport {
                name: name.into(),
                codec: codec.name().into(),
                pass: false,
                handshake_hash_matched: false,
                audit_events_matched: 0,
                audit_events_expected: 12,
                host_summary: None,
                controller_summary: None,
                error: Some(e),
            };
        }
    };

    let (ctl_res, host_res) = tokio::join!(
        ctl_child.wait_with_output(Duration::from_secs(45)),
        host_child.wait_with_output(Duration::from_secs(45)),
    );

    let (ctl_summary, host_summary, err) = match (ctl_res, host_res) {
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
    let mut audit_err = err;
    if audit_err.is_none() {
        match (read_audit_jsonl(&ctrl_audit), read_audit_jsonl(&host_audit)) {
            (Ok(c_recs), Ok(h_recs)) => {
                let c_cmp: Vec<_> = c_recs.iter().filter_map(audit_to_comparable).collect();
                let h_cmp: Vec<_> = h_recs.iter().filter_map(audit_to_comparable).collect();
                if c_cmp == h_cmp {
                    matched = c_cmp.len();
                } else {
                    audit_err = Some(format!(
                        "audit mismatch: ctrl={} host={}",
                        c_cmp.len(),
                        h_cmp.len()
                    ));
                }
            }
            (Err(e), _) | (_, Err(e)) => audit_err = Some(e),
        }
    }

    let hs_matched = match (&host_summary, &ctl_summary) {
        (Some(h), Some(c)) => {
            !h.handshake_hash_hex.is_empty() && h.handshake_hash_hex == c.handshake_hash_hex
        }
        _ => false,
    };
    let clean_close = host_summary
        .as_ref()
        .is_some_and(|h| h.close_reason == "peer_closed:0x0000");
    let pass = audit_err.is_none()
        && hs_matched
        && matched == 12
        && clean_close
        && host_summary.as_ref().is_some_and(|h| h.pass)
        && ctl_summary.as_ref().is_some_and(|c| c.pass);

    ScenarioReport {
        name: name.into(),
        codec: codec.name().into(),
        pass,
        handshake_hash_matched: hs_matched,
        audit_events_matched: matched,
        audit_events_expected: 12,
        host_summary,
        controller_summary: ctl_summary,
        error: audit_err,
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_signaling_sigkill_watchdog_scenario(
    exe: &Path,
    config_path: &Path,
    ca_der: Option<&Path>,
    host_id_dir: &Path,
    ctrl_id_dir: &Path,
    work_dir: &Path,
    tenant_id_hex: &str,
    enrollment_token: &str,
) -> ScenarioReport {
    let name = "scenario_3_sigkill_watchdog";
    let ready_file = work_dir.join(format!("{name}_host_ready.json"));
    let stuck_ready = work_dir.join(format!("{name}_stuck.ready"));
    let host_audit = work_dir.join(format!("{name}_host_audit.jsonl"));
    let ctrl_audit = work_dir.join(format!("{name}_ctrl_audit.jsonl"));

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
        .arg("vp9")
        .arg("--fps")
        .arg("30")
        .arg("--watchdog-ms")
        .arg("1200")
        .arg("--idle-exit-ms")
        .arg("10000")
        .arg("--ready-file")
        .arg(&ready_file)
        .arg("--enrollment-token")
        .arg(enrollment_token)
        .arg("--audit-key-identity");
    if let Some(ca) = ca_der {
        host_cmd.arg("--ca-der").arg(ca);
    }

    let host_child = match ChildGroupGuard::spawn_in_group(&mut host_cmd) {
        Ok(c) => c,
        Err(e) => {
            return ScenarioReport {
                name: name.into(),
                codec: "vp9".into(),
                pass: false,
                handshake_hash_matched: false,
                audit_events_matched: 0,
                audit_events_expected: 3,
                host_summary: None,
                controller_summary: None,
                error: Some(e),
            };
        }
    };

    let ready_bytes = match wait_for_file(&ready_file, Duration::from_secs(15)).await {
        Ok(b) => b,
        Err(e) => {
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return ScenarioReport {
                name: name.into(),
                codec: "vp9".into(),
                pass: false,
                handshake_hash_matched: false,
                audit_events_matched: 0,
                audit_events_expected: 3,
                host_summary: None,
                controller_summary: None,
                error: Some(e),
            };
        }
    };
    let ready: HostReadyFile = match serde_json::from_slice(&ready_bytes) {
        Ok(r) => r,
        Err(e) => {
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return ScenarioReport {
                name: name.into(),
                codec: "vp9".into(),
                pass: false,
                handshake_hash_matched: false,
                audit_events_matched: 0,
                audit_events_expected: 3,
                host_summary: None,
                controller_summary: None,
                error: Some(format!("parse ready file: {e}")),
            };
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
        .arg("vp9")
        .arg("--leave-stuck")
        .arg("--hold-after-stuck-ms")
        .arg("15000")
        .arg("--stuck-ready-file")
        .arg(&stuck_ready)
        .arg("--audit-key-identity");
    if let Some(ca) = ca_der {
        ctl_cmd.arg("--ca-der").arg(ca);
    }

    let mut ctl_child = match ChildGroupGuard::spawn_in_group(&mut ctl_cmd) {
        Ok(c) => c,
        Err(e) => {
            let _ = host_child.wait_with_output(Duration::from_secs(2)).await;
            return ScenarioReport {
                name: name.into(),
                codec: "vp9".into(),
                pass: false,
                handshake_hash_matched: false,
                audit_events_matched: 0,
                audit_events_expected: 3,
                host_summary: None,
                controller_summary: None,
                error: Some(e),
            };
        }
    };

    if let Err(e) = wait_for_file(&stuck_ready, Duration::from_secs(20)).await {
        ctl_child.sigkill_group();
        let _ = host_child.wait_with_output(Duration::from_secs(5)).await;
        return ScenarioReport {
            name: name.into(),
            codec: "vp9".into(),
            pass: false,
            handshake_hash_matched: false,
            audit_events_matched: 0,
            audit_events_expected: 3,
            host_summary: None,
            controller_summary: None,
            error: Some(e),
        };
    }

    // Hard SIGKILL controller while LeftShift + KeyA + Left mouse button are held!
    ctl_child.sigkill_group();
    let _ = ctl_child.wait_with_output(Duration::from_secs(5)).await;

    let (host_summary, err) = match host_child.wait_with_output(Duration::from_secs(15)).await {
        Ok((_st, hout, herr)) => match serde_json::from_str::<HostDaemonSummary>(&hout) {
            Ok(hs) => (Some(hs), None),
            Err(e) => (None, Some(format!("parse host summary: {e}; stderr={herr}"))),
        },
        Err(e) => (None, Some(e)),
    };

    let watchdog_audit_ok = read_audit_jsonl(&host_audit)
        .map(|recs| {
            recs.iter().any(|r| {
                matches!(
                    r,
                    AuditRecord::ReleaseAll {
                        reason,
                        released_buttons,
                        released_keys,
                        failed_buttons,
                        failed_keys,
                        ..
                    } if reason == "watchdog_timeout"
                        && *released_buttons == MOUSE_BUTTON_LEFT
                        && released_keys.contains(&SafeHidKey::KeyA)
                        && released_keys.contains(&SafeHidKey::LeftShift)
                        && *failed_buttons == 0
                        && failed_keys.is_empty()
                )
            })
        })
        .unwrap_or(false);

    let pass = err.is_none()
        && watchdog_audit_ok
        && host_summary.as_ref().is_some_and(|h| {
            h.pass
                && h.close_reason == "watchdog_timeout"
                && h.watchdog_release_count >= 1
                && h.final_pressed_buttons == 0
                && h.final_pressed_keys.is_empty()
                && !h.input_faulted
        });

    ScenarioReport {
        name: name.into(),
        codec: "vp9".into(),
        pass,
        handshake_hash_matched: host_summary
            .as_ref()
            .is_some_and(|h| !h.handshake_hash_hex.is_empty()),
        audit_events_matched: if watchdog_audit_ok { 3 } else { 0 },
        audit_events_expected: 3,
        host_summary,
        controller_summary: None,
        error: err.or_else(|| {
            if !watchdog_audit_ok {
                Some("host audit missing watchdog_timeout ReleaseAll of stuck inputs".into())
            } else {
                None
            }
        }),
    }
}

pub async fn cmd_signaling_e2e(args: &[String]) -> ExitCode {
    let mut config_path: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut codec = VideoCodec::Vp9;
    let mut frames = 30usize;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| {
                config_path = Some(PathBuf::from(v));
            }),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| {
                ca_der = Some(PathBuf::from(v));
            }),
            "--codec" => parse_flag_value(args, &mut i, "--codec")
                .and_then(|v| VideoCodec::parse_name(&v).map_err(|e| e.to_string()))
                .map(|c| codec = c),
            "--frames" => parse_flag_value(args, &mut i, "--frames")
                .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                .map(|n| frames = n),
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
            "usage: signaling-e2e --config <cluster.json> [--ca-der <path>] [--codec vp9] [--frames 30]"
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
        eprintln!("cluster.json missing admin_token for signaling-e2e tenant bootstrap");
        return ExitCode::FAILURE;
    };

    let tenant_id = random_bytes::<16>();
    let tenant_id_hex = hex::encode(tenant_id);
    let enrollment_token = format!("v2-p4a-sig-{}", hex::encode(random_bytes::<8>()));
    let tenant_req = CreateTenantReq {
        tenant_id_hex: tenant_id_hex.clone(),
        name: Some("zerodesk-p4a-signaling-e2e".into()),
        home_region: Some("local".into()),
        plan_tier: Some("pro".into()),
        monthly_quota_bytes: 20 * 1024 * 1024 * 1024,
        bw_cap_kbps: 50_000,
        exhaust_policy: 0,
        allow_file_transfer: true,
        enrollment_token: enrollment_token.clone(),
        enrollment_ttl_sec: 3600,
        policy_hash_hex: None,
    };
    if let Err(e) = cp.create_tenant(admin_token, &tenant_req).await {
        eprintln!("create tenant failed: {e}");
        return ExitCode::FAILURE;
    }

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let work_dir = std::env::temp_dir().join(format!(
        "zd-p4a-signaling-e2e-{}-{uniq}",
        std::process::id()
    ));
    let host_id_dir = work_dir.join("host_identity");
    let ctrl_id_dir = work_dir.join("ctrl_identity");
    if let Err(e) = ensure_dir_0700(&work_dir)
        .and_then(|_| ensure_dir_0700(&host_id_dir))
        .and_then(|_| ensure_dir_0700(&ctrl_id_dir))
    {
        eprintln!("create temp identity dirs: {e}");
        return ExitCode::FAILURE;
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("resolve current_exe: {e}");
            let _ = fs::remove_dir_all(&work_dir);
            return ExitCode::FAILURE;
        }
    };

    let s1 = run_signaling_normal_scenario(
        &exe,
        "scenario_1_vp9",
        &config_path,
        ca_der.as_deref(),
        &host_id_dir,
        &ctrl_id_dir,
        &work_dir,
        &tenant_id_hex,
        &enrollment_token,
        codec,
        frames,
    )
    .await;

    let s2 = run_signaling_normal_scenario(
        &exe,
        "scenario_2_av1",
        &config_path,
        ca_der.as_deref(),
        &host_id_dir,
        &ctrl_id_dir,
        &work_dir,
        &tenant_id_hex,
        &enrollment_token,
        VideoCodec::Av1,
        10,
    )
    .await;

    let s3 = run_signaling_sigkill_watchdog_scenario(
        &exe,
        &config_path,
        ca_der.as_deref(),
        &host_id_dir,
        &ctrl_id_dir,
        &work_dir,
        &tenant_id_hex,
        &enrollment_token,
    )
    .await;

    // Strictly assert ZERO rendezvous files exist anywhere in work_dir or either identity_dir.
    let rendezvous_found = contains_rendezvous_file(&work_dir).unwrap_or(None);
    let zero_rendezvous_verified = rendezvous_found.is_none();

    let pass = s1.pass && s2.pass && s3.pass && zero_rendezvous_verified;
    let report = SignalingE2eReport {
        pass,
        zero_rendezvous_verified,
        scenario_1_vp9: s1,
        scenario_2_av1: s2,
        scenario_3_sigkill_watchdog: s3,
        error: rendezvous_found
            .map(|p| format!("unexpected rendezvous file found: {}", p.display())),
    };
    let _ = fs::remove_dir_all(&work_dir);

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
    fn v123_hid_script_encodes_12_valid_wire_events() {
        let script = build_v123_hid_script(true);
        assert_eq!(script.len(), 12);
        for (idx, (payload, _rec)) in script.iter().enumerate() {
            let frame = encode_hid_frame(payload)
                .unwrap_or_else(|e| panic!("script item {idx} failed v1.2.3 encode: {e}"));
            let decoded = decode_hid_frame(&frame)
                .unwrap_or_else(|e| panic!("script item {idx} failed v1.2.3 decode: {e}"));
            assert_eq!(&decoded, payload);
        }
    }

    #[test]
    fn contains_rendezvous_file_detects_forbidden_files() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-no-rdv-{}-{uniq}", std::process::id()));
        ensure_dir_0700(&dir).unwrap();
        write_file_atomic_0600(&dir.join("identity_v2.json"), b"{}").unwrap();
        assert!(contains_rendezvous_file(&dir).unwrap().is_none());

        write_file_atomic_0600(&dir.join("rendezvous.json"), b"{}").unwrap();
        assert!(contains_rendezvous_file(&dir).unwrap().is_some());
        let _ = fs::remove_dir_all(&dir);
    }
}
