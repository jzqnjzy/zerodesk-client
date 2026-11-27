// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
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
    decode_hex_array, ClusterConfig, ControlPlaneClient, CreateTenantReq, V2RecvEvent,
};
use v2_e2e::{
    decode_clipboard_l4, decode_file_l4, decode_hid_frame, detect_visual_marker, encode_hid_frame,
    ensure_dir_0700, measure_audio_quality, ordered_session_teardown, parse_request_idr,
    parse_session_close, prepare_outbound_clipboard, send_redundant_session_close_3x,
    spawn_capture_pipeline, spawn_independent_release_watchdog, write_audit_records_jsonl,
    write_file_atomic_0600, AudioChannelGate, AudioJitterBuffer, AudioSource, AuditKey,
    AuditRecord, ChannelFramingErrorCounter, ClipMessage, ClipSync, ClipboardReceiver,
    ClipboardRecvAction, CloseReason, DecodedVideoDelivery, DesktopControllerClient,
    DesktopControllerSession, DesktopHostDaemon, DesktopHostSession, DryRunSink, FileChunk,
    FileMessage, FileOffer, FileRecvAction, FileSenderWindow, FileTransferReceiver, HidEchoAck,
    HidInputExecutor, HidPayload, InputError, JitterPlayoutAction, KeyEvent, MouseEvent, MouseKind,
    NoopUiCallback, OpusWireFrame, SafeHidKey, SessionError, SharedVisualMarker,
    SyntheticAnimatedSource, SyntheticMultiToneSource, TransportMode, UiCallbackDispatcher,
    V2AudioDecoder, V2AudioEncoder, V2ClientConfig, V2VideoDecoder, V2VideoEncoder, VideoCodec,
    AUDIO_DEFAULT_BITRATE_BPS, AUDIO_FRAME_SAMPLES_PER_CH, AUDIO_JITTER_MAX_FRAMES,
    AUDIO_JITTER_MIN_FRAMES, CLIP_ACK_OK, CLIP_ACK_POLICY_DENIED, CLIP_MIME_IMAGE_PNG,
    CLIP_MIME_TEXT_UTF8, CLIP_MSG_ACK, CLIP_MSG_CHUNK, CLIP_MSG_SYNC,
    DEFAULT_HID_RATE_LIMIT_PER_SEC, DEFAULT_SYNTHETIC_HEIGHT, DEFAULT_SYNTHETIC_WIDTH,
    FILE_ERR_POLICY_DENIED, FILE_MSG_ABORT, FILE_MSG_ACCEPT, FILE_MSG_ACK, FILE_MSG_CHUNK,
    FILE_MSG_COMPLETE, FILE_MSG_COMPLETE_ACK, FILE_MSG_OFFER, MOD_SHIFT, MOUSE_BUTTON_LEFT,
};
use v2_transport::{
    TransportEvent, CHAN_AUDIO, CHAN_CLIPBOARD, CHAN_FILE_TRANSFER, IDR_MIN_INTERVAL_MS,
};

const ENCODER_QUALITY: f32 = 2.0;
const KEYFRAME_INTERVAL: usize = 30;
const MARKER_TARGET_X: i32 = 640;
const MARKER_TARGET_Y: i32 = 360;
const CTRL_MSG_KEEPALIVE: u8 = 0x03;
const AUDIO_LEAD_ACTIVE_FRAMES: usize = 25;
const AUDIO_SILENCE_DTX_FRAMES: usize = 15;
const AUDIO_TAIL_ACTIVE_FRAMES: usize = 10;
const FILE_E2E_CHUNK_SIZE: u32 = 1024;
// Valid minimal 1x1 RGB PNG (67 bytes, passes IHDR + full PNG decoders).
const VALID_MINIMAL_PNG: &[u8] = &[
    0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A, // PNG signature
    0x00, 0x00, 0x00, 0x0D, b'I', b'H', b'D', b'R', // IHDR length=13
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, // 1x1
    0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53, 0xDE, // 8-bit RGB + CRC
    0x00, 0x00, 0x00, 0x0C, b'I', b'D', b'A', b'T', // IDAT
    0x08, 0xD7, 0x63, 0xF8, 0xCF, 0xC0, 0x00, 0x00, 0x03, 0x01, 0x01, 0x00,
    0x18, 0xDD, 0x8D, 0xB0, // IDAT CRC
    0x00, 0x00, 0x00, 0x00, b'I', b'E', b'N', b'D', 0xAE, 0x42, 0x60, 0x82,
];

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

pub(crate) fn parse_flag_value(
    args: &[String],
    idx: &mut usize,
    flag: &str,
) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HostReadyFile {
    pub device_id_hex: String,
    pub tenant_id_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HostDaemonSummary {
    pub pass: bool,
    pub role: String,
    pub codec: String,
    pub device_id_hex: String,
    pub tenant_id_hex: String,
    pub handshake_hash_hex: String,
    pub width: usize,
    pub height: usize,
    pub frames_sent: u64,
    pub frames_captured: u64,
    pub frames_overwritten: u64,
    pub hid_executed: u64,
    pub release_all_count: u64,
    pub watchdog_release_count: u64,
    pub final_pressed_buttons: u8,
    pub final_pressed_keys: Vec<SafeHidKey>,
    pub input_faulted: bool,
    pub close_reason: String,
    pub capture_thread_joined: bool,
    pub watchdog_thread_joined: bool,
    #[serde(default)]
    pub active_transport_mode: String,
    #[serde(default)]
    pub transport_attach_ms: u64,
    #[serde(default)]
    pub p3_dropped: u64,
    #[serde(default)]
    pub policy_version: u64,
    #[serde(default)]
    pub policy_degraded: bool,
    #[serde(default)]
    pub audio_frames_sent: u64,
    #[serde(default)]
    pub audio_dtx_frames_sent: u64,
    #[serde(default)]
    pub audio_policy_denied: u64,
    #[serde(default)]
    pub clipboard_received_text: u64,
    #[serde(default)]
    pub clipboard_received_png: u64,
    #[serde(default)]
    pub clipboard_acks_denied: u64,
    #[serde(default)]
    pub clipboard_anti_echo_suppressed: bool,
    #[serde(default)]
    pub file_transfers_completed: u64,
    #[serde(default)]
    pub file_transfers_aborted_policy: u64,
    #[serde(default)]
    pub file_saved_paths: Vec<String>,
    #[serde(default)]
    pub file_sha256_hex: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ControllerClientSummary {
    pub pass: bool,
    pub role: String,
    pub codec: String,
    pub device_id_hex: String,
    pub target_device_id_hex: String,
    pub tenant_id_hex: String,
    pub handshake_hash_hex: String,
    pub frames_decoded: u64,
    pub frame_id_monotonic: bool,
    pub decode_errors: u64,
    pub decoder_flushed_frames: u64,
    pub hid_events_sent: u64,
    pub visual_marker_before_hid: bool,
    pub visual_marker_detected_frames: u64,
    pub lease_renewals_ok: u64,
    pub lease_renewals_err: u64,
    pub leave_stuck: bool,
    #[serde(default)]
    pub active_transport_mode: String,
    #[serde(default)]
    pub transport_attach_ms: u64,
    #[serde(default)]
    pub p3_dropped: u64,
    #[serde(default)]
    pub policy_version: u64,
    #[serde(default)]
    pub policy_degraded: bool,
    #[serde(default)]
    pub audio_frames_received: u64,
    #[serde(default)]
    pub audio_dtx_frames_received: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_snr_db: Option<f64>,
    #[serde(default)]
    pub audio_local_policy_denied: bool,
    #[serde(default)]
    pub clipboard_acks_ok: u64,
    #[serde(default)]
    pub clipboard_acks_denied: u64,
    #[serde(default)]
    pub clipboard_local_policy_denied: bool,
    #[serde(default)]
    pub clipboard_anti_echo_preserved: bool,
    #[serde(default)]
    pub file_transfers_completed: u64,
    #[serde(default)]
    pub file_transfers_aborted_policy: u64,
    #[serde(default)]
    pub file_local_policy_denied: bool,
    #[serde(default)]
    pub file_sha256_hex: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ComparableHidEvent {
    MouseMoveAbs { x: i32, y: i32 },
    MouseMoveRel { dx: i32, dy: i32 },
    MouseDown { button_bit: u8, x: i32, y: i32 },
    MouseUp { button_bit: u8, x: i32, y: i32 },
    MouseWheel { dx: i16, dy: i16 },
    KeyDown { key: AuditKey },
    KeyUp { key: AuditKey },
}

pub(crate) fn audit_to_comparable(rec: &AuditRecord) -> Option<ComparableHidEvent> {
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

pub(crate) fn read_audit_jsonl(path: &Path) -> Result<Vec<AuditRecord>, String> {
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
    signaling_tls: bool,
    identity_dir: PathBuf,
    audit_out: PathBuf,
    codec: VideoCodec,
    fps: u32,
    watchdog_ms: u64,
    idle_exit_ms: u64,
    ready_file: Option<PathBuf>,
    enrollment_token: Option<String>,
    audit_key_identity: bool,
    transport: TransportMode,
    drop_udp: bool,
    audio: bool,
    clipboard: bool,
    download_dir: Option<PathBuf>,
}

async fn run_v2_hostd(args: &HostDaemonArgs) -> Result<HostDaemonSummary, String> {
    let cluster = ClusterConfig::from_file(&args.config).map_err(|e| e.to_string())?;
    let mut v2_cfg = V2ClientConfig::from_cluster_config(
        &cluster,
        args.identity_dir.clone(),
        args.ca_der.clone(),
        args.enrollment_token.clone(),
    );
    if args.signaling_tls {
        v2_cfg.signaling_tls = Some(true);
    }
    v2_cfg.codec = args.codec;
    v2_cfg.fps = args.fps;
    v2_cfg.watchdog_timeout_ms = args.watchdog_ms;
    v2_cfg.transport_mode = args.transport;
    v2_cfg.drop_udp_for_test = args.drop_udp;
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
    let active_transport_mode = accepted.active_transport_mode.label().to_string();
    let transport_attach_ms = accepted.transport_attach_ms;
    let effective_policy = accepted.effective_policy;
    let policy_version = effective_policy.version;
    let policy_degraded = effective_policy.degraded;
    let host_lease_renewal = accepted.lease_renewal;

    let mut framing_errs = ChannelFramingErrorCounter::new();
    let audio_gate = AudioChannelGate::from_policy(&effective_policy);
    let mut clip_rx = ClipboardReceiver::new(effective_policy.clone());
    let download_dir = args
        .download_dir
        .clone()
        .unwrap_or_else(|| args.identity_dir.join("downloads"));
    let mut file_rx = FileTransferReceiver::new(effective_policy.clone(), download_dir);
    let mut audio_tx_state: Option<(SyntheticMultiToneSource, V2AudioEncoder, u32, Instant)> =
        if args.audio && audio_gate.policy_allows_audio() {
            let src = SyntheticMultiToneSource::new(
                1,
                AUDIO_LEAD_ACTIVE_FRAMES,
                AUDIO_SILENCE_DTX_FRAMES,
                AUDIO_TAIL_ACTIVE_FRAMES,
            )
            .map_err(|e| e.to_string())?;
            let enc = V2AudioEncoder::new(1, AUDIO_DEFAULT_BITRATE_BPS)
                .map_err(|e| e.to_string())?;
            Some((src, enc, 0u32, Instant::now()))
        } else {
            None
        };
    let mut audio_frames_sent = 0u64;
    let mut audio_dtx_frames_sent = 0u64;
    let mut audio_policy_denied = 0u64;
    let mut clipboard_received_text = 0u64;
    let mut clipboard_received_png = 0u64;
    let mut clipboard_acks_denied = 0u64;
    let mut clipboard_anti_echo_suppressed = false;
    let mut host_sent_reply_clip = false;
    let mut host_clip_seq = 1000u64;
    let mut file_transfers_completed = 0u64;
    let mut file_transfers_aborted_policy = 0u64;
    let mut file_saved_paths = Vec::<String>::new();
    let mut file_sha256_hex = Vec::<String>::new();

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
    let mut peer_ready = false;
    let mut audio_started = false;
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
        if host_lease_renewal.is_expired() {
            close_reason = CloseReason::LeaseExpired;
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
        match host.session_mut().recv_v124_event(recv_wait).await {
            Ok(V2RecvEvent::Transport(TransportEvent::Hid(frame))) => {
                peer_ready = true;
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
            Ok(V2RecvEvent::Transport(TransportEvent::Control(ctrl))) => {
                peer_ready = true;
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
            Ok(V2RecvEvent::AudioRaw(raw)) => {
                peer_ready = true;
                last_peer_activity = Instant::now();
                executor.touch_activity();
                if !audio_gate.policy_allows_audio() {
                    audio_policy_denied = audio_policy_denied.saturating_add(1);
                } else if let Err(e) = OpusWireFrame::decode(&raw.body) {
                    close_reason = CloseReason::InvalidFraming;
                    fatal_error = Some(format!("audio framing error: {e}"));
                    break;
                }
            }
            Ok(V2RecvEvent::ClipboardRaw(raw)) => {
                peer_ready = true;
                last_peer_activity = Instant::now();
                executor.touch_activity();
                match clip_rx.on_l4_frame(
                    &raw.header,
                    &raw.body,
                    Instant::now(),
                    &mut framing_errs,
                ) {
                    ClipboardRecvAction::None => {}
                    ClipboardRecvAction::SendAck(ack) => {
                        if ack.status == CLIP_ACK_POLICY_DENIED {
                            clipboard_acks_denied = clipboard_acks_denied.saturating_add(1);
                        }
                        if let Ok(ack_bytes) = ack.encode() {
                            let _ = host
                                .session_mut()
                                .send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &ack_bytes)
                                .await;
                        }
                    }
                    ClipboardRecvAction::DeliverAndAck { delivered, ack } => {
                        if let Ok(ack_bytes) = ack.encode() {
                            let _ = host
                                .session_mut()
                                .send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &ack_bytes)
                                .await;
                        }
                        if delivered.mime_kind == CLIP_MIME_TEXT_UTF8 {
                            clipboard_received_text = clipboard_received_text.saturating_add(1);
                            if !clip_rx.anti_echo.should_sync_local(delivered.sha256) {
                                clipboard_anti_echo_suppressed = true;
                            }
                            if args.clipboard
                                && !host_sent_reply_clip
                                && effective_policy.allow_clipboard()
                            {
                                host_sent_reply_clip = true;
                                host_clip_seq = host_clip_seq.wrapping_add(1);
                                let reply_text = b"ZeroDesk Host B->A clipboard reply";
                                let bulk_paused = host.session_mut().is_bulk_paused();
                                if let Ok(tx) = prepare_outbound_clipboard(
                                    &effective_policy,
                                    CLIP_MIME_TEXT_UTF8,
                                    reply_text,
                                    host_clip_seq,
                                    0xBEEF_0001,
                                    bulk_paused,
                                ) {
                                    if let Ok(sync_bytes) = tx.sync.encode() {
                                        let _ = host
                                            .session_mut()
                                            .send_l4_raw(
                                                CHAN_CLIPBOARD,
                                                CLIP_MSG_SYNC,
                                                0,
                                                false,
                                                &sync_bytes,
                                            )
                                            .await;
                                    }
                                    for ch in &tx.chunks {
                                        if let Ok(ch_bytes) = ch.encode() {
                                            let _ = host
                                                .session_mut()
                                                .send_l4_raw(
                                                    CHAN_CLIPBOARD,
                                                    CLIP_MSG_CHUNK,
                                                    0,
                                                    false,
                                                    &ch_bytes,
                                                )
                                                .await;
                                        }
                                    }
                                }
                            }
                        } else if delivered.mime_kind == CLIP_MIME_IMAGE_PNG {
                            clipboard_received_png = clipboard_received_png.saturating_add(1);
                        }
                    }
                    ClipboardRecvAction::SessionFatal(reason) => {
                        close_reason = CloseReason::InvalidFraming;
                        fatal_error = Some(reason);
                        break;
                    }
                }
            }
            Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                peer_ready = true;
                last_peer_activity = Instant::now();
                executor.touch_activity();
                match file_rx.on_l4_frame(
                    &raw.header,
                    &raw.body,
                    Instant::now(),
                    &mut framing_errs,
                ) {
                    FileRecvAction::None => {}
                    FileRecvAction::SendAccept(acc) => {
                        if let Ok(bytes) = acc.encode() {
                            let _ = host
                                .session_mut()
                                .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ACCEPT, 0, false, &bytes)
                                .await;
                        }
                    }
                    FileRecvAction::SendAck(ack) => {
                        if let Ok(bytes) = ack.encode() {
                            let _ = host
                                .session_mut()
                                .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_ACK, 0, false, &bytes)
                                .await;
                        }
                    }
                    FileRecvAction::SendAbort(ab) => {
                        if ab.error_code == FILE_ERR_POLICY_DENIED {
                            file_transfers_aborted_policy =
                                file_transfers_aborted_policy.saturating_add(1);
                        }
                        let _ = host
                            .session_mut()
                            .send_l4_raw(
                                CHAN_FILE_TRANSFER,
                                FILE_MSG_ABORT,
                                0,
                                false,
                                &ab.encode(),
                            )
                            .await;
                    }
                    FileRecvAction::SendCompleteAck {
                        ack,
                        saved_path,
                        audit,
                    } => {
                        if let Ok(bytes) = ack.encode() {
                            let _ = host
                                .session_mut()
                                .send_l4_raw(
                                    CHAN_FILE_TRANSFER,
                                    FILE_MSG_COMPLETE_ACK,
                                    0,
                                    false,
                                    &bytes,
                                )
                                .await;
                        }
                        if ack.status == 0 {
                            file_transfers_completed = file_transfers_completed.saturating_add(1);
                            if let Some(p) = saved_path {
                                file_saved_paths.push(p.display().to_string());
                            }
                            file_sha256_hex.push(audit.sha256_hex);
                        }
                    }
                    FileRecvAction::SessionFatal(reason) => {
                        close_reason = CloseReason::InvalidFraming;
                        fatal_error = Some(reason);
                        break;
                    }
                }
            }
            Ok(V2RecvEvent::Transport(_)) => {
                peer_ready = true;
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

        if let Some((ref mut src, ref mut enc, ref mut ts_u32, ref mut next_audio_at)) =
            audio_tx_state
        {
            if peer_ready || session_start.elapsed() >= Duration::from_secs(2) {
                if !audio_started {
                    audio_started = true;
                    *next_audio_at = Instant::now();
                }
                if Instant::now() >= *next_audio_at {
                    *next_audio_at = Instant::now() + Duration::from_millis(20);
                    if let Some(pcm) = src.next_frame() {
                        if let Ok(encoded) = enc.encode_frame(&pcm) {
                            let wire = OpusWireFrame {
                                ts_u32: *ts_u32,
                                dtx: encoded.dtx,
                                payload: encoded.payload,
                            };
                            if let Ok(bytes) = wire.encode() {
                                if host
                                    .session_mut()
                                    .send_l4_raw(CHAN_AUDIO, 0x01, 0, false, &bytes)
                                    .await
                                    .is_ok()
                                {
                                    audio_frames_sent = audio_frames_sent.saturating_add(1);
                                    if encoded.dtx {
                                        audio_dtx_frames_sent =
                                            audio_dtx_frames_sent.saturating_add(1);
                                    }
                                }
                            }
                        }
                        *ts_u32 = ts_u32.wrapping_add(AUDIO_FRAME_SAMPLES_PER_CH as u32);
                    }
                }
            }
        }

        if let Some(timeout_ack) = clip_rx.poll_timeout(Instant::now()) {
            if let Ok(ack_bytes) = timeout_ack.encode() {
                let _ = host
                    .session_mut()
                    .send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_ACK, 0, false, &ack_bytes)
                    .await;
            }
        }
        for stall_abort in file_rx.poll_stalls(Instant::now()) {
            let _ = host
                .session_mut()
                .send_l4_raw(
                    CHAN_FILE_TRANSFER,
                    FILE_MSG_ABORT,
                    0,
                    false,
                    &stall_abort.encode(),
                )
                .await;
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
    let p3_dropped = e2ee_session.p3_dropped();

    // Strict ordered teardown: latch_closed + release_all -> stop capture (2s) -> 3x SESSION_CLOSE
    // -> shutdown Host Edge B LeaseRenewalTask -> close data plane
    let teardown = ordered_session_teardown(
        Some(&mut executor),
        Some(capture),
        Some(e2ee_session),
        Some(host_lease_renewal),
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
    let final_error = fatal_error
        .or(teardown.release_all_error.clone())
        .or(teardown.lease_renewal_error.clone());
    let pass = final_error.is_none()
        && teardown.release_all_ok
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
        active_transport_mode,
        transport_attach_ms,
        p3_dropped,
        policy_version,
        policy_degraded,
        audio_frames_sent,
        audio_dtx_frames_sent,
        audio_policy_denied,
        clipboard_received_text,
        clipboard_received_png,
        clipboard_acks_denied,
        clipboard_anti_echo_suppressed,
        file_transfers_completed,
        file_transfers_aborted_policy,
        file_saved_paths,
        file_sha256_hex,
        error: final_error,
    })
}

pub async fn cmd_v2_hostd(args: &[String]) -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut signaling_tls = false;
    let mut identity_dir: Option<PathBuf> = None;
    let mut audit_out: Option<PathBuf> = None;
    let mut codec = VideoCodec::Vp9;
    let mut fps = 30u32;
    let mut watchdog_ms = 1200u64;
    let mut idle_exit_ms = 10_000u64;
    let mut ready_file: Option<PathBuf> = None;
    let mut enrollment_token: Option<String> = None;
    let mut audit_key_identity = false;
    let mut transport = TransportMode::Auto;
    let mut drop_udp = false;
    let mut audio = false;
    let mut clipboard = false;
    let mut download_dir: Option<PathBuf> = None;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| {
                config = Some(PathBuf::from(v));
            }),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| {
                ca_der = Some(PathBuf::from(v));
            }),
            "--signaling-tls" => {
                signaling_tls = true;
                Ok(())
            }
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
            "--transport" => parse_flag_value(args, &mut i, "--transport")
                .and_then(|v| TransportMode::parse_name(&v).map_err(|e| e.to_string()))
                .map(|m| transport = m),
            "--drop-udp" => {
                drop_udp = true;
                Ok(())
            }
            "--audio" => {
                audio = true;
                Ok(())
            }
            "--clipboard" => {
                clipboard = true;
                Ok(())
            }
            "--download-dir" => parse_flag_value(args, &mut i, "--download-dir").map(|v| {
                download_dir = Some(PathBuf::from(v));
            }),
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
            "usage: v2-hostd --config <cluster.json> [--ca-der <path>] [--signaling-tls] --identity-dir <dir> --audit-out <jsonl> [--codec vp9|av1] [--fps 30] [--watchdog-ms 1200] [--idle-exit-ms 10000] [--ready-file <path>] [--enrollment-token <tok>] [--transport auto|udp|tls443] [--drop-udp] [--audio] [--clipboard] [--download-dir <dir>]"
        );
        return ExitCode::from(2);
    };

    let host_args = HostDaemonArgs {
        config,
        ca_der,
        signaling_tls,
        identity_dir,
        audit_out,
        codec,
        fps,
        watchdog_ms,
        idle_exit_ms,
        ready_file,
        enrollment_token,
        audit_key_identity,
        transport,
        drop_udp,
        audio,
        clipboard,
        download_dir,
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
    signaling_tls: bool,
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
    transport: TransportMode,
    drop_udp: bool,
    audio: bool,
    clipboard: bool,
    send_file: Option<PathBuf>,
    send_file_twice: bool,
    probe_denied_channels: bool,
}

struct AudioRecvTracker {
    jb: AudioJitterBuffer,
    dec: V2AudioDecoder,
    decoded_by_idx: BTreeMap<usize, Vec<f32>>,
    frames_received: u64,
    dtx_frames_received: u64,
}

impl AudioRecvTracker {
    fn new() -> Result<Self, String> {
        let dec = V2AudioDecoder::new(1).map_err(|e| e.to_string())?;
        Ok(Self {
            jb: AudioJitterBuffer::new(AUDIO_JITTER_MIN_FRAMES, AUDIO_JITTER_MAX_FRAMES),
            dec,
            decoded_by_idx: BTreeMap::new(),
            frames_received: 0,
            dtx_frames_received: 0,
        })
    }

    fn on_raw_body(&mut self, body: &[u8]) -> Result<(), String> {
        let frame = OpusWireFrame::decode(body).map_err(|e| e.to_string())?;
        self.frames_received = self.frames_received.saturating_add(1);
        if frame.dtx {
            self.dtx_frames_received = self.dtx_frames_received.saturating_add(1);
        }
        let _ = self.jb.push(frame);
        while self.jb.buffered_len() >= AUDIO_JITTER_MIN_FRAMES {
            self.playout_one()?;
        }
        Ok(())
    }

    fn drain(&mut self) -> Result<(), String> {
        while self.jb.buffered_len() > 0 {
            self.playout_one()?;
        }
        Ok(())
    }

    fn playout_one(&mut self) -> Result<(), String> {
        let cur_ts = self.jb.playout_ts();
        let action = self.jb.pop_playout();
        if matches!(action, JitterPlayoutAction::WaitingPrime) {
            return Ok(());
        }
        let pcm = self.dec.execute_playout(action).map_err(|e| e.to_string())?;
        if let Some(ts) = cur_ts {
            let idx = (ts as usize) / AUDIO_FRAME_SAMPLES_PER_CH;
            self.decoded_by_idx.insert(idx, pcm);
        }
        Ok(())
    }

    fn compute_active_snr_db(&self) -> Option<f64> {
        let mut ref_pcm = Vec::new();
        let mut dec_pcm = Vec::new();
        for idx in 2..AUDIO_LEAD_ACTIVE_FRAMES.saturating_sub(2) {
            if let Some(pcm) = self.decoded_by_idx.get(&idx) {
                ref_pcm.extend_from_slice(&SyntheticMultiToneSource::frame_pcm(1, idx, false));
                dec_pcm.extend_from_slice(pcm);
            }
        }
        if ref_pcm.len() < AUDIO_FRAME_SAMPLES_PER_CH * 4 {
            return None;
        }
        Some(measure_audio_quality(&ref_pcm, &dec_pcm, AUDIO_FRAME_SAMPLES_PER_CH).snr_db)
    }
}

async fn maybe_send_keepalive(
    session: &mut v2_client::UdpE2eeSession,
    keepalive_interval: Duration,
    last_tx: &mut Instant,
) -> Result<(), String> {
    if last_tx.elapsed() >= keepalive_interval {
        session
            .send_control(CTRL_MSG_KEEPALIVE, &now_ms().to_be_bytes())
            .await
            .map_err(|e| e.to_string())?;
        *last_tx = Instant::now();
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn recv_video_p4b_with_keepalive(
    session: &mut v2_client::UdpE2eeSession,
    decoder: &mut V2VideoDecoder,
    need_idr: &mut bool,
    last_frame_id: &mut Option<u32>,
    frame_id_monotonic: &mut bool,
    decode_errors: &mut u64,
    audio_tracker: Option<&mut AudioRecvTracker>,
    timeout: Duration,
    keepalive_interval: Duration,
    last_tx: &mut Instant,
) -> Result<(u32, v2_e2e::I420Frame), String> {
    let deadline = Instant::now() + timeout;
    let mut audio_opt = audio_tracker;
    loop {
        maybe_send_keepalive(session, keepalive_interval, last_tx).await?;
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            return Err("controller p4b video recv timed out".into());
        };
        let until_ka = keepalive_interval
            .saturating_sub(last_tx.elapsed())
            .max(Duration::from_millis(1));
        match session.recv_v124_event(rem.min(until_ka)).await {
            Ok(V2RecvEvent::Transport(TransportEvent::VideoFrame(vf))) => {
                if *need_idr && !vf.is_idr {
                    continue;
                }
                if let Some(prev) = *last_frame_id {
                    if vf.frame_id <= prev {
                        *frame_id_monotonic = false;
                        continue;
                    }
                }
                match decoder.decode_raw(&vf.data) {
                    Ok(i420) => {
                        *need_idr = false;
                        *last_frame_id = Some(vf.frame_id);
                        return Ok((vf.frame_id, i420));
                    }
                    Err(_) => {
                        *decode_errors = decode_errors.saturating_add(1);
                        *need_idr = true;
                    }
                }
            }
            Ok(V2RecvEvent::AudioRaw(raw)) => {
                if let Some(ref mut tr) = audio_opt {
                    tr.on_raw_body(&raw.body)?;
                }
            }
            Ok(V2RecvEvent::Transport(TransportEvent::Control(ctrl))) => {
                if let Some(code) = parse_session_close(&ctrl) {
                    return Err(format!("peer closed session: 0x{code:04x}"));
                }
            }
            Ok(_) => {}
            Err(v2_client::ClientError::Timeout(_)) => {
                if Instant::now() >= deadline {
                    return Err("controller p4b video recv timed out".into());
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

async fn send_hid_and_await_echo_p4b(
    session: &mut v2_client::UdpE2eeSession,
    payload: &HidPayload,
    expected_seq: u32,
    audio_tracker: Option<&mut AudioRecvTracker>,
    timeout: Duration,
    keepalive_interval: Duration,
    last_tx: &mut Instant,
) -> Result<(), String> {
    let frame = encode_hid_frame(payload).map_err(|e| e.to_string())?;
    session.send_hid(&frame).await.map_err(|e| e.to_string())?;
    *last_tx = Instant::now();
    let deadline = Instant::now() + timeout;
    let mut audio_opt = audio_tracker;
    loop {
        maybe_send_keepalive(session, keepalive_interval, last_tx).await?;
        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            return Err(format!("HID seq {expected_seq} echo timed out"));
        };
        let until_ka = keepalive_interval
            .saturating_sub(last_tx.elapsed())
            .max(Duration::from_millis(1));
        match session.recv_v124_event(rem.min(until_ka)).await {
            Ok(V2RecvEvent::Transport(TransportEvent::Hid(hf))) => {
                if let Ok(HidPayload::EchoAck(ack)) = decode_hid_frame(&hf) {
                    if ack.echo_seq == expected_seq {
                        return Ok(());
                    }
                }
            }
            Ok(V2RecvEvent::AudioRaw(raw)) => {
                if let Some(ref mut tr) = audio_opt {
                    tr.on_raw_body(&raw.body)?;
                }
            }
            Ok(V2RecvEvent::Transport(TransportEvent::Control(ctrl))) => {
                if let Some(code) = parse_session_close(&ctrl) {
                    return Err(format!("peer closed session during HID echo: 0x{code:04x}"));
                }
            }
            Ok(_) => {}
            Err(v2_client::ClientError::Timeout(_)) => {
                if Instant::now() >= deadline {
                    return Err(format!("HID seq {expected_seq} echo timed out"));
                }
            }
            Err(e) => return Err(e.to_string()),
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn push_file_transfer_p4b(
    session: &mut v2_client::UdpE2eeSession,
    policy: &v2_e2e::EffectiveTenantPolicy,
    transfer_id: u64,
    rel_name: &str,
    data: &[u8],
    audio_tracker: Option<&mut AudioRecvTracker>,
    keepalive_interval: Duration,
    last_tx: &mut Instant,
) -> Result<[u8; 32], String> {
    let sha256: [u8; 32] = Sha256::digest(data).into();
    let (mut win, offer) = FileSenderWindow::new(
        policy,
        transfer_id,
        rel_name,
        data.len() as u64,
        FILE_E2E_CHUNK_SIZE,
        sha256,
        Instant::now(),
    )
    .map_err(|e| format!("prepare FileOffer: {e}"))?;
    let offer_bytes = offer.encode().map_err(|e| e.to_string())?;
    let mut offer_sent = match session
        .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_OFFER, 0, false, &offer_bytes)
        .await
    {
        Ok(_) => {
            *last_tx = Instant::now();
            true
        }
        Err(v2_client::ClientError::P3Backpressure { .. }) => false,
        Err(e) => return Err(e.to_string()),
    };

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut audio_opt = audio_tracker;
    let mut complete_sent = false;
    loop {
        maybe_send_keepalive(session, keepalive_interval, last_tx).await?;
        let bulk_paused = session.is_bulk_paused();
        if !offer_sent && !bulk_paused {
            match session
                .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_OFFER, 0, false, &offer_bytes)
                .await
            {
                Ok(_) => {
                    offer_sent = true;
                    *last_tx = Instant::now();
                }
                Err(v2_client::ClientError::P3Backpressure { .. }) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        while let Some((offset, len)) = win.next_chunk_range(bulk_paused) {
            let start = offset as usize;
            let end = start + len;
            let chunk = FileChunk {
                transfer_id,
                offset,
                data: data[start..end].to_vec(),
            };
            let chunk_bytes = chunk.encode().map_err(|e| e.to_string())?;
            match session
                .send_l4_raw(CHAN_FILE_TRANSFER, FILE_MSG_CHUNK, 0, false, &chunk_bytes)
                .await
            {
                Ok(_) => {
                    win.mark_chunk_sent(offset, len, Instant::now());
                    *last_tx = Instant::now();
                }
                Err(v2_client::ClientError::P3Backpressure { .. }) => break,
                Err(e) => return Err(e.to_string()),
            }
        }
        if !complete_sent && !bulk_paused && win.ready_for_complete() {
            let comp = win.peek_complete();
            match session
                .send_l4_raw(
                    CHAN_FILE_TRANSFER,
                    FILE_MSG_COMPLETE,
                    0,
                    false,
                    &comp.encode(),
                )
                .await
            {
                Ok(_) => {
                    win.commit_complete(Instant::now());
                    complete_sent = true;
                    *last_tx = Instant::now();
                }
                Err(v2_client::ClientError::P3Backpressure { .. }) => {}
                Err(e) => return Err(e.to_string()),
            }
        }

        let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
            return Err("file transfer timed out".into());
        };
        let wait = rem.min(Duration::from_millis(50));
        match session.recv_v124_event(wait).await {
            Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                match decode_file_l4(&raw.header, &raw.body).map_err(|e| e.to_string())? {
                    FileMessage::Accept(acc) if acc.transfer_id == transfer_id => {
                        win.on_accept(&acc, Instant::now())
                            .map_err(|e| e.to_string())?;
                    }
                    FileMessage::Ack(ack) if ack.transfer_id == transfer_id => {
                        win.on_ack(&ack, Instant::now())
                            .map_err(|e| e.to_string())?;
                    }
                    FileMessage::CompleteAck(cack) if cack.transfer_id == transfer_id => {
                        if cack.status != 0 {
                            return Err(format!(
                                "FILE_COMPLETE_ACK status={}",
                                cack.status
                            ));
                        }
                        return Ok(sha256);
                    }
                    FileMessage::Abort(ab) if ab.transfer_id == transfer_id => {
                        return Err(format!("FILE_ABORT error_code=0x{:04x}", ab.error_code));
                    }
                    _ => {}
                }
            }
            Ok(V2RecvEvent::AudioRaw(raw)) => {
                if let Some(ref mut tr) = audio_opt {
                    tr.on_raw_body(&raw.body)?;
                }
            }
            Ok(V2RecvEvent::Transport(TransportEvent::Control(ctrl))) => {
                if let Some(code) = parse_session_close(&ctrl) {
                    return Err(format!("peer closed during file transfer: 0x{code:04x}"));
                }
            }
            Ok(_) => {}
            Err(v2_client::ClientError::Timeout(_)) => {}
            Err(e) => return Err(e.to_string()),
        }
    }
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
    if args.signaling_tls {
        v2_cfg.signaling_tls = Some(true);
    }
    v2_cfg.codec = args.codec;
    v2_cfg.transport_mode = args.transport;
    v2_cfg.drop_udp_for_test = args.drop_udp;
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
    let active_transport_mode = connected.active_transport_mode.label().to_string();
    let transport_attach_ms = connected.transport_attach_ms;
    let effective_policy = connected.effective_policy;
    let policy_version = effective_policy.version;
    let policy_degraded = effective_policy.degraded;
    let keepalive_interval = connected.keepalive_interval;
    let lease_renewal = connected.lease_renewal;

    let mut frames_decoded = 0u64;
    let mut last_frame_id: Option<u32> = None;
    let mut frame_id_monotonic = true;
    let mut decode_errors = 0u64;
    let mut decoder_flushed_frames = 0u64;
    let mut hid_events_sent = 0u64;
    let mut visual_marker_before_hid = false;
    let mut visual_marker_detected_frames = 0u64;
    let mut sent_audit = Vec::<AuditRecord>::new();
    let mut last_tx = Instant::now();

    let mut audio_frames_received = 0u64;
    let mut audio_dtx_frames_received = 0u64;
    let mut audio_snr_db: Option<f64> = None;
    let mut audio_local_policy_denied = !effective_policy.allow_audio();
    let mut clipboard_acks_ok = 0u64;
    let mut clipboard_acks_denied = 0u64;
    let mut clipboard_local_policy_denied = !effective_policy.allow_clipboard();
    let mut clipboard_anti_echo_preserved = false;
    let mut file_transfers_completed = 0u64;
    let mut file_transfers_aborted_policy = 0u64;
    let mut file_local_policy_denied = !effective_policy.allow_file_transfer();
    let mut file_sha256_hex = Vec::<String>::new();

    let p4b_channels_active =
        args.audio || args.clipboard || args.send_file.is_some() || args.probe_denied_channels;

    let (run_res, p3_dropped): (Result<(), String>, u64) = if !p4b_channels_active {
        let decoder = V2VideoDecoder::new(args.codec).map_err(|e| e.to_string())?;
        let mut controller = DesktopControllerSession::new(connected.e2ee_session, decoder);

        let res: Result<(), String> = if args.leave_stuck {
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

        let p3_drop = controller.session().p3_dropped();
        let _ = send_redundant_session_close_3x(controller.session_mut(), 0x0000).await;
        decode_errors = controller.decode_errors;
        decoder_flushed_frames = controller.decoder_flushed_frames;
        (res, p3_drop)
    } else {
        let mut session = connected.e2ee_session;
        let mut decoder = V2VideoDecoder::new(args.codec).map_err(|e| e.to_string())?;
        let mut need_idr = true;
        let mut audio_tracker = if args.audio && effective_policy.allow_audio() {
            Some(AudioRecvTracker::new()?)
        } else {
            None
        };

        let res: Result<(), String> = async {
            let target_frames = args.frames.max(1);
            let pre_hid_frames = 2usize.min(target_frames);
            for _ in 0..pre_hid_frames {
                let (_fid, i420) = recv_video_p4b_with_keepalive(
                    &mut session,
                    &mut decoder,
                    &mut need_idr,
                    &mut last_frame_id,
                    &mut frame_id_monotonic,
                    &mut decode_errors,
                    audio_tracker.as_mut(),
                    Duration::from_secs(10),
                    keepalive_interval,
                    &mut last_tx,
                )
                .await
                .map_err(|e| format!("pre-HID video recv: {e}"))?;
                frames_decoded += 1;
                if detect_visual_marker(&i420, MARKER_TARGET_X, MARKER_TARGET_Y).detected {
                    visual_marker_before_hid = true;
                }
            }

            let script = build_v123_hid_script(args.audit_key_identity);
            for (idx, (payload, rec)) in script.into_iter().enumerate() {
                send_hid_and_await_echo_p4b(
                    &mut session,
                    &payload,
                    idx as u32,
                    audio_tracker.as_mut(),
                    Duration::from_secs(5),
                    keepalive_interval,
                    &mut last_tx,
                )
                .await
                .map_err(|e| format!("HID seq {idx} echo failed: {e}"))?;
                hid_events_sent += 1;
                sent_audit.push(rec);
            }

            while (frames_decoded as usize) < target_frames {
                let (_fid, i420) = recv_video_p4b_with_keepalive(
                    &mut session,
                    &mut decoder,
                    &mut need_idr,
                    &mut last_frame_id,
                    &mut frame_id_monotonic,
                    &mut decode_errors,
                    audio_tracker.as_mut(),
                    Duration::from_secs(10),
                    keepalive_interval,
                    &mut last_tx,
                )
                .await
                .map_err(|e| format!("post-HID video recv: {e}"))?;
                frames_decoded += 1;
                if detect_visual_marker(&i420, MARKER_TARGET_X, MARKER_TARGET_Y).detected {
                    visual_marker_detected_frames += 1;
                }
            }

            if let Ok(flushed) = decoder.flush_pending() {
                decoder_flushed_frames = flushed.len() as u64;
            }
            write_audit_records_jsonl(&sent_audit, &args.audit_out)
                .map_err(|e| format!("write controller audit: {e}"))?;

            if args.probe_denied_channels {
                // Verify Controller-side policy gate first:
                audio_local_policy_denied = !effective_policy.allow_audio();
                clipboard_local_policy_denied = !effective_policy.allow_clipboard();
                file_local_policy_denied = !effective_policy.allow_file_transfer();

                // Now intentionally send raw channel probes ONLY for locally denied channels
                // to verify Edge L2 allowed_mask AND remote Host defense-in-depth!
                let expect_clip_deny = clipboard_local_policy_denied;
                let expect_file_deny = file_local_policy_denied;
                // When BOTH clipboard and file transfer are denied, Edge L2 drops all p3 frames,
                // so use `send_negative_policy_probe` (bypasses ARQ with stream_seq=u32::MAX).
                // When only ONE channel is denied, Edge forwards p3 to Host, so use
                // `send_l4_bypass_local_policy` (keeps ARQ) to reliably elicit Host's
                // FILE_ABORT(0x0401) or CLIP_ACK(POLICY_DENIED).
                let edge_drops_p3 = expect_clip_deny && expect_file_deny;

                if expect_clip_deny {
                    let clip_payload = b"denied-probe-text";
                    let clip_sync = ClipSync {
                        mime_kind: CLIP_MIME_TEXT_UTF8,
                        clip_id: 901,
                        origin_nonce: 0xDEAD_0001,
                        total_len: clip_payload.len() as u32,
                        total_chunks: 1,
                        sha256: Sha256::digest(clip_payload).into(),
                    };
                    let clip_sync_bytes = clip_sync.encode().map_err(|e| e.to_string())?;
                    if edge_drops_p3 {
                        session
                            .send_negative_policy_probe(
                                CHAN_CLIPBOARD,
                                CLIP_MSG_SYNC,
                                &clip_sync_bytes,
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                    } else {
                        session
                            .send_l4_bypass_local_policy(
                                CHAN_CLIPBOARD,
                                CLIP_MSG_SYNC,
                                &clip_sync_bytes,
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                }

                if expect_file_deny {
                    let file_offer = FileOffer {
                        transfer_id: 902,
                        file_size: 16,
                        chunk_size: FILE_E2E_CHUNK_SIZE,
                        sha256: Sha256::digest(b"0123456789abcdef").into(),
                        rel_name: "denied.txt".into(),
                    };
                    let offer_bytes = file_offer.encode().map_err(|e| e.to_string())?;
                    if edge_drops_p3 {
                        session
                            .send_negative_policy_probe(
                                CHAN_FILE_TRANSFER,
                                FILE_MSG_OFFER,
                                &offer_bytes,
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                    } else {
                        session
                            .send_l4_bypass_local_policy(
                                CHAN_FILE_TRANSFER,
                                FILE_MSG_OFFER,
                                &offer_bytes,
                            )
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                }

                if audio_local_policy_denied {
                    let audio_probe = OpusWireFrame {
                        ts_u32: 0,
                        dtx: true,
                        payload: Vec::new(),
                    };
                    let audio_bytes = audio_probe.encode().map_err(|e| e.to_string())?;
                    session
                        .send_negative_policy_probe(CHAN_AUDIO, 0x01, &audio_bytes)
                        .await
                        .map_err(|e| e.to_string())?;
                }
                last_tx = Instant::now();

                // Wait up to 1.5s for remote policy replies (note: when BOTH clipboard and file
                // transfer are denied, Edge L2 allowed_mask=0x07 silently drops p3 before Host,
                // while partial-deny allows p3 through so Host emits FILE_ABORT 0x0401 live!).
                let probe_deadline = Instant::now() + Duration::from_millis(1_500);
                while Instant::now() < probe_deadline
                    && ((expect_clip_deny && clipboard_acks_denied == 0)
                        || (expect_file_deny && file_transfers_aborted_policy == 0))
                {
                    maybe_send_keepalive(&mut session, keepalive_interval, &mut last_tx).await?;
                    match session.recv_v124_event(Duration::from_millis(50)).await {
                        Ok(V2RecvEvent::ClipboardRaw(raw)) => {
                            if let Ok(ClipMessage::Ack(ack)) =
                                decode_clipboard_l4(&raw.header, &raw.body)
                            {
                                if ack.status == CLIP_ACK_POLICY_DENIED {
                                    clipboard_acks_denied = clipboard_acks_denied.saturating_add(1);
                                } else if ack.status == CLIP_ACK_OK {
                                    clipboard_acks_ok = clipboard_acks_ok.saturating_add(1);
                                }
                            }
                        }
                        Ok(V2RecvEvent::FileTransferRaw(raw)) => {
                            if let Ok(FileMessage::Abort(ab)) =
                                decode_file_l4(&raw.header, &raw.body)
                            {
                                if ab.error_code == FILE_ERR_POLICY_DENIED {
                                    file_transfers_aborted_policy =
                                        file_transfers_aborted_policy.saturating_add(1);
                                }
                            }
                        }
                        Ok(V2RecvEvent::AudioRaw(_)) => {
                            audio_frames_received = audio_frames_received.saturating_add(1);
                        }
                        Ok(V2RecvEvent::Transport(TransportEvent::Control(ctrl))) => {
                            if let Some(code) = parse_session_close(&ctrl) {
                                return Err(format!("peer closed during denied probe: 0x{code:04x}"));
                            }
                        }
                        Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
                // Brief settle so Host processes the audio probe frame before SESSION_CLOSE.
                tokio::time::sleep(Duration::from_millis(150)).await;
            } else {
                if args.clipboard {
                    let mut clip_rx = ClipboardReceiver::new(effective_policy.clone());
                    let mut clip_framing = ChannelFramingErrorCounter::new();
                    let text_a = "ZeroDesk Phase 4B UTF-8 clipboard 🚀".as_bytes();
                    let hash_a: [u8; 32] = Sha256::digest(text_a).into();

                    // Step 1: A -> B UTF-8 text (clip_id=1)
                    let tx1 = prepare_outbound_clipboard(
                        &effective_policy,
                        CLIP_MIME_TEXT_UTF8,
                        text_a,
                        1,
                        0xCAFE_0001,
                        session.is_bulk_paused(),
                    )
                    .map_err(|e| format!("prepare clip 1: {e}"))?;
                    let tx1_sync_bytes = tx1.sync.encode().map_err(|e| e.to_string())?;
                    session
                        .send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_SYNC, 0, false, &tx1_sync_bytes)
                        .await
                        .map_err(|e| e.to_string())?;
                    for ch in &tx1.chunks {
                        let ch_bytes = ch.encode().map_err(|e| e.to_string())?;
                        session
                            .send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_CHUNK, 0, false, &ch_bytes)
                            .await
                            .map_err(|e| e.to_string())?;
                    }
                    last_tx = Instant::now();

                    // Await CLIP_ACK(1, OK) AND Host B->A reply clipboard item
                    let mut ack1_ok = false;
                    let mut got_host_reply_hash: Option<[u8; 32]> = None;
                    let clip_deadline = Instant::now() + Duration::from_secs(10);
                    while Instant::now() < clip_deadline && (!ack1_ok || got_host_reply_hash.is_none())
                    {
                        maybe_send_keepalive(&mut session, keepalive_interval, &mut last_tx)
                            .await?;
                        match session.recv_v124_event(Duration::from_millis(50)).await {
                            Ok(V2RecvEvent::ClipboardRaw(raw)) => {
                                if let Ok(ClipMessage::Ack(ack)) =
                                    decode_clipboard_l4(&raw.header, &raw.body)
                                {
                                    if ack.clip_id == 1 && ack.status == CLIP_ACK_OK {
                                        ack1_ok = true;
                                        clipboard_acks_ok = clipboard_acks_ok.saturating_add(1);
                                    } else if ack.status == CLIP_ACK_POLICY_DENIED {
                                        clipboard_acks_denied =
                                            clipboard_acks_denied.saturating_add(1);
                                    }
                                    continue;
                                }
                                match clip_rx.on_l4_frame(
                                    &raw.header,
                                    &raw.body,
                                    Instant::now(),
                                    &mut clip_framing,
                                ) {
                                    ClipboardRecvAction::DeliverAndAck { delivered, ack } => {
                                        if let Ok(ack_bytes) = ack.encode() {
                                            let _ = session
                                                .send_l4_raw(
                                                    CHAN_CLIPBOARD,
                                                    CLIP_MSG_ACK,
                                                    0,
                                                    false,
                                                    &ack_bytes,
                                                )
                                                .await;
                                        }
                                        got_host_reply_hash = Some(delivered.sha256);
                                    }
                                    ClipboardRecvAction::SendAck(ack) => {
                                        if let Ok(ack_bytes) = ack.encode() {
                                            let _ = session
                                                .send_l4_raw(
                                                    CHAN_CLIPBOARD,
                                                    CLIP_MSG_ACK,
                                                    0,
                                                    false,
                                                    &ack_bytes,
                                                )
                                                .await;
                                        }
                                    }
                                    ClipboardRecvAction::None => {}
                                    ClipboardRecvAction::SessionFatal(r) => return Err(r),
                                }
                            }
                            Ok(V2RecvEvent::AudioRaw(raw)) => {
                                if let Some(ref mut tr) = audio_tracker {
                                    tr.on_raw_body(&raw.body)?;
                                }
                            }
                            Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                    if !ack1_ok {
                        return Err("timed out awaiting CLIP_ACK(1, OK)".into());
                    }
                    if let Some(hash_b) = got_host_reply_hash {
                        let echo_suppressed = !clip_rx.anti_echo.should_sync_local(hash_b);
                        let aba_preserved = clip_rx.anti_echo.should_sync_local(hash_a);
                        clipboard_anti_echo_preserved = echo_suppressed && aba_preserved;
                    }

                    // Step 2: Re-send A -> B UTF-8 (clip_id=2, proving A->B->A flows cleanly)
                    // and Step 3: A -> B valid PNG (clip_id=3)
                    let items: &[(u64, u8, &[u8])] = &[
                        (2, CLIP_MIME_TEXT_UTF8, text_a),
                        (3, CLIP_MIME_IMAGE_PNG, VALID_MINIMAL_PNG),
                    ];
                    for &(cid, mime, data) in items {
                        let tx = prepare_outbound_clipboard(
                            &effective_policy,
                            mime,
                            data,
                            cid,
                            0xCAFE_0000 + cid,
                            session.is_bulk_paused(),
                        )
                        .map_err(|e| format!("prepare clip {cid}: {e}"))?;
                        let sync_bytes = tx.sync.encode().map_err(|e| e.to_string())?;
                        session
                            .send_l4_raw(CHAN_CLIPBOARD, CLIP_MSG_SYNC, 0, false, &sync_bytes)
                            .await
                            .map_err(|e| e.to_string())?;
                        for ch in &tx.chunks {
                            let ch_bytes = ch.encode().map_err(|e| e.to_string())?;
                            session
                                .send_l4_raw(
                                    CHAN_CLIPBOARD,
                                    CLIP_MSG_CHUNK,
                                    0,
                                    false,
                                    &ch_bytes,
                                )
                                .await
                                .map_err(|e| e.to_string())?;
                        }
                        last_tx = Instant::now();
                        let ack_deadline = Instant::now() + Duration::from_secs(10);
                        let mut got_ack = false;
                        while Instant::now() < ack_deadline && !got_ack {
                            maybe_send_keepalive(&mut session, keepalive_interval, &mut last_tx)
                                .await?;
                            match session.recv_v124_event(Duration::from_millis(50)).await {
                                Ok(V2RecvEvent::ClipboardRaw(raw)) => {
                                    if let Ok(ClipMessage::Ack(ack)) =
                                        decode_clipboard_l4(&raw.header, &raw.body)
                                    {
                                        if ack.clip_id == cid && ack.status == CLIP_ACK_OK {
                                            got_ack = true;
                                            clipboard_acks_ok = clipboard_acks_ok.saturating_add(1);
                                        }
                                    }
                                }
                                Ok(V2RecvEvent::AudioRaw(raw)) => {
                                    if let Some(ref mut tr) = audio_tracker {
                                        tr.on_raw_body(&raw.body)?;
                                    }
                                }
                                Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
                                Err(e) => return Err(e.to_string()),
                            }
                        }
                        if !got_ack {
                            return Err(format!("timed out awaiting CLIP_ACK({cid}, OK)"));
                        }
                    }
                }

                if let Some(ref file_path) = args.send_file {
                    let bytes = fs::read(file_path)
                        .map_err(|e| format!("read --send-file '{}': {e}", file_path.display()))?;
                    let rel_name = file_path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .ok_or_else(|| "invalid --send-file filename".to_string())?;
                    let sends = if args.send_file_twice { 2u64 } else { 1u64 };
                    for send_idx in 1..=sends {
                        let sha = push_file_transfer_p4b(
                            &mut session,
                            &effective_policy,
                            100 + send_idx,
                            rel_name,
                            &bytes,
                            audio_tracker.as_mut(),
                            keepalive_interval,
                            &mut last_tx,
                        )
                        .await?;
                        file_transfers_completed = file_transfers_completed.saturating_add(1);
                        file_sha256_hex.push(hex::encode(sha));
                    }
                }

                if let Some(ref mut tr) = audio_tracker {
                    let target_audio =
                        (AUDIO_LEAD_ACTIVE_FRAMES + AUDIO_SILENCE_DTX_FRAMES) as u64;
                    let audio_deadline = Instant::now() + Duration::from_secs(3);
                    while tr.frames_received < target_audio && Instant::now() < audio_deadline {
                        maybe_send_keepalive(&mut session, keepalive_interval, &mut last_tx)
                            .await?;
                        match session.recv_v124_event(Duration::from_millis(50)).await {
                            Ok(V2RecvEvent::AudioRaw(raw)) => {
                                tr.on_raw_body(&raw.body)?;
                            }
                            Ok(_) | Err(v2_client::ClientError::Timeout(_)) => {}
                            Err(e) => return Err(e.to_string()),
                        }
                    }
                }
            }

            Ok(())
        }
        .await;

        let mut res = res;
        if let Some(ref mut tr) = audio_tracker {
            let drain_res = tr.drain();
            audio_frames_received = tr.frames_received;
            audio_dtx_frames_received = tr.dtx_frames_received;
            audio_snr_db = tr.compute_active_snr_db();
            if res.is_ok() {
                res = drain_res;
            }
        }
        let p3_drop = session.p3_dropped();
        let _ = send_redundant_session_close_3x(&mut session, 0x0000).await;
        (res, p3_drop)
    };

    let lease_shut = lease_renewal.shutdown().await;
    if let Some(mut sig) = client.take_signaling() {
        let _ = sig.shutdown().await;
    }

    let final_error = run_res.err().or(lease_shut.join_error);
    let pass = final_error.is_none()
        && frame_id_monotonic
        && decode_errors == 0
        && p3_dropped == 0
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
        lease_renewals_ok: lease_shut.renewals_ok,
        lease_renewals_err: lease_shut.renewals_err,
        leave_stuck: args.leave_stuck,
        active_transport_mode,
        transport_attach_ms,
        p3_dropped,
        policy_version,
        policy_degraded,
        audio_frames_received,
        audio_dtx_frames_received,
        audio_snr_db,
        audio_local_policy_denied,
        clipboard_acks_ok,
        clipboard_acks_denied,
        clipboard_local_policy_denied,
        clipboard_anti_echo_preserved,
        file_transfers_completed,
        file_transfers_aborted_policy,
        file_local_policy_denied,
        file_sha256_hex,
        error: final_error,
    })
}

pub async fn cmd_v2_ctl(args: &[String]) -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut signaling_tls = false;
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
    let mut transport = TransportMode::Auto;
    let mut drop_udp = false;
    let mut audio = false;
    let mut clipboard = false;
    let mut send_file: Option<PathBuf> = None;
    let mut send_file_twice = false;
    let mut probe_denied_channels = false;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| {
                config = Some(PathBuf::from(v));
            }),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| {
                ca_der = Some(PathBuf::from(v));
            }),
            "--signaling-tls" => {
                signaling_tls = true;
                Ok(())
            }
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
                .and_then(|n| {
                    if n == 0 {
                        Err("--frames must be >= 1".to_string())
                    } else {
                        Ok(n)
                    }
                })
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
            "--transport" => parse_flag_value(args, &mut i, "--transport")
                .and_then(|v| TransportMode::parse_name(&v).map_err(|e| e.to_string()))
                .map(|m| transport = m),
            "--drop-udp" => {
                drop_udp = true;
                Ok(())
            }
            "--audio" => {
                audio = true;
                Ok(())
            }
            "--clipboard" => {
                clipboard = true;
                Ok(())
            }
            "--send-file" => parse_flag_value(args, &mut i, "--send-file").map(|v| {
                send_file = Some(PathBuf::from(v));
            }),
            "--send-file-twice" => {
                send_file_twice = true;
                Ok(())
            }
            "--probe-denied-channels" => {
                probe_denied_channels = true;
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
            "usage: v2-ctl --config <cluster.json> [--ca-der <path>] [--signaling-tls] --identity-dir <dir> --target-device-id <hex> --tenant-id <hex> --enrollment-token <tok> --audit-out <jsonl> [--codec vp9|av1] [--frames 30] [--leave-stuck] [--hold-after-stuck-ms <ms>] [--transport auto|udp|tls443] [--drop-udp] [--audio] [--clipboard] [--send-file <path>] [--send-file-twice] [--probe-denied-channels]"
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
        signaling_tls,
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
        transport,
        drop_udp,
        audio,
        clipboard,
        send_file,
        send_file_twice,
        probe_denied_channels,
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

pub(crate) struct ChildGroupGuard {
    child: Option<Child>,
    pgid: Option<i32>,
}

impl ChildGroupGuard {
    pub(crate) fn spawn_in_group(cmd: &mut Command) -> Result<Self, String> {
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

    pub(crate) fn sigkill_group(&mut self) {
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

    pub(crate) async fn wait_with_output(
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
            Ok(Err(e)) => {
                #[cfg(unix)]
                if let Some(pgid) = self.pgid {
                    unsafe {
                        let _ = kill(-pgid, 9);
                    }
                }
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
                return Err(format!("wait child: {e}"));
            }
            Err(_) => {
                #[cfg(unix)]
                if let Some(pgid) = self.pgid {
                    unsafe {
                        let _ = kill(-pgid, 9);
                    }
                }
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
                return Err("child process timed out".into());
            }
        };
        let out_str = out_task.await.unwrap_or_default();
        let err_str = err_task.await.unwrap_or_default();
        Ok((status, out_str, err_str))
    }

    pub(crate) async fn wait_and_reap_on_err(
        &mut self,
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
            Ok(Err(e)) => {
                self.sigkill_group();
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
                return Err(format!("wait child: {e}"));
            }
            Err(_) => {
                self.sigkill_group();
                let _ = child.start_kill();
                let _ = tokio::time::timeout(Duration::from_secs(3), child.wait()).await;
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

pub(crate) async fn wait_for_file(path: &Path, timeout: Duration) -> Result<Vec<u8>, String> {
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

pub(crate) struct TempDirGuard(pub(crate) PathBuf);

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) fn contains_rendezvous_file(root: &Path) -> Result<Option<PathBuf>, String> {
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
        // Use `entry.file_type()` which does NOT follow symlinks, preventing symlink-loop DoS.
        let ft = entry
            .file_type()
            .map_err(|e| format!("file_type '{}': {e}", p.display()))?;
        if ft.is_dir() {
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
    signaling_tls: bool,
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
    let _ = fs::remove_file(&ready_file);
    let _ = fs::remove_file(&host_audit);
    let _ = fs::remove_file(&ctrl_audit);

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
    if signaling_tls {
        host_cmd.arg("--signaling-tls");
    }

    let mut host_child = match ChildGroupGuard::spawn_in_group(&mut host_cmd) {
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
            host_child.sigkill_group();
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
            host_child.sigkill_group();
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
    if signaling_tls {
        ctl_cmd.arg("--signaling-tls");
    }

    let ctl_child = match ChildGroupGuard::spawn_in_group(&mut ctl_cmd) {
        Ok(c) => c,
        Err(e) => {
            host_child.sigkill_group();
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
    signaling_tls: bool,
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
    let _ = fs::remove_file(&ready_file);
    let _ = fs::remove_file(&stuck_ready);
    let _ = fs::remove_file(&host_audit);
    let _ = fs::remove_file(&ctrl_audit);

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
    if signaling_tls {
        host_cmd.arg("--signaling-tls");
    }

    let mut host_child = match ChildGroupGuard::spawn_in_group(&mut host_cmd) {
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
            host_child.sigkill_group();
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
            host_child.sigkill_group();
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
    if signaling_tls {
        ctl_cmd.arg("--signaling-tls");
    }

    let mut ctl_child = match ChildGroupGuard::spawn_in_group(&mut ctl_cmd) {
        Ok(c) => c,
        Err(e) => {
            host_child.sigkill_group();
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
        let _ = ctl_child.wait_with_output(Duration::from_secs(2)).await;
        host_child.sigkill_group();
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
    let mut signaling_tls = false;
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
            "usage: signaling-e2e --config <cluster.json> [--ca-der <path>] [--signaling-tls] [--codec vp9] [--frames 30]"
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
        ..Default::default()
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
    let _work_dir_guard = TempDirGuard(work_dir.clone());
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
            return ExitCode::FAILURE;
        }
    };

    let s1 = run_signaling_normal_scenario(
        &exe,
        "scenario_1_vp9",
        &config_path,
        resolved_ca.as_deref(),
        signaling_tls,
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
        resolved_ca.as_deref(),
        signaling_tls,
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
        resolved_ca.as_deref(),
        signaling_tls,
        &host_id_dir,
        &ctrl_id_dir,
        &work_dir,
        &tenant_id_hex,
        &enrollment_token,
    )
    .await;

    // Strictly assert fail-closed ZERO rendezvous files exist anywhere in work_dir.
    let (zero_rendezvous_verified, rendezvous_err) = match contains_rendezvous_file(&work_dir) {
        Ok(None) => (true, None),
        Ok(Some(p)) => (
            false,
            Some(format!("unexpected rendezvous file found: {}", p.display())),
        ),
        Err(e) => (false, Some(format!("rendezvous scan failed: {e}"))),
    };

    let pass = s1.pass && s2.pass && s3.pass && zero_rendezvous_verified;
    let report = SignalingE2eReport {
        pass,
        zero_rendezvous_verified,
        scenario_1_vp9: s1,
        scenario_2_av1: s2,
        scenario_3_sigkill_watchdog: s3,
        error: rendezvous_err,
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

        // Symlink pointing back to parent dir MUST NOT cause infinite recursion (uses file_type())
        #[cfg(unix)]
        {
            let _ = fs::remove_file(dir.join("rendezvous.json"));
            let loop_link = dir.join("self_loop");
            std::os::unix::fs::symlink(&dir, &loop_link).unwrap();
            assert!(contains_rendezvous_file(&dir).unwrap().is_none());
        }

        // Missing/unreadable directory MUST return Err (fail-closed)
        let missing = dir.join("does_not_exist");
        assert!(contains_rendezvous_file(&missing).is_err());

        let _ = fs::remove_dir_all(&dir);
    }
}
