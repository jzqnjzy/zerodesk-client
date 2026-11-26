use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, DirBuilder, File, OpenOptions},
    io::{BufRead, BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    process::{ExitCode, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
};
use v2_client::{
    decode_hex_array, now_unix_secs, AccessControlTunnel, ClientError, ClusterConfig,
    ControlPlaneClient, CreateTenantReq, RelayTicketWire, UdpAccessLink, UdpE2eeSession,
};
#[cfg(all(
    feature = "os-input",
    not(any(target_os = "android", target_os = "ios"))
))]
use v2_e2e::EnigoOsSink;
use v2_e2e::{
    compute_y_variance, decode_hid_frame, detect_visual_marker, encode_hid_frame,
    parse_session_close, spawn_capture_pipeline, spawn_release_watchdog, AuditKey, AuditRecord,
    CaptureError, CapturePipelineHandle, DesktopControllerSession, DesktopHostSession, DryRunSink,
    HidEchoAck, HidInputExecutor, HidInputSink, HidPayload, InputError, KeyEvent, MouseEvent,
    MouseKind, SafeHidKey, ScrapDisplaySource, SessionError, SharedVisualMarker,
    SyntheticAnimatedSource, V2VideoDecoder, V2VideoEncoder, VideoCodec, DEFAULT_SYNTHETIC_HEIGHT,
    DEFAULT_SYNTHETIC_WIDTH, MOUSE_BUTTON_LEFT,
};
use v2_identity::{
    verify_p256_low_s, DelegationStatement, DeviceCert, DeviceKeyStore, SoftwareDeviceKeyStore,
    TenantPolicyBlob, X25519StaticKeyRotator, DEVCERT_DOMAIN,
};
use v2_transport::{
    PrologueInput, QuotaExhaustPolicy, TenantPolicyRules, TransportEvent, VerifiedTenantPolicy,
    CAP_ACCESS_LEG_SEQ_V11, CAP_CODEC_AV1, CAP_CODEC_VP9, CAP_SURVIVAL_MODE,
    CAP_TRANSPORT_TCP443_DUAL, CIPHER_AESGCM, L3_MTU_DEFAULT, PATTERN_IK,
    TRANSPORT_MODE_RELAY_UDP, VER_MAJOR_MINOR,
};

const ENCODER_QUALITY: f32 = 2.0;
const KEYFRAME_INTERVAL: usize = 30;
const DEFAULT_CAP_BITS: u64 = CAP_CODEC_AV1
    | CAP_CODEC_VP9
    | CAP_TRANSPORT_TCP443_DUAL
    | CAP_ACCESS_LEG_SEQ_V11
    | CAP_SURVIVAL_MODE;
const MARKER_TARGET_X: i32 = 640;
const MARKER_TARGET_Y: i32 = 360;
const ENROLLMENT_TTL_SEC: u64 = 120;
const CAPTURE_PROBE_EXIT_PERMISSION_DENIED: u8 = 10;
const CAPTURE_PROBE_EXIT_UNAVAILABLE: u8 = 11;
const CAPTURE_PROBE_EXIT_DEGRADED_OR_PANICKED: u8 = 12;

static FILE_TEMP_NONCE: AtomicU64 = AtomicU64::new(1);

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

fn create_dir_0700(dir: &Path) -> Result<(), String> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| format!("create directory '{}': {e}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("set 0700 permissions on '{}': {e}", dir.display()))?;
    }
    Ok(())
}

fn write_bytes_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        create_dir_0700(parent)?;
    }
    let nonce = FILE_TEMP_NONCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!(
        ".{}.tmp.{}.{nonce}.{nanos}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("file"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        #[cfg(target_os = "macos")]
        const O_NOFOLLOW_FLAG: i32 = 0x0100;
        #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
        const O_NOFOLLOW_FLAG: i32 = 0o100000;
        #[cfg(all(
            target_os = "linux",
            not(any(target_arch = "aarch64", target_arch = "arm"))
        ))]
        const O_NOFOLLOW_FLAG: i32 = 0o400000;
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        opts.custom_flags(O_NOFOLLOW_FLAG);
    }

    let write_res = (|| -> Result<(), String> {
        let mut f = opts
            .open(&tmp_path)
            .map_err(|e| format!("create temp file '{}': {e}", tmp_path.display()))?;
        f.write_all(bytes)
            .map_err(|e| format!("write temp file '{}': {e}", tmp_path.display()))?;
        f.sync_all()
            .map_err(|e| format!("sync temp file '{}': {e}", tmp_path.display()))?;
        fs::rename(&tmp_path, path).map_err(|e| {
            format!(
                "atomic rename '{}' -> '{}': {e}",
                tmp_path.display(),
                path.display()
            )
        })
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

fn write_json_atomic<T: Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("json serialize: {e}"))?;
    write_bytes_atomic_0600(path, &bytes)
}

fn resolve_ca_der_path(
    cfg: &ClusterConfig,
    ca_der_override: Option<&Path>,
) -> Result<Option<PathBuf>, String> {
    let resolved = ca_der_override
        .map(Path::to_path_buf)
        .or_else(|| {
            cfg.ca_der_path
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        });
    if cfg.cp_use_tls && resolved.is_none() {
        return Err(
            "cp_use_tls=true requires a CA DER certificate via --ca-der or cluster.json ca_der_path"
                .into(),
        );
    }
    Ok(resolved)
}

/// Cryptographically verifies a CA-signed `V2-DEVCERT-v1` TBS payload and binds
/// `device_id`, `tenant_id`, `p256_pub_der`, `exp_unix`, and `SHA-256(tbs)` to the CA signature.
#[allow(clippy::too_many_arguments)]
fn verify_ca_signed_devcert_tbs(
    ca_spki_der: &[u8],
    tbs: &[u8],
    sig_der: &[u8],
    expected_tbs_sha256: &[u8; 32],
    expected_device_id: &[u8; 16],
    expected_tenant_id: &[u8; 16],
    expected_device_spki_der: &[u8],
    expected_exp_unix: u64,
    now_unix: u64,
) -> Result<(), String> {
    verify_p256_low_s(ca_spki_der, tbs, sig_der)
        .map_err(|e| format!("CA P-256 signature verification failed on DeviceCert TBS: {e}"))?;

    let actual_sha: [u8; 32] = Sha256::digest(tbs).into();
    if &actual_sha != expected_tbs_sha256 {
        return Err("DeviceCert TBS SHA-256 mismatch".into());
    }

    // Canonical DEVCERT_TBS layout (protocol-spec/spec/03-crypto-handshake.md §1.1):
    // domain(13) || version(4) || cert_id(16) || device_id(16) || tenant_id(16)
    // || pub_len(2) || p256_pub_der(pub_len) || key_epoch(8) || policy_hash(32)
    // || cap_bits(8) || iat_unix(8) || exp_unix(8)
    const PREFIX_LEN: usize = 13 + 4 + 16 + 16 + 16 + 2;
    const SUFFIX_LEN: usize = 8 + 32 + 8 + 8 + 8;
    if tbs.len() < PREFIX_LEN + SUFFIX_LEN {
        return Err(format!("DeviceCert TBS truncated ({} bytes)", tbs.len()));
    }
    if &tbs[0..13] != DEVCERT_DOMAIN {
        return Err("DeviceCert TBS domain separator mismatch".into());
    }
    if &tbs[33..49] != expected_device_id {
        return Err("DeviceCert TBS device_id does not match claimed device_id".into());
    }
    if &tbs[49..65] != expected_tenant_id {
        return Err("DeviceCert TBS tenant_id does not match session tenant_id".into());
    }
    let pub_len = u16::from_be_bytes([tbs[65], tbs[66]]) as usize;
    if tbs.len() != PREFIX_LEN + pub_len + SUFFIX_LEN {
        return Err(format!(
            "DeviceCert TBS length {} does not match pub_len {}",
            tbs.len(),
            pub_len
        ));
    }
    let pub_der = &tbs[67..67 + pub_len];
    if pub_der != expected_device_spki_der {
        return Err("DeviceCert TBS p256_pub_der does not match claimed device SPKI".into());
    }
    let exp_off = 67 + pub_len + 8 + 32 + 8 + 8;
    let exp_unix = u64::from_be_bytes([
        tbs[exp_off],
        tbs[exp_off + 1],
        tbs[exp_off + 2],
        tbs[exp_off + 3],
        tbs[exp_off + 4],
        tbs[exp_off + 5],
        tbs[exp_off + 6],
        tbs[exp_off + 7],
    ]);
    if exp_unix != expected_exp_unix {
        return Err(format!(
            "DeviceCert TBS exp_unix {exp_unix} != claimed {expected_exp_unix}"
        ));
    }
    if now_unix > exp_unix {
        return Err("DeviceCert is expired".into());
    }
    Ok(())
}

fn ctrl_rendezvous_path(rendezvous: &Path) -> PathBuf {
    PathBuf::from(format!("{}.ctrl.json", rendezvous.display()))
}

fn stuck_ready_path(rendezvous: &Path) -> PathBuf {
    PathBuf::from(format!("{}.stuck.ready", rendezvous.display()))
}

async fn wait_for_json_file<T: for<'de> Deserialize<'de>>(
    path: &Path,
    timeout: Duration,
) -> Result<T, String> {
    let deadline = Instant::now()
        .checked_add(timeout)
        .ok_or_else(|| "deadline overflow waiting for rendezvous file".to_string())?;
    loop {
        if let Ok(bytes) = fs::read(path) {
            if let Ok(parsed) = serde_json::from_slice::<T>(&bytes) {
                return Ok(parsed);
            }
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for rendezvous file '{}'",
                path.display()
            ));
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostRendezvous {
    tenant_id_hex: String,
    enrollment_token: String,
    session_id_hex: String,
    host_device_id_hex: String,
    host_device_spki_b64: String,
    host_devcert_tbs_b64: String,
    host_devcert_sig_b64: String,
    host_devcert_tbs_sha256_hex: String,
    host_cert_exp_unix: u64,
    host_x25519_pub_hex: String,
    host_delegation_json: String,
    policy_ca_spki_b64: String,
    policy_cert_json: String,
    policy_blob_json: String,
    policy_rules_json: String,
    cid_b_hex: String,
    pop_b: String,
    lease_seq: u64,
    capture_width: usize,
    capture_height: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControllerRendezvous {
    session_id_hex: String,
    host_device_id_hex: String,
    ctrl_device_id_hex: String,
    ctrl_device_spki_b64: String,
    ctrl_devcert_tbs_b64: String,
    ctrl_devcert_sig_b64: String,
    ctrl_devcert_tbs_sha256_hex: String,
    ctrl_cert_exp_unix: u64,
    ctrl_x25519_pub_hex: String,
    ctrl_delegation_json: String,
    cid_a_hex: String,
    pop_a: String,
    lease_seq: u64,
    ticket_b_key_id: u32,
    ticket_b_body_b64: String,
    ticket_b_mac_b64: String,
    ticket_b_bw_cap_kbps: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HostSummary {
    pass: bool,
    role: String,
    codec: String,
    source: String,
    os_input_enabled: bool,
    handshake_hash_hex: String,
    width: usize,
    height: usize,
    frames_sent: u64,
    frames_captured: u64,
    frames_overwritten: u64,
    hid_executed: u64,
    release_all_count: u64,
    final_pressed_buttons: u8,
    final_pressed_keys: Vec<SafeHidKey>,
    close_reason: String,
    capture_thread_joined: bool,
    watchdog_thread_joined: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ControllerSummary {
    pass: bool,
    role: String,
    codec: String,
    handshake_hash_hex: String,
    frames_decoded: u64,
    frame_id_monotonic: bool,
    decode_errors: u64,
    decoder_flushed_frames: u64,
    hid_events_sent: u64,
    visual_marker_before_hid: bool,
    visual_marker_detected_frames: u64,
    leave_stuck: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CaptureProbeReport {
    status: String,
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    frames: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_frames_captured: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    width: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    height: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    non_zero_variance: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_y_variance: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zero_variance_warning: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    thread_joined: Option<bool>,
    panic_free: bool,
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
    for (idx, line) in reader.lines().enumerate() {
        let line = line.map_err(|e| format!("read audit line {idx}: {e}"))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let rec: AuditRecord = serde_json::from_str(trimmed)
            .map_err(|e| format!("parse audit line {idx}: {e}"))?;
        records.push(rec);
    }
    Ok(records)
}

fn write_audit_jsonl_atomic(path: &Path, records: &[AuditRecord]) -> Result<(), String> {
    let mut buf = Vec::new();
    {
        let mut w = BufWriter::new(&mut buf);
        for rec in records {
            let line = serde_json::to_string(rec).map_err(|e| format!("serialize audit: {e}"))?;
            w.write_all(line.as_bytes()).map_err(|e| e.to_string())?;
            w.write_all(b"\n").map_err(|e| e.to_string())?;
        }
        w.flush().map_err(|e| e.to_string())?;
    }
    write_bytes_atomic_0600(path, &buf)
}

fn check_file_mode_0600(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(path)
            .map_err(|e| format!("stat '{}': {e}", path.display()))?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(format!(
                "file '{}' expected mode 0600, got {:04o}",
                path.display(),
                mode
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn build_interactive_hid_sequence(
    base_ts: u64,
    audit_key_identity: bool,
) -> Vec<(HidPayload, AuditRecord)> {
    let mut items = Vec::new();
    let mut seq = 0u32;

    let mut push_mouse = |kind: MouseKind,
                          buttons: u8,
                          x: i32,
                          y: i32,
                          wx: i16,
                          wy: i16,
                          audit: AuditRecord| {
        let ev = MouseEvent {
            kind,
            buttons,
            x_or_dx: x,
            y_or_dy: y,
            wheel_dx: wx,
            wheel_dy: wy,
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
    push_mouse(
        MouseKind::Up,
        MOUSE_BUTTON_LEFT,
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
    for &(down, key) in key_steps {
        let ts = base_ts + u64::from(seq);
        let ev = KeyEvent {
            down,
            modifiers: 0,
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

    // Final deterministic move to (640, 360) for closed-loop HID -> Video visual marker verification.
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

struct HostArgs {
    rendezvous: PathBuf,
    audit_out: PathBuf,
    source: String,
    codec: VideoCodec,
    fps: u32,
    watchdog_ms: u64,
    idle_exit_ms: u64,
    allow_idle_exit: bool,
    audit_key_identity: bool,
    enable_os_input: bool,
}

async fn run_host_with_sink<S: HidInputSink + 'static>(
    args: &HostArgs,
    cfg: &ClusterConfig,
    ca_path: Option<&Path>,
    sink: S,
    mut capture: CapturePipelineHandle,
    visual_marker: SharedVisualMarker,
    stop_flag: Arc<AtomicBool>,
) -> Result<HostSummary, String> {
    let (width, height) = capture.dimensions();
    let cp = ControlPlaneClient::new(&cfg.cp_base_url(), ca_path).map_err(|e| e.to_string())?;
    cp.healthz().await.map_err(|e| e.to_string())?;
    let ca_pub = cp.get_ca_pubkey().await.map_err(|e| e.to_string())?;
    let ca_spki_der = ca_pub.spki_der().map_err(|e| e.to_string())?;

    // Remove any stale controller rendezvous artifacts before advertising our new session.
    let ctrl_rdv_path = ctrl_rendezvous_path(&args.rendezvous);
    let _ = fs::remove_file(&ctrl_rdv_path);
    let _ = fs::remove_file(stuck_ready_path(&args.rendezvous));

    let tenant_id = random_bytes::<16>();
    let enrollment_token = format!("v2-desktop-p3-{}", hex::encode(random_bytes::<8>()));
    let bw_cap_kbps = 50_000u32;
    let admin_token = cfg
        .admin_token
        .as_deref()
        .ok_or_else(|| "cluster.json missing admin_token".to_string())?;

    let tenant_req = CreateTenantReq {
        tenant_id_hex: hex::encode(tenant_id),
        name: Some("zerodesk-desktop-p3-dual".into()),
        home_region: Some("local".into()),
        plan_tier: Some("pro".into()),
        monthly_quota_bytes: 20 * 1024 * 1024 * 1024,
        bw_cap_kbps,
        exhaust_policy: 0,
        allow_file_transfer: true,
        enrollment_token: enrollment_token.clone(),
        enrollment_ttl_sec: ENROLLMENT_TTL_SEC,
        policy_hash_hex: None,
    };
    cp.create_tenant(admin_token, &tenant_req)
        .await
        .map_err(|e| e.to_string())?;

    // Host generates its own P-256 identity and X25519 static keypair (private keys never leave host).
    let host_dev_id = random_bytes::<16>();
    let ks_host = SoftwareDeviceKeyStore::generate();
    let reg_host = cp
        .register_device(
            &ks_host,
            &host_dev_id,
            &enrollment_token,
            DEFAULT_CAP_BITS,
            "local",
            None,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
    let tbs_host = reg_host.tbs_bytes().map_err(|e| e.to_string())?;
    let sig_host = reg_host.sig_der().map_err(|e| e.to_string())?;
    let host_devcert_tbs_sha256: [u8; 32] = Sha256::digest(&tbs_host).into();
    let pub_spki_host = ks_host.public_key_spki_der().map_err(|e| e.to_string())?;
    verify_ca_signed_devcert_tbs(
        &ca_spki_der,
        &tbs_host,
        &sig_host,
        &host_devcert_tbs_sha256,
        &host_dev_id,
        &tenant_id,
        &pub_spki_host,
        reg_host.exp_unix,
        now_unix_secs(),
    )?;

    let now_unix = now_unix_secs();
    let mut rot_host = X25519StaticKeyRotator::new(host_dev_id, false, 0);
    let gen_host = rot_host
        .ensure_current(&ks_host, now_unix, reg_host.exp_unix)
        .map_err(|e| e.to_string())?;
    let x25519_priv_host = *gen_host.secret_bytes();
    let x25519_pub_host = gen_host.public_key;
    let deleg_host = gen_host.delegation.clone();

    let session_id = random_bytes::<16>();
    let pop_a_expected = cfg.edge_a.pop_id_bytes().map_err(|e| e.to_string())?;
    let pop_b = cfg.edge_b.pop_id_bytes().map_err(|e| e.to_string())?;
    let cid_b = random_bytes::<8>();
    let edge_b_pub = cfg.edge_b.x25519_pub().map_err(|e| e.to_string())?;
    let edge_b_hash = cfg.edge_b.edge_cert_hash().map_err(|e| e.to_string())?;
    let edge_a_hash = cfg.edge_a.edge_cert_hash().map_err(|e| e.to_string())?;

    let mut ctrl_b = AccessControlTunnel::connect(
        &cfg.edge_b.ctrl_addr,
        &x25519_priv_host,
        &edge_b_pub,
        &pop_b,
        &edge_b_hash,
        Duration::from_secs(5),
    )
    .await
    .map_err(|e| format!("host Edge B control tunnel failed: {e}"))?;

    // Anchor tenant policy signing directly to the CA-verified Host device key `ks_host`
    // (eliminating any unanchored ephemeral policy CA).
    let policy_ca_spki = pub_spki_host.clone();
    let rules = TenantPolicyRules {
        allow_file_transfer: true,
        allow_clipboard: true,
        allow_file_clipboard: true,
        allow_tcp_tunnel: true,
        allow_terminal: true,
        allow_realtime_actuator: false,
        bw_cap_kbps,
        exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
    };
    let mut policy_cert = DeviceCert {
        version: 1,
        cert_id: random_bytes::<16>(),
        device_id: host_dev_id,
        tenant_id,
        p256_pub_der: pub_spki_host.clone(),
        key_epoch: reg_host.key_epoch,
        policy_hash: rules.canonical_hash(),
        cap_bits: DEFAULT_CAP_BITS,
        iat_unix: now_unix.saturating_sub(10),
        exp_unix: now_unix.saturating_add(3600),
        hardware_backed: false,
        sig_der: Vec::new(),
    };
    policy_cert.sig_der = ks_host
        .sign_p256_low_s(&policy_cert.tbs_bytes().map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let mut policy_blob = TenantPolicyBlob {
        tenant_id,
        version: 1,
        policy_hash: rules.canonical_hash(),
        iat_unix: now_unix.saturating_sub(10),
        exp_unix: now_unix.saturating_add(3600),
        sig_der: Vec::new(),
    };
    policy_blob.sig_der = ks_host
        .sign_p256_low_s(&policy_blob.tbs_bytes())
        .map_err(|e| e.to_string())?;
    let policy = VerifiedTenantPolicy::from_verified_blob(
        &policy_blob,
        &policy_cert,
        &rules,
        &policy_ca_spki,
        now_unix,
    )
    .map_err(|e| e.to_string())?;

    let rdv = HostRendezvous {
        tenant_id_hex: hex::encode(tenant_id),
        enrollment_token,
        session_id_hex: hex::encode(session_id),
        host_device_id_hex: hex::encode(host_dev_id),
        host_device_spki_b64: B64.encode(&pub_spki_host),
        host_devcert_tbs_b64: B64.encode(&tbs_host),
        host_devcert_sig_b64: B64.encode(&sig_host),
        host_devcert_tbs_sha256_hex: hex::encode(host_devcert_tbs_sha256),
        host_cert_exp_unix: reg_host.exp_unix,
        host_x25519_pub_hex: hex::encode(x25519_pub_host),
        host_delegation_json: serde_json::to_string(&deleg_host).map_err(|e| e.to_string())?,
        policy_ca_spki_b64: B64.encode(&policy_ca_spki),
        policy_cert_json: serde_json::to_string(&policy_cert).map_err(|e| e.to_string())?,
        policy_blob_json: serde_json::to_string(&policy_blob).map_err(|e| e.to_string())?,
        policy_rules_json: serde_json::to_string(&rules).map_err(|e| e.to_string())?,
        cid_b_hex: hex::encode(cid_b),
        pop_b: cfg.edge_b.pop_id.clone(),
        lease_seq: 0,
        capture_width: width,
        capture_height: height,
    };
    write_json_atomic(&args.rendezvous, &rdv)?;

    // Wait for Controller's CA-anchored identity, session binding, and lease ticket_b.
    let ctrl_rdv: ControllerRendezvous =
        wait_for_json_file(&ctrl_rdv_path, Duration::from_secs(20)).await?;

    let rdv_session_id =
        decode_hex_array::<16>(&ctrl_rdv.session_id_hex, "session_id_hex")
            .map_err(|e| e.to_string())?;
    if rdv_session_id != session_id {
        return Err("controller rendezvous session_id mismatch".into());
    }
    let rdv_host_dev_id =
        decode_hex_array::<16>(&ctrl_rdv.host_device_id_hex, "host_device_id_hex")
            .map_err(|e| e.to_string())?;
    if rdv_host_dev_id != host_dev_id {
        return Err("controller rendezvous host_device_id mismatch".into());
    }
    if ctrl_rdv.pop_a != cfg.edge_a.pop_id {
        return Err(format!(
            "controller rendezvous pop_a '{}' does not match local edge_a pop_id '{}'",
            ctrl_rdv.pop_a, cfg.edge_a.pop_id
        ));
    }

    let ctrl_dev_id =
        decode_hex_array::<16>(&ctrl_rdv.ctrl_device_id_hex, "ctrl_device_id_hex")
            .map_err(|e| e.to_string())?;
    let ctrl_dev_spki = B64
        .decode(&ctrl_rdv.ctrl_device_spki_b64)
        .map_err(|e| format!("decode ctrl_device_spki_b64: {e}"))?;
    let ctrl_tbs = B64
        .decode(&ctrl_rdv.ctrl_devcert_tbs_b64)
        .map_err(|e| format!("decode ctrl_devcert_tbs_b64: {e}"))?;
    let ctrl_sig = B64
        .decode(&ctrl_rdv.ctrl_devcert_sig_b64)
        .map_err(|e| format!("decode ctrl_devcert_sig_b64: {e}"))?;
    let ctrl_tbs_sha = decode_hex_array::<32>(
        &ctrl_rdv.ctrl_devcert_tbs_sha256_hex,
        "ctrl_devcert_tbs_sha256_hex",
    )
    .map_err(|e| e.to_string())?;
    verify_ca_signed_devcert_tbs(
        &ca_spki_der,
        &ctrl_tbs,
        &ctrl_sig,
        &ctrl_tbs_sha,
        &ctrl_dev_id,
        &tenant_id,
        &ctrl_dev_spki,
        ctrl_rdv.ctrl_cert_exp_unix,
        now_unix_secs(),
    )?;

    let ctrl_x25519_pub =
        decode_hex_array::<32>(&ctrl_rdv.ctrl_x25519_pub_hex, "ctrl_x25519_pub_hex")
            .map_err(|e| e.to_string())?;
    let ctrl_deleg: DelegationStatement = serde_json::from_str(&ctrl_rdv.ctrl_delegation_json)
        .map_err(|e| format!("parse ctrl_delegation_json: {e}"))?;
    if ctrl_deleg.x25519_pub != ctrl_x25519_pub {
        return Err("controller delegation x25519_pub mismatch".into());
    }
    ctrl_deleg
        .verify(&ctrl_dev_spki, ctrl_rdv.ctrl_cert_exp_unix, now_unix_secs())
        .map_err(|e| format!("controller delegation verify failed: {e}"))?;

    let cid_a = decode_hex_array::<8>(&ctrl_rdv.cid_a_hex, "cid_a_hex")
        .map_err(|e| e.to_string())?;

    let ticket_b_body = B64
        .decode(&ctrl_rdv.ticket_b_body_b64)
        .map_err(|e| format!("decode ticket_b_body_b64: {e}"))?;
    let ticket_b_mac_vec = B64
        .decode(&ctrl_rdv.ticket_b_mac_b64)
        .map_err(|e| format!("decode ticket_b_mac_b64: {e}"))?;
    if ticket_b_mac_vec.len() != 32 {
        return Err("ticket_b_mac_b64 must be 32 bytes".into());
    }
    let mut ticket_b_mac = [0u8; 32];
    ticket_b_mac.copy_from_slice(&ticket_b_mac_vec);
    let ticket_b = RelayTicketWire {
        key_id: ctrl_rdv.ticket_b_key_id,
        body: ticket_b_body,
        mac: ticket_b_mac,
    };

    let (bind_b, keys_b) = ctrl_b
        .relay_bind(&ticket_b, &cid_a, &pop_a_expected)
        .await
        .map_err(|e| format!("host Edge B relay_bind failed: {e}"))?;
    if bind_b.route_cid != cid_b {
        return Err("Edge B RelayBindResp route_cid mismatch".into());
    }

    let mut udp_b = UdpAccessLink::connect(
        &cfg.edge_b.udp_addr,
        &keys_b,
        ctrl_rdv.ticket_b_bw_cap_kbps,
    )
    .await
    .map_err(|e| format!("host Edge B UDP connect failed: {e}"))?;
    let _ = udp_b
        .ping_with_retry(3, Duration::from_secs(1))
        .await
        .map_err(|e| format!("host Edge B UDP ping failed: {e}"))?;

    let prologue_input = PrologueInput {
        ver_major_minor: VER_MAJOR_MINOR,
        handshake_pattern: PATTERN_IK,
        cipher_suite: CIPHER_AESGCM,
        transport_mode: TRANSPORT_MODE_RELAY_UDP,
        device_id_ctrl: ctrl_dev_id,
        device_id_host: host_dev_id,
        ctrl_devcert_tbs_sha256: ctrl_tbs_sha,
        host_devcert_tbs_sha256,
        policy_hash: policy.policy_hash,
        edge_cert_tbs_sha256_or_zero: edge_a_hash,
        negotiated_cap_bits: DEFAULT_CAP_BITS,
        session_id,
    };

    let (e2ee_session, hs_out) = UdpE2eeSession::handshake_responder(
        udp_b,
        &prologue_input,
        &x25519_priv_host,
        &ctrl_deleg,
        &ctrl_dev_id,
        &ctrl_dev_spki,
        ctrl_rdv.ctrl_cert_exp_unix,
        now_unix_secs(),
        policy,
        host_dev_id,
        L3_MTU_DEFAULT,
        Duration::from_secs(10),
    )
    .await
    .map_err(|e| format!("host Noise_IK responder handshake failed: {e}"))?;

    if hs_out.remote_static_x25519 != ctrl_x25519_pub {
        return Err("Noise_IK remote static X25519 pubkey mismatch".into());
    }
    let handshake_hash_hex = hex::encode(*hs_out.hs_hash);
    eprintln!("[host] handshake_hash_hex={handshake_hash_hex}");

    let encoder = V2VideoEncoder::new(
        args.codec,
        width as u32,
        height as u32,
        ENCODER_QUALITY,
        Some(KEYFRAME_INTERVAL),
    )
    .map_err(|e| e.to_string())?;
    let mut host = DesktopHostSession::new(e2ee_session, encoder);

    let executor = Arc::new(Mutex::new(
        HidInputExecutor::with_options(
            sink,
            width as i32,
            height as i32,
            v2_e2e::DEFAULT_HID_RATE_LIMIT_PER_SEC,
            Some(visual_marker),
        )
        .map_err(|e| e.to_string())?
        .with_audit_key_identity(args.audit_key_identity),
    ));
    let mut watchdog_handle = spawn_release_watchdog(
        Arc::clone(&executor),
        Duration::from_millis(args.watchdog_ms),
        Arc::clone(&stop_flag),
    )
    .map_err(|e| format!("spawn watchdog failed: {e}"))?;

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

    let frame_interval = Duration::from_nanos(1_000_000_000u64 / u64::from(args.fps.max(1)));
    let keepalive_interval = Duration::from_millis(500);
    let idle_exit = Duration::from_millis(args.idle_exit_ms);
    let session_start = Instant::now();
    let mut last_peer_activity = Instant::now();
    let mut next_frame_at = Instant::now();
    let mut next_hid_seq = 0u32;
    let close_reason: String;
    let mut fatal_error: Option<String> = None;

    'session_loop: loop {
        if sig_stop.load(Ordering::Acquire) {
            close_reason = "signal".into();
            break;
        }
        if last_peer_activity.elapsed() >= idle_exit {
            close_reason = "idle_timeout".into();
            break;
        }

        let recv_wait = next_frame_at
            .saturating_duration_since(Instant::now())
            .clamp(Duration::from_millis(1), Duration::from_millis(10));
        match host.session_mut().recv_event(recv_wait).await {
            Ok(TransportEvent::Hid(frame)) => {
                last_peer_activity = Instant::now();
                match decode_hid_frame(&frame) {
                    Ok(payload) => {
                        let ts_now = now_ms();
                        let seq = next_hid_seq;
                        next_hid_seq = next_hid_seq.wrapping_add(1);
                        let apply_res = {
                            let mut guard = executor
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner());
                            guard.apply_batch(&[(seq, payload, ts_now)], ts_now)
                        };
                        match apply_res {
                            Ok(_) => {
                                let ack = HidPayload::EchoAck(HidEchoAck {
                                    echo_seq: seq,
                                    client_ts_ms: payload.client_ts_ms(),
                                });
                                if let Ok(ack_frame) = encode_hid_frame(&ack) {
                                    if let Err(e) = host.session_mut().send_hid(&ack_frame).await {
                                        close_reason = "transport_error".into();
                                        fatal_error = Some(e.to_string());
                                        break 'session_loop;
                                    }
                                }
                            }
                            Err(InputError::SinkFailed(msg)) => {
                                close_reason = "sink_failed".into();
                                fatal_error = Some(msg);
                                break 'session_loop;
                            }
                            Err(InputError::SessionTerminated) => {
                                close_reason = "session_terminated".into();
                                fatal_error = Some("HID executor terminated".into());
                                break 'session_loop;
                            }
                            Err(_) => {}
                        }
                    }
                    Err(_) => {
                        host.malformed_hid_frames_dropped =
                            host.malformed_hid_frames_dropped.saturating_add(1);
                    }
                }
            }
            Ok(TransportEvent::Control(ctrl)) => {
                last_peer_activity = Instant::now();
                {
                    let guard = executor
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    guard.touch_activity();
                }
                if parse_session_close(&ctrl).is_some() {
                    close_reason = "session_close".into();
                    break 'session_loop;
                }
            }
            Ok(
                TransportEvent::Audio(_)
                | TransportEvent::VideoFrame(_)
                | TransportEvent::Clipboard(_)
                | TransportEvent::FileTransfer(_)
                | TransportEvent::Diagnostics(_)
                | TransportEvent::RealtimeActuator(_)
                | TransportEvent::Telemetry(_)
                | TransportEvent::TransportModeChanged(_)
                | TransportEvent::BandwidthEstimate { .. }
                | TransportEvent::RequestIdr { .. }
                | TransportEvent::PolicyUpdated(_),
            ) => {
                last_peer_activity = Instant::now();
            }
            Err(ClientError::Timeout(_)) => {}
            Err(e) => {
                close_reason = "transport_error".into();
                fatal_error = Some(e.to_string());
                break 'session_loop;
            }
        }

        let now = Instant::now();
        if now >= next_frame_at {
            if let Some(captured) = capture.try_take_latest_or_keepalive(keepalive_interval) {
                let pts_ms = session_start.elapsed().as_millis() as i64;
                if let Err(e) = host.publish_i420_frame(captured.frame, pts_ms).await {
                    close_reason = "video_publish_error".into();
                    fatal_error = Some(e.to_string());
                    break 'session_loop;
                }
            }
            next_frame_at += frame_interval;
            if next_frame_at + frame_interval < now {
                next_frame_at = now + frame_interval;
            }
        }
    }

    // 2A-P1-2 & 2A-P1-3: signal stop, IMMEDIATELY release held inputs & flush audit JSONL
    // (recovering poisoned mutexes rather than exiting early), BEFORE joining capture/watchdog
    // threads so slow capture teardown can never leave keys held.
    stop_flag.store(true, Ordering::Release);
    let mut audit_flush_err: Option<String> = None;
    let (hid_executed, release_all_count, final_pressed_buttons, final_pressed_keys) = {
        let mut guard = executor
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.has_pressed_state() {
            let _ = guard.release_all(&close_reason);
        }
        if let Err(e) = guard.flush_audit_jsonl(&args.audit_out) {
            audit_flush_err = Some(format!("flush host audit JSONL failed: {e}"));
        }
        (
            guard.executed_events,
            guard.release_all_count,
            guard.pressed_buttons(),
            guard.pressed_keys().iter().copied().collect::<Vec<_>>(),
        )
    };

    let capture_thread_joined = capture.stop_and_join().is_ok();
    let watchdog_thread_joined = watchdog_handle.stop_and_join().is_ok();
    drop(ctrl_b);

    if fatal_error.is_none() {
        fatal_error = audit_flush_err;
    }

    // 2A-P1-1: idle_timeout fails by default unless --allow-idle-exit is explicitly set.
    let allowed_close = close_reason == "session_close"
        || close_reason == "signal"
        || (args.allow_idle_exit && close_reason == "idle_timeout");
    let stats = capture.stats();
    let pass = fatal_error.is_none()
        && allowed_close
        && capture_thread_joined
        && watchdog_thread_joined
        && final_pressed_buttons == 0
        && final_pressed_keys.is_empty();

    if pass {
        let _ = fs::remove_file(&args.rendezvous);
        let _ = fs::remove_file(&ctrl_rdv_path);
        let _ = fs::remove_file(stuck_ready_path(&args.rendezvous));
    }

    Ok(HostSummary {
        pass,
        role: "host".into(),
        codec: args.codec.name().into(),
        source: args.source.clone(),
        os_input_enabled: args.enable_os_input,
        handshake_hash_hex,
        width,
        height,
        frames_sent: host.video_frames_sent,
        frames_captured: stats.frames_captured.load(Ordering::Relaxed),
        frames_overwritten: stats.frames_overwritten.load(Ordering::Relaxed),
        hid_executed,
        release_all_count,
        final_pressed_buttons,
        final_pressed_keys,
        close_reason,
        capture_thread_joined,
        watchdog_thread_joined,
        error: fatal_error,
    })
}

pub async fn cmd_host(args: &[String]) -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut rendezvous: Option<PathBuf> = None;
    let mut audit_out: Option<PathBuf> = None;
    let mut source = String::from("synthetic");
    let mut codec = VideoCodec::Vp9;
    let mut fps = 30u32;
    let mut watchdog_ms = 800u64;
    let mut idle_exit_ms = 2500u64;
    let mut allow_idle_exit = false;
    let mut audit_key_identity = false;
    let mut enable_os_input = false;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| config = Some(v.into())),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| ca_der = Some(v.into())),
            "--rendezvous" => {
                parse_flag_value(args, &mut i, "--rendezvous").map(|v| rendezvous = Some(v.into()))
            }
            "--audit-out" => {
                parse_flag_value(args, &mut i, "--audit-out").map(|v| audit_out = Some(v.into()))
            }
            "--source" => parse_flag_value(args, &mut i, "--source").map(|v| source = v),
            "--codec" => parse_flag_value(args, &mut i, "--codec")
                .and_then(|v| VideoCodec::parse_name(&v).map_err(|e| e.to_string()))
                .map(|c| codec = c),
            "--fps" => parse_flag_value(args, &mut i, "--fps")
                .and_then(|v| v.parse::<u32>().map_err(|e| e.to_string()))
                .map(|v| fps = v.max(1)),
            "--watchdog-ms" => parse_flag_value(args, &mut i, "--watchdog-ms")
                .and_then(|v| v.parse::<u64>().map_err(|e| e.to_string()))
                .map(|v| watchdog_ms = v.max(50)),
            "--idle-exit-ms" => parse_flag_value(args, &mut i, "--idle-exit-ms")
                .and_then(|v| v.parse::<u64>().map_err(|e| e.to_string()))
                .map(|v| idle_exit_ms = v.max(100)),
            "--allow-idle-exit" => {
                allow_idle_exit = true;
                Ok(())
            }
            "--audit-key-identity" => {
                audit_key_identity = true;
                Ok(())
            }
            "--enable-os-input" => {
                enable_os_input = true;
                Ok(())
            }
            other => Err(format!("unknown argument '{other}'")),
        };
        if let Err(e) = res {
            eprintln!("[host] {e}");
            return ExitCode::from(2);
        }
        i += 1;
    }

    let (Some(config), Some(rendezvous), Some(audit_out)) = (config, rendezvous, audit_out) else {
        eprintln!("[host] --config, --rendezvous, and --audit-out are required");
        return ExitCode::from(2);
    };

    // Fail closed if user explicitly requested OS input without `os-input` feature compiled in.
    #[cfg(not(all(
        feature = "os-input",
        not(any(target_os = "android", target_os = "ios"))
    )))]
    if enable_os_input {
        let err = serde_json::json!({
            "pass": false,
            "role": "host",
            "error": "--enable-os-input requested, but binary was built without the 'os-input' feature (refusing to silently fall back to dry-run)"
        });
        if let Ok(s) = serde_json::to_string_pretty(&err) {
            println!("{s}");
        }
        return ExitCode::FAILURE;
    }

    let cfg = match ClusterConfig::from_file(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[host] failed to load config: {e}");
            return ExitCode::from(2);
        }
    };
    let ca_path = match resolve_ca_der_path(&cfg, ca_der.as_deref()) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("[host] {msg}");
            return ExitCode::from(2);
        }
    };

    let host_args = HostArgs {
        rendezvous,
        audit_out,
        source: source.clone(),
        codec,
        fps,
        watchdog_ms,
        idle_exit_ms,
        allow_idle_exit,
        audit_key_identity,
        enable_os_input,
    };

    let stop_flag = Arc::new(AtomicBool::new(false));
    let visual_marker: SharedVisualMarker = Arc::new(Mutex::new(None));
    let capture_res = match source.as_str() {
        "synthetic" => {
            let src = SyntheticAnimatedSource::new(
                DEFAULT_SYNTHETIC_WIDTH,
                DEFAULT_SYNTHETIC_HEIGHT,
                fps,
                Some(Arc::clone(&visual_marker)),
            );
            src.and_then(|s| spawn_capture_pipeline(s, Arc::clone(&stop_flag)))
        }
        "screen" => ScrapDisplaySource::new()
            .and_then(|s| spawn_capture_pipeline(s, Arc::clone(&stop_flag))),
        other => Err(CaptureError::Unavailable(format!(
            "unsupported capture source '{other}' (expected synthetic or screen)"
        ))),
    };

    let capture = match capture_res {
        Ok(c) => c,
        Err(e) => {
            let err = serde_json::json!({
                "pass": false,
                "role": "host",
                "error": e.to_string(),
            });
            if let Ok(s) = serde_json::to_string_pretty(&err) {
                println!("{s}");
            }
            return ExitCode::FAILURE;
        }
    };

    let outcome = if enable_os_input {
        #[cfg(all(
            feature = "os-input",
            not(any(target_os = "android", target_os = "ios"))
        ))]
        {
            match EnigoOsSink::new() {
                Ok(sink) => {
                    run_host_with_sink(
                        &host_args,
                        &cfg,
                        ca_path.as_deref(),
                        sink,
                        capture,
                        visual_marker,
                        stop_flag,
                    )
                    .await
                }
                Err(e) => Err(e.to_string()),
            }
        }
        #[cfg(not(all(
            feature = "os-input",
            not(any(target_os = "android", target_os = "ios"))
        )))]
        {
            Err("--enable-os-input unavailable without os-input feature".to_string())
        }
    } else {
        run_host_with_sink(
            &host_args,
            &cfg,
            ca_path.as_deref(),
            DryRunSink::new(),
            capture,
            visual_marker,
            stop_flag,
        )
        .await
    };

    match outcome {
        Ok(summary) => {
            if let Ok(s) = serde_json::to_string_pretty(&summary) {
                println!("{s}");
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
                "role": "host",
                "error": e,
            });
            if let Ok(s) = serde_json::to_string_pretty(&err) {
                println!("{s}");
            }
            ExitCode::FAILURE
        }
    }
}

struct ControllerArgs {
    rendezvous: PathBuf,
    audit_out: PathBuf,
    frames: usize,
    codec: VideoCodec,
    leave_stuck: bool,
    hold_after_stuck_ms: u64,
    no_visual_marker: bool,
    audit_key_identity: bool,
}

async fn run_controller(
    args: &ControllerArgs,
    cfg: &ClusterConfig,
    ca_path: Option<&Path>,
) -> Result<ControllerSummary, String> {
    let cp = ControlPlaneClient::new(&cfg.cp_base_url(), ca_path).map_err(|e| e.to_string())?;
    cp.healthz().await.map_err(|e| e.to_string())?;
    let ca_pub = cp.get_ca_pubkey().await.map_err(|e| e.to_string())?;
    let ca_spki_der = ca_pub.spki_der().map_err(|e| e.to_string())?;

    let host_rdv: HostRendezvous =
        wait_for_json_file(&args.rendezvous, Duration::from_secs(20)).await?;

    let tenant_id = decode_hex_array::<16>(&host_rdv.tenant_id_hex, "tenant_id_hex")
        .map_err(|e| e.to_string())?;
    let session_id = decode_hex_array::<16>(&host_rdv.session_id_hex, "session_id_hex")
        .map_err(|e| e.to_string())?;
    let host_dev_id = decode_hex_array::<16>(&host_rdv.host_device_id_hex, "host_device_id_hex")
        .map_err(|e| e.to_string())?;
    let host_spki = B64
        .decode(&host_rdv.host_device_spki_b64)
        .map_err(|e| format!("decode host_device_spki_b64: {e}"))?;
    let host_tbs = B64
        .decode(&host_rdv.host_devcert_tbs_b64)
        .map_err(|e| format!("decode host_devcert_tbs_b64: {e}"))?;
    let host_sig = B64
        .decode(&host_rdv.host_devcert_sig_b64)
        .map_err(|e| format!("decode host_devcert_sig_b64: {e}"))?;
    let host_tbs_sha = decode_hex_array::<32>(
        &host_rdv.host_devcert_tbs_sha256_hex,
        "host_devcert_tbs_sha256_hex",
    )
    .map_err(|e| e.to_string())?;

    // 2B-P1-2: Cryptographically verify Host identity against Control-Plane CA.
    verify_ca_signed_devcert_tbs(
        &ca_spki_der,
        &host_tbs,
        &host_sig,
        &host_tbs_sha,
        &host_dev_id,
        &tenant_id,
        &host_spki,
        host_rdv.host_cert_exp_unix,
        now_unix_secs(),
    )?;

    let host_x25519_pub =
        decode_hex_array::<32>(&host_rdv.host_x25519_pub_hex, "host_x25519_pub_hex")
            .map_err(|e| e.to_string())?;
    let host_deleg: DelegationStatement = serde_json::from_str(&host_rdv.host_delegation_json)
        .map_err(|e| format!("parse host_delegation_json: {e}"))?;
    if host_deleg.x25519_pub != host_x25519_pub {
        return Err("host delegation x25519_pub mismatch".into());
    }
    host_deleg
        .verify(&host_spki, host_rdv.host_cert_exp_unix, now_unix_secs())
        .map_err(|e| format!("host delegation verify failed: {e}"))?;

    // 2B-P1-1: Policy MUST be signed by the CA-verified Host device key (`policy_ca_spki == host_spki`).
    let policy_ca_spki = B64
        .decode(&host_rdv.policy_ca_spki_b64)
        .map_err(|e| format!("decode policy_ca_spki_b64: {e}"))?;
    if policy_ca_spki != host_spki {
        return Err(
            "policy_ca_spki is not anchored to the CA-verified host device public key".into(),
        );
    }
    let policy_cert: DeviceCert = serde_json::from_str(&host_rdv.policy_cert_json)
        .map_err(|e| format!("parse policy_cert_json: {e}"))?;
    let policy_blob: TenantPolicyBlob = serde_json::from_str(&host_rdv.policy_blob_json)
        .map_err(|e| format!("parse policy_blob_json: {e}"))?;
    let policy_rules: TenantPolicyRules = serde_json::from_str(&host_rdv.policy_rules_json)
        .map_err(|e| format!("parse policy_rules_json: {e}"))?;
    let policy = VerifiedTenantPolicy::from_verified_blob(
        &policy_blob,
        &policy_cert,
        &policy_rules,
        &policy_ca_spki,
        now_unix_secs(),
    )
    .map_err(|e| format!("controller policy verification failed: {e}"))?;

    let cid_b =
        decode_hex_array::<8>(&host_rdv.cid_b_hex, "cid_b_hex").map_err(|e| e.to_string())?;
    let pop_b = cfg.edge_b.pop_id_bytes().map_err(|e| e.to_string())?;
    if host_rdv.pop_b.as_bytes() != pop_b {
        return Err(format!(
            "host rendezvous pop_b '{}' does not match local edge_b pop_id '{}'",
            host_rdv.pop_b, cfg.edge_b.pop_id
        ));
    }

    // Controller generates its own P-256 identity and X25519 keypair (private keys never leave process).
    let ctrl_dev_id = random_bytes::<16>();
    let ks_ctrl = SoftwareDeviceKeyStore::generate();
    let reg_ctrl = cp
        .register_device(
            &ks_ctrl,
            &ctrl_dev_id,
            &host_rdv.enrollment_token,
            DEFAULT_CAP_BITS,
            "local",
            None,
            None,
        )
        .await
        .map_err(|e| e.to_string())?;
    let tbs_ctrl = reg_ctrl.tbs_bytes().map_err(|e| e.to_string())?;
    let sig_ctrl = reg_ctrl.sig_der().map_err(|e| e.to_string())?;
    let ctrl_devcert_tbs_sha256: [u8; 32] = Sha256::digest(&tbs_ctrl).into();
    let pub_spki_ctrl = ks_ctrl.public_key_spki_der().map_err(|e| e.to_string())?;
    verify_ca_signed_devcert_tbs(
        &ca_spki_der,
        &tbs_ctrl,
        &sig_ctrl,
        &ctrl_devcert_tbs_sha256,
        &ctrl_dev_id,
        &tenant_id,
        &pub_spki_ctrl,
        reg_ctrl.exp_unix,
        now_unix_secs(),
    )?;

    let now_unix = now_unix_secs();
    let mut rot_ctrl = X25519StaticKeyRotator::new(ctrl_dev_id, false, 0);
    let gen_ctrl = rot_ctrl
        .ensure_current(&ks_ctrl, now_unix, reg_ctrl.exp_unix)
        .map_err(|e| e.to_string())?;
    let x25519_priv_ctrl = *gen_ctrl.secret_bytes();
    let x25519_pub_ctrl = gen_ctrl.public_key;
    let deleg_ctrl = gen_ctrl.delegation.clone();

    let pop_a = cfg.edge_a.pop_id_bytes().map_err(|e| e.to_string())?;
    let cid_a = random_bytes::<8>();
    let edge_a_pub = cfg.edge_a.x25519_pub().map_err(|e| e.to_string())?;
    let edge_a_hash = cfg.edge_a.edge_cert_hash().map_err(|e| e.to_string())?;

    let lease_a = cp
        .issue_lease(
            &ks_ctrl,
            Some(&tenant_id),
            &session_id,
            &cid_a,
            &pop_a,
            &ctrl_dev_id,
            &host_dev_id,
            1,
        )
        .await
        .map_err(|e| format!("controller issue_lease(a) failed: {e}"))?;
    let lease_b = cp
        .renew_lease(
            &ks_ctrl,
            Some(&tenant_id),
            &session_id,
            &cid_b,
            &pop_b,
            &ctrl_dev_id,
            &host_dev_id,
            lease_a.lease_seq,
            0,
            1,
        )
        .await
        .map_err(|e| format!("controller renew_lease(b) failed: {e}"))?;
    let ticket_a = lease_a.to_relay_ticket().map_err(|e| e.to_string())?;

    let mut ctrl_a = AccessControlTunnel::connect(
        &cfg.edge_a.ctrl_addr,
        &x25519_priv_ctrl,
        &edge_a_pub,
        &pop_a,
        &edge_a_hash,
        Duration::from_secs(5),
    )
    .await
    .map_err(|e| format!("controller Edge A control tunnel failed: {e}"))?;
    let (bind_a, keys_a) = ctrl_a
        .relay_bind(&ticket_a, &cid_b, &pop_b)
        .await
        .map_err(|e| format!("controller Edge A relay_bind failed: {e}"))?;
    if bind_a.route_cid != cid_a {
        return Err("Edge A RelayBindResp route_cid mismatch".into());
    }

    let mut udp_a = UdpAccessLink::connect(&cfg.edge_a.udp_addr, &keys_a, lease_a.bw_cap_kbps)
        .await
        .map_err(|e| format!("controller Edge A UDP connect failed: {e}"))?;
    let _ = udp_a
        .ping_with_retry(3, Duration::from_secs(1))
        .await
        .map_err(|e| format!("controller Edge A UDP ping failed: {e}"))?;

    let ctrl_rdv = ControllerRendezvous {
        session_id_hex: hex::encode(session_id),
        host_device_id_hex: hex::encode(host_dev_id),
        ctrl_device_id_hex: hex::encode(ctrl_dev_id),
        ctrl_device_spki_b64: B64.encode(&pub_spki_ctrl),
        ctrl_devcert_tbs_b64: B64.encode(&tbs_ctrl),
        ctrl_devcert_sig_b64: B64.encode(&sig_ctrl),
        ctrl_devcert_tbs_sha256_hex: hex::encode(ctrl_devcert_tbs_sha256),
        ctrl_cert_exp_unix: reg_ctrl.exp_unix,
        ctrl_x25519_pub_hex: hex::encode(x25519_pub_ctrl),
        ctrl_delegation_json: serde_json::to_string(&deleg_ctrl).map_err(|e| e.to_string())?,
        cid_a_hex: hex::encode(cid_a),
        pop_a: cfg.edge_a.pop_id.clone(),
        lease_seq: lease_b.lease_seq,
        ticket_b_key_id: lease_b.key_id,
        ticket_b_body_b64: lease_b.ticket_body_b64.clone(),
        ticket_b_mac_b64: lease_b.ticket_mac_b64.clone(),
        ticket_b_bw_cap_kbps: lease_b.bw_cap_kbps,
    };
    write_json_atomic(&ctrl_rendezvous_path(&args.rendezvous), &ctrl_rdv)?;

    let prologue_input = PrologueInput {
        ver_major_minor: VER_MAJOR_MINOR,
        handshake_pattern: PATTERN_IK,
        cipher_suite: CIPHER_AESGCM,
        transport_mode: TRANSPORT_MODE_RELAY_UDP,
        device_id_ctrl: ctrl_dev_id,
        device_id_host: host_dev_id,
        ctrl_devcert_tbs_sha256,
        host_devcert_tbs_sha256: host_tbs_sha,
        policy_hash: policy.policy_hash,
        edge_cert_tbs_sha256_or_zero: edge_a_hash,
        negotiated_cap_bits: DEFAULT_CAP_BITS,
        session_id,
    };

    let (e2ee_session, hs_out) = UdpE2eeSession::handshake_initiator(
        udp_a,
        &prologue_input,
        &x25519_priv_ctrl,
        &host_x25519_pub,
        &host_deleg,
        &host_dev_id,
        &host_spki,
        host_rdv.host_cert_exp_unix,
        now_unix_secs(),
        policy,
        ctrl_dev_id,
        L3_MTU_DEFAULT,
        Duration::from_secs(10),
    )
    .await
    .map_err(|e| format!("controller Noise_IK initiator handshake failed: {e}"))?;

    let handshake_hash_hex = hex::encode(*hs_out.hs_hash);
    eprintln!("[controller] handshake_hash_hex={handshake_hash_hex}");

    let decoder = V2VideoDecoder::new(args.codec).map_err(|e| e.to_string())?;
    let mut controller = DesktopControllerSession::new(e2ee_session, decoder);

    let mut sent_audit: Vec<AuditRecord> = Vec::new();
    let mut prev_frame_id: Option<u32> = None;
    let mut frame_id_monotonic = true;
    let mut frames_decoded = 0u64;
    let mut visual_marker_before_hid = false;
    let mut visual_marker_detected_frames = 0u64;

    if args.leave_stuck {
        // Confirm at least 1 real decoded frame before latching stuck keys/buttons.
        let _d0 = controller
            .recv_and_decode_video(Duration::from_secs(10))
            .await
            .map_err(|e| format!("controller initial video recv failed: {e}"))?;
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
                    modifiers: 0,
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
                    modifiers: 0,
                    usb_hid_usage: SafeHidKey::KeyA.usb_hid_usage(),
                    unicode_scalar: 'a' as u32,
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
            sent_audit.push(rec);
        }
        write_audit_jsonl_atomic(&args.audit_out, &sent_audit)?;
        write_bytes_atomic_0600(&stuck_ready_path(&args.rendezvous), b"ready\n")?;

        if args.hold_after_stuck_ms > 0 {
            tokio::time::sleep(Duration::from_millis(args.hold_after_stuck_ms)).await;
        }
        // Graceful close (if not SIGKILLed during hold_after_stuck_ms).
        let _ = controller.send_session_close(0x0000).await;
    } else {
        let target_frames = args.frames.max(1);
        let pre_hid_frames = 2usize.min(target_frames);
        for idx in 0..pre_hid_frames {
            let delivery = controller
                .recv_and_decode_video(Duration::from_secs(10))
                .await
                .map_err(|e| format!("controller video recv #{idx} failed: {e}"))?;
            if let Some(prev) = prev_frame_id {
                if delivery.frame.frame_id <= prev {
                    frame_id_monotonic = false;
                }
            }
            prev_frame_id = Some(delivery.frame.frame_id);
            frames_decoded += 1;
            // 2B-P1-3: check ALL pre-HID frames (not only frame #0).
            if detect_visual_marker(&delivery.i420, MARKER_TARGET_X, MARKER_TARGET_Y).detected {
                visual_marker_before_hid = true;
            }
        }

        // Send deterministic safe HID sequence and await Host's P0 EchoAck for every event.
        let hid_seq = build_interactive_hid_sequence(now_ms(), args.audit_key_identity);
        for (idx, (payload, audit_rec)) in hid_seq.into_iter().enumerate() {
            let _ = controller
                .send_hid_and_await_echo(&payload, idx as u32, Duration::from_secs(5))
                .await
                .map_err(|e| format!("controller HID seq {idx} echo failed: {e}"))?;
            sent_audit.push(audit_rec);
        }
        write_audit_jsonl_atomic(&args.audit_out, &sent_audit)?;

        // Decode remaining video frames and verify closed-loop visual marker at (640, 360).
        while (frames_decoded as usize) < target_frames {
            let delivery = controller
                .recv_and_decode_video(Duration::from_secs(10))
                .await
                .map_err(|e| format!("controller video recv #{frames_decoded} failed: {e}"))?;
            if let Some(prev) = prev_frame_id {
                if delivery.frame.frame_id <= prev {
                    frame_id_monotonic = false;
                }
            }
            prev_frame_id = Some(delivery.frame.frame_id);
            frames_decoded += 1;
            if detect_visual_marker(&delivery.i420, MARKER_TARGET_X, MARKER_TARGET_Y).detected {
                visual_marker_detected_frames += 1;
            }
        }

        // Graceful SESSION_CLOSE (`0x04`)
        controller
            .send_session_close(0x0000)
            .await
            .map_err(|e| format!("send_session_close failed: {e}"))?;
    }

    let _ = controller
        .flush_decoder()
        .map_err(|e: SessionError| format!("flush_decoder failed: {e}"))?;
    drop(ctrl_a);

    // 2B-P1-3: visual marker causality is enforced directly in ControllerSummary.pass
    // in non-stuck mode unless --no-visual-marker is passed.
    let marker_ok = args.leave_stuck
        || args.no_visual_marker
        || (!visual_marker_before_hid && visual_marker_detected_frames >= 1);
    let pass = frames_decoded >= if args.leave_stuck { 1 } else { args.frames as u64 }
        && frame_id_monotonic
        && controller.decode_errors == 0
        && marker_ok;

    Ok(ControllerSummary {
        pass,
        role: "controller".into(),
        codec: args.codec.name().into(),
        handshake_hash_hex,
        frames_decoded,
        frame_id_monotonic,
        decode_errors: controller.decode_errors,
        decoder_flushed_frames: controller.decoder_flushed_frames,
        hid_events_sent: sent_audit.len() as u64,
        visual_marker_before_hid,
        visual_marker_detected_frames,
        leave_stuck: args.leave_stuck,
        error: if pass {
            None
        } else {
            Some("controller verification assertions failed".into())
        },
    })
}

pub async fn cmd_controller(args: &[String]) -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut rendezvous: Option<PathBuf> = None;
    let mut audit_out: Option<PathBuf> = None;
    let mut frames = 60usize;
    let mut codec = VideoCodec::Vp9;
    let mut leave_stuck = false;
    let mut hold_after_stuck_ms = 0u64;
    let mut no_visual_marker = false;
    let mut audit_key_identity = false;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| config = Some(v.into())),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| ca_der = Some(v.into())),
            "--rendezvous" => {
                parse_flag_value(args, &mut i, "--rendezvous").map(|v| rendezvous = Some(v.into()))
            }
            "--audit-out" => {
                parse_flag_value(args, &mut i, "--audit-out").map(|v| audit_out = Some(v.into()))
            }
            "--frames" => parse_flag_value(args, &mut i, "--frames")
                .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                .map(|v| frames = v.max(1)),
            "--codec" => parse_flag_value(args, &mut i, "--codec")
                .and_then(|v| VideoCodec::parse_name(&v).map_err(|e| e.to_string()))
                .map(|c| codec = c),
            "--leave-stuck" => {
                leave_stuck = true;
                Ok(())
            }
            "--hold-after-stuck-ms" => parse_flag_value(args, &mut i, "--hold-after-stuck-ms")
                .and_then(|v| v.parse::<u64>().map_err(|e| e.to_string()))
                .map(|v| hold_after_stuck_ms = v),
            "--no-visual-marker" => {
                no_visual_marker = true;
                Ok(())
            }
            "--audit-key-identity" => {
                audit_key_identity = true;
                Ok(())
            }
            other => Err(format!("unknown argument '{other}'")),
        };
        if let Err(e) = res {
            eprintln!("[controller] {e}");
            return ExitCode::from(2);
        }
        i += 1;
    }

    let (Some(config), Some(rendezvous), Some(audit_out)) = (config, rendezvous, audit_out) else {
        eprintln!("[controller] --config, --rendezvous, and --audit-out are required");
        return ExitCode::from(2);
    };

    let cfg = match ClusterConfig::from_file(&config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[controller] failed to load config: {e}");
            return ExitCode::from(2);
        }
    };
    let ca_path = match resolve_ca_der_path(&cfg, ca_der.as_deref()) {
        Ok(p) => p,
        Err(msg) => {
            eprintln!("[controller] {msg}");
            return ExitCode::from(2);
        }
    };

    let ctrl_args = ControllerArgs {
        rendezvous,
        audit_out,
        frames,
        codec,
        leave_stuck,
        hold_after_stuck_ms,
        no_visual_marker,
        audit_key_identity,
    };
    match run_controller(&ctrl_args, &cfg, ca_path.as_deref()).await {
        Ok(summary) => {
            if let Ok(s) = serde_json::to_string_pretty(&summary) {
                println!("{s}");
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
                "role": "controller",
                "error": e,
            });
            if let Ok(s) = serde_json::to_string_pretty(&err) {
                println!("{s}");
            }
            ExitCode::FAILURE
        }
    }
}

struct ManagedChild {
    child: Option<Child>,
    pid: u32,
    stdout_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
    stderr_task: Option<tokio::task::JoinHandle<Vec<u8>>>,
}

impl ManagedChild {
    fn spawn(mut cmd: Command) -> Result<Self, String> {
        cmd.stdout(Stdio::piped()).stderr(Stdio::piped());
        #[cfg(unix)]
        {
            // SAFETY: `setpgid(0, 0)` is async-signal-safe and isolates child process group.
            unsafe {
                cmd.pre_exec(|| {
                    if setpgid(0, 0) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let mut child = cmd.spawn().map_err(|e| format!("spawn child failed: {e}"))?;
        let pid = child
            .id()
            .ok_or_else(|| "spawned child missing PID".to_string())?;

        // Drain stdout & stderr concurrently from spawn so child pipe buffers can never deadlock.
        let stdout_task = child.stdout.take().map(|mut out| {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = out.read_to_end(&mut buf).await;
                buf
            })
        });
        let stderr_task = child.stderr.take().map(|mut err| {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let _ = err.read_to_end(&mut buf).await;
                buf
            })
        });

        Ok(Self {
            child: Some(child),
            pid,
            stdout_task,
            stderr_task,
        })
    }

    fn kill_process_group(&mut self) {
        #[cfg(unix)]
        unsafe {
            let _ = kill(-(self.pid as i32), 9);
            let _ = kill(self.pid as i32, 9);
        }
        #[cfg(not(unix))]
        if let Some(ref mut c) = self.child {
            let _ = c.start_kill();
        }
    }

    async fn collect_pipes(&mut self) -> (Vec<u8>, Vec<u8>) {
        let stdout = match self.stdout_task.take() {
            Some(t) => tokio::time::timeout(Duration::from_secs(2), t)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        let stderr = match self.stderr_task.take() {
            Some(t) => tokio::time::timeout(Duration::from_secs(2), t)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default(),
            None => Vec::new(),
        };
        (stdout, stderr)
    }

    async fn wait_with_timeout(&mut self, timeout: Duration) -> Result<std::process::Output, String> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| "child already consumed".to_string())?;
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(Ok(status)) => {
                let (stdout, stderr) = self.collect_pipes().await;
                Ok(std::process::Output {
                    status,
                    stdout,
                    stderr,
                })
            }
            Ok(Err(e)) => {
                self.kill_process_group();
                let _ = child.wait().await;
                let (stdout, stderr) = self.collect_pipes().await;
                Err(format!(
                    "wait failed for pid {}: {e}; stdout={}; stderr={}",
                    self.pid,
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr),
                ))
            }
            Err(_) => {
                self.kill_process_group();
                let _ = child.wait().await;
                let (stdout, stderr) = self.collect_pipes().await;
                Err(format!(
                    "child process {} timed out after {} ms; stdout={}; stderr={}",
                    self.pid,
                    timeout.as_millis(),
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr),
                ))
            }
        }
    }

    async fn sigkill_and_reap(&mut self) -> Result<Option<i32>, String> {
        let Some(mut child) = self.child.take() else {
            return Ok(None);
        };
        self.kill_process_group();
        #[cfg(not(unix))]
        let _ = child.start_kill();
        let status = child
            .wait()
            .await
            .map_err(|e| format!("wait after SIGKILL: {e}"))?;
        let _ = self.collect_pipes().await;
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Ok(status.signal())
        }
        #[cfg(not(unix))]
        {
            Ok(status.code())
        }
    }
}

impl Drop for ManagedChild {
    fn drop(&mut self) {
        if self.child.is_some() {
            self.kill_process_group();
            if let Some(mut c) = self.child.take() {
                let _ = c.start_kill();
            }
        }
    }
}

#[derive(Debug, Serialize)]
struct ScenarioAReport {
    pass: bool,
    host_pid: u32,
    controller_pid: u32,
    handshake_hash_hex: String,
    handshake_hash_match: bool,
    frames_decoded: u64,
    frame_id_monotonic: bool,
    decode_errors: u64,
    decoder_flushed_frames: u64,
    hid_events_matched: usize,
    hid_audit_exact_match: bool,
    audit_files_0600: bool,
    visual_marker_before_hid: bool,
    visual_marker_detected_frames: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScenarioBReport {
    pass: bool,
    host_pid: u32,
    controller_pid: u32,
    handshake_hash_hex: String,
    handshake_hash_match: bool,
    frames_decoded: u64,
    frame_id_monotonic: bool,
    decode_errors: u64,
    decoder_flushed_frames: u64,
    hid_events_matched: usize,
    hid_audit_exact_match: bool,
    audit_files_0600: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct ScenarioStuckReport {
    pass: bool,
    mode: String,
    host_pid: u32,
    controller_pid: u32,
    handshake_hash_hex: String,
    handshake_hash_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    sigkill_signal: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    watchdog_release_latency_ms: Option<u64>,
    pre_release_events_matched: usize,
    release_all_records_count: usize,
    release_all_reason: String,
    released_buttons: u8,
    released_keys: Vec<SafeHidKey>,
    audit_files_0600: bool,
    final_pressed_buttons: u8,
    final_pressed_keys: Vec<SafeHidKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct DualE2eReport {
    pass: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    preserved_work_dir: Option<String>,
    scenario_a_vp9_hid_marker: ScenarioAReport,
    scenario_b_av1: ScenarioBReport,
    scenario_c_graceful_release_all: ScenarioStuckReport,
    scenario_d_sigkill_watchdog_release_all: ScenarioStuckReport,
}

fn spawn_subcommand(exe: &Path, subcmd: &str, extra_args: &[String]) -> Result<ManagedChild, String> {
    let mut cmd = Command::new(exe);
    cmd.arg(subcmd);
    for a in extra_args {
        cmd.arg(a);
    }
    ManagedChild::spawn(cmd)
}

fn parse_child_json<T: for<'de> Deserialize<'de>>(
    name: &str,
    out: &std::process::Output,
) -> Result<T, String> {
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    if !out.status.success() {
        return Err(format!(
            "{name} exited with {:?}; stdout={stdout}; stderr={stderr}",
            out.status.code()
        ));
    }
    serde_json::from_str(&stdout)
        .map_err(|e| format!("parse {name} stdout JSON failed: {e}; stdout={stdout}; stderr={stderr}"))
}

async fn run_scenario_a(
    exe: &Path,
    work_dir: &Path,
    cfg: &Path,
    ca_der: Option<&Path>,
    codec: VideoCodec,
    frames: usize,
) -> ScenarioAReport {
    let rdv = work_dir.join("scenario_a.rdv.json");
    let host_audit = work_dir.join("scenario_a.host.jsonl");
    let ctrl_audit = work_dir.join("scenario_a.ctrl.jsonl");

    let mut host_args = vec![
        "--config".into(),
        cfg.display().to_string(),
        "--rendezvous".into(),
        rdv.display().to_string(),
        "--audit-out".into(),
        host_audit.display().to_string(),
        "--source".into(),
        "synthetic".into(),
        "--codec".into(),
        codec.name().into(),
        "--fps".into(),
        "30".into(),
        "--watchdog-ms".into(),
        "1200".into(),
        "--idle-exit-ms".into(),
        "4000".into(),
        "--audit-key-identity".into(),
    ];
    let mut ctrl_args = vec![
        "--config".into(),
        cfg.display().to_string(),
        "--rendezvous".into(),
        rdv.display().to_string(),
        "--audit-out".into(),
        ctrl_audit.display().to_string(),
        "--codec".into(),
        codec.name().into(),
        "--frames".into(),
        frames.to_string(),
        "--audit-key-identity".into(),
    ];
    if let Some(ca) = ca_der {
        host_args.push("--ca-der".into());
        host_args.push(ca.display().to_string());
        ctrl_args.push("--ca-der".into());
        ctrl_args.push(ca.display().to_string());
    }

    let make_err = |msg: String| ScenarioAReport {
        pass: false,
        host_pid: 0,
        controller_pid: 0,
        handshake_hash_hex: String::new(),
        handshake_hash_match: false,
        frames_decoded: 0,
        frame_id_monotonic: false,
        decode_errors: 0,
        decoder_flushed_frames: 0,
        hid_events_matched: 0,
        hid_audit_exact_match: false,
        audit_files_0600: false,
        visual_marker_before_hid: false,
        visual_marker_detected_frames: 0,
        error: Some(msg),
    };

    let mut host = match spawn_subcommand(exe, "host", &host_args) {
        Ok(c) => c,
        Err(e) => return make_err(e),
    };
    let mut ctrl = match spawn_subcommand(exe, "controller", &ctrl_args) {
        Ok(c) => c,
        Err(e) => return make_err(e),
    };
    let host_pid = host.pid;
    let ctrl_pid = ctrl.pid;

    let timeout = Duration::from_secs(45);
    let (host_res, ctrl_res) =
        tokio::join!(host.wait_with_timeout(timeout), ctrl.wait_with_timeout(timeout));
    let host_out = match host_res {
        Ok(o) => o,
        Err(e) => return make_err(e),
    };
    let ctrl_out = match ctrl_res {
        Ok(o) => o,
        Err(e) => return make_err(e),
    };

    let host_sum: HostSummary = match parse_child_json("host", &host_out) {
        Ok(s) => s,
        Err(e) => return make_err(e),
    };
    let ctrl_sum: ControllerSummary = match parse_child_json("controller", &ctrl_out) {
        Ok(s) => s,
        Err(e) => return make_err(e),
    };

    let audit_files_0600 =
        check_file_mode_0600(&host_audit).is_ok() && check_file_mode_0600(&ctrl_audit).is_ok();
    let host_recs = match read_audit_jsonl(&host_audit) {
        Ok(r) => r,
        Err(e) => return make_err(e),
    };
    let ctrl_recs = match read_audit_jsonl(&ctrl_audit) {
        Ok(r) => r,
        Err(e) => return make_err(e),
    };
    let host_cmp: Vec<ComparableHidEvent> = host_recs.iter().filter_map(audit_to_comparable).collect();
    let ctrl_cmp: Vec<ComparableHidEvent> = ctrl_recs.iter().filter_map(audit_to_comparable).collect();
    let hid_audit_exact_match = !ctrl_cmp.is_empty() && host_cmp == ctrl_cmp;

    let handshake_hash_match = host_sum.handshake_hash_hex.len() == 64
        && host_sum.handshake_hash_hex == ctrl_sum.handshake_hash_hex;
    let pass = host_sum.pass
        && ctrl_sum.pass
        && host_pid != ctrl_pid
        && handshake_hash_match
        && ctrl_sum.frames_decoded >= frames as u64
        && ctrl_sum.frame_id_monotonic
        && ctrl_sum.decode_errors == 0
        && hid_audit_exact_match
        && audit_files_0600
        && !ctrl_sum.visual_marker_before_hid
        && ctrl_sum.visual_marker_detected_frames >= 1;

    ScenarioAReport {
        pass,
        host_pid,
        controller_pid: ctrl_pid,
        handshake_hash_hex: ctrl_sum.handshake_hash_hex,
        handshake_hash_match,
        frames_decoded: ctrl_sum.frames_decoded,
        frame_id_monotonic: ctrl_sum.frame_id_monotonic,
        decode_errors: ctrl_sum.decode_errors,
        decoder_flushed_frames: ctrl_sum.decoder_flushed_frames,
        hid_events_matched: ctrl_cmp.len(),
        hid_audit_exact_match,
        audit_files_0600,
        visual_marker_before_hid: ctrl_sum.visual_marker_before_hid,
        visual_marker_detected_frames: ctrl_sum.visual_marker_detected_frames,
        error: if pass {
            None
        } else {
            Some("Scenario A assertion failed".into())
        },
    }
}

async fn run_scenario_b(
    exe: &Path,
    work_dir: &Path,
    cfg: &Path,
    ca_der: Option<&Path>,
) -> ScenarioBReport {
    let rdv = work_dir.join("scenario_b.rdv.json");
    let host_audit = work_dir.join("scenario_b.host.jsonl");
    let ctrl_audit = work_dir.join("scenario_b.ctrl.jsonl");

    let mut host_args = vec![
        "--config".into(),
        cfg.display().to_string(),
        "--rendezvous".into(),
        rdv.display().to_string(),
        "--audit-out".into(),
        host_audit.display().to_string(),
        "--source".into(),
        "synthetic".into(),
        "--codec".into(),
        "av1".into(),
        "--fps".into(),
        "15".into(),
        "--watchdog-ms".into(),
        "1200".into(),
        "--idle-exit-ms".into(),
        "5000".into(),
        "--audit-key-identity".into(),
    ];
    let mut ctrl_args = vec![
        "--config".into(),
        cfg.display().to_string(),
        "--rendezvous".into(),
        rdv.display().to_string(),
        "--audit-out".into(),
        ctrl_audit.display().to_string(),
        "--codec".into(),
        "av1".into(),
        "--frames".into(),
        "10".into(),
        "--audit-key-identity".into(),
    ];
    if let Some(ca) = ca_der {
        host_args.push("--ca-der".into());
        host_args.push(ca.display().to_string());
        ctrl_args.push("--ca-der".into());
        ctrl_args.push(ca.display().to_string());
    }

    let make_err = |msg: String| ScenarioBReport {
        pass: false,
        host_pid: 0,
        controller_pid: 0,
        handshake_hash_hex: String::new(),
        handshake_hash_match: false,
        frames_decoded: 0,
        frame_id_monotonic: false,
        decode_errors: 0,
        decoder_flushed_frames: 0,
        hid_events_matched: 0,
        hid_audit_exact_match: false,
        audit_files_0600: false,
        error: Some(msg),
    };

    let mut host = match spawn_subcommand(exe, "host", &host_args) {
        Ok(c) => c,
        Err(e) => return make_err(e),
    };
    let mut ctrl = match spawn_subcommand(exe, "controller", &ctrl_args) {
        Ok(c) => c,
        Err(e) => return make_err(e),
    };
    let host_pid = host.pid;
    let ctrl_pid = ctrl.pid;

    let timeout = Duration::from_secs(45);
    let (host_res, ctrl_res) =
        tokio::join!(host.wait_with_timeout(timeout), ctrl.wait_with_timeout(timeout));
    let host_out = match host_res {
        Ok(o) => o,
        Err(e) => return make_err(e),
    };
    let ctrl_out = match ctrl_res {
        Ok(o) => o,
        Err(e) => return make_err(e),
    };

    let host_sum: HostSummary = match parse_child_json("host", &host_out) {
        Ok(s) => s,
        Err(e) => return make_err(e),
    };
    let ctrl_sum: ControllerSummary = match parse_child_json("controller", &ctrl_out) {
        Ok(s) => s,
        Err(e) => return make_err(e),
    };

    let audit_files_0600 =
        check_file_mode_0600(&host_audit).is_ok() && check_file_mode_0600(&ctrl_audit).is_ok();
    let host_recs = match read_audit_jsonl(&host_audit) {
        Ok(r) => r,
        Err(e) => return make_err(e),
    };
    let ctrl_recs = match read_audit_jsonl(&ctrl_audit) {
        Ok(r) => r,
        Err(e) => return make_err(e),
    };
    let host_cmp: Vec<ComparableHidEvent> = host_recs.iter().filter_map(audit_to_comparable).collect();
    let ctrl_cmp: Vec<ComparableHidEvent> = ctrl_recs.iter().filter_map(audit_to_comparable).collect();
    let hid_audit_exact_match = !ctrl_cmp.is_empty() && host_cmp == ctrl_cmp;

    let handshake_hash_match = host_sum.handshake_hash_hex.len() == 64
        && host_sum.handshake_hash_hex == ctrl_sum.handshake_hash_hex;
    let pass = host_sum.pass
        && ctrl_sum.pass
        && host_pid != ctrl_pid
        && handshake_hash_match
        && ctrl_sum.frames_decoded >= 10
        && ctrl_sum.frame_id_monotonic
        && ctrl_sum.decode_errors == 0
        && hid_audit_exact_match
        && audit_files_0600;

    ScenarioBReport {
        pass,
        host_pid,
        controller_pid: ctrl_pid,
        handshake_hash_hex: ctrl_sum.handshake_hash_hex,
        handshake_hash_match,
        frames_decoded: ctrl_sum.frames_decoded,
        frame_id_monotonic: ctrl_sum.frame_id_monotonic,
        decode_errors: ctrl_sum.decode_errors,
        decoder_flushed_frames: ctrl_sum.decoder_flushed_frames,
        hid_events_matched: ctrl_cmp.len(),
        hid_audit_exact_match,
        audit_files_0600,
        error: if pass {
            None
        } else {
            Some("Scenario B AV1 assertion failed".into())
        },
    }
}

async fn run_scenario_stuck(
    exe: &Path,
    work_dir: &Path,
    cfg: &Path,
    ca_der: Option<&Path>,
    sigkill_mode: bool,
) -> ScenarioStuckReport {
    let tag = if sigkill_mode { "scenario_d" } else { "scenario_c" };
    let mode = if sigkill_mode {
        "sigkill_watchdog"
    } else {
        "graceful_session_close"
    };
    let rdv = work_dir.join(format!("{tag}.rdv.json"));
    let host_audit = work_dir.join(format!("{tag}.host.jsonl"));
    let ctrl_audit = work_dir.join(format!("{tag}.ctrl.jsonl"));

    let watchdog_ms: u64 = if sigkill_mode { 500 } else { 1500 };
    let idle_exit_ms: u64 = if sigkill_mode { 1500 } else { 3000 };
    let hold_ms = if sigkill_mode { "8000" } else { "0" };

    let mut host_args = vec![
        "--config".into(),
        cfg.display().to_string(),
        "--rendezvous".into(),
        rdv.display().to_string(),
        "--audit-out".into(),
        host_audit.display().to_string(),
        "--source".into(),
        "synthetic".into(),
        "--codec".into(),
        "vp9".into(),
        "--fps".into(),
        "20".into(),
        "--watchdog-ms".into(),
        watchdog_ms.to_string(),
        "--idle-exit-ms".into(),
        idle_exit_ms.to_string(),
        "--audit-key-identity".into(),
    ];
    if sigkill_mode {
        // 2A-P1-1: only Scenario D allows idle_timeout as a passing exit reason.
        host_args.push("--allow-idle-exit".into());
    }
    let mut ctrl_args = vec![
        "--config".into(),
        cfg.display().to_string(),
        "--rendezvous".into(),
        rdv.display().to_string(),
        "--audit-out".into(),
        ctrl_audit.display().to_string(),
        "--codec".into(),
        "vp9".into(),
        "--frames".into(),
        "5".into(),
        "--leave-stuck".into(),
        "--hold-after-stuck-ms".into(),
        hold_ms.into(),
        "--audit-key-identity".into(),
    ];
    if let Some(ca) = ca_der {
        host_args.push("--ca-der".into());
        host_args.push(ca.display().to_string());
        ctrl_args.push("--ca-der".into());
        ctrl_args.push(ca.display().to_string());
    }

    let make_err = |msg: String| ScenarioStuckReport {
        pass: false,
        mode: mode.into(),
        host_pid: 0,
        controller_pid: 0,
        handshake_hash_hex: String::new(),
        handshake_hash_match: false,
        sigkill_signal: None,
        watchdog_release_latency_ms: None,
        pre_release_events_matched: 0,
        release_all_records_count: 0,
        release_all_reason: String::new(),
        released_buttons: 0,
        released_keys: Vec::new(),
        audit_files_0600: false,
        final_pressed_buttons: 0,
        final_pressed_keys: Vec::new(),
        error: Some(msg),
    };

    let mut host = match spawn_subcommand(exe, "host", &host_args) {
        Ok(c) => c,
        Err(e) => return make_err(e),
    };
    let mut ctrl = match spawn_subcommand(exe, "controller", &ctrl_args) {
        Ok(c) => c,
        Err(e) => return make_err(e),
    };
    let host_pid = host.pid;
    let ctrl_pid = ctrl.pid;
    let mut sigkill_signal = None;
    let mut sigkill_ts_ms: Option<u64> = None;
    let mut ctrl_hs_hash: Option<String> = None;

    if sigkill_mode {
        let ready = stuck_ready_path(&rdv);
        let deadline = Instant::now() + Duration::from_secs(20);
        while !ready.is_file() {
            if Instant::now() >= deadline {
                return make_err("timed out waiting for controller stuck.ready marker".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        sigkill_ts_ms = Some(now_ms());
        sigkill_signal = match ctrl.sigkill_and_reap().await {
            Ok(sig) => sig,
            Err(e) => return make_err(e),
        };
    } else {
        match ctrl.wait_with_timeout(Duration::from_secs(25)).await {
            Ok(out) => match parse_child_json::<ControllerSummary>("controller", &out) {
                Ok(cs) => {
                    if !cs.pass {
                        return make_err("controller reported pass=false in Scenario C".into());
                    }
                    ctrl_hs_hash = Some(cs.handshake_hash_hex);
                }
                Err(e) => return make_err(e),
            },
            Err(e) => return make_err(e),
        }
    }

    let host_out = match host.wait_with_timeout(Duration::from_secs(25)).await {
        Ok(o) => o,
        Err(e) => return make_err(e),
    };
    let host_sum: HostSummary = match parse_child_json("host", &host_out) {
        Ok(s) => s,
        Err(e) => return make_err(e),
    };
    let audit_files_0600 =
        check_file_mode_0600(&host_audit).is_ok() && check_file_mode_0600(&ctrl_audit).is_ok();
    let host_recs = match read_audit_jsonl(&host_audit) {
        Ok(r) => r,
        Err(e) => return make_err(e),
    };
    let ctrl_recs = match read_audit_jsonl(&ctrl_audit) {
        Ok(r) => r,
        Err(e) => return make_err(e),
    };

    let expected_reason = if sigkill_mode {
        "watchdog_timeout"
    } else {
        "session_close"
    };
    let expected_keys = vec![SafeHidKey::KeyA, SafeHidKey::LeftShift];

    // 2B-P1-4: ALL ReleaseAll records in Host JSONL must match ONLY the expected reason (exact count == 1).
    let release_indices: Vec<usize> = host_recs
        .iter()
        .enumerate()
        .filter_map(|(idx, r)| matches!(r, AuditRecord::ReleaseAll { .. }).then_some(idx))
        .collect();
    let release_all_records_count = release_indices.len();
    if release_all_records_count != 1 {
        return make_err(format!(
            "expected exactly 1 ReleaseAll record in host audit log, found {release_all_records_count}"
        ));
    }
    let rel_idx = release_indices[0];
    let (release_all_reason, released_buttons, released_keys, failed_buttons, failed_keys, rel_ts_ms) =
        match &host_recs[rel_idx] {
            AuditRecord::ReleaseAll {
                reason,
                released_buttons,
                released_keys,
                failed_buttons,
                failed_keys,
                ts_ms,
            } => (
                reason.clone(),
                *released_buttons,
                released_keys.clone(),
                *failed_buttons,
                failed_keys.clone(),
                *ts_ms,
            ),
            _ => unreachable!(),
        };

    // Verify all 3 pressed events (LeftShift down, KeyA down, Mouse Left down) appear in Host JSONL
    // BEFORE ReleaseAll and match Controller's sent JSONL 1-for-1.
    let host_pre_release: Vec<ComparableHidEvent> = host_recs[..rel_idx]
        .iter()
        .filter_map(audit_to_comparable)
        .collect();
    let ctrl_sent: Vec<ComparableHidEvent> =
        ctrl_recs.iter().filter_map(audit_to_comparable).collect();
    let expected_pre_release = vec![
        ComparableHidEvent::KeyDown {
            key: AuditKey::Key(SafeHidKey::LeftShift),
        },
        ComparableHidEvent::KeyDown {
            key: AuditKey::Key(SafeHidKey::KeyA),
        },
        ComparableHidEvent::MouseDown {
            button_bit: MOUSE_BUTTON_LEFT,
            x: MARKER_TARGET_X,
            y: MARKER_TARGET_Y,
        },
    ];
    let pre_release_exact =
        host_pre_release == expected_pre_release && ctrl_sent == expected_pre_release;

    let handshake_hash_match = if let Some(ref ch) = ctrl_hs_hash {
        host_sum.handshake_hash_hex.len() == 64 && &host_sum.handshake_hash_hex == ch
    } else {
        // In Scenario D (SIGKILL), Controller is killed mid-session before printing summary;
        // verify Host completed handshake with a valid 64-hex-char transcript hash.
        host_sum.handshake_hash_hex.len() == 64
    };

    let watchdog_release_latency_ms =
        sigkill_ts_ms.map(|kill_ts| rel_ts_ms.saturating_sub(kill_ts));
    let latency_ok = watchdog_release_latency_ms
        .map(|lat| lat <= watchdog_ms + 2500)
        .unwrap_or(true);

    let pass = host_sum.pass
        && host_pid != ctrl_pid
        && handshake_hash_match
        && (!sigkill_mode || sigkill_signal == Some(9))
        && pre_release_exact
        && release_all_records_count == 1
        && release_all_reason == expected_reason
        && released_buttons == MOUSE_BUTTON_LEFT
        && released_keys == expected_keys
        && failed_buttons == 0
        && failed_keys.is_empty()
        && latency_ok
        && audit_files_0600
        && host_sum.final_pressed_buttons == 0
        && host_sum.final_pressed_keys.is_empty();

    ScenarioStuckReport {
        pass,
        mode: mode.into(),
        host_pid,
        controller_pid: ctrl_pid,
        handshake_hash_hex: host_sum.handshake_hash_hex,
        handshake_hash_match,
        sigkill_signal,
        watchdog_release_latency_ms,
        pre_release_events_matched: if pre_release_exact {
            expected_pre_release.len()
        } else {
            0
        },
        release_all_records_count,
        release_all_reason,
        released_buttons,
        released_keys,
        audit_files_0600,
        final_pressed_buttons: host_sum.final_pressed_buttons,
        final_pressed_keys: host_sum.final_pressed_keys,
        error: if pass {
            None
        } else {
            Some(format!("Scenario {mode} assertion failed"))
        },
    }
}

pub async fn cmd_dual_e2e(args: &[String]) -> ExitCode {
    let mut config: Option<PathBuf> = None;
    let mut ca_der: Option<PathBuf> = None;
    let mut codec = VideoCodec::Vp9;
    let mut frames = 60usize;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--config" => parse_flag_value(args, &mut i, "--config").map(|v| config = Some(v.into())),
            "--ca-der" => parse_flag_value(args, &mut i, "--ca-der").map(|v| ca_der = Some(v.into())),
            "--codec" => parse_flag_value(args, &mut i, "--codec")
                .and_then(|v| VideoCodec::parse_name(&v).map_err(|e| e.to_string()))
                .map(|c| codec = c),
            "--frames" => parse_flag_value(args, &mut i, "--frames")
                .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                .map(|v| frames = v.max(1)),
            other => Err(format!("unknown argument '{other}'")),
        };
        if let Err(e) = res {
            eprintln!("[dual-e2e] {e}");
            return ExitCode::from(2);
        }
        i += 1;
    }

    let Some(cfg_path) = config else {
        eprintln!("[dual-e2e] --config <cluster.json> is required");
        return ExitCode::from(2);
    };
    let cfg = match ClusterConfig::from_file(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[dual-e2e] failed to load config: {e}");
            return ExitCode::from(2);
        }
    };
    if let Err(msg) = resolve_ca_der_path(&cfg, ca_der.as_deref()) {
        eprintln!("[dual-e2e] {msg}");
        return ExitCode::from(2);
    }

    let exe = match std::env::current_exe() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[dual-e2e] current_exe failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let work_dir = std::env::temp_dir().join(format!(
        "zd-dual-e2e-{}-{uniq}",
        std::process::id()
    ));
    if let Err(e) = create_dir_0700(&work_dir) {
        eprintln!("[dual-e2e] create temp dir failed: {e}");
        return ExitCode::FAILURE;
    }

    let scenario_a =
        run_scenario_a(&exe, &work_dir, &cfg_path, ca_der.as_deref(), codec, frames).await;
    let scenario_b = run_scenario_b(&exe, &work_dir, &cfg_path, ca_der.as_deref()).await;
    let scenario_c =
        run_scenario_stuck(&exe, &work_dir, &cfg_path, ca_der.as_deref(), false).await;
    let scenario_d =
        run_scenario_stuck(&exe, &work_dir, &cfg_path, ca_der.as_deref(), true).await;

    let pass = scenario_a.pass && scenario_b.pass && scenario_c.pass && scenario_d.pass;
    let preserved_work_dir = if pass {
        let _ = fs::remove_dir_all(&work_dir);
        None
    } else {
        let dir_str = work_dir.display().to_string();
        eprintln!("[dual-e2e] preserving work_dir for debugging: {dir_str}");
        Some(dir_str)
    };

    let report = DualE2eReport {
        pass,
        preserved_work_dir,
        scenario_a_vp9_hid_marker: scenario_a,
        scenario_b_av1: scenario_b,
        scenario_c_graceful_release_all: scenario_c,
        scenario_d_sigkill_watchdog_release_all: scenario_d,
    };
    if let Ok(s) = serde_json::to_string_pretty(&report) {
        println!("{s}");
    }
    if pass {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

pub async fn cmd_capture_probe(args: &[String]) -> ExitCode {
    let mut source_name = String::from("screen");
    let mut target_frames = 30usize;
    let mut timeout_ms = 5000u64;

    let mut i = 2;
    while i < args.len() {
        let res: Result<(), String> = match args[i].as_str() {
            "--source" => parse_flag_value(args, &mut i, "--source").map(|v| source_name = v),
            "--frames" => parse_flag_value(args, &mut i, "--frames")
                .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                .map(|v| target_frames = v.max(1)),
            "--timeout-ms" => parse_flag_value(args, &mut i, "--timeout-ms")
                .and_then(|v| v.parse::<u64>().map_err(|e| e.to_string()))
                .map(|v| timeout_ms = v.max(200)),
            other => Err(format!("unknown argument '{other}'")),
        };
        if let Err(e) = res {
            eprintln!("[capture-probe] {e}");
            return ExitCode::from(2);
        }
        i += 1;
    }

    let stop_flag = Arc::new(AtomicBool::new(false));
    let handle_res = match source_name.as_str() {
        "screen" => ScrapDisplaySource::new()
            .and_then(|s| spawn_capture_pipeline(s, Arc::clone(&stop_flag))),
        "synthetic" => SyntheticAnimatedSource::new(
            DEFAULT_SYNTHETIC_WIDTH,
            DEFAULT_SYNTHETIC_HEIGHT,
            60,
            None,
        )
        .and_then(|s| spawn_capture_pipeline(s, Arc::clone(&stop_flag))),
        other => Err(CaptureError::Unavailable(format!(
            "unsupported source '{other}' (expected screen or synthetic)"
        ))),
    };

    let (report, exit_code) = match handle_res {
        Err(CaptureError::PermissionDenied(msg)) => (
            CaptureProbeReport {
                status: "permission_denied".into(),
                source: source_name,
                frames: None,
                raw_frames_captured: None,
                width: None,
                height: None,
                non_zero_variance: None,
                max_y_variance: None,
                zero_variance_warning: None,
                thread_joined: None,
                panic_free: true,
                error: Some(msg),
            },
            ExitCode::from(CAPTURE_PROBE_EXIT_PERMISSION_DENIED),
        ),
        Err(e) => (
            CaptureProbeReport {
                status: "unavailable".into(),
                source: source_name,
                frames: None,
                raw_frames_captured: None,
                width: None,
                height: None,
                non_zero_variance: None,
                max_y_variance: None,
                zero_variance_warning: None,
                thread_joined: None,
                panic_free: true,
                error: Some(e.to_string()),
            },
            ExitCode::from(CAPTURE_PROBE_EXIT_UNAVAILABLE),
        ),
        Ok(mut handle) => {
            let (width, height) = handle.dimensions();
            let deadline = Instant::now().checked_add(Duration::from_millis(timeout_ms));
            let mut frames_pulled = 0usize;
            let mut max_y_variance = 0.0f64;

            if let Some(deadline) = deadline {
                while frames_pulled < target_frames {
                    let Some(rem) = deadline.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    if rem.is_zero() {
                        break;
                    }
                    if let Some(captured) = handle
                        .next_frame_for_sender(30, Duration::from_millis(33), rem)
                        .await
                    {
                        let var = compute_y_variance(&captured.frame);
                        if var > max_y_variance {
                            max_y_variance = var;
                        }
                        frames_pulled += 1;
                    } else {
                        break;
                    }
                }
            }

            let raw_frames_captured = handle.stats().frames_captured.load(Ordering::Relaxed);
            let zero_var_warn = handle.stats().zero_variance_warning.load(Ordering::Acquire);
            let last_err = handle.stats().last_error();
            let join_res = handle.stop_and_join();
            let thread_joined = join_res.is_ok();
            let panic_free = thread_joined;
            let non_zero_variance = max_y_variance > 1e-6;

            if !panic_free {
                (
                    CaptureProbeReport {
                        status: "panicked".into(),
                        source: source_name,
                        frames: Some(frames_pulled),
                        raw_frames_captured: Some(raw_frames_captured),
                        width: Some(width),
                        height: Some(height),
                        non_zero_variance: Some(non_zero_variance),
                        max_y_variance: Some(max_y_variance),
                        zero_variance_warning: Some(zero_var_warn),
                        thread_joined: Some(false),
                        panic_free: false,
                        error: Some(
                            join_res
                                .err()
                                .map(|e| e.to_string())
                                .unwrap_or_else(|| "capture thread panicked".into()),
                        ),
                    },
                    ExitCode::from(CAPTURE_PROBE_EXIT_DEGRADED_OR_PANICKED),
                )
            } else if raw_frames_captured == 0 {
                (
                    CaptureProbeReport {
                        status: "unavailable".into(),
                        source: source_name,
                        frames: Some(0),
                        raw_frames_captured: Some(0),
                        width: Some(width),
                        height: Some(height),
                        non_zero_variance: Some(false),
                        max_y_variance: Some(0.0),
                        zero_variance_warning: Some(zero_var_warn),
                        thread_joined: Some(true),
                        panic_free: true,
                        error: Some(
                            last_err
                                .map(|e| e.to_string())
                                .unwrap_or_else(|| "timed out waiting for first captured frame".into()),
                        ),
                    },
                    ExitCode::from(CAPTURE_PROBE_EXIT_UNAVAILABLE),
                )
            } else if frames_pulled < target_frames || !non_zero_variance || last_err.is_some() {
                let err_msg = if let Some(e) = last_err {
                    e.to_string()
                } else if !non_zero_variance {
                    "captured frames had zero Y-plane variance".into()
                } else {
                    format!(
                        "captured only {frames_pulled}/{target_frames} frames before timeout"
                    )
                };
                (
                    CaptureProbeReport {
                        status: "degraded".into(),
                        source: source_name,
                        frames: Some(frames_pulled),
                        raw_frames_captured: Some(raw_frames_captured),
                        width: Some(width),
                        height: Some(height),
                        non_zero_variance: Some(non_zero_variance),
                        max_y_variance: Some(max_y_variance),
                        zero_variance_warning: Some(zero_var_warn),
                        thread_joined: Some(true),
                        panic_free: true,
                        error: Some(err_msg),
                    },
                    ExitCode::from(CAPTURE_PROBE_EXIT_DEGRADED_OR_PANICKED),
                )
            } else {
                (
                    CaptureProbeReport {
                        status: "captured".into(),
                        source: source_name,
                        frames: Some(frames_pulled),
                        raw_frames_captured: Some(raw_frames_captured),
                        width: Some(width),
                        height: Some(height),
                        non_zero_variance: Some(true),
                        max_y_variance: Some(max_y_variance),
                        zero_variance_warning: Some(zero_var_warn),
                        thread_joined: Some(true),
                        panic_free: true,
                        error: None,
                    },
                    ExitCode::SUCCESS,
                )
            }
        }
    };

    if let Ok(s) = serde_json::to_string_pretty(&report) {
        println!("{s}");
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use v2_client::EdgeEndpointConfig;

    #[test]
    fn verify_ca_signed_devcert_tbs_accepts_valid_and_rejects_tampering() {
        let ca = SoftwareDeviceKeyStore::generate();
        let dev = SoftwareDeviceKeyStore::generate();
        let ca_spki = ca.public_key_spki_der().unwrap();
        let dev_spki = dev.public_key_spki_der().unwrap();
        let dev_id = [0x11; 16];
        let tenant_id = [0x22; 16];
        let now = now_unix_secs();
        let exp = now + 3600;

        let cert = DeviceCert {
            version: 1,
            cert_id: [0x33; 16],
            device_id: dev_id,
            tenant_id,
            p256_pub_der: dev_spki.clone(),
            key_epoch: 1,
            policy_hash: [0x44; 32],
            cap_bits: DEFAULT_CAP_BITS,
            iat_unix: now.saturating_sub(10),
            exp_unix: exp,
            hardware_backed: false,
            sig_der: Vec::new(),
        };
        let tbs = cert.tbs_bytes().unwrap();
        let sig = ca.sign_p256_low_s(&tbs).unwrap();
        let sha: [u8; 32] = Sha256::digest(&tbs).into();

        assert!(verify_ca_signed_devcert_tbs(
            &ca_spki, &tbs, &sig, &sha, &dev_id, &tenant_id, &dev_spki, exp, now
        )
        .is_ok());

        // Wrong device_id rejected
        assert!(verify_ca_signed_devcert_tbs(
            &ca_spki, &tbs, &sig, &sha, &[0x99; 16], &tenant_id, &dev_spki, exp, now
        )
        .is_err());

        // Wrong tenant_id rejected
        assert!(verify_ca_signed_devcert_tbs(
            &ca_spki, &tbs, &sig, &sha, &dev_id, &[0x99; 16], &dev_spki, exp, now
        )
        .is_err());

        // Wrong SPKI rejected
        let other_spki = SoftwareDeviceKeyStore::generate()
            .public_key_spki_der()
            .unwrap();
        assert!(verify_ca_signed_devcert_tbs(
            &ca_spki, &tbs, &sig, &sha, &dev_id, &tenant_id, &other_spki, exp, now
        )
        .is_err());

        // Wrong CA rejected
        assert!(verify_ca_signed_devcert_tbs(
            &other_spki, &tbs, &sig, &sha, &dev_id, &tenant_id, &dev_spki, exp, now
        )
        .is_err());
    }

    #[test]
    fn resolve_ca_der_path_requires_ca_when_tls_enabled() {
        let edge = EdgeEndpointConfig {
            pop_id: "edge-a01".into(),
            udp_addr: "127.0.0.1:1".into(),
            ctrl_addr: "127.0.0.1:2".into(),
            tls443_addr: "127.0.0.1:3".into(),
            x25519_pub_hex: "00".repeat(32),
            cert_hash_hex: None,
            bb_addr: None,
            dlq_path: None,
        };
        let cfg_tls = ClusterConfig {
            cp_addr: "127.0.0.1:443".into(),
            cp_use_tls: true,
            signaling_addr: "127.0.0.1:4".into(),
            admin_token: None,
            ca_der_path: None,
            edge_a: edge.clone(),
            edge_b: edge,
            tenant_zd_hex: None,
            tenant_zd_quota_hex: None,
            tenant_drone_hex: None,
        };
        assert!(resolve_ca_der_path(&cfg_tls, None).is_err());
        assert_eq!(
            resolve_ca_der_path(&cfg_tls, Some(Path::new("/tmp/ca.der"))).unwrap(),
            Some(PathBuf::from("/tmp/ca.der"))
        );
    }
}
