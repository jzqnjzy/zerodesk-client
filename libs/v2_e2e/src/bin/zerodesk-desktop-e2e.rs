#[path = "../phase3_cli.rs"]
mod phase3_cli;

// Standalone headless `v2_e2e` does not link `src/platform/macos.mm`, which normally provides
// `BackingScaleFactor` for `scrap::quartz::Display::scale()`.
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn BackingScaleFactor(display: u32) -> f32 {
    use std::ffi::c_void;
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGDisplayPixelsWide(display: u32) -> usize;
        fn CGDisplayCopyDisplayMode(display: u32) -> *const c_void;
        fn CGDisplayModeGetPixelWidth(mode: *const c_void) -> usize;
        fn CGDisplayModeRelease(mode: *const c_void);
    }
    unsafe {
        let mode = CGDisplayCopyDisplayMode(display);
        if mode.is_null() {
            return 1.0;
        }
        let pixel_w = CGDisplayModeGetPixelWidth(mode);
        CGDisplayModeRelease(mode);
        let point_w = CGDisplayPixelsWide(display);
        if point_w == 0 || pixel_w == 0 {
            1.0
        } else {
            (pixel_w as f32 / point_w as f32).max(1.0)
        }
    }
}

use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::mpsc;
use v2_client::{
    decode_hex_array, now_unix_secs, AccessControlTunnel, ClientError, ClusterConfig,
    ControlPlaneClient, CreateTenantReq, SignalingClient, UdpAccessLink, UdpE2eeSession,
};
use v2_e2e::{
    compute_y_psnr, compute_y_ssim, decode_hid_frame, encode_hid_frame, generate_animated_i420,
    DesktopControllerSession, DesktopHostSession, HidEchoAck, HidPayload, KeyEvent, MouseEvent,
    MouseKind, SessionError, V2VideoDecoder, V2VideoEncoder, VideoCodec, MOD_ALT, MOD_CTRL,
    MOD_META, MOD_SHIFT,
};
use v2_identity::{
    verify_p256_low_s, DeviceCert, DeviceKeyStore, SoftwareDeviceKeyStore, TenantPolicyBlob,
    X25519StaticKeyRotator,
};
use v2_transport::{
    PrologueInput, QuotaExhaustPolicy, TenantPolicyRules, TransportEvent, VerifiedTenantPolicy,
    VideoFrameMeta, CAP_ACCESS_LEG_SEQ_V11, CAP_CODEC_AV1, CAP_CODEC_VP9, CAP_SURVIVAL_MODE,
    CAP_TRANSPORT_TCP443_DUAL, CIPHER_AESGCM, L3_MTU_DEFAULT, PATTERN_IK,
    TRANSPORT_MODE_RELAY_UDP, VER_MAJOR_MINOR,
};

const WIDTH: usize = 1280;
const HEIGHT: usize = 720;
const MIN_PSNR_DB: f64 = 32.0;
const MIN_SSIM: f64 = 0.95;
const ENCODER_QUALITY: f32 = 2.0;
const KEYFRAME_INTERVAL: usize = 60;
// Per protocol-spec/spec/04-inner-channels.md §3.3, CAP_VIDEO_LTR must stay 0 until Phase 3
// implements true encoder mark_ltr/force_ref_ltr reference pinning.
const DEFAULT_CAP_BITS: u64 = CAP_CODEC_AV1
    | CAP_CODEC_VP9
    | CAP_TRANSPORT_TCP443_DUAL
    | CAP_ACCESS_LEG_SEQ_V11
    | CAP_SURVIVAL_MODE;

#[derive(Debug, Serialize)]
struct CodecSelftestMetrics {
    codec: String,
    frames: usize,
    min_psnr_db: f64,
    avg_psnr_db: f64,
    min_ssim: f64,
    avg_ssim: f64,
    avg_frame_bytes: f64,
    total_encode_ms: f64,
    total_decode_ms: f64,
    pass: bool,
}

#[derive(Debug, Serialize)]
struct CodecSelftestReport {
    pass: bool,
    width: usize,
    height: usize,
    vp9: CodecSelftestMetrics,
    av1: CodecSelftestMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct VideoStreamMetrics {
    codec: String,
    frames_target: usize,
    frames_delivered: usize,
    sha256_matches: usize,
    total_raw_bytes: u64,
    total_slices_sent: u64,
    min_psnr_db: f64,
    avg_psnr_db: f64,
    min_ssim: f64,
    avg_ssim: f64,
    elapsed_ms: f64,
    pass: bool,
}

#[derive(Debug, Serialize)]
struct HidMetrics {
    probes_per_phase: usize,
    mouse_events_per_phase: usize,
    key_events_per_phase: usize,
    unloaded_received: usize,
    unloaded_field_exact_match: bool,
    p50_unloaded_ms: f64,
    p95_unloaded_ms: f64,
    max_unloaded_ms: f64,
    loaded_received: usize,
    loaded_field_exact_match: bool,
    p50_loaded_ms: f64,
    p95_loaded_ms: f64,
    max_loaded_ms: f64,
    p95_threshold_ms: f64,
    bg_target_mbps: u32,
    bg_sent_video_bytes: u64,
    bg_recv_video_frames: u64,
    bg_achieved_mbps: f64,
    os_input_injection_count: u64,
    pass: bool,
}

#[derive(Debug, Serialize)]
struct DesktopE2eReport {
    pass: bool,
    width: usize,
    height: usize,
    edge_a_ping_rtt_ms: f64,
    edge_b_ping_rtt_ms: f64,
    signaling_tcp_rtt_ms: f64,
    g2_primary_video: VideoStreamMetrics,
    g2_secondary_video: VideoStreamMetrics,
    g3_hid: HidMetrics,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
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

fn percentile_ms(samples_us: &[u64], pct: f64) -> f64 {
    if samples_us.is_empty() {
        return 0.0;
    }
    let mut sorted = samples_us.to_vec();
    sorted.sort_unstable();
    let idx = (((sorted.len() - 1) as f64) * pct).round() as usize;
    (sorted[idx.min(sorted.len() - 1)] as f64) / 1000.0
}

fn run_codec_selftest_one(
    codec: VideoCodec,
    frames: usize,
) -> Result<CodecSelftestMetrics, String> {
    let mut encoder = V2VideoEncoder::new(
        codec,
        WIDTH as u32,
        HEIGHT as u32,
        ENCODER_QUALITY,
        Some(KEYFRAME_INTERVAL),
    )
    .map_err(|e| e.to_string())?;
    let mut decoder = V2VideoDecoder::new(codec).map_err(|e| e.to_string())?;

    let mut min_psnr = f64::MAX;
    let mut sum_psnr = 0.0f64;
    let mut min_ssim = f64::MAX;
    let mut sum_ssim = 0.0f64;
    let mut total_bytes = 0usize;
    let mut enc_dur = Duration::ZERO;
    let mut dec_dur = Duration::ZERO;

    for idx in 0..frames {
        let src = generate_animated_i420(WIDTH, HEIGHT, idx as u32);
        let t0 = Instant::now();
        let encoded = encoder
            .encode_i420(&src, (idx as i64) * 33)
            .map_err(|e| format!("{} encode frame {idx}: {e}", codec.name()))?;
        enc_dur += t0.elapsed();
        total_bytes += encoded.data.len();

        let t1 = Instant::now();
        let decoded = decoder
            .decode_raw(&encoded.data)
            .map_err(|e| format!("{} decode frame {idx}: {e}", codec.name()))?;
        dec_dur += t1.elapsed();

        let psnr = compute_y_psnr(&src, &decoded).map_err(|e| e.to_string())?;
        let ssim = compute_y_ssim(&src, &decoded).map_err(|e| e.to_string())?;
        if psnr < min_psnr {
            min_psnr = psnr;
        }
        if ssim < min_ssim {
            min_ssim = ssim;
        }
        sum_psnr += psnr;
        sum_ssim += ssim;
    }

    let count_f = frames.max(1) as f64;
    let pass = frames > 0 && min_psnr >= MIN_PSNR_DB && min_ssim >= MIN_SSIM;
    Ok(CodecSelftestMetrics {
        codec: codec.name().to_string(),
        frames,
        min_psnr_db: min_psnr,
        avg_psnr_db: sum_psnr / count_f,
        min_ssim,
        avg_ssim: sum_ssim / count_f,
        avg_frame_bytes: (total_bytes as f64) / count_f,
        total_encode_ms: enc_dur.as_secs_f64() * 1000.0,
        total_decode_ms: dec_dur.as_secs_f64() * 1000.0,
        pass,
    })
}

fn cmd_codec_selftest(vp9_frames: usize, av1_frames: usize) -> CodecSelftestReport {
    let vp9 = match run_codec_selftest_one(VideoCodec::Vp9, vp9_frames) {
        Ok(m) => m,
        Err(e) => {
            return CodecSelftestReport {
                pass: false,
                width: WIDTH,
                height: HEIGHT,
                vp9: CodecSelftestMetrics {
                    codec: "vp9".into(),
                    frames: 0,
                    min_psnr_db: 0.0,
                    avg_psnr_db: 0.0,
                    min_ssim: 0.0,
                    avg_ssim: 0.0,
                    avg_frame_bytes: 0.0,
                    total_encode_ms: 0.0,
                    total_decode_ms: 0.0,
                    pass: false,
                },
                av1: CodecSelftestMetrics {
                    codec: "av1".into(),
                    frames: 0,
                    min_psnr_db: 0.0,
                    avg_psnr_db: 0.0,
                    min_ssim: 0.0,
                    avg_ssim: 0.0,
                    avg_frame_bytes: 0.0,
                    total_encode_ms: 0.0,
                    total_decode_ms: 0.0,
                    pass: false,
                },
                error: Some(e),
            };
        }
    };
    let av1 = match run_codec_selftest_one(VideoCodec::Av1, av1_frames) {
        Ok(m) => m,
        Err(e) => {
            return CodecSelftestReport {
                pass: false,
                width: WIDTH,
                height: HEIGHT,
                vp9,
                av1: CodecSelftestMetrics {
                    codec: "av1".into(),
                    frames: 0,
                    min_psnr_db: 0.0,
                    avg_psnr_db: 0.0,
                    min_ssim: 0.0,
                    avg_ssim: 0.0,
                    avg_frame_bytes: 0.0,
                    total_encode_ms: 0.0,
                    total_decode_ms: 0.0,
                    pass: false,
                },
                error: Some(e),
            };
        }
    };
    let pass = vp9.pass && av1.pass;
    CodecSelftestReport {
        pass,
        width: WIDTH,
        height: HEIGHT,
        vp9,
        av1,
        error: if pass {
            None
        } else {
            Some("codec quality below PSNR >= 32 dB or SSIM >= 0.95 threshold".into())
        },
    }
}

struct BootstrappedSessions {
    controller: UdpE2eeSession,
    host: UdpE2eeSession,
    edge_a_ping_us: u64,
    edge_b_ping_us: u64,
    signaling_rtt_us: u64,
    // Keep Noise_IK control tunnels alive for the duration of the E2EE session.
    _ctrl_a: AccessControlTunnel,
    _ctrl_b: AccessControlTunnel,
}

async fn bootstrap_live_pair(
    cfg: &ClusterConfig,
    ca_der_override: Option<&Path>,
    bg_mbps: u32,
) -> Result<BootstrappedSessions, ClientError> {
    let ca_path: Option<PathBuf> = ca_der_override
        .map(Path::to_path_buf)
        .or_else(|| cfg.ca_der_path.as_ref().map(PathBuf::from));
    let cp = ControlPlaneClient::new(&cfg.cp_base_url(), ca_path.as_deref())?;
    cp.healthz().await?;
    let ca_pub = cp.get_ca_pubkey().await?;
    let ca_spki_der = ca_pub.spki_der()?;

    let tenant_id = if let Some(hex_tid) = &cfg.tenant_zd_hex {
        decode_hex_array::<16>(hex_tid, "tenant_zd_hex")?
    } else {
        random_bytes::<16>()
    };
    let enrollment_token = format!("v2-desktop-p2-{}", hex::encode(random_bytes::<8>()));
    let bw_cap_kbps = (bg_mbps.saturating_mul(2_500)).max(50_000);

    let admin_token = cfg.admin_token.as_deref().ok_or_else(|| {
        ClientError::Config("cluster.json missing admin_token for E2E bootstrap".into())
    })?;
    let tenant_req = CreateTenantReq {
        tenant_id_hex: hex::encode(tenant_id),
        name: Some("zerodesk-desktop-p2-e2e".into()),
        home_region: Some("local".into()),
        plan_tier: Some("pro".into()),
        monthly_quota_bytes: 20 * 1024 * 1024 * 1024,
        bw_cap_kbps,
        exhaust_policy: 0,
        allow_file_transfer: true,
        enrollment_token: enrollment_token.clone(),
        enrollment_ttl_sec: 3600,
        policy_hash_hex: None,
    };
    cp.create_tenant(admin_token, &tenant_req).await?;

    let ctrl_dev_id = random_bytes::<16>();
    let host_dev_id = random_bytes::<16>();
    let ks_ctrl = SoftwareDeviceKeyStore::generate();
    let ks_host = SoftwareDeviceKeyStore::generate();

    let reg_ctrl = cp
        .register_device(
            &ks_ctrl,
            &ctrl_dev_id,
            &enrollment_token,
            DEFAULT_CAP_BITS,
            "local",
            None,
            None,
        )
        .await?;
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
        .await?;

    let tbs_ctrl = reg_ctrl.tbs_bytes()?;
    let sig_ctrl = reg_ctrl.sig_der()?;
    verify_p256_low_s(&ca_spki_der, &tbs_ctrl, &sig_ctrl)?;

    let tbs_host = reg_host.tbs_bytes()?;
    let sig_host = reg_host.sig_der()?;
    verify_p256_low_s(&ca_spki_der, &tbs_host, &sig_host)?;

    let signaling = SignalingClient::new(&cfg.signaling_addr);
    let sig_probe = signaling.probe_tcp().await?;

    let session_id = random_bytes::<16>();
    let pop_a = cfg.edge_a.pop_id_bytes()?;
    let pop_b = cfg.edge_b.pop_id_bytes()?;
    let cid_a = random_bytes::<8>();
    let cid_b = random_bytes::<8>();

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
        .await?;
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
        .await?;

    let ticket_a = lease_a.to_relay_ticket()?;
    let ticket_b = lease_b.to_relay_ticket()?;

    let now_unix = now_unix_secs();
    let mut rot_ctrl = X25519StaticKeyRotator::new(ctrl_dev_id, false, 0);
    let mut rot_host = X25519StaticKeyRotator::new(host_dev_id, false, 0);
    let gen_ctrl = rot_ctrl.ensure_current(&ks_ctrl, now_unix, reg_ctrl.exp_unix)?;
    let gen_host = rot_host.ensure_current(&ks_host, now_unix, reg_host.exp_unix)?;
    let x25519_priv_ctrl = *gen_ctrl.secret_bytes();
    let x25519_priv_host = *gen_host.secret_bytes();
    let x25519_pub_host = gen_host.public_key;
    let deleg_ctrl = gen_ctrl.delegation.clone();
    let deleg_host = gen_host.delegation.clone();

    let edge_a_pub = cfg.edge_a.x25519_pub()?;
    let edge_b_pub = cfg.edge_b.x25519_pub()?;
    let edge_a_hash = cfg.edge_a.edge_cert_hash()?;
    let edge_b_hash = cfg.edge_b.edge_cert_hash()?;

    let mut ctrl_a = AccessControlTunnel::connect(
        &cfg.edge_a.ctrl_addr,
        &x25519_priv_ctrl,
        &edge_a_pub,
        &pop_a,
        &edge_a_hash,
        Duration::from_secs(5),
    )
    .await?;
    let mut ctrl_b = AccessControlTunnel::connect(
        &cfg.edge_b.ctrl_addr,
        &x25519_priv_host,
        &edge_b_pub,
        &pop_b,
        &edge_b_hash,
        Duration::from_secs(5),
    )
    .await?;

    let (bind_a, keys_a) = ctrl_a.relay_bind(&ticket_a, &cid_b, &pop_b).await?;
    let (bind_b, keys_b) = ctrl_b.relay_bind(&ticket_b, &cid_a, &pop_a).await?;
    if bind_a.route_cid != cid_a || bind_b.route_cid != cid_b {
        return Err(ClientError::Protocol("Edge RelayBindResp route_cid mismatch".into()));
    }

    let mut udp_a = UdpAccessLink::connect(&cfg.edge_a.udp_addr, &keys_a, lease_a.bw_cap_kbps).await?;
    let mut udp_b = UdpAccessLink::connect(&cfg.edge_b.udp_addr, &keys_b, lease_b.bw_cap_kbps).await?;

    let edge_a_ping_us = udp_a.ping_with_retry(3, Duration::from_secs(1)).await?;
    let edge_b_ping_us = udp_b.ping_with_retry(3, Duration::from_secs(1)).await?;

    let policy_ca = SoftwareDeviceKeyStore::generate();
    let policy_ca_spki = policy_ca.public_key_spki_der()?;
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
        device_id: ctrl_dev_id,
        tenant_id,
        p256_pub_der: ks_ctrl.public_key_spki_der()?,
        key_epoch: reg_ctrl.key_epoch,
        policy_hash: rules.canonical_hash(),
        cap_bits: DEFAULT_CAP_BITS,
        iat_unix: now_unix.saturating_sub(10),
        exp_unix: now_unix.saturating_add(3600),
        hardware_backed: false,
        sig_der: Vec::new(),
    };
    policy_cert.sig_der = policy_ca.sign_p256_low_s(&policy_cert.tbs_bytes()?)?;
    let mut policy_blob = TenantPolicyBlob {
        tenant_id,
        version: 1,
        policy_hash: rules.canonical_hash(),
        iat_unix: now_unix.saturating_sub(10),
        exp_unix: now_unix.saturating_add(3600),
        sig_der: Vec::new(),
    };
    policy_blob.sig_der = policy_ca.sign_p256_low_s(&policy_blob.tbs_bytes())?;
    let policy = VerifiedTenantPolicy::from_verified_blob(
        &policy_blob,
        &policy_cert,
        &rules,
        &policy_ca_spki,
        now_unix,
    )?;

    let prologue_input = PrologueInput {
        ver_major_minor: VER_MAJOR_MINOR,
        handshake_pattern: PATTERN_IK,
        cipher_suite: CIPHER_AESGCM,
        transport_mode: TRANSPORT_MODE_RELAY_UDP,
        device_id_ctrl: ctrl_dev_id,
        device_id_host: host_dev_id,
        ctrl_devcert_tbs_sha256: Sha256::digest(&tbs_ctrl).into(),
        host_devcert_tbs_sha256: Sha256::digest(&tbs_host).into(),
        policy_hash: policy.policy_hash,
        edge_cert_tbs_sha256_or_zero: edge_a_hash,
        negotiated_cap_bits: DEFAULT_CAP_BITS,
        session_id,
    };

    let pub_spki_ctrl = ks_ctrl.public_key_spki_der()?;
    let pub_spki_host = ks_host.public_key_spki_der()?;

    let hs_ctrl = UdpE2eeSession::handshake_initiator(
        udp_a,
        &prologue_input,
        &x25519_priv_ctrl,
        &x25519_pub_host,
        &deleg_host,
        &host_dev_id,
        &pub_spki_host,
        reg_host.exp_unix,
        now_unix,
        policy.clone(),
        ctrl_dev_id,
        L3_MTU_DEFAULT,
        Duration::from_secs(5),
    );
    let hs_host = UdpE2eeSession::handshake_responder(
        udp_b,
        &prologue_input,
        &x25519_priv_host,
        &deleg_ctrl,
        &ctrl_dev_id,
        &pub_spki_ctrl,
        reg_ctrl.exp_unix,
        now_unix,
        policy,
        host_dev_id,
        L3_MTU_DEFAULT,
        Duration::from_secs(5),
    );
    let ((controller, _), (host, _)) = tokio::try_join!(hs_ctrl, hs_host)?;

    Ok(BootstrappedSessions {
        controller,
        host,
        edge_a_ping_us,
        edge_b_ping_us,
        signaling_rtt_us: sig_probe.connect_rtt_us,
        _ctrl_a: ctrl_a,
        _ctrl_b: ctrl_b,
    })
}

async fn run_live_video_stream(
    host: &mut DesktopHostSession,
    controller: &mut DesktopControllerSession,
    codec: VideoCodec,
    frames: usize,
) -> Result<VideoStreamMetrics, SessionError> {
    host.replace_encoder(V2VideoEncoder::new(
        codec,
        WIDTH as u32,
        HEIGHT as u32,
        ENCODER_QUALITY,
        Some(KEYFRAME_INTERVAL),
    )?);
    controller.replace_decoder(V2VideoDecoder::new(codec)?);

    let (meta_tx, mut meta_rx) = mpsc::unbounded_channel::<(usize, u32, [u8; 32], usize, usize)>();
    let started = Instant::now();

    let send_task = async {
        let mut total_raw_bytes = 0u64;
        let mut total_slices = 0u64;
        for idx in 0..frames {
            let src = Arc::new(generate_animated_i420(WIDTH, HEIGHT, idx as u32));
            let info = host.publish_i420_frame(src, (idx as i64) * 33).await?;
            total_raw_bytes = total_raw_bytes.saturating_add(info.raw_bytes as u64);
            total_slices = total_slices.saturating_add(info.slices_sent as u64);
            meta_tx
                .send((
                    idx,
                    info.meta.frame_id,
                    info.sha256,
                    info.raw_bytes,
                    info.slices_sent,
                ))
                .map_err(|_| SessionError::Protocol("verification metadata channel closed".into()))?;
            // Gentle pacing keeps loopback UDP buffers well within headroom while staying real-time.
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        Ok::<(u64, u64), SessionError>((total_raw_bytes, total_slices))
    };

    let recv_task = async {
        let mut delivered = 0usize;
        let mut sha_matches = 0usize;
        let mut min_psnr = f64::MAX;
        let mut sum_psnr = 0.0f64;
        let mut min_ssim = f64::MAX;
        let mut sum_ssim = 0.0f64;

        for expected_idx in 0..frames {
            let delivery = controller
                .recv_and_decode_video(Duration::from_secs(10))
                .await?;
            let (idx, expected_frame_id, expected_sha, expected_len, _) = meta_rx
                .recv()
                .await
                .ok_or_else(|| SessionError::Protocol("missing expected frame metadata".into()))?;
            if idx != expected_idx || delivery.frame.frame_id != expected_frame_id {
                return Err(SessionError::Protocol(format!(
                    "frame ordering mismatch: expected idx {expected_idx} (frame_id {expected_frame_id}), got frame_id {}",
                    delivery.frame.frame_id
                )));
            }
            if delivery.frame.data.len() == expected_len && delivery.sha256 == expected_sha {
                sha_matches += 1;
            }
            let reference = generate_animated_i420(WIDTH, HEIGHT, idx as u32);
            let psnr = compute_y_psnr(&reference, &delivery.i420)?;
            let ssim = compute_y_ssim(&reference, &delivery.i420)?;
            if psnr < min_psnr {
                min_psnr = psnr;
            }
            if ssim < min_ssim {
                min_ssim = ssim;
            }
            sum_psnr += psnr;
            sum_ssim += ssim;
            delivered += 1;
        }
        Ok::<(usize, usize, f64, f64, f64, f64), SessionError>((
            delivered,
            sha_matches,
            min_psnr,
            sum_psnr,
            min_ssim,
            sum_ssim,
        ))
    };

    let ((total_raw_bytes, total_slices_sent), (delivered, sha_matches, min_psnr, sum_psnr, min_ssim, sum_ssim)) =
        tokio::try_join!(send_task, recv_task)?;
    let elapsed_ms = started.elapsed().as_secs_f64() * 1000.0;
    let denom = delivered.max(1) as f64;
    let pass = delivered == frames
        && sha_matches == frames
        && min_psnr >= MIN_PSNR_DB
        && min_ssim >= MIN_SSIM;

    Ok(VideoStreamMetrics {
        codec: codec.name().to_string(),
        frames_target: frames,
        frames_delivered: delivered,
        sha256_matches: sha_matches,
        total_raw_bytes,
        total_slices_sent,
        min_psnr_db: min_psnr,
        avg_psnr_db: sum_psnr / denom,
        min_ssim,
        avg_ssim: sum_ssim / denom,
        elapsed_ms,
        pass,
    })
}

fn build_hid_test_sequence(base_ts_ms: u64) -> Vec<HidPayload> {
    let mut seq = Vec::with_capacity(40);
    // 20 MouseEvents covering MoveAbs, MoveRel, Down, Up, Wheel press/release pairs.
    for i in 0..20u32 {
        let kind = match i % 5 {
            0 => MouseKind::MoveAbs,
            1 => MouseKind::MoveRel,
            2 => MouseKind::Down,
            3 => MouseKind::Up,
            _ => MouseKind::Wheel,
        };
        let buttons = match kind {
            MouseKind::Down => 0x01,
            MouseKind::Up => 0x00,
            _ => (i as u8) & 0x07,
        };
        let (x_or_dx, y_or_dy, wheel_dx, wheel_dy) = match kind {
            MouseKind::MoveAbs => (100 + (i as i32) * 37, 80 + (i as i32) * 23, 0, 0),
            MouseKind::MoveRel => ((i as i32) * 3 - 15, 12 - (i as i32) * 2, 0, 0),
            MouseKind::Down | MouseKind::Up => (640 + (i as i32) * 5, 360 - (i as i32) * 4, 0, 0),
            MouseKind::Wheel => (640, 360, -1, 3),
        };
        seq.push(HidPayload::Mouse(MouseEvent {
            kind,
            buttons,
            x_or_dx,
            y_or_dy,
            wheel_dx,
            wheel_dy,
            client_ts_ms: base_ts_ms + u64::from(i),
        }));
    }
    // 20 KeyEvents = 10 press/release pairs with varied modifiers, USB HID usages, and Unicode scalars.
    let keys: &[(u32, char, u8)] = &[
        (0x04, 'a', 0),
        (0x05, 'B', MOD_SHIFT),
        (0x06, 'c', MOD_CTRL),
        (0x16, 's', MOD_CTRL | MOD_SHIFT),
        (0x09, 'f', MOD_ALT),
        (0x17, 't', MOD_META),
        (0x1E, '1', 0),
        (0x28, '\n', 0),
        (0x2C, ' ', 0),
        (0x1D, 'Z', MOD_SHIFT | MOD_ALT),
    ];
    for (pair_idx, &(usage, ch, mods)) in keys.iter().enumerate() {
        let ts = base_ts_ms + 100 + (pair_idx as u64) * 2;
        seq.push(HidPayload::Key(KeyEvent {
            down: true,
            modifiers: mods,
            usb_hid_usage: usage,
            unicode_scalar: ch as u32,
            client_ts_ms: ts,
        }));
        seq.push(HidPayload::Key(KeyEvent {
            down: false,
            modifiers: mods,
            usb_hid_usage: usage,
            unicode_scalar: ch as u32,
            client_ts_ms: ts + 1,
        }));
    }
    seq
}

async fn run_g3_hid_and_preemption(
    host: &mut DesktopHostSession,
    controller: &mut DesktopControllerSession,
    bg_mbps: u32,
) -> Result<HidMetrics, SessionError> {
    let probes = build_hid_test_sequence(now_ms());
    let probe_count = probes.len();
    let mouse_count = probes
        .iter()
        .filter(|p| matches!(p, HidPayload::Mouse(_)))
        .count();
    let key_count = probes
        .iter()
        .filter(|p| matches!(p, HidPayload::Key(_)))
        .count();

    // Phase 1: Unloaded P0 HID baseline (20 Mouse + 20 Key press/release pairs).
    let unloaded_host = async {
        let mut received = Vec::with_capacity(probe_count);
        for seq in 0..probe_count {
            let payload = host
                .recv_hid_and_echo(seq as u32, Duration::from_secs(3))
                .await?;
            received.push(payload);
        }
        Ok::<Vec<HidPayload>, SessionError>(received)
    };
    let unloaded_ctrl = async {
        let mut rtts_us = Vec::with_capacity(probe_count);
        for (seq, payload) in probes.iter().enumerate() {
            let (ack, rtt_us, _) = controller
                .send_hid_and_await_echo(payload, seq as u32, Duration::from_secs(3))
                .await?;
            if ack.client_ts_ms != payload.client_ts_ms() {
                return Err(SessionError::Protocol(format!(
                    "unloaded HidEchoAck timestamp mismatch at seq {seq}"
                )));
            }
            rtts_us.push(rtt_us);
        }
        Ok::<Vec<u64>, SessionError>(rtts_us)
    };
    let (unloaded_rx, unloaded_rtts) = tokio::try_join!(unloaded_host, unloaded_ctrl)?;
    let unloaded_field_exact_match = unloaded_rx == probes;
    let p50_unloaded_ms = percentile_ms(&unloaded_rtts, 0.50);
    let p95_unloaded_ms = percentile_ms(&unloaded_rtts, 0.95);
    let max_unloaded_ms = percentile_ms(&unloaded_rtts, 1.0);

    // Phase 2: Loaded P0 preemption under paced P2 video saturation (`bg_mbps`, default 20 Mbps).
    // Pre-encode a real ~5 KB VP9 bitstream burst so pacing stays accurate without encoder stalls.
    let mut bg_enc = V2VideoEncoder::new(VideoCodec::Vp9, WIDTH as u32, HEIGHT as u32, 2.0, Some(60))?;
    let bg_frame = bg_enc.encode_i420(&generate_animated_i420(WIDTH, HEIGHT, 7), 0)?;
    let mut bg_payload = bg_frame.data;
    if bg_payload.len() < 5_000 {
        bg_payload.resize(5_000, 0x5A);
    } else if bg_payload.len() > 6_000 {
        bg_payload.truncate(5_500);
    }
    let burst_bytes = bg_payload.len();
    let target_mbps = bg_mbps.max(1);
    let burst_interval_us = ((burst_bytes as u64) * 8) / u64::from(target_mbps);
    let burst_interval = Duration::from_micros(burst_interval_us.max(500));

    let done_flag = Arc::new(AtomicBool::new(false));
    let done_host = Arc::clone(&done_flag);
    let load_started = Instant::now();

    let loaded_host = async {
        let mut received = Vec::with_capacity(probe_count);
        let mut next_echo_seq = 1000u32;
        let mut bg_frame_id = 10_000u32;
        let mut bg_bytes_sent = 0u64;
        let mut next_burst_at = Instant::now();
        let hard_deadline = Instant::now() + Duration::from_secs(15);

        while !done_host.load(Ordering::Acquire) || received.len() < probe_count {
            if Instant::now() >= hard_deadline {
                return Err(ClientError::Timeout("loaded host loop timed out".into()).into());
            }
            let now = Instant::now();
            if now >= next_burst_at {
                let meta = VideoFrameMeta {
                    display_idx: 0,
                    codec_id: VideoCodec::Vp9.codec_id(),
                    frame_id: bg_frame_id,
                    ref_frame_id: bg_frame_id,
                    ltr_slot: 0,
                    is_idr: false,
                    is_ref: false,
                    max_age_ms: 200,
                };
                bg_frame_id = bg_frame_id.wrapping_add(1);
                host.publish_raw_video(&meta, &bg_payload).await?;
                bg_bytes_sent = bg_bytes_sent.saturating_add(burst_bytes as u64);
                next_burst_at += burst_interval;
                if next_burst_at + Duration::from_millis(20) < now {
                    next_burst_at = now + burst_interval;
                }
            }

            let wait = next_burst_at
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(2));
            if !wait.is_zero() {
                match host.session_mut().recv_event(wait).await {
                    Ok(TransportEvent::Hid(frame)) => {
                        let payload = decode_hid_frame(&frame)?;
                        host.hid_frames_received = host.hid_frames_received.saturating_add(1);
                        let ack = HidPayload::EchoAck(HidEchoAck {
                            echo_seq: next_echo_seq,
                            client_ts_ms: payload.client_ts_ms(),
                        });
                        next_echo_seq = next_echo_seq.wrapping_add(1);
                        let ack_frame = encode_hid_frame(&ack)?;
                        host.session_mut().send_hid(&ack_frame).await?;
                        received.push(payload);
                    }
                    Ok(_) => {}
                    Err(ClientError::Timeout(_)) => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }
        Ok::<(Vec<HidPayload>, u64), SessionError>((received, bg_bytes_sent))
    };

    let loaded_ctrl = async {
        // Warm up P2 traffic for 120ms while actively draining incoming P2 frames.
        let mut bg_recv_frames = 0u64;
        let warmup_end = Instant::now() + Duration::from_millis(120);
        while Instant::now() < warmup_end {
            let rem = warmup_end.saturating_duration_since(Instant::now());
            match controller.session_mut().recv_event(rem).await {
                Ok(TransportEvent::VideoFrame(_)) => bg_recv_frames += 1,
                Ok(_) => {}
                Err(ClientError::Timeout(_)) => break,
                Err(e) => return Err(SessionError::from(e)),
            }
        }

        let mut rtts_us = Vec::with_capacity(probe_count);
        for (idx, payload) in probes.iter().enumerate() {
            let expected_echo_seq = 1000u32 + (idx as u32);
            let (ack, rtt_us, interleaved) = controller
                .send_hid_and_await_echo(payload, expected_echo_seq, Duration::from_secs(3))
                .await?;
            bg_recv_frames = bg_recv_frames.saturating_add(interleaved);
            if ack.client_ts_ms != payload.client_ts_ms() {
                return Err(SessionError::Protocol(format!(
                    "loaded HidEchoAck timestamp mismatch at seq {expected_echo_seq}"
                )));
            }
            rtts_us.push(rtt_us);

            // Drain incoming P2 video for 15ms between probes so kernel UDP buffers stay clear.
            let pace_end = Instant::now() + Duration::from_millis(15);
            while Instant::now() < pace_end {
                let rem = pace_end.saturating_duration_since(Instant::now());
                match controller.session_mut().recv_event(rem).await {
                    Ok(TransportEvent::VideoFrame(_)) => bg_recv_frames += 1,
                    Ok(_) => {}
                    Err(ClientError::Timeout(_)) => break,
                    Err(e) => return Err(SessionError::from(e)),
                }
            }
        }
        done_flag.store(true, Ordering::Release);
        Ok::<(Vec<u64>, u64), SessionError>((rtts_us, bg_recv_frames))
    };

    let ((loaded_rx, bg_sent_video_bytes), (loaded_rtts, bg_recv_video_frames)) =
        tokio::try_join!(loaded_host, loaded_ctrl)?;
    let load_elapsed_secs = load_started.elapsed().as_secs_f64().max(0.001);
    let bg_achieved_mbps = ((bg_sent_video_bytes as f64) * 8.0) / (load_elapsed_secs * 1_000_000.0);

    let loaded_field_exact_match = loaded_rx == probes;
    let p50_loaded_ms = percentile_ms(&loaded_rtts, 0.50);
    let p95_loaded_ms = percentile_ms(&loaded_rtts, 0.95);
    let max_loaded_ms = percentile_ms(&loaded_rtts, 1.0);
    let p95_threshold_ms = 50.0f64.max(3.0 * p50_unloaded_ms);

    let pass = unloaded_rx.len() == probe_count
        && unloaded_field_exact_match
        && loaded_rx.len() == probe_count
        && loaded_field_exact_match
        && bg_sent_video_bytes > 0
        && bg_recv_video_frames > 0
        && p95_loaded_ms <= p95_threshold_ms;

    Ok(HidMetrics {
        probes_per_phase: probe_count,
        mouse_events_per_phase: mouse_count,
        key_events_per_phase: key_count,
        unloaded_received: unloaded_rx.len(),
        unloaded_field_exact_match,
        p50_unloaded_ms,
        p95_unloaded_ms,
        max_unloaded_ms,
        loaded_received: loaded_rx.len(),
        loaded_field_exact_match,
        p50_loaded_ms,
        p95_loaded_ms,
        max_loaded_ms,
        p95_threshold_ms,
        bg_target_mbps: target_mbps,
        bg_sent_video_bytes,
        bg_recv_video_frames,
        bg_achieved_mbps,
        os_input_injection_count: 0,
        pass,
    })
}

async fn cmd_e2e(
    cfg_path: &Path,
    ca_der_override: Option<&Path>,
    frames: usize,
    primary_codec: VideoCodec,
    bg_mbps: u32,
    secondary_burst: usize,
) -> Result<DesktopE2eReport, SessionError> {
    let cfg = ClusterConfig::from_file(cfg_path)?;
    let pair = bootstrap_live_pair(&cfg, ca_der_override, bg_mbps).await?;
    let secondary_codec = match primary_codec {
        VideoCodec::Vp9 => VideoCodec::Av1,
        VideoCodec::Av1 => VideoCodec::Vp9,
    };

    let init_enc = V2VideoEncoder::new(
        primary_codec,
        WIDTH as u32,
        HEIGHT as u32,
        ENCODER_QUALITY,
        Some(KEYFRAME_INTERVAL),
    )?;
    let init_dec = V2VideoDecoder::new(primary_codec)?;
    let mut host = DesktopHostSession::new(pair.host, init_enc);
    let mut controller = DesktopControllerSession::new(pair.controller, init_dec);

    let g2_primary_video =
        run_live_video_stream(&mut host, &mut controller, primary_codec, frames).await?;
    let g2_secondary_video =
        run_live_video_stream(&mut host, &mut controller, secondary_codec, secondary_burst).await?;
    let g3_hid = run_g3_hid_and_preemption(&mut host, &mut controller, bg_mbps).await?;

    let pass = g2_primary_video.pass && g2_secondary_video.pass && g3_hid.pass;
    Ok(DesktopE2eReport {
        pass,
        width: WIDTH,
        height: HEIGHT,
        edge_a_ping_rtt_ms: (pair.edge_a_ping_us as f64) / 1000.0,
        edge_b_ping_rtt_ms: (pair.edge_b_ping_us as f64) / 1000.0,
        signaling_tcp_rtt_ms: (pair.signaling_rtt_us as f64) / 1000.0,
        g2_primary_video,
        g2_secondary_video,
        g3_hid,
        error: if pass {
            None
        } else {
            Some("one or more G2/G3 verification gates failed".into())
        },
    })
}

fn print_usage() {
    eprintln!(
        "Usage:\n  zerodesk-desktop-e2e codec-selftest [--frames 30] [--av1-frames 10]\n  zerodesk-desktop-e2e e2e --config <cluster.json> [--ca-der <ca.der>] [--frames 300] [--codec vp9|av1] [--bg-mbps 20] [--av1-burst 10]\n  zerodesk-desktop-e2e host --config <cluster.json> [--ca-der <ca.der>] --rendezvous <path> --audit-out <jsonl> [--source synthetic|screen] [--codec vp9|av1] [--fps 30] [--watchdog-ms 800] [--idle-exit-ms 2500] [--allow-idle-exit] [--audit-key-identity] [--enable-os-input]\n  zerodesk-desktop-e2e controller --config <cluster.json> [--ca-der <ca.der>] --rendezvous <path> --audit-out <jsonl> [--frames 60] [--codec vp9|av1] [--leave-stuck] [--hold-after-stuck-ms 0] [--no-visual-marker] [--audit-key-identity]\n  zerodesk-desktop-e2e dual-e2e --config <cluster.json> [--ca-der <ca.der>] [--codec vp9|av1] [--frames 60]\n  zerodesk-desktop-e2e capture-probe --source screen|synthetic [--frames 30] [--timeout-ms 5000]"
    );
}

fn parse_flag_value(args: &[String], idx: &mut usize, flag: &str) -> Result<String, String> {
    *idx += 1;
    args.get(*idx)
        .cloned()
        .ok_or_else(|| format!("missing value for {flag}"))
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(2);
    }

    match args[1].as_str() {
        "codec-selftest" => {
            let mut vp9_frames = 30usize;
            let mut av1_frames = 10usize;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--frames" => match parse_flag_value(&args, &mut i, "--frames")
                        .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                    {
                        Ok(n) => vp9_frames = n,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    },
                    "--av1-frames" => match parse_flag_value(&args, &mut i, "--av1-frames")
                        .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                    {
                        Ok(n) => av1_frames = n,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    },
                    other => {
                        eprintln!("unknown argument '{other}'");
                        print_usage();
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            let report = cmd_codec_selftest(vp9_frames, av1_frames);
            if let Ok(json) = serde_json::to_string_pretty(&report) {
                println!("{json}");
            }
            if report.pass {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
        "e2e" => {
            let mut config: Option<PathBuf> = None;
            let mut ca_der: Option<PathBuf> = None;
            let mut frames = 300usize;
            let mut codec = VideoCodec::Vp9;
            let mut bg_mbps = 20u32;
            let mut secondary_burst = 10usize;
            let mut i = 2;
            while i < args.len() {
                match args[i].as_str() {
                    "--config" => match parse_flag_value(&args, &mut i, "--config") {
                        Ok(v) => config = Some(PathBuf::from(v)),
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    },
                    "--ca-der" => match parse_flag_value(&args, &mut i, "--ca-der") {
                        Ok(v) => ca_der = Some(PathBuf::from(v)),
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    },
                    "--frames" => match parse_flag_value(&args, &mut i, "--frames")
                        .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                    {
                        Ok(n) => frames = n,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    },
                    "--codec" => match parse_flag_value(&args, &mut i, "--codec")
                        .and_then(|v| VideoCodec::parse_name(&v).map_err(|e| e.to_string()))
                    {
                        Ok(c) => codec = c,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    },
                    "--bg-mbps" => match parse_flag_value(&args, &mut i, "--bg-mbps")
                        .and_then(|v| v.parse::<u32>().map_err(|e| e.to_string()))
                    {
                        Ok(n) => bg_mbps = n,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    },
                    "--av1-burst" => match parse_flag_value(&args, &mut i, "--av1-burst")
                        .and_then(|v| v.parse::<usize>().map_err(|e| e.to_string()))
                    {
                        Ok(n) => secondary_burst = n,
                        Err(e) => {
                            eprintln!("{e}");
                            return ExitCode::from(2);
                        }
                    },
                    other => {
                        eprintln!("unknown argument '{other}'");
                        print_usage();
                        return ExitCode::from(2);
                    }
                }
                i += 1;
            }
            let Some(cfg_path) = config else {
                eprintln!("--config <cluster.json> is required");
                print_usage();
                return ExitCode::from(2);
            };
            match cmd_e2e(
                &cfg_path,
                ca_der.as_deref(),
                frames,
                codec,
                bg_mbps,
                secondary_burst,
            )
            .await
            {
                Ok(report) => {
                    if let Ok(json) = serde_json::to_string_pretty(&report) {
                        println!("{json}");
                    }
                    if report.pass {
                        ExitCode::SUCCESS
                    } else {
                        ExitCode::FAILURE
                    }
                }
                Err(e) => {
                    let err_json = serde_json::json!({
                        "pass": false,
                        "error": e.to_string(),
                    });
                    if let Ok(s) = serde_json::to_string_pretty(&err_json) {
                        println!("{s}");
                    }
                    ExitCode::FAILURE
                }
            }
        }
        "host" => phase3_cli::cmd_host(&args).await,
        "controller" => phase3_cli::cmd_controller(&args).await,
        "dual-e2e" => phase3_cli::cmd_dual_e2e(&args).await,
        "capture-probe" => phase3_cli::cmd_capture_probe(&args).await,
        other => {
            eprintln!("unknown subcommand '{other}'");
            print_usage();
            ExitCode::from(2)
        }
    }
}
