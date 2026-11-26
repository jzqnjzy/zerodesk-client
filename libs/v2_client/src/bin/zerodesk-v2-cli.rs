use bytes::Bytes;
use rand_core::{OsRng, RngCore};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use v2_client::{
    decode_hex_array, decode_survival_rs64_shards, encode_signaling_frame,
    encode_survival_rs64_shards, now_unix_secs, AccessControlTunnel, AccessKeys, ClientError,
    ClusterConfig, ControlPlaneClient, CreateTenantReq, DualTls443Client, HeartbeatMsg,
    PresenceState, SignalingClient, SignalingConnectAccept, SignalingConnectReq, SignalingMsgKind,
    UdpAccessLink, UdpE2eeSession, V2LoopbackBridge, V2SessionMux, DEFAULT_BRIDGE_CHANNEL,
};
use v2_identity::{
    verify_p256_low_s, DeviceCert, DeviceKeyStore, SoftwareDeviceKeyStore, TenantPolicyBlob,
    X25519StaticKeyRotator,
};
use v2_transport::{
    ClipboardFrame, EdgeCtrlFrame, HidFrame, PrologueInput, QuotaExhaustPolicy, TenantPolicyRules,
    TransportEvent, VerifiedTenantPolicy, VideoFrameMeta, CAP_ACCESS_LEG_SEQ_V11, CAP_CODEC_AV1,
    CAP_CODEC_H264, CAP_SURVIVAL_MODE, CAP_TRANSPORT_TCP443_DUAL, CAP_VIDEO_LTR, CIPHER_AESGCM,
    PATTERN_IK, TRANSPORT_MODE_RELAY_UDP, VER_MAJOR_MINOR,
};

const DEFAULT_CAP_BITS: u64 = CAP_CODEC_AV1
    | CAP_CODEC_H264
    | CAP_TRANSPORT_TCP443_DUAL
    | CAP_VIDEO_LTR
    | CAP_ACCESS_LEG_SEQ_V11
    | CAP_SURVIVAL_MODE;

const VIDEO_FRAME_BYTES: usize = 48 * 1024;
const VIDEO_SLICE_L3_MTU: usize = 1082; // 1082 - (16+16+8+18) = 1024B/slice => exact 48 slices

#[derive(Debug, Serialize)]
struct ProbeReport {
    pass: bool,
    count: usize,
    received: usize,
    loss_pct: f64,
    edge_a_ping_rtt_ms: f64,
    edge_b_ping_rtt_ms: f64,
    p0_rtt_min_ms: f64,
    p0_rtt_p50_ms: f64,
    p0_rtt_p95_ms: f64,
    p0_rtt_max_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Debug, Serialize)]
struct E2eReport {
    pass: bool,
    enrollment_ok: bool,
    signaling_tcp_rtt_ms: f64,
    edge_a_bind_ok: bool,
    edge_b_bind_ok: bool,
    edge_a_ping_rtt_ms: f64,
    edge_b_ping_rtt_ms: f64,
    e2ee_handshake_ok: bool,
    video_frame_bytes: usize,
    video_slices_sent: usize,
    video_sha256_match: bool,
    p0_hid_count: usize,
    p0_hid_received: usize,
    p0_hid_rtt_p50_ms: f64,
    p0_hid_rtt_p95_ms: f64,
    clipboard_ok: bool,
    rs64_dropped_shards: usize,
    rs64_recovered_ok: bool,
    leg_nack_rtx_verified: bool,
    tls443_realtime_ping_rtt_ms: f64,
    tls443_bulk_ping_rtt_ms: f64,
    tls443_passthrough_ok: bool,
    lease_renew_ok: bool,
    lease_renew_route_cid_preserved: bool,
    lease_renew_seq: u64,
    fallback_metering_ok: bool,
    loopback_bridge_bytes: usize,
    loopback_bridge_sha256_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn random_bytes<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    OsRng.fill_bytes(&mut b);
    b
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

struct BootstrappedPair {
    cp: ControlPlaneClient,
    tenant_id: [u8; 16],
    session_id: [u8; 16],
    dev_a_id: [u8; 16],
    dev_b_id: [u8; 16],
    ks_a: SoftwareDeviceKeyStore,
    #[allow(dead_code)]
    ks_b: SoftwareDeviceKeyStore,
    cid_a: [u8; 8],
    pop_a: [u8; 8],
    lease_a_seq: u64,
    lease_a_start: u64,
    ctrl_a: AccessControlTunnel,
    #[allow(dead_code)]
    ctrl_b: AccessControlTunnel,
    keys_a: AccessKeys,
    keys_b: AccessKeys,
    edge_a_ping_us: u64,
    edge_b_ping_us: u64,
    signaling_rtt_us: u64,
    sess_a: UdpE2eeSession,
    sess_b: UdpE2eeSession,
}

async fn bootstrap_pair(
    cfg: &ClusterConfig,
    ca_der_override: Option<&Path>,
    l3_mtu: usize,
) -> Result<BootstrappedPair, ClientError> {
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
    let enrollment_token = format!("v2-client-enroll-{}", hex::encode(random_bytes::<8>()));

    if let Some(admin_token) = &cfg.admin_token {
        let tenant_req = CreateTenantReq {
            tenant_id_hex: hex::encode(tenant_id),
            name: Some("zerodesk-v2-client-e2e".into()),
            home_region: Some("local".into()),
            plan_tier: Some("pro".into()),
            monthly_quota_bytes: 10 * 1024 * 1024 * 1024,
            bw_cap_kbps: 20_000,
            exhaust_policy: 0,
            allow_file_transfer: true,
            enrollment_token: enrollment_token.clone(),
            enrollment_ttl_sec: 3600,
            policy_hash_hex: None,
        };
        cp.create_tenant(admin_token, &tenant_req).await?;
    } else {
        return Err(ClientError::Config(
            "cluster.json missing admin_token for E2E tenant/enrollment setup".into(),
        ));
    }

    let dev_a_id = random_bytes::<16>();
    let dev_b_id = random_bytes::<16>();
    let ks_a = SoftwareDeviceKeyStore::generate();
    let ks_b = SoftwareDeviceKeyStore::generate();

    let reg_a = cp
        .register_device(
            &ks_a,
            &dev_a_id,
            &enrollment_token,
            DEFAULT_CAP_BITS,
            "local",
            None,
            None,
        )
        .await?;
    let reg_b = cp
        .register_device(
            &ks_b,
            &dev_b_id,
            &enrollment_token,
            DEFAULT_CAP_BITS,
            "local",
            None,
            None,
        )
        .await?;

    let tbs_a = reg_a.tbs_bytes()?;
    let sig_a = reg_a.sig_der()?;
    verify_p256_low_s(&ca_spki_der, &tbs_a, &sig_a)?;

    let tbs_b = reg_b.tbs_bytes()?;
    let sig_b = reg_b.sig_der()?;
    verify_p256_low_s(&ca_spki_der, &tbs_b, &sig_b)?;

    let signaling = SignalingClient::new(&cfg.signaling_addr);
    let sig_probe = signaling.probe_tcp().await?;

    // Exercise protocol-spec signaling protobuf3 frame serialization/deserialization.
    let session_id = random_bytes::<16>();
    let pop_a = cfg.edge_a.pop_id_bytes()?;
    let pop_b = cfg.edge_b.pop_id_bytes()?;
    let hb = HeartbeatMsg {
        device_id: dev_a_id,
        presence: PresenceState::Online,
        client_unix: now_unix_secs(),
        active_pop_id: Some(pop_a),
        rtt_ms: 1,
    };
    let hb_frame = encode_signaling_frame(SignalingMsgKind::Heartbeat, &hb.encode_pb())?;
    let _ = v2_client::decode_signaling_frame(&hb_frame)?;
    let conn_req = SignalingConnectReq {
        session_id,
        controller_device_id: dev_a_id,
        controlled_device_id: dev_b_id,
        proposed_l3_mtu: l3_mtu as u32,
        cap_bits: DEFAULT_CAP_BITS,
        preferred_cipher_suite: CIPHER_AESGCM as u32,
        requested_exhaust_policy: 0,
    };
    let conn_req_dec = SignalingConnectReq::decode_pb(&conn_req.encode_pb())?;
    if conn_req_dec.session_id != session_id {
        return Err(ClientError::Protocol("signaling ConnectReq roundtrip mismatch".into()));
    }
    let conn_acc = SignalingConnectAccept {
        session_id,
        error_code: 0,
        negotiated_l3_mtu: l3_mtu as u32,
        negotiated_cap_bits: DEFAULT_CAP_BITS,
        negotiated_cipher_suite: CIPHER_AESGCM as u32,
        ice_candidates: vec![cfg.edge_b.udp_addr.clone()],
    };
    let conn_acc_dec = SignalingConnectAccept::decode_pb(&conn_acc.encode_pb())?;
    if conn_acc_dec.negotiated_l3_mtu != l3_mtu as u32 {
        return Err(ClientError::Protocol("signaling ConnectAccept roundtrip mismatch".into()));
    }

    let cid_a = random_bytes::<8>();
    let cid_b = random_bytes::<8>();

    let lease_a = cp
        .issue_lease(
            &ks_a,
            Some(&tenant_id),
            &session_id,
            &cid_a,
            &pop_a,
            &dev_a_id,
            &dev_b_id,
            1,
        )
        .await?;
    let lease_b = cp
        .renew_lease(
            &ks_a,
            Some(&tenant_id),
            &session_id,
            &cid_b,
            &pop_b,
            &dev_a_id,
            &dev_b_id,
            lease_a.lease_seq,
            0,
            1,
        )
        .await?;

    let ticket_a = lease_a.to_relay_ticket()?;
    let ticket_b = lease_b.to_relay_ticket()?;

    let now_unix = now_unix_secs();
    let mut rot_a = X25519StaticKeyRotator::new(dev_a_id, false, 0);
    let mut rot_b = X25519StaticKeyRotator::new(dev_b_id, false, 0);
    let gen_a = rot_a.ensure_current(&ks_a, now_unix, reg_a.exp_unix)?;
    let gen_b = rot_b.ensure_current(&ks_b, now_unix, reg_b.exp_unix)?;
    let x25519_priv_a = *gen_a.secret_bytes();
    let x25519_priv_b = *gen_b.secret_bytes();
    let x25519_pub_b = gen_b.public_key;
    let deleg_a = gen_a.delegation.clone();
    let deleg_b = gen_b.delegation.clone();

    let edge_a_pub = cfg.edge_a.x25519_pub()?;
    let edge_b_pub = cfg.edge_b.x25519_pub()?;
    let edge_a_hash = cfg.edge_a.edge_cert_hash()?;
    let edge_b_hash = cfg.edge_b.edge_cert_hash()?;

    let mut ctrl_a = AccessControlTunnel::connect(
        &cfg.edge_a.ctrl_addr,
        &x25519_priv_a,
        &edge_a_pub,
        &pop_a,
        &edge_a_hash,
        Duration::from_secs(5),
    )
    .await?;
    let mut ctrl_b = AccessControlTunnel::connect(
        &cfg.edge_b.ctrl_addr,
        &x25519_priv_b,
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

    // Bind both UDP 5-tuples on Edge A & Edge B via authenticated Ping/Pong before E2EE traffic.
    let edge_a_ping_us = udp_a.ping_with_retry(3, Duration::from_secs(1)).await?;
    let edge_b_ping_us = udp_b.ping_with_retry(3, Duration::from_secs(1)).await?;

    // Exercise authorized NAT RebindReq over Noise_IK control tunnel.
    let rebind_resp = ctrl_a.rebind(&cid_a).await?;
    if rebind_resp.route_cid != cid_a {
        return Err(ClientError::Protocol("Edge RebindResp route_cid mismatch".into()));
    }
    // Re-register UDP 5-tuple after RebindReq clears old binding on Edge A.
    let _ = udp_a.ping_with_retry(3, Duration::from_secs(1)).await?;

    // Verify a signed Pro-tier TenantPolicyBlob (matching the pro tenant created above).
    let policy_ca = SoftwareDeviceKeyStore::generate();
    let policy_ca_spki = policy_ca.public_key_spki_der()?;
    let pro_rules = TenantPolicyRules {
        allow_file_transfer: true,
        allow_clipboard: true,
        allow_file_clipboard: true,
        allow_tcp_tunnel: true,
        allow_terminal: true,
        allow_realtime_actuator: false,
        bw_cap_kbps: 20_000,
        exhaust_policy: QuotaExhaustPolicy::Throttle256Kbps,
    };
    let mut policy_cert = DeviceCert {
        version: 1,
        cert_id: random_bytes::<16>(),
        device_id: dev_a_id,
        tenant_id,
        p256_pub_der: ks_a.public_key_spki_der()?,
        key_epoch: reg_a.key_epoch,
        policy_hash: pro_rules.canonical_hash(),
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
        policy_hash: pro_rules.canonical_hash(),
        iat_unix: now_unix.saturating_sub(10),
        exp_unix: now_unix.saturating_add(3600),
        sig_der: Vec::new(),
    };
    policy_blob.sig_der = policy_ca.sign_p256_low_s(&policy_blob.tbs_bytes())?;
    let policy = VerifiedTenantPolicy::from_verified_blob(
        &policy_blob,
        &policy_cert,
        &pro_rules,
        &policy_ca_spki,
        now_unix,
    )?;
    let prologue_input = PrologueInput {
        ver_major_minor: VER_MAJOR_MINOR,
        handshake_pattern: PATTERN_IK,
        cipher_suite: CIPHER_AESGCM,
        transport_mode: TRANSPORT_MODE_RELAY_UDP,
        device_id_ctrl: dev_a_id,
        device_id_host: dev_b_id,
        ctrl_devcert_tbs_sha256: Sha256::digest(&tbs_a).into(),
        host_devcert_tbs_sha256: Sha256::digest(&tbs_b).into(),
        policy_hash: policy.policy_hash,
        edge_cert_tbs_sha256_or_zero: edge_a_hash,
        negotiated_cap_bits: DEFAULT_CAP_BITS,
        session_id,
    };

    let pub_spki_a = ks_a.public_key_spki_der()?;
    let pub_spki_b = ks_b.public_key_spki_der()?;

    let hs_a = UdpE2eeSession::handshake_initiator(
        udp_a,
        &prologue_input,
        &x25519_priv_a,
        &x25519_pub_b,
        &deleg_b,
        &dev_b_id,
        &pub_spki_b,
        reg_b.exp_unix,
        now_unix,
        policy.clone(),
        dev_a_id,
        l3_mtu,
        Duration::from_secs(5),
    );
    let hs_b = UdpE2eeSession::handshake_responder(
        udp_b,
        &prologue_input,
        &x25519_priv_b,
        &deleg_a,
        &dev_a_id,
        &pub_spki_a,
        reg_a.exp_unix,
        now_unix,
        policy,
        dev_b_id,
        l3_mtu,
        Duration::from_secs(5),
    );
    let ((sess_a, _), (sess_b, _)) = tokio::try_join!(hs_a, hs_b)?;

    Ok(BootstrappedPair {
        cp,
        tenant_id,
        session_id,
        dev_a_id,
        dev_b_id,
        ks_a,
        ks_b,
        cid_a,
        pop_a,
        lease_a_seq: lease_b.lease_seq,
        lease_a_start: lease_a.session_start_unix,
        ctrl_a,
        ctrl_b,
        keys_a,
        keys_b,
        edge_a_ping_us,
        edge_b_ping_us,
        signaling_rtt_us: sig_probe.connect_rtt_us,
        sess_a,
        sess_b,
    })
}

async fn run_p0_hid_ping_pong(
    sess_a: &mut UdpE2eeSession,
    sess_b: &mut UdpE2eeSession,
    count: usize,
) -> Result<Vec<u64>, ClientError> {
    let mut rtts_us = Vec::with_capacity(count);
    for i in 0..count {
        let nonce = (i as u64).to_be_bytes();
        let sent = Instant::now();
        sess_a
            .send_hid(&HidFrame {
                msg_type: 0x01,
                payload: Bytes::copy_from_slice(&nonce),
            })
            .await?;

        let rx_b = sess_b.recv_event(Duration::from_secs(2)).await?;
        let TransportEvent::Hid(hid_b) = rx_b else {
            return Err(ClientError::Protocol("expected Hid frame at peer B".into()));
        };
        if hid_b.payload.as_ref() != nonce {
            return Err(ClientError::Protocol("HID payload mismatch at peer B".into()));
        }
        sess_b
            .send_hid(&HidFrame {
                msg_type: 0x02,
                payload: hid_b.payload,
            })
            .await?;

        let rx_a = sess_a.recv_event(Duration::from_secs(2)).await?;
        let TransportEvent::Hid(hid_a) = rx_a else {
            return Err(ClientError::Protocol("expected Hid echo at peer A".into()));
        };
        if hid_a.payload.as_ref() != nonce {
            return Err(ClientError::Protocol("HID echo mismatch at peer A".into()));
        }
        rtts_us.push(sent.elapsed().as_micros() as u64);
    }
    Ok(rtts_us)
}

async fn cmd_probe(
    cfg_path: &Path,
    count: usize,
    ca_der_override: Option<&Path>,
) -> Result<ProbeReport, ClientError> {
    let cfg = ClusterConfig::from_file(cfg_path)?;
    let mut pair = bootstrap_pair(&cfg, ca_der_override, 1200).await?;
    let rtts = run_p0_hid_ping_pong(&mut pair.sess_a, &mut pair.sess_b, count).await?;
    let received = rtts.len();
    let loss_pct = if count == 0 {
        0.0
    } else {
        ((count.saturating_sub(received)) as f64) * 100.0 / (count as f64)
    };
    Ok(ProbeReport {
        pass: received == count,
        count,
        received,
        loss_pct,
        edge_a_ping_rtt_ms: (pair.edge_a_ping_us as f64) / 1000.0,
        edge_b_ping_rtt_ms: (pair.edge_b_ping_us as f64) / 1000.0,
        p0_rtt_min_ms: percentile_ms(&rtts, 0.0),
        p0_rtt_p50_ms: percentile_ms(&rtts, 0.50),
        p0_rtt_p95_ms: percentile_ms(&rtts, 0.95),
        p0_rtt_max_ms: percentile_ms(&rtts, 1.0),
        error: None,
    })
}

async fn cmd_e2e(
    cfg_path: &Path,
    ca_der_override: Option<&Path>,
) -> Result<E2eReport, ClientError> {
    let cfg = ClusterConfig::from_file(cfg_path)?;
    let ca_path: Option<PathBuf> = ca_der_override
        .map(Path::to_path_buf)
        .or_else(|| cfg.ca_der_path.as_ref().map(PathBuf::from));

    let mut pair = bootstrap_pair(&cfg, ca_der_override, VIDEO_SLICE_L3_MTU).await?;

    // Step 3a: Synthetic 1080p 48 KiB video frame (exact 48 slices, byte-exact SHA-256 verified)
    let mut video_frame = vec![0u8; VIDEO_FRAME_BYTES];
    for (i, b) in video_frame.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(31).wrapping_add(17)) & 0xFF) as u8;
    }
    let expected_video_sha: [u8; 32] = Sha256::digest(&video_frame).into();
    let video_meta = VideoFrameMeta {
        display_idx: 0,
        codec_id: 1, // AV1
        frame_id: 1,
        ref_frame_id: 1,
        ltr_slot: 1,
        is_idr: true,
        is_ref: true,
        max_age_ms: 500,
    };
    let send_video = pair.sess_a.send_video_frame(&video_meta, &video_frame);
    let recv_video = pair.sess_b.recv_event(Duration::from_secs(5));
    let (video_slices_sent, video_ev) = tokio::try_join!(send_video, recv_video)?;
    let video_sha256_match = match video_ev {
        TransportEvent::VideoFrame(frame) => {
            let got_sha: [u8; 32] = Sha256::digest(&frame.data).into();
            frame.data.len() == VIDEO_FRAME_BYTES && got_sha == expected_video_sha
        }
        _ => false,
    };
    if !video_sha256_match {
        return Err(ClientError::Protocol("48KB video frame SHA-256 verification failed".into()));
    }

    // Step 3b: 20x P0 HID RTT
    let hid_count = 20usize;
    let hid_rtts = run_p0_hid_ping_pong(&mut pair.sess_a, &mut pair.sess_b, hid_count).await?;

    // Step 3c: Clipboard channel (0x04)
    let clip_payload = b"ZeroDesk-V2-Clipboard-CleanRoom-UTF8-Payload";
    pair.sess_a
        .send_clipboard(&ClipboardFrame {
            is_file_clipboard: false,
            payload: Bytes::from_static(clip_payload),
        })
        .await?;
    let clip_ev = pair.sess_b.recv_event(Duration::from_secs(2)).await?;
    let clipboard_ok = matches!(
        clip_ev,
        TransportEvent::Clipboard(ref f) if !f.is_file_clipboard && f.payload.as_ref() == clip_payload
    );
    if !clipboard_ok {
        return Err(ClientError::Protocol("Clipboard channel roundtrip failed".into()));
    }

    // Step 4a: RS(6,4) Survival Mode recovery over live E2EE session (drop 4 of 10 shards)
    let rs_originals: Vec<Vec<u8>> = (0..6)
        .map(|i| vec![0xA0u8.wrapping_add(i as u8); 180 + i * 19])
        .collect();
    let rs_shards = encode_survival_rs64_shards(42, &rs_originals)?;
    let dropped_set = [0usize, 2, 4, 7];
    let mut rx_shards = Vec::new();
    for (idx, shard) in rs_shards.iter().enumerate() {
        pair.sess_a.send_control(0x52, shard).await?;
        let ev = pair.sess_b.recv_event(Duration::from_secs(2)).await?;
        if let TransportEvent::Control(cf) = ev {
            if !dropped_set.contains(&idx) {
                rx_shards.push(cf.payload.to_vec());
            }
        }
    }
    let recovered = decode_survival_rs64_shards(42, &rx_shards)?;
    let rs64_recovered_ok = recovered == rs_originals;
    if !rs64_recovered_ok {
        return Err(ClientError::Protocol("RS(6,4) 4-erasure recovery failed".into()));
    }

    // Step 4b: LEG_NACK cache rtx=1 verification + live EdgeCtrl::LegNack send
    let last_seq_a = pair
        .sess_a
        .send_control(0x03, b"leg-nack-target-packet")
        .await?;
    let _ = pair.sess_b.recv_event(Duration::from_secs(2)).await?;
    let rtx_pkts = pair.sess_a.link_mut().handle_local_leg_nack(last_seq_a, 1);
    let leg_nack_rtx_verified = if let Some(pkt) = rtx_pkts.first() {
        let hdr = v2_transport::AccessHeaderV11::decode(pkt)?;
        hdr.flags.rtx && hdr.leg_seq == last_seq_a && !hdr.eligible_for_rtt_sample()
    } else {
        false
    };
    pair.sess_a
        .link_mut()
        .send_edge_ctrl(&EdgeCtrlFrame::LegNack {
            base_leg_seq: last_seq_a,
            loss_bitmap: 0,
        })
        .await?;
    if !leg_nack_rtx_verified {
        return Err(ClientError::Protocol("LEG_NACK rtx=1 cache verification failed".into()));
    }

    // Step 3d: V2LoopbackBridge TCP-over-V2 tunnel byte-exact transfer over live 4-process UDP cluster
    let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
    let echo_addr = echo_listener.local_addr()?;
    let echo_task = tokio::spawn(async move {
        let Ok((mut sock, _)) = echo_listener.accept().await else {
            return;
        };
        let mut buf = [0u8; 4096];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = sock.shutdown().await;
    });

    let mux_a = V2SessionMux::spawn_udp(pair.sess_a);
    let mux_b = V2SessionMux::spawn_udp(pair.sess_b);
    let bridge_a = V2LoopbackBridge::bind("127.0.0.1:0", &mux_a, DEFAULT_BRIDGE_CHANNEL).await?;
    let bridge_addr = bridge_a.local_addr();

    let serve_a = tokio::spawn(bridge_a.serve_one());
    let fwd_b = tokio::spawn(async move {
        let res =
            V2LoopbackBridge::forward_to_loopback_target(echo_addr, &mux_b, DEFAULT_BRIDGE_CHANNEL)
                .await;
        mux_b.shutdown().await;
        res
    });

    let tunnel_bytes = 32 * 1024usize;
    let mut tunnel_payload = vec![0u8; tunnel_bytes];
    for (i, b) in tunnel_payload.iter_mut().enumerate() {
        *b = ((i.wrapping_mul(13).wrapping_add(7)) & 0xFF) as u8;
    }
    let expected_tunnel_sha: [u8; 32] = Sha256::digest(&tunnel_payload).into();

    let tcp_client = TcpStream::connect(bridge_addr).await?;
    let _ = tcp_client.set_nodelay(true);
    let (mut tcp_r, mut tcp_w) = tcp_client.into_split();

    let write_payload = tunnel_payload.clone();
    let writer = tokio::spawn(async move {
        tcp_w.write_all(&write_payload).await?;
        tcp_w.shutdown().await?;
        Ok::<(), std::io::Error>(())
    });

    let mut echoed = Vec::with_capacity(tunnel_bytes);
    tokio::time::timeout(Duration::from_secs(10), tcp_r.read_to_end(&mut echoed))
        .await
        .map_err(|_| ClientError::Timeout("V2LoopbackBridge TCP read timed out".into()))??;
    writer
        .await
        .map_err(|e| ClientError::Protocol(format!("bridge writer task failed: {e}")))??;

    let _ = tokio::time::timeout(Duration::from_secs(5), serve_a).await;
    let _ = tokio::time::timeout(Duration::from_secs(5), fwd_b).await;
    let _ = echo_task.await;
    mux_a.shutdown().await;

    let got_tunnel_sha: [u8; 32] = Sha256::digest(&echoed).into();
    let loopback_bridge_sha256_match =
        echoed.len() == tunnel_bytes && got_tunnel_sha == expected_tunnel_sha;
    if !loopback_bridge_sha256_match {
        return Err(ClientError::Protocol(format!(
            "V2LoopbackBridge byte mismatch: sent {tunnel_bytes}, got {}",
            echoed.len()
        )));
    }

    // Step 5: Dual TLS-443 (Realtime + Bulk) fallback connect + Ping/Pong + passthrough
    let mut tls_a = DualTls443Client::connect(
        &cfg.edge_a.tls443_addr,
        &pair.keys_a,
        ca_path.as_deref(),
        20_000,
    )
    .await?;
    let mut tls_b = DualTls443Client::connect(
        &cfg.edge_b.tls443_addr,
        &pair.keys_b,
        ca_path.as_deref(),
        20_000,
    )
    .await?;

    // Send a 64B test L3-sized payload over TLS-443 Realtime stream from Edge A -> Edge B
    let tls_marker = vec![0x7Au8; 64];
    tls_a.send_l3(0, false, true, 0, &tls_marker).await?;
    let tls_rx = tls_b.realtime.recv_frame(Duration::from_secs(3)).await?;
    let tls443_passthrough_ok = matches!(
        tls_rx,
        v2_client::StreamRecvEvent::L3Data { ref payload, .. } if payload == &tls_marker
    );
    if !tls443_passthrough_ok {
        return Err(ClientError::Protocol("TLS-443 Realtime passthrough mismatch".into()));
    }
    let tls443_realtime_ping_rtt_ms = (tls_a.realtime_ping_rtt_us as f64) / 1000.0;
    let tls443_bulk_ping_rtt_ms = (tls_a.bulk_ping_rtt_us as f64) / 1000.0;
    drop(tls_a);
    drop(tls_b);

    // Step 6: Lease renewal (CP /v2/leases/renew + Edge Noise_IK LeaseRenewReq) preserving route_cid
    let renewed_cp = pair
        .cp
        .renew_lease(
            &pair.ks_a,
            Some(&pair.tenant_id),
            &pair.session_id,
            &pair.cid_a,
            &pair.pop_a,
            &pair.dev_a_id,
            &pair.dev_b_id,
            pair.lease_a_seq,
            65_536,
            1,
        )
        .await?;
    let renewed_ticket = renewed_cp.to_relay_ticket()?;
    let renewed_edge = pair.ctrl_a.lease_renew(&renewed_ticket).await?;
    let lease_renew_route_cid_preserved = renewed_edge.route_cid == pair.cid_a;
    let lease_renew_ok =
        renewed_cp.lease_seq > pair.lease_a_seq && lease_renew_route_cid_preserved;
    if !lease_renew_ok {
        return Err(ClientError::Protocol("lease renewal check failed".into()));
    }

    // Client fallback metering verification (/v2/metering/client-report)
    let meter_resp = pair
        .cp
        .report_metering_fallback(
            &pair.ks_a,
            &pair.dev_a_id,
            &pair.session_id,
            &cfg.edge_a.pop_id,
            pair.lease_a_start,
            0,
            65_536,
        )
        .await?;
    let fallback_metering_ok = meter_resp.rejected == 0;

    Ok(E2eReport {
        pass: true,
        enrollment_ok: true,
        signaling_tcp_rtt_ms: (pair.signaling_rtt_us as f64) / 1000.0,
        edge_a_bind_ok: true,
        edge_b_bind_ok: true,
        edge_a_ping_rtt_ms: (pair.edge_a_ping_us as f64) / 1000.0,
        edge_b_ping_rtt_ms: (pair.edge_b_ping_us as f64) / 1000.0,
        e2ee_handshake_ok: true,
        video_frame_bytes: VIDEO_FRAME_BYTES,
        video_slices_sent,
        video_sha256_match,
        p0_hid_count: hid_count,
        p0_hid_received: hid_rtts.len(),
        p0_hid_rtt_p50_ms: percentile_ms(&hid_rtts, 0.50),
        p0_hid_rtt_p95_ms: percentile_ms(&hid_rtts, 0.95),
        clipboard_ok,
        rs64_dropped_shards: dropped_set.len(),
        rs64_recovered_ok,
        leg_nack_rtx_verified,
        tls443_realtime_ping_rtt_ms,
        tls443_bulk_ping_rtt_ms,
        tls443_passthrough_ok,
        lease_renew_ok,
        lease_renew_route_cid_preserved,
        lease_renew_seq: renewed_cp.lease_seq,
        fallback_metering_ok,
        loopback_bridge_bytes: echoed.len(),
        loopback_bridge_sha256_match,
        error: None,
    })
}

async fn cmd_loopback_bridge(
    listen: &str,
    cfg_path: &Path,
    target: Option<&str>,
    ca_der_override: Option<&Path>,
) -> Result<(), ClientError> {
    let cfg = ClusterConfig::from_file(cfg_path)?;
    let pair = bootstrap_pair(&cfg, ca_der_override, 1200).await?;
    let mux_a = V2SessionMux::spawn_udp(pair.sess_a);
    let mux_b = V2SessionMux::spawn_udp(pair.sess_b);
    let bridge = V2LoopbackBridge::bind(listen, &mux_a, DEFAULT_BRIDGE_CHANNEL).await?;
    let bound = bridge.local_addr();

    let target_addr: SocketAddr = if let Some(t) = target {
        t.parse()
            .map_err(|e| ClientError::Config(format!("invalid --target '{t}': {e}")))?
    } else {
        // Default: spawn a local echo target for self-contained verification.
        let echo_listener = TcpListener::bind("127.0.0.1:0").await?;
        let addr = echo_listener.local_addr()?;
        tokio::spawn(async move {
            if let Ok((mut s, _)) = echo_listener.accept().await {
                let mut buf = [0u8; 4096];
                while let Ok(n) = s.read(&mut buf).await {
                    if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
                let _ = s.shutdown().await;
            }
        });
        addr
    };

    eprintln!("[zerodesk-v2-cli] V2LoopbackBridge listening on {bound} -> V2 E2EE -> {target_addr}");
    let fwd = tokio::spawn(async move {
        let res = V2LoopbackBridge::forward_to_loopback_target(
            target_addr,
            &mux_b,
            DEFAULT_BRIDGE_CHANNEL,
        )
        .await;
        mux_b.shutdown().await;
        res
    });
    let (tx, rx) = bridge.serve_one().await?;
    let _ = fwd.await;
    mux_a.shutdown().await;
    println!(
        "{}",
        serde_json::json!({
            "pass": true,
            "listen": bound.to_string(),
            "target": target_addr.to_string(),
            "tx_bytes": tx,
            "rx_bytes": rx,
        })
    );
    Ok(())
}

fn print_usage() {
    eprintln!(
        "Usage:\n  \
         zerodesk-v2-cli probe --config <cluster.json> [--count 20] [--cp-ca-der <path>]\n  \
         zerodesk-v2-cli e2e --config <cluster.json> [--cp-ca-der <path>]\n  \
         zerodesk-v2-cli loopback-bridge --listen 127.0.0.1:<port> --config <cluster.json> [--target 127.0.0.1:<port>] [--cp-ca-der <path>]"
    );
}

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage();
        return ExitCode::from(2);
    }

    let subcmd = args[1].as_str();
    let mut config_path: Option<PathBuf> = None;
    let mut ca_der_path: Option<PathBuf> = None;
    let mut count: usize = 20;
    let mut listen: Option<String> = None;
    let mut target: Option<String> = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--config" if i + 1 < args.len() => {
                config_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--cp-ca-der" if i + 1 < args.len() => {
                ca_der_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--count" if i + 1 < args.len() => {
                match args[i + 1].parse::<usize>() {
                    Ok(v) => count = v,
                    Err(_) => {
                        eprintln!("invalid --count value");
                        return ExitCode::from(2);
                    }
                }
                i += 2;
            }
            "--listen" if i + 1 < args.len() => {
                listen = Some(args[i + 1].clone());
                i += 2;
            }
            "--target" if i + 1 < args.len() => {
                target = Some(args[i + 1].clone());
                i += 2;
            }
            "-h" | "--help" => {
                print_usage();
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("unknown argument: {other}");
                print_usage();
                return ExitCode::from(2);
            }
        }
    }

    let Some(cfg_path) = config_path else {
        eprintln!("missing required --config <cluster.json>");
        print_usage();
        return ExitCode::from(2);
    };

    match subcmd {
        "probe" => match cmd_probe(&cfg_path, count, ca_der_path.as_deref()).await {
            Ok(report) => {
                let ok = report.pass;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
                );
                if ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(e) => {
                let report = ProbeReport {
                    pass: false,
                    count,
                    received: 0,
                    loss_pct: 100.0,
                    edge_a_ping_rtt_ms: 0.0,
                    edge_b_ping_rtt_ms: 0.0,
                    p0_rtt_min_ms: 0.0,
                    p0_rtt_p50_ms: 0.0,
                    p0_rtt_p95_ms: 0.0,
                    p0_rtt_max_ms: 0.0,
                    error: Some(e.to_string()),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
                );
                ExitCode::FAILURE
            }
        },
        "e2e" => match cmd_e2e(&cfg_path, ca_der_path.as_deref()).await {
            Ok(report) => {
                let ok = report.pass;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".into())
                );
                if ok {
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
                println!(
                    "{}",
                    serde_json::to_string_pretty(&err_json).unwrap_or_else(|_| "{}".into())
                );
                ExitCode::FAILURE
            }
        },
        "loopback-bridge" => {
            let Some(listen_addr) = listen else {
                eprintln!("missing required --listen 127.0.0.1:<port>");
                return ExitCode::from(2);
            };
            match cmd_loopback_bridge(&listen_addr, &cfg_path, target.as_deref(), ca_der_path.as_deref()).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("loopback-bridge error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        other => {
            eprintln!("unknown subcommand: {other}");
            print_usage();
            ExitCode::from(2)
        }
    }
}
