use bytes::Bytes;
use v2_identity::{DeviceKeyStore, EdgeCert, SoftwareDeviceKeyStore, X25519StaticKeyRotator};
use v2_transport::{
    derive_access_key, sanitize_log_line, seal_udp_v11, AccessEpochState, AccessFlags,
    AccessHeaderV11, AccessNoiseHandshake, ActuatorCmd, AudioPacket, ClipboardFrame,
    DiagnosticBundle, DiagnosticsRing, E2eeNoiseHandshake, ErrorCode, HidFrame, L3Receiver,
    L3Sender, LoopbackTransportV2, PathHandle, PathId, PathSet, PathState, PrologueInput,
    QoeSnapshot, QuotaExhaustPolicy, TelemetryFrame, TenantPolicyRules, TransportError,
    TransportEvent, TransportMode, TransportV2, VerifiedTenantPolicy, VideoFrameMeta,
    CHAN_FILE_TRANSFER, CIPHER_AESGCM, CIPHER_CHACHAPOLY, DIR_CLIENT_TO_EDGE, PATTERN_IK,
    PATTERN_XX, TRANSPORT_DATAGRAM, TRANSPORT_MODE_RELAY_UDP, VER_MAJOR_MINOR,
};

fn sample_prologue(pattern: u8, cipher_suite: u16) -> [u8; 32] {
    PrologueInput {
        ver_major_minor: VER_MAJOR_MINOR,
        handshake_pattern: pattern,
        cipher_suite,
        transport_mode: TRANSPORT_MODE_RELAY_UDP,
        device_id_ctrl: [0x11; 16],
        device_id_host: [0x22; 16],
        ctrl_devcert_tbs_sha256: [0x33; 32],
        host_devcert_tbs_sha256: [0x44; 32],
        policy_hash: [0x55; 32],
        edge_cert_tbs_sha256_or_zero: [0x66; 32],
        negotiated_cap_bits: 0x1_7001,
        session_id: [0x77; 16],
    }
    .compute_prologue()
}

#[test]
fn dual_layer_snow_access_and_e2ee_ik_xx_handshakes() {
    let ca = SoftwareDeviceKeyStore::generate();
    let ca_spki = ca.public_key_spki_der().unwrap();

    // 1. Access layer Noise_IK with CA-signed EdgeCert
    let edge_ks = SoftwareDeviceKeyStore::generate();
    let mut edge_rot = X25519StaticKeyRotator::new([0xEE; 16], false, 0);
    let edge_gen = edge_rot
        .ensure_current(&edge_ks, 1_700_000_000, 1_700_021_600)
        .unwrap();
    let edge_priv = *edge_gen.secret_bytes();
    let edge_pub = edge_gen.public_key;

    let mut edge_cert = EdgeCert {
        version: 1,
        pop_id: *b"pop-hkg1",
        x25519_pub: edge_pub,
        iat_unix: 1_700_000_000,
        exp_unix: 1_700_086_400,
        sig_der: Vec::new(),
    };
    edge_cert.sig_der = ca.sign_p256_low_s(&edge_cert.tbs_bytes()).unwrap();

    let dev_ks = SoftwareDeviceKeyStore::generate();
    let mut dev_rot = X25519StaticKeyRotator::new([0x11; 16], false, 0);
    let dev_priv = *dev_rot
        .ensure_current(&dev_ks, 1_700_000_000, 1_700_021_600)
        .unwrap()
        .secret_bytes();

    let mut acc_i = AccessNoiseHandshake::build_initiator(
        &dev_priv,
        &edge_cert,
        &ca_spki,
        1_700_000_010,
    )
    .unwrap();
    let mut acc_r = AccessNoiseHandshake::build_responder(&edge_priv, &edge_cert).unwrap();

    let m1 = acc_i.write_message(b"bind-req").unwrap();
    assert_eq!(acc_r.read_message(&m1).unwrap(), b"bind-req");
    let m2 = acc_r.write_message(b"bind-resp").unwrap();
    assert_eq!(acc_i.read_message(&m2).unwrap(), b"bind-resp");

    let out_i = acc_i.finish().unwrap();
    let out_r = acc_r.finish().unwrap();
    assert_eq!(out_i.hs_hash, out_r.hs_hash);

    // Derive L2 access MAC key from hs_hash and verify UDP packet.
    let route_cid = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
    let key_c2e =
        derive_access_key(&route_cid, &out_i.hs_hash, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0)
            .unwrap();
    let mut edge_state = AccessEpochState::new(
        route_cid,
        out_r.hs_hash,
        TRANSPORT_DATAGRAM,
        DIR_CLIENT_TO_EDGE,
        0,
        20,
    )
    .unwrap();
    let hdr = AccessHeaderV11 {
        flags: AccessFlags {
            pp: 2,
            discardable: false,
            frame_end: false,
            is_ctrl_edge: false,
            dir_edge_to_client: false,
            rtx: false,
        },
        route_cid,
        access_epoch: 0,
        leg_seq: 1,
        mac_64: [0; 8],
    };
    let wire = seal_udp_v11(&key_c2e, hdr, &[0xAB; 40]).unwrap();
    let (decoded_hdr, payload) = edge_state.verify_udp_packet(&wire, 100).unwrap();
    assert_eq!(decoded_hdr.leg_seq, 1);
    assert_eq!(payload, &[0xAB; 40]);

    // 2. E2EE Noise_IK (AESGCM & ChaChaPoly) and Noise_XX + anti-downgrade rejection
    let host_ks = SoftwareDeviceKeyStore::generate();
    let mut host_rot = X25519StaticKeyRotator::new([0x22; 16], false, 0);
    let host_gen = host_rot
        .ensure_current(&host_ks, 1_700_000_000, 1_700_021_600)
        .unwrap();
    let host_priv = *host_gen.secret_bytes();
    let host_pub = host_gen.public_key;

    for suite in [CIPHER_AESGCM, CIPHER_CHACHAPOLY] {
        let prologue = sample_prologue(PATTERN_IK, suite);
        let mut i = E2eeNoiseHandshake::build_ik_initiator(suite, &dev_priv, &host_pub, &prologue)
            .unwrap();
        let mut r = E2eeNoiseHandshake::build_ik_responder(suite, &host_priv, &prologue).unwrap();
        let msg1 = i.write_message(b"session-open-0rtt").unwrap();
        assert_eq!(r.read_message(&msg1).unwrap(), b"session-open-0rtt");
        let msg2 = r.write_message(b"session-accept").unwrap();
        assert_eq!(i.read_message(&msg2).unwrap(), b"session-accept");
        let split_i = i.finish_split().unwrap();
        let split_r = r.finish_split().unwrap();
        assert_eq!(split_i.tx_key, split_r.rx_key);
        assert_eq!(split_i.rx_key, split_r.tx_key);
        assert_ne!(split_i.tx_key, split_i.rx_key);

        let mut tx = L3Sender::new(suite, 1, split_i.tx_key);
        let mut rx = L3Receiver::new(suite, 1, split_r.rx_key);
        let (_, pkt) = tx.encrypt(0x01, 0, 1234, b"hid-key").unwrap();
        let (h, pt) = rx.decrypt_and_verify(&pkt, Some(0), 100).unwrap();
        assert_eq!(h.chan_id, 0x01);
        assert_eq!(pt, b"hid-key");

        // Mismatched prologue (downgrade mutation) MUST fail handshake decryption.
        let mut bad_prologue = prologue;
        bad_prologue[0] ^= 0x01;
        let mut i_bad =
            E2eeNoiseHandshake::build_ik_initiator(suite, &dev_priv, &host_pub, &bad_prologue)
                .unwrap();
        let mut r_good =
            E2eeNoiseHandshake::build_ik_responder(suite, &host_priv, &prologue).unwrap();
        let msg1_bad = i_bad.write_message(b"open").unwrap();
        assert!(r_good.read_message(&msg1_bad).is_err());
    }

    // Noise_XX fallback
    let xx_prologue = sample_prologue(PATTERN_XX, CIPHER_AESGCM);
    let mut xi =
        E2eeNoiseHandshake::build_xx_initiator(CIPHER_AESGCM, &dev_priv, &xx_prologue).unwrap();
    let mut xr =
        E2eeNoiseHandshake::build_xx_responder(CIPHER_AESGCM, &host_priv, &xx_prologue).unwrap();
    let xm1 = xi.write_message(b"").unwrap();
    let _ = xr.read_message(&xm1).unwrap();
    let xm2 = xr.write_message(b"host-delegation").unwrap();
    assert_eq!(xi.read_message(&xm2).unwrap(), b"host-delegation");
    let xm3 = xi.write_message(b"ctrl-delegation").unwrap();
    assert_eq!(xr.read_message(&xm3).unwrap(), b"ctrl-delegation");
    let x_out_i = xi.finish_split().unwrap();
    let x_out_r = xr.finish_split().unwrap();
    assert_eq!(x_out_i.tx_key, x_out_r.rx_key);
    assert_eq!(x_out_i.remote_static_x25519, host_pub);
}

#[tokio::test]
async fn transport_v2_channels_video_slicing_and_free_tier_policy_ceiling() {
    let policy = VerifiedTenantPolicy::free_tier([0x42; 16]);
    assert!(!policy.allow_file_transfer);
    assert!(!policy.allow_file_clipboard);
    assert!(policy.allow_clipboard);
    assert_eq!(policy.on_quota_exhausted(), (256, false));

    let (ctrl, mut host) =
        LoopbackTransportV2::pair(CIPHER_AESGCM, [0xAA; 32], [0xBB; 32], policy);

    // Free tier MUST block 0x05 FileTransfer and file-clipboard (Cliprdr) bypass!
    let file_err = ctrl
        .send_reliable(CHAN_FILE_TRANSFER, Bytes::from_static(b"secret.bin"))
        .await
        .unwrap_err();
    assert_eq!(file_err.error_code(), ErrorCode::PolicyDenied);

    let clip_file_err = ctrl
        .send_clipboard(ClipboardFrame {
            is_file_clipboard: true,
            payload: Bytes::from_static(b"file:///tmp/bypass.txt"),
        })
        .await
        .unwrap_err();
    assert_eq!(clip_file_err.error_code(), ErrorCode::PolicyDenied);

    // Text clipboard, HID, Audio, multi-slice Video (> 1200B MTU), Actuator, Telemetry, Diagnostics succeed.
    ctrl.send_clipboard(ClipboardFrame {
        is_file_clipboard: false,
        payload: Bytes::from_static(b"hello text"),
    })
    .await
    .unwrap();
    assert_eq!(
        host.recv().await.unwrap(),
        TransportEvent::Clipboard(ClipboardFrame {
            is_file_clipboard: false,
            payload: Bytes::from_static(b"hello text"),
        })
    );

    ctrl.send_hid(HidFrame {
        msg_type: 1,
        payload: Bytes::from_static(b"KEY_A"),
    })
    .await
    .unwrap();
    assert_eq!(
        host.recv().await.unwrap(),
        TransportEvent::Hid(HidFrame {
            msg_type: 1,
            payload: Bytes::from_static(b"KEY_A"),
        })
    );

    ctrl.send_audio(AudioPacket {
        ts: 48000,
        dtx: true,
        payload: Bytes::from_static(b"opus"),
    })
    .await
    .unwrap();
    assert_eq!(
        host.recv().await.unwrap(),
        TransportEvent::Audio(AudioPacket {
            ts: 48000,
            dtx: true,
            payload: Bytes::from_static(b"opus"),
        })
    );

    // Large 4000B video frame splits into 4 slices <= 1200B L3 MTU and reassembles cleanly.
    let big_video = vec![0x5Au8; 4000];
    ctrl.send_video(
        VideoFrameMeta {
            display_idx: 0,
            codec_id: 1, // AV1
            frame_id: 99,
            ref_frame_id: 99,
            ltr_slot: 1,
            is_idr: true,
            is_ref: true,
            max_age_ms: 80,
        },
        Bytes::from(big_video.clone()),
    )
    .await
    .unwrap();
    match host.recv().await.unwrap() {
        TransportEvent::VideoFrame(vf) => {
            assert_eq!(vf.frame_id, 99);
            assert!(vf.is_idr);
            assert_eq!(vf.data.as_ref(), big_video.as_slice());
        }
        other => panic!("expected VideoFrame, got {other:?}"),
    }

    let act = ActuatorCmd {
        control_epoch: 1,
        cmd_seq: 1,
        send_ts_ms: 1000,
        ttl_ms: 50,
        payload: b"THR=0.5".to_vec(),
    };
    ctrl.send_actuator(act.clone()).await.unwrap();
    assert_eq!(host.recv().await.unwrap(), TransportEvent::RealtimeActuator(act));

    let telem = TelemetryFrame {
        telem_seq: 7,
        sample_ts_ms: 1005,
        mask: 0x1F,
        payload: b"BAT=90".to_vec(),
    };
    ctrl.send_telemetry(telem.clone()).await.unwrap();
    assert_eq!(host.recv().await.unwrap(), TransportEvent::Telemetry(telem));

    let snap = QoeSnapshot {
        rtt_ms: 18,
        effective_bw_kbps: 4000,
        ..Default::default()
    };
    ctrl.send_diagnostics(snap.clone()).await.unwrap();
    assert_eq!(host.recv().await.unwrap(), TransportEvent::Diagnostics(snap));

    let stats = ctrl.session_stats();
    assert_eq!(stats.policy_denied_drops, 2);
    assert!(stats.tx_packets >= 9);
}

#[test]
fn path_set_hot_switch_inherits_bandwidth_and_dual_sends() {
    let mut ps = PathSet::new(PathHandle {
        id: PathId(1),
        mode: TransportMode::P2p,
        pop_id: None,
        route_cid: None,
        state: PathState::Active,
        rtt_ms: 25,
        loss_pct: 0.5,
        estimated_bw_kbps: 12_000,
        last_probe_ms: 1000,
    });
    ps.add_standby(PathHandle {
        id: PathId(2),
        mode: TransportMode::RelayUdp,
        pop_id: Some(*b"pop-hkg1"),
        route_cid: Some([1; 8]),
        state: PathState::Probing,
        rtt_ms: 0,
        loss_pct: 0.0,
        estimated_bw_kbps: 0,
        last_probe_ms: 0,
    });
    assert!(ps.mark_probe_response(PathId(2), 30, 1100));
    assert!(ps.begin_hot_switch(PathId(2), 1200, 250));

    // Inherited CC bandwidth from previous active path
    assert_eq!(ps.standby[0].estimated_bw_kbps, 12_000);
    // Dual-sending on both active and standby during 250ms window
    assert_eq!(ps.tx_paths(false), vec![PathId(1), PathId(2)]);
    assert_eq!(ps.commit_hot_switch(1400, false), None);
    assert_eq!(ps.commit_hot_switch(1450, false), Some(PathId(2)));
    assert_eq!(ps.active.id, PathId(2));
    assert_eq!(ps.switch_count, 1);

    // Survival mode Active-Active dual send for high-priority/reference traffic
    ps.standby[0].state = PathState::Ready;
    ps.set_survival_active_active(true);
    assert_eq!(ps.tx_paths(true), vec![PathId(2), PathId(1)]);
    assert_eq!(ps.tx_paths(false), vec![PathId(2)]);
}

#[test]
fn diagnostics_bundle_sanitizes_sensitive_fields_and_mission_locked_policy() {
    let line = "connect 192.168.1.42:21116 /Users/alice/secret.key token=abc123 password=xyz";
    let clean = sanitize_log_line(line);
    assert!(clean.contains("192.168.1.x:21116"));
    assert!(clean.contains("[REDACTED_PATH]"));
    assert!(clean.contains("token=[REDACTED]"));
    assert!(clean.contains("password=[REDACTED]"));
    assert!(!clean.contains("alice"));
    assert!(!clean.contains("abc123"));
    assert!(!clean.contains("xyz"));

    let mut ring = DiagnosticsRing::new();
    ring.push(QoeSnapshot {
        rtt_ms: 22,
        ..Default::default()
    });
    let bundle = DiagnosticBundle::build_sanitized(
        false,
        vec!["videotoolbox".to_owned()],
        &ring,
        &[line.to_owned()],
    );
    assert_eq!(bundle.app_name, "ZeroDesk");
    assert!(!bundle.hardware_backed_identity);
    assert_eq!(bundle.qoe_history.len(), 1);
    assert_eq!(bundle.sanitized_log_tail[0], clean);

    let uav_rules = TenantPolicyRules {
        allow_file_transfer: false,
        allow_clipboard: false,
        allow_file_clipboard: true, // MUST still be forced false!
        allow_tcp_tunnel: false,
        allow_terminal: false,
        allow_realtime_actuator: true,
        bw_cap_kbps: 6_000,
        exhaust_policy: QuotaExhaustPolicy::MissionLockedAlert,
    };
    let uav_policy = VerifiedTenantPolicy::from_rules_unchecked(
        [0x7E; 16],
        1,
        uav_rules.canonical_hash(),
        &uav_rules,
    );
    assert!(!uav_policy.allow_file_clipboard);
    assert_eq!(uav_policy.on_quota_exhausted(), (6_000, true));
    assert!(matches!(
        uav_policy.enforce_tcp_tunnel(),
        Err(TransportError::PolicyDenied(_))
    ));
}
