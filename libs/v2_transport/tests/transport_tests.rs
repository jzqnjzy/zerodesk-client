// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use bytes::Bytes;
use v2_identity::{
    ControlPreemptToken, DeviceCert, DeviceKeyStore, EdgeCert, IdentityError,
    SoftwareDeviceKeyStore, TenantPolicyBlob, X25519StaticKeyRotator,
};
use v2_transport::{
    derive_access_key, sanitize_log_line, seal_udp_v11, AccessEpochState, AccessFlags,
    AccessHeaderV11, AccessNoiseHandshake, ActuatorCmd, AudioPacket, ClipboardFrame,
    DiagnosticBundle, DiagnosticsRing, E2eeNoiseHandshake, ErrorCode, HidFrame, L3Header,
    L3Receiver, L3Sender, LegCiphertextCache, LoopbackTransportV2, PathHandle, PathId, PathSet,
    PathState, PrologueInput, QoeSnapshot, QuotaExhaustPolicy, StreamSeqDedup, TelemetryFrame,
    TenantPolicyRules, TransportError, TransportEvent, TransportMode, TransportV2,
    VerifiedTenantPolicy, VideoFrameMeta, VideoReassembler, VideoSlice, ZeroRttGuard,
    CHAN_FILE_TRANSFER, CHAN_REALTIME_ACTUATOR, CIPHER_AESGCM, CIPHER_CHACHAPOLY,
    DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT, LEG_CACHE_MAX_BYTES, PATTERN_IK, PATTERN_XX,
    STREAM_SEQ_DEDUP_CAPACITY, TRANSPORT_DATAGRAM, TRANSPORT_MODE_RELAY_UDP, VER_MAJOR_MINOR,
    VIDEO_REASSEMBLER_MAX_AGE_MS, VIDEO_REASSEMBLER_MAX_PARTIALS,
};

fn build_verified_policy(
    ca: &SoftwareDeviceKeyStore,
    tenant_id: [u8; 16],
    device_id: [u8; 16],
    rules: &TenantPolicyRules,
    now_unix: u64,
) -> VerifiedTenantPolicy {
    let ca_spki = ca.public_key_spki_der().unwrap();
    let dev = SoftwareDeviceKeyStore::generate();
    let policy_hash = rules.canonical_hash();
    let mut cert = DeviceCert {
        version: 1,
        cert_id: [0x10; 16],
        device_id,
        tenant_id,
        p256_pub_der: dev.public_key_spki_der().unwrap(),
        key_epoch: 1,
        policy_hash,
        cap_bits: 0x1_7001,
        iat_unix: now_unix - 10,
        exp_unix: now_unix + 6 * 3600,
        hardware_backed: false,
        sig_der: Vec::new(),
    };
    cert.sig_der = ca.sign_p256_low_s(&cert.tbs_bytes().unwrap()).unwrap();

    let mut blob = TenantPolicyBlob {
        tenant_id,
        version: 1,
        policy_hash,
        iat_unix: now_unix - 10,
        exp_unix: now_unix + 24 * 3600,
        sig_der: Vec::new(),
    };
    blob.sig_der = ca.sign_p256_low_s(&blob.tbs_bytes()).unwrap();

    VerifiedTenantPolicy::from_verified_blob(&blob, &cert, rules, &ca_spki, now_unix).unwrap()
}

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
    let dev_spki = dev_ks.public_key_spki_der().unwrap();
    let dev_device_id = [0x11; 16];
    let now_unix = 1_700_000_010;
    let cert_exp = 1_700_021_600;
    let mut dev_rot = X25519StaticKeyRotator::new(dev_device_id, false, 0);
    let dev_gen = dev_rot
        .ensure_current(&dev_ks, 1_700_000_000, cert_exp)
        .unwrap();
    let dev_priv = *dev_gen.secret_bytes();
    let dev_deleg = dev_gen.delegation.clone();

    let mut acc_i = AccessNoiseHandshake::build_initiator(
        &dev_priv,
        &edge_cert,
        &ca_spki,
        now_unix,
    )
    .unwrap();
    let mut acc_r = AccessNoiseHandshake::build_responder(&edge_priv, &edge_cert).unwrap();

    let m1 = acc_i.write_message(b"bind-req").unwrap();
    assert_eq!(acc_r.read_message(&m1).unwrap(), b"bind-req");
    let m2 = acc_r.write_message(b"bind-resp").unwrap();
    assert_eq!(acc_i.read_message(&m2).unwrap(), b"bind-resp");

    let out_i = acc_i.finish().unwrap();
    let out_r = acc_r.finish().unwrap();
    assert_eq!(*out_i.hs_hash, *out_r.hs_hash);

    // Derive L2 access MAC key from hs_hash and verify UDP packet.
    let route_cid = [0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18];
    let key_c2e =
        derive_access_key(&route_cid, &out_i.hs_hash, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0)
            .unwrap();
    let mut edge_state = AccessEpochState::new(
        route_cid,
        *out_r.hs_hash,
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

    // 2. E2EE Noise_IK (AESGCM & ChaChaPoly) and Noise_XX + anti-downgrade & DelegationSig binding
    let host_ks = SoftwareDeviceKeyStore::generate();
    let host_spki = host_ks.public_key_spki_der().unwrap();
    let host_device_id = [0x22; 16];
    let mut host_rot = X25519StaticKeyRotator::new(host_device_id, false, 0);
    let host_gen = host_rot
        .ensure_current(&host_ks, 1_700_000_000, cert_exp)
        .unwrap();
    let host_priv = *host_gen.secret_bytes();
    let host_pub = host_gen.public_key;
    let host_deleg = host_gen.delegation.clone();

    for suite in [CIPHER_AESGCM, CIPHER_CHACHAPOLY] {
        let prologue = sample_prologue(PATTERN_IK, suite);
        let mut i = E2eeNoiseHandshake::build_ik_initiator(suite, &dev_priv, &host_pub, &prologue)
            .unwrap();
        let mut r = E2eeNoiseHandshake::build_ik_responder(suite, &host_priv, &prologue).unwrap();
        let msg1 = i.write_message(b"session-open-0rtt").unwrap();
        assert_eq!(r.read_message(&msg1).unwrap(), b"session-open-0rtt");
        let msg2 = r.write_message(b"session-accept").unwrap();
        assert_eq!(i.read_message(&msg2).unwrap(), b"session-accept");
        let split_i = i
            .finish_split(
                Some(&host_deleg),
                &host_device_id,
                &host_spki,
                cert_exp,
                now_unix,
            )
            .unwrap();
        let split_r = r
            .finish_split(
                Some(&dev_deleg),
                &dev_device_id,
                &dev_spki,
                cert_exp,
                now_unix,
            )
            .unwrap();
        assert_eq!(*split_i.tx_key, *split_r.rx_key);
        assert_eq!(*split_i.rx_key, *split_r.tx_key);
        assert_ne!(*split_i.tx_key, *split_i.rx_key);

        let mut tx = L3Sender::new(suite, 1, *split_i.tx_key);
        let mut rx = L3Receiver::new(suite, 1, *split_r.rx_key);
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

    // Noise_IK negative cases: mismatched static pubkey or forged DelegationSig MUST be rejected.
    {
        let prologue = sample_prologue(PATTERN_IK, CIPHER_AESGCM);
        let mut i =
            E2eeNoiseHandshake::build_ik_initiator(CIPHER_AESGCM, &dev_priv, &host_pub, &prologue)
                .unwrap();
        let mut r =
            E2eeNoiseHandshake::build_ik_responder(CIPHER_AESGCM, &host_priv, &prologue).unwrap();
        let msg1 = i.write_message(b"open").unwrap();
        let _ = r.read_message(&msg1).unwrap();
        let msg2 = r.write_message(b"ok").unwrap();
        let _ = i.read_message(&msg2).unwrap();

        let mut wrong_pub_deleg = host_deleg.clone();
        wrong_pub_deleg.x25519_pub[0] ^= 0xFF;
        wrong_pub_deleg.sig_der = host_ks.sign_p256_low_s(&wrong_pub_deleg.tbs_bytes()).unwrap();
        assert_eq!(
            i.finish_split(
                Some(&wrong_pub_deleg),
                &host_device_id,
                &host_spki,
                cert_exp,
                now_unix,
            )
            .err(),
            Some(TransportError::Identity(IdentityError::BindingMismatch))
        );

        let mut bad_sig_deleg = dev_deleg.clone();
        if let Some(last) = bad_sig_deleg.sig_der.last_mut() {
            *last ^= 0x55;
        }
        assert_eq!(
            r.finish_split(
                Some(&bad_sig_deleg),
                &dev_device_id,
                &dev_spki,
                cert_exp,
                now_unix,
            )
            .err(),
            Some(TransportError::Identity(IdentityError::InvalidSignature))
        );
    }

    // Noise_XX fallback MUST carry and verify real signed DelegationStatement in msg2/msg3.
    let xx_prologue = sample_prologue(PATTERN_XX, CIPHER_AESGCM);
    let host_deleg_wire = host_deleg.encode_wire().unwrap();
    let dev_deleg_wire = dev_deleg.encode_wire().unwrap();
    let mut xi =
        E2eeNoiseHandshake::build_xx_initiator(CIPHER_AESGCM, &dev_priv, &xx_prologue).unwrap();
    let mut xr =
        E2eeNoiseHandshake::build_xx_responder(CIPHER_AESGCM, &host_priv, &xx_prologue).unwrap();
    let xm1 = xi.write_message(b"").unwrap();
    let _ = xr.read_message(&xm1).unwrap();
    let xm2 = xr.write_message(&host_deleg_wire).unwrap();
    assert_eq!(xi.read_message(&xm2).unwrap(), host_deleg_wire);
    let xm3 = xi.write_message(&dev_deleg_wire).unwrap();
    assert_eq!(xr.read_message(&xm3).unwrap(), dev_deleg_wire);
    let x_out_i = xi
        .finish_split(None, &host_device_id, &host_spki, cert_exp, now_unix)
        .unwrap();
    let x_out_r = xr
        .finish_split(None, &dev_device_id, &dev_spki, cert_exp, now_unix)
        .unwrap();
    assert_eq!(*x_out_i.tx_key, *x_out_r.rx_key);
    assert_eq!(x_out_i.remote_static_x25519, host_pub);
    assert_eq!(x_out_i.peer_delegation, host_deleg);

    // Noise_XX negative case 1: plaintext placeholder bytes in msg2 rejected immediately.
    {
        let mut xi_bad =
            E2eeNoiseHandshake::build_xx_initiator(CIPHER_AESGCM, &dev_priv, &xx_prologue).unwrap();
        let mut xr_bad =
            E2eeNoiseHandshake::build_xx_responder(CIPHER_AESGCM, &host_priv, &xx_prologue)
                .unwrap();
        let m1 = xi_bad.write_message(b"").unwrap();
        let _ = xr_bad.read_message(&m1).unwrap();
        let m2 = xr_bad.write_message(b"host-delegation").unwrap();
        assert!(matches!(
            xi_bad.read_message(&m2),
            Err(TransportError::Identity(IdentityError::InvalidFraming(_)))
        ));
    }

    // Noise_XX negative case 2: msg2 DelegationStatement with wrong X25519 pubkey rejected.
    {
        let mut wrong_pub_deleg = host_deleg.clone();
        wrong_pub_deleg.x25519_pub[31] ^= 0x01;
        wrong_pub_deleg.sig_der = host_ks.sign_p256_low_s(&wrong_pub_deleg.tbs_bytes()).unwrap();
        let mut xi_mm =
            E2eeNoiseHandshake::build_xx_initiator(CIPHER_AESGCM, &dev_priv, &xx_prologue).unwrap();
        let mut xr_mm =
            E2eeNoiseHandshake::build_xx_responder(CIPHER_AESGCM, &host_priv, &xx_prologue)
                .unwrap();
        let m1 = xi_mm.write_message(b"").unwrap();
        let _ = xr_mm.read_message(&m1).unwrap();
        let m2 = xr_mm
            .write_message(&wrong_pub_deleg.encode_wire().unwrap())
            .unwrap();
        let _ = xi_mm.read_message(&m2).unwrap();
        let m3 = xi_mm.write_message(&dev_deleg_wire).unwrap();
        let _ = xr_mm.read_message(&m3).unwrap();
        assert_eq!(
            xi_mm
                .finish_split(None, &host_device_id, &host_spki, cert_exp, now_unix)
                .err(),
            Some(TransportError::Identity(IdentityError::BindingMismatch))
        );
    }

    // Noise_XX negative case 3: msg2 DelegationStatement with forged signature rejected.
    {
        let mut forged_deleg = host_deleg.clone();
        if let Some(last) = forged_deleg.sig_der.last_mut() {
            *last ^= 0xAA;
        }
        let mut xi_fg =
            E2eeNoiseHandshake::build_xx_initiator(CIPHER_AESGCM, &dev_priv, &xx_prologue).unwrap();
        let mut xr_fg =
            E2eeNoiseHandshake::build_xx_responder(CIPHER_AESGCM, &host_priv, &xx_prologue)
                .unwrap();
        let m1 = xi_fg.write_message(b"").unwrap();
        let _ = xr_fg.read_message(&m1).unwrap();
        let m2 = xr_fg
            .write_message(&forged_deleg.encode_wire().unwrap())
            .unwrap();
        let _ = xi_fg.read_message(&m2).unwrap();
        let m3 = xi_fg.write_message(&dev_deleg_wire).unwrap();
        let _ = xr_fg.read_message(&m3).unwrap();
        assert_eq!(
            xi_fg
                .finish_split(None, &host_device_id, &host_spki, cert_exp, now_unix)
                .err(),
            Some(TransportError::Identity(IdentityError::InvalidSignature))
        );
    }
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

    // Free tier MUST block 0x07 RealtimeActuator by default!
    let act = ActuatorCmd {
        control_epoch: 1,
        cmd_seq: 1,
        send_ts_ms: 1000,
        ttl_ms: 50,
        payload: b"THR=0.5".to_vec(),
    };
    let act_err = ctrl.send_actuator(act.clone()).await.unwrap_err();
    assert_eq!(act_err.error_code(), ErrorCode::PolicyDenied);
    assert_eq!(
        ctrl.verified_policy()
            .enforce_channel(CHAN_REALTIME_ACTUATOR, false)
            .unwrap_err()
            .error_code(),
        ErrorCode::PolicyDenied
    );

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
    assert_eq!(stats.policy_denied_drops, 3);
    assert!(stats.tx_packets >= 8);

    // Authorized mission policy permits 0x07 RealtimeActuator AND enforces ActuatorReceiver safety checks.
    let ca = SoftwareDeviceKeyStore::generate();
    let ca_spki = ca.public_key_spki_der().unwrap();
    let tenant_id = [0x7E; 16];
    let drone_id = [0xD1; 16];
    let now_unix = 1_700_000_050;
    let uav_rules = TenantPolicyRules {
        allow_file_transfer: false,
        allow_clipboard: false,
        allow_file_clipboard: false,
        allow_tcp_tunnel: false,
        allow_terminal: false,
        allow_realtime_actuator: true,
        bw_cap_kbps: 6_000,
        exhaust_policy: QuotaExhaustPolicy::MissionLockedAlert,
    };
    let uav_policy = build_verified_policy(&ca, tenant_id, drone_id, &uav_rules, now_unix);
    let (uav_ctrl, mut uav_drone) = LoopbackTransportV2::pair_with_device_ids(
        CIPHER_AESGCM,
        [0xCC; 32],
        [0xDD; 32],
        uav_policy,
        [0xC1; 16],
        drone_id,
    );
    uav_drone.set_now_ms(1000);

    // Valid command accepted
    uav_ctrl.send_actuator(act.clone()).await.unwrap();
    assert_eq!(
        uav_drone.recv().await.unwrap(),
        TransportEvent::RealtimeActuator(act)
    );

    // Future skew > 50ms rejected
    uav_ctrl
        .send_actuator(ActuatorCmd {
            control_epoch: 1,
            cmd_seq: 2,
            send_ts_ms: 1051,
            ttl_ms: 50,
            payload: b"FUTURE".to_vec(),
        })
        .await
        .unwrap();
    assert!(uav_drone.recv().await.is_err());

    // TTL > 150ms and TTL == 0 rejected
    for bad_ttl in [0u16, 151u16] {
        uav_ctrl
            .send_actuator(ActuatorCmd {
                control_epoch: 1,
                cmd_seq: 3,
                send_ts_ms: 1000,
                ttl_ms: bad_ttl,
                payload: b"BADTTL".to_vec(),
            })
            .await
            .unwrap();
        assert!(uav_drone.recv().await.is_err());
    }

    // Non-monotonic cmd_seq rejected
    uav_ctrl
        .send_actuator(ActuatorCmd {
            control_epoch: 1,
            cmd_seq: 1,
            send_ts_ms: 1000,
            ttl_ms: 50,
            payload: b"REPLAY".to_vec(),
        })
        .await
        .unwrap();
    assert!(uav_drone.recv().await.is_err());

    // Unilateral control_epoch bump without CA-signed ControlPreemptToken rejected
    let epoch2_cmd = ActuatorCmd {
        control_epoch: 2,
        cmd_seq: 1,
        send_ts_ms: 1000,
        ttl_ms: 50,
        payload: b"PREEMPT".to_vec(),
    };
    uav_ctrl.send_actuator(epoch2_cmd.clone()).await.unwrap();
    assert!(uav_drone.recv().await.is_err());

    // After verifying CA-signed ControlPreemptToken, epoch 2 executes and old epoch 1 is rejected
    let mut preempt = ControlPreemptToken {
        tenant_id,
        drone_device_id: drone_id,
        operator_id: [0x99; 16],
        new_control_epoch: 2,
        iat_unix: now_unix - 10,
        exp_unix: now_unix + 300,
        sig_der: Vec::new(),
    };
    preempt.sig_der = ca.sign_p256_low_s(&preempt.tbs_bytes()).unwrap();
    assert_eq!(
        uav_drone
            .apply_actuator_preempt(&preempt, &ca_spki, now_unix)
            .unwrap(),
        2
    );
    uav_ctrl.send_actuator(epoch2_cmd.clone()).await.unwrap();
    assert_eq!(
        uav_drone.recv().await.unwrap(),
        TransportEvent::RealtimeActuator(epoch2_cmd)
    );
    uav_ctrl
        .send_actuator(ActuatorCmd {
            control_epoch: 1,
            cmd_seq: 99,
            send_ts_ms: 1000,
            ttl_ms: 50,
            payload: b"OLD".to_vec(),
        })
        .await
        .unwrap();
    assert!(uav_drone.recv().await.is_err());
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

    // Bypass resistance: Authorization: Bearer, JSON secrets, punctuated IPs, Windows user paths.
    let auth_line = "req Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig from (1.2.3.4), next 5.6.7.8,";
    let auth_clean = sanitize_log_line(auth_line);
    assert!(auth_clean.contains("Authorization: [REDACTED]"), "{auth_clean}");
    assert!(auth_clean.contains("(1.2.3.x),"), "{auth_clean}");
    assert!(auth_clean.contains("5.6.7.x,"), "{auth_clean}");
    assert!(!auth_clean.contains("eyJhbGciOiJIUzI1NiJ9"), "{auth_clean}");
    assert!(!auth_clean.contains("Bearer"), "{auth_clean}");
    assert!(!auth_clean.contains("1.2.3.4"), "{auth_clean}");
    assert!(!auth_clean.contains("5.6.7.8"), "{auth_clean}");

    let json_line = r#"{"password":"my\"p@ssw0rd","token": "tok_999","secret":"shh","authorization":"Bearer jwt_secret","path":"C:\\Users\\bob\\AppData\\id.key","peer":"10.20.30.40"}"#;
    let json_clean = sanitize_log_line(json_line);
    assert!(json_clean.contains(r#""password":"[REDACTED]""#), "{json_clean}");
    assert!(json_clean.contains(r#""token": "[REDACTED]""#), "{json_clean}");
    assert!(json_clean.contains(r#""secret":"[REDACTED]""#), "{json_clean}");
    assert!(json_clean.contains(r#""authorization":"[REDACTED]""#), "{json_clean}");
    assert!(json_clean.contains(r#""path":"[REDACTED_PATH]""#), "{json_clean}");
    assert!(json_clean.contains(r#""peer":"10.20.30.x""#), "{json_clean}");
    for leaked in ["p@ssw0rd", "tok_999", "shh", "jwt_secret", "bob", "10.20.30.40"] {
        assert!(!json_clean.contains(leaked), "leaked {leaked} in {json_clean}");
    }

    let win_line = r"open C:\Users\alice\Documents\ZeroDesk\key.der and D:/Users/carol/cfg.json";
    let win_clean = sanitize_log_line(win_line);
    assert_eq!(win_clean, "open [REDACTED_PATH] and [REDACTED_PATH]");

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

    let ca = SoftwareDeviceKeyStore::generate();
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
    let uav_policy = build_verified_policy(&ca, [0x7E; 16], [0x22; 16], &uav_rules, 1_700_000_100);
    assert!(!uav_policy.allow_file_clipboard);
    assert_eq!(uav_policy.on_quota_exhausted(), (6_000, true));
    assert!(matches!(
        uav_policy.enforce_tcp_tunnel(),
        Err(TransportError::PolicyDenied(_))
    ));
}

#[test]
fn p2_hardening_bounds_lru_l3_flags_and_cache_priority_protection() {
    // 1. StreamSeqDedup hard cap (<= 4096).
    let mut dedup = StreamSeqDedup::default();
    for seq in 0..(STREAM_SEQ_DEDUP_CAPACITY as u32 + 500) {
        assert!(dedup.mark_if_new(0x01, seq));
    }
    assert_eq!(dedup.len(), STREAM_SEQ_DEDUP_CAPACITY);

    // 2. VideoReassembler hard cap (<= 64 partials) and clamped max_age_ms (<= 500ms).
    let mut vr = VideoReassembler::default();
    for fid in 1..=(VIDEO_REASSEMBLER_MAX_PARTIALS as u32 + 20) {
        let slice = VideoSlice {
            codec_id: 1,
            frame_id: fid,
            ref_frame_id: 0,
            ltr_slot: 0,
            is_idr: false,
            is_ref: true,
            max_age_ms: 60_000, // hostile huge max_age_ms MUST be clamped to <= 500ms
            slice_idx: 0,
            slice_cnt: 2,
            data: vec![0xAA; 16],
        };
        assert!(vr.push_slice(slice, 1000).is_none());
    }
    assert_eq!(vr.partial_count(), VIDEO_REASSEMBLER_MAX_PARTIALS);
    // At +501ms, clamped partials expire even though sender requested 60_000ms.
    let expired = vr.evict_expired(1000 + VIDEO_REASSEMBLER_MAX_AGE_MS as u64 + 1);
    assert_eq!(expired.len(), VIDEO_REASSEMBLER_MAX_PARTIALS);
    assert_eq!(vr.partial_count(), 0);

    // 3. L3Header MUST reject non-zero frame_flags including low 2 reserved bits.
    for bad_flag in [0x01u8, 0x02, 0x03, 0x04, 0x80] {
        let hdr = L3Header {
            e2ee_epoch: 1,
            pkt_seq: 0,
            send_ts_us_mod: 0,
            chan_id: 1,
            frame_flags: bad_flag,
        };
        assert!(hdr.encode().is_err(), "encode accepted flag {bad_flag:#x}");
        let mut raw = [0u8; 16];
        raw[12] = 1;
        raw[13] = bad_flag;
        assert!(L3Header::decode(&raw).is_err(), "decode accepted flag {bad_flag:#x}");
    }

    // 4. LegCiphertextCache 512KB full cache: p3 MUST NEVER evict p0, AND 150ms rekey grace is reachable.
    let route_cid = [0x11; 8];
    let hs_hash = [0x22; 32];
    let mut epoch_state = AccessEpochState::new(
        route_cid,
        hs_hash,
        TRANSPORT_DATAGRAM,
        DIR_EDGE_TO_CLIENT,
        2,
        20,
    )
    .unwrap();
    let mut cache = LegCiphertextCache::new(2);
    let payload_1k = vec![0x55; 1024 - 28]; // 1024B total wire size each
    let num_p0 = (LEG_CACHE_MAX_BYTES / 1024) as u32;
    for seq in 0..num_p0 {
        let hdr = AccessHeaderV11 {
            flags: AccessFlags {
                pp: 0,
                discardable: false,
                frame_end: false,
                is_ctrl_edge: false,
                dir_edge_to_client: true,
                rtx: false,
            },
            route_cid,
            access_epoch: 2,
            leg_seq: seq,
            mac_64: [0; 8],
        };
        cache.record_original(&hdr, payload_1k.clone(), 1000);
    }
    assert_eq!(cache.total_bytes(), LEG_CACHE_MAX_BYTES);

    // Incoming p3 packet MUST NOT evict any p0 packet.
    let p3_hdr = AccessHeaderV11 {
        flags: AccessFlags {
            pp: 3,
            discardable: false,
            frame_end: false,
            is_ctrl_edge: false,
            dir_edge_to_client: true,
            rtx: false,
        },
        route_cid,
        access_epoch: 2,
        leg_seq: 9999,
        mac_64: [0; 8],
    };
    cache.record_original(&p3_hdr, payload_1k.clone(), 1010);
    assert!(!cache.contains_seq(9999));
    assert!(cache.contains_seq(0));
    assert_eq!(cache.len(), num_p0 as usize);

    // Soft rekey 150ms grace branch test: packet inserted mid-grace (t=2070, epoch 2) after
    // soft rekey at t=2000 (epoch 3) is NOT TTL-evicted at t=2150/2151 (age 80/81ms <= 150ms),
    // yet accepted at t=2150 (rekey+150ms) and rejected at t=2151 (rekey+151ms)!
    let mut rekey_cache = LegCiphertextCache::new(2);
    rekey_cache.on_soft_rekey(3, 2000);
    epoch_state.advance_epoch(3, 2000).unwrap();
    let old_epoch_hdr = AccessHeaderV11 {
        flags: AccessFlags {
            pp: 0,
            discardable: false,
            frame_end: false,
            is_ctrl_edge: false,
            dir_edge_to_client: true,
            rtx: false,
        },
        route_cid,
        access_epoch: 2,
        leg_seq: 42,
        mac_64: [0; 8],
    };
    rekey_cache.record_original(&old_epoch_hdr, vec![0x77; 64], 2070);
    let rtx_ok = rekey_cache.handle_leg_nack(42, 1, 2150, 10, None, &epoch_state);
    assert_eq!(rtx_ok.len(), 1);
    let rtx_decoded = AccessHeaderV11::decode(&rtx_ok[0]).unwrap();
    assert!(rtx_decoded.flags.rtx);
    assert!(!rtx_decoded.eligible_for_rtt_sample());
    assert_eq!(rtx_decoded.access_epoch, 2);
    // Receiver verifies the recomputed epoch-2 MAC cleanly!
    epoch_state.verify_udp_packet(&rtx_ok[0], 2150).unwrap();
    // 1ms past 150ms rekey grace: entry is STILL in cache (age 81ms <= 150ms TTL), rejected solely by rekey grace!
    assert!(rekey_cache.contains_seq(42));
    assert!(rekey_cache
        .handle_leg_nack(42, 1, 2151, 0, None, &epoch_state)
        .is_empty());

    // 5. ZeroRttGuard true LRU recency + out-of-order expiry purge.
    let dev = SoftwareDeviceKeyStore::generate();
    let spki = dev.public_key_spki_der().unwrap();
    let mut rot = X25519StaticKeyRotator::new([0x33; 16], false, 0);
    let deleg = rot.ensure_current(&dev, 1000, 3000).unwrap().delegation.clone();
    let mut guard = ZeroRttGuard::new(2);
    let s1 = [1u8; 16];
    let s2 = [2u8; 16];
    let s3 = [3u8; 16];
    assert!(guard
        .evaluate_0rtt(&deleg, &spki, 3000, s1, 0, 2500, 1000)
        .unwrap()
        .accepted);
    assert!(guard
        .evaluate_0rtt(&deleg, &spki, 3000, s2, 0, 1500, 1000)
        .unwrap()
        .accepted);
    assert_eq!(guard.lru_session_id(), Some(s1));
    // Replaying s1 refreshes its LRU recency so s2 becomes the LRU entry.
    assert!(!guard
        .evaluate_0rtt(&deleg, &spki, 3000, s1, 0, 2500, 1005)
        .unwrap()
        .accepted);
    assert_eq!(guard.lru_session_id(), Some(s2));
    // At t=1600, s2 (exp=1500) is purged even though s1 (exp=2500) was inserted first,
    // allowing s3 to be accepted without false cache-full fallback!
    assert!(guard
        .evaluate_0rtt(&deleg, &spki, 3000, s3, 0, 2500, 1600)
        .unwrap()
        .accepted);
    assert_eq!(guard.len(), 2);
}
