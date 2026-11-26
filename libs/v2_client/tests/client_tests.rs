use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::ServerConfig;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use snow::{params::NoiseParams, Builder};
use std::{
    io::{Read, Write},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
};
use tokio_rustls::TlsAcceptor;
use v2_client::{
    access_ctrl::{
        build_access_prologue, read_ctrl_frame, write_ctrl_frame, CTRL_OP_LEASE_RENEW_REQ,
        CTRL_OP_LEASE_RENEW_RESP, CTRL_OP_REBIND_REQ, CTRL_OP_REBIND_RESP, CTRL_OP_RELAY_BIND_REQ,
        CTRL_OP_RELAY_BIND_RESP,
    },
    build_client_meter_tbs, build_dev_pop_tbs, build_lease_renew_tbs, build_tls_client_config,
    decode_survival_rs64_shards, encode_survival_rs64_shards, AccessControlTunnel, AccessKeys,
    ClientError, ControlPlaneClient, DualTls443Client, HeartbeatMsg, LegGapTracker, PresenceState,
    RelayTicketWire, SignalingClient, SignalingConnectAccept, SignalingConnectReq,
    SignalingMsgKind, StreamRecvEvent, Tls443StreamRole, UdpAccessLink, UdpE2eeSession,
    V2LoopbackBridge, V2SessionMux, DEFAULT_BRIDGE_CHANNEL,
};
use v2_identity::{
    verify_p256_low_s, ControlPreemptToken, DeviceCert, DeviceKeyStore, SoftwareDeviceKeyStore,
    TenantPolicyBlob,
};
use v2_transport::{
    compute_stream_mac64, derive_stream_role_key, seal_stream_v11, seal_udp_v11, verify_mac64_ct,
    AccessEpochState, AccessFlags, AccessHeaderV11, ActuatorCmd, EdgeCtrlFrame, QuotaExhaustPolicy,
    StreamFrameParser, TenantPolicyRules, VerifiedTenantPolicy,
    BW_EVENT_DROP_ACTIVE, BW_EVENT_PAUSE_FILE_CHUNK, CHAN_CLIPBOARD, CHAN_INPUT_HID,
    DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT, TRANSPORT_DATAGRAM,
};

fn generate_test_ca_and_server_tls() -> (Vec<u8>, Arc<ServerConfig>) {
    let mut ca_params = CertificateParams::default();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "ZeroDesk Test CA");
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let mut srv_params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    srv_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    let srv_key = KeyPair::generate().unwrap();
    let srv_cert = srv_params
        .signed_by(&srv_key, &ca_cert, &ca_key)
        .unwrap();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(srv_cert.der().to_vec())],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(srv_key.serialize_der())),
        )
        .unwrap();

    (ca_cert.der().to_vec(), Arc::new(server_cfg))
}

#[tokio::test]
async fn control_plane_tls_fail_closed_and_https_signing_roundtrip() {
    // 1. Fail-closed on empty or corrupt custom CA DER
    let tmp = std::env::temp_dir();
    let empty_ca = tmp.join(format!("zd-empty-ca-{}.der", std::process::id()));
    std::fs::write(&empty_ca, b"").unwrap();
    assert!(build_tls_client_config(Some(&empty_ca)).is_err());
    let _ = std::fs::remove_file(&empty_ca);

    let bad_ca = tmp.join(format!("zd-bad-ca-{}.der", std::process::id()));
    std::fs::write(&bad_ca, b"not-a-valid-der-cert").unwrap();
    assert!(build_tls_client_config(Some(&bad_ca)).is_err());
    let _ = std::fs::remove_file(&bad_ca);

    // 2. Non-loopback plaintext http:// MUST be rejected
    assert!(ControlPlaneClient::new("http://203.0.113.10:8080", None).is_err());

    // 3. Real HTTPS server with custom CA DER verifying low-S P-256 signatures
    let (ca_der, server_cfg) = generate_test_ca_and_server_tls();
    let ca_path = tmp.join(format!("zd-valid-ca-{}.der", std::process::id()));
    std::fs::write(&ca_path, &ca_der).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_cfg);

    let dev_ks = SoftwareDeviceKeyStore::generate();
    let dev_spki = dev_ks.public_key_spki_der().unwrap();
    let dev_id = [0x42u8; 16];
    let sess_id = [0x77u8; 16];
    let route_cid = [0x11u8; 8];
    let pop_id = *b"edge-a01";
    let dev_spki_srv = dev_spki.clone();

    let srv = tokio::spawn(async move {
        for _ in 0..4 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut raw = Vec::new();
            let mut chunk = [0u8; 4096];
            let body_start = loop {
                let n = tls.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&chunk[..n]);
                if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                    break pos + 4;
                }
            };
            let head_str = String::from_utf8_lossy(&raw[..body_start]).into_owned();
            let content_len: usize = head_str
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    if k.trim().eq_ignore_ascii_case("content-length") {
                        v.trim().parse().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            while raw.len() < body_start + content_len {
                let n = tls.read(&mut chunk).await.unwrap();
                assert!(n > 0);
                raw.extend_from_slice(&chunk[..n]);
            }
            let first_line = head_str.lines().next().unwrap_or("");
            let body_str = std::str::from_utf8(&raw[body_start..body_start + content_len]).unwrap();

            let resp_body = if first_line.starts_with("GET /healthz") {
                r#"{"status":"ok"}"#.to_string()
            } else if first_line.starts_with("POST /v2/devices/register") {
                let v: serde_json::Value = serde_json::from_str(body_str).unwrap();
                let ts = v["timestamp_unix"].as_u64().unwrap();
                let sig = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    v["pop_sig_der_b64"].as_str().unwrap(),
                )
                .unwrap();
                let tbs = build_dev_pop_tbs(&dev_id, &dev_spki_srv, ts);
                verify_p256_low_s(&dev_spki_srv, &tbs, &sig).unwrap();
                r#"{"cert_id_hex":"0102030405060708090a0b0c0d0e0f10","key_epoch":1,"iat_unix":100,"exp_unix":20000,"tbs_b64":"AQID","sig_der_b64":"BAUG"}"#.to_string()
            } else if first_line.starts_with("POST /v2/leases/renew") {
                let v: serde_json::Value = serde_json::from_str(body_str).unwrap();
                let ts = v["timestamp_unix"].as_u64().unwrap();
                let last_seq = v["last_lease_seq"].as_u64().unwrap();
                let sig = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    v["device_sig_der_b64"].as_str().unwrap(),
                )
                .unwrap();
                let tbs = build_lease_renew_tbs(&sess_id, &route_cid, &pop_id, last_seq, ts);
                verify_p256_low_s(&dev_spki_srv, &tbs, &sig).unwrap();
                let mac_b64 = base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    [0xABu8; 32],
                );
                format!(
                    r#"{{"key_id":1,"ticket_body_b64":"AQID","ticket_mac_b64":"{mac_b64}","lease_seq":2,"session_start_unix":1700000000,"byte_budget":1000000,"bw_cap_kbps":10000,"exhaust_policy":0,"quota_exhausted":false,"mission_rth_alert":false,"next_renew_sec":30,"server_unix":{ts},"quota_remaining_bytes":999999,"renew_at_unix":{},"migrated":false}}"#,
                    ts + 30
                )
            } else if first_line.starts_with("POST /v2/metering/client-report") {
                let v: serde_json::Value = serde_json::from_str(body_str).unwrap();
                let ts = v["timestamp_unix"].as_u64().unwrap();
                let sig = base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    v["device_sig_der_b64"].as_str().unwrap(),
                )
                .unwrap();
                let tbs = build_client_meter_tbs(&dev_id, &sess_id, 1700000000, 0, 4096, ts);
                verify_p256_low_s(&dev_spki_srv, &tbs, &sig).unwrap();
                r#"{"accepted":1,"upgraded":0,"deduplicated":0,"rejected":0,"total_billed":4096,"results":[]}"#.to_string()
            } else {
                panic!("unexpected path: {first_line}");
            };

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                resp_body.len(),
                resp_body
            );
            tls.write_all(resp.as_bytes()).await.unwrap();
            tls.shutdown().await.unwrap();
        }
    });

    let cp = ControlPlaneClient::new(&format!("https://{addr}"), Some(&ca_path)).unwrap();
    cp.healthz().await.unwrap();
    let reg = cp
        .register_device(&dev_ks, &dev_id, "tok", 0x3FFF, "local", None, None)
        .await
        .unwrap();
    assert_eq!(reg.key_epoch, 1);

    let lease = cp
        .renew_lease(
            &dev_ks,
            None,
            &sess_id,
            &route_cid,
            &pop_id,
            &dev_id,
            &dev_id,
            1,
            4096,
            1,
        )
        .await
        .unwrap();
    assert_eq!(lease.lease_seq, 2);
    let ticket = lease.to_relay_ticket().unwrap();
    assert_eq!(ticket.mac, [0xABu8; 32]);

    let meter = cp
        .report_metering_fallback(&dev_ks, &dev_id, &sess_id, "edge-a01", 1700000000, 0, 4096)
        .await
        .unwrap();
    assert_eq!(meter.accepted, 1);
    assert_eq!(meter.rejected, 0);

    srv.await.unwrap();
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn signaling_tcp_probe_and_proto_wire_roundtrip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let srv = tokio::spawn(async move {
        // 1. Accept TCP reachability probe
        let (_probe_sock, _) = listener.accept().await.unwrap();
        // 2. Accept framed ConnectReq and echo ConnectAccept
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut len_buf = [0u8; 4];
        sock.read_exact(&mut len_buf).await.unwrap();
        let total = u32::from_be_bytes(len_buf) as usize;
        let mut body = vec![0u8; total];
        sock.read_exact(&mut body).await.unwrap();
        assert_eq!(body[0], SignalingMsgKind::ConnectReq as u8);
        let req = SignalingConnectReq::decode_pb(&body[1..]).unwrap();
        let acc = SignalingConnectAccept {
            session_id: req.session_id,
            error_code: 0,
            negotiated_l3_mtu: req.proposed_l3_mtu,
            negotiated_cap_bits: req.cap_bits,
            negotiated_cipher_suite: req.preferred_cipher_suite,
            ice_candidates: vec!["127.0.0.1:4430".into()],
        };
        let frame = v2_client::encode_signaling_frame(SignalingMsgKind::ConnectAccept, &acc.encode_pb())
            .unwrap();
        sock.write_all(&frame).await.unwrap();
        sock.flush().await.unwrap();
    });

    let client = SignalingClient::new(addr.to_string());
    let probe = client.probe_tcp().await.unwrap();
    assert_eq!(probe.addr, addr.to_string());

    let hb = HeartbeatMsg {
        device_id: [0x11; 16],
        presence: PresenceState::Online,
        client_unix: 1_700_000_000,
        active_pop_id: Some(*b"edge-a01"),
        rtt_ms: 12,
    };
    assert_eq!(HeartbeatMsg::decode_pb(&hb.encode_pb()).unwrap(), hb);

    let req = SignalingConnectReq {
        session_id: [0x99; 16],
        controller_device_id: [0x11; 16],
        controlled_device_id: [0x22; 16],
        proposed_l3_mtu: 1200,
        cap_bits: 0x1_7001,
        preferred_cipher_suite: 1,
        requested_exhaust_policy: 0,
    };
    let (resp_kind, resp_payload) = client
        .exchange_frame(SignalingMsgKind::ConnectReq, &req.encode_pb())
        .await
        .unwrap();
    assert_eq!(resp_kind, SignalingMsgKind::ConnectAccept);
    let acc = SignalingConnectAccept::decode_pb(&resp_payload).unwrap();
    assert_eq!(acc.session_id, [0x99; 16]);
    assert_eq!(acc.negotiated_l3_mtu, 1200);
    srv.await.unwrap();
}

#[tokio::test]
async fn access_ctrl_noise_ik_bind_renew_rebind_and_bad_prologue_reject() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let params: NoiseParams = "Noise_IK_25519_AESGCM_SHA256".parse().unwrap();
    let edge_kp = Builder::new(params.clone()).generate_keypair().unwrap();
    let cli_kp = Builder::new(params.clone()).generate_keypair().unwrap();
    let edge_pub: [u8; 32] = edge_kp.public.clone().try_into().unwrap();
    let cli_priv: [u8; 32] = cli_kp.private.clone().try_into().unwrap();

    let pop_id = *b"edge-a01";
    let cert_hash = [0x5Au8; 32];
    let prologue = build_access_prologue(&pop_id, &cert_hash);
    let route_cid = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

    let srv = tokio::spawn(async move {
        // Conn 1: valid prologue + bind + renew + rebind
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut hs = Builder::new(params.clone())
            .local_private_key(&edge_kp.private)
            .unwrap()
            .prologue(&prologue)
            .unwrap()
            .build_responder()
            .unwrap();
        let m1 = read_ctrl_frame(&mut sock).await.unwrap();
        let mut pt = vec![0u8; m1.len() + 64];
        hs.read_message(&m1, &mut pt).unwrap();
        let mut m2 = vec![0u8; 256];
        let n2 = hs.write_message(&[], &mut m2).unwrap();
        write_ctrl_frame(&mut sock, &m2[..n2]).await.unwrap();
        let mut srv_hash = [0u8; 32];
        srv_hash.copy_from_slice(hs.get_handshake_hash());
        let mut tr = hs.into_transport_mode().unwrap();

        for expected_op in [CTRL_OP_RELAY_BIND_REQ, CTRL_OP_LEASE_RENEW_REQ, CTRL_OP_REBIND_REQ] {
            let ct = read_ctrl_frame(&mut sock).await.unwrap();
            let mut req = vec![0u8; ct.len() + 64];
            let n = tr.read_message(&ct, &mut req).unwrap();
            assert_eq!(req[0], expected_op);
            let mut resp = Vec::new();
            match expected_op {
                CTRL_OP_RELAY_BIND_REQ => {
                    resp.push(CTRL_OP_RELAY_BIND_RESP);
                    resp.extend_from_slice(&0u16.to_be_bytes());
                    resp.extend_from_slice(&route_cid);
                    resp.extend_from_slice(&1_700_000_000u64.to_be_bytes());
                    resp.extend_from_slice(&0u32.to_be_bytes());
                    resp.extend_from_slice(&2000u32.to_be_bytes());
                    resp.extend_from_slice(&1200u16.to_be_bytes());
                }
                CTRL_OP_LEASE_RENEW_REQ => {
                    resp.push(CTRL_OP_LEASE_RENEW_RESP);
                    resp.extend_from_slice(&0u16.to_be_bytes());
                    resp.extend_from_slice(&route_cid);
                    resp.extend_from_slice(&1_700_000_000u64.to_be_bytes());
                }
                CTRL_OP_REBIND_REQ => {
                    assert_eq!(&req[1..n], &route_cid);
                    resp.push(CTRL_OP_REBIND_RESP);
                    resp.extend_from_slice(&0u16.to_be_bytes());
                    resp.extend_from_slice(&route_cid);
                }
                _ => unreachable!(),
            }
            let mut out = vec![0u8; resp.len() + 64];
            let cn = tr.write_message(&resp, &mut out).unwrap();
            write_ctrl_frame(&mut sock, &out[..cn]).await.unwrap();
        }

        // Conn 2: wrong prologue MUST fail decryption on responder
        let (mut sock2, _) = listener.accept().await.unwrap();
        let mut hs2 = Builder::new(params)
            .local_private_key(&edge_kp.private)
            .unwrap()
            .prologue(&prologue)
            .unwrap()
            .build_responder()
            .unwrap();
        let m1_bad = read_ctrl_frame(&mut sock2).await.unwrap();
        let mut pt2 = vec![0u8; m1_bad.len() + 64];
        assert!(hs2.read_message(&m1_bad, &mut pt2).is_err());
        srv_hash
    });

    let mut tunnel = AccessControlTunnel::connect(
        &addr.to_string(),
        &cli_priv,
        &edge_pub,
        &pop_id,
        &cert_hash,
        Duration::from_secs(3),
    )
    .await
    .unwrap();
    let cli_hash = *tunnel.session_access_secret();

    let ticket = RelayTicketWire {
        key_id: 1,
        body: vec![1, 2, 3, 4],
        mac: [0xCC; 32],
    };
    let (bind_resp, keys) = tunnel
        .relay_bind(&ticket, &[0x99; 8], b"edge-b02")
        .await
        .unwrap();
    assert_eq!(bind_resp.route_cid, route_cid);
    assert_eq!(keys.route_cid, route_cid);

    let renew_resp = tunnel.lease_renew(&ticket).await.unwrap();
    assert_eq!(renew_resp.route_cid, route_cid);

    let rebind_resp = tunnel.rebind(&route_cid).await.unwrap();
    assert_eq!(rebind_resp.route_cid, route_cid);

    // Wrong cert_hash fails handshake
    let mut bad_hash = cert_hash;
    bad_hash[0] ^= 0xFF;
    let bad_res = AccessControlTunnel::connect(
        &addr.to_string(),
        &cli_priv,
        &edge_pub,
        &pop_id,
        &bad_hash,
        Duration::from_secs(2),
    )
    .await;
    assert!(bad_res.is_err());

    let srv_hash = srv.await.unwrap();
    assert_eq!(cli_hash, srv_hash);
}

#[tokio::test]
async fn udp_ping_retry_leg_nack_rtx_and_rs64_survival() {
    // 1. Gap tracker: opens gap on d=0, ignores d=1
    let mut tracker = LegGapTracker::new();
    assert_eq!(tracker.on_recv(1, false), None);
    assert_eq!(tracker.on_recv(3, true), None); // discardable skips NACK emission
    assert_eq!(tracker.on_recv(5, false), Some((2, 0b101))); // missing 2 and 4
    assert_eq!(tracker.on_recv(2, false), None);
    assert_eq!(tracker.build_nack(), Some((4, 0b1)));

    // 2. RS(6,4) Survival Mode 4-erasure recovery
    let orig: Vec<Vec<u8>> = (0..6).map(|i| vec![0x30 + i as u8; 100 + i * 17]).collect();
    let shards = encode_survival_rs64_shards(7, &orig).unwrap();
    assert_eq!(shards.len(), 10);
    let surviving: Vec<Vec<u8>> = shards
        .into_iter()
        .enumerate()
        .filter(|(idx, _)| ![0, 3, 5, 9].contains(idx))
        .map(|(_, s)| s)
        .collect();
    assert_eq!(decode_survival_rs64_shards(7, &surviving).unwrap(), orig);

    // 3. Simulated UDP Edge: drop 1st Ping, reply 2nd Ping with Pong, then send LEG_NACK and verify rtx=1
    let edge_sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = edge_sock.local_addr().unwrap();
    let route_cid = [0xAA; 8];
    let hs_hash = [0x55; 32];
    let keys = AccessKeys::derive(route_cid, hs_hash, 0).unwrap();

    let edge_keys = keys.clone();
    let edge_task = tokio::spawn(async move {
        let mut rx_state = AccessEpochState::new(
            route_cid,
            hs_hash,
            TRANSPORT_DATAGRAM,
            DIR_CLIENT_TO_EDGE,
            0,
            20,
        )
        .unwrap();
        let mut buf = [0u8; 2048];
        // Drop first Ping to test retry
        let _ = edge_sock.recv_from(&mut buf).await.unwrap();

        // Reply to second Ping
        let (n, peer) = edge_sock.recv_from(&mut buf).await.unwrap();
        let (hdr, body) = rx_state.verify_udp_packet(&buf[..n], 100).unwrap();
        assert!(hdr.flags.is_ctrl_edge);
        let EdgeCtrlFrame::Ping { ts_us } = EdgeCtrlFrame::decode(body).unwrap() else {
            panic!("expected Ping");
        };
        let pong = EdgeCtrlFrame::Pong { ts_us }.encode();
        let pong_hdr = AccessHeaderV11 {
            flags: AccessFlags {
                pp: 0,
                discardable: false,
                frame_end: false,
                is_ctrl_edge: true,
                dir_edge_to_client: true,
                rtx: false,
            },
            route_cid,
            access_epoch: 0,
            leg_seq: 0,
            mac_64: [0; 8],
        };
        let wire_pong = seal_udp_v11(&edge_keys.udp_key_e2c, pong_hdr, &pong).unwrap();
        edge_sock.send_to(&wire_pong, peer).await.unwrap();

        // Receive one data packet and immediately send LEG_NACK for its leg_seq
        let (n2, peer2) = edge_sock.recv_from(&mut buf).await.unwrap();
        let (dhdr, dpayload) = rx_state.verify_udp_packet(&buf[..n2], 120).unwrap();
        assert!(!dhdr.flags.rtx);
        let dpayload_orig = dpayload.to_vec();
        let nack = EdgeCtrlFrame::LegNack {
            base_leg_seq: dhdr.leg_seq,
            loss_bitmap: 1,
        }
        .encode();
        let nack_hdr = AccessHeaderV11 {
            flags: AccessFlags {
                pp: 0,
                discardable: false,
                frame_end: false,
                is_ctrl_edge: true,
                dir_edge_to_client: true,
                rtx: false,
            },
            route_cid,
            access_epoch: 0,
            leg_seq: 0,
            mac_64: [0; 8],
        };
        let wire_nack = seal_udp_v11(&edge_keys.udp_key_e2c, nack_hdr, &nack).unwrap();
        edge_sock.send_to(&wire_nack, peer2).await.unwrap();

        // Expect retransmitted packet with flags.rtx == true and identical payload
        let (n3, _) = edge_sock.recv_from(&mut buf).await.unwrap();
        let (rhdr, rpayload) = rx_state.verify_udp_packet(&buf[..n3], 130).unwrap();
        assert!(rhdr.flags.rtx);
        assert!(!rhdr.eligible_for_rtt_sample());
        assert_eq!(rhdr.leg_seq, dhdr.leg_seq);
        assert_eq!(rpayload, dpayload_orig.as_slice());
    });

    let mut link = UdpAccessLink::connect(&edge_addr.to_string(), &keys, 10_000)
        .await
        .unwrap();
    let rtt_us = link
        .ping_with_retry(3, Duration::from_millis(200))
        .await
        .unwrap();
    assert!(rtt_us < 1_000_000);

    let _seq = link.send_l3_packet(0, false, &[0xEEu8; 48]).await.unwrap();
    let _ev = link.recv_packet(Duration::from_secs(2)).await.unwrap();
    assert_eq!(link.stats.leg_nacks_recv, 1);
    assert_eq!(link.stats.rtx_packets_sent, 1);

    edge_task.await.unwrap();
}

#[tokio::test]
async fn tls443_dual_streams_role_keys_bw_hint_and_80ms_hol_discard() {
    let (ca_der, server_cfg) = generate_test_ca_and_server_tls();
    let ca_path = std::env::temp_dir().join(format!("zd-tls443-ca-{}.der", std::process::id()));
    std::fs::write(&ca_path, &ca_der).unwrap();

    let route_cid = [0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44];
    let hs_hash = [0x77u8; 32];
    let keys = AccessKeys::derive(route_cid, hs_hash, 0).unwrap();

    // Role isolation check
    let k_rt = derive_stream_role_key(&route_cid, &hs_hash, DIR_CLIENT_TO_EDGE, 0, 1).unwrap();
    let k_bk = derive_stream_role_key(&route_cid, &hs_hash, DIR_CLIENT_TO_EDGE, 0, 2).unwrap();
    assert_ne!(k_rt, k_bk);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_cfg);

    let srv = tokio::spawn(async move {
        for expected_role in [Tls443StreamRole::Realtime.as_u8(), Tls443StreamRole::Bulk.as_u8()] {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut tls = acceptor.accept(tcp).await.unwrap();
            let mut preface = [0u8; 9];
            tls.read_exact(&mut preface).await.unwrap();
            assert_eq!(preface[0], expected_role);
            assert_eq!(&preface[1..9], &route_cid);

            let rx_key =
                derive_stream_role_key(&route_cid, &hs_hash, DIR_CLIENT_TO_EDGE, 0, expected_role)
                    .unwrap();
            let tx_key =
                derive_stream_role_key(&route_cid, &hs_hash, DIR_EDGE_TO_CLIENT, 0, expected_role)
                    .unwrap();

            let mut parser = StreamFrameParser::new();
            let mut buf = [0u8; 2048];
            let ping_frame = loop {
                if let Some(f) = parser.next_frame().unwrap() {
                    break f;
                }
                let n = tls.read(&mut buf).await.unwrap();
                parser.feed(&buf[..n]);
            };
            let exp_mac = compute_stream_mac64(
                &rx_key,
                &ping_frame.header.encode_mac_zero(),
                ping_frame.frame_id,
                &ping_frame.payload,
            )
            .unwrap();
            verify_mac64_ct(&exp_mac, &ping_frame.header.mac_64).unwrap();
            let EdgeCtrlFrame::Ping { ts_us } = EdgeCtrlFrame::decode(&ping_frame.payload).unwrap()
            else {
                panic!("expected first-frame Ping");
            };

            let pong_hdr = AccessHeaderV11 {
                flags: AccessFlags {
                    pp: 0,
                    discardable: false,
                    frame_end: true,
                    is_ctrl_edge: true,
                    dir_edge_to_client: true,
                    rtx: false,
                },
                route_cid,
                access_epoch: 0,
                leg_seq: 0,
                mac_64: [0; 8],
            };
            let wire_pong =
                seal_stream_v11(&tx_key, pong_hdr, 0, &EdgeCtrlFrame::Pong { ts_us }.encode())
                    .unwrap();
            tls.write_all(&wire_pong).await.unwrap();

            if expected_role == Tls443StreamRole::Realtime.as_u8() {
                // Send EdgeCtrl::BwHint with DROP_ACTIVE | PAUSE_FILE_CHUNK
                let hint = EdgeCtrlFrame::BwHint {
                    cap_kbps: 2000,
                    queue_delay_ms: 95,
                    report_age_ms: 0,
                    bottleneck_leg: 1,
                    event_flags: BW_EVENT_DROP_ACTIVE | BW_EVENT_PAUSE_FILE_CHUNK,
                };
                let wire_hint = seal_stream_v11(&tx_key, pong_hdr, 0, &hint.encode()).unwrap();
                tls.write_all(&wire_hint).await.unwrap();
                tls.flush().await.unwrap();
                // Keep socket open briefly for client to read BwHint
                tokio::time::sleep(Duration::from_millis(150)).await;
            } else {
                tls.flush().await.unwrap();
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
        }
    });

    let mut dual =
        DualTls443Client::connect(&addr.to_string(), &keys, Some(&ca_path), 10_000)
            .await
            .unwrap();

    // Receive BwHint on Realtime stream -> pauses Bulk p3
    let ev = dual.realtime.recv_frame(Duration::from_secs(2)).await.unwrap();
    assert!(matches!(ev, StreamRecvEvent::EdgeCtrl(EdgeCtrlFrame::BwHint { .. })));
    assert!(dual.realtime.bulk_paused);
    assert!(dual.send_l3(3, false, true, 0, &[0x11; 64]).await.is_err());

    // Enqueue non-video (fid=0), complete discardable (fid=100), and reference (fid=102)
    dual.realtime
        .enqueue_l3_slice(0, false, true, 0, &[0xAA; 48], 1000)
        .unwrap();
    dual.realtime
        .enqueue_l3_slice(2, true, false, 100, &[0xBB; 48], 1005)
        .unwrap();
    dual.realtime
        .enqueue_l3_slice(2, true, true, 100, &[0xBC; 48], 1006)
        .unwrap();
    dual.realtime
        .enqueue_l3_slice(2, false, true, 102, &[0xCC; 48], 1010)
        .unwrap();
    let (dropped, hint_opt) = dual.realtime.prune_hol_queue(1095);
    assert_eq!(dropped, vec![100]);
    assert!(hint_opt.is_some());
    assert_eq!(dual.realtime.hol_dropped_frames, 1);

    drop(dual);
    srv.await.unwrap();
    let _ = std::fs::remove_file(&ca_path);
}

#[tokio::test]
async fn v2_service_stream_and_v2_loopback_bridge_over_udp_e2ee() {
    // Wire two UdpE2eeSessions through a local zero-knowledge UDP relay stub
    let relay_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr_a = relay_a.local_addr().unwrap();
    let addr_b = relay_b.local_addr().unwrap();

    let cid_a = [0x11; 8];
    let cid_b = [0x22; 8];
    let hs_a = [0x33; 32];
    let hs_b = [0x44; 32];
    let keys_a = AccessKeys::derive(cid_a, hs_a, 0).unwrap();
    let keys_b = AccessKeys::derive(cid_b, hs_b, 0).unwrap();

    let (stop_tx, mut stop_rx) = mpsc::channel::<()>(1);
    let ka = keys_a.clone();
    let kb = keys_b.clone();
    let relay_task = tokio::spawn(async move {
        let mut rx_a =
            AccessEpochState::new(cid_a, hs_a, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                .unwrap();
        let mut rx_b =
            AccessEpochState::new(cid_b, hs_b, TRANSPORT_DATAGRAM, DIR_CLIENT_TO_EDGE, 0, 10)
                .unwrap();
        let mut peer_a: Option<SocketAddr> = None;
        let mut peer_b: Option<SocketAddr> = None;
        let mut seq_to_a = 1u32;
        let mut seq_to_b = 1u32;
        let mut ba = [0u8; 2048];
        let mut bb = [0u8; 2048];

        loop {
            tokio::select! {
                _ = stop_rx.recv() => break,
                Ok((n, src)) = relay_a.recv_from(&mut ba) => {
                    peer_a = Some(src);
                    if let Ok((hdr, body)) = rx_a.verify_udp_packet(&ba[..n], 100) {
                        if hdr.flags.is_ctrl_edge {
                            if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                let ph = AccessHeaderV11 {
                                    flags: AccessFlags { pp: 0, discardable: false, frame_end: false, is_ctrl_edge: true, dir_edge_to_client: true, rtx: false },
                                    route_cid: cid_a, access_epoch: 0, leg_seq: 0, mac_64: [0; 8],
                                };
                                let w = seal_udp_v11(&ka.udp_key_e2c, ph, &EdgeCtrlFrame::Pong { ts_us }.encode()).unwrap();
                                let _ = relay_a.send_to(&w, src).await;
                            }
                        } else if let Some(dst) = peer_b {
                            let fh = AccessHeaderV11 {
                                flags: AccessFlags { pp: hdr.flags.pp, discardable: hdr.flags.discardable, frame_end: false, is_ctrl_edge: false, dir_edge_to_client: true, rtx: false },
                                route_cid: cid_b, access_epoch: 0, leg_seq: seq_to_b, mac_64: [0; 8],
                            };
                            seq_to_b = seq_to_b.wrapping_add(1);
                            let w = seal_udp_v11(&kb.udp_key_e2c, fh, body).unwrap();
                            let _ = relay_b.send_to(&w, dst).await;
                        }
                    }
                }
                Ok((n, src)) = relay_b.recv_from(&mut bb) => {
                    peer_b = Some(src);
                    if let Ok((hdr, body)) = rx_b.verify_udp_packet(&bb[..n], 100) {
                        if hdr.flags.is_ctrl_edge {
                            if let Ok(EdgeCtrlFrame::Ping { ts_us }) = EdgeCtrlFrame::decode(body) {
                                let ph = AccessHeaderV11 {
                                    flags: AccessFlags { pp: 0, discardable: false, frame_end: false, is_ctrl_edge: true, dir_edge_to_client: true, rtx: false },
                                    route_cid: cid_b, access_epoch: 0, leg_seq: 0, mac_64: [0; 8],
                                };
                                let w = seal_udp_v11(&kb.udp_key_e2c, ph, &EdgeCtrlFrame::Pong { ts_us }.encode()).unwrap();
                                let _ = relay_b.send_to(&w, src).await;
                            }
                        } else if let Some(dst) = peer_a {
                            let fh = AccessHeaderV11 {
                                flags: AccessFlags { pp: hdr.flags.pp, discardable: hdr.flags.discardable, frame_end: false, is_ctrl_edge: false, dir_edge_to_client: true, rtx: false },
                                route_cid: cid_a, access_epoch: 0, leg_seq: seq_to_a, mac_64: [0; 8],
                            };
                            seq_to_a = seq_to_a.wrapping_add(1);
                            let w = seal_udp_v11(&ka.udp_key_e2c, fh, body).unwrap();
                            let _ = relay_a.send_to(&w, dst).await;
                        }
                    }
                }
            }
        }
    });

    let mut link_a = UdpAccessLink::connect(&addr_a.to_string(), &keys_a, 10_000)
        .await
        .unwrap();
    let mut link_b = UdpAccessLink::connect(&addr_b.to_string(), &keys_b, 10_000)
        .await
        .unwrap();
    link_a.ping_with_retry(2, Duration::from_secs(1)).await.unwrap();
    link_b.ping_with_retry(2, Duration::from_secs(1)).await.unwrap();

    let ca = SoftwareDeviceKeyStore::generate();
    let ca_spki = ca.public_key_spki_der().unwrap();
    let dev = SoftwareDeviceKeyStore::generate();
    let now_u = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
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
    let mut cert = DeviceCert {
        version: 1,
        cert_id: [0x01; 16],
        device_id: [0x01; 16],
        tenant_id: [0x01; 16],
        p256_pub_der: dev.public_key_spki_der().unwrap(),
        key_epoch: 1,
        policy_hash: pro_rules.canonical_hash(),
        cap_bits: 0x3FFF,
        iat_unix: now_u - 10,
        exp_unix: now_u + 3600,
        hardware_backed: false,
        sig_der: Vec::new(),
    };
    cert.sig_der = ca.sign_p256_low_s(&cert.tbs_bytes().unwrap()).unwrap();
    let mut blob = TenantPolicyBlob {
        tenant_id: [0x01; 16],
        version: 1,
        policy_hash: pro_rules.canonical_hash(),
        iat_unix: now_u - 10,
        exp_unix: now_u + 3600,
        sig_der: Vec::new(),
    };
    blob.sig_der = ca.sign_p256_low_s(&blob.tbs_bytes()).unwrap();
    let policy =
        VerifiedTenantPolicy::from_verified_blob(&blob, &cert, &pro_rules, &ca_spki, now_u)
            .unwrap();
    let sess_a = UdpE2eeSession::from_keys(link_a, [0xA1; 32], [0xB2; 32], policy.clone(), [0x01; 16]);
    let sess_b = UdpE2eeSession::from_keys(link_b, [0xB2; 32], [0xA1; 32], policy, [0x02; 16]);

    let mux_a = V2SessionMux::spawn_udp(sess_a);
    let mux_b = V2SessionMux::spawn_udp(sess_b);

    // 1. Test multi-stream synchronous V2ServiceStream (std::io::Read + Write) across 2 channels
    let mut hid_a = mux_a
        .open_service_stream(CHAN_INPUT_HID, Some(Duration::from_secs(3)))
        .unwrap();
    let mut hid_b = mux_b
        .open_service_stream(CHAN_INPUT_HID, Some(Duration::from_secs(3)))
        .unwrap();
    let mut clip_a = mux_a
        .open_service_stream(CHAN_CLIPBOARD, Some(Duration::from_secs(3)))
        .unwrap();
    let mut clip_b = mux_b
        .open_service_stream(CHAN_CLIPBOARD, Some(Duration::from_secs(3)))
        .unwrap();

    tokio::task::spawn_blocking(move || {
        hid_a.write_all(b"HID-EVENT-STREAM-1234").unwrap();
        clip_a.write_all(b"CLIPBOARD-SYNC-PAYLOAD-5678").unwrap();
        let mut hbuf = [0u8; 21];
        hid_b.read_exact(&mut hbuf).unwrap();
        assert_eq!(&hbuf, b"HID-EVENT-STREAM-1234");
        let mut cbuf = [0u8; 27];
        clip_b.read_exact(&mut cbuf).unwrap();
        assert_eq!(&cbuf, b"CLIPBOARD-SYNC-PAYLOAD-5678");
    })
    .await
    .unwrap();

    // 2. Test V2LoopbackBridge rejects non-loopback bind
    assert!(matches!(
        V2LoopbackBridge::bind("0.0.0.0:0", &mux_a, DEFAULT_BRIDGE_CHANNEL).await,
        Err(ClientError::Config(_))
    ));

    // 3. Test V2LoopbackBridge 32 KiB byte-exact SHA-256 TCP tunnel over V2 E2EE
    let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo_listener.local_addr().unwrap();
    let echo_srv = tokio::spawn(async move {
        let (mut s, _) = echo_listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf).await.unwrap() {
                0 => break,
                n => s.write_all(&buf[..n]).await.unwrap(),
            }
        }
        s.shutdown().await.unwrap();
    });

    let bridge_a = V2LoopbackBridge::bind("127.0.0.1:0", &mux_a, DEFAULT_BRIDGE_CHANNEL)
        .await
        .unwrap();
    let bridge_addr = bridge_a.local_addr();

    let serve_a = tokio::spawn(bridge_a.serve_one());
    let fwd_b = tokio::spawn(async move {
        let r =
            V2LoopbackBridge::forward_to_loopback_target(echo_addr, &mux_b, DEFAULT_BRIDGE_CHANNEL)
                .await
                .unwrap();
        mux_b.shutdown().await;
        r
    });

    let data: Vec<u8> = (0..32 * 1024).map(|i| ((i * 7 + 3) & 0xFF) as u8).collect();
    let expected_sha: [u8; 32] = Sha256::digest(&data).into();
    let cli = TcpStream::connect(bridge_addr).await.unwrap();
    let (mut cr, mut cw) = cli.into_split();
    let tx_data = data.clone();
    let writer = tokio::spawn(async move {
        cw.write_all(&tx_data).await.unwrap();
        cw.shutdown().await.unwrap();
    });
    let mut got = Vec::new();
    cr.read_to_end(&mut got).await.unwrap();
    writer.await.unwrap();

    let (tx_a, rx_a) = serve_a.await.unwrap().unwrap();
    let _ = fwd_b.await.unwrap();
    echo_srv.await.unwrap();
    mux_a.shutdown().await;
    let _ = stop_tx.send(()).await;
    let _ = relay_task.await;

    assert_eq!(tx_a as usize, data.len());
    assert_eq!(rx_a as usize, data.len());
    let got_sha: [u8; 32] = Sha256::digest(&got).into();
    assert_eq!(got_sha, expected_sha);
}

#[tokio::test]
async fn udp_e2ee_actuator_channel_policy_gate_and_preemption() {
    let ca = SoftwareDeviceKeyStore::generate();
    let ca_spki = ca.public_key_spki_der().unwrap();
    let dev = SoftwareDeviceKeyStore::generate();
    let tenant_id = [0xD0; 16];
    let drone_id = [0xD1; 16];
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let now_ms = now_unix * 1000;

    let rules = TenantPolicyRules {
        allow_file_transfer: false,
        allow_clipboard: false,
        allow_file_clipboard: false,
        allow_tcp_tunnel: false,
        allow_terminal: false,
        allow_realtime_actuator: true,
        bw_cap_kbps: 6000,
        exhaust_policy: QuotaExhaustPolicy::MissionLockedAlert,
    };
    let mut cert = DeviceCert {
        version: 1,
        cert_id: [0x11; 16],
        device_id: drone_id,
        tenant_id,
        p256_pub_der: dev.public_key_spki_der().unwrap(),
        key_epoch: 1,
        policy_hash: rules.canonical_hash(),
        cap_bits: 0x1_7001,
        iat_unix: now_unix - 10,
        exp_unix: now_unix + 3600,
        hardware_backed: false,
        sig_der: Vec::new(),
    };
    cert.sig_der = ca.sign_p256_low_s(&cert.tbs_bytes().unwrap()).unwrap();
    let mut blob = TenantPolicyBlob {
        tenant_id,
        version: 1,
        policy_hash: rules.canonical_hash(),
        iat_unix: now_unix - 10,
        exp_unix: now_unix + 3600,
        sig_der: Vec::new(),
    };
    blob.sig_der = ca.sign_p256_low_s(&blob.tbs_bytes()).unwrap();
    let drone_policy =
        VerifiedTenantPolicy::from_verified_blob(&blob, &cert, &rules, &ca_spki, now_unix).unwrap();

    // Free tier blocks 0x07 RealtimeActuator on send
    let dummy_edge = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let edge_addr = dummy_edge.local_addr().unwrap();
    let keys = AccessKeys::derive([0x01; 8], [0x02; 32], 0).unwrap();
    let free_link = UdpAccessLink::connect(&edge_addr.to_string(), &keys, 4000)
        .await
        .unwrap();
    let mut free_sess = UdpE2eeSession::from_keys(
        free_link,
        [0x11; 32],
        [0x22; 32],
        VerifiedTenantPolicy::free_tier(tenant_id),
        drone_id,
    );
    let cmd = ActuatorCmd {
        control_epoch: 1,
        cmd_seq: 1,
        send_ts_ms: now_ms,
        ttl_ms: 100,
        payload: b"THR=0.5".to_vec(),
    };
    assert!(free_sess.send_actuator(&cmd).await.is_err());

    // Drone policy allows 0x07 and enforces CA-signed ControlPreemptToken epoch promotion
    let drone_link = UdpAccessLink::connect(&edge_addr.to_string(), &keys, 6000)
        .await
        .unwrap();
    let mut drone_sess =
        UdpE2eeSession::from_keys(drone_link, [0x11; 32], [0x22; 32], drone_policy, drone_id);
    assert!(drone_sess.send_actuator(&cmd).await.is_ok());

    let mut token = ControlPreemptToken {
        tenant_id,
        drone_device_id: drone_id,
        operator_id: [0xD2; 16],
        new_control_epoch: 2,
        iat_unix: now_unix - 5,
        exp_unix: now_unix + 300,
        sig_der: Vec::new(),
    };
    token.sig_der = ca.sign_p256_low_s(&token.tbs_bytes()).unwrap();
    let new_ep = drone_sess
        .apply_actuator_preempt(&token, &ca_spki, now_unix)
        .unwrap();
    assert_eq!(new_ep, 2);
}
