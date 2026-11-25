use serde_json::Value;
use std::path::PathBuf;
use v2_identity::{ControlPreemptToken, DelegationStatement};
use v2_transport::{
    anchor_rs_parity_count, build_sack_bitmap, check_arq_retry_limit, compute_rto_ms,
    compute_stream_mac64, compute_udp_mac64, derive_access_key, derive_access_key_with_prk,
    effective_p3_credit, open_l3, process_hid_queue, seal_l3, seal_stream_v11, seal_udp_v11,
    seq_u32_gt, verify_mac64_ct, AccessEpochState, AccessFlags, AccessHeaderV10, AccessHeaderV11,
    ActuatorCmd, ActuatorReceiver, BwHintController, EdgeCtrlFrame, HidEvent, L3Header, L3Receiver,
    L4Header, LegCiphertextCache, LegSeqDedupWindow, LtrRecoveryController, LtrRecoveryReq,
    PrologueInput, QueuedStreamSlice, QuotaExhaustPolicy, RecoveryAction, ReplayWindow2048,
    StreamFrameParser, StreamSeqDedup, TcpStreamSendQueue, TelemetryFrame, TenantPolicyRules,
    TransportError, VerifiedTenantPolicy, ZeroRttGuard, ACCESS_HDR_V10_LEN,
    BACKBONE_MAX_WIRE_BYTES, BW_EVENT_SURVIVAL_MODE, CIPHER_AESGCM, CIPHER_CHACHAPOLY,
    DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT, TRANSPORT_DATAGRAM, TRANSPORT_STREAM,
};

fn vectors_dir() -> PathBuf {
    std::env::var("ZERODESK_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/Volumes/data/github/zerodesk/protocol-spec/vectors"))
}

fn load_vector(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read golden vector {}: {}", path.display(), e));
    serde_json::from_str(&data).expect("valid json")
}

fn hex_bytes(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn hex_arr<const N: usize>(s: &str) -> [u8; N] {
    hex_bytes(s).try_into().expect("exact length")
}

#[test]
fn vector_v01_access_mac_hkdf() {
    let v = load_vector("v01_access_mac_hkdf.json");
    let inp = &v["input"];
    let der = &v["derived"];
    let exp = &v["expected"];

    let route_cid: [u8; 8] = hex_arr(inp["route_cid_hex"].as_str().unwrap());
    let hs_hash: [u8; 32] = hex_arr(inp["hs_hash_hex"].as_str().unwrap());
    let transport = inp["transport"].as_u64().unwrap() as u8;
    let dir = inp["dir"].as_u64().unwrap() as u8;
    let access_epoch = inp["access_epoch"].as_u64().unwrap() as u32;
    let leg_seq = inp["leg_seq"].as_u64().unwrap() as u32;
    let flags_u16 = inp["flags_u16"].as_u64().unwrap() as u16;
    let payload = hex_bytes(inp["payload_hex"].as_str().unwrap());

    let (prk, key_dir) =
        derive_access_key_with_prk(&route_cid, &hs_hash, transport, dir, access_epoch).unwrap();
    assert_eq!(hex::encode(prk), der["prk_hex"].as_str().unwrap());
    assert_eq!(hex::encode(key_dir), der["key_dir_hex"].as_str().unwrap());

    let hdr = AccessHeaderV11 {
        flags: AccessFlags::from_u16(flags_u16).unwrap(),
        route_cid,
        access_epoch,
        leg_seq,
        mac_64: [0; 8],
    };
    assert_eq!(
        hex::encode(hdr.encode_mac_zero()),
        der["hdr_mac_zero_hex"].as_str().unwrap()
    );
    let wire = seal_udp_v11(&key_dir, hdr, &payload).unwrap();
    assert_eq!(wire.len(), exp["wire_len"].as_u64().unwrap() as usize);
    assert_eq!(hex::encode(&wire[20..28]), exp["mac_64_hex"].as_str().unwrap());
    assert_eq!(hex::encode(&wire), exp["wire_packet_hex"].as_str().unwrap());

    for neg in v["negative_cases"].as_array().unwrap() {
        let hdr_bytes = hex_bytes(neg["hdr_hex"].as_str().unwrap());
        let payload_len = neg["payload_len"].as_u64().unwrap() as usize;
        let expected_err = neg["expected_err"].as_u64().unwrap() as u16;
        let res = AccessHeaderV11::decode(&hdr_bytes)
            .and_then(|h| h.validate_udp_ingress(hdr_bytes.len() + payload_len));
        let err = res.unwrap_err();
        assert_eq!(err.error_code().as_u16(), expected_err);
    }
}

#[test]
fn vector_v03_tcp_frame_drop_80ms() {
    let v = load_vector("v03_tcp_frame_drop_80ms.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let route_cid: [u8; 8] = hex_arr(inp["route_cid_hex"].as_str().unwrap());
    let hs_hash: [u8; 32] = hex_arr(inp["hs_hash_hex"].as_str().unwrap());
    let key_c2e = derive_access_key(&route_cid, &hs_hash, TRANSPORT_STREAM, DIR_CLIENT_TO_EDGE, 0)
        .unwrap();
    let key_e2c = derive_access_key(&route_cid, &hs_hash, TRANSPORT_STREAM, DIR_EDGE_TO_CLIENT, 0)
        .unwrap();

    let mut q = TcpStreamSendQueue::default();
    for item in inp["queued_frames"].as_array().unwrap() {
        let wire = hex_bytes(item["wire_hex"].as_str().unwrap());
        let mut parser = StreamFrameParser::new();
        parser.feed(&wire);
        let decoded = parser.next_frame().unwrap().unwrap();
        let mac = compute_stream_mac64(
            &key_c2e,
            &decoded.header.encode_mac_zero(),
            decoded.frame_id,
            &decoded.payload,
        )
        .unwrap();
        verify_mac64_ct(&mac, &decoded.header.mac_64).unwrap();
        q.push(QueuedStreamSlice {
            enqueue_ms: item["enqueue_ms"].as_u64().unwrap(),
            frame_id: decoded.frame_id,
            flags: decoded.header.flags,
            wire_bytes: wire,
        });
    }

    let now_ms = inp["now_ms"].as_u64().unwrap();
    let hol = inp["hol_threshold_ms"].as_u64().unwrap();
    let (dropped, maybe_hint) = q.prune_hol_expired(now_ms, hol);
    let exp_dropped: Vec<u32> = exp["dropped_frame_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect();
    let exp_surviving: Vec<u32> = exp["surviving_frame_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect();
    assert_eq!(dropped, exp_dropped);
    assert_eq!(q.surviving_frame_ids(), exp_surviving);

    let hint = maybe_hint.expect("BW_HINT emitted");
    let hint_payload = hint.encode();
    assert_eq!(
        hex::encode(&hint_payload),
        exp["bw_hint_payload_hex"].as_str().unwrap()
    );
    let hint_wire = seal_stream_v11(
        &key_e2c,
        AccessHeaderV11 {
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
        },
        0,
        &hint_payload,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&hint_wire),
        exp["bw_hint_stream_wire_hex"].as_str().unwrap()
    );
}

#[test]
fn vector_v04_noise_downgrade_reject() {
    let v = load_vector("v04_noise_downgrade_reject.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let sha256_of_hex = |s: &str| -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(hex_bytes(s)).into()
    };

    let ctrl_hash = sha256_of_hex(inp["ctrl_devcert_tbs_hex"].as_str().unwrap());
    let host_hash = sha256_of_hex(inp["host_devcert_tbs_hex"].as_str().unwrap());
    let edge_hash = sha256_of_hex(inp["edge_cert_tbs_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(ctrl_hash),
        exp["ctrl_devcert_tbs_sha256_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(host_hash),
        exp["host_devcert_tbs_sha256_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(edge_hash),
        exp["edge_cert_tbs_sha256_hex"].as_str().unwrap()
    );

    let base = PrologueInput {
        ver_major_minor: inp["ver_major_minor"].as_u64().unwrap() as u16,
        handshake_pattern: inp["handshake_pattern"].as_u64().unwrap() as u8,
        cipher_suite: inp["cipher_suite"].as_u64().unwrap() as u16,
        transport_mode: inp["transport_mode"].as_u64().unwrap() as u8,
        device_id_ctrl: hex_arr(inp["device_id_ctrl_hex"].as_str().unwrap()),
        device_id_host: hex_arr(inp["device_id_host_hex"].as_str().unwrap()),
        ctrl_devcert_tbs_sha256: ctrl_hash,
        host_devcert_tbs_sha256: host_hash,
        policy_hash: hex_arr(inp["policy_hash_hex"].as_str().unwrap()),
        edge_cert_tbs_sha256_or_zero: edge_hash,
        negotiated_cap_bits: inp["negotiated_cap_bits"].as_u64().unwrap(),
        session_id: hex_arr(inp["session_id_hex"].as_str().unwrap()),
    };

    assert_eq!(
        base.preimage_bytes().len(),
        exp["prologue_preimage_len"].as_u64().unwrap() as usize
    );
    assert_eq!(
        hex::encode(base.preimage_bytes()),
        exp["prologue_preimage_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(base.compute_prologue()),
        exp["prologue_sha256_hex"].as_str().unwrap()
    );

    for m in v["downgrade_mutations"].as_array().unwrap() {
        let mut mutated = base.clone();
        match m["mutated_field"].as_str().unwrap() {
            "handshake_pattern" => {
                mutated.handshake_pattern = m["mutated_value"].as_u64().unwrap() as u8
            }
            "cipher_suite" => mutated.cipher_suite = m["mutated_value"].as_u64().unwrap() as u16,
            "transport_mode" => mutated.transport_mode = m["mutated_value"].as_u64().unwrap() as u8,
            "policy_hash_bit0" => {
                mutated.policy_hash = hex_arr(m["mutated_hex"].as_str().unwrap())
            }
            "edge_cert_hash_bit255" => {
                mutated.edge_cert_tbs_sha256_or_zero = hex_arr(m["mutated_hex"].as_str().unwrap())
            }
            other => panic!("unexpected mutation {other}"),
        }
        let got = mutated.compute_prologue();
        assert_eq!(hex::encode(got), m["mutated_prologue_hex"].as_str().unwrap());
        assert_ne!(got, base.compute_prologue());
    }
}

#[test]
fn vector_v05_zero_rtt_idempotency() {
    let v = load_vector("v05_zero_rtt_idempotency.json");
    let inp = &v["input"];

    let dev_pub = hex_bytes(inp["device_pub_spki_der_hex"].as_str().unwrap());
    let exp_unix = inp["exp_unix"].as_u64().unwrap();
    let deleg = DelegationStatement {
        device_id: hex_arr(inp["device_id_hex"].as_str().unwrap()),
        x25519_pub: hex_arr(inp["x25519_pub_hex"].as_str().unwrap()),
        prefer_chacha: inp["prefer_chacha"].as_bool().unwrap(),
        delegation_seq: inp["delegation_seq"].as_u64().unwrap(),
        exp_unix,
        sig_der: hex_bytes(inp["deleg_sig_der_hex"].as_str().unwrap()),
    };
    assert_eq!(hex::encode(deleg.tbs_bytes()), inp["deleg_tbs_hex"].as_str().unwrap());

    let sid: [u8; 16] = hex_arr(inp["session_id_hex"].as_str().unwrap());
    let cap = inp["lru_capacity"].as_u64().unwrap() as usize;
    let mut guard = ZeroRttGuard::new(cap);
    let now = exp_unix - 10;

    for sc in v["scenarios"].as_array().unwrap() {
        let chan_id = sc["chan_id"].as_u64().unwrap() as u8;
        let lru_full = sc["lru_full"].as_bool().unwrap();
        let is_replay = sc["is_replay"].as_bool().unwrap();

        let (decision, drop_delta) = if lru_full {
            let mut full_guard = ZeroRttGuard::new(1);
            let filler = [0xEE; 16];
            let _ = full_guard
                .evaluate_0rtt(&deleg, &dev_pub, exp_unix, filler, 0, exp_unix, now)
                .unwrap();
            let before = full_guard.diag_drop_count;
            let d = full_guard
                .evaluate_0rtt(&deleg, &dev_pub, exp_unix, sid, chan_id, exp_unix, now)
                .unwrap();
            (d, full_guard.diag_drop_count - before)
        } else {
            let use_sid = if is_replay || chan_id == 0 {
                sid
            } else {
                [0x99; 16]
            };
            let before = guard.diag_drop_count;
            let d = guard
                .evaluate_0rtt(&deleg, &dev_pub, exp_unix, use_sid, chan_id, exp_unix, now)
                .unwrap();
            (d, guard.diag_drop_count - before)
        };

        assert_eq!(
            decision.accepted,
            sc["expect_0rtt_accepted"].as_bool().unwrap(),
            "scenario {}",
            sc["name"]
        );
        assert_eq!(
            decision.handshake_continue,
            sc["expect_handshake_continue"].as_bool().unwrap()
        );
        assert_eq!(drop_delta, sc["expect_diag_drop_inc"].as_u64().unwrap());
    }
}

#[test]
fn vector_v06_unified_seq_dual_send_dedup() {
    let v = load_vector("v06_unified_seq_dual_send_dedup.json");
    let inp = &v["input"];
    let suite = inp["cipher_suite"].as_u64().unwrap() as u16;
    let key: [u8; 32] = hex_arr(inp["e2ee_key_hex"].as_str().unwrap());

    for pkt in inp["sample_packets"].as_array().unwrap() {
        let wire = hex_bytes(pkt["l3_packet_hex"].as_str().unwrap());
        let (hdr, pt) = open_l3(suite, &key, &wire).unwrap();
        assert_eq!(hdr.pkt_seq, pkt["pkt_seq"].as_u64().unwrap());
        assert_eq!(hdr.unified_seq(), pkt["unified_seq"].as_u64().unwrap());
        assert_eq!(hex::encode(hdr.nonce_96()), pkt["nonce_hex"].as_str().unwrap());
        assert_eq!(hex::encode(&pt), pkt["plaintext_hex"].as_str().unwrap());
        let resealed = seal_l3(suite, &key, &hdr, &pt).unwrap();
        assert_eq!(resealed, wire);
    }

    let mut win = ReplayWindow2048::new();
    for step in v["window_trace"].as_array().unwrap() {
        let seq = step["pkt_seq"].as_u64().unwrap();
        let expect = step["expect_accept"].as_bool().unwrap();
        assert_eq!(win.check_and_mark(seq), expect, "trace step {step}");
    }
}

#[test]
fn vector_v09_access_epoch_rekey_race() {
    let v = load_vector("v09_access_epoch_rekey_race.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let route_cid: [u8; 8] = hex_arr(inp["route_cid_hex"].as_str().unwrap());
    let hs_hash: [u8; 32] = hex_arr(inp["hs_hash_hex"].as_str().unwrap());
    let init_epoch = inp["initial_epoch"].as_u64().unwrap() as u32;
    let rtt_ms = inp["rtt_ms"].as_u64().unwrap();

    let mut st = AccessEpochState::new(
        route_cid,
        hs_hash,
        TRANSPORT_DATAGRAM,
        DIR_CLIENT_TO_EDGE,
        init_epoch,
        rtt_ms,
    )
    .unwrap();

    // epoch 3 (cur-2) & epoch 7 (cur+2) rejected
    let p3 = hex_bytes(inp["pkt_epoch_3_too_old"]["wire_hex"].as_str().unwrap());
    assert!(st.verify_udp_packet(&p3, 1000).is_err());
    let p7 = hex_bytes(inp["pkt_epoch_7_too_new"]["wire_hex"].as_str().unwrap());
    assert!(st.verify_udp_packet(&p7, 1000).is_err());

    // Forged cur+1 (epoch 6) rejected and does NOT promote
    let p6_forged = hex_bytes(inp["pkt_epoch_6_forged"]["wire_hex"].as_str().unwrap());
    assert_eq!(
        st.verify_udp_packet(&p6_forged, 1000).is_ok(),
        exp["forged_6_accepted"].as_bool().unwrap()
    );
    assert_eq!(st.cur_epoch(), exp["cur_after_forged_6"].as_u64().unwrap() as u32);

    // Valid cur+1 (epoch 6) promotes cur to 6 at t=1000
    let p6_valid = hex_bytes(inp["pkt_epoch_6_valid"]["wire_hex"].as_str().unwrap());
    st.verify_udp_packet(&p6_valid, 1000).unwrap();
    assert_eq!(st.cur_epoch(), exp["valid_6_promotes_to"].as_u64().unwrap() as u32);

    // Late epoch 5 passes at +1500ms (within 2000ms grace) and fails at +2500ms
    let p5_late = hex_bytes(inp["pkt_epoch_5_late"]["wire_hex"].as_str().unwrap());
    assert_eq!(
        st.verify_udp_packet(&p5_late, 2500).is_ok(),
        exp["late_5_at_1500ms_accepted"].as_bool().unwrap()
    );
    assert_eq!(
        st.verify_udp_packet(&p5_late, 3500).is_ok(),
        exp["late_5_at_2500ms_accepted"].as_bool().unwrap()
    );
}

#[test]
fn vector_v10_e2ee_rekey_boundary() {
    let v = load_vector("v10_e2ee_rekey_boundary.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let suite = inp["cipher_suite"].as_u64().unwrap() as u16;
    let k1: [u8; 32] = hex_arr(inp["key_epoch1_hex"].as_str().unwrap());
    let k2: [u8; 32] = hex_arr(inp["key_epoch2_hex"].as_str().unwrap());

    let mut rx = L3Receiver::new(suite, 1, k1);
    let mut l4_dedup = StreamSeqDedup::default();
    let mut delivered = Vec::new();

    // Epoch 1 original (stream_seq 77)
    let p1 = hex_bytes(inp["pkt_e1_orig"]["l3_packet_hex"].as_str().unwrap());
    let (h1, pt1) = rx.decrypt_and_verify(&p1, Some(0), 1000).unwrap();
    let l4_1 = L4Header::decode(&pt1).unwrap();
    if l4_dedup.mark_if_new(h1.chan_id, l4_1.stream_seq) {
        delivered.push(l4_1.stream_seq);
    }

    // Install epoch 2 at t=1000 with 2000ms grace
    rx.install_next_epoch(2, k2, 1000, 50);

    // Epoch 2 first packet (stream_seq 78)
    let p2 = hex_bytes(inp["pkt_e2_first"]["l3_packet_hex"].as_str().unwrap());
    let (h2, pt2) = rx.decrypt_and_verify(&p2, Some(0), 1200).unwrap();
    let l4_2 = L4Header::decode(&pt2).unwrap();
    if l4_dedup.mark_if_new(h2.chan_id, l4_2.stream_seq) {
        delivered.push(l4_2.stream_seq);
    }

    // Epoch 1 ARQ retransmit in grace: new unified_seq (501) passes L3, deduped by L4 stream_seq 77!
    let p1_rtx = hex_bytes(inp["pkt_e1_rtx_in_grace"]["l3_packet_hex"].as_str().unwrap());
    let (h1r, pt1r) = rx.decrypt_and_verify(&p1_rtx, Some(0), 1500).unwrap();
    let l4_1r = L4Header::decode(&pt1r).unwrap();
    let is_dup = !l4_dedup.mark_if_new(h1r.chan_id, l4_1r.stream_seq);
    assert_eq!(is_dup, exp["e1_rtx_deduped_by_stream_seq"].as_bool().unwrap());

    // Epoch 1 after 2000ms grace is rejected
    let p1_after = hex_bytes(inp["pkt_e1_after_grace"]["l3_packet_hex"].as_str().unwrap());
    assert_eq!(
        rx.decrypt_and_verify(&p1_after, Some(0), 3500).is_err(),
        exp["e1_after_grace_rejected"].as_bool().unwrap()
    );

    let exp_seqs: Vec<u32> = exp["unique_l4_delivered_stream_seqs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect();
    assert_eq!(delivered, exp_seqs);
}

#[test]
fn vector_v11_nonce_isolation() {
    let v = load_vector("v11_nonce_isolation.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let k_c2h: [u8; 32] = hex_arr(inp["key_c2h_hex"].as_str().unwrap());
    let k_h2c: [u8; 32] = hex_arr(inp["key_h2c_hex"].as_str().unwrap());
    let pt_c2h = hex_bytes(inp["plaintext_c2h_hex"].as_str().unwrap());
    let pt_h2c = hex_bytes(inp["plaintext_h2c_hex"].as_str().unwrap());

    let h_c2h = L3Header {
        e2ee_epoch: 0,
        pkt_seq: 0,
        send_ts_us_mod: 0x3039,
        chan_id: 1,
        frame_flags: 0,
    };
    let h_h2c = L3Header {
        e2ee_epoch: 0,
        pkt_seq: 0,
        send_ts_us_mod: 0xd431,
        chan_id: 3,
        frame_flags: 0,
    };
    assert_eq!(hex::encode(h_c2h.nonce_96()), exp["nonce_seq0_hex"].as_str().unwrap());

    let aes_c2h = seal_l3(CIPHER_AESGCM, &k_c2h, &h_c2h, &pt_c2h).unwrap();
    let aes_h2c = seal_l3(CIPHER_AESGCM, &k_h2c, &h_h2c, &pt_h2c).unwrap();
    let chacha_c2h = seal_l3(CIPHER_CHACHAPOLY, &k_c2h, &h_c2h, &pt_c2h).unwrap();

    assert_eq!(hex::encode(&aes_c2h), exp["aes_c2h_packet_hex"].as_str().unwrap());
    assert_eq!(hex::encode(&aes_h2c), exp["aes_h2c_packet_hex"].as_str().unwrap());
    assert_eq!(
        hex::encode(&chacha_c2h),
        exp["chacha_c2h_packet_hex"].as_str().unwrap()
    );

    // Flipped AAD byte fails AEAD with 0x0204 (516)
    let flipped = hex_bytes(exp["aad_flipped_packet_hex"].as_str().unwrap());
    let err = open_l3(CIPHER_AESGCM, &k_c2h, &flipped).unwrap_err();
    assert_eq!(err.error_code().as_u16(), exp["aad_flipped_err"].as_u64().unwrap() as u16);

    // UDP vs Stream HKDF transport-byte isolation
    let route_cid: [u8; 8] = hex_arr(inp["route_cid_hex"].as_str().unwrap());
    let hs_hash: [u8; 32] = hex_arr(inp["hs_hash_hex"].as_str().unwrap());
    let k_udp = derive_access_key(&route_cid, &hs_hash, TRANSPORT_DATAGRAM, 0, 0).unwrap();
    let k_stream = derive_access_key(&route_cid, &hs_hash, TRANSPORT_STREAM, 0, 0).unwrap();
    assert_eq!(hex::encode(k_udp), exp["key_udp_hex"].as_str().unwrap());
    assert_eq!(hex::encode(k_stream), exp["key_stream_hex"].as_str().unwrap());

    let hdr = AccessHeaderV11 {
        flags: AccessFlags {
            pp: 0,
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
    let hdr_zero = hdr.encode_mac_zero();
    let mac_udp = compute_udp_mac64(&k_udp, &hdr_zero, &aes_c2h).unwrap();
    let mac_stream = compute_stream_mac64(&k_stream, &hdr_zero, 0, &aes_c2h).unwrap();
    assert_eq!(hex::encode(mac_udp), exp["mac_udp_hex"].as_str().unwrap());
    assert_eq!(hex::encode(mac_stream), exp["mac_stream_hex"].as_str().unwrap());
    assert_eq!(mac_udp == mac_stream, exp["cross_transport_mac_equal"].as_bool().unwrap());
}

#[test]
fn vector_v12_tcp_half_frame_resync() {
    let v = load_vector("v12_tcp_half_frame_resync.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let route_cid: [u8; 8] = hex_arr(inp["route_cid_hex"].as_str().unwrap());
    let hs_hash: [u8; 32] = hex_arr(inp["hs_hash_hex"].as_str().unwrap());
    let key = derive_access_key(&route_cid, &hs_hash, TRANSPORT_STREAM, 0, 0).unwrap();

    for illegal in inp["illegal_frame_lens"].as_array().unwrap() {
        let len = illegal.as_u64().unwrap() as u32;
        let mut parser = StreamFrameParser::new();
        parser.feed(&len.to_be_bytes());
        let err = parser.next_frame().unwrap_err();
        assert_eq!(
            err.error_code().as_u16(),
            exp["illegal_len_err"].as_u64().unwrap() as u16
        );
    }

    // Flipped frame_id fails stream MAC
    let mut p_bad = StreamFrameParser::new();
    p_bad.feed(&hex_bytes(inp["frame1_fid_flipped_hex"].as_str().unwrap()));
    let f_bad = p_bad.next_frame().unwrap().unwrap();
    let calc = compute_stream_mac64(
        &key,
        &f_bad.header.encode_mac_zero(),
        f_bad.frame_id,
        &f_bad.payload,
    )
    .unwrap();
    assert_eq!(
        verify_mac64_ct(&calc, &f_bad.header.mac_64).is_ok(),
        exp["fid_flipped_mac_valid"].as_bool().unwrap()
    );

    // Coalesced WebSocket chunk split byte-by-byte parses 2 frames cleanly
    let coalesced = hex_bytes(inp["coalesced_ws_hex"].as_str().unwrap());
    let mut parser = StreamFrameParser::new();
    let mut frames = Vec::new();
    for chunk in coalesced.chunks(7) {
        parser.feed(chunk);
        while let Some(f) = parser.next_frame().unwrap() {
            let mac = compute_stream_mac64(
                &key,
                &f.header.encode_mac_zero(),
                f.frame_id,
                &f.payload,
            )
            .unwrap();
            verify_mac64_ct(&mac, &f.header.mac_64).unwrap();
            frames.push(f);
        }
    }
    assert_eq!(frames.len(), exp["coalesced_frame_count"].as_u64().unwrap() as usize);

    let old_fid = inp["rfc1982_old_fid"].as_u64().unwrap() as u32;
    let new_fid = inp["rfc1982_new_fid"].as_u64().unwrap() as u32;
    assert_eq!(seq_u32_gt(new_fid, old_fid), exp["rfc1982_new_gt_old"].as_bool().unwrap());
    assert_eq!(seq_u32_gt(old_fid, new_fid), exp["rfc1982_old_gt_new"].as_bool().unwrap());
}

#[test]
fn vector_v16_arq_state_machine() {
    let v = load_vector("v16_arq_state_machine.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let hdr = L4Header::decode(&hex_bytes(inp["l4_header_hex"].as_str().unwrap())).unwrap();
    assert_eq!(hdr.stream_seq, inp["l4_stream_seq"].as_u64().unwrap() as u32);

    let cum_ack = inp["sack_cum_ack"].as_u64().unwrap() as u32;
    let recvd: Vec<u32> = inp["sack_received_seqs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_u64().unwrap() as u32)
        .collect();
    let bitmap = build_sack_bitmap(cum_ack, &recvd);
    assert_eq!(format!("{bitmap:016x}"), exp["sack_bitmap_hex"].as_str().unwrap());

    let srtt = inp["srtt_ms"].as_u64().unwrap();
    let rttvar = inp["rttvar_ms"].as_u64().unwrap();
    assert_eq!(compute_rto_ms(srtt, rttvar, 0), exp["rto_retry0_ms"].as_u64().unwrap());
    assert_eq!(compute_rto_ms(srtt, rttvar, 1), exp["rto_retry1_ms"].as_u64().unwrap());
    assert_eq!(
        compute_rto_ms(srtt, rttvar, 4),
        exp["rto_retry4_capped_ms"].as_u64().unwrap()
    );

    let max_retries = inp["max_retries_before_fail"].as_u64().unwrap() as u8;
    let err = check_arq_retry_limit(max_retries).unwrap_err();
    assert_eq!(
        err.error_code().as_u16(),
        exp["retry8_error_code"].as_u64().unwrap() as u16
    );

    assert_eq!(
        effective_p3_credit(
            inp["p3_rwnd_bytes"].as_u64().unwrap() as u32,
            inp["p3_cwnd_bytes"].as_u64().unwrap() as u32,
        ),
        exp["p3_effective_credit_bytes"].as_u64().unwrap() as u32
    );

    let hid_res = process_hid_queue(
        &[
            HidEvent::Key { seq: 1, code: 65, enqueue_ms: 900 },
            HidEvent::Key { seq: 2, code: 66, enqueue_ms: 800 }, // age 200ms > 150ms
            HidEvent::MouseRel { seq: 3, dx: 5, dy: 2, enqueue_ms: 700 },
            HidEvent::MouseRel { seq: 4, dx: 3, dy: 2, enqueue_ms: 950 },
        ],
        1000,
    );
    assert_eq!(hid_res.acked_seqs, vec![1, 2, 3, 4]);
    assert_eq!(hid_res.executed_keys, vec![1]);
    assert_eq!(hid_res.dropped_keys, vec![2]);
    assert_eq!(
        hid_res.accumulated_mouse_dx,
        exp["hid_accumulated_mouse_dx"].as_i64().unwrap() as i32
    );
    assert_eq!(
        hid_res.accumulated_mouse_dy,
        exp["hid_accumulated_mouse_dy"].as_i64().unwrap() as i32
    );
}

#[test]
fn vector_v19_leg_nack_anti_amplification() {
    let v = load_vector("v19_leg_nack_anti_amplification.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let route_cid: [u8; 8] = hex_arr(inp["route_cid_hex"].as_str().unwrap());
    let hs_hash: [u8; 32] = hex_arr(inp["hs_hash_hex"].as_str().unwrap());
    let access_epoch = inp["access_epoch"].as_u64().unwrap() as u32;
    let base_leg_seq = inp["base_leg_seq"].as_u64().unwrap() as u32;
    let loss_bitmap = inp["loss_bitmap"].as_u64().unwrap();
    let rtt_ms = inp["rtt_ms"].as_u64().unwrap();

    // Verify LEG_NACK control wire format & MAC
    let nack = EdgeCtrlFrame::LegNack {
        base_leg_seq,
        loss_bitmap,
    };
    let nack_body = nack.encode();
    assert_eq!(
        hex::encode(&nack_body),
        inp["leg_nack_body_hex"].as_str().unwrap()
    );
    let key_e2c = derive_access_key(
        &route_cid,
        &hs_hash,
        TRANSPORT_DATAGRAM,
        DIR_EDGE_TO_CLIENT,
        access_epoch,
    )
    .unwrap();
    let nack_wire = seal_udp_v11(
        &key_e2c,
        AccessHeaderV11 {
            flags: AccessFlags {
                pp: 0,
                discardable: false,
                frame_end: false,
                is_ctrl_edge: true,
                dir_edge_to_client: true,
                rtx: false,
            },
            route_cid,
            access_epoch,
            leg_seq: 0,
            mac_64: [0; 8],
        },
        &nack_body,
    )
    .unwrap();
    assert_eq!(
        hex::encode(&nack_wire),
        inp["leg_nack_wire_hex"].as_str().unwrap()
    );

    // Exercise 100x replayed LEG_NACK against wraparound leg_seq cache
    let mut cache = LegCiphertextCache::new(access_epoch);
    let mk_hdr = |seq: u32, pp: u8, d: bool| AccessHeaderV11 {
        flags: AccessFlags {
            pp,
            discardable: d,
            frame_end: false,
            is_ctrl_edge: false,
            dir_edge_to_client: true,
            rtx: false,
        },
        route_cid,
        access_epoch,
        leg_seq: seq,
        mac_64: [0; 8],
    };
    // seq 0xFFFFFFFE (p0), 0xFFFFFFFF (p3), 0 (p2 d=1), 1 (p2 ref), 2 (p0 old)
    cache.record_original(&mk_hdr(base_leg_seq, 0, false), vec![1; 100], 1000);
    cache.record_original(&mk_hdr(base_leg_seq.wrapping_add(1), 3, false), vec![2; 100], 1000);
    cache.record_original(&mk_hdr(base_leg_seq.wrapping_add(2), 2, true), vec![3; 100], 1000);
    cache.record_original(&mk_hdr(base_leg_seq.wrapping_add(3), 2, false), vec![4; 100], 1000);

    let mut p0_rtx = 0usize;
    let mut p3_rtx = 0usize;
    let mut d1_rtx = 0usize;
    for i in 0..inp["replay_count"].as_u64().unwrap() {
        let t = 1000 + i * (rtt_ms + 1);
        if t - 1000 > 99 {
            break;
        }
        for pkt in cache.handle_leg_nack(base_leg_seq, loss_bitmap, t, rtt_ms, None) {
            match pkt[0] {
                1 => p0_rtx += 1,
                2 => p3_rtx += 1,
                3 => d1_rtx += 1,
                _ => {}
            }
        }
    }
    assert_eq!(p0_rtx as u64, exp["p0_max_rtx"].as_u64().unwrap());
    assert_eq!(p3_rtx as u64, exp["p3_max_rtx"].as_u64().unwrap());
    assert_eq!(d1_rtx as u64, exp["d1_rtx_count"].as_u64().unwrap());
    assert!(
        cache.billed_bytes
            <= cache.orig_emitted_bytes * exp["max_wire_multiplier"].as_u64().unwrap()
    );
    assert_eq!(
        cache.billed_bytes,
        cache.orig_emitted_bytes + cache.rtx_emitted_bytes
    );

    // Expired > 100ms emits 0 RTX
    assert_eq!(
        cache.handle_leg_nack(base_leg_seq, loss_bitmap, 1101, rtt_ms, None).len() as u64,
        exp["expired_101ms_rtx_count"].as_u64().unwrap()
    );

    // Soft rekey 150ms old-epoch grace check
    let mut rekey_cache = LegCiphertextCache::new(2);
    rekey_cache.record_original(&mk_hdr(10, 0, false), vec![9; 100], 2000);
    rekey_cache.on_soft_rekey(3, 2000);
    assert_eq!(
        !rekey_cache.handle_leg_nack(10, 1, 2100, 10, None).is_empty(),
        exp["old_epoch_at_100ms_accepted"].as_bool().unwrap()
    );
    assert_eq!(
        !rekey_cache.handle_leg_nack(10, 1, 2160, 10, None).is_empty(),
        exp["old_epoch_at_160ms_accepted"].as_bool().unwrap()
    );
}

#[test]
fn vector_v20_three_leg_bw_hint_stability() {
    let v = load_vector("v20_three_leg_bw_hint_stability.json");
    let inp = &v["input"];

    let route_cid: [u8; 8] = hex_arr(inp["route_cid_hex"].as_str().unwrap());
    let hs_hash: [u8; 32] = hex_arr(inp["hs_hash_hex"].as_str().unwrap());
    let key_e2c =
        derive_access_key(&route_cid, &hs_hash, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 0).unwrap();

    for key_name in [
        "hint_random_loss_3pct",
        "hint_leg3_drop_2mbps",
        "hint_expired_501ms",
    ] {
        let h = &inp[key_name];
        let frame = EdgeCtrlFrame::BwHint {
            cap_kbps: h["cap_kbps"].as_u64().unwrap() as u32,
            queue_delay_ms: h["queue_delay_ms"].as_u64().unwrap() as u16,
            report_age_ms: h["report_age_ms"].as_u64().unwrap() as u16,
            bottleneck_leg: h["bottleneck_leg"].as_u64().unwrap() as u8,
            event_flags: h["event_flags"].as_u64().unwrap() as u8,
        };
        let body = frame.encode();
        assert_eq!(hex::encode(&body), h["body_hex"].as_str().unwrap());
        let wire = seal_udp_v11(
            &key_e2c,
            AccessHeaderV11 {
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
            },
            &body,
        )
        .unwrap();
        assert_eq!(hex::encode(&wire), h["wire_hex"].as_str().unwrap());
    }

    let mut ctrl = BwHintController::new(
        inp["e2e_gcc_kbps"].as_u64().unwrap() as u32,
        inp["lease_bw_cap_kbps"].as_u64().unwrap() as u32,
    );
    for step in inp["controller_timeline"].as_array().unwrap() {
        let bw = ctrl.on_bw_hint(
            step["e2e_gcc_kbps"].as_u64().unwrap() as u32,
            step["cap_kbps"].as_u64().unwrap() as u32,
            step["report_age_ms"].as_u64().unwrap() as u16,
            step["bottleneck_leg"].as_u64().unwrap() as u8,
            step["event_flags"].as_u64().unwrap() as u8,
            step["now_ms"].as_u64().unwrap(),
        );
        assert_eq!(
            bw,
            step["expected_bw_kbps"].as_u64().unwrap() as u32,
            "timeline step {}",
            step["step"]
        );
        if let Some(expect_dis) = step["expect_gcc_loss_backoff_disabled"].as_bool() {
            assert_eq!(ctrl.gcc_loss_backoff_disabled, expect_dis);
        }
    }
}

#[test]
fn vector_v21_ltr_recovery_fallback() {
    let v = load_vector("v21_ltr_recovery_fallback.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let req_lost =
        LtrRecoveryReq::decode(&hex_bytes(inp["ltr_req_slice_lost_hex"].as_str().unwrap()))
            .unwrap();
    let req_dec =
        LtrRecoveryReq::decode(&hex_bytes(inp["ltr_req_decode_err_hex"].as_str().unwrap()))
            .unwrap();

    let mut ltr = LtrRecoveryController::new(true, true);
    assert!(ltr.try_mark_ltr(0, 100));
    // Unconfirmed slot overwrite MUST be rejected
    assert_eq!(
        ltr.try_mark_ltr(0, 101),
        exp["unconfirmed_slot_overwrite_allowed"].as_bool().unwrap()
    );
    // Unconfirmed/stale slot falls back to IntraRefresh
    assert_eq!(ltr.handle_recovery_req(req_lost, 1000), RecoveryAction::IntraRefresh);

    // Confirm slot 100 -> recovers via ForceRefLtr(100) with 0 IDR
    ltr.confirm_ltr(100);
    assert_eq!(
        ltr.handle_recovery_req(req_lost, 1050),
        RecoveryAction::ForceRefLtr(100)
    );

    // DECODE_ERROR skips LTR straight to rate-limited ForceIdr (>=500ms)
    assert_eq!(ltr.handle_recovery_req(req_dec, 1100), RecoveryAction::ForceIdr);
    assert_eq!(
        ltr.handle_recovery_req(req_dec, 1400),
        RecoveryAction::RateLimitedSkip
    );
    assert_eq!(ltr.handle_recovery_req(req_dec, 1600), RecoveryAction::ForceIdr);

    // Non-LTR encoder falls back to IntraRefresh
    let mut non_ltr = LtrRecoveryController::new(false, true);
    assert_eq!(
        non_ltr.handle_recovery_req(req_lost, 1000),
        RecoveryAction::IntraRefresh
    );

    assert_eq!(
        anchor_rs_parity_count(
            inp["anchor_k"].as_u64().unwrap() as usize,
            inp["leg2_loss_rate"].as_f64().unwrap(),
        ),
        exp["anchor_rs_m"].as_u64().unwrap() as usize
    );
}

#[test]
fn vector_v22_leg_seq_header_rekey() {
    let v = load_vector("v22_leg_seq_header_rekey.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    assert_eq!(
        BACKBONE_MAX_WIRE_BYTES as u64,
        exp["backbone_max_wire_bytes"].as_u64().unwrap()
    );
    let l3_payload = hex_bytes(inp["l3_payload_hex"].as_str().unwrap());

    // Leg 1 v1.0 (24B) header verification
    let leg1 = &inp["leg1_v10"];
    let leg1_wire = hex_bytes(leg1["wire_hex"].as_str().unwrap());
    let h10 = AccessHeaderV10::decode(&leg1_wire[..ACCESS_HDR_V10_LEN]).unwrap();
    let k10 = derive_access_key(
        &h10.route_cid,
        &hex_arr(leg1["hs_hash_hex"].as_str().unwrap()),
        TRANSPORT_DATAGRAM,
        DIR_CLIENT_TO_EDGE,
        h10.access_epoch,
    )
    .unwrap();
    let mac10 = compute_udp_mac64(&k10, &h10.encode_mac_zero(), &leg1_wire[ACCESS_HDR_V10_LEN..])
        .unwrap();
    assert_eq!(hex::encode(mac10), leg1["mac_64_hex"].as_str().unwrap());
    assert_eq!(&leg1_wire[ACCESS_HDR_V10_LEN..], l3_payload.as_slice());

    // Leg 3 v1.1 (28B): orig (rtx=0), rtx (rtx=1 excluded from RTT), and wraparound + rekey
    let leg3 = &inp["leg3_v11"];
    let cid3: [u8; 8] = hex_arr(leg3["route_cid_hex"].as_str().unwrap());
    let hs3: [u8; 32] = hex_arr(leg3["hs_hash_hex"].as_str().unwrap());
    let k3_e1 = derive_access_key(&cid3, &hs3, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 1).unwrap();
    let k3_e2 = derive_access_key(&cid3, &hs3, TRANSPORT_DATAGRAM, DIR_EDGE_TO_CLIENT, 2).unwrap();

    let h_orig = AccessHeaderV11::decode(&hex_bytes(leg3["hdr_orig_hex"].as_str().unwrap())).unwrap();
    let h_rtx = AccessHeaderV11::decode(&hex_bytes(leg3["hdr_rtx_hex"].as_str().unwrap())).unwrap();
    let h_wrap =
        AccessHeaderV11::decode(&hex_bytes(leg3["hdr_wrap_rekey_hex"].as_str().unwrap())).unwrap();

    assert!(h_orig.eligible_for_rtt_sample());
    assert!(!h_rtx.eligible_for_rtt_sample());
    assert_eq!(!h_rtx.eligible_for_rtt_sample(), exp["rtx_excluded_from_rtt"].as_bool().unwrap());

    assert_eq!(
        hex::encode(compute_udp_mac64(&k3_e1, &h_orig.encode_mac_zero(), &l3_payload).unwrap()),
        leg3["mac_orig_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(compute_udp_mac64(&k3_e1, &h_rtx.encode_mac_zero(), &l3_payload).unwrap()),
        leg3["mac_rtx_hex"].as_str().unwrap()
    );
    assert_eq!(
        hex::encode(compute_udp_mac64(&k3_e2, &h_wrap.encode_mac_zero(), &l3_payload).unwrap()),
        leg3["mac_wrap_rekey_hex"].as_str().unwrap()
    );

    // Modular leg_seq wraparound 0xFFFFFFFF -> 0 across access_epoch 1 -> 2
    let mut dedup = LegSeqDedupWindow::new();
    assert!(dedup.check_and_mark(h_orig.leg_seq));
    assert!(!dedup.check_and_mark(h_rtx.leg_seq)); // same leg_seq deduplicated
    assert!(dedup.check_and_mark(h_wrap.leg_seq));
    assert_eq!(
        seq_u32_gt(h_wrap.leg_seq, h_orig.leg_seq),
        exp["leg_seq_wrap_next_gt_prev"].as_bool().unwrap()
    );
}

#[test]
fn vector_v24_realtime_actuator_telemetry_and_survival() {
    let v = load_vector("v24_realtime_actuator_and_survival.json");
    let inp = &v["input"];
    let exp = &v["expected"];

    let pt = &inp["preempt_token"];
    let ca_pub = hex_bytes(pt["ca_pub_spki_der_hex"].as_str().unwrap());
    let tenant_id: [u8; 16] = hex_arr(pt["tenant_id_hex"].as_str().unwrap());
    let drone_id: [u8; 16] = hex_arr(pt["drone_device_id_hex"].as_str().unwrap());
    let operator_id: [u8; 16] = hex_arr(pt["operator_id_hex"].as_str().unwrap());
    let now_ms = inp["now_ms"].as_u64().unwrap();

    let mut rx = ActuatorReceiver::new(tenant_id, drone_id, 1);

    // Normal command executes
    let cmd_normal = ActuatorCmd::decode(&hex_bytes(inp["cmd_normal_hex"].as_str().unwrap())).unwrap();
    assert_eq!(rx.accept_cmd(&cmd_normal, now_ms), exp["cmd_normal_exec"].as_bool().unwrap());

    // Expired, ttl>150, ttl==0, future skew 51ms, unilateral epoch bump MUST all be rejected
    for (field, exp_field) in [
        ("cmd_expired_hex", "cmd_expired_exec"),
        ("cmd_ttl_over_150_hex", "cmd_ttl_over_150_exec"),
        ("cmd_ttl_zero_hex", "cmd_ttl_zero_exec"),
        ("cmd_future_skew_51ms_hex", "cmd_future_skew_51ms_exec"),
        ("cmd_unauth_epoch_bump_hex", "cmd_unauth_epoch_bump_exec"),
    ] {
        let cmd = ActuatorCmd::decode(&hex_bytes(inp[field].as_str().unwrap())).unwrap();
        assert_eq!(
            rx.accept_cmd(&cmd, now_ms),
            exp[exp_field].as_bool().unwrap(),
            "case {field}"
        );
    }

    // Future skew == 50ms boundary succeeds (cmd_seq 11), then stale seq 11 fails
    let cmd_skew50 =
        ActuatorCmd::decode(&hex_bytes(inp["cmd_future_skew_50ms_ok_hex"].as_str().unwrap()))
            .unwrap();
    assert_eq!(
        rx.accept_cmd(&cmd_skew50, now_ms),
        exp["cmd_future_skew_50ms_ok_exec"].as_bool().unwrap()
    );
    let cmd_stale =
        ActuatorCmd::decode(&hex_bytes(inp["cmd_stale_seq_hex"].as_str().unwrap())).unwrap();
    assert_eq!(
        rx.accept_cmd(&cmd_stale, now_ms),
        exp["cmd_stale_seq_exec"].as_bool().unwrap()
    );

    // Bad ControlPreemptToken fails; valid CA-signed token raises control_epoch to 2
    let mut token = ControlPreemptToken {
        tenant_id,
        drone_device_id: drone_id,
        operator_id,
        new_control_epoch: pt["new_control_epoch"].as_u64().unwrap() as u32,
        iat_unix: pt["iat_unix"].as_u64().unwrap(),
        exp_unix: pt["exp_unix"].as_u64().unwrap(),
        sig_der: hex_bytes(pt["bad_sig_der_hex"].as_str().unwrap()),
    };
    let now_unix = pt["now_unix"].as_u64().unwrap();
    assert!(matches!(
        rx.apply_preempt_token(&token, &ca_pub, now_unix),
        Err(TransportError::Identity(_))
    ));
    token.sig_der = hex_bytes(pt["sig_der_hex"].as_str().unwrap());
    let new_ep = rx.apply_preempt_token(&token, &ca_pub, now_unix).unwrap();
    assert_eq!(new_ep, exp["cmd_safety_preempt_new_epoch"].as_u64().unwrap() as u32);

    // Safety officer command in epoch 2 executes; old pilot command in epoch 1 rejected
    let cmd_safety =
        ActuatorCmd::decode(&hex_bytes(inp["cmd_safety_preempt_hex"].as_str().unwrap())).unwrap();
    assert_eq!(
        rx.accept_cmd(&cmd_safety, now_ms),
        exp["cmd_safety_preempt_exec"].as_bool().unwrap()
    );
    let cmd_old =
        ActuatorCmd::decode(&hex_bytes(inp["cmd_old_pilot_after_preempt_hex"].as_str().unwrap()))
            .unwrap();
    assert_eq!(
        rx.accept_cmd(&cmd_old, now_ms),
        exp["cmd_old_pilot_after_preempt_exec"].as_bool().unwrap()
    );

    // 0x08 Telemetry wire format round-trip
    let tf_json = &inp["telemetry_frame"];
    let tf = TelemetryFrame {
        telem_seq: tf_json["telem_seq"].as_u64().unwrap() as u32,
        sample_ts_ms: tf_json["sample_ts_ms"].as_u64().unwrap(),
        mask: tf_json["mask"].as_u64().unwrap() as u16,
        payload: hex_bytes(tf_json["payload_hex"].as_str().unwrap()),
    };
    assert_eq!(hex::encode(tf.encode()), tf_json["wire_hex"].as_str().unwrap());
    assert_eq!(
        TelemetryFrame::decode(&hex_bytes(tf_json["wire_hex"].as_str().unwrap())).unwrap(),
        tf
    );

    // Survival Mode BW_HINT decode & controller trigger
    let surv_hint =
        EdgeCtrlFrame::decode(&hex_bytes(inp["bw_hint_survival_body_hex"].as_str().unwrap()))
            .unwrap();
    match surv_hint {
        EdgeCtrlFrame::BwHint {
            cap_kbps,
            report_age_ms,
            bottleneck_leg,
            event_flags,
            ..
        } => {
            assert_ne!(event_flags & BW_EVENT_SURVIVAL_MODE, 0);
            let mut bw = BwHintController::new(6000, 6000);
            bw.on_bw_hint(6000, cap_kbps, report_age_ms, bottleneck_leg, event_flags, now_ms);
            assert_eq!(
                bw.survival_mode,
                exp["survival_mode_triggered"].as_bool().unwrap()
            );
        }
        other => panic!("expected BwHint, got {other:?}"),
    }

    // EXHAUST_MISSION_LOCKED_ALERT never throttles mid-mission and raises RTH alert
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
    let pol = VerifiedTenantPolicy::from_rules_unchecked(
        tenant_id,
        1,
        rules.canonical_hash(),
        &rules,
    );
    let (cap_on_exhaust, rth_alert) = pol.on_quota_exhausted();
    assert_eq!(cap_on_exhaust == 256, exp["mission_locked_throttled_on_exhaust"].as_bool().unwrap());
    assert_eq!(rth_alert, exp["mission_locked_rth_alert"].as_bool().unwrap());
}
