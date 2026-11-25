use p256::ecdsa::{DerSignature, Signature};
use serde_json::Value;
use std::path::PathBuf;
use v2_identity::{
    verify_p256_low_s, ControlPreemptToken, DelegationCache, DelegationStatement, DeviceCert,
    DeviceKeyStore, EdgeCert, IdentityError, KeyProtectionLevel, RevocationNotice,
    SoftwareDeviceKeyStore, StaticKeyHintRetry, TenantPolicyBlob, X25519StaticKeyRotator,
    ERR_CERT_EXPIRED, ERR_CERT_REVOKED, ERR_DELEGATION_ROLLBACK, X25519_SLICE_SECS,
};

/// Golden vector directory resolution:
/// - Set `ZERODESK_VECTORS_DIR` to point at `protocol-spec/vectors` in CI or custom checkouts.
/// - Defaults to `/Volumes/data/github/zerodesk/protocol-spec/vectors` when unset.
const DEFAULT_VECTORS_DIR: &str = "/Volumes/data/github/zerodesk/protocol-spec/vectors";

fn vectors_dir() -> PathBuf {
    std::env::var("ZERODESK_VECTORS_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from(DEFAULT_VECTORS_DIR))
}

fn load_vector(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let data = std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "failed to read golden vector {} (set ZERODESK_VECTORS_DIR or populate default {}): {}",
            path.display(),
            DEFAULT_VECTORS_DIR,
            e
        )
    });
    serde_json::from_str(&data).expect("valid vector json")
}

fn decode_hex_arr<const N: usize>(s: &str) -> [u8; N] {
    let bytes = hex::decode(s).expect("valid hex");
    bytes.try_into().expect("exact length")
}

#[test]
fn software_keystore_never_claims_hardware_backed_and_rejects_high_s() {
    let ks = SoftwareDeviceKeyStore::generate();
    assert!(!ks.hardware_backed());
    assert_eq!(ks.protection_level(), KeyProtectionLevel::SoftwareFallback);

    let pkcs8 = ks.to_pkcs8_der().expect("export pkcs8");
    let reloaded = SoftwareDeviceKeyStore::from_pkcs8_der(&pkcs8).expect("reload pkcs8");
    assert_eq!(
        ks.public_key_spki_der().unwrap(),
        reloaded.public_key_spki_der().unwrap()
    );

    let tbs = b"V2-TEST-LOW-S-CHECK";
    let sig_der = ks.sign_p256_low_s(tbs).expect("sign");
    let spki = ks.public_key_spki_der().expect("spki");
    verify_p256_low_s(&spki, tbs, &sig_der).expect("valid low-S signature");

    // Flip S to N - S (high-S malleable form) and assert strict rejection.
    let sig = Signature::from_der(&sig_der).expect("parse sig");
    let (r, s) = sig.split_scalars();
    let high_s = -*s;
    let high_sig = Signature::from_scalars(*r, high_s).expect("high-S sig");
    let high_der: DerSignature = high_sig.to_der();
    assert_eq!(
        verify_p256_low_s(&spki, tbs, high_der.as_bytes()),
        Err(IdentityError::InvalidSignature)
    );
}

#[test]
fn x25519_rotator_rotates_on_12h_slice_and_retains_two_generations() {
    let ks = SoftwareDeviceKeyStore::generate();
    let spki = ks.public_key_spki_der().unwrap();
    let device_id = [0xAB; 16];
    let mut rotator = X25519StaticKeyRotator::new(device_id, false, 0);

    let t0 = 1_700_000_000;
    let cert_exp = t0 + 6 * 3600;
    let g1 = rotator.ensure_current(&ks, t0, cert_exp).unwrap();
    let g1_pub = g1.public_key;
    assert_eq!(g1.delegation_seq, 1);
    assert!(g1.delegation.exp_unix <= cert_exp);
    g1.delegation.verify(&spki, cert_exp, t0).unwrap();

    // Same 12h slice within cert expiry does not rotate.
    let g1_again = rotator.ensure_current(&ks, t0 + 1000, cert_exp).unwrap();
    assert_eq!(g1_again.delegation_seq, 1);
    assert_eq!(g1_again.public_key, g1_pub);

    // Next 12h slice rotates and keeps both generations in memory.
    let t1 = t0 + X25519_SLICE_SECS;
    let cert_exp2 = t1 + 6 * 3600;
    let g2 = rotator.ensure_current(&ks, t1, cert_exp2).unwrap();
    let g2_pub = g2.public_key;
    assert_eq!(g2.delegation_seq, 2);
    assert_ne!(g2_pub, g1_pub);

    let retained: Vec<[u8; 32]> = rotator.retained_generations().map(|g| g.public_key).collect();
    assert_eq!(retained, vec![g2_pub, g1_pub]);

    // Retaining window >= 48h still holds previous generation at +24h.
    rotator.prune_expired(t0 + 24 * 3600);
    assert_eq!(rotator.retained_generations().count(), 2);

    // After 48h retention passes, older generation is pruned while current stays.
    rotator.prune_expired(t0 + 49 * 3600);
    assert_eq!(rotator.retained_generations().count(), 1);
    assert_eq!(rotator.current().unwrap().public_key, g2_pub);
}

#[test]
fn golden_vector_v14_delegation_rollback_and_certs() {
    let v = load_vector("v14_delegation_rollback.json");
    let input = &v["input"];
    let expected = &v["expected"];

    let ca_pub = hex::decode(input["ca_pub_spki_der_hex"].as_str().unwrap()).unwrap();
    let dev_pub = hex::decode(input["device_pub_spki_der_hex"].as_str().unwrap()).unwrap();
    let device_id: [u8; 16] = decode_hex_arr(input["device_id_hex"].as_str().unwrap());
    let cert_exp = input["devcert_exp_unix"].as_u64().unwrap();
    let cert_key_epoch = input["devcert_key_epoch"].as_u64().unwrap();

    // 1. Verify DeviceCert TBS + low-S signature.
    let devcert_tbs_expected = hex::decode(input["devcert_tbs_hex"].as_str().unwrap()).unwrap();
    let devcert_sig = hex::decode(input["devcert_sig_der_hex"].as_str().unwrap()).unwrap();
    let cert = DeviceCert {
        version: u32::from_be_bytes(devcert_tbs_expected[13..17].try_into().unwrap()),
        cert_id: devcert_tbs_expected[17..33].try_into().unwrap(),
        device_id,
        tenant_id: devcert_tbs_expected[49..65].try_into().unwrap(),
        p256_pub_der: dev_pub.clone(),
        key_epoch: cert_key_epoch,
        policy_hash: devcert_tbs_expected[67 + dev_pub.len() + 8..67 + dev_pub.len() + 40]
            .try_into()
            .unwrap(),
        cap_bits: u64::from_be_bytes(
            devcert_tbs_expected[67 + dev_pub.len() + 40..67 + dev_pub.len() + 48]
                .try_into()
                .unwrap(),
        ),
        iat_unix: u64::from_be_bytes(
            devcert_tbs_expected[67 + dev_pub.len() + 48..67 + dev_pub.len() + 56]
                .try_into()
                .unwrap(),
        ),
        exp_unix: cert_exp,
        hardware_backed: false,
        sig_der: devcert_sig,
    };
    assert_eq!(cert.tbs_bytes().unwrap(), devcert_tbs_expected);
    cert.verify(&ca_pub, cert_exp - 10).unwrap();

    // 2. Verify TenantPolicyBlob and cross-tenant replay rejection.
    let tpb_json = &input["tenant_policy_blob"];
    let tpb = TenantPolicyBlob {
        tenant_id: decode_hex_arr(tpb_json["tenant_id_hex"].as_str().unwrap()),
        version: tpb_json["version"].as_u64().unwrap(),
        policy_hash: decode_hex_arr(tpb_json["policy_hash_hex"].as_str().unwrap()),
        iat_unix: tpb_json["iat_unix"].as_u64().unwrap(),
        exp_unix: tpb_json["exp_unix"].as_u64().unwrap(),
        sig_der: hex::decode(tpb_json["sig_der_hex"].as_str().unwrap()).unwrap(),
    };
    assert_eq!(
        hex::encode(tpb.tbs_bytes()),
        tpb_json["tbs_hex"].as_str().unwrap()
    );
    tpb.verify(&ca_pub, &tpb.tenant_id, tpb.iat_unix + 10).unwrap();
    let other_tenant: [u8; 16] = decode_hex_arr(tpb_json["other_tenant_id_hex"].as_str().unwrap());
    assert_eq!(
        tpb.verify(&ca_pub, &other_tenant, tpb.iat_unix + 10),
        Err(IdentityError::BindingMismatch)
    );
    let mut forged_tpb = tpb.clone();
    forged_tpb.tenant_id = other_tenant;
    assert_eq!(
        hex::encode(forged_tpb.tbs_bytes()),
        tpb_json["cross_tenant_tbs_hex"].as_str().unwrap()
    );
    assert_eq!(
        forged_tpb.verify(&ca_pub, &other_tenant, tpb.iat_unix + 10),
        Err(IdentityError::InvalidSignature)
    );

    // 3. Verify RevocationNotice and revocation enforcement.
    let rev_json = &input["revocation_notice"];
    let rev = RevocationNotice {
        device_id: decode_hex_arr(rev_json["device_id_hex"].as_str().unwrap()),
        min_key_epoch: rev_json["min_key_epoch"].as_u64().unwrap(),
        iat_unix: rev_json["iat_unix"].as_u64().unwrap(),
        sig_der: hex::decode(rev_json["sig_der_hex"].as_str().unwrap()).unwrap(),
    };
    assert_eq!(
        hex::encode(rev.tbs_bytes()),
        rev_json["tbs_hex"].as_str().unwrap()
    );
    rev.verify(&ca_pub).unwrap();
    let rev_err = cert.check_revocation(&rev, &ca_pub).unwrap_err();
    assert_eq!(rev_err, IdentityError::CertRevoked);
    assert_eq!(
        rev_err.error_code(),
        expected["revocation_triggers_cert_revoked_err"].as_u64().unwrap() as u16
    );
    assert_eq!(rev_err.error_code(), ERR_CERT_REVOKED);

    let mut tampered_rev = rev.clone();
    tampered_rev.min_key_epoch = 4;
    assert_eq!(
        hex::encode(tampered_rev.tbs_bytes()),
        rev_json["tampered_tbs_hex"].as_str().unwrap()
    );
    assert_eq!(
        tampered_rev.verify(&ca_pub),
        Err(IdentityError::InvalidSignature)
    );

    // 4. DelegationStatement rollback, key substitution, exp+/-1s, and StaticKeyHint.
    let parse_deleg = |obj: &Value| DelegationStatement {
        device_id,
        x25519_pub: decode_hex_arr(obj["x25519_pub_hex"].as_str().unwrap()),
        prefer_chacha: obj["prefer_chacha"].as_bool().unwrap(),
        delegation_seq: obj["delegation_seq"].as_u64().unwrap(),
        exp_unix: obj["exp_unix"].as_u64().unwrap(),
        sig_der: hex::decode(obj["sig_der_hex"].as_str().unwrap()).unwrap(),
    };

    let d10 = parse_deleg(&input["deleg_seq10_valid"]);
    assert_eq!(
        hex::encode(d10.tbs_bytes()),
        input["deleg_seq10_valid"]["tbs_hex"].as_str().unwrap()
    );

    let mut cache = DelegationCache::new();
    // exp - 1s accepted
    assert!(expected["seq10_at_exp_minus_1_accept"].as_bool().unwrap());
    cache
        .verify_and_record(&d10, &dev_pub, cert_exp, d10.exp_unix - 1)
        .unwrap();

    // exp + 1s rejected with 0x0201 (513)
    let exp_err = cache
        .verify_and_record(&d10, &dev_pub, cert_exp, d10.exp_unix + 1)
        .unwrap_err();
    assert_eq!(exp_err.error_code(), ERR_CERT_EXPIRED);
    assert_eq!(
        exp_err.error_code(),
        expected["seq10_at_exp_plus_1_err"].as_u64().unwrap() as u16
    );

    // seq 9 rollback rejected with 0x0203 (515)
    let d9 = parse_deleg(&input["deleg_seq9_rollback"]);
    assert_eq!(
        hex::encode(d9.tbs_bytes()),
        input["deleg_seq9_rollback"]["tbs_hex"].as_str().unwrap()
    );
    let rb_err = cache
        .verify_and_record(&d9, &dev_pub, cert_exp, d9.exp_unix - 1)
        .unwrap_err();
    assert_eq!(rb_err.error_code(), ERR_DELEGATION_ROLLBACK);
    assert_eq!(
        rb_err.error_code(),
        expected["seq9_rollback_err"].as_u64().unwrap() as u16
    );

    // seq 10 substituted key rejected with 0x0203 (515)
    let d10_sub = parse_deleg(&input["deleg_seq10_substituted_key"]);
    assert_eq!(
        hex::encode(d10_sub.tbs_bytes()),
        input["deleg_seq10_substituted_key"]["tbs_hex"].as_str().unwrap()
    );
    let sub_err = cache
        .verify_and_record(&d10_sub, &dev_pub, cert_exp, d10_sub.exp_unix - 1)
        .unwrap_err();
    assert_eq!(sub_err.error_code(), ERR_DELEGATION_ROLLBACK);
    assert_eq!(
        sub_err.error_code(),
        expected["seq10_sub_key_err"].as_u64().unwrap() as u16
    );

    // seq 11 exceeding DeviceCert.exp_unix rejected with 0x0201 (513)
    let d11_bad_exp = parse_deleg(&input["deleg_seq11_exceeds_cert_exp"]);
    assert_eq!(
        hex::encode(d11_bad_exp.tbs_bytes()),
        input["deleg_seq11_exceeds_cert_exp"]["tbs_hex"].as_str().unwrap()
    );
    let bad_exp_err = cache
        .verify_and_record(&d11_bad_exp, &dev_pub, cert_exp, cert_exp - 100)
        .unwrap_err();
    assert_eq!(bad_exp_err.error_code(), ERR_CERT_EXPIRED);
    assert_eq!(
        bad_exp_err.error_code(),
        expected["seq11_exceeds_cert_exp_err"].as_u64().unwrap() as u16
    );

    // StaticKeyHint retry succeeds once per handshake session and rejects a second retry
    // in the same session, without deadlocking a subsequent handshake session.
    let d11_hint = parse_deleg(&input["deleg_seq11_hint_valid"]);
    assert_eq!(
        hex::encode(d11_hint.tbs_bytes()),
        input["deleg_seq11_hint_valid"]["tbs_hex"].as_str().unwrap()
    );
    let mut hint_retry = StaticKeyHintRetry::new();
    let hs_session_1 = [0x01; 16];
    hint_retry
        .accept_hint(
            hs_session_1,
            &mut cache,
            &d11_hint,
            &dev_pub,
            cert_exp,
            d11_hint.exp_unix - 10,
        )
        .unwrap();
    assert_eq!(
        hint_retry.retries_used(&hs_session_1) as u64,
        expected["static_key_hint_max_retries"].as_u64().unwrap()
    );
    assert_eq!(
        hint_retry.accept_hint(
            hs_session_1,
            &mut cache,
            &d11_hint,
            &dev_pub,
            cert_exp,
            d11_hint.exp_unix - 10,
        ),
        Err(IdentityError::RetryLimitExceeded)
    );
}

#[test]
fn golden_vector_v04_edge_cert_and_v24_preempt_token() {
    // V04 EdgeCert verification
    let v04 = load_vector("v04_noise_downgrade_reject.json");
    let ca_pub = hex::decode(v04["input"]["ca_pub_spki_der_hex"].as_str().unwrap()).unwrap();
    let edge_tbs = hex::decode(v04["input"]["edge_cert_tbs_hex"].as_str().unwrap()).unwrap();
    let edge_sig = hex::decode(v04["input"]["edge_cert_sig_der_hex"].as_str().unwrap()).unwrap();
    let edge_cert = EdgeCert {
        version: u32::from_be_bytes(edge_tbs[14..18].try_into().unwrap()),
        pop_id: edge_tbs[18..26].try_into().unwrap(),
        x25519_pub: edge_tbs[26..58].try_into().unwrap(),
        iat_unix: u64::from_be_bytes(edge_tbs[58..66].try_into().unwrap()),
        exp_unix: u64::from_be_bytes(edge_tbs[66..74].try_into().unwrap()),
        sig_der: edge_sig,
    };
    assert_eq!(edge_cert.tbs_bytes(), edge_tbs);
    assert_eq!(
        hex::encode(edge_cert.tbs_sha256()),
        v04["expected"]["edge_cert_tbs_sha256_hex"].as_str().unwrap()
    );
    edge_cert.verify(&ca_pub, edge_cert.iat_unix + 10).unwrap();

    // V24 ControlPreemptToken verification
    let v24 = load_vector("v24_realtime_actuator_and_survival.json");
    let pt = &v24["input"]["preempt_token"];
    let pt_ca = hex::decode(pt["ca_pub_spki_der_hex"].as_str().unwrap()).unwrap();
    let tenant_id: [u8; 16] = decode_hex_arr(pt["tenant_id_hex"].as_str().unwrap());
    let drone_id: [u8; 16] = decode_hex_arr(pt["drone_device_id_hex"].as_str().unwrap());
    let operator_id: [u8; 16] = decode_hex_arr(pt["operator_id_hex"].as_str().unwrap());
    let token = ControlPreemptToken {
        tenant_id,
        drone_device_id: drone_id,
        operator_id,
        new_control_epoch: pt["new_control_epoch"].as_u64().unwrap() as u32,
        iat_unix: pt["iat_unix"].as_u64().unwrap(),
        exp_unix: pt["exp_unix"].as_u64().unwrap(),
        sig_der: hex::decode(pt["sig_der_hex"].as_str().unwrap()).unwrap(),
    };
    assert_eq!(
        hex::encode(token.tbs_bytes()),
        pt["tbs_hex"].as_str().unwrap()
    );
    let now_unix = pt["now_unix"].as_u64().unwrap();
    token
        .verify(&pt_ca, &tenant_id, &drone_id, now_unix)
        .unwrap();

    let mut bad_token = token.clone();
    bad_token.sig_der = hex::decode(pt["bad_sig_der_hex"].as_str().unwrap()).unwrap();
    assert_eq!(
        bad_token.verify(&pt_ca, &tenant_id, &drone_id, now_unix),
        Err(IdentityError::InvalidSignature)
    );
}

#[test]
fn x25519_rotator_persists_state_across_restart_and_hint_retry_is_per_session() {
    let ks = SoftwareDeviceKeyStore::generate();
    let spki = ks.public_key_spki_der().unwrap();
    let device_id = [0xCD; 16];
    let t0 = 1_700_000_000;
    let cert_exp = t0 + 6 * 3600;

    let mut rotator = X25519StaticKeyRotator::new(device_id, true, 9);
    let g10 = rotator.ensure_current(&ks, t0, cert_exp).unwrap();
    let d10 = g10.delegation.clone();
    assert_eq!(d10.delegation_seq, 10);

    let mut cache = DelegationCache::new();
    cache.verify_and_record(&d10, &spki, cert_exp, t0).unwrap();

    // Persist state to disk atomically (temp + sync_all + rename) and reload after restart.
    let tmp_dir = std::env::temp_dir().join(format!(
        "zerodesk_rotator_atomic_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).unwrap();
    let tmp_path = tmp_dir.join("rotator_state.bin");
    rotator.save_state(&tmp_path).unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&tmp_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    let mut restarted = X25519StaticKeyRotator::load_state(&tmp_path).unwrap();
    assert_eq!(restarted.last_delegation_seq(), 10);
    assert_eq!(restarted.retained_metadata().len(), 1);

    // After restart, new in-memory key MUST advance to seq 11 (never colliding on seq 10).
    let g11 = restarted.ensure_current(&ks, t0 + 5, cert_exp).unwrap();
    let d11 = g11.delegation.clone();
    assert_eq!(d11.delegation_seq, 11);
    assert_ne!(d11.x25519_pub, d10.x25519_pub);

    // Atomic overwrite leaves zero leftover temp files and advances persisted sequence.
    restarted.save_state(&tmp_path).unwrap();
    let entries: Vec<_> = std::fs::read_dir(&tmp_dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        X25519StaticKeyRotator::load_state(&tmp_path)
            .unwrap()
            .last_delegation_seq(),
        11
    );
    let _ = std::fs::remove_dir_all(&tmp_dir);

    // StaticKeyHintRetry tracks retries per handshake session instead of deadlocking globally.
    let mut hint_retry = StaticKeyHintRetry::new();
    let session_a = [0xA1; 16];
    let session_b = [0xB2; 16];

    hint_retry
        .accept_hint(session_a, &mut cache, &d11, &spki, cert_exp, t0 + 10)
        .unwrap();
    assert_eq!(hint_retry.retries_used(&session_a), 1);
    assert_eq!(
        hint_retry.accept_hint(session_a, &mut cache, &d11, &spki, cert_exp, t0 + 11),
        Err(IdentityError::RetryLimitExceeded)
    );

    // Rotate again to seq 12: a fresh handshake session B MUST still get its 1 retry.
    let d12 = restarted
        .rotate_now(&ks, t0 + 20, cert_exp)
        .unwrap()
        .delegation
        .clone();
    assert_eq!(d12.delegation_seq, 12);
    hint_retry
        .accept_hint(session_b, &mut cache, &d12, &spki, cert_exp, t0 + 25)
        .unwrap();
    assert_eq!(hint_retry.retries_used(&session_b), 1);
    assert_eq!(
        hint_retry.accept_hint(session_b, &mut cache, &d12, &spki, cert_exp, t0 + 26),
        Err(IdentityError::RetryLimitExceeded)
    );

    // Wire round-trip + DH shared secret returns Zeroizing<[u8; 32]>.
    let wire = d12.encode_wire().unwrap();
    assert_eq!(DelegationStatement::decode_wire(&wire).unwrap(), d12);
    assert!(DelegationStatement::decode_wire(b"host-delegation").is_err());

    let shared = restarted.current().unwrap().diffie_hellman(d10.x25519_pub);
    assert_eq!(shared.len(), 32);
}

#[test]
fn certs_reject_future_iat_and_excessive_ttl_and_keystore_sets_0600() {
    let ca = SoftwareDeviceKeyStore::generate();
    let ca_spki = ca.public_key_spki_der().unwrap();
    let dev = SoftwareDeviceKeyStore::generate();
    let dev_spki = dev.public_key_spki_der().unwrap();

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let key_path = std::env::temp_dir().join(format!(
            "zerodesk_pkcs8_mode_{}.der",
            std::process::id()
        ));
        dev.save_pkcs8_der(&key_path).unwrap();
        let mode = std::fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let reloaded = SoftwareDeviceKeyStore::load_pkcs8_der(&key_path).unwrap();
        assert_eq!(reloaded.public_key_spki_der().unwrap(), dev_spki);
        let _ = std::fs::remove_file(&key_path);
    }

    let now = 1_700_000_000;
    let mut cert = DeviceCert {
        version: 1,
        cert_id: [1; 16],
        device_id: [2; 16],
        tenant_id: [3; 16],
        p256_pub_der: dev_spki,
        key_epoch: 1,
        policy_hash: [4; 32],
        cap_bits: 1,
        iat_unix: now + 60, // future iat
        exp_unix: now + 3600,
        hardware_backed: false,
        sig_der: Vec::new(),
    };
    cert.sig_der = ca.sign_p256_low_s(&cert.tbs_bytes().unwrap()).unwrap();
    assert_eq!(cert.verify(&ca_spki, now), Err(IdentityError::CertExpired));

    // Excessive TTL (> 24h max for DeviceCert) rejected even with valid signature.
    cert.iat_unix = now;
    cert.exp_unix = now + 30 * 86_400;
    cert.sig_der = ca.sign_p256_low_s(&cert.tbs_bytes().unwrap()).unwrap();
    assert_eq!(cert.verify(&ca_spki, now + 10), Err(IdentityError::CertExpired));

    // Reasonable TTL within [iat, exp] succeeds.
    cert.exp_unix = now + 6 * 3600;
    cert.sig_der = ca.sign_p256_low_s(&cert.tbs_bytes().unwrap()).unwrap();
    cert.verify(&ca_spki, now + 10).unwrap();
}
