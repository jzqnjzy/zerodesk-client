// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use std::{
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use zerodesk_core::{
    bridge::json_abi::parse_and_validate_command,
    os::{EmergencyKeyReleaser, OsError, OsHidSink, ReleaseReport},
    parse_bridge_event_forward_compat,
    session::hid::{KeyEvent, MouseEvent, MouseKind},
    BridgeEvent, ClipboardSyncStatusPayload, CodecAckPayload, FileTransferCompletePayload,
    GatedOsHidSink, HandshakeCapabilitiesData, HudStatsPayload, InputEnabledAckPayload,
    OsInputGateError, ParsedBridgeEvent, PermissionProbe, PermissionProbeSource,
    PermissionStatusReport, RuntimeReplyEnvelope, V2BridgeRuntime, V2BridgeRuntimeOptions,
    BRIDGE_JSON_ABI_V2,
};

fn golden_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name)
}

fn read_golden(name: &str) -> String {
    std::fs::read_to_string(golden_path(name))
        .unwrap_or_else(|e| panic!("failed to read golden fixture {name}: {e}"))
}

struct MockPermissionProbe {
    screen: AtomicBool,
    ax: AtomicBool,
    source_is_watchdog: AtomicBool,
}

impl MockPermissionProbe {
    fn new(screen: bool, ax: bool, source_is_watchdog: bool) -> Self {
        Self {
            screen: AtomicBool::new(screen),
            ax: AtomicBool::new(ax),
            source_is_watchdog: AtomicBool::new(source_is_watchdog),
        }
    }
}

impl PermissionProbe for MockPermissionProbe {
    fn probe(
        &self,
        watchdog_ax_override: Option<bool>,
        enable_os_input: bool,
    ) -> PermissionStatusReport {
        let screen = self.screen.load(Ordering::Acquire);
        let ax = watchdog_ax_override.unwrap_or_else(|| self.ax.load(Ordering::Acquire));
        let probe_source = if watchdog_ax_override.is_some()
            || self.source_is_watchdog.load(Ordering::Acquire)
        {
            PermissionProbeSource::Watchdog
        } else {
            PermissionProbeSource::UiProcessHint
        };
        PermissionStatusReport {
            screen_capture_granted: screen,
            accessibility_granted: ax,
            probe_source,
            enable_os_input,
            secure_event_input_enabled: Some(false),
        }
    }
}

struct SpyInjectorSink {
    key_calls: Arc<AtomicUsize>,
    mouse_calls: Arc<AtomicUsize>,
    release_calls: Arc<AtomicUsize>,
}

struct SpyReleaser {
    release_calls: Arc<AtomicUsize>,
}

impl EmergencyKeyReleaser for SpyReleaser {
    fn release_all_keys(&self) -> ReleaseReport {
        self.release_calls.fetch_add(1, Ordering::AcqRel);
        ReleaseReport::default()
    }
}

impl OsHidSink for SpyInjectorSink {
    fn send_key(&mut self, _ev: &KeyEvent) -> Result<(), OsError> {
        self.key_calls.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn send_mouse(&mut self, _ev: &MouseEvent) -> Result<(), OsError> {
        self.mouse_calls.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
        Arc::new(SpyReleaser {
            release_calls: Arc::clone(&self.release_calls),
        })
    }
}

#[test]
fn golden_abi_v2_handshake_matches_live_runtime_exactly() {
    let expected_raw = read_golden("abi_v2_handshake_reply.json");
    let expected_val: serde_json::Value = serde_json::from_str(&expected_raw).unwrap();
    let expected_env: RuntimeReplyEnvelope = serde_json::from_str(&expected_raw).unwrap();
    assert!(expected_env.ok);
    let expected_caps: HandshakeCapabilitiesData =
        serde_json::from_value(expected_env.data.unwrap()).unwrap();
    assert_eq!(expected_caps.abi_version, BRIDGE_JSON_ABI_V2);

    let rt = V2BridgeRuntime::new().unwrap();
    let live_raw = rt.exec_json(r#"{"v":1,"cmd":"handshake"}"#);
    let live_val: serde_json::Value = serde_json::from_str(&live_raw).unwrap();
    assert_eq!(
        live_val, expected_val,
        "live handshake reply drifted from golden abi_v2_handshake_reply.json"
    );

    // Snapshot also exposes additive abi_version + caps + enable_os_input = false by default.
    let snap = rt.snapshot();
    assert_eq!(snap.abi_version, Some(BRIDGE_JSON_ABI_V2));
    assert_eq!(snap.caps, Some(expected_caps.caps));
    assert_eq!(snap.enable_os_input, Some(false));
}

#[test]
fn golden_abi_v2_requests_and_events_round_trip_and_ignore_unknown_fields() {
    // Requests
    let get_perm_req =
        parse_and_validate_command(&read_golden("abi_v2_get_permissions_req.json")).unwrap();
    assert_eq!(get_perm_req.cmd, "get_permissions");

    let set_input_req =
        parse_and_validate_command(&read_golden("abi_v2_set_input_enabled_req.json")).unwrap();
    assert_eq!(set_input_req.cmd, "set_input_enabled");
    assert_eq!(set_input_req.enabled, Some(true));
    assert_eq!(set_input_req.reason.as_deref(), Some("user_toggle"));

    let quality_req =
        parse_and_validate_command(&read_golden("abi_v2_set_video_quality_req.json")).unwrap();
    assert_eq!(quality_req.cmd, "set_video_quality");
    assert_eq!(quality_req.bitrate_kbps, Some(10_000));
    assert_eq!(quality_req.fps_cap, Some(60));

    // Request with unknown extra fields & type field MUST be accepted cleanly.
    let req_with_unknowns = parse_and_validate_command(
        r#"{"v":1,"cmd":"get_permissions","type":"get_permissions","future_field":{"a":1}}"#,
    )
    .unwrap();
    assert_eq!(req_with_unknowns.cmd, "get_permissions");

    // Events
    let perm_ev =
        parse_bridge_event_forward_compat(&read_golden("abi_v2_permission_status_event.json"))
            .unwrap();
    assert_eq!(
        perm_ev,
        ParsedBridgeEvent::PermissionStatus(PermissionStatusReport {
            screen_capture_granted: true,
            accessibility_granted: false,
            probe_source: PermissionProbeSource::Watchdog,
            enable_os_input: false,
            secure_event_input_enabled: Some(false),
        })
    );

    // Backward-compat alias `watchdog_or_injector_process` -> InjectorProcess, unknown -> Unknown(...)
    let legacy_ps = parse_bridge_event_forward_compat(
        r#"{"v":1,"seq":1,"kind":"permission_status","payload":{"screen_capture_granted":true,"accessibility_granted":true,"probe_source":"watchdog_or_injector_process","enable_os_input":false}}"#,
    )
    .unwrap();
    assert!(matches!(
        legacy_ps,
        ParsedBridgeEvent::PermissionStatus(PermissionStatusReport {
            probe_source: PermissionProbeSource::InjectorProcess,
            ..
        })
    ));
    let unknown_ps = parse_bridge_event_forward_compat(
        r#"{"v":1,"seq":2,"kind":"permission_status","payload":{"screen_capture_granted":true,"accessibility_granted":true,"probe_source":"future_xpc_daemon","enable_os_input":false}}"#,
    )
    .unwrap();
    match unknown_ps {
        ParsedBridgeEvent::PermissionStatus(rep) => {
            assert_eq!(
                rep.probe_source,
                PermissionProbeSource::Unknown("future_xpc_daemon".into())
            );
            assert!(!rep.probe_source.is_authoritative());
        }
        other => panic!("expected PermissionStatus with Unknown probe_source, got {other:?}"),
    }

    let ack_ev =
        parse_bridge_event_forward_compat(&read_golden("abi_v2_input_enabled_ack_event.json"))
            .unwrap();
    assert_eq!(
        ack_ev,
        ParsedBridgeEvent::InputEnabledAck(InputEnabledAckPayload {
            enabled: false,
            status: "not_permitted".into(),
            screen_capture_granted: Some(true),
            accessibility_granted: Some(false),
            probe_source: Some("ui_process_hint".into()),
            reason: None,
            release_all: None,
        })
    );

    let hud_ev =
        parse_bridge_event_forward_compat(&read_golden("abi_v2_hud_stats_event.json")).unwrap();
    assert_eq!(
        hud_ev,
        ParsedBridgeEvent::HudStats(HudStatsPayload {
            fps: 59.8,
            decode_ms: 1.45,
            active_codec: "hevc".into(),
            transport_mode: "udp".into(),
            rtt_ms: 11.2,
            bitrate_kbps: 8450,
        })
    );

    let codec_ev =
        parse_bridge_event_forward_compat(&read_golden("abi_v2_codec_ack_event.json")).unwrap();
    assert_eq!(
        codec_ev,
        ParsedBridgeEvent::CodecAck(CodecAckPayload {
            active_codec: "hevc".into(),
            requested_codec: Some("hevc".into()),
            accepted: true,
        })
    );

    let clip_ev =
        parse_bridge_event_forward_compat(&read_golden("abi_v2_clipboard_sync_status_event.json"))
            .unwrap();
    assert_eq!(
        clip_ev,
        ParsedBridgeEvent::ClipboardSyncStatus(ClipboardSyncStatusPayload {
            enabled: false,
            status: "policy_denied".into(),
            code: Some("policy_denied".into()),
        })
    );

    let ft_ev = parse_bridge_event_forward_compat(&read_golden(
        "abi_v2_file_transfer_complete_event.json",
    ))
    .unwrap();
    let expected_ft = FileTransferCompletePayload {
        transfer_id: 7,
        rel_name: "report.pdf".into(),
        bytes: 0,
        sha256_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
        checksum_algo: Some("sha256".into()),
        saved_path: Some("/tmp/report.pdf".into()),
    };
    assert_eq!(ft_ev, ParsedBridgeEvent::FileTransferComplete(expected_ft.clone()));
    // Debug formatting MUST redact saved_path!
    let ft_dbg = format!("{expected_ft:?}");
    assert!(!ft_dbg.contains("/tmp/report.pdf"));
    assert!(ft_dbg.contains("<redacted>"));

    // Legacy PascalCase `"FileTransferComplete"` alias MUST still decode identically.
    let legacy_ft = parse_bridge_event_forward_compat(
        r#"{"v":1,"seq":48,"kind":"FileTransferComplete","payload":{"transfer_id":7,"rel_name":"report.pdf","bytes":0,"sha256_hex":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","checksum_algo":"sha256","saved_path":"/tmp/report.pdf"}}"#,
    )
    .unwrap();
    assert_eq!(legacy_ft, ParsedBridgeEvent::FileTransferComplete(expected_ft));

    // Malformed known event kind MUST be distinguished from Unknown.
    let malformed = parse_bridge_event_forward_compat(
        r#"{"v":1,"seq":50,"kind":"codec_ack","payload":{"wrong_field":123}}"#,
    )
    .unwrap();
    assert!(matches!(
        malformed,
        ParsedBridgeEvent::Malformed { ref kind, .. } if kind == "codec_ack"
    ));

    // Future envelope version (`v > 1`) MUST map cleanly to Unknown.
    let future_v = parse_bridge_event_forward_compat(
        r#"{"v":99,"seq":51,"kind":"codec_ack","payload":{}}"#,
    )
    .unwrap();
    assert_eq!(
        future_v,
        ParsedBridgeEvent::Unknown {
            kind: "codec_ack".into()
        }
    );

    // Unknown event kind + unknown top-level & nested fields MUST decode cleanly as Unknown without error!
    let unknown_raw = read_golden("abi_v2_unknown_event_and_fields.json");
    let unknown_ev = parse_bridge_event_forward_compat(&unknown_raw).unwrap();
    assert_eq!(
        unknown_ev,
        ParsedBridgeEvent::Unknown {
            kind: "future_phase9_event_type".into()
        }
    );
    let raw_bridge_ev: BridgeEvent = serde_json::from_str(&unknown_raw).unwrap();
    assert_eq!(raw_bridge_ev.seq, 99);
}

#[test]
fn runtime_permission_probe_and_secondary_enable_os_input_gate_fail_closed() {
    let probe = Arc::new(MockPermissionProbe::new(true, false, false));
    let rt = V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
        permission_probe: Some(Arc::clone(&probe) as Arc<dyn PermissionProbe>),
        ..V2BridgeRuntimeOptions::default()
    })
    .unwrap();

    // 1. Default state is View-Only (`enable_os_input == false`).
    assert_eq!(rt.snapshot().enable_os_input, Some(false));

    // 2. get_permissions returns structured report + emits permission_status event ONCE on change
    //    (subsequent identical polls MUST NOT flood the critical queue!).
    let perm_reply: serde_json::Value =
        serde_json::from_str(&rt.exec_json(r#"{"v":1,"cmd":"get_permissions"}"#)).unwrap();
    assert_eq!(perm_reply["ok"], true);
    assert_eq!(perm_reply["data"]["screen_capture_granted"], true);
    assert_eq!(perm_reply["data"]["accessibility_granted"], false);
    assert_eq!(perm_reply["data"]["probe_source"], "ui_process_hint");
    assert_eq!(perm_reply["data"]["enable_os_input"], false);

    let ev_raw = rt
        .poll_event_json_timeout(Duration::from_millis(500))
        .expect("permission_status event expected on first probe");
    let parsed_ev = parse_bridge_event_forward_compat(&ev_raw).unwrap();
    assert!(matches!(parsed_ev, ParsedBridgeEvent::PermissionStatus(_)));

    // Second identical get_permissions call must NOT push a duplicate permission_status event.
    let perm_reply2: serde_json::Value =
        serde_json::from_str(&rt.exec_json(r#"{"v":1,"cmd":"get_permissions"}"#)).unwrap();
    assert_eq!(perm_reply2["ok"], true);
    assert!(rt.poll_event_json().is_none());

    // 3. Attempting to enable OS input while Accessibility is missing MUST fail closed with "not_permitted"!
    let denied_reply: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"set_input_enabled","enabled":true}"#),
    )
    .unwrap();
    assert_eq!(denied_reply["ok"], false);
    assert_eq!(denied_reply["error_code"], "not_permitted");
    assert_eq!(rt.snapshot().enable_os_input, Some(false));

    let ack_raw = rt
        .poll_event_json_timeout(Duration::from_millis(500))
        .expect("input_enabled_ack event expected");
    match parse_bridge_event_forward_compat(&ack_raw).unwrap() {
        ParsedBridgeEvent::InputEnabledAck(ack) => {
            assert!(!ack.enabled);
            assert_eq!(ack.status, "not_permitted");
        }
        other => panic!("expected InputEnabledAck, got {other:?}"),
    }

    // 3b. ui_process_hint + ax=true + screen=true MUST STILL fail closed with "not_permitted"!
    probe.ax.store(true, Ordering::Release);
    probe.source_is_watchdog.store(false, Ordering::Release);
    let ui_hint_denied: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"set_input_enabled","enabled":true}"#),
    )
    .unwrap();
    assert_eq!(ui_hint_denied["ok"], false);
    assert_eq!(ui_hint_denied["error_code"], "not_permitted");
    assert_eq!(rt.snapshot().enable_os_input, Some(false));
    let _ = rt.poll_event_json_timeout(Duration::from_millis(200));

    // 3c. screen_capture=false + ax=true + watchdog MUST fail closed with "not_permitted"!
    probe.screen.store(false, Ordering::Release);
    probe.source_is_watchdog.store(true, Ordering::Release);
    let no_screen_denied: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"set_input_enabled","enabled":true}"#),
    )
    .unwrap();
    assert_eq!(no_screen_denied["ok"], false);
    assert_eq!(no_screen_denied["error_code"], "not_permitted");
    assert_eq!(rt.snapshot().enable_os_input, Some(false));
    let _ = rt.poll_event_json_timeout(Duration::from_millis(200));

    // 4. Even with authoritative watchdog + screen=true + ax=true, Idle (not Streaming) MUST fail closed!
    probe.screen.store(true, Ordering::Release);
    let idle_denied: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"set_input_enabled","enabled":true}"#),
    )
    .unwrap();
    assert_eq!(idle_denied["ok"], false);
    assert_eq!(idle_denied["error_code"], "IllegalStateTransition");
    assert_eq!(rt.snapshot().enable_os_input, Some(false));
    let _ = rt.poll_event_json_timeout(Duration::from_millis(200));

    // 5. Missing `enabled` on `set_input_enabled` / `enable_os_input` MUST be rejected with InvalidArgument.
    for cmd in ["set_input_enabled", "enable_os_input"] {
        let missing: serde_json::Value = serde_json::from_str(
            &rt.exec_json(&format!(r#"{{"v":1,"cmd":"{cmd}"}}"#)),
        )
        .unwrap();
        assert_eq!(missing["ok"], false);
        assert_eq!(missing["error_code"], "InvalidArgument");
    }

    // 6. Emergency escape release_all works unconditionally (even with invalid buttons bitmask 0xFF)
    //    and emits input_enabled_ack { enabled: false, reason: "emergency_escape" }!
    let esc_reply: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"release_all","emergency_escape":true,"buttons":255}"#),
    )
    .unwrap();
    assert_eq!(esc_reply["ok"], true);
    assert_eq!(rt.snapshot().enable_os_input, Some(false));

    let esc_ack_raw = rt
        .poll_event_json_timeout(Duration::from_millis(500))
        .expect("emergency escape input_enabled_ack expected");
    match parse_bridge_event_forward_compat(&esc_ack_raw).unwrap() {
        ParsedBridgeEvent::InputEnabledAck(ack) => {
            assert!(!ack.enabled);
            assert_eq!(ack.status, "disabled");
            assert_eq!(ack.reason.as_deref(), Some("emergency_escape"));
        }
        other => panic!("expected InputEnabledAck(disabled), got {other:?}"),
    }

    // 7. Out-of-range set_video_quality inputs (`bitrate_kbps: -1`, `fps_cap: 0`, `v: 99`) MUST be rejected!
    for bad in [
        r#"{"v":1,"cmd":"set_video_quality","bitrate_kbps":-1,"fps_cap":60}"#,
        r#"{"v":1,"cmd":"set_video_quality","bitrate_kbps":5000,"fps_cap":0}"#,
        r#"{"v":99,"cmd":"set_video_quality","bitrate_kbps":5000,"fps_cap":60}"#,
        r#"{"v":1,"cmd":"set_video_quality","bitrate_kbps":100,"fps_cap":60}"#,
        r#"{"v":1,"cmd":"set_video_quality","bitrate_kbps":5000,"fps_cap":121}"#,
    ] {
        let bad_reply: serde_json::Value = serde_json::from_str(&rt.exec_json(bad)).unwrap();
        assert_eq!(bad_reply["ok"], false, "expected rejection for {bad}");
    }

    // 8. Valid video quality & clipboard sync commands work and update snapshot.
    let q_reply: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"set_video_quality","bitrate_kbps":5000,"fps_cap":60}"#),
    )
    .unwrap();
    assert_eq!(q_reply["ok"], true);
    assert_eq!(q_reply["data"]["bitrate_kbps"], 5000);
    assert_eq!(q_reply["data"]["fps_cap"], 60);
    assert_eq!(rt.snapshot().bitrate_kbps, Some(5000));
    assert_eq!(rt.snapshot().fps_cap, Some(60));

    let clip_reply: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"set_clipboard_sync","enabled":false}"#),
    )
    .unwrap();
    assert_eq!(clip_reply["ok"], true);
    assert_eq!(rt.snapshot().clipboard_sync_enabled, Some(false));

    // 9. Session non-persistence: recreating V2BridgeRuntime always starts with enable_os_input = false!
    rt.destroy();
    let rt2 = V2BridgeRuntime::with_options(V2BridgeRuntimeOptions {
        permission_probe: Some(Arc::clone(&probe) as Arc<dyn PermissionProbe>),
        ..V2BridgeRuntimeOptions::default()
    })
    .unwrap();
    assert_eq!(rt2.snapshot().enable_os_input, Some(false));
    rt2.destroy();
}

#[test]
fn unpermitted_or_disabled_os_input_injector_receives_zero_calls_and_returns_not_permitted() {
    let key_calls = Arc::new(AtomicUsize::new(0));
    let mouse_calls = Arc::new(AtomicUsize::new(0));
    let release_calls = Arc::new(AtomicUsize::new(0));
    let enable_os_input = Arc::new(AtomicBool::new(false));
    let screen_granted = Arc::new(AtomicBool::new(false));
    let ax_granted = Arc::new(AtomicBool::new(false));

    let sc = Arc::clone(&screen_granted);
    let ax = Arc::clone(&ax_granted);
    let mut gated = GatedOsHidSink::new(
        Box::new(SpyInjectorSink {
            key_calls: Arc::clone(&key_calls),
            mouse_calls: Arc::clone(&mouse_calls),
            release_calls: Arc::clone(&release_calls),
        }),
        Arc::clone(&enable_os_input),
        Arc::new(move || sc.load(Ordering::Acquire) && ax.load(Ordering::Acquire)),
    );

    let key = KeyEvent {
        down: true,
        modifiers: 0,
        usb_hid_usage: 0x04,
        unicode_scalar: 0,
        client_ts_ms: 100,
    };
    let mouse = MouseEvent {
        kind: MouseKind::Down,
        buttons: 1,
        x_or_dx: 50,
        y_or_dy: 60,
        wheel_dx: 0,
        wheel_dy: 0,
        client_ts_ms: 100,
    };

    // Case A: enable_os_input=false, permissions=false -> 0 calls, not_permitted; emergency_releaser bypasses gate!
    for _ in 0..10 {
        assert_eq!(gated.dispatch_key(&key), Err(OsInputGateError::NotPermitted));
        assert_eq!(
            gated.dispatch_mouse(&mouse),
            Err(OsInputGateError::NotPermitted)
        );
    }
    assert_eq!(key_calls.load(Ordering::Acquire), 0);
    assert_eq!(mouse_calls.load(Ordering::Acquire), 0);
    let _ = gated.emergency_releaser().release_all_keys();
    assert_eq!(release_calls.load(Ordering::Acquire), 1);

    // Case B: permissions=true, enable_os_input=false (View-Only) -> 0 calls, not_permitted; emergency_releaser bypasses gate!
    screen_granted.store(true, Ordering::Release);
    ax_granted.store(true, Ordering::Release);
    assert_eq!(gated.dispatch_key(&key), Err(OsInputGateError::NotPermitted));
    assert_eq!(
        gated.dispatch_mouse(&mouse),
        Err(OsInputGateError::NotPermitted)
    );
    assert_eq!(key_calls.load(Ordering::Acquire), 0);
    assert_eq!(mouse_calls.load(Ordering::Acquire), 0);
    let _ = gated.emergency_releaser().release_all_keys();
    assert_eq!(release_calls.load(Ordering::Acquire), 2);

    // Case C: enable_os_input=true, one permission missing -> 0 calls, not_permitted; emergency_releaser bypasses gate!
    enable_os_input.store(true, Ordering::Release);
    ax_granted.store(false, Ordering::Release);
    assert_eq!(gated.dispatch_key(&key), Err(OsInputGateError::NotPermitted));
    assert_eq!(
        gated.dispatch_mouse(&mouse),
        Err(OsInputGateError::NotPermitted)
    );
    assert_eq!(key_calls.load(Ordering::Acquire), 0);
    assert_eq!(mouse_calls.load(Ordering::Acquire), 0);
    let _ = gated.emergency_releaser().release_all_keys();
    assert_eq!(release_calls.load(Ordering::Acquire), 3);

    // Case D: enable_os_input=true AND both permissions granted -> ONLY 1 new event dispatched (zero buffering!)
    ax_granted.store(true, Ordering::Release);
    gated.dispatch_key(&key).unwrap();
    gated.dispatch_mouse(&mouse).unwrap();
    assert_eq!(key_calls.load(Ordering::Acquire), 1);
    assert_eq!(mouse_calls.load(Ordering::Acquire), 1);

    // Case E: Mid-keypress TCC permission loss while `was_permitted == true` MUST auto-release all keys
    //         BEFORE returning NotPermitted so no key can ever stick!
    ax_granted.store(false, Ordering::Release);
    assert_eq!(gated.dispatch_key(&key), Err(OsInputGateError::NotPermitted));
    assert_eq!(
        release_calls.load(Ordering::Acquire),
        4,
        "mid-keypress permission loss must auto-release held keys"
    );
    // Subsequent dropped events do not repeatedly spam emergency_releaser once was_permitted is cleared.
    assert_eq!(gated.dispatch_key(&key), Err(OsInputGateError::NotPermitted));
    assert_eq!(release_calls.load(Ordering::Acquire), 4);

    // Case F: Drop of GatedOsHidSink unconditionally calls disable_and_release!
    drop(gated);
    assert!(!enable_os_input.load(Ordering::Acquire));
    assert_eq!(release_calls.load(Ordering::Acquire), 5);
}
