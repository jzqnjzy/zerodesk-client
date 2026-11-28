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
            PermissionProbeSource::WatchdogOrInjectorProcess
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
            probe_source: PermissionProbeSource::WatchdogOrInjectorProcess,
            enable_os_input: false,
            secure_event_input_enabled: Some(false),
        })
    );

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
    assert_eq!(
        ft_ev,
        ParsedBridgeEvent::FileTransferComplete(FileTransferCompletePayload {
            transfer_id: 7,
            rel_name: "report.pdf".into(),
            bytes: 1_048_576,
            sha256_hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".into(),
            checksum_algo: Some("sha256".into()),
            saved_path: Some("/tmp/report.pdf".into()),
        })
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

    // 2. get_permissions returns structured report + emits permission_status event.
    let perm_reply: serde_json::Value =
        serde_json::from_str(&rt.exec_json(r#"{"v":1,"cmd":"get_permissions"}"#)).unwrap();
    assert_eq!(perm_reply["ok"], true);
    assert_eq!(perm_reply["data"]["screen_capture_granted"], true);
    assert_eq!(perm_reply["data"]["accessibility_granted"], false);
    assert_eq!(perm_reply["data"]["probe_source"], "ui_process_hint");
    assert_eq!(perm_reply["data"]["enable_os_input"], false);

    let ev_raw = rt
        .poll_event_json_timeout(Duration::from_millis(500))
        .expect("permission_status event expected");
    let parsed_ev = parse_bridge_event_forward_compat(&ev_raw).unwrap();
    assert!(matches!(parsed_ev, ParsedBridgeEvent::PermissionStatus(_)));

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
    let ack_parsed = parse_bridge_event_forward_compat(&ack_raw).unwrap();
    match ack_parsed {
        ParsedBridgeEvent::InputEnabledAck(ack) => {
            assert!(!ack.enabled);
            assert_eq!(ack.status, "not_permitted");
        }
        other => panic!("expected InputEnabledAck, got {other:?}"),
    }

    // 4. Grant Accessibility & switch probe source to watchdog_or_injector_process -> enable succeeds!
    probe.ax.store(true, Ordering::Release);
    probe.source_is_watchdog.store(true, Ordering::Release);
    let ok_reply: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"set_input_enabled","enabled":true}"#),
    )
    .unwrap();
    assert_eq!(ok_reply["ok"], true);
    assert_eq!(ok_reply["data"]["enabled"], true);
    assert_eq!(rt.snapshot().enable_os_input, Some(true));

    let ok_ack_raw = rt
        .poll_event_json_timeout(Duration::from_millis(500))
        .expect("input_enabled_ack ok event expected");
    match parse_bridge_event_forward_compat(&ok_ack_raw).unwrap() {
        ParsedBridgeEvent::InputEnabledAck(ack) => {
            assert!(ack.enabled);
            assert_eq!(ack.status, "ok");
            assert_eq!(
                ack.probe_source.as_deref(),
                Some("watchdog_or_injector_process")
            );
        }
        other => panic!("expected InputEnabledAck(ok), got {other:?}"),
    }

    // 5. Emergency escape release_all MUST reset enable_os_input = false and emit ack!
    let esc_reply: serde_json::Value = serde_json::from_str(
        &rt.exec_json(r#"{"v":1,"cmd":"release_all","reason":"emergencyEscapeHotkey"}"#),
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

    // 6. Video quality & clipboard sync commands work and emit ack events.
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

    // Case A: enable_os_input=false, permissions=false -> 0 calls, not_permitted
    for _ in 0..10 {
        assert_eq!(gated.dispatch_key(&key), Err(OsInputGateError::NotPermitted));
        assert_eq!(
            gated.dispatch_mouse(&mouse),
            Err(OsInputGateError::NotPermitted)
        );
    }
    assert_eq!(key_calls.load(Ordering::Acquire), 0);
    assert_eq!(mouse_calls.load(Ordering::Acquire), 0);

    // Case B: permissions=true, enable_os_input=false (View-Only) -> 0 calls, not_permitted
    screen_granted.store(true, Ordering::Release);
    ax_granted.store(true, Ordering::Release);
    assert_eq!(gated.dispatch_key(&key), Err(OsInputGateError::NotPermitted));
    assert_eq!(
        gated.dispatch_mouse(&mouse),
        Err(OsInputGateError::NotPermitted)
    );
    assert_eq!(key_calls.load(Ordering::Acquire), 0);
    assert_eq!(mouse_calls.load(Ordering::Acquire), 0);

    // Case C: enable_os_input=true, one permission missing -> 0 calls, not_permitted
    enable_os_input.store(true, Ordering::Release);
    ax_granted.store(false, Ordering::Release);
    assert_eq!(gated.dispatch_key(&key), Err(OsInputGateError::NotPermitted));
    assert_eq!(
        gated.dispatch_mouse(&mouse),
        Err(OsInputGateError::NotPermitted)
    );
    assert_eq!(key_calls.load(Ordering::Acquire), 0);
    assert_eq!(mouse_calls.load(Ordering::Acquire), 0);

    // Case D: enable_os_input=true AND both permissions granted -> ONLY 1 new event dispatched (zero buffering!)
    ax_granted.store(true, Ordering::Release);
    gated.dispatch_key(&key).unwrap();
    gated.dispatch_mouse(&mouse).unwrap();
    assert_eq!(key_calls.load(Ordering::Acquire), 1);
    assert_eq!(mouse_calls.load(Ordering::Acquire), 1);
}
