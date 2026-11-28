// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import Foundation
import XCTest
@testable import ZeroDeskBridge

/// Cross-language ABI v2 Golden Contract Tests: verifies Swift encodes/decodes the EXACT SAME
/// golden JSON fixtures (`libs/zerodesk_core/tests/golden/abi_v2_*.json`) as Rust and ignores
/// unknown `kind`/`type` values and unknown JSON fields without failing or disconnecting.
final class Phase8AAbiContractTests: XCTestCase {
    private func goldenDirectoryURL() -> URL {
        // Navigate relative to this test file:
        // apps/macos/ZeroDeskApp/Tests/ZeroDeskBridgeTests/Phase8AAbiContractTests.swift
        // -> repo root -> libs/zerodesk_core/tests/golden
        let thisFile = URL(fileURLWithPath: #filePath)
        let repoRoot = thisFile
            .deletingLastPathComponent() // ZeroDeskBridgeTests
            .deletingLastPathComponent() // Tests
            .deletingLastPathComponent() // ZeroDeskApp
            .deletingLastPathComponent() // macos
            .deletingLastPathComponent() // apps
            .deletingLastPathComponent() // repo root
        return repoRoot
            .appendingPathComponent("libs", isDirectory: true)
            .appendingPathComponent("zerodesk_core", isDirectory: true)
            .appendingPathComponent("tests", isDirectory: true)
            .appendingPathComponent("golden", isDirectory: true)
    }

    private func loadGolden(_ name: String) throws -> Data {
        let url = goldenDirectoryURL().appendingPathComponent(name)
        return try Data(contentsOf: url)
    }

    private func canonicalJSONObject(_ data: Data) throws -> NSDictionary {
        let obj = try JSONSerialization.jsonObject(with: data, options: [])
        return try XCTUnwrap(obj as? NSDictionary)
    }

    func testSwiftLiveHandshakeMatchesGoldenFixtureExactly() throws {
        let goldenData = try loadGolden("abi_v2_handshake_reply.json")
        let goldenReply = try JSONDecoder().decode(BridgeTypedReply<HandshakeCapabilitiesData>.self, from: goldenData)
        XCTAssertTrue(goldenReply.ok)
        let expectedCaps = try XCTUnwrap(goldenReply.data)
        XCTAssertEqual(expectedCaps.abiVersion, 2)

        let client = try ZeroDeskBridgeClient()
        defer { client.close() }

        let liveCaps = try client.handshake()
        XCTAssertEqual(liveCaps, expectedCaps, "Swift live handshake() drifted from golden abi_v2_handshake_reply.json")

        let snap = try client.snapshot()
        XCTAssertEqual(snap.abiVersion, 2)
        XCTAssertEqual(snap.caps, expectedCaps.caps)
        XCTAssertEqual(snap.enableOsInput, false, "every new session must start in View-Only mode (enable_os_input = false)")
    }

    func testSwiftEncodesAndDecodesAllGoldenRequestsAndEventsIdenticallyToRust() throws {
        let decoder = JSONDecoder()
        let encoder = JSONEncoder()

        // 1. Requests decode AND JSONEncoder round-trip against golden fixtures
        let getPermGolden = try loadGolden("abi_v2_get_permissions_req.json")
        let getPermReq = try decoder.decode(GetPermissionsRequest.self, from: getPermGolden)
        XCTAssertEqual(getPermReq, GetPermissionsRequest(v: 1))
        XCTAssertEqual(
            try canonicalJSONObject(try encoder.encode(getPermReq)),
            try canonicalJSONObject(getPermGolden)
        )

        let setInputGolden = try loadGolden("abi_v2_set_input_enabled_req.json")
        let setInputReq = try decoder.decode(SetInputEnabledRequest.self, from: setInputGolden)
        XCTAssertEqual(setInputReq, SetInputEnabledRequest(v: 1, enabled: true, reason: "user_toggle"))
        XCTAssertEqual(
            try canonicalJSONObject(try encoder.encode(setInputReq)),
            try canonicalJSONObject(setInputGolden)
        )

        let qualityGolden = try loadGolden("abi_v2_set_video_quality_req.json")
        let qualityReq = try decoder.decode(SetVideoQualityRequest.self, from: qualityGolden)
        XCTAssertEqual(qualityReq, SetVideoQualityRequest(v: 1, bitrateKbps: 10_000, fpsCap: 60))
        XCTAssertEqual(
            try canonicalJSONObject(try encoder.encode(qualityReq)),
            try canonicalJSONObject(qualityGolden)
        )

        // 2. Events parity
        let permEv = try ParsedBridgeEvent.decodeForwardCompat(from: try loadGolden("abi_v2_permission_status_event.json"))
        XCTAssertEqual(
            permEv,
            .permissionStatus(
                PermissionStatusReport(
                    screenCaptureGranted: true,
                    accessibilityGranted: false,
                    probeSource: .watchdog,
                    enableOsInput: false,
                    secureEventInputEnabled: false
                )
            )
        )

        let ackEv = try ParsedBridgeEvent.decodeForwardCompat(from: try loadGolden("abi_v2_input_enabled_ack_event.json"))
        XCTAssertEqual(
            ackEv,
            .inputEnabledAck(
                InputEnabledAckPayload(
                    enabled: false,
                    status: "not_permitted",
                    screenCaptureGranted: true,
                    accessibilityGranted: false,
                    probeSource: "ui_process_hint",
                    reason: nil,
                    releaseAll: nil
                )
            )
        )

        let hudEv = try ParsedBridgeEvent.decodeForwardCompat(from: try loadGolden("abi_v2_hud_stats_event.json"))
        XCTAssertEqual(
            hudEv,
            .hudStats(
                HudStatsPayload(
                    fps: 59.8,
                    decodeMs: 1.45,
                    activeCodec: "hevc",
                    transportMode: "udp",
                    rttMs: 11.2,
                    bitrateKbps: 8450
                )
            )
        )

        let codecEv = try ParsedBridgeEvent.decodeForwardCompat(from: try loadGolden("abi_v2_codec_ack_event.json"))
        XCTAssertEqual(
            codecEv,
            .codecAck(CodecAckPayload(activeCodec: "hevc", requestedCodec: "hevc", accepted: true))
        )

        let clipEv = try ParsedBridgeEvent.decodeForwardCompat(from: try loadGolden("abi_v2_clipboard_sync_status_event.json"))
        XCTAssertEqual(
            clipEv,
            .clipboardSyncStatus(ClipboardSyncStatusPayload(enabled: false, status: "policy_denied", code: "policy_denied"))
        )

        let ftEv = try ParsedBridgeEvent.decodeForwardCompat(from: try loadGolden("abi_v2_file_transfer_complete_event.json"))
        XCTAssertEqual(
            ftEv,
            .fileTransferComplete(
                FileTransferCompletePayload(
                    transferId: 7,
                    relName: "report.pdf",
                    bytes: 0,
                    sha256Hex: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    checksumAlgo: "sha256",
                    savedPath: "/tmp/report.pdf"
                )
            )
        )

        // Backward-compat PascalCase "FileTransferComplete" AND honest checksum_algo decoding ("md5").
        let md5JSON = Data(#"{"v":1,"seq":48,"kind":"FileTransferComplete","payload":{"transfer_id":8,"rel_name":"a.bin","bytes":12,"sha256_hex":"00","checksum_algo":"md5"}}"#.utf8)
        let md5Ev = try ParsedBridgeEvent.decodeForwardCompat(from: md5JSON)
        if case .fileTransferComplete(let payload) = md5Ev {
            XCTAssertEqual(payload.checksumAlgo, "md5")
        } else {
            XCTFail("expected fileTransferComplete")
        }

        // 3. Unknown event kind/type & unknown JSON fields MUST be ignored cleanly without throwing!
        let unknownEv = try ParsedBridgeEvent.decodeForwardCompat(from: try loadGolden("abi_v2_unknown_event_and_fields.json"))
        XCTAssertEqual(unknownEv, .unknown(kind: "future_phase9_event_type"))

        // 4. Unknown probe_source forward-compat & authoritative rules
        let unknownProbeJSON = Data(#"{"v":1,"seq":51,"kind":"permission_status","payload":{"screen_capture_granted":true,"accessibility_granted":true,"probe_source":"future_sandbox_broker","enable_os_input":false}}"#.utf8)
        let unknownProbeEv = try ParsedBridgeEvent.decodeForwardCompat(from: unknownProbeJSON)
        if case .permissionStatus(let report) = unknownProbeEv {
            XCTAssertEqual(report.probeSource, .unknown("future_sandbox_broker"))
            XCTAssertFalse(report.probeSource.isAuthoritative)
        } else {
            XCTFail("expected permissionStatus with unknown probe_source")
        }
        XCTAssertTrue(PermissionProbeSource.watchdog.isAuthoritative)
        XCTAssertTrue(PermissionProbeSource.injectorProcess.isAuthoritative)
        XCTAssertFalse(PermissionProbeSource.uiProcessHint.isAuthoritative)

        // Legacy alias "watchdog_or_injector_process" decodes to authoritative .injectorProcess
        let legacyProbe = try decoder.decode(PermissionProbeSource.self, from: Data(#""watchdog_or_injector_process""#.utf8))
        XCTAssertEqual(legacyProbe, .injectorProcess)
        XCTAssertTrue(legacyProbe.isAuthoritative)

        // 5. Malformed known event kind decodes to .malformed(kind:) rather than crashing or faking .unknown
        let malformedJSON = Data(#"{"v":1,"seq":52,"kind":"codec_ack","payload":{"wrong_field":123}}"#.utf8)
        let malformedEv = try ParsedBridgeEvent.decodeForwardCompat(from: malformedJSON)
        XCTAssertEqual(malformedEv, .malformed(kind: "codec_ack"))

        // 6. Future envelope version (v > 1) maps to .unknown cleanly
        let futureVJSON = Data(#"{"v":9,"seq":53,"kind":"hud_stats","payload":{}}"#.utf8)
        let futureVEv = try ParsedBridgeEvent.decodeForwardCompat(from: futureVJSON)
        XCTAssertEqual(futureVEv, .unknown(kind: "hud_stats"))
    }

    func testLiveBridgePermissionsAndQualityAndClipboardCommands() throws {
        let client = try ZeroDeskBridgeClient()
        defer { client.close() }

        let perms = try client.getPermissions()
        XCTAssertFalse(perms.enableOsInput)
        XCTAssertEqual(perms.probeSource, .uiProcessHint)

        // Fail-closed: enabling OS input while Idle / non-authoritative MUST return not_permitted!
        let enableReply = try client.setInputEnabled(true, reason: "test_enable_idle")
        XCTAssertFalse(enableReply.ok)
        XCTAssertEqual(enableReply.errorCode, "not_permitted")
        XCTAssertEqual(try client.snapshot().enableOsInput, false)

        // Disabling input is always safe and idempotent.
        let disableReply = try client.setInputEnabled(false, reason: "test_disable")
        XCTAssertTrue(disableReply.ok)

        // Video quality & clipboard sync commands succeed cleanly.
        let qReply = try client.setVideoQuality(bitrateKbps: 5_000, fpsCap: 60)
        XCTAssertTrue(qReply.ok)
        let snapAfterQ = try client.snapshot()
        XCTAssertEqual(snapAfterQ.bitrateKbps, 5_000)
        XCTAssertEqual(snapAfterQ.fpsCap, 60)

        let clipReply = try client.setClipboardSync(false)
        XCTAssertTrue(clipReply.ok)
        let snapAfterClip = try client.snapshot()
        XCTAssertEqual(snapAfterClip.clipboardSyncEnabled, false)
    }
}
