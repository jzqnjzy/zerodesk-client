// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import Darwin
import Foundation
import XCTest
@testable import ZeroDeskBridge

final class ZeroDeskBridgeTests: XCTestCase {
    private func makeTempDir(_ tag: String) throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("zd-swift-\(tag)-\(getpid())-\(UUID().uuidString)", isDirectory: true)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testAbiVersionAndOsSelftest() throws {
        XCTAssertEqual(ZeroDeskBridgeClient.abiVersion(), 1)
        let report = try ZeroDeskBridgeClient.osSelftest()
        XCTAssertEqual(report.schemaVersion, 1)
        XCTAssertEqual(report.platform, "macos")
        XCTAssertTrue(report.zeroWritesEnforced)
        XCTAssertFalse(report.screenRecording.status.isEmpty)
        XCTAssertFalse(report.accessibility.status.isEmpty)
    }

    func testRedactedSecretNeverLeaks() {
        let canary = "CANARY_SWIFT_ENROLL_SECRET_987654321"
        let secret = RedactedSecret(canary)
        XCTAssertEqual(String(describing: secret), "<redacted>")
        XCTAssertEqual(String(reflecting: secret), "<redacted>")
        XCTAssertFalse(String(describing: secret).contains(canary))
        XCTAssertFalse(String(reflecting: secret).contains(canary))
        XCTAssertEqual(secret.byteCount, canary.utf8.count)

        let seen = secret.withExposedUTF8String { $0 }
        XCTAssertEqual(seen, canary)

        secret.wipe()
        XCTAssertTrue(secret.isEmpty)
        XCTAssertEqual(secret.byteCount, 0)
        XCTAssertTrue(secret.snapshotBytesForTesting().isEmpty)

        let sanitizedUrl = sanitizeLogMessage("https://example.test/enroll?enrollment_token=\(canary)")
        XCTAssertFalse(sanitizedUrl.contains(canary))

        let samples = [
            "{\"enrollment_token\":\"\(canary)\"}",
            "{\"client_secret\": \"\(canary)\", \"api_key\": \"\(canary)\"}",
            "Authorization: Bearer \(canary)",
            "authorization: basic \(canary)",
            "https://user:\(canary)@host.example/path",
            "https://example.test/api?foo=1&access_token=\(canary)&bar=2",
        ]
        for sample in samples {
            let clean = sanitizeLogMessage(sample)
            XCTAssertFalse(clean.contains(canary), "sanitizer leaked canary for sample: \(sample) -> \(clean)")
        }
    }

    func testConfig0600SaveLoadAndSnapshot() throws {
        let tmpDir = try makeTempDir("cfg0600")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        let cfgDir = tmpDir.appendingPathComponent("cfg", isDirectory: true)
        let idDir = tmpDir.appendingPathComponent("identity", isDirectory: true)
        let cfgPath = cfgDir.appendingPathComponent("config.json").path
        let canaryToken = "CANARY_SWIFT_CONFIG_TOKEN_ABCDEF123456"
        let secret = RedactedSecret(canaryToken)

        let client = try ZeroDeskBridgeClient()
        defer { client.close() }

        let input = BridgeConfigInput(
            controlPlaneEndpoint: "https://127.0.0.1:8443",
            signalingAddr: "127.0.0.1:8444",
            identityDir: idDir.path,
            homeRegion: "local",
            codec: "vp9",
            fps: 30,
            transportMode: "auto",
            enrollmentToken: secret
        )
        let saveReply = try client.saveConfig0600(at: cfgPath, config: input)
        XCTAssertTrue(saveReply.ok, "saveConfig0600 failed: \(saveReply.error ?? "nil")")
        secret.wipe()

        // Verify 0700 directory and 0600 file permissions.
        var stDir = stat()
        XCTAssertEqual(stat(cfgDir.path, &stDir), 0)
        XCTAssertEqual(stDir.st_mode & 0o777, 0o700)

        var stFile = stat()
        XCTAssertEqual(stat(cfgPath, &stFile), 0)
        XCTAssertEqual(stFile.st_mode & 0o777, 0o600)

        let loadReply = try client.loadConfig(at: cfgPath)
        XCTAssertTrue(loadReply.ok, "loadConfig failed: \(loadReply.error ?? "nil")")

        // Verify snapshot JSON redacts enrollment token canary completely.
        let rawSnapData = try client.snapshotRawJSON()
        let rawSnapString = String(decoding: rawSnapData, as: UTF8.self)
        XCTAssertFalse(rawSnapString.contains(canaryToken), "snapshot leaked enrollment token canary!")

        let snap = try client.snapshot()
        XCTAssertEqual(snap.v, 1)
        XCTAssertEqual(snap.config?.hasEnrollmentToken, true)
        XCTAssertEqual(snap.config?.controlPlaneEndpoint, "https://127.0.0.1:8443")
        XCTAssertEqual(snap.realInputEnabled, false)
    }

    func testInvalidCommandAndFrameNoFrameFailClosed() throws {
        let client = try ZeroDeskBridgeClient()
        defer { client.close() }

        // Malformed JSON returns structured error without crashing.
        let badJsonData = try client.execRawJSON("{not valid json")
        let badReply = try JSONDecoder().decode(BridgeCommandReply.self, from: badJsonData)
        XCTAssertFalse(badReply.ok)
        XCTAssertEqual(badReply.errorCode, "InvalidJson")

        // Unknown command returns UnknownCommand.
        let unknownReply = try client.execCommand(["cmd": "definitely_not_a_real_command"])
        XCTAssertFalse(unknownReply.ok)
        XCTAssertEqual(unknownReply.errorCode, "UnknownCommand")

        // No frame published -> returns nil cleanly (ZERODESK_ERR_NO_FRAME).
        let frame = try client.fetchLatestFrameCGImage()
        XCTAssertNil(frame)
    }

    func testExplicitCloseDoubleCloseAndConcurrentStress() throws {
        // 1. Explicit close + idempotent double close + fail-closed post-close calls.
        let client = try ZeroDeskBridgeClient()
        client.setEventHandler { _ in }
        _ = try client.snapshot()
        client.close()
        client.close()

        XCTAssertThrowsError(try client.snapshot()) { err in
            XCTAssertEqual(err as? ZeroDeskBridgeError, .closed)
        }
        XCTAssertThrowsError(try client.execCommand(["cmd": "get_snapshot"])) { err in
            XCTAssertEqual(err as? ZeroDeskBridgeError, .closed)
        }
        XCTAssertThrowsError(try client.fetchLatestFrameCGImage()) { err in
            XCTAssertEqual(err as? ZeroDeskBridgeError, .closed)
        }

        // 2. Concurrent multi-thread snapshot/command stress while event handler is active,
        //    followed by multiple create/close lifecycle cycles.
        let stressClient = try ZeroDeskBridgeClient()
        stressClient.setEventHandler { _ in }
        let group = DispatchGroup()
        let queue = DispatchQueue(label: "zd.test.concurrent", attributes: .concurrent)
        for _ in 0..<8 {
            group.enter()
            queue.async {
                defer { group.leave() }
                for _ in 0..<15 {
                    _ = try? stressClient.snapshot()
                    _ = try? stressClient.fetchLatestFrameCGImage()
                }
            }
        }
        group.wait()
        stressClient.close()

        for _ in 0..<5 {
            let c = try ZeroDeskBridgeClient()
            _ = try c.snapshot()
            c.close()
        }
    }

    func testCreateAndImmediateDropNoDeadlock() throws {
        for _ in 0..<200 {
            _ = try ZeroDeskBridgeClient()
        }
    }

    func testZeroCallbacksAfterCloseAndConcurrentTSan() throws {
        final class CallbackTracker: @unchecked Sendable {
            private let lock = NSLock()
            private var closed = false
            private var beforeClose = 0
            private var afterClose = 0

            func record() {
                lock.lock()
                if closed {
                    afterClose += 1
                } else {
                    beforeClose += 1
                }
                lock.unlock()
            }

            func markClosed() {
                lock.lock()
                closed = true
                lock.unlock()
            }

            func counts() -> (before: Int, after: Int) {
                lock.lock()
                defer { lock.unlock() }
                return (beforeClose, afterClose)
            }
        }

        let tmpDir = try makeTempDir("zero_cb_close")
        defer { try? FileManager.default.removeItem(at: tmpDir) }

        for round in 0..<3 {
            let tracker = CallbackTracker()
            let client = try ZeroDeskBridgeClient()
            client.setEventHandler { _ in
                tracker.record()
            }

            let cfgPath = tmpDir.appendingPathComponent("cfg_\(round).json").path
            let idDir = tmpDir.appendingPathComponent("id_\(round)", isDirectory: true).path
            let input = BridgeConfigInput(
                controlPlaneEndpoint: "https://127.0.0.1:8443",
                signalingAddr: "127.0.0.1:8444",
                identityDir: idDir,
                homeRegion: "local",
                codec: "vp9",
                fps: 30,
                transportMode: "auto"
            )
            XCTAssertTrue(try client.saveConfig0600(at: cfgPath, config: input).ok)
            XCTAssertTrue(try client.loadConfig(at: cfgPath).ok)
            XCTAssertTrue(try client.execCommand(["cmd": "set_transport_mode", "mode": "tls443"]).ok)
            XCTAssertTrue(try client.execCommand(["cmd": "set_transport_mode", "mode": "auto"]).ok)

            // Wait briefly until at least one real Rust event callback is observed before closing.
            let deadline = Date().addingTimeInterval(2.0)
            while tracker.counts().before == 0 && Date() < deadline {
                Thread.sleep(forTimeInterval: 0.01)
            }
            XCTAssertGreaterThan(tracker.counts().before, 0, "expected real Rust events before close (round \(round))")

            let group = DispatchGroup()
            let queue = DispatchQueue(label: "zd.test.tsan.events.\(round)", attributes: .concurrent)
            for worker in 0..<4 {
                group.enter()
                queue.async {
                    defer { group.leave() }
                    for i in 0..<20 {
                        let mode = ((worker + i) % 2 == 0) ? "tls443" : "auto"
                        _ = try? client.execCommand(["cmd": "set_transport_mode", "mode": mode])
                        _ = try? client.snapshot()
                    }
                }
            }

            // Close concurrently while event producers & snapshot callers are in flight.
            Thread.sleep(forTimeInterval: 0.01)
            client.close()
            tracker.markClosed()
            group.wait()

            // Verify zero callbacks execute after close() returned.
            Thread.sleep(forTimeInterval: 0.2)
            let finalCounts = tracker.counts()
            XCTAssertEqual(finalCounts.after, 0, "observed \(finalCounts.after) callbacks after close() returned")
        }
    }
}
