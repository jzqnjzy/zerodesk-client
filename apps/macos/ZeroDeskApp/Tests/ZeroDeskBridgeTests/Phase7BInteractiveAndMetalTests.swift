// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import CoreGraphics
import Foundation
import Metal
import XCTest
@testable import ZeroDeskBridge

final class Phase7BInteractiveAndMetalTests: XCTestCase {
    // MARK: - 1. Coordinate Mapper Matrix Test (>= 12 combinations)

    func testCoordinateMapperMatrixAcrossAspectRatiosAndRetinaScales() {
        struct Case {
            let name: String
            let viewSize: CGSize
            let remoteSize: RemoteSize
            let backingScale: CGFloat
            let expectPillarbox: Bool // black bars left/right
            let expectLetterbox: Bool // black bars top/bottom
        }

        let cases: [Case] = [
            // 16:9 remote in various views (1x & 2x Retina)
            Case(name: "16:9 exact 1x", viewSize: CGSize(width: 1920, height: 1080), remoteSize: RemoteSize(width: 1920, height: 1080), backingScale: 1.0, expectPillarbox: false, expectLetterbox: false),
            Case(name: "16:9 scaled 2x Retina", viewSize: CGSize(width: 960, height: 540), remoteSize: RemoteSize(width: 1920, height: 1080), backingScale: 2.0, expectPillarbox: false, expectLetterbox: false),
            Case(name: "16:9 in 21:9 ultrawide 1x", viewSize: CGSize(width: 2560, height: 1080), remoteSize: RemoteSize(width: 1920, height: 1080), backingScale: 1.0, expectPillarbox: true, expectLetterbox: false),
            Case(name: "16:9 in 21:9 ultrawide 2x", viewSize: CGSize(width: 1720, height: 720), remoteSize: RemoteSize(width: 1920, height: 1080), backingScale: 2.0, expectPillarbox: true, expectLetterbox: false),
            Case(name: "16:9 in 4:3 view 1x", viewSize: CGSize(width: 1024, height: 768), remoteSize: RemoteSize(width: 1920, height: 1080), backingScale: 1.0, expectPillarbox: false, expectLetterbox: true),
            Case(name: "16:9 in portrait view 2x", viewSize: CGSize(width: 600, height: 1000), remoteSize: RemoteSize(width: 1920, height: 1080), backingScale: 2.0, expectPillarbox: false, expectLetterbox: true),

            // 4:3 remote in various views
            Case(name: "4:3 in 16:9 view 1x", viewSize: CGSize(width: 1920, height: 1080), remoteSize: RemoteSize(width: 1024, height: 768), backingScale: 1.0, expectPillarbox: true, expectLetterbox: false),
            Case(name: "4:3 in 16:9 view 2x", viewSize: CGSize(width: 1280, height: 720), remoteSize: RemoteSize(width: 1600, height: 1200), backingScale: 2.0, expectPillarbox: true, expectLetterbox: false),
            Case(name: "4:3 in portrait view 1x", viewSize: CGSize(width: 800, height: 1200), remoteSize: RemoteSize(width: 1024, height: 768), backingScale: 1.0, expectPillarbox: false, expectLetterbox: true),

            // 21:9 ultrawide remote
            Case(name: "21:9 in 16:9 view 1x", viewSize: CGSize(width: 1920, height: 1080), remoteSize: RemoteSize(width: 3440, height: 1440), backingScale: 1.0, expectPillarbox: false, expectLetterbox: true),
            Case(name: "21:9 in 16:9 view 2x", viewSize: CGSize(width: 1440, height: 900), remoteSize: RemoteSize(width: 2560, height: 1080), backingScale: 2.0, expectPillarbox: false, expectLetterbox: true),

            // Portrait remote (9:16)
            Case(name: "Portrait 9:16 in 16:9 view 1x", viewSize: CGSize(width: 1920, height: 1080), remoteSize: RemoteSize(width: 1080, height: 1920), backingScale: 1.0, expectPillarbox: true, expectLetterbox: false),
            Case(name: "Portrait 9:16 in 4:3 view 2x", viewSize: CGSize(width: 800, height: 600), remoteSize: RemoteSize(width: 1080, height: 1920), backingScale: 2.0, expectPillarbox: true, expectLetterbox: false),
            Case(name: "4K 16:9 in 1440x900 2x Retina", viewSize: CGSize(width: 1440, height: 900), remoteSize: RemoteSize(width: 3840, height: 2160), backingScale: 2.0, expectPillarbox: false, expectLetterbox: true),
        ]

        XCTAssertGreaterThanOrEqual(cases.count, 12)

        for tc in cases {
            guard let layout = RemoteCoordinateMapper.computeLayout(
                viewSize: tc.viewSize,
                remoteSize: tc.remoteSize
            ) else {
                XCTFail("computeLayout returned nil for \(tc.name)")
                continue
            }

            // Sample normalized interior targets (0.0, 0.25, 0.5, 0.75, 1.0) in BOTH origins & backing scale.
            let samples: [(Double, Double)] = [
                (0.0, 0.0),
                (0.25, 0.25),
                (0.5, 0.5),
                (0.75, 0.75),
                (0.999, 0.999),
            ]
            for (u, v) in samples {
                let topLeftPt = CGPoint(
                    x: layout.videoRect.minX + layout.videoRect.width * u,
                    y: layout.videoRect.minY + layout.videoRect.height * v
                )
                let bottomLeftPt = CGPoint(
                    x: topLeftPt.x,
                    y: tc.viewSize.height - topLeftPt.y
                )

                let expectedX = min(Int(floor(u * Double(tc.remoteSize.width))), tc.remoteSize.width - 1)
                let expectedY = min(Int(floor(v * Double(tc.remoteSize.height))), tc.remoteSize.height - 1)

                let mappedTL = RemoteCoordinateMapper.mapPoint(
                    topLeftPt,
                    viewSize: tc.viewSize,
                    backingScale: tc.backingScale,
                    remoteSize: tc.remoteSize,
                    origin: .topLeft,
                    isDragging: false
                )
                let mappedBL = RemoteCoordinateMapper.mapPoint(
                    bottomLeftPt,
                    viewSize: tc.viewSize,
                    backingScale: tc.backingScale,
                    remoteSize: tc.remoteSize,
                    origin: .bottomLeft,
                    isDragging: false
                )
                XCTAssertNotNil(mappedTL, "[\(tc.name)] topLeft interior (\(u),\(v)) unexpectedly nil")
                XCTAssertNotNil(mappedBL, "[\(tc.name)] bottomLeft interior (\(u),\(v)) unexpectedly nil")
                if let pt = mappedTL {
                    XCTAssertLessThanOrEqual(abs(pt.x - expectedX), 1, "[\(tc.name)] topLeft X error > 1px")
                    XCTAssertLessThanOrEqual(abs(pt.y - expectedY), 1, "[\(tc.name)] topLeft Y error > 1px")
                }
                if let pt = mappedBL {
                    XCTAssertLessThanOrEqual(abs(pt.x - expectedX), 1, "[\(tc.name)] bottomLeft X error > 1px")
                    XCTAssertLessThanOrEqual(abs(pt.y - expectedY), 1, "[\(tc.name)] bottomLeft Y error > 1px")
                }
            }

            // Black bar swallowing (isDragging == false -> nil) and edge clamping (isDragging == true).
            if tc.expectPillarbox {
                XCTAssertGreaterThan(layout.videoRect.minX, 1.0, "[\(tc.name)] expected left pillarbox bar")
                let leftBar = CGPoint(x: layout.videoRect.minX * 0.5, y: tc.viewSize.height * 0.5)
                let rightBar = CGPoint(x: layout.videoRect.maxX + (tc.viewSize.width - layout.videoRect.maxX) * 0.5, y: tc.viewSize.height * 0.5)

                XCTAssertNil(RemoteCoordinateMapper.mapPoint(leftBar, viewSize: tc.viewSize, backingScale: tc.backingScale, remoteSize: tc.remoteSize, origin: .bottomLeft, isDragging: false))
                XCTAssertNil(RemoteCoordinateMapper.mapPoint(rightBar, viewSize: tc.viewSize, backingScale: tc.backingScale, remoteSize: tc.remoteSize, origin: .bottomLeft, isDragging: false))

                let clampedLeft = RemoteCoordinateMapper.mapPoint(leftBar, viewSize: tc.viewSize, backingScale: tc.backingScale, remoteSize: tc.remoteSize, origin: .bottomLeft, isDragging: true)
                let clampedRight = RemoteCoordinateMapper.mapPoint(rightBar, viewSize: tc.viewSize, backingScale: tc.backingScale, remoteSize: tc.remoteSize, origin: .bottomLeft, isDragging: true)
                XCTAssertEqual(clampedLeft?.x, 0, "[\(tc.name)] drag in left pillarbox must clamp X to 0")
                XCTAssertEqual(clampedRight?.x, tc.remoteSize.width - 1, "[\(tc.name)] drag in right pillarbox must clamp X to W-1")
            }

            if tc.expectLetterbox {
                XCTAssertGreaterThan(layout.videoRect.minY, 1.0, "[\(tc.name)] expected top letterbox bar")
                // In bottomLeft NSView coordinates: top bar is near y = viewSize.height, bottom bar near y = 0.
                let topBarBL = CGPoint(x: tc.viewSize.width * 0.5, y: tc.viewSize.height - layout.videoRect.minY * 0.5)
                let bottomBarBL = CGPoint(x: tc.viewSize.width * 0.5, y: layout.videoRect.minY * 0.5)

                XCTAssertNil(RemoteCoordinateMapper.mapPoint(topBarBL, viewSize: tc.viewSize, backingScale: tc.backingScale, remoteSize: tc.remoteSize, origin: .bottomLeft, isDragging: false))
                XCTAssertNil(RemoteCoordinateMapper.mapPoint(bottomBarBL, viewSize: tc.viewSize, backingScale: tc.backingScale, remoteSize: tc.remoteSize, origin: .bottomLeft, isDragging: false))

                let clampedTop = RemoteCoordinateMapper.mapPoint(topBarBL, viewSize: tc.viewSize, backingScale: tc.backingScale, remoteSize: tc.remoteSize, origin: .bottomLeft, isDragging: true)
                let clampedBottom = RemoteCoordinateMapper.mapPoint(bottomBarBL, viewSize: tc.viewSize, backingScale: tc.backingScale, remoteSize: tc.remoteSize, origin: .bottomLeft, isDragging: true)
                XCTAssertEqual(clampedTop?.y, 0, "[\(tc.name)] drag in top letterbox must clamp Y to 0")
                XCTAssertEqual(clampedBottom?.y, tc.remoteSize.height - 1, "[\(tc.name)] drag in bottom letterbox must clamp Y to H-1")
            }
        }
    }

    // MARK: - 2. HID KeyMap & Scroll Quantizer Tests

    func testMacHidKeyMapWhitelistUnmappedDropCountAndEmergencyCombo() {
        // Every mapped keyCode MUST land inside spec/04 §6.1.2 whitelist (and never 0x66 Power).
        XCTAssertGreaterThan(MacHidKeyMap.keyCodeToHidUsage.count, 90)
        for (keyCode, usageId) in MacHidKeyMap.keyCodeToHidUsage {
            XCTAssertTrue(
                MacHidKeyMap.isWhitelistedUsageId(usageId),
                "macOS keyCode 0x\(String(keyCode, radix: 16)) mapped to non-whitelisted HID usage 0x\(String(usageId, radix: 16))"
            )
            XCTAssertNotEqual(usageId, 0x66, "Keyboard Power (0x66) must never be mapped")
        }

        // Spot-check critical mappings (A-Z, 0-9, control, F1-F12, arrows, nav, distinct L/R modifiers).
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x00), 0x04) // A
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x06), 0x1D) // Z
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x12), 0x1E) // 1
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x1D), 0x27) // 0
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x24), 0x28) // Return -> Enter
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x35), 0x29) // Escape
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x33), 0x2A) // Backspace
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x30), 0x2B) // Tab
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x31), 0x2C) // Space
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x7A), 0x3A) // F1
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x6F), 0x45) // F12
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x72), 0x49) // Help -> Insert
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x73), 0x4A) // Home
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x74), 0x4B) // PageUp
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x75), 0x4C) // ForwardDelete
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x77), 0x4D) // End
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x79), 0x4E) // PageDown
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x7C), 0x4F) // RightArrow
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x7B), 0x50) // LeftArrow
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x7D), 0x51) // DownArrow
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x7E), 0x52) // UpArrow
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x3B), 0xE0) // LeftControl
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x38), 0xE1) // LeftShift
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x3A), 0xE2) // LeftAlt
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x37), 0xE3) // LeftMeta
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x3E), 0xE4) // RightControl
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x3C), 0xE5) // RightShift
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x3D), 0xE6) // RightAlt
        XCTAssertEqual(MacHidKeyMap.hidUsage(forMacKeyCode: 0x36), 0xE7) // RightMeta

        // Unmapped keys return nil and increment telemetry counter cleanly.
        let mapper = MacHidKeyMap()
        XCTAssertEqual(mapper.unmappedKeyDropCount, 0)
        XCTAssertEqual(mapper.lookup(0x00), 0x04)
        XCTAssertEqual(mapper.unmappedKeyDropCount, 0)
        XCTAssertNil(mapper.lookup(0x3F)) // kVK_Function
        XCTAssertNil(mapper.lookup(0x48)) // kVK_VolumeUp
        XCTAssertNil(mapper.lookup(0xFFFF))
        XCTAssertEqual(mapper.unmappedKeyDropCount, 3)

        // Emergency escape combo: Ctrl + Opt + Cmd + Escape ONLY.
        let escapeMods: UInt8 = HidModifierMask.ctrl | HidModifierMask.alt | HidModifierMask.meta
        XCTAssertTrue(MacHidKeyMap.isEmergencyEscapeCombo(usageId: 0x29, modifiers: escapeMods))
        XCTAssertFalse(MacHidKeyMap.isEmergencyEscapeCombo(usageId: 0x29, modifiers: HidModifierMask.ctrl | HidModifierMask.meta))
        XCTAssertFalse(MacHidKeyMap.isEmergencyEscapeCombo(usageId: 0x29, modifiers: 0))
        XCTAssertFalse(MacHidKeyMap.isEmergencyEscapeCombo(usageId: 0x04, modifiers: escapeMods))
    }

    func testScrollQuantizerMomentumDiscardAccumulationInversionAndReset() {
        var q = ScrollQuantizer(preciseStepThreshold: 10.0)

        // 1. Momentum phase strictly discarded (must NOT accumulate or emit).
        XCTAssertNil(q.process(deltaX: 50, deltaY: 50, hasPreciseScrollingDeltas: true, momentumPhaseRaw: 1, isDirectionInvertedFromDevice: false))
        XCTAssertEqual(q.pendingRemainderX, 0)
        XCTAssertEqual(q.pendingRemainderY, 0)

        // 2. Sub-tick precise deltas accumulate until crossing threshold.
        XCTAssertNil(q.process(deltaX: 0, deltaY: 4.0, hasPreciseScrollingDeltas: true, momentumPhaseRaw: 0, isDirectionInvertedFromDevice: false))
        XCTAssertNil(q.process(deltaX: 0, deltaY: 4.0, hasPreciseScrollingDeltas: true, momentumPhaseRaw: 0, isDirectionInvertedFromDevice: false))
        let step1 = q.process(deltaX: 0, deltaY: 4.0, hasPreciseScrollingDeltas: true, momentumPhaseRaw: 0, isDirectionInvertedFromDevice: false)
        XCTAssertEqual(step1, ScrollStep(wheelDx: 0, wheelDy: 1))
        XCTAssertEqual(q.pendingRemainderY, 2.0, accuracy: 0.0001)

        // 3. Gesture end resets fractional remainder cleanly.
        _ = q.process(deltaX: 0, deltaY: 1.0, hasPreciseScrollingDeltas: true, momentumPhaseRaw: 0, isDirectionInvertedFromDevice: false, phaseRaw: ScrollQuantizer.phaseEndedRaw)
        XCTAssertEqual(q.pendingRemainderX, 0)
        XCTAssertEqual(q.pendingRemainderY, 0)

        // 4. Direction inversion flips emitted step sign.
        let normalStep = q.process(deltaX: 12.0, deltaY: -22.0, hasPreciseScrollingDeltas: true, momentumPhaseRaw: 0, isDirectionInvertedFromDevice: false)
        XCTAssertEqual(normalStep, ScrollStep(wheelDx: 1, wheelDy: -2))
        q.reset()
        let invertedStep = q.process(deltaX: 12.0, deltaY: -22.0, hasPreciseScrollingDeltas: true, momentumPhaseRaw: 0, isDirectionInvertedFromDevice: true)
        XCTAssertEqual(invertedStep, ScrollStep(wheelDx: -1, wheelDy: 2))

        // 5. Non-precise wheel emits quantized integer ticks directly.
        let wheelStep = q.process(deltaX: -0.2, deltaY: 3.0, hasPreciseScrollingDeltas: false, momentumPhaseRaw: 0, isDirectionInvertedFromDevice: false)
        XCTAssertEqual(wheelStep, ScrollStep(wheelDx: -1, wheelDy: 3))
    }

    // MARK: - 3. Anti-Stuck-Key 5-Trigger Test (20 keys + 3 mouse buttons)

    private final class MockRemoteInputSink: RemoteInputSink, @unchecked Sendable {
        struct KeyRecord: Equatable {
            let usageId: UInt16
            let down: Bool
            let modifiers: UInt8
        }

        struct ReleaseRecord: Equatable {
            let keys: [UInt16]
            let buttons: UInt8
            let reason: ReleaseReason
            let timeoutMs: UInt32
        }

        private let lock = NSLock()
        private var _keyEvents: [KeyRecord] = []
        private var _releases: [ReleaseRecord] = []

        var keyEvents: [KeyRecord] {
            lock.lock()
            defer { lock.unlock() }
            return _keyEvents
        }

        var releases: [ReleaseRecord] {
            lock.lock()
            defer { lock.unlock() }
            return _releases
        }

        func sendKeyEvent(usageId: UInt16, down: Bool, modifiers: UInt8) {
            lock.lock()
            _keyEvents.append(KeyRecord(usageId: usageId, down: down, modifiers: modifiers))
            lock.unlock()
        }

        func sendMouseEvent(kind: RemoteMouseKind, x: Int, y: Int, buttons: UInt8, wheelDx: Int16, wheelDy: Int16) {
            _ = (kind, x, y, buttons, wheelDx, wheelDy)
        }

        func flushReleaseAll(keys: [UInt16], buttons: UInt8, reason: ReleaseReason, timeoutMs: UInt32) {
            lock.lock()
            _releases.append(ReleaseRecord(keys: keys, buttons: buttons, reason: reason, timeoutMs: timeoutMs))
            lock.unlock()
        }
    }

    func testAntiStuckKeyAllFiveTriggersHold20KeysAnd3Buttons() throws {
        // 20 distinct HID keys (16 letters + 4 left/right modifiers) + 3 mouse buttons.
        let heldKeys: [UInt16] = [
            0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
            MacHidKeyMap.leftControlUsageId,
            MacHidKeyMap.leftShiftUsageId,
            MacHidKeyMap.leftAltUsageId,
            MacHidKeyMap.leftMetaUsageId,
        ]
        XCTAssertEqual(heldKeys.count, 20)
        let expectedSortedKeys = heldKeys.sorted()
        let allThreeButtons: UInt8 = HidMouseButtonMask.left | HidMouseButtonMask.right | HidMouseButtonMask.middle

        for reason in ReleaseReason.allCases {
            let sink = MockRemoteInputSink()
            let tracker = PressedInputTracker(sink: sink)

            for key in heldKeys {
                let forwarded = tracker.handleKeyDown(usageId: key, modifiers: HidModifierMask.validMask)
                XCTAssertTrue(forwarded)
            }
            tracker.handleMouseDown(button: HidMouseButtonMask.left, x: 100, y: 100)
            tracker.handleMouseDown(button: HidMouseButtonMask.right, x: 100, y: 100)
            tracker.handleMouseDown(button: HidMouseButtonMask.middle, x: 100, y: 100)

            let startNs = DispatchTime.now().uptimeNanoseconds
            if reason == .emergencyEscapeHotkey {
                // Trigger via real Ctrl+Opt+Cmd+Escape keyDown — must NOT forward Escape!
                let keyCountBefore = sink.keyEvents.count
                let forwarded = tracker.handleKeyDown(
                    usageId: MacHidKeyMap.escapeUsageId,
                    modifiers: HidModifierMask.ctrl | HidModifierMask.alt | HidModifierMask.meta
                )
                XCTAssertFalse(forwarded, "Ctrl+Opt+Cmd+Escape must be intercepted locally")
                XCTAssertEqual(sink.keyEvents.count, keyCountBefore, "Emergency Escape must NEVER be forwarded to remote")
            } else {
                let snap = tracker.releaseAll(reason: reason)
                XCTAssertNotNil(snap)
            }
            let elapsedMs = Double(DispatchTime.now().uptimeNanoseconds - startNs) / 1_000_000.0
            XCTAssertLessThanOrEqual(elapsedMs, 100.0, "releaseAll(\(reason)) exceeded 100ms budget")

            // Assert EXACTLY 1 release_all containing ALL 20 held keys and ALL 3 mouse buttons!
            let releases = sink.releases
            XCTAssertEqual(releases.count, 1, "expected exactly 1 release_all for \(reason)")
            XCTAssertEqual(releases.first?.reason, reason)
            XCTAssertEqual(releases.first?.keys, expectedSortedKeys)
            XCTAssertEqual(releases.first?.buttons, allThreeButtons)
            XCTAssertLessThanOrEqual(releases.first?.timeoutMs ?? 999, 200)
            XCTAssertFalse(tracker.hasAnyPressedInput)

            // Idempotent double-release: zero duplicate spam!
            XCTAssertNil(tracker.releaseAll(reason: reason))
            XCTAssertEqual(sink.releases.count, 1, "second releaseAll on clean state must be a no-op")
        }

        // Cmd+key keyUp delivery test (simulating local event monitor capturing keyUp while Cmd held).
        let cmdSink = MockRemoteInputSink()
        let cmdTracker = PressedInputTracker(sink: cmdSink)
        cmdTracker.handleFlagsChanged(modifierUsageId: MacHidKeyMap.leftMetaUsageId, isPressed: true, modifiers: HidModifierMask.meta)
        XCTAssertTrue(cmdTracker.handleKeyDown(usageId: 0x06, modifiers: HidModifierMask.meta)) // Cmd+C down
        cmdTracker.handleKeyUp(usageId: 0x06, modifiers: HidModifierMask.meta) // Cmd+C up
        cmdTracker.handleFlagsChanged(modifierUsageId: MacHidKeyMap.leftMetaUsageId, isPressed: false, modifiers: 0)
        XCTAssertEqual(cmdSink.keyEvents.count, 4)
        XCTAssertEqual(cmdSink.keyEvents[2], .init(usageId: 0x06, down: false, modifiers: HidModifierMask.meta))
        XCTAssertEqual(cmdSink.keyEvents[3], .init(usageId: MacHidKeyMap.leftMetaUsageId, down: false, modifiers: 0))
        XCTAssertFalse(cmdTracker.hasAnyPressedInput)

        // End-to-end bounded flush test against real Rust bridge client (<= 100 ms).
        let client = try ZeroDeskBridgeClient()
        defer { client.close() }
        let bridgeStartNs = DispatchTime.now().uptimeNanoseconds
        let reply = try client.releaseAllInput(
            keys: heldKeys,
            buttons: allThreeButtons,
            reason: .windowResignedKey,
            timeoutMs: 150
        )
        let bridgeElapsedMs = Double(DispatchTime.now().uptimeNanoseconds - bridgeStartNs) / 1_000_000.0
        XCTAssertTrue(reply.ok)
        XCTAssertLessThanOrEqual(bridgeElapsedMs, 100.0, "live bridge releaseAllInput exceeded 100ms")
    }

    // MARK: - 4. Metal GPU Renderer 1080p Benchmark, Zero-Work Idle Skip & Color Accuracy

    func testMetalRenderer1080pBenchmarkIdleSkipAndColorCardAccuracy() throws {
        guard let device = MTLCreateSystemDefaultDevice() else {
            throw XCTSkip("No Metal GPU device available on host")
        }
        let renderer = try MetalVideoRenderer(device: device)

        // A. 1080p (1920x1080) BGRA upload + Metal render across double-buffered .bgra8Unorm ring.
        let width = 1920
        let height = 1080
        let stride = width * 4
        let drawableSize = CGSize(width: width, height: height)
        guard let targetTex = renderer.makeOffscreenTargetTexture(width: width, height: height) else {
            XCTFail("failed to create 1080p offscreen target texture")
            return
        }

        // Pre-fill a 1080p BGRA buffer.
        var pixels = Data(count: stride * height)
        pixels.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            for i in Swift.stride(from: 0, to: stride * height, by: 4) {
                base[i + 0] = 0x20 // B
                base[i + 1] = 0x80 // G
                base[i + 2] = 0xE0 // R
                base[i + 3] = 0xFF // A
            }
        }

        // Warm up texture ring allocation & pipeline on frame 1.
        let warmupFrame = CapturedBGRAFrame(seq: 1, width: width, height: height, stride: stride, data: pixels)
        let warmupRes = renderer.renderOffscreen(frame: warmupFrame, drawableSize: drawableSize, targetTexture: targetTex, waitUntilCompleted: true)
        XCTAssertTrue(warmupRes.rendered)

        // Benchmark 60 consecutive 1080p frames (alternating double-buffered .bgra8Unorm textures).
        var samplesMs: [Double] = []
        samplesMs.reserveCapacity(60)
        for seq in UInt64(2)...UInt64(61) {
            let frame = CapturedBGRAFrame(seq: seq, width: width, height: height, stride: stride, data: pixels)
            let res = renderer.renderOffscreen(frame: frame, drawableSize: drawableSize, targetTexture: targetTex, waitUntilCompleted: false)
            XCTAssertTrue(res.rendered)
            samplesMs.append(res.elapsedMs)
        }

        let sorted = samplesMs.sorted()
        let p50 = sorted[sorted.count / 2]
        let p95 = sorted[Int(Double(sorted.count - 1) * 0.95)]
        let maxMs = sorted.last ?? 0
        print(String(format: "[METAL_1080P_BENCH] frames=60 device=%@ p50=%.3fms p95=%.3fms max=%.3fms", device.name, p50, p95, maxMs))

        // Verify double-buffered ring allocated ONLY 2 textures across all 61 frames!
        XCTAssertEqual(renderer.telemetry.textureAllocations, 2, "double-buffered texture ring must allocate exactly 2 textures for constant dimensions")
        XCTAssertEqual(renderer.framesRendered, 61)
        XCTAssertLessThanOrEqual(p50, 1.0, "1080p Metal upload+encode p50 (\(p50)ms) exceeded 1.0ms target")
        XCTAssertLessThanOrEqual(p95, 1.0, "1080p Metal upload+encode p95 (\(p95)ms) exceeded 1.0ms target")

        // B. Zero GPU work when idle: re-submitting identical frameSeq + drawableSize skips render pass!
        let renderedBeforeIdle = renderer.framesRendered
        let idleBefore = renderer.idleFramesSkipped
        let duplicateFrame = CapturedBGRAFrame(seq: 61, width: width, height: height, stride: stride, data: pixels)
        for _ in 0..<10 {
            let res = renderer.renderOffscreen(frame: duplicateFrame, drawableSize: drawableSize, targetTexture: targetTex)
            XCTAssertFalse(res.rendered, "unchanged frameSeq must skip GPU render pass")
        }
        XCTAssertEqual(renderer.framesRendered, renderedBeforeIdle, "idle frames must perform zero GPU render passes")
        XCTAssertEqual(renderer.idleFramesSkipped, idleBefore + 10)

        // C. Color-card BGRA pixel readback accuracy (<= 2 per channel, zero R/B swap, top-left origin).
        let cardW = 64
        let cardH = 64
        let cardStride = cardW * 4
        var cardBytes = Data(count: cardStride * cardH)
        // Four quadrants in top-left BGRA8 layout:
        //   TL: Pure Red   (B=0,   G=0,   R=255, A=255)
        //   TR: Pure Green (B=0,   G=255, R=0,   A=255)
        //   BL: Pure Blue  (B=255, G=0,   R=0,   A=255)
        //   BR: Mid-tone   (B=42,  G=128, R=210, A=255)
        cardBytes.withUnsafeMutableBytes { raw in
            guard let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
            for y in 0..<cardH {
                for x in 0..<cardW {
                    let off = y * cardStride + x * 4
                    let (b, g, r): (UInt8, UInt8, UInt8)
                    if y < cardH / 2 && x < cardW / 2 {
                        (b, g, r) = (0, 0, 255)
                    } else if y < cardH / 2 && x >= cardW / 2 {
                        (b, g, r) = (0, 255, 0)
                    } else if y >= cardH / 2 && x < cardW / 2 {
                        (b, g, r) = (255, 0, 0)
                    } else {
                        (b, g, r) = (42, 128, 210)
                    }
                    base[off + 0] = b
                    base[off + 1] = g
                    base[off + 2] = r
                    base[off + 3] = 255
                }
            }
        }

        let cardRenderer = try MetalVideoRenderer(device: device)
        guard let cardTarget = cardRenderer.makeOffscreenTargetTexture(width: cardW, height: cardH) else {
            XCTFail("failed to create 64x64 offscreen target texture")
            return
        }
        let cardFrame = CapturedBGRAFrame(seq: 1, width: cardW, height: cardH, stride: cardStride, data: cardBytes)
        let cardRes = cardRenderer.renderOffscreen(
            frame: cardFrame,
            drawableSize: CGSize(width: cardW, height: cardH),
            targetTexture: cardTarget,
            waitUntilCompleted: true
        )
        XCTAssertTrue(cardRes.rendered)

        var readback = [UInt8](repeating: 0, count: cardStride * cardH)
        cardTarget.getBytes(
            &readback,
            bytesPerRow: cardStride,
            from: MTLRegionMake2D(0, 0, cardW, cardH),
            mipmapLevel: 0
        )

        func assertPixel(_ label: String, x: Int, y: Int, expectedB: Int, expectedG: Int, expectedR: Int) {
            let off = y * cardStride + x * 4
            let b = Int(readback[off + 0])
            let g = Int(readback[off + 1])
            let r = Int(readback[off + 2])
            let a = Int(readback[off + 3])
            XCTAssertLessThanOrEqual(abs(b - expectedB), 2, "[\(label)] B mismatch: got \(b), expected \(expectedB)")
            XCTAssertLessThanOrEqual(abs(g - expectedG), 2, "[\(label)] G mismatch: got \(g), expected \(expectedG)")
            XCTAssertLessThanOrEqual(abs(r - expectedR), 2, "[\(label)] R mismatch: got \(r), expected \(expectedR)")
            XCTAssertEqual(a, 255, "[\(label)] A must be opaque 255")
        }

        assertPixel("TL Red", x: 16, y: 16, expectedB: 0, expectedG: 0, expectedR: 255)
        assertPixel("TR Green", x: 48, y: 16, expectedB: 0, expectedG: 255, expectedR: 0)
        assertPixel("BL Blue", x: 16, y: 48, expectedB: 255, expectedG: 0, expectedR: 0)
        assertPixel("BR Mid-tone", x: 48, y: 48, expectedB: 42, expectedG: 128, expectedR: 210)
    }
}
