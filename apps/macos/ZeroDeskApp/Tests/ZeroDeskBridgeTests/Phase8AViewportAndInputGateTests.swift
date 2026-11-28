// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import CoreGraphics
import Foundation
import XCTest
@testable import ZeroDeskBridge

final class Phase8AViewportAndInputGateTests: XCTestCase {
    // MARK: - Helpers

    private final class MockSink: RemoteInputSink, @unchecked Sendable {
        struct KeyCall: Equatable {
            let usageId: UInt16
            let down: Bool
            let modifiers: UInt8
        }

        struct MouseCall: Equatable {
            let kind: RemoteMouseKind
            let x: Int
            let y: Int
            let buttons: UInt8
            let wheelDx: Int16
            let wheelDy: Int16
        }

        struct ReleaseCall: Equatable {
            let keys: [UInt16]
            let buttons: UInt8
            let reason: ReleaseReason
            let timeoutMs: UInt32
        }

        private let lock = NSLock()
        private var _keys: [KeyCall] = []
        private var _mice: [MouseCall] = []
        private var _releases: [ReleaseCall] = []

        var keys: [KeyCall] {
            lock.lock()
            defer { lock.unlock() }
            return _keys
        }

        var mice: [MouseCall] {
            lock.lock()
            defer { lock.unlock() }
            return _mice
        }

        var releases: [ReleaseCall] {
            lock.lock()
            defer { lock.unlock() }
            return _releases
        }

        func sendKeyEvent(usageId: UInt16, down: Bool, modifiers: UInt8) {
            lock.lock()
            _keys.append(KeyCall(usageId: usageId, down: down, modifiers: modifiers))
            lock.unlock()
        }

        func sendMouseEvent(
            kind: RemoteMouseKind,
            x: Int,
            y: Int,
            buttons: UInt8,
            wheelDx: Int16,
            wheelDy: Int16
        ) {
            lock.lock()
            _mice.append(MouseCall(kind: kind, x: x, y: y, buttons: buttons, wheelDx: wheelDx, wheelDy: wheelDy))
            lock.unlock()
        }

        func flushReleaseAll(keys: [UInt16], buttons: UInt8, reason: ReleaseReason, timeoutMs: UInt32) {
            lock.lock()
            _releases.append(ReleaseCall(keys: keys, buttons: buttons, reason: reason, timeoutMs: timeoutMs))
            lock.unlock()
        }
    }

    private final class MockOsInputStateProvider: OsInputStateProvider, @unchecked Sendable {
        private let lock = NSLock()
        private var pressedKeyCodes: Set<UInt16> = []
        private var modifierMask: UInt8 = 0
        private var mouseButtons: UInt8 = 0
        private var explicitModifierUsages: Set<UInt16>?

        func setState(
            keyCodes: Set<UInt16>,
            modifiers: UInt8,
            mouseButtons: UInt8,
            explicitModifierUsages: Set<UInt16>? = nil
        ) {
            lock.lock()
            self.pressedKeyCodes = keyCodes
            self.modifierMask = modifiers
            self.mouseButtons = mouseButtons
            self.explicitModifierUsages = explicitModifierUsages
            lock.unlock()
        }

        func isKeyPressed(macKeyCode: UInt16) -> Bool {
            lock.lock()
            defer { lock.unlock() }
            return pressedKeyCodes.contains(macKeyCode)
        }

        func currentModifierMask() -> UInt8 {
            lock.lock()
            defer { lock.unlock() }
            return modifierMask
        }

        func currentPressedMouseButtons() -> UInt8 {
            lock.lock()
            defer { lock.unlock() }
            return mouseButtons
        }

        func isModifierPressed(hidUsageId: UInt16) -> Bool {
            lock.lock()
            let explicit = explicitModifierUsages
            lock.unlock()
            if let explicit {
                return explicit.contains(hidUsageId)
            }
            let bitDown = MacHidKeyMap.modifierBit(forUsageId: hidUsageId)
                .map { (currentModifierMask() & $0) != 0 } ?? false
            let keyDown = MacHidKeyMap.macKeyCode(forHidUsage: hidUsageId)
                .map { isKeyPressed(macKeyCode: $0) } ?? bitDown
            return bitDown && keyDown
        }
    }

    // MARK: - 1. 3-Mode RemoteCoordinateMapper Round-Trip Matrix (Fit / 1:1 / Fill, 1x/2x/3x Retina)

    func testThreeModeCoordinateMapperRoundTripAcrossRetinaScalesAndAspectRatios() {
        struct MatrixCase {
            let name: String
            let viewPoints: CGSize
            let backingScale: CGFloat
            let frameSize: CGSize
            let scrollOffset: CGPoint
        }

        let cases: [MatrixCase] = [
            MatrixCase(name: "16:9 in 16:9 1x", viewPoints: CGSize(width: 1920, height: 1080), backingScale: 1.0, frameSize: CGSize(width: 1920, height: 1080), scrollOffset: .zero),
            MatrixCase(name: "16:9 in 21:9 2x Retina", viewPoints: CGSize(width: 1280, height: 540), backingScale: 2.0, frameSize: CGSize(width: 1920, height: 1080), scrollOffset: .zero),
            MatrixCase(name: "16:9 in 4:3 3x Retina", viewPoints: CGSize(width: 400, height: 300), backingScale: 3.0, frameSize: CGSize(width: 1920, height: 1080), scrollOffset: CGPoint(x: 320, y: 120)),
            MatrixCase(name: "4:3 in 16:9 2x Retina", viewPoints: CGSize(width: 960, height: 540), backingScale: 2.0, frameSize: CGSize(width: 1600, height: 1200), scrollOffset: CGPoint(x: 0, y: 80)),
            MatrixCase(name: "21:9 in 16:9 1x", viewPoints: CGSize(width: 1280, height: 720), backingScale: 1.0, frameSize: CGSize(width: 3440, height: 1440), scrollOffset: CGPoint(x: 1100, y: 400)),
            MatrixCase(name: "9:16 portrait in 16:9 3x", viewPoints: CGSize(width: 640, height: 360), backingScale: 3.0, frameSize: CGSize(width: 1080, height: 1920), scrollOffset: CGPoint(x: 0, y: 500)),
            MatrixCase(name: "4K in MacBook 1440x900 2x", viewPoints: CGSize(width: 1440, height: 900), backingScale: 2.0, frameSize: CGSize(width: 3840, height: 2160), scrollOffset: CGPoint(x: 960, y: 360)),
            MatrixCase(name: "Small 800x600 in large 1600x1200 1x", viewPoints: CGSize(width: 1600, height: 1200), backingScale: 1.0, frameSize: CGSize(width: 800, height: 600), scrollOffset: .zero),
        ]

        let sampleFractions: [(Double, Double)] = [
            (0.05, 0.05),
            (0.25, 0.75),
            (0.50, 0.50),
            (0.75, 0.25),
            (0.95, 0.95),
        ]

        for tc in cases {
            let backingSize = CGSize(
                width: Double(tc.viewPoints.width) * Double(tc.backingScale),
                height: Double(tc.viewPoints.height) * Double(tc.backingScale)
            )
            let fw = Int(tc.frameSize.width)
            let fh = Int(tc.frameSize.height)

            for mode in DisplayScaleMode.allCases {
                let vp = ViewportState(
                    mode: mode,
                    viewBackingSize: backingSize,
                    frameSize: tc.frameSize,
                    scrollOffset: tc.scrollOffset
                )
                guard let geo = RemoteCoordinateMapper.computeGeometry(for: vp) else {
                    XCTFail("computeGeometry returned nil for \(tc.name) mode=\(mode)")
                    continue
                }

                // Verify scale invariant per mode.
                switch mode {
                case .fit:
                    XCTAssertEqual(
                        geo.scale,
                        min(Double(backingSize.width) / Double(fw), Double(backingSize.height) / Double(fh)),
                        accuracy: 1e-9
                    )
                case .fill:
                    XCTAssertEqual(
                        geo.scale,
                        max(Double(backingSize.width) / Double(fw), Double(backingSize.height) / Double(fh)),
                        accuracy: 1e-9
                    )
                case .actual1to1:
                    XCTAssertEqual(geo.scale, 1.0, accuracy: 1e-9)
                }

                // Round-trip: remote -> view point -> remote across BOTH origins with error <= 1px!
                var visibleHits = 0
                for (u, v) in sampleFractions {
                    let remotePt = RemotePoint(
                        x: min(max(Int(Double(fw) * u), 0), fw - 1),
                        y: min(max(Int(Double(fh) * v), 0), fh - 1)
                    )
                    for origin in [CoordinateOrigin.topLeft, CoordinateOrigin.bottomLeft] {
                        if let viewPt = RemoteCoordinateMapper.mapRemoteToViewPoint(
                            remotePt,
                            backingScale: tc.backingScale,
                            in: vp,
                            origin: origin
                        ) {
                            visibleHits += 1
                            let roundTripped = RemoteCoordinateMapper.mapViewPoint(
                                viewPt,
                                backingScale: tc.backingScale,
                                in: vp,
                                origin: origin
                            )
                            XCTAssertNotNil(roundTripped, "[\(tc.name) \(mode) \(origin)] visible point round-trip returned nil")
                            if let rt = roundTripped {
                                XCTAssertLessThanOrEqual(abs(rt.x - remotePt.x), 1, "[\(tc.name) \(mode)] X error > 1px")
                                XCTAssertLessThanOrEqual(abs(rt.y - remotePt.y), 1, "[\(tc.name) \(mode)] Y error > 1px")
                            }
                        }
                    }
                }
                XCTAssertGreaterThan(visibleHits, 0, "[\(tc.name) \(mode)] expected at least one visible sample")
            }
        }
    }

    func testFitLetterboxAndPillarboxReturnNilNeverClamp() {
        // 16:9 remote inside 4:3 view -> top/bottom letterbox bars MUST return nil!
        let letterboxVP = ViewportState(
            mode: .fit,
            viewBackingSize: CGSize(width: 1024, height: 768),
            frameSize: CGSize(width: 1920, height: 1080)
        )
        let geoL = RemoteCoordinateMapper.computeGeometry(for: letterboxVP)!
        XCTAssertGreaterThan(geoL.visibleBackingRect.minY, 50)
        // Top black bar & bottom black bar in topLeft origin
        XCTAssertNil(RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 512, y: 10), in: letterboxVP, origin: .topLeft))
        XCTAssertNil(RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 512, y: 760), in: letterboxVP, origin: .topLeft))
        // Bottom-left origin equivalent
        XCTAssertNil(RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 512, y: 10), in: letterboxVP, origin: .bottomLeft))
        XCTAssertNil(RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 512, y: 760), in: letterboxVP, origin: .bottomLeft))

        // 4:3 remote inside 16:9 view -> left/right pillarbox bars MUST return nil!
        let pillarboxVP = ViewportState(
            mode: .fit,
            viewBackingSize: CGSize(width: 1920, height: 1080),
            frameSize: CGSize(width: 1024, height: 768)
        )
        let geoP = RemoteCoordinateMapper.computeGeometry(for: pillarboxVP)!
        XCTAssertGreaterThan(geoP.visibleBackingRect.minX, 100)
        XCTAssertNil(RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 20, y: 540), in: pillarboxVP, origin: .topLeft))
        XCTAssertNil(RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 1900, y: 540), in: pillarboxVP, origin: .topLeft))
    }

    func testFillCenteredCropAnd1to1ScrollOffsetAccuracy() {
        // Fill: 1920x1080 inside 1000x1000 -> scale = 1000/1080, horizontal crop centered!
        let fillVP = ViewportState(
            mode: .fill,
            viewBackingSize: CGSize(width: 1000, height: 1000),
            frameSize: CGSize(width: 1920, height: 1080)
        )
        let centerMapped = RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 500, y: 500), in: fillVP, origin: .topLeft)
        XCTAssertNotNil(centerMapped)
        if let c = centerMapped {
            XCTAssertLessThanOrEqual(abs(c.x - 960), 1)
            XCTAssertLessThanOrEqual(abs(c.y - 540), 1)
        }
        // Cropped far-left pixel (x=10) is NOT visible in centered Fill crop -> inverse returns nil!
        XCTAssertNil(RemoteCoordinateMapper.mapRemoteToBackingPoint(RemotePoint(x: 10, y: 540), in: fillVP, origin: .topLeft))

        // 1:1 with scrollOffset=(500, 300) on 2000x1500 frame inside 1000x800 view:
        let scrollVP = ViewportState(
            mode: .actual1to1,
            viewBackingSize: CGSize(width: 1000, height: 800),
            frameSize: CGSize(width: 2000, height: 1500),
            scrollOffset: CGPoint(x: 500, y: 300)
        )
        let topLeftPixel = RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 0.5, y: 0.5), in: scrollVP, origin: .topLeft)
        XCTAssertEqual(topLeftPixel, RemotePoint(x: 500, y: 300))
        let midPixel = RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 250.5, y: 150.5), in: scrollVP, origin: .topLeft)
        XCTAssertEqual(midPixel, RemotePoint(x: 750, y: 450))
    }

    func testExactAbsoluteCoordinatesCrossOriginYFlipAndInvalidDimensionGuards() {
        // 16:9 remote (1920x1080) inside 4:3 view (1024x768) in .fit:
        // scale = 1024 / 1920 = 8/15; renderedH = 1080 * 8/15 = 576; top bar = (768 - 576)/2 = 96px exact!
        let lb = ViewportState(
            mode: .fit,
            viewBackingSize: CGSize(width: 1024, height: 768),
            frameSize: CGSize(width: 1920, height: 1080),
            scrollOffset: CGPoint(x: 99, y: 99) // must be forced to .zero for .fit!
        )
        XCTAssertEqual(lb.scrollOffset, .zero)
        let geo = RemoteCoordinateMapper.computeGeometry(for: lb)!
        XCTAssertEqual(geo.renderedFrameRect.minX, 0.0, accuracy: 1e-9)
        XCTAssertEqual(geo.renderedFrameRect.minY, 96.0, accuracy: 1e-9)
        XCTAssertEqual(geo.renderedFrameRect.height, 576.0, accuracy: 1e-9)
        // Exact top-left remote pixel (0, 0) lies at backing (0, 96) in topLeft origin:
        XCTAssertEqual(
            RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 0.0, y: 96.0), in: lb, origin: .topLeft),
            RemotePoint(x: 0, y: 0)
        )
        // Cross-origin Y-flip: y_tl + y_bl == viewBackingHeight (768.0) maps to the exact same remote pixel!
        let ptTL = CGPoint(x: 512.0, y: 240.0)
        let ptBL = CGPoint(x: 512.0, y: 768.0 - 240.0)
        XCTAssertEqual(
            RemoteCoordinateMapper.mapBackingPoint(ptTL, in: lb, origin: .topLeft),
            RemoteCoordinateMapper.mapBackingPoint(ptBL, in: lb, origin: .bottomLeft)
        )

        // Pillarbox: 4:3 remote (1024x768) inside 16:9 view (1920x1080) in .fit:
        // scale = 1080 / 768 = 1.40625; renderedW = 1440; left bar = (1920 - 1440)/2 = 240px exact!
        let pb = ViewportState(
            mode: .fit,
            viewBackingSize: CGSize(width: 1920, height: 1080),
            frameSize: CGSize(width: 1024, height: 768)
        )
        let geoP = RemoteCoordinateMapper.computeGeometry(for: pb)!
        XCTAssertEqual(geoP.renderedFrameRect.minX, 240.0, accuracy: 1e-9)
        XCTAssertEqual(
            RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 240.0, y: 0.0), in: pb, origin: .topLeft),
            RemotePoint(x: 0, y: 0)
        )

        // Invalid dimensions (zero, NaN, Inf, > 16384) return nil cleanly with zero Int(NaN) trap!
        let invalidViewports = [
            ViewportState(mode: .fit, viewBackingSize: .zero, frameSize: CGSize(width: 1920, height: 1080)),
            ViewportState(mode: .fit, viewBackingSize: CGSize(width: CGFloat.nan, height: 1080), frameSize: CGSize(width: 1920, height: 1080)),
            ViewportState(mode: .fit, viewBackingSize: CGSize(width: 20_000, height: 1080), frameSize: CGSize(width: 1920, height: 1080)),
            ViewportState(mode: .actual1to1, viewBackingSize: CGSize(width: 1000, height: 1000), frameSize: CGSize(width: 1920, height: 20_000)),
        ]
        for bad in invalidViewports {
            XCTAssertFalse(bad.isValid)
            XCTAssertNil(RemoteCoordinateMapper.computeGeometry(for: bad))
            XCTAssertNil(RemoteCoordinateMapper.mapBackingPoint(CGPoint(x: 10, y: 10), in: bad))
        }

        // 1:1 non-finite scrollOffset sanitizes to 0 and fractional offsets round to integer pixels.
        let san = ViewportState(
            mode: .actual1to1,
            viewBackingSize: CGSize(width: 800, height: 600),
            frameSize: CGSize(width: 1600, height: 1200),
            scrollOffset: CGPoint(x: CGFloat.nan, y: 120.7)
        )
        XCTAssertEqual(san.scrollOffset, CGPoint(x: 0, y: 121))
    }

    // MARK: - 2. Unified InputGate Event-Sequence & Trigger Tests

    func testInputGateHoldKeyModifierMouseThenOpenDrawerFilePickerOrSwitchViewportEmitsReleaseAll() {
        let sink = MockSink()
        let mockOs = MockOsInputStateProvider()
        let gate = InputGate(
            sink: sink,
            osStateProvider: mockOs,
            observeAppFocusNotifications: false
        )
        defer { gate.stop() }
        XCTAssertFalse(gate.isInputEnabled, "InputGate must default to View-Only (false)")
        gate.setInputEnabledFromAck(true)

        let fitVP = ViewportState(
            mode: .fit,
            viewBackingSize: CGSize(width: 1920, height: 1080),
            frameSize: CGSize(width: 1920, height: 1080)
        )
        gate.updateViewport(fitVP)

        // Scenario A: Hold key 'A' (0x04) + LeftCmd via flagsChanged (0xE3) + Left Mouse Button -> open drawer/file picker.
        gate.handleFlagsChanged(modifierUsageId: MacHidKeyMap.leftMetaUsageId, isPressed: true, modifiers: HidModifierMask.meta)
        XCTAssertEqual(gate.handleKeyDown(usageId: 0x04, modifiers: HidModifierMask.meta), .forwarded)
        let pt = gate.handleMouseDown(
            button: HidMouseButtonMask.left,
            viewPoint: CGPoint(x: 500, y: 500),
            backingScale: 1.0,
            origin: .topLeft
        )
        XCTAssertEqual(pt, RemotePoint(x: 500, y: 500))

        let before = gate.pressedSnapshot()
        XCTAssertEqual(before.pressedKeys, [0x04])
        XCTAssertEqual(before.pressedModifiers, [MacHidKeyMap.leftMetaUsageId])
        XCTAssertEqual(before.pressedMouseButtons, [HidMouseButtonMask.left])

        // Trigger: opening control drawer or NSOpenPanel file picker!
        let rel = gate.notifyOverlayOpened()
        XCTAssertNotNil(rel)
        XCTAssertTrue(gate.pressedSnapshot().isEmpty)
        XCTAssertEqual(sink.releases.count, 1)
        XCTAssertEqual(sink.releases[0].reason, .uiOverlayOpened)
        XCTAssertEqual(sink.releases[0].keys, [0x04, MacHidKeyMap.leftMetaUsageId])
        XCTAssertEqual(sink.releases[0].buttons, HidMouseButtonMask.left)

        // Scenario B: Hold key 'B' (0x05) + RightShift (0xE5) + Right Mouse Button -> switch viewport Fit -> 1:1!
        gate.handleFlagsChanged(modifierUsageId: MacHidKeyMap.rightShiftUsageId, isPressed: true, modifiers: HidModifierMask.shift)
        XCTAssertEqual(gate.handleKeyDown(usageId: 0x05, modifiers: HidModifierMask.shift), .forwarded)
        _ = gate.handleMouseDown(
            button: HidMouseButtonMask.right,
            viewPoint: CGPoint(x: 200, y: 200),
            backingScale: 1.0,
            origin: .topLeft
        )
        XCTAssertFalse(gate.pressedSnapshot().isEmpty)

        let actualVP = ViewportState(
            mode: .actual1to1,
            viewBackingSize: CGSize(width: 1920, height: 1080),
            frameSize: CGSize(width: 1920, height: 1080)
        )
        gate.updateViewport(actualVP)
        XCTAssertTrue(gate.pressedSnapshot().isEmpty)
        XCTAssertEqual(sink.releases.count, 2)
        XCTAssertEqual(sink.releases[1].reason, .viewportChanged)
        XCTAssertEqual(sink.releases[1].keys, [0x05, MacHidKeyMap.rightShiftUsageId])
        XCTAssertEqual(sink.releases[1].buttons, HidMouseButtonMask.right)
        XCTAssertEqual(gate.viewport, actualVP)

        // Scenario C: Fit letterbox click NEVER dispatches mouse down to sink!
        let letterboxVP = ViewportState(
            mode: .fit,
            viewBackingSize: CGSize(width: 1024, height: 768),
            frameSize: CGSize(width: 1920, height: 1080)
        )
        gate.updateViewport(letterboxVP)
        let miceBefore = sink.mice.count
        XCTAssertNil(gate.handleMouseDown(button: HidMouseButtonMask.left, viewPoint: CGPoint(x: 512, y: 10), backingScale: 1.0, origin: .topLeft))
        XCTAssertEqual(sink.mice.count, miceBefore)
        XCTAssertTrue(gate.pressedSnapshot().isEmpty)

        // Scenario D: Emergency Escape (Ctrl+Opt+Cmd+Escape) releases all, NEVER forwards Escape, and sets isInputEnabled = false!
        XCTAssertEqual(gate.handleKeyDown(usageId: 0x06, modifiers: 0), .forwarded)
        let keysBeforeEsc = sink.keys.count
        let outcome = gate.handleKeyDown(
            usageId: MacHidKeyMap.escapeUsageId,
            modifiers: HidModifierMask.ctrl | HidModifierMask.alt | HidModifierMask.meta
        )
        XCTAssertEqual(outcome, .emergencyEscapeTriggered)
        XCTAssertEqual(sink.keys.count, keysBeforeEsc, "Escape must NEVER be forwarded to remote")
        XCTAssertFalse(gate.isInputEnabled)
        XCTAssertTrue(gate.pressedSnapshot().isEmpty)
        XCTAssertEqual(sink.releases.last?.reason, .emergencyEscapeHotkey)

        // Subsequent keyDown while isInputEnabled == false is dropped with 0 sink calls!
        XCTAssertEqual(gate.handleKeyDown(usageId: 0x07, modifiers: 0), .ignored)
        XCTAssertEqual(sink.keys.count, keysBeforeEsc)
    }

    // MARK: - 3. 200ms OS State Reconciliation Test (Mock OsInputStateProvider)

    func testInputGate200msOsReconciliationEmitsSyntheticUpWhenOsReleasesInputs() {
        let sink = MockSink()
        let mockOs = MockOsInputStateProvider()
        let macKeyA = MacHidKeyMap.macKeyCode(forHidUsage: 0x04)!
        let macKeyLCtrl = MacHidKeyMap.macKeyCode(forHidUsage: MacHidKeyMap.leftControlUsageId)!

        // Initially OS reports 'A', LCtrl, and Left Mouse button ALL pressed.
        mockOs.setState(
            keyCodes: [macKeyA, macKeyLCtrl],
            modifiers: HidModifierMask.ctrl,
            mouseButtons: HidMouseButtonMask.left
        )

        let gate = InputGate(
            sink: sink,
            osStateProvider: mockOs,
            reconciliationIntervalMs: 50,
            observeAppFocusNotifications: false
        )
        defer { gate.stop() }
        gate.setInputEnabledFromAck(true)

        gate.updateViewport(
            ViewportState(
                mode: .fit,
                viewBackingSize: CGSize(width: 1000, height: 1000),
                frameSize: CGSize(width: 1000, height: 1000)
            )
        )

        gate.handleFlagsChanged(modifierUsageId: MacHidKeyMap.leftControlUsageId, isPressed: true, modifiers: HidModifierMask.ctrl)
        XCTAssertEqual(gate.handleKeyDown(usageId: 0x04, modifiers: HidModifierMask.ctrl), .forwarded)
        _ = gate.handleMouseDown(
            button: HidMouseButtonMask.left,
            viewPoint: CGPoint(x: 400, y: 400),
            backingScale: 1.0,
            origin: .topLeft
        )

        // Reconcile while OS still reports all pressed -> 0 synthetic ups!
        let r0 = gate.reconcileWithOsState()
        XCTAssertTrue(r0.releasedKeys.isEmpty)
        XCTAssertTrue(r0.releasedModifiers.isEmpty)
        XCTAssertTrue(r0.releasedMouseButtons.isEmpty)

        // Now OS reports key 'A' was released (dropped keyUp event), while LCtrl + mouse remain held.
        mockOs.setState(
            keyCodes: [macKeyLCtrl],
            modifiers: HidModifierMask.ctrl,
            mouseButtons: HidMouseButtonMask.left
        )
        let r1 = gate.reconcileWithOsState()
        XCTAssertEqual(r1.releasedKeys, [0x04])
        XCTAssertTrue(r1.releasedModifiers.isEmpty)
        XCTAssertTrue(r1.releasedMouseButtons.isEmpty)
        XCTAssertEqual(sink.keys.last, .init(usageId: 0x04, down: false, modifiers: HidModifierMask.ctrl))
        XCTAssertTrue(gate.pressedSnapshot().pressedKeys.isEmpty)
        XCTAssertEqual(gate.pressedSnapshot().pressedModifiers, [MacHidKeyMap.leftControlUsageId])

        // Now OS releases LCtrl + Left Mouse button -> background reconciliation timer automatically emits synthetic ups!
        mockOs.setState(keyCodes: [], modifiers: 0, mouseButtons: 0)
        let deadline = Date().addingTimeInterval(1.0)
        while gate.hasAnyPressedInput && Date() < deadline {
            Thread.sleep(forTimeInterval: 0.01)
        }
        XCTAssertTrue(gate.pressedSnapshot().isEmpty, "background OS reconciliation timer must clear stale modifier & mouse button")
        XCTAssertTrue(sink.keys.contains(.init(usageId: MacHidKeyMap.leftControlUsageId, down: false, modifiers: 0)))
        XCTAssertTrue(sink.mice.contains(.init(kind: .buttonUp, x: 400, y: 400, buttons: 0, wheelDx: 0, wheelDy: 0)))
    }

    func testRightSideModifiers0xE4To0xE7Survive200msReconciliationAndReleaseCleanly() {
        let sink = MockSink()
        let mockOs = MockOsInputStateProvider()
        let rightModifiers: [(UInt16, UInt8)] = [
            (MacHidKeyMap.rightControlUsageId, HidModifierMask.ctrl),
            (MacHidKeyMap.rightShiftUsageId, HidModifierMask.shift),
            (MacHidKeyMap.rightAltUsageId, HidModifierMask.alt),
            (MacHidKeyMap.rightMetaUsageId, HidModifierMask.meta),
        ]

        // Simulate macOS CGEventSource.keyState returning false for right modifiers while NX flags
        // (`isModifierPressed(hidUsageId:)`) accurately report all 4 right-side modifiers held!
        let allRightSet = Set(rightModifiers.map(\.0))
        mockOs.setState(
            keyCodes: [],
            modifiers: HidModifierMask.validMask,
            mouseButtons: 0,
            explicitModifierUsages: allRightSet
        )

        let gate = InputGate(
            sink: sink,
            osStateProvider: mockOs,
            reconciliationIntervalMs: 50,
            observeAppFocusNotifications: false
        )
        defer { gate.stop() }
        gate.setInputEnabledFromAck(true)

        for (usage, bit) in rightModifiers {
            gate.handleFlagsChanged(modifierUsageId: usage, isPressed: true, modifiers: bit)
        }
        XCTAssertEqual(gate.pressedSnapshot().pressedModifiers, allRightSet)

        // Reconciliation MUST NOT falsely release held right-side modifiers!
        let r0 = gate.reconcileWithOsState()
        XCTAssertTrue(r0.releasedModifiers.isEmpty)
        XCTAssertEqual(gate.pressedSnapshot().pressedModifiers, allRightSet)

        // Once OS releases RightShift (0xE5) and RightCmd (0xE7), ONLY those two are synthesized up!
        mockOs.setState(
            keyCodes: [],
            modifiers: HidModifierMask.ctrl | HidModifierMask.alt,
            mouseButtons: 0,
            explicitModifierUsages: [MacHidKeyMap.rightControlUsageId, MacHidKeyMap.rightAltUsageId]
        )
        let r1 = gate.reconcileWithOsState()
        XCTAssertEqual(r1.releasedModifiers, [MacHidKeyMap.rightShiftUsageId, MacHidKeyMap.rightMetaUsageId])
        XCTAssertEqual(
            gate.pressedSnapshot().pressedModifiers,
            [MacHidKeyMap.rightControlUsageId, MacHidKeyMap.rightAltUsageId]
        )
    }

    func testInputGateRepeatDedupDragSafeKeyReleaseAndEmitReleaseOrdering() {
        let sink = MockSink()
        let mockOs = MockOsInputStateProvider()
        let gate = InputGate(
            sink: sink,
            osStateProvider: mockOs,
            observeAppFocusNotifications: false
        )
        defer { gate.stop() }
        gate.setInputEnabledFromAck(true)
        gate.updateViewport(
            ViewportState(
                mode: .fit,
                viewBackingSize: CGSize(width: 1000, height: 1000),
                frameSize: CGSize(width: 1000, height: 1000)
            )
        )

        // Repeat keyDown is deduplicated (never double-emits down).
        XCTAssertEqual(gate.handleKeyDown(usageId: 0x04, modifiers: 0, isARepeat: false), .forwarded)
        XCTAssertEqual(gate.handleKeyDown(usageId: 0x04, modifiers: 0, isARepeat: true), .ignored)
        XCTAssertEqual(sink.keys.count, 1)

        // Stray mouseUp for an unpressed button is dropped (zero spurious buttonUp).
        XCTAssertNil(
            gate.handleMouseUp(
                button: HidMouseButtonMask.right,
                viewPoint: CGPoint(x: 100, y: 100),
                backingScale: 1.0,
                origin: .topLeft
            )
        )
        XCTAssertTrue(sink.mice.isEmpty)

        // Active drag + held key: releaseKeysAndModifiersOnly releases key 'A' while preserving left drag button!
        _ = gate.handleMouseDown(
            button: HidMouseButtonMask.left,
            viewPoint: CGPoint(x: 100, y: 100),
            backingScale: 1.0,
            origin: .topLeft
        )
        let partial = gate.releaseKeysAndModifiersOnly(reason: .mouseExitedView)
        XCTAssertNotNil(partial)
        XCTAssertEqual(partial?.keys, [0x04])
        XCTAssertEqual(partial?.mouseButtons, 0)
        XCTAssertTrue(gate.pressedSnapshot().pressedKeys.isEmpty)
        XCTAssertEqual(gate.pressedSnapshot().pressedMouseButtons, [HidMouseButtonMask.left])

        // Concurrent emit vs releaseAll under DispatchGroup exercises emitLock -> lock ordering cleanly (TSan safe).
        let group = DispatchGroup()
        let q1 = DispatchQueue(label: "zd.test.emit1", attributes: .concurrent)
        for _ in 0..<25 {
            group.enter()
            q1.async {
                _ = gate.handleKeyDown(usageId: 0x05, modifiers: 0)
                group.leave()
            }
            group.enter()
            q1.async {
                _ = gate.releaseAll(reason: .uiOverlayOpened)
                group.leave()
            }
        }
        group.wait()
        gate.releaseAll(reason: .sessionLeftConnected)
        XCTAssertTrue(gate.pressedSnapshot().isEmpty)
    }

    // MARK: - 4. SystemPermissionGuide Deep Links, Debouncer & Clipboard Anti-Echo Tests

    @MainActor
    func testSystemPermissionDeepLinkFallbackOrderingAndNeverAutoRequests() {
        var promptSpyCalls = 0
        for kind in MacSystemPermissionKind.allCases {
            let urls = SystemPermissionLinks.candidateURLs(for: kind, isMacOS13OrLater: true)
            XCTAssertEqual(urls.count, 4)
            XCTAssertTrue(urls[0].absoluteString.contains("PrivacySecurity.extension?Privacy_"))
            XCTAssertTrue(urls[1].absoluteString.contains("preference.security?Privacy_"))

            // Legacy macOS (< 13) prioritizes legacy preference URL first.
            let legacyUrls = SystemPermissionLinks.candidateURLs(for: kind, isMacOS13OrLater: false)
            XCTAssertTrue(legacyUrls[0].absoluteString.contains("preference.security?Privacy_"))

            // Simulate macOS 13+ deep link failing, legacy deep link failing -> falls back to pane!
            var attempted: [URL] = []
            let opened = SystemPermissionLinks.openSettings(for: kind) { url in
                attempted.append(url)
                return attempted.count == 3
            }
            XCTAssertEqual(attempted.count, 3)
            XCTAssertEqual(opened, urls[2])
        }

        // Building candidate URLs and opening System Settings NEVER invokes CGRequestScreenCaptureAccess!
        XCTAssertEqual(promptSpyCalls, 0)

        // Only an explicit UserInitiatedPermissionAction triggers the requester closure!
        let granted = SystemPermissionLinks.requestScreenCaptureAccessExplicitly(
            UserInitiatedPermissionAction()
        ) {
            promptSpyCalls += 1
            return true
        }
        XCTAssertTrue(granted)
        XCTAssertEqual(promptSpyCalls, 1)
    }

    func testQualityControlDebouncerCoalescesRapidChanges() {
        final class ValueBox: @unchecked Sendable {
            private let lock = NSLock()
            private var storage: [Int] = []

            func append(_ v: Int) {
                lock.lock()
                storage.append(v)
                lock.unlock()
            }

            func snapshot() -> [Int] {
                lock.lock()
                defer { lock.unlock() }
                return storage
            }
        }

        let exp = expectation(description: "debounced quality callback fires once")
        let queue = DispatchQueue(label: "zd.test.debounce")
        let debouncer = QualityControlDebouncer(delayMs: 160, queue: queue)
        let box = ValueBox()

        for v in [2000, 5000, 10000, 20000] {
            debouncer.schedule {
                box.append(v)
                exp.fulfill()
            }
        }
        XCTAssertTrue(debouncer.isPending)
        wait(for: [exp], timeout: 1.0)
        Thread.sleep(forTimeInterval: 0.2)
        XCTAssertFalse(debouncer.isPending)
        XCTAssertEqual(box.snapshot(), [20000], "rapid UI changes must coalesce to latest value only")
    }

    func testClipboardSyncGuardAntiEchoAndZeroContentLogging() {
        let guardObj = ClipboardSyncGuard()
        XCTAssertFalse(guardObj.shouldSuppressEcho(currentChangeCount: 10))
        guardObj.beginLocalWrite(changeCountBefore: 10)
        // Simulate clearContents() (+1 -> 11) and setString() (+1 -> 12).
        guardObj.endLocalWrite(changeCountAfter: 12)
        // Own write range (10 < current <= 12) is suppressed!
        XCTAssertFalse(guardObj.shouldSuppressEcho(currentChangeCount: 10))
        XCTAssertTrue(guardObj.shouldSuppressEcho(currentChangeCount: 11))
        XCTAssertTrue(guardObj.shouldSuppressEcho(currentChangeCount: 12))
        // Concurrent/subsequent external user copy (changeCount == 13) is NOT suppressed!
        XCTAssertFalse(guardObj.shouldSuppressEcho(currentChangeCount: 13))

        let secretText = "SUPER_SECRET_CLIPBOARD_PASSWORD_12345"
        let logLine = ClipboardSyncGuard.redactedSyncLogLine(byteCount: secretText.utf8.count)
        XCTAssertEqual(logLine, "clipboard synced (<1 KB)")
        XCTAssertFalse(logLine.contains(secretText))
        XCTAssertEqual(ClipboardSyncGuard.sizeBucket(forByteCount: 2048), "1-64 KB")
        XCTAssertEqual(ClipboardSyncGuard.sizeBucket(forByteCount: 128_000), ">64 KB")
        XCTAssertEqual(ClipboardSyncGuard.redactedPolicyDeniedLogLine, "clipboard denied by policy")
    }
}
