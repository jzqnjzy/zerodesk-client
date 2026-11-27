// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import Foundation
import MetalKit
import SwiftUI
import ZeroDeskBridge

/// Interactive Metal `MTKView` capturing mouse, wheel, and keyboard input (including `Cmd+key`
/// `keyUp` via local event monitor) with 5-trigger anti-stuck-key `releaseAll` safety.
@MainActor
public final class InteractiveMetalNSView: MTKView {
    // Device-dependent NX modifier masks from <IOKit/hidsystem/IOLLEvent.h> to distinguish
    // left vs right Shift/Ctrl/Alt/Cmd on `flagsChanged` without merging left & right modifiers.
    private static let nxDeviceLControlMask: UInt = 0x00000001
    private static let nxDeviceLShiftMask: UInt = 0x00000002
    private static let nxDeviceRShiftMask: UInt = 0x00000004
    private static let nxDeviceLCmdMask: UInt = 0x00000008
    private static let nxDeviceRCmdMask: UInt = 0x00000010
    private static let nxDeviceLAltMask: UInt = 0x00000020
    private static let nxDeviceRAltMask: UInt = 0x00000040
    private static let nxDeviceRControlMask: UInt = 0x00002000

    private let videoRenderer: MetalVideoRenderer
    private let keyMapper = MacHidKeyMap()
    private var scrollQuantizer = ScrollQuantizer()
    private var trackingAreaRef: NSTrackingArea?

    private var _inputTracker: PressedInputTracker?
    private var _isSessionActive: Bool = false
    private var _remoteSize: RemoteSize = RemoteSize(width: 0, height: 0)
    private var onEmergencyEscape: (() -> Void)?

    // Stored in a Sendable box so teardown in `deinit` stays Swift 6 concurrency-warning-free.
    private final class MonitorCleanupBox: @unchecked Sendable {
        private let lock = NSLock()
        private var keyMonitor: Any?
        private var observers: [NSObjectProtocol] = []

        func replaceKeyMonitor(_ monitor: Any?) {
            let old: Any?
            lock.lock()
            old = keyMonitor
            keyMonitor = monitor
            lock.unlock()
            if let old {
                NSEvent.removeMonitor(old)
            }
        }

        func replaceObservers(_ next: [NSObjectProtocol]) {
            let old: [NSObjectProtocol]
            lock.lock()
            old = observers
            observers = next
            lock.unlock()
            for obs in old {
                NotificationCenter.default.removeObserver(obs)
            }
        }

        func teardownAll() {
            replaceKeyMonitor(nil)
            replaceObservers([])
        }
    }

    private let cleanupBox = MonitorCleanupBox()

    public init(renderer: MetalVideoRenderer) {
        self.videoRenderer = renderer
        super.init(frame: .zero, device: renderer.device)
        renderer.configure(view: self)
        wantsLayer = true
    }

    @available(*, unavailable)
    required init(coder: NSCoder) {
        fatalError("init(coder:) is not supported")
    }

    deinit {
        cleanupBox.teardownAll()
    }

    public override var acceptsFirstResponder: Bool {
        true
    }

    public override func resignFirstResponder() -> Bool {
        let ok = super.resignFirstResponder()
        _inputTracker?.releaseAll(reason: .windowResignedKey)
        scrollQuantizer.reset()
        return ok
    }

    public override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        installLifecycleObservers()
        if window != nil && _isSessionActive {
            installKeyMonitor()
        }
    }

    public override func viewWillMove(toWindow newWindow: NSWindow?) {
        if newWindow == nil {
            _inputTracker?.releaseAll(reason: .viewTeardownOrTerminate)
            scrollQuantizer.reset()
            cleanupBox.teardownAll()
        }
        super.viewWillMove(toWindow: newWindow)
    }

    public override func updateTrackingAreas() {
        super.updateTrackingAreas()
        if let existing = trackingAreaRef {
            removeTrackingArea(existing)
        }
        let area = NSTrackingArea(
            rect: bounds,
            options: [.mouseMoved, .activeInKeyWindow, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
        trackingAreaRef = area
    }

    public func updateSessionBinding(
        inputTracker: PressedInputTracker?,
        isSessionActive: Bool,
        remoteSize: RemoteSize,
        onEmergencyEscape: (() -> Void)?
    ) {
        let wasActive = _isSessionActive
        let oldTracker = _inputTracker

        _inputTracker = inputTracker
        _isSessionActive = isSessionActive
        _remoteSize = remoteSize
        self.onEmergencyEscape = onEmergencyEscape

        if wasActive && !isSessionActive {
            oldTracker?.releaseAll(reason: .sessionLeftConnected)
            inputTracker?.releaseAll(reason: .sessionLeftConnected)
            scrollQuantizer.reset()
            cleanupBox.replaceKeyMonitor(nil)
        } else if !wasActive && isSessionActive {
            installKeyMonitor()
        } else if isSessionActive && oldTracker !== inputTracker {
            oldTracker?.releaseAll(reason: .sessionLeftConnected)
            installKeyMonitor()
        }
    }

    public func teardown() {
        _inputTracker?.releaseAll(reason: .viewTeardownOrTerminate)
        scrollQuantizer.reset()
        cleanupBox.teardownAll()
        _isSessionActive = false
    }

    private func installLifecycleObservers() {
        let nc = NotificationCenter.default
        var next: [NSObjectProtocol] = []

        if let win = window {
            next.append(
                nc.addObserver(
                    forName: NSWindow.didResignKeyNotification,
                    object: win,
                    queue: .main
                ) { [weak self] _ in
                    MainActor.assumeIsolated {
                        self?._inputTracker?.releaseAll(reason: .windowResignedKey)
                        self?.scrollQuantizer.reset()
                    }
                }
            )
        }

        next.append(
            nc.addObserver(
                forName: NSApplication.didResignActiveNotification,
                object: NSApp,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?._inputTracker?.releaseAll(reason: .appResignedActiveOrHidden)
                    self?.scrollQuantizer.reset()
                }
            }
        )

        next.append(
            nc.addObserver(
                forName: NSApplication.didHideNotification,
                object: NSApp,
                queue: .main
            ) { [weak self] _ in
                MainActor.assumeIsolated {
                    self?._inputTracker?.releaseAll(reason: .appResignedActiveOrHidden)
                    self?.scrollQuantizer.reset()
                }
            }
        )

        cleanupBox.replaceObservers(next)
    }

    private func installKeyMonitor() {
        let monitor = NSEvent.addLocalMonitorForEvents(
            matching: [.keyDown, .keyUp, .flagsChanged]
        ) { [weak self] event in
            let consumed = MainActor.assumeIsolated { () -> Bool in
                guard let self else { return false }
                return self.handleMonitoredKeyEvent(event)
            }
            return consumed ? nil : event
        }
        cleanupBox.replaceKeyMonitor(monitor)
    }

    /// Returns `true` when the event was consumed (should be swallowed locally), `false` to pass through.
    private func handleMonitoredKeyEvent(_ event: NSEvent) -> Bool {
        guard _isSessionActive,
              let tracker = _inputTracker,
              let win = window,
              win.isKeyWindow,
              win.firstResponder === self else {
            return false
        }

        let usageId = keyMapper.lookup(event.keyCode)
        let mods = Self.hidModifiers(from: event.modifierFlags)

        switch event.type {
        case .keyDown:
            switch tracker.handleKeyDownEvent(usageId: usageId, modifiers: mods) {
            case .forwarded:
                return true
            case .emergencyEscapeTriggered:
                // Emergency escape combo (Ctrl+Opt+Cmd+Escape) intercepted locally.
                scrollQuantizer.reset()
                onEmergencyEscape?()
                return true
            case .ignored:
                return false
            }

        case .keyUp:
            guard let usageId else { return false }
            tracker.handleKeyUp(usageId: usageId, modifiers: mods)
            return true

        case .flagsChanged:
            guard let usageId else { return false }
            let isDown = Self.isModifierKeyDown(keyCode: event.keyCode, flags: event.modifierFlags)
            tracker.handleFlagsChanged(modifierUsageId: usageId, isPressed: isDown, modifiers: mods)
            return false

        default:
            return false
        }
    }

    private func mappedPoint(for event: NSEvent, isDragging: Bool) -> RemotePoint? {
        guard _isSessionActive, _remoteSize.isValid else {
            return nil
        }
        let localPoint = convert(event.locationInWindow, from: nil)
        return RemoteCoordinateMapper.mapPoint(
            localPoint,
            viewSize: bounds.size,
            remoteSize: _remoteSize,
            origin: .bottomLeft,
            isDragging: isDragging
        )
    }

    public override func mouseMoved(with event: NSEvent) {
        guard let tracker = _inputTracker,
              let pt = mappedPoint(for: event, isDragging: tracker.hasPressedMouseButtons) else {
            return
        }
        tracker.handleMouseMove(x: pt.x, y: pt.y)
    }

    public override func mouseDragged(with event: NSEvent) {
        guard let tracker = _inputTracker,
              let pt = mappedPoint(for: event, isDragging: true) else {
            return
        }
        tracker.handleMouseMove(x: pt.x, y: pt.y)
    }

    public override func rightMouseDragged(with event: NSEvent) {
        mouseDragged(with: event)
    }

    public override func otherMouseDragged(with event: NSEvent) {
        mouseDragged(with: event)
    }

    public override func mouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        guard let tracker = _inputTracker,
              let pt = mappedPoint(for: event, isDragging: false) else {
            return
        }
        tracker.handleMouseDown(button: HidMouseButtonMask.left, x: pt.x, y: pt.y)
    }

    public override func mouseUp(with event: NSEvent) {
        guard _isSessionActive, let tracker = _inputTracker else {
            return
        }
        tracker.handleMouseUp(button: HidMouseButtonMask.left, point: mappedPoint(for: event, isDragging: true))
    }

    public override func rightMouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        guard let tracker = _inputTracker,
              let pt = mappedPoint(for: event, isDragging: false) else {
            return
        }
        tracker.handleMouseDown(button: HidMouseButtonMask.right, x: pt.x, y: pt.y)
    }

    public override func rightMouseUp(with event: NSEvent) {
        guard _isSessionActive, let tracker = _inputTracker else {
            return
        }
        tracker.handleMouseUp(button: HidMouseButtonMask.right, point: mappedPoint(for: event, isDragging: true))
    }

    public override func otherMouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        guard let tracker = _inputTracker,
              let bit = Self.otherMouseButtonMask(event.buttonNumber),
              let pt = mappedPoint(for: event, isDragging: false) else {
            return
        }
        tracker.handleMouseDown(button: bit, x: pt.x, y: pt.y)
    }

    public override func otherMouseUp(with event: NSEvent) {
        guard _isSessionActive,
              let tracker = _inputTracker,
              let bit = Self.otherMouseButtonMask(event.buttonNumber) else {
            return
        }
        tracker.handleMouseUp(button: bit, point: mappedPoint(for: event, isDragging: true))
    }

    public override func scrollWheel(with event: NSEvent) {
        guard let tracker = _inputTracker,
              let pt = mappedPoint(for: event, isDragging: tracker.hasPressedMouseButtons) else {
            return
        }
        if let step = scrollQuantizer.process(
            deltaX: Double(event.scrollingDeltaX),
            deltaY: Double(event.scrollingDeltaY),
            hasPreciseScrollingDeltas: event.hasPreciseScrollingDeltas,
            momentumPhaseRaw: event.momentumPhase.rawValue,
            isDirectionInvertedFromDevice: event.isDirectionInvertedFromDevice,
            phaseRaw: event.phase.rawValue
        ) {
            tracker.handleMouseWheel(
                wheelDx: step.wheelDx,
                wheelDy: step.wheelDy,
                x: pt.x,
                y: pt.y
            )
        }
    }

    private static func otherMouseButtonMask(_ buttonNumber: Int) -> UInt8? {
        switch buttonNumber {
        case 2: return HidMouseButtonMask.middle
        case 3: return HidMouseButtonMask.back
        case 4: return HidMouseButtonMask.forward
        default: return nil
        }
    }

    private static func hidModifiers(from flags: NSEvent.ModifierFlags) -> UInt8 {
        var mask: UInt8 = 0
        if flags.contains(.shift) { mask |= HidModifierMask.shift }
        if flags.contains(.control) { mask |= HidModifierMask.ctrl }
        if flags.contains(.option) { mask |= HidModifierMask.alt }
        if flags.contains(.command) { mask |= HidModifierMask.meta }
        return mask
    }

    private static func isModifierKeyDown(keyCode: UInt16, flags: NSEvent.ModifierFlags) -> Bool {
        let raw = flags.rawValue
        switch keyCode {
        case 0x3B: // kVK_Control (Left)
            return (raw & nxDeviceLControlMask) != 0 || (flags.contains(.control) && (raw & nxDeviceRControlMask) == 0)
        case 0x3E: // kVK_RightControl
            return (raw & nxDeviceRControlMask) != 0
        case 0x38: // kVK_Shift (Left)
            return (raw & nxDeviceLShiftMask) != 0 || (flags.contains(.shift) && (raw & nxDeviceRShiftMask) == 0)
        case 0x3C: // kVK_RightShift
            return (raw & nxDeviceRShiftMask) != 0
        case 0x3A: // kVK_Option (Left)
            return (raw & nxDeviceLAltMask) != 0 || (flags.contains(.option) && (raw & nxDeviceRAltMask) == 0)
        case 0x3D: // kVK_RightOption
            return (raw & nxDeviceRAltMask) != 0
        case 0x37: // kVK_Command (Left)
            return (raw & nxDeviceLCmdMask) != 0 || (flags.contains(.command) && (raw & nxDeviceRCmdMask) == 0)
        case 0x36: // kVK_RightCommand
            return (raw & nxDeviceRCmdMask) != 0
        default:
            return false
        }
    }
}

/// SwiftUI wrapper over `InteractiveMetalNSView` (zero `CGImage` allocation).
public struct RemoteMetalView: NSViewRepresentable {
    public let renderer: MetalVideoRenderer
    public let inputTracker: PressedInputTracker?
    public let isSessionActive: Bool
    public let remoteSize: RemoteSize
    public let onEmergencyEscape: (() -> Void)?

    public init(
        renderer: MetalVideoRenderer,
        inputTracker: PressedInputTracker?,
        isSessionActive: Bool,
        remoteSize: RemoteSize,
        onEmergencyEscape: (() -> Void)? = nil
    ) {
        self.renderer = renderer
        self.inputTracker = inputTracker
        self.isSessionActive = isSessionActive
        self.remoteSize = remoteSize
        self.onEmergencyEscape = onEmergencyEscape
    }

    public func makeNSView(context: Context) -> InteractiveMetalNSView {
        let view = InteractiveMetalNSView(renderer: renderer)
        view.updateSessionBinding(
            inputTracker: inputTracker,
            isSessionActive: isSessionActive,
            remoteSize: remoteSize,
            onEmergencyEscape: onEmergencyEscape
        )
        return view
    }

    public func updateNSView(_ nsView: InteractiveMetalNSView, context: Context) {
        nsView.updateSessionBinding(
            inputTracker: inputTracker,
            isSessionActive: isSessionActive,
            remoteSize: remoteSize,
            onEmergencyEscape: onEmergencyEscape
        )
    }

    public static func dismantleNSView(_ nsView: InteractiveMetalNSView, coordinator: ()) {
        nsView.teardown()
    }
}
