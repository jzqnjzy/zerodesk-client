// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import Foundation
import MetalKit
import SwiftUI
import ZeroDeskBridge

/// Interactive Metal `MTKView` capturing mouse, wheel, and keyboard input through the single
/// unified `InputGate` with full Phase 7B + Phase 8A anti-stuck-key release triggers and
/// 3-mode `ViewportState` (`Fit` / `1:1` / `Fill`) coordinate mapping.
///
/// NOTE: Drag-and-drop file dropzones MUST NEVER be attached to this view (they belong strictly
/// on the Session Control Toolbar / Drawer).
@MainActor
public final class InteractiveMetalNSView: MTKView {
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

    private var _inputGate: InputGate?
    private var _isSessionActive: Bool = false
    private var _remoteSize: RemoteSize = RemoteSize(width: 0, height: 0)
    private var _displayScaleMode: DisplayScaleMode = .fit
    private var _scrollOffset: CGPoint = .zero
    private var onEmergencyEscape: (() -> Void)?
    private var onLocalScrollChanged: ((CGPoint) -> Void)?

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
        _inputGate?.releaseAll(reason: .focusLost)
        scrollQuantizer.reset()
        return ok
    }

    public override func setFrameSize(_ newSize: NSSize) {
        super.setFrameSize(newSize)
        syncViewportState()
    }

    public override func viewDidChangeBackingProperties() {
        super.viewDidChangeBackingProperties()
        syncViewportState()
    }

    public override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        installLifecycleObservers()
        syncViewportState()
        if window != nil && _isSessionActive {
            installKeyMonitor()
        }
    }

    public override func viewWillMove(toWindow newWindow: NSWindow?) {
        if newWindow == nil {
            _inputGate?.releaseAll(reason: .viewTeardownOrTerminate)
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
            options: [.mouseMoved, .mouseEnteredAndExited, .activeInKeyWindow, .inVisibleRect],
            owner: self,
            userInfo: nil
        )
        addTrackingArea(area)
        trackingAreaRef = area
    }

    public override func mouseExited(with event: NSEvent) {
        super.mouseExited(with: event)
        if NSEvent.pressedMouseButtons != 0 {
            _inputGate?.releaseKeysAndModifiersOnly(reason: .mouseExitedView)
        } else {
            _inputGate?.releaseAll(reason: .mouseExitedView)
        }
        scrollQuantizer.reset()
    }

    public func updateSessionBinding(
        inputGate: InputGate?,
        isSessionActive: Bool,
        remoteSize: RemoteSize,
        displayScaleMode: DisplayScaleMode,
        scrollOffset: CGPoint,
        onEmergencyEscape: (() -> Void)?,
        onLocalScrollChanged: ((CGPoint) -> Void)?
    ) {
        let wasActive = _isSessionActive
        let oldGate = _inputGate

        _inputGate = inputGate
        _isSessionActive = isSessionActive
        _remoteSize = remoteSize
        _displayScaleMode = displayScaleMode
        _scrollOffset = scrollOffset
        self.onEmergencyEscape = onEmergencyEscape
        self.onLocalScrollChanged = onLocalScrollChanged

        if wasActive && !isSessionActive {
            oldGate?.releaseAll(reason: .sessionLeftConnected)
            inputGate?.releaseAll(reason: .sessionLeftConnected)
            scrollQuantizer.reset()
            cleanupBox.replaceKeyMonitor(nil)
        } else if !wasActive && isSessionActive {
            installKeyMonitor()
        } else if isSessionActive && oldGate !== inputGate {
            oldGate?.releaseAll(reason: .sessionLeftConnected)
            installKeyMonitor()
        }

        syncViewportState()
    }

    public func teardown() {
        _inputGate?.releaseAll(reason: .viewTeardownOrTerminate)
        scrollQuantizer.reset()
        cleanupBox.teardownAll()
        _isSessionActive = false
    }

    private var unifiedBackingMetrics: (backingSize: CGSize, scale: CGFloat) {
        let fallbackScale = window?.backingScaleFactor ?? NSScreen.main?.backingScaleFactor ?? 1.0
        let safeFallback: CGFloat = (fallbackScale.isFinite && fallbackScale > 0) ? fallbackScale : 1.0
        if drawableSize.width >= 1 && drawableSize.height >= 1 {
            if bounds.size.width > 0 && bounds.size.height > 0 {
                let sx = drawableSize.width / bounds.size.width
                let sy = drawableSize.height / bounds.size.height
                if sx.isFinite && sy.isFinite && sx > 0 && sy > 0 {
                    return (drawableSize, (sx + sy) * 0.5)
                }
            }
            return (drawableSize, safeFallback)
        }
        let backingSize = CGSize(
            width: bounds.size.width * safeFallback,
            height: bounds.size.height * safeFallback
        )
        return (backingSize, safeFallback)
    }

    private var effectiveBackingScale: CGFloat {
        unifiedBackingMetrics.scale
    }

    private func computeCurrentViewport() -> ViewportState {
        let metrics = unifiedBackingMetrics
        return ViewportState(
            mode: _displayScaleMode,
            viewBackingSize: metrics.backingSize,
            frameSize: _remoteSize.cgSize,
            scrollOffset: _scrollOffset
        )
    }

    private func syncViewportState() {
        let vp = computeCurrentViewport()
        // Always release held inputs BEFORE recomputing viewport geometry!
        _inputGate?.updateViewport(vp)
        videoRenderer.updateViewport(mode: vp.mode, scrollOffset: vp.scrollOffset)
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
                        self?._inputGate?.releaseAll(reason: .windowResignedKey)
                        self?.scrollQuantizer.reset()
                    }
                }
            )
            next.append(
                nc.addObserver(
                    forName: NSWindow.didResignMainNotification,
                    object: win,
                    queue: .main
                ) { [weak self] _ in
                    MainActor.assumeIsolated {
                        self?._inputGate?.releaseAll(reason: .windowResignedKey)
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
                    self?._inputGate?.releaseAll(reason: .appResignedActiveOrHidden)
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
                    self?._inputGate?.releaseAll(reason: .appResignedActiveOrHidden)
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

    private func handleMonitoredKeyEvent(_ event: NSEvent) -> Bool {
        guard _isSessionActive,
              let gate = _inputGate,
              let win = window,
              win.isKeyWindow,
              win.firstResponder === self else {
            return false
        }

        let usageId = keyMapper.lookup(event.keyCode)
        let mods = Self.hidModifiers(from: event.modifierFlags)

        switch event.type {
        case .keyDown:
            switch gate.handleKeyDown(usageId: usageId, modifiers: mods, isARepeat: event.isARepeat) {
            case .forwarded:
                return true
            case .emergencyEscapeTriggered:
                scrollQuantizer.reset()
                onEmergencyEscape?()
                return true
            case .ignored:
                return false
            }

        case .keyUp:
            guard let usageId else { return false }
            guard gate.isInputEnabled || gate.hasAnyPressedInput else { return false }
            gate.handleKeyUp(usageId: usageId, modifiers: mods)
            return true

        case .flagsChanged:
            guard let usageId else { return false }
            let isDown = Self.isModifierKeyDown(keyCode: event.keyCode, flags: event.modifierFlags)
            gate.handleFlagsChanged(modifierUsageId: usageId, isPressed: isDown, modifiers: mods)
            return false

        default:
            return false
        }
    }

    public override func mouseMoved(with event: NSEvent) {
        guard _isSessionActive, let gate = _inputGate else { return }
        let localPoint = convert(event.locationInWindow, from: nil)
        gate.handleMouseMove(viewPoint: localPoint, backingScale: effectiveBackingScale, origin: .bottomLeft)
    }

    public override func mouseDragged(with event: NSEvent) {
        guard _isSessionActive, let gate = _inputGate else { return }
        let localPoint = convert(event.locationInWindow, from: nil)
        gate.handleMouseMove(viewPoint: localPoint, backingScale: effectiveBackingScale, origin: .bottomLeft)
    }

    public override func rightMouseDragged(with event: NSEvent) {
        mouseDragged(with: event)
    }

    public override func otherMouseDragged(with event: NSEvent) {
        mouseDragged(with: event)
    }

    public override func mouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        guard _isSessionActive, let gate = _inputGate else { return }
        let localPoint = convert(event.locationInWindow, from: nil)
        gate.handleMouseDown(
            button: HidMouseButtonMask.left,
            viewPoint: localPoint,
            backingScale: effectiveBackingScale,
            origin: .bottomLeft
        )
    }

    public override func mouseUp(with event: NSEvent) {
        guard _isSessionActive, let gate = _inputGate else { return }
        let localPoint = convert(event.locationInWindow, from: nil)
        gate.handleMouseUp(
            button: HidMouseButtonMask.left,
            viewPoint: localPoint,
            backingScale: effectiveBackingScale,
            origin: .bottomLeft
        )
    }

    public override func rightMouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        guard _isSessionActive, let gate = _inputGate else { return }
        let localPoint = convert(event.locationInWindow, from: nil)
        gate.handleMouseDown(
            button: HidMouseButtonMask.right,
            viewPoint: localPoint,
            backingScale: effectiveBackingScale,
            origin: .bottomLeft
        )
    }

    public override func rightMouseUp(with event: NSEvent) {
        guard _isSessionActive, let gate = _inputGate else { return }
        let localPoint = convert(event.locationInWindow, from: nil)
        gate.handleMouseUp(
            button: HidMouseButtonMask.right,
            viewPoint: localPoint,
            backingScale: effectiveBackingScale,
            origin: .bottomLeft
        )
    }

    public override func otherMouseDown(with event: NSEvent) {
        window?.makeFirstResponder(self)
        guard _isSessionActive,
              let gate = _inputGate,
              let bit = Self.otherMouseButtonMask(event.buttonNumber) else {
            return
        }
        let localPoint = convert(event.locationInWindow, from: nil)
        gate.handleMouseDown(
            button: bit,
            viewPoint: localPoint,
            backingScale: effectiveBackingScale,
            origin: .bottomLeft
        )
    }

    public override func otherMouseUp(with event: NSEvent) {
        guard _isSessionActive,
              let gate = _inputGate,
              let bit = Self.otherMouseButtonMask(event.buttonNumber) else {
            return
        }
        let localPoint = convert(event.locationInWindow, from: nil)
        gate.handleMouseUp(
            button: bit,
            viewPoint: localPoint,
            backingScale: effectiveBackingScale,
            origin: .bottomLeft
        )
    }

    public override func scrollWheel(with event: NSEvent) {
        guard _isSessionActive, let gate = _inputGate else { return }

        // In 1:1 mode when frame exceeds view backing size:
        // - Default scroll pans the local viewport (`scrollOffset`);
        // - Cmd + scroll forwards scroll events to the remote host!
        let vp = computeCurrentViewport()
        if let geo = RemoteCoordinateMapper.computeGeometry(for: vp),
           geo.canScrollLocally,
           !event.modifierFlags.contains(.command)
        {
            let scale = Double(effectiveBackingScale)
            let dx = Double(event.scrollingDeltaX) * (event.hasPreciseScrollingDeltas ? scale : 18.0 * scale)
            let dy = Double(event.scrollingDeltaY) * (event.hasPreciseScrollingDeltas ? scale : 18.0 * scale)
            let nextX = min(max((Double(_scrollOffset.x) - dx).rounded(), 0.0), geo.maxScrollX)
            let nextY = min(max((Double(_scrollOffset.y) - dy).rounded(), 0.0), geo.maxScrollY)
            let nextOffset = CGPoint(x: nextX, y: nextY)
            if nextOffset != _scrollOffset {
                gate.releaseAll(reason: .viewportChanged)
                _scrollOffset = nextOffset
                syncViewportState()
                onLocalScrollChanged?(nextOffset)
            }
            return
        }

        let localPoint = convert(event.locationInWindow, from: nil)
        if let step = scrollQuantizer.process(
            deltaX: Double(event.scrollingDeltaX),
            deltaY: Double(event.scrollingDeltaY),
            hasPreciseScrollingDeltas: event.hasPreciseScrollingDeltas,
            momentumPhaseRaw: event.momentumPhase.rawValue,
            isDirectionInvertedFromDevice: event.isDirectionInvertedFromDevice,
            phaseRaw: event.phase.rawValue
        ) {
            gate.handleMouseWheel(
                wheelDx: step.wheelDx,
                wheelDy: step.wheelDy,
                viewPoint: localPoint,
                backingScale: effectiveBackingScale,
                origin: .bottomLeft
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
        case 0x3B:
            return (raw & nxDeviceLControlMask) != 0 || (flags.contains(.control) && (raw & nxDeviceRControlMask) == 0)
        case 0x3E:
            return (raw & nxDeviceRControlMask) != 0
        case 0x38:
            return (raw & nxDeviceLShiftMask) != 0 || (flags.contains(.shift) && (raw & nxDeviceRShiftMask) == 0)
        case 0x3C:
            return (raw & nxDeviceRShiftMask) != 0
        case 0x3A:
            return (raw & nxDeviceLAltMask) != 0 || (flags.contains(.option) && (raw & nxDeviceRAltMask) == 0)
        case 0x3D:
            return (raw & nxDeviceRAltMask) != 0
        case 0x37:
            return (raw & nxDeviceLCmdMask) != 0 || (flags.contains(.command) && (raw & nxDeviceRCmdMask) == 0)
        case 0x36:
            return (raw & nxDeviceRCmdMask) != 0
        default:
            return false
        }
    }
}

/// SwiftUI wrapper over `InteractiveMetalNSView` (zero `CGImage` allocation, zero file dropzone).
public struct RemoteMetalView: NSViewRepresentable {
    public let renderer: MetalVideoRenderer
    public let inputGate: InputGate?
    public let isSessionActive: Bool
    public let remoteSize: RemoteSize
    public let displayScaleMode: DisplayScaleMode
    public let scrollOffset: CGPoint
    public let onEmergencyEscape: (() -> Void)?
    public let onLocalScrollChanged: ((CGPoint) -> Void)?

    public init(
        renderer: MetalVideoRenderer,
        inputGate: InputGate?,
        isSessionActive: Bool,
        remoteSize: RemoteSize,
        displayScaleMode: DisplayScaleMode = .fit,
        scrollOffset: CGPoint = .zero,
        onEmergencyEscape: (() -> Void)? = nil,
        onLocalScrollChanged: ((CGPoint) -> Void)? = nil
    ) {
        self.renderer = renderer
        self.inputGate = inputGate
        self.isSessionActive = isSessionActive
        self.remoteSize = remoteSize
        self.displayScaleMode = displayScaleMode
        self.scrollOffset = scrollOffset
        self.onEmergencyEscape = onEmergencyEscape
        self.onLocalScrollChanged = onLocalScrollChanged
    }

    public func makeNSView(context: Context) -> InteractiveMetalNSView {
        let view = InteractiveMetalNSView(renderer: renderer)
        view.updateSessionBinding(
            inputGate: inputGate,
            isSessionActive: isSessionActive,
            remoteSize: remoteSize,
            displayScaleMode: displayScaleMode,
            scrollOffset: scrollOffset,
            onEmergencyEscape: onEmergencyEscape,
            onLocalScrollChanged: onLocalScrollChanged
        )
        return view
    }

    public func updateNSView(_ nsView: InteractiveMetalNSView, context: Context) {
        nsView.updateSessionBinding(
            inputGate: inputGate,
            isSessionActive: isSessionActive,
            remoteSize: remoteSize,
            displayScaleMode: displayScaleMode,
            scrollOffset: scrollOffset,
            onEmergencyEscape: onEmergencyEscape,
            onLocalScrollChanged: onLocalScrollChanged
        )
    }

    public static func dismantleNSView(_ nsView: InteractiveMetalNSView, coordinator: ()) {
        nsView.teardown()
    }
}
