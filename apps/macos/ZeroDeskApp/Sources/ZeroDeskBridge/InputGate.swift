// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import CoreGraphics
import Foundation

/// Injectable OS input state reader used by `InputGate`'s 200ms reconciliation loop.
/// Backed in production by `CGEventSource.keyState`, `NSEvent.modifierFlags`, and
/// `NSEvent.pressedMouseButtons`, and mockable in unit tests.
public protocol OsInputStateProvider: Sendable {
    func isKeyPressed(macKeyCode: UInt16) -> Bool
    func currentModifierMask() -> UInt8
    func currentPressedMouseButtons() -> UInt8
}

/// Production macOS live OS input state provider.
public struct MacOsInputStateProvider: OsInputStateProvider {
    public init() {}

    public func isKeyPressed(macKeyCode: UInt16) -> Bool {
        CGEventSource.keyState(.combinedSessionState, key: CGKeyCode(macKeyCode))
    }

    public func currentModifierMask() -> UInt8 {
        let flags = NSEvent.modifierFlags
        var mask: UInt8 = 0
        if flags.contains(.shift) { mask |= HidModifierMask.shift }
        if flags.contains(.control) { mask |= HidModifierMask.ctrl }
        if flags.contains(.option) { mask |= HidModifierMask.alt }
        if flags.contains(.command) { mask |= HidModifierMask.meta }
        return mask
    }

    public func currentPressedMouseButtons() -> UInt8 {
        let raw = NSEvent.pressedMouseButtons
        return UInt8(truncatingIfNeeded: raw) & HidMouseButtonMask.validMask
    }
}

/// Snapshot of the 3 explicit pressed sets tracked by `InputGate`.
public struct InputGatePressedSnapshot: Sendable, Equatable {
    public let pressedKeys: Set<UInt16>
    public let pressedModifiers: Set<UInt16>
    public let pressedMouseButtons: Set<UInt8>

    public init(
        pressedKeys: Set<UInt16>,
        pressedModifiers: Set<UInt16>,
        pressedMouseButtons: Set<UInt8>
    ) {
        self.pressedKeys = pressedKeys
        self.pressedModifiers = pressedModifiers
        self.pressedMouseButtons = pressedMouseButtons
    }

    public var isEmpty: Bool {
        pressedKeys.isEmpty && pressedModifiers.isEmpty && pressedMouseButtons.isEmpty
    }
}

/// Single unified Swift `InputGate` routing ALL keyboard (`keyDown`/`keyUp`/`flagsChanged`) and
/// mouse (`down`/`up`/`move`/`wheel`) events with:
/// - 3 explicit pressed sets (`pressedKeys`, `pressedModifiers`, `pressedMouseButtons`)
/// - Secondary per-session `isInputEnabled` gate (default OFF, updated ONLY from Rust ack)
/// - Press-to-release captured `ViewportState` snapshot
/// - Mandatory `releaseAll(reason:)` BEFORE any viewport change or UI overlay open
/// - 200ms OS state reconciliation synthesizing `up` for any OS-released key/modifier/button
public final class InputGate: @unchecked Sendable {
    public static let defaultReconciliationIntervalMs: Int = 200
    public static let maxReleaseTimeoutMs: UInt32 = 200
    public static let defaultReleaseTimeoutMs: UInt32 = 150

    private let lock = NSLock()
    private let sink: any RemoteInputSink
    private let osStateProvider: any OsInputStateProvider
    private let releaseTimeoutMs: UInt32
    private let reconciliationIntervalMs: Int
    private let reconcileQueue = DispatchQueue(label: "io.zerodesk.desktop.inputgate.reconcile")

    private var pressedKeys: Set<UInt16> = []
    private var pressedModifiers: Set<UInt16> = []
    private var pressedMouseButtons: Set<UInt8> = []
    private var isInputEnabledFlag: Bool = false
    private var currentViewport: ViewportState?
    private var activeGestureViewport: ViewportState?
    private var lastValidRemotePoint: RemotePoint = RemotePoint(x: 0, y: 0)
    private var reconcileTimer: DispatchSourceTimer?
    private var isStopped: Bool = false

    public init(
        sink: any RemoteInputSink,
        osStateProvider: any OsInputStateProvider = MacOsInputStateProvider(),
        initialInputEnabled: Bool = false,
        releaseTimeoutMs: UInt32 = InputGate.defaultReleaseTimeoutMs,
        reconciliationIntervalMs: Int = InputGate.defaultReconciliationIntervalMs
    ) {
        self.sink = sink
        self.osStateProvider = osStateProvider
        self.isInputEnabledFlag = initialInputEnabled
        self.releaseTimeoutMs = min(max(releaseTimeoutMs, 1), Self.maxReleaseTimeoutMs)
        self.reconciliationIntervalMs = max(10, reconciliationIntervalMs)
    }

    deinit {
        stop()
    }

    /// Cancels any active 200ms reconciliation timer cleanly.
    public func stop() {
        lock.lock()
        isStopped = true
        let timer = reconcileTimer
        reconcileTimer = nil
        lock.unlock()
        timer?.cancel()
    }

    public var isInputEnabled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isInputEnabledFlag
    }

    /// Updates input enablement strictly from Rust-acknowledged state.
    /// Transitioning to `false` immediately triggers `releaseAll(reason: .inputDisabled)`.
    public func setInputEnabledFromAck(_ enabled: Bool) {
        lock.lock()
        let wasEnabled = isInputEnabledFlag
        isInputEnabledFlag = enabled
        lock.unlock()

        if wasEnabled && !enabled {
            releaseAll(reason: .inputDisabled)
        }
    }

    public var hasAnyPressedInput: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !pressedKeys.isEmpty || !pressedModifiers.isEmpty || !pressedMouseButtons.isEmpty
    }

    public var hasPressedMouseButtons: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !pressedMouseButtons.isEmpty
    }

    public func pressedSnapshot() -> InputGatePressedSnapshot {
        lock.lock()
        defer { lock.unlock() }
        return InputGatePressedSnapshot(
            pressedKeys: pressedKeys,
            pressedModifiers: pressedModifiers,
            pressedMouseButtons: pressedMouseButtons
        )
    }

    public var viewport: ViewportState? {
        lock.lock()
        defer { lock.unlock() }
        return currentViewport
    }

    /// Updates the active `ViewportState`. If the viewport changed (mode switch, window resize,
    /// remote frame resolution change, or scroll offset change), triggers `releaseAll(.viewportChanged)`
    /// BEFORE installing the new viewport so press-to-release gestures never straddle geometry changes.
    public func updateViewport(_ next: ViewportState?) {
        lock.lock()
        let changed = currentViewport != next
        lock.unlock()

        if changed {
            releaseAll(reason: .viewportChanged)
            lock.lock()
            currentViewport = next
            activeGestureViewport = nil
            lock.unlock()
        }
    }

    /// Convenience trigger for opening any toolbar popover, side drawer, sheet, or `NSOpenPanel`.
    @discardableResult
    public func notifyOverlayOpened() -> ReleaseAllSnapshot? {
        releaseAll(reason: .uiOverlayOpened)
    }

    // MARK: - Keyboard Routing (`keyDown` / `keyUp` / `flagsChanged`)

    @discardableResult
    public func handleKeyDown(usageId: UInt16?, modifiers: UInt8) -> KeyDownOutcome {
        guard let usageId, MacHidKeyMap.isWhitelistedUsageId(usageId) else {
            return .ignored
        }
        let maskedMods = modifiers & HidModifierMask.validMask

        // Emergency escape (`Ctrl+Opt+Cmd+Escape`) is ALWAYS intercepted locally and NEVER forwarded!
        if MacHidKeyMap.isEmergencyEscapeCombo(usageId: usageId, modifiers: maskedMods) {
            lock.lock()
            isInputEnabledFlag = false
            lock.unlock()
            releaseAll(reason: .emergencyEscapeHotkey, forceEmit: true)
            return .emergencyEscapeTriggered
        }

        let effectiveMods: UInt8
        lock.lock()
        guard isInputEnabledFlag else {
            lock.unlock()
            return .ignored
        }
        if let modBit = MacHidKeyMap.modifierBit(forUsageId: usageId) {
            pressedModifiers.insert(usageId)
            effectiveMods = (maskedMods | derivedModifierMaskLocked() | modBit) & HidModifierMask.validMask
        } else {
            pressedKeys.insert(usageId)
            effectiveMods = (maskedMods | derivedModifierMaskLocked()) & HidModifierMask.validMask
        }
        ensureReconcileTimerLocked()
        lock.unlock()

        sink.sendKeyEvent(usageId: usageId, down: true, modifiers: effectiveMods)
        return .forwarded
    }

    public func handleKeyUp(usageId: UInt16, modifiers: UInt8) {
        let maskedMods = modifiers & HidModifierMask.validMask
        let effectiveMods: UInt8
        let shouldSend: Bool

        lock.lock()
        let wasTracked: Bool
        if let modBit = MacHidKeyMap.modifierBit(forUsageId: usageId) {
            wasTracked = pressedModifiers.remove(usageId) != nil
            let derived = derivedModifierMaskLocked()
            let kept = (derived & modBit) != 0 ? modBit : 0
            effectiveMods = ((maskedMods & ~modBit) | derived | kept) & HidModifierMask.validMask
        } else {
            wasTracked = pressedKeys.remove(usageId) != nil
            effectiveMods = (maskedMods | derivedModifierMaskLocked()) & HidModifierMask.validMask
        }
        shouldSend = isInputEnabledFlag || wasTracked
        let timerToStop = stopReconcileTimerIfIdleLocked()
        lock.unlock()

        timerToStop?.cancel()
        if shouldSend {
            sink.sendKeyEvent(usageId: usageId, down: false, modifiers: effectiveMods)
        }
    }

    /// Explicitly handles macOS `flagsChanged` for distinct Left/Right modifiers (`0xE0..=0xE7`).
    public func handleFlagsChanged(modifierUsageId: UInt16, isPressed: Bool, modifiers: UInt8) {
        guard MacHidKeyMap.modifierBit(forUsageId: modifierUsageId) != nil else {
            return
        }
        lock.lock()
        let wasPressed = pressedModifiers.contains(modifierUsageId)
        let enabled = isInputEnabledFlag
        lock.unlock()

        if isPressed {
            if enabled && !wasPressed {
                _ = handleKeyDown(usageId: modifierUsageId, modifiers: modifiers)
            }
        } else if wasPressed {
            handleKeyUp(usageId: modifierUsageId, modifiers: modifiers)
        }
    }

    // MARK: - Mouse Routing (Captured Press-to-Release `ViewportState`)

    @discardableResult
    public func handleMouseDown(
        button: UInt8,
        viewPoint: CGPoint,
        backingScale: CGFloat,
        origin: CoordinateOrigin = .bottomLeft
    ) -> RemotePoint? {
        let bit = button & HidMouseButtonMask.validMask
        guard bit != 0 else { return nil }

        lock.lock()
        guard isInputEnabledFlag, let vp = currentViewport else {
            lock.unlock()
            return nil
        }
        let gestureViewport = activeGestureViewport ?? vp
        lock.unlock()

        // Fit letterbox/pillarbox regions return `nil` — NEVER dispatch or clamp!
        guard let remotePt = RemoteCoordinateMapper.mapViewPoint(
            viewPoint,
            backingScale: backingScale,
            in: gestureViewport,
            origin: origin
        ) else {
            return nil
        }

        lock.lock()
        guard isInputEnabledFlag else {
            lock.unlock()
            return nil
        }
        if activeGestureViewport == nil {
            activeGestureViewport = gestureViewport
        }
        pressedMouseButtons.insert(bit)
        lastValidRemotePoint = remotePt
        let combinedButtons = combinedMouseButtonMaskLocked()
        ensureReconcileTimerLocked()
        lock.unlock()

        sink.sendMouseEvent(
            kind: .buttonDown,
            x: remotePt.x,
            y: remotePt.y,
            buttons: combinedButtons,
            wheelDx: 0,
            wheelDy: 0
        )
        return remotePt
    }

    @discardableResult
    public func handleMouseMove(
        viewPoint: CGPoint,
        backingScale: CGFloat,
        origin: CoordinateOrigin = .bottomLeft
    ) -> RemotePoint? {
        lock.lock()
        guard isInputEnabledFlag else {
            lock.unlock()
            return nil
        }
        let vp = activeGestureViewport ?? currentViewport
        lock.unlock()

        guard let vp,
              let remotePt = RemoteCoordinateMapper.mapViewPoint(
                  viewPoint,
                  backingScale: backingScale,
                  in: vp,
                  origin: origin
              ) else {
            return nil
        }

        lock.lock()
        lastValidRemotePoint = remotePt
        let combinedButtons = combinedMouseButtonMaskLocked()
        lock.unlock()

        sink.sendMouseEvent(
            kind: .moveAbs,
            x: remotePt.x,
            y: remotePt.y,
            buttons: combinedButtons,
            wheelDx: 0,
            wheelDy: 0
        )
        return remotePt
    }

    @discardableResult
    public func handleMouseUp(
        button: UInt8,
        viewPoint: CGPoint,
        backingScale: CGFloat,
        origin: CoordinateOrigin = .bottomLeft
    ) -> RemotePoint? {
        let bit = button & HidMouseButtonMask.validMask
        guard bit != 0 else { return nil }

        lock.lock()
        let wasPressed = pressedMouseButtons.contains(bit)
        let enabled = isInputEnabledFlag
        let vp = activeGestureViewport ?? currentViewport
        let fallbackPt = lastValidRemotePoint
        lock.unlock()

        guard wasPressed || enabled else {
            return nil
        }

        let mappedPt: RemotePoint?
        if let vp {
            mappedPt = RemoteCoordinateMapper.mapViewPoint(
                viewPoint,
                backingScale: backingScale,
                in: vp,
                origin: origin
            )
        } else {
            mappedPt = nil
        }
        let targetPt = mappedPt ?? fallbackPt

        lock.lock()
        pressedMouseButtons.remove(bit)
        if let mappedPt {
            lastValidRemotePoint = mappedPt
        }
        if pressedMouseButtons.isEmpty {
            activeGestureViewport = nil
        }
        let remainingButtons = combinedMouseButtonMaskLocked()
        let timerToStop = stopReconcileTimerIfIdleLocked()
        lock.unlock()

        timerToStop?.cancel()
        sink.sendMouseEvent(
            kind: .buttonUp,
            x: targetPt.x,
            y: targetPt.y,
            buttons: remainingButtons,
            wheelDx: 0,
            wheelDy: 0
        )
        return targetPt
    }

    @discardableResult
    public func handleMouseWheel(
        wheelDx: Int16,
        wheelDy: Int16,
        viewPoint: CGPoint,
        backingScale: CGFloat,
        origin: CoordinateOrigin = .bottomLeft
    ) -> RemotePoint? {
        guard wheelDx != 0 || wheelDy != 0 else { return nil }
        lock.lock()
        guard isInputEnabledFlag, let vp = activeGestureViewport ?? currentViewport else {
            lock.unlock()
            return nil
        }
        let combinedButtons = combinedMouseButtonMaskLocked()
        lock.unlock()

        guard let remotePt = RemoteCoordinateMapper.mapViewPoint(
            viewPoint,
            backingScale: backingScale,
            in: vp,
            origin: origin
        ) else {
            return nil
        }

        sink.sendMouseEvent(
            kind: .wheel,
            x: remotePt.x,
            y: remotePt.y,
            buttons: combinedButtons,
            wheelDx: wheelDx,
            wheelDy: wheelDy
        )
        return remotePt
    }

    // MARK: - Unified `releaseAll(reason:)`

    /// Atomically clears ALL 3 pressed sets (`pressedKeys`, `pressedModifiers`, `pressedMouseButtons`),
    /// cancels the reconciliation timer, and emits ONE bounded `release_all` command through the sink.
    @discardableResult
    public func releaseAll(reason: ReleaseReason, forceEmit: Bool = false) -> ReleaseAllSnapshot? {
        let keysToRelease: [UInt16]
        let combinedButtons: UInt8
        let snapshot: ReleaseAllSnapshot
        let timerToStop: DispatchSourceTimer?

        lock.lock()
        let empty = pressedKeys.isEmpty && pressedModifiers.isEmpty && pressedMouseButtons.isEmpty
        if empty && !forceEmit {
            activeGestureViewport = nil
            lock.unlock()
            return nil
        }

        let allKeys = pressedKeys.union(pressedModifiers)
        let modMask = derivedModifierMaskLocked()
        combinedButtons = combinedMouseButtonMaskLocked()
        keysToRelease = allKeys.sorted()
        snapshot = ReleaseAllSnapshot(
            reason: reason,
            keys: allKeys,
            modifiers: modMask,
            mouseButtons: combinedButtons
        )
        pressedKeys.removeAll(keepingCapacity: true)
        pressedModifiers.removeAll(keepingCapacity: true)
        pressedMouseButtons.removeAll(keepingCapacity: true)
        activeGestureViewport = nil
        timerToStop = reconcileTimer
        reconcileTimer = nil
        lock.unlock()

        timerToStop?.cancel()
        sink.flushReleaseAll(
            keys: keysToRelease,
            buttons: combinedButtons,
            reason: reason,
            timeoutMs: releaseTimeoutMs
        )
        return snapshot
    }

    // MARK: - 200ms OS State Reconciliation

    /// Compares all 3 pressed sets against live OS state (`osStateProvider`) and immediately
    /// synthesizes & emits `up` events for any key, modifier, or mouse button that was released
    /// at the OS level while still marked pressed in `InputGate`.
    @discardableResult
    public func reconcileWithOsState() -> (releasedKeys: [UInt16], releasedModifiers: [UInt16], releasedMouseButtons: [UInt8]) {
        lock.lock()
        let trackedKeys = pressedKeys
        let trackedMods = pressedModifiers
        let trackedButtons = pressedMouseButtons
        let lastPt = lastValidRemotePoint
        lock.unlock()

        if trackedKeys.isEmpty && trackedMods.isEmpty && trackedButtons.isEmpty {
            return ([], [], [])
        }

        let liveModMask = osStateProvider.currentModifierMask()
        let liveMouseMask = osStateProvider.currentPressedMouseButtons()

        var staleKeys: [UInt16] = []
        for usage in trackedKeys.sorted() {
            if let macCode = MacHidKeyMap.macKeyCode(forHidUsage: usage) {
                if !osStateProvider.isKeyPressed(macKeyCode: macCode) {
                    staleKeys.append(usage)
                }
            }
        }

        var staleMods: [UInt16] = []
        for modUsage in trackedMods.sorted() {
            let bitDown = MacHidKeyMap.modifierBit(forUsageId: modUsage).map { (liveModMask & $0) != 0 } ?? false
            let keyDown = MacHidKeyMap.macKeyCode(forHidUsage: modUsage).map { osStateProvider.isKeyPressed(macKeyCode: $0) } ?? bitDown
            if !bitDown || !keyDown {
                staleMods.append(modUsage)
            }
        }

        var staleButtons: [UInt8] = []
        for btn in trackedButtons.sorted() {
            if (liveMouseMask & btn) == 0 {
                staleButtons.append(btn)
            }
        }

        if staleKeys.isEmpty && staleMods.isEmpty && staleButtons.isEmpty {
            return ([], [], [])
        }

        var syntheticKeyUps: [(UInt16, UInt8)] = []
        var syntheticMouseUps: [UInt8] = []
        let timerToStop: DispatchSourceTimer?

        lock.lock()
        for usage in staleKeys where pressedKeys.remove(usage) != nil {
            syntheticKeyUps.append((usage, derivedModifierMaskLocked()))
        }
        for modUsage in staleMods where pressedModifiers.remove(modUsage) != nil {
            syntheticKeyUps.append((modUsage, derivedModifierMaskLocked()))
        }
        for btn in staleButtons where pressedMouseButtons.remove(btn) != nil {
            syntheticMouseUps.append(combinedMouseButtonMaskLocked())
        }
        if pressedMouseButtons.isEmpty {
            activeGestureViewport = nil
        }
        timerToStop = stopReconcileTimerIfIdleLocked()
        lock.unlock()

        timerToStop?.cancel()

        for (usage, mods) in syntheticKeyUps {
            sink.sendKeyEvent(usageId: usage, down: false, modifiers: mods)
        }
        for remainingMask in syntheticMouseUps {
            sink.sendMouseEvent(
                kind: .buttonUp,
                x: lastPt.x,
                y: lastPt.y,
                buttons: remainingMask,
                wheelDx: 0,
                wheelDy: 0
            )
        }

        return (staleKeys, staleMods, staleButtons)
    }

    // MARK: - Private Locked Helpers

    private func derivedModifierMaskLocked() -> UInt8 {
        var mask: UInt8 = 0
        for usage in pressedModifiers {
            if let bit = MacHidKeyMap.modifierBit(forUsageId: usage) {
                mask |= bit
            }
        }
        return mask
    }

    private func combinedMouseButtonMaskLocked() -> UInt8 {
        var mask: UInt8 = 0
        for b in pressedMouseButtons {
            mask |= (b & HidMouseButtonMask.validMask)
        }
        return mask
    }

    private func ensureReconcileTimerLocked() {
        guard !isStopped, reconcileTimer == nil else { return }
        let timer = DispatchSource.makeTimerSource(queue: reconcileQueue)
        let interval = DispatchTimeInterval.milliseconds(reconciliationIntervalMs)
        timer.schedule(deadline: .now() + interval, repeating: interval)
        timer.setEventHandler { [weak self] in
            _ = self?.reconcileWithOsState()
        }
        reconcileTimer = timer
        timer.resume()
    }

    private func stopReconcileTimerIfIdleLocked() -> DispatchSourceTimer? {
        guard pressedKeys.isEmpty && pressedModifiers.isEmpty && pressedMouseButtons.isEmpty else {
            return nil
        }
        let t = reconcileTimer
        reconcileTimer = nil
        return t
    }
}
