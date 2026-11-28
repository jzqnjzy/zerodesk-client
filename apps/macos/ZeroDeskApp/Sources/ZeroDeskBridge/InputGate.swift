// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import CoreGraphics
import Foundation

/// Injectable OS input state reader used by `InputGate`'s 200ms reconciliation loop.
/// Backed in production by thread-safe CoreGraphics `CGEventSource` queries
/// (`keyState`, `flagsState`, `buttonState`) and mockable in unit tests.
public protocol OsInputStateProvider: Sendable {
    func isKeyPressed(macKeyCode: UInt16) -> Bool
    func currentModifierMask() -> UInt8
    func currentPressedMouseButtons() -> UInt8
    func isModifierPressed(hidUsageId: UInt16) -> Bool
}

public extension OsInputStateProvider {
    func isModifierPressed(hidUsageId: UInt16) -> Bool {
        let bitDown = MacHidKeyMap.modifierBit(forUsageId: hidUsageId)
            .map { (currentModifierMask() & $0) != 0 } ?? false
        let keyDown = MacHidKeyMap.macKeyCode(forHidUsage: hidUsageId)
            .map { isKeyPressed(macKeyCode: $0) } ?? bitDown
        return bitDown && keyDown
    }
}

/// Production macOS live OS input state provider using exclusively thread-safe `CGEventSource`
/// APIs (never touching main-thread-only `NSEvent` state from the reconciliation background queue).
public struct MacOsInputStateProvider: OsInputStateProvider {
    // NX device-dependent modifier masks from <IOKit/hidsystem/IOLLEvent.h>
    private static let nxDeviceLCtlMask: UInt64 = 0x0000_0001
    private static let nxDeviceLShiftMask: UInt64 = 0x0000_0002
    private static let nxDeviceRShiftMask: UInt64 = 0x0000_0004
    private static let nxDeviceLCmdMask: UInt64 = 0x0000_0008
    private static let nxDeviceRCmdMask: UInt64 = 0x0000_0010
    private static let nxDeviceLAltMask: UInt64 = 0x0000_0020
    private static let nxDeviceRAltMask: UInt64 = 0x0000_0040
    private static let nxDeviceRCtlMask: UInt64 = 0x0000_2000

    public init() {}

    public func isKeyPressed(macKeyCode: UInt16) -> Bool {
        CGEventSource.keyState(.hidSystemState, key: CGKeyCode(macKeyCode))
    }

    public func currentModifierMask() -> UInt8 {
        let flags = CGEventSource.flagsState(.hidSystemState)
        var mask: UInt8 = 0
        if flags.contains(.maskShift) { mask |= HidModifierMask.shift }
        if flags.contains(.maskControl) { mask |= HidModifierMask.ctrl }
        if flags.contains(.maskAlternate) { mask |= HidModifierMask.alt }
        if flags.contains(.maskCommand) { mask |= HidModifierMask.meta }
        return mask
    }

    public func isModifierPressed(hidUsageId: UInt16) -> Bool {
        let flags = CGEventSource.flagsState(.hidSystemState)
        let raw = flags.rawValue
        let deviceMask: UInt64
        let oppositeDeviceMask: UInt64
        let genericFlag: CGEventFlags
        switch hidUsageId {
        case 0xE0:
            deviceMask = Self.nxDeviceLCtlMask
            oppositeDeviceMask = Self.nxDeviceRCtlMask
            genericFlag = .maskControl
        case 0xE1:
            deviceMask = Self.nxDeviceLShiftMask
            oppositeDeviceMask = Self.nxDeviceRShiftMask
            genericFlag = .maskShift
        case 0xE2:
            deviceMask = Self.nxDeviceLAltMask
            oppositeDeviceMask = Self.nxDeviceRAltMask
            genericFlag = .maskAlternate
        case 0xE3:
            deviceMask = Self.nxDeviceLCmdMask
            oppositeDeviceMask = Self.nxDeviceRCmdMask
            genericFlag = .maskCommand
        case 0xE4:
            deviceMask = Self.nxDeviceRCtlMask
            oppositeDeviceMask = Self.nxDeviceLCtlMask
            genericFlag = .maskControl
        case 0xE5:
            deviceMask = Self.nxDeviceRShiftMask
            oppositeDeviceMask = Self.nxDeviceLShiftMask
            genericFlag = .maskShift
        case 0xE6:
            deviceMask = Self.nxDeviceRAltMask
            oppositeDeviceMask = Self.nxDeviceLAltMask
            genericFlag = .maskAlternate
        case 0xE7:
            deviceMask = Self.nxDeviceRCmdMask
            oppositeDeviceMask = Self.nxDeviceLCmdMask
            genericFlag = .maskCommand
        default:
            return false
        }
        // Fail-safe AND semantics: BOTH CGEventSource flags AND keyState must confirm pressed;
        // if either reports released, treat as released so stuck modifiers are always reconciled.
        let flagDown = (raw & deviceMask) != 0
            || (flags.contains(genericFlag) && (raw & oppositeDeviceMask) == 0)
        guard flagDown,
              let macCode = MacHidKeyMap.macKeyCode(forHidUsage: hidUsageId)
        else {
            return false
        }
        return isKeyPressed(macKeyCode: macCode)
    }

    public func currentPressedMouseButtons() -> UInt8 {
        var mask: UInt8 = 0
        if CGEventSource.buttonState(.hidSystemState, button: .left) {
            mask |= HidMouseButtonMask.left
        }
        if CGEventSource.buttonState(.hidSystemState, button: .right) {
            mask |= HidMouseButtonMask.right
        }
        if CGEventSource.buttonState(.hidSystemState, button: .center) {
            mask |= HidMouseButtonMask.middle
        }
        if let x1 = CGMouseButton(rawValue: 3),
           CGEventSource.buttonState(.hidSystemState, button: x1)
        {
            mask |= HidMouseButtonMask.back
        }
        if let x2 = CGMouseButton(rawValue: 4),
           CGEventSource.buttonState(.hidSystemState, button: x2)
        {
            mask |= HidMouseButtonMask.forward
        }
        return mask & HidMouseButtonMask.validMask
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
/// - Strict lock order `emitLock -> lock` (never holding `lock` across sink IPC)
/// - Press-to-release captured `ViewportState` snapshot
/// - Mandatory atomic `releaseAll(reason:)` on viewport change, focus loss, or UI overlay open
/// - 200ms OS state reconciliation synthesizing `up` for any OS-released key/modifier/button
public final class InputGate: @unchecked Sendable {
    public static let defaultReconciliationIntervalMs: Int = 200
    public static let maxReleaseTimeoutMs: UInt32 = 200
    public static let defaultReleaseTimeoutMs: UInt32 = 150

    /// Strict lock ordering: always acquire `emitLock` BEFORE `lock`, and release `lock`
    /// BEFORE invoking any `sink.*` method.
    private let emitLock = NSLock()
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
    private var notificationObservers: [NSObjectProtocol] = []
    private var isStopped: Bool = false

    public init(
        sink: any RemoteInputSink,
        osStateProvider: any OsInputStateProvider = MacOsInputStateProvider(),
        releaseTimeoutMs: UInt32 = InputGate.defaultReleaseTimeoutMs,
        reconciliationIntervalMs: Int = InputGate.defaultReconciliationIntervalMs,
        observeAppFocusNotifications: Bool = true
    ) {
        self.sink = sink
        self.osStateProvider = osStateProvider
        self.isInputEnabledFlag = false
        self.releaseTimeoutMs = min(max(releaseTimeoutMs, 1), Self.maxReleaseTimeoutMs)
        self.reconciliationIntervalMs = max(10, reconciliationIntervalMs)

        if observeAppFocusNotifications {
            let center = NotificationCenter.default
            let resignActive = center.addObserver(
                forName: NSApplication.didResignActiveNotification,
                object: nil,
                queue: nil
            ) { [weak self] _ in
                self?.releaseAll(reason: .focusLost)
            }
            let resignKey = center.addObserver(
                forName: NSWindow.didResignKeyNotification,
                object: nil,
                queue: nil
            ) { [weak self] _ in
                self?.releaseAll(reason: .focusLost)
            }
            lock.lock()
            notificationObservers = [resignActive, resignKey]
            lock.unlock()
        }
    }

    deinit {
        stop()
    }

    /// Releases any held inputs with `.stopped`, detaches focus observers, cancels any active
    /// 200ms reconciliation timer, flushes final `releaseAll` under `emitLock`, and then latches
    /// `isStopped = true` so subsequent events are ignored.
    public func stop() {
        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        if isStopped {
            let observers = notificationObservers
            notificationObservers.removeAll()
            lock.unlock()
            for obs in observers {
                NotificationCenter.default.removeObserver(obs)
            }
            return
        }

        let releasePayload = takeReleaseAllPayloadLocked(reason: .stopped, forceEmit: false)
        isInputEnabledFlag = false
        let timer = releasePayload?.timer ?? reconcileTimer
        reconcileTimer = nil
        let observers = notificationObservers
        notificationObservers.removeAll()
        lock.unlock()

        for obs in observers {
            NotificationCenter.default.removeObserver(obs)
        }
        timer?.cancel()

        if let payload = releasePayload {
            sink.flushReleaseAll(
                keys: payload.keys,
                buttons: payload.buttons,
                reason: .stopped,
                timeoutMs: releaseTimeoutMs
            )
        }

        lock.lock()
        isStopped = true
        lock.unlock()
    }

    public var isInputEnabled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return isInputEnabledFlag
    }

    /// Updates input enablement strictly from Rust-acknowledged state.
    /// Transitioning to `false` immediately triggers `releaseAll(reason: .inputDisabled)`.
    public func setInputEnabledFromAck(_ enabled: Bool) {
        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return
        }
        let wasEnabled = isInputEnabledFlag
        isInputEnabledFlag = enabled
        let releasePayload: ReleasePayload?
        if wasEnabled && !enabled {
            releasePayload = takeReleaseAllPayloadLocked(reason: .inputDisabled, forceEmit: false)
        } else {
            releasePayload = nil
        }
        lock.unlock()

        if let payload = releasePayload {
            payload.timer?.cancel()
            sink.flushReleaseAll(
                keys: payload.keys,
                buttons: payload.buttons,
                reason: .inputDisabled,
                timeoutMs: releaseTimeoutMs
            )
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

    /// Atomically swaps `ViewportState` when changed, clamping/resetting `lastValidRemotePoint`,
    /// clearing `activeGestureViewport`, and flushing `releaseAll(.viewportChanged)` strictly before
    /// any subsequent input event can emit on the new viewport.
    public func updateViewport(_ next: ViewportState?) {
        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped, currentViewport != next else {
            lock.unlock()
            return
        }
        let releasePayload = takeReleaseAllPayloadLocked(reason: .viewportChanged, forceEmit: false)
        currentViewport = next
        activeGestureViewport = nil
        if let next, next.isValid {
            let maxX = max(0, Int(next.frameSize.width.rounded(.towardZero)) - 1)
            let maxY = max(0, Int(next.frameSize.height.rounded(.towardZero)) - 1)
            lastValidRemotePoint = RemotePoint(
                x: min(max(lastValidRemotePoint.x, 0), maxX),
                y: min(max(lastValidRemotePoint.y, 0), maxY)
            )
        } else {
            lastValidRemotePoint = RemotePoint(x: 0, y: 0)
        }
        lock.unlock()

        if let payload = releasePayload {
            payload.timer?.cancel()
            sink.flushReleaseAll(
                keys: payload.keys,
                buttons: payload.buttons,
                reason: .viewportChanged,
                timeoutMs: releaseTimeoutMs
            )
        }
    }

    /// Convenience trigger for opening any toolbar popover, side drawer, sheet, or `NSOpenPanel`.
    @discardableResult
    public func notifyOverlayOpened() -> ReleaseAllSnapshot? {
        releaseAll(reason: .uiOverlayOpened)
    }

    // MARK: - Keyboard Routing (`keyDown` / `keyUp` / `flagsChanged`)

    @discardableResult
    public func handleKeyDown(
        usageId: UInt16?,
        modifiers: UInt8,
        isARepeat: Bool = false
    ) -> KeyDownOutcome {
        emitLock.lock()
        defer { emitLock.unlock() }
        return handleKeyDownEmitLocked(usageId: usageId, modifiers: modifiers, isARepeat: isARepeat)
    }

    public func handleKeyUp(usageId: UInt16, modifiers: UInt8) {
        emitLock.lock()
        defer { emitLock.unlock() }
        handleKeyUpEmitLocked(usageId: usageId, modifiers: modifiers)
    }

    /// Explicitly handles macOS `flagsChanged` for distinct Left/Right modifiers (`0xE0..=0xE7`).
    public func handleFlagsChanged(modifierUsageId: UInt16, isPressed: Bool, modifiers: UInt8) {
        guard MacHidKeyMap.modifierBit(forUsageId: modifierUsageId) != nil else {
            return
        }
        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return
        }
        let wasPressed = pressedModifiers.contains(modifierUsageId)
        let enabled = isInputEnabledFlag
        lock.unlock()

        if isPressed {
            if enabled && !wasPressed {
                _ = handleKeyDownEmitLocked(usageId: modifierUsageId, modifiers: modifiers, isARepeat: false)
            }
        } else if wasPressed {
            handleKeyUpEmitLocked(usageId: modifierUsageId, modifiers: modifiers)
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

        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped, isInputEnabledFlag, let vp = currentViewport else {
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
        guard !isStopped, isInputEnabledFlag else {
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
        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped, isInputEnabledFlag, let vp = activeGestureViewport ?? currentViewport else {
            lock.unlock()
            return nil
        }
        lock.unlock()

        guard let remotePt = RemoteCoordinateMapper.mapViewPoint(
            viewPoint,
            backingScale: backingScale,
            in: vp,
            origin: origin
        ) else {
            return nil
        }

        lock.lock()
        guard !isStopped, isInputEnabledFlag else {
            lock.unlock()
            return nil
        }
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

        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return nil
        }
        let wasPressed = pressedMouseButtons.contains(bit)
        guard wasPressed else {
            lock.unlock()
            return nil
        }
        let vp = activeGestureViewport ?? currentViewport
        let fallbackPt = lastValidRemotePoint
        lock.unlock()

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

        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped, isInputEnabledFlag, let vp = activeGestureViewport ?? currentViewport else {
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

    // MARK: - Unified `releaseAll(reason:)` & Drag-Safe Key Release

    /// Atomically clears ALL 3 pressed sets (`pressedKeys`, `pressedModifiers`, `pressedMouseButtons`),
    /// cancels the reconciliation timer, and emits ONE bounded `release_all` command through the sink.
    @discardableResult
    public func releaseAll(reason: ReleaseReason, forceEmit: Bool = false) -> ReleaseAllSnapshot? {
        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return nil
        }
        let releasePayload = takeReleaseAllPayloadLocked(reason: reason, forceEmit: forceEmit)
        lock.unlock()

        guard let payload = releasePayload else {
            return nil
        }
        payload.timer?.cancel()
        sink.flushReleaseAll(
            keys: payload.keys,
            buttons: payload.buttons,
            reason: reason,
            timeoutMs: releaseTimeoutMs
        )
        return payload.snapshot
    }

    /// Releases held keys and modifiers WITHOUT releasing active mouse buttons (used when the pointer
    /// exits the view mid-drag so the drag gesture can still finish cleanly while preventing stuck keys).
    @discardableResult
    public func releaseKeysAndModifiersOnly(reason: ReleaseReason) -> ReleaseAllSnapshot? {
        emitLock.lock()
        defer { emitLock.unlock() }

        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return nil
        }
        if pressedKeys.isEmpty && pressedModifiers.isEmpty {
            lock.unlock()
            return nil
        }
        let allKeys = pressedKeys.union(pressedModifiers)
        let modMask = derivedModifierMaskLocked()
        let keysToRelease = allKeys.sorted()
        let snapshot = ReleaseAllSnapshot(
            reason: reason,
            keys: allKeys,
            modifiers: modMask,
            mouseButtons: 0
        )
        pressedKeys.removeAll(keepingCapacity: true)
        pressedModifiers.removeAll(keepingCapacity: true)
        let timerToStop = stopReconcileTimerIfIdleLocked()
        lock.unlock()

        timerToStop?.cancel()
        sink.flushReleaseAll(
            keys: keysToRelease,
            buttons: 0,
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
        if isStopped || (pressedKeys.isEmpty && pressedModifiers.isEmpty && pressedMouseButtons.isEmpty) {
            lock.unlock()
            return ([], [], [])
        }
        let initialKeys = pressedKeys
        let initialMods = pressedModifiers
        let initialButtons = pressedMouseButtons
        lock.unlock()

        // Fast pre-check outside emitLock so the common "everything still held" case never contends.
        let quickMouseMask = osStateProvider.currentPressedMouseButtons()
        var hasCandidate = false
        for usage in initialKeys {
            if let macCode = MacHidKeyMap.macKeyCode(forHidUsage: usage),
               !osStateProvider.isKeyPressed(macKeyCode: macCode)
            {
                hasCandidate = true
                break
            }
        }
        if !hasCandidate {
            for modUsage in initialMods where !osStateProvider.isModifierPressed(hidUsageId: modUsage) {
                hasCandidate = true
                break
            }
        }
        if !hasCandidate {
            for btn in initialButtons where (quickMouseMask & btn) == 0 {
                hasCandidate = true
                break
            }
        }
        guard hasCandidate else {
            return ([], [], [])
        }

        emitLock.lock()
        defer { emitLock.unlock() }

        // Re-verify OS state inside emitLock before removing entries so a concurrent keyDown/mouseDown
        // serialized on emitLock can never be falsely released.
        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return ([], [], [])
        }
        let trackedKeys = pressedKeys
        let trackedMods = pressedModifiers
        let trackedButtons = pressedMouseButtons
        lock.unlock()

        let liveMouseMask = osStateProvider.currentPressedMouseButtons()
        var staleKeys: [UInt16] = []
        for usage in trackedKeys.sorted() {
            if let macCode = MacHidKeyMap.macKeyCode(forHidUsage: usage),
               !osStateProvider.isKeyPressed(macKeyCode: macCode)
            {
                staleKeys.append(usage)
            }
        }

        var staleMods: [UInt16] = []
        for modUsage in trackedMods.sorted() {
            if !osStateProvider.isModifierPressed(hidUsageId: modUsage) {
                staleMods.append(modUsage)
            }
        }

        var staleButtons: [UInt8] = []
        for btn in trackedButtons.sorted() where (liveMouseMask & btn) == 0 {
            staleButtons.append(btn)
        }

        if staleKeys.isEmpty && staleMods.isEmpty && staleButtons.isEmpty {
            return ([], [], [])
        }

        var releasedKeys: [UInt16] = []
        var releasedMods: [UInt16] = []
        var releasedButtons: [UInt8] = []
        var syntheticKeyUps: [(UInt16, UInt8)] = []
        var syntheticMouseUps: [UInt8] = []
        let lastPt: RemotePoint
        let timerToStop: DispatchSourceTimer?

        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return ([], [], [])
        }
        lastPt = lastValidRemotePoint
        for usage in staleKeys where pressedKeys.remove(usage) != nil {
            releasedKeys.append(usage)
            syntheticKeyUps.append((usage, derivedModifierMaskLocked()))
        }
        for modUsage in staleMods where pressedModifiers.remove(modUsage) != nil {
            releasedMods.append(modUsage)
            syntheticKeyUps.append((modUsage, derivedModifierMaskLocked()))
        }
        for btn in staleButtons where pressedMouseButtons.remove(btn) != nil {
            releasedButtons.append(btn)
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

        return (releasedKeys, releasedMods, releasedButtons)
    }

    // MARK: - Private Emit-Locked & State-Locked Helpers

    private struct ReleasePayload {
        let keys: [UInt16]
        let buttons: UInt8
        let snapshot: ReleaseAllSnapshot
        let timer: DispatchSourceTimer?
    }

    private func takeReleaseAllPayloadLocked(
        reason: ReleaseReason,
        forceEmit: Bool
    ) -> ReleasePayload? {
        let empty = pressedKeys.isEmpty && pressedModifiers.isEmpty && pressedMouseButtons.isEmpty
        if empty && !forceEmit {
            activeGestureViewport = nil
            return nil
        }
        let allKeys = pressedKeys.union(pressedModifiers)
        let modMask = derivedModifierMaskLocked()
        let combinedButtons = combinedMouseButtonMaskLocked()
        let keysToRelease = allKeys.sorted()
        let snapshot = ReleaseAllSnapshot(
            reason: reason,
            keys: allKeys,
            modifiers: modMask,
            mouseButtons: combinedButtons
        )
        pressedKeys.removeAll(keepingCapacity: true)
        pressedModifiers.removeAll(keepingCapacity: true)
        pressedMouseButtons.removeAll(keepingCapacity: true)
        activeGestureViewport = nil
        let timer = reconcileTimer
        reconcileTimer = nil
        return ReleasePayload(
            keys: keysToRelease,
            buttons: combinedButtons,
            snapshot: snapshot,
            timer: timer
        )
    }

    private func handleKeyDownEmitLocked(
        usageId: UInt16?,
        modifiers: UInt8,
        isARepeat: Bool
    ) -> KeyDownOutcome {
        let maskedMods = modifiers & HidModifierMask.validMask

        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return .ignored
        }

        // Emergency escape (`Ctrl+Opt+Cmd+Escape`) is evaluated BEFORE whitelist & repeat checks
        // (so holding Escape then adding modifiers still triggers!), while keeping side-effects
        // idempotent across OS key repeats once already disabled with no held inputs.
        let combinedMods = (maskedMods | derivedModifierMaskLocked()) & HidModifierMask.validMask
        if let usageId, MacHidKeyMap.isEmergencyEscapeCombo(usageId: usageId, modifiers: combinedMods) {
            let wasEnabled = isInputEnabledFlag
            isInputEnabledFlag = false
            let releasePayload = takeReleaseAllPayloadLocked(
                reason: .emergencyEscapeHotkey,
                forceEmit: wasEnabled || !isARepeat
            )
            lock.unlock()

            guard let payload = releasePayload else {
                return .ignored
            }
            payload.timer?.cancel()
            sink.flushReleaseAll(
                keys: payload.keys,
                buttons: payload.buttons,
                reason: .emergencyEscapeHotkey,
                timeoutMs: releaseTimeoutMs
            )
            return .emergencyEscapeTriggered
        }

        guard let usageId, MacHidKeyMap.isWhitelistedUsageId(usageId), isInputEnabledFlag else {
            lock.unlock()
            return .ignored
        }

        // Deduplicate OS key-repeat events (remote OS generates native repeat from a single down/up).
        if isARepeat {
            lock.unlock()
            return .ignored
        }

        let effectiveMods: UInt8
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

    private func handleKeyUpEmitLocked(usageId: UInt16, modifiers: UInt8) {
        let maskedMods = modifiers & HidModifierMask.validMask
        let effectiveMods: UInt8
        let shouldSend: Bool

        lock.lock()
        guard !isStopped else {
            lock.unlock()
            return
        }
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
        shouldSend = wasTracked || (isInputEnabledFlag && MacHidKeyMap.isWhitelistedUsageId(usageId))
        let timerToStop = stopReconcileTimerIfIdleLocked()
        lock.unlock()

        timerToStop?.cancel()
        if shouldSend {
            sink.sendKeyEvent(usageId: usageId, down: false, modifiers: effectiveMods)
        }
    }

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
