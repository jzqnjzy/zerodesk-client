// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import Foundation

/// Normative remote mouse event kinds matching `spec/04` §6.1.1 and Rust bridge JSON ABI.
public enum RemoteMouseKind: String, Sendable, Equatable {
    case moveAbs = "move_abs"
    case moveRel = "move_rel"
    case buttonDown = "button_down"
    case buttonUp = "button_up"
    case wheel = "wheel"
}

/// All anti-stuck-key `releaseAll` triggers (Phase 7B + Phase 8A UI triggers).
public enum ReleaseReason: String, Sendable, CaseIterable, Equatable {
    case windowResignedKey
    case appResignedActiveOrHidden
    case sessionLeftConnected
    case emergencyEscapeHotkey
    case viewTeardownOrTerminate
    case focusLost
    case uiOverlayOpened
    case mouseExitedView
    case viewportChanged
    case inputDisabled
}

/// Snapshot of held inputs atomically cleared by a single `releaseAll(reason:)` invocation.
public struct ReleaseAllSnapshot: Sendable, Equatable {
    public let reason: ReleaseReason
    public let keys: Set<UInt16>
    public let modifiers: UInt8
    public let mouseButtons: UInt8

    public init(reason: ReleaseReason, keys: Set<UInt16>, modifiers: UInt8, mouseButtons: UInt8) {
        self.reason = reason
        self.keys = keys
        self.modifiers = modifiers
        self.mouseButtons = mouseButtons
    }
}

/// Distinct outcome of processing a keyboard `keyDown` event so callers never confuse
/// an ignored/unmapped key with a local emergency escape trigger.
public enum KeyDownOutcome: Sendable, Equatable {
    case forwarded
    case emergencyEscapeTriggered
    case ignored
}

/// Sink receiving outbound interactive HID events and bounded synchronous `release_all` flushes.
public protocol RemoteInputSink: Sendable {
    func sendKeyEvent(usageId: UInt16, down: Bool, modifiers: UInt8)
    func sendMouseEvent(
        kind: RemoteMouseKind,
        x: Int,
        y: Int,
        buttons: UInt8,
        wheelDx: Int16,
        wheelDy: Int16
    )
    func flushReleaseAll(
        keys: [UInt16],
        buttons: UInt8,
        reason: ReleaseReason,
        timeoutMs: UInt32
    )
}

/// Thread-safe, TSan-clean tracker for currently held remote HID keys, modifiers, and mouse buttons.
///
/// Guarantees:
/// - Tracks left and right physical modifiers independently (`0xE0..=0xE7`).
/// - Enforces `spec/04` §6.1.2 modifier consistency on modifier `keyDown`.
/// - Intercepts `Ctrl + Opt + Cmd + Escape` locally -> invokes `releaseAll(.emergencyEscapeHotkey)`
///   and NEVER forwards the Escape press to the remote peer.
/// - On any of the 5 `ReleaseReason` triggers, atomically clears local tracked state and emits
///   EXACTLY ONE bounded synchronous `release_all` call (`<= 200 ms`), with repeated calls on clean
///   state acting as safe idempotent no-ops.
public final class PressedInputTracker: @unchecked Sendable {
    public static let maxReleaseTimeoutMs: UInt32 = 200
    public static let defaultReleaseTimeoutMs: UInt32 = 150

    private let lock = NSLock()
    private var pressedKeys: Set<UInt16> = []
    private var modifierMask: UInt8 = 0
    private var mouseButtons: UInt8 = 0
    private var lastValidMousePoint: RemotePoint = RemotePoint(x: 0, y: 0)
    private let sink: any RemoteInputSink
    private let releaseTimeoutMs: UInt32

    public init(
        sink: any RemoteInputSink,
        releaseTimeoutMs: UInt32 = PressedInputTracker.defaultReleaseTimeoutMs
    ) {
        self.sink = sink
        self.releaseTimeoutMs = min(max(releaseTimeoutMs, 1), Self.maxReleaseTimeoutMs)
    }

    public var hasPressedMouseButtons: Bool {
        lock.lock()
        defer { lock.unlock() }
        return mouseButtons != 0
    }

    public var hasAnyPressedInput: Bool {
        lock.lock()
        defer { lock.unlock() }
        return !pressedKeys.isEmpty || modifierMask != 0 || mouseButtons != 0
    }

    public func snapshotState() -> (keys: Set<UInt16>, modifiers: UInt8, mouseButtons: UInt8) {
        lock.lock()
        defer { lock.unlock() }
        return (pressedKeys, modifierMask, mouseButtons)
    }

    /// Classifies and processes a `keyDown` event with explicit distinction between `.forwarded`,
    /// `.emergencyEscapeTriggered`, and `.ignored` (nil/unmapped or non-whitelisted usage IDs).
    @discardableResult
    public func handleKeyDownEvent(usageId: UInt16?, modifiers: UInt8) -> KeyDownOutcome {
        guard let usageId, MacHidKeyMap.isWhitelistedUsageId(usageId) else {
            return .ignored
        }
        let maskedMods = modifiers & HidModifierMask.validMask
        if MacHidKeyMap.isEmergencyEscapeCombo(usageId: usageId, modifiers: maskedMods) {
            releaseAll(reason: .emergencyEscapeHotkey)
            return .emergencyEscapeTriggered
        }

        let effectiveMods: UInt8
        lock.lock()
        pressedKeys.insert(usageId)
        var computed = maskedMods | derivedModifierMaskLocked()
        if let modBit = MacHidKeyMap.modifierBit(forUsageId: usageId) {
            computed |= modBit
        }
        modifierMask = computed & HidModifierMask.validMask
        effectiveMods = modifierMask
        lock.unlock()

        sink.sendKeyEvent(usageId: usageId, down: true, modifiers: effectiveMods)
        return .forwarded
    }

    /// Records and forwards a key press.
    /// Returns `false` if intercepted locally as `Ctrl + Opt + Cmd + Escape` (after triggering
    /// `releaseAll(.emergencyEscapeHotkey)`) or ignored, or `true` if forwarded to the remote peer.
    @discardableResult
    public func handleKeyDown(usageId: UInt16, modifiers: UInt8) -> Bool {
        handleKeyDownEvent(usageId: usageId, modifiers: modifiers) == .forwarded
    }

    /// Records and forwards a key release (including `Cmd + key` releases captured by local monitor).
    public func handleKeyUp(usageId: UInt16, modifiers: UInt8) {
        let maskedMods = modifiers & HidModifierMask.validMask
        let effectiveMods: UInt8

        lock.lock()
        pressedKeys.remove(usageId)
        let derived = derivedModifierMaskLocked()
        if let modBit = MacHidKeyMap.modifierBit(forUsageId: usageId) {
            // Keep modifier bit set only if the opposite-side modifier key is still held.
            let kept = (derived & modBit) != 0 ? modBit : 0
            modifierMask = ((maskedMods & ~modBit) | derived | kept) & HidModifierMask.validMask
        } else {
            modifierMask = (maskedMods | derived) & HidModifierMask.validMask
        }
        effectiveMods = modifierMask
        lock.unlock()

        sink.sendKeyEvent(usageId: usageId, down: false, modifiers: effectiveMods)
    }

    /// Translates AppKit `flagsChanged` into synthetic `keyDown` / `keyUp` transitions for the
    /// specific left/right modifier HID usage (`0xE0..=0xE7`).
    public func handleFlagsChanged(modifierUsageId: UInt16, isPressed: Bool, modifiers: UInt8) {
        guard MacHidKeyMap.modifierBit(forUsageId: modifierUsageId) != nil else {
            return
        }
        lock.lock()
        let wasPressed = pressedKeys.contains(modifierUsageId)
        lock.unlock()

        if isPressed && !wasPressed {
            _ = handleKeyDown(usageId: modifierUsageId, modifiers: modifiers)
        } else if !isPressed && wasPressed {
            handleKeyUp(usageId: modifierUsageId, modifiers: modifiers)
        }
    }

    public func handleMouseDown(button: UInt8, x: Int, y: Int) {
        let bit = button & HidMouseButtonMask.validMask
        guard bit != 0 else { return }

        lock.lock()
        mouseButtons |= bit
        lastValidMousePoint = RemotePoint(x: x, y: y)
        let currentButtons = mouseButtons
        lock.unlock()

        sink.sendMouseEvent(
            kind: .buttonDown,
            x: x,
            y: y,
            buttons: currentButtons,
            wheelDx: 0,
            wheelDy: 0
        )
    }

    public func handleMouseUp(button: UInt8, x: Int, y: Int) {
        handleMouseUp(button: button, point: RemotePoint(x: x, y: y))
    }

    /// Releases a mouse button even when coordinate mapping returns `nil` (e.g., zero/invalid
    /// remote dimensions or out-of-rect release), falling back to the last valid remote point
    /// (or `(0, 0)`) so held mouse buttons are never stranded.
    public func handleMouseUp(button: UInt8, point: RemotePoint?) {
        let bit = button & HidMouseButtonMask.validMask
        guard bit != 0 else { return }

        let targetPoint: RemotePoint
        lock.lock()
        mouseButtons &= ~bit
        if let point {
            lastValidMousePoint = point
            targetPoint = point
        } else {
            targetPoint = lastValidMousePoint
        }
        let currentButtons = mouseButtons
        lock.unlock()

        sink.sendMouseEvent(
            kind: .buttonUp,
            x: targetPoint.x,
            y: targetPoint.y,
            buttons: currentButtons,
            wheelDx: 0,
            wheelDy: 0
        )
    }

    public func handleMouseMove(x: Int, y: Int) {
        lock.lock()
        lastValidMousePoint = RemotePoint(x: x, y: y)
        let currentButtons = mouseButtons
        lock.unlock()

        sink.sendMouseEvent(
            kind: .moveAbs,
            x: x,
            y: y,
            buttons: currentButtons,
            wheelDx: 0,
            wheelDy: 0
        )
    }

    public func handleMouseWheel(wheelDx: Int16, wheelDy: Int16, x: Int = 0, y: Int = 0) {
        guard wheelDx != 0 || wheelDy != 0 else { return }
        lock.lock()
        let currentButtons = mouseButtons
        lock.unlock()

        sink.sendMouseEvent(
            kind: .wheel,
            x: x,
            y: y,
            buttons: currentButtons,
            wheelDx: wheelDx,
            wheelDy: wheelDy
        )
    }

    /// Atomically clears all locally tracked pressed keys, modifiers, and mouse buttons and emits
    /// EXACTLY ONE bounded synchronous `release_all` command (`<= 200 ms`).
    /// Calling repeatedly when already clean is a safe idempotent no-op returning `nil`.
    @discardableResult
    public func releaseAll(reason: ReleaseReason) -> ReleaseAllSnapshot? {
        let snapshot: ReleaseAllSnapshot
        lock.lock()
        if pressedKeys.isEmpty && modifierMask == 0 && mouseButtons == 0 {
            lock.unlock()
            return nil
        }
        snapshot = ReleaseAllSnapshot(
            reason: reason,
            keys: pressedKeys,
            modifiers: modifierMask,
            mouseButtons: mouseButtons
        )
        pressedKeys.removeAll(keepingCapacity: true)
        modifierMask = 0
        mouseButtons = 0
        lock.unlock()

        sink.flushReleaseAll(
            keys: Array(snapshot.keys).sorted(),
            buttons: snapshot.mouseButtons,
            reason: reason,
            timeoutMs: releaseTimeoutMs
        )
        return snapshot
    }

    private func derivedModifierMaskLocked() -> UInt8 {
        var mask: UInt8 = 0
        for usage in pressedKeys {
            if let bit = MacHidKeyMap.modifierBit(forUsageId: usage) {
                mask |= bit
            }
        }
        return mask
    }
}
