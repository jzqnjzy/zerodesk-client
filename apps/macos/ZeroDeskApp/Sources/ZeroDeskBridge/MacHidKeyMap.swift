// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import Foundation

/// Normative `spec/04` §6.1.2 `KeyEvent.modifiers` bitmask constants.
public enum HidModifierMask {
    public static let shift: UInt8 = 1 << 0
    public static let ctrl: UInt8 = 1 << 1
    public static let alt: UInt8 = 1 << 2
    public static let meta: UInt8 = 1 << 3
    public static let validMask: UInt8 = shift | ctrl | alt | meta
}

/// Normative `spec/04` §6.1.1 `MouseEvent.buttons` bitmask constants.
public enum HidMouseButtonMask {
    public static let left: UInt8 = 1 << 0
    public static let right: UInt8 = 1 << 1
    public static let middle: UInt8 = 1 << 2
    public static let back: UInt8 = 1 << 3
    public static let forward: UInt8 = 1 << 4
    public static let validMask: UInt8 = 0x1F
}

/// Strict compile-time lookup table mapping macOS virtual keyCodes (`NSEvent.keyCode` / HIToolbox
/// `kVK_*`) to USB HID Usage Page `0x07` usage IDs matching `protocol-spec v1.2.4` `spec/04` §6.
///
/// Unmapped keyCodes ALWAYS return `nil` (never synthesized or guessed) and increment
/// `unmappedKeyDropCount`.
public final class MacHidKeyMap: @unchecked Sendable {
    public static let escapeUsageId: UInt16 = 0x29

    public static let leftControlUsageId: UInt16 = 0xE0
    public static let leftShiftUsageId: UInt16 = 0xE1
    public static let leftAltUsageId: UInt16 = 0xE2
    public static let leftMetaUsageId: UInt16 = 0xE3
    public static let rightControlUsageId: UInt16 = 0xE4
    public static let rightShiftUsageId: UInt16 = 0xE5
    public static let rightAltUsageId: UInt16 = 0xE6
    public static let rightMetaUsageId: UInt16 = 0xE7

    /// Static compile-time table: macOS `kVK_*` virtual keyCode -> USB HID Usage Page `0x07` ID.
    /// Every value lies strictly within `spec/04` §6.1.2 normative whitelist ranges.
    public static let keyCodeToHidUsage: [UInt16: UInt16] = [
        // Letters A-Z (0x04..=0x1D)
        0x00: 0x04, // kVK_ANSI_A
        0x0B: 0x05, // kVK_ANSI_B
        0x08: 0x06, // kVK_ANSI_C
        0x02: 0x07, // kVK_ANSI_D
        0x0E: 0x08, // kVK_ANSI_E
        0x03: 0x09, // kVK_ANSI_F
        0x05: 0x0A, // kVK_ANSI_G
        0x04: 0x0B, // kVK_ANSI_H
        0x22: 0x0C, // kVK_ANSI_I
        0x26: 0x0D, // kVK_ANSI_J
        0x28: 0x0E, // kVK_ANSI_K
        0x25: 0x0F, // kVK_ANSI_L
        0x2E: 0x10, // kVK_ANSI_M
        0x2D: 0x11, // kVK_ANSI_N
        0x1F: 0x12, // kVK_ANSI_O
        0x23: 0x13, // kVK_ANSI_P
        0x0C: 0x14, // kVK_ANSI_Q
        0x0F: 0x15, // kVK_ANSI_R
        0x01: 0x16, // kVK_ANSI_S
        0x11: 0x17, // kVK_ANSI_T
        0x20: 0x18, // kVK_ANSI_U
        0x09: 0x19, // kVK_ANSI_V
        0x0D: 0x1A, // kVK_ANSI_W
        0x07: 0x1B, // kVK_ANSI_X
        0x10: 0x1C, // kVK_ANSI_Y
        0x06: 0x1D, // kVK_ANSI_Z

        // Digits 1-9, 0 (0x1E..=0x27)
        0x12: 0x1E, // kVK_ANSI_1
        0x13: 0x1F, // kVK_ANSI_2
        0x14: 0x20, // kVK_ANSI_3
        0x15: 0x21, // kVK_ANSI_4
        0x17: 0x22, // kVK_ANSI_5
        0x16: 0x23, // kVK_ANSI_6
        0x1A: 0x24, // kVK_ANSI_7
        0x1C: 0x25, // kVK_ANSI_8
        0x19: 0x26, // kVK_ANSI_9
        0x1D: 0x27, // kVK_ANSI_0

        // Core control keys (0x28..=0x2C)
        0x24: 0x28, // kVK_Return -> Enter
        0x35: 0x29, // kVK_Escape -> Escape
        0x33: 0x2A, // kVK_Delete -> Backspace
        0x30: 0x2B, // kVK_Tab -> Tab
        0x31: 0x2C, // kVK_Space -> Space

        // Punctuation & CapsLock (0x2D..=0x39)
        0x1B: 0x2D, // kVK_ANSI_Minus
        0x18: 0x2E, // kVK_ANSI_Equal
        0x21: 0x2F, // kVK_ANSI_LeftBracket
        0x1E: 0x30, // kVK_ANSI_RightBracket
        0x2A: 0x31, // kVK_ANSI_Backslash
        0x29: 0x33, // kVK_ANSI_Semicolon
        0x27: 0x34, // kVK_ANSI_Quote
        0x32: 0x35, // kVK_ANSI_Grave
        0x2B: 0x36, // kVK_ANSI_Comma
        0x2F: 0x37, // kVK_ANSI_Period
        0x2C: 0x38, // kVK_ANSI_Slash
        0x39: 0x39, // kVK_CapsLock

        // Function keys F1-F12 (0x3A..=0x45)
        0x7A: 0x3A, // kVK_F1
        0x78: 0x3B, // kVK_F2
        0x63: 0x3C, // kVK_F3
        0x76: 0x3D, // kVK_F4
        0x60: 0x3E, // kVK_F5
        0x61: 0x3F, // kVK_F6
        0x62: 0x40, // kVK_F7
        0x64: 0x41, // kVK_F8
        0x65: 0x42, // kVK_F9
        0x6D: 0x43, // kVK_F10
        0x67: 0x44, // kVK_F11
        0x6F: 0x45, // kVK_F12

        // Navigation & editing cluster (0x49..=0x4E)
        0x72: 0x49, // kVK_Help -> Insert
        0x73: 0x4A, // kVK_Home
        0x74: 0x4B, // kVK_PageUp
        0x75: 0x4C, // kVK_ForwardDelete -> Delete Forward
        0x77: 0x4D, // kVK_End
        0x79: 0x4E, // kVK_PageDown

        // Arrow keys (0x4F..=0x52)
        0x7C: 0x4F, // kVK_RightArrow
        0x7B: 0x50, // kVK_LeftArrow
        0x7D: 0x51, // kVK_DownArrow
        0x7E: 0x52, // kVK_UpArrow

        // Keypad cluster (0x53..=0x67)
        0x47: 0x53, // kVK_ANSI_KeypadClear -> NumLock/Clear
        0x4B: 0x54, // kVK_ANSI_KeypadDivide
        0x43: 0x55, // kVK_ANSI_KeypadMultiply
        0x4E: 0x56, // kVK_ANSI_KeypadMinus
        0x45: 0x57, // kVK_ANSI_KeypadPlus
        0x4C: 0x58, // kVK_ANSI_KeypadEnter
        0x53: 0x59, // kVK_ANSI_Keypad1
        0x54: 0x5A, // kVK_ANSI_Keypad2
        0x55: 0x5B, // kVK_ANSI_Keypad3
        0x56: 0x5C, // kVK_ANSI_Keypad4
        0x57: 0x5D, // kVK_ANSI_Keypad5
        0x58: 0x5E, // kVK_ANSI_Keypad6
        0x59: 0x5F, // kVK_ANSI_Keypad7
        0x5B: 0x60, // kVK_ANSI_Keypad8
        0x5C: 0x61, // kVK_ANSI_Keypad9
        0x52: 0x62, // kVK_ANSI_Keypad0
        0x41: 0x63, // kVK_ANSI_KeypadDecimal
        0x51: 0x67, // kVK_ANSI_KeypadEquals

        // Left & Right Modifiers (0xE0..=0xE7) — strictly distinct, never merged
        0x3B: 0xE0, // kVK_Control -> LeftControl
        0x38: 0xE1, // kVK_Shift -> LeftShift
        0x3A: 0xE2, // kVK_Option -> LeftAlt
        0x37: 0xE3, // kVK_Command -> LeftMeta
        0x3E: 0xE4, // kVK_RightControl -> RightControl
        0x3C: 0xE5, // kVK_RightShift -> RightShift
        0x3D: 0xE6, // kVK_RightOption -> RightAlt
        0x36: 0xE7, // kVK_RightCommand -> RightMeta
    ]

    private let lock = NSLock()
    private var droppedCount: UInt64 = 0

    public init() {}

    /// Thread-safe count of unmapped keyCodes dropped by `lookup(_:)`.
    public var unmappedKeyDropCount: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return droppedCount
    }

    public func resetTelemetry() {
        lock.lock()
        droppedCount = 0
        lock.unlock()
    }

    /// Maps a macOS virtual keyCode to a whitelisted USB HID Usage ID.
    /// Returns `nil` and increments `unmappedKeyDropCount` for unmapped keyCodes.
    public func lookup(_ keyCode: UInt16) -> UInt16? {
        if let usage = Self.keyCodeToHidUsage[keyCode] {
            return usage
        }
        lock.lock()
        droppedCount &+= 1
        lock.unlock()
        return nil
    }

    /// Pure stateless lookup (does not mutate drop telemetry).
    public static func hidUsage(forMacKeyCode keyCode: UInt16) -> UInt16? {
        keyCodeToHidUsage[keyCode]
    }

    /// Reverse lookup table: USB HID Usage Page `0x07` ID -> macOS virtual keyCode (`CGKeyCode`).
    /// Deterministic on any collision: always selects the minimum macOS keyCode.
    public static let hidUsageToMacKeyCode: [UInt16: UInt16] = {
        var reverse: [UInt16: UInt16] = [:]
        reverse.reserveCapacity(keyCodeToHidUsage.count)
        for (macCode, usage) in keyCodeToHidUsage {
            if let existing = reverse[usage] {
                reverse[usage] = min(existing, macCode)
            } else {
                reverse[usage] = macCode
            }
        }
        return reverse
    }()

    /// Pure reverse lookup from USB HID usage ID to macOS virtual keyCode (used by OS reconciliation).
    public static func macKeyCode(forHidUsage usageId: UInt16) -> UInt16? {
        hidUsageToMacKeyCode[usageId]
    }

    /// Returns the required `spec/04` §6.1.2 `modifiers` bitmap bit when pressing a physical
    /// modifier key (`0xE0..=0xE7`), or `nil` for non-modifier usages.
    public static func modifierBit(forUsageId usageId: UInt16) -> UInt8? {
        switch usageId {
        case leftControlUsageId, rightControlUsageId:
            return HidModifierMask.ctrl
        case leftShiftUsageId, rightShiftUsageId:
            return HidModifierMask.shift
        case leftAltUsageId, rightAltUsageId:
            return HidModifierMask.alt
        case leftMetaUsageId, rightMetaUsageId:
            return HidModifierMask.meta
        default:
            return nil
        }
    }

    /// Verifies whether a USB HID usage ID lies within the `spec/04` §6.1.2 normative whitelist
    /// (excluding `0x66 Keyboard Power`).
    public static func isWhitelistedUsageId(_ usageId: UInt16) -> Bool {
        if usageId == 0x66 {
            return false
        }
        switch usageId {
        case 0x04...0x1D,
             0x1E...0x27,
             0x28...0x2C,
             0x2D...0x39,
             0x3A...0x45,
             0x46...0x4E,
             0x4F...0x52,
             0x53...0x73,
             0x87...0x8B,
             0x90...0x94,
             0xE0...0xE7:
            return true
        default:
            return false
        }
    }

    /// Returns `true` for the local emergency escape combo **`Ctrl + Opt + Cmd + Escape`**
    /// (must be intercepted locally to trigger `releaseAll` and NEVER forwarded to remote).
    public static func isEmergencyEscapeCombo(usageId: UInt16, modifiers: UInt8) -> Bool {
        guard usageId == escapeUsageId else {
            return false
        }
        let required: UInt8 = HidModifierMask.ctrl | HidModifierMask.alt | HidModifierMask.meta
        return (modifiers & required) == required
    }
}
