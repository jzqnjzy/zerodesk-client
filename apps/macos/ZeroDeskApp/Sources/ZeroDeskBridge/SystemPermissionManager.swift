// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import CoreGraphics
import Foundation

/// macOS privacy permissions managed by `SystemPermissionGuideView`.
public enum MacSystemPermissionKind: String, Sendable, CaseIterable, Equatable {
    case screenRecording
    case accessibility
}

/// Explicit token proving that a Screen Recording permission request originated from a direct
/// user button click (preventing silent calls from `onAppear`, timers, or background refreshes).
public struct UserInitiatedPermissionAction: Sendable {
    public init(userAction: Bool = true) {
        precondition(userAction, "UserInitiatedPermissionAction requires an explicit user action")
    }
}

/// Pure, unit-testable System Settings deep-link builder & explicit Screen Recording request helper.
public enum SystemPermissionLinks {
    /// Ordered deep-link candidates for opening macOS System Settings -> Privacy & Security.
    /// Selects candidate order according to macOS version (`macOS 13+` System Settings extension
    /// first on Ventura+, legacy `com.apple.preference.security` first on earlier macOS).
    public static func candidateURLs(
        for kind: MacSystemPermissionKind,
        isMacOS13OrLater: Bool = {
            if #available(macOS 13, *) {
                return true
            } else {
                return false
            }
        }()
    ) -> [URL] {
        let modernSpecific: String
        let legacySpecific: String
        switch kind {
        case .screenRecording:
            modernSpecific = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_ScreenCapture"
            legacySpecific = "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture"
        case .accessibility:
            modernSpecific = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility"
            legacySpecific = "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility"
        }
        let modernPane = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension"
        let legacyPane = "x-apple.systempreferences:com.apple.preference.security"

        let rawStrings: [String]
        if isMacOS13OrLater {
            rawStrings = [modernSpecific, legacySpecific, modernPane, legacyPane]
        } else {
            rawStrings = [legacySpecific, modernSpecific, legacyPane, modernPane]
        }
        return rawStrings.compactMap(URL.init(string:))
    }

    /// Tries each deep-link URL in priority order until `openURL` returns `true`.
    /// Returns the URL that succeeded, or `nil` if all failed.
    @MainActor
    @discardableResult
    public static func openSettings(
        for kind: MacSystemPermissionKind,
        openURL: (URL) -> Bool = { NSWorkspace.shared.open($0) }
    ) -> URL? {
        for url in candidateURLs(for: kind) {
            if openURL(url) {
                return url
            }
        }
        return nil
    }

    /// Explicitly requests macOS Screen Recording permission via `CGRequestScreenCaptureAccess()`.
    /// MUST ONLY be invoked in response to an explicit user button click (enforced by
    /// `UserInitiatedPermissionAction`) — NEVER on view load or polling!
    @discardableResult
    public static func requestScreenCaptureAccessExplicitly(
        _ action: UserInitiatedPermissionAction,
        requester: () -> Bool = { CGRequestScreenCaptureAccess() }
    ) -> Bool {
        _ = action
        return requester()
    }
}

/// Debounces rapid UI bitrate/FPS tier changes by 150–200ms (default 180ms) before dispatching
/// a single JSON-ABI command.
public final class QualityControlDebouncer: @unchecked Sendable {
    public static let defaultDelayMs: Int = 180

    private let lock = NSLock()
    private let queue: DispatchQueue
    private let delayMs: Int
    private var pendingWork: DispatchWorkItem?
    private var pendingAction: (@Sendable () -> Void)?

    public init(
        delayMs: Int = QualityControlDebouncer.defaultDelayMs,
        clampDelay: Bool = true,
        queue: DispatchQueue = .main
    ) {
        self.delayMs = clampDelay ? min(max(delayMs, 150), 200) : max(delayMs, 1)
        self.queue = queue
    }

    deinit {
        cancel()
    }

    public var isPending: Bool {
        lock.lock()
        defer { lock.unlock() }
        return pendingWork != nil
    }

    public func schedule(_ action: @escaping @Sendable () -> Void) {
        var item: DispatchWorkItem!
        item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let stillCurrent = (self.pendingWork === item)
            if stillCurrent {
                self.pendingWork = nil
                self.pendingAction = nil
            }
            self.lock.unlock()
            if stillCurrent {
                action()
            }
        }
        lock.lock()
        pendingWork?.cancel()
        pendingWork = item
        pendingAction = action
        lock.unlock()
        queue.asyncAfter(deadline: .now() + .milliseconds(delayMs), execute: item)
    }

    /// Immediately cancels any pending delay timer and runs the latest scheduled action once.
    public func flush() {
        lock.lock()
        let oldWork = pendingWork
        let action = pendingAction
        pendingWork = nil
        pendingAction = nil
        lock.unlock()
        oldWork?.cancel()
        action?()
    }

    public func cancel() {
        lock.lock()
        let old = pendingWork
        pendingWork = nil
        pendingAction = nil
        lock.unlock()
        old?.cancel()
    }
}

/// Clipboard sync status badge displayed in the session control drawer.
public enum ClipboardSyncBadge: Sendable, Equatable {
    case idle
    case synced(sizeBucket: String)
    case policyDenied
    case disabled
}

/// Anti-echo `NSPasteboard.changeCount` tracker & zero-content-leak byte-size bucket formatter.
/// Tracks explicit `(before, after)` write ranges (`before < current && current <= after`) so
/// concurrent external writes after our write are NEVER swallowed.
/// NEVER logs clipboard text, hash, or prefix.
public final class ClipboardSyncGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var inFlightBefore: Int?
    private var lastWriteRange: (before: Int, after: Int)?

    public init() {}

    /// Marks the start of a remote-to-local pasteboard write, capturing `changeCount` BEFORE writing.
    public func beginLocalWrite(changeCountBefore: Int) {
        lock.lock()
        inFlightBefore = changeCountBefore
        lock.unlock()
    }

    /// Marks the end of a remote-to-local pasteboard write, recording the `(before, after)` range.
    public func endLocalWrite(changeCountAfter: Int) {
        lock.lock()
        let before = inFlightBefore ?? (changeCountAfter - 1)
        inFlightBefore = nil
        if changeCountAfter > before {
            lastWriteRange = (before: before, after: changeCountAfter)
        }
        lock.unlock()
    }

    /// Convenience helper for recording a single pasteboard changeCount (`(changeCount - 1, changeCount)`).
    public func recordLocalWrite(changeCount: Int) {
        beginLocalWrite(changeCountBefore: changeCount - 1)
        endLocalWrite(changeCountAfter: changeCount)
    }

    /// Returns `true` iff `currentChangeCount` falls strictly inside the recorded `(before, after]`
    /// write range (`before < current && current <= after`). Any concurrent external write advancing
    /// `changeCount` beyond `after` returns `false` and is NEVER swallowed.
    public func shouldSuppressEcho(currentChangeCount: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard let range = lastWriteRange else {
            return false
        }
        return range.before < currentChangeCount && currentChangeCount <= range.after
    }

    /// Formats a strictly redacted byte-size bucket (ZERO clipboard text, hash, or prefix).
    public static func sizeBucket(forByteCount bytes: Int) -> String {
        switch bytes {
        case ...0:
            return "0 B"
        case 1..<1024:
            return "<1 KB"
        case 1024..<(64 * 1024):
            return "1-64 KB"
        default:
            return ">64 KB"
        }
    }

    /// Formats a safe, policy-compliant log line with ZERO clipboard text, hash, or prefix.
    public static func redactedSyncLogLine(byteCount: Int) -> String {
        "clipboard synced (\(sizeBucket(forByteCount: byteCount)))"
    }

    public static let redactedPolicyDeniedLogLine = "clipboard denied by policy"
}
