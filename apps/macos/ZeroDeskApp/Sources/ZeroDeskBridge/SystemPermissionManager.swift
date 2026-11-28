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

/// Pure, unit-testable System Settings deep-link builder & explicit Screen Recording request helper.
public enum SystemPermissionLinks {
    /// Ordered deep-link candidates for opening macOS System Settings -> Privacy & Security.
    ///
    /// Order:
    /// 1. macOS 13+ System Settings extension deep link (`Privacy_ScreenCapture` / `Privacy_Accessibility`)
    /// 2. Legacy System Preferences deep link (`com.apple.preference.security?Privacy_*`)
    /// 3. Security & Privacy pane fallback (macOS 13+ then legacy)
    public static func candidateURLs(for kind: MacSystemPermissionKind) -> [URL] {
        let rawStrings: [String]
        switch kind {
        case .screenRecording:
            rawStrings = [
                "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_ScreenCapture",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture",
                "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
                "x-apple.systempreferences:com.apple.preference.security",
            ]
        case .accessibility:
            rawStrings = [
                "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_Accessibility",
                "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility",
                "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension",
                "x-apple.systempreferences:com.apple.preference.security",
            ]
        }
        return rawStrings.compactMap(URL.init(string:))
    }

    /// Tries each deep-link URL in priority order until `openURL` returns `true`.
    /// Returns the URL that succeeded, or `nil` if all failed.
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
    /// MUST ONLY be invoked in response to an explicit user button click — NEVER on view load or polling!
    @discardableResult
    public static func requestScreenCaptureAccessExplicitly() -> Bool {
        CGRequestScreenCaptureAccess()
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

    public init(delayMs: Int = QualityControlDebouncer.defaultDelayMs, queue: DispatchQueue = .main) {
        self.delayMs = min(max(delayMs, 150), 200)
        self.queue = queue
    }

    deinit {
        cancel()
    }

    public func schedule(_ action: @escaping @Sendable () -> Void) {
        let item = DispatchWorkItem(block: action)
        lock.lock()
        pendingWork?.cancel()
        pendingWork = item
        lock.unlock()
        queue.asyncAfter(deadline: .now() + .milliseconds(delayMs), execute: item)
    }

    public func cancel() {
        lock.lock()
        let old = pendingWork
        pendingWork = nil
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
/// NEVER logs clipboard text, hash, or prefix.
public final class ClipboardSyncGuard: @unchecked Sendable {
    private let lock = NSLock()
    private var lastWrittenChangeCount: Int?

    public init() {}

    /// Records the `NSPasteboard.changeCount` produced by a remote-to-local clipboard write.
    public func recordLocalWrite(changeCount: Int) {
        lock.lock()
        lastWrittenChangeCount = changeCount
        lock.unlock()
    }

    /// Returns `true` if `currentChangeCount` matches the last remote-originated write
    /// (meaning the local poll must skip it to prevent an echo loop).
    public func shouldSuppressEcho(currentChangeCount: Int) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return lastWrittenChangeCount == currentChangeCount
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
