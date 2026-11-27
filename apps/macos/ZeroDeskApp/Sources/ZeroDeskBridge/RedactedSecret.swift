// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import Darwin
import Foundation

/// Memory-wiped, log-redacted secret container for enrollment tokens and sensitive credentials.
/// Never prints its underlying bytes in `description`, `debugDescription`, or string interpolation.
public final class RedactedSecret: @unchecked Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    private let lock = NSLock()
    private var storage: ContiguousArray<UInt8>

    public init(_ string: String) {
        self.storage = ContiguousArray(string.utf8)
    }

    public init(bytes: [UInt8]) {
        self.storage = ContiguousArray(bytes)
    }

    deinit {
        wipe()
    }

    public var description: String { "<redacted>" }
    public var debugDescription: String { "<redacted>" }

    public var byteCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return storage.count
    }

    public var isEmpty: Bool {
        byteCount == 0
    }

    /// Overwrites all stored bytes with zeros using `memset_s` and clears the buffer.
    public func wipe() {
        lock.lock()
        defer { lock.unlock() }
        if !storage.isEmpty {
            let count = storage.count
            storage.withUnsafeMutableBufferPointer { buf in
                if let base = buf.baseAddress {
                    _ = memset_s(base, count, 0, count)
                }
            }
            storage.removeAll(keepingCapacity: false)
        }
    }

    /// Exposes a temporary UTF-8 string copy only inside `body` for explicit serialization.
    public func withExposedUTF8String<T>(_ body: (String) throws -> T) rethrows -> T {
        lock.lock()
        var copy = Array(storage)
        lock.unlock()
        defer {
            let count = copy.count
            if count > 0 {
                copy.withUnsafeMutableBufferPointer { buf in
                    if let base = buf.baseAddress {
                        _ = memset_s(base, count, 0, count)
                    }
                }
            }
            copy.removeAll(keepingCapacity: false)
        }
        let str = String(decoding: copy, as: UTF8.self)
        return try body(str)
    }

    /// Returns a snapshot copy of the raw bytes (for unit testing wipe semantics).
    internal func snapshotBytesForTesting() -> [UInt8] {
        lock.lock()
        defer { lock.unlock() }
        return Array(storage)
    }
}

private enum SanitizerRegex {
    static let rules: [(regex: NSRegularExpression, template: String)] = {
        let patterns: [(String, String)] = [
            (#"(?i)\bbearer\s+[^\s,;"]+"#, "Bearer <redacted>"),
            (#"(?i)\bbasic\s+[^\s,;"]+"#, "Basic <redacted>"),
            (#"(?i)([?&][\w-]*token)=[^&\s]+"#, "$1=<redacted>"),
            (#"(?i)("(?:[^"]*(?:token|secret|key)[^"]*)"\s*:\s*)"[^"]*""#, #"$1"<redacted>""#),
            (#"://[^/\s@]+@"#, "://<redacted>@"),
        ]
        return patterns.compactMap { pattern, template in
            guard let regex = try? NSRegularExpression(pattern: pattern, options: []) else {
                return nil
            }
            return (regex, template)
        }
    }()
}

/// Redacts auth headers, URL credentials, query tokens, and JSON secret fields before logging.
public func sanitizeLogMessage(_ raw: String) -> String {
    var out = raw
    for rule in SanitizerRegex.rules {
        let range = NSRange(out.startIndex..<out.endIndex, in: out)
        out = rule.regex.stringByReplacingMatches(
            in: out,
            options: [],
            range: range,
            withTemplate: rule.template
        )
    }
    return out
}
