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
        let copy = Array(storage)
        lock.unlock()
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

/// Redacts URL query strings and bearer/enrollment token fragments before logging.
public func sanitizeLogMessage(_ raw: String) -> String {
    var out = raw
    if let qRange = out.range(of: "?") {
        let prefix = String(out[..<qRange.lowerBound])
        out = prefix + "?<redacted>"
    }
    for marker in ["enrollment_token", "Bearer ", "token="] {
        if let idx = out.range(of: marker) {
            let head = String(out[..<idx.upperBound])
            out = head + "<redacted>"
        }
    }
    return out
}
