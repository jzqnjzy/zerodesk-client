// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import CZeroDeskCore
import CoreGraphics
import Darwin
import Foundation
import os

/// Thread-safe Swift bridge over `zerodesk_core`'s narrow C-ABI.
///
/// Concurrency & memory safety invariants:
/// - Owns a dedicated serial OS `Thread` (`"zerodesk-swift-bridge"`) that exclusively executes
///   all `zerodesk_v2_*` handle calls and `poll_event_json_timeout(<=50ms)` — NEVER blocks
///   Swift's cooperative async thread pool.
/// - Every `ZeroDeskOwnedBuffer` returned by Rust is copied into Swift `Data` and immediately
///   freed via `defer { zerodesk_v2_buffer_free(buf) }` on the same thread; raw pointers never
///   escape the bridge thread.
/// - `close()` is idempotent and joins the bridge thread after `zerodesk_v2_destroy(handle)`.
public final class ZeroDeskBridgeClient: @unchecked Sendable {
    public typealias EventHandler = @Sendable (BridgeEventEnvelope) -> Void

    private static let logger = Logger(subsystem: "io.zerodesk.desktop", category: "bridge")
    private static let maxFrameCopyRetries = 3
    private static let eventPollTimeoutMs: UInt32 = 50

    private final class WorkBox: @unchecked Sendable {
        let sem = DispatchSemaphore(value: 0)
        let run: (UInt64) -> Void

        init(_ run: @escaping (UInt64) -> Void) {
            self.run = run
        }
    }

    private final class ResultBox<T>: @unchecked Sendable {
        var result: Result<T, Error>?
    }

    private let condition = NSCondition()
    private var workQueue: [WorkBox] = []
    private var eventHandler: EventHandler?
    private var closing = false
    private var exited = false

    private let eventDeliveryQueue = DispatchQueue(
        label: "io.zerodesk.desktop.events",
        qos: .userInitiated
    )
    private var workerThread: Thread?

    public static func abiVersion() -> UInt32 {
        zerodesk_v2_abi_version()
    }

    /// Runs the zero-write OS capability preflight without creating a session handle.
    public static func osSelftest() throws -> OsSelftestReport {
        var buf = ZeroDeskOwnedBuffer(ptr: nil, len: 0, cap: 0)
        let rc = zerodesk_v2_os_selftest_json(&buf)
        defer { zerodesk_v2_buffer_free(buf) }
        guard rc == ZERODESK_OK else {
            throw ZeroDeskBridgeError.fromCode(rc)
        }
        let data = copyOwnedBuffer(buf)
        do {
            return try JSONDecoder().decode(OsSelftestReport.self, from: data)
        } catch {
            throw ZeroDeskBridgeError.protocolError("decode os_selftest JSON failed: \(error)")
        }
    }

    public init() throws {
        let initSem = DispatchSemaphore(value: 0)
        final class InitResultBox: @unchecked Sendable {
            var error: ZeroDeskBridgeError?
        }
        let initBox = InitResultBox()

        let thread = Thread { [weak self] in
            var handle: UInt64 = 0
            let rc = zerodesk_v2_create(&handle)
            if rc != ZERODESK_OK || handle == 0 {
                initBox.error = rc == ZERODESK_OK ? .internalError : ZeroDeskBridgeError.fromCode(rc)
                initSem.signal()
                return
            }
            initSem.signal()
            self?.runBridgeLoop(handle: handle)
        }
        thread.name = "zerodesk-swift-bridge"
        self.workerThread = thread
        thread.start()

        initSem.wait()
        if let err = initBox.error {
            condition.lock()
            closing = true
            exited = true
            condition.broadcast()
            condition.unlock()
            throw err
        }
    }

    deinit {
        close()
    }

    /// Registers or clears the asynchronous bridge event callback.
    public func setEventHandler(_ handler: EventHandler?) {
        condition.lock()
        eventHandler = handler
        condition.signal()
        condition.unlock()
    }

    /// Idempotently destroys the underlying Rust runtime handle and joins the dedicated bridge
    /// thread so zero callbacks or FFI calls can execute after `close()` returns.
    public func close() {
        condition.lock()
        closing = true
        eventHandler = nil
        condition.broadcast()
        while !exited {
            condition.wait()
        }
        condition.unlock()
        workerThread = nil
    }

    /// Executes a raw JSON command against `V2BridgeRuntime::exec_json`.
    public func execRawJSON(_ json: String) throws -> Data {
        try performOnBridgeThread { handle in
            let utf8 = Array(json.utf8)
            var outBuf = ZeroDeskOwnedBuffer(ptr: nil, len: 0, cap: 0)
            let rc: Int32 = utf8.withUnsafeBufferPointer { raw in
                zerodesk_v2_exec_json(handle, raw.baseAddress, raw.count, &outBuf)
            }
            defer { zerodesk_v2_buffer_free(outBuf) }
            guard rc == ZERODESK_OK else {
                throw ZeroDeskBridgeError.fromCode(rc)
            }
            return Self.copyOwnedBuffer(outBuf)
        }
    }

    /// Executes a JSON command and decodes the structured `BridgeCommandReply`.
    public func execCommand(_ payload: [String: Any]) throws -> BridgeCommandReply {
        var dict = payload
        dict["v"] = Int(ZERODESK_V2_ABI_VERSION)
        let encoded: Data
        do {
            encoded = try JSONSerialization.data(withJSONObject: dict, options: [])
        } catch {
            throw ZeroDeskBridgeError.protocolError("encode command JSON failed: \(error)")
        }
        let jsonStr = String(decoding: encoded, as: UTF8.self)
        let replyData = try execRawJSON(jsonStr)
        do {
            return try JSONDecoder().decode(BridgeCommandReply.self, from: replyData)
        } catch {
            throw ZeroDeskBridgeError.protocolError("decode command reply failed: \(error)")
        }
    }

    /// Fetches the current redacted `BridgeSnapshot` JSON from Rust.
    public func snapshotRawJSON() throws -> Data {
        try performOnBridgeThread { handle in
            var outBuf = ZeroDeskOwnedBuffer(ptr: nil, len: 0, cap: 0)
            let rc = zerodesk_v2_snapshot_json(handle, &outBuf)
            defer { zerodesk_v2_buffer_free(outBuf) }
            guard rc == ZERODESK_OK else {
                throw ZeroDeskBridgeError.fromCode(rc)
            }
            return Self.copyOwnedBuffer(outBuf)
        }
    }

    public func snapshot() throws -> BridgeSnapshot {
        let data = try snapshotRawJSON()
        do {
            return try JSONDecoder().decode(BridgeSnapshot.self, from: data)
        } catch {
            throw ZeroDeskBridgeError.protocolError("decode snapshot JSON failed: \(error)")
        }
    }

    /// Ensures the config directory has `0700` permissions, saves config via Rust `save_config`,
    /// and verifies/enforces `0600` permissions on the persisted config file.
    public func saveConfig0600(at path: String, config: BridgeConfigInput) throws -> BridgeCommandReply {
        let url = URL(fileURLWithPath: path)
        let parentDir = url.deletingLastPathComponent().path
        try Self.ensureDirectory0700(parentDir)
        try Self.ensureDirectory0700(config.identityDir)

        var cfgObj: [String: Any] = [
            "v": 1,
            "control_plane_endpoint": config.controlPlaneEndpoint,
            "signaling_addr": config.signalingAddr,
            "identity_dir": config.identityDir,
            "home_region": config.homeRegion,
            "codec": config.codec,
            "fps": Int(config.fps),
            "watchdog_timeout_ms": 3000,
            "keepalive_interval_ms": 500,
            "lease_renew_interval_sec": 15,
            "bw_cap_kbps": 20_000,
            "transport_mode": config.transportMode,
            "udp_probe_timeout_ms": 800,
        ]
        if let tls = config.signalingTls {
            cfgObj["signaling_tls"] = tls
        }
        if let edgeA = config.edgeA, !edgeA.isEmpty {
            cfgObj["edge_a"] = edgeA
        }
        if let edgeB = config.edgeB, !edgeB.isEmpty {
            cfgObj["edge_b"] = edgeB
        }
        if let ca = config.caDerPath, !ca.isEmpty {
            cfgObj["ca_der_path"] = ca
        }

        let reply: BridgeCommandReply
        if let secret = config.enrollmentToken, !secret.isEmpty {
            reply = try secret.withExposedUTF8String { token in
                cfgObj["enrollment_token"] = token
                return try execCommand([
                    "cmd": "save_config",
                    "path": path,
                    "config": cfgObj,
                ])
            }
        } else {
            reply = try execCommand([
                "cmd": "save_config",
                "path": path,
                "config": cfgObj,
            ])
        }

        if reply.ok {
            if chmod(path, 0o600) != 0 {
                throw ZeroDeskBridgeError.ioError("chmod(0600) failed for config file")
            }
        }
        return reply
    }

    public func loadConfig(at path: String) throws -> BridgeCommandReply {
        try execCommand(["cmd": "load_config", "path": path])
    }

    public func sendClipboardPNG(_ pngData: Data) throws -> BridgeCommandReply {
        let data = try performOnBridgeThread { handle in
            var outBuf = ZeroDeskOwnedBuffer(ptr: nil, len: 0, cap: 0)
            let rc: Int32 = pngData.withUnsafeBytes { raw in
                let ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
                return zerodesk_v2_send_clipboard_png(handle, ptr, raw.count, &outBuf)
            }
            defer { zerodesk_v2_buffer_free(outBuf) }
            guard rc == ZERODESK_OK else {
                throw ZeroDeskBridgeError.fromCode(rc)
            }
            return Self.copyOwnedBuffer(outBuf)
        }
        return try JSONDecoder().decode(BridgeCommandReply.self, from: data)
    }

    public func sendFile(at path: String) throws -> BridgeCommandReply {
        let data = try performOnBridgeThread { handle in
            let utf8 = Array(path.utf8)
            var outBuf = ZeroDeskOwnedBuffer(ptr: nil, len: 0, cap: 0)
            let rc: Int32 = utf8.withUnsafeBufferPointer { raw in
                zerodesk_v2_send_file(handle, raw.baseAddress, raw.count, &outBuf)
            }
            defer { zerodesk_v2_buffer_free(outBuf) }
            guard rc == ZERODESK_OK else {
                throw ZeroDeskBridgeError.fromCode(rc)
            }
            return Self.copyOwnedBuffer(outBuf)
        }
        return try JSONDecoder().decode(BridgeCommandReply.self, from: data)
    }

    /// Two-phase frame fetch (`frame_info` -> allocate -> `take_latest_frame`, up to 3 retries on
    /// `BUFFER_TOO_SMALL`) returning a ready-to-render `CGImage`, or `nil` when no frame exists.
    public func fetchLatestFrameCGImage() throws -> CapturedFrameImage? {
        try performOnBridgeThread { handle in
            for _ in 0..<Self.maxFrameCopyRetries {
                var info = ZeroDeskFrameInfo(
                    seq: 0,
                    width: 0,
                    height: 0,
                    stride: 0,
                    pixel_format: 0,
                    byte_len: 0,
                    pts_ms: 0,
                    dropped_ui_frames: 0
                )
                let infoRc = zerodesk_v2_frame_info(handle, &info)
                if infoRc == ZERODESK_ERR_NO_FRAME {
                    return nil
                }
                guard infoRc == ZERODESK_OK else {
                    throw ZeroDeskBridgeError.fromCode(infoRc)
                }
                guard info.byte_len > 0, info.width > 0, info.height > 0 else {
                    throw ZeroDeskBridgeError.protocolError("invalid frame metadata dimensions")
                }

                let cap = info.byte_len
                var pixelData = Data(count: cap)
                var copiedInfo = info
                let takeRc: Int32 = pixelData.withUnsafeMutableBytes { raw in
                    let ptr = raw.baseAddress?.assumingMemoryBound(to: UInt8.self)
                    return zerodesk_v2_take_latest_frame(handle, ptr, cap, &copiedInfo)
                }
                if takeRc == ZERODESK_ERR_NO_FRAME {
                    return nil
                }
                if takeRc == ZERODESK_ERR_BUFFER_TOO_SMALL {
                    continue
                }
                guard takeRc == ZERODESK_OK else {
                    throw ZeroDeskBridgeError.fromCode(takeRc)
                }
                guard copiedInfo.byte_len <= cap,
                      copiedInfo.width > 0,
                      copiedInfo.height > 0,
                      copiedInfo.stride >= copiedInfo.width * 4 else {
                    throw ZeroDeskBridgeError.protocolError("frame byte_len/stride invariant violation")
                }

                let slice = copiedInfo.byte_len == cap ? pixelData : pixelData.prefix(copiedInfo.byte_len)
                let cgImage = try Self.makeCGImage(
                    data: slice,
                    width: Int(copiedInfo.width),
                    height: Int(copiedInfo.height),
                    stride: Int(copiedInfo.stride),
                    pixelFormat: copiedInfo.pixel_format
                )
                return CapturedFrameImage(
                    seq: copiedInfo.seq,
                    width: Int(copiedInfo.width),
                    height: Int(copiedInfo.height),
                    ptsMs: copiedInfo.pts_ms,
                    droppedUiFrames: copiedInfo.dropped_ui_frames,
                    image: cgImage
                )
            }
            throw ZeroDeskBridgeError.bufferTooSmall
        }
    }

    private func performOnBridgeThread<T: Sendable>(_ op: @escaping @Sendable (UInt64) throws -> T) throws -> T {
        let box = ResultBox<T>()
        let work = WorkBox { handle in
            box.result = Result { try op(handle) }
        }

        condition.lock()
        if closing || exited {
            condition.unlock()
            throw ZeroDeskBridgeError.closed
        }
        workQueue.append(work)
        condition.signal()
        condition.unlock()

        work.sem.wait()
        guard let res = box.result else {
            throw ZeroDeskBridgeError.closed
        }
        return try res.get()
    }

    private func runBridgeLoop(handle: UInt64) {
        defer {
            let rc = zerodesk_v2_destroy(handle)
            if rc != ZERODESK_OK {
                Self.logger.error("zerodesk_v2_destroy returned code \(rc, privacy: .public)")
            }
            condition.lock()
            let residual = workQueue
            workQueue.removeAll()
            exited = true
            condition.broadcast()
            condition.unlock()
            for item in residual {
                item.sem.signal()
            }
        }

        while true {
            var pending: [WorkBox] = []
            var activeHandler: EventHandler?
            var shouldStop = false

            condition.lock()
            if !workQueue.isEmpty {
                pending = workQueue
                workQueue.removeAll(keepingCapacity: true)
            } else if closing {
                shouldStop = true
            } else if let handler = eventHandler {
                activeHandler = handler
            } else {
                // Idle with no event listener: sleep cleanly with zero CPU usage.
                condition.wait()
                condition.unlock()
                continue
            }
            condition.unlock()

            for item in pending {
                item.run(handle)
                item.sem.signal()
            }

            if shouldStop {
                break
            }

            if let handler = activeHandler {
                var evBuf = ZeroDeskOwnedBuffer(ptr: nil, len: 0, cap: 0)
                let rc = zerodesk_v2_poll_event_json_timeout(handle, Self.eventPollTimeoutMs, &evBuf)
                if rc == ZERODESK_OK {
                    let data = Self.copyOwnedBuffer(evBuf)
                    zerodesk_v2_buffer_free(evBuf)
                    if let envelope = Self.decodeEventEnvelope(from: data) {
                        Self.logger.debug(
                            "bridge event kind=\(envelope.kind, privacy: .public) seq=\(envelope.seq, privacy: .public)"
                        )
                        eventDeliveryQueue.async {
                            handler(envelope)
                        }
                    }
                } else {
                    zerodesk_v2_buffer_free(evBuf)
                    if rc != ZERODESK_ERR_TIMEOUT && rc != ZERODESK_ERR_NO_EVENT {
                        let msg = sanitizeLogMessage("poll_event_json_timeout rc=\(rc)")
                        Self.logger.warning("bridge poll error: \(msg, privacy: .private(mask: .hash))")
                    }
                }
            }
        }
    }

    private static func copyOwnedBuffer(_ buf: ZeroDeskOwnedBuffer) -> Data {
        guard let ptr = buf.ptr, buf.len > 0 else {
            return Data()
        }
        return Data(bytes: ptr, count: buf.len)
    }

    private static func decodeEventEnvelope(from data: Data) -> BridgeEventEnvelope? {
        let raw = String(decoding: data, as: UTF8.self)
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let kind = obj["kind"] as? String else {
            return nil
        }
        let v = (obj["v"] as? NSNumber)?.uint32Value ?? 1
        let seq = (obj["seq"] as? NSNumber)?.uint64Value ?? 0
        var flatPayload: [String: String] = [:]
        if let payload = obj["payload"] as? [String: Any] {
            for (k, val) in payload {
                if let s = val as? String {
                    flatPayload[k] = s
                } else if let n = val as? NSNumber {
                    flatPayload[k] = n.stringValue
                }
            }
        }
        return BridgeEventEnvelope(v: v, seq: seq, kind: kind, rawJSON: raw, payloadJSON: flatPayload)
    }

    private static func makeCGImage(
        data: Data,
        width: Int,
        height: Int,
        stride: Int,
        pixelFormat: UInt32
    ) throws -> CGImage {
        let bitmapInfo: CGBitmapInfo
        if pixelFormat == ZERODESK_PIXEL_FORMAT_BGRA8 {
            bitmapInfo = CGBitmapInfo(
                rawValue: CGBitmapInfo.byteOrder32Little.rawValue
                    | CGImageAlphaInfo.premultipliedFirst.rawValue
            )
        } else if pixelFormat == ZERODESK_PIXEL_FORMAT_RGBA8 {
            bitmapInfo = CGBitmapInfo(
                rawValue: CGBitmapInfo.byteOrder32Big.rawValue
                    | CGImageAlphaInfo.premultipliedLast.rawValue
            )
        } else {
            throw ZeroDeskBridgeError.protocolError("unsupported pixel_format \(pixelFormat)")
        }

        guard let provider = CGDataProvider(data: data as CFData) else {
            throw ZeroDeskBridgeError.internalError
        }
        guard let cg = CGImage(
            width: width,
            height: height,
            bitsPerComponent: 8,
            bitsPerPixel: 32,
            bytesPerRow: stride,
            space: CGColorSpaceCreateDeviceRGB(),
            bitmapInfo: bitmapInfo,
            provider: provider,
            decode: nil,
            shouldInterpolate: true,
            intent: .defaultIntent
        ) else {
            throw ZeroDeskBridgeError.internalError
        }
        return cg
    }

    private static func ensureDirectory0700(_ path: String) throws {
        do {
            try FileManager.default.createDirectory(
                atPath: path,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw ZeroDeskBridgeError.ioError("create dir \(path) failed: \(error)")
        }
        if chmod(path, 0o700) != 0 {
            throw ZeroDeskBridgeError.ioError("chmod(0700) failed for \(path)")
        }
    }
}
