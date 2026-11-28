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
        private let lock = NSLock()
        private var storage: Result<T, Error>?

        func store(_ value: Result<T, Error>) {
            lock.lock()
            storage = value
            lock.unlock()
        }

        func load() -> Result<T, Error>? {
            lock.lock()
            defer { lock.unlock() }
            return storage
        }
    }

    private final class BridgeState: @unchecked Sendable {
        static let onEventQueueKey = DispatchSpecificKey<UInt8>()

        let condition = NSCondition()
        var workQueue: [WorkBox] = []
        var eventHandler: EventHandler?
        var handlerEpoch: UInt64 = 0
        var closing = false
        var exited = false
        var workerThread: Thread?
        let eventDeliveryQueue: DispatchQueue

        init() {
            let queue = DispatchQueue(
                label: "io.zerodesk.desktop.events",
                qos: .userInitiated
            )
            queue.setSpecific(key: Self.onEventQueueKey, value: 1)
            self.eventDeliveryQueue = queue
        }

        func isEpochActive(_ epoch: UInt64) -> Bool {
            condition.lock()
            defer { condition.unlock() }
            return !closing && handlerEpoch == epoch
        }
    }

    private let state = BridgeState()

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
        let bridgeState = self.state

        let thread = Thread {
            var handle: UInt64 = 0
            let rc = zerodesk_v2_create(&handle)
            if rc != ZERODESK_OK || handle == 0 {
                initBox.error = rc == ZERODESK_OK ? .internalError : ZeroDeskBridgeError.fromCode(rc)
                initSem.signal()
                return
            }
            initSem.signal()
            Self.runBridgeLoop(state: bridgeState, handle: handle)
        }
        thread.name = "zerodesk-swift-bridge"
        thread.stackSize = 2 * 1024 * 1024
        bridgeState.condition.lock()
        bridgeState.workerThread = thread
        bridgeState.condition.unlock()
        thread.start()

        initSem.wait()
        if let err = initBox.error {
            bridgeState.condition.lock()
            bridgeState.closing = true
            bridgeState.exited = true
            bridgeState.workerThread = nil
            bridgeState.condition.broadcast()
            bridgeState.condition.unlock()
            throw err
        }
    }

    deinit {
        close()
    }

    /// Registers or clears the asynchronous bridge event callback.
    public func setEventHandler(_ handler: EventHandler?) {
        state.condition.lock()
        state.handlerEpoch &+= 1
        state.eventHandler = handler
        state.condition.signal()
        state.condition.unlock()
    }

    /// Idempotently destroys the underlying Rust runtime handle and joins the dedicated bridge
    /// thread so zero callbacks or FFI calls can execute after `close()` returns.
    public func close() {
        state.condition.lock()
        state.closing = true
        state.handlerEpoch &+= 1
        state.eventHandler = nil
        state.condition.broadcast()
        while !state.exited {
            state.condition.wait()
        }
        state.workerThread = nil
        state.condition.unlock()
        if DispatchQueue.getSpecific(key: BridgeState.onEventQueueKey) == nil {
            state.eventDeliveryQueue.sync {}
        }
    }

    /// Executes a raw JSON command against `V2BridgeRuntime::exec_json`.
    public func execRawJSON(_ json: String, timeoutMs: UInt32? = nil) throws -> Data {
        try performOnBridgeThread(timeoutMs: timeoutMs) { handle in
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
    public func execCommand(_ payload: [String: Any], timeoutMs: UInt32? = nil) throws -> BridgeCommandReply {
        var dict = payload
        dict["v"] = Int(ZERODESK_V2_ABI_VERSION)
        let encoded: Data
        do {
            encoded = try JSONSerialization.data(withJSONObject: dict, options: [])
        } catch {
            throw ZeroDeskBridgeError.protocolError("encode command JSON failed: \(error)")
        }
        let jsonStr = String(decoding: encoded, as: UTF8.self)
        let replyData = try execRawJSON(jsonStr, timeoutMs: timeoutMs)
        do {
            return try JSONDecoder().decode(BridgeCommandReply.self, from: replyData)
        } catch {
            throw ZeroDeskBridgeError.protocolError("decode command reply failed: \(error)")
        }
    }

    /// Executes the Phase 8A startup handshake returning `abi_version` and `caps`.
    /// Validates `abi_version` is in supported range `1...2` (fails closed with `.unsupportedAbi`).
    public func handshake() throws -> HandshakeCapabilitiesData {
        let raw = try execRawJSON(#"{"v":1,"cmd":"handshake"}"#)
        let decoded = try JSONDecoder().decode(BridgeTypedReply<HandshakeCapabilitiesData>.self, from: raw)
        guard decoded.ok, let data = decoded.data else {
            throw ZeroDeskBridgeError.protocolError(decoded.error ?? decoded.errorCode ?? "handshake failed")
        }
        guard (1...2).contains(data.abiVersion) else {
            throw ZeroDeskBridgeError.unsupportedAbi(data.abiVersion)
        }
        return data
    }

    /// Queries structured macOS permission status (`screen_capture_granted`, `accessibility_granted`,
    /// `probe_source`, `enable_os_input`) from Rust without popping any OS permission dialog.
    public func getPermissions() throws -> PermissionStatusReport {
        let raw = try execRawJSON(#"{"v":1,"cmd":"get_permissions"}"#)
        let decoded = try JSONDecoder().decode(BridgeTypedReply<PermissionStatusReport>.self, from: raw)
        guard decoded.ok, let data = decoded.data else {
            throw ZeroDeskBridgeError.protocolError(decoded.error ?? decoded.errorCode ?? "get_permissions failed")
        }
        return data
    }

    /// Requests toggling the per-session `enable_os_input` gate via JSON-ABI (UI MUST await Rust ack).
    @discardableResult
    public func setInputEnabled(_ enabled: Bool, reason: String? = nil) throws -> BridgeCommandReply {
        var payload: [String: Any] = [
            "cmd": "set_input_enabled",
            "enabled": enabled,
        ]
        if let reason {
            payload["reason"] = reason
        }
        return try execCommand(payload)
    }

    /// Requests bitrate tier (`0` = Auto, or kbps) & FPS cap (`30`/`60`) update via JSON-ABI.
    @discardableResult
    public func setVideoQuality(bitrateKbps: UInt32, fpsCap: UInt32) throws -> BridgeCommandReply {
        try execCommand([
            "cmd": "set_video_quality",
            "bitrate_kbps": Int(bitrateKbps),
            "fps_cap": Int(fpsCap),
        ])
    }

    /// Toggles clipboard synchronization via JSON-ABI.
    @discardableResult
    public func setClipboardSync(_ enabled: Bool) throws -> BridgeCommandReply {
        try execCommand([
            "cmd": "set_clipboard_sync",
            "enabled": enabled,
        ])
    }

    /// Requests a codec selection (`auto` / `h264` / `hevc` / `vp9` / `av1`) via JSON-ABI.
    @discardableResult
    public func setCodec(_ codec: String) throws -> BridgeCommandReply {
        try execCommand([
            "cmd": "set_codec",
            "codec": codec,
        ])
    }

    /// Cancels an in-flight file transfer by ID (passes `UInt64` safely via `NSNumber` without overflow).
    @discardableResult
    public func cancelFile(transferId: UInt64) throws -> BridgeCommandReply {
        try execCommand([
            "cmd": "cancel_file",
            "transfer_id": NSNumber(value: transferId),
        ])
    }

    /// Sends a mouse HID event (`move_abs`, `button_down`, `button_up`, `wheel`).
    @discardableResult
    public func sendMouse(
        kind: RemoteMouseKind,
        x: Int,
        y: Int,
        buttons: UInt8,
        wheelDx: Int16 = 0,
        wheelDy: Int16 = 0
    ) throws -> BridgeCommandReply {
        let clampedX = min(max(x, 0), Int(UInt16.max))
        let clampedY = min(max(y, 0), Int(UInt16.max))
        let payload: [String: Any] = [
            "cmd": "send_hid_mouse",
            "mouse_kind": kind.rawValue,
            "x": clampedX,
            "y": clampedY,
            "buttons": Int(buttons & HidMouseButtonMask.validMask),
            "wheel_dx": Int(wheelDx),
            "wheel_dy": Int(wheelDy),
        ]
        return try execCommand(payload)
    }

    /// Sends a keyboard HID event (`key_down` / `key_up` via `send_hid_key`).
    @discardableResult
    public func sendKey(
        usageId: UInt16,
        down: Bool,
        modifiers: UInt8,
        unicodeScalar: UInt32 = 0
    ) throws -> BridgeCommandReply {
        var payload: [String: Any] = [
            "cmd": "send_hid_key",
            "usb_hid_usage": Int(usageId),
            "down": down,
            "modifiers": Int(modifiers & HidModifierMask.validMask),
        ]
        if unicodeScalar != 0 {
            payload["unicode_scalar"] = Int(unicodeScalar)
        }
        return try execCommand(payload)
    }

    /// Synchronously flushes `release_all` on the bridge worker thread within a strict bounded budget
    /// (`<= 200 ms`) so `resignKey`, `didResignActive`, and app teardown never hang the UI thread.
    @discardableResult
    public func releaseAllInput(
        keys: [UInt16] = [],
        buttons: UInt8 = 0,
        reason: ReleaseReason = .sessionLeftConnected,
        timeoutMs: UInt32 = PressedInputTracker.defaultReleaseTimeoutMs
    ) throws -> BridgeCommandReply {
        let boundedTimeout = min(max(timeoutMs, 1), PressedInputTracker.maxReleaseTimeoutMs)
        var payload: [String: Any] = [
            "cmd": "release_all",
            "keys": keys.map { Int($0) },
            "buttons": Int(buttons & HidMouseButtonMask.validMask),
            "reason": reason.rawValue,
        ]
        if reason == .emergencyEscapeHotkey {
            payload["emergency_escape"] = true
        }
        return try execCommand(payload, timeoutMs: boundedTimeout)
    }

    /// Non-blocking FIFO enqueue of a fire-and-forget JSON command onto the single worker thread.
    /// Any subsequent synchronous `releaseAllInput` executes strictly AFTER enqueued commands.
    private func enqueueFireAndForgetCommand(_ payload: [String: Any]) {
        var dict = payload
        dict["v"] = Int(ZERODESK_V2_ABI_VERSION)
        guard let encoded = try? JSONSerialization.data(withJSONObject: dict, options: []) else {
            return
        }
        let utf8 = Array(encoded)
        let work = WorkBox { handle in
            var outBuf = ZeroDeskOwnedBuffer(ptr: nil, len: 0, cap: 0)
            _ = utf8.withUnsafeBufferPointer { raw in
                zerodesk_v2_exec_json(handle, raw.baseAddress, raw.count, &outBuf)
            }
            zerodesk_v2_buffer_free(outBuf)
        }

        state.condition.lock()
        if !state.closing && !state.exited {
            state.workQueue.append(work)
            state.condition.signal()
        }
        state.condition.unlock()
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
        do {
            return try JSONDecoder().decode(BridgeCommandReply.self, from: data)
        } catch {
            throw ZeroDeskBridgeError.protocolError("decode send_clipboard_png reply failed: \(error)")
        }
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
        do {
            return try JSONDecoder().decode(BridgeCommandReply.self, from: data)
        } catch {
            throw ZeroDeskBridgeError.protocolError("decode send_file reply failed: \(error)")
        }
    }

    /// Two-phase raw BGRA frame fetch (`frame_info` -> allocate -> `take_latest_frame`, up to 3
    /// retries on `BUFFER_TOO_SMALL`) returning raw pixel bytes for direct Metal `MTLTexture.replaceRegion`
    /// upload with ZERO `CGImage` conversion.
    public func fetchLatestFrameBGRA() throws -> CapturedBGRAFrame? {
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
                      copiedInfo.height > 0 else {
                    throw ZeroDeskBridgeError.protocolError("frame metadata invariant violation")
                }

                let width = Int(copiedInfo.width)
                let height = Int(copiedInfo.height)
                let stride = Int(copiedInfo.stride)
                let (rowBytes, rowOverflow) = width.multipliedReportingOverflow(by: 4)
                guard !rowOverflow, stride >= rowBytes else {
                    throw ZeroDeskBridgeError.protocolError("frame stride invariant violation")
                }
                let (prefixBytes, prefixOverflow) = (height - 1).multipliedReportingOverflow(by: stride)
                let (requiredBytes, totalOverflow) = prefixBytes.addingReportingOverflow(rowBytes)
                guard !prefixOverflow, !totalOverflow, copiedInfo.byte_len >= requiredBytes else {
                    throw ZeroDeskBridgeError.protocolError("frame byte_len smaller than required image bytes")
                }

                let slice = copiedInfo.byte_len == cap ? pixelData : pixelData.prefix(copiedInfo.byte_len)
                return CapturedBGRAFrame(
                    seq: copiedInfo.seq,
                    width: width,
                    height: height,
                    stride: stride,
                    pixelFormat: copiedInfo.pixel_format,
                    ptsMs: copiedInfo.pts_ms,
                    droppedUiFrames: copiedInfo.dropped_ui_frames,
                    data: slice
                )
            }
            throw ZeroDeskBridgeError.bufferTooSmall
        }
    }

    /// Two-phase frame fetch (`frame_info` -> allocate -> `take_latest_frame`, up to 3 retries on
    /// `BUFFER_TOO_SMALL`) returning a ready-to-render `CGImage`, or `nil` when no frame exists.
    public func fetchLatestFrameCGImage() throws -> CapturedFrameImage? {
        guard let raw = try fetchLatestFrameBGRA() else {
            return nil
        }
        let cgImage = try Self.makeCGImage(
            data: raw.data,
            width: raw.width,
            height: raw.height,
            stride: raw.stride,
            pixelFormat: raw.pixelFormat
        )
        return CapturedFrameImage(
            seq: raw.seq,
            width: raw.width,
            height: raw.height,
            ptsMs: raw.ptsMs,
            droppedUiFrames: raw.droppedUiFrames,
            image: cgImage
        )
    }

    private func performOnBridgeThread<T: Sendable>(
        timeoutMs: UInt32? = nil,
        _ op: @escaping @Sendable (UInt64) throws -> T
    ) throws -> T {
        let box = ResultBox<T>()
        let work = WorkBox { handle in
            box.store(Result { try op(handle) })
        }

        state.condition.lock()
        if state.closing || state.exited {
            state.condition.unlock()
            throw ZeroDeskBridgeError.closed
        }
        state.workQueue.append(work)
        state.condition.signal()
        state.condition.unlock()

        if let timeoutMs {
            let waitRes = work.sem.wait(timeout: .now() + .milliseconds(Int(timeoutMs)))
            if waitRes == .timedOut {
                throw ZeroDeskBridgeError.timeout
            }
        } else {
            work.sem.wait()
        }
        guard let res = box.load() else {
            throw ZeroDeskBridgeError.closed
        }
        return try res.get()
    }

    private static func runBridgeLoop(state: BridgeState, handle: UInt64) {
        defer {
            let rc = zerodesk_v2_destroy(handle)
            if rc != ZERODESK_OK {
                Self.logger.error("zerodesk_v2_destroy returned code \(rc, privacy: .public)")
            }
            state.condition.lock()
            let residual = state.workQueue
            state.workQueue.removeAll()
            state.exited = true
            state.condition.broadcast()
            state.condition.unlock()
            for item in residual {
                item.sem.signal()
            }
        }

        while true {
            var pending: [WorkBox] = []
            var activeHandler: EventHandler?
            var activeEpoch: UInt64 = 0
            var shouldStop = false

            state.condition.lock()
            if !state.workQueue.isEmpty {
                pending = state.workQueue
                state.workQueue.removeAll(keepingCapacity: true)
            } else if state.closing {
                shouldStop = true
            } else if let handler = state.eventHandler {
                activeHandler = handler
                activeEpoch = state.handlerEpoch
            } else {
                // Idle with no event listener: sleep cleanly with zero CPU usage.
                state.condition.wait()
                state.condition.unlock()
                continue
            }
            state.condition.unlock()

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
                        let deliveryEpoch = activeEpoch
                        if state.isEpochActive(deliveryEpoch) {
                            state.eventDeliveryQueue.async {
                                guard state.isEpochActive(deliveryEpoch) else { return }
                                handler(envelope)
                            }
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
              let kind = (obj["kind"] as? String) ?? (obj["type"] as? String) else {
            return nil
        }
        let v = (obj["v"] as? NSNumber)?.uint32Value ?? 1
        let seq = (obj["seq"] as? NSNumber)?.uint64Value ?? 0
        var flatPayload: [String: String] = [:]
        var boolPayload: [String: Bool] = [:]
        if let payload = obj["payload"] as? [String: Any] {
            for (k, val) in payload {
                if let s = val as? String {
                    flatPayload[k] = s
                } else if let n = val as? NSNumber {
                    if CFGetTypeID(n) == CFBooleanGetTypeID() {
                        let b = n.boolValue
                        boolPayload[k] = b
                        flatPayload[k] = b ? "true" : "false"
                    } else {
                        flatPayload[k] = n.stringValue
                    }
                }
            }
        }
        return BridgeEventEnvelope(
            v: v,
            seq: seq,
            kind: kind,
            rawJSON: raw,
            payloadJSON: flatPayload,
            payloadBools: boolPayload
        )
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

extension ZeroDeskBridgeClient: RemoteInputSink {
    public func sendKeyEvent(usageId: UInt16, down: Bool, modifiers: UInt8) {
        enqueueFireAndForgetCommand([
            "cmd": "send_hid_key",
            "usb_hid_usage": Int(usageId),
            "down": down,
            "modifiers": Int(modifiers & HidModifierMask.validMask),
        ])
    }

    public func sendMouseEvent(
        kind: RemoteMouseKind,
        x: Int,
        y: Int,
        buttons: UInt8,
        wheelDx: Int16,
        wheelDy: Int16
    ) {
        let clampedX = min(max(x, 0), Int(UInt16.max))
        let clampedY = min(max(y, 0), Int(UInt16.max))
        enqueueFireAndForgetCommand([
            "cmd": "send_hid_mouse",
            "mouse_kind": kind.rawValue,
            "x": clampedX,
            "y": clampedY,
            "buttons": Int(buttons & HidMouseButtonMask.validMask),
            "wheel_dx": Int(wheelDx),
            "wheel_dy": Int(wheelDy),
        ])
    }

    public func flushReleaseAll(
        keys: [UInt16],
        buttons: UInt8,
        reason: ReleaseReason,
        timeoutMs: UInt32
    ) {
        _ = try? releaseAllInput(
            keys: keys,
            buttons: buttons,
            reason: reason,
            timeoutMs: timeoutMs
        )
    }
}
