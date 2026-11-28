// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import CoreGraphics
import Foundation

public enum ZeroDeskBridgeError: Error, Sendable, Equatable, CustomStringConvertible {
    case invalidArg
    case invalidHandle
    case invalidUtf8
    case bufferTooSmall
    case timeout
    case noEvent
    case noFrame
    case busy
    case internalError
    case panic
    case closed
    case unsupportedAbi(UInt32)
    case protocolError(String)
    case ioError(String)

    public var description: String {
        switch self {
        case .invalidArg: return "invalid argument"
        case .invalidHandle: return "invalid bridge handle"
        case .invalidUtf8: return "invalid UTF-8"
        case .bufferTooSmall: return "frame buffer too small"
        case .timeout: return "operation timed out"
        case .noEvent: return "no event available"
        case .noFrame: return "no video frame available"
        case .busy: return "runtime busy"
        case .internalError: return "internal bridge error"
        case .panic: return "panic across FFI boundary"
        case .closed: return "bridge client is closed"
        case .unsupportedAbi(let v): return "unsupported bridge ABI version \(v)"
        case .protocolError(let msg): return "bridge protocol error: \(msg)"
        case .ioError(let msg): return "bridge I/O error: \(msg)"
        }
    }

    public static func fromCode(_ code: Int32) -> ZeroDeskBridgeError {
        switch code {
        case -1: return .invalidArg
        case -2: return .invalidHandle
        case -3: return .invalidUtf8
        case -4: return .bufferTooSmall
        case -5: return .timeout
        case -6: return .noEvent
        case -7: return .noFrame
        case -8: return .busy
        case -9: return .internalError
        case -10: return .panic
        default: return .protocolError("unknown C-ABI status code \(code)")
        }
    }
}

public struct ProbeOutcome: Codable, Sendable, Equatable {
    public let status: String
    public let granted: Bool
    public let note: String?
}

public struct AudioDeviceProbe: Codable, Sendable, Equatable {
    public let available: Bool
    public let inputDeviceCount: Int
    public let outputDeviceCount: Int
    public let note: String?

    enum CodingKeys: String, CodingKey {
        case available
        case inputDeviceCount = "input_device_count"
        case outputDeviceCount = "output_device_count"
        case note
    }
}

public struct OsSelftestReport: Codable, Sendable, Equatable {
    public let schemaVersion: UInt32
    public let platform: String
    public let zeroWritesEnforced: Bool
    public let realInputCompiledIn: Bool
    public let screenRecording: ProbeOutcome
    public let accessibility: ProbeOutcome
    public let secureEventInputEnabled: Bool?
    public let audio: AudioDeviceProbe
    public let clipboardReadonlyAvailable: Bool

    enum CodingKeys: String, CodingKey {
        case schemaVersion = "schema_version"
        case platform
        case zeroWritesEnforced = "zero_writes_enforced"
        case realInputCompiledIn = "real_input_compiled_in"
        case screenRecording = "screen_recording"
        case accessibility
        case secureEventInputEnabled = "secure_event_input_enabled"
        case audio
        case clipboardReadonlyAvailable = "clipboard_readonly_available"
    }
}

public struct PolicySummary: Codable, Sendable, Equatable {
    public let version: UInt64
    public let degraded: Bool
    public let degradedReason: String?
    public let allowFileTransfer: Bool
    public let allowClipboard: Bool
    public let allowFileClipboard: Bool
    public let allowTcpTunnel: Bool
    public let allowTerminal: Bool
    public let allowAudio: Bool
    public let maxBwKbps: UInt32
    public let maxFileBytes: UInt64
    public let maxClipboardBytes: UInt64

    enum CodingKeys: String, CodingKey {
        case version
        case degraded
        case degradedReason = "degraded_reason"
        case allowFileTransfer = "allow_file_transfer"
        case allowClipboard = "allow_clipboard"
        case allowFileClipboard = "allow_file_clipboard"
        case allowTcpTunnel = "allow_tcp_tunnel"
        case allowTerminal = "allow_terminal"
        case allowAudio = "allow_audio"
        case maxBwKbps = "max_bw_kbps"
        case maxFileBytes = "max_file_bytes"
        case maxClipboardBytes = "max_clipboard_bytes"
    }
}

public struct VerifiedCallerDisplay: Codable, Sendable, Equatable {
    public let deviceIdHex: String
    public let tenantIdHex: String
    public let certIdHex: String
    public let keyEpoch: UInt64
    public let verifiedByCa: Bool

    enum CodingKeys: String, CodingKey {
        case deviceIdHex = "device_id_hex"
        case tenantIdHex = "tenant_id_hex"
        case certIdHex = "cert_id_hex"
        case keyEpoch = "key_epoch"
        case verifiedByCa = "verified_by_ca"
    }
}

public struct RedactedConfigView: Codable, Sendable, Equatable {
    public let controlPlaneEndpoint: String
    public let signalingAddr: String
    public let hasEnrollmentToken: Bool
    public let homeRegion: String
    public let codec: String
    public let fps: UInt32
    public let transportMode: String

    enum CodingKeys: String, CodingKey {
        case controlPlaneEndpoint = "control_plane_endpoint"
        case signalingAddr = "signaling_addr"
        case hasEnrollmentToken = "has_enrollment_token"
        case homeRegion = "home_region"
        case codec
        case fps
        case transportMode = "transport_mode"
    }
}

public struct BridgeSnapshot: Codable, Sendable, Equatable {
    public let v: UInt32
    public let state: String
    public let transportMode: String
    public let activeTransportMode: String?
    public let audioMuted: Bool
    public let realInputEnabled: Bool?
    public let abiVersion: UInt32?
    public let caps: [String]?
    public let enableOsInput: Bool?
    public let activeCodec: String?
    public let bitrateKbps: UInt32?
    public let fpsCap: UInt32?
    public let clipboardSyncEnabled: Bool?
    public let localDeviceIdHex: String?
    public let localTenantIdHex: String?
    public let activeSessionIdHex: String?
    public let pendingIncomingSessionIdHex: String?
    public let verifiedCaller: VerifiedCallerDisplay?
    public let policy: PolicySummary?
    public let config: RedactedConfigView?
    public let activeFileTransfers: [UInt64]?
    public let faultReason: String?

    enum CodingKeys: String, CodingKey {
        case v
        case state
        case transportMode = "transport_mode"
        case activeTransportMode = "active_transport_mode"
        case audioMuted = "audio_muted"
        case realInputEnabled = "real_input_enabled"
        case abiVersion = "abi_version"
        case caps
        case enableOsInput = "enable_os_input"
        case activeCodec = "active_codec"
        case bitrateKbps = "bitrate_kbps"
        case fpsCap = "fps_cap"
        case clipboardSyncEnabled = "clipboard_sync_enabled"
        case localDeviceIdHex = "local_device_id_hex"
        case localTenantIdHex = "local_tenant_id_hex"
        case activeSessionIdHex = "active_session_id_hex"
        case pendingIncomingSessionIdHex = "pending_incoming_session_id_hex"
        case verifiedCaller = "verified_caller"
        case policy
        case config
        case activeFileTransfers = "active_file_transfers"
        case faultReason = "fault_reason"
    }
}

public struct BridgeCommandReply: Codable, Sendable, Equatable {
    public let v: UInt32
    public let ok: Bool
    public let accepted: Bool?
    public let alreadyRunning: Bool?
    public let alreadyStopped: Bool?
    public let cmdId: UInt64?
    public let sessionGen: UInt64?
    public let errorCode: String?
    public let error: String?

    enum CodingKeys: String, CodingKey {
        case v
        case ok
        case accepted
        case alreadyRunning = "already_running"
        case alreadyStopped = "already_stopped"
        case cmdId = "cmd_id"
        case sessionGen = "session_gen"
        case errorCode = "error_code"
        case error
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.v = try c.decodeIfPresent(UInt32.self, forKey: .v) ?? 1
        self.ok = try c.decodeIfPresent(Bool.self, forKey: .ok) ?? false
        self.accepted = try c.decodeIfPresent(Bool.self, forKey: .accepted)
        self.alreadyRunning = try c.decodeIfPresent(Bool.self, forKey: .alreadyRunning)
        self.alreadyStopped = try c.decodeIfPresent(Bool.self, forKey: .alreadyStopped)
        self.cmdId = try c.decodeIfPresent(UInt64.self, forKey: .cmdId)
        self.sessionGen = try c.decodeIfPresent(UInt64.self, forKey: .sessionGen)
        self.errorCode = try c.decodeIfPresent(String.self, forKey: .errorCode)
        self.error = try c.decodeIfPresent(String.self, forKey: .error)
    }
}

public struct BridgeEventEnvelope: Sendable {
    public let v: UInt32
    public let seq: UInt64
    public let kind: String
    public let rawJSON: String
    public let payloadJSON: [String: String]
    public let payloadBools: [String: Bool]

    public init(
        v: UInt32,
        seq: UInt64,
        kind: String,
        rawJSON: String,
        payloadJSON: [String: String],
        payloadBools: [String: Bool] = [:]
    ) {
        self.v = v
        self.seq = seq
        self.kind = kind
        self.rawJSON = rawJSON
        self.payloadJSON = payloadJSON
        self.payloadBools = payloadBools
    }
}

public struct BridgeConfigInput: Sendable {
    public var controlPlaneEndpoint: String
    public var signalingAddr: String
    public var signalingTls: Bool?
    public var edgeA: String?
    public var edgeB: String?
    public var caDerPath: String?
    public var identityDir: String
    public var homeRegion: String
    public var codec: String
    public var fps: UInt32
    public var transportMode: String
    public var enrollmentToken: RedactedSecret?

    public init(
        controlPlaneEndpoint: String,
        signalingAddr: String,
        signalingTls: Bool? = nil,
        edgeA: String? = nil,
        edgeB: String? = nil,
        caDerPath: String? = nil,
        identityDir: String,
        homeRegion: String = "local",
        codec: String = "vp9",
        fps: UInt32 = 30,
        transportMode: String = "auto",
        enrollmentToken: RedactedSecret? = nil
    ) {
        self.controlPlaneEndpoint = controlPlaneEndpoint
        self.signalingAddr = signalingAddr
        self.signalingTls = signalingTls
        self.edgeA = edgeA
        self.edgeB = edgeB
        self.caDerPath = caDerPath
        self.identityDir = identityDir
        self.homeRegion = homeRegion
        self.codec = codec
        self.fps = fps
        self.transportMode = transportMode
        self.enrollmentToken = enrollmentToken
    }
}

public struct CapturedFrameImage: @unchecked Sendable {
    public let seq: UInt64
    public let width: Int
    public let height: Int
    public let ptsMs: UInt64
    public let droppedUiFrames: UInt64
    public let image: CGImage
}

/// Raw BGRA8 frame fetched directly from Rust's `FrameMailbox` for zero-CGImage Metal texture upload.
public struct CapturedBGRAFrame: Sendable {
    public let seq: UInt64
    public let width: Int
    public let height: Int
    public let stride: Int
    public let pixelFormat: UInt32
    public let ptsMs: UInt64
    public let droppedUiFrames: UInt64
    public let data: Data

    public init(
        seq: UInt64,
        width: Int,
        height: Int,
        stride: Int,
        pixelFormat: UInt32 = 1,
        ptsMs: UInt64 = 0,
        droppedUiFrames: UInt64 = 0,
        data: Data
    ) {
        self.seq = seq
        self.width = width
        self.height = height
        self.stride = stride
        self.pixelFormat = pixelFormat
        self.ptsMs = ptsMs
        self.droppedUiFrames = droppedUiFrames
        self.data = data
    }
}

// MARK: - Phase 8A Additive JSON-ABI v2 Models

public struct HandshakeCapabilitiesData: Codable, Sendable, Equatable {
    public let abiVersion: UInt32
    public let caps: [String]

    enum CodingKeys: String, CodingKey {
        case abiVersion = "abi_version"
        case caps
    }

    public init(abiVersion: UInt32 = 1, caps: [String] = []) {
        self.abiVersion = abiVersion
        self.caps = caps
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.abiVersion = try c.decodeIfPresent(UInt32.self, forKey: .abiVersion) ?? 1
        self.caps = try c.decodeIfPresent([String].self, forKey: .caps) ?? []
    }
}

public struct BridgeTypedReply<T: Codable & Sendable & Equatable>: Codable, Sendable, Equatable {
    public let v: UInt32
    public let ok: Bool
    public let errorCode: String?
    public let error: String?
    public let data: T?

    enum CodingKeys: String, CodingKey {
        case v
        case ok
        case errorCode = "error_code"
        case error
        case data
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.v = try c.decodeIfPresent(UInt32.self, forKey: .v) ?? 1
        self.ok = try c.decodeIfPresent(Bool.self, forKey: .ok) ?? false
        self.errorCode = try c.decodeIfPresent(String.self, forKey: .errorCode)
        self.error = try c.decodeIfPresent(String.self, forKey: .error)
        self.data = try c.decodeIfPresent(T.self, forKey: .data)
    }
}

public enum PermissionProbeSource: Codable, Sendable, Equatable {
    case watchdog
    case injectorProcess
    case uiProcessHint
    case unknown(String)

    public var rawValue: String {
        switch self {
        case .watchdog:
            return "watchdog"
        case .injectorProcess:
            return "injector_process"
        case .uiProcessHint:
            return "ui_process_hint"
        case .unknown(let value):
            return value
        }
    }

    public var isAuthoritative: Bool {
        switch self {
        case .watchdog, .injectorProcess:
            return true
        case .uiProcessHint, .unknown:
            return false
        }
    }

    public init(rawValue: String) {
        switch rawValue {
        case "watchdog":
            self = .watchdog
        case "injector_process", "watchdog_or_injector_process":
            self = .injectorProcess
        case "ui_process_hint":
            self = .uiProcessHint
        default:
            self = .unknown(rawValue)
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        self.init(rawValue: raw)
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

public struct PermissionStatusReport: Codable, Sendable, Equatable {
    public let screenCaptureGranted: Bool
    public let accessibilityGranted: Bool
    public let probeSource: PermissionProbeSource
    public let enableOsInput: Bool
    public let secureEventInputEnabled: Bool?

    enum CodingKeys: String, CodingKey {
        case screenCaptureGranted = "screen_capture_granted"
        case accessibilityGranted = "accessibility_granted"
        case probeSource = "probe_source"
        case enableOsInput = "enable_os_input"
        case secureEventInputEnabled = "secure_event_input_enabled"
    }

    public init(
        screenCaptureGranted: Bool,
        accessibilityGranted: Bool,
        probeSource: PermissionProbeSource,
        enableOsInput: Bool,
        secureEventInputEnabled: Bool? = nil
    ) {
        self.screenCaptureGranted = screenCaptureGranted
        self.accessibilityGranted = accessibilityGranted
        self.probeSource = probeSource
        self.enableOsInput = enableOsInput
        self.secureEventInputEnabled = secureEventInputEnabled
    }

    public var allRequiredPermissionsGranted: Bool {
        screenCaptureGranted && accessibilityGranted
    }

    public var canAuthorizeOsInput: Bool {
        screenCaptureGranted && accessibilityGranted && probeSource.isAuthoritative
    }
}

public struct InputEnabledAckPayload: Codable, Sendable, Equatable {
    public let enabled: Bool
    public let status: String
    public let screenCaptureGranted: Bool?
    public let accessibilityGranted: Bool?
    public let probeSource: String?
    public let reason: String?
    public let releaseAll: String?

    enum CodingKeys: String, CodingKey {
        case enabled
        case status
        case screenCaptureGranted = "screen_capture_granted"
        case accessibilityGranted = "accessibility_granted"
        case probeSource = "probe_source"
        case reason
        case releaseAll = "release_all"
    }

    public init(
        enabled: Bool,
        status: String,
        screenCaptureGranted: Bool? = nil,
        accessibilityGranted: Bool? = nil,
        probeSource: String? = nil,
        reason: String? = nil,
        releaseAll: String? = nil
    ) {
        self.enabled = enabled
        self.status = status
        self.screenCaptureGranted = screenCaptureGranted
        self.accessibilityGranted = accessibilityGranted
        self.probeSource = probeSource
        self.reason = reason
        self.releaseAll = releaseAll
    }
}

public struct HudStatsPayload: Codable, Sendable, Equatable {
    public let fps: Double
    public let decodeMs: Double
    public let activeCodec: String
    public let transportMode: String
    public let rttMs: Double
    public let bitrateKbps: UInt32

    enum CodingKeys: String, CodingKey {
        case fps
        case decodeMs = "decode_ms"
        case activeCodec = "active_codec"
        case transportMode = "transport_mode"
        case rttMs = "rtt_ms"
        case bitrateKbps = "bitrate_kbps"
    }

    private static func sanitizeNonNegative(_ value: Double) -> Double {
        (value.isFinite && value >= 0) ? value : 0
    }

    public init(
        fps: Double = 0,
        decodeMs: Double = 0,
        activeCodec: String = "auto",
        transportMode: String = "udp",
        rttMs: Double = 0,
        bitrateKbps: UInt32 = 0
    ) {
        self.fps = Self.sanitizeNonNegative(fps)
        self.decodeMs = Self.sanitizeNonNegative(decodeMs)
        self.activeCodec = activeCodec
        self.transportMode = transportMode
        self.rttMs = Self.sanitizeNonNegative(rttMs)
        self.bitrateKbps = bitrateKbps
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let rawFps = try c.decodeIfPresent(Double.self, forKey: .fps) ?? 0
        let rawDecodeMs = try c.decodeIfPresent(Double.self, forKey: .decodeMs) ?? 0
        let rawRttMs = try c.decodeIfPresent(Double.self, forKey: .rttMs) ?? 0
        self.fps = Self.sanitizeNonNegative(rawFps)
        self.decodeMs = Self.sanitizeNonNegative(rawDecodeMs)
        self.activeCodec = try c.decodeIfPresent(String.self, forKey: .activeCodec) ?? ""
        self.transportMode = try c.decodeIfPresent(String.self, forKey: .transportMode) ?? ""
        self.rttMs = Self.sanitizeNonNegative(rawRttMs)
        self.bitrateKbps = try c.decodeIfPresent(UInt32.self, forKey: .bitrateKbps) ?? 0
    }
}

public struct CodecAckPayload: Codable, Sendable, Equatable {
    public let activeCodec: String
    public let requestedCodec: String?
    public let accepted: Bool

    enum CodingKeys: String, CodingKey {
        case activeCodec = "active_codec"
        case requestedCodec = "requested_codec"
        case accepted
    }

    public init(activeCodec: String, requestedCodec: String? = nil, accepted: Bool) {
        self.activeCodec = activeCodec
        self.requestedCodec = requestedCodec
        self.accepted = accepted
    }
}

public struct VideoQualityAckPayload: Codable, Sendable, Equatable {
    public let bitrateKbps: UInt32
    public let fpsCap: UInt32

    enum CodingKeys: String, CodingKey {
        case bitrateKbps = "bitrate_kbps"
        case fpsCap = "fps_cap"
    }

    public init(bitrateKbps: UInt32, fpsCap: UInt32) {
        self.bitrateKbps = bitrateKbps
        self.fpsCap = fpsCap
    }
}

public struct ClipboardSyncStatusPayload: Codable, Sendable, Equatable {
    public let enabled: Bool
    public let status: String
    public let code: String?

    public init(enabled: Bool, status: String, code: String? = nil) {
        self.enabled = enabled
        self.status = status
        self.code = code
    }
}

public struct FileTransferCompletePayload: Codable, Sendable, Equatable {
    public let transferId: UInt64
    public let relName: String
    public let bytes: UInt64
    public let sha256Hex: String
    public let checksumAlgo: String?
    public let savedPath: String?

    enum CodingKeys: String, CodingKey {
        case transferId = "transfer_id"
        case relName = "rel_name"
        case bytes
        case sha256Hex = "sha256_hex"
        case checksumAlgo = "checksum_algo"
        case savedPath = "saved_path"
    }

    public init(
        transferId: UInt64,
        relName: String,
        bytes: UInt64,
        sha256Hex: String,
        checksumAlgo: String? = nil,
        savedPath: String? = nil
    ) {
        self.transferId = transferId
        self.relName = relName
        self.bytes = bytes
        self.sha256Hex = sha256Hex
        self.checksumAlgo = checksumAlgo
        self.savedPath = savedPath
    }
}

/// Forward-compatible decoded bridge event:
/// - Unknown `kind`/`type` values or future envelope versions (`v > 1`) map to `.unknown(kind:)`.
/// - Known `kind` values with malformed/missing payload fields map to `.malformed(kind:)`.
public enum ParsedBridgeEvent: Sendable, Equatable {
    case permissionStatus(PermissionStatusReport)
    case inputEnabledAck(InputEnabledAckPayload)
    case hudStats(HudStatsPayload)
    case codecAck(CodecAckPayload)
    case videoQualityAck(VideoQualityAckPayload)
    case clipboardSyncStatus(ClipboardSyncStatusPayload)
    case fileTransferComplete(FileTransferCompletePayload)
    case malformed(kind: String)
    case unknown(kind: String)

    private struct EventHeader: Decodable {
        let v: UInt32?
        let seq: UInt64?
        let kind: String?
        let type: String?
    }

    private struct TypedEventWrapper<P: Decodable>: Decodable {
        let payload: P
    }

    public static func decodeForwardCompat(from data: Data) throws -> ParsedBridgeEvent {
        let decoder = JSONDecoder()
        let header = try decoder.decode(EventHeader.self, from: data)
        let resolvedKind = header.kind ?? header.type ?? ""
        if let envelopeV = header.v, envelopeV > 1 {
            return .unknown(kind: resolvedKind)
        }
        switch resolvedKind {
        case "permission_status":
            if let wrapped = try? decoder.decode(TypedEventWrapper<PermissionStatusReport>.self, from: data) {
                return .permissionStatus(wrapped.payload)
            }
            return .malformed(kind: resolvedKind)
        case "input_enabled_ack":
            if let wrapped = try? decoder.decode(TypedEventWrapper<InputEnabledAckPayload>.self, from: data) {
                return .inputEnabledAck(wrapped.payload)
            }
            return .malformed(kind: resolvedKind)
        case "hud_stats":
            if let wrapped = try? decoder.decode(TypedEventWrapper<HudStatsPayload>.self, from: data) {
                return .hudStats(wrapped.payload)
            }
            return .malformed(kind: resolvedKind)
        case "codec_ack":
            if let wrapped = try? decoder.decode(TypedEventWrapper<CodecAckPayload>.self, from: data) {
                return .codecAck(wrapped.payload)
            }
            return .malformed(kind: resolvedKind)
        case "video_quality_ack":
            if let wrapped = try? decoder.decode(TypedEventWrapper<VideoQualityAckPayload>.self, from: data) {
                return .videoQualityAck(wrapped.payload)
            }
            return .malformed(kind: resolvedKind)
        case "clipboard_sync_status":
            if let wrapped = try? decoder.decode(TypedEventWrapper<ClipboardSyncStatusPayload>.self, from: data) {
                return .clipboardSyncStatus(wrapped.payload)
            }
            return .malformed(kind: resolvedKind)
        case "file_transfer_complete", "FileTransferComplete":
            if let wrapped = try? decoder.decode(TypedEventWrapper<FileTransferCompletePayload>.self, from: data) {
                return .fileTransferComplete(wrapped.payload)
            }
            return .malformed(kind: resolvedKind)
        default:
            return .unknown(kind: resolvedKind)
        }
    }
}

/// Typed ABI v2 command request payloads for golden round-trip parity verification.
public struct SetInputEnabledRequest: Codable, Sendable, Equatable {
    public let v: UInt32
    public let cmd: String
    public let enabled: Bool
    public let reason: String?

    public init(v: UInt32 = 1, enabled: Bool, reason: String? = nil) {
        self.v = v
        self.cmd = "set_input_enabled"
        self.enabled = enabled
        self.reason = reason
    }
}

public struct GetPermissionsRequest: Codable, Sendable, Equatable {
    public let v: UInt32
    public let cmd: String

    public init(v: UInt32 = 1) {
        self.v = v
        self.cmd = "get_permissions"
    }
}

public struct SetVideoQualityRequest: Codable, Sendable, Equatable {
    public let v: UInt32
    public let cmd: String
    public let bitrateKbps: UInt32
    public let fpsCap: UInt32

    enum CodingKeys: String, CodingKey {
        case v
        case cmd
        case bitrateKbps = "bitrate_kbps"
        case fpsCap = "fps_cap"
    }

    public init(v: UInt32 = 1, bitrateKbps: UInt32, fpsCap: UInt32) {
        self.v = v
        self.cmd = "set_video_quality"
        self.bitrateKbps = bitrateKbps
        self.fpsCap = fpsCap
    }
}
