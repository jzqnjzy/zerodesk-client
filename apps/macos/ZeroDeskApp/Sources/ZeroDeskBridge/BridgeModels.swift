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
