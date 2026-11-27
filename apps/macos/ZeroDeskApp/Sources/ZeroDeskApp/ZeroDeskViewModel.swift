// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import CoreGraphics
import Foundation
import ZeroDeskBridge

public struct IncomingCallPrompt: Identifiable, Sendable {
    public let id: String
    public let callerDeviceId: String
    public let callerTenantId: String
    public let verifiedByCa: Bool
}

@MainActor
public final class ZeroDeskViewModel: ObservableObject {
    @Published public var snapshot: BridgeSnapshot?
    @Published public var selftest: OsSelftestReport?
    @Published public var latestFrame: CGImage?
    @Published public var frameCounter: UInt64 = 0
    @Published public var incomingCall: IncomingCallPrompt?
    @Published public var statusMessage: String = "Idle"
    @Published public var eventLog: [String] = []
    @Published public var isSettingsPresented: Bool = false

    @Published public var targetDeviceId: String = ""
    @Published public var outboundClipboardText: String = ""
    @Published public var outboundFilePath: String = ""

    // Settings sheet draft fields (token is converted to RedactedSecret and wiped after save).
    @Published public var controlPlaneEndpoint: String = "https://127.0.0.1:8443"
    @Published public var signalingAddr: String = "127.0.0.1:8444"
    @Published public var transportMode: String = "auto"
    @Published public var codec: String = "vp9"
    @Published public var enrollmentTokenDraft: String = ""

    private var client: ZeroDeskBridgeClient?
    private let configDirPath: String
    private let configFilePath: String
    private let identityDirPath: String
    private var isFrameFetchScheduled = false
    private var hasPendingFrame = false

    public init() {
        guard let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            self.configDirPath = ""
            self.configFilePath = ""
            self.identityDirPath = ""
            self.client = nil
            refreshSelftest()
            setStatus("Failed to locate Application Support directory")
            return
        }
        let baseDir = appSupport.appendingPathComponent("ZeroDesk", isDirectory: true)
        self.configDirPath = baseDir.path
        self.configFilePath = baseDir.appendingPathComponent("bridge_config.json").path
        self.identityDirPath = baseDir.appendingPathComponent("identity", isDirectory: true).path

        refreshSelftest()
        do {
            let bridge = try ZeroDeskBridgeClient()
            bridge.setEventHandler { [weak self] ev in
                Task { @MainActor [weak self] in
                    self?.handleBridgeEvent(ev)
                }
            }
            self.client = bridge
            refreshSnapshot()
            if FileManager.default.fileExists(atPath: configFilePath) {
                if let reply = try? bridge.loadConfig(at: configFilePath), reply.ok {
                    refreshSnapshot()
                    setStatus("Loaded saved configuration")
                }
            }
        } catch {
            setStatus("Bridge init error: \(error)")
        }
    }

    public func refreshSelftest() {
        do {
            selftest = try ZeroDeskBridgeClient.osSelftest()
        } catch {
            appendLog("os-selftest failed: \(error)")
        }
    }

    public func refreshSnapshot() {
        guard let client else { return }
        do {
            let snap = try client.snapshot()
            snapshot = snap
            if let cfg = snap.config, !isSettingsPresented {
                controlPlaneEndpoint = cfg.controlPlaneEndpoint
                signalingAddr = cfg.signalingAddr
                transportMode = cfg.transportMode
                codec = cfg.codec
            }
        } catch {
            appendLog("snapshot failed: \(error)")
        }
    }

    public func saveSettings() {
        guard let client else { return }
        let secret: RedactedSecret? = enrollmentTokenDraft.isEmpty ? nil : RedactedSecret(enrollmentTokenDraft)
        enrollmentTokenDraft = ""
        defer { secret?.wipe() }

        let input = BridgeConfigInput(
            controlPlaneEndpoint: controlPlaneEndpoint.trimmingCharacters(in: .whitespacesAndNewlines),
            signalingAddr: signalingAddr.trimmingCharacters(in: .whitespacesAndNewlines),
            identityDir: identityDirPath,
            codec: codec,
            fps: 30,
            transportMode: transportMode,
            enrollmentToken: secret
        )
        do {
            let saveReply = try client.saveConfig0600(at: configFilePath, config: input)
            if !saveReply.ok {
                setStatus("Save config failed: \(saveReply.error ?? "unknown")")
                return
            }
            let loadReply = try client.loadConfig(at: configFilePath)
            if loadReply.ok {
                setStatus("Configuration saved (0600) and loaded")
                isSettingsPresented = false
                refreshSnapshot()
            } else {
                setStatus("Load config failed: \(loadReply.error ?? "unknown")")
            }
        } catch {
            setStatus("Save config error: \(error)")
        }
    }

    public func startHost() {
        runSimpleCommand(["cmd": "start_host"], label: "Start Host")
    }

    public func stopHost() {
        runSimpleCommand(["cmd": "stop_host"], label: "Stop Host")
    }

    public func dial() {
        let trimmed = targetDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            setStatus("Enter a 32-hex target Device ID")
            return
        }
        runSimpleCommand(["cmd": "dial", "target_device_id_hex": trimmed], label: "Dial")
    }

    public func disconnect() {
        runSimpleCommand(["cmd": "disconnect"], label: "Disconnect")
        latestFrame = nil
    }

    public func acceptIncoming() {
        guard let call = incomingCall else { return }
        incomingCall = nil
        runSimpleCommand(["cmd": "accept_incoming", "incoming_id": call.id], label: "Accept Call")
    }

    public func rejectIncoming() {
        guard let call = incomingCall else { return }
        incomingCall = nil
        runSimpleCommand(["cmd": "reject_incoming", "incoming_id": call.id], label: "Reject Call")
    }

    public func toggleMute() {
        let next = !(snapshot?.audioMuted ?? false)
        runSimpleCommand(["cmd": "set_audio_mute", "muted": next], label: next ? "Mute Audio" : "Unmute Audio")
    }

    public func sendClipboardText() {
        let text = outboundClipboardText
        guard !text.isEmpty else { return }
        runSimpleCommand(["cmd": "send_clipboard", "text": text], label: "Send Clipboard")
    }

    public func sendFile() {
        let path = outboundFilePath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty, let client else { return }
        do {
            let reply = try client.sendFile(at: path)
            setStatus(reply.ok ? "File transfer queued" : "Send file failed: \(reply.error ?? "error")")
            appendLog(statusMessage)
        } catch {
            setStatus("Send file error: \(error)")
            appendLog(statusMessage)
        }
    }

    public func shutdown() {
        if let client {
            _ = try? client.execCommand(["cmd": "disconnect"])
            _ = try? client.execCommand(["cmd": "stop_host"])
            client.close()
        }
        client = nil
    }

    private func runSimpleCommand(_ cmd: [String: Any], label: String) {
        guard let client else {
            setStatus("\(label): bridge unavailable")
            return
        }
        do {
            let reply = try client.execCommand(cmd)
            if reply.ok {
                setStatus("\(label): accepted")
            } else {
                setStatus("\(label) failed: \(reply.error ?? reply.errorCode ?? "unknown")")
            }
            appendLog(statusMessage)
            refreshSnapshot()
        } catch {
            setStatus("\(label) error: \(error)")
            appendLog(statusMessage)
        }
    }

    private func handleBridgeEvent(_ ev: BridgeEventEnvelope) {
        if ev.kind == "VideoFrameReady" {
            scheduleFrameFetch()
            return
        }

        appendLog("[\(ev.seq)] \(ev.kind)")
        if ev.kind == "IncomingCall", let incomingId = ev.payloadJSON["incoming_id"] {
            let verifiedByCa = ev.payloadBools["verified_by_ca"] ?? false
            incomingCall = IncomingCallPrompt(
                id: incomingId,
                callerDeviceId: ev.payloadJSON["caller_device_id_hex"] ?? "unknown",
                callerTenantId: ev.payloadJSON["caller_tenant_id_hex"] ?? "unknown",
                verifiedByCa: verifiedByCa
            )
        } else if ev.kind == "SessionEnded" {
            latestFrame = nil
            incomingCall = nil
        }
        refreshSnapshot()
    }

    private func scheduleFrameFetch() {
        if isFrameFetchScheduled {
            hasPendingFrame = true
            return
        }
        guard let client else { return }
        isFrameFetchScheduled = true
        hasPendingFrame = false
        Task { @MainActor [weak self] in
            let captured = await Task.detached(priority: .userInitiated) {
                try? client.fetchLatestFrameCGImage()
            }.value
            guard let self else { return }
            self.isFrameFetchScheduled = false
            if let captured {
                self.latestFrame = captured.image
                self.frameCounter = captured.seq
            }
            if self.hasPendingFrame {
                self.hasPendingFrame = false
                self.scheduleFrameFetch()
            }
        }
    }

    private func setStatus(_ raw: String) {
        statusMessage = sanitizeLogMessage(raw)
    }

    private func appendLog(_ line: String) {
        let clean = sanitizeLogMessage(line)
        eventLog.append(clean)
        if eventLog.count > 200 {
            eventLog.removeFirst(eventLog.count - 200)
        }
    }
}
