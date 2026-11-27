// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
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
    @Published public var hasVideoFrame: Bool = false
    @Published public var remoteSize: RemoteSize = RemoteSize(width: 0, height: 0)
    @Published public var frameCounter: UInt64 = 0
    @Published public var activeCodecLabel: String = "auto"
    @Published public var renderFps: Double = 0
    @Published public var metalRenderMs: Double = 0
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
    @Published public var codec: String = "auto"
    @Published public var enrollmentTokenDraft: String = ""

    public let metalRenderer: MetalVideoRenderer?
    public private(set) var inputTracker: PressedInputTracker?

    public var isSessionStreaming: Bool {
        snapshot?.state == "streaming"
    }

    private var client: ZeroDeskBridgeClient?
    private let configDirPath: String
    private let configFilePath: String
    private let identityDirPath: String
    private var isFrameFetchScheduled = false
    private var hasPendingFrame = false
    private var frameGeneration: UInt64 = 0
    private var fpsWindowStartNs: UInt64 = 0
    private var fpsWindowFrames: UInt64 = 0

    public init() {
        self.metalRenderer = try? MetalVideoRenderer()

        guard let appSupport = FileManager.default.urls(
            for: .applicationSupportDirectory,
            in: .userDomainMask
        ).first else {
            self.configDirPath = ""
            self.configFilePath = ""
            self.identityDirPath = ""
            self.client = nil
            self.inputTracker = nil
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
            self.inputTracker = PressedInputTracker(sink: bridge)
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
            let wasStreaming = snapshot?.state == "streaming"
            snapshot = snap
            if wasStreaming && snap.state != "streaming" {
                inputTracker?.releaseAll(reason: .sessionLeftConnected)
            }
            if let cfg = snap.config, !isSettingsPresented {
                controlPlaneEndpoint = cfg.controlPlaneEndpoint
                signalingAddr = cfg.signalingAddr
                transportMode = cfg.transportMode
                codec = cfg.codec
                if !isSessionStreaming {
                    activeCodecLabel = cfg.codec
                }
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
        runSimpleCommand(["cmd": "start_host", "codec": codec], label: "Start Host")
    }

    public func stopHost() {
        clearVideoState(releaseReason: .sessionLeftConnected)
        runSimpleCommand(["cmd": "stop_host"], label: "Stop Host")
    }

    public func dial() {
        let trimmed = targetDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            setStatus("Enter a 32-hex target Device ID")
            return
        }
        activeCodecLabel = codec
        runSimpleCommand(
            ["cmd": "dial", "target_device_id_hex": trimmed, "codec": codec],
            label: "Dial"
        )
    }

    public func disconnect() {
        clearVideoState(releaseReason: .sessionLeftConnected)
        runSimpleCommand(["cmd": "disconnect"], label: "Disconnect")
    }

    public func handleEmergencyEscapeTriggered() {
        setStatus("Emergency Escape (Ctrl+Opt+Cmd+Esc): released all remote inputs")
        appendLog("Emergency Escape: sent release_all")
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
        clearVideoState(releaseReason: .viewTeardownOrTerminate)
        if let client {
            _ = try? client.releaseAllInput(reason: .viewTeardownOrTerminate)
            _ = try? client.execCommand(["cmd": "disconnect"])
            _ = try? client.execCommand(["cmd": "stop_host"])
            client.close()
        }
        inputTracker = nil
        client = nil
    }

    private func clearVideoState(releaseReason: ReleaseReason) {
        inputTracker?.releaseAll(reason: releaseReason)
        frameGeneration &+= 1
        hasPendingFrame = false
        hasVideoFrame = false
        remoteSize = RemoteSize(width: 0, height: 0)
        renderFps = 0
        metalRenderMs = 0
        fpsWindowStartNs = 0
        fpsWindowFrames = 0
        metalRenderer?.clearFrame()
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
        if ev.kind == "QoeTelemetry" {
            if let active = ev.payloadJSON["active_codec"], !active.isEmpty {
                activeCodecLabel = active
            }
            if let renderer = metalRenderer {
                metalRenderMs = renderer.lastUploadAndDrawMs
            }
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
            clearVideoState(releaseReason: .sessionLeftConnected)
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
        let gen = frameGeneration
        isFrameFetchScheduled = true
        hasPendingFrame = false
        Task { @MainActor [weak self] in
            let captured = await Task.detached(priority: .userInitiated) {
                try? client.fetchLatestFrameBGRA()
            }.value
            guard let self else { return }
            self.isFrameFetchScheduled = false
            if let captured, gen == self.frameGeneration {
                self.metalRenderer?.submitFrame(captured)
                self.hasVideoFrame = true
                self.remoteSize = RemoteSize(width: captured.width, height: captured.height)
                self.frameCounter = captured.seq
                self.updateRenderTelemetry()
            }
            if self.hasPendingFrame, gen == self.frameGeneration {
                self.hasPendingFrame = false
                self.scheduleFrameFetch()
            }
        }
    }

    private func updateRenderTelemetry() {
        let nowNs = DispatchTime.now().uptimeNanoseconds
        if fpsWindowStartNs == 0 {
            fpsWindowStartNs = nowNs
            fpsWindowFrames = 1
        } else {
            fpsWindowFrames &+= 1
            let elapsedNs = nowNs - fpsWindowStartNs
            if elapsedNs >= 500_000_000 {
                renderFps = Double(fpsWindowFrames) / (Double(elapsedNs) / 1_000_000_000.0)
                fpsWindowStartNs = nowNs
                fpsWindowFrames = 0
            }
        }
        if let renderer = metalRenderer {
            metalRenderMs = renderer.lastUploadAndDrawMs
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
