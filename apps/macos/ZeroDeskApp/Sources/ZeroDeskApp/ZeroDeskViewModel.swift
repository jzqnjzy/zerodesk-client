// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import Foundation
import UniformTypeIdentifiers
import ZeroDeskBridge

public struct IncomingCallPrompt: Identifiable, Sendable {
    public let id: String
    public let callerDeviceId: String
    public let callerTenantId: String
    public let verifiedByCa: Bool
}

public struct FileTransferItem: Identifiable, Sendable, Equatable {
    public let id: UInt64
    public var relName: String
    public var bytesTransferred: UInt64
    public var totalBytes: UInt64
    public var statusLabel: String
    public var isInFlight: Bool
    public var isError: Bool
    public var errorMessage: String?
    /// Exact negotiated checksum algorithm reported by Rust/peer (e.g. `"sha256"`, `"md5"`).
    /// NEVER hardcoded when peer reports a different algorithm.
    public var checksumAlgo: String?

    public var progressFraction: Double {
        guard totalBytes > 0 else { return isInFlight ? 0.0 : 1.0 }
        return min(max(Double(bytesTransferred) / Double(totalBytes), 0.0), 1.0)
    }
}

@MainActor
public final class ZeroDeskViewModel: ObservableObject {
    @Published public var snapshot: BridgeSnapshot?
    @Published public var selftest: OsSelftestReport?
    @Published public var permissionStatus: PermissionStatusReport?
    @Published public var abiVersion: UInt32 = 2
    @Published public var capabilities: Set<String> = []

    // Per-session OS input control (default OFF, NEVER persisted, strictly Rust-acknowledged!).
    @Published public var isOsInputEnabled: Bool = false
    @Published public var isInputTogglePending: Bool = false
    @Published public var isPermissionGuidePresented: Bool = false

    // Viewport & session control drawer state.
    @Published public var hasVideoFrame: Bool = false
    @Published public var remoteSize: RemoteSize = RemoteSize(width: 0, height: 0)
    @Published public var displayScaleMode: DisplayScaleMode = .fit
    @Published public var scrollOffset: CGPoint = .zero
    @Published public var isControlDrawerOpen: Bool = false

    // Live 1 Hz Telemetry HUD (updated strictly from Rust `hud_stats`, NEVER per-frame!).
    @Published public var hudStats: HudStatsPayload = HudStatsPayload()

    // Codec / Bitrate / FPS controls.
    @Published public var activeCodecLabel: String = "auto"
    @Published public var selectedCodecOption: String = "auto"
    @Published public var selectedBitrateKbps: UInt32 = 0
    @Published public var selectedFpsCap: UInt32 = 30
    @Published public var toastNotice: String?

    // Clipboard & File transfer drawer state.
    @Published public var clipboardSyncEnabled: Bool = true
    @Published public var clipboardSyncBadge: ClipboardSyncBadge = .idle
    @Published public var fileTransfers: [FileTransferItem] = []

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
    public private(set) var inputGate: InputGate?

    public var isSessionStreaming: Bool {
        snapshot?.state == "streaming"
    }

    public func hasCapability(_ cap: String) -> Bool {
        capabilities.contains(cap)
    }

    private var client: ZeroDeskBridgeClient?
    private let configDirPath: String
    private let configFilePath: String
    private let identityDirPath: String
    private let qualityDebouncer = QualityControlDebouncer(delayMs: QualityControlDebouncer.defaultDelayMs)
    private let clipboardGuard = ClipboardSyncGuard()
    private var codecAckTimeoutTask: Task<Void, Never>?
    private var pendingCodecRequest: String?
    private var isFrameFetchScheduled = false
    private var hasPendingFrame = false
    private var frameGeneration: UInt64 = 0

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
            self.inputGate = nil
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
            self.inputGate = InputGate(sink: bridge, initialInputEnabled: false)

            if let hs = try? bridge.handshake() {
                self.abiVersion = hs.abiVersion
                self.capabilities = Set(hs.caps)
            }
            refreshPermissions()
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

    // MARK: - Permissions & `enable_os_input` Gate

    public func refreshSelftest() {
        do {
            selftest = try ZeroDeskBridgeClient.osSelftest()
        } catch {
            appendLog("os-selftest failed: \(error)")
        }
    }

    /// Queries structured macOS permissions from Rust without popping any OS permission dialog.
    public func refreshPermissions() {
        refreshSelftest()
        guard let client else { return }
        if let report = try? client.getPermissions() {
            permissionStatus = report
            applyAcknowledgedInputEnabled(report.enableOsInput)
        }
    }

    public func openPermissionGuide() {
        notifyOverlayOpened()
        isPermissionGuidePresented = true
    }

    public func closePermissionGuide() {
        isPermissionGuidePresented = false
    }

    /// Requests toggling per-session `enable_os_input` over JSON-ABI.
    /// NEVER optimistically flips `isOsInputEnabled` locally — UI updates strictly on Rust ack!
    public func requestSetInputEnabled(_ enabled: Bool, reason: String? = nil) {
        guard let client else { return }
        isInputTogglePending = true
        do {
            let reply = try client.setInputEnabled(enabled, reason: reason)
            if !reply.ok {
                isInputTogglePending = false
                if reply.errorCode == "not_permitted" {
                    applyAcknowledgedInputEnabled(false)
                    showToast("Permissions required (Screen Recording + Accessibility) before enabling OS input.")
                    openPermissionGuide()
                } else {
                    showToast("Input toggle failed: \(reply.error ?? reply.errorCode ?? "unknown")")
                }
            }
        } catch {
            isInputTogglePending = false
            showToast("Input toggle error: \(error)")
        }
    }

    private func applyAcknowledgedInputEnabled(_ enabled: Bool) {
        isOsInputEnabled = enabled
        isInputTogglePending = false
        inputGate?.setInputEnabledFromAck(enabled)
    }

    // MARK: - Overlay & Viewport Controls (Anti-Stuck-Key Triggers)

    public func notifyOverlayOpened() {
        inputGate?.notifyOverlayOpened()
    }

    public func toggleControlDrawer() {
        if !isControlDrawerOpen {
            notifyOverlayOpened()
        }
        isControlDrawerOpen.toggle()
    }

    public func closeControlDrawer() {
        isControlDrawerOpen = false
    }

    public func openSettingsSheet() {
        notifyOverlayOpened()
        isSettingsPresented = true
    }

    public func selectDisplayScaleMode(_ mode: DisplayScaleMode) {
        guard mode != displayScaleMode else { return }
        // Mandatory: release all held inputs BEFORE switching viewport mode!
        inputGate?.releaseAll(reason: .viewportChanged)
        scrollOffset = .zero
        displayScaleMode = mode
        metalRenderer?.updateViewport(mode: mode, scrollOffset: .zero)
    }

    public func updateLocalScrollOffset(_ offset: CGPoint) {
        scrollOffset = offset
    }

    // MARK: - Codec (Peer-Acknowledged + 3s Timeout Revert) & Debounced Quality Controls

    public func requestCodecChange(_ requested: String) {
        selectedCodecOption = requested
        codec = requested
        guard let client else { return }

        if !isSessionStreaming {
            if let reply = try? client.setCodec(requested), reply.ok {
                activeCodecLabel = requested
                refreshSnapshot()
            }
            return
        }

        pendingCodecRequest = requested
        codecAckTimeoutTask?.cancel()
        codecAckTimeoutTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard let self, !Task.isCancelled, self.pendingCodecRequest == requested else { return }
            self.pendingCodecRequest = nil
            self.selectedCodecOption = self.activeCodecLabel
            self.showToast("Codec switch to \(requested.uppercased()) timed out (3s); reverted to \(self.activeCodecLabel.uppercased()).")
        }

        do {
            let reply = try client.setCodec(requested)
            if !reply.ok {
                codecAckTimeoutTask?.cancel()
                pendingCodecRequest = nil
                selectedCodecOption = activeCodecLabel
                showToast("Codec change rejected: \(reply.error ?? "unsupported")")
            }
        } catch {
            codecAckTimeoutTask?.cancel()
            pendingCodecRequest = nil
            selectedCodecOption = activeCodecLabel
            showToast("Codec change error: \(error)")
        }
    }

    public func updateBitrateTierDebounced(_ kbps: UInt32) {
        selectedBitrateKbps = kbps
        scheduleDebouncedQualityUpdate()
    }

    public func updateFpsCapDebounced(_ fps: UInt32) {
        selectedFpsCap = fps
        scheduleDebouncedQualityUpdate()
    }

    private func scheduleDebouncedQualityUpdate() {
        let kbps = selectedBitrateKbps
        let fps = selectedFpsCap
        qualityDebouncer.schedule { [weak self] in
            Task { @MainActor [weak self] in
                guard let self, let client = self.client else { return }
                _ = try? client.setVideoQuality(bitrateKbps: kbps, fpsCap: fps)
            }
        }
    }

    // MARK: - Clipboard & File Transfer Drawer

    public func setClipboardSyncEnabled(_ enabled: Bool) {
        guard let client else { return }
        do {
            let reply = try client.setClipboardSync(enabled)
            if reply.ok {
                clipboardSyncEnabled = enabled
                clipboardSyncBadge = enabled ? .idle : .disabled
            } else if isPolicyDeniedCode(reply.errorCode) {
                clipboardSyncEnabled = false
                clipboardSyncBadge = .policyDenied
                appendLog(ClipboardSyncGuard.redactedPolicyDeniedLogLine)
            }
        } catch {
            appendLog("clipboard sync toggle error: \(error)")
        }
    }

    public func sendClipboardText() {
        let text = outboundClipboardText
        guard !text.isEmpty, let client else { return }
        let byteCount = text.utf8.count
        outboundClipboardText = ""
        do {
            let reply = try client.execCommand(["cmd": "send_clipboard", "text": text])
            if reply.ok {
                let bucket = ClipboardSyncGuard.sizeBucket(forByteCount: byteCount)
                clipboardSyncBadge = .synced(sizeBucket: bucket)
                // ZERO clipboard text, hash, or prefix ever written to logs!
                appendLog(ClipboardSyncGuard.redactedSyncLogLine(byteCount: byteCount))
            } else if isPolicyDeniedCode(reply.errorCode) {
                clipboardSyncBadge = .policyDenied
                appendLog(ClipboardSyncGuard.redactedPolicyDeniedLogLine)
            } else {
                setStatus("Clipboard send failed: \(reply.errorCode ?? "error")")
            }
        } catch {
            setStatus("Clipboard send error: \(error)")
        }
    }

    /// Writes remote clipboard text to `NSPasteboard.general` while recording `changeCount`
    /// so local polls skip echoing the remote write back.
    public func applyLocalPasteboardTextAntiEcho(_ text: String) {
        let pb = NSPasteboard.general
        pb.clearContents()
        pb.setString(text, forType: .string)
        clipboardGuard.recordLocalWrite(changeCount: pb.changeCount)
    }

    public func shouldSkipLocalPasteboardPoll() -> Bool {
        clipboardGuard.shouldSuppressEcho(currentChangeCount: NSPasteboard.general.changeCount)
    }

    public func presentFilePickerAndSend() {
        notifyOverlayOpened()
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.prompt = "Send File"
        if panel.runModal() == .OK, let url = panel.url {
            sendFile(at: url.path)
        }
    }

    public func handleDroppedFileProviders(_ providers: [NSItemProvider]) -> Bool {
        var accepted = false
        for provider in providers where provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            accepted = true
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { [weak self] item, _ in
                let url: URL?
                if let data = item as? Data {
                    url = URL(dataRepresentation: data, relativeTo: nil)
                } else if let direct = item as? URL {
                    url = direct
                } else {
                    url = nil
                }
                guard let fileURL = url, fileURL.isFileURL else { return }
                Task { @MainActor [weak self] in
                    self?.sendFile(at: fileURL.path)
                }
            }
        }
        return accepted
    }

    public func sendFile() {
        let path = outboundFilePath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else { return }
        sendFile(at: path)
    }

    public func sendFile(at path: String) {
        guard let client else { return }
        let fileName = URL(fileURLWithPath: path).lastPathComponent
        do {
            let reply = try client.sendFile(at: path)
            if reply.ok {
                setStatus("File transfer queued: \(fileName)")
                appendLog("File transfer queued")
            } else {
                let errMsg: String
                if isPolicyDeniedCode(reply.errorCode) {
                    errMsg = "Policy Denied: \(reply.error ?? "file transfer blocked by policy")"
                } else {
                    errMsg = reply.error ?? reply.errorCode ?? "send file failed"
                }
                setStatus(errMsg)
                appendLog("File transfer rejected: \(reply.errorCode ?? "error")")
                let syntheticId = UInt64(Date().timeIntervalSince1970 * 1000)
                fileTransfers.insert(
                    FileTransferItem(
                        id: syntheticId,
                        relName: fileName,
                        bytesTransferred: 0,
                        totalBytes: 0,
                        statusLabel: isPolicyDeniedCode(reply.errorCode) ? "Policy Denied" : "Failed",
                        isInFlight: false,
                        isError: true,
                        errorMessage: errMsg,
                        checksumAlgo: nil
                    ),
                    at: 0
                )
            }
        } catch {
            setStatus("Send file error: \(error)")
        }
    }

    public func cancelFileTransfer(_ transferId: UInt64) {
        guard let client else { return }
        _ = try? client.cancelFile(transferId: transferId)
    }

    // MARK: - Session Lifecycle Commands

    public func refreshSnapshot() {
        guard let client else { return }
        do {
            let snap = try client.snapshot()
            let wasStreaming = snapshot?.state == "streaming"
            snapshot = snap
            if let v = snap.abiVersion {
                abiVersion = v
            }
            if let snapCaps = snap.caps, !snapCaps.isEmpty {
                capabilities = Set(snapCaps)
            }
            if let enabled = snap.enableOsInput {
                applyAcknowledgedInputEnabled(enabled)
            }
            if let clipOn = snap.clipboardSyncEnabled {
                clipboardSyncEnabled = clipOn
            }
            if wasStreaming && snap.state != "streaming" {
                inputGate?.releaseAll(reason: .sessionLeftConnected)
                applyAcknowledgedInputEnabled(false)
            }
            if let cfg = snap.config, !isSettingsPresented {
                controlPlaneEndpoint = cfg.controlPlaneEndpoint
                signalingAddr = cfg.signalingAddr
                transportMode = cfg.transportMode
                codec = cfg.codec
                if !isSessionStreaming {
                    activeCodecLabel = cfg.codec
                    selectedCodecOption = cfg.codec
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
            fps: selectedFpsCap,
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
        applyAcknowledgedInputEnabled(false)
        runSimpleCommand(["cmd": "start_host", "codec": codec], label: "Start Host")
    }

    public func stopHost() {
        clearVideoState(releaseReason: .sessionLeftConnected)
        applyAcknowledgedInputEnabled(false)
        runSimpleCommand(["cmd": "stop_host"], label: "Stop Host")
    }

    public func dial() {
        let trimmed = targetDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            setStatus("Enter a 32-hex target Device ID")
            return
        }
        applyAcknowledgedInputEnabled(false)
        activeCodecLabel = codec
        selectedCodecOption = codec
        runSimpleCommand(
            ["cmd": "dial", "target_device_id_hex": trimmed, "codec": codec],
            label: "Dial"
        )
    }

    public func disconnect() {
        clearVideoState(releaseReason: .sessionLeftConnected)
        applyAcknowledgedInputEnabled(false)
        runSimpleCommand(["cmd": "disconnect"], label: "Disconnect")
    }

    /// Emergency escape (`Ctrl+Opt+Cmd+Escape`): `InputGate` already emitted `release_all` and
    /// disabled input locally; sync `set_input_enabled(false, reason: "emergency_escape")` with Rust!
    public func handleEmergencyEscapeTriggered() {
        applyAcknowledgedInputEnabled(false)
        if let client {
            _ = try? client.setInputEnabled(false, reason: "emergency_escape")
        }
        setStatus("Emergency Escape (Ctrl+Opt+Cmd+Esc): released all inputs & returned to View-Only")
        showToast("Emergency Escape triggered — OS input disabled (View-Only).")
        appendLog("Emergency Escape: released all inputs & disabled OS input")
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

    public func shutdown() {
        codecAckTimeoutTask?.cancel()
        qualityDebouncer.cancel()
        clearVideoState(releaseReason: .viewTeardownOrTerminate)
        inputGate?.stop()
        if let client {
            _ = try? client.releaseAllInput(reason: .viewTeardownOrTerminate)
            _ = try? client.execCommand(["cmd": "disconnect"])
            _ = try? client.execCommand(["cmd": "stop_host"])
            client.close()
        }
        inputGate = nil
        client = nil
    }

    // MARK: - Private Event Handling

    private func clearVideoState(releaseReason: ReleaseReason) {
        inputGate?.releaseAll(reason: releaseReason)
        frameGeneration &+= 1
        hasPendingFrame = false
        hasVideoFrame = false
        remoteSize = RemoteSize(width: 0, height: 0)
        scrollOffset = .zero
        hudStats = HudStatsPayload()
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

        let rawData = Data(ev.rawJSON.utf8)
        if let parsed = try? ParsedBridgeEvent.decodeForwardCompat(from: rawData) {
            switch parsed {
            case .hudStats(let stats):
                // Strictly 1 Hz HUD update (zero per-frame SwiftUI redraws!).
                hudStats = stats
                if !stats.activeCodec.isEmpty {
                    activeCodecLabel = stats.activeCodec
                    if pendingCodecRequest == stats.activeCodec {
                        codecAckTimeoutTask?.cancel()
                        pendingCodecRequest = nil
                        selectedCodecOption = stats.activeCodec
                    }
                }
                return

            case .permissionStatus(let report):
                permissionStatus = report
                applyAcknowledgedInputEnabled(report.enableOsInput)
                if !report.screenCaptureGranted && isSessionStreaming {
                    clearVideoState(releaseReason: .sessionLeftConnected)
                    openPermissionGuide()
                    showToast("Screen Recording permission revoked — capture stopped.")
                }
                return

            case .inputEnabledAck(let ack):
                applyAcknowledgedInputEnabled(ack.enabled)
                if ack.status == "not_permitted" {
                    showToast("OS input denied: Screen Recording and Accessibility permissions required.")
                    openPermissionGuide()
                }
                return

            case .codecAck(let ack):
                codecAckTimeoutTask?.cancel()
                pendingCodecRequest = nil
                activeCodecLabel = ack.activeCodec
                selectedCodecOption = ack.activeCodec
                if !ack.accepted {
                    showToast("Peer rejected codec switch; using \(ack.activeCodec.uppercased()).")
                }
                return

            case .videoQualityAck(let ack):
                selectedBitrateKbps = ack.bitrateKbps
                selectedFpsCap = ack.fpsCap
                return

            case .clipboardSyncStatus(let st):
                clipboardSyncEnabled = st.enabled
                if st.status == "policy_denied" || isPolicyDeniedCode(st.code) {
                    clipboardSyncBadge = .policyDenied
                    appendLog(ClipboardSyncGuard.redactedPolicyDeniedLogLine)
                } else if !st.enabled {
                    clipboardSyncBadge = .disabled
                } else {
                    clipboardSyncBadge = .idle
                }
                return

            case .fileTransferComplete(let done):
                upsertFileTransfer(
                    id: done.transferId,
                    relName: done.relName,
                    bytesTransferred: done.bytes,
                    totalBytes: done.bytes,
                    statusLabel: "Completed",
                    isInFlight: false,
                    isError: false,
                    errorMessage: nil,
                    checksumAlgo: done.checksumAlgo
                )
                appendLog("FileTransferComplete (#\(done.transferId))")
                return

            case .unknown:
                // Unknown event kinds/fields are ignored safely without error or disconnect!
                break
            }
        }

        if ev.kind == "QoeTelemetry" {
            if let active = ev.payloadJSON["active_codec"], !active.isEmpty {
                activeCodecLabel = active
            }
            return
        }

        if ev.kind == "ClipboardReceived" {
            let bytes = Int(ev.payloadJSON["bytes"] ?? "0") ?? 0
            let bucket = ClipboardSyncGuard.sizeBucket(forByteCount: bytes)
            clipboardSyncBadge = .synced(sizeBucket: bucket)
            // Strictly log ONLY byte-size bucket (ZERO text, hash, or prefix!).
            appendLog(ClipboardSyncGuard.redactedSyncLogLine(byteCount: bytes))
            return
        }

        if ev.kind == "PolicyDenied" {
            let channel = ev.payloadJSON["channel"] ?? ""
            if channel == "clipboard" {
                clipboardSyncBadge = .policyDenied
                appendLog(ClipboardSyncGuard.redactedPolicyDeniedLogLine)
            } else {
                appendLog("PolicyDenied (\(channel))")
            }
            return
        }

        if ev.kind == "HostCapabilityDegraded",
           ev.payloadJSON["capability"] == "screen_recording_revoked"
        {
            clearVideoState(releaseReason: .sessionLeftConnected)
            applyAcknowledgedInputEnabled(false)
            openPermissionGuide()
            showToast("Screen Recording permission revoked mid-session — capture stopped.")
            appendLog("[\(ev.seq)] screen_recording_revoked")
            refreshSnapshot()
            return
        }

        if ev.kind == "FileTransferProgress",
           let tid = UInt64(ev.payloadJSON["transfer_id"] ?? "")
        {
            let transferred = UInt64(ev.payloadJSON["bytes_transferred"] ?? "0") ?? 0
            let total = UInt64(ev.payloadJSON["total_bytes"] ?? "0") ?? 0
            upsertFileTransfer(
                id: tid,
                relName: "Transfer #\(tid)",
                bytesTransferred: transferred,
                totalBytes: total,
                statusLabel: "Transferring...",
                isInFlight: true,
                isError: false,
                errorMessage: nil,
                checksumAlgo: nil
            )
            return
        }

        if ev.kind == "FileTransferAborted",
           let tid = UInt64(ev.payloadJSON["transfer_id"] ?? "")
        {
            let reason = ev.payloadJSON["reason"] ?? "aborted"
            upsertFileTransfer(
                id: tid,
                relName: "Transfer #\(tid)",
                bytesTransferred: 0,
                totalBytes: 0,
                statusLabel: "Aborted",
                isInFlight: false,
                isError: true,
                errorMessage: reason,
                checksumAlgo: nil
            )
            appendLog("FileTransferAborted (#\(tid))")
            return
        }

        appendLog("[\(ev.seq)] \(ev.kind)")
        if ev.kind == "IncomingCall", let incomingId = ev.payloadJSON["incoming_id"] {
            notifyOverlayOpened()
            let verifiedByCa = ev.payloadBools["verified_by_ca"] ?? false
            incomingCall = IncomingCallPrompt(
                id: incomingId,
                callerDeviceId: ev.payloadJSON["caller_device_id_hex"] ?? "unknown",
                callerTenantId: ev.payloadJSON["caller_tenant_id_hex"] ?? "unknown",
                verifiedByCa: verifiedByCa
            )
        } else if ev.kind == "SessionEnded" {
            clearVideoState(releaseReason: .sessionLeftConnected)
            applyAcknowledgedInputEnabled(false)
            incomingCall = nil
        }
        refreshSnapshot()
    }

    private func upsertFileTransfer(
        id: UInt64,
        relName: String,
        bytesTransferred: UInt64,
        totalBytes: UInt64,
        statusLabel: String,
        isInFlight: Bool,
        isError: Bool,
        errorMessage: String?,
        checksumAlgo: String?
    ) {
        if let idx = fileTransfers.firstIndex(where: { $0.id == id }) {
            var existing = fileTransfers[idx]
            if !relName.hasPrefix("Transfer #") {
                existing.relName = relName
            }
            existing.bytesTransferred = bytesTransferred
            if totalBytes > 0 {
                existing.totalBytes = totalBytes
            }
            existing.statusLabel = statusLabel
            existing.isInFlight = isInFlight
            existing.isError = isError
            existing.errorMessage = errorMessage
            if let checksumAlgo {
                existing.checksumAlgo = checksumAlgo
            }
            fileTransfers[idx] = existing
        } else {
            fileTransfers.insert(
                FileTransferItem(
                    id: id,
                    relName: relName,
                    bytesTransferred: bytesTransferred,
                    totalBytes: totalBytes,
                    statusLabel: statusLabel,
                    isInFlight: isInFlight,
                    isError: isError,
                    errorMessage: errorMessage,
                    checksumAlgo: checksumAlgo
                ),
                at: 0
            )
            if fileTransfers.count > 20 {
                fileTransfers.removeLast(fileTransfers.count - 20)
            }
        }
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
                // Submit directly to Metal renderer — ZERO per-frame SwiftUI redraws!
                self.metalRenderer?.submitFrame(captured)
                if !self.hasVideoFrame {
                    self.hasVideoFrame = true
                }
                let nextSize = RemoteSize(width: captured.width, height: captured.height)
                if nextSize != self.remoteSize {
                    self.inputGate?.releaseAll(reason: .viewportChanged)
                    self.remoteSize = nextSize
                }
            }
            if self.hasPendingFrame, gen == self.frameGeneration {
                self.hasPendingFrame = false
                self.scheduleFrameFetch()
            }
        }
    }

    private func isPolicyDeniedCode(_ code: String?) -> Bool {
        guard let code else { return false }
        let norm = code.lowercased()
        return norm == "policy_denied" || norm == "policydenied"
    }

    private func showToast(_ message: String) {
        toastNotice = sanitizeLogMessage(message)
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
