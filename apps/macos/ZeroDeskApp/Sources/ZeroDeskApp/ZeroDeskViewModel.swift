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
        let raw = Double(bytesTransferred) / Double(totalBytes)
        guard raw.isFinite else { return 0.0 }
        return min(max(raw, 0.0), 1.0)
    }
}

/// Isolated `@MainActor` store for 1 Hz HUD telemetry so `hud_stats` updates redraw ONLY
/// `TelemetryHudView` instead of invalidating the entire `ContentView` hierarchy.
@MainActor
public final class HudStatsStore: ObservableObject {
    @Published public var stats: HudStatsPayload = HudStatsPayload()

    public init() {}
}

@MainActor
public final class ZeroDeskViewModel: ObservableObject {
    private static let defaultMaxDropFileBytes: UInt64 = 512 * 1024 * 1024 // 512 MiB hard UI cap

    private final class AppMonitorCleanupBox: @unchecked Sendable {
        private let lock = NSLock()
        private var escapeMonitor: Any?
        private var observers: [NSObjectProtocol] = []

        func setEscapeMonitor(_ monitor: Any?) {
            let old: Any?
            lock.lock()
            old = escapeMonitor
            escapeMonitor = monitor
            lock.unlock()
            if let old {
                NSEvent.removeMonitor(old)
            }
        }

        func setObservers(_ next: [NSObjectProtocol]) {
            let old: [NSObjectProtocol]
            lock.lock()
            old = observers
            observers = next
            lock.unlock()
            for obs in old {
                NotificationCenter.default.removeObserver(obs)
            }
        }

        func teardownAll() {
            setEscapeMonitor(nil)
            setObservers([])
        }
    }

    @Published public var snapshot: BridgeSnapshot?
    @Published public var selftest: OsSelftestReport?
    @Published public var permissionStatus: PermissionStatusReport?
    @Published public var abiVersion: UInt32 = 2
    @Published public var capabilities: Set<String> = []

    // Per-session OS input control (default OFF, NEVER persisted, strictly Rust-acknowledged!).
    @Published public var isOsInputEnabled: Bool = false
    @Published public var isInputTogglePending: Bool = false
    @Published public var inputRevokedNotice: String?
    @Published public var isPermissionGuidePresented: Bool = false {
        didSet {
            if isPermissionGuidePresented {
                inputGate?.releaseAll(reason: .sheetPresented)
            }
        }
    }

    // Viewport & session control drawer state.
    @Published public var hasVideoFrame: Bool = false
    @Published public var remoteSize: RemoteSize = RemoteSize(width: 0, height: 0)
    @Published public var displayScaleMode: DisplayScaleMode = .fit
    @Published public var scrollOffset: CGPoint = .zero
    @Published public var isControlDrawerOpen: Bool = false

    // Isolated 1 Hz HUD telemetry store (zero full-view-tree SwiftUI redraws!).
    public let hudStore = HudStatsStore()
    public var hudStats: HudStatsPayload { hudStore.stats }

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
    @Published public var isSettingsPresented: Bool = false {
        didSet {
            if isSettingsPresented {
                inputGate?.releaseAll(reason: .sheetPresented)
            }
        }
    }

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

    /// Single truth source for macOS Screen Recording & Accessibility permission state across
    /// `ContentView`, `SessionControlPanelView`, and `SystemPermissionGuideView`.
    public var effectivePermissionStatus: PermissionStatusReport? {
        if let report = permissionStatus {
            return report
        }
        guard let st = selftest else { return nil }
        return PermissionStatusReport(
            screenCaptureGranted: st.screenRecording.granted,
            accessibilityGranted: st.accessibility.granted,
            probeSource: .uiProcessHint,
            enableOsInput: isOsInputEnabled
        )
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
    private let monitorCleanupBox = AppMonitorCleanupBox()
    private var codecAckTimeoutTask: Task<Void, Never>?
    private var inputToggleTimeoutTask: Task<Void, Never>?
    private var pendingCodecRequest: String?
    private var isRefreshingPermissions = false
    private var isFrameFetchScheduled = false
    private var hasPendingFrame = false
    private var frameGeneration: UInt64 = 0
    private var syntheticTransferCounter: UInt64 = 0

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
            self.inputGate = InputGate(sink: bridge)

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

        installAppLevelMonitors()
    }

    deinit {
        monitorCleanupBox.teardownAll()
    }

    private func installAppLevelMonitors() {
        // Unconditional app-level Emergency Escape (`Ctrl+Opt+Cmd+Escape`) monitor — active
        // regardless of which view/drawer/sheet holds first responder!
        let escapeMonitor = NSEvent.addLocalMonitorForEvents(matching: .keyDown) { [weak self] event in
            let consumed = MainActor.assumeIsolated { () -> Bool in
                guard let self else { return false }
                let flags = event.modifierFlags
                var hidMods: UInt8 = 0
                if flags.contains(.shift) { hidMods |= HidModifierMask.shift }
                if flags.contains(.control) { hidMods |= HidModifierMask.ctrl }
                if flags.contains(.option) { hidMods |= HidModifierMask.alt }
                if flags.contains(.command) { hidMods |= HidModifierMask.meta }
                let usage = MacHidKeyMap().lookup(event.keyCode)
                guard let usage,
                      MacHidKeyMap.isEmergencyEscapeCombo(usageId: usage, modifiers: hidMods)
                else {
                    return false
                }
                let shouldIntercept = self.isSessionStreaming
                    || self.isOsInputEnabled
                    || (self.inputGate?.hasAnyPressedInput == true)
                guard shouldIntercept else { return false }
                self.inputGate?.releaseAll(reason: .emergencyEscapeHotkey, forceEmit: true)
                self.handleEmergencyEscapeTriggered()
                return true
            }
            return consumed ? nil : event
        }
        monitorCleanupBox.setEscapeMonitor(escapeMonitor)

        // Auto-refresh permissions whenever the user switches back from System Settings.
        let becomeActive = NotificationCenter.default.addObserver(
            forName: NSApplication.didBecomeActiveNotification,
            object: NSApp,
            queue: .main
        ) { [weak self] _ in
            MainActor.assumeIsolated {
                self?.refreshPermissions()
            }
        }
        monitorCleanupBox.setObservers([becomeActive])
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
    /// Deduplicates overlapping calls triggered by notifications + polling.
    public func refreshPermissions() {
        guard !isRefreshingPermissions else { return }
        isRefreshingPermissions = true
        defer { isRefreshingPermissions = false }

        refreshSelftest()
        guard let client else { return }
        if let report = try? client.getPermissions() {
            let wasEnabled = isOsInputEnabled
            permissionStatus = report
            if wasEnabled && !report.allRequiredPermissionsGranted {
                inputRevokedNotice = "Input suspended — permission revoked"
            } else if report.allRequiredPermissionsGranted {
                inputRevokedNotice = nil
            }
            applyAcknowledgedInputEnabled(report.enableOsInput)
        }
    }

    public func openPermissionSettings(for permission: MacSystemPermissionKind) {
        if SystemPermissionLinks.openSettings(for: permission) == nil {
            showToast("Could not open System Settings automatically. Open System Settings -> Privacy & Security manually.")
        }
    }

    public func openPermissionGuide() {
        notifyOverlayOpened()
        isPermissionGuidePresented = true
    }

    public func closePermissionGuide() {
        isPermissionGuidePresented = false
        refreshPermissions()
    }

    /// Requests toggling per-session `enable_os_input` over JSON-ABI.
    /// NEVER optimistically flips `isOsInputEnabled` locally — UI updates strictly on Rust ack!
    public func requestSetInputEnabled(_ enabled: Bool, reason: String? = nil) {
        guard let client else { return }
        isInputTogglePending = true
        inputToggleTimeoutTask?.cancel()
        inputToggleTimeoutTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard let self, !Task.isCancelled, self.isInputTogglePending else { return }
            self.isInputTogglePending = false
            if enabled {
                self.applyAcknowledgedInputEnabled(false)
            }
            self.showToast("OS input toggle timed out (3s); remaining in View-Only mode.")
        }
        do {
            let reply = try client.setInputEnabled(enabled, reason: reason)
            if !reply.ok {
                inputToggleTimeoutTask?.cancel()
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
            inputToggleTimeoutTask?.cancel()
            isInputTogglePending = false
            showToast("Input toggle error: \(error)")
        }
    }

    private func applyAcknowledgedInputEnabled(_ enabled: Bool) {
        inputToggleTimeoutTask?.cancel()
        let screenOk = effectivePermissionStatus?.screenCaptureGranted ?? true
        let effectiveEnabled = enabled && screenOk
        isOsInputEnabled = effectiveEnabled
        isInputTogglePending = false
        if effectiveEnabled {
            inputRevokedNotice = nil
        }
        inputGate?.setInputEnabledFromAck(effectiveEnabled)
    }

    /// Unified fail-closed helper invoked at every session boundary, permission revocation, and
    /// Emergency Escape to guarantee Swift `InputGate` and Rust `enable_os_input` never diverge.
    private func forceDisableInputAndSync(reason: String, releaseReason: ReleaseReason = .inputDisabled) {
        inputGate?.releaseAll(reason: releaseReason)
        applyAcknowledgedInputEnabled(false)
        if let client {
            _ = try? client.setInputEnabled(false, reason: reason)
        }
    }

    // MARK: - Overlay & Viewport Controls (Anti-Stuck-Key Triggers)

    public func notifyOverlayOpened() {
        inputGate?.notifyOverlayOpened()
    }

    public func toggleControlDrawer() {
        notifyOverlayOpened()
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
        let previousSelected = selectedCodecOption
        let previousCodec = codec
        notifyOverlayOpened()
        selectedCodecOption = requested
        codec = requested
        guard let client else {
            selectedCodecOption = previousSelected
            codec = previousCodec
            return
        }

        if !isSessionStreaming {
            do {
                let reply = try client.setCodec(requested)
                if reply.ok {
                    activeCodecLabel = requested
                    refreshSnapshot()
                } else {
                    selectedCodecOption = previousSelected
                    codec = previousCodec
                    showToast("Codec change rejected: \(reply.error ?? reply.errorCode ?? "unsupported")")
                }
            } catch {
                selectedCodecOption = previousSelected
                codec = previousCodec
                showToast("Codec change error: \(error)")
            }
            return
        }

        startCodecAckTimeout(for: requested)

        do {
            let reply = try client.setCodec(requested)
            if !reply.ok {
                codecAckTimeoutTask?.cancel()
                pendingCodecRequest = nil
                selectedCodecOption = activeCodecLabel
                codec = activeCodecLabel
                showToast("Codec change rejected: \(reply.error ?? reply.errorCode ?? "unsupported")")
            }
        } catch {
            codecAckTimeoutTask?.cancel()
            pendingCodecRequest = nil
            selectedCodecOption = activeCodecLabel
            codec = activeCodecLabel
            showToast("Codec change error: \(error)")
        }
    }

    private func startCodecAckTimeout(for requested: String) {
        pendingCodecRequest = requested
        codecAckTimeoutTask?.cancel()
        codecAckTimeoutTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 3_000_000_000)
            guard let self, !Task.isCancelled, self.pendingCodecRequest == requested else { return }
            self.pendingCodecRequest = nil
            self.selectedCodecOption = self.activeCodecLabel
            self.codec = self.activeCodecLabel
            self.showToast("Codec switch to \(requested.uppercased()) timed out (3s); reverted to \(self.activeCodecLabel.uppercased()).")
        }
    }

    public func updateBitrateTierDebounced(_ kbps: UInt32) {
        notifyOverlayOpened()
        selectedBitrateKbps = kbps
        scheduleDebouncedQualityUpdate()
    }

    public func updateFpsCapDebounced(_ fps: UInt32) {
        notifyOverlayOpened()
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
        outboundClipboardText = ""
        sendClipboardText(text)
    }

    public func sendClipboardText(_ text: String) {
        guard !text.isEmpty, let client else { return }
        let byteCount = text.utf8.count
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

    /// Writes remote clipboard text to `NSPasteboard.general` while bracketing `changeCount`
    /// (`before < current <= after`) so local polls skip echoing the remote write back without
    /// suppressing concurrent external user copies.
    public func applyLocalPasteboardTextAntiEcho(_ text: String) {
        let pb = NSPasteboard.general
        let before = pb.changeCount
        clipboardGuard.beginLocalWrite(changeCountBefore: before)
        pb.clearContents()
        pb.setString(text, forType: .string)
        clipboardGuard.endLocalWrite(changeCountAfter: pb.changeCount)
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
            validateAndSendFile(at: url)
        }
    }

    public func handleDroppedFileProviders(_ providers: [NSItemProvider]) -> Bool {
        var accepted = false
        for provider in providers where provider.hasItemConformingToTypeIdentifier(UTType.fileURL.identifier) {
            accepted = true
            provider.loadItem(forTypeIdentifier: UTType.fileURL.identifier, options: nil) { [weak self] item, error in
                if let error {
                    Task { @MainActor [weak self] in
                        self?.showToast("Dropped item unreadable: \(error.localizedDescription)")
                    }
                    return
                }
                let url: URL?
                if let data = item as? Data {
                    url = URL(dataRepresentation: data, relativeTo: nil)
                } else if let direct = item as? URL {
                    url = direct
                } else if let str = item as? String {
                    url = URL(string: str)
                } else {
                    url = nil
                }
                guard let fileURL = url, fileURL.isFileURL else {
                    Task { @MainActor [weak self] in
                        self?.showToast("Only local regular files can be transferred.")
                    }
                    return
                }
                Task { @MainActor [weak self] in
                    self?.validateAndSendFile(at: fileURL)
                }
            }
        }
        return accepted
    }

    public func sendFile() {
        let path = outboundFilePath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else { return }
        validateAndSendFile(at: URL(fileURLWithPath: path))
    }

    private func maxAllowedTransferBytes() -> UInt64 {
        if let policyMax = snapshot?.policy?.maxFileBytes, policyMax > 0 {
            return min(policyMax, Self.defaultMaxDropFileBytes)
        }
        return Self.defaultMaxDropFileBytes
    }

    private func validateAndSendFile(at url: URL) {
        let maxBytes = maxAllowedTransferBytes()
        let fileName = url.lastPathComponent.isEmpty ? url.path : url.lastPathComponent
        Task { @MainActor [weak self] in
            let validationError = await Task.detached(priority: .userInitiated) {
                Self.validateLocalTransferFile(at: url, maxBytes: maxBytes)
            }.value
            guard let self else { return }
            if let validationError {
                self.recordLocalFileTransferError(fileName: fileName, message: validationError)
            } else {
                self.sendFile(at: url.path)
            }
        }
    }

    private nonisolated static func validateLocalTransferFile(at url: URL, maxBytes: UInt64) -> String? {
        let path = url.path
        var st = stat()
        guard lstat(path, &st) == 0 else {
            return "File does not exist or cannot be accessed."
        }
        let fileType = st.st_mode & S_IFMT
        if fileType == S_IFLNK {
            return "Symbolic links cannot be transferred."
        }
        if fileType == S_IFDIR {
            return "Directories cannot be transferred."
        }
        if fileType != S_IFREG {
            return "Only regular files can be transferred."
        }
        let size = UInt64(max(0, st.st_size))
        if size > maxBytes {
            let maxMiB = maxBytes / (1024 * 1024)
            return "File exceeds maximum transfer size (\(maxMiB) MiB)."
        }
        return nil
    }

    private func recordLocalFileTransferError(fileName: String, message: String) {
        showToast(message)
        setStatus(message)
        appendLog("File transfer rejected locally")
        syntheticTransferCounter &+= 1
        let syntheticId = UInt64(Date().timeIntervalSince1970 * 1000) &+ syntheticTransferCounter
        fileTransfers.insert(
            FileTransferItem(
                id: syntheticId,
                relName: fileName,
                bytesTransferred: 0,
                totalBytes: 0,
                statusLabel: "Rejected",
                isInFlight: false,
                isError: true,
                errorMessage: message,
                checksumAlgo: nil
            ),
            at: 0
        )
        if fileTransfers.count > 20 {
            fileTransfers.removeLast(fileTransfers.count - 20)
        }
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
                syntheticTransferCounter &+= 1
                let syntheticId = UInt64(Date().timeIntervalSince1970 * 1000) &+ syntheticTransferCounter
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
                forceDisableInputAndSync(reason: "session_ended", releaseReason: .sessionLeftConnected)
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
        forceDisableInputAndSync(reason: "start_host", releaseReason: .sessionLeftConnected)
        runSimpleCommand(["cmd": "start_host", "codec": codec], label: "Start Host")
    }

    public func stopHost() {
        clearVideoState(releaseReason: .sessionLeftConnected)
        forceDisableInputAndSync(reason: "stop_host", releaseReason: .sessionLeftConnected)
        runSimpleCommand(["cmd": "stop_host"], label: "Stop Host")
    }

    public func dial() {
        let trimmed = targetDeviceId.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            setStatus("Enter a 32-hex target Device ID")
            return
        }
        forceDisableInputAndSync(reason: "dial_start", releaseReason: .sessionLeftConnected)
        activeCodecLabel = codec
        selectedCodecOption = codec
        startCodecAckTimeout(for: codec)
        runSimpleCommand(
            ["cmd": "dial", "target_device_id_hex": trimmed, "codec": codec],
            label: "Dial"
        )
    }

    public func disconnect() {
        clearVideoState(releaseReason: .sessionLeftConnected)
        forceDisableInputAndSync(reason: "disconnect", releaseReason: .sessionLeftConnected)
        runSimpleCommand(["cmd": "disconnect"], label: "Disconnect")
    }

    /// Emergency escape (`Ctrl+Opt+Cmd+Escape`): `InputGate` already emitted `release_all` and
    /// disabled input locally; sync `set_input_enabled(false, reason: "emergency_escape")` with Rust!
    public func handleEmergencyEscapeTriggered() {
        forceDisableInputAndSync(reason: "emergency_escape", releaseReason: .emergencyEscapeHotkey)
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
        monitorCleanupBox.teardownAll()
        codecAckTimeoutTask?.cancel()
        inputToggleTimeoutTask?.cancel()
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
        inputRevokedNotice = nil
        hudStore.stats = HudStatsPayload()
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
                // Strictly 1 Hz HUD update isolated in `hudStore` (zero full-view-tree redraws!).
                hudStore.stats = stats
                if !stats.activeCodec.isEmpty {
                    if activeCodecLabel != stats.activeCodec {
                        activeCodecLabel = stats.activeCodec
                    }
                    if pendingCodecRequest == stats.activeCodec {
                        codecAckTimeoutTask?.cancel()
                        pendingCodecRequest = nil
                        selectedCodecOption = stats.activeCodec
                        codec = stats.activeCodec
                    }
                }
                return

            case .permissionStatus(let report):
                let wasEnabled = isOsInputEnabled
                permissionStatus = report
                if wasEnabled && !report.allRequiredPermissionsGranted {
                    inputRevokedNotice = "Input suspended — permission revoked"
                } else if report.allRequiredPermissionsGranted {
                    inputRevokedNotice = nil
                }
                if !report.screenCaptureGranted && isSessionStreaming {
                    forceDisableInputAndSync(
                        reason: "screen_capture_revoked",
                        releaseReason: .sessionLeftConnected
                    )
                    clearVideoState(releaseReason: .sessionLeftConnected)
                    inputRevokedNotice = "Input suspended — permission revoked"
                    openPermissionGuide()
                    showToast("Screen Recording permission revoked — capture stopped.")
                } else {
                    applyAcknowledgedInputEnabled(report.enableOsInput)
                }
                return

            case .inputEnabledAck(let ack):
                let wasEnabled = isOsInputEnabled
                applyAcknowledgedInputEnabled(ack.enabled)
                if ack.releaseAll == "failed" {
                    showToast("Warning: OS key release reported failure; press Emergency Escape if keys feel stuck.")
                    appendLog("input_enabled_ack reported release_all=failed")
                }
                if ack.status == "not_permitted" {
                    if wasEnabled {
                        inputRevokedNotice = "Input suspended — permission revoked"
                    }
                    showToast("OS input denied: Screen Recording and Accessibility permissions required.")
                    openPermissionGuide()
                } else if !ack.enabled && ack.reason == "permission_lost" {
                    inputRevokedNotice = "Input suspended — permission revoked"
                    showToast("Input suspended — permission revoked.")
                }
                return

            case .codecAck(let ack):
                codecAckTimeoutTask?.cancel()
                pendingCodecRequest = nil
                activeCodecLabel = ack.activeCodec
                selectedCodecOption = ack.activeCodec
                codec = ack.activeCodec
                if !ack.accepted {
                    showToast("Peer rejected codec switch; using \(ack.activeCodec.uppercased()).")
                }
                return

            case .videoQualityAck(let ack):
                if !qualityDebouncer.isPending {
                    selectedBitrateKbps = ack.bitrateKbps
                    selectedFpsCap = ack.fpsCap
                }
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

            case .malformed(let kind):
                appendLog("[\(ev.seq)] Malformed bridge event (\(kind)) ignored")
                return

            case .unknown:
                // Unknown event kinds/fields are ignored safely without error or disconnect!
                break
            }
        }

        if ev.kind == "QoeTelemetry" {
            // Active codec is updated strictly from peer-confirmed `codec_ack` / `hud_stats`.
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

        if ev.kind == "HostCapabilityDegraded" {
            let capability = ev.payloadJSON["capability"] ?? "unknown"
            if capability == "screen_recording_revoked" {
                forceDisableInputAndSync(
                    reason: "screen_recording_revoked",
                    releaseReason: .sessionLeftConnected
                )
                clearVideoState(releaseReason: .sessionLeftConnected)
                inputRevokedNotice = "Input suspended — permission revoked"
                openPermissionGuide()
                showToast("Screen Recording permission revoked mid-session — capture stopped.")
                appendLog("[\(ev.seq)] screen_recording_revoked")
                refreshSnapshot()
            } else {
                forceDisableInputAndSync(
                    reason: "capability_degraded",
                    releaseReason: .inputDisabled
                )
                showToast("Host capability degraded (\(capability)).")
                appendLog("[\(ev.seq)] HostCapabilityDegraded (\(capability))")
            }
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
            // Ensure the incoming call approval sheet always takes priority over settings/guide!
            isSettingsPresented = false
            isPermissionGuidePresented = false
            let verifiedByCa = ev.payloadBools["verified_by_ca"] ?? false
            incomingCall = IncomingCallPrompt(
                id: incomingId,
                callerDeviceId: ev.payloadJSON["caller_device_id_hex"] ?? "unknown",
                callerTenantId: ev.payloadJSON["caller_tenant_id_hex"] ?? "unknown",
                verifiedByCa: verifiedByCa
            )
        } else if ev.kind == "SessionEnded" {
            codecAckTimeoutTask?.cancel()
            pendingCodecRequest = nil
            clearVideoState(releaseReason: .sessionLeftConnected)
            forceDisableInputAndSync(reason: "session_ended", releaseReason: .sessionLeftConnected)
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
