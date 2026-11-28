// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import SwiftUI
import ZeroDeskBridge

public struct ContentView: View {
    @ObservedObject var vm: ZeroDeskViewModel

    public init(vm: ZeroDeskViewModel) {
        self.vm = vm
    }

    public var body: some View {
        VStack(spacing: 0) {
            topStatusBar
            Divider()
            HSplitView {
                sidebar
                    .frame(minWidth: 280, idealWidth: 310, maxWidth: 360)
                mainCanvasArea
                    .frame(minWidth: 560, maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .frame(minWidth: 920, minHeight: 620)
        .sheet(isPresented: $vm.isSettingsPresented) {
            SettingsSheetView(vm: vm)
        }
        .sheet(isPresented: $vm.isPermissionGuidePresented, onDismiss: {
            vm.refreshPermissions()
        }) {
            SystemPermissionGuideView(vm: vm) {
                vm.closePermissionGuide()
            }
        }
        .sheet(item: $vm.incomingCall) { call in
            IncomingCallSheetView(call: call, onAccept: vm.acceptIncoming, onReject: vm.rejectIncoming)
        }
    }

    private var topStatusBar: some View {
        HStack(spacing: 12) {
            Label(vm.snapshot?.state.uppercased() ?? "OFFLINE", systemImage: "bolt.horizontal.circle.fill")
                .font(.headline)
                .foregroundColor(stateColor)

            if let mode = vm.snapshot?.activeTransportMode ?? vm.snapshot?.transportMode {
                Text("Transport: \(mode)")
                    .font(.caption)
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(Color.secondary.opacity(0.15))
                    .clipShape(Capsule())
            }

            if let policy = vm.snapshot?.policy {
                HStack(spacing: 6) {
                    policyBadge("Audio", enabled: policy.allowAudio)
                    policyBadge("Clip", enabled: policy.allowClipboard)
                    policyBadge("Files", enabled: policy.allowFileTransfer)
                }
            }

            Spacer()

            Text(vm.statusMessage)
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(1)

            Button {
                vm.openPermissionGuide()
            } label: {
                Label("Permissions", systemImage: "lock.shield")
                    .font(.caption)
            }
            .help("Open macOS Screen Recording & Accessibility Permission Guide")

            Button(action: vm.toggleMute) {
                Image(systemName: (vm.snapshot?.audioMuted ?? false) ? "speaker.slash.fill" : "speaker.wave.2.fill")
            }
            .help("Toggle Audio Mute")

            Button("Settings") {
                vm.openSettingsSheet()
            }
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 10)
    }

    private var sidebar: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                GroupBox("OS Permissions & Preflight") {
                    VStack(alignment: .leading, spacing: 6) {
                        if let perms = vm.effectivePermissionStatus {
                            permissionStatusRow("Screen Recording", granted: perms.screenCaptureGranted)
                            permissionStatusRow("Accessibility", granted: perms.accessibilityGranted)
                        } else if let st = vm.selftest {
                            preflightRow("Screen Recording", outcome: st.screenRecording)
                            preflightRow("Accessibility", outcome: st.accessibility)
                        } else {
                            Text("Preflight pending...").font(.caption).foregroundColor(.secondary)
                        }
                        if let st = vm.selftest {
                            HStack {
                                Text("Audio Devices")
                                    .font(.caption)
                                Spacer()
                                Text("in:\(st.audio.inputDeviceCount) out:\(st.audio.outputDeviceCount)")
                                    .font(.caption.monospaced())
                                    .foregroundColor(.secondary)
                            }
                            HStack {
                                Text("Clipboard Read-Only")
                                    .font(.caption)
                                Spacer()
                                Text(st.clipboardReadonlyAvailable ? "OK" : "Unavailable")
                                    .font(.caption)
                                    .foregroundColor(st.clipboardReadonlyAvailable ? .green : .orange)
                            }
                        }
                        HStack(spacing: 8) {
                            Button("Refresh", action: vm.refreshPermissions)
                                .controlSize(.small)
                            Button("Permission Guide...", action: vm.openPermissionGuide)
                                .controlSize(.small)
                        }
                    }
                    .padding(4)
                }

                GroupBox("Host Mode") {
                    VStack(alignment: .leading, spacing: 8) {
                        if let id = vm.snapshot?.localDeviceIdHex {
                            HStack {
                                Text(id)
                                    .font(.caption.monospaced())
                                    .lineLimit(1)
                                    .truncationMode(.middle)
                                Button("Copy") {
                                    NSPasteboard.general.clearContents()
                                    NSPasteboard.general.setString(id, forType: .string)
                                }
                                .controlSize(.small)
                            }
                        } else {
                            Text("Start Host to enroll and publish Device ID")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        HStack {
                            Button("Start Host", action: vm.startHost)
                            Button("Stop Host", action: vm.stopHost)
                        }
                    }
                    .padding(4)
                }

                GroupBox("Controller Mode") {
                    VStack(alignment: .leading, spacing: 8) {
                        TextField("Target 32-hex Device ID", text: $vm.targetDeviceId)
                            .textFieldStyle(.roundedBorder)
                            .font(.body.monospaced())
                        HStack {
                            Button("Connect", action: vm.dial)
                            Button("Disconnect", action: vm.disconnect)
                        }
                    }
                    .padding(4)
                }

                GroupBox("Quick File Path") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            TextField("File path", text: $vm.outboundFilePath)
                                .textFieldStyle(.roundedBorder)
                            Button("Send", action: vm.sendFile)
                                .controlSize(.small)
                                .disabled(!vm.hasCapability("file_transfer"))
                        }
                        Button("Choose File...", action: vm.presentFilePickerAndSend)
                            .controlSize(.small)
                            .disabled(!vm.hasCapability("file_transfer"))
                    }
                    .padding(4)
                }
            }
            .padding(12)
        }
    }

    private var mainCanvasArea: some View {
        VStack(spacing: 0) {
            ZStack {
                Color.black
                if let renderer = vm.metalRenderer {
                    RemoteMetalView(
                        renderer: renderer,
                        inputGate: vm.inputGate,
                        isSessionActive: vm.isSessionStreaming,
                        remoteSize: vm.remoteSize,
                        displayScaleMode: vm.displayScaleMode,
                        scrollOffset: vm.scrollOffset,
                        onEmergencyEscape: vm.handleEmergencyEscapeTriggered,
                        onLocalScrollChanged: vm.updateLocalScrollOffset
                    )
                }
                if !vm.hasVideoFrame {
                    VStack(spacing: 8) {
                        Image(systemName: "desktopcomputer")
                            .font(.system(size: 40))
                            .foregroundColor(.secondary)
                        Text("No Active Video Stream")
                            .foregroundColor(.secondary)
                        Text("Sessions start in View-Only mode. Press Ctrl+Opt+Cmd+Escape for Emergency Escape.")
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .allowsHitTesting(false)
                }
                SessionControlOverlayView(vm: vm)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            Divider()

            VStack(alignment: .leading, spacing: 4) {
                Text("Activity Log (Redacted)")
                    .font(.caption.bold())
                    .foregroundColor(.secondary)
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 2) {
                        ForEach(Array(vm.eventLog.enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.caption.monospaced())
                                .foregroundColor(.secondary)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                }
            }
            .padding(8)
            .frame(height: 110)
        }
    }

    private var stateColor: Color {
        switch vm.snapshot?.state {
        case "streaming", "hosting": return .green
        case "ringing", "connecting", "dialing": return .orange
        case "faulted": return .red
        default: return .secondary
        }
    }

    private func policyBadge(_ title: String, enabled: Bool) -> some View {
        Text(title)
            .font(.caption2)
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(enabled ? Color.green.opacity(0.2) : Color.red.opacity(0.2))
            .foregroundColor(enabled ? .green : .red)
            .clipShape(Capsule())
    }

    private func permissionStatusRow(_ label: String, granted: Bool) -> some View {
        HStack {
            Text(label).font(.caption)
            Spacer()
            Text(granted ? "granted" : "required")
                .font(.caption.bold())
                .foregroundColor(granted ? .green : .orange)
        }
    }

    private func preflightRow(_ label: String, outcome: ProbeOutcome) -> some View {
        HStack {
            Text(label).font(.caption)
            Spacer()
            Text(outcome.status)
                .font(.caption.bold())
                .foregroundColor(outcome.granted ? .green : .orange)
        }
    }
}

private struct IncomingCallSheetView: View {
    let call: IncomingCallPrompt
    let onAccept: () -> Void
    let onReject: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("Incoming Remote Session", systemImage: "person.badge.shield.checkmark.fill")
                .font(.title3.bold())
            Text("Caller Device ID: \(call.callerDeviceId)")
                .font(.caption.monospaced())
            Text("Tenant ID: \(call.callerTenantId)")
                .font(.caption.monospaced())
            Text(call.verifiedByCa ? "CA-Verified Device Certificate" : "Unverified")
                .font(.caption)
                .foregroundColor(call.verifiedByCa ? .green : .red)
            HStack {
                Spacer()
                Button("Reject", role: .cancel, action: onReject)
                    .keyboardShortcut(.cancelAction)
                Button("Approve", action: onAccept)
            }
        }
        .padding(20)
        .frame(width: 420)
        .interactiveDismissDisabled(true)
    }
}

private struct SettingsSheetView: View {
    @ObservedObject var vm: ZeroDeskViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("ZeroDesk Configuration (0600)")
                .font(.title3.bold())
            Form {
                TextField("Control Plane URL", text: $vm.controlPlaneEndpoint)
                TextField("Signaling Address", text: $vm.signalingAddr)
                Picker("Transport", selection: $vm.transportMode) {
                    Text("Auto").tag("auto")
                    Text("Relay UDP").tag("relay_udp")
                    Text("TLS 443").tag("tls443")
                }
                Picker("Codec", selection: $vm.codec) {
                    Text("Auto (HEVC/H.264/VP9)").tag("auto")
                    Text("HEVC").tag("hevc")
                    Text("H.264").tag("h264")
                    Text("VP9").tag("vp9")
                    Text("AV1").tag("av1")
                }
                SecureField("Enrollment Token (wiped after save)", text: $vm.enrollmentTokenDraft)
            }
            HStack {
                Spacer()
                Button("Cancel") {
                    vm.enrollmentTokenDraft = ""
                    vm.isSettingsPresented = false
                }
                Button("Save & Load", action: vm.saveSettings)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 460)
        .onDisappear {
            vm.enrollmentTokenDraft = ""
        }
    }
}
