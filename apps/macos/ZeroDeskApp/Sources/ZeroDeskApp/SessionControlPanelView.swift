// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import SwiftUI
import UniformTypeIdentifiers
import ZeroDeskBridge

/// Collapsible floating session toolbar, 1 Hz Telemetry HUD, and side control drawer overlaid
/// on top of `RemoteMetalView`.
///
/// NOTE: File drag-and-drop is attached STRICTLY to the drawer's file-transfer dropzone — NEVER
/// to `RemoteMetalView`.
public struct SessionControlOverlayView: View {
    @ObservedObject var vm: ZeroDeskViewModel
    @State private var isToolbarExpanded: Bool = true
    @State private var isDropTargeted: Bool = false

    public init(vm: ZeroDeskViewModel) {
        self.vm = vm
    }

    public var body: some View {
        ZStack(alignment: .topTrailing) {
            VStack(spacing: 8) {
                HStack(alignment: .top, spacing: 8) {
                    floatingToolbar
                    Spacer()
                    telemetryHud
                }
                if let toast = vm.toastNotice {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .foregroundColor(.yellow)
                        Text(toast)
                            .font(.caption)
                            .foregroundColor(.white)
                        Button {
                            vm.toastNotice = nil
                        } label: {
                            Image(systemName: "xmark")
                                .font(.caption2)
                                .foregroundColor(.white.opacity(0.8))
                        }
                        .buttonStyle(.plain)
                    }
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Color.black.opacity(0.82))
                    .cornerRadius(8)
                }
                Spacer()
            }
            .padding(10)

            if vm.isControlDrawerOpen {
                sideControlDrawer
                    .padding(.top, 56)
                    .padding(.trailing, 10)
                    .padding(.bottom, 10)
                    .transition(.move(edge: .trailing))
            }
        }
    }

    // MARK: - Floating Collapsible Toolbar

    private var floatingToolbar: some View {
        HStack(spacing: 8) {
            Button {
                vm.notifyOverlayOpened()
                isToolbarExpanded.toggle()
            } label: {
                Image(systemName: isToolbarExpanded ? "chevron.left.circle.fill" : "slider.horizontal.3")
                    .foregroundColor(.white)
            }
            .buttonStyle(.plain)
            .help(isToolbarExpanded ? "Collapse Toolbar" : "Expand Session Controls")

            if isToolbarExpanded {
                // Secondary per-session `enable_os_input` gate (strictly Rust-acknowledged state!).
                inputControlButton

                Divider()
                    .frame(height: 16)
                    .background(Color.white.opacity(0.3))

                // 3-Mode Scale Mode Switcher: Fit / 1:1 / Fill
                HStack(spacing: 2) {
                    ForEach(DisplayScaleMode.allCases, id: \.self) { mode in
                        Button(mode.displayLabel) {
                            vm.selectDisplayScaleMode(mode)
                        }
                        .font(.caption.bold())
                        .padding(.horizontal, 7)
                        .padding(.vertical, 3)
                        .background(vm.displayScaleMode == mode ? Color.accentColor : Color.white.opacity(0.12))
                        .foregroundColor(.white)
                        .cornerRadius(4)
                        .buttonStyle(.plain)
                    }
                }
                .disabled(!vm.hasCapability("viewport_scale_modes"))
                .opacity(vm.hasCapability("viewport_scale_modes") ? 1.0 : 0.45)

                Divider()
                    .frame(height: 16)
                    .background(Color.white.opacity(0.3))

                Button {
                    vm.toggleControlDrawer()
                } label: {
                    Label(vm.isControlDrawerOpen ? "Hide Panel" : "Controls", systemImage: "sidebar.right")
                        .font(.caption.bold())
                        .foregroundColor(.white)
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 6)
        .background(Color.black.opacity(0.75))
        .cornerRadius(8)
    }

    private var inputControlButton: some View {
        let canToggle = vm.hasCapability("input_enable_gate")
        let permsOk = vm.permissionStatus?.allRequiredPermissionsGranted ?? false
        return HStack(spacing: 6) {
            Button {
                if !vm.isOsInputEnabled && !permsOk {
                    vm.openPermissionGuide()
                } else {
                    vm.requestSetInputEnabled(!vm.isOsInputEnabled)
                }
            } label: {
                HStack(spacing: 5) {
                    Image(systemName: vm.isOsInputEnabled ? "keyboard.fill" : "eye.fill")
                    Text(vm.isOsInputEnabled ? "Control ON" : "View-Only")
                        .font(.caption.bold())
                    if vm.isInputTogglePending {
                        ProgressView()
                            .controlSize(.mini)
                    }
                }
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(vm.isOsInputEnabled ? Color.green.opacity(0.85) : Color.orange.opacity(0.75))
                .foregroundColor(.white)
                .cornerRadius(5)
            }
            .buttonStyle(.plain)
            .disabled(!canToggle || vm.isInputTogglePending)
            .opacity(canToggle ? 1.0 : 0.45)
            .help("Toggle OS input control (per-session only). Emergency Escape: Ctrl+Opt+Cmd+Esc")

            Text("Esc: ⌃⌥⌘⎋")
                .font(.caption2.monospaced())
                .foregroundColor(.white.opacity(0.85))
                .help("Emergency Escape (Ctrl+Opt+Cmd+Escape): release all keys and return to View-Only mode")
        }
    }

    // MARK: - Live 1 Hz Telemetry HUD (strictly updated from Rust 1 Hz `hud_stats`!)

    private var telemetryHud: some View {
        HStack(spacing: 10) {
            Text(vm.hudStats.activeCodec.uppercased())
                .fontWeight(.bold)
            Text(String(format: "%.1f FPS", vm.hudStats.fps))
            Text(String(format: "Dec %.1fms", vm.hudStats.decodeMs))
            Text(vm.hudStats.transportMode.uppercased())
            Text(String(format: "RTT %.0fms", vm.hudStats.rttMs))
            Text("\(vm.hudStats.bitrateKbps) kbps")
        }
        .font(.caption.monospaced())
        .padding(.horizontal, 10)
        .padding(.vertical, 5)
        .background(Color.black.opacity(0.70))
        .foregroundColor(.white)
        .cornerRadius(6)
        .allowsHitTesting(false)
    }

    // MARK: - Side Control Drawer

    private var sideControlDrawer: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Session Control Panel")
                        .font(.headline)
                    Spacer()
                    Button {
                        vm.closeControlDrawer()
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                            .foregroundColor(.secondary)
                    }
                    .buttonStyle(.plain)
                }

                // Input Control & Emergency Escape Hint
                GroupBox("Input Control") {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack {
                            Text(vm.isOsInputEnabled ? "OS Input Active" : "View-Only Mode")
                                .font(.caption.bold())
                                .foregroundColor(vm.isOsInputEnabled ? .green : .orange)
                            Spacer()
                            Button("Permissions...") {
                                vm.openPermissionGuide()
                            }
                            .controlSize(.small)
                        }
                        Text("Emergency Escape: Ctrl+Opt+Cmd+Escape releases all keys & returns to View-Only.")
                            .font(.caption2)
                            .foregroundColor(.secondary)
                        if vm.displayScaleMode == .actual1to1 {
                            Text("1:1 Mode: Scroll pans viewport; hold ⌘ + scroll to scroll remote.")
                                .font(.caption2)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(4)
                }

                // Codec, Bitrate & FPS Panel
                GroupBox("Video Quality") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Text("Active Codec")
                                .font(.caption)
                            Spacer()
                            Text(vm.activeCodecLabel.uppercased())
                                .font(.caption.monospaced().bold())
                                .foregroundColor(.green)
                        }

                        Picker("Codec", selection: Binding(
                            get: { vm.selectedCodecOption },
                            set: { vm.requestCodecChange($0) }
                        )) {
                            Text("Auto").tag("auto")
                            Text("H.264").tag("h264")
                            Text("HEVC").tag("hevc")
                            Text("VP9").tag("vp9")
                        }
                        .pickerStyle(.segmented)
                        .disabled(!vm.hasCapability("codec_switch"))

                        Picker("Bitrate", selection: Binding(
                            get: { vm.selectedBitrateKbps },
                            set: { vm.updateBitrateTierDebounced($0) }
                        )) {
                            Text("Auto").tag(UInt32(0))
                            Text("2M").tag(UInt32(2_000))
                            Text("5M").tag(UInt32(5_000))
                            Text("10M").tag(UInt32(10_000))
                            Text("20M").tag(UInt32(20_000))
                        }
                        .pickerStyle(.segmented)
                        .disabled(!vm.hasCapability("bitrate_fps_control"))

                        Picker("FPS Cap", selection: Binding(
                            get: { vm.selectedFpsCap },
                            set: { vm.updateFpsCapDebounced($0) }
                        )) {
                            Text("30 fps").tag(UInt32(30))
                            Text("60 fps").tag(UInt32(60))
                        }
                        .pickerStyle(.segmented)
                        .disabled(!vm.hasCapability("bitrate_fps_control"))
                    }
                    .padding(4)
                }

                // Clipboard Sync Drawer Section
                GroupBox("Clipboard Sync") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Toggle("Sync Enabled", isOn: Binding(
                                get: { vm.clipboardSyncEnabled },
                                set: { vm.setClipboardSyncEnabled($0) }
                            ))
                            .font(.caption)
                            .disabled(!vm.hasCapability("clipboard_sync"))
                            Spacer()
                            clipboardBadgeView
                        }

                        HStack(spacing: 6) {
                            TextField("Text to send", text: $vm.outboundClipboardText)
                                .textFieldStyle(.roundedBorder)
                                .font(.caption)
                            Button("Send") {
                                vm.sendClipboardText()
                            }
                            .controlSize(.small)
                            .disabled(!vm.hasCapability("clipboard_sync") || vm.outboundClipboardText.isEmpty)
                        }
                    }
                    .padding(4)
                }

                // File Transfer Section (drag-and-drop dropzone STRICTLY here, NEVER on RemoteMetalView!)
                GroupBox("File Transfer") {
                    VStack(alignment: .leading, spacing: 8) {
                        HStack {
                            Button("Choose File...") {
                                vm.presentFilePickerAndSend()
                            }
                            .controlSize(.small)
                            .disabled(!vm.hasCapability("file_transfer"))
                            Spacer()
                        }

                        ZStack {
                            RoundedRectangle(cornerRadius: 6)
                                .strokeBorder(
                                    isDropTargeted ? Color.accentColor : Color.secondary.opacity(0.45),
                                    style: StrokeStyle(lineWidth: 1.5, dash: [5])
                                )
                                .background(
                                    RoundedRectangle(cornerRadius: 6)
                                        .fill(isDropTargeted ? Color.accentColor.opacity(0.12) : Color.clear)
                                )
                            Text("Drop files here to transfer")
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                        .frame(height: 46)
                        .onDrop(of: [UTType.fileURL], isTargeted: $isDropTargeted) { providers in
                            guard vm.hasCapability("file_transfer") else { return false }
                            vm.notifyOverlayOpened()
                            return vm.handleDroppedFileProviders(providers)
                        }

                        if !vm.fileTransfers.isEmpty {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(vm.fileTransfers) { item in
                                    fileTransferRow(item)
                                }
                            }
                        }
                    }
                    .padding(4)
                }
            }
            .padding(12)
        }
        .frame(width: 310)
        .background(.regularMaterial)
        .cornerRadius(10)
        .shadow(radius: 8)
    }

    private var clipboardBadgeView: some View {
        let (label, color): (String, Color) = {
            switch vm.clipboardSyncBadge {
            case .idle:
                return ("Idle", .secondary)
            case .synced(let bucket):
                return ("Synced (\(bucket))", .green)
            case .policyDenied:
                return ("Policy Denied", .red)
            case .disabled:
                return ("Disabled", .orange)
            }
        }()
        return Text(label)
            .font(.caption2.bold())
            .padding(.horizontal, 6)
            .padding(.vertical, 2)
            .background(color.opacity(0.18))
            .foregroundColor(color)
            .clipShape(Capsule())
    }

    private func fileTransferRow(_ item: FileTransferItem) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(item.relName)
                    .font(.caption.bold())
                    .lineLimit(1)
                    .truncationMode(.middle)
                Spacer()
                if item.isInFlight {
                    Button("Cancel") {
                        vm.cancelFileTransfer(item.id)
                    }
                    .controlSize(.mini)
                }
            }
            if item.isInFlight {
                ProgressView(value: item.progressFraction)
                    .controlSize(.small)
            }
            HStack {
                Text(item.statusLabel)
                    .font(.caption2)
                    .foregroundColor(item.isError ? .red : .secondary)
                Spacer()
                if let algo = item.checksumAlgo, !algo.isEmpty {
                    Text("Checksum: \(algo.uppercased())")
                        .font(.caption2.monospaced())
                        .foregroundColor(.secondary)
                }
            }
            if let err = item.errorMessage {
                Text(err)
                    .font(.caption2)
                    .foregroundColor(.red)
                    .lineLimit(2)
            }
        }
        .padding(6)
        .background(Color.secondary.opacity(0.08))
        .cornerRadius(6)
    }
}
