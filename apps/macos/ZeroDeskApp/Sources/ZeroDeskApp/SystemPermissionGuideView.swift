// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import SwiftUI
import ZeroDeskBridge

/// Interactive macOS System Permission Onboarding Guide (`Screen Recording` + `Accessibility`).
///
/// Safety invariants:
/// - NEVER calls `CGRequestScreenCaptureAccess()` automatically on view load or during polling!
///   Only triggers it when the user explicitly clicks "Request Permission".
/// - Refreshes immediately on `NSApplication.didBecomeActiveNotification` and window foregrounding,
///   plus background polling strictly `<= 1 Hz` (`1.2s`) ONLY while visible.
public struct SystemPermissionGuideView: View {
    @ObservedObject var vm: ZeroDeskViewModel
    let onDismiss: () -> Void

    @State private var pollTask: Task<Void, Never>?

    public init(vm: ZeroDeskViewModel, onDismiss: @escaping () -> Void) {
        self.vm = vm
        self.onDismiss = onDismiss
    }

    private var screenGranted: Bool {
        vm.effectivePermissionStatus?.screenCaptureGranted ?? false
    }

    private var accessibilityGranted: Bool {
        vm.effectivePermissionStatus?.accessibilityGranted ?? false
    }

    private var probeSourceLabel: String {
        switch vm.effectivePermissionStatus?.probeSource {
        case .watchdog:
            return "Watchdog Process (Authoritative)"
        case .injectorProcess:
            return "Injector Process (Authoritative)"
        case .uiProcessHint, .none:
            return "UI Process Hint (TCC evaluates active injector process)"
        case .unknown(let raw):
            return "Unknown (\(raw))"
        }
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Label("macOS System Permissions", systemImage: "lock.shield.fill")
                    .font(.title3.bold())
                Spacer()
                Button("Refresh Now") {
                    vm.refreshPermissions()
                }
                .controlSize(.small)
            }

            Text("ZeroDesk starts every session in View-Only mode. Enabling OS input control requires both Screen Recording and Accessibility permissions.")
                .font(.callout)
                .foregroundColor(.secondary)

            permissionCard(
                title: "Screen Recording",
                granted: screenGranted,
                guidance: "Required to capture and stream the display via ScreenCaptureKit. If revoked mid-session, capture stops immediately.",
                primaryButtonTitle: "Open Screen Recording Settings",
                primaryAction: {
                    vm.openPermissionSettings(for: .screenRecording)
                },
                secondaryButtonTitle: screenGranted ? nil : "Request Permission",
                secondaryAction: {
                    _ = SystemPermissionLinks.requestScreenCaptureAccessExplicitly(UserInitiatedPermissionAction())
                    vm.refreshPermissions()
                }
            )

            permissionCard(
                title: "Accessibility",
                granted: accessibilityGranted,
                guidance: "Required for OS keyboard and mouse control. Accessibility cannot be auto-granted: open System Settings and manually toggle the ZeroDesk checkbox ON.",
                primaryButtonTitle: "Open Accessibility Settings",
                primaryAction: {
                    vm.openPermissionSettings(for: .accessibility)
                },
                secondaryButtonTitle: nil,
                secondaryAction: nil
            )

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Image(systemName: "info.circle")
                        .foregroundColor(.secondary)
                    Text("Probe source: \(probeSourceLabel)")
                        .font(.caption.monospaced())
                        .foregroundColor(.secondary)
                }
                Text("Emergency Escape: Press Ctrl+Opt+Cmd+Escape at any time to immediately release all keys and disable OS input control.")
                    .font(.caption)
                    .foregroundColor(.orange)
            }
            .padding(10)
            .background(Color.secondary.opacity(0.08))
            .cornerRadius(8)

            HStack {
                if screenGranted && accessibilityGranted {
                    Label("All required permissions granted", systemImage: "checkmark.circle.fill")
                        .font(.callout.bold())
                        .foregroundColor(.green)
                } else {
                    Label("Waiting for permissions (refreshing <= 1 Hz)", systemImage: "clock")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                Spacer()
                Button(screenGranted && accessibilityGranted ? "Continue" : "Close") {
                    onDismiss()
                }
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 540)
        .onAppear {
            vm.notifyOverlayOpened()
            vm.refreshPermissions()
            startBoundedPolling()
        }
        .onDisappear {
            pollTask?.cancel()
            pollTask = nil
        }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            vm.refreshPermissions()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeKeyNotification)) { _ in
            vm.refreshPermissions()
        }
        .onReceive(NotificationCenter.default.publisher(for: NSWindow.didBecomeMainNotification)) { _ in
            vm.refreshPermissions()
        }
    }

    private func startBoundedPolling() {
        pollTask?.cancel()
        pollTask = Task { @MainActor in
            while !Task.isCancelled {
                // Strictly <= 1 Hz (1.2 seconds between polls) while guide is visible.
                try? await Task.sleep(nanoseconds: 1_200_000_000)
                if Task.isCancelled { break }
                vm.refreshPermissions()
            }
        }
    }

    private func permissionCard(
        title: String,
        granted: Bool,
        guidance: String,
        primaryButtonTitle: String,
        primaryAction: @escaping () -> Void,
        secondaryButtonTitle: String?,
        secondaryAction: (() -> Void)?
    ) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text(title)
                    .font(.headline)
                Spacer()
                Text(granted ? "GRANTED" : "REQUIRED")
                    .font(.caption.bold())
                    .padding(.horizontal, 8)
                    .padding(.vertical, 3)
                    .background(granted ? Color.green.opacity(0.2) : Color.orange.opacity(0.2))
                    .foregroundColor(granted ? .green : .orange)
                    .clipShape(Capsule())
            }
            Text(guidance)
                .font(.caption)
                .foregroundColor(.secondary)
            HStack(spacing: 8) {
                Button(primaryButtonTitle, action: primaryAction)
                    .controlSize(.small)
                if let secTitle = secondaryButtonTitle, let secAction = secondaryAction {
                    Button(secTitle, action: secAction)
                        .controlSize(.small)
                }
            }
        }
        .padding(12)
        .background(Color.secondary.opacity(0.08))
        .cornerRadius(8)
    }
}
