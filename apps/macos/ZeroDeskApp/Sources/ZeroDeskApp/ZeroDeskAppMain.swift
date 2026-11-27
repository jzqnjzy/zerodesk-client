// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import AppKit
import SwiftUI

final class ZeroDeskAppDelegate: NSObject, NSApplicationDelegate {
    var onTerminate: (@MainActor () -> Void)?

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        true
    }

    func applicationWillTerminate(_ notification: Notification) {
        if let onTerminate {
            MainActor.assumeIsolated {
                onTerminate()
            }
        }
    }
}

@main
struct ZeroDeskDesktopApp: App {
    @NSApplicationDelegateAdaptor(ZeroDeskAppDelegate.self) var appDelegate
    @StateObject private var vm = ZeroDeskViewModel()

    var body: some Scene {
        WindowGroup("ZeroDesk") {
            ContentView(vm: vm)
                .onAppear {
                    appDelegate.onTerminate = { [weak vm] in
                        vm?.shutdown()
                    }
                }
        }
    }
}
