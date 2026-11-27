// swift-tools-version: 6.0
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

import PackageDescription

let macosSystemLinkerSettings: [LinkerSetting] = [
    .linkedFramework("CoreGraphics"),
    .linkedFramework("CoreFoundation"),
    .linkedFramework("ApplicationServices"),
    .linkedFramework("Carbon"),
    .linkedFramework("AppKit"),
    .linkedFramework("ScreenCaptureKit"),
    .linkedFramework("VideoToolbox"),
    .linkedFramework("CoreMedia"),
    .linkedFramework("CoreVideo"),
    .linkedFramework("Foundation"),
    .linkedFramework("CoreAudio"),
    .linkedFramework("AudioUnit"),
    .linkedFramework("IOSurface"),
    .linkedFramework("AVFoundation"),
    .linkedFramework("Metal"),
    .linkedFramework("QuartzCore"),
    .linkedFramework("SystemConfiguration"),
    .linkedFramework("IOKit"),
    .linkedFramework("Security"),
    .linkedLibrary("c++"),
    .linkedLibrary("iconv"),
]

let package = Package(
    name: "ZeroDeskApp",
    platforms: [
        .macOS(.v13),
    ],
    products: [
        .library(
            name: "ZeroDeskBridge",
            targets: ["ZeroDeskBridge"]
        ),
        .executable(
            name: "ZeroDeskApp",
            targets: ["ZeroDeskApp"]
        ),
    ],
    targets: [
        .binaryTarget(
            name: "ZeroDeskCore",
            path: "Vendor/ZeroDeskCore.xcframework"
        ),
        .target(
            name: "ZeroDeskBridge",
            dependencies: ["ZeroDeskCore"],
            path: "Sources/ZeroDeskBridge",
            linkerSettings: macosSystemLinkerSettings
        ),
        .executableTarget(
            name: "ZeroDeskApp",
            dependencies: ["ZeroDeskBridge"],
            path: "Sources/ZeroDeskApp"
        ),
        .testTarget(
            name: "ZeroDeskBridgeTests",
            dependencies: ["ZeroDeskBridge"],
            path: "Tests/ZeroDeskBridgeTests"
        ),
    ]
)
