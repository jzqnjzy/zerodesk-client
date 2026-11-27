#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

APP_PKG="$REPO_ROOT/apps/macos/ZeroDeskApp"
XCFW_PATH="$APP_PKG/Vendor/ZeroDeskCore.xcframework"
WATCHDOG_BIN="$REPO_ROOT/libs/zerodesk_core/target/release/zerodesk-hid-watchdog"

if [ ! -d "$XCFW_PATH" ] || [ ! -f "$WATCHDOG_BIN" ]; then
  echo "[0/4] Building ZeroDeskCore.xcframework and zerodesk-hid-watchdog..."
  "$REPO_ROOT/scripts/build-macos-xcframework.sh"
fi

echo "[1/4] Building ZeroDeskApp SwiftUI executable (-c release)..."
(
  cd "$APP_PKG"
  MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}" swift build -c release
)

SWIFT_BIN="$(cd "$APP_PKG" && swift build -c release --show-bin-path)/ZeroDeskApp"
if [ ! -f "$SWIFT_BIN" ]; then
  echo "FAIL: built SwiftUI binary not found at $SWIFT_BIN" >&2
  exit 1
fi

echo "[2/4] Assembling ZeroDesk.app bundle..."
DIST_DIR="$APP_PKG/dist"
APP_BUNDLE="$DIST_DIR/ZeroDesk.app"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

cp "$SWIFT_BIN" "$APP_BUNDLE/Contents/MacOS/ZeroDeskApp"
cp "$WATCHDOG_BIN" "$APP_BUNDLE/Contents/MacOS/zerodesk-hid-watchdog"
chmod 0755 "$APP_BUNDLE/Contents/MacOS/ZeroDeskApp" "$APP_BUNDLE/Contents/MacOS/zerodesk-hid-watchdog"

cp "$APP_PKG/Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
cp "$APP_PKG/Resources/PrivacyInfo.xcprivacy" "$APP_BUNDLE/Contents/Resources/PrivacyInfo.xcprivacy"

echo "[3/4] Ad-hoc signing and verifying ZeroDesk.app..."
codesign --force --deep --sign - "$APP_BUNDLE"
codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"

echo "[4/4] Hard gate: verifying ZERO non-system dylibs (otool -L) on ZeroDeskApp & zerodesk-hid-watchdog..."
check_otool_system_only() {
  local bin="$1"
  echo "  Checking $bin:"
  local deps
  deps="$(otool -L "$bin" | tail -n +2 | awk '{print $1}')"
  while IFS= read -r dylib; do
    [ -z "$dylib" ] && continue
    echo "    $dylib"
    case "$dylib" in
      /System/Library/*|/usr/lib/*) ;;
      *)
        echo "FAIL: non-system runtime dylib detected in $bin: $dylib" >&2
        exit 1
        ;;
    esac
  done <<<"$deps"
}

check_otool_system_only "$APP_BUNDLE/Contents/MacOS/ZeroDeskApp"
check_otool_system_only "$APP_BUNDLE/Contents/MacOS/zerodesk-hid-watchdog"

echo "OK: Built and verified self-contained bundle at $APP_BUNDLE"
