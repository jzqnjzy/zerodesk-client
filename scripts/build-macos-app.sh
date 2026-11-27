#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

APP_PKG="$REPO_ROOT/apps/macos/ZeroDeskApp"
XCFW_PATH="$APP_PKG/Vendor/ZeroDeskCore.xcframework"
WATCHDOG_BIN="$REPO_ROOT/libs/zerodesk_core/target/release/zerodesk-hid-watchdog"
DEPLOY_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

# Always rebuild core staticlib/XCFramework by default so .app never packages a stale core;
# skip ONLY when ZERODESK_SKIP_CORE=1 is explicitly set.
if [ "${ZERODESK_SKIP_CORE:-0}" != "1" ] || [ ! -d "$XCFW_PATH" ] || [ ! -f "$WATCHDOG_BIN" ]; then
  echo "[0/5] Building ZeroDeskCore.xcframework and zerodesk-hid-watchdog..."
  "$REPO_ROOT/scripts/build-macos-xcframework.sh"
fi

echo "[1/5] Validating Info.plist & PrivacyInfo.xcprivacy with plutil -lint..."
plutil -lint "$APP_PKG/Resources/Info.plist"
plutil -lint "$APP_PKG/Resources/PrivacyInfo.xcprivacy"

echo "[2/5] Building ZeroDeskApp SwiftUI executable (-c release)..."
(
  cd "$APP_PKG"
  MACOSX_DEPLOYMENT_TARGET="$DEPLOY_TARGET" swift build -c release
)

SWIFT_BIN="$(cd "$APP_PKG" && swift build -c release --show-bin-path)/ZeroDeskApp"
if [ ! -f "$SWIFT_BIN" ]; then
  echo "FAIL: built SwiftUI binary not found at $SWIFT_BIN" >&2
  exit 1
fi

echo "[3/5] Assembling ZeroDesk.app bundle..."
DIST_DIR="$APP_PKG/dist"
APP_BUNDLE="$DIST_DIR/ZeroDesk.app"
rm -rf "$APP_BUNDLE"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"

cp "$SWIFT_BIN" "$APP_BUNDLE/Contents/MacOS/ZeroDeskApp"
cp "$WATCHDOG_BIN" "$APP_BUNDLE/Contents/MacOS/zerodesk-hid-watchdog"
chmod 0755 "$APP_BUNDLE/Contents/MacOS/ZeroDeskApp" "$APP_BUNDLE/Contents/MacOS/zerodesk-hid-watchdog"

cp "$APP_PKG/Resources/Info.plist" "$APP_BUNDLE/Contents/Info.plist"
cp "$APP_PKG/Resources/PrivacyInfo.xcprivacy" "$APP_BUNDLE/Contents/Resources/PrivacyInfo.xcprivacy"

echo "[4/5] Ad-hoc signing and verifying ZeroDesk.app..."
codesign --force --deep --sign - "$APP_BUNDLE"
codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"

echo "[5/5] Hard gates: otool -L system-only, LC_RPATH audit, and vtool minos..."
FORBIDDEN_USER_PREFIX="/Us""ers/"

check_binary_gates() {
  local bin="$1"
  local require_zero_rpath="$2"
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

  local rpaths
  rpaths="$(otool -l "$bin" | awk '/cmd LC_RPATH/{f=1} f && /path /{print $2; f=0}')"
  if [ "$require_zero_rpath" = "1" ] && [ -n "$rpaths" ]; then
    echo "FAIL: unexpected LC_RPATH in $bin: $rpaths" >&2
    exit 1
  fi
  while IFS= read -r rp; do
    [ -z "$rp" ] && continue
    if [[ "$rp" == *"/opt/homebrew"* ]] || [[ "$rp" == *"$FORBIDDEN_USER_PREFIX"* ]]; then
      echo "FAIL: forbidden LC_RPATH in $bin: $rp" >&2
      exit 1
    fi
  done <<<"$rpaths"

  local vinfo minos
  vinfo="$(vtool -show-build "$bin")" || {
    echo "FAIL: vtool -show-build failed on $bin" >&2
    exit 1
  }
  minos="$(awk '$1=="minos"{print $2; exit}' <<<"$vinfo")"
  if [ -z "$minos" ]; then
    echo "FAIL: missing minos metadata in $bin" >&2
    exit 1
  fi
  echo "    minos=${minos} (LC_RPATH clean)"
  if [ "$minos" != "$DEPLOY_TARGET" ]; then
    echo "    NOTE: minos=${minos} differs from target ${DEPLOY_TARGET} (host Homebrew static codecs may carry host SDK minos)."
  fi
}

check_binary_gates "$APP_BUNDLE/Contents/MacOS/ZeroDeskApp" 0
check_binary_gates "$APP_BUNDLE/Contents/MacOS/zerodesk-hid-watchdog" 1

echo "OK: Built and verified self-contained bundle at $APP_BUNDLE"
