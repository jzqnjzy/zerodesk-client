#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

LIBYUV_PREFIX="${ZERODESK_LIBYUV_PREFIX:-/Users/taole/.local/libyuv}"
DEPLOY_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"

ENV_PREFIX=(
  env -u VCPKG_ROOT
  PATH="/usr/bin:$PATH"
  RUSTC_WRAPPER=""
  TMPDIR=/tmp
  ZERODESK_LIBYUV_PREFIX="$LIBYUV_PREFIX"
  ZERODESK_STATIC_CODECS=1
  MACOSX_DEPLOYMENT_TARGET="$DEPLOY_TARGET"
)

echo "[1/5] Building libs/zerodesk_core staticlib + zerodesk-hid-watchdog (--release, static codecs, macOS >= ${DEPLOY_TARGET})..."
"${ENV_PREFIX[@]}" cargo build \
  --manifest-path libs/zerodesk_core/Cargo.toml \
  --release \
  --lib \
  --bin zerodesk-hid-watchdog

CORE_LIB="libs/zerodesk_core/target/release/libzerodesk_core.a"
WATCHDOG_BIN="libs/zerodesk_core/target/release/zerodesk-hid-watchdog"
if [ ! -f "$CORE_LIB" ]; then
  echo "FAIL: missing staticlib: $CORE_LIB" >&2
  exit 1
fi
if [ ! -f "$WATCHDOG_BIN" ]; then
  echo "FAIL: missing watchdog binary: $WATCHDOG_BIN" >&2
  exit 1
fi

echo "[2/5] Preparing self-contained static archive (verifying vpx/aom/opus/yuv symbols)..."
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zd-xcfw-stage.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

DEFINED_SYMS="$STAGE_DIR/defined_syms.txt"
nm -gU "$CORE_LIB" >"$DEFINED_SYMS" 2>/dev/null || true

MERGE_LIBS=("$CORE_LIB")

resolve_static_lib() {
  local libname="$1"
  shift
  for cand in "$@"; do
    if [ -f "$cand" ]; then
      echo "$cand"
      return 0
    fi
  done
  return 1
}

maybe_add_codec_archive() {
  local name="$1"
  local sym="$2"
  shift 2
  if grep -qE "[[:space:]]_${sym}\$" "$DEFINED_SYMS"; then
    echo "  - ${name}: already embedded in libzerodesk_core.a"
  else
    local arch
    arch="$(resolve_static_lib "$name" "$@")" || {
      echo "FAIL: required static archive ${name} not found" >&2
      exit 1
    }
    echo "  - ${name}: merging $arch"
    MERGE_LIBS+=("$arch")
  fi
}

maybe_add_codec_archive "libvpx.a" "vpx_codec_vp9_cx" \
  "/opt/homebrew/opt/libvpx/lib/libvpx.a" "/opt/homebrew/lib/libvpx.a" "/usr/local/lib/libvpx.a"
maybe_add_codec_archive "libaom.a" "aom_codec_av1_cx" \
  "/opt/homebrew/opt/aom/lib/libaom.a" "/opt/homebrew/lib/libaom.a" "/usr/local/lib/libaom.a"
maybe_add_codec_archive "libopus.a" "opus_encode_float" \
  "${ZERODESK_LIBOPUS_PREFIX:-/opt/homebrew/opt/opus}/lib/libopus.a" "/opt/homebrew/lib/libopus.a" "/usr/local/lib/libopus.a"
maybe_add_codec_archive "libyuv.a" "ARGBToI420" \
  "${LIBYUV_PREFIX}/lib/libyuv.a" "/opt/homebrew/lib/libyuv.a" "/usr/local/lib/libyuv.a"

MERGED_LIB="$STAGE_DIR/libzerodesk_core.a"
if [ "${#MERGE_LIBS[@]}" -eq 1 ]; then
  cp "$CORE_LIB" "$MERGED_LIB"
else
  /usr/bin/libtool -static -o "$MERGED_LIB" "${MERGE_LIBS[@]}"
fi

echo "[3/5] Auditing merged static archive symbols (nm -u / nm -gU)..."
MERGED_DEFINED="$STAGE_DIR/merged_defined.txt"
MERGED_UNDEF="$STAGE_DIR/merged_undef.txt"
nm -gU "$MERGED_LIB" | awk '{print $NF}' | sort -u >"$MERGED_DEFINED"
nm -u "$MERGED_LIB" | awk '{print $NF}' | sort -u >"$MERGED_UNDEF"

# Compute truly external undefined symbols = UNDEF minus DEFINED inside the archive.
TRULY_UNDEF="$STAGE_DIR/truly_undef.txt"
comm -23 "$MERGED_UNDEF" "$MERGED_DEFINED" >"$TRULY_UNDEF"

for req_sym in _zerodesk_v2_abi_version _zerodesk_v2_create _zerodesk_v2_os_selftest_json _opus_encode_float _vpx_codec_vp9_cx _aom_codec_av1_cx _ARGBToI420 _BackingScaleFactor; do
  if ! grep -qx "$req_sym" "$MERGED_DEFINED"; then
    echo "FAIL: required exported symbol missing from merged archive: $req_sym" >&2
    exit 1
  fi
done

for bad_pat in "stdc\+\+" "^_swift" "^_opus_" "^_vpx_" "^_aom_" "^_ARGBToI420$" "^_BackingScaleFactor$"; do
  rc=0
  grep -E "$bad_pat" "$TRULY_UNDEF" || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "FAIL: forbidden unresolved symbol matching /$bad_pat/ in $MERGED_LIB!" >&2
    exit 1
  elif [ "$rc" -ne 1 ]; then
    echo "FAIL: grep error ($rc) auditing symbols" >&2
    exit 1
  fi
done
echo "  OK: merged static archive is self-contained (zero stdc++/_swift/codec unresolved symbols)."

echo "[4/5] Verifying zerodesk-hid-watchdog has zero Homebrew runtime dylibs..."
WD_OTOOL="$(otool -L "$WATCHDOG_BIN" | tail -n +2 | awk '{print $1}')"
while IFS= read -r dylib; do
  [ -z "$dylib" ] && continue
  case "$dylib" in
    /System/Library/*|/usr/lib/*) ;;
    *)
      echo "FAIL: non-system dylib linked in zerodesk-hid-watchdog: $dylib" >&2
      exit 1
      ;;
  esac
done <<<"$WD_OTOOL"
echo "  OK: zerodesk-hid-watchdog links only /System/Library/* and /usr/lib/*."

echo "[5/5] Packaging ZeroDeskCore.xcframework via xcodebuild..."
HEADERS_DIR="$STAGE_DIR/headers"
mkdir -p "$HEADERS_DIR"
cp "libs/zerodesk_core/include/zerodesk_v2.h" "$HEADERS_DIR/zerodesk_v2.h"
cat >"$HEADERS_DIR/module.modulemap" <<'EOF'
// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

module CZeroDeskCore {
    header "zerodesk_v2.h"
    export *
}
EOF

OUT_DIR="$REPO_ROOT/apps/macos/ZeroDeskApp/Vendor"
mkdir -p "$OUT_DIR"
XCFW_PATH="$OUT_DIR/ZeroDeskCore.xcframework"
rm -rf "$XCFW_PATH"

xcodebuild -create-xcframework \
  -library "$MERGED_LIB" \
  -headers "$HEADERS_DIR" \
  -output "$XCFW_PATH"

echo "OK: Built self-contained XCFramework at $XCFW_PATH"
