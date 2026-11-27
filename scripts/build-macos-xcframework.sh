#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

DEPLOY_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
ENABLE_REAL_INPUT="${ZERODESK_ENABLE_REAL_INPUT:-0}"

resolve_libyuv_prefix() {
  if [ -n "${ZERODESK_LIBYUV_PREFIX:-}" ]; then
    echo "$ZERODESK_LIBYUV_PREFIX"
    return 0
  fi
  if command -v pkg-config >/dev/null 2>&1; then
    local pc_prefix
    pc_prefix="$(pkg-config --variable=prefix libyuv 2>/dev/null || true)"
    if [ -n "$pc_prefix" ] && [ -f "$pc_prefix/lib/libyuv.a" ]; then
      echo "$pc_prefix"
      return 0
    fi
  fi
  for cand in /opt/homebrew/opt/libyuv /opt/homebrew /usr/local/opt/libyuv /usr/local; do
    if [ -f "$cand/lib/libyuv.a" ] && [ -f "$cand/include/libyuv.h" ]; then
      echo "$cand"
      return 0
    fi
  done
  echo "FAIL: ZERODESK_LIBYUV_PREFIX is unset and libyuv.a was not found via pkg-config or standard prefixes." >&2
  echo "      Set ZERODESK_LIBYUV_PREFIX=/path/to/libyuv (containing lib/libyuv.a and include/libyuv.h)." >&2
  return 1
}

LIBYUV_PREFIX="$(resolve_libyuv_prefix)"
if [ ! -f "$LIBYUV_PREFIX/lib/libyuv.a" ]; then
  echo "FAIL: libyuv.a missing under ZERODESK_LIBYUV_PREFIX=$LIBYUV_PREFIX" >&2
  exit 1
fi

CARGO_EXTRA_FLAGS=()
if [ "$ENABLE_REAL_INPUT" = "1" ]; then
  CARGO_EXTRA_FLAGS=(--features real-input)
  echo "Build config: real-input=ENABLED (ZERODESK_ENABLE_REAL_INPUT=1), MACOSX_DEPLOYMENT_TARGET=${DEPLOY_TARGET}"
elif [ "$ENABLE_REAL_INPUT" = "0" ]; then
  echo "Build config: real-input=DISABLED (safe default; set ZERODESK_ENABLE_REAL_INPUT=1 to enable), MACOSX_DEPLOYMENT_TARGET=${DEPLOY_TARGET}"
else
  echo "FAIL: ZERODESK_ENABLE_REAL_INPUT must be 0 or 1 (got '$ENABLE_REAL_INPUT')" >&2
  exit 1
fi

ENV_PREFIX=(
  env -u VCPKG_ROOT
  PATH="/usr/bin:$PATH"
  RUSTC_WRAPPER=""
  TMPDIR=/tmp
  ZERODESK_LIBYUV_PREFIX="$LIBYUV_PREFIX"
  ZERODESK_STATIC_CODECS=1
  MACOSX_DEPLOYMENT_TARGET="$DEPLOY_TARGET"
)

echo "[1/5] Building libs/zerodesk_core staticlib + zerodesk-hid-watchdog (--release, static codecs)..."
"${ENV_PREFIX[@]}" cargo build \
  --manifest-path libs/zerodesk_core/Cargo.toml \
  --release \
  --lib \
  --bin zerodesk-hid-watchdog \
  ${CARGO_EXTRA_FLAGS[@]+"${CARGO_EXTRA_FLAGS[@]}"}

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

echo "[2/5] Resolving static codec archives and verifying embedding..."
STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zd-xcfw-stage.XXXXXX")"
trap 'rm -rf "$STAGE_DIR"' EXIT

DEFINED_SYMS="$STAGE_DIR/defined_syms.txt"
nm -gU "$CORE_LIB" 2>/dev/null | awk 'NF>=3 {print $NF}' | sort -u >"$DEFINED_SYMS"

resolve_static_lib() {
  local libname="$1"
  shift
  for cand in "$@"; do
    if [ -f "$cand" ]; then
      echo "$cand"
      return 0
    fi
  done
  echo "FAIL: required static archive ${libname} not found" >&2
  return 1
}

VPX_A="$(resolve_static_lib "libvpx.a" \
  "/opt/homebrew/opt/libvpx/lib/libvpx.a" "/opt/homebrew/lib/libvpx.a" "/usr/local/lib/libvpx.a")"
AOM_A="$(resolve_static_lib "libaom.a" \
  "/opt/homebrew/opt/aom/lib/libaom.a" "/opt/homebrew/lib/libaom.a" "/usr/local/lib/libaom.a")"
OPUS_A="$(resolve_static_lib "libopus.a" \
  "${ZERODESK_LIBOPUS_PREFIX:-/opt/homebrew/opt/opus}/lib/libopus.a" "/opt/homebrew/lib/libopus.a" "/usr/local/lib/libopus.a")"
YUV_A="$(resolve_static_lib "libyuv.a" \
  "${LIBYUV_PREFIX}/lib/libyuv.a" "/opt/homebrew/lib/libyuv.a" "/usr/local/lib/libyuv.a")"

MERGE_LIBS=("$CORE_LIB")
CODEC_DEFINED_ALL="$STAGE_DIR/codec_defined_all.txt"
: >"$CODEC_DEFINED_ALL"

check_or_merge_codec() {
  local label="$1"
  local sym="$2"
  local archive="$3"
  nm -gU "$archive" 2>/dev/null | awk 'NF>=3 {print $NF}' >>"$CODEC_DEFINED_ALL"
  if grep -qx "_${sym}" "$DEFINED_SYMS"; then
    echo "  - ${label}: already embedded in libzerodesk_core.a"
  else
    echo "  - ${label}: merging $archive"
    MERGE_LIBS+=("$archive")
  fi
}

check_or_merge_codec "libvpx.a" "vpx_codec_vp9_cx" "$VPX_A"
check_or_merge_codec "libaom.a" "aom_codec_av1_cx" "$AOM_A"
check_or_merge_codec "libopus.a" "opus_encode_float" "$OPUS_A"
check_or_merge_codec "libyuv.a" "ARGBToI420" "$YUV_A"

sort -u -o "$CODEC_DEFINED_ALL" "$CODEC_DEFINED_ALL"
if [ ! -s "$CODEC_DEFINED_ALL" ]; then
  echo "FAIL: extracted 0 symbols from static codec archives" >&2
  exit 1
fi

MERGED_LIB="$STAGE_DIR/libzerodesk_core.a"
if [ "${#MERGE_LIBS[@]}" -eq 1 ]; then
  cp "$CORE_LIB" "$MERGED_LIB"
else
  /usr/bin/libtool -static -o "$MERGED_LIB" "${MERGE_LIBS[@]}"
fi

echo "[3/5] Set-based nm self-containment & minos audit on merged archive..."
MERGED_DEFINED="$STAGE_DIR/merged_defined.txt"
MERGED_UNDEF="$STAGE_DIR/merged_undef.txt"
nm -gU "$MERGED_LIB" 2>/dev/null | awk 'NF>=3 {print $NF}' | sort -u >"$MERGED_DEFINED"
nm -u "$MERGED_LIB" 2>/dev/null | awk 'NF>=1 {print $NF}' | sort -u >"$MERGED_UNDEF"
if [ ! -s "$MERGED_DEFINED" ]; then
  echo "FAIL: nm -gU produced 0 defined symbols for $MERGED_LIB" >&2
  exit 1
fi

TRULY_UNDEF="$STAGE_DIR/truly_undef.txt"
comm -23 "$MERGED_UNDEF" "$MERGED_DEFINED" >"$TRULY_UNDEF"

# Assert core C-ABI exports and BackingScaleFactor are defined.
for req_sym in _zerodesk_v2_abi_version _zerodesk_v2_create _zerodesk_v2_destroy _zerodesk_v2_exec_json _zerodesk_v2_os_selftest_json _BackingScaleFactor; do
  if ! grep -qx "$req_sym" "$MERGED_DEFINED"; then
    echo "FAIL: required exported symbol missing from merged archive: $req_sym" >&2
    exit 1
  fi
done

# Set-based codec check: intersection of TRULY_UNDEF with ALL defined codec archive symbols MUST be empty!
UNRESOLVED_CODEC="$STAGE_DIR/unresolved_codec.txt"
comm -12 "$TRULY_UNDEF" "$CODEC_DEFINED_ALL" >"$UNRESOLVED_CODEC"
if [ -s "$UNRESOLVED_CODEC" ]; then
  echo "FAIL: unresolved static codec symbols remain in $MERGED_LIB:" >&2
  head -n 20 "$UNRESOLVED_CODEC" >&2
  exit 1
fi

# Reject unresolved stdc++ or Swift runtime symbols (^_\$[sS] and ^_swift).
for bad_pat in "stdc\+\+" "^_swift" "^_\\\$[sS]" "^_BackingScaleFactor$"; do
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
echo "  OK: set-based nm audit passed (0 unresolved codec/stdc++/Swift/BackingScaleFactor symbols)."

echo "[4/5] Verifying zerodesk-hid-watchdog dylibs, LC_RPATH==0, and vtool minos..."
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

RPATH_COUNT="$(otool -l "$WATCHDOG_BIN" | grep -c "cmd LC_RPATH" || true)"
if [ "$RPATH_COUNT" -ne 0 ]; then
  echo "FAIL: zerodesk-hid-watchdog has $RPATH_COUNT LC_RPATH entries (expected 0)" >&2
  exit 1
fi

WD_BUILD_INFO="$(vtool -show-build "$WATCHDOG_BIN")" || {
  echo "FAIL: vtool -show-build failed on $WATCHDOG_BIN" >&2
  exit 1
}
WD_MINOS="$(awk '$1=="minos"{print $2; exit}' <<<"$WD_BUILD_INFO")"
if [ -z "$WD_MINOS" ]; then
  echo "FAIL: missing minos in vtool output for $WATCHDOG_BIN" >&2
  exit 1
fi
echo "  OK: zerodesk-hid-watchdog system-only dylibs, LC_RPATH=0, minos=${WD_MINOS}."
if [ "$WD_MINOS" != "$DEPLOY_TARGET" ]; then
  echo "  NOTE: zerodesk-hid-watchdog minos=${WD_MINOS} differs from target ${DEPLOY_TARGET} (expected if Homebrew static codecs carry host SDK minos)."
fi

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
