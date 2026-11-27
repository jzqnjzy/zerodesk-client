#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ENV_PREFIX=(
  env -u VCPKG_ROOT
  PATH="/usr/bin:$PATH"
  RUSTC_WRAPPER=""
  TMPDIR=/tmp
  ZERODESK_LIBYUV_PREFIX="${ZERODESK_LIBYUV_PREFIX:-/Users/taole/.local/libyuv}"
  MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-13.0}"
)

TMP_SPDX_LIST="$(mktemp "${TMPDIR:-/tmp}/zd-spdx-list.XXXXXX")"
trap 'rm -f "$TMP_SPDX_LIST"' EXIT

for req_path in \
  Cargo.toml \
  libs/zerodesk_core/Cargo.toml \
  libs/zerodesk_core/src \
  libs/zerodesk_core/include \
  libs/zerodesk_core/tests \
  libs/zerodesk_core/build.rs \
  libs/v2_e2e/Cargo.toml \
  libs/v2_e2e/src \
  libs/v2_client/Cargo.toml \
  libs/v2_client/src \
  libs/v2_transport/Cargo.toml \
  libs/v2_transport/src \
  libs/v2_identity/Cargo.toml \
  libs/v2_identity/src \
  src/v2_session \
  scripts/check-compliance.sh; do
  if [ ! -e "$req_path" ]; then
    echo "FAIL: required path missing: $req_path" >&2
    exit 1
  fi
done

echo "[1/5] Checking zero test-utils leakage & default-feature safety in libs/zerodesk_core..."
rc=0
grep -q "test-utils" libs/zerodesk_core/Cargo.toml || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "FAIL: libs/zerodesk_core/Cargo.toml must NOT mention test-utils anywhere!" >&2
  exit 1
elif [ "$rc" -ne 1 ]; then
  echo "FAIL: grep error ($rc) checking libs/zerodesk_core/Cargo.toml" >&2
  exit 1
fi

for flags in "" "--no-default-features" "--all-features"; do
  # Fail-closed: capture cargo tree output first so any cargo error aborts immediately.
  # shellcheck disable=SC2086
  tree_host="$("${ENV_PREFIX[@]}" cargo tree --locked --manifest-path libs/zerodesk_core/Cargo.toml $flags -e features,no-dev)" \
    || { echo "FAIL: cargo tree (host) failed for flags '$flags'" >&2; exit 1; }
  rc=0
  grep -q "test-utils" <<<"$tree_host" || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "FAIL: test-utils leaked into libs/zerodesk_core host tree (flags: '$flags')!" >&2
    exit 1
  elif [ "$rc" -ne 1 ]; then
    echo "FAIL: grep error ($rc) inspecting host tree" >&2
    exit 1
  fi

  # Also inspect --target all (across cfg(windows/linux/macos) dep trees).
  # shellcheck disable=SC2086
  tree_all="$("${ENV_PREFIX[@]}" cargo tree --locked --target all --manifest-path libs/zerodesk_core/Cargo.toml $flags -e features,no-dev)" \
    || { echo "FAIL: cargo tree (--target all) failed for flags '$flags'" >&2; exit 1; }
  rc=0
  grep -q "test-utils" <<<"$tree_all" || rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "FAIL: test-utils leaked into libs/zerodesk_core --target all tree (flags: '$flags')!" >&2
    exit 1
  elif [ "$rc" -ne 1 ]; then
    echo "FAIL: grep error ($rc) inspecting --target all tree" >&2
    exit 1
  fi
done

# Ensure dangerous opt-in features are NEVER in default features of libs/zerodesk_core.
python3 -c '
import json, subprocess, sys
out = subprocess.check_output(sys.argv[1:], text=True)
data = json.loads(out)
pkg = next((p for p in data["packages"] if p["name"] == "zerodesk_core"), None)
if pkg is None:
    print("FAIL: zerodesk_core package not found in metadata", file=sys.stderr)
    sys.exit(1)
defaults = set(pkg.get("features", {}).get("default", []))
forbidden = {"real-input", "e2e-fault-injection", "test-utils"}
bad = defaults & forbidden
if bad:
    print(f"FAIL: forbidden features in zerodesk_core default: {sorted(bad)}", file=sys.stderr)
    sys.exit(1)
' "${ENV_PREFIX[@]}" cargo metadata --locked --no-deps --manifest-path libs/zerodesk_core/Cargo.toml --format-version 1
echo "  OK: zero test-utils leakage across default, --no-default-features, and --all-features (host + --target all); default features safe."

echo "[2/5] Checking clean-room isolation (zero cloud-backend references across all Cargo.toml & ZeroDesk code)..."
TMP_CARGO_LIST="$(mktemp "${TMPDIR:-/tmp}/zd-cargo-list.XXXXXX")"
trap 'rm -f "$TMP_SPDX_LIST" "$TMP_CARGO_LIST"' EXIT
find . -maxdepth 4 -name "Cargo.toml" -not -path "*/target/*" -not -path "./.git/*" >"$TMP_CARGO_LIST" \
  || { echo "FAIL: find Cargo.toml failed" >&2; exit 1; }

CARGO_TOMLS=()
while IFS= read -r ct; do
  [ -n "$ct" ] && CARGO_TOMLS+=("$ct")
done <"$TMP_CARGO_LIST"
if [ "${#CARGO_TOMLS[@]}" -eq 0 ]; then
  echo "FAIL: no Cargo.toml files found" >&2
  exit 1
fi

CLEANROOM_PATHS=(
  "${CARGO_TOMLS[@]}"
  libs/zerodesk_core
  libs/v2_e2e/src
  libs/v2_client/src
  libs/v2_transport/src
  libs/v2_identity/src
  src/v2_session
)
if [ -d apps/macos ]; then
  CLEANROOM_PATHS+=(apps/macos)
fi

rc=0
grep -rn --exclude-dir=target "cloud-backend" "${CLEANROOM_PATHS[@]}" || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "FAIL: forbidden cloud-backend reference detected!" >&2
  exit 1
elif [ "$rc" -ne 1 ]; then
  echo "FAIL: grep error ($rc) during clean-room isolation check (fail-closed)!" >&2
  exit 1
fi
echo "  OK: zero cloud-backend references across ${#CARGO_TOMLS[@]} Cargo.toml files and all ZeroDesk code."

echo "[3/5] Checking SPDX AGPL-3.0-only headers on all ZeroDesk source/header/script files..."
SPDX_ROOTS=(
  libs/zerodesk_core
  libs/v2_e2e
  libs/v2_client/src
  libs/v2_transport/src
  libs/v2_identity/src
  src/v2_session
)
if [ -d apps/macos ]; then
  SPDX_ROOTS+=(apps/macos)
fi

: >"$TMP_SPDX_LIST"
for root in "${SPDX_ROOTS[@]}"; do
  root_tmp="$(mktemp "${TMPDIR:-/tmp}/zd-spdx-root.XXXXXX")"
  if ! find "$root" -not -path "*/target/*" -not -path "*/.build/*" -type f \
    \( -name "*.rs" -o -name "*.h" -o -name "*.c" -o -name "*.m" -o -name "*.mm" \
       -o -name "*.cpp" -o -name "*.hpp" -o -name "*.swift" -o -name "*.metal" -o -name "*.sh" \) \
    >"$root_tmp"; then
    rm -f "$root_tmp"
    echo "FAIL: find failed for SPDX root '$root'" >&2
    exit 1
  fi
  root_cnt="$(wc -l <"$root_tmp" | tr -d ' ')"
  if [ "$root_cnt" -lt 1 ]; then
    rm -f "$root_tmp"
    echo "FAIL: SPDX root '$root' matched 0 files (fail-closed)" >&2
    exit 1
  fi
  cat "$root_tmp" >>"$TMP_SPDX_LIST"
  rm -f "$root_tmp"
done

scripts_tmp="$(mktemp "${TMPDIR:-/tmp}/zd-spdx-scripts.XXXXXX")"
if ! find scripts -maxdepth 1 -type f -name "check-*.sh" >"$scripts_tmp"; then
  rm -f "$scripts_tmp"
  echo "FAIL: find failed for scripts/check-*.sh" >&2
  exit 1
fi
scripts_cnt="$(wc -l <"$scripts_tmp" | tr -d ' ')"
if [ "$scripts_cnt" -lt 1 ]; then
  rm -f "$scripts_tmp"
  echo "FAIL: scripts/check-*.sh matched 0 files" >&2
  exit 1
fi
cat "$scripts_tmp" >>"$TMP_SPDX_LIST"
rm -f "$scripts_tmp"

sort -u -o "$TMP_SPDX_LIST" "$TMP_SPDX_LIST"

MISSING_SPDX=0
CHECKED_FILES=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  CHECKED_FILES=$((CHECKED_FILES + 1))
  rc=0
  head -n 3 "$f" | grep -q "SPDX-License-Identifier: AGPL-3.0-only" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "FAIL: missing SPDX-License-Identifier: AGPL-3.0-only in $f" >&2
    MISSING_SPDX=1
  fi
done <"$TMP_SPDX_LIST"
if [ "$CHECKED_FILES" -eq 0 ] || [ "$MISSING_SPDX" -ne 0 ]; then
  echo "FAIL: SPDX verification failed (checked=$CHECKED_FILES)" >&2
  exit 1
fi
echo "  OK: all $CHECKED_FILES ZeroDesk source/header/ObjC/C++/Swift/Metal/script files carry SPDX-License-Identifier: AGPL-3.0-only."

echo "[4/5] Checking AGPL-3.0 §5(a) modification notice on modified upstream RustDesk files..."
rc=0
head -n 5 Cargo.toml | grep -q "Modified by ZeroDesk Contributors (2026) under GNU AGPL-3.0-only" || rc=$?
if [ "$rc" -ne 0 ]; then
  echo "FAIL: root Cargo.toml missing AGPL-3.0 §5(a) dated modification notice!" >&2
  exit 1
fi
echo "  OK: modified upstream RustDesk files retain AGPL-3.0 §5(a) notice."

echo "[5/5] Auditing libs/zerodesk_core dependency licenses (count > 0, zero GPL-2.0-only/GPL-2.0+, no missing license)..."
meta_json="$("${ENV_PREFIX[@]}" cargo metadata --locked --manifest-path libs/zerodesk_core/Cargo.toml --format-version 1)" \
  || { echo "FAIL: cargo metadata --locked failed" >&2; exit 1; }
python3 -c '
import json, re, sys
data = json.load(sys.stdin)
pkgs = data.get("packages") or []
n = len(pkgs)
if n <= 0:
    print("FAIL: cargo metadata returned 0 packages", file=sys.stderr)
    sys.exit(1)
# Upstream RustDesk internal/fork crates whose Cargo.toml omits the license field
# (base/hbb_common are AGPL-3.0-only in the parent/submodule repo; default_net is MIT).
UPSTREAM_UNSPECIFIED_ALLOWLIST = {"base", "hbb_common", "default_net"}
bad = []
missing = []
for pkg in pkgs:
    name = pkg["name"]
    ver = pkg["version"]
    lic = (pkg.get("license") or "").strip()
    lf = (pkg.get("license_file") or "").strip()
    if not lic and not lf:
        if name not in UPSTREAM_UNSPECIFIED_ALLOWLIST:
            missing.append((name, ver))
        continue
    if (
        "GPL-2.0-only" in lic
        or "GPL-2.0+" in lic
        or re.search(r"\bGPL-2\.0\b(?!-or-later)", lic)
    ):
        bad.append((name, ver, lic))
if bad:
    for name, ver, lic in bad:
        print(f"FAIL: incompatible license on {name} {ver}: {lic}", file=sys.stderr)
    sys.exit(1)
if missing:
    for name, ver in missing:
        print(f"FAIL: missing license & license_file metadata on {name} {ver}", file=sys.stderr)
    sys.exit(1)
print(f"  OK: audited {n} resolved packages (count > 0); zero GPL-2.0-only/GPL-2.0+ or unaudited missing-license crates.")
' <<<"$meta_json"

echo "ALL ZERODESK COMPLIANCE CHECKS PASSED!"
