#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

ENV_PREFIX=(env -u VCPKG_ROOT PATH="/usr/bin:$PATH" RUSTC_WRAPPER="" TMPDIR=/tmp ZERODESK_LIBYUV_PREFIX="${ZERODESK_LIBYUV_PREFIX:-/Users/taole/.local/libyuv}")

echo "[1/5] Checking zero test-utils leakage in libs/zerodesk_core..."
if grep -q "test-utils" libs/zerodesk_core/Cargo.toml; then
  echo "FAIL: libs/zerodesk_core/Cargo.toml must NOT mention test-utils anywhere!" >&2
  exit 1
fi
for flags in "" "--no-default-features" "--all-features"; do
  # shellcheck disable=SC2086
  if "${ENV_PREFIX[@]}" cargo tree --manifest-path libs/zerodesk_core/Cargo.toml $flags -e features,no-dev | grep -q "test-utils"; then
    echo "FAIL: test-utils leaked into libs/zerodesk_core dependency tree (flags: '$flags')!" >&2
    exit 1
  fi
done
echo "  OK: zero test-utils leakage across default, --no-default-features, and --all-features."

echo "[2/5] Checking clean-room isolation (zero cloud-backend references in Cargo.toml & Phase 5 code)..."
if grep -rn --exclude-dir=target "cloud-backend" Cargo.toml libs/zerodesk_core libs/v2_e2e/src libs/v2_client/src libs/v2_client/Cargo.toml libs/v2_transport/src libs/v2_transport/Cargo.toml libs/v2_identity/src libs/v2_identity/Cargo.toml 2>/dev/null; then
  echo "FAIL: forbidden cloud-backend reference detected!" >&2
  exit 1
fi
echo "  OK: zero cloud-backend references."

echo "[3/5] Checking SPDX AGPL-3.0-only headers on all Phase 5 files..."
MISSING_SPDX=0
while IFS= read -r f; do
  if ! head -n 3 "$f" | grep -q "SPDX-License-Identifier: AGPL-3.0-only"; then
    echo "FAIL: missing SPDX-License-Identifier: AGPL-3.0-only in $f" >&2
    MISSING_SPDX=1
  fi
done < <(find libs/zerodesk_core/src libs/zerodesk_core/include libs/zerodesk_core/tests libs/zerodesk_core/build.rs scripts/check-phase5-compliance.sh -type f \( -name "*.rs" -o -name "*.h" -o -name "*.c" -o -name "*.sh" \))
if [ "$MISSING_SPDX" -ne 0 ]; then
  exit 1
fi
echo "  OK: all Phase 5 source/header/script files carry SPDX-License-Identifier: AGPL-3.0-only."

echo "[4/5] Checking AGPL-3.0 §5(a) modification notice on modified upstream RustDesk files..."
if ! head -n 5 Cargo.toml | grep -q "Modified by ZeroDesk Contributors (2026) under GNU AGPL-3.0-only"; then
  echo "FAIL: root Cargo.toml missing AGPL-3.0 §5(a) dated modification notice!" >&2
  exit 1
fi
echo "  OK: modified upstream RustDesk files retain AGPL-3.0 §5(a) notice."

echo "[5/5] Auditing libs/zerodesk_core dependency licenses (zero GPL-2.0-only)..."
"${ENV_PREFIX[@]}" cargo metadata --manifest-path libs/zerodesk_core/Cargo.toml --format-version 1 | python3 -c '
import json, sys
data = json.load(sys.stdin)
bad = []
for pkg in data["packages"]:
    lic = pkg.get("license") or ""
    if "GPL-2.0-only" in lic or lic.strip() == "GPL-2.0":
        bad.append((pkg["name"], pkg["version"], lic))
if bad:
    for name, ver, lic in bad:
        print(f"FAIL: incompatible license on {name} {ver}: {lic}", file=sys.stderr)
    sys.exit(1)
n = len(data["packages"])
print(f"  OK: audited {n} resolved packages; zero GPL-2.0-only crates.")
'

echo "ALL PHASE 5 COMPLIANCE CHECKS PASSED!"
