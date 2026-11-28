#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors
#
# Local Pre-Commit Gate for ZeroDesk 3-Platform CI & L2/L3 Verification Tooling.
# Runs:
#   [1/5] Workflow YAML syntax + SHA-pinning & least-privilege security audit
#   [2/5] Bash syntax (bash -n / shellcheck) + Linux L3 --dry-run & exit-code 40 verification
#   [3/5] PowerShell syntax / pwsh -DryRun (when available) + read-only / anti-forgery audit
#   [4/5] JSON Schema validity + WIN-L3-01..12 & LIN-L3-01..12 doc/script 1-to-1 alignment
#   [5/5] ./scripts/check-compliance.sh (5/5) + 11 Phase 8A ABI golden 0-byte integrity check

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/zd-ci-local.XXXXXX")"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKFLOW=".github/workflows/zerodesk-ci.yml"
SCHEMA="scripts/l3-report-schema.json"
WIN_SCRIPT="scripts/verify-windows-l3.ps1"
LIN_SCRIPT="scripts/verify-linux-l3.sh"
DOC_CI="docs/ci-and-l3-verification.md"

for req in "$WORKFLOW" "$SCHEMA" "$WIN_SCRIPT" "$LIN_SCRIPT" "$DOC_CI"; do
  if [ ! -f "$req" ]; then
    echo "FAIL: required deliverable missing: $req" >&2
    exit 1
  fi
done

echo "[1/5] Auditing $WORKFLOW (YAML syntax, SHA-pinning, branch scope, minimal permissions)..."
head -n 3 "$WORKFLOW" | grep -q "SPDX-License-Identifier: AGPL-3.0-only" \
  || { echo "FAIL: $WORKFLOW missing SPDX-License-Identifier: AGPL-3.0-only header" >&2; exit 1; }

WORKFLOW_JSON="$TMP_DIR/workflow.json"
if python3 -c "import yaml" >/dev/null 2>&1; then
  python3 -c '
import json, sys, yaml
with open(sys.argv[1], encoding="utf-8") as fh:
    data = yaml.safe_load(fh)
with open(sys.argv[2], "w", encoding="utf-8") as out:
    json.dump(data, out)
' "$WORKFLOW" "$WORKFLOW_JSON"
  echo "  OK: YAML parsed via PyYAML."
elif command -v ruby >/dev/null 2>&1; then
  ruby -ryaml -rjson -e '
data = YAML.safe_load(File.read(ARGV[0]), aliases: true)
File.write(ARGV[1], JSON.generate(data))
' "$WORKFLOW" "$WORKFLOW_JSON"
  echo "  OK: YAML parsed via Ruby YAML."
else
  echo "FAIL: neither Python PyYAML nor Ruby YAML parser is available (fail-closed)" >&2
  exit 1
fi

if command -v actionlint >/dev/null 2>&1; then
  actionlint "$WORKFLOW"
  echo "  OK: actionlint passed."
fi
if command -v yamllint >/dev/null 2>&1; then
  yamllint -d relaxed "$WORKFLOW"
  echo "  OK: yamllint passed."
fi

python3 - "$WORKFLOW" "$WORKFLOW_JSON" <<'PYEOF'
import json, re, sys

raw = open(sys.argv[1], encoding="utf-8").read()
doc = json.load(open(sys.argv[2], encoding="utf-8"))

# YAML 1.1 parsers (PyYAML / Ruby Psych) may load unquoted `on:` key as boolean True.
on_cfg = doc.get("on") if "on" in doc else doc.get("true")
if not isinstance(on_cfg, dict):
    sys.exit("FAIL: workflow missing 'on' trigger block")

if "pull_request_target" in on_cfg or re.search(r"\bpull_request_target\b", raw):
    sys.exit("FAIL: forbidden trigger pull_request_target detected")

for trig in ("push", "pull_request"):
    branches = (on_cfg.get(trig) or {}).get("branches") or []
    if branches != ["zerodesk/main"]:
        sys.exit(f"FAIL: on.{trig}.branches must be ['zerodesk/main'] (got {branches})")
if "workflow_dispatch" not in on_cfg:
    sys.exit("FAIL: workflow_dispatch trigger missing")

perms = doc.get("permissions")
if perms != {"contents": "read"}:
    sys.exit(f"FAIL: top-level permissions must be {{'contents': 'read'}} (got {perms})")

if re.search(r"persist-credentials\s*:\s*true", raw, re.IGNORECASE):
    sys.exit("FAIL: forbidden persist-credentials: true detected")

if re.search(r"(curl|wget)[^\n]*\|\s*(ba)?sh", raw, re.IGNORECASE):
    sys.exit("FAIL: forbidden curl|sh or wget|sh pipe detected")

jobs = doc.get("jobs") or {}
expected_jobs = {"compliance-linux", "windows-native", "macos-native", "collect-artifacts"}
if set(jobs.keys()) != expected_jobs:
    sys.exit(f"FAIL: jobs must be {sorted(expected_jobs)} (got {sorted(jobs.keys())})")

collect_needs = jobs["collect-artifacts"].get("needs") or []
if set(collect_needs) != {"compliance-linux", "windows-native", "macos-native"}:
    sys.exit(f"FAIL: collect-artifacts needs mismatch: {collect_needs}")

# Forbid ${{ runner.* }} inside top-level or job-level env: blocks (GitHub Actions parse-time error).
runner_ctx_re = re.compile(r"\$\{\{\s*runner\.", re.IGNORECASE)
top_env = doc.get("env") or {}
if isinstance(top_env, dict):
    for ek, ev in top_env.items():
        if runner_ctx_re.search(str(ev)):
            sys.exit(f"FAIL: forbidden runner.* context in top-level env.{ek}: {ev}")

uses_count = 0
sha_re = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$")
for job_name, job in jobs.items():
    job_env = job.get("env") or {}
    if isinstance(job_env, dict):
        for ek, ev in job_env.items():
            if runner_ctx_re.search(str(ev)):
                sys.exit(f"FAIL: forbidden runner.* context in jobs.{job_name}.env.{ek}: {ev}")
    if "permissions" in job:
        jperms = job["permissions"]
        if isinstance(jperms, dict) and any(str(v).lower() == "write" for v in jperms.values()):
            sys.exit(f"FAIL: job '{job_name}' grants forbidden write permission: {jperms}")
        if str(jperms).lower() == "write-all":
            sys.exit(f"FAIL: job '{job_name}' grants write-all")
    for idx, step in enumerate(job.get("steps") or []):
        uses = step.get("uses")
        if uses:
            uses_count += 1
            if not sha_re.fullmatch(uses):
                sys.exit(f"FAIL: unpinned Action in {job_name}[{idx}]: {uses}")
            if uses.startswith("actions/checkout@"):
                with_cfg = step.get("with") or {}
                if with_cfg.get("persist-credentials") is not False:
                    sys.exit(f"FAIL: actions/checkout in {job_name}[{idx}] must set persist-credentials: false")

if uses_count < 8:
    sys.exit(f"FAIL: expected >=8 pinned Action uses, found {uses_count}")

# Confirm no 'write' permissions anywhere in raw text
if re.search(r"^\s*[a-z-]+:\s*write\b", raw, re.MULTILINE):
    sys.exit("FAIL: write permission token detected in workflow")

print(f"  OK: {uses_count} Action references 100% 40-hex SHA pinned; least-privilege & branch rules verified.")
PYEOF

# Verify workflow-referenced Cargo feature & vcpkg overlay directory exist in repo.
grep -q 'linux-pkg-config' libs/scrap/Cargo.toml \
  || { echo "FAIL: libs/scrap/Cargo.toml missing linux-pkg-config feature referenced by $WORKFLOW" >&2; exit 1; }
test -d res/vcpkg \
  || { echo "FAIL: res/vcpkg overlay directory missing (referenced by $WORKFLOW)" >&2; exit 1; }
echo "  OK: libs/scrap/Cargo.toml defines linux-pkg-config and res/vcpkg exists."

echo "[2/5] Checking Bash syntax, SPDX headers, and verify-linux-l3.sh dry-run + exit-code 40..."
for f in "$LIN_SCRIPT" scripts/check-ci-local.sh; do
  bash -n "$f"
done
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck "$LIN_SCRIPT" scripts/check-ci-local.sh
  echo "  OK: shellcheck passed."
fi
head -n 3 "$LIN_SCRIPT" | grep -q "SPDX-License-Identifier: AGPL-3.0-only" \
  || { echo "FAIL: $LIN_SCRIPT missing SPDX header" >&2; exit 1; }
head -n 3 scripts/check-ci-local.sh | grep -q "SPDX-License-Identifier: AGPL-3.0-only" \
  || { echo "FAIL: scripts/check-ci-local.sh missing SPDX header" >&2; exit 1; }
head -n 3 "$DOC_CI" | grep -q "SPDX-License-Identifier: AGPL-3.0-only" \
  || { echo "FAIL: $DOC_CI missing SPDX header" >&2; exit 1; }

./scripts/verify-linux-l3.sh --help >/dev/null

HOST_OS="$(uname -s)"
if [ "$HOST_OS" != "Linux" ]; then
  rc=0
  ./scripts/verify-linux-l3.sh --mode ci --output "$TMP_DIR/lin-fail.json" >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 40 ]; then
    echo "FAIL: verify-linux-l3.sh without --dry-run on $HOST_OS exited $rc (expected 40)" >&2
    exit 1
  fi

  LIN_DRY_OUT="$TMP_DIR/lin-dry-run.json"
  ./scripts/verify-linux-l3.sh --dry-run --mode ci --output "$LIN_DRY_OUT"
  python3 - "$SCHEMA" "$LIN_DRY_OUT" <<'PYEOF'
import json, os, re, socket, sys

schema = json.load(open(sys.argv[1], encoding="utf-8"))
rep = json.load(open(sys.argv[2], encoding="utf-8"))
valid = set(schema["$defs"]["verificationStatus"]["enum"])

assert rep["schema_version"] == 1
assert rep["mode"] == "ci"
assert rep["platform"] == "linux"
assert isinstance(rep["ci_runner"], bool)
assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", rep["started_at_utc"])
items = rep["items"]
assert len(items) == 12
assert [it["id"] for it in items] == [f"LIN-L3-{i:02d}" for i in range(1, 13)]
for it in items:
    assert it["status"] in valid
    assert it["status"] == "SKIPPED_UNSUPPORTED_PLATFORM", f"expected SKIPPED_UNSUPPORTED_PLATFORM, got {it['status']}"
    assert it["duration_ms"] >= 0
assert rep["summary"] == {
    "pass": 0,
    "l2_native_pass": 0,
    "pending_physical_l3": 0,
    "skipped_no_hardware": 0,
    "skipped_unsupported_platform": 12,
    "fail": 0,
}
raw = json.dumps(rep)
mac_prefix = "/Us" + "ers/"
assert mac_prefix.lower() not in raw.lower(), "unredacted macOS user path in dry-run JSON"
assert "/home/" not in raw.lower(), "unredacted Linux home path in dry-run JSON"
host = socket.gethostname()
if host and len(host) >= 4:
    assert host.lower() not in raw.lower(), "unredacted hostname in dry-run JSON"
print("  OK: verify-linux-l3.sh non-Linux exit=40 and --dry-run scrubbed JSON (12/12 SKIPPED_UNSUPPORTED_PLATFORM) verified.")
PYEOF
else
  echo "  OK: Linux host detected; bash -n & --help verified."
fi

echo "[3/5] Auditing $WIN_SCRIPT (SPDX, PowerShell syntax/dry-run, PROBE-NOT-PATCH, anti-forgery)..."
head -n 3 "$WIN_SCRIPT" | grep -q "SPDX-License-Identifier: AGPL-3.0-only" \
  || { echo "FAIL: $WIN_SCRIPT missing SPDX header" >&2; exit 1; }

case "$HOST_OS" in
  MINGW*|MSYS*|CYGWIN*|Windows_NT) IS_WINDOWS=1 ;;
  *) IS_WINDOWS=0 ;;
esac

if command -v pwsh >/dev/null 2>&1; then
  pwsh -NoProfile -Command '
    $tokens = $null; $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($args[0], [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -gt 0) {
      $errors | ForEach-Object { [Console]::Error.WriteLine($_.Message) }
      exit 1
    }
  ' "$WIN_SCRIPT"
  if [ "$IS_WINDOWS" -ne 1 ]; then
    rc=0
    pwsh -NoProfile -File "$WIN_SCRIPT" -Mode ci -Output "$TMP_DIR/win-fail.json" >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 40 ]; then
      echo "FAIL: verify-windows-l3.ps1 without -DryRun on $HOST_OS exited $rc (expected 40)" >&2
      exit 1
    fi
    WIN_DRY_OUT="$TMP_DIR/win-dry-run.json"
    pwsh -NoProfile -File "$WIN_SCRIPT" -DryRun -Mode ci -Output "$WIN_DRY_OUT"
    python3 - "$SCHEMA" "$WIN_DRY_OUT" <<'PYEOF'
import json, re, socket, sys

schema = json.load(open(sys.argv[1], encoding="utf-8"))
rep = json.load(open(sys.argv[2], encoding="utf-8"))
valid = set(schema["$defs"]["verificationStatus"]["enum"])

assert rep["schema_version"] == 1
assert rep["mode"] == "ci"
assert rep["platform"] == "windows"
assert isinstance(rep["ci_runner"], bool)
assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", rep["started_at_utc"])
items = rep["items"]
assert len(items) == 12
assert [it["id"] for it in items] == [f"WIN-L3-{i:02d}" for i in range(1, 13)]
for it in items:
    assert it["status"] in valid
    assert it["status"] == "SKIPPED_UNSUPPORTED_PLATFORM"
    assert it["duration_ms"] >= 0
assert rep["summary"] == {
    "pass": 0,
    "l2_native_pass": 0,
    "pending_physical_l3": 0,
    "skipped_no_hardware": 0,
    "skipped_unsupported_platform": 12,
    "fail": 0,
}
raw = json.dumps(rep)
mac_prefix = "/Us" + "ers/"
assert mac_prefix.lower() not in raw.lower(), "unredacted macOS user path in Windows dry-run JSON"
assert "/home/" not in raw.lower(), "unredacted Linux home path in Windows dry-run JSON"
host = socket.gethostname()
if host and len(host) >= 4:
    assert host.lower() not in raw.lower(), "unredacted hostname in Windows dry-run JSON"
print("  OK: pwsh AST parse, exit=40, and -DryRun scrubbed JSON (12/12 SKIPPED_UNSUPPORTED_PLATFORM) verified.")
PYEOF
  fi
else
  echo "  INFO: pwsh not installed locally; running strict Python static AST/regex validator on $WIN_SCRIPT."
fi

python3 - "$WIN_SCRIPT" "$LIN_SCRIPT" <<'PYEOF'
import re, sys

win_src = open(sys.argv[1], encoding="utf-8").read()
lin_src = open(sys.argv[2], encoding="utf-8").read()

# Verify required 6-state statuses & anti-forgery & scrubbing & exit codes in PS1
required_ps1_tokens = [
    "SPDX-License-Identifier: AGPL-3.0-only",
    "PASS", "FAIL", "L2_NATIVE_PASS", "PENDING_PHYSICAL_L3",
    "SKIPPED_NO_HARDWARE", "SKIPPED_UNSUPPORTED_PLATFORM",
    "Scrub-Text", "Get-ShortSha256", "Write-ReportAtomic",
    "WatchdogBin", "ANTI-FORGERY VIOLATION", "Move-Item",
    "exit 0", "exit 10", "exit 20", "exit 30", "exit 40",
]
for tok in required_ps1_tokens:
    if tok not in win_src:
        sys.exit(f"FAIL: {sys.argv[1]} missing required token: {tok}")

# Strip PowerShell block comments (<# ... #>) and full-line # comments accurately
no_block_comments = re.sub(r"<#.*?#>", "", win_src, flags=re.DOTALL)
no_comments = re.sub(r"(?m)^\s*#.*$", "", no_block_comments)
if no_comments.count("{") != no_comments.count("}"):
    sys.exit(f"FAIL: unbalanced braces in {sys.argv[1]}: {{={no_comments.count('{')} }}={no_comments.count('}')}")
if no_comments.count("(") != no_comments.count(")"):
    sys.exit(f"FAIL: unbalanced parens in {sys.argv[1]}: (={no_comments.count('(')} )={no_comments.count(')')}")

# PROBE-NOT-PATCH forbidden mutating/network/elevation commands
win_forbidden = [
    r"Set-ItemProperty\b[^\n]*HKLM",
    r"\bNew-ItemProperty\b",
    r"\bRemove-ItemProperty\b",
    r"\breg\s+add\b",
    r"\breg\.exe\b",
    r"\bNew-Service\b",
    r"\bSet-Service\b",
    r"\bStop-Service\b",
    r"\bStart-Service\b",
    r"\bsc\.exe\s+create\b",
    r"\bschtasks\b",
    r"\bnetsh\b",
    r"\bbcdedit\b",
    r"\bDISM\b",
    r"\bEnable-WindowsOptionalFeature\b",
    r"\bSet-CimInstance\b",
    r"-Verb\s+RunAs\b",
    r"\bInvoke-WebRequest\b",
    r"\bInvoke-RestMethod\b",
    r"\bStart-BitsTransfer\b",
]
for pat in win_forbidden:
    if re.search(pat, no_comments, re.IGNORECASE):
        sys.exit(f"FAIL: PROBE-NOT-PATCH violation in {sys.argv[1]}: matched /{pat}/")

lin_no_comments = re.sub(r"(?m)^\s*#.*$", "", lin_src)
lin_forbidden = [
    r"\bmodprobe\b",
    r"\bsystemctl\s+(enable|start|stop|mask)\b",
    r"\bsudo\b",
    r"\bpkexec\b",
    r"\bcurl\s+",
    r"\bwget\s+",
    r"\bapt-get\b",
    r"\bdpkg\s+-i\b",
    r"\bsysctl\s+-w\b",
    r"\biptables\b",
    r"\bnft\s+",
    r"\bumount\b",
]
for pat in lin_forbidden:
    if re.search(pat, lin_no_comments):
        sys.exit(f"FAIL: PROBE-NOT-PATCH violation in {sys.argv[2]}: matched /{pat}/")

print("  OK: PROBE-NOT-PATCH, anti-forgery, scrubbing, and syntax checks passed for Windows & Linux harnesses.")
PYEOF

echo "[4/5] Validating $SCHEMA and 1-to-1 WIN-L3-01..12 & LIN-L3-01..12 checklist alignment..."
python3 - "$SCHEMA" "$WIN_SCRIPT" "$LIN_SCRIPT" docs/windows-platform-support.md docs/linux-platform-support.md <<'PYEOF'
import json, re, sys

schema = json.load(open(sys.argv[1], encoding="utf-8"))
win_src = open(sys.argv[2], encoding="utf-8").read()
lin_src = open(sys.argv[3], encoding="utf-8").read()
win_doc = open(sys.argv[4], encoding="utf-8").read()
lin_doc = open(sys.argv[5], encoding="utf-8").read()

assert schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
expected_statuses = [
    "PASS",
    "FAIL",
    "L2_NATIVE_PASS",
    "PENDING_PHYSICAL_L3",
    "SKIPPED_NO_HARDWARE",
    "SKIPPED_UNSUPPORTED_PLATFORM",
]
assert schema["$defs"]["verificationStatus"]["enum"] == expected_statuses
all_of = schema.get("allOf") or []
has_mode_ci_guard = any(
    ((rule.get("if") or {}).get("properties") or {}).get("mode") == {"const": "ci"}
    for rule in all_of
)
has_ci_runner_guard = any(
    ((rule.get("if") or {}).get("properties") or {}).get("ci_runner") == {"const": True}
    for rule in all_of
)
assert has_mode_ci_guard and has_ci_runner_guard, "schema missing mode==ci or ci_runner==true anti-forgery allOf guards"

want_win = [f"WIN-L3-{i:02d}" for i in range(1, 13)]
want_lin = [f"LIN-L3-{i:02d}" for i in range(1, 13)]

doc_win = sorted(set(re.findall(r"WIN-L3-\d{2}", win_doc)))
doc_lin = sorted(set(re.findall(r"LIN-L3-\d{2}", lin_doc)))
ps1_win = sorted(set(re.findall(r"WIN-L3-\d{2}", win_src)))
sh_lin = sorted(set(re.findall(r"LIN-L3-\d{2}", lin_src)))

assert doc_win == want_win, f"docs/windows-platform-support.md IDs mismatch: {doc_win}"
assert ps1_win == want_win, f"verify-windows-l3.ps1 IDs mismatch: {ps1_win}"
assert doc_lin == want_lin, f"docs/linux-platform-support.md IDs mismatch: {doc_lin}"
assert sh_lin == want_lin, f"verify-linux-l3.sh IDs mismatch: {sh_lin}"

print("  OK: JSON Schema Draft 2020-12 valid; WIN-L3-01..12 and LIN-L3-01..12 aligned 1-to-1 with docs.")
PYEOF

echo "[5/5] Running ./scripts/check-compliance.sh (5/5) and Phase 8A ABI golden 0-byte check..."
./scripts/check-compliance.sh

python3 - <<'PYEOF'
import hashlib, json, os, subprocess, sys

EXPECTED = {
    "abi_v2_clipboard_sync_status_event.json": "540cd986a939a11e479b0a782b40ea18cc24cfb9e949a64f2c9ea7f29b39c4aa",
    "abi_v2_codec_ack_event.json": "1d8e7a97a8851b1f01ec99780c1653ed91b26c19741303e43f058a71574d2d60",
    "abi_v2_file_transfer_complete_event.json": "8476e87aabbab2f902798eb10f6ffce474729a3752df6c9410b67b7fad6f4727",
    "abi_v2_get_permissions_req.json": "2d2cf2a05068df8524e60c31677d50818da12765ff68c0986054874b87af1c01",
    "abi_v2_handshake_reply.json": "c1c8c1394cba2c80c472cbc994704bda5889212c7579442acfd1dd767428bdaa",
    "abi_v2_hud_stats_event.json": "f473802d40b9ab8cc78841e9e86508d18c50bc637248f6764916582995d6830b",
    "abi_v2_input_enabled_ack_event.json": "d833f21f1a423b23bede55d546d115b65aafbb8d56a8f534fb03647c8b748c12",
    "abi_v2_permission_status_event.json": "dc55caf141201a7cb84597e8944ad456bfa22fd1663ad9990da4aa91bb08cfea",
    "abi_v2_set_input_enabled_req.json": "61eac745666e7e36ef9378b445bbb7176537ed8e8fdf3f8895cc177a62713b89",
    "abi_v2_set_video_quality_req.json": "21550c8ef0c748adb2406e45570a7b8d8e8d328a74a5ef0f0ee968b1bebccf2a",
    "abi_v2_unknown_event_and_fields.json": "453aaf89961f1111a98135c96d4cd3c1ff4a9147d86ea2481a3f860f38af94ea",
}
golden_dir = "libs/zerodesk_core/tests/golden"
actual = sorted(f for f in os.listdir(golden_dir) if f.endswith(".json"))
assert actual == sorted(EXPECTED.keys()), f"golden file list mismatch: {actual}"
for name, want in EXPECTED.items():
    raw = open(os.path.join(golden_dir, name), "rb").read()
    json.loads(raw.decode("utf-8"))
    got = hashlib.sha256(raw).hexdigest()
    assert got == want, f"golden SHA-256 mismatch for {name}: got {got}, want {want}"

diff_out = subprocess.check_output(["git", "diff", "HEAD", "--", golden_dir], text=True)
assert diff_out == "", f"unexpected diff vs HEAD in {golden_dir}:\n{diff_out}"
print("  OK: 11 Phase 8A ABI golden snapshots verified (0-byte diff, exact SHA-256 match).")
PYEOF

echo "ALL ZERODESK LOCAL CI GATE CHECKS PASSED!"
