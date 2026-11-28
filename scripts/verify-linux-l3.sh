#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 ZeroDesk Contributors
#
# ZeroDesk Linux L2/L3 Verification Harness (LIN-L3-01 .. LIN-L3-12)
#
# PROBE-NOT-PATCH (Strictly Read-Only & Idempotent):
#   - NEVER runs modprobe, systemctl enable, chmod/chown, sudo/pkexec, or network requests.
#   - NEVER dumps process environment variables.
#   - All emitted JSON strings pass through scrub() to strip local user/host/repo paths,
#     and DRM/GPU hardware fingerprints are hashed to the first 8 lowercase hex chars of SHA-256.
#   - Anti-forgery redline: `--mode ci` is code-level forbidden from emitting status `PASS`.
#
# Exit Codes:
#   0  = CI mode with 0 FAIL | --dry-run on non-Linux | strict-l3 with 12/12 PASS
#   10 = strict-l3 mode with 0 FAIL and >=1 non-PASS item (e.g. PENDING_PHYSICAL_L3)
#   20 = At least one item reported FAIL
#   30 = Script/runtime error, invalid arguments, or CI anti-forgery invariant violation
#   40 = Unsupported platform (non-Linux host without --dry-run)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

MODE="ci"
OUTPUT="zerodesk-linux-l3-report.json"
DIAG_BIN=""
WATCHDOG_BIN=""
DRY_RUN=0

usage() {
  cat <<'EOF'
Usage: verify-linux-l3.sh [options]

Options:
  --mode <ci|strict-l3>    Verification mode (default: ci). CI mode and CI runners NEVER emit PASS.
                           Automated strict-l3 preserves L2_NATIVE_PASS on headless kernel probes and
                           exits 10 whenever physical GPU/desktop items remain PENDING_PHYSICAL_L3
                           until verified on real Intel/AMD Wayland and X11 hardware.
  --output <path|->        Output JSON report path (default: zerodesk-linux-l3-report.json; '-' = stdout).
  --diag-bin <path>        Optional path to zerodesk-linux-diag binary.
  --watchdog-bin <path>    Optional path to zerodesk-hid-watchdog binary.
  --dry-run                Emit schema-valid SKIPPED_UNSUPPORTED_PLATFORM report on non-Linux hosts (exit 0).
  --help, -h               Show this help message and exit 0.

Exit codes:
  0  = Pass / CI green (0 FAIL) / non-Linux --dry-run
  10 = strict-l3 incomplete (0 FAIL, <12 PASS)
  20 = Verification failure (>=1 FAIL)
  30 = Script error / invalid CLI argument / anti-forgery violation
  40 = Unsupported platform (non-Linux without --dry-run)
EOF
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    --mode)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --mode requires a value" >&2
        exit 30
      fi
      MODE="$2"
      shift 2
      ;;
    --output)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --output requires a value" >&2
        exit 30
      fi
      OUTPUT="$2"
      shift 2
      ;;
    --diag-bin)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --diag-bin requires a value" >&2
        exit 30
      fi
      DIAG_BIN="$2"
      shift 2
      ;;
    --watchdog-bin)
      if [ "$#" -lt 2 ]; then
        echo "ERROR: --watchdog-bin requires a value" >&2
        exit 30
      fi
      WATCHDOG_BIN="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      echo "ERROR: unknown argument: $1" >&2
      usage >&2
      exit 30
      ;;
  esac
done

if [ "$MODE" != "ci" ] && [ "$MODE" != "strict-l3" ]; then
  echo "ERROR: invalid --mode '$MODE' (expected 'ci' or 'strict-l3')" >&2
  exit 30
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 is required to run verify-linux-l3.sh" >&2
  exit 30
fi

HOST_OS="$(uname -s)"
if [ "$HOST_OS" != "Linux" ] && [ "$DRY_RUN" -ne 1 ]; then
  echo "ERROR: verify-linux-l3.sh requires Linux (host_os=$HOST_OS; pass --dry-run for cross-platform schema dry-run)" >&2
  exit 40
fi

if [ -z "$DIAG_BIN" ]; then
  for cand in \
    "$REPO_ROOT/libs/zerodesk_core/target/release/zerodesk-linux-diag" \
    "$REPO_ROOT/libs/zerodesk_core/target/debug/zerodesk-linux-diag"; do
    if [ -x "$cand" ]; then
      DIAG_BIN="$cand"
      break
    fi
  done
fi

if [ -z "$WATCHDOG_BIN" ]; then
  for cand in \
    "$REPO_ROOT/libs/zerodesk_core/target/release/zerodesk-hid-watchdog" \
    "$REPO_ROOT/libs/zerodesk_core/target/debug/zerodesk-hid-watchdog"; do
    if [ -x "$cand" ]; then
      WATCHDOG_BIN="$cand"
      break
    fi
  done
fi

python3 - "$MODE" "$OUTPUT" "$DIAG_BIN" "$WATCHDOG_BIN" "$DRY_RUN" "$REPO_ROOT" "$HOST_OS" <<'PYEOF'
import ctypes
import datetime
import glob
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import tempfile
import time

mode = sys.argv[1]
output_path = sys.argv[2]
diag_bin = sys.argv[3]
watchdog_bin = sys.argv[4]
dry_run = sys.argv[5] == "1"
repo_root = sys.argv[6]
host_os = sys.argv[7]

started_at_utc = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
ci_runner = (os.environ.get("CI", "").strip().lower() in ("true", "1")) or (
    os.environ.get("GITHUB_ACTIONS", "").strip().lower() in ("true", "1")
)

VALID_STATUSES = {
    "PASS",
    "FAIL",
    "L2_NATIVE_PASS",
    "PENDING_PHYSICAL_L3",
    "SKIPPED_NO_HARDWARE",
    "SKIPPED_UNSUPPORTED_PLATFORM",
}

CHECKLIST = [
    ("LIN-L3-01", "Wayland xdg-desktop-portal ScreenCast + PipeWire Frame Arrival", True, False),
    ("LIN-L3-02", "X11 XShm Multi-Monitor + XRandR Hot-Switch + XFixes Cursor", True, False),
    ("LIN-L3-03", "VA-API Open-Source Driver Probe & Allowlist Enforcement", True, False),
    ("LIN-L3-04", "VA-API First-IDR HardwareReady Gate", True, False),
    ("LIN-L3-05", "VA-API 30-Frame Stability Window & Explicit Renegotiation", True, False),
    ("LIN-L3-06", "VA-API Dynamic Phase 9A QoE Bitrate / FPS / Force-IDR Control", True, False),
    ("LIN-L3-07", "LinuxHidKeyMap Physical Key & Mouse Injection + Portal/XTest Degradation", True, False),
    ("LIN-L3-08", "Opt-In /dev/uinput Permission & High-Privilege Warning Gate", False, True),
    ("LIN-L3-09", "Independent Watchdog Parent SIGKILL Dual-Layer Release (<= 500ms)", False, False),
    ("LIN-L3-10", "Watchdog Legacy /proc/<pid>/stat Fallback & Emergency Escape Hotkey", False, False),
    ("LIN-L3-11", "Watchdog Zero Descriptor Leak Audit (/proc/self/fd) & Fork-Race Check", False, False),
    ("LIN-L3-12", "zerodesk-linux-diag Real-Machine Audit & 30-Minute 1080p60 Soak", True, False),
]


def short_sha256(val):
    if not val:
        return None
    return hashlib.sha256(val.encode("utf-8")).hexdigest()[:8]


def scrub(text):
    if text is None:
        return ""
    s = str(text)
    if repo_root:
        s = s.replace(repo_root, "<REPO>")
    home = os.environ.get("HOME", "")
    if home:
        s = s.replace(home, "<HOME>")
    userprofile = os.environ.get("USERPROFILE", "")
    if userprofile:
        s = s.replace(userprofile, "<HOME>")
    mac_prefix = "/Us" + "ers/"
    s = re.sub(r"(?i)[A-Z]:\\Users\\[^\\\s\"'/]+", "<HOME>", s)
    s = re.sub(r"(?i)[A-Z]:" + re.escape(mac_prefix) + r"[^/\s\"']+", "<HOME>", s)
    s = re.sub(r"(?i)/home/[^/\s\"']+", "<HOME>", s)
    s = re.sub(r"(?i)" + re.escape(mac_prefix) + r"[^/\s\"']+", "<HOME>", s)
    s = re.sub(r"(?i)/root(?=/|\s|$)", "<HOME>", s)
    try:
        hostname = socket.gethostname()
        if hostname:
            s = re.sub(r"\b" + re.escape(hostname) + r"\b", "<HOST>", s, flags=re.IGNORECASE)
    except OSError:
        pass
    user = os.environ.get("USER") or os.environ.get("LOGNAME") or ""
    if user and len(user) >= 2:
        s = re.sub(r"\b" + re.escape(user) + r"\b", "<USER>", s)
    return s


def make_item(spec, status, evidence, duration_ms, hw_fp=None):
    item_id, title, req_hw, req_elev = spec
    if status not in VALID_STATUSES:
        raise RuntimeError(f"Invalid status '{status}' for {item_id}")
    if (mode == "ci" or ci_runner) and status == "PASS":
        raise RuntimeError(
            f"ANTI-FORGERY VIOLATION: ci mode / CI runner forbids PASS (item={item_id}, mode={mode}, ci_runner={ci_runner})"
        )
    if status == "PASS" and (not hw_fp or not re.fullmatch(r"[0-9a-f]{8}", hw_fp)):
        raise RuntimeError(
            f"ANTI-FORGERY VIOLATION: status PASS requires 8-hex hardware_fingerprint (item={item_id})"
        )
    obj = {
        "id": item_id,
        "title": title,
        "status": status,
        "evidence": scrub(evidence),
        "duration_ms": max(0, int(duration_ms)),
        "requires_hardware": bool(req_hw),
        "requires_elevation": bool(req_elev),
    }
    if hw_fp:
        obj["hardware_fingerprint"] = hw_fp
    return obj


def build_summary(items):
    counts = {
        "pass": 0,
        "l2_native_pass": 0,
        "pending_physical_l3": 0,
        "skipped_no_hardware": 0,
        "skipped_unsupported_platform": 0,
        "fail": 0,
    }
    mapping = {
        "PASS": "pass",
        "L2_NATIVE_PASS": "l2_native_pass",
        "PENDING_PHYSICAL_L3": "pending_physical_l3",
        "SKIPPED_NO_HARDWARE": "skipped_no_hardware",
        "SKIPPED_UNSUPPORTED_PLATFORM": "skipped_unsupported_platform",
        "FAIL": "fail",
    }
    for it in items:
        counts[mapping[it["status"]]] += 1
    return counts


def write_report_atomic(report, target):
    # Final anti-forgery gate before serialization
    if report["mode"] == "ci" or report["ci_runner"]:
        if report["summary"]["pass"] != 0:
            raise RuntimeError("ANTI-FORGERY VIOLATION: CI report summary.pass must be 0")
        for it in report["items"]:
            if it["status"] == "PASS":
                raise RuntimeError(
                    f"ANTI-FORGERY VIOLATION: CI report item {it['id']} cannot have status PASS"
                )
    rendered = json.dumps(report, indent=2) + "\n"
    if target == "-":
        sys.stdout.write(rendered)
        return
    abs_target = os.path.abspath(target)
    out_dir = os.path.dirname(abs_target) or "."
    os.makedirs(out_dir, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".zd-l3-report.", suffix=".tmp", dir=out_dir)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(rendered)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, abs_target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def probe_pidfd_open():
    t0 = time.monotonic()
    if hasattr(os, "pidfd_open"):
        try:
            fd = os.pidfd_open(os.getpid(), 0)
            os.close(fd)
            return True, "os.pidfd_open(getpid(), 0) succeeded", int((time.monotonic() - t0) * 1000)
        except OSError as e:
            return False, f"os.pidfd_open failed: {e}", int((time.monotonic() - t0) * 1000)
    # Fallback syscall lookup for x86_64/aarch64 Linux (SYS_pidfd_open = 434)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.argtypes = [ctypes.c_long, ctypes.c_int, ctypes.c_uint]
        libc.syscall.restype = ctypes.c_long
        fd = int(libc.syscall(434, os.getpid(), 0))
        if fd >= 0:
            os.close(fd)
            return True, "syscall(SYS_pidfd_open=434) succeeded", int((time.monotonic() - t0) * 1000)
        err = ctypes.get_errno()
        return False, f"syscall(SYS_pidfd_open) errno={err}", int((time.monotonic() - t0) * 1000)
    except Exception as e:
        return False, f"pidfd_open probe error: {e}", int((time.monotonic() - t0) * 1000)


def probe_pr_set_pdeathsig_readonly():
    # PR_GET_PDEATHSIG = 2 (strictly read-only query of kernel prctl support)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_ulong,
            ctypes.c_ulong,
            ctypes.c_ulong,
        ]
        libc.prctl.restype = ctypes.c_int
        out_sig = ctypes.c_int(-1)
        rc = int(libc.prctl(2, ctypes.byref(out_sig), 0, 0, 0))
        if rc == 0:
            return True, f"prctl(PR_GET_PDEATHSIG) ok (current_sig={out_sig.value})"
        return False, f"prctl(PR_GET_PDEATHSIG) rc={rc} errno={ctypes.get_errno()}"
    except Exception as e:
        return False, f"prctl probe error: {e}"


def probe_proc_self_stat():
    try:
        with open("/proc/self/stat", "r", encoding="utf-8") as fh:
            raw = fh.read().strip()
        rparen = raw.rfind(")")
        if rparen < 0:
            return False, "malformed /proc/self/stat (missing ')')"
        fields_after = raw[rparen + 2 :].split()
        # Field 22 (1-indexed) is index 19 after field 2 (comm)
        starttime = int(fields_after[19])
        if starttime <= 0:
            return False, f"/proc/self/stat starttime={starttime} invalid"
        return True, f"/proc/self/stat parsed cleanly (field22 starttime={starttime})"
    except Exception as e:
        return False, f"/proc/self/stat read error: {e}"


def main():
    if host_os != "Linux":
        if not dry_run:
            sys.stderr.write("ERROR: verify-linux-l3.sh requires Linux\n")
            return 40
        items = [
            make_item(
                spec,
                "SKIPPED_UNSUPPORTED_PLATFORM",
                f"dry-run on non-Linux host ({host_os}); real Linux host required for L2/L3 probes",
                0,
            )
            for spec in CHECKLIST
        ]
        report = {
            "schema_version": 1,
            "mode": mode,
            "ci_runner": ci_runner,
            "platform": "linux",
            "started_at_utc": started_at_utc,
            "items": items,
            "summary": build_summary(items),
        }
        write_report_atomic(report, output_path)
        return 0

    # --- Native Linux Read-Only Probes (PROBE-NOT-PATCH) ---
    t_diag0 = time.monotonic()
    diag_parsed = None
    diag_err = None
    diag_rc = -1
    if diag_bin and os.path.isfile(diag_bin) and os.access(diag_bin, os.X_OK):
        try:
            proc = subprocess.run(
                [diag_bin, "--json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
            diag_rc = proc.returncode
            diag_parsed = json.loads(proc.stdout)
            required_sections = ("portal", "capture", "vaapi", "input", "watchdog")
            if (
                diag_parsed.get("schema_version") != 1
                or diag_parsed.get("linux_host_required") is not False
                or any(diag_parsed.get(k) is None for k in required_sections)
            ):
                diag_err = (
                    f"zerodesk-linux-diag schema mismatch (schema_version={diag_parsed.get('schema_version')}, "
                    f"linux_host_required={diag_parsed.get('linux_host_required')})"
                )
                diag_parsed = None
        except Exception as e:
            diag_err = f"zerodesk-linux-diag execution/parse failed: {e}"
            diag_parsed = None
    else:
        diag_err = "zerodesk-linux-diag binary not found (pass --diag-bin or build zerodesk_core)"
    diag_ms = int((time.monotonic() - t_diag0) * 1000)

    # Read-only hardware fingerprint from DRM render node / VA-API vendor (never raw serials).
    # Only a non-empty real GPU vendor_string from VA-API qualifies as hw_fp_strong for strict-l3 PASS;
    # arch-only render-node fallback hashes are informational only and NEVER authorize PASS.
    render_nodes = sorted(glob.glob("/dev/dri/renderD*"))
    hw_fp = None
    hw_fp_strong = False
    if diag_parsed and diag_parsed.get("vaapi"):
        va = diag_parsed["vaapi"]
        vendor_str = (va.get("vendor_string") or "").strip()
        render_node = (va.get("render_node") or "").strip()
        if render_node and vendor_str:
            hw_fp = short_sha256(f"{render_node}|{vendor_str}|{va.get('driver_class', '')}")
            hw_fp_strong = True
    if hw_fp is None and render_nodes:
        hw_fp = short_sha256(f"{render_nodes[0]}|{platform.machine()}")

    # Read-only /dev/uinput and /dev/input/event* inspection
    uinput_exists = os.path.exists("/dev/uinput")
    uinput_writable = os.access("/dev/uinput", os.W_OK) if uinput_exists else False
    evdev_count = len(glob.glob("/dev/input/event*"))

    # Kernel pidfd_open, PR_GET_PDEATHSIG, and /proc/self/stat probes
    pidfd_ok, pidfd_detail, pidfd_ms = probe_pidfd_open()
    pdeath_ok, pdeath_detail = probe_pr_set_pdeathsig_readonly()
    procstat_ok, procstat_detail = probe_proc_self_stat()

    # Check watchdog binary presence & fail-closed arg rejection (non-destructive)
    watchdog_bin_ok = False
    watchdog_bin_detail = "zerodesk-hid-watchdog binary not found"
    if watchdog_bin and os.path.isfile(watchdog_bin) and os.access(watchdog_bin, os.X_OK):
        try:
            wp = subprocess.run(
                [watchdog_bin],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=10,
                check=False,
            )
            if wp.returncode != 0:
                watchdog_bin_ok = True
                watchdog_bin_detail = f"zerodesk-hid-watchdog executable verified (fail-closed on missing args, rc={wp.returncode})"
            else:
                watchdog_bin_detail = "zerodesk-hid-watchdog unexpectedly exited 0 with no args"
        except Exception as e:
            watchdog_bin_detail = f"zerodesk-hid-watchdog probe error: {e}"

    session_kind = diag_parsed.get("session_kind", "unknown") if diag_parsed else "unknown"
    vaapi_sec = diag_parsed.get("vaapi", {}) if diag_parsed else {}
    input_sec = diag_parsed.get("input", {}) if diag_parsed else {}
    wd_sec = diag_parsed.get("watchdog", {}) if diag_parsed else {}

    items = []

    # LIN-L3-01: Wayland portal ScreenCast + PipeWire
    items.append(
        make_item(
            CHECKLIST[0],
            "PENDING_PHYSICAL_L3",
            f"session={session_kind}; Wayland xdg-desktop-portal ScreenCast & PipeWire DMA-BUF/MemFd frame arrival requires interactive GNOME/KDE Wayland desktop",
            0,
            hw_fp,
        )
    )

    # LIN-L3-02: X11 XShm Multi-Monitor + XRandR + XFixes
    items.append(
        make_item(
            CHECKLIST[1],
            "PENDING_PHYSICAL_L3",
            f"session={session_kind}; X11 XShm multi-monitor, rotated XRandR hot-switch, and XFixes cursor require physical X11 display session",
            0,
            hw_fp,
        )
    )

    # LIN-L3-03: VA-API Open-Source Driver Probe & Allowlist Enforcement
    va_driver = vaapi_sec.get("driver_class", "unprobed")
    va_allowed = bool(vaapi_sec.get("allowed_open_source_hw", False))
    va_codecs = vaapi_sec.get("supported_encode_codecs", [])
    if (
        mode == "strict-l3"
        and not ci_runner
        and diag_parsed
        and vaapi_sec.get("ok")
        and va_allowed
        and hw_fp_strong
        and hw_fp
    ):
        items.append(
            make_item(
                CHECKLIST[2],
                "PASS",
                f"VA-API allowlisted open-source hardware driver active (driver_class={va_driver}, codecs={va_codecs}, drm_nodes={len(render_nodes)}, fp={hw_fp})",
                diag_ms,
                hw_fp,
            )
        )
    else:
        items.append(
            make_item(
                CHECKLIST[2],
                "PENDING_PHYSICAL_L3",
                f"VA-API probe result: driver_class={va_driver}, allowed_open_source_hw={va_allowed}, strong_gpu_fp={hw_fp_strong}, drm_render_nodes={len(render_nodes)}; physical Intel iHD/i965 or AMD Mesa radeonsi GPU required for L3 PASS",
                0,
                hw_fp,
            )
        )

    # LIN-L3-04: VA-API First-IDR HardwareReady Gate
    items.append(
        make_item(
            CHECKLIST[3],
            "PENDING_PHYSICAL_L3",
            f"VA-API H.264/HEVC first-IDR HardwareReady gate requires physical Intel/AMD VA-API GPU (drm_render_nodes={len(render_nodes)})",
            0,
            hw_fp,
        )
    )

    # LIN-L3-05: VA-API 30-Frame Stability Window & Explicit Renegotiation
    items.append(
        make_item(
            CHECKLIST[4],
            "PENDING_PHYSICAL_L3",
            "VA-API mid-stream fault injection, 30-frame stability reset, and explicit VP9 renegotiation require physical Intel/AMD GPU",
            0,
            hw_fp,
        )
    )

    # LIN-L3-06: VA-API Dynamic Phase 9A QoE Bitrate / FPS / Force-IDR Control
    items.append(
        make_item(
            CHECKLIST[5],
            "PENDING_PHYSICAL_L3",
            "Live QoeEngine EncoderTarget bitrate/FPS/force-IDR tracking on VA-API requires physical Intel/AMD GPU",
            0,
            hw_fp,
        )
    )

    # LIN-L3-07: LinuxHidKeyMap Physical Key & Mouse Injection + Portal/XTest Degradation
    access_selected = (input_sec.get("access_plan") or {}).get("selected", "unknown")
    items.append(
        make_item(
            CHECKLIST[6],
            "PENDING_PHYSICAL_L3",
            f"Physical 106-key ANSI/ISO & 5-button mouse injection requires interactive desktop session (evdev_nodes={evdev_count}, selected_input_backend={access_selected})",
            0,
        )
    )

    # LIN-L3-08: Opt-In /dev/uinput Permission & High-Privilege Warning Gate
    uinput_status = input_sec.get("uinput_status")
    if diag_parsed is None:
        items.append(
            make_item(
                CHECKLIST[7],
                "FAIL",
                f"Cannot verify /dev/uinput default-off gate because zerodesk-linux-diag failed: {diag_err}",
                diag_ms,
            )
        )
    elif uinput_status != "disabled_by_default":
        items.append(
            make_item(
                CHECKLIST[7],
                "FAIL",
                f"SECURITY REGRESSION: /dev/uinput was not disabled_by_default (got {uinput_status})",
                diag_ms,
            )
        )
    else:
        items.append(
            make_item(
                CHECKLIST[7],
                "L2_NATIVE_PASS",
                f"Read-only /dev/uinput probe verified default-off invariant (uinput_exists={uinput_exists}, uinput_writable={uinput_writable}, evdev_nodes={evdev_count}, diag.uinput_status={uinput_status}; explicit --opt-in-uinput udev ACL negative & warning tests required for physical L3 PASS)",
                diag_ms,
            )
        )

    # LIN-L3-09: Independent Watchdog Parent SIGKILL Dual-Layer Release (<= 500ms)
    wd_ok = bool(wd_sec.get("ok", False))
    wd_tested = bool(wd_sec.get("tested", False))
    wd_pidfd = bool(wd_sec.get("pidfd_supported", False))
    if diag_parsed is None:
        items.append(
            make_item(
                CHECKLIST[8],
                "FAIL",
                f"Watchdog probe unavailable because zerodesk-linux-diag failed: {diag_err}",
                diag_ms,
            )
        )
    elif not (wd_tested and wd_ok and pidfd_ok and wd_pidfd and watchdog_bin_ok):
        items.append(
            make_item(
                CHECKLIST[8],
                "FAIL",
                f"Linux watchdog headless probe failed (wd_tested={wd_tested}, wd_ok={wd_ok}, diag_pidfd={wd_pidfd}, kernel_pidfd={pidfd_ok}:{pidfd_detail}, bin={watchdog_bin_detail}, err={wd_sec.get('error')})",
                diag_ms + pidfd_ms,
            )
        )
    else:
        items.append(
            make_item(
                CHECKLIST[8],
                "L2_NATIVE_PASS",
                f"Native Linux watchdog lifecycle & pidfd_open verified (wd.ok=true, pidfd_supported=true, {pidfd_detail}; {watchdog_bin_detail}; physical EV_KEY=0 + SYN_REPORT <=500ms SIGKILL torture required for physical L3 PASS)",
                diag_ms + pidfd_ms,
            )
        )

    # LIN-L3-10: Watchdog Legacy /proc/<pid>/stat Fallback & Emergency Escape Hotkey
    if not (procstat_ok and pdeath_ok):
        items.append(
            make_item(
                CHECKLIST[9],
                "FAIL",
                f"Kernel /proc/self/stat or prctl probe failed ({procstat_detail}; {pdeath_detail})",
                1,
            )
        )
    else:
        items.append(
            make_item(
                CHECKLIST[9],
                "L2_NATIVE_PASS",
                f"Native Linux /proc/self/stat field-22 & PR_SET_PDEATHSIG kernel support verified ({procstat_detail}; {pdeath_detail}; interactive Ctrl+Alt+Super+Escape physical hotkey release required for physical L3 PASS)",
                1,
            )
        )

    # LIN-L3-11: Watchdog Zero Descriptor Leak Audit (/proc/self/fd) & Fork-Race Check
    leaked_fds = wd_sec.get("leaked_fds_detected", -1)
    if diag_parsed is None:
        items.append(
            make_item(
                CHECKLIST[10],
                "FAIL",
                f"Cannot verify /proc/self/fd leak audit because zerodesk-linux-diag failed: {diag_err}",
                diag_ms,
            )
        )
    elif not (wd_tested and wd_ok and leaked_fds == 0 and pdeath_ok):
        items.append(
            make_item(
                CHECKLIST[10],
                "FAIL",
                f"Watchdog FD leak or fork-race probe failed (wd_tested={wd_tested}, wd_ok={wd_ok}, leaked_fds_detected={leaked_fds}, {pdeath_detail})",
                diag_ms,
            )
        )
    else:
        items.append(
            make_item(
                CHECKLIST[10],
                "L2_NATIVE_PASS",
                f"Post-watchdog /proc/self/fd zero-leak audit & PR_SET_PDEATHSIG verified (leaked_fds_detected=0, monitor_mode={wd_sec.get('monitor_mode')}, {pdeath_detail}; physical multi-fd inheritance torture required for physical L3 PASS)",
                diag_ms,
            )
        )

    # LIN-L3-12: zerodesk-linux-diag Real-Machine Audit & 30-Minute 1080p60 Soak
    if diag_parsed is None:
        items.append(
            make_item(
                CHECKLIST[11],
                "FAIL",
                f"zerodesk-linux-diag schema v1 JSON audit failed: {diag_err}",
                diag_ms,
            )
        )
    else:
        items.append(
            make_item(
                CHECKLIST[11],
                "PENDING_PHYSICAL_L3",
                f"zerodesk-linux-diag --json schema_v1 validated (rc={diag_rc}, session={session_kind}, watchdog.ok={wd_ok}); physical Wayland+X11 audit and 30-minute 1080p60 cross-OS soak required for L3 PASS",
                diag_ms,
                hw_fp,
            )
        )

    summary = build_summary(items)
    report = {
        "schema_version": 1,
        "mode": mode,
        "ci_runner": ci_runner,
        "platform": "linux",
        "started_at_utc": started_at_utc,
        "items": items,
        "summary": summary,
    }
    write_report_atomic(report, output_path)

    if summary["fail"] > 0:
        return 20
    if mode == "strict-l3":
        return 0 if summary["pass"] == 12 else 10
    return 0


try:
    sys.exit(main())
except Exception as exc:
    sys.stderr.write(f"FATAL: {scrub(str(exc))}\n")
    sys.exit(30)
PYEOF
