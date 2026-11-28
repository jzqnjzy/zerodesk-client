// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `zerodesk-linux-diag` — Built-in non-destructive Linux platform diagnostic CLI.
//!
//! Outputs a versioned (`schema_version: 1`) path-redacted JSON report (`--json`,
//! default) or human-readable summary (`--summary`) covering:
//! 1. Active session kind (`wayland` / `x11` / `headless`),
//! 2. `xdg-desktop-portal` ScreenCast & RemoteDesktop availability,
//! 3. Capture backend selection & XRandR monitor topology,
//! 4. VA-API DRM render node + open-source driver allowlist (`iHD`/`i965`/`radeonsi`),
//! 5. Input 3-tier degradation chain + `/dev/uinput` opt-in & permission status,
//! 6. Watchdog `pidfd_open` vs `/proc/<pid>/stat` capability & `/proc/self/fd` audit.
//!
//! On non-Linux hosts (macOS / Windows), emits a clean static non-Linux stub
//! without linking `zerodesk_core` or platform screen-capture libraries.

use std::{
    io::{self, Write},
    process::ExitCode,
};

#[cfg(not(target_os = "linux"))]
const STUB_NOTE: &str = "zerodesk-linux-diag requires a Linux host to probe Wayland portals/PipeWire, X11 XShm/XRandR/XTest, /dev/uinput permissions, VA-API DRM drivers, and pidfd watchdog handles";

#[cfg(target_os = "linux")]
fn run_linux_diagnostics(
    skip_watchdog: bool,
    opt_in_uinput: bool,
) -> zerodesk_core::os::linux_diag::LinuxDiagReport {
    use zerodesk_core::os::{
        linux_capture::{
            current_linux_session_kind, enumerate_x11_monitors, probe_portal_availability,
        },
        linux_capture_logic::LinuxSessionKind,
        linux_diag::{
            LinuxDiagCaptureSection, LinuxDiagInputSection, LinuxDiagPortalSection,
            LinuxDiagReport, LinuxDiagVaapiSection, LinuxDiagWatchdogSection,
            LINUX_DIAG_SCHEMA_VERSION,
        },
        linux_input::probe_linux_input_capabilities,
        linux_vaapi::probe_vaapi_device,
        linux_vaapi_logic::VaapiDriverClass,
        linux_watchdog::{
            count_unexpected_open_fds, probe_pidfd_supported, read_proc_stat_identity,
            LinuxHidWatchdogBackend,
        },
        linux_watchdog_logic::{resolve_linux_input_access_plan, LinuxParentMonitorMode},
        traits::HidWatchdogBackend,
        watchdog_supervisor::HidWatchdogConfig,
        win_diag::sanitize_diag_text,
    };

    let session_kind = current_linux_session_kind();

    // 1. Portal probe
    let (dbus_ok, sc_ok, rd_ok, portal_err) = probe_portal_availability();
    let portal = LinuxDiagPortalSection {
        dbus_session_bus_present: dbus_ok,
        screencast_available: sc_ok,
        remote_desktop_available: rd_ok,
        error: portal_err.map(|e| sanitize_diag_text(&e)),
    };

    // 2. Capture probe
    let capture = match session_kind {
        LinuxSessionKind::Wayland => LinuxDiagCaptureSection {
            ok: sc_ok,
            selected_backend: "wayland_portal_pipewire".into(),
            monitors: Vec::new(),
            error: if sc_ok {
                None
            } else {
                Some("Wayland portal ScreenCast or libpipewire-0.3.so.0 unavailable".into())
            },
        },
        LinuxSessionKind::X11 => match enumerate_x11_monitors() {
            Ok(monitors) => LinuxDiagCaptureSection {
                ok: !monitors.is_empty(),
                selected_backend: "x11_xshm_xrandr_xfixes".into(),
                monitors,
                error: None,
            },
            Err(e) => LinuxDiagCaptureSection {
                ok: false,
                selected_backend: "x11_xshm_xrandr_xfixes".into(),
                monitors: Vec::new(),
                error: Some(sanitize_diag_text(&e.to_string())),
            },
        },
        LinuxSessionKind::Headless => LinuxDiagCaptureSection {
            ok: false,
            selected_backend: "none_headless".into(),
            monitors: Vec::new(),
            error: Some("headless Linux session has no Wayland or X11 display".into()),
        },
    };

    // 3. VA-API open-source hardware driver probe
    let vaapi = match probe_vaapi_device() {
        Ok(res) => {
            let allowed = res.driver_class.is_allowed_open_source_hw();
            let ok = allowed && !res.supported_encode_codecs.is_empty();
            let error = if ok {
                None
            } else if !allowed {
                Some(format!(
                    "VA-API driver rejected by open-source hardware allowlist ({})",
                    res.driver_class.as_str()
                ))
            } else {
                Some("VA-API open-source driver exposes no supported H.264/HEVC encode entrypoint".into())
            };
            LinuxDiagVaapiSection {
                ok,
                render_node: Some(res.render_node),
                vendor_string: Some(sanitize_diag_text(&res.vendor_string)),
                driver_class: res.driver_class,
                allowed_open_source_hw: allowed,
                supported_encode_codecs: res.supported_encode_codecs,
                error,
            }
        }
        Err(e) => LinuxDiagVaapiSection {
            ok: false,
            render_node: None,
            vendor_string: None,
            driver_class: VaapiDriverClass::RejectedProprietaryOrUnknown,
            allowed_open_source_hw: false,
            supported_encode_codecs: Vec::new(),
            error: Some(sanitize_diag_text(&e.to_string())),
        },
    };

    // 4. Input 3-tier access chain + /dev/uinput status
    let caps = probe_linux_input_capabilities(opt_in_uinput);
    let plan = resolve_linux_input_access_plan(&caps);
    let input = LinuxDiagInputSection {
        uinput_status: plan.uinput_status.clone(),
        warnings: plan.warnings.iter().map(|w| sanitize_diag_text(w)).collect(),
        access_plan: plan,
        error: None,
    };

    // 5. Watchdog pidfd + /proc/self/fd + optional spawn self-test
    let pidfd_supported = probe_pidfd_supported();
    let monitor_mode = if pidfd_supported {
        LinuxParentMonitorMode::PidFd
    } else {
        let my_pid = std::process::id();
        let start_ticks = read_proc_stat_identity(my_pid)
            .map(|id| id.start_time_ticks)
            .unwrap_or(0);
        LinuxParentMonitorMode::FallbackLegacyProcStat {
            parent_pid: my_pid,
            start_time_ticks: start_ticks,
        }
    };
    let leaked_fds_detected = count_unexpected_open_fds(&[0, 1, 2]);
    let watchdog = if skip_watchdog {
        LinuxDiagWatchdogSection {
            tested: false,
            ok: true,
            pidfd_supported,
            monitor_mode,
            leaked_fds_detected,
            error: Some("skipped via --skip-watchdog".into()),
        }
    } else {
        let mut backend = LinuxHidWatchdogBackend::new();
        let cfg = HidWatchdogConfig {
            real_os_input: false,
            ..HidWatchdogConfig::default()
        };
        match backend.spawn(cfg) {
            Ok(_) => {
                let hb_ok = backend.heartbeat().is_ok();
                let _ = backend.shutdown(None);
                LinuxDiagWatchdogSection {
                    tested: true,
                    ok: hb_ok,
                    pidfd_supported,
                    monitor_mode,
                    leaked_fds_detected,
                    error: if hb_ok {
                        None
                    } else {
                        Some("Linux watchdog heartbeat check failed".into())
                    },
                }
            }
            Err(e) => LinuxDiagWatchdogSection {
                tested: true,
                ok: false,
                pidfd_supported,
                monitor_mode,
                leaked_fds_detected,
                error: Some(sanitize_diag_text(&e.to_string())),
            },
        }
    };

    LinuxDiagReport {
        schema_version: LINUX_DIAG_SCHEMA_VERSION,
        host_os: std::env::consts::OS.to_string(),
        linux_host_required: false,
        session_kind,
        note: None,
        portal: Some(portal),
        capture: Some(capture),
        vaapi: Some(vaapi),
        input: Some(input),
        watchdog: Some(watchdog),
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let human_summary = args.iter().any(|a| a == "--summary" || a == "--human");
    let _json_flag = args.iter().any(|a| a == "--json");

    #[cfg(target_os = "linux")]
    {
        let skip_watchdog = args.iter().any(|a| a == "--skip-watchdog");
        let opt_in_uinput = args.iter().any(|a| a == "--opt-in-uinput");
        let report = run_linux_diagnostics(skip_watchdog, opt_in_uinput);
        let all_ok = report.all_sections_ok();
        let rendered = if human_summary {
            Ok(report.format_human_summary())
        } else {
            serde_json::to_string_pretty(&report)
        };
        match rendered {
            Ok(text) => {
                let mut out = io::stdout().lock();
                if writeln!(out, "{text}").is_ok() && all_ok {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::FAILURE
                }
            }
            Err(_) => ExitCode::FAILURE,
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let mut out = io::stdout().lock();
        let res = if human_summary {
            writeln!(
                out,
                "ZeroDesk Linux Diagnostics (schema v1, host_os={}, session=headless)\nStatus  : non-Linux host ({STUB_NOTE})",
                std::env::consts::OS
            )
        } else {
            writeln!(
                out,
                "{{\n  \"schema_version\": 1,\n  \"host_os\": \"{}\",\n  \"linux_host_required\": true,\n  \"session_kind\": \"headless\",\n  \"note\": \"{STUB_NOTE}\"\n}}",
                std::env::consts::OS
            )
        };
        if res.is_ok() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        }
    }
}
