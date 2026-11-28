// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Platform-agnostic structured JSON schema, human-readable formatter, and
//! path-redaction validator for `zerodesk-linux-diag` diagnostics.
//!
//! Unit-tested on ALL platforms (including macOS) without any Linux `.so` dependency.

use super::{
    linux_capture_logic::{LinuxSessionKind, X11OutputDescriptor},
    linux_vaapi_logic::{VaapiCodec, VaapiDriverClass},
    linux_watchdog_logic::{LinuxInputAccessPlan, LinuxParentMonitorMode, UinputOptInStatus},
    win_diag::sanitize_diag_text,
};
use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

pub const LINUX_DIAG_SCHEMA_VERSION: u32 = 1;

pub const NON_LINUX_DIAG_NOTE: &str = "zerodesk-linux-diag requires a Linux host to probe Wayland portals/PipeWire, X11 XShm/XRandR/XTest, /dev/uinput permissions, VA-API DRM drivers, and pidfd watchdog handles";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDiagPortalSection {
    pub dbus_session_bus_present: bool,
    pub screencast_available: bool,
    pub remote_desktop_available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDiagCaptureSection {
    pub ok: bool,
    pub selected_backend: String,
    pub monitors: Vec<X11OutputDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDiagVaapiSection {
    /// `true` ONLY when an allowlisted open-source hardware driver (`iHD`, `i965`,
    /// or AMD Mesa `radeonsi`) initialized AND exposed at least one hardware encode codec.
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub render_node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vendor_string: Option<String>,
    pub driver_class: VaapiDriverClass,
    pub allowed_open_source_hw: bool,
    pub supported_encode_codecs: Vec<VaapiCodec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDiagInputSection {
    pub access_plan: LinuxInputAccessPlan,
    pub uinput_status: UinputOptInStatus,
    pub warnings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDiagWatchdogSection {
    pub tested: bool,
    pub ok: bool,
    pub pidfd_supported: bool,
    pub monitor_mode: LinuxParentMonitorMode,
    pub leaked_fds_detected: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Top-level path-redacted diagnostic report emitted by `zerodesk-linux-diag`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxDiagReport {
    pub schema_version: u32,
    pub host_os: String,
    pub linux_host_required: bool,
    pub session_kind: LinuxSessionKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portal: Option<LinuxDiagPortalSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capture: Option<LinuxDiagCaptureSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vaapi: Option<LinuxDiagVaapiSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<LinuxDiagInputSection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub watchdog: Option<LinuxDiagWatchdogSection>,
}

impl LinuxDiagReport {
    pub fn non_linux_stub() -> Self {
        Self {
            schema_version: LINUX_DIAG_SCHEMA_VERSION,
            host_os: std::env::consts::OS.to_string(),
            linux_host_required: true,
            session_kind: LinuxSessionKind::Headless,
            note: Some(NON_LINUX_DIAG_NOTE.into()),
            portal: None,
            capture: None,
            vaapi: None,
            input: None,
            watchdog: None,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != LINUX_DIAG_SCHEMA_VERSION {
            return Err(format!(
                "unsupported linux_diag schema_version {} (expected {LINUX_DIAG_SCHEMA_VERSION})",
                self.schema_version
            ));
        }
        if self.host_os.trim().is_empty() {
            return Err("host_os must be non-empty".into());
        }
        if self.linux_host_required {
            if self.portal.is_some()
                || self.capture.is_some()
                || self.vaapi.is_some()
                || self.input.is_some()
                || self.watchdog.is_some()
            {
                return Err(
                    "non-Linux stub report must not populate Linux runtime probe sections".into(),
                );
            }
        } else {
            if self.portal.is_none()
                || self.capture.is_none()
                || self.vaapi.is_none()
                || self.input.is_none()
                || self.watchdog.is_none()
            {
                return Err("Linux diagnostic report must populate all 5 probe sections".into());
            }
            if let Some(vaapi) = &self.vaapi {
                if vaapi.ok && (!vaapi.allowed_open_source_hw || vaapi.supported_encode_codecs.is_empty()) {
                    return Err(
                        "vaapi.ok must only be true when an allowlisted open-source HW driver exposes >= 1 encode codec"
                            .into(),
                    );
                }
            }
        }

        let serialized =
            serde_json::to_string(self).map_err(|e| format!("serialize failed: {e}"))?;
        let lower = serialized.to_ascii_lowercase();
        if lower.contains("/home/") || lower.contains("/users/") || lower.contains("c:\\\\users\\\\")
        {
            return Err("unredacted local user home path detected in LinuxDiagReport".into());
        }
        Ok(())
    }

    pub fn all_sections_ok(&self) -> bool {
        if self.linux_host_required {
            return true;
        }
        let cap_ok = self.capture.as_ref().is_some_and(|s| s.ok);
        let vaapi_ok = self.vaapi.as_ref().is_some_and(|s| s.ok);
        let input_ok = self
            .input
            .as_ref()
            .is_some_and(|s| s.access_plan.permitted);
        let wd_ok = self
            .watchdog
            .as_ref()
            .is_some_and(|s| !s.tested || s.ok);
        cap_ok && vaapi_ok && input_ok && wd_ok
    }

    /// Formats a concise, human-readable diagnostic summary without leaking local paths.
    pub fn format_human_summary(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "ZeroDesk Linux Diagnostics (schema v{}, host_os={}, session={})",
            self.schema_version,
            self.host_os,
            self.session_kind.as_str()
        );
        if self.linux_host_required {
            if let Some(note) = &self.note {
                let _ = writeln!(out, "Status  : non-Linux host ({})", sanitize_diag_text(note));
            }
            return out;
        }
        if let Some(p) = &self.portal {
            let _ = writeln!(
                out,
                "Portal  : dbus={}, screencast={}, remote_desktop={}",
                p.dbus_session_bus_present, p.screencast_available, p.remote_desktop_available
            );
        }
        if let Some(c) = &self.capture {
            let _ = writeln!(
                out,
                "Capture : ok={}, backend={}, monitors={}",
                c.ok,
                c.selected_backend,
                c.monitors.len()
            );
        }
        if let Some(v) = &self.vaapi {
            let _ = writeln!(
                out,
                "VA-API  : ok={}, driver={} (allowed_open_source_hw={}), codecs={:?}",
                v.ok,
                v.driver_class.as_str(),
                v.allowed_open_source_hw,
                v.supported_encode_codecs
            );
        }
        if let Some(i) = &self.input {
            let _ = writeln!(
                out,
                "Input   : permitted={}, selected={:?}, uinput={:?}",
                i.access_plan.permitted, i.access_plan.selected, i.uinput_status
            );
            for w in &i.warnings {
                let _ = writeln!(out, "  WARN  : {}", sanitize_diag_text(w));
            }
        }
        if let Some(w) = &self.watchdog {
            let _ = writeln!(
                out,
                "Watchdog: ok={}, tested={}, pidfd={}, mode={:?}, leaked_fds={}",
                w.ok, w.tested, w.pidfd_supported, w.monitor_mode, w.leaked_fds_detected
            );
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::os::linux_watchdog_logic::{
        resolve_linux_input_access_plan, LinuxInputCapabilities,
    };

    #[test]
    fn non_linux_stub_validates_and_formats_summary() {
        let stub = LinuxDiagReport::non_linux_stub();
        stub.validate().unwrap();
        assert!(stub.all_sections_ok());
        let json = serde_json::to_string_pretty(&stub).unwrap();
        let parsed: LinuxDiagReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, stub);
        let summary = stub.format_human_summary();
        assert!(summary.contains("ZeroDesk Linux Diagnostics"));
        assert!(summary.contains("non-Linux host"));
    }

    #[test]
    fn full_linux_diag_report_validates_open_source_vaapi_gate_and_redaction() {
        let caps = LinuxInputCapabilities {
            session_kind: LinuxSessionKind::Wayland,
            portal_remote_desktop_available: true,
            xtest_available: false,
            uinput_explicit_opt_in: false,
            uinput_writable: false,
            uinput_device_path: "/dev/uinput".into(),
        };
        let plan = resolve_linux_input_access_plan(&caps);

        let mut report = LinuxDiagReport {
            schema_version: LINUX_DIAG_SCHEMA_VERSION,
            host_os: "linux".into(),
            linux_host_required: false,
            session_kind: LinuxSessionKind::Wayland,
            note: None,
            portal: Some(LinuxDiagPortalSection {
                dbus_session_bus_present: true,
                screencast_available: true,
                remote_desktop_available: true,
                error: None,
            }),
            capture: Some(LinuxDiagCaptureSection {
                ok: true,
                selected_backend: "wayland_portal_pipewire".into(),
                monitors: Vec::new(),
                error: None,
            }),
            vaapi: Some(LinuxDiagVaapiSection {
                ok: true,
                render_node: Some("/dev/dri/renderD128".into()),
                vendor_string: Some("Intel iHD driver - 24.1.0".into()),
                driver_class: VaapiDriverClass::IntelIhd,
                allowed_open_source_hw: true,
                supported_encode_codecs: vec![VaapiCodec::H264, VaapiCodec::Hevc],
                error: None,
            }),
            input: Some(LinuxDiagInputSection {
                uinput_status: plan.uinput_status.clone(),
                warnings: plan.warnings.clone(),
                access_plan: plan,
                error: None,
            }),
            watchdog: Some(LinuxDiagWatchdogSection {
                tested: true,
                ok: true,
                pidfd_supported: true,
                monitor_mode: LinuxParentMonitorMode::PidFd,
                leaked_fds_detected: 0,
                error: None,
            }),
        };

        report.validate().unwrap();
        assert!(report.all_sections_ok());
        let summary = report.format_human_summary();
        assert!(summary.contains("intel_ihd"));
        assert!(summary.contains("wayland_portal_pipewire"));

        // Reject VA-API claiming ok=true with disallowed software rasterizer.
        report.vaapi.as_mut().unwrap().allowed_open_source_hw = false;
        report.vaapi.as_mut().unwrap().driver_class = VaapiDriverClass::RejectedSoftwareRasterizer;
        assert!(report.validate().is_err());

        // Reject unredacted /home/<user>/ path.
        report.vaapi.as_mut().unwrap().allowed_open_source_hw = true;
        report.vaapi.as_mut().unwrap().driver_class = VaapiDriverClass::IntelIhd;
        report.capture.as_mut().unwrap().error = Some("failed reading /home/alice/cfg".into());
        assert!(report.validate().is_err());
    }
}
