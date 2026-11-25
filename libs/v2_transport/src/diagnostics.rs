use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

pub const DIAGNOSTICS_RING_CAPACITY: usize = 300; // 5 minutes at 1 snapshot/sec

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct QoeSnapshot {
    pub ts_unix_ms: u64,
    pub rtt_ms: u32,
    pub jitter_gradient_us: i32,
    pub loss_pct: f32,
    pub effective_bw_kbps: u32,
    pub active_mode: String,
    pub standby_ready_count: u8,
    pub path_switches: u32,
    pub tcp443_fallbacks: u32,
    pub survival_mode_active: bool,
    pub encoder_name: String,
    pub fps: f32,
    pub expired_video_frames: u64,
    pub zero_rtt_dropped_frames: u64,
    pub idr_requests: u64,
    pub ltr_recoveries: u64,
}

#[derive(Debug, Clone, Default)]
pub struct DiagnosticsRing {
    snapshots: VecDeque<QoeSnapshot>,
}

impl DiagnosticsRing {
    pub fn new() -> Self {
        Self {
            snapshots: VecDeque::with_capacity(DIAGNOSTICS_RING_CAPACITY),
        }
    }

    pub fn push(&mut self, snap: QoeSnapshot) {
        if self.snapshots.len() >= DIAGNOSTICS_RING_CAPACITY {
            self.snapshots.pop_front();
        }
        self.snapshots.push_back(snap);
    }

    pub fn snapshots(&self) -> Vec<QoeSnapshot> {
        self.snapshots.iter().cloned().collect()
    }
}

/// Sanitized Phase 1 client diagnostic bundle for user-initiated export.
///
/// MUST NEVER contain private keys, session tokens, passwords, raw clipboard
/// contents, or unredacted user home paths / IPv4 last octets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DiagnosticBundle {
    pub schema_version: u32,
    pub app_name: String,
    pub protocol_version: String,
    pub hardware_backed_identity: bool,
    pub platform_os: String,
    pub detected_hw_codecs: Vec<String>,
    pub qoe_history: Vec<QoeSnapshot>,
    pub sanitized_log_tail: Vec<String>,
}

impl DiagnosticBundle {
    pub fn build_sanitized(
        hardware_backed_identity: bool,
        detected_hw_codecs: Vec<String>,
        ring: &DiagnosticsRing,
        raw_log_lines: &[String],
    ) -> Self {
        Self {
            schema_version: 1,
            app_name: "ZeroDesk".to_owned(),
            protocol_version: "v1.2-FROZEN".to_owned(),
            hardware_backed_identity,
            platform_os: std::env::consts::OS.to_owned(),
            detected_hw_codecs,
            qoe_history: ring.snapshots(),
            sanitized_log_tail: raw_log_lines
                .iter()
                .map(|line| sanitize_log_line(line))
                .collect(),
        }
    }
}

/// Strips sensitive tokens, credentials, user home paths, and last IPv4 octets.
pub fn sanitize_log_line(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for token in input.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let lower = token.to_ascii_lowercase();
        if lower.contains("password=")
            || lower.contains("token=")
            || lower.contains("secret=")
            || lower.contains("privkey=")
            || lower.contains("authorization:")
        {
            if let Some((k, _)) = token.split_once('=') {
                out.push_str(k);
                out.push_str("=[REDACTED]");
            } else {
                out.push_str("[REDACTED]");
            }
            continue;
        }
        if token.starts_with("/Users/") || token.starts_with("/home/") {
            out.push_str("[REDACTED_PATH]");
            continue;
        }
        if let Some(redacted_ip) = redact_ipv4_token(token) {
            out.push_str(&redacted_ip);
            continue;
        }
        out.push_str(token);
    }
    out
}

fn redact_ipv4_token(token: &str) -> Option<String> {
    let (host, port_part) = match token.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (token, None),
    };
    let parts: Vec<&str> = host.split('.').collect();
    if parts.len() != 4 || !parts.iter().all(|p| p.parse::<u8>().is_ok()) {
        return None;
    }
    match port_part {
        Some(p) => Some(format!("{}.{}.{}.x:{}", parts[0], parts[1], parts[2], p)),
        None => Some(format!("{}.{}.{}.x", parts[0], parts[1], parts[2])),
    }
}
