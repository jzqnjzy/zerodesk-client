// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

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

/// Strips sensitive tokens, credentials (`Authorization: Bearer ...`, JSON fields,
/// `key=value`), Unix/Windows user home paths, and last IPv4 octets (including
/// punctuation-wrapped IPs like `1.2.3.4,` or `(1.2.3.4)`).
pub fn sanitize_log_line(input: &str) -> String {
    let s1 = redact_authorization_headers(input);
    let s2 = redact_quoted_json_secrets(&s1);
    let s3 = redact_equals_secrets(&s2);
    let s4 = redact_user_paths(&s3);
    redact_ipv4_addresses(&s4)
}

fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "password"
            | "passwd"
            | "token"
            | "secret"
            | "privkey"
            | "private_key"
            | "api_key"
            | "authorization"
            | "access_token"
            | "refresh_token"
    ) || lower.ends_with("_password")
        || lower.ends_with("_token")
        || lower.ends_with("_secret")
        || lower.ends_with("_privkey")
        || lower.ends_with("_api_key")
}

fn is_value_stop(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b',' | b';' | b')' | b']' | b'}' | b'"' | b'\'' | b'&')
}

fn is_path_boundary_before(bytes: &[u8], idx: usize) -> bool {
    if idx == 0 {
        return true;
    }
    let prev = bytes[idx - 1];
    !prev.is_ascii_alphanumeric() && prev != b'_' && prev != b'/' && prev != b'\\'
}

fn is_path_stop(b: u8) -> bool {
    b.is_ascii_whitespace() || matches!(b, b',' | b';' | b')' | b']' | b'}' | b'"' | b'\'')
}

fn consume_quoted_string(bytes: &[u8], open_quote_idx: usize) -> usize {
    let quote = bytes[open_quote_idx];
    let mut i = open_quote_idx + 1;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            i += 2;
            continue;
        }
        if bytes[i] == quote {
            return i + 1;
        }
        i += 1;
    }
    bytes.len()
}

fn redact_authorization_headers(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let matches_auth = i + 13 <= bytes.len()
            && bytes[i..i + 13].eq_ignore_ascii_case(b"authorization")
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_');
        if matches_auth {
            let mut j = i + 13;
            let quoted_key = j < bytes.len() && bytes[j] == b'"';
            if quoted_key {
                j += 1;
            }
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b':' {
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if j < bytes.len() && bytes[j] == b'"' {
                    out.push_str(&input[i..j]);
                    out.push_str("\"[REDACTED]\"");
                    i = consume_quoted_string(bytes, j);
                    continue;
                }
                out.push_str(&input[i..j]);
                out.push_str("[REDACTED]");
                // Consume optional auth scheme (Bearer/Basic/Token/Digest/ApiKey) + credential value.
                let first_start = j;
                while j < bytes.len() && !is_value_stop(bytes[j]) {
                    j += 1;
                }
                let first_tok = &input[first_start..j];
                let is_scheme = first_tok.eq_ignore_ascii_case("bearer")
                    || first_tok.eq_ignore_ascii_case("basic")
                    || first_tok.eq_ignore_ascii_case("token")
                    || first_tok.eq_ignore_ascii_case("digest")
                    || first_tok.eq_ignore_ascii_case("apikey");
                if is_scheme {
                    let mut k = j;
                    while k < bytes.len() && bytes[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if k > j && k < bytes.len() && !is_value_stop(bytes[k]) {
                        while k < bytes.len() && !is_value_stop(bytes[k]) {
                            k += 1;
                        }
                        j = k;
                    }
                }
                i = j;
                continue;
            }
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn redact_quoted_json_secrets(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let key_end_excl = consume_quoted_string(bytes, i);
            if key_end_excl >= i + 2 && bytes[key_end_excl - 1] == b'"' {
                let key = &input[i + 1..key_end_excl - 1];
                if is_sensitive_key(key) {
                    let mut j = key_end_excl;
                    while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                        j += 1;
                    }
                    if j < bytes.len() && bytes[j] == b':' {
                        j += 1;
                        while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                            j += 1;
                        }
                        if j < bytes.len() && bytes[j] == b'"' {
                            out.push_str(&input[i..j]);
                            out.push_str("\"[REDACTED]\"");
                            i = consume_quoted_string(bytes, j);
                            continue;
                        } else if j < bytes.len() && !is_value_stop(bytes[j]) {
                            out.push_str(&input[i..j]);
                            out.push_str("[REDACTED]");
                            while j < bytes.len() && !is_value_stop(bytes[j]) {
                                j += 1;
                            }
                            i = j;
                            continue;
                        }
                    }
                }
            }
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn redact_equals_secrets(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_alphabetic()
            && (i == 0 || !bytes[i - 1].is_ascii_alphanumeric() && bytes[i - 1] != b'_')
        {
            let mut j = i;
            while j < bytes.len()
                && (bytes[j].is_ascii_alphanumeric() || matches!(bytes[j], b'_' | b'-' | b'.'))
            {
                j += 1;
            }
            if j < bytes.len() && bytes[j] == b'=' && is_sensitive_key(&input[i..j]) {
                out.push_str(&input[i..=j]);
                let val_start = j + 1;
                if val_start < bytes.len() && (bytes[val_start] == b'"' || bytes[val_start] == b'\'')
                {
                    let q = bytes[val_start] as char;
                    out.push(q);
                    out.push_str("[REDACTED]");
                    out.push(q);
                    i = consume_quoted_string(bytes, val_start);
                } else {
                    out.push_str("[REDACTED]");
                    let mut k = val_start;
                    while k < bytes.len() && !is_value_stop(bytes[k]) {
                        k += 1;
                    }
                    i = k;
                }
                continue;
            }
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn match_windows_user_path_prefix(bytes: &[u8], i: usize) -> bool {
    if i + 9 > bytes.len() || !bytes[i].is_ascii_alphabetic() || bytes[i + 1] != b':' {
        return false;
    }
    let after_sep1 = if bytes[i + 2] == b'\\' && i + 3 < bytes.len() && bytes[i + 3] == b'\\' {
        i + 4
    } else if bytes[i + 2] == b'\\' || bytes[i + 2] == b'/' {
        i + 3
    } else {
        return false;
    };
    if after_sep1 + 6 > bytes.len() || !bytes[after_sep1..after_sep1 + 5].eq_ignore_ascii_case(b"users")
    {
        return false;
    }
    let sep2 = after_sep1 + 5;
    bytes[sep2] == b'\\' || bytes[sep2] == b'/'
}

fn redact_user_paths(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        let is_unix_home = is_path_boundary_before(bytes, i)
            && ((i + 7 <= bytes.len() && &bytes[i..i + 7] == b"/Users/")
                || (i + 6 <= bytes.len() && &bytes[i..i + 6] == b"/home/"));
        let is_win_home = is_path_boundary_before(bytes, i) && match_windows_user_path_prefix(bytes, i);
        if is_unix_home || is_win_home {
            out.push_str("[REDACTED_PATH]");
            while i < bytes.len() && !is_path_stop(bytes[i]) {
                i += 1;
            }
            continue;
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}

fn parse_ipv4_at(bytes: &[u8], start: usize) -> Option<(usize, [u8; 3])> {
    if start > 0 && (bytes[start - 1].is_ascii_alphanumeric() || bytes[start - 1] == b'.') {
        return None;
    }
    let mut i = start;
    let mut octets = [0u8; 4];
    for (idx, slot) in octets.iter_mut().enumerate() {
        let d_start = i;
        while i < bytes.len() && bytes[i].is_ascii_digit() && i - d_start < 3 {
            i += 1;
        }
        if i == d_start {
            return None;
        }
        // Reject 4+ digit run
        if i < bytes.len() && bytes[i].is_ascii_digit() {
            return None;
        }
        let s = std::str::from_utf8(&bytes[d_start..i]).ok()?;
        *slot = s.parse::<u8>().ok()?;
        if idx < 3 {
            if i >= bytes.len() || bytes[i] != b'.' {
                return None;
            }
            i += 1;
        }
    }
    if i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'.') {
        return None;
    }
    Some((i, [octets[0], octets[1], octets[2]]))
}

fn redact_ipv4_addresses(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            if let Some((end, prefix)) = parse_ipv4_at(bytes, i) {
                out.push_str(&format!("{}.{}.{}.x", prefix[0], prefix[1], prefix[2]));
                i = end;
                continue;
            }
        }
        if let Some(ch) = input[i..].chars().next() {
            out.push(ch);
            i += ch.len_utf8();
        } else {
            break;
        }
    }
    out
}
