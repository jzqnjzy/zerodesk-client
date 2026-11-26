// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{
    input::{HID_WATCHDOG_MAX_MS, HID_WATCHDOG_MIN_MS},
    video::VideoCodec,
};
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    fs::{self, DirBuilder, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};
use v2_client::{is_loopback_host, resolve_signaling_tls, ClusterConfig, EdgeEndpointConfig};

pub const DEFAULT_WATCHDOG_TIMEOUT_MS: u64 = 3_000;
pub const DEFAULT_KEEPALIVE_INTERVAL_MS: u64 = 500;
pub const DEFAULT_LEASE_RENEW_INTERVAL_SEC: u64 = 15;
pub const MAX_LEASE_RENEW_INTERVAL_SEC: u64 = 15;
pub const DEFAULT_FPS: u32 = 30;
pub const DEFAULT_BW_CAP_KBPS: u32 = 50_000;
pub const DEFAULT_UDP_PROBE_TIMEOUT_MS: u64 = 1_500;
pub const MIN_UDP_PROBE_TIMEOUT_MS: u64 = 100;
pub const MAX_UDP_PROBE_TIMEOUT_MS: u64 = 10_000;

/// Access data-plane transport selection policy (`Auto` [default], `UdpOnly`, `Tls443Only`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportMode {
    #[default]
    Auto,
    UdpOnly,
    Tls443Only,
}

impl TransportMode {
    pub fn parse_name(s: &str) -> Result<Self, V2ConfigError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Ok(Self::Auto),
            "udp" | "udp_only" | "udponly" => Ok(Self::UdpOnly),
            "tls443" | "tls443_only" | "tls443only" | "dual_tls443" => Ok(Self::Tls443Only),
            other => Err(V2ConfigError::InvalidValue(format!(
                "invalid transport mode '{other}' (expected auto|udp|tls443)"
            ))),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::UdpOnly => "udp_only",
            Self::Tls443Only => "tls443_only",
        }
    }
}

pub const IDENTITY_FILE_NAME: &str = "identity_v2.json";
pub const DELEGATION_FILE_NAME: &str = "delegation_v2.json";

static ATOMIC_FILE_NONCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum V2ConfigError {
    InvalidValue(String),
    InsecurePermissions(String),
    Io(String),
}

impl fmt::Display for V2ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidValue(msg) => write!(f, "invalid V2 client config: {msg}"),
            Self::InsecurePermissions(msg) => {
                write!(f, "insecure key/directory permissions (fail-closed): {msg}")
            }
            Self::Io(msg) => write!(f, "V2 config I/O error: {msg}"),
        }
    }
}

impl std::error::Error for V2ConfigError {}

/// Production ZeroDesk V2 client configuration shared by Host Daemon and Controller Client.
#[derive(Clone)]
pub struct V2ClientConfig {
    pub control_plane_endpoint: String,
    pub signaling_addr: String,
    /// Optional TLS override for `v2-signaling`:
    /// - `None`: auto (TLS 1.3 on non-loopback, plaintext allowed on loopback)
    /// - `Some(true)`: always require TLS 1.3
    /// - `Some(false)`: loopback plaintext only (non-loopback fails closed)
    pub signaling_tls: Option<bool>,
    pub edge_a: EdgeEndpointConfig,
    pub edge_b: EdgeEndpointConfig,
    pub enrollment_token: Option<String>,
    pub ca_der_path: Option<PathBuf>,
    pub identity_dir: PathBuf,
    pub home_region: String,
    pub codec: VideoCodec,
    pub fps: u32,
    pub watchdog_timeout_ms: u64,
    pub keepalive_interval_ms: u64,
    pub lease_renew_interval_sec: u64,
    pub bw_cap_kbps: u32,
    pub transport_mode: TransportMode,
    pub udp_probe_timeout_ms: u64,
    /// Test/E2E hook simulating a local firewall blocking UDP (`--drop-udp`) so `Auto`
    /// exercises the real UDP probe failure -> Dual TLS-443 fallback path.
    pub drop_udp_for_test: bool,
}

impl fmt::Debug for V2ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("V2ClientConfig")
            .field("control_plane_endpoint", &self.control_plane_endpoint)
            .field("signaling_addr", &self.signaling_addr)
            .field("signaling_tls", &self.signaling_tls)
            .field("edge_a", &self.edge_a)
            .field("edge_b", &self.edge_b)
            .field(
                "enrollment_token",
                &self.enrollment_token.as_ref().map(|_| "<redacted>"),
            )
            .field("ca_der_path", &self.ca_der_path)
            .field("identity_dir", &self.identity_dir)
            .field("home_region", &self.home_region)
            .field("codec", &self.codec)
            .field("fps", &self.fps)
            .field("watchdog_timeout_ms", &self.watchdog_timeout_ms)
            .field("keepalive_interval_ms", &self.keepalive_interval_ms)
            .field("lease_renew_interval_sec", &self.lease_renew_interval_sec)
            .field("bw_cap_kbps", &self.bw_cap_kbps)
            .field("transport_mode", &self.transport_mode)
            .field("udp_probe_timeout_ms", &self.udp_probe_timeout_ms)
            .field("drop_udp_for_test", &self.drop_udp_for_test)
            .finish()
    }
}

fn extract_url_host(url: &str) -> Result<String, V2ConfigError> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .ok_or_else(|| {
            V2ConfigError::InvalidValue(format!(
                "control_plane_endpoint must start with http:// or https://, got '{url}'"
            ))
        })?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(V2ConfigError::InvalidValue(format!(
            "invalid control_plane_endpoint authority in '{url}'"
        )));
    }
    if let Some(ipv6_rest) = authority.strip_prefix('[') {
        let Some((host, after_bracket)) = ipv6_rest.split_once(']') else {
            return Err(V2ConfigError::InvalidValue(format!(
                "unterminated IPv6 literal in control_plane_endpoint '{url}'"
            )));
        };
        if host.is_empty() {
            return Err(V2ConfigError::InvalidValue(format!(
                "empty IPv6 host in control_plane_endpoint '{url}'"
            )));
        }
        if let Some(port_part) = after_bracket.strip_prefix(':') {
            if port_part.parse::<u16>().is_err() {
                return Err(V2ConfigError::InvalidValue(format!(
                    "invalid port in control_plane_endpoint '{url}'"
                )));
            }
        } else if !after_bracket.is_empty() {
            return Err(V2ConfigError::InvalidValue(format!(
                "invalid authority suffix in control_plane_endpoint '{url}'"
            )));
        }
        return Ok(host.to_string());
    }
    let host = match authority.rsplit_once(':') {
        Some((h, port_part)) => {
            if h.contains(':') || port_part.parse::<u16>().is_err() {
                return Err(V2ConfigError::InvalidValue(format!(
                    "invalid host/port in control_plane_endpoint '{url}'"
                )));
            }
            h
        }
        None => authority,
    };
    if host.is_empty() {
        return Err(V2ConfigError::InvalidValue(format!(
            "empty host in control_plane_endpoint '{url}'"
        )));
    }
    Ok(host.to_string())
}

impl V2ClientConfig {
    pub fn from_cluster_config(
        cfg: &ClusterConfig,
        identity_dir: PathBuf,
        ca_der_override: Option<PathBuf>,
        enrollment_token: Option<String>,
    ) -> Self {
        let ca_der_path = ca_der_override.or_else(|| {
            cfg.ca_der_path
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from)
        });
        Self {
            control_plane_endpoint: cfg.cp_base_url(),
            signaling_addr: cfg.signaling_addr.clone(),
            signaling_tls: cfg.signaling_tls,
            edge_a: cfg.edge_a.clone(),
            edge_b: cfg.edge_b.clone(),
            enrollment_token,
            ca_der_path,
            identity_dir,
            home_region: "local".to_string(),
            codec: VideoCodec::Vp9,
            fps: DEFAULT_FPS,
            watchdog_timeout_ms: DEFAULT_WATCHDOG_TIMEOUT_MS,
            keepalive_interval_ms: DEFAULT_KEEPALIVE_INTERVAL_MS,
            lease_renew_interval_sec: DEFAULT_LEASE_RENEW_INTERVAL_SEC,
            bw_cap_kbps: DEFAULT_BW_CAP_KBPS,
            transport_mode: TransportMode::Auto,
            udp_probe_timeout_ms: DEFAULT_UDP_PROBE_TIMEOUT_MS,
            drop_udp_for_test: false,
        }
    }

    /// Resolves the edge endpoint matching an 8-byte `pop_id`.
    pub fn edge_for_pop(&self, pop_id: &[u8; 8]) -> Option<&EdgeEndpointConfig> {
        if self.edge_a.pop_id.as_bytes() == pop_id {
            Some(&self.edge_a)
        } else if self.edge_b.pop_id.as_bytes() == pop_id {
            Some(&self.edge_b)
        } else {
            None
        }
    }

    /// Fail-closed validation enforcing `spec/04` §6.2.4, `spec/06` §1.2.1, loopback-only plaintext
    /// HTTP, and strict Unix key directory (`0700`) / key file (`0600`) ownership & permissions.
    pub fn validate(&self) -> Result<(), V2ConfigError> {
        let cp_host = extract_url_host(&self.control_plane_endpoint)?;
        if self.control_plane_endpoint.starts_with("http://") && !is_loopback_host(&cp_host) {
            return Err(V2ConfigError::InvalidValue(format!(
                "plaintext http:// control_plane_endpoint is forbidden on non-loopback host '{cp_host}'; https:// is mandatory"
            )));
        }
        if self.signaling_addr.is_empty() {
            return Err(V2ConfigError::InvalidValue(
                "signaling_addr must not be empty".into(),
            ));
        }
        resolve_signaling_tls(&self.signaling_addr, self.signaling_tls)
            .map_err(|e| V2ConfigError::InvalidValue(format!("signaling TLS policy invalid: {e}")))?;
        let pop_a = self
            .edge_a
            .pop_id_bytes()
            .and_then(|p| self.edge_a.x25519_pub().map(|_| p))
            .map_err(|e| V2ConfigError::InvalidValue(format!("edge_a invalid: {e}")))?;
        let pop_b = self
            .edge_b
            .pop_id_bytes()
            .and_then(|p| self.edge_b.x25519_pub().map(|_| p))
            .map_err(|e| V2ConfigError::InvalidValue(format!("edge_b invalid: {e}")))?;
        if pop_a == pop_b {
            return Err(V2ConfigError::InvalidValue(format!(
                "edge_a.pop_id and edge_b.pop_id must be distinct, both are '{}'",
                self.edge_a.pop_id
            )));
        }

        if !(HID_WATCHDOG_MIN_MS..=HID_WATCHDOG_MAX_MS).contains(&self.watchdog_timeout_ms) {
            return Err(V2ConfigError::InvalidValue(format!(
                "watchdog_timeout_ms={} out of normative range {}..={}",
                self.watchdog_timeout_ms, HID_WATCHDOG_MIN_MS, HID_WATCHDOG_MAX_MS
            )));
        }
        if self.keepalive_interval_ms == 0 {
            return Err(V2ConfigError::InvalidValue(
                "keepalive_interval_ms must be > 0".into(),
            ));
        }
        let min_watchdog = self.keepalive_interval_ms.saturating_mul(2);
        if self.watchdog_timeout_ms < min_watchdog {
            return Err(V2ConfigError::InvalidValue(format!(
                "watchdog_timeout_ms={} must be >= 2 * keepalive_interval_ms ({})",
                self.watchdog_timeout_ms, min_watchdog
            )));
        }
        if self.lease_renew_interval_sec == 0
            || self.lease_renew_interval_sec > MAX_LEASE_RENEW_INTERVAL_SEC
        {
            return Err(V2ConfigError::InvalidValue(format!(
                "lease_renew_interval_sec={} out of spec/06 conservative range 1..={}",
                self.lease_renew_interval_sec, MAX_LEASE_RENEW_INTERVAL_SEC
            )));
        }
        if self.fps == 0 || self.fps > 240 {
            return Err(V2ConfigError::InvalidValue(format!(
                "fps={} must be in 1..=240",
                self.fps
            )));
        }
        if self.bw_cap_kbps == 0 {
            return Err(V2ConfigError::InvalidValue(
                "bw_cap_kbps must be > 0".into(),
            ));
        }
        if !(MIN_UDP_PROBE_TIMEOUT_MS..=MAX_UDP_PROBE_TIMEOUT_MS)
            .contains(&self.udp_probe_timeout_ms)
        {
            return Err(V2ConfigError::InvalidValue(format!(
                "udp_probe_timeout_ms={} must be in {}..={}",
                self.udp_probe_timeout_ms, MIN_UDP_PROBE_TIMEOUT_MS, MAX_UDP_PROBE_TIMEOUT_MS
            )));
        }
        if self.identity_dir.as_os_str().is_empty() {
            return Err(V2ConfigError::InvalidValue(
                "identity_dir must not be empty".into(),
            ));
        }

        if self.identity_dir.exists() {
            verify_dir_permissions_0700(&self.identity_dir)?;
            for fname in [IDENTITY_FILE_NAME, DELEGATION_FILE_NAME] {
                let p = self.identity_dir.join(fname);
                if p.exists() {
                    verify_file_permissions_0600(&p)?;
                }
            }
        }
        Ok(())
    }
}

/// Ensures `dir` exists and is strictly `0700` on Unix. Fails closed if an existing directory
/// has group/other permissions (`mode & 0o077 != 0`).
pub fn ensure_dir_0700(dir: &Path) -> Result<(), V2ConfigError> {
    if dir.as_os_str().is_empty() {
        return Ok(());
    }
    if dir.exists() {
        verify_dir_permissions_0700(dir)?;
        return Ok(());
    }
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| V2ConfigError::Io(format!("create directory '{}': {e}", dir.display())))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| {
            V2ConfigError::Io(format!("chmod 0700 '{}': {e}", dir.display()))
        })?;
    }
    verify_dir_permissions_0700(dir)
}

/// Verifies on Unix that `dir` is a regular directory (not a symlink) owned by `geteuid()`
/// with strict `0700` permissions (no group/other bits).
pub fn verify_dir_permissions_0700(dir: &Path) -> Result<(), V2ConfigError> {
    let meta = fs::symlink_metadata(dir)
        .map_err(|e| V2ConfigError::Io(format!("stat '{}': {e}", dir.display())))?;
    if meta.file_type().is_symlink() || !meta.is_dir() {
        return Err(V2ConfigError::InsecurePermissions(format!(
            "'{}' must be a regular directory (not a symlink)",
            dir.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let expected_uid = unsafe { libc::geteuid() };
        if meta.uid() != expected_uid {
            return Err(V2ConfigError::InsecurePermissions(format!(
                "directory '{}' is owned by uid {}, expected effective uid {expected_uid}",
                dir.display(),
                meta.uid()
            )));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o700 {
            return Err(V2ConfigError::InsecurePermissions(format!(
                "directory '{}' has mode {mode:#05o}, expected strict 0700",
                dir.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        // Phase 4A targets Unix (macOS/Linux); Windows DACL enforcement (e.g., SetNamedSecurityInfoW
        // restricting ownership & access to the current user SID) is required before Windows
        // production release.
        let _ = dir;
    }
    Ok(())
}

/// Verifies on Unix that `path` is a regular file (not a symlink) owned by `geteuid()` with
/// strict `0600` permissions.
pub fn verify_file_permissions_0600(path: &Path) -> Result<(), V2ConfigError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|e| V2ConfigError::Io(format!("stat '{}': {e}", path.display())))?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(V2ConfigError::InsecurePermissions(format!(
            "'{}' must be a regular file (not a symlink)",
            path.display()
        )));
    }
    verify_file_meta_0600(&meta, path)
}

fn verify_file_meta_0600(meta: &fs::Metadata, path: &Path) -> Result<(), V2ConfigError> {
    if !meta.is_file() {
        return Err(V2ConfigError::InsecurePermissions(format!(
            "'{}' must be a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let expected_uid = unsafe { libc::geteuid() };
        if meta.uid() != expected_uid {
            return Err(V2ConfigError::InsecurePermissions(format!(
                "private key/state file '{}' is owned by uid {}, expected effective uid {expected_uid}",
                path.display(),
                meta.uid()
            )));
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 {
            return Err(V2ConfigError::InsecurePermissions(format!(
                "private key/state file '{}' has mode {mode:#05o}, expected strict 0600",
                path.display()
            )));
        }
    }
    #[cfg(not(unix))]
    {
        // Phase 4A targets Unix (macOS/Linux); Windows DACL enforcement is required before
        // Windows production release.
        let _ = path;
    }
    Ok(())
}

/// Opens `path` with `O_NOFOLLOW` on Unix, verifies `f.metadata()` (regular file, `0600`,
/// `uid == geteuid()`), and reads directly from the verified open file descriptor (zero TOCTOU).
pub fn read_file_0600_to_string(path: &Path) -> Result<String, V2ConfigError> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = opts
        .open(path)
        .map_err(|e| V2ConfigError::Io(format!("open '{}': {e}", path.display())))?;
    let meta = file
        .metadata()
        .map_err(|e| V2ConfigError::Io(format!("fstat '{}': {e}", path.display())))?;
    verify_file_meta_0600(&meta, path)?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| V2ConfigError::Io(format!("read '{}': {e}", path.display())))?;
    Ok(content)
}

/// Calls `fsync` on the parent directory of `path` after an atomic `rename` or `create_new` so
/// directory entries (e.g., `delegation_seq` updates) survive power loss on Unix.
pub(crate) fn sync_parent_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let parent = path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let dir = File::open(parent)?;
        dir.sync_all()?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        // Phase 4A targets Unix (macOS/Linux); Windows directory metadata durability uses
        // filesystem-specific semantics outside POSIX dir fsync.
        let _ = path;
        Ok(())
    }
}

/// Atomically creates a brand-new `0600` file (`O_CREAT | O_EXCL | O_NOFOLLOW` on Unix),
/// sets permissions on the open handle, calls `sync_all()` on the file and parent directory,
/// and fails with `io::ErrorKind::AlreadyExists` if the file already exists.
pub(crate) fn write_file_create_new_0600(path: &Path, bytes: &[u8]) -> Result<(), V2ConfigError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir_0700(parent)?;
        }
    }
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let mut f = opts
        .open(path)
        .map_err(|e| V2ConfigError::Io(format!("create_new '{}': {e}", path.display())))?;
    let write_res = (|| -> Result<(), V2ConfigError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| V2ConfigError::Io(format!("fchmod 0600 '{}': {e}", path.display())))?;
        }
        f.write_all(bytes)
            .map_err(|e| V2ConfigError::Io(format!("write '{}': {e}", path.display())))?;
        f.sync_all()
            .map_err(|e| V2ConfigError::Io(format!("sync '{}': {e}", path.display())))?;
        drop(f);
        sync_parent_dir(path)
            .map_err(|e| V2ConfigError::Io(format!("fsync parent dir '{}': {e}", path.display())))?;
        Ok(())
    })();
    if write_res.is_err() {
        let _ = fs::remove_file(path);
    }
    write_res
}

/// Atomically writes `bytes` to `path` via a unique temp file (`0600`, `O_CREAT | O_EXCL | O_NOFOLLOW`
/// on Unix), `f.set_permissions(0600)`, `sync_all()`, `rename()`, and parent directory `sync_all()`.
pub fn write_file_atomic_0600(path: &Path, bytes: &[u8]) -> Result<(), V2ConfigError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            ensure_dir_0700(parent)?;
        }
    }
    let nonce = ATOMIC_FILE_NONCE.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let tmp_name = format!(
        ".{}.tmp.{}.{nonce}.{nanos}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("state"),
        std::process::id()
    );
    let tmp_path = path.with_file_name(tmp_name);

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
        opts.custom_flags(libc::O_NOFOLLOW);
    }

    let write_res = (|| -> Result<(), V2ConfigError> {
        let mut f = opts.open(&tmp_path).map_err(|e| {
            V2ConfigError::Io(format!("create temp file '{}': {e}", tmp_path.display()))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(0o600)).map_err(|e| {
                V2ConfigError::Io(format!("fchmod 0600 '{}': {e}", tmp_path.display()))
            })?;
        }
        f.write_all(bytes).map_err(|e| {
            V2ConfigError::Io(format!("write temp file '{}': {e}", tmp_path.display()))
        })?;
        f.sync_all().map_err(|e| {
            V2ConfigError::Io(format!("sync temp file '{}': {e}", tmp_path.display()))
        })?;
        drop(f);
        fs::rename(&tmp_path, path).map_err(|e| {
            V2ConfigError::Io(format!(
                "rename '{}' -> '{}': {e}",
                tmp_path.display(),
                path.display()
            ))
        })?;
        sync_parent_dir(path)
            .map_err(|e| V2ConfigError::Io(format!("fsync parent dir '{}': {e}", path.display())))?;
        Ok(())
    })();

    if write_res.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    write_res
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_edge(pop_id: &str) -> EdgeEndpointConfig {
        EdgeEndpointConfig {
            pop_id: pop_id.to_string(),
            udp_addr: "127.0.0.1:4430".into(),
            ctrl_addr: "127.0.0.1:4431".into(),
            tls443_addr: "127.0.0.1:4432".into(),
            x25519_pub_hex: hex::encode([0x11u8; 32]),
            cert_hash_hex: None,
            bb_addr: None,
            dlq_path: None,
        }
    }

    fn sample_config(dir: PathBuf) -> V2ClientConfig {
        V2ClientConfig {
            control_plane_endpoint: "http://127.0.0.1:18080".into(),
            signaling_addr: "127.0.0.1:18090".into(),
            signaling_tls: None,
            edge_a: sample_edge("edge-a01"),
            edge_b: sample_edge("edge-b02"),
            enrollment_token: Some("tok".into()),
            ca_der_path: None,
            identity_dir: dir,
            home_region: "local".into(),
            codec: VideoCodec::Vp9,
            fps: 30,
            watchdog_timeout_ms: 3000,
            keepalive_interval_ms: 500,
            lease_renew_interval_sec: 15,
            bw_cap_kbps: 50_000,
            transport_mode: TransportMode::Auto,
            udp_probe_timeout_ms: DEFAULT_UDP_PROBE_TIMEOUT_MS,
            drop_udp_for_test: false,
        }
    }

    #[test]
    fn config_validation_enforces_watchdog_keepalive_lease_and_unix_permissions() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("zd-cfg-test-{}-{uniq}", std::process::id()));
        let mut cfg = sample_config(dir.clone());
        cfg.validate().unwrap();

        // Non-loopback signaling with explicit plaintext MUST fail closed
        cfg.signaling_addr = "203.0.113.10:18090".into();
        cfg.signaling_tls = Some(false);
        assert!(cfg.validate().is_err());
        cfg.signaling_tls = None;
        cfg.validate().unwrap();
        cfg.signaling_addr = "127.0.0.1:18090".into();
        cfg.signaling_tls = None;
        cfg.validate().unwrap();

        // Non-loopback plaintext http:// control_plane_endpoint MUST fail closed
        cfg.control_plane_endpoint = "http://cp.zerodesk.example:18080".into();
        assert!(cfg.validate().is_err());
        cfg.control_plane_endpoint = "http://203.0.113.10:18080".into();
        assert!(cfg.validate().is_err());
        cfg.control_plane_endpoint = "https://cp.zerodesk.example:443".into();
        cfg.validate().unwrap();
        cfg.control_plane_endpoint = "http://[::1]:18080".into();
        cfg.validate().unwrap();
        cfg.control_plane_endpoint = "http://localhost:18080".into();
        cfg.validate().unwrap();
        cfg.control_plane_endpoint = "http://127.0.0.1:18080".into();
        cfg.validate().unwrap();

        // Identical edge_a and edge_b pop_id MUST be rejected
        let orig_b = cfg.edge_b.pop_id.clone();
        cfg.edge_b.pop_id = cfg.edge_a.pop_id.clone();
        assert!(cfg.validate().is_err());
        cfg.edge_b.pop_id = orig_b;
        cfg.validate().unwrap();

        // V2ClientConfig Debug MUST redact enrollment_token
        cfg.enrollment_token = Some("super-secret-enrollment-token".into());
        let dbg = format!("{cfg:?}");
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("super-secret-enrollment-token"));

        // Watchdog bounds [1000, 10000]
        cfg.watchdog_timeout_ms = 999;
        assert!(cfg.validate().is_err());
        cfg.watchdog_timeout_ms = 10_001;
        assert!(cfg.validate().is_err());
        cfg.watchdog_timeout_ms = 1_000;
        cfg.keepalive_interval_ms = 600; // 1000 < 2 * 600
        assert!(cfg.validate().is_err());
        cfg.keepalive_interval_ms = 500;
        cfg.validate().unwrap();

        // Lease renew interval strictly 1..=15
        cfg.lease_renew_interval_sec = 0;
        assert!(cfg.validate().is_err());
        cfg.lease_renew_interval_sec = 16;
        assert!(cfg.validate().is_err());
        cfg.lease_renew_interval_sec = 15;
        cfg.validate().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure_dir_0700(&dir).unwrap();
            cfg.validate().unwrap();

            // Permissive directory (0755) must fail closed
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
            assert!(matches!(
                cfg.validate(),
                Err(V2ConfigError::InsecurePermissions(_))
            ));
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();

            // Permissive identity key file (0644) must fail closed
            let key_file = dir.join(IDENTITY_FILE_NAME);
            write_file_atomic_0600(&key_file, b"{}").unwrap();
            cfg.validate().unwrap();
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(matches!(
                cfg.validate(),
                Err(V2ConfigError::InsecurePermissions(_))
            ));
            fs::set_permissions(&key_file, fs::Permissions::from_mode(0o600)).unwrap();
            cfg.validate().unwrap();
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
