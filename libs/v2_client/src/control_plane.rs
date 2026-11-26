use crate::error::ClientError;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{CertificateDer, ServerName};
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::Path,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};
use tokio_rustls::TlsConnector;
use v2_identity::DeviceKeyStore;

pub const MAX_HTTP_BODY_BYTES: usize = 1024 * 1024;
pub const DEV_POP_DOMAIN: &[u8; 13] = b"V2-DEV-POP-v1";
pub const DEV_ROTATE_DOMAIN: &[u8; 16] = b"V2-DEV-ROTATE-v1";
pub const LEASE_RENEW_DOMAIN: &[u8; 17] = b"V2-LEASE-RENEW-v1";
pub const CLIENT_METER_DOMAIN: &[u8; 18] = b"V2-CLIENT-METER-v1";

pub fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Builds a pure-Rust `rustls::ClientConfig` trusting `webpki-roots` plus an optional
/// custom CA DER certificate (`--cp-ca-der`). Fails closed on empty or invalid DER.
pub fn build_tls_client_config(ca_der_path: Option<&Path>) -> Result<Arc<ClientConfig>, ClientError> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    if let Some(path) = ca_der_path {
        let der = std::fs::read(path).map_err(|e| {
            ClientError::Tls(format!("failed to read custom CA DER '{}': {e}", path.display()))
        })?;
        if der.is_empty() {
            return Err(ClientError::Tls(format!(
                "custom CA DER '{}' is empty",
                path.display()
            )));
        }
        roots.add(CertificateDer::from(der)).map_err(|e| {
            ClientError::Tls(format!(
                "invalid custom CA DER '{}': {e}",
                path.display()
            ))
        })?;
    }

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ClientError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(cfg))
}

/// Resolves TLS SNI / IP SAN `ServerName`.
/// IP literals (including loopback IPs) verify directly via IP SAN;
/// DNS hostnames (such as `"localhost"`) verify via DNS SAN.
pub fn tls_server_name_for_host(host: &str) -> Result<ServerName<'static>, ClientError> {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return ServerName::try_from(ip.to_string())
            .map_err(|e| ClientError::Tls(e.to_string()));
    }
    ServerName::try_from(trimmed.to_string()).map_err(|e| ClientError::Tls(e.to_string()))
}

pub fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed
        .parse::<IpAddr>()
        .map(|ip| ip.is_loopback())
        .unwrap_or(false)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTicketWire {
    pub key_id: u32,
    pub body: Vec<u8>,
    pub mac: [u8; 32],
}

#[derive(Debug, Clone, Deserialize)]
pub struct CaPubkeyResp {
    pub ca_p256_pub_der_b64: String,
    pub ca_p256_pub_der_hex: String,
}

impl CaPubkeyResp {
    pub fn spki_der(&self) -> Result<Vec<u8>, ClientError> {
        Ok(B64.decode(&self.ca_p256_pub_der_b64)?)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateTenantReq {
    pub tenant_id_hex: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub home_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_tier: Option<String>,
    pub monthly_quota_bytes: u64,
    pub bw_cap_kbps: u32,
    pub exhaust_policy: u32,
    pub allow_file_transfer: bool,
    pub enrollment_token: String,
    pub enrollment_ttl_sec: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_hash_hex: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RegisterDeviceReq {
    pub device_id_hex: String,
    pub p256_pub_der_b64: String,
    pub pop_sig_der_b64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_key_sig_der_b64: Option<String>,
    pub timestamp_unix: u64,
    pub cap_bits: u64,
    pub home_region: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RegisterDeviceResp {
    pub cert_id_hex: String,
    pub key_epoch: u64,
    pub iat_unix: u64,
    pub exp_unix: u64,
    pub tbs_b64: String,
    pub sig_der_b64: String,
}

impl RegisterDeviceResp {
    pub fn tbs_bytes(&self) -> Result<Vec<u8>, ClientError> {
        Ok(B64.decode(&self.tbs_b64)?)
    }

    pub fn sig_der(&self) -> Result<Vec<u8>, ClientError> {
        Ok(B64.decode(&self.sig_der_b64)?)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LeaseRenewReq {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id_hex: Option<String>,
    pub session_id_hex: String,
    pub route_cid_hex: String,
    pub pop_id_hex: String,
    pub controller_device_id_hex: String,
    pub controlled_device_id_hex: String,
    pub last_lease_seq: u64,
    pub delta_egress_bytes: u64,
    pub key_id: u32,
    pub timestamp_unix: u64,
    pub device_sig_der_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LeaseRenewResp {
    pub key_id: u32,
    pub ticket_body_b64: String,
    pub ticket_mac_b64: String,
    pub lease_seq: u64,
    pub session_start_unix: u64,
    pub byte_budget: u64,
    pub bw_cap_kbps: u32,
    pub exhaust_policy: serde_json::Value,
    pub quota_exhausted: bool,
    pub mission_rth_alert: bool,
    pub next_renew_sec: u32,
    pub server_unix: u64,
    pub quota_remaining_bytes: u64,
    pub renew_at_unix: u64,
    pub migrated: bool,
}

impl LeaseRenewResp {
    pub fn to_relay_ticket(&self) -> Result<RelayTicketWire, ClientError> {
        let body = B64.decode(&self.ticket_body_b64)?;
        let mac_vec = B64.decode(&self.ticket_mac_b64)?;
        if mac_vec.len() != 32 {
            return Err(ClientError::Protocol(format!(
                "ticket_mac_b64 decoded to {} bytes, expected 32",
                mac_vec.len()
            )));
        }
        let mut mac = [0u8; 32];
        mac.copy_from_slice(&mac_vec);
        Ok(RelayTicketWire {
            key_id: self.key_id,
            body,
            mac,
        })
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ClientMeterReportReq {
    pub device_id_hex: String,
    pub session_id_hex: String,
    pub edge_id: String,
    pub session_start_unix: u64,
    pub window_index: u64,
    pub egress_bytes: u64,
    pub timestamp_unix: u64,
    pub device_sig_der_b64: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ClientMeterReportResp {
    #[serde(default)]
    pub accepted: u64,
    #[serde(default)]
    pub upgraded: u64,
    #[serde(default)]
    pub deduplicated: u64,
    #[serde(default)]
    pub rejected: u64,
    #[serde(default)]
    pub retryable: u64,
    #[serde(default)]
    pub total_billed: u64,
    #[serde(default)]
    pub results: serde_json::Value,
}

pub fn build_dev_pop_tbs(device_id: &[u8; 16], p256_pub_der: &[u8], timestamp_unix: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEV_POP_DOMAIN.len() + 16 + p256_pub_der.len() + 8);
    out.extend_from_slice(DEV_POP_DOMAIN);
    out.extend_from_slice(device_id);
    out.extend_from_slice(p256_pub_der);
    out.extend_from_slice(&timestamp_unix.to_be_bytes());
    out
}

pub fn build_dev_rotate_tbs(
    device_id: &[u8; 16],
    new_pub_der: &[u8],
    timestamp_unix: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DEV_ROTATE_DOMAIN.len() + 16 + new_pub_der.len() + 8);
    out.extend_from_slice(DEV_ROTATE_DOMAIN);
    out.extend_from_slice(device_id);
    out.extend_from_slice(new_pub_der);
    out.extend_from_slice(&timestamp_unix.to_be_bytes());
    out
}

pub fn build_lease_renew_tbs(
    session_id: &[u8; 16],
    route_cid: &[u8; 8],
    pop_id: &[u8; 8],
    last_lease_seq: u64,
    timestamp_unix: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(LEASE_RENEW_DOMAIN.len() + 16 + 8 + 8 + 8 + 8);
    out.extend_from_slice(LEASE_RENEW_DOMAIN);
    out.extend_from_slice(session_id);
    out.extend_from_slice(route_cid);
    out.extend_from_slice(pop_id);
    out.extend_from_slice(&last_lease_seq.to_be_bytes());
    out.extend_from_slice(&timestamp_unix.to_be_bytes());
    out
}

pub fn build_client_meter_tbs(
    device_id: &[u8; 16],
    session_id: &[u8; 16],
    session_start_unix: u64,
    window_index: u64,
    egress_bytes: u64,
    timestamp_unix: u64,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(CLIENT_METER_DOMAIN.len() + 16 + 16 + 8 * 4);
    out.extend_from_slice(CLIENT_METER_DOMAIN);
    out.extend_from_slice(device_id);
    out.extend_from_slice(session_id);
    out.extend_from_slice(&session_start_unix.to_be_bytes());
    out.extend_from_slice(&window_index.to_be_bytes());
    out.extend_from_slice(&egress_bytes.to_be_bytes());
    out.extend_from_slice(&timestamp_unix.to_be_bytes());
    out
}

#[derive(Debug, Clone)]
struct ParsedEndpoint {
    use_tls: bool,
    host: String,
    port: u16,
    host_header: String,
}

fn parse_endpoint(base_url: &str) -> Result<ParsedEndpoint, ClientError> {
    let (use_tls, rest) = if let Some(r) = base_url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = base_url.strip_prefix("http://") {
        (false, r)
    } else {
        return Err(ClientError::Config(format!(
            "control-plane URL must start with http:// or https://, got '{base_url}'"
        )));
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err(ClientError::Config("empty control-plane authority".into()));
    }
    let (host, port) = if let Some(bracket_end) = authority.find(']') {
        let h = &authority[..=bracket_end];
        let rem = &authority[bracket_end + 1..];
        let p = if let Some(p_str) = rem.strip_prefix(':') {
            p_str
                .parse::<u16>()
                .map_err(|_| ClientError::Config(format!("invalid port in '{base_url}'")))?
        } else if use_tls {
            443
        } else {
            80
        };
        (h.to_string(), p)
    } else if let Some((h, p_str)) = authority.rsplit_once(':') {
        let p = p_str
            .parse::<u16>()
            .map_err(|_| ClientError::Config(format!("invalid port in '{base_url}'")))?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), if use_tls { 443 } else { 80 })
    };

    if !use_tls && !is_loopback_host(&host) {
        return Err(ClientError::Config(format!(
            "plaintext http:// is restricted to loopback hosts; refusing '{host}'"
        )));
    }

    let host_header = format!("{host}:{port}");
    Ok(ParsedEndpoint {
        use_tls,
        host,
        port,
        host_header,
    })
}

#[derive(Clone)]
pub struct ControlPlaneClient {
    endpoint: ParsedEndpoint,
    tls_config: Option<Arc<ClientConfig>>,
    timeout: Duration,
}

impl ControlPlaneClient {
    pub fn new(base_url: &str, ca_der_path: Option<&Path>) -> Result<Self, ClientError> {
        let endpoint = parse_endpoint(base_url)?;
        let tls_config = if endpoint.use_tls {
            Some(build_tls_client_config(ca_der_path)?)
        } else if let Some(path) = ca_der_path {
            // Still validate explicit custom CA DER fail-closed even when http:// loopback is used.
            let _ = build_tls_client_config(Some(path))?;
            None
        } else {
            None
        };
        Ok(Self {
            endpoint,
            tls_config,
            timeout: Duration::from_secs(10),
        })
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub async fn healthz(&self) -> Result<(), ClientError> {
        let (status, body) = self.request("GET", "/healthz", &[], None).await?;
        if status != 200 {
            return Err(ClientError::HttpStatus {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(())
    }

    pub async fn get_ca_pubkey(&self) -> Result<CaPubkeyResp, ClientError> {
        let (status, body) = self.request("GET", "/v2/ca/pubkey", &[], None).await?;
        if status != 200 {
            return Err(ClientError::HttpStatus {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(serde_json::from_slice(&body)?)
    }

    pub async fn create_tenant(
        &self,
        admin_token: &str,
        req: &CreateTenantReq,
    ) -> Result<serde_json::Value, ClientError> {
        let payload = serde_json::to_vec(req)?;
        let auth = format!("Bearer {admin_token}");
        let (status, body) = self
            .request(
                "POST",
                "/v2/admin/tenants",
                &[("Authorization", auth.as_str())],
                Some(&payload),
            )
            .await?;
        if !(200..300).contains(&status) {
            return Err(ClientError::HttpStatus {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        if body.is_empty() {
            Ok(serde_json::Value::Null)
        } else {
            Ok(serde_json::from_slice(&body)?)
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn register_device(
        &self,
        keystore: &dyn DeviceKeyStore,
        device_id: &[u8; 16],
        enrollment_token: &str,
        cap_bits: u64,
        home_region: &str,
        old_keystore: Option<&dyn DeviceKeyStore>,
        admin_rotation_token: Option<&str>,
    ) -> Result<RegisterDeviceResp, ClientError> {
        let ts = now_unix_secs();
        let pub_der = keystore.public_key_spki_der()?;
        let pop_tbs = build_dev_pop_tbs(device_id, &pub_der, ts);
        let pop_sig = keystore.sign_p256_low_s(&pop_tbs)?;

        let old_key_sig_der_b64 = if let Some(old_ks) = old_keystore {
            let rot_tbs = build_dev_rotate_tbs(device_id, &pub_der, ts);
            let rot_sig = old_ks.sign_p256_low_s(&rot_tbs)?;
            Some(B64.encode(rot_sig))
        } else {
            None
        };

        let req = RegisterDeviceReq {
            device_id_hex: hex::encode(device_id),
            p256_pub_der_b64: B64.encode(&pub_der),
            pop_sig_der_b64: B64.encode(&pop_sig),
            old_key_sig_der_b64,
            timestamp_unix: ts,
            cap_bits,
            home_region: home_region.to_string(),
        };
        let payload = serde_json::to_vec(&req)?;
        let auth = format!("Bearer {enrollment_token}");
        let mut headers: Vec<(&str, &str)> = vec![("Authorization", auth.as_str())];
        if let Some(rot_tok) = admin_rotation_token {
            headers.push(("X-Admin-Rotation-Token", rot_tok));
        }

        let (status, body) = self
            .request("POST", "/v2/devices/register", &headers, Some(&payload))
            .await?;
        if !(200..300).contains(&status) {
            return Err(ClientError::HttpStatus {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// Issues an initial relay lease (`last_lease_seq == 0`) via `POST /v2/leases/renew`.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_lease(
        &self,
        keystore: &dyn DeviceKeyStore,
        tenant_id: Option<&[u8; 16]>,
        session_id: &[u8; 16],
        route_cid: &[u8; 8],
        pop_id: &[u8; 8],
        controller_device_id: &[u8; 16],
        controlled_device_id: &[u8; 16],
        key_id: u32,
    ) -> Result<LeaseRenewResp, ClientError> {
        self.renew_lease(
            keystore,
            tenant_id,
            session_id,
            route_cid,
            pop_id,
            controller_device_id,
            controlled_device_id,
            0,
            0,
            key_id,
        )
        .await
    }

    /// Renews an active relay lease (preserving `route_cid` and advancing `lease_seq`).
    #[allow(clippy::too_many_arguments)]
    pub async fn renew_lease(
        &self,
        keystore: &dyn DeviceKeyStore,
        tenant_id: Option<&[u8; 16]>,
        session_id: &[u8; 16],
        route_cid: &[u8; 8],
        pop_id: &[u8; 8],
        controller_device_id: &[u8; 16],
        controlled_device_id: &[u8; 16],
        last_lease_seq: u64,
        delta_egress_bytes: u64,
        key_id: u32,
    ) -> Result<LeaseRenewResp, ClientError> {
        let ts = now_unix_secs();
        let tbs = build_lease_renew_tbs(session_id, route_cid, pop_id, last_lease_seq, ts);
        let sig = keystore.sign_p256_low_s(&tbs)?;

        let req = LeaseRenewReq {
            tenant_id_hex: tenant_id.map(hex::encode),
            session_id_hex: hex::encode(session_id),
            route_cid_hex: hex::encode(route_cid),
            pop_id_hex: hex::encode(pop_id),
            controller_device_id_hex: hex::encode(controller_device_id),
            controlled_device_id_hex: hex::encode(controlled_device_id),
            last_lease_seq,
            delta_egress_bytes,
            key_id,
            timestamp_unix: ts,
            device_sig_der_b64: B64.encode(&sig),
        };
        let payload = serde_json::to_vec(&req)?;
        let (status, body) = self
            .request("POST", "/v2/leases/renew", &[], Some(&payload))
            .await?;
        if !(200..300).contains(&status) {
            return Err(ClientError::HttpStatus {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(serde_json::from_slice(&body)?)
    }

    /// Submits client fallback metering via `POST /v2/metering/client-report`.
    #[allow(clippy::too_many_arguments)]
    pub async fn report_metering_fallback(
        &self,
        keystore: &dyn DeviceKeyStore,
        device_id: &[u8; 16],
        session_id: &[u8; 16],
        edge_id: &str,
        session_start_unix: u64,
        window_index: u64,
        egress_bytes: u64,
    ) -> Result<ClientMeterReportResp, ClientError> {
        if edge_id.is_empty() || edge_id.len() > 64 {
            return Err(ClientError::Config(
                "edge_id must be 1..=64 bytes".into(),
            ));
        }
        let ts = now_unix_secs();
        let tbs = build_client_meter_tbs(
            device_id,
            session_id,
            session_start_unix,
            window_index,
            egress_bytes,
            ts,
        );
        let sig = keystore.sign_p256_low_s(&tbs)?;

        let req = ClientMeterReportReq {
            device_id_hex: hex::encode(device_id),
            session_id_hex: hex::encode(session_id),
            edge_id: edge_id.to_string(),
            session_start_unix,
            window_index,
            egress_bytes,
            timestamp_unix: ts,
            device_sig_der_b64: B64.encode(&sig),
        };
        let payload = serde_json::to_vec(&req)?;
        let (status, body) = self
            .request("POST", "/v2/metering/client-report", &[], Some(&payload))
            .await?;
        if !(200..300).contains(&status) {
            return Err(ClientError::HttpStatus {
                status,
                body: String::from_utf8_lossy(&body).into_owned(),
            });
        }
        Ok(serde_json::from_slice(&body)?)
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        extra_headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Result<(u16, Vec<u8>), ClientError> {
        if let Some(b) = body {
            if b.len() > MAX_HTTP_BODY_BYTES {
                return Err(ClientError::Http("request body exceeds 1 MiB limit".into()));
            }
        }
        let mut raw_req = format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: application/json\r\n",
            self.endpoint.host_header
        );
        for (k, v) in extra_headers {
            raw_req.push_str(&format!("{k}: {v}\r\n"));
        }
        if let Some(b) = body {
            raw_req.push_str("Content-Type: application/json\r\n");
            raw_req.push_str(&format!("Content-Length: {}\r\n", b.len()));
        }
        raw_req.push_str("\r\n");

        let addr = format!("{}:{}", self.endpoint.host, self.endpoint.port);
        let fut = async {
            let tcp = TcpStream::connect(&addr).await?;
            let _ = tcp.set_nodelay(true);
            if let Some(tls_cfg) = &self.tls_config {
                let server_name = tls_server_name_for_host(&self.endpoint.host)?;
                let connector = TlsConnector::from(Arc::clone(tls_cfg));
                let mut stream = connector
                    .connect(server_name, tcp)
                    .await
                    .map_err(|e| ClientError::Tls(e.to_string()))?;
                write_and_read_http(&mut stream, raw_req.as_bytes(), body).await
            } else {
                let mut stream = tcp;
                write_and_read_http(&mut stream, raw_req.as_bytes(), body).await
            }
        };

        tokio::time::timeout(self.timeout, fut)
            .await
            .map_err(|_| ClientError::Timeout(format!("HTTP {method} {path} timed out")))?
    }
}

async fn write_and_read_http<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    head: &[u8],
    body: Option<&[u8]>,
) -> Result<(u16, Vec<u8>), ClientError> {
    if let Some(b) = body {
        let mut combined = Vec::with_capacity(head.len() + b.len());
        combined.extend_from_slice(head);
        combined.extend_from_slice(b);
        stream.write_all(&combined).await?;
    } else {
        stream.write_all(head).await?;
    }
    stream.flush().await?;

    let mut raw = Vec::new();
    let mut chunk = [0u8; 4096];
    let max_total = MAX_HTTP_BODY_BYTES + 64 * 1024;
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            break;
        }
        if raw.len() + n > max_total {
            return Err(ClientError::Http(
                "HTTP response exceeds 1 MiB body limit".into(),
            ));
        }
        raw.extend_from_slice(&chunk[..n]);
    }
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, Vec<u8>), ClientError> {
    let sep = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or_else(|| ClientError::Http("malformed HTTP response: missing header terminator".into()))?;
    let head_str = std::str::from_utf8(&raw[..sep])
        .map_err(|_| ClientError::Http("non-UTF8 HTTP response headers".into()))?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ClientError::Http("missing HTTP status line".into()))?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or_else(|| ClientError::Http(format!("malformed status line: {status_line}")))?
        .parse()
        .map_err(|_| ClientError::Http(format!("invalid status code: {status_line}")))?;

    let mut is_chunked = false;
    let mut content_length: Option<usize> = None;
    for line in lines {
        if let Some((name, val)) = line.split_once(':') {
            let name = name.trim().to_ascii_lowercase();
            let val = val.trim();
            if name == "transfer-encoding" && val.to_ascii_lowercase().contains("chunked") {
                is_chunked = true;
            } else if name == "content-length" {
                content_length = val.parse::<usize>().ok();
            }
        }
    }

    let body_slice = &raw[sep + 4..];
    let decoded = if is_chunked {
        decode_chunked(body_slice)?
    } else if let Some(len) = content_length {
        if body_slice.len() < len {
            return Err(ClientError::Http("truncated HTTP response body".into()));
        }
        body_slice[..len].to_vec()
    } else {
        body_slice.to_vec()
    };

    if decoded.len() > MAX_HTTP_BODY_BYTES {
        return Err(ClientError::Http(
            "decoded HTTP body exceeds 1 MiB limit".into(),
        ));
    }
    Ok((status, decoded))
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, ClientError> {
    let mut out = Vec::new();
    loop {
        let crlf = input
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| ClientError::Http("malformed chunked header".into()))?;
        let size_line = std::str::from_utf8(&input[..crlf])
            .map_err(|_| ClientError::Http("invalid UTF-8 in chunk size".into()))?
            .split(';')
            .next()
            .unwrap_or("")
            .trim();
        let size = usize::from_str_radix(size_line, 16)
            .map_err(|_| ClientError::Http(format!("invalid chunk size '{size_line}'")))?;
        input = &input[crlf + 2..];
        if size == 0 {
            break;
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err(ClientError::Http("truncated chunked payload".into()));
        }
        if out.len() + size > MAX_HTTP_BODY_BYTES {
            return Err(ClientError::Http(
                "chunked HTTP body exceeds 1 MiB limit".into(),
            ));
        }
        out.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::ClientMeterReportResp;

    #[test]
    fn client_meter_report_resp_deserializes_retryable_u64_counts() {
        let json_zero = r#"{"accepted":1,"upgraded":0,"deduplicated":0,"rejected":0,"retryable":0,"total_billed":4096,"results":[]}"#;
        let resp_zero: ClientMeterReportResp = serde_json::from_str(json_zero).unwrap();
        assert_eq!(resp_zero.accepted, 1);
        assert_eq!(resp_zero.rejected, 0);
        assert_eq!(resp_zero.retryable, 0);
        assert_eq!(resp_zero.total_billed, 4096);

        let json_two = r#"{"accepted":1,"upgraded":0,"deduplicated":0,"rejected":0,"retryable":2,"total_billed":4096,"results":[]}"#;
        let resp_two: ClientMeterReportResp = serde_json::from_str(json_two).unwrap();
        assert_eq!(resp_two.retryable, 2);

        let json_default = r#"{"accepted":1,"upgraded":0,"deduplicated":0,"rejected":0,"total_billed":4096,"results":[]}"#;
        let resp_default: ClientMeterReportResp = serde_json::from_str(json_default).unwrap();
        assert_eq!(resp_default.retryable, 0);
    }
}
