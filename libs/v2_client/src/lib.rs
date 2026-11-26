pub mod access_ctrl;
pub mod bridge;
pub mod config;
pub mod control_plane;
pub mod error;
pub mod signaling;
pub mod tls443;
pub mod udp_session;

pub use access_ctrl::{
    build_access_prologue, encode_ticket_wire, AccessControlTunnel, AccessKeys,
    EdgeLeaseRenewResp, EdgeRebindResp, RelayBindResp, ACCESS_IK_PATTERN, ACCESS_PROLOGUE_LEN,
    ACCESS_PROLOGUE_PREFIX, MAX_CTRL_FRAME_LEN,
};
pub use bridge::{V2LoopbackBridge, V2ServiceStream, V2SessionMux, DEFAULT_BRIDGE_CHANNEL};
pub use config::{
    decode_hex_array, default_edge_cert_hash, ClusterConfig, EdgeEndpointConfig,
};
pub use control_plane::{
    build_client_meter_tbs, build_dev_pop_tbs, build_dev_rotate_tbs, build_lease_renew_tbs,
    build_tls_client_config, is_loopback_host, now_unix_secs, tls_server_name_for_host,
    CaPubkeyResp, ClientMeterReportReq, ClientMeterReportResp, ControlPlaneClient,
    CreateTenantReq, LeaseRenewReq, LeaseRenewResp, RegisterDeviceReq, RegisterDeviceResp,
    RelayTicketWire,
};
pub use error::ClientError;
pub use signaling::{
    decode_signaling_frame, encode_signaling_frame, HeartbeatMsg, MovedRedirect, PresenceState,
    SignalingClient, SignalingConnectAccept, SignalingConnectOffer, SignalingConnectReq,
    SignalingMsgKind, SignalingProbeResult,
};
pub use tls443::{
    encode_stream_preface, DualTls443Client, StreamRecvEvent, Tls443Stream, Tls443StreamRole,
    TLS443_AUTH_DEADLINE, TLS443_HOL_THRESHOLD_MS, TLS443_PREFACE_LEN,
};
pub use udp_session::{
    bind_addr_for_edge, decode_survival_rs64_shards, encode_survival_rs64_shards, LegGapTracker,
    UdpAccessLink, UdpE2eeSession, UdpLinkStats, UdpRecvEvent,
};
