// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

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
pub use bridge::{
    TunnelReorderBuffer, V2LoopbackBridge, V2ServiceStream, V2SessionMux, BRIDGE_CHANNEL_CAPACITY,
    DEFAULT_BRIDGE_CHANNEL, MAX_REORDER_WINDOW, MAX_RETRANSMIT_ATTEMPTS,
    MAX_RETRANSMIT_TOTAL_TIMEOUT,
};
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
    build_register_pop_tbs, decode_delegation_pb, decode_signaling_frame, encode_delegation_pb,
    encode_signaling_frame, parse_signaling_host, resolve_signaling_tls, HeartbeatMsg,
    MovedRedirect, PeerRouteCandidate, PresenceState, SignalingClient, SignalingConnectAccept,
    SignalingConnectOffer, SignalingConnectReq, SignalingDeviceCert, SignalingMsgKind,
    SignalingProbeResult, SignalingReconnectBackoff, SignalingRegisterChallenge,
    SignalingRegisterReq, SignalingRegisterResp, SignalingSession, SignalingStaticKeyHint,
    MAX_SIGNALING_FRAME_BYTES, SIGNALING_BACKOFF_INITIAL_MS, SIGNALING_BACKOFF_MAX_MS,
    SIGNALING_POP_DOMAIN, SIGNALING_POP_TBS_LEN,
};
pub use tls443::{
    encode_stream_preface, validate_stream_frame_len, DualTls443Client, StreamRecvEvent,
    Tls443Stream, Tls443StreamRole, STREAM_CTRL_MAX_LEN, STREAM_CTRL_MIN_LEN, STREAM_DATA_MAX_LEN,
    STREAM_DATA_MIN_LEN, TLS443_AUTH_DEADLINE, TLS443_HOL_THRESHOLD_MS, TLS443_PREFACE_LEN,
};
pub use udp_session::{
    bind_addr_for_edge, decode_survival_rs64_shards, encode_survival_rs64_shards, LegGapTracker,
    UdpAccessLink, UdpE2eeSession, UdpLinkStats, UdpRecvEvent, MAX_LEG_GAP_MISSING,
};
