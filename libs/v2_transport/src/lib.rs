pub mod access;
pub mod constants;
pub mod diagnostics;
pub mod error;
pub mod fec;
pub mod handshake;
pub mod l3;
pub mod l4;
pub mod path;
pub mod policy;
pub mod transport;

pub use access::{
    compute_stream_mac64, compute_udp_mac64, derive_access_key, derive_access_key_with_prk,
    derive_stream_role_key, seal_stream_v11, seal_udp_v11, verify_mac64_ct, AccessEpochState, AccessFlags,
    AccessHeaderV10, AccessHeaderV11, BwHintController, DecodedStreamFrame, EdgeCtrlFrame,
    LegCiphertextCache, LegSeqDedupWindow, QueuedStreamSlice, StreamFrameParser,
    TcpStreamSendQueue, ACCESS_HKDF_LABEL, DIR_CLIENT_TO_EDGE, DIR_EDGE_TO_CLIENT,
    TRANSPORT_DATAGRAM, TRANSPORT_STREAM,
};
pub use constants::{
    channel_priority_matches, default_channel_priority, seq_u32_gt, ErrorCode,
    ACCESS_HDR_V10_LEN, ACCESS_HDR_V11_LEN, ACTUATOR_MAX_TTL_MS, AEAD_TAG_LEN, ARQ_MAX_RETRIES,
    ARQ_MAX_RTO_MS, ARQ_MIN_RTO_MS, BACKBONE_MAX_WIRE_BYTES, BW_EVENT_DROP_ACTIVE,
    BW_EVENT_PAUSE_FILE_CHUNK, BW_EVENT_SURVIVAL_MODE, CAP_ACCESS_LEG_SEQ_V11,
    CAP_AUDIO_OPUS_DTX, CAP_CIPHER_CHACHA_PREF, CAP_CODEC_AV1, CAP_CODEC_H264,
    CAP_CODEC_HEVC_OS_HW, CAP_CODEC_VP9, CAP_ENTERPRISE_AUDIT_DUAL, CAP_MULTIPATH_ACTIVE_ACTIVE,
    CAP_REALTIME_ACTUATOR_CH, CAP_SURVIVAL_MODE, CAP_TRANSPORT_P2P_IPV6,
    CAP_TRANSPORT_TCP443_DUAL, CAP_TRANSPORT_WEBTRANSPORT, CAP_VIDEO_INTRA_REFRESH,
    CAP_VIDEO_LTR, CAP_VIDEO_TEMPORAL_SVC, CHAN_AUDIO, CHAN_CLIPBOARD, CHAN_DIAGNOSTICS,
    CHAN_FILE_TRANSFER, CHAN_INPUT_HID, CHAN_REALTIME_ACTUATOR, CHAN_TELEMETRY,
    CHAN_TRANSPORT_CTRL, CHAN_VIDEO, CIPHER_AESGCM, CIPHER_CHACHAPOLY, EDGE_CTRL_BW_HINT,
    EDGE_CTRL_LEG_NACK, EDGE_CTRL_MTU_HINT, EDGE_CTRL_PING, EDGE_CTRL_PONG,
    EDGE_CTRL_REKEY_ACCESS, EDGE_CTRL_TICKET_EXPIRING, HID_STALE_DROP_MS, IDR_MIN_INTERVAL_MS,
    L3_HDR_LEN, L3_MTU_DEFAULT, L3_MTU_WEBTRANSPORT, L4_HDR_LEN, LEG_CACHE_MAX_BYTES,
    LEG_CACHE_TTL_MS, LEG_NACK_VIDEO_MAX_AGE_MS, LEG_REKEY_GRACE_MS, MAGIC_VER,
    MAX_FUTURE_SKEW_MS, PATTERN_IK, PATTERN_XX, QUOTA_THROTTLE_KBPS, REPLAY_WINDOW_BITS,
    STREAM_FRAME_MAX_LEN, STREAM_FRAME_MIN_LEN, STREAM_QUEUE_CAP_BYTES, TRANSPORT_MODE_P2P,
    TRANSPORT_MODE_RELAY_UDP, TRANSPORT_MODE_TCP443, TRANSPORT_MODE_WEBTRANSPORT,
    UDP_CTRL_MAX_LEN, UDP_L3_MIN_LEN, UDP_MAX_LEN, UDP_MIN_LEN, VER_MAJOR, VER_MAJOR_MINOR,
    VER_MINOR, ZERO_RTT_LRU_CAPACITY,
};
pub use diagnostics::{
    sanitize_log_line, DiagnosticBundle, DiagnosticsRing, QoeSnapshot, DIAGNOSTICS_RING_CAPACITY,
};
pub use error::TransportError;
pub use fec::{
    cauchy_coeff, gf_inv, gf_mul, rs64_decode_block, rs64_encode_block, rs_cauchy_decode_unequal,
    rs_cauchy_encode_unequal, SURVIVAL_RS_K, SURVIVAL_RS_M,
};
pub use handshake::{
    AccessHandshakeOutput, AccessNoiseHandshake, E2eeHandshakeOutput, E2eeNoiseHandshake,
    PrologueInput, ZeroRttDecision, ZeroRttGuard, PROLOGUE_DOMAIN, PROLOGUE_PREIMAGE_LEN,
};
pub use l3::{open_l3, seal_l3, L3Header, L3Receiver, L3Sender, ReplayWindow2048, PKT_SEQ_MAX};
pub use l4::{
    anchor_rs_parity_count, build_sack_bitmap, check_arq_retry_limit, compute_rto_ms,
    decode_l4_frame, effective_p3_credit, encode_l4_frame, process_hid_queue, ActuatorCmd,
    ActuatorReceiver, HidBatchResult, HidEvent, L4Header, LtrRecoveryController, LtrRecoveryReq,
    ReassembledVideoFrame, RecoveryAction, StreamSeqDedup, TelemetryFrame, VideoReassembler,
    VideoSlice, ACTUATOR_HDR_LEN, LTR_REASON_DECODE_ERROR, LTR_REASON_SLICE_LOST_TIMEOUT,
    STREAM_SEQ_DEDUP_CAPACITY, TELEMETRY_HDR_LEN, VIDEO_REASSEMBLER_MAX_AGE_MS,
    VIDEO_REASSEMBLER_MAX_PARTIALS, VIDEO_SLICE_META_LEN,
};
pub use path::{
    DualSendWindow, PathHandle, PathId, PathSet, PathState, TransportMode, DUAL_SEND_MAX_MS,
    DUAL_SEND_MIN_MS, PATH_PROBE_INTERVAL_MS,
};
pub use policy::{QuotaExhaustPolicy, TenantPolicyRules, VerifiedTenantPolicy};
pub use transport::{
    AssembledVideoFrame, AudioPacket, ClipboardFrame, ControlFrame, FileFrame, HidFrame, IdrReason,
    LoopbackTransportV2, TransportEvent, TransportStats, TransportV2, VideoFrameMeta,
};
