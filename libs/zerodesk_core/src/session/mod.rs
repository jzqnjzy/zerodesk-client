// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub mod audio;
pub mod capture;
pub mod clipboard;
pub mod config;
pub mod file_transfer;
pub mod hid;
pub mod identity;
pub mod input;
pub mod manager;
pub mod policy;
pub mod runtime;
#[allow(clippy::module_inception)]
pub mod session;
pub mod video;
pub mod vt_codec;

pub use audio::{
    audio_ts_delta, audio_ts_gt, measure_audio_quality, AudioChannelGate, AudioError,
    AudioJitterBuffer, AudioJitterStats, AudioQualityMetrics, AudioSink, AudioSource,
    EncodedAudioFrame, JitterPlayoutAction, JitterPushOutcome, OpusWireFrame, RecordingAudioSink,
    SyntheticMultiToneSource, V2AudioDecoder, V2AudioEncoder, AUDIO_DEFAULT_BITRATE_BPS,
    AUDIO_ERROR_INVALID_FRAMING, AUDIO_ERROR_POLICY_DENIED, AUDIO_FRAME_MS,
    AUDIO_FRAME_SAMPLES_PER_CH, AUDIO_JITTER_MAX_FRAMES, AUDIO_JITTER_MIN_FRAMES,
    AUDIO_LATE_DROP_MS, AUDIO_MAX_CONSECUTIVE_PLC, AUDIO_MAX_NORMAL_BITRATE_BPS,
    AUDIO_MAX_OPUS_PACKET_BYTES, AUDIO_MIN_NORMAL_BITRATE_BPS, AUDIO_SAMPLE_RATE_HZ,
    AUDIO_SURVIVAL_BITRATE_BPS, AUDIO_SURVIVAL_MAX_BITRATE_BPS, AUDIO_SURVIVAL_MIN_BITRATE_BPS,
    AUDIO_WIRE_HDR_LEN,
};
pub use capture::{
    bgra_to_i420_bt601, compute_y_variance, crop_and_validate_dimensions, detect_visual_marker,
    overlay_visual_marker, spawn_capture_pipeline, CaptureError, CapturePipelineHandle,
    CaptureStats, CapturedFrame, ScrapDisplaySource, ScreenCaptureSource, SharedVisualMarker,
    SyntheticAnimatedSource, VisualMarkerCheck, DEFAULT_SYNTHETIC_HEIGHT, DEFAULT_SYNTHETIC_WIDTH,
    MIN_CAPTURE_DIM, ZERO_VARIANCE_WARN_THRESHOLD,
};
pub use clipboard::{
    check_clipboard_policy_for_sync, decode_clipboard_l4, prepare_outbound_clipboard,
    validate_clipboard_content, validate_png_ihdr, ChannelFramingErrorCounter, ClipAck, ClipChunk,
    ClipMessage, ClipSync, ClipboardAntiEchoGuard, ClipboardError, ClipboardReceiver,
    ClipboardRecvAction, DeliveredClipboard, OutboundClipboardTransfer,
    CHANNEL_CONSECUTIVE_FRAMING_ERROR_LIMIT, CLIP_ACK_HASH_MISMATCH, CLIP_ACK_OK,
    CLIP_ACK_POLICY_DENIED, CLIP_ACK_RATE_LIMITED, CLIP_ACK_TIMEOUT, CLIP_ACK_TOO_LARGE,
    CLIP_ACK_UNSUPPORTED, CLIP_ACK_WIRE_LEN, CLIP_CHUNK_HDR_LEN, CLIP_CHUNK_MAX_PAYLOAD,
    CLIP_CHUNK_MAX_WIRE_LEN, CLIP_CHUNK_MIN_WIRE_LEN, CLIP_ERROR_INVALID_FRAMING,
    CLIP_HARD_MAX_BYTES, CLIP_MIME_FILE_URI_LIST, CLIP_MIME_IMAGE_PNG, CLIP_MIME_TEXT_UTF8,
    CLIP_MSG_ACK, CLIP_MSG_CHUNK, CLIP_MSG_SYNC, CLIP_PNG_MAX_DIM, CLIP_PNG_MAX_PIXELS,
    CLIP_REASSEMBLY_TIMEOUT, CLIP_SYNC_WIRE_LEN,
};
pub use config::{
    ensure_dir_0700, read_file_0600_to_string, verify_dir_permissions_0700,
    verify_file_permissions_0600, write_file_atomic_0600, TransportMode, V2ClientConfig,
    V2ConfigError, DEFAULT_BW_CAP_KBPS, DEFAULT_FPS, DEFAULT_KEEPALIVE_INTERVAL_MS,
    DEFAULT_LEASE_RENEW_INTERVAL_SEC, DEFAULT_UDP_PROBE_TIMEOUT_MS, DEFAULT_WATCHDOG_TIMEOUT_MS,
    DELEGATION_FILE_NAME, IDENTITY_FILE_NAME, MAX_LEASE_RENEW_INTERVAL_SEC,
    MAX_UDP_PROBE_TIMEOUT_MS, MIN_UDP_PROBE_TIMEOUT_MS,
};
pub use file_transfer::{
    build_collision_filename, check_disk_space_for_file, check_file_policy, decode_file_l4,
    validate_safe_filename, FileAbort, FileAccept, FileAck, FileChunk, FileComplete,
    FileCompleteAck, FileMessage, FileOffer, FileOfferRaw, FileRecvAction, FileSenderWindow,
    FileTransferAuditRecord, FileTransferError, FileTransferReceiver, FILE_ABORT_WIRE_LEN,
    FILE_ACCEPT_WIRE_LEN, FILE_ACK_WIRE_LEN, FILE_CHUNK_HDR_LEN, FILE_CHUNK_MAX_SIZE,
    FILE_CHUNK_MIN_SIZE, FILE_COLLISION_MAX_RETRIES, FILE_COMPLETE_ACK_HASH_MISMATCH,
    FILE_COMPLETE_ACK_IO_ERROR, FILE_COMPLETE_ACK_OK, FILE_COMPLETE_ACK_WIRE_LEN,
    FILE_COMPLETE_WIRE_LEN, FILE_DEFAULT_WINDOW_BYTES, FILE_ERR_AUDIT_UNAVAILABLE,
    FILE_ERR_INVALID_FRAMING, FILE_ERR_OK, FILE_ERR_PATH_FAILED, FILE_ERR_POLICY_DENIED,
    FILE_ERR_RATE_LIMITED, FILE_MAX_CONCURRENT_PER_DIR, FILE_MSG_ABORT, FILE_MSG_ACCEPT,
    FILE_MSG_ACK, FILE_MSG_CHUNK, FILE_MSG_COMPLETE, FILE_MSG_COMPLETE_ACK, FILE_MSG_OFFER,
    FILE_NAME_MAX_BYTES, FILE_OFFER_FIXED_LEN, FILE_RECOMMENDED_CHUNK_SIZE, FILE_STALL_TIMEOUT,
};
pub use hid::{
    coalesce_hid_batch, decode_hid_frame, decode_l4_hid_frame, encode_hid_frame,
    encode_l4_hid_frame, required_modifier_bit_for_usage, HidBatchOutcome, HidCodecError,
    HidEchoAck, HidPayload, KeyEvent, MouseEvent, MouseKind, ERROR_CODE_INVALID_FRAMING,
    HID_ECHO_ACK_WIRE_LEN, HID_MAX_COALESCE_HOLD_MS, HID_MOVEREL_COALESCE_MAX, HID_MSG_ECHO_ACK,
    HID_MSG_KEY, HID_MSG_MOUSE, KEY_EVENT_WIRE_LEN, MOD_ALT, MOD_CTRL, MOD_META, MOD_SHIFT,
    MOUSE_BUTTONS_VALID_MASK, MOUSE_EVENT_WIRE_LEN,
};
pub use identity::{IdentityStoreError, PersistentV2Identity};
#[cfg(all(
    feature = "os-input",
    not(any(target_os = "android", target_os = "ios"))
))]
pub use input::EnigoOsSink;
pub use input::{
    run_independent_release_all, spawn_independent_release_watchdog, spawn_release_watchdog,
    write_audit_records_jsonl, AtomicHeldState, AuditKey, AuditRecord, DryRunOp, DryRunSink,
    HidInputExecutor, HidInputSink, InputError, InputSinkError, ReleaseAllResult,
    ReleaseAllSummary, SafeHidKey, WatchdogHandle, DEFAULT_AUDIT_LOG_CAP,
    DEFAULT_HID_RATE_LIMIT_PER_SEC, HID_RELEASE_ALL_BACKOFF_MS, HID_RELEASE_ALL_MAX_RETRIES,
    HID_WATCHDOG_FLOOR_MS, HID_WATCHDOG_MAX_MS, HID_WATCHDOG_MIN_MS, MAX_HID_BATCH_SIZE,
    MOUSE_BUTTON_BACK, MOUSE_BUTTON_FORWARD, MOUSE_BUTTON_LEFT, MOUSE_BUTTON_MIDDLE,
    MOUSE_BUTTON_RIGHT, WATCHDOG_JOIN_TIMEOUT,
};
pub use manager::{
    attach_access_data_plane, build_verified_policy_from_cert, AcceptedHostSession, CallDecision,
    ConnectedControllerSession, DesktopControllerClient, DesktopHostDaemon, IncomingCall,
    ManagerError, NoopUiCallback, SecurityEvent, SeenSessionCache, UdpNegativeCache,
    UiCallbackDispatcher, V2SessionManager, V2SessionState, V2UiCallback, DEFAULT_V2_CAP_BITS,
    SEEN_SESSION_CACHE_CAP, UDP_NEGATIVE_CACHE_TTL,
};
pub use policy::{
    build_tenant_policy_tbs, verify_raw_tenant_policy_blob, verify_tenant_policy_blob,
    EffectiveTenantPolicy, PolicyError, PolicyVerifyOutcome, RawTenantPolicyBlob, TenantPolicyBody,
    DEGRADED_BASELINE_BW_KBPS, MAX_CLIPBOARD_HARD_CAP_BYTES, POLICY_CLOCK_SKEW_SECS,
    POLICY_FLAGS_RESERVED_MASK, POLICY_FLAGS_VALID_MASK, POLICY_FLAG_ALLOW_AUDIO,
    POLICY_FLAG_ALLOW_CLIPBOARD, POLICY_FLAG_ALLOW_FILE_CLIPBOARD, POLICY_FLAG_ALLOW_FILE_TRANSFER,
    POLICY_FLAG_ALLOW_TCP_TUNNEL, POLICY_FLAG_ALLOW_TERMINAL, TENANT_POLICY_BODY_LEN,
    TENANT_POLICY_SCHEMA_VER, TENANT_POLICY_TBS_LEN,
};
pub use runtime::{
    ordered_session_teardown, send_redundant_session_close_3x, CloseReason, LeaseRenewalConfig,
    LeaseRenewalLeg, LeaseRenewalShutdown, LeaseRenewalTask, OrderedTeardownReport, QoeSnapshot,
    CAPTURE_JOIN_TIMEOUT, LEASE_RENEW_CALL_TIMEOUT, LEASE_RENEW_MAX_CONSECUTIVE_FAILURES,
    LEASE_RENEW_SHUTDOWN_TIMEOUT, MAX_LEASE_RENEW_INTERVAL, SESSION_CLOSE_REDUNDANT_COUNT,
    SESSION_CLOSE_REDUNDANT_SPACING,
};
pub use session::{
    parse_request_idr, parse_session_close, DecodedVideoDelivery, DesktopControllerSession,
    DesktopHostSession, PublishedFrameInfo, SessionError, CTRL_MSG_REQUEST_IDR,
    CTRL_MSG_SESSION_CLOSE, PENDING_VIDEO_QUEUE_CAP,
};
pub use video::{
    compute_y_psnr, compute_y_ssim, generate_animated_i420, generate_desktop_scene_i420,
    local_v2_cap_bits, local_v2_cap_bits_with_vt_disable, negotiate_video_codec,
    read_desktop_scene_frame_idx, BgraFrame, DecodedVideoFrame, EncodedV2Frame,
    FrameQualityMetrics, I420Frame, V2VideoDecoder, V2VideoEncoder, VideoCodec, VideoError,
    CODEC_ID_AV1, CODEC_ID_H264, CODEC_ID_HEVC, CODEC_ID_VP9, DEFAULT_H264_1080P_BITRATE_BPS,
    DEFAULT_HEVC_1080P_BITRATE_BPS, MAX_CONSECUTIVE_DECODE_FAILURES, MAX_FRAME_DIM,
};
pub use vt_codec::{
    bgra_to_i420_bt709, parse_annexb_checked, probe_vt_cap_bits_uncached, probed_vt_cap_bits,
    probed_vt_cap_bits_with_disable, AnnexbParseSummary, VT_DISABLE_ENV_VAR,
    VT_MAX_REBUILDS_IN_WINDOW, VT_REBUILD_WINDOW,
};
