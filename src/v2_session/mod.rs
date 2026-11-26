// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub mod capture;
pub mod config;
pub mod hid;
pub mod identity;
pub mod input;
pub mod manager;
pub mod runtime;
pub mod session;
pub mod video;

pub use capture::{
    bgra_to_i420_bt601, compute_y_variance, crop_and_validate_dimensions, detect_visual_marker,
    overlay_visual_marker, spawn_capture_pipeline, CaptureError, CapturePipelineHandle,
    CaptureStats, CapturedFrame, ScrapDisplaySource, ScreenCaptureSource, SharedVisualMarker,
    SyntheticAnimatedSource, VisualMarkerCheck, DEFAULT_SYNTHETIC_HEIGHT, DEFAULT_SYNTHETIC_WIDTH,
    MIN_CAPTURE_DIM, ZERO_VARIANCE_WARN_THRESHOLD,
};
pub use config::{
    ensure_dir_0700, read_file_0600_to_string, verify_dir_permissions_0700,
    verify_file_permissions_0600, write_file_atomic_0600, V2ClientConfig, V2ConfigError,
    DEFAULT_BW_CAP_KBPS, DEFAULT_FPS, DEFAULT_KEEPALIVE_INTERVAL_MS,
    DEFAULT_LEASE_RENEW_INTERVAL_SEC, DEFAULT_WATCHDOG_TIMEOUT_MS, DELEGATION_FILE_NAME,
    IDENTITY_FILE_NAME, MAX_LEASE_RENEW_INTERVAL_SEC,
};
pub use identity::{IdentityStoreError, PersistentV2Identity};
pub use manager::{
    build_verified_policy_from_cert, AcceptedHostSession, CallDecision, ConnectedControllerSession,
    DesktopControllerClient, DesktopHostDaemon, IncomingCall, ManagerError, NoopUiCallback,
    SecurityEvent, SeenSessionCache, UiCallbackDispatcher, V2SessionManager, V2SessionState,
    V2UiCallback, DEFAULT_V2_CAP_BITS, SEEN_SESSION_CACHE_CAP,
};
pub use runtime::{
    ordered_session_teardown, send_redundant_session_close_3x, CloseReason, LeaseRenewalConfig,
    LeaseRenewalLeg, LeaseRenewalShutdown, LeaseRenewalTask, OrderedTeardownReport, QoeSnapshot,
    CAPTURE_JOIN_TIMEOUT, LEASE_RENEW_CALL_TIMEOUT, LEASE_RENEW_MAX_CONSECUTIVE_FAILURES,
    LEASE_RENEW_SHUTDOWN_TIMEOUT, MAX_LEASE_RENEW_INTERVAL, SESSION_CLOSE_REDUNDANT_COUNT,
    SESSION_CLOSE_REDUNDANT_SPACING,
};
pub use hid::{
    coalesce_hid_batch, decode_hid_frame, decode_l4_hid_frame, encode_hid_frame,
    encode_l4_hid_frame, required_modifier_bit_for_usage, HidBatchOutcome, HidCodecError,
    HidEchoAck, HidPayload, KeyEvent, MouseEvent, MouseKind, ERROR_CODE_INVALID_FRAMING,
    HID_ECHO_ACK_WIRE_LEN, HID_MAX_COALESCE_HOLD_MS, HID_MOVEREL_COALESCE_MAX, HID_MSG_ECHO_ACK,
    HID_MSG_KEY, HID_MSG_MOUSE, KEY_EVENT_WIRE_LEN, MOD_ALT, MOD_CTRL, MOD_META, MOD_SHIFT,
    MOUSE_BUTTONS_VALID_MASK, MOUSE_EVENT_WIRE_LEN,
};
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
pub use session::{
    parse_request_idr, parse_session_close, DecodedVideoDelivery, DesktopControllerSession,
    DesktopHostSession, PublishedFrameInfo, SessionError, CTRL_MSG_REQUEST_IDR,
    CTRL_MSG_SESSION_CLOSE, PENDING_VIDEO_QUEUE_CAP,
};
pub use video::{
    compute_y_psnr, compute_y_ssim, generate_animated_i420, EncodedV2Frame, FrameQualityMetrics,
    I420Frame, V2VideoDecoder, V2VideoEncoder, VideoCodec, VideoError, CODEC_ID_AV1, CODEC_ID_VP9,
    MAX_FRAME_DIM,
};
