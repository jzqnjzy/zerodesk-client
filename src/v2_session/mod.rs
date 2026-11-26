pub mod capture;
pub mod hid;
pub mod input;
pub mod session;
pub mod video;

pub use capture::{
    bgra_to_i420_bt601, compute_y_variance, crop_and_validate_dimensions, detect_visual_marker,
    overlay_visual_marker, spawn_capture_pipeline, CaptureError, CapturePipelineHandle,
    CaptureStats, CapturedFrame, ScrapDisplaySource, ScreenCaptureSource, SharedVisualMarker,
    SyntheticAnimatedSource, VisualMarkerCheck, DEFAULT_SYNTHETIC_HEIGHT, DEFAULT_SYNTHETIC_WIDTH,
    MIN_CAPTURE_DIM, ZERO_VARIANCE_WARN_THRESHOLD,
};
pub use hid::{
    coalesce_hid_batch, decode_hid_frame, encode_hid_frame, HidBatchOutcome, HidCodecError,
    HidEchoAck, HidPayload, KeyEvent, MouseEvent, MouseKind, HID_ECHO_ACK_WIRE_LEN,
    HID_MSG_ECHO_ACK, HID_MSG_KEY, HID_MSG_MOUSE, KEY_EVENT_WIRE_LEN, MOD_ALT, MOD_CTRL, MOD_META,
    MOD_SHIFT, MOUSE_BUTTONS_VALID_MASK, MOUSE_EVENT_WIRE_LEN,
};
#[cfg(all(
    feature = "os-input",
    not(any(target_os = "android", target_os = "ios"))
))]
pub use input::EnigoOsSink;
pub use input::{
    spawn_release_watchdog, AuditKey, AuditRecord, DryRunOp, DryRunSink, HidInputExecutor,
    HidInputSink, InputError, InputSinkError, ReleaseAllResult, ReleaseAllSummary, SafeHidKey,
    WatchdogHandle, DEFAULT_AUDIT_LOG_CAP, DEFAULT_HID_RATE_LIMIT_PER_SEC, MAX_HID_BATCH_SIZE,
    MOUSE_BUTTON_BACK, MOUSE_BUTTON_FORWARD, MOUSE_BUTTON_LEFT, MOUSE_BUTTON_MIDDLE,
    MOUSE_BUTTON_RIGHT,
};
pub use session::{
    parse_session_close, DecodedVideoDelivery, DesktopControllerSession, DesktopHostSession,
    PublishedFrameInfo, SessionError, CTRL_MSG_SESSION_CLOSE, PENDING_VIDEO_QUEUE_CAP,
};
pub use video::{
    compute_y_psnr, compute_y_ssim, generate_animated_i420, EncodedV2Frame, FrameQualityMetrics,
    I420Frame, V2VideoDecoder, V2VideoEncoder, VideoCodec, VideoError, CODEC_ID_AV1, CODEC_ID_VP9,
    MAX_FRAME_DIM,
};
