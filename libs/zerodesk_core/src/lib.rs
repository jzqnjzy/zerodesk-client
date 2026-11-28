// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub mod bridge;
pub mod ffi_abi;
pub mod frame;
pub mod os;
pub mod session;

pub use bridge::{
    load_config_json, parse_bridge_event_forward_compat, save_config_json, BridgeEvent,
    BridgeEventHub, BridgePersistedConfig, BridgeResponseEnvelope, BridgeSnapshot, BridgeState,
    ClipboardSyncStatusPayload, CodecAckPayload, FileTransferCompletePayload,
    HandshakeCapabilitiesData, HudStatsPayload, InputEnabledAckPayload, ParsedBridgeEvent,
    PolicySummary, RedactedConfigView, RuntimeCommandEnvelope, RuntimeReplyEnvelope,
    V2BridgeController, V2BridgeRuntime, V2BridgeRuntimeOptions, VerifiedCallerDisplay,
    VideoQualityAckPayload, BRIDGE_ABI_VERSION, BRIDGE_EVENT_QUEUE_CAP, BRIDGE_JSON_ABI_V2,
    BRIDGE_V2_CAPABILITIES,
};
pub use frame::{
    checked_frame_byte_len, DecodedFrame, FrameError, FrameInfo, FrameMailbox, FramePool,
    PixelFormat,
};
pub use os::{
    input::{
        GatedOsHidSink, OsInputGateError, PermissionProbe, PermissionProbeSource,
        PermissionStatusReport, SystemPermissionProbe,
    },
    os_selftest, CaptureError, CapturedFrame, CapturedSurface, CursorMetadata, CursorShapeKind,
    D3d11SurfaceFormat, HardwareCodec, HardwareCodecEvent, HardwareCodecKind, HardwareCodecState,
    HardwareEncodedPacket, HardwareVideoDecoder, HardwareVideoEncoder, HidWatchdogBackend,
    InputPrivilegeStatus, MacVtHardwareDecoder, MacVtHardwareEncoder, OsError, OsHidSinkInjector,
    OsInputInjector, OsPermission, OsScreenCaptureAdapter, OsSelftestReport, ScreenCapturer,
    UnixHidWatchdogBackend, HW_DECODER_FAILED_RENEGOTIATE_EVENT,
    HW_ENCODER_FAILED_RENEGOTIATE_EVENT,
};
