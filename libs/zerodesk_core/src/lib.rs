// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub mod bridge;
pub mod ffi_abi;
pub mod frame;
pub mod os;
pub mod session;

pub use bridge::{
    load_config_json, save_config_json, BridgeEvent, BridgeEventHub, BridgePersistedConfig,
    BridgeResponseEnvelope, BridgeSnapshot, BridgeState, PolicySummary, RedactedConfigView,
    RuntimeCommandEnvelope, RuntimeReplyEnvelope, V2BridgeController, V2BridgeRuntime,
    V2BridgeRuntimeOptions, VerifiedCallerDisplay, BRIDGE_ABI_VERSION, BRIDGE_EVENT_QUEUE_CAP,
};
pub use frame::{
    checked_frame_byte_len, DecodedFrame, FrameError, FrameInfo, FrameMailbox, FramePool,
    PixelFormat,
};
pub use os::{os_selftest, OsError, OsPermission, OsSelftestReport};
