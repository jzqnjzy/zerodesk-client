// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub mod controller;
pub mod events;
pub mod json_abi;
pub mod runtime;

pub use controller::{
    load_config_json, save_config_json, BridgeEvent, BridgePersistedConfig, BridgeResponseEnvelope,
    BridgeSnapshot, BridgeState, PolicySummary, RedactedConfigView, V2BridgeController,
    VerifiedCallerDisplay, BRIDGE_ABI_VERSION, BRIDGE_EVENT_QUEUE_CAP,
};
pub use events::{BridgeEventHub, CRITICAL_EVENT_QUEUE_CAP};
pub use json_abi::{
    parse_and_validate_command, scan_json_for_secret_canaries, RuntimeCommandEnvelope,
    RuntimeReplyEnvelope,
};
pub use runtime::{
    V2BridgeRuntime, V2BridgeRuntimeOptions, DEFAULT_RING_TIMEOUT, SYNC_CMD_TIMEOUT,
    UNIFIED_SHUTDOWN_BUDGET,
};
