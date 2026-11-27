// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub use zerodesk_core::bridge::{
    load_config_json, save_config_json, BridgeEvent, BridgePersistedConfig, BridgeResponseEnvelope,
    BridgeSnapshot, BridgeState, PolicySummary, RedactedConfigView, V2BridgeController,
    V2BridgeRuntime, V2BridgeRuntimeOptions, VerifiedCallerDisplay, BRIDGE_ABI_VERSION,
    BRIDGE_EVENT_QUEUE_CAP,
};
pub use zerodesk_core::session::*;
