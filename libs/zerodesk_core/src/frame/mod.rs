// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub mod mailbox;
pub mod pool;

pub use mailbox::{
    checked_frame_byte_len, DecodedFrame, FrameError, FrameInfo, FrameMailbox, PixelFormat,
    MAX_MAILBOX_HEIGHT, MAX_MAILBOX_PIXELS, MAX_MAILBOX_WIDTH,
};
pub use pool::{FramePool, DEFAULT_FRAME_POOL_CAP};
