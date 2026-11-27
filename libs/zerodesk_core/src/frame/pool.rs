// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

pub const DEFAULT_FRAME_POOL_CAP: usize = 4;

/// Lock-minimal buffer pool that ONLY recycles a `DecodedFrame` pixel buffer when
/// `Arc::try_unwrap` succeeds (proving zero UI readers still hold a reference).
pub struct FramePool {
    max_pooled: usize,
    buffers: Mutex<Vec<Vec<u8>>>,
    recycled_hits: AtomicU64,
    alloc_misses: AtomicU64,
    recycle_skipped_in_use: AtomicU64,
}

impl Default for FramePool {
    fn default() -> Self {
        Self::new(DEFAULT_FRAME_POOL_CAP)
    }
}

impl FramePool {
    pub fn new(max_pooled: usize) -> Self {
        Self {
            max_pooled: max_pooled.max(1),
            buffers: Mutex::new(Vec::with_capacity(max_pooled.max(1))),
            recycled_hits: AtomicU64::new(0),
            alloc_misses: AtomicU64::new(0),
            recycle_skipped_in_use: AtomicU64::new(0),
        }
    }

    /// Acquires a buffer of exact length `byte_len`, reusing a pooled allocation if one is
    /// available with sufficient capacity.
    pub fn acquire(&self, byte_len: usize) -> Vec<u8> {
        let reused = {
            let mut pool = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
            pool.iter()
                .position(|b| b.capacity() >= byte_len)
                .map(|idx| pool.swap_remove(idx))
        };
        if let Some(mut buf) = reused {
            self.recycled_hits.fetch_add(1, Ordering::Relaxed);
            buf.resize(byte_len, 0);
            buf
        } else {
            self.alloc_misses.fetch_add(1, Ordering::Relaxed);
            vec![0u8; byte_len]
        }
    }

    /// Recycles `buf` into the pool if capacity remains.
    pub fn release(&self, mut buf: Vec<u8>) {
        if buf.capacity() == 0 {
            return;
        }
        buf.clear();
        let mut pool = self.buffers.lock().unwrap_or_else(|e| e.into_inner());
        if pool.len() < self.max_pooled {
            pool.push(buf);
        }
    }

    /// Zero-tear `Arc::try_unwrap` recycling helper: if `arc` has no other strong references,
    /// extracts its backing buffer via `extract` and returns it to the pool; otherwise drops our
    /// handle without mutating memory held by active UI readers.
    pub fn recycle_arc<T>(&self, arc: Arc<T>, extract: impl FnOnce(T) -> Vec<u8>) -> bool {
        match Arc::try_unwrap(arc) {
            Ok(owned) => {
                self.release(extract(owned));
                true
            }
            Err(_) => {
                self.recycle_skipped_in_use.fetch_add(1, Ordering::Relaxed);
                false
            }
        }
    }

    pub fn pooled_count(&self) -> usize {
        self.buffers.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn recycled_hits(&self) -> u64 {
        self.recycled_hits.load(Ordering::Relaxed)
    }

    pub fn alloc_misses(&self) -> u64 {
        self.alloc_misses.load(Ordering::Relaxed)
    }

    pub fn recycle_skipped_in_use(&self) -> u64 {
        self.recycle_skipped_in_use.load(Ordering::Relaxed)
    }
}
