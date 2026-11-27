// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{OsAudioCapture, OsAudioPlayback, OsError};
use serde::{Deserialize, Serialize};
use std::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};

pub const OS_AUDIO_SAMPLE_RATE: u32 = 48_000;
pub const OS_AUDIO_CHANNELS: u16 = 2;
/// 20ms stereo 48kHz frame = 960 * 2 = 1920 f32 samples.
pub const OS_AUDIO_FRAME_SAMPLES: usize = 960 * 2;
/// Exact frame-aligned ring capacity: 16 frames * 1920 samples = 30,720 samples (320 ms).
pub const SPSC_AUDIO_RING_FRAMES: usize = 16;
pub const SPSC_AUDIO_RING_CAP: usize = SPSC_AUDIO_RING_FRAMES * OS_AUDIO_FRAME_SAMPLES;
/// Low-latency backlog cap: if buffered audio reaches >= 4 frames (80 ms), drop oldest whole
/// frames down to 2 frames (40 ms) so playout/capture latency never latches high.
pub const AUDIO_MAX_BACKLOG_FRAMES: usize = 4;
pub const AUDIO_TARGET_BACKLOG_FRAMES: usize = 2;

/// Lock-free, allocation-free SPSC ring buffer for real-time CoreAudio / WASAPI / ALSA callbacks.
/// Backing buffer is heap-allocated (`Box<[UnsafeCell<f32>]>` -> never places >120 KiB on stack)
/// and holds an exact integer multiple of stereo 20ms frames (`30,720` f32 samples = 320 ms).
struct SpscRingInner {
    buf: Box<[UnsafeCell<f32>]>,
    write_idx: AtomicUsize,
    read_idx: AtomicUsize,
    dropped_frames: AtomicU64,
}

// SAFETY: Access to `buf` is strictly partitioned between the sole `SpscAudioProducer`
// (writing `[write_idx .. read_idx + CAP)`) and the sole `SpscAudioConsumer`
// (reading `[read_idx .. write_idx)`), synchronized via `Acquire`/`Release` on `write_idx`/`read_idx`.
unsafe impl Sync for SpscRingInner {}

pub struct SpscAudioProducer {
    inner: Arc<SpscRingInner>,
}

pub struct SpscAudioConsumer {
    inner: Arc<SpscRingInner>,
}

pub fn create_spsc_audio_ring() -> (SpscAudioProducer, SpscAudioConsumer) {
    let mut vec = Vec::with_capacity(SPSC_AUDIO_RING_CAP);
    for _ in 0..SPSC_AUDIO_RING_CAP {
        vec.push(UnsafeCell::new(0.0));
    }
    let inner = Arc::new(SpscRingInner {
        buf: vec.into_boxed_slice(),
        write_idx: AtomicUsize::new(0),
        read_idx: AtomicUsize::new(0),
        dropped_frames: AtomicU64::new(0),
    });
    (
        SpscAudioProducer {
            inner: Arc::clone(&inner),
        },
        SpscAudioConsumer { inner },
    )
}

impl SpscAudioProducer {
    /// Pushes as many samples as fit without blocking, locking, or allocating (for RT callbacks).
    pub fn push_slice(&mut self, samples: &[f32]) -> usize {
        let cap = self.inner.buf.len();
        let w = self.inner.write_idx.load(Ordering::Relaxed);
        let r = self.inner.read_idx.load(Ordering::Acquire);
        let used = w.wrapping_sub(r);
        let free = cap.saturating_sub(used);
        let n = samples.len().min(free);
        if n == 0 {
            if !samples.is_empty() {
                self.inner.dropped_frames.fetch_add(1, Ordering::Relaxed);
            }
            return 0;
        }
        for (i, &sample) in samples[..n].iter().enumerate() {
            let slot = w.wrapping_add(i) % cap;
            // SAFETY: sole producer owns slots `[w .. w + n)` disjoint from consumer `[r .. w)`.
            unsafe {
                *self.inner.buf[slot].get() = sample;
            }
        }
        self.inner
            .write_idx
            .store(w.wrapping_add(n), Ordering::Release);
        n
    }

    /// Whole-frame admission: either writes all `frame.len()` samples or rejects the entire frame
    /// (incrementing `dropped_frames`) so stereo frames are never torn.
    pub fn push_whole_frame(&mut self, frame: &[f32]) -> bool {
        let cap = self.inner.buf.len();
        let w = self.inner.write_idx.load(Ordering::Relaxed);
        let r = self.inner.read_idx.load(Ordering::Acquire);
        let used = w.wrapping_sub(r);
        let free = cap.saturating_sub(used);
        if free < frame.len() {
            self.inner.dropped_frames.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        for (i, &sample) in frame.iter().enumerate() {
            let slot = w.wrapping_add(i) % cap;
            unsafe {
                *self.inner.buf[slot].get() = sample;
            }
        }
        self.inner
            .write_idx
            .store(w.wrapping_add(frame.len()), Ordering::Release);
        true
    }

    pub fn dropped_frames(&self) -> u64 {
        self.inner.dropped_frames.load(Ordering::Relaxed)
    }
}

impl SpscAudioConsumer {
    pub fn available(&self) -> usize {
        let w = self.inner.write_idx.load(Ordering::Acquire);
        let r = self.inner.read_idx.load(Ordering::Relaxed);
        w.wrapping_sub(r)
    }

    pub fn dropped_frames(&self) -> u64 {
        self.inner.dropped_frames.load(Ordering::Relaxed)
    }

    /// Drops oldest whole frames when backlog >= `AUDIO_MAX_BACKLOG_FRAMES` so latency stays low.
    pub fn trim_backlog_to_low_latency(&mut self) -> u64 {
        let max_samples = AUDIO_MAX_BACKLOG_FRAMES * OS_AUDIO_FRAME_SAMPLES;
        let target_samples = AUDIO_TARGET_BACKLOG_FRAMES * OS_AUDIO_FRAME_SAMPLES;
        let r = self.inner.read_idx.load(Ordering::Relaxed);
        let w = self.inner.write_idx.load(Ordering::Acquire);
        let avail = w.wrapping_sub(r);
        if avail < max_samples {
            return 0;
        }
        let excess = avail.saturating_sub(target_samples);
        let frames_to_drop = excess / OS_AUDIO_FRAME_SAMPLES;
        if frames_to_drop == 0 {
            return 0;
        }
        let samples_to_drop = frames_to_drop * OS_AUDIO_FRAME_SAMPLES;
        self.inner
            .read_idx
            .store(r.wrapping_add(samples_to_drop), Ordering::Release);
        self.inner
            .dropped_frames
            .fetch_add(frames_to_drop as u64, Ordering::Relaxed);
        frames_to_drop as u64
    }

    /// Pops up to `out.len()` samples without blocking, locking, or allocating.
    pub fn pop_slice(&mut self, out: &mut [f32]) -> usize {
        let cap = self.inner.buf.len();
        let r = self.inner.read_idx.load(Ordering::Relaxed);
        let w = self.inner.write_idx.load(Ordering::Acquire);
        let avail = w.wrapping_sub(r);
        let n = out.len().min(avail);
        if n == 0 {
            return 0;
        }
        for (i, dst) in out[..n].iter_mut().enumerate() {
            let slot = r.wrapping_add(i) % cap;
            // SAFETY: sole consumer owns slots `[r .. r + n)` published by producer with Release.
            *dst = unsafe { *self.inner.buf[slot].get() };
        }
        self.inner
            .read_idx
            .store(r.wrapping_add(n), Ordering::Release);
        n
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioStatusChanged {
    pub available: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AudioDeviceProbe {
    pub available: bool,
    pub input_device_count: usize,
    pub output_device_count: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

/// Read-only audio device count probe for `os-selftest` (never opens an audio stream, never fails
/// when zero devices exist).
pub fn probe_audio_devices() -> AudioDeviceProbe {
    #[cfg(feature = "os-audio")]
    {
        use cpal::traits::HostTrait;
        let host = cpal::default_host();
        let input_count = host.input_devices().map(|it| it.count()).unwrap_or(0);
        let output_count = host.output_devices().map(|it| it.count()).unwrap_or(0);
        AudioDeviceProbe {
            available: input_count > 0 || output_count > 0,
            input_device_count: input_count,
            output_device_count: output_count,
            note: if input_count == 0 && output_count == 0 {
                Some(
                    "no audio devices detected; session degrades gracefully to silent audio".into(),
                )
            } else {
                None
            },
        }
    }
    #[cfg(not(feature = "os-audio"))]
    {
        AudioDeviceProbe {
            available: false,
            input_device_count: 0,
            output_device_count: 0,
            note: Some("os-audio feature disabled at compile time".into()),
        }
    }
}

#[cfg(feature = "os-audio")]
mod cpal_impl {
    use super::*;
    use cpal::traits::{DeviceTrait, HostTrait, StreamTrait};
    use cpal::{SampleFormat, StreamConfig};
    use std::{
        sync::mpsc,
        thread::{self, JoinHandle},
        time::Duration,
    };

    /// Owns the `!Send` `cpal::Stream` exclusively on a dedicated named OS thread
    /// (`"zerodesk-audio-in"`), so `CpalAudioCapture` is naturally `Send` with ZERO `unsafe impl Send`.
    pub struct CpalAudioCapture {
        consumer: SpscAudioConsumer,
        stop_tx: Option<mpsc::SyncSender<()>>,
        stream_failed: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl CpalAudioCapture {
        pub fn try_open() -> Result<Self, AudioStatusChanged> {
            let (mut producer, consumer) = create_spsc_audio_ring();
            let (init_tx, init_rx) = mpsc::sync_channel::<Result<(), AudioStatusChanged>>(1);
            let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
            let stream_failed = Arc::new(AtomicBool::new(false));
            let failed_cb = Arc::clone(&stream_failed);

            let worker = thread::Builder::new()
                .name("zerodesk-audio-in".to_string())
                .spawn(move || {
                    let host = cpal::default_host();
                    let Some(device) = host.default_input_device() else {
                        let _ = init_tx.send(Err(AudioStatusChanged {
                            available: false,
                            reason: Some("no default audio input device".into()),
                        }));
                        return;
                    };
                    let supported = match device.supported_input_configs() {
                        Ok(mut it) => it.find(|cfg| {
                            cfg.channels() == OS_AUDIO_CHANNELS
                                && cfg.sample_format() == SampleFormat::F32
                                && cfg.min_sample_rate().0 <= OS_AUDIO_SAMPLE_RATE
                                && cfg.max_sample_rate().0 >= OS_AUDIO_SAMPLE_RATE
                        }),
                        Err(e) => {
                            let _ = init_tx.send(Err(AudioStatusChanged {
                                available: false,
                                reason: Some(format!("input configs unavailable: {e}")),
                            }));
                            return;
                        }
                    };
                    let Some(supported) = supported else {
                        let _ = init_tx.send(Err(AudioStatusChanged {
                            available: false,
                            reason: Some(
                                "48kHz/2ch/f32 capture format not supported by default device"
                                    .into(),
                            ),
                        }));
                        return;
                    };
                    let config: StreamConfig = supported
                        .with_sample_rate(cpal::SampleRate(OS_AUDIO_SAMPLE_RATE))
                        .into();
                    let stream = match device.build_input_stream(
                        &config,
                        move |data: &[f32], _| {
                            let _ = producer.push_slice(data);
                        },
                        move |_err| {
                            failed_cb.store(true, Ordering::Release);
                        },
                        None,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = init_tx.send(Err(AudioStatusChanged {
                                available: false,
                                reason: Some(format!("build_input_stream failed: {e}")),
                            }));
                            return;
                        }
                    };
                    if let Err(e) = stream.play() {
                        let _ = init_tx.send(Err(AudioStatusChanged {
                            available: false,
                            reason: Some(format!("input stream play failed: {e}")),
                        }));
                        return;
                    }
                    let _ = init_tx.send(Ok(()));
                    // Keep `!Send` stream alive on this dedicated thread until shutdown.
                    let _ = stop_rx.recv();
                    drop(stream);
                })
                .map_err(|e| AudioStatusChanged {
                    available: false,
                    reason: Some(format!("spawn audio-in thread failed: {e}")),
                })?;

            match init_rx.recv_timeout(Duration::from_secs(3)) {
                Ok(Ok(())) => Ok(Self {
                    consumer,
                    stop_tx: Some(stop_tx),
                    stream_failed,
                    worker: Some(worker),
                }),
                Ok(Err(status)) => {
                    let _ = worker.join();
                    Err(status)
                }
                Err(_) => {
                    let _ = stop_tx.try_send(());
                    Err(AudioStatusChanged {
                        available: false,
                        reason: Some("audio input stream init timed out".into()),
                    })
                }
            }
        }

        pub fn dropped_frames(&self) -> u64 {
            self.consumer.dropped_frames()
        }

        pub fn has_stream_error(&self) -> bool {
            self.stream_failed.load(Ordering::Acquire)
        }
    }

    impl Drop for CpalAudioCapture {
        fn drop(&mut self) {
            if let Some(tx) = self.stop_tx.take() {
                let _ = tx.try_send(());
            }
            // Do not block a Tokio worker thread on drop; the dedicated audio thread exits promptly
            // once `stop_tx` drops/signals and drops `cpal::Stream` on its own OS thread.
            let _ = self.worker.take();
        }
    }

    impl OsAudioCapture for CpalAudioCapture {
        fn read_frame(&mut self, out_pcm: &mut [f32]) -> Result<bool, OsError> {
            if out_pcm.len() != OS_AUDIO_FRAME_SAMPLES {
                return Err(OsError::InvalidData(format!(
                    "expected {OS_AUDIO_FRAME_SAMPLES} PCM samples, got {}",
                    out_pcm.len()
                )));
            }
            if self.stream_failed.load(Ordering::Acquire) {
                return Err(OsError::AudioUnavailable(
                    "audio capture stream reported device error".into(),
                ));
            }
            let _ = self.consumer.trim_backlog_to_low_latency();
            if self.consumer.available() < out_pcm.len() {
                return Ok(false);
            }
            let n = self.consumer.pop_slice(out_pcm);
            Ok(n == out_pcm.len())
        }

        fn dropped_frames(&self) -> u64 {
            CpalAudioCapture::dropped_frames(self)
        }

        fn has_stream_error(&self) -> bool {
            CpalAudioCapture::has_stream_error(self)
        }
    }

    /// Owns the `!Send` `cpal::Stream` exclusively on a dedicated named OS thread
    /// (`"zerodesk-audio-out"`), so `CpalAudioPlayback` is naturally `Send` with ZERO `unsafe impl Send`.
    pub struct CpalAudioPlayback {
        producer: SpscAudioProducer,
        stop_tx: Option<mpsc::SyncSender<()>>,
        stream_failed: Arc<AtomicBool>,
        worker: Option<JoinHandle<()>>,
    }

    impl CpalAudioPlayback {
        pub fn try_open() -> Result<Self, AudioStatusChanged> {
            let (producer, mut consumer) = create_spsc_audio_ring();
            let (init_tx, init_rx) = mpsc::sync_channel::<Result<(), AudioStatusChanged>>(1);
            let (stop_tx, stop_rx) = mpsc::sync_channel::<()>(1);
            let stream_failed = Arc::new(AtomicBool::new(false));
            let failed_cb = Arc::clone(&stream_failed);

            let worker = thread::Builder::new()
                .name("zerodesk-audio-out".to_string())
                .spawn(move || {
                    let host = cpal::default_host();
                    let Some(device) = host.default_output_device() else {
                        let _ = init_tx.send(Err(AudioStatusChanged {
                            available: false,
                            reason: Some("no default audio output device".into()),
                        }));
                        return;
                    };
                    let supported = match device.supported_output_configs() {
                        Ok(mut it) => it.find(|cfg| {
                            cfg.channels() == OS_AUDIO_CHANNELS
                                && cfg.sample_format() == SampleFormat::F32
                                && cfg.min_sample_rate().0 <= OS_AUDIO_SAMPLE_RATE
                                && cfg.max_sample_rate().0 >= OS_AUDIO_SAMPLE_RATE
                        }),
                        Err(e) => {
                            let _ = init_tx.send(Err(AudioStatusChanged {
                                available: false,
                                reason: Some(format!("output configs unavailable: {e}")),
                            }));
                            return;
                        }
                    };
                    let Some(supported) = supported else {
                        let _ = init_tx.send(Err(AudioStatusChanged {
                            available: false,
                            reason: Some(
                                "48kHz/2ch/f32 playback format not supported by default device"
                                    .into(),
                            ),
                        }));
                        return;
                    };
                    let config: StreamConfig = supported
                        .with_sample_rate(cpal::SampleRate(OS_AUDIO_SAMPLE_RATE))
                        .into();
                    let stream = match device.build_output_stream(
                        &config,
                        move |out: &mut [f32], _| {
                            let n = consumer.pop_slice(out);
                            if n < out.len() {
                                out[n..].fill(0.0);
                            }
                        },
                        move |_err| {
                            failed_cb.store(true, Ordering::Release);
                        },
                        None,
                    ) {
                        Ok(s) => s,
                        Err(e) => {
                            let _ = init_tx.send(Err(AudioStatusChanged {
                                available: false,
                                reason: Some(format!("build_output_stream failed: {e}")),
                            }));
                            return;
                        }
                    };
                    if let Err(e) = stream.play() {
                        let _ = init_tx.send(Err(AudioStatusChanged {
                            available: false,
                            reason: Some(format!("output stream play failed: {e}")),
                        }));
                        return;
                    }
                    let _ = init_tx.send(Ok(()));
                    let _ = stop_rx.recv();
                    drop(stream);
                })
                .map_err(|e| AudioStatusChanged {
                    available: false,
                    reason: Some(format!("spawn audio-out thread failed: {e}")),
                })?;

            match init_rx.recv_timeout(Duration::from_secs(3)) {
                Ok(Ok(())) => Ok(Self {
                    producer,
                    stop_tx: Some(stop_tx),
                    stream_failed,
                    worker: Some(worker),
                }),
                Ok(Err(status)) => {
                    let _ = worker.join();
                    Err(status)
                }
                Err(_) => {
                    let _ = stop_tx.try_send(());
                    Err(AudioStatusChanged {
                        available: false,
                        reason: Some("audio output stream init timed out".into()),
                    })
                }
            }
        }

        pub fn dropped_frames(&self) -> u64 {
            self.producer.dropped_frames()
        }

        pub fn has_stream_error(&self) -> bool {
            self.stream_failed.load(Ordering::Acquire)
        }
    }

    impl Drop for CpalAudioPlayback {
        fn drop(&mut self) {
            if let Some(tx) = self.stop_tx.take() {
                let _ = tx.try_send(());
            }
            let _ = self.worker.take();
        }
    }

    impl OsAudioPlayback for CpalAudioPlayback {
        fn write_frame(&mut self, pcm: &[f32]) -> Result<bool, OsError> {
            if pcm.len() != OS_AUDIO_FRAME_SAMPLES {
                return Err(OsError::InvalidData(format!(
                    "expected {OS_AUDIO_FRAME_SAMPLES} PCM samples, got {}",
                    pcm.len()
                )));
            }
            if self.stream_failed.load(Ordering::Acquire) {
                return Err(OsError::AudioUnavailable(
                    "audio playback stream reported device error".into(),
                ));
            }
            Ok(self.producer.push_whole_frame(pcm))
        }

        fn dropped_frames(&self) -> u64 {
            CpalAudioPlayback::dropped_frames(self)
        }

        fn has_stream_error(&self) -> bool {
            CpalAudioPlayback::has_stream_error(self)
        }
    }
}

pub fn open_os_audio_capture() -> Result<Box<dyn OsAudioCapture>, AudioStatusChanged> {
    #[cfg(feature = "os-audio")]
    {
        cpal_impl::CpalAudioCapture::try_open().map(|c| Box::new(c) as Box<dyn OsAudioCapture>)
    }
    #[cfg(not(feature = "os-audio"))]
    {
        Err(AudioStatusChanged {
            available: false,
            reason: Some("os-audio feature disabled".into()),
        })
    }
}

pub fn open_os_audio_playback() -> Result<Box<dyn OsAudioPlayback>, AudioStatusChanged> {
    #[cfg(feature = "os-audio")]
    {
        cpal_impl::CpalAudioPlayback::try_open().map(|p| Box::new(p) as Box<dyn OsAudioPlayback>)
    }
    #[cfg(not(feature = "os-audio"))]
    {
        Err(AudioStatusChanged {
            available: false,
            reason: Some("os-audio feature disabled".into()),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spsc_audio_ring_lock_free_whole_frame_admission_and_backlog_trim() {
        let (mut tx, mut rx) = create_spsc_audio_ring();
        let frame_in: Vec<f32> = (0..OS_AUDIO_FRAME_SAMPLES)
            .map(|i| (i as f32) * 0.001)
            .collect();
        let mut frame_out = vec![0.0f32; OS_AUDIO_FRAME_SAMPLES];

        // Roundtrip across multiple full wrap-arounds
        for round in 0..40 {
            assert!(tx.push_whole_frame(&frame_in), "round {round}");
            let popped = rx.pop_slice(&mut frame_out);
            assert_eq!(popped, OS_AUDIO_FRAME_SAMPLES, "round {round}");
            assert_eq!(frame_in, frame_out);
        }
        assert_eq!(rx.available(), 0);

        // Fill ring completely (16 frames) -> 17th frame rejected atomically (no partial tear)
        for f in 0..SPSC_AUDIO_RING_FRAMES {
            let tagged = vec![f as f32; OS_AUDIO_FRAME_SAMPLES];
            assert!(tx.push_whole_frame(&tagged));
        }
        assert!(!tx.push_whole_frame(&frame_in));
        assert_eq!(tx.dropped_frames(), 1);

        // Backlog trim reduces 16 buffered frames down to 2 newest frames (frames 14 & 15)
        let trimmed = rx.trim_backlog_to_low_latency();
        assert_eq!(trimmed, (SPSC_AUDIO_RING_FRAMES - AUDIO_TARGET_BACKLOG_FRAMES) as u64);
        assert_eq!(rx.available(), AUDIO_TARGET_BACKLOG_FRAMES * OS_AUDIO_FRAME_SAMPLES);
        assert_eq!(rx.pop_slice(&mut frame_out), OS_AUDIO_FRAME_SAMPLES);
        assert!((frame_out[0] - 14.0).abs() < 1e-6);
    }
}
