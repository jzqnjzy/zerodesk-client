// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use super::{OsAudioCapture, OsAudioPlayback, OsError};
use serde::{Deserialize, Serialize};
use std::{
    cell::UnsafeCell,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};

pub const OS_AUDIO_SAMPLE_RATE: u32 = 48_000;
pub const OS_AUDIO_CHANNELS: u16 = 2;
/// 20ms stereo 48kHz frame = 960 * 2 = 1920 f32 samples.
pub const OS_AUDIO_FRAME_SAMPLES: usize = 960 * 2;
/// Power-of-two capacity holding ~200ms of stereo 48kHz audio (16384 * 2 > 19200 -> 32768).
pub const SPSC_AUDIO_RING_CAP: usize = 32_768;

/// Lock-free, allocation-free SPSC ring buffer for real-time CoreAudio / WASAPI / ALSA callbacks.
/// Guaranteed zero locks and zero heap allocations in `push_slice` / `pop_slice`.
struct SpscRingInner {
    buf: UnsafeCell<[f32; SPSC_AUDIO_RING_CAP]>,
    write_idx: AtomicUsize,
    read_idx: AtomicUsize,
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
    let inner = Arc::new(SpscRingInner {
        buf: UnsafeCell::new([0.0; SPSC_AUDIO_RING_CAP]),
        write_idx: AtomicUsize::new(0),
        read_idx: AtomicUsize::new(0),
    });
    (
        SpscAudioProducer {
            inner: Arc::clone(&inner),
        },
        SpscAudioConsumer { inner },
    )
}

impl SpscAudioProducer {
    /// Pushes as many samples as fit without blocking, locking, or allocating.
    /// Returns the number of samples written.
    pub fn push_slice(&mut self, samples: &[f32]) -> usize {
        let mask = SPSC_AUDIO_RING_CAP - 1;
        let w = self.inner.write_idx.load(Ordering::Relaxed);
        let r = self.inner.read_idx.load(Ordering::Acquire);
        let used = w.wrapping_sub(r);
        let free = SPSC_AUDIO_RING_CAP.saturating_sub(used);
        let n = samples.len().min(free);
        if n == 0 {
            return 0;
        }
        let ptr = self.inner.buf.get() as *mut f32;
        for (i, &sample) in samples[..n].iter().enumerate() {
            let slot = w.wrapping_add(i) & mask;
            // SAFETY: sole producer owns slots `[w .. w + n)` which are disjoint from consumer's `[r .. w)`.
            unsafe {
                ptr.add(slot).write(sample);
            }
        }
        self.inner
            .write_idx
            .store(w.wrapping_add(n), Ordering::Release);
        n
    }
}

impl SpscAudioConsumer {
    pub fn available(&self) -> usize {
        let w = self.inner.write_idx.load(Ordering::Acquire);
        let r = self.inner.read_idx.load(Ordering::Relaxed);
        w.wrapping_sub(r)
    }

    /// Pops up to `out.len()` samples without blocking, locking, or allocating.
    /// Returns the number of samples read.
    pub fn pop_slice(&mut self, out: &mut [f32]) -> usize {
        let mask = SPSC_AUDIO_RING_CAP - 1;
        let r = self.inner.read_idx.load(Ordering::Relaxed);
        let w = self.inner.write_idx.load(Ordering::Acquire);
        let avail = w.wrapping_sub(r);
        let n = out.len().min(avail);
        if n == 0 {
            return 0;
        }
        let ptr = self.inner.buf.get() as *const f32;
        for (i, dst) in out[..n].iter_mut().enumerate() {
            let slot = r.wrapping_add(i) & mask;
            // SAFETY: sole consumer owns slots `[r .. r + n)` published by producer with Release.
            *dst = unsafe { ptr.add(slot).read() };
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
                Some("no audio devices detected; session degrades gracefully to silent audio".into())
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

    pub struct CpalAudioCapture {
        _stream: cpal::Stream,
        consumer: SpscAudioConsumer,
    }

    // SAFETY: `cpal::Stream` is kept alive only until dropped on the owning capture thread/struct.
    unsafe impl Send for CpalAudioCapture {}

    impl CpalAudioCapture {
        pub fn try_open() -> Result<Self, AudioStatusChanged> {
            let host = cpal::default_host();
            let device = host.default_input_device().ok_or_else(|| AudioStatusChanged {
                available: false,
                reason: Some("no default audio input device".into()),
            })?;
            let supported = device
                .supported_input_configs()
                .map_err(|e| AudioStatusChanged {
                    available: false,
                    reason: Some(format!("input configs unavailable: {e}")),
                })?
                .find(|cfg| {
                    cfg.channels() == OS_AUDIO_CHANNELS
                        && cfg.sample_format() == SampleFormat::F32
                        && cfg.min_sample_rate().0 <= OS_AUDIO_SAMPLE_RATE
                        && cfg.max_sample_rate().0 >= OS_AUDIO_SAMPLE_RATE
                })
                .ok_or_else(|| AudioStatusChanged {
                    available: false,
                    reason: Some("48kHz/2ch/f32 capture format not supported by default device".into()),
                })?;
            let config: StreamConfig = supported
                .with_sample_rate(cpal::SampleRate(OS_AUDIO_SAMPLE_RATE))
                .into();
            let (mut producer, consumer) = create_spsc_audio_ring();
            let stream = device
                .build_input_stream(
                    &config,
                    move |data: &[f32], _| {
                        // Lock-free, alloc-free real-time CoreAudio callback.
                        let _ = producer.push_slice(data);
                    },
                    |_err| {},
                    None,
                )
                .map_err(|e| AudioStatusChanged {
                    available: false,
                    reason: Some(format!("build_input_stream failed: {e}")),
                })?;
            stream.play().map_err(|e| AudioStatusChanged {
                available: false,
                reason: Some(format!("input stream play failed: {e}")),
            })?;
            Ok(Self {
                _stream: stream,
                consumer,
            })
        }
    }

    impl OsAudioCapture for CpalAudioCapture {
        fn read_frame(&mut self, out_pcm: &mut [f32]) -> Result<bool, OsError> {
            if self.consumer.available() < out_pcm.len() {
                return Ok(false);
            }
            let n = self.consumer.pop_slice(out_pcm);
            Ok(n == out_pcm.len())
        }
    }

    pub struct CpalAudioPlayback {
        _stream: cpal::Stream,
        producer: SpscAudioProducer,
    }

    // SAFETY: `cpal::Stream` is kept alive only until dropped on the owning playback struct.
    unsafe impl Send for CpalAudioPlayback {}

    impl CpalAudioPlayback {
        pub fn try_open() -> Result<Self, AudioStatusChanged> {
            let host = cpal::default_host();
            let device = host.default_output_device().ok_or_else(|| AudioStatusChanged {
                available: false,
                reason: Some("no default audio output device".into()),
            })?;
            let supported = device
                .supported_output_configs()
                .map_err(|e| AudioStatusChanged {
                    available: false,
                    reason: Some(format!("output configs unavailable: {e}")),
                })?
                .find(|cfg| {
                    cfg.channels() == OS_AUDIO_CHANNELS
                        && cfg.sample_format() == SampleFormat::F32
                        && cfg.min_sample_rate().0 <= OS_AUDIO_SAMPLE_RATE
                        && cfg.max_sample_rate().0 >= OS_AUDIO_SAMPLE_RATE
                })
                .ok_or_else(|| AudioStatusChanged {
                    available: false,
                    reason: Some("48kHz/2ch/f32 playback format not supported by default device".into()),
                })?;
            let config: StreamConfig = supported
                .with_sample_rate(cpal::SampleRate(OS_AUDIO_SAMPLE_RATE))
                .into();
            let (producer, mut consumer) = create_spsc_audio_ring();
            let stream = device
                .build_output_stream(
                    &config,
                    move |out: &mut [f32], _| {
                        // Lock-free, alloc-free real-time CoreAudio callback.
                        let n = consumer.pop_slice(out);
                        if n < out.len() {
                            out[n..].fill(0.0);
                        }
                    },
                    |_err| {},
                    None,
                )
                .map_err(|e| AudioStatusChanged {
                    available: false,
                    reason: Some(format!("build_output_stream failed: {e}")),
                })?;
            stream.play().map_err(|e| AudioStatusChanged {
                available: false,
                reason: Some(format!("output stream play failed: {e}")),
            })?;
            Ok(Self {
                _stream: stream,
                producer,
            })
        }
    }

    impl OsAudioPlayback for CpalAudioPlayback {
        fn write_frame(&mut self, pcm: &[f32]) -> Result<(), OsError> {
            let _ = self.producer.push_slice(pcm);
            Ok(())
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
    fn spsc_audio_ring_lock_free_roundtrip_and_wraparound() {
        let (mut tx, mut rx) = create_spsc_audio_ring();
        let frame_in: Vec<f32> = (0..OS_AUDIO_FRAME_SAMPLES)
            .map(|i| (i as f32) * 0.001)
            .collect();
        let mut frame_out = vec![0.0f32; OS_AUDIO_FRAME_SAMPLES];
        // Exercise multiple full wrap-arounds of the 32768-sample ring.
        for round in 0..40 {
            let pushed = tx.push_slice(&frame_in);
            assert_eq!(pushed, OS_AUDIO_FRAME_SAMPLES, "round {round}");
            let popped = rx.pop_slice(&mut frame_out);
            assert_eq!(popped, OS_AUDIO_FRAME_SAMPLES, "round {round}");
            assert_eq!(frame_in, frame_out);
        }
        assert_eq!(rx.available(), 0);
    }
}
