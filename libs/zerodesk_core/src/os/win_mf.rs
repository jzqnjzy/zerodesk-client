// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(windows)]` Windows Media Foundation Hardware MFT FFI adapter
//! driven by `win_mf_logic`.
//!
//! Mandatory constraints:
//! - Uses Windows Media Foundation ONLY (`MFTEnumEx(MFT_ENUM_FLAG_HARDWARE)` +
//!   `MFT_ENUM_ADAPTER_LUID`); ZERO proprietary NVENC / AMF / QSV SDKs.
//! - Marks `HardwareReady` ONLY after the first IDR keyframe (`MFSampleExtension_CleanPoint`)
//!   encodes with non-zero bytes.
//! - On mid-stream hardware errors: performs bounded MFT reinit retries, then
//!   fails explicitly with `VideoError::CodecFailed` + renegotiation event
//!   (NEVER silently falls back to software MFTs!).

use super::{
    traits::{
        CapturedFrame, CapturedSurface, HardwareCodec, HardwareCodecEvent, HardwareCodecKind,
        HardwareCodecState, HardwareEncodedPacket, HardwareVideoEncoder,
    },
    win_dxgi_logic::DxgiAdapterLuid,
    win_mf_logic::{
        bgra_to_nv12, select_hw_mft_for_luid, ColorMatrix, LuidMatchOutcome, MfErrorDecision,
        MfHwCodec, MfHwEncoderStateMachine, MfHwMftDescriptor, MfHwVendor,
    },
};
use crate::session::video::{I420Frame, VideoError};
use std::ptr;
use windows::{
    core::{GUID, PWSTR},
    Win32::{
        Graphics::Direct3D11::ID3D11Device,
        Media::MediaFoundation::{
            IMFActivate, IMFDXGIDeviceManager, IMFMediaBuffer, IMFMediaType, IMFSample,
            IMFTransform, MFCreateDXGIDeviceManager, MFCreateMediaType, MFCreateMemoryBuffer,
            MFCreateSample, MFShutdown, MFStartup, MFTEnumEx, MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_ADAPTER_LUID, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
            MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_COMMAND_FLUSH,
            MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_START_OF_STREAM,
            MFT_OUTPUT_DATA_BUFFER, MFT_OUTPUT_STREAM_INFO, MFT_REGISTER_TYPE_INFO,
            MFMediaType_Video, MFSampleExtension_CleanPoint,
            MFVideoFormat_AV1, MFVideoFormat_H264, MFVideoFormat_HEVC, MFVideoFormat_NV12,
            MF_E_TRANSFORM_NEED_MORE_INPUT, MF_MT_AVG_BITRATE, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE,
            MF_MT_INTERLACE_MODE, MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE, MF_SA_D3D11_AWARE,
            MF_VERSION, MFSTARTUP_NOSOCKET, MFVideoInterlace_Progressive,
        },
        System::Com::CoTaskMemFree,
    },
};

fn codec_to_mf_subtype(codec: MfHwCodec) -> GUID {
    match codec {
        MfHwCodec::H264 => MFVideoFormat_H264,
        MfHwCodec::Hevc => MFVideoFormat_HEVC,
        MfHwCodec::Av1 => MFVideoFormat_AV1,
    }
}

fn pack_u32_pair(hi: u32, lo: u32) -> u64 {
    (u64::from(hi) << 32) | u64::from(lo)
}

/// RAII guard pairing `MFStartup` with `MFShutdown`.
pub struct MfRuntimeGuard {
    _private: (),
}

impl MfRuntimeGuard {
    pub fn start() -> Result<Self, VideoError> {
        unsafe { MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET) }
            .map_err(|e| VideoError::HardwareUnavailable(format!("MFStartup failed: {e}")))?;
        Ok(Self { _private: () })
    }
}

impl Drop for MfRuntimeGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = MFShutdown();
        }
    }
}

fn read_mft_friendly_name(activate: &IMFActivate) -> String {
    let mut name_ptr = PWSTR::null();
    let mut name_len = 0u32;
    let res = unsafe {
        activate.GetAllocatedString(&MFT_FRIENDLY_NAME_Attribute, &mut name_ptr, &mut name_len)
    };
    if res.is_err() || name_ptr.is_null() {
        return "Unknown Hardware MFT".into();
    }
    let text = unsafe {
        let slice = std::slice::from_raw_parts(name_ptr.0, name_len as usize);
        let s = String::from_utf16_lossy(slice);
        CoTaskMemFree(Some(name_ptr.0.cast()));
        s
    };
    text
}

fn read_mft_descriptor(activate: &IMFActivate, codec: MfHwCodec) -> MfHwMftDescriptor {
    let friendly_name = read_mft_friendly_name(activate);
    let adapter_luid = unsafe { activate.GetUINT64(&MFT_ENUM_ADAPTER_LUID) }
        .ok()
        .map(DxgiAdapterLuid::from_u64);
    let supports_d3d11_aware = unsafe { activate.GetUINT32(&MF_SA_D3D11_AWARE) }
        .map(|v| v != 0)
        .unwrap_or(false);
    let vendor = MfHwVendor::infer_from_friendly_name(&friendly_name);
    MfHwMftDescriptor {
        friendly_name,
        codec,
        adapter_luid,
        is_hardware: true,
        supports_d3d11_aware,
        vendor,
    }
}

/// Enumerates ONLY OS-registered Windows Media Foundation hardware video encoder
/// MFTs (`MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER`) for `codec`.
pub fn enumerate_hw_video_mfts(codec: MfHwCodec) -> Result<Vec<MfHwMftDescriptor>, VideoError> {
    let _mf = MfRuntimeGuard::start()?;
    let activates = enumerate_raw_hw_mft_activates(codec)?;
    Ok(activates
        .iter()
        .map(|a| read_mft_descriptor(a, codec))
        .collect())
}

fn enumerate_raw_hw_mft_activates(codec: MfHwCodec) -> Result<Vec<IMFActivate>, VideoError> {
    let input_type = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: MFVideoFormat_NV12,
    };
    let output_type = MFT_REGISTER_TYPE_INFO {
        guidMajorType: MFMediaType_Video,
        guidSubtype: codec_to_mf_subtype(codec),
    };
    let mut raw_ptr: *mut Option<IMFActivate> = ptr::null_mut();
    let mut count = 0u32;
    unsafe {
        MFTEnumEx(
            MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_FLAG_HARDWARE | MFT_ENUM_FLAG_SORTANDFILTER,
            Some(&input_type),
            Some(&output_type),
            &mut raw_ptr,
            &mut count,
        )
    }
    .map_err(|e| VideoError::HardwareUnavailable(format!("MFTEnumEx(HARDWARE) failed: {e}")))?;

    let mut out = Vec::with_capacity(count as usize);
    if !raw_ptr.is_null() {
        let slice = unsafe { std::slice::from_raw_parts_mut(raw_ptr, count as usize) };
        for slot in slice.iter_mut() {
            if let Some(act) = slot.take() {
                out.push(act);
            }
        }
        unsafe {
            CoTaskMemFree(Some(raw_ptr.cast()));
        }
    }
    Ok(out)
}

#[derive(Debug, Clone, Copy)]
pub struct WinMfEncoderConfig {
    pub codec: MfHwCodec,
    pub width: u32,
    pub height: u32,
    pub fps: u32,
    pub bitrate_bps: u32,
    pub capture_adapter_luid: DxgiAdapterLuid,
    pub allow_cross_adapter_copy: bool,
}

/// Thin Windows Media Foundation Hardware Video Encoder implementing
/// `HardwareCodec` and `HardwareVideoEncoder`.
pub struct WinMfHardwareEncoder {
    _mf_guard: MfRuntimeGuard,
    cfg: WinMfEncoderConfig,
    d3d11_device: Option<ID3D11Device>,
    dxgi_manager: Option<IMFDXGIDeviceManager>,
    transform: IMFTransform,
    state_machine: MfHwEncoderStateMachine,
    force_next_idr: bool,
}

// Safety: COM transform & DXGI device manager owned exclusively by this encoder (`&mut self`).
unsafe impl Send for WinMfHardwareEncoder {}

impl WinMfHardwareEncoder {
    pub fn new(
        cfg: WinMfEncoderConfig,
        d3d11_device: Option<ID3D11Device>,
    ) -> Result<Self, VideoError> {
        let mf_guard = MfRuntimeGuard::start()?;
        let (transform, dxgi_manager, mft_name) =
            Self::build_hardware_mft(&cfg, d3d11_device.as_ref())?;
        let mut state_machine = MfHwEncoderStateMachine::new(cfg.codec, mft_name);
        state_machine.on_initialized()?;
        state_machine.on_streaming_started()?;

        Ok(Self {
            _mf_guard: mf_guard,
            cfg,
            d3d11_device,
            dxgi_manager,
            transform,
            state_machine,
            force_next_idr: true,
        })
    }

    pub fn state_machine(&self) -> &MfHwEncoderStateMachine {
        &self.state_machine
    }

    fn build_hardware_mft(
        cfg: &WinMfEncoderConfig,
        d3d11_device: Option<&ID3D11Device>,
    ) -> Result<(IMFTransform, Option<IMFDXGIDeviceManager>, String), VideoError> {
        let activates = enumerate_raw_hw_mft_activates(cfg.codec)?;
        let descriptors: Vec<MfHwMftDescriptor> = activates
            .iter()
            .map(|a| read_mft_descriptor(a, cfg.codec))
            .collect();

        let selected_idx = match select_hw_mft_for_luid(
            &descriptors,
            cfg.codec,
            cfg.capture_adapter_luid,
            cfg.allow_cross_adapter_copy,
        ) {
            LuidMatchOutcome::ExactLuidZeroCopy { selected_index, .. } => selected_index,
            LuidMatchOutcome::LuidMismatchDiagnostic {
                selected_index: Some(idx),
                ..
            } => idx,
            LuidMatchOutcome::LuidMismatchDiagnostic {
                selected_index: None,
                diagnostic,
                ..
            }
            | LuidMatchOutcome::NoHardwareMftAvailable { diagnostic, .. } => {
                return Err(VideoError::HardwareUnavailable(diagnostic));
            }
        };

        let activate = &activates[selected_idx];
        let mft_name = descriptors[selected_idx].friendly_name.clone();
        let transform: IMFTransform = unsafe { activate.ActivateObject() }.map_err(|e| {
            VideoError::HardwareUnavailable(format!(
                "IMFActivate::ActivateObject({mft_name}) failed: {e}"
            ))
        })?;

        // Bind IMFDXGIDeviceManager when D3D11 device is supplied for zero-copy NV12 path.
        let mut dxgi_manager = None;
        if let Some(dev) = d3d11_device {
            let mut reset_token = 0u32;
            let mut mgr: Option<IMFDXGIDeviceManager> = None;
            if unsafe { MFCreateDXGIDeviceManager(&mut reset_token, &mut mgr) }.is_ok() {
                if let Some(m) = mgr {
                    if unsafe { m.ResetDevice(dev, reset_token) }.is_ok() {
                        let ptr_val = windows::core::Interface::as_raw(&m) as usize;
                        let _ = unsafe {
                            transform.ProcessMessage(
                                windows::Win32::Media::MediaFoundation::MFT_MESSAGE_SET_D3D_MANAGER,
                                ptr_val,
                            )
                        };
                        dxgi_manager = Some(m);
                    }
                }
            }
        }

        Self::configure_media_types(&transform, cfg)?;
        unsafe {
            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                .map_err(|e| {
                    VideoError::Encoder(format!("MFT_MESSAGE_NOTIFY_BEGIN_STREAMING failed: {e}"))
                })?;
            transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                .map_err(|e| {
                    VideoError::Encoder(format!("MFT_MESSAGE_NOTIFY_START_OF_STREAM failed: {e}"))
                })?;
        }

        Ok((transform, dxgi_manager, mft_name))
    }

    fn configure_media_types(
        transform: &IMFTransform,
        cfg: &WinMfEncoderConfig,
    ) -> Result<(), VideoError> {
        let out_type: IMFMediaType = unsafe { MFCreateMediaType() }
            .map_err(|e| VideoError::Encoder(format!("MFCreateMediaType(out) failed: {e}")))?;
        unsafe {
            out_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            out_type
                .SetGUID(&MF_MT_SUBTYPE, &codec_to_mf_subtype(cfg.codec))
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            out_type
                .SetUINT32(&MF_MT_AVG_BITRATE, cfg.bitrate_bps.max(64_000))
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            out_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            out_type
                .SetUINT64(&MF_MT_FRAME_SIZE, pack_u32_pair(cfg.width, cfg.height))
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            out_type
                .SetUINT64(&MF_MT_FRAME_RATE, pack_u32_pair(cfg.fps.max(1), 1))
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            transform
                .SetOutputType(0, &out_type, 0)
                .map_err(|e| VideoError::Encoder(format!("IMFTransform::SetOutputType failed: {e}")))?;
        }

        let in_type: IMFMediaType = unsafe { MFCreateMediaType() }
            .map_err(|e| VideoError::Encoder(format!("MFCreateMediaType(in) failed: {e}")))?;
        unsafe {
            in_type
                .SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video)
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            in_type
                .SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_NV12)
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            in_type
                .SetUINT32(&MF_MT_INTERLACE_MODE, MFVideoInterlace_Progressive.0 as u32)
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            in_type
                .SetUINT64(&MF_MT_FRAME_SIZE, pack_u32_pair(cfg.width, cfg.height))
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            in_type
                .SetUINT64(&MF_MT_FRAME_RATE, pack_u32_pair(cfg.fps.max(1), 1))
                .map_err(|e| VideoError::Encoder(e.to_string()))?;
            transform
                .SetInputType(0, &in_type, 0)
                .map_err(|e| VideoError::Encoder(format!("IMFTransform::SetInputType failed: {e}")))?;
        }
        Ok(())
    }

    fn handle_midstream_failure(&mut self, reason: String) -> VideoError {
        match self.state_machine.on_hw_error(reason) {
            MfErrorDecision::RetryReinit { attempt } => {
                match Self::build_hardware_mft(&self.cfg, self.d3d11_device.as_ref()) {
                    Ok((new_mft, new_mgr, _)) => {
                        self.transform = new_mft;
                        self.dxgi_manager = new_mgr;
                        self.force_next_idr = true;
                        let _ = self.state_machine.on_reinit_succeeded();
                        VideoError::NeedIdr(format!(
                            "Windows MF hardware MFT reinitialized (attempt {attempt}); waiting for IDR"
                        ))
                    }
                    Err(reinit_err) => self.handle_midstream_failure(format!(
                        "Windows MF hardware MFT reinit attempt {attempt} failed: {reinit_err}"
                    )),
                }
            }
            MfErrorDecision::FailedNeedsRenegotiation { reason, .. } => VideoError::CodecFailed {
                codec: self.cfg.codec.to_video_codec(),
                reason,
            },
        }
    }

    fn encode_nv12_bytes(
        &mut self,
        y_plane: &[u8],
        uv_plane: &[u8],
        pts_us: i64,
        force_idr: bool,
    ) -> Result<HardwareEncodedPacket, VideoError> {
        if self.state_machine.needs_renegotiation() {
            return Err(VideoError::CodecFailed {
                codec: self.cfg.codec.to_video_codec(),
                reason: "Windows MF hardware encoder previously failed; session renegotiation required".into(),
            });
        }
        let _want_idr = force_idr || std::mem::take(&mut self.force_next_idr);

        let total_len = y_plane
            .len()
            .checked_add(uv_plane.len())
            .ok_or_else(|| VideoError::InvalidInput("NV12 plane length overflow".into()))?;
        let total_u32 = u32::try_from(total_len)
            .map_err(|_| VideoError::InvalidInput("NV12 buffer exceeds u32::MAX".into()))?;

        let sample: IMFSample = unsafe { MFCreateSample() }
            .map_err(|e| VideoError::Encoder(format!("MFCreateSample failed: {e}")))?;
        let buffer: IMFMediaBuffer = unsafe { MFCreateMemoryBuffer(total_u32) }
            .map_err(|e| VideoError::Encoder(format!("MFCreateMemoryBuffer failed: {e}")))?;

        unsafe {
            let mut raw_buf: *mut u8 = ptr::null_mut();
            buffer
                .Lock(&mut raw_buf, None, None)
                .map_err(|e| VideoError::Encoder(format!("IMFMediaBuffer::Lock failed: {e}")))?;
            if raw_buf.is_null() {
                let _ = buffer.Unlock();
                return Err(VideoError::Encoder("IMFMediaBuffer::Lock returned null".into()));
            }
            ptr::copy_nonoverlapping(y_plane.as_ptr(), raw_buf, y_plane.len());
            ptr::copy_nonoverlapping(uv_plane.as_ptr(), raw_buf.add(y_plane.len()), uv_plane.len());
            buffer
                .Unlock()
                .map_err(|e| VideoError::Encoder(format!("IMFMediaBuffer::Unlock failed: {e}")))?;
            buffer
                .SetCurrentLength(total_u32)
                .map_err(|e| VideoError::Encoder(format!("SetCurrentLength failed: {e}")))?;
            sample
                .AddBuffer(&buffer)
                .map_err(|e| VideoError::Encoder(format!("IMFSample::AddBuffer failed: {e}")))?;
            // Media Foundation timestamps are in 100-nanosecond units.
            sample
                .SetSampleTime(pts_us.saturating_mul(10))
                .map_err(|e| VideoError::Encoder(format!("SetSampleTime failed: {e}")))?;
        }

        if let Err(err) = unsafe { self.transform.ProcessInput(0, &sample, 0) } {
            return Err(self.handle_midstream_failure(format!("IMFTransform::ProcessInput failed: {err}")));
        }

        let out_info: MFT_OUTPUT_STREAM_INFO = unsafe { self.transform.GetOutputStreamInfo(0) }
            .map_err(|e| self.handle_midstream_failure(format!("GetOutputStreamInfo failed: {e}")))?;
        let alloc_sample = if (out_info.dwFlags & 0x100) == 0 && (out_info.dwFlags & 0x200) == 0 {
            let out_sample: IMFSample = unsafe { MFCreateSample() }
                .map_err(|e| VideoError::Encoder(format!("MFCreateSample(out) failed: {e}")))?;
            let out_buf: IMFMediaBuffer = unsafe { MFCreateMemoryBuffer(out_info.cbSize.max(65_536)) }
                .map_err(|e| VideoError::Encoder(format!("MFCreateMemoryBuffer(out) failed: {e}")))?;
            unsafe {
                out_sample
                    .AddBuffer(&out_buf)
                    .map_err(|e| VideoError::Encoder(format!("AddBuffer(out) failed: {e}")))?;
            }
            Some(out_sample)
        } else {
            None
        };

        let mut output_buffers = [MFT_OUTPUT_DATA_BUFFER {
            dwStreamID: 0,
            pSample: std::mem::ManuallyDrop::new(alloc_sample),
            dwStatus: 0,
            pEvents: std::mem::ManuallyDrop::new(None),
        }];
        let mut status = 0u32;
        let out_res = unsafe { self.transform.ProcessOutput(0, &mut output_buffers, &mut status) };

        // Always reclaim ManuallyDrop COM references before returning.
        let produced_sample = unsafe { std::mem::ManuallyDrop::take(&mut output_buffers[0].pSample) };
        let _events = unsafe { std::mem::ManuallyDrop::take(&mut output_buffers[0].pEvents) };

        if let Err(err) = out_res {
            if err.code() == MF_E_TRANSFORM_NEED_MORE_INPUT {
                return Err(VideoError::NoOutputFrame);
            }
            return Err(self.handle_midstream_failure(format!("IMFTransform::ProcessOutput failed: {err}")));
        }

        let Some(out_sample) = produced_sample else {
            return Err(VideoError::NoOutputFrame);
        };

        let is_idr = unsafe { out_sample.GetUINT32(&MFSampleExtension_CleanPoint) }
            .map(|v| v != 0)
            .unwrap_or(false);

        let contiguous = unsafe { out_sample.ConvertToContiguousBuffer() }
            .map_err(|e| VideoError::Encoder(format!("ConvertToContiguousBuffer failed: {e}")))?;
        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len = 0u32;
        let bytes = unsafe {
            contiguous
                .Lock(&mut out_ptr, None, Some(&mut out_len))
                .map_err(|e| VideoError::Encoder(format!("output buffer Lock failed: {e}")))?;
            let slice = if out_ptr.is_null() || out_len == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts(out_ptr, out_len as usize).to_vec()
            };
            let _ = contiguous.Unlock();
            slice
        };

        self.state_machine.on_sample_encoded(is_idr, bytes.len());
        Ok(HardwareEncodedPacket {
            data: bytes,
            is_idr,
            pts_us,
            codec: self.cfg.codec.to_hardware_codec_kind(),
        })
    }
}

impl Drop for WinMfHardwareEncoder {
    fn drop(&mut self) {
        unsafe {
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
        }
    }
}

impl HardwareCodec for WinMfHardwareEncoder {
    fn codec(&self) -> HardwareCodecKind {
        self.cfg.codec.to_hardware_codec_kind()
    }

    fn backend_name(&self) -> &'static str {
        "windows_media_foundation_hw"
    }

    fn state(&self) -> HardwareCodecState {
        self.state_machine.hardware_codec_state()
    }

    fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        self.state_machine.drain_events()
    }
}

impl HardwareVideoEncoder for WinMfHardwareEncoder {
    fn encode_frame(
        &mut self,
        frame: &CapturedFrame,
        force_idr: bool,
    ) -> Result<HardwareEncodedPacket, VideoError> {
        match &frame.surface {
            CapturedSurface::Nv12 {
                y_plane, uv_plane, ..
            } => self.encode_nv12_bytes(y_plane, uv_plane, frame.timestamp_us, force_idr),
            CapturedSurface::Bgra8 { data } => {
                // CPU color-space conversion fallback only (NOT software encoding).
                let nv12 = bgra_to_nv12(
                    data,
                    frame.width as usize,
                    frame.height as usize,
                    frame.stride as usize,
                    ColorMatrix::Bt709,
                )?;
                self.encode_nv12_bytes(&nv12.y_plane, &nv12.uv_plane, frame.timestamp_us, force_idr)
            }
            CapturedSurface::Rgba8 { .. } | CapturedSurface::D3d11TextureHandle { .. } => {
                Err(VideoError::InvalidInput(
                    "WinMfHardwareEncoder requires NV12 or BGRA8 frame surface".into(),
                ))
            }
        }
    }

    fn encode_i420(
        &mut self,
        frame: &I420Frame,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<HardwareEncodedPacket, VideoError> {
        frame.validate()?;
        let uv_w = frame.width / 2;
        let uv_h = frame.height / 2;
        let mut uv = vec![0u8; frame.width * uv_h];
        for row in 0..uv_h {
            for col in 0..uv_w {
                uv[row * frame.width + col * 2] = frame.u[row * uv_w + col];
                uv[row * frame.width + col * 2 + 1] = frame.v[row * uv_w + col];
            }
        }
        self.encode_nv12_bytes(&frame.y, &uv, pts_us, force_idr)
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError> {
        if bitrate_bps == 0 {
            return Err(VideoError::InvalidInput("bitrate_bps must be > 0".into()));
        }
        self.cfg.bitrate_bps = bitrate_bps;
        Ok(())
    }

    fn force_next_idr(&mut self) {
        self.force_next_idr = true;
    }
}
