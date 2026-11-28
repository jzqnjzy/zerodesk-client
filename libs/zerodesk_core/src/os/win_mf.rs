// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(windows)]` Windows Media Foundation Hardware MFT FFI adapter
//! driven by `win_mf_logic`.
//!
//! Mandatory constraints:
//! - Uses Windows Media Foundation ONLY (`MFTEnumEx(MFT_ENUM_FLAG_HARDWARE)` +
//!   `MFT_ENUM_ADAPTER_LUID`); ZERO proprietary NVENC / AMF / QSV SDKs.
//! - Supports BOTH asynchronous hardware MFTs (`MF_TRANSFORM_ASYNC_UNLOCK` +
//!   `IMFMediaEventGenerator::GetEvent`) and synchronous MFTs.
//! - Wires `ICodecAPI` (`CODECAPI_AVEncVideoForceKeyFrame`,
//!   `CODECAPI_AVEncCommonMeanBitRate`) directly to the active hardware MFT.
//! - Implements true D3D11 NV12 zero-copy input via `ID3D11VideoContext::VideoProcessorBlt`
//!   + `MFCreateDXGISurfaceBuffer` over `IMFDXGIDeviceManager`.
//! - Marks `HardwareReady` ONLY after the first IDR keyframe (`MFSampleExtension_CleanPoint`)
//!   encodes with non-zero bytes.
//! - On mid-stream hardware errors: performs bounded MFT reinit retries, then
//!   fails explicitly with `VideoError::CodecFailed` + renegotiation event
//!   (NEVER silently falls back to software MFTs!).

#![cfg(windows)]

use super::{
    traits::{
        CapturedFrame, CapturedSurface, D3d11SurfaceFormat, HardwareCodec, HardwareCodecEvent,
        HardwareCodecKind, HardwareCodecState, HardwareEncodedPacket, HardwareVideoEncoder,
    },
    win_dxgi_logic::DxgiAdapterLuid,
    win_mf_logic::{
        bgra_to_nv12, classify_mf_hresult, select_hw_mft_for_luid, ColorMatrix, LuidMatchOutcome,
        MfErrorDecision, MfHresultClass, MfHwCodec, MfHwEncoderStateMachine, MfHwMftDescriptor,
        MfHwVendor,
    },
};
use crate::session::video::{I420Frame, VideoError};
use std::{
    ptr,
    time::{Duration, Instant},
};
use windows::{
    core::{Interface, GUID, PWSTR, VARIANT},
    Win32::{
        Foundation::{RPC_E_CHANGED_MODE, S_FALSE, S_OK},
        Graphics::{
            Direct3D11::{
                ID3D11Device, ID3D11DeviceContext, ID3D11Resource, ID3D11Texture2D,
                ID3D11VideoContext, ID3D11VideoDevice, ID3D11VideoProcessor,
                ID3D11VideoProcessorEnumerator, ID3D11VideoProcessorInputView,
                ID3D11VideoProcessorOutputView, D3D11_BIND_RENDER_TARGET,
                D3D11_BIND_SHADER_RESOURCE, D3D11_TEXTURE2D_DESC, D3D11_USAGE_DEFAULT,
                D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE, D3D11_VIDEO_PROCESSOR_CONTENT_DESC,
                D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0,
                D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC, D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0,
                D3D11_VIDEO_PROCESSOR_STREAM, D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
                D3D11_VPIV_DIMENSION_TEXTURE2D, D3D11_VPOV_DIMENSION_TEXTURE2D,
                D3D11_TEX2D_VPIV, D3D11_TEX2D_VPOV,
            },
            Dxgi::Common::{DXGI_FORMAT_NV12, DXGI_RATIONAL, DXGI_SAMPLE_DESC},
        },
        Media::MediaFoundation::{
            ICodecAPI, IMFActivate, IMFDXGIDeviceManager, IMFMediaBuffer, IMFMediaEventGenerator,
            IMFMediaType, IMFSample, IMFTransform, MFCreateDXGIDeviceManager,
            MFCreateDXGISurfaceBuffer, MFCreateMediaType, MFCreateMemoryBuffer, MFCreateSample,
            MFShutdown, MFStartup, MFTEnumEx, CODECAPI_AVEncCommonMeanBitRate,
            CODECAPI_AVEncVideoForceKeyFrame, METransformHaveOutput, METransformNeedInput,
            MFMediaType_Video, MFSampleExtension_CleanPoint, MFT_CATEGORY_VIDEO_ENCODER,
            MFT_ENUM_ADAPTER_LUID, MFT_ENUM_FLAG_HARDWARE, MFT_ENUM_FLAG_SORTANDFILTER,
            MFT_FRIENDLY_NAME_Attribute, MFT_MESSAGE_COMMAND_FLUSH,
            MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, MFT_MESSAGE_NOTIFY_END_OF_STREAM,
            MFT_MESSAGE_NOTIFY_START_OF_STREAM, MFT_MESSAGE_SET_D3D_MANAGER,
            MFT_OUTPUT_DATA_BUFFER, MFT_OUTPUT_STREAM_INFO, MFT_REGISTER_TYPE_INFO,
            MFVideoFormat_AV1, MFVideoFormat_H264, MFVideoFormat_HEVC, MFVideoFormat_NV12,
            MFVideoInterlace_Progressive, MFSTARTUP_NOSOCKET, MF_EVENT_FLAG_NO_WAIT,
            MF_MT_AVG_BITRATE, MF_MT_FRAME_RATE, MF_MT_FRAME_SIZE, MF_MT_INTERLACE_MODE,
            MF_MT_MAJOR_TYPE, MF_MT_SUBTYPE, MF_SA_D3D11_AWARE, MF_TRANSFORM_ASYNC,
            MF_TRANSFORM_ASYNC_UNLOCK, MF_VERSION,
        },
        System::Com::{CoInitializeEx, CoTaskMemFree, CoUninitialize, COINIT_MULTITHREADED},
    },
};

const ASYNC_EVENT_TIMEOUT: Duration = Duration::from_millis(100);
const ASYNC_POLL_SLEEP: Duration = Duration::from_millis(1);

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

/// RAII guard ensuring COM is initialized in `COINIT_MULTITHREADED` (MTA) mode
/// (never STA!) and pairing `CoUninitialize` strictly when this guard initialized COM.
struct ComMtaGuard {
    should_uninit: bool,
}

impl ComMtaGuard {
    fn enter() -> Result<Self, VideoError> {
        let hr = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        if hr == S_OK || hr == S_FALSE {
            Ok(Self {
                should_uninit: true,
            })
        } else if hr == RPC_E_CHANGED_MODE {
            Err(VideoError::HardwareUnavailable(
                "COM thread is already initialized as STA; Media Foundation hardware MFT requires COINIT_MULTITHREADED".into(),
            ))
        } else {
            Err(VideoError::HardwareUnavailable(format!(
                "CoInitializeEx(COINIT_MULTITHREADED) failed: {hr:?}"
            )))
        }
    }
}

impl Drop for ComMtaGuard {
    fn drop(&mut self) {
        if self.should_uninit {
            unsafe { CoUninitialize() };
        }
    }
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
    unsafe {
        let slice = std::slice::from_raw_parts(name_ptr.0, name_len as usize);
        let s = String::from_utf16_lossy(slice)
            .trim_end_matches('\0')
            .to_string();
        CoTaskMemFree(Some(name_ptr.0.cast()));
        if s.is_empty() {
            "Unknown Hardware MFT".into()
        } else {
            s
        }
    }
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
    let _com = ComMtaGuard::enter()?;
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

/// GPU-side BGRA -> NV12 D3D11 Video Processor pipeline for zero-copy MFT encoding.
struct D3d11Nv12Converter {
    video_device: ID3D11VideoDevice,
    video_context: ID3D11VideoContext,
    enumerator: ID3D11VideoProcessorEnumerator,
    processor: ID3D11VideoProcessor,
    nv12_texture: ID3D11Texture2D,
    output_view: ID3D11VideoProcessorOutputView,
    frame_index: u32,
}

impl D3d11Nv12Converter {
    fn new(device: &ID3D11Device, width: u32, height: u32, fps: u32) -> Result<Self, VideoError> {
        let context: ID3D11DeviceContext = unsafe { device.GetImmediateContext() }
            .map_err(|e| VideoError::Encoder(format!("GetImmediateContext failed: {e}")))?;
        let video_device: ID3D11VideoDevice = device.cast().map_err(|e| {
            VideoError::HardwareUnavailable(format!(
                "QueryInterface(ID3D11VideoDevice) failed (device requires D3D11_CREATE_DEVICE_VIDEO_SUPPORT): {e}"
            ))
        })?;
        let video_context: ID3D11VideoContext = context.cast().map_err(|e| {
            VideoError::HardwareUnavailable(format!("QueryInterface(ID3D11VideoContext) failed: {e}"))
        })?;

        let content_desc = D3D11_VIDEO_PROCESSOR_CONTENT_DESC {
            InputFrameFormat: D3D11_VIDEO_FRAME_FORMAT_PROGRESSIVE,
            InputFrameRate: DXGI_RATIONAL {
                Numerator: fps.max(1),
                Denominator: 1,
            },
            InputWidth: width,
            InputHeight: height,
            OutputFrameRate: DXGI_RATIONAL {
                Numerator: fps.max(1),
                Denominator: 1,
            },
            OutputWidth: width,
            OutputHeight: height,
            Usage: D3D11_VIDEO_USAGE_PLAYBACK_NORMAL,
        };
        let enumerator = unsafe { video_device.CreateVideoProcessorEnumerator(&content_desc) }
            .map_err(|e| VideoError::Encoder(format!("CreateVideoProcessorEnumerator failed: {e}")))?;
        let processor = unsafe { video_device.CreateVideoProcessor(&enumerator, 0) }
            .map_err(|e| VideoError::Encoder(format!("CreateVideoProcessor failed: {e}")))?;

        let nv12_desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_NV12,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: (D3D11_BIND_RENDER_TARGET.0 | D3D11_BIND_SHADER_RESOURCE.0) as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let mut nv12_texture: Option<ID3D11Texture2D> = None;
        unsafe { device.CreateTexture2D(&nv12_desc, None, Some(&mut nv12_texture)) }
            .map_err(|e| VideoError::Encoder(format!("CreateTexture2D(NV12) failed: {e}")))?;
        let nv12_texture = nv12_texture
            .ok_or_else(|| VideoError::Encoder("CreateTexture2D(NV12) returned null".into()))?;

        let out_res: ID3D11Resource = nv12_texture
            .cast()
            .map_err(|e| VideoError::Encoder(format!("NV12 texture cast to ID3D11Resource failed: {e}")))?;
        let out_desc = D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC {
            ViewDimension: D3D11_VPOV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_OUTPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPOV { MipSlice: 0 },
            },
        };
        let mut output_view: Option<ID3D11VideoProcessorOutputView> = None;
        unsafe {
            video_device.CreateVideoProcessorOutputView(
                &out_res,
                &enumerator,
                &out_desc,
                Some(&mut output_view),
            )
        }
        .map_err(|e| VideoError::Encoder(format!("CreateVideoProcessorOutputView failed: {e}")))?;
        let output_view = output_view.ok_or_else(|| {
            VideoError::Encoder("CreateVideoProcessorOutputView returned null".into())
        })?;

        Ok(Self {
            video_device,
            video_context,
            enumerator,
            processor,
            nv12_texture,
            output_view,
            frame_index: 0,
        })
    }

    fn convert_bgra_to_nv12(&mut self, bgra_tex: &ID3D11Texture2D) -> Result<ID3D11Texture2D, VideoError> {
        let in_res: ID3D11Resource = bgra_tex
            .cast()
            .map_err(|e| VideoError::Encoder(format!("BGRA texture cast to ID3D11Resource failed: {e}")))?;
        let in_desc = D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC {
            FourCC: 0,
            ViewDimension: D3D11_VPIV_DIMENSION_TEXTURE2D,
            Anonymous: D3D11_VIDEO_PROCESSOR_INPUT_VIEW_DESC_0 {
                Texture2D: D3D11_TEX2D_VPIV {
                    MipSlice: 0,
                    ArraySlice: 0,
                },
            },
        };
        let mut input_view: Option<ID3D11VideoProcessorInputView> = None;
        unsafe {
            self.video_device.CreateVideoProcessorInputView(
                &in_res,
                &self.enumerator,
                &in_desc,
                Some(&mut input_view),
            )
        }
        .map_err(|e| VideoError::Encoder(format!("CreateVideoProcessorInputView failed: {e}")))?;
        let input_view = input_view.ok_or_else(|| {
            VideoError::Encoder("CreateVideoProcessorInputView returned null".into())
        })?;

        let stream = D3D11_VIDEO_PROCESSOR_STREAM {
            Enable: true.into(),
            OutputIndex: 0,
            InputFrameOrField: 0,
            PastFrames: 0,
            FutureFrames: 0,
            ppPastSurfaces: ptr::null_mut(),
            pInputSurface: std::mem::ManuallyDrop::new(Some(input_view)),
            ppFutureSurfaces: ptr::null_mut(),
            ppPastSurfacesRight: ptr::null_mut(),
            pInputSurfaceRight: std::mem::ManuallyDrop::new(None),
            ppFutureSurfacesRight: ptr::null_mut(),
        };
        let mut streams = [stream];
        let blt_res = unsafe {
            self.video_context.VideoProcessorBlt(
                &self.processor,
                &self.output_view,
                self.frame_index,
                &streams,
            )
        };
        // Always release ManuallyDrop input view COM reference before returning!
        let _input_view = unsafe { std::mem::ManuallyDrop::take(&mut streams[0].pInputSurface) };
        let _input_view_r =
            unsafe { std::mem::ManuallyDrop::take(&mut streams[0].pInputSurfaceRight) };
        blt_res.map_err(|e| VideoError::Encoder(format!("VideoProcessorBlt(BGRA->NV12) failed: {e}")))?;
        self.frame_index = self.frame_index.wrapping_add(1);
        Ok(self.nv12_texture.clone())
    }
}

struct MftInitState {
    event_gen: Option<IMFMediaEventGenerator>,
    dxgi_manager: Option<IMFDXGIDeviceManager>,
    nv12_converter: Option<D3d11Nv12Converter>,
}

struct BuiltMft {
    activate: IMFActivate,
    transform: IMFTransform,
    event_gen: Option<IMFMediaEventGenerator>,
    dxgi_manager: Option<IMFDXGIDeviceManager>,
    nv12_converter: Option<D3d11Nv12Converter>,
    mft_name: String,
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
///
/// Field drop order is CRITICAL: all COM interfaces (`transform`, `event_gen`,
/// `activate`, `nv12_converter`, `dxgi_manager`, `d3d11_device`) MUST drop
/// BEFORE `_mf_guard` (`MFShutdown()`) and `_com_guard` (`CoUninitialize()`).
pub struct WinMfHardwareEncoder {
    cfg: WinMfEncoderConfig,
    d3d11_device: Option<ID3D11Device>,
    dxgi_manager: Option<IMFDXGIDeviceManager>,
    nv12_converter: Option<D3d11Nv12Converter>,
    event_gen: Option<IMFMediaEventGenerator>,
    transform: IMFTransform,
    activate: IMFActivate,
    state_machine: MfHwEncoderStateMachine,
    force_next_idr: bool,
    // Declared LAST so Rust drops all COM/MF objects before MFShutdown & CoUninitialize!
    _mf_guard: MfRuntimeGuard,
    _com_guard: ComMtaGuard,
}

// SAFETY: COM is initialized strictly in `COINIT_MULTITHREADED` (MTA) mode via `ComMtaGuard`
// (never STA), and all COM interfaces (`IMFTransform`, `IMFMediaEventGenerator`,
// `IMFDXGIDeviceManager`, `ID3D11Device`) are agile/MTA-owned exclusively by `&mut self`.
unsafe impl Send for WinMfHardwareEncoder {}

impl WinMfHardwareEncoder {
    pub fn new(
        cfg: WinMfEncoderConfig,
        d3d11_device: Option<ID3D11Device>,
    ) -> Result<Self, VideoError> {
        Self::validate_config(&cfg)?;
        let com_guard = ComMtaGuard::enter()?;
        let mf_guard = MfRuntimeGuard::start()?;
        let built = Self::build_hardware_mft(&cfg, d3d11_device.as_ref())?;
        let mut state_machine = MfHwEncoderStateMachine::new(cfg.codec, built.mft_name);
        state_machine.on_initialized()?;
        state_machine.on_streaming_started()?;

        Ok(Self {
            cfg,
            d3d11_device,
            dxgi_manager: built.dxgi_manager,
            nv12_converter: built.nv12_converter,
            event_gen: built.event_gen,
            transform: built.transform,
            activate: built.activate,
            state_machine,
            force_next_idr: true,
            _mf_guard: mf_guard,
            _com_guard: com_guard,
        })
    }

    pub fn state_machine(&self) -> &MfHwEncoderStateMachine {
        &self.state_machine
    }

    fn validate_config(cfg: &WinMfEncoderConfig) -> Result<(), VideoError> {
        if cfg.width == 0 || cfg.height == 0 || (cfg.width & 1) != 0 || (cfg.height & 1) != 0 {
            return Err(VideoError::InvalidInput(format!(
                "MF encoder dimensions must be positive and even, got {}x{}",
                cfg.width, cfg.height
            )));
        }
        if cfg.bitrate_bps == 0 {
            return Err(VideoError::InvalidInput("bitrate_bps must be > 0".into()));
        }
        Ok(())
    }

    fn build_hardware_mft(
        cfg: &WinMfEncoderConfig,
        d3d11_device: Option<&ID3D11Device>,
    ) -> Result<BuiltMft, VideoError> {
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
            LuidMatchOutcome::ExactLuidZeroCopy { selected_index, .. }
            | LuidMatchOutcome::ExactLuidCpuUpload { selected_index, .. }
            | LuidMatchOutcome::CrossAdapterCopy { selected_index, .. } => selected_index,
            LuidMatchOutcome::LuidMismatchDiagnostic { diagnostic, .. }
            | LuidMatchOutcome::NoHardwareMftAvailable { diagnostic, .. } => {
                return Err(VideoError::HardwareUnavailable(diagnostic));
            }
        };

        let activate = activates[selected_idx].clone();
        let mft_name = descriptors[selected_idx].friendly_name.clone();
        let transform: IMFTransform = unsafe { activate.ActivateObject() }.map_err(|e| {
            unsafe {
                let _ = activate.ShutdownObject();
            }
            VideoError::HardwareUnavailable(format!(
                "IMFActivate::ActivateObject({mft_name}) failed: {e}"
            ))
        })?;

        let init_res = (|| -> Result<MftInitState, VideoError> {
            // Unlock async hardware MFTs (NVIDIA NVENC / AMD AMF / Intel QSV frequently register as async MFTs).
            let mut event_gen = None;
            if let Ok(attrs) = unsafe { transform.GetAttributes() } {
                let is_async = unsafe { attrs.GetUINT32(&MF_TRANSFORM_ASYNC) }
                    .map(|v| v != 0)
                    .unwrap_or(false);
                if is_async {
                    unsafe { attrs.SetUINT32(&MF_TRANSFORM_ASYNC_UNLOCK, 1) }.map_err(|e| {
                        VideoError::HardwareUnavailable(format!(
                            "MF_TRANSFORM_ASYNC_UNLOCK failed on '{mft_name}': {e}"
                        ))
                    })?;
                    let eg: IMFMediaEventGenerator = transform.cast().map_err(|e| {
                        VideoError::HardwareUnavailable(format!(
                            "QueryInterface(IMFMediaEventGenerator) failed on async MFT '{mft_name}': {e}"
                        ))
                    })?;
                    event_gen = Some(eg);
                }
            }

            // Bind IMFDXGIDeviceManager & D3D11 NV12 converter when D3D11 device is supplied;
            // NEVER silently swallow DXGI manager setup failures.
            let mut dxgi_manager = None;
            let mut nv12_converter = None;
            if let Some(dev) = d3d11_device {
                let mut reset_token = 0u32;
                let mut mgr: Option<IMFDXGIDeviceManager> = None;
                unsafe { MFCreateDXGIDeviceManager(&mut reset_token, &mut mgr) }.map_err(|e| {
                    VideoError::HardwareUnavailable(format!(
                        "MFCreateDXGIDeviceManager failed: {e}"
                    ))
                })?;
                let mgr = mgr.ok_or_else(|| {
                    VideoError::HardwareUnavailable(
                        "MFCreateDXGIDeviceManager returned null".into(),
                    )
                })?;
                unsafe { mgr.ResetDevice(dev, reset_token) }.map_err(|e| {
                    VideoError::HardwareUnavailable(format!(
                        "IMFDXGIDeviceManager::ResetDevice failed: {e}"
                    ))
                })?;
                let ptr_val = Interface::as_raw(&mgr) as usize;
                unsafe { transform.ProcessMessage(MFT_MESSAGE_SET_D3D_MANAGER, ptr_val) }.map_err(
                    |e| {
                        VideoError::HardwareUnavailable(format!(
                            "MFT_MESSAGE_SET_D3D_MANAGER failed on '{mft_name}': {e}"
                        ))
                    },
                )?;
                let conv = D3d11Nv12Converter::new(dev, cfg.width, cfg.height, cfg.fps)?;
                dxgi_manager = Some(mgr);
                nv12_converter = Some(conv);
            }

            Self::configure_media_types(&transform, cfg)?;
            unsafe {
                transform
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_BEGIN_STREAMING, 0)
                    .map_err(|e| {
                        VideoError::Encoder(format!(
                            "MFT_MESSAGE_NOTIFY_BEGIN_STREAMING failed: {e}"
                        ))
                    })?;
                transform
                    .ProcessMessage(MFT_MESSAGE_NOTIFY_START_OF_STREAM, 0)
                    .map_err(|e| {
                        VideoError::Encoder(format!(
                            "MFT_MESSAGE_NOTIFY_START_OF_STREAM failed: {e}"
                        ))
                    })?;
            }
            Ok(MftInitState {
                event_gen,
                dxgi_manager,
                nv12_converter,
            })
        })();

        match init_res {
            Ok(init) => Ok(BuiltMft {
                activate,
                transform,
                event_gen: init.event_gen,
                dxgi_manager: init.dxgi_manager,
                nv12_converter: init.nv12_converter,
                mft_name,
            }),
            Err(e) => {
                unsafe {
                    let _ = activate.ShutdownObject();
                }
                Err(e)
            }
        }
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
            transform.SetOutputType(0, &out_type, 0).map_err(|e| {
                VideoError::Encoder(format!("IMFTransform::SetOutputType failed: {e}"))
            })?;
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
            transform.SetInputType(0, &in_type, 0).map_err(|e| {
                VideoError::Encoder(format!("IMFTransform::SetInputType failed: {e}"))
            })?;
        }
        Ok(())
    }

    fn apply_force_idr_codec_api(&self) -> Result<(), VideoError> {
        let codec_api: ICodecAPI = self.transform.cast().map_err(|e| {
            VideoError::Encoder(format!("QueryInterface(ICodecAPI) for force-IDR failed: {e}"))
        })?;
        let val_bool = VARIANT::from(true);
        if unsafe { codec_api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &val_bool) }.is_ok() {
            return Ok(());
        }
        let val_u32 = VARIANT::from(1u32);
        unsafe { codec_api.SetValue(&CODECAPI_AVEncVideoForceKeyFrame, &val_u32) }.map_err(|e| {
            VideoError::Encoder(format!(
                "ICodecAPI::SetValue(CODECAPI_AVEncVideoForceKeyFrame) failed: {e}"
            ))
        })
    }

    fn shutdown_current_mft(&mut self) {
        unsafe {
            let _ = self.transform.ProcessMessage(MFT_MESSAGE_COMMAND_FLUSH, 0);
            let _ = self
                .transform
                .ProcessMessage(MFT_MESSAGE_NOTIFY_END_OF_STREAM, 0);
            let _ = self.activate.ShutdownObject();
        }
    }

    fn handle_midstream_failure(&mut self, reason: String) -> VideoError {
        match self.state_machine.on_hw_error(reason) {
            MfErrorDecision::RetryReinit { attempt } => {
                self.shutdown_current_mft();
                match Self::build_hardware_mft(&self.cfg, self.d3d11_device.as_ref()) {
                    Ok(built) => {
                        self.activate = built.activate;
                        self.transform = built.transform;
                        self.event_gen = built.event_gen;
                        self.dxgi_manager = built.dxgi_manager;
                        self.nv12_converter = built.nv12_converter;
                        self.force_next_idr = true;
                        if let Err(e) = self.state_machine.on_reinit_succeeded() {
                            return e;
                        }
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

    fn pull_one_output_packet(&mut self, fallback_pts_us: i64) -> Result<Option<HardwareEncodedPacket>, VideoError> {
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

        let produced_sample =
            unsafe { std::mem::ManuallyDrop::take(&mut output_buffers[0].pSample) };
        let _events = unsafe { std::mem::ManuallyDrop::take(&mut output_buffers[0].pEvents) };

        if let Err(err) = out_res {
            let hr = err.code().0;
            return match classify_mf_hresult(hr) {
                MfHresultClass::Benign => Ok(None),
                MfHresultClass::OutputTypeChange => {
                    Self::configure_media_types(&self.transform, &self.cfg)?;
                    Ok(None)
                }
                MfHresultClass::DeviceLost | MfHresultClass::Fatal => Err(
                    self.handle_midstream_failure(format!("IMFTransform::ProcessOutput failed: {err}")),
                ),
            };
        }

        let Some(out_sample) = produced_sample else {
            return Ok(None);
        };

        let is_idr = unsafe { out_sample.GetUINT32(&MFSampleExtension_CleanPoint) }
            .map(|v| v != 0)
            .unwrap_or(false);
        let sample_pts_us = unsafe { out_sample.GetSampleTime() }
            .map(|t100ns| t100ns / 10)
            .unwrap_or(fallback_pts_us);

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
        Ok(Some(HardwareEncodedPacket {
            data: bytes,
            is_idr,
            pts_us: sample_pts_us,
            codec: self.cfg.codec.to_hardware_codec_kind(),
        }))
    }

    fn submit_sample_and_collect(
        &mut self,
        sample: &IMFSample,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        if self.state_machine.needs_renegotiation() {
            return Err(VideoError::CodecFailed {
                codec: self.cfg.codec.to_video_codec(),
                reason: "Windows MF hardware encoder previously failed; session renegotiation required".into(),
            });
        }
        let want_idr = force_idr || std::mem::take(&mut self.force_next_idr);
        if want_idr {
            if let Err(err) = self.apply_force_idr_codec_api() {
                return Err(self.handle_midstream_failure(err.to_string()));
            }
        }

        let mut packets = Vec::new();
        if let Some(eg) = self.event_gen.clone() {
            // Asynchronous hardware MFT path: pump METransformNeedInput / METransformHaveOutput
            // with a strict bounded deadline so we never block indefinitely.
            let deadline = Instant::now() + ASYNC_EVENT_TIMEOUT;
            let mut input_fed = false;
            loop {
                match unsafe { eg.GetEvent(MF_EVENT_FLAG_NO_WAIT) } {
                    Ok(ev) => {
                        let ev_type = unsafe { ev.GetType() }.map_err(|e| {
                            self.handle_midstream_failure(format!("IMFMediaEvent::GetType failed: {e}"))
                        })?;
                        if ev_type == METransformNeedInput.0 as u32 && !input_fed {
                            if let Err(err) = unsafe { self.transform.ProcessInput(0, sample, 0) } {
                                return Err(self.handle_midstream_failure(format!(
                                    "async ProcessInput failed: {err}"
                                )));
                            }
                            input_fed = true;
                        } else if ev_type == METransformHaveOutput.0 as u32 {
                            if let Some(pkt) = self.pull_one_output_packet(pts_us)? {
                                packets.push(pkt);
                            }
                            if input_fed {
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        let hr = err.code().0;
                        match classify_mf_hresult(hr) {
                            MfHresultClass::Benign => {
                                if input_fed && !packets.is_empty() {
                                    break;
                                }
                                if Instant::now() >= deadline {
                                    if !input_fed {
                                        return Err(self.handle_midstream_failure(
                                            "async MF hardware MFT timed out waiting for METransformNeedInput".into(),
                                        ));
                                    }
                                    break;
                                }
                                std::thread::sleep(ASYNC_POLL_SLEEP);
                            }
                            MfHresultClass::OutputTypeChange => {
                                Self::configure_media_types(&self.transform, &self.cfg)?;
                            }
                            MfHresultClass::DeviceLost | MfHresultClass::Fatal => {
                                return Err(self.handle_midstream_failure(format!(
                                    "IMFMediaEventGenerator::GetEvent failed: {err}"
                                )));
                            }
                        }
                    }
                }
            }
        } else {
            // Synchronous MFT path: ProcessInput then drain all available output packets.
            if let Err(err) = unsafe { self.transform.ProcessInput(0, sample, 0) } {
                return Err(
                    self.handle_midstream_failure(format!("IMFTransform::ProcessInput failed: {err}")),
                );
            }
            while let Some(pkt) = self.pull_one_output_packet(pts_us)? {
                packets.push(pkt);
            }
        }

        // Track WaitingFirstIdr budget so a silent MFT triggers bounded reinit / renegotiation.
        if let Some(MfErrorDecision::FailedNeedsRenegotiation { reason, .. }) =
            self.state_machine.on_input_queued()
        {
            return Err(VideoError::CodecFailed {
                codec: self.cfg.codec.to_video_codec(),
                reason,
            });
        }

        Ok(packets)
    }

    /// True D3D11 NV12 zero-copy encoding path: converts GPU BGRA -> NV12 via
    /// `ID3D11VideoContext::VideoProcessorBlt` (or consumes NV12 texture directly)
    /// and binds it via `MFCreateDXGISurfaceBuffer` over `IMFDXGIDeviceManager`.
    pub fn encode_d3d11_texture(
        &mut self,
        texture: &ID3D11Texture2D,
        format: D3d11SurfaceFormat,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        let nv12_tex = match format {
            D3d11SurfaceFormat::Nv12 => texture.clone(),
            D3d11SurfaceFormat::Bgra8Unorm => {
                let converter = self.nv12_converter.as_mut().ok_or_else(|| {
                    VideoError::HardwareUnavailable(
                        "D3D11 NV12 VideoProcessor not initialized (pass D3D11 device to WinMfHardwareEncoder::new)".into(),
                    )
                })?;
                converter.convert_bgra_to_nv12(texture)?
            }
        };

        let dxgi_buf: IMFMediaBuffer =
            unsafe { MFCreateDXGISurfaceBuffer(&ID3D11Texture2D::IID, &nv12_tex, 0, true) }
                .map_err(|e| {
                    VideoError::Encoder(format!("MFCreateDXGISurfaceBuffer failed: {e}"))
                })?;
        let sample: IMFSample = unsafe { MFCreateSample() }
            .map_err(|e| VideoError::Encoder(format!("MFCreateSample failed: {e}")))?;
        unsafe {
            sample
                .AddBuffer(&dxgi_buf)
                .map_err(|e| VideoError::Encoder(format!("IMFSample::AddBuffer(DXGI) failed: {e}")))?;
            sample
                .SetSampleTime(pts_us.saturating_mul(10))
                .map_err(|e| VideoError::Encoder(format!("SetSampleTime failed: {e}")))?;
        }
        self.submit_sample_and_collect(&sample, pts_us, force_idr)
    }

    fn encode_nv12_bytes(
        &mut self,
        y_plane: &[u8],
        uv_plane: &[u8],
        pts_us: i64,
        force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        let w = self.cfg.width as usize;
        let h = self.cfg.height as usize;
        let expected_y = w
            .checked_mul(h)
            .ok_or_else(|| VideoError::InvalidInput("NV12 Y length overflow".into()))?;
        let expected_uv = w
            .checked_mul(h / 2)
            .ok_or_else(|| VideoError::InvalidInput("NV12 UV length overflow".into()))?;
        if y_plane.len() != expected_y || uv_plane.len() != expected_uv {
            return Err(VideoError::InvalidInput(format!(
                "NV12 plane sizes ({}, {}) do not match configured {}x{} ({expected_y}, {expected_uv})",
                y_plane.len(),
                uv_plane.len(),
                w,
                h
            )));
        }

        let total_len = expected_y
            .checked_add(expected_uv)
            .ok_or_else(|| VideoError::InvalidInput("NV12 total length overflow".into()))?;
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
            ptr::copy_nonoverlapping(
                uv_plane.as_ptr(),
                raw_buf.add(y_plane.len()),
                uv_plane.len(),
            );
            buffer
                .Unlock()
                .map_err(|e| VideoError::Encoder(format!("IMFMediaBuffer::Unlock failed: {e}")))?;
            buffer
                .SetCurrentLength(total_u32)
                .map_err(|e| VideoError::Encoder(format!("SetCurrentLength failed: {e}")))?;
            sample
                .AddBuffer(&buffer)
                .map_err(|e| VideoError::Encoder(format!("IMFSample::AddBuffer failed: {e}")))?;
            sample
                .SetSampleTime(pts_us.saturating_mul(10))
                .map_err(|e| VideoError::Encoder(format!("SetSampleTime failed: {e}")))?;
        }

        self.submit_sample_and_collect(&sample, pts_us, force_idr)
    }
}

impl Drop for WinMfHardwareEncoder {
    fn drop(&mut self) {
        self.shutdown_current_mft();
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
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        if frame.width != self.cfg.width || frame.height != self.cfg.height {
            return Err(VideoError::InvalidInput(format!(
                "frame dimensions {}x{} do not match MF encoder {}x{}",
                frame.width, frame.height, self.cfg.width, self.cfg.height
            )));
        }
        match &frame.surface {
            CapturedSurface::D3d11Texture(shared) => {
                let tex = shared.texture().ok_or_else(|| {
                    VideoError::InvalidInput(
                        "CapturedSurface::D3d11Texture missing ID3D11Texture2D payload".into(),
                    )
                })?;
                self.encode_d3d11_texture(tex, shared.format(), frame.timestamp_us, force_idr)
            }
            CapturedSurface::Nv12 {
                y_plane, uv_plane, ..
            } => self.encode_nv12_bytes(y_plane, uv_plane, frame.timestamp_us, force_idr),
            CapturedSurface::Bgra8 { data } => {
                // Explicit diagnostic event whenever CPU color-space conversion fallback is used
                // (never silent, and still encodes strictly via the Hardware MFT).
                self.state_machine.record_cpu_color_convert_fallback(
                    "CPU BGRA->NV12 color-space conversion fallback (no D3D11 GPU surface provided)",
                );
                let nv12 = bgra_to_nv12(
                    data,
                    frame.width as usize,
                    frame.height as usize,
                    frame.stride as usize,
                    ColorMatrix::Bt709,
                )?;
                self.encode_nv12_bytes(&nv12.y_plane, &nv12.uv_plane, frame.timestamp_us, force_idr)
            }
            CapturedSurface::Rgba8 { .. } => Err(VideoError::InvalidInput(
                "WinMfHardwareEncoder requires D3D11 texture, NV12, or BGRA8 frame surface".into(),
            )),
        }
    }

    fn encode_i420(
        &mut self,
        frame: &I420Frame,
        pts_us: i64,
        force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        frame.validate()?;
        let w = self.cfg.width as usize;
        let h = self.cfg.height as usize;
        if frame.width != w || frame.height != h {
            return Err(VideoError::InvalidInput(format!(
                "I420 frame dimensions {}x{} do not match MF encoder {}x{}",
                frame.width, frame.height, w, h
            )));
        }
        let uv_w = w / 2;
        let uv_h = h / 2;
        let uv_len = w
            .checked_mul(uv_h)
            .ok_or_else(|| VideoError::InvalidInput("NV12 UV buffer length overflow".into()))?;
        let mut uv = vec![0u8; uv_len];
        for row in 0..uv_h {
            for col in 0..uv_w {
                uv[row * w + col * 2] = frame.u[row * uv_w + col];
                uv[row * w + col * 2 + 1] = frame.v[row * uv_w + col];
            }
        }
        self.encode_nv12_bytes(&frame.y, &uv, pts_us, force_idr)
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError> {
        if bitrate_bps == 0 {
            return Err(VideoError::InvalidInput("bitrate_bps must be > 0".into()));
        }
        let codec_api: ICodecAPI = self.transform.cast().map_err(|e| {
            VideoError::Encoder(format!(
                "QueryInterface(ICodecAPI) for set_bitrate failed: {e}"
            ))
        })?;
        let val = VARIANT::from(bitrate_bps);
        unsafe { codec_api.SetValue(&CODECAPI_AVEncCommonMeanBitRate, &val) }.map_err(|e| {
            VideoError::Encoder(format!(
                "ICodecAPI::SetValue(CODECAPI_AVEncCommonMeanBitRate={bitrate_bps}) failed: {e}"
            ))
        })?;
        self.cfg.bitrate_bps = bitrate_bps;
        Ok(())
    }

    fn force_next_idr(&mut self) {
        self.force_next_idr = true;
    }

    fn reinit(&mut self) -> Result<(), VideoError> {
        self.shutdown_current_mft();
        let built = Self::build_hardware_mft(&self.cfg, self.d3d11_device.as_ref())?;
        self.activate = built.activate;
        self.transform = built.transform;
        self.event_gen = built.event_gen;
        self.dxgi_manager = built.dxgi_manager;
        self.nv12_converter = built.nv12_converter;
        self.force_next_idr = true;
        let mut fresh_sm = MfHwEncoderStateMachine::new(self.cfg.codec, built.mft_name);
        fresh_sm.on_initialized()?;
        fresh_sm.on_streaming_started()?;
        self.state_machine = fresh_sm;
        Ok(())
    }
}
