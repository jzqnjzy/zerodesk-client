// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(windows)]` DXGI Desktop Duplication FFI adapter backed by the
//! official Microsoft `windows` crate and driven by `win_dxgi_logic`.
//!
//! Uses `CreateDXGIFactory1`, `D3D11CreateDevice`, `IDXGIOutput1::DuplicateOutput`,
//! `AcquireNextFrame` -> `classify_dxgi_hresult`, cursor shape/position readback,
//! staging `ID3D11Texture2D` BGRA readback, and RAII `ReleaseFrame`/`Unmap` guards.

use super::{
    traits::{CaptureError, CapturedFrame, CapturedSurface, ScreenCapturer},
    win_dxgi_logic::{
        CursorShapeUpdate, DxgiAdapterLuid, DxgiCaptureStateMachine, DxgiOutputDescriptor,
        DxgiTransitionOutcome,
    },
    OsError, OsScreenCapture, RawCapturedFrame,
};
use crate::frame::PixelFormat;
use std::{
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    time::{SystemTime, UNIX_EPOCH},
};
use windows::{
    core::Interface,
    Win32::{
        Foundation::HMODULE,
        Graphics::{
            Direct3D::{
                D3D_DRIVER_TYPE_UNKNOWN, D3D_FEATURE_LEVEL, D3D_FEATURE_LEVEL_11_0,
                D3D_FEATURE_LEVEL_11_1,
            },
            Direct3D11::{
                D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Texture2D,
                D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_MAPPED_SUBRESOURCE,
                D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC, D3D11_USAGE_STAGING,
            },
            Dxgi::{
                Common::{
                    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_ROTATION_ROTATE180,
                    DXGI_MODE_ROTATION_ROTATE270, DXGI_MODE_ROTATION_ROTATE90, DXGI_SAMPLE_DESC,
                },
                CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1,
                IDXGIOutputDuplication, IDXGIResource, DXGI_ADAPTER_DESC1, DXGI_ERROR_NOT_FOUND,
                DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_POINTER_SHAPE_INFO, DXGI_OUTPUT_DESC,
            },
        },
    },
};

fn utf16_z_to_string(buf: &[u16]) -> String {
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    OsString::from_wide(&buf[..len])
        .to_string_lossy()
        .into_owned()
}

fn now_epoch_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// Enumerates all attached DXGI outputs across all GPU adapters along with
/// their `AdapterLuid`, virtual desktop coordinates, and primary-monitor status.
pub fn enumerate_dxgi_outputs() -> Result<Vec<DxgiOutputDescriptor>, CaptureError> {
    let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }
        .map_err(|e| CaptureError::Fatal(format!("CreateDXGIFactory1 failed: {e}")))?;

    let mut outputs = Vec::new();
    let mut monitor_index = 0u32;
    let mut adapter_index = 0u32;

    loop {
        let adapter: IDXGIAdapter1 = match unsafe { factory.EnumAdapters1(adapter_index) } {
            Ok(a) => a,
            Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
            Err(e) => {
                return Err(CaptureError::Fatal(format!(
                    "EnumAdapters1({adapter_index}) failed: {e}"
                )));
            }
        };
        let mut adesc = DXGI_ADAPTER_DESC1::default();
        unsafe { adapter.GetDesc1(&mut adesc) }
            .map_err(|e| CaptureError::Fatal(format!("IDXGIAdapter1::GetDesc1 failed: {e}")))?;
        let adapter_luid = DxgiAdapterLuid::new(adesc.AdapterLuid.LowPart, adesc.AdapterLuid.HighPart);
        let adapter_name = utf16_z_to_string(&adesc.Description);

        let mut output_index = 0u32;
        loop {
            let output: IDXGIOutput = match unsafe { adapter.EnumOutputs(output_index) } {
                Ok(o) => o,
                Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => break,
                Err(e) => {
                    return Err(CaptureError::Fatal(format!(
                        "EnumOutputs({output_index}) failed: {e}"
                    )));
                }
            };
            let mut odesc = DXGI_OUTPUT_DESC::default();
            if unsafe { output.GetDesc(&mut odesc) }.is_ok() && odesc.AttachedToDesktop.as_bool() {
                let r = odesc.DesktopCoordinates;
                let width = (r.right - r.left).max(0) as u32;
                let height = (r.bottom - r.top).max(0) as u32;
                let rotation_degrees = match odesc.Rotation {
                    DXGI_MODE_ROTATION_ROTATE90 => 90,
                    DXGI_MODE_ROTATION_ROTATE180 => 180,
                    DXGI_MODE_ROTATION_ROTATE270 => 270,
                    _ => 0,
                };
                outputs.push(DxgiOutputDescriptor {
                    monitor_index,
                    adapter_index,
                    output_index,
                    adapter_luid,
                    adapter_name: adapter_name.clone(),
                    device_name: utf16_z_to_string(&odesc.DeviceName),
                    left: r.left,
                    top: r.top,
                    width,
                    height,
                    is_primary: r.left == 0 && r.top == 0,
                    rotation_degrees,
                });
                monitor_index = monitor_index.saturating_add(1);
            }
            output_index = output_index.saturating_add(1);
        }
        adapter_index = adapter_index.saturating_add(1);
    }

    Ok(outputs)
}

/// RAII guard guaranteeing `IDXGIOutputDuplication::ReleaseFrame()` runs on every exit path.
struct AcquiredFrameGuard {
    duplication: IDXGIOutputDuplication,
}

impl Drop for AcquiredFrameGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = self.duplication.ReleaseFrame();
        }
    }
}

/// RAII guard guaranteeing `ID3D11DeviceContext::Unmap()` runs on every exit path.
struct MappedStagingGuard<'a> {
    context: &'a ID3D11DeviceContext,
    texture: &'a ID3D11Texture2D,
}

impl Drop for MappedStagingGuard<'_> {
    fn drop(&mut self) {
        unsafe {
            self.context.Unmap(self.texture, 0);
        }
    }
}

/// Windows DXGI Desktop Duplication capturer implementing `ScreenCapturer` and
/// `OsScreenCapture`, exposing its D3D11 device and adapter LUID for zero-copy
/// Media Foundation hardware MFT binding.
pub struct WinDxgiCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    staging: Option<ID3D11Texture2D>,
    staging_dims: (u32, u32),
    state: DxgiCaptureStateMachine,
    acquire_timeout_ms: u32,
}

// Safety: COM interfaces used exclusively from the single owning capturer thread (`&mut self`);
// D3D11 device/context and DXGI duplication objects are free-threaded agile COM interfaces.
unsafe impl Send for WinDxgiCapturer {}

impl WinDxgiCapturer {
    pub fn new(monitor_index: u32) -> Result<Self, CaptureError> {
        let outputs = enumerate_dxgi_outputs()?;
        if outputs.is_empty() {
            return Err(CaptureError::DesktopUnavailable(
                "no attached DXGI outputs found".into(),
            ));
        }
        let mut state = DxgiCaptureStateMachine::new();
        state.set_outputs(outputs);
        let target = state.select_monitor(monitor_index)?.clone();
        let (device, context, duplication) = Self::create_duplication_for_output(&target)?;
        state.on_recreate_succeeded();

        Ok(Self {
            device,
            context,
            duplication,
            staging: None,
            staging_dims: (target.width, target.height),
            state,
            acquire_timeout_ms: 16,
        })
    }

    pub fn set_acquire_timeout_ms(&mut self, timeout_ms: u32) {
        self.acquire_timeout_ms = timeout_ms;
    }

    pub fn d3d11_device(&self) -> &ID3D11Device {
        &self.device
    }

    pub fn adapter_luid(&self) -> Option<DxgiAdapterLuid> {
        self.state.active_adapter_luid()
    }

    pub fn state_machine(&self) -> &DxgiCaptureStateMachine {
        &self.state
    }

    fn create_duplication_for_output(
        target: &DxgiOutputDescriptor,
    ) -> Result<(ID3D11Device, ID3D11DeviceContext, IDXGIOutputDuplication), CaptureError> {
        let factory: IDXGIFactory1 = unsafe { CreateDXGIFactory1() }
            .map_err(|e| CaptureError::Fatal(format!("CreateDXGIFactory1 failed: {e}")))?;
        let adapter: IDXGIAdapter1 = unsafe { factory.EnumAdapters1(target.adapter_index) }
            .map_err(|e| {
                CaptureError::ReinitRequired(format!(
                    "EnumAdapters1({}) failed: {e}",
                    target.adapter_index
                ))
            })?;
        let output: IDXGIOutput = unsafe { adapter.EnumOutputs(target.output_index) }.map_err(
            |e| {
                CaptureError::ReinitRequired(format!(
                    "EnumOutputs({}) failed: {e}",
                    target.output_index
                ))
            },
        )?;
        let output1: IDXGIOutput1 = output
            .cast()
            .map_err(|e| CaptureError::Fatal(format!("QueryInterface(IDXGIOutput1) failed: {e}")))?;

        let feature_levels: [D3D_FEATURE_LEVEL; 2] =
            [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        unsafe {
            D3D11CreateDevice(
                &adapter,
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&feature_levels),
                D3D11_SDK_VERSION,
                Some(&mut device),
                None,
                Some(&mut context),
            )
        }
        .map_err(|e| CaptureError::ReinitRequired(format!("D3D11CreateDevice failed: {e}")))?;

        let device = device
            .ok_or_else(|| CaptureError::Fatal("D3D11CreateDevice returned null device".into()))?;
        let context = context.ok_or_else(|| {
            CaptureError::Fatal("D3D11CreateDevice returned null immediate context".into())
        })?;

        let duplication = unsafe { output1.DuplicateOutput(&device) }.map_err(|e| {
            let hr = e.code().0;
            match super::win_dxgi_logic::classify_dxgi_hresult(hr) {
                super::win_dxgi_logic::DxgiAction::PauseAndWaitDesktop => {
                    CaptureError::DesktopUnavailable(format!("DuplicateOutput paused: {e}"))
                }
                super::win_dxgi_logic::DxgiAction::RecreateDuplication => {
                    CaptureError::ReinitRequired(format!("DuplicateOutput needs recreate: {e}"))
                }
                _ => CaptureError::Fatal(format!("DuplicateOutput failed: {e}")),
            }
        })?;

        Ok((device, context, duplication))
    }

    fn ensure_staging_texture(&mut self, width: u32, height: u32) -> Result<&ID3D11Texture2D, CaptureError> {
        let needs_new = self.staging.is_none() || self.staging_dims != (width, height);
        if needs_new {
            let desc = D3D11_TEXTURE2D_DESC {
                Width: width,
                Height: height,
                MipLevels: 1,
                ArraySize: 1,
                Format: DXGI_FORMAT_B8G8R8A8_UNORM,
                SampleDesc: DXGI_SAMPLE_DESC {
                    Count: 1,
                    Quality: 0,
                },
                Usage: D3D11_USAGE_STAGING,
                BindFlags: 0,
                CPUAccessFlags: D3D11_CPU_ACCESS_READ.0 as u32,
                MiscFlags: 0,
            };
            let mut tex: Option<ID3D11Texture2D> = None;
            unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex)) }
                .map_err(|e| CaptureError::Fatal(format!("CreateTexture2D(staging) failed: {e}")))?;
            self.staging = tex;
            self.staging_dims = (width, height);
        }
        self.staging
            .as_ref()
            .ok_or_else(|| CaptureError::Fatal("staging texture missing after creation".into()))
    }

    fn update_cursor_from_frame_info(&mut self, info: &DXGI_OUTDUPL_FRAME_INFO) {
        self.state.cursor_mut().update_position(
            info.PointerPosition.Position.x,
            info.PointerPosition.Position.y,
            info.PointerPosition.Visible.as_bool(),
            info.LastMouseUpdateTime,
        );
        if info.PointerShapeBufferSize > 0 {
            let mut buf = vec![0u8; info.PointerShapeBufferSize as usize];
            let mut required = 0u32;
            let mut shape_info = DXGI_OUTDUPL_POINTER_SHAPE_INFO::default();
            let res = unsafe {
                self.duplication.GetFramePointerShape(
                    info.PointerShapeBufferSize,
                    buf.as_mut_ptr().cast(),
                    &mut required,
                    &mut shape_info,
                )
            };
            if res.is_ok() {
                buf.truncate(required as usize);
                let _ = self.state.cursor_mut().update_shape(CursorShapeUpdate {
                    raw_shape_type: shape_info.Type,
                    width: shape_info.Width,
                    height: shape_info.Height,
                    pitch: shape_info.Pitch,
                    hotspot_x: shape_info.HotSpot.x.max(0) as u32,
                    hotspot_y: shape_info.HotSpot.y.max(0) as u32,
                    bytes: buf,
                });
            }
        }
    }

    pub fn recreate(&mut self) -> Result<(), CaptureError> {
        let outputs = enumerate_dxgi_outputs()?;
        self.state.set_outputs(outputs);
        let Some(target) = self.state.active_output().cloned() else {
            return Err(CaptureError::DesktopUnavailable(
                "no active DXGI output available during recreate".into(),
            ));
        };
        let (device, context, duplication) = Self::create_duplication_for_output(&target)?;
        self.device = device;
        self.context = context;
        self.duplication = duplication;
        self.staging = None;
        self.staging_dims = (target.width, target.height);
        self.state.on_recreate_succeeded();
        Ok(())
    }
}

impl ScreenCapturer for WinDxgiCapturer {
    fn dimensions(&self) -> (u32, u32) {
        self.staging_dims
    }

    fn monitor_id(&self) -> u32 {
        self.state.active_monitor_index()
    }

    fn capture_next_frame(&mut self) -> Result<CapturedFrame, CaptureError> {
        let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();
        let mut desktop_resource: Option<IDXGIResource> = None;

        let acquire_res = unsafe {
            self.duplication.AcquireNextFrame(
                self.acquire_timeout_ms,
                &mut frame_info,
                &mut desktop_resource,
            )
        };

        if let Err(err) = acquire_res {
            let hr = err.code().0;
            return match self.state.on_acquire_hresult(hr) {
                DxgiTransitionOutcome::TimeoutNoChange => Err(CaptureError::Timeout),
                DxgiTransitionOutcome::ScheduleRecreate {
                    backoff_ms,
                    attempt,
                } => Err(CaptureError::ReinitRequired(format!(
                    "DXGI acquire requires recreate (attempt={attempt}, backoff_ms={backoff_ms}, hr={:#010x})",
                    hr as u32
                ))),
                DxgiTransitionOutcome::PauseDesktop {
                    reason,
                    retry_after_ms,
                } => Err(CaptureError::DesktopUnavailable(format!(
                    "DXGI desktop paused ({reason:?}, retry_after_ms={retry_after_ms}, hr={:#010x})",
                    hr as u32
                ))),
                DxgiTransitionOutcome::Failed { error, .. } => Err(error),
                DxgiTransitionOutcome::FrameReady => Err(CaptureError::Timeout),
            };
        }

        // Frame acquired: guard guarantees ReleaseFrame runs before returning.
        let _frame_guard = AcquiredFrameGuard {
            duplication: self.duplication.clone(),
        };
        self.state.on_frame_acquired();
        self.update_cursor_from_frame_info(&frame_info);

        let resource = desktop_resource.ok_or_else(|| {
            CaptureError::ReinitRequired("AcquireNextFrame returned null IDXGIResource".into())
        })?;
        let gpu_tex: ID3D11Texture2D = resource.cast().map_err(|e| {
            CaptureError::Fatal(format!("QueryInterface(ID3D11Texture2D) failed: {e}"))
        })?;

        let mut tex_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { gpu_tex.GetDesc(&mut tex_desc) };
        let width = tex_desc.Width;
        let height = tex_desc.Height;

        let staging = self.ensure_staging_texture(width, height)?.clone();
        unsafe {
            self.context.CopyResource(&staging, &gpu_tex);
        }

        let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();
        unsafe {
            self.context
                .Map(&staging, 0, D3D11_MAP_READ, 0, Some(&mut mapped))
        }
        .map_err(|e| CaptureError::Fatal(format!("ID3D11DeviceContext::Map failed: {e}")))?;
        let _map_guard = MappedStagingGuard {
            context: &self.context,
            texture: &staging,
        };

        let row_pitch = mapped.RowPitch;
        let total_bytes = (row_pitch as usize)
            .checked_mul(height as usize)
            .ok_or_else(|| CaptureError::Fatal("mapped BGRA buffer size overflow".into()))?;
        if mapped.pData.is_null() {
            return Err(CaptureError::Fatal(
                "ID3D11DeviceContext::Map returned null pData".into(),
            ));
        }
        let data = unsafe { std::slice::from_raw_parts(mapped.pData.cast::<u8>(), total_bytes) }
            .to_vec();

        Ok(CapturedFrame {
            width,
            height,
            stride: row_pitch,
            surface: CapturedSurface::Bgra8 { data },
            timestamp_us: now_epoch_us(),
            monitor_id: self.state.active_monitor_index(),
            cursor: Some(self.state.cursor().to_metadata()),
        })
    }
}

impl OsScreenCapture for WinDxgiCapturer {
    fn dimensions(&self) -> (u32, u32) {
        ScreenCapturer::dimensions(self)
    }

    fn capture_frame(&mut self) -> Result<RawCapturedFrame, OsError> {
        let frame = self
            .capture_next_frame()
            .map_err(CaptureError::into_os_error)?;
        let width = frame.width;
        let height = frame.height;
        let stride = frame.stride;
        match frame.surface {
            CapturedSurface::Bgra8 { data } => Ok(RawCapturedFrame {
                width,
                height,
                stride,
                pixel_format: PixelFormat::Bgra8,
                data,
            }),
            _ => Err(OsError::CaptureFailed(
                "WinDxgiCapturer produced non-BGRA frame".into(),
            )),
        }
    }
}
