// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(windows)]` DXGI Desktop Duplication FFI adapter backed by the
//! official Microsoft `windows` crate and driven by `win_dxgi_logic`.
//!
//! Uses `CreateDXGIFactory1`, `D3D11CreateDevice` with `BGRA_SUPPORT | VIDEO_SUPPORT`
//! plus `ID3D11Multithread::SetMultithreadProtected(true)`, `IDXGIOutput1::DuplicateOutput`,
//! `AcquireNextFrame` -> `classify_dxgi_hresult`, rotation-aware cursor & dimensions,
//! row-by-row staging readback, and RAII `ReleaseFrame`/`Unmap` guards.

#![cfg(windows)]

use super::{
    traits::{
        CaptureError, CapturedFrame, CapturedSurface, D3d11SharedFrame, D3d11SurfaceFormat,
        ScreenCapturer,
    },
    win_dxgi_logic::{
        rotate_point, rotated_dims, CursorShapeUpdate, DxgiAdapterLuid, DxgiCaptureStateMachine,
        DxgiOutputDescriptor, DxgiTransitionOutcome,
    },
    OsError, OsScreenCapture, RawCapturedFrame,
};
use crate::frame::PixelFormat;
use std::{
    ffi::OsString,
    os::windows::ffi::OsStringExt,
    sync::Arc,
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
                D3D11CreateDevice, ID3D11Device, ID3D11DeviceContext, ID3D11Multithread,
                ID3D11Texture2D, D3D11_BIND_SHADER_RESOURCE, D3D11_CPU_ACCESS_READ,
                D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
                D3D11_MAPPED_SUBRESOURCE, D3D11_MAP_READ, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC,
                D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING,
            },
            Dxgi::{
                Common::{
                    DXGI_FORMAT_B8G8R8A8_UNORM, DXGI_MODE_ROTATION, DXGI_MODE_ROTATION_ROTATE180,
                    DXGI_MODE_ROTATION_ROTATE270, DXGI_MODE_ROTATION_ROTATE90, DXGI_SAMPLE_DESC,
                },
                CreateDXGIFactory1, IDXGIAdapter1, IDXGIFactory1, IDXGIOutput, IDXGIOutput1,
                IDXGIOutputDuplication, IDXGIResource, DXGI_ADAPTER_DESC1, DXGI_ERROR_NOT_FOUND,
                DXGI_OUTDUPL_DESC, DXGI_OUTDUPL_FRAME_INFO, DXGI_OUTDUPL_POINTER_SHAPE_INFO,
                DXGI_OUTPUT_DESC,
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

fn rotation_enum_to_degrees(rot: DXGI_MODE_ROTATION) -> u16 {
    match rot {
        DXGI_MODE_ROTATION_ROTATE90 => 90,
        DXGI_MODE_ROTATION_ROTATE180 => 180,
        DXGI_MODE_ROTATION_ROTATE270 => 270,
        _ => 0,
    }
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
                let width = r.right.saturating_sub(r.left).max(0) as u32;
                let height = r.bottom.saturating_sub(r.top).max(0) as u32;
                let rotation_degrees = rotation_enum_to_degrees(odesc.Rotation);
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

struct DuplicationBundle {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    surface_dims: (u32, u32),
    rotation_degrees: u16,
}

/// Windows DXGI Desktop Duplication capturer implementing `ScreenCapturer` and
/// `OsScreenCapture`, exposing its D3D11 device (with `VIDEO_SUPPORT` +
/// `ID3D11Multithread::SetMultithreadProtected(true)`) and adapter LUID for
/// zero-copy Media Foundation hardware MFT binding.
pub struct WinDxgiCapturer {
    device: ID3D11Device,
    context: ID3D11DeviceContext,
    duplication: IDXGIOutputDuplication,
    staging: Option<ID3D11Texture2D>,
    surface_dims: (u32, u32),
    effective_dims: (u32, u32),
    rotation_degrees: u16,
    state: DxgiCaptureStateMachine,
    acquire_timeout_ms: u32,
}

// SAFETY: COM interfaces are owned exclusively by this capturer (`&mut self`), and
// `ID3D11Multithread::SetMultithreadProtected(true)` is enabled on the immediate context.
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
        let bundle = Self::create_duplication_for_output(&target)?;
        state.on_recreate_succeeded()?;
        let effective_dims = rotated_dims(
            bundle.surface_dims.0,
            bundle.surface_dims.1,
            bundle.rotation_degrees,
        );

        Ok(Self {
            device: bundle.device,
            context: bundle.context,
            duplication: bundle.duplication,
            staging: None,
            surface_dims: bundle.surface_dims,
            effective_dims,
            rotation_degrees: bundle.rotation_degrees,
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

    pub fn d3d11_context(&self) -> &ID3D11DeviceContext {
        &self.context
    }

    pub fn adapter_luid(&self) -> Option<DxgiAdapterLuid> {
        self.state.active_adapter_luid()
    }

    pub fn rotation_degrees(&self) -> u16 {
        self.rotation_degrees
    }

    pub fn state_machine(&self) -> &DxgiCaptureStateMachine {
        &self.state
    }

    fn create_duplication_for_output(
        target: &DxgiOutputDescriptor,
    ) -> Result<DuplicationBundle, CaptureError> {
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
        let output1: IDXGIOutput1 = output.cast().map_err(|e| {
            CaptureError::Fatal(format!("QueryInterface(IDXGIOutput1) failed: {e}"))
        })?;

        let feature_levels: [D3D_FEATURE_LEVEL; 2] =
            [D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0];
        let mut device: Option<ID3D11Device> = None;
        let mut context: Option<ID3D11DeviceContext> = None;
        unsafe {
            D3D11CreateDevice(
                &adapter,
                D3D_DRIVER_TYPE_UNKNOWN,
                HMODULE::default(),
                D3D11_CREATE_DEVICE_BGRA_SUPPORT | D3D11_CREATE_DEVICE_VIDEO_SUPPORT,
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

        let mt: ID3D11Multithread = context.cast().map_err(|e| {
            CaptureError::Fatal(format!("QueryInterface(ID3D11Multithread) failed: {e}"))
        })?;
        unsafe {
            let _ = mt.SetMultithreadProtected(true);
        }

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

        let mut dupl_desc = DXGI_OUTDUPL_DESC::default();
        unsafe { duplication.GetDesc(&mut dupl_desc) };
        let surface_w = dupl_desc.ModeDesc.Width.max(1);
        let surface_h = dupl_desc.ModeDesc.Height.max(1);
        let rotation_degrees = rotation_enum_to_degrees(dupl_desc.Rotation);

        Ok(DuplicationBundle {
            device,
            context,
            duplication,
            surface_dims: (surface_w, surface_h),
            rotation_degrees,
        })
    }

    fn ensure_staging_texture(
        &mut self,
        width: u32,
        height: u32,
    ) -> Result<&ID3D11Texture2D, CaptureError> {
        let needs_new = self.staging.is_none() || self.surface_dims != (width, height);
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
            unsafe { self.device.CreateTexture2D(&desc, None, Some(&mut tex)) }.map_err(|e| {
                CaptureError::Fatal(format!("CreateTexture2D(staging) failed: {e}"))
            })?;
            self.staging = tex;
            self.surface_dims = (width, height);
            self.effective_dims = rotated_dims(width, height, self.rotation_degrees);
        }
        self.staging
            .as_ref()
            .ok_or_else(|| CaptureError::Fatal("staging texture missing after creation".into()))
    }

    fn update_cursor_from_frame_info(&mut self, info: &DXGI_OUTDUPL_FRAME_INFO) {
        let (rx, ry) = rotate_point(
            info.PointerPosition.Position.x,
            info.PointerPosition.Position.y,
            self.surface_dims.0,
            self.surface_dims.1,
            self.rotation_degrees,
        );
        self.state.cursor_mut().update_position(
            rx,
            ry,
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

    /// Captures the next desktop frame directly into a GPU-resident `ID3D11Texture2D`
    /// copy wrapped in `CapturedSurface::D3d11Texture(Arc<D3d11SharedFrame>)` for
    /// zero-copy Media Foundation hardware encoding (zero CPU readback).
    pub fn capture_next_d3d11_frame(&mut self) -> Result<CapturedFrame, CaptureError> {
        let (gpu_tex, _guard) = self.acquire_gpu_texture()?;
        let mut tex_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { gpu_tex.GetDesc(&mut tex_desc) };
        if tex_desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return Err(CaptureError::Fatal(format!(
                "unsupported DXGI surface format {:?} (expected DXGI_FORMAT_B8G8R8A8_UNORM)",
                tex_desc.Format
            )));
        }
        let copy_desc = D3D11_TEXTURE2D_DESC {
            Width: tex_desc.Width,
            Height: tex_desc.Height,
            MipLevels: 1,
            ArraySize: 1,
            Format: DXGI_FORMAT_B8G8R8A8_UNORM,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: D3D11_USAGE_DEFAULT,
            BindFlags: D3D11_BIND_SHADER_RESOURCE.0 as u32,
            CPUAccessFlags: 0,
            MiscFlags: 0,
        };
        let mut owned_tex: Option<ID3D11Texture2D> = None;
        unsafe { self.device.CreateTexture2D(&copy_desc, None, Some(&mut owned_tex)) }
            .map_err(|e| CaptureError::Fatal(format!("CreateTexture2D(gpu copy) failed: {e}")))?;
        let owned_tex = owned_tex
            .ok_or_else(|| CaptureError::Fatal("CreateTexture2D(gpu copy) returned null".into()))?;
        unsafe {
            self.context.CopyResource(&owned_tex, &gpu_tex);
        }
        let luid = self.state.active_adapter_luid().unwrap_or_default().as_tuple();
        let shared = Arc::new(D3d11SharedFrame::from_texture(
            owned_tex,
            luid,
            D3d11SurfaceFormat::Bgra8Unorm,
            None,
        ));
        Ok(CapturedFrame {
            width: tex_desc.Width,
            height: tex_desc.Height,
            stride: tex_desc.Width.saturating_mul(4),
            surface: CapturedSurface::D3d11Texture(shared),
            timestamp_us: now_epoch_us(),
            monitor_id: self.state.active_monitor_index(),
            cursor: Some(self.state.cursor().to_metadata()),
        })
    }

    fn acquire_gpu_texture(&mut self) -> Result<(ID3D11Texture2D, AcquiredFrameGuard), CaptureError> {
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

        let frame_guard = AcquiredFrameGuard {
            duplication: self.duplication.clone(),
        };
        if let DxgiTransitionOutcome::Failed { error, .. } = self.state.on_frame_acquired() {
            return Err(error);
        }
        self.update_cursor_from_frame_info(&frame_info);

        let resource = desktop_resource.ok_or_else(|| {
            CaptureError::ReinitRequired("AcquireNextFrame returned null IDXGIResource".into())
        })?;
        let gpu_tex: ID3D11Texture2D = resource.cast().map_err(|e| {
            CaptureError::Fatal(format!("QueryInterface(ID3D11Texture2D) failed: {e}"))
        })?;
        Ok((gpu_tex, frame_guard))
    }

    pub fn recreate(&mut self) -> Result<(), CaptureError> {
        let outputs = enumerate_dxgi_outputs()?;
        self.state.set_outputs(outputs);
        let Some(target) = self.state.active_output().cloned() else {
            return Err(CaptureError::DesktopUnavailable(
                "no active DXGI output available during recreate".into(),
            ));
        };
        let bundle = Self::create_duplication_for_output(&target)?;
        self.device = bundle.device;
        self.context = bundle.context;
        self.duplication = bundle.duplication;
        self.staging = None;
        self.surface_dims = bundle.surface_dims;
        self.rotation_degrees = bundle.rotation_degrees;
        self.effective_dims = rotated_dims(
            bundle.surface_dims.0,
            bundle.surface_dims.1,
            bundle.rotation_degrees,
        );
        self.state.on_recreate_succeeded()?;
        Ok(())
    }
}

impl ScreenCapturer for WinDxgiCapturer {
    fn dimensions(&self) -> (u32, u32) {
        self.effective_dims
    }

    fn monitor_id(&self) -> u32 {
        self.state.active_monitor_index()
    }

    fn capture_next_frame(&mut self) -> Result<CapturedFrame, CaptureError> {
        let (gpu_tex, _frame_guard) = self.acquire_gpu_texture()?;

        let mut tex_desc = D3D11_TEXTURE2D_DESC::default();
        unsafe { gpu_tex.GetDesc(&mut tex_desc) };
        if tex_desc.Format != DXGI_FORMAT_B8G8R8A8_UNORM {
            return Err(CaptureError::Fatal(format!(
                "unsupported DXGI surface format {:?} (expected DXGI_FORMAT_B8G8R8A8_UNORM)",
                tex_desc.Format
            )));
        }
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

        let row_bytes = (width as usize)
            .checked_mul(4)
            .ok_or_else(|| CaptureError::Fatal("BGRA row_bytes overflow".into()))?;
        let row_pitch = mapped.RowPitch as usize;
        if row_pitch < row_bytes {
            return Err(CaptureError::Fatal(format!(
                "mapped RowPitch {row_pitch} < width*4 ({row_bytes})"
            )));
        }
        let packed_len = row_bytes
            .checked_mul(height as usize)
            .ok_or_else(|| CaptureError::Fatal("packed BGRA buffer overflow".into()))?;
        if mapped.pData.is_null() {
            return Err(CaptureError::Fatal(
                "ID3D11DeviceContext::Map returned null pData".into(),
            ));
        }

        // Copy strictly row-by-row (`width * 4` bytes per row) so we NEVER read past
        // `RowPitch * (Height - 1) + Width * 4` on the last scanline.
        let mut data = vec![0u8; packed_len];
        let src_base = mapped.pData.cast::<u8>();
        for row in 0..(height as usize) {
            let src_row = unsafe {
                std::slice::from_raw_parts(src_base.add(row * row_pitch), row_bytes)
            };
            data[row * row_bytes..(row + 1) * row_bytes].copy_from_slice(src_row);
        }

        Ok(CapturedFrame {
            width,
            height,
            stride: width.saturating_mul(4),
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
