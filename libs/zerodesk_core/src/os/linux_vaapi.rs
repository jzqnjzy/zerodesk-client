// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(target_os = "linux")]` VA-API hardware video encoder adapter loaded
//! strictly at runtime via `dlopen("libva.so.2")` + `dlopen("libva-drm.so.2")`.
//!
//! Mandatory constraints:
//! - Open-source Intel (`iHD` / `i965`) and AMD Mesa (`radeonsi`) drivers ONLY.
//! - ZERO proprietary SDKs (no MediaSDK / NVENC), ZERO compile-time `.so` linkage.
//! - Driven by `VaapiHwEncoderStateMachine`: `HardwareReady` ONLY on first valid IDR,
//!   30-frame stability window before resetting reinit attempts, monotonic `Instant`
//!   first-IDR timeout clock, and explicit `FailedNeedsRenegotiation` on exhaustion
//!   (NEVER silent software fallback!).
//! - Implementation status: runtime `libva.so.2` DRM render-node probing, open-source
//!   driver allowlist classification, profile/entrypoint capability querying,
//!   `vaCreateConfig`, and rate-control/lifecycle state management are live;
//!   hardware surface/coded-buffer bitstream submission in `encode_frame` /
//!   `encode_i420` honestly returns `VideoError::HardwareUnavailable` pending
//!   physical Linux Intel/AMD GPU bringup (`LIN-L3-04..06`) without burning reinit budget.

#![cfg(target_os = "linux")]

use super::{
    linux_dl::DynLib,
    linux_vaapi_logic::{
        clamp_vaapi_bitrate_bps, classify_vaapi_vendor_string, select_vaapi_encode_profile,
        validate_and_clamp_rate_control, validate_vaapi_enum_counts, VaapiCodec,
        VaapiCodecCapabilities, VaapiDriverClass, VaapiHwEncoderStateMachine,
        VaapiProfileEntrypoint, VAAPI_MAX_DIM, VA_ENTRYPOINT_ENC_SLICE, VA_ENTRYPOINT_ENC_SLICE_LP,
        VA_STATUS_SUCCESS,
    },
    traits::{
        CapturedFrame, HardwareCodec, HardwareCodecEvent, HardwareCodecKind, HardwareCodecState,
        HardwareEncodedPacket, HardwareVideoEncoder,
    },
};
use crate::{
    qoe::EncoderTarget,
    session::video::{I420Frame, VideoError},
};
use std::{
    ffi::{c_char, c_int, c_uint, c_void, CStr, CString},
    time::Instant,
};

type VaDisplay = *mut c_void;
type VaStatus = c_int;
type VaProfile = c_int;
type VaEntrypoint = c_int;
type VaConfigId = c_uint;
type VaContextId = c_uint;

struct VaApis {
    va_get_display_drm: unsafe extern "C" fn(c_int) -> VaDisplay,
    va_initialize: unsafe extern "C" fn(VaDisplay, *mut c_int, *mut c_int) -> VaStatus,
    va_terminate: unsafe extern "C" fn(VaDisplay) -> VaStatus,
    va_query_vendor_string: unsafe extern "C" fn(VaDisplay) -> *const c_char,
    va_max_num_profiles: unsafe extern "C" fn(VaDisplay) -> c_int,
    va_max_num_entrypoints: unsafe extern "C" fn(VaDisplay) -> c_int,
    va_query_config_profiles:
        unsafe extern "C" fn(VaDisplay, *mut VaProfile, *mut c_int) -> VaStatus,
    va_query_config_entrypoints:
        unsafe extern "C" fn(VaDisplay, VaProfile, *mut VaEntrypoint, *mut c_int) -> VaStatus,
    va_create_config: unsafe extern "C" fn(
        VaDisplay,
        VaProfile,
        VaEntrypoint,
        *mut c_void,
        c_int,
        *mut VaConfigId,
    ) -> VaStatus,
    va_destroy_config: unsafe extern "C" fn(VaDisplay, VaConfigId) -> VaStatus,
    va_destroy_context: unsafe extern "C" fn(VaDisplay, VaContextId) -> VaStatus,
    // Keep DynLib handles LAST for defense-in-depth drop ordering.
    _libva_drm: DynLib,
    _libva: DynLib,
}

// SAFETY: `VaApis` stores dlopen handles and immutable C function pointers.
unsafe impl Send for VaApis {}

impl VaApis {
    fn load() -> Result<Self, VideoError> {
        let libva = DynLib::open("libva.so.2").map_err(VideoError::HardwareUnavailable)?;
        let libva_drm = DynLib::open("libva-drm.so.2").map_err(VideoError::HardwareUnavailable)?;
        unsafe {
            Ok(Self {
                va_get_display_drm: libva_drm
                    .symbol("vaGetDisplayDRM")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_initialize: libva
                    .symbol("vaInitialize")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_terminate: libva
                    .symbol("vaTerminate")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_query_vendor_string: libva
                    .symbol("vaQueryVendorString")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_max_num_profiles: libva
                    .symbol("vaMaxNumProfiles")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_max_num_entrypoints: libva
                    .symbol("vaMaxNumEntrypoints")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_query_config_profiles: libva
                    .symbol("vaQueryConfigProfiles")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_query_config_entrypoints: libva
                    .symbol("vaQueryConfigEntrypoints")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_create_config: libva
                    .symbol("vaCreateConfig")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_destroy_config: libva
                    .symbol("vaDestroyConfig")
                    .map_err(VideoError::HardwareUnavailable)?,
                va_destroy_context: libva
                    .symbol("vaDestroyContext")
                    .map_err(VideoError::HardwareUnavailable)?,
                _libva_drm: libva_drm,
                _libva: libva,
            })
        }
    }
}

/// Summary produced by non-destructive DRM + VA-API device probing.
#[derive(Debug, Clone)]
pub struct VaapiProbeResult {
    pub render_node: String,
    pub vendor_string: String,
    pub driver_class: VaapiDriverClass,
    pub capabilities: VaapiCodecCapabilities,
    pub supported_encode_codecs: Vec<VaapiCodec>,
}

struct OwnedDrmVaSession {
    apis: VaApis,
    drm_fd: c_int,
    display: VaDisplay,
    config_id: Option<VaConfigId>,
    context_id: Option<VaContextId>,
}

// SAFETY: Exclusively owned by a single `LinuxVaapiHardwareEncoder` instance (`&mut self`).
unsafe impl Send for OwnedDrmVaSession {}

impl OwnedDrmVaSession {
    fn open_render_node(render_node: &str) -> Result<(Self, String, VaapiDriverClass), VideoError> {
        let apis = VaApis::load()?;
        let c_path = CString::new(render_node)
            .map_err(|_| VideoError::HardwareUnavailable("invalid DRM render node path".into()))?;
        let drm_fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
        if drm_fd < 0 {
            return Err(VideoError::HardwareUnavailable(format!(
                "open('{render_node}') failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let display = unsafe { (apis.va_get_display_drm)(drm_fd) };
        if display.is_null() {
            unsafe {
                libc::close(drm_fd);
            }
            return Err(VideoError::HardwareUnavailable(format!(
                "vaGetDisplayDRM('{render_node}') returned NULL"
            )));
        }
        let mut major: c_int = 0;
        let mut minor: c_int = 0;
        let st = unsafe { (apis.va_initialize)(display, &mut major, &mut minor) };
        if st != VA_STATUS_SUCCESS {
            unsafe {
                let _ = (apis.va_terminate)(display);
                libc::close(drm_fd);
            }
            return Err(VideoError::HardwareUnavailable(format!(
                "vaInitialize('{render_node}') failed with VAStatus {st:#x}"
            )));
        }

        let vendor_ptr = unsafe { (apis.va_query_vendor_string)(display) };
        let vendor = if vendor_ptr.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(vendor_ptr) }
                .to_string_lossy()
                .into_owned()
        };
        let driver_class = classify_vaapi_vendor_string(&vendor);

        Ok((
            Self {
                apis,
                drm_fd,
                display,
                config_id: None,
                context_id: None,
            },
            vendor,
            driver_class,
        ))
    }

    fn query_capabilities(&self) -> Result<VaapiCodecCapabilities, VideoError> {
        let raw_max_profiles = unsafe { (self.apis.va_max_num_profiles)(self.display) };
        let raw_max_entrypoints = unsafe { (self.apis.va_max_num_entrypoints)(self.display) };
        let Some((max_profiles, max_entrypoints)) =
            validate_vaapi_enum_counts(raw_max_profiles, raw_max_entrypoints)?
        else {
            return Ok(VaapiCodecCapabilities::default());
        };

        let mut profiles = vec![0 as VaProfile; max_profiles];
        let mut num_profiles: c_int = 0;
        let st = unsafe {
            (self.apis.va_query_config_profiles)(
                self.display,
                profiles.as_mut_ptr(),
                &mut num_profiles,
            )
        };
        if st != VA_STATUS_SUCCESS || num_profiles <= 0 {
            return Err(VideoError::HardwareUnavailable(format!(
                "vaQueryConfigProfiles failed with VAStatus {st:#x}"
            )));
        }
        let mut supported = Vec::new();
        let mut eps = vec![0 as VaEntrypoint; max_entrypoints];
        for &prof in &profiles[..(num_profiles as usize).min(profiles.len())] {
            let mut num_eps: c_int = 0;
            let ep_st = unsafe {
                (self.apis.va_query_config_entrypoints)(
                    self.display,
                    prof,
                    eps.as_mut_ptr(),
                    &mut num_eps,
                )
            };
            if ep_st != VA_STATUS_SUCCESS || num_eps <= 0 {
                continue;
            }
            for &ep in &eps[..(num_eps as usize).min(eps.len())] {
                if ep == VA_ENTRYPOINT_ENC_SLICE || ep == VA_ENTRYPOINT_ENC_SLICE_LP {
                    supported.push(VaapiProfileEntrypoint {
                        profile_id: prof,
                        entrypoint_id: ep,
                        low_power: ep == VA_ENTRYPOINT_ENC_SLICE_LP,
                    });
                }
            }
        }
        Ok(VaapiCodecCapabilities {
            supported_profiles: supported,
        })
    }

    fn create_encode_config(&mut self, sel: VaapiProfileEntrypoint) -> Result<VaConfigId, VideoError> {
        let mut cfg_id: VaConfigId = 0;
        let st = unsafe {
            (self.apis.va_create_config)(
                self.display,
                sel.profile_id,
                sel.entrypoint_id,
                std::ptr::null_mut(),
                0,
                &mut cfg_id,
            )
        };
        if st != VA_STATUS_SUCCESS {
            return Err(VideoError::HardwareUnavailable(format!(
                "vaCreateConfig(profile={}, ep={}) failed with VAStatus {st:#x}",
                sel.profile_id, sel.entrypoint_id
            )));
        }
        self.config_id = Some(cfg_id);
        Ok(cfg_id)
    }
}

impl Drop for OwnedDrmVaSession {
    fn drop(&mut self) {
        unsafe {
            if let Some(ctx) = self.context_id.take() {
                let _ = (self.apis.va_destroy_context)(self.display, ctx);
            }
            if let Some(cfg) = self.config_id.take() {
                let _ = (self.apis.va_destroy_config)(self.display, cfg);
            }
            if !self.display.is_null() {
                let _ = (self.apis.va_terminate)(self.display);
                self.display = std::ptr::null_mut();
            }
            if self.drm_fd >= 0 {
                let _ = libc::close(self.drm_fd);
                self.drm_fd = -1;
            }
        }
    }
}

/// Scans `/dev/dri/renderD128..renderD135` via runtime-loaded `libva.so.2` +
/// `libva-drm.so.2` and returns the first render node that satisfies the
/// open-source hardware driver allowlist AND exposes at least one supported
/// H.264/HEVC hardware encode entrypoint (continuing across multi-GPU nodes when
/// an earlier node is rejected or decode-only).
pub fn probe_vaapi_device() -> Result<VaapiProbeResult, VideoError> {
    let mut last_err = VideoError::HardwareUnavailable(
        "no accessible open-source hardware VA-API render node (/dev/dri/renderD128..135) found"
            .into(),
    );
    for idx in 128u32..=135u32 {
        let node = format!("/dev/dri/renderD{idx}");
        match OwnedDrmVaSession::open_render_node(&node) {
            Ok((session, vendor_string, driver_class)) => {
                if !driver_class.is_allowed_open_source_hw() {
                    last_err = VideoError::HardwareUnavailable(format!(
                        "skipped {node}: driver '{vendor_string}' ({}) rejected by open-source hardware allowlist",
                        driver_class.as_str()
                    ));
                    continue;
                }
                let capabilities = match session.query_capabilities() {
                    Ok(c) => c,
                    Err(e) => {
                        last_err = e;
                        continue;
                    }
                };
                let mut supported_encode_codecs = Vec::new();
                for codec in [VaapiCodec::H264, VaapiCodec::Hevc] {
                    if select_vaapi_encode_profile(codec, &capabilities).is_ok() {
                        supported_encode_codecs.push(codec);
                    }
                }
                if supported_encode_codecs.is_empty() {
                    last_err = VideoError::HardwareUnavailable(format!(
                        "skipped {node} ('{vendor_string}'): no supported H.264/HEVC hardware encode entrypoint"
                    ));
                    continue;
                }
                return Ok(VaapiProbeResult {
                    render_node: node,
                    vendor_string,
                    driver_class,
                    capabilities,
                    supported_encode_codecs,
                });
            }
            Err(e) => last_err = e,
        }
    }
    Err(last_err)
}

/// Thin Linux VA-API hardware encoder adapter implementing `HardwareCodec` +
/// `HardwareVideoEncoder`.
pub struct LinuxVaapiHardwareEncoder {
    render_node: String,
    codec: VaapiCodec,
    width: u32,
    height: u32,
    fps: u32,
    bitrate_bps: u32,
    force_idr_pending: bool,
    selected_profile: VaapiProfileEntrypoint,
    session: OwnedDrmVaSession,
    state: VaapiHwEncoderStateMachine,
    clock_epoch: Instant,
}

impl LinuxVaapiHardwareEncoder {
    pub fn new(
        codec: VaapiCodec,
        width: u32,
        height: u32,
        fps: u32,
        bitrate_bps: u32,
    ) -> Result<Self, VideoError> {
        let clamped_bps = clamp_vaapi_bitrate_bps(bitrate_bps)?;
        let raw_target = EncoderTarget {
            media_bitrate_kbps: clamped_bps / 1_000,
            fec_budget_kbps: 0,
            total_bitrate_kbps: clamped_bps / 1_000,
            width,
            height,
            fps_cap: fps,
            force_idr: true,
            bitrate_changed: true,
        };
        let rc = validate_and_clamp_rate_control(&raw_target, VAAPI_MAX_DIM, VAAPI_MAX_DIM)?;

        let probe = probe_vaapi_device()?;
        if !probe.driver_class.is_allowed_open_source_hw() {
            return Err(VideoError::HardwareUnavailable(format!(
                "VA-API driver '{}' ({}) rejected by open-source hardware allowlist (no silent SW fallback)",
                probe.vendor_string,
                probe.driver_class.as_str()
            )));
        }
        let selected_profile = select_vaapi_encode_profile(codec, &probe.capabilities)?;
        let (mut session, _vendor, driver_class) =
            OwnedDrmVaSession::open_render_node(&probe.render_node)?;
        session.create_encode_config(selected_profile)?;

        let clock_epoch = Instant::now();
        let mut state = VaapiHwEncoderStateMachine::new(codec, driver_class)?;
        state.mark_initialized()?;
        state.begin_waiting_first_idr(0)?;

        Ok(Self {
            render_node: probe.render_node,
            codec,
            width: rc.width,
            height: rc.height,
            fps: rc.fps_cap,
            bitrate_bps: rc.bitrate_bps,
            force_idr_pending: true,
            selected_profile,
            session,
            state,
            clock_epoch,
        })
    }

    pub fn driver_class(&self) -> VaapiDriverClass {
        self.state.driver_class()
    }

    pub fn selected_profile(&self) -> VaapiProfileEntrypoint {
        self.selected_profile
    }

    pub fn target_bitrate_bps(&self) -> u32 {
        self.bitrate_bps
    }

    pub fn fps_cap(&self) -> u32 {
        self.fps
    }

    fn monotonic_elapsed_ms(&self) -> u64 {
        self.clock_epoch.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
}

impl HardwareCodec for LinuxVaapiHardwareEncoder {
    fn codec(&self) -> HardwareCodecKind {
        self.codec.to_hardware_codec_kind()
    }

    fn backend_name(&self) -> &'static str {
        match self.state.driver_class() {
            VaapiDriverClass::IntelIhd => "linux_vaapi_intel_ihd",
            VaapiDriverClass::IntelI965 => "linux_vaapi_intel_i965",
            VaapiDriverClass::AmdRadeonsiMesa => "linux_vaapi_amd_radeonsi_mesa",
            VaapiDriverClass::RejectedSoftwareRasterizer
            | VaapiDriverClass::RejectedProprietaryOrUnknown => "linux_vaapi_rejected",
        }
    }

    fn state(&self) -> HardwareCodecState {
        self.state.state()
    }

    fn drain_events(&mut self) -> Vec<HardwareCodecEvent> {
        self.state.drain_events()
    }
}

impl HardwareVideoEncoder for LinuxVaapiHardwareEncoder {
    fn encode_frame(
        &mut self,
        frame: &CapturedFrame,
        _force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        self.state.ensure_not_terminal()?;
        if frame.width != self.width || frame.height != self.height {
            return Err(VideoError::InvalidInput(format!(
                "VA-API frame dims {}x{} != configured {}x{}",
                frame.width, frame.height, self.width, self.height
            )));
        }
        // Honest L1/L2 boundary: VA-API surface upload + coded-buffer bitstream submission
        // is pending physical Linux Intel/AMD GPU bringup (LIN-L3-04..06). Return
        // HardwareUnavailable explicitly without mutating encoder state, burning reinit
        // budget, or falling back to software.
        Err(VideoError::HardwareUnavailable(
            "VA-API bitstream submission pending physical Linux Intel/AMD GPU bringup (LIN-L3-04..06)"
                .into(),
        ))
    }

    fn encode_i420(
        &mut self,
        frame: &I420Frame,
        _pts_us: i64,
        _force_idr: bool,
    ) -> Result<Vec<HardwareEncodedPacket>, VideoError> {
        self.state.ensure_not_terminal()?;
        if frame.width as u32 != self.width || frame.height as u32 != self.height {
            return Err(VideoError::InvalidInput(format!(
                "VA-API I420 dims {}x{} != configured {}x{}",
                frame.width, frame.height, self.width, self.height
            )));
        }
        Err(VideoError::HardwareUnavailable(
            "VA-API bitstream submission pending physical Linux Intel/AMD GPU bringup (LIN-L3-04..06)"
                .into(),
        ))
    }

    fn set_bitrate(&mut self, bitrate_bps: u32) -> Result<(), VideoError> {
        self.state.ensure_not_terminal()?;
        self.bitrate_bps = clamp_vaapi_bitrate_bps(bitrate_bps)?;
        Ok(())
    }

    fn force_next_idr(&mut self) {
        self.force_idr_pending = true;
    }

    fn reinit(&mut self) -> Result<(), VideoError> {
        self.state.ensure_not_terminal()?;
        let (mut fresh_session, _vendor, driver_class) =
            OwnedDrmVaSession::open_render_node(&self.render_node)?;
        if !driver_class.is_allowed_open_source_hw() {
            return Err(VideoError::HardwareUnavailable(
                "VA-API driver no longer satisfies open-source hardware allowlist".into(),
            ));
        }
        fresh_session.create_encode_config(self.selected_profile)?;
        self.session = fresh_session;
        self.force_idr_pending = true;
        self.state
            .begin_waiting_first_idr(self.monotonic_elapsed_ms())?;
        Ok(())
    }
}
