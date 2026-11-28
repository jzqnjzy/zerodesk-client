// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(target_os = "linux")]` screen capture adapter supporting:
//! - Wayland `xdg-desktop-portal` ScreenCast + PipeWire (`dlopen("libpipewire-0.3.so.0")`)
//! - X11 `XShm` / `XRandR` / `XFixes` (`dlopen("libX11.so.6")` + `libXext.so.6` +
//!   `libXrandr.so.2` + `libXfixes.so.3`)
//!
//! All state transitions, buffer bounds checks, rotation math, and cursor ARGB
//! validation are delegated to `linux_capture_logic.rs`. ZERO compile-time `.so`
//! linking is used.

#![cfg(target_os = "linux")]

use super::{
    linux_capture_logic::{
        convert_xfixes_argb_to_cursor_metadata, copy_shm_frame_rows, detect_linux_session_kind,
        LinuxSessionKind, PipeWireBufferKind, PipeWireFrameArrival, PipeWireStreamParams,
        WaylandPortalCaptureStateMachine, X11CaptureErrorKind, X11CaptureStateMachine,
        X11MonitorTopology, X11OutputDescriptor,
    },
    linux_dl::DynLib,
    traits::{CaptureError, CapturedFrame, CapturedSurface, CursorMetadata, ScreenCapturer},
    OsPermission,
};
use std::{
    ffi::{c_char, c_int, c_long, c_uint, c_ulong, c_ushort, c_void, CStr, CString},
    path::Path,
    ptr,
    time::{SystemTime, UNIX_EPOCH},
};

fn now_epoch_us() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// Detects the current Linux session class from live environment variables.
pub fn current_linux_session_kind() -> LinuxSessionKind {
    let xdg = std::env::var("XDG_SESSION_TYPE").ok();
    let wl = std::env::var("WAYLAND_DISPLAY").ok();
    let disp = std::env::var("DISPLAY").ok();
    detect_linux_session_kind(xdg.as_deref(), wl.as_deref(), disp.as_deref())
}

/// Non-destructive probe checking whether a D-Bus session bus and
/// `xdg-desktop-portal` runtime artifacts are present on this Linux host.
pub fn probe_portal_availability() -> (bool, bool, bool, Option<String>) {
    let dbus_addr = std::env::var("DBUS_SESSION_BUS_ADDRESS").ok();
    let xdg_runtime = std::env::var("XDG_RUNTIME_DIR").ok();
    let dbus_present = dbus_addr
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
        || xdg_runtime
            .as_deref()
            .is_some_and(|dir| Path::new(dir).join("bus").exists());

    if !dbus_present {
        return (
            false,
            false,
            false,
            Some("D-Bus session bus not detected (DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR/bus absent)".into()),
        );
    }

    let portal_service_installed = [
        "/usr/share/dbus-1/services/org.freedesktop.portal.Desktop.service",
        "/usr/local/share/dbus-1/services/org.freedesktop.portal.Desktop.service",
    ]
    .iter()
    .any(|p| Path::new(p).exists());

    let pipewire_lib_ok = DynLib::open("libpipewire-0.3.so.0").is_ok();
    let screencast_ok = portal_service_installed && pipewire_lib_ok;
    let remote_desktop_ok = portal_service_installed;

    let note = if !portal_service_installed {
        Some("xdg-desktop-portal D-Bus service descriptor not found".into())
    } else if !pipewire_lib_ok {
        Some("libpipewire-0.3.so.0 not installed; Wayland ScreenCast unavailable".into())
    } else {
        None
    };

    (dbus_present, screencast_ok, remote_desktop_ok, note)
}

// ============================================================================
// X11 / XShm / XRandR / XFixes Clean-Room Dynamic ABI Bindings
// ============================================================================

type XDisplay = c_void;
type XWindow = c_ulong;
type XAtom = c_ulong;
type XVisual = c_void;
type XDrawable = c_ulong;
type XBool = c_int;
type XStatus = c_int;

const X_ZPIXMAP: c_int = 2;
const X_ALL_PLANES: c_ulong = !0;

#[repr(C)]
struct XShmSegmentInfo {
    shmseg: c_ulong,
    shmid: c_int,
    shmaddr: *mut c_char,
    read_only: XBool,
}

#[repr(C)]
struct XImage {
    width: c_int,
    height: c_int,
    xoffset: c_int,
    format: c_int,
    data: *mut c_char,
    byte_order: c_int,
    bitmap_unit: c_int,
    bitmap_bit_order: c_int,
    bitmap_pad: c_int,
    depth: c_int,
    bytes_per_line: c_int,
    bits_per_pixel: c_int,
    red_mask: c_ulong,
    green_mask: c_ulong,
    blue_mask: c_ulong,
    obdata: *mut c_void,
    // Function table follows in Xlib; we never construct XImage by value.
}

#[repr(C)]
struct XRRMonitorInfo {
    name: XAtom,
    primary: XBool,
    automatic: XBool,
    noutput: c_int,
    x: c_int,
    y: c_int,
    width: c_int,
    height: c_int,
    mwidth: c_int,
    mheight: c_int,
    outputs: *mut c_ulong,
}

#[repr(C)]
struct XFixesCursorImage {
    x: i16,
    y: i16,
    width: c_ushort,
    height: c_ushort,
    xhot: c_ushort,
    yhot: c_ushort,
    cursor_serial: c_ulong,
    pixels: *mut c_ulong,
    atom: XAtom,
    name: *const c_char,
}

struct X11Apis {
    _x11: DynLib,
    _xext: DynLib,
    _xrandr: Option<DynLib>,
    _xfixes: Option<DynLib>,
    x_open_display: unsafe extern "C" fn(*const c_char) -> *mut XDisplay,
    x_close_display: unsafe extern "C" fn(*mut XDisplay) -> c_int,
    x_default_screen: unsafe extern "C" fn(*mut XDisplay) -> c_int,
    x_root_window: unsafe extern "C" fn(*mut XDisplay, c_int) -> XWindow,
    x_default_visual: unsafe extern "C" fn(*mut XDisplay, c_int) -> *mut XVisual,
    x_default_depth: unsafe extern "C" fn(*mut XDisplay, c_int) -> c_int,
    x_display_width: unsafe extern "C" fn(*mut XDisplay, c_int) -> c_int,
    x_display_height: unsafe extern "C" fn(*mut XDisplay, c_int) -> c_int,
    x_get_atom_name: unsafe extern "C" fn(*mut XDisplay, XAtom) -> *mut c_char,
    x_free: unsafe extern "C" fn(*mut c_void) -> c_int,
    x_destroy_image_fallback: unsafe extern "C" fn(*mut XDisplay) -> c_int,
    x_shm_query_extension: unsafe extern "C" fn(*mut XDisplay) -> XBool,
    x_shm_create_image: unsafe extern "C" fn(
        *mut XDisplay,
        *mut XVisual,
        c_uint,
        c_int,
        *mut c_char,
        *mut XShmSegmentInfo,
        c_uint,
        c_uint,
    ) -> *mut XImage,
    x_shm_attach: unsafe extern "C" fn(*mut XDisplay, *mut XShmSegmentInfo) -> XStatus,
    x_shm_detach: unsafe extern "C" fn(*mut XDisplay, *mut XShmSegmentInfo) -> XStatus,
    x_shm_get_image: unsafe extern "C" fn(
        *mut XDisplay,
        XDrawable,
        *mut XImage,
        c_int,
        c_int,
        c_ulong,
    ) -> XBool,
    xrr_get_monitors: Option<
        unsafe extern "C" fn(*mut XDisplay, XWindow, XBool, *mut c_int) -> *mut XRRMonitorInfo,
    >,
    xrr_free_monitors: Option<unsafe extern "C" fn(*mut XRRMonitorInfo)>,
    xfixes_get_cursor_image: Option<unsafe extern "C" fn(*mut XDisplay) -> *mut XFixesCursorImage>,
}

// SAFETY: X11Apis holds function pointers and process-global dlopen handles; XDisplay access
// is strictly owned by `X11ShmCapturer` (`&mut self`).
unsafe impl Send for X11Apis {}

impl X11Apis {
    fn load() -> Result<Self, CaptureError> {
        let x11 = DynLib::open("libX11.so.6").map_err(CaptureError::Fatal)?;
        let xext = DynLib::open("libXext.so.6").map_err(CaptureError::Fatal)?;
        let xrandr = DynLib::open("libXrandr.so.2").ok();
        let xfixes = DynLib::open("libXfixes.so.3").ok();

        unsafe {
            let x_open_display = x11.symbol("XOpenDisplay").map_err(CaptureError::Fatal)?;
            let x_close_display = x11.symbol("XCloseDisplay").map_err(CaptureError::Fatal)?;
            let x_default_screen = x11.symbol("XDefaultScreen").map_err(CaptureError::Fatal)?;
            let x_root_window = x11.symbol("XRootWindow").map_err(CaptureError::Fatal)?;
            let x_default_visual = x11.symbol("XDefaultVisual").map_err(CaptureError::Fatal)?;
            let x_default_depth = x11.symbol("XDefaultDepth").map_err(CaptureError::Fatal)?;
            let x_display_width = x11.symbol("XDisplayWidth").map_err(CaptureError::Fatal)?;
            let x_display_height = x11.symbol("XDisplayHeight").map_err(CaptureError::Fatal)?;
            let x_get_atom_name = x11.symbol("XGetAtomName").map_err(CaptureError::Fatal)?;
            let x_free = x11.symbol("XFree").map_err(CaptureError::Fatal)?;
            let x_destroy_image_fallback = x11.symbol("XSync").map_err(CaptureError::Fatal)?;
            let x_shm_query_extension = xext
                .symbol("XShmQueryExtension")
                .map_err(CaptureError::Fatal)?;
            let x_shm_create_image = xext
                .symbol("XShmCreateImage")
                .map_err(CaptureError::Fatal)?;
            let x_shm_attach = xext.symbol("XShmAttach").map_err(CaptureError::Fatal)?;
            let x_shm_detach = xext.symbol("XShmDetach").map_err(CaptureError::Fatal)?;
            let x_shm_get_image = xext.symbol("XShmGetImage").map_err(CaptureError::Fatal)?;

            let (xrr_get_monitors, xrr_free_monitors) = match &xrandr {
                Some(rr) => (
                    rr.symbol("XRRGetMonitors").ok(),
                    rr.symbol("XRRFreeMonitors").ok(),
                ),
                None => (None, None),
            };
            let xfixes_get_cursor_image = xfixes
                .as_ref()
                .and_then(|xf| xf.symbol("XFixesGetCursorImage").ok());

            Ok(Self {
                _x11: x11,
                _xext: xext,
                _xrandr: xrandr,
                _xfixes: xfixes,
                x_open_display,
                x_close_display,
                x_default_screen,
                x_root_window,
                x_default_visual,
                x_default_depth,
                x_display_width,
                x_display_height,
                x_get_atom_name,
                x_free,
                x_destroy_image_fallback,
                x_shm_query_extension,
                x_shm_create_image,
                x_shm_attach,
                x_shm_detach,
                x_shm_get_image,
                xrr_get_monitors,
                xrr_free_monitors,
                xfixes_get_cursor_image,
            })
        }
    }
}

/// Enumerates X11 monitors via XRandR (falling back to the default screen root
/// dimensions when `libXrandr.so.2` is unavailable).
pub fn enumerate_x11_monitors() -> Result<Vec<X11OutputDescriptor>, CaptureError> {
    let apis = X11Apis::load()?;
    let display = unsafe { (apis.x_open_display)(ptr::null()) };
    if display.is_null() {
        return Err(CaptureError::Fatal(
            "XOpenDisplay(NULL) failed; check DISPLAY / Xauthority".into(),
        ));
    }
    let res = enumerate_x11_monitors_on_display(&apis, display);
    unsafe {
        (apis.x_close_display)(display);
    }
    res
}

fn enumerate_x11_monitors_on_display(
    apis: &X11Apis,
    display: *mut XDisplay,
) -> Result<Vec<X11OutputDescriptor>, CaptureError> {
    let screen = unsafe { (apis.x_default_screen)(display) };
    let root = unsafe { (apis.x_root_window)(display, screen) };

    if let (Some(get_mons), Some(free_mons)) = (apis.xrr_get_monitors, apis.xrr_free_monitors) {
        let mut count: c_int = 0;
        let ptr = unsafe { get_mons(display, root, 1, &mut count) };
        if !ptr.is_null() && count > 0 {
            let slice = unsafe { std::slice::from_raw_parts(ptr, count as usize) };
            let mut outputs = Vec::with_capacity(slice.len());
            for (idx, m) in slice.iter().enumerate() {
                let name = if m.name != 0 {
                    let cname = unsafe { (apis.x_get_atom_name)(display, m.name) };
                    if cname.is_null() {
                        format!("X11-{idx}")
                    } else {
                        let s = unsafe { CStr::from_ptr(cname) }
                            .to_string_lossy()
                            .into_owned();
                        unsafe {
                            (apis.x_free)(cname.cast());
                        }
                        s
                    }
                } else {
                    format!("X11-{idx}")
                };
                if m.width > 0 && m.height > 0 {
                    outputs.push(X11OutputDescriptor {
                        monitor_id: idx as u32,
                        name,
                        x: m.x,
                        y: m.y,
                        width: m.width as u32,
                        height: m.height as u32,
                        rotation_degrees: 0,
                        is_primary: m.primary != 0,
                    });
                }
            }
            unsafe {
                free_mons(ptr);
            }
            if !outputs.is_empty() {
                return Ok(outputs);
            }
        } else if !ptr.is_null() {
            unsafe {
                free_mons(ptr);
            }
        }
    }

    let width = unsafe { (apis.x_display_width)(display, screen) };
    let height = unsafe { (apis.x_display_height)(display, screen) };
    if width <= 0 || height <= 0 {
        return Err(CaptureError::Fatal(format!(
            "X11 default screen returned invalid dimensions {width}x{height}"
        )));
    }
    Ok(vec![X11OutputDescriptor {
        monitor_id: 0,
        name: "X11-root".into(),
        x: 0,
        y: 0,
        width: width as u32,
        height: height as u32,
        rotation_degrees: 0,
        is_primary: true,
    }])
}

/// Attached `XShm` segment bundle cleaned up deterministically on Drop.
struct AttachedShm {
    image: *mut XImage,
    seg: Box<XShmSegmentInfo>,
    byte_len: usize,
    width: u32,
    height: u32,
    stride: usize,
}

/// Thin X11 `XShm` + `XRandR` + `XFixes` capturer implementing `ScreenCapturer`.
pub struct X11ShmCapturer {
    apis: X11Apis,
    display: *mut XDisplay,
    root: XWindow,
    screen: c_int,
    topology: X11MonitorTopology,
    active_monitor: X11OutputDescriptor,
    shm: Option<AttachedShm>,
    state: X11CaptureStateMachine,
}

// SAFETY: `X11ShmCapturer` owns its private `XDisplay*` exclusively and requires `&mut self`
// for every X11 call.
unsafe impl Send for X11ShmCapturer {}

impl X11ShmCapturer {
    pub fn open(requested_monitor_id: Option<u32>) -> Result<Self, CaptureError> {
        let apis = X11Apis::load()?;
        let display = unsafe { (apis.x_open_display)(ptr::null()) };
        if display.is_null() {
            return Err(CaptureError::Fatal(
                "XOpenDisplay(NULL) failed; check DISPLAY".into(),
            ));
        }
        if unsafe { (apis.x_shm_query_extension)(display) } == 0 {
            unsafe {
                (apis.x_close_display)(display);
            }
            return Err(CaptureError::Fatal(
                "X11 MIT-SHM (XShm) extension is unavailable on active X server".into(),
            ));
        }
        let screen = unsafe { (apis.x_default_screen)(display) };
        let root = unsafe { (apis.x_root_window)(display, screen) };
        let outputs = match enumerate_x11_monitors_on_display(&apis, display) {
            Ok(o) => o,
            Err(e) => {
                unsafe {
                    (apis.x_close_display)(display);
                }
                return Err(e);
            }
        };
        let topology = match X11MonitorTopology::from_outputs(outputs) {
            Ok(t) => t,
            Err(e) => {
                unsafe {
                    (apis.x_close_display)(display);
                }
                return Err(e);
            }
        };
        let Some(active_monitor) = topology.select_monitor(requested_monitor_id).cloned() else {
            unsafe {
                (apis.x_close_display)(display);
            }
            return Err(CaptureError::Fatal("no X11 monitor selected".into()));
        };

        let mut cap = Self {
            apis,
            display,
            root,
            screen,
            topology,
            active_monitor,
            shm: None,
            state: X11CaptureStateMachine::default(),
        };
        cap.attach_shm_for_active_monitor()?;
        Ok(cap)
    }

    fn detach_shm(&mut self) {
        if let Some(mut attached) = self.shm.take() {
            unsafe {
                let _ = (self.apis.x_shm_detach)(self.display, attached.seg.as_mut());
                let _ = (self.apis.x_destroy_image_fallback)(self.display);
                if !attached.image.is_null() {
                    let _ = (self.apis.x_free)(attached.image.cast());
                }
                if !attached.seg.shmaddr.is_null()
                    && attached.seg.shmaddr != (-1isize as *mut c_char)
                {
                    let _ = libc::shmdt(attached.seg.shmaddr.cast());
                }
                if attached.seg.shmid >= 0 {
                    let _ = libc::shmctl(attached.seg.shmid, libc::IPC_RMID, ptr::null_mut());
                }
            }
        }
    }

    fn attach_shm_for_active_monitor(&mut self) -> Result<(), CaptureError> {
        self.detach_shm();
        let w = self.active_monitor.width;
        let h = self.active_monitor.height;
        let visual = unsafe { (self.apis.x_default_visual)(self.display, self.screen) };
        let depth = unsafe { (self.apis.x_default_depth)(self.display, self.screen) };
        let mut seg = Box::new(XShmSegmentInfo {
            shmseg: 0,
            shmid: -1,
            shmaddr: ptr::null_mut(),
            read_only: 0,
        });
        let img = unsafe {
            (self.apis.x_shm_create_image)(
                self.display,
                visual,
                depth as c_uint,
                X_ZPIXMAP,
                ptr::null_mut(),
                seg.as_mut(),
                w as c_uint,
                h as c_uint,
            )
        };
        if img.is_null() {
            return Err(CaptureError::ReinitRequired("XShmCreateImage returned NULL".into()));
        }
        let stride = unsafe { (*img).bytes_per_line };
        let img_h = unsafe { (*img).height };
        if stride <= 0 || img_h <= 0 {
            unsafe {
                let _ = (self.apis.x_free)(img.cast());
            }
            return Err(CaptureError::Fatal("XShmCreateImage returned invalid geometry".into()));
        }
        let byte_len = (stride as usize)
            .checked_mul(img_h as usize)
            .ok_or_else(|| CaptureError::Fatal("XShm byte_len overflow".into()))?;
        let shmid = unsafe { libc::shmget(libc::IPC_PRIVATE, byte_len, libc::IPC_CREAT | 0o600) };
        if shmid < 0 {
            unsafe {
                let _ = (self.apis.x_free)(img.cast());
            }
            return Err(CaptureError::ReinitRequired("shmget(IPC_PRIVATE) failed".into()));
        }
        let addr = unsafe { libc::shmat(shmid, ptr::null(), 0) };
        if addr.is_null() || addr == (-1isize as *mut c_void) {
            unsafe {
                let _ = libc::shmctl(shmid, libc::IPC_RMID, ptr::null_mut());
                let _ = (self.apis.x_free)(img.cast());
            }
            return Err(CaptureError::ReinitRequired("shmat failed".into()));
        }
        seg.shmid = shmid;
        seg.shmaddr = addr.cast();
        unsafe {
            (*img).data = seg.shmaddr;
        }
        let attached_ok = unsafe { (self.apis.x_shm_attach)(self.display, seg.as_mut()) };
        // Mark segment for automatic deletion once detached or process exits.
        unsafe {
            let _ = libc::shmctl(shmid, libc::IPC_RMID, ptr::null_mut());
        }
        if attached_ok == 0 {
            unsafe {
                let _ = libc::shmdt(addr);
                let _ = (self.apis.x_free)(img.cast());
            }
            return Err(CaptureError::ReinitRequired("XShmAttach failed".into()));
        }
        self.shm = Some(AttachedShm {
            image: img,
            seg,
            byte_len,
            width: w,
            height: h,
            stride: stride as usize,
        });
        let _ = self.state.on_recreated();
        Ok(())
    }

    fn fetch_xfixes_cursor(&self) -> Option<CursorMetadata> {
        let get_cursor = self.apis.xfixes_get_cursor_image?;
        let cur = unsafe { get_cursor(self.display) };
        if cur.is_null() {
            return None;
        }
        let result = unsafe {
            let c = &*cur;
            if c.pixels.is_null() || c.width == 0 || c.height == 0 {
                None
            } else {
                let count = (c.width as usize).checked_mul(c.height as usize)?;
                let raw_ulongs = std::slice::from_raw_parts(c.pixels, count);
                let argb_u32: Vec<u32> = raw_ulongs.iter().map(|&v| v as u32).collect();
                let rel_x = i32::from(c.x) - self.active_monitor.x;
                let rel_y = i32::from(c.y) - self.active_monitor.y;
                let visible = self
                    .active_monitor
                    .contains_point(i32::from(c.x), i32::from(c.y));
                convert_xfixes_argb_to_cursor_metadata(
                    &super::linux_capture_logic::XFixesCursorInput {
                        x: rel_x,
                        y: rel_y,
                        width: u32::from(c.width),
                        height: u32::from(c.height),
                        hotspot_x: u32::from(c.xhot),
                        hotspot_y: u32::from(c.yhot),
                        visible,
                        argb_pixels: &argb_u32,
                    },
                )
                .ok()
            }
        };
        unsafe {
            let _ = (self.apis.x_free)(cur.cast());
        }
        result
    }
}

impl Drop for X11ShmCapturer {
    fn drop(&mut self) {
        self.detach_shm();
        if !self.display.is_null() {
            unsafe {
                let _ = (self.apis.x_close_display)(self.display);
            }
            self.display = ptr::null_mut();
        }
    }
}

impl ScreenCapturer for X11ShmCapturer {
    fn dimensions(&self) -> (u32, u32) {
        self.active_monitor.effective_dims()
    }

    fn monitor_id(&self) -> u32 {
        self.active_monitor.monitor_id
    }

    fn capture_next_frame(&mut self) -> Result<CapturedFrame, CaptureError> {
        // Check if XRandR monitor layout changed before grabbing.
        if let Ok(fresh) = enumerate_x11_monitors_on_display(&self.apis, self.display) {
            if let Ok(new_topo) = X11MonitorTopology::from_outputs(fresh) {
                if self.topology.has_layout_changed(&new_topo) {
                    let decision = self
                        .state
                        .on_error(X11CaptureErrorKind::MonitorLayoutChanged, "XRandR changed");
                    self.topology = new_topo;
                    if let Some(m) = self
                        .topology
                        .select_monitor(Some(self.active_monitor.monitor_id))
                        .cloned()
                    {
                        self.active_monitor = m;
                    }
                    match decision {
                        super::linux_capture_logic::X11CaptureDecision::RecreateShm { .. } => {
                            self.attach_shm_for_active_monitor()?;
                        }
                        super::linux_capture_logic::X11CaptureDecision::TerminalFailure(err) => {
                            return Err(err);
                        }
                        super::linux_capture_logic::X11CaptureDecision::TimeoutNoChange => {
                            return Err(CaptureError::Timeout);
                        }
                    }
                }
            }
        }

        let Some(attached) = &self.shm else {
            return Err(CaptureError::ReinitRequired("XShm segment not attached".into()));
        };

        let ok = unsafe {
            (self.apis.x_shm_get_image)(
                self.display,
                self.root,
                attached.image,
                self.active_monitor.x,
                self.active_monitor.y,
                X_ALL_PLANES,
            )
        };
        if ok == 0 {
            let decision = self
                .state
                .on_error(X11CaptureErrorKind::BadMatch, "XShmGetImage returned 0");
            return match decision {
                super::linux_capture_logic::X11CaptureDecision::RecreateShm { .. } => {
                    self.attach_shm_for_active_monitor()?;
                    Err(CaptureError::ReinitRequired("XShm recreated after BadMatch".into()))
                }
                super::linux_capture_logic::X11CaptureDecision::TerminalFailure(e) => Err(e),
                super::linux_capture_logic::X11CaptureDecision::TimeoutNoChange => {
                    Err(CaptureError::Timeout)
                }
            };
        }

        let src_slice = unsafe {
            std::slice::from_raw_parts(attached.seg.shmaddr as *const u8, attached.byte_len)
        };
        let dst_stride = (attached.width as usize)
            .checked_mul(4)
            .ok_or_else(|| CaptureError::Fatal("X11 dst_stride overflow".into()))?;
        let bgra = copy_shm_frame_rows(
            src_slice,
            attached.width,
            attached.height,
            attached.stride,
            4,
            dst_stride,
        )?;
        let width = attached.width;
        let height = attached.height;
        self.state.on_frame_ok();
        let cursor = self.fetch_xfixes_cursor();

        Ok(CapturedFrame {
            width,
            height,
            stride: dst_stride as u32,
            surface: CapturedSurface::Bgra8 { data: bgra },
            timestamp_us: now_epoch_us(),
            monitor_id: self.active_monitor.monitor_id,
            cursor,
        })
    }
}

// ============================================================================
// Wayland Portal + PipeWire Thin Runtime Adapter (`dlopen("libpipewire-0.3.so.0")`)
// ============================================================================

struct PipeWireLib {
    _lib: DynLib,
    pw_get_library_version: unsafe extern "C" fn() -> *const c_char,
}

// SAFETY: Process-global shared library function pointer.
unsafe impl Send for PipeWireLib {}

impl PipeWireLib {
    fn load() -> Result<Self, CaptureError> {
        let lib = DynLib::open("libpipewire-0.3.so.0").map_err(CaptureError::Fatal)?;
        let pw_get_library_version = unsafe {
            lib.symbol("pw_get_library_version")
                .map_err(CaptureError::Fatal)?
        };
        Ok(Self {
            _lib: lib,
            pw_get_library_version,
        })
    }

    fn version_string(&self) -> String {
        let ptr = unsafe { (self.pw_get_library_version)() };
        if ptr.is_null() {
            return "unknown".into();
        }
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}

/// Wayland `xdg-desktop-portal` ScreenCast + PipeWire runtime capturer driven by
/// `WaylandPortalCaptureStateMachine` and dynamically loaded `libpipewire-0.3.so.0`.
pub struct WaylandPipeWireCapturer {
    pw: PipeWireLib,
    state: WaylandPortalCaptureStateMachine,
    pending_shm_frame: Option<Vec<u8>>,
    monitor_id: u32,
}

impl WaylandPipeWireCapturer {
    pub fn new(monitor_id: u32) -> Result<Self, CaptureError> {
        let (dbus_ok, sc_ok, _, err_note) = probe_portal_availability();
        if !dbus_ok || !sc_ok {
            return Err(CaptureError::PermissionDenied(
                OsPermission::ScreenRecording,
            ));
        }
        let pw = PipeWireLib::load()?;
        let _ = err_note;
        Ok(Self {
            pw,
            state: WaylandPortalCaptureStateMachine::default(),
            pending_shm_frame: None,
            monitor_id,
        })
    }

    pub fn pipewire_version(&self) -> String {
        self.pw.version_string()
    }

    pub fn state_machine(&self) -> &WaylandPortalCaptureStateMachine {
        &self.state
    }

    pub fn state_machine_mut(&mut self) -> &mut WaylandPortalCaptureStateMachine {
        &mut self.state
    }

    /// Ingests a validated PipeWire MemFd SHM buffer after portal stream negotiation.
    pub fn ingest_memfd_buffer(
        &mut self,
        params: &PipeWireStreamParams,
        raw_shm: &[u8],
        seq: u64,
        pts_us: i64,
    ) -> Result<(), CaptureError> {
        let bpp = params
            .format
            .packed_bpp()
            .ok_or_else(|| CaptureError::Fatal("planar NV12 MemFd ingest requires NV12 path".into()))?;
        let dst_stride = (params.width as usize)
            .checked_mul(bpp)
            .ok_or_else(|| CaptureError::Fatal("Wayland dst_stride overflow".into()))?;
        let packed = copy_shm_frame_rows(
            raw_shm,
            params.width,
            params.height,
            params.stride as usize,
            bpp,
            dst_stride,
        )?;
        self.state.on_frame_arrived(PipeWireFrameArrival {
            seq,
            pts_us,
            byte_len: raw_shm.len(),
            buffer_kind: PipeWireBufferKind::MemFdShm,
        })?;
        self.pending_shm_frame = Some(packed);
        Ok(())
    }
}

impl ScreenCapturer for WaylandPipeWireCapturer {
    fn dimensions(&self) -> (u32, u32) {
        self.state
            .negotiated_stream()
            .map(|s| (s.width, s.height))
            .unwrap_or((0, 0))
    }

    fn monitor_id(&self) -> u32 {
        self.monitor_id
    }

    fn capture_next_frame(&mut self) -> Result<CapturedFrame, CaptureError> {
        let Some(stream) = self.state.negotiated_stream().cloned() else {
            return Err(CaptureError::ReinitRequired(
                "Wayland PipeWire stream not yet negotiated with xdg-desktop-portal".into(),
            ));
        };
        let Some(data) = self.pending_shm_frame.take() else {
            return Err(CaptureError::Timeout);
        };
        let arrival = self.state.frame_ring_mut().pop();
        let ts = arrival.map(|a| a.pts_us).unwrap_or_else(now_epoch_us);
        let stride = stream.width.saturating_mul(4);
        Ok(CapturedFrame {
            width: stream.width,
            height: stream.height,
            stride,
            surface: CapturedSurface::Bgra8 { data },
            timestamp_us: ts,
            monitor_id: self.monitor_id,
            cursor: None,
        })
    }
}

/// Unified Linux `ScreenCapturer` dispatching strictly by detected session kind.
pub enum LinuxScreenCapturer {
    Wayland(Box<WaylandPipeWireCapturer>),
    X11(Box<X11ShmCapturer>),
}

impl LinuxScreenCapturer {
    pub fn open_auto(requested_monitor_id: Option<u32>) -> Result<Self, CaptureError> {
        match current_linux_session_kind() {
            LinuxSessionKind::Wayland => {
                WaylandPipeWireCapturer::new(requested_monitor_id.unwrap_or(0))
                    .map(Box::new)
                    .map(Self::Wayland)
            }
            LinuxSessionKind::X11 => X11ShmCapturer::open(requested_monitor_id)
                .map(Box::new)
                .map(Self::X11),
            LinuxSessionKind::Headless => Err(CaptureError::DesktopUnavailable(
                "headless Linux session has no Wayland or X11 display".into(),
            )),
        }
    }
}

impl ScreenCapturer for LinuxScreenCapturer {
    fn dimensions(&self) -> (u32, u32) {
        match self {
            Self::Wayland(w) => w.dimensions(),
            Self::X11(x) => x.dimensions(),
        }
    }

    fn monitor_id(&self) -> u32 {
        match self {
            Self::Wayland(w) => w.monitor_id(),
            Self::X11(x) => x.monitor_id(),
        }
    }

    fn capture_next_frame(&mut self) -> Result<CapturedFrame, CaptureError> {
        match self {
            Self::Wayland(w) => w.capture_next_frame(),
            Self::X11(x) => x.capture_next_frame(),
        }
    }
}

// Unused import suppression for clean-room C string construction if needed by callers.
#[allow(dead_code)]
fn _cstr_helper(s: &str) -> Option<CString> {
    CString::new(s).ok()
}

#[allow(dead_code)]
const _C_LONG_CHECK: usize = std::mem::size_of::<c_long>();
