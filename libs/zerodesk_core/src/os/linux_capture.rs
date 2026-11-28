// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(target_os = "linux")]` screen capture adapter supporting:
//! - Wayland `xdg-desktop-portal` ScreenCast + PipeWire (`dlopen("libpipewire-0.3.so.0")`)
//! - X11 `XShm` / `XRandR` / `XFixes` (`dlopen("libX11.so.6")` + `libXext.so.6` +
//!   `libXrandr.so.2` + `libXfixes.so.3`)
//!
//! All state transitions, buffer bounds checks, pixel-format normalization, rotation
//! math, and cursor ARGB validation are delegated to `linux_capture_logic.rs`.
//! ZERO compile-time `.so` linking is used.

#![cfg(target_os = "linux")]

use super::{
    linux_capture_logic::{
        convert_xfixes_argb_to_cursor_metadata, copy_shm_frame_rows, detect_linux_session_kind,
        normalize_packed_to_bgra_in_place, LinuxSessionKind, PackedFrame, PipeWireBufferKind,
        PipeWireFrameArrival, PipeWirePixelFormat, PipeWireStreamParams,
        WaylandPortalCaptureStateMachine, X11CaptureDecision, X11CaptureErrorKind,
        X11CaptureStateMachine, X11MonitorTopology, X11OutputDescriptor, XFixesCursorInput,
        MAX_XFIXES_CURSOR_DIM,
    },
    linux_dl::DynLib,
    traits::{CaptureError, CapturedFrame, CapturedSurface, CursorMetadata, ScreenCapturer},
};
use std::{
    collections::VecDeque,
    ffi::{c_char, c_int, c_uint, c_ulong, c_ushort, c_void, CStr},
    path::Path,
    ptr,
    sync::{
        atomic::{AtomicBool, AtomicI32, AtomicUsize, Ordering},
        Once,
    },
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
            Some(
                "D-Bus session bus not detected (DBUS_SESSION_BUS_ADDRESS / XDG_RUNTIME_DIR/bus absent)"
                    .into(),
            ),
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
type XErrorHandler = unsafe extern "C" fn(*mut XDisplay, *mut XErrorEvent) -> c_int;
type XIOErrorHandler = unsafe extern "C" fn(*mut XDisplay) -> c_int;

const X_ZPIXMAP: c_int = 2;
const X_ALL_PLANES: c_ulong = !0;

/// Lock-free, signal/reentrancy-safe per-`Display*` Xlib error & IO-error table.
/// Prevents cross-contamination between concurrent `X11ShmCapturer` instances and
/// chains cleanly to previously installed handlers for unregistered `Display*`s.
const MAX_X11_DISPLAY_SLOTS: usize = 16;

struct DisplayErrorSlot {
    display_ptr: AtomicUsize,
    dead: AtomicBool,
    last_error: AtomicI32,
}

impl DisplayErrorSlot {
    const fn new() -> Self {
        Self {
            display_ptr: AtomicUsize::new(0),
            dead: AtomicBool::new(false),
            last_error: AtomicI32::new(0),
        }
    }
}

static X11_DISPLAY_SLOTS: [DisplayErrorSlot; MAX_X11_DISPLAY_SLOTS] =
    [const { DisplayErrorSlot::new() }; MAX_X11_DISPLAY_SLOTS];
static X11_HANDLERS_INSTALLED: Once = Once::new();
static PREV_X11_ERROR_HANDLER: AtomicUsize = AtomicUsize::new(0);
static PREV_X11_IO_ERROR_HANDLER: AtomicUsize = AtomicUsize::new(0);

fn find_x11_display_slot(display: *mut XDisplay) -> Option<usize> {
    let key = display as usize;
    if key == 0 {
        return None;
    }
    for (idx, slot) in X11_DISPLAY_SLOTS.iter().enumerate() {
        if slot.display_ptr.load(Ordering::Acquire) == key {
            return Some(idx);
        }
    }
    None
}

struct RegisteredDisplayGuard {
    display: *mut XDisplay,
    slot: Option<usize>,
}

// SAFETY: Only tracks an integer pointer key + slot index inside the lock-free table.
unsafe impl Send for RegisteredDisplayGuard {}

impl RegisteredDisplayGuard {
    fn register(display: *mut XDisplay) -> Self {
        let key = display as usize;
        let mut claimed = None;
        if key != 0 {
            for (idx, slot) in X11_DISPLAY_SLOTS.iter().enumerate() {
                if slot
                    .display_ptr
                    .compare_exchange(0, key, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
                {
                    slot.dead.store(false, Ordering::Release);
                    slot.last_error.store(0, Ordering::Release);
                    claimed = Some(idx);
                    break;
                }
            }
        }
        Self {
            display,
            slot: claimed,
        }
    }

    fn is_dead(&self) -> bool {
        self.slot
            .map(|idx| X11_DISPLAY_SLOTS[idx].dead.load(Ordering::Acquire))
            .unwrap_or(false)
    }

    fn clear_last_error(&self) {
        if let Some(idx) = self.slot {
            X11_DISPLAY_SLOTS[idx].last_error.store(0, Ordering::Release);
        }
    }

    fn last_error(&self) -> i32 {
        self.slot
            .map(|idx| X11_DISPLAY_SLOTS[idx].last_error.load(Ordering::Acquire))
            .unwrap_or(0)
    }
}

impl Drop for RegisteredDisplayGuard {
    fn drop(&mut self) {
        if let Some(idx) = self.slot.take() {
            let key = self.display as usize;
            let slot = &X11_DISPLAY_SLOTS[idx];
            slot.dead.store(false, Ordering::Release);
            slot.last_error.store(0, Ordering::Release);
            let _ = slot
                .display_ptr
                .compare_exchange(key, 0, Ordering::AcqRel, Ordering::Acquire);
        }
    }
}

#[repr(C)]
struct XErrorEvent {
    ev_type: c_int,
    display: *mut XDisplay,
    resourceid: c_ulong,
    serial: c_ulong,
    error_code: u8,
    request_code: u8,
    minor_code: u8,
}

unsafe extern "C" fn zerodesk_x11_error_handler(
    display: *mut XDisplay,
    err: *mut XErrorEvent,
) -> c_int {
    if let Some(idx) = find_x11_display_slot(display) {
        if !err.is_null() {
            X11_DISPLAY_SLOTS[idx]
                .last_error
                .store(i32::from((*err).error_code), Ordering::Release);
        }
        return 0;
    }
    let prev_addr = PREV_X11_ERROR_HANDLER.load(Ordering::Acquire);
    if prev_addr != 0 {
        let prev: XErrorHandler = std::mem::transmute(prev_addr);
        return prev(display, err);
    }
    0
}

unsafe extern "C" fn zerodesk_x11_io_error_handler(display: *mut XDisplay) -> c_int {
    if let Some(idx) = find_x11_display_slot(display) {
        X11_DISPLAY_SLOTS[idx].dead.store(true, Ordering::Release);
        return 0;
    }
    let prev_addr = PREV_X11_IO_ERROR_HANDLER.load(Ordering::Acquire);
    if prev_addr != 0 {
        let prev: XIOErrorHandler = std::mem::transmute(prev_addr);
        return prev(display);
    }
    0
}

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
    x_sync: unsafe extern "C" fn(*mut XDisplay, XBool) -> c_int,
    x_set_error_handler: unsafe extern "C" fn(Option<XErrorHandler>) -> Option<XErrorHandler>,
    x_set_io_error_handler: unsafe extern "C" fn(Option<XIOErrorHandler>) -> Option<XIOErrorHandler>,
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
    // Keep DynLib handles last for defense-in-depth drop ordering.
    _xfixes: Option<DynLib>,
    _xrandr: Option<DynLib>,
    _xext: DynLib,
    _x11: DynLib,
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
            let x_sync = x11.symbol("XSync").map_err(CaptureError::Fatal)?;
            let x_set_error_handler = x11
                .symbol("XSetErrorHandler")
                .map_err(CaptureError::Fatal)?;
            let x_set_io_error_handler = x11
                .symbol("XSetIOErrorHandler")
                .map_err(CaptureError::Fatal)?;
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
                x_sync,
                x_set_error_handler,
                x_set_io_error_handler,
                x_shm_query_extension,
                x_shm_create_image,
                x_shm_attach,
                x_shm_detach,
                x_shm_get_image,
                xrr_get_monitors,
                xrr_free_monitors,
                xfixes_get_cursor_image,
                _xfixes: xfixes,
                _xrandr: xrandr,
                _xext: xext,
                _x11: x11,
            })
        }
    }

    fn install_error_handlers_once(&self) {
        X11_HANDLERS_INSTALLED.call_once(|| unsafe {
            if let Some(prev) = (self.x_set_error_handler)(Some(zerodesk_x11_error_handler)) {
                if prev as usize != zerodesk_x11_error_handler as usize {
                    PREV_X11_ERROR_HANDLER.store(prev as usize, Ordering::Release);
                }
            }
            if let Some(prev) = (self.x_set_io_error_handler)(Some(zerodesk_x11_io_error_handler)) {
                if prev as usize != zerodesk_x11_io_error_handler as usize {
                    PREV_X11_IO_ERROR_HANDLER.store(prev as usize, Ordering::Release);
                }
            }
        });
    }
}

/// Enumerates X11 monitors via XRandR (falling back to the default screen root
/// dimensions when `libXrandr.so.2` is unavailable).
pub fn enumerate_x11_monitors() -> Result<Vec<X11OutputDescriptor>, CaptureError> {
    let apis = X11Apis::load()?;
    apis.install_error_handlers_once();
    let display = unsafe { (apis.x_open_display)(ptr::null()) };
    if display.is_null() {
        return Err(CaptureError::Fatal(
            "XOpenDisplay(NULL) failed; check DISPLAY / Xauthority".into(),
        ));
    }
    let _guard = RegisteredDisplayGuard::register(display);
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
    display_guard: RegisteredDisplayGuard,
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
        apis.install_error_handlers_once();
        let display = unsafe { (apis.x_open_display)(ptr::null()) };
        if display.is_null() {
            return Err(CaptureError::Fatal(
                "XOpenDisplay(NULL) failed; check DISPLAY".into(),
            ));
        }
        let display_guard = RegisteredDisplayGuard::register(display);
        if unsafe { (apis.x_shm_query_extension)(display) } == 0 {
            unsafe {
                (apis.x_close_display)(display);
            }
            drop(display_guard);
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
                drop(display_guard);
                return Err(e);
            }
        };
        let topology = match X11MonitorTopology::from_outputs(outputs) {
            Ok(t) => t,
            Err(e) => {
                unsafe {
                    (apis.x_close_display)(display);
                }
                drop(display_guard);
                return Err(e);
            }
        };
        let Some(active_monitor) = topology.select_monitor(requested_monitor_id).cloned() else {
            unsafe {
                (apis.x_close_display)(display);
            }
            drop(display_guard);
            return Err(CaptureError::Fatal("no X11 monitor selected".into()));
        };

        let mut cap = Self {
            apis,
            display,
            display_guard,
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
                let _ = (self.apis.x_sync)(self.display, 0);
                // Intentional `XFree(image)` instead of `XDestroyImage`: for MIT-SHM
                // images, `image->data` points into our `shmat()` segment (which we detach
                // via `shmdt` below), NOT an Xlib-allocated buffer, so freeing only the
                // `XImage` descriptor avoids double-freeing the shared memory segment.
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
        if visual.is_null() {
            return Err(CaptureError::ReinitRequired(
                "XDefaultVisual returned NULL".into(),
            ));
        }
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
            return Err(CaptureError::ReinitRequired(
                "XShmCreateImage returned NULL".into(),
            ));
        }
        let (stride, img_h, bpp, red_mask, green_mask, blue_mask) = unsafe {
            (
                (*img).bytes_per_line,
                (*img).height,
                (*img).bits_per_pixel,
                (*img).red_mask,
                (*img).green_mask,
                (*img).blue_mask,
            )
        };
        if stride <= 0 || img_h <= 0 {
            unsafe {
                let _ = (self.apis.x_free)(img.cast());
            }
            return Err(CaptureError::Fatal(
                "XShmCreateImage returned invalid geometry".into(),
            ));
        }
        // Fail closed unless the X11 server delivers 32-bit BGRX/BGRA pixel layout
        // (R=0x00FF0000, G=0x0000FF00, B=0x000000FF on little-endian Linux).
        if bpp != 32
            || red_mask != 0x00FF_0000
            || green_mask != 0x0000_FF00
            || blue_mask != 0x0000_00FF
        {
            unsafe {
                let _ = (self.apis.x_free)(img.cast());
            }
            return Err(CaptureError::ReinitRequired(format!(
                "unsupported X11 XShm pixel format: bpp={bpp}, masks=({red_mask:#x}, {green_mask:#x}, {blue_mask:#x}) (expected 32-bit BGRA/BGRX)"
            )));
        }
        let byte_len = (stride as usize)
            .checked_mul(img_h as usize)
            .ok_or_else(|| CaptureError::Fatal("XShm byte_len overflow".into()))?;
        let shmid = unsafe { libc::shmget(libc::IPC_PRIVATE, byte_len, libc::IPC_CREAT | 0o600) };
        if shmid < 0 {
            unsafe {
                let _ = (self.apis.x_free)(img.cast());
            }
            return Err(CaptureError::ReinitRequired(
                "shmget(IPC_PRIVATE) failed".into(),
            ));
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
        // Never use `?` before `XFree(cur)`: guarantee `XFree` executes on EVERY path.
        let result = unsafe {
            let c = &*cur;
            let cw = u32::from(c.width);
            let ch = u32::from(c.height);
            if c.pixels.is_null()
                || cw == 0
                || ch == 0
                || cw > MAX_XFIXES_CURSOR_DIM
                || ch > MAX_XFIXES_CURSOR_DIM
            {
                None
            } else if let Some(count) = (cw as usize).checked_mul(ch as usize) {
                let raw_ulongs = std::slice::from_raw_parts(c.pixels, count);
                let argb_u32: Vec<u32> = raw_ulongs.iter().map(|&v| v as u32).collect();
                let rel_x = i32::from(c.x) - self.active_monitor.x;
                let rel_y = i32::from(c.y) - self.active_monitor.y;
                let visible = self
                    .active_monitor
                    .contains_point(i32::from(c.x), i32::from(c.y));
                convert_xfixes_argb_to_cursor_metadata(&XFixesCursorInput {
                    x: rel_x,
                    y: rel_y,
                    width: cw,
                    height: ch,
                    hotspot_x: u32::from(c.xhot),
                    hotspot_y: u32::from(c.yhot),
                    visible,
                    argb_pixels: &argb_u32,
                })
                .ok()
            } else {
                None
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
        // Check THIS display's Xlib IO error latch before making any further X11 requests.
        if self.display_guard.is_dead() {
            return match self.state.on_error(
                X11CaptureErrorKind::DisplayDisconnected,
                "X11 IO error handler observed display disconnect",
            ) {
                X11CaptureDecision::TerminalFailure(err) => Err(err),
                _ => Err(CaptureError::Fatal("X11 display disconnected".into())),
            };
        }

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
                        X11CaptureDecision::RecreateShm { .. } => {
                            self.attach_shm_for_active_monitor()?;
                        }
                        X11CaptureDecision::TerminalFailure(err) => return Err(err),
                        X11CaptureDecision::TimeoutNoChange => return Err(CaptureError::Timeout),
                    }
                }
            }
        }

        // Recoverable SHM re-attach if `self.shm` was previously detached.
        if self.shm.is_none() {
            match self.state.on_error(
                X11CaptureErrorKind::ShmAttachFailed,
                "XShm segment detached; attempting bounded re-attach",
            ) {
                X11CaptureDecision::RecreateShm { .. } => {
                    self.attach_shm_for_active_monitor()?;
                }
                X11CaptureDecision::TerminalFailure(err) => return Err(err),
                X11CaptureDecision::TimeoutNoChange => return Err(CaptureError::Timeout),
            }
        }

        let Some(attached) = &self.shm else {
            return Err(CaptureError::ReinitRequired(
                "XShm segment unavailable after re-attach".into(),
            ));
        };

        self.display_guard.clear_last_error();
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
        if self.display_guard.is_dead() {
            return match self.state.on_error(
                X11CaptureErrorKind::DisplayDisconnected,
                "X11 display disconnected during XShmGetImage",
            ) {
                X11CaptureDecision::TerminalFailure(err) => Err(err),
                _ => Err(CaptureError::Fatal("X11 display disconnected".into())),
            };
        }
        let proto_err = self.display_guard.last_error();
        if ok == 0 || proto_err != 0 {
            let decision = self.state.on_error(
                X11CaptureErrorKind::BadMatch,
                &format!("XShmGetImage failed (ok={ok}, proto_err={proto_err})"),
            );
            return match decision {
                X11CaptureDecision::RecreateShm { .. } => {
                    self.attach_shm_for_active_monitor()?;
                    Err(CaptureError::ReinitRequired(
                        "XShm recreated after BadMatch".into(),
                    ))
                }
                X11CaptureDecision::TerminalFailure(e) => Err(e),
                X11CaptureDecision::TimeoutNoChange => Err(CaptureError::Timeout),
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
    pw_get_library_version: unsafe extern "C" fn() -> *const c_char,
    _lib: DynLib,
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
            pw_get_library_version,
            _lib: lib,
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
    pending_frames: VecDeque<PackedFrame>,
    monitor_id: u32,
}

impl WaylandPipeWireCapturer {
    pub fn new(monitor_id: u32) -> Result<Self, CaptureError> {
        let (dbus_ok, sc_ok, _, err_note) = probe_portal_availability();
        if !dbus_ok {
            return Err(CaptureError::DesktopUnavailable(
                err_note.unwrap_or_else(|| "D-Bus session bus unavailable".into()),
            ));
        }
        if !sc_ok {
            return Err(CaptureError::Fatal(
                err_note.unwrap_or_else(|| {
                    "Wayland xdg-desktop-portal ScreenCast or libpipewire-0.3.so.0 unavailable"
                        .into()
                }),
            ));
        }
        let pw = PipeWireLib::load()?;
        Ok(Self {
            pw,
            state: WaylandPortalCaptureStateMachine::default(),
            pending_frames: VecDeque::with_capacity(8),
            monitor_id,
        })
    }

    pub fn pipewire_version(&self) -> String {
        self.pw.version_string()
    }

    pub fn state_machine(&self) -> &WaylandPortalCaptureStateMachine {
        &self.state
    }

    /// Applies PipeWire stream negotiation and synchronously clears any queued
    /// stale frames from the previous stream geometry.
    pub fn on_pipewire_negotiated(
        &mut self,
        params: PipeWireStreamParams,
    ) -> Result<(), CaptureError> {
        let changed = self.state.negotiated_stream() != Some(&params);
        let _ = self.state.on_pipewire_negotiated(params)?;
        if changed {
            self.pending_frames.clear();
        }
        Ok(())
    }

    /// Ingests a validated PipeWire MemFd SHM buffer after portal stream negotiation.
    /// Cross-validates `params` against the active negotiated stream and normalizes
    /// `Rgba8`/`Rgbx8`/`Bgrx8` into packed `BGRA8`.
    pub fn ingest_memfd_buffer(
        &mut self,
        params: &PipeWireStreamParams,
        raw_shm: &[u8],
        seq: u64,
        pts_us: i64,
    ) -> Result<(), CaptureError> {
        let Some(negotiated) = self.state.negotiated_stream() else {
            return Err(CaptureError::ReinitRequired(
                "PipeWire MemFd buffer arrived before stream negotiation".into(),
            ));
        };
        if negotiated.node_id != params.node_id
            || negotiated.width != params.width
            || negotiated.height != params.height
            || negotiated.stride != params.stride
            || negotiated.format != params.format
        {
            return Err(CaptureError::ReinitRequired(format!(
                "PipeWire buffer params (node={}, {}x{}, stride={}, {:?}) mismatch negotiated stream (node={}, {}x{}, stride={}, {:?})",
                params.node_id,
                params.width,
                params.height,
                params.stride,
                params.format,
                negotiated.node_id,
                negotiated.width,
                negotiated.height,
                negotiated.stride,
                negotiated.format,
            )));
        }

        let bpp = params.format.packed_bpp().ok_or_else(|| {
            CaptureError::Fatal("planar NV12 MemFd ingest requires NV12 path".into())
        })?;
        let dst_stride = (params.width as usize)
            .checked_mul(bpp)
            .ok_or_else(|| CaptureError::Fatal("Wayland dst_stride overflow".into()))?;
        let mut packed = copy_shm_frame_rows(
            raw_shm,
            params.width,
            params.height,
            params.stride as usize,
            bpp,
            dst_stride,
        )?;
        normalize_packed_to_bgra_in_place(&mut packed, params.format);

        let accepted = self.state.on_frame_arrived(PipeWireFrameArrival {
            seq,
            pts_us,
            byte_len: raw_shm.len(),
            buffer_kind: PipeWireBufferKind::MemFdShm,
        })?;
        if !accepted {
            return Ok(());
        }

        let frame = PackedFrame {
            data: packed,
            width: params.width,
            height: params.height,
            stride: dst_stride as u32,
            format: PipeWirePixelFormat::Bgra8,
            pts_us,
        };
        frame.validate_bgra_bounds()?;

        let cap = self.state.frame_ring().capacity();
        while self.pending_frames.len() >= cap {
            let _ = self.pending_frames.pop_front();
        }
        self.pending_frames.push_back(frame);
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
            self.pending_frames.clear();
            return Err(CaptureError::ReinitRequired(
                "Wayland PipeWire stream not yet negotiated with xdg-desktop-portal".into(),
            ));
        };
        while let Some(frame) = self.pending_frames.pop_front() {
            let _ = self.state.frame_ring_mut().pop();
            if frame.width != stream.width || frame.height != stream.height {
                // Discard stale frame whose geometry no longer matches the negotiated stream.
                continue;
            }
            frame.validate_bgra_bounds()?;
            return Ok(CapturedFrame {
                width: frame.width,
                height: frame.height,
                stride: frame.stride,
                surface: CapturedSurface::Bgra8 { data: frame.data },
                timestamp_us: frame.pts_us,
                monitor_id: self.monitor_id,
                cursor: None,
            });
        }
        Err(CaptureError::Timeout)
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
