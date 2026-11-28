// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(target_os = "linux")]` OS input injector implementing `OsInputInjector`
//! and dual-layer emergency key release for Linux:
//! - Explicit opt-in `/dev/uinput` (pure `libc::ioctl`, `O_CLOEXEC`, `input_event`,
//!   and `SYN_REPORT`, supporting both `EV_ABS` absolute pointer and `EV_REL` relative/wheel,
//!   with root-equivalent warning enforced by `LinuxInputAccessPlan`),
//! - X11 `XTest` (`dlopen("libX11.so.6")` + `dlopen("libXtst.so.6")`),
//! - Wayland `xdg-desktop-portal` RemoteDesktop status reporting.
//!
//! ZERO compile-time `.so` linkage; ZERO copied Linux kernel headers.

#![cfg(target_os = "linux")]

use super::{
    linux_capture::{current_linux_session_kind, probe_portal_availability},
    linux_dl::DynLib,
    linux_hid_keymap::{
        mouse_button_bit_to_linux, LinuxHidKeyMap, ABS_X, ABS_Y, BTN_EXTRA, BTN_LEFT, BTN_MIDDLE,
        BTN_RIGHT, BTN_SIDE, EV_ABS, EV_KEY, EV_REL, EV_SYN, REL_HWHEEL, REL_WHEEL, REL_X, REL_Y,
        SYN_REPORT,
    },
    linux_watchdog_logic::{
        resolve_linux_input_access_plan, LinuxInputAccessPlan, LinuxInputBackendChoice,
        LinuxInputCapabilities, LinuxReleaseStep, LinuxWatchdogShadowSet,
    },
    traits::{InputPrivilegeStatus, OsInputInjector},
    EmergencyKeyReleaser, OsError, ReleaseReport,
};
use crate::session::hid::{KeyEvent, MouseEvent, MouseKind};
use std::{
    ffi::{c_char, c_int, c_uint, c_ulong, c_void, CString},
    mem::size_of,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

// Clean-room Linux uinput ioctl numbers (`_IO` / `_IOW` with type `'U' = 0x55`).
const UINPUT_IOCTL_TYPE: u32 = b'U' as u32;
const IOC_NONE: u32 = 0;
const IOC_WRITE: u32 = 1;

const fn linux_ioc(dir: u32, ty: u32, nr: u32, size: u32) -> u32 {
    (dir << 30) | (size << 16) | (ty << 8) | nr
}

const UI_DEV_CREATE: u32 = linux_ioc(IOC_NONE, UINPUT_IOCTL_TYPE, 1, 0);
const UI_DEV_DESTROY: u32 = linux_ioc(IOC_NONE, UINPUT_IOCTL_TYPE, 2, 0);
const UI_DEV_SETUP: u32 =
    linux_ioc(IOC_WRITE, UINPUT_IOCTL_TYPE, 3, size_of::<UinputSetup>() as u32);
const UI_ABS_SETUP: u32 =
    linux_ioc(IOC_WRITE, UINPUT_IOCTL_TYPE, 4, size_of::<UinputAbsSetup>() as u32);
const UI_SET_EVBIT: u32 = linux_ioc(IOC_WRITE, UINPUT_IOCTL_TYPE, 100, size_of::<c_int>() as u32);
const UI_SET_KEYBIT: u32 = linux_ioc(IOC_WRITE, UINPUT_IOCTL_TYPE, 101, size_of::<c_int>() as u32);
const UI_SET_RELBIT: u32 = linux_ioc(IOC_WRITE, UINPUT_IOCTL_TYPE, 102, size_of::<c_int>() as u32);
const UI_SET_ABSBIT: u32 = linux_ioc(IOC_WRITE, UINPUT_IOCTL_TYPE, 103, size_of::<c_int>() as u32);

const BUS_VIRTUAL: u16 = 0x06;
const DEFAULT_UINPUT_PATH: &str = "/dev/uinput";
const UINPUT_DEV_LABEL: &[u8] = b"ZeroDesk Virtual HID";
const UINPUT_ABS_MAX: i32 = 65_535;
const XTEST_MAX_WHEEL_CLICKS: u16 = 32;

#[repr(C)]
struct InputId {
    bustype: u16,
    vendor: u16,
    product: u16,
    version: u16,
}

#[repr(C)]
struct UinputSetup {
    id: InputId,
    name: [c_char; 80],
    ff_effects_max: u32,
}

#[repr(C)]
struct InputAbsInfo {
    value: i32,
    minimum: i32,
    maximum: i32,
    fuzz: i32,
    flat: i32,
    resolution: i32,
}

#[repr(C)]
struct UinputAbsSetup {
    code: u16,
    _pad: u16,
    absinfo: InputAbsInfo,
}

#[repr(C)]
struct LinuxInputEvent {
    time: libc::timeval,
    ev_type: u16,
    code: u16,
    value: i32,
}

// Compile-time ABI sanity checks matching Linux kernel uinput UAPI exactly.
const _: () = assert!(size_of::<UinputSetup>() == 92);
const _: () = assert!(UI_DEV_SETUP == 0x405c_5503);
const _: () = assert!(size_of::<UinputAbsSetup>() == 28);
const _: () = assert!(UI_ABS_SETUP == 0x401c_5504);
const _: () = assert!(UINPUT_DEV_LABEL.len() < 80);
const _: () = assert!(size_of::<LinuxInputEvent>() == size_of::<libc::timeval>() + 8);

/// Probes whether `/dev/uinput` is currently writable by this process (non-destructive `access(W_OK)`).
pub fn is_uinput_writable(path: &str) -> bool {
    let Ok(c_path) = CString::new(path) else {
        return false;
    };
    unsafe { libc::access(c_path.as_ptr(), libc::W_OK) == 0 }
}

/// Probes whether X11 `XTest` (`libX11.so.6` + `libXtst.so.6` + active X display) is available.
pub fn probe_xtest_available() -> bool {
    let Ok(x11) = DynLib::open("libX11.so.6") else {
        return false;
    };
    let Ok(xtst) = DynLib::open("libXtst.so.6") else {
        return false;
    };
    unsafe {
        let Ok(open_disp) =
            x11.symbol::<unsafe extern "C" fn(*const c_char) -> *mut c_void>("XOpenDisplay")
        else {
            return false;
        };
        let Ok(close_disp) = x11.symbol::<unsafe extern "C" fn(*mut c_void) -> c_int>("XCloseDisplay")
        else {
            return false;
        };
        let Ok(query_ext) = xtst.symbol::<unsafe extern "C" fn(
            *mut c_void,
            *mut c_int,
            *mut c_int,
            *mut c_int,
            *mut c_int,
        ) -> c_int>("XTestQueryExtension") else {
            return false;
        };
        let disp = open_disp(ptr::null());
        if disp.is_null() {
            return false;
        }
        let (mut ev, mut err, mut maj, mut min) = (0, 0, 0, 0);
        let ok = query_ext(disp, &mut ev, &mut err, &mut maj, &mut min) != 0;
        let _ = close_disp(disp);
        ok
    }
}

/// Probes live Linux input capabilities and builds the `LinuxInputCapabilities` struct.
/// `uinput_writable` reflects live `/dev/uinput` write permission, while activation
/// remains disabled unless `uinput_explicit_opt_in == true`.
pub fn probe_linux_input_capabilities(uinput_explicit_opt_in: bool) -> LinuxInputCapabilities {
    let session_kind = current_linux_session_kind();
    let (_, _, portal_rd, _) = probe_portal_availability();
    let xtest_available = probe_xtest_available();
    let uinput_writable = is_uinput_writable(DEFAULT_UINPUT_PATH);
    LinuxInputCapabilities {
        session_kind,
        portal_remote_desktop_available: portal_rd,
        xtest_available,
        uinput_explicit_opt_in,
        uinput_writable,
        uinput_device_path: DEFAULT_UINPUT_PATH.to_string(),
    }
}

/// Cross-platform `InputPrivilegeStatus` probe wired into `OsHidSinkInjector::privilege_status`.
pub fn linux_input_privilege_status() -> InputPrivilegeStatus {
    let caps = probe_linux_input_capabilities(false);
    let plan = resolve_linux_input_access_plan(&caps);
    let note = if !plan.warnings.is_empty() {
        Some(plan.warnings.join("; "))
    } else {
        Some(format!("Linux input backend selected: {:?}", plan.selected))
    };
    InputPrivilegeStatus {
        accessibility_granted: plan.permitted,
        uipi_elevated: None,
        secure_desktop_blocked: false,
        note,
    }
}

// ============================================================================
// Pure `libc` `/dev/uinput` Virtual Device (Explicit Opt-In Only!)
// ============================================================================

/// RAII handle owning an open `/dev/uinput` virtual keyboard+mouse descriptor.
pub struct UinputVirtualDevice {
    fd: c_int,
    created: bool,
}

// SAFETY: Kernel file descriptor operations are synchronized by caller's Mutex / `&mut self`.
unsafe impl Send for UinputVirtualDevice {}

impl UinputVirtualDevice {
    pub fn open_opt_in(device_path: &str, explicit_opt_in: bool) -> Result<Self, OsError> {
        if !explicit_opt_in {
            return Err(OsError::NotPermitted);
        }
        let c_path = CString::new(device_path)
            .map_err(|_| OsError::InvalidData("invalid uinput device path".into()))?;
        let fd = unsafe {
            libc::open(
                c_path.as_ptr(),
                libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(OsError::CaptureFailed(format!(
                "open('{device_path}', O_CLOEXEC) failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let mut dev = Self { fd, created: false };
        dev.configure_and_create()?;
        Ok(dev)
    }

    pub fn raw_fd(&self) -> c_int {
        self.fd
    }

    fn ioctl_int(&self, req: u32, val: c_int) -> Result<(), OsError> {
        let rc = unsafe { libc::ioctl(self.fd, req as libc::Ioctl, val) };
        if rc < 0 {
            return Err(OsError::CaptureFailed(format!(
                "uinput ioctl({req:#x}, {val}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn setup_abs_axis(&self, axis_code: u16) -> Result<(), OsError> {
        self.ioctl_int(UI_SET_ABSBIT, c_int::from(axis_code))?;
        let abs_setup = UinputAbsSetup {
            code: axis_code,
            _pad: 0,
            absinfo: InputAbsInfo {
                value: 0,
                minimum: 0,
                maximum: UINPUT_ABS_MAX,
                fuzz: 0,
                flat: 0,
                resolution: 0,
            },
        };
        let rc = unsafe {
            libc::ioctl(
                self.fd,
                UI_ABS_SETUP as libc::Ioctl,
                &abs_setup as *const UinputAbsSetup,
            )
        };
        if rc < 0 {
            return Err(OsError::CaptureFailed(format!(
                "uinput UI_ABS_SETUP(axis={axis_code}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(())
    }

    fn configure_and_create(&mut self) -> Result<(), OsError> {
        self.ioctl_int(UI_SET_EVBIT, c_int::from(EV_KEY))?;
        self.ioctl_int(UI_SET_EVBIT, c_int::from(EV_REL))?;
        self.ioctl_int(UI_SET_EVBIT, c_int::from(EV_ABS))?;
        self.ioctl_int(UI_SET_EVBIT, c_int::from(EV_SYN))?;

        for mapping in LinuxHidKeyMap::all_mappings() {
            self.ioctl_int(UI_SET_KEYBIT, c_int::from(mapping.evdev_code))?;
        }
        for btn in [BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA] {
            self.ioctl_int(UI_SET_KEYBIT, c_int::from(btn))?;
        }
        for rel in [REL_X, REL_Y, REL_WHEEL, REL_HWHEEL] {
            self.ioctl_int(UI_SET_RELBIT, c_int::from(rel))?;
        }
        self.setup_abs_axis(ABS_X)?;
        self.setup_abs_axis(ABS_Y)?;

        let mut setup = UinputSetup {
            id: InputId {
                bustype: BUS_VIRTUAL,
                vendor: 0x5A44,  // "ZD"
                product: 0x0002, // ZeroDesk V2 virtual HID
                version: 1,
            },
            name: [0; 80],
            ff_effects_max: 0,
        };
        for (idx, &b) in UINPUT_DEV_LABEL.iter().enumerate() {
            setup.name[idx] = b as c_char;
        }

        let rc_setup = unsafe {
            libc::ioctl(
                self.fd,
                UI_DEV_SETUP as libc::Ioctl,
                &setup as *const UinputSetup,
            )
        };
        if rc_setup < 0 {
            return Err(OsError::CaptureFailed(format!(
                "uinput UI_DEV_SETUP failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        let rc_create = unsafe { libc::ioctl(self.fd, UI_DEV_CREATE as libc::Ioctl) };
        if rc_create < 0 {
            return Err(OsError::CaptureFailed(format!(
                "uinput UI_DEV_CREATE failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        self.created = true;
        Ok(())
    }

    pub fn write_event(&self, ev_type: u16, code: u16, value: i32) -> Result<(), OsError> {
        if self.fd < 0 {
            return Err(OsError::Interlocked);
        }
        let ev = LinuxInputEvent {
            time: libc::timeval {
                tv_sec: 0,
                tv_usec: 0,
            },
            ev_type,
            code,
            value,
        };
        let bytes = unsafe {
            std::slice::from_raw_parts(
                (&ev as *const LinuxInputEvent).cast::<u8>(),
                size_of::<LinuxInputEvent>(),
            )
        };
        let n = unsafe { libc::write(self.fd, bytes.as_ptr().cast(), bytes.len()) };
        if n < 0 {
            return Err(OsError::CaptureFailed(format!(
                "uinput write(type={ev_type}, code={code}, val={value}) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
        if (n as usize) != bytes.len() {
            return Err(OsError::CaptureFailed(format!(
                "uinput short write(type={ev_type}, code={code}, val={value}): wrote {n}/{} bytes",
                bytes.len()
            )));
        }
        Ok(())
    }

    pub fn write_syn_report(&self) -> Result<(), OsError> {
        self.write_event(EV_SYN, SYN_REPORT, 0)
    }

    /// Executes the Layer 2 backup teardown (`UI_DEV_DESTROY` + `close(fd)`),
    /// called strictly AFTER Layer 1 explicit `EV_KEY=0` + `SYN_REPORT`.
    pub fn destroy_and_close(&mut self) {
        if self.fd >= 0 {
            if self.created {
                unsafe {
                    let _ = libc::ioctl(self.fd, UI_DEV_DESTROY as libc::Ioctl);
                }
                self.created = false;
            }
            unsafe {
                let _ = libc::close(self.fd);
            }
            self.fd = -1;
        }
    }
}

impl Drop for UinputVirtualDevice {
    fn drop(&mut self) {
        self.destroy_and_close();
    }
}

// ============================================================================
// X11 XTest Runtime Dynamic Binding (`dlopen("libX11.so.6")` + `libXtst.so.6`)
// ============================================================================

struct XTestInjector {
    display: *mut c_void,
    x_close_display: unsafe extern "C" fn(*mut c_void) -> c_int,
    x_flush: unsafe extern "C" fn(*mut c_void) -> c_int,
    xtest_fake_key: unsafe extern "C" fn(*mut c_void, c_uint, c_int, c_ulong) -> c_int,
    xtest_fake_button: unsafe extern "C" fn(*mut c_void, c_uint, c_int, c_ulong) -> c_int,
    xtest_fake_motion: unsafe extern "C" fn(*mut c_void, c_int, c_int, c_int, c_ulong) -> c_int,
    xtest_fake_rel_motion: unsafe extern "C" fn(*mut c_void, c_int, c_int, c_ulong) -> c_int,
    // Keep DynLib handles last for defense-in-depth drop order.
    _xtst: DynLib,
    _x11: DynLib,
}

// SAFETY: `XTestInjector` owns its private XDisplay* behind a Mutex.
unsafe impl Send for XTestInjector {}

impl XTestInjector {
    fn open() -> Result<Self, OsError> {
        let x11 = DynLib::open("libX11.so.6").map_err(OsError::CaptureFailed)?;
        let xtst = DynLib::open("libXtst.so.6").map_err(OsError::CaptureFailed)?;
        unsafe {
            let open_disp = x11
                .symbol::<unsafe extern "C" fn(*const c_char) -> *mut c_void>("XOpenDisplay")
                .map_err(OsError::CaptureFailed)?;
            let x_close_display: unsafe extern "C" fn(*mut c_void) -> c_int = x11
                .symbol("XCloseDisplay")
                .map_err(OsError::CaptureFailed)?;
            let x_flush = x11.symbol("XFlush").map_err(OsError::CaptureFailed)?;
            let query_ext = xtst
                .symbol::<unsafe extern "C" fn(
                    *mut c_void,
                    *mut c_int,
                    *mut c_int,
                    *mut c_int,
                    *mut c_int,
                ) -> c_int>("XTestQueryExtension")
                .map_err(OsError::CaptureFailed)?;
            let xtest_fake_key = xtst
                .symbol("XTestFakeKeyEvent")
                .map_err(OsError::CaptureFailed)?;
            let xtest_fake_button = xtst
                .symbol("XTestFakeButtonEvent")
                .map_err(OsError::CaptureFailed)?;
            let xtest_fake_motion = xtst
                .symbol("XTestFakeMotionEvent")
                .map_err(OsError::CaptureFailed)?;
            let xtest_fake_rel_motion = xtst
                .symbol("XTestFakeRelativeMotionEvent")
                .map_err(OsError::CaptureFailed)?;

            let display = open_disp(ptr::null());
            if display.is_null() {
                return Err(OsError::CaptureFailed(
                    "XOpenDisplay(NULL) failed for XTest injector".into(),
                ));
            }
            let (mut ev, mut err, mut maj, mut min) = (0, 0, 0, 0);
            if query_ext(display, &mut ev, &mut err, &mut maj, &mut min) == 0 {
                let _ = x_close_display(display);
                return Err(OsError::CaptureFailed(
                    "XTest extension unavailable on active X11 display".into(),
                ));
            }

            Ok(Self {
                display,
                x_close_display,
                x_flush,
                xtest_fake_key,
                xtest_fake_button,
                xtest_fake_motion,
                xtest_fake_rel_motion,
                _xtst: xtst,
                _x11: x11,
            })
        }
    }

    fn send_key(&self, x11_keycode: u8, down: bool) -> Result<(), OsError> {
        let rc = unsafe {
            (self.xtest_fake_key)(self.display, c_uint::from(x11_keycode), c_int::from(down), 0)
        };
        unsafe {
            let _ = (self.x_flush)(self.display);
        }
        if rc == 0 {
            return Err(OsError::CaptureFailed("XTestFakeKeyEvent failed".into()));
        }
        Ok(())
    }

    fn send_button(&self, button: u32, down: bool) -> Result<(), OsError> {
        let rc = unsafe {
            (self.xtest_fake_button)(self.display, button as c_uint, c_int::from(down), 0)
        };
        unsafe {
            let _ = (self.x_flush)(self.display);
        }
        if rc == 0 {
            return Err(OsError::CaptureFailed("XTestFakeButtonEvent failed".into()));
        }
        Ok(())
    }

    fn send_abs_motion(&self, x: i32, y: i32) -> Result<(), OsError> {
        let rc = unsafe { (self.xtest_fake_motion)(self.display, -1, x as c_int, y as c_int, 0) };
        unsafe {
            let _ = (self.x_flush)(self.display);
        }
        if rc == 0 {
            return Err(OsError::CaptureFailed("XTestFakeMotionEvent failed".into()));
        }
        Ok(())
    }

    fn send_rel_motion(&self, dx: i32, dy: i32) -> Result<(), OsError> {
        let rc = unsafe { (self.xtest_fake_rel_motion)(self.display, dx as c_int, dy as c_int, 0) };
        unsafe {
            let _ = (self.x_flush)(self.display);
        }
        if rc == 0 {
            return Err(OsError::CaptureFailed(
                "XTestFakeRelativeMotionEvent failed".into(),
            ));
        }
        Ok(())
    }
}

impl Drop for XTestInjector {
    fn drop(&mut self) {
        if !self.display.is_null() {
            unsafe {
                let _ = (self.x_close_display)(self.display);
            }
            self.display = ptr::null_mut();
        }
    }
}

// ============================================================================
// Dual-Layer Release Executor & Unified `LinuxOsInputInjector`
// ============================================================================

/// Executes a `LinuxReleaseStep` plan on an active `UinputVirtualDevice`:
/// - Layer 1: writes every explicit `EV_KEY value=0` + `EV_SYN SYN_REPORT`
///   (if `SYN_REPORT` fails, records residual failure so callers fail closed),
/// - Layer 2: executes `destroy_and_close()` ONLY when `CloseUinputFd` is reached.
pub fn execute_uinput_dual_layer_release(
    dev: &mut UinputVirtualDevice,
    steps: &[LinuxReleaseStep],
) -> ReleaseReport {
    let mut report = ReleaseReport::default();
    for &step in steps {
        match step {
            LinuxReleaseStep::KeyRelease { evdev_code, .. } => {
                if dev.write_event(EV_KEY, evdev_code, 0).is_ok() {
                    report.released_keys += 1;
                } else {
                    report.residual_keys += 1;
                }
            }
            LinuxReleaseStep::MouseButtonRelease { evdev_code, .. } => {
                if dev.write_event(EV_KEY, evdev_code, 0).is_ok() {
                    report.released_buttons += 1;
                } else {
                    report.residual_buttons += 1;
                }
            }
            LinuxReleaseStep::SynReport => {
                if dev.write_syn_report().is_err() {
                    // Unflushed SYN_REPORT means kernel may not have committed releases; fail closed.
                    report.residual_keys = report.residual_keys.saturating_add(1);
                }
            }
            LinuxReleaseStep::CloseUinputFd => {
                dev.destroy_and_close();
            }
        }
    }
    report
}

fn execute_xtest_release_on(xtest: &XTestInjector, steps: &[LinuxReleaseStep]) -> ReleaseReport {
    let mut report = ReleaseReport::default();
    for &step in steps {
        match step {
            LinuxReleaseStep::KeyRelease { hid_usage, .. } => {
                if let Some(m) = LinuxHidKeyMap::hid_to_linux(hid_usage) {
                    if xtest.send_key(m.x11_keycode, false).is_ok() {
                        report.released_keys += 1;
                    } else {
                        report.residual_keys += 1;
                    }
                }
            }
            LinuxReleaseStep::MouseButtonRelease { button_bit, .. } => {
                if let Some(m) = mouse_button_bit_to_linux(button_bit) {
                    if xtest.send_button(m.x11_button, false).is_ok() {
                        report.released_buttons += 1;
                    } else {
                        report.residual_buttons += 1;
                    }
                }
            }
            LinuxReleaseStep::SynReport | LinuxReleaseStep::CloseUinputFd => {}
        }
    }
    report
}

/// Executes a `LinuxReleaseStep` plan via X11 `XTest` (Layer 1 explicit key/button-up + flush).
pub fn execute_xtest_release(steps: &[LinuxReleaseStep]) -> Result<ReleaseReport, OsError> {
    let xtest = XTestInjector::open()?;
    Ok(execute_xtest_release_on(&xtest, steps))
}

enum LinuxInputBackend {
    Uinput(UinputVirtualDevice),
    XTest(XTestInjector),
}

struct SharedLinuxInputState {
    backend: Mutex<Option<LinuxInputBackend>>,
    shadow: Mutex<LinuxWatchdogShadowSet>,
    interlocked: AtomicBool,
}

pub struct LinuxEmergencyKeyReleaser {
    shared: Arc<SharedLinuxInputState>,
}

impl EmergencyKeyReleaser for LinuxEmergencyKeyReleaser {
    fn release_all_keys(&self) -> ReleaseReport {
        // Lock backend FIRST, latch interlocked inside the mutex so no concurrent
        // `inject_key` / `inject_mouse` can slip past in a TOCTOU race.
        let mut backend_guard = match self.shared.backend.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        self.shared.interlocked.store(true, Ordering::Release);
        let mut shadow_guard = match self.shared.shadow.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let has_uinput = matches!(&*backend_guard, Some(LinuxInputBackend::Uinput(_)));
        let steps = shadow_guard.build_dual_layer_release_plan(has_uinput);
        let report = match &mut *backend_guard {
            Some(LinuxInputBackend::Uinput(dev)) => execute_uinput_dual_layer_release(dev, &steps),
            Some(LinuxInputBackend::XTest(xtest)) => execute_xtest_release_on(xtest, &steps),
            None => ReleaseReport::default(),
        };
        shadow_guard.clear();
        report
    }
}

/// Unified Linux `OsInputInjector` strictly governed by `LinuxInputAccessPlan`.
pub struct LinuxOsInputInjector {
    plan: LinuxInputAccessPlan,
    shared: Arc<SharedLinuxInputState>,
    last_buttons: u8,
}

impl LinuxOsInputInjector {
    pub fn open(uinput_explicit_opt_in: bool) -> Result<Self, OsError> {
        let caps = probe_linux_input_capabilities(uinput_explicit_opt_in);
        let plan = resolve_linux_input_access_plan(&caps);
        if !plan.permitted {
            return Err(OsError::NotPermitted);
        }
        let backend = match &plan.selected {
            LinuxInputBackendChoice::UinputRootEquivalentOptIn { device_path } => {
                let dev = UinputVirtualDevice::open_opt_in(device_path, uinput_explicit_opt_in)?;
                LinuxInputBackend::Uinput(dev)
            }
            LinuxInputBackendChoice::X11XTest => {
                let xtest = XTestInjector::open()?;
                LinuxInputBackend::XTest(xtest)
            }
            LinuxInputBackendChoice::WaylandPortalRemoteDesktop { .. } => {
                return Err(OsError::UnsupportedPlatform(
                    "Wayland portal RemoteDesktop D-Bus session requires interactive compositor approval",
                ));
            }
            LinuxInputBackendChoice::ExplicitDeny { .. } => return Err(OsError::NotPermitted),
        };
        Ok(Self {
            plan,
            shared: Arc::new(SharedLinuxInputState {
                backend: Mutex::new(Some(backend)),
                shadow: Mutex::new(LinuxWatchdogShadowSet::new()),
                interlocked: AtomicBool::new(false),
            }),
            last_buttons: 0,
        })
    }

    pub fn access_plan(&self) -> &LinuxInputAccessPlan {
        &self.plan
    }
}

impl OsInputInjector for LinuxOsInputInjector {
    fn inject_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
        let Ok(hid_usage) = u16::try_from(ev.usb_hid_usage) else {
            return Ok(());
        };
        let Some(mapping) = LinuxHidKeyMap::hid_to_linux(hid_usage) else {
            return Ok(());
        };
        let backend_guard = match self.shared.backend.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if self.shared.interlocked.load(Ordering::Acquire) {
            return Err(OsError::Interlocked);
        }
        match &*backend_guard {
            Some(LinuxInputBackend::Uinput(dev)) => {
                dev.write_event(EV_KEY, mapping.evdev_code, i32::from(ev.down))?;
                dev.write_syn_report()?;
            }
            Some(LinuxInputBackend::XTest(xtest)) => {
                xtest.send_key(mapping.x11_keycode, ev.down)?;
            }
            None => return Err(OsError::Interlocked),
        }

        let mut shadow = match self.shared.shadow.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if self.shared.interlocked.load(Ordering::Acquire) {
            return Err(OsError::Interlocked);
        }
        let mut keys = shadow.pressed_hid_keys();
        if ev.down {
            if !keys.contains(&hid_usage) {
                keys.push(hid_usage);
            }
        } else {
            keys.retain(|&k| k != hid_usage);
        }
        let btns = shadow.pressed_mouse_buttons();
        shadow.set_pressed_keys(&keys, btns, ev.modifiers);
        drop(shadow);
        drop(backend_guard);
        Ok(())
    }

    fn inject_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError> {
        let backend_guard = match self.shared.backend.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if self.shared.interlocked.load(Ordering::Acquire) {
            return Err(OsError::Interlocked);
        }
        match &*backend_guard {
            Some(LinuxInputBackend::Uinput(dev)) => {
                match ev.kind {
                    MouseKind::MoveAbs => {
                        let abs_x = ev.x_or_dx.clamp(0, UINPUT_ABS_MAX);
                        let abs_y = ev.y_or_dy.clamp(0, UINPUT_ABS_MAX);
                        dev.write_event(EV_ABS, ABS_X, abs_x)?;
                        dev.write_event(EV_ABS, ABS_Y, abs_y)?;
                    }
                    MouseKind::MoveRel => {
                        if ev.x_or_dx != 0 {
                            dev.write_event(EV_REL, REL_X, ev.x_or_dx)?;
                        }
                        if ev.y_or_dy != 0 {
                            dev.write_event(EV_REL, REL_Y, ev.y_or_dy)?;
                        }
                    }
                    MouseKind::Down | MouseKind::Up => {
                        let new_mask = ev.buttons & 0x1F;
                        let changed = self.last_buttons ^ new_mask;
                        for bit in [1u8, 2, 4, 8, 16] {
                            if (changed & bit) != 0 {
                                if let Some(m) = mouse_button_bit_to_linux(bit) {
                                    let pressed = (new_mask & bit) != 0;
                                    dev.write_event(EV_KEY, m.evdev_code, i32::from(pressed))?;
                                }
                            }
                        }
                        self.last_buttons = new_mask;
                    }
                    MouseKind::Wheel => {
                        if ev.wheel_dy != 0 {
                            dev.write_event(EV_REL, REL_WHEEL, i32::from(ev.wheel_dy))?;
                        }
                        if ev.wheel_dx != 0 {
                            dev.write_event(EV_REL, REL_HWHEEL, i32::from(ev.wheel_dx))?;
                        }
                    }
                }
                dev.write_syn_report()?;
            }
            Some(LinuxInputBackend::XTest(xtest)) => match ev.kind {
                MouseKind::MoveAbs => {
                    xtest.send_abs_motion(ev.x_or_dx, ev.y_or_dy)?;
                }
                MouseKind::MoveRel => {
                    xtest.send_rel_motion(ev.x_or_dx, ev.y_or_dy)?;
                }
                MouseKind::Down | MouseKind::Up => {
                    let new_mask = ev.buttons & 0x1F;
                    let changed = self.last_buttons ^ new_mask;
                    for bit in [1u8, 2, 4, 8, 16] {
                        if (changed & bit) != 0 {
                            if let Some(m) = mouse_button_bit_to_linux(bit) {
                                let pressed = (new_mask & bit) != 0;
                                xtest.send_button(m.x11_button, pressed)?;
                            }
                        }
                    }
                    self.last_buttons = new_mask;
                }
                MouseKind::Wheel => {
                    if ev.wheel_dy != 0 {
                        let btn = if ev.wheel_dy > 0 { 4 } else { 5 };
                        let clicks = ev.wheel_dy.unsigned_abs().clamp(1, XTEST_MAX_WHEEL_CLICKS);
                        for _ in 0..clicks {
                            xtest.send_button(btn, true)?;
                            xtest.send_button(btn, false)?;
                        }
                    }
                    if ev.wheel_dx != 0 {
                        let btn = if ev.wheel_dx > 0 { 7 } else { 6 };
                        let clicks = ev.wheel_dx.unsigned_abs().clamp(1, XTEST_MAX_WHEEL_CLICKS);
                        for _ in 0..clicks {
                            xtest.send_button(btn, true)?;
                            xtest.send_button(btn, false)?;
                        }
                    }
                }
            },
            None => return Err(OsError::Interlocked),
        }

        let mut shadow = match self.shared.shadow.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        if self.shared.interlocked.load(Ordering::Acquire) {
            return Err(OsError::Interlocked);
        }
        let keys = shadow.pressed_hid_keys();
        let mods = shadow.pressed_modifiers();
        shadow.set_pressed_keys(&keys, self.last_buttons, mods);
        drop(shadow);
        drop(backend_guard);
        Ok(())
    }

    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
        Arc::new(LinuxEmergencyKeyReleaser {
            shared: Arc::clone(&self.shared),
        })
    }

    fn privilege_status(&self) -> InputPrivilegeStatus {
        let note = if !self.plan.warnings.is_empty() {
            Some(self.plan.warnings.join("; "))
        } else {
            Some(format!("Linux input backend active: {:?}", self.plan.selected))
        };
        InputPrivilegeStatus {
            accessibility_granted: self.plan.permitted,
            uipi_elevated: None,
            secure_desktop_blocked: false,
            note,
        }
    }
}
