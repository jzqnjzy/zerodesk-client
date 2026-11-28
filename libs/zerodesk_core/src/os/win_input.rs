// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Thin `#[cfg(windows)]` Win32 `SendInput` input injector & atomic single-batch
//! emergency releaser backed by `win_hid_keymap` and `win_watchdog_logic`.
//!
//! # UIPI Limitation (Windows User Interface Privilege Isolation)
//! Without an installed Windows Service (running as `LocalSystem` / `S-1-5-18` in
//! Session 0 spawning a helper into the active user session) or a signed
//! `uiAccess=true` manifest installed under a trusted location (`Program Files`),
//! Windows UIPI silently blocks `SendInput` targeting elevated (`Administrator`)
//! windows and blocks `OpenInputDesktop` / injection on the Secure/UAC Desktop
//! (`Winlogon`). ZeroDesk explicitly surfaces UIPI elevation status
//! (`is_process_elevated()`), `LocalSystem` status (`is_local_system()`), and
//! accounts for every `SendInput` short return in `ReleaseReport::residual_*`.

#![cfg(windows)]

use super::{
    input::{PressedHidState, RealInputPermit},
    traits::{InputPrivilegeStatus, OsInputInjector},
    win_hid_keymap::{
        mouse_button_bit_to_win, WinHidKeyMap, WinKeyMapping, ALL_MOUSE_BUTTON_BITS,
        WIN_KEYEVENTF_EXTENDEDKEY, WIN_KEYEVENTF_KEYUP, WIN_KEYEVENTF_SCANCODE,
        WIN_MOUSEEVENTF_ABSOLUTE, WIN_MOUSEEVENTF_HWHEEL, WIN_MOUSEEVENTF_MOVE,
        WIN_MOUSEEVENTF_VIRTUALDESK, WIN_MOUSEEVENTF_WHEEL,
    },
    win_watchdog_logic::{build_release_batch, WinInputEventDesc},
    EmergencyKeyReleaser, OsError, OsHidSink, ReleaseReport,
};
use crate::session::hid::{KeyEvent, MouseEvent, MouseKind};
use std::{
    mem::size_of,
    sync::{Arc, Mutex},
};
use windows::Win32::{
    Foundation::{CloseHandle, HANDLE, PSID},
    Security::{
        CreateWellKnownSid, EqualSid, GetTokenInformation, TokenElevation, TokenUser,
        WinLocalSystemSid, TOKEN_ELEVATION, TOKEN_QUERY, TOKEN_USER,
    },
    System::{
        StationsAndDesktops::{
            CloseDesktop, GetThreadDesktop, OpenInputDesktop, SetThreadDesktop,
            DESKTOP_ACCESS_FLAGS, DESKTOP_CONTROL_FLAGS, HDESK,
        },
        Threading::{GetCurrentProcess, GetCurrentThreadId, OpenProcessToken},
    },
    UI::Input::KeyboardAndMouse::{
        SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, INPUT_MOUSE, KEYBDINPUT, KEYBD_EVENT_FLAGS,
        MOUSEINPUT, MOUSE_EVENT_FLAGS, VIRTUAL_KEY,
    },
};

const DESKTOP_READOBJECTS_FLAG: u32 = 0x0001;
const DESKTOP_WRITEOBJECTS_FLAG: u32 = 0x0080;
const WHEEL_DELTA_CLAMP: i32 = 2400;
const SECURITY_MAX_SID_SIZE: usize = 68;

// Compile-time layout sanity for Win32 INPUT struct.
const _: () = assert!(size_of::<INPUT>() > 0 && size_of::<INPUT>() <= i32::MAX as usize);

/// Public documentation string explaining Windows UIPI constraints.
pub const WIN_UIPI_LIMITATION_NOTE: &str = "Without an installed Windows Service (LocalSystem S-1-5-18) or signed uiAccess=true binary, Windows UIPI blocks SendInput into elevated windows and Secure/UAC desktops.";

/// RAII guard binding the calling thread to the current active input desktop via
/// `OpenInputDesktop(0, FALSE, DESKTOP_WRITEOBJECTS | DESKTOP_READOBJECTS)` +
/// `SetThreadDesktop`, restoring the previous thread desktop and closing `HDESK`
/// unconditionally on Drop.
pub struct ScopedInputDesktop {
    previous: HDESK,
    opened: HDESK,
}

impl ScopedInputDesktop {
    pub fn enter() -> Result<Self, OsError> {
        // Query previous thread desktop FIRST so failure never leaks an opened HDESK.
        let previous = unsafe { GetThreadDesktop(GetCurrentThreadId()) }.map_err(|e| {
            OsError::CaptureFailed(format!("GetThreadDesktop failed before desktop switch: {e}"))
        })?;
        let access = DESKTOP_ACCESS_FLAGS(DESKTOP_READOBJECTS_FLAG | DESKTOP_WRITEOBJECTS_FLAG);
        let opened = unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, access) }.map_err(
            |e| {
                OsError::CaptureFailed(format!(
                    "OpenInputDesktop failed (UAC/Secure Desktop or UIPI restriction): {e}"
                ))
            },
        )?;
        if let Err(e) = unsafe { SetThreadDesktop(opened) } {
            unsafe {
                let _ = CloseDesktop(opened);
            }
            return Err(OsError::CaptureFailed(format!(
                "SetThreadDesktop failed: {e}"
            )));
        }
        Ok(Self { previous, opened })
    }
}

impl Drop for ScopedInputDesktop {
    fn drop(&mut self) {
        unsafe {
            let _ = SetThreadDesktop(self.previous);
            let _ = CloseDesktop(self.opened);
        }
    }
}

/// Non-destructive check verifying whether the current process can open the active
/// interactive input desktop (`OpenInputDesktop` + immediate `CloseDesktop`).
pub fn probe_input_desktop_accessible() -> Result<(), OsError> {
    let access = DESKTOP_ACCESS_FLAGS(DESKTOP_READOBJECTS_FLAG | DESKTOP_WRITEOBJECTS_FLAG);
    let desk = unsafe { OpenInputDesktop(DESKTOP_CONTROL_FLAGS(0), false, access) }
        .map_err(|e| OsError::CaptureFailed(format!("OpenInputDesktop probe failed: {e}")))?;
    unsafe {
        let _ = CloseDesktop(desk);
    }
    Ok(())
}

/// Queries whether the current Windows process token is elevated (`TokenElevation`).
/// Returns `Some(true)` if elevated, `Some(false)` if standard user (UIPI restricts
/// injection into elevated windows), or `None` if token query failed.
pub fn is_process_elevated() -> Option<bool> {
    let mut token = HANDLE::default();
    unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.ok()?;
    let mut elevation = TOKEN_ELEVATION::default();
    let mut ret_len = 0u32;
    let res = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        )
    };
    unsafe {
        let _ = CloseHandle(token);
    }
    res.ok().map(|()| elevation.TokenIsElevated != 0)
}

/// Queries whether the current Windows process runs as `NT AUTHORITY\SYSTEM`
/// (`S-1-5-18`, `WinLocalSystemSid`) via `GetTokenInformation(TokenUser)`.
/// Only `LocalSystem` (or a signed `uiAccess=true` broker) can inject into the
/// Secure/UAC Desktop (`Winlogon`).
pub fn is_local_system() -> bool {
    let mut token = HANDLE::default();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }.is_err() {
        return false;
    }
    struct TokenGuard(HANDLE);
    impl Drop for TokenGuard {
        fn drop(&mut self) {
            if !self.0.is_invalid() && self.0 .0 != 0 {
                unsafe {
                    let _ = CloseHandle(self.0);
                }
            }
        }
    }
    let _token_guard = TokenGuard(token);

    let mut needed = 0u32;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut needed) };
    if needed < size_of::<TOKEN_USER>() as u32 {
        return false;
    }
    let mut buf = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr().cast()),
            needed,
            &mut needed,
        )
    }
    .is_err()
    {
        return false;
    }

    let mut system_sid_buf = [0u8; SECURITY_MAX_SID_SIZE];
    let mut sid_len = system_sid_buf.len() as u32;
    let system_psid = PSID(system_sid_buf.as_mut_ptr().cast());
    if unsafe { CreateWellKnownSid(WinLocalSystemSid, PSID::default(), system_psid, &mut sid_len) }
        .is_err()
    {
        return false;
    }

    let user_sid = unsafe { (*buf.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    unsafe { EqualSid(user_sid, system_psid) }.is_ok()
}

fn build_kb_input_for_mapping(mapping: WinKeyMapping, down: bool) -> INPUT {
    if mapping.use_vk_mode {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(mapping.vk_code),
                    wScan: 0,
                    dwFlags: KEYBD_EVENT_FLAGS(mapping.send_input_flags(down)),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    } else {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(0),
                    wScan: mapping.scan_code,
                    dwFlags: KEYBD_EVENT_FLAGS(mapping.send_input_flags(down)),
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    }
}

fn build_mouse_input(dx: i32, dy: i32, mouse_data: u32, flags: u32) -> INPUT {
    INPUT {
        r#type: INPUT_MOUSE,
        Anonymous: INPUT_0 {
            mi: MOUSEINPUT {
                dx,
                dy,
                mouseData: mouse_data,
                dwFlags: MOUSE_EVENT_FLAGS(flags),
                time: 0,
                dwExtraInfo: 0,
            },
        },
    }
}

fn desc_to_win_input(desc: &WinInputEventDesc) -> INPUT {
    match *desc {
        WinInputEventDesc::KeyboardScanUp {
            scan_code,
            extended,
            vk_code,
            use_vk_mode,
            ..
        } => {
            if use_vk_mode {
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(vk_code),
                            wScan: 0,
                            dwFlags: KEYBD_EVENT_FLAGS(WIN_KEYEVENTF_KEYUP),
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            } else {
                let mut flags = WIN_KEYEVENTF_SCANCODE | WIN_KEYEVENTF_KEYUP;
                if extended {
                    flags |= WIN_KEYEVENTF_EXTENDEDKEY;
                }
                INPUT {
                    r#type: INPUT_KEYBOARD,
                    Anonymous: INPUT_0 {
                        ki: KEYBDINPUT {
                            wVk: VIRTUAL_KEY(0),
                            wScan: scan_code,
                            dwFlags: KEYBD_EVENT_FLAGS(flags),
                            time: 0,
                            dwExtraInfo: 0,
                        },
                    },
                }
            }
        }
        WinInputEventDesc::MouseButtonUp {
            flags, mouse_data, ..
        } => build_mouse_input(0, 0, mouse_data, flags),
    }
}

fn count_batch_events(batch: &[WinInputEventDesc]) -> (usize, usize) {
    let mut keys = 0usize;
    let mut buttons = 0usize;
    for desc in batch {
        match desc {
            WinInputEventDesc::KeyboardScanUp { .. } => keys += 1,
            WinInputEventDesc::MouseButtonUp { .. } => buttons += 1,
        }
    }
    (keys, buttons)
}

/// Executes an atomic single-call `SendInput` batch release after switching the
/// calling thread onto the active input desktop via `ScopedInputDesktop`.
///
/// Windows guarantees events in a single `SendInput(&inputs, size_of::<INPUT>() as i32)`
/// call are NOT interleaved with other threads' input. Any shortfall (`sent < inputs.len()`,
/// e.g. due to UIPI) is reported accurately in `ReleaseReport::residual_*`.
pub fn execute_atomic_release_batch(batch: &[WinInputEventDesc]) -> Result<ReleaseReport, OsError> {
    if batch.is_empty() {
        return Ok(ReleaseReport::default());
    }
    let _desktop_guard = match ScopedInputDesktop::enter() {
        Ok(guard) => Some(guard),
        Err(err) => {
            eprintln!(
                "[zerodesk_core::os::win_input] WARN: ScopedInputDesktop::enter failed before atomic release batch: {err}"
            );
            None
        }
    };

    let inputs: Vec<INPUT> = batch.iter().map(desc_to_win_input).collect();
    let cb_size = i32::try_from(size_of::<INPUT>())
        .map_err(|_| OsError::InvalidData("size_of::<INPUT>() overflow".into()))?;
    let sent = unsafe { SendInput(&inputs, cb_size) } as usize;

    let mut released_keys = 0usize;
    let mut released_buttons = 0usize;
    let mut residual_keys = 0usize;
    let mut residual_buttons = 0usize;

    for (idx, desc) in batch.iter().enumerate() {
        let succeeded = idx < sent;
        match desc {
            WinInputEventDesc::KeyboardScanUp { .. } => {
                if succeeded {
                    released_keys += 1;
                } else {
                    residual_keys += 1;
                }
            }
            WinInputEventDesc::MouseButtonUp { .. } => {
                if succeeded {
                    released_buttons += 1;
                } else {
                    residual_buttons += 1;
                }
            }
        }
    }

    Ok(ReleaseReport {
        released_keys,
        released_buttons,
        residual_keys,
        residual_buttons,
    })
}

/// Stateless emergency releaser for `WinOsInputInjector`: latches `interlocked = true`,
/// snapshots & clears held keys/buttons under a brief lock, drops the lock, then submits
/// ONE atomic `SendInput` release batch covering all held keys, all 8 modifiers, and all
/// 5 mouse buttons.
pub struct WinEmergencyKeyReleaser {
    pressed: Arc<Mutex<PressedHidState>>,
}

impl EmergencyKeyReleaser for WinEmergencyKeyReleaser {
    fn release_all_keys(&self) -> ReleaseReport {
        let (keys, buttons) = {
            let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
            g.interlocked = true;
            let keys: Vec<u16> = g.keys.iter().copied().collect();
            let buttons = g.buttons;
            g.keys.clear();
            g.buttons = 0;
            (keys, buttons)
        };
        let batch = build_release_batch(&keys, 0, buttons);
        let (total_keys, total_buttons) = count_batch_events(&batch);
        execute_atomic_release_batch(&batch).unwrap_or(ReleaseReport {
            released_keys: 0,
            released_buttons: 0,
            residual_keys: total_keys,
            residual_buttons: total_buttons,
        })
    }
}

/// Windows `SendInput` HID injector implementing `OsHidSink` and `OsInputInjector`.
pub struct WinOsInputInjector {
    permit: Arc<RealInputPermit>,
    pressed: Arc<Mutex<PressedHidState>>,
}

impl WinOsInputInjector {
    /// Requires explicit runtime `Arc<RealInputPermit>` (same fail-closed gating
    /// contract as macOS `MacOsHidSink`).
    pub fn new(permit: Arc<RealInputPermit>) -> Result<Self, OsError> {
        if !super::input::real_input_compiled_in() {
            return Err(OsError::UnsupportedPlatform(
                "real OS input disabled at compile time (enable --features real-input)",
            ));
        }
        Ok(Self {
            permit,
            pressed: PressedHidState::new_shared(),
        })
    }

    fn verify_permit(&self) -> Result<(), OsError> {
        let _ = &self.permit;
        if !super::input::real_input_compiled_in() {
            return Err(OsError::NotPermitted);
        }
        Ok(())
    }

    fn send_single_input(input: INPUT) -> Result<(), OsError> {
        let cb_size = i32::try_from(size_of::<INPUT>())
            .map_err(|_| OsError::InvalidData("size_of::<INPUT>() overflow".into()))?;
        let sent = unsafe { SendInput(&[input], cb_size) };
        if sent == 1 {
            Ok(())
        } else {
            Err(OsError::CaptureFailed(
                "Win32 SendInput returned 0 (blocked by UIPI or desktop switch)".into(),
            ))
        }
    }
}

impl OsHidSink for WinOsInputInjector {
    fn send_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
        self.verify_permit()?;
        let Ok(usage) = u16::try_from(ev.usb_hid_usage) else {
            return Err(OsError::InvalidData(format!(
                "USB HID usage {:#x} exceeds u16 range",
                ev.usb_hid_usage
            )));
        };
        let Some(mapping) = WinHidKeyMap::hid_to_win(usage) else {
            return Ok(());
        };
        {
            let g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
            if g.interlocked {
                return Err(OsError::Interlocked);
            }
        }
        let input = build_kb_input_for_mapping(mapping, ev.down);
        Self::send_single_input(input)?;

        let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
        if g.interlocked {
            if ev.down {
                drop(g);
                let _ = Self::send_single_input(build_kb_input_for_mapping(mapping, false));
            }
            return Err(OsError::Interlocked);
        }
        if ev.down {
            g.keys.insert(usage);
        } else {
            g.keys.remove(&usage);
        }
        Ok(())
    }

    fn send_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError> {
        self.verify_permit()?;
        {
            let g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
            if g.interlocked {
                return Err(OsError::Interlocked);
            }
        }
        let buttons = ev.buttons & 0x1F;
        match ev.kind {
            MouseKind::MoveAbs => {
                let x = ev.x_or_dx.clamp(0, 65_535);
                let y = ev.y_or_dy.clamp(0, 65_535);
                let flags =
                    WIN_MOUSEEVENTF_MOVE | WIN_MOUSEEVENTF_ABSOLUTE | WIN_MOUSEEVENTF_VIRTUALDESK;
                Self::send_single_input(build_mouse_input(x, y, 0, flags))?;
            }
            MouseKind::MoveRel => {
                Self::send_single_input(build_mouse_input(
                    ev.x_or_dx,
                    ev.y_or_dy,
                    0,
                    WIN_MOUSEEVENTF_MOVE,
                ))?;
            }
            MouseKind::Down => {
                let mut inputs = Vec::new();
                for bit in ALL_MOUSE_BUTTON_BITS {
                    if (buttons & bit) != 0 {
                        if let Some(act) = mouse_button_bit_to_win(bit, true) {
                            inputs.push(build_mouse_input(0, 0, act.mouse_data, act.flags));
                        }
                    }
                }
                if !inputs.is_empty() {
                    let cb_size = i32::try_from(size_of::<INPUT>())
                        .map_err(|_| OsError::InvalidData("size_of::<INPUT>() overflow".into()))?;
                    let sent = unsafe { SendInput(&inputs, cb_size) } as usize;
                    if sent != inputs.len() {
                        return Err(OsError::CaptureFailed(
                            "Win32 SendInput(mouse down) partially blocked by UIPI".into(),
                        ));
                    }
                    let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                    if g.interlocked {
                        drop(g);
                        let _ = execute_atomic_release_batch(&build_release_batch(&[], 0, buttons));
                        return Err(OsError::Interlocked);
                    }
                    g.buttons |= buttons;
                }
            }
            MouseKind::Up => {
                let mut inputs = Vec::new();
                for bit in ALL_MOUSE_BUTTON_BITS {
                    if (buttons & bit) != 0 {
                        if let Some(act) = mouse_button_bit_to_win(bit, false) {
                            inputs.push(build_mouse_input(0, 0, act.mouse_data, act.flags));
                        }
                    }
                }
                if !inputs.is_empty() {
                    let cb_size = i32::try_from(size_of::<INPUT>())
                        .map_err(|_| OsError::InvalidData("size_of::<INPUT>() overflow".into()))?;
                    let sent = unsafe { SendInput(&inputs, cb_size) } as usize;
                    if sent != inputs.len() {
                        return Err(OsError::CaptureFailed(
                            "Win32 SendInput(mouse up) partially blocked by UIPI".into(),
                        ));
                    }
                    let mut g = self.pressed.lock().unwrap_or_else(|e| e.into_inner());
                    g.buttons &= !buttons;
                }
            }
            MouseKind::Wheel => {
                let wy = i32::from(ev.wheel_dy).clamp(-WHEEL_DELTA_CLAMP, WHEEL_DELTA_CLAMP);
                let wx = i32::from(ev.wheel_dx).clamp(-WHEEL_DELTA_CLAMP, WHEEL_DELTA_CLAMP);
                let mut inputs = Vec::with_capacity(2);
                if wy != 0 {
                    inputs.push(build_mouse_input(0, 0, wy as u32, WIN_MOUSEEVENTF_WHEEL));
                }
                if wx != 0 {
                    inputs.push(build_mouse_input(0, 0, wx as u32, WIN_MOUSEEVENTF_HWHEEL));
                }
                if !inputs.is_empty() {
                    let cb_size = i32::try_from(size_of::<INPUT>())
                        .map_err(|_| OsError::InvalidData("size_of::<INPUT>() overflow".into()))?;
                    let _ = unsafe { SendInput(&inputs, cb_size) };
                }
            }
        }
        Ok(())
    }

    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
        Arc::new(WinEmergencyKeyReleaser {
            pressed: Arc::clone(&self.pressed),
        })
    }
}

impl OsInputInjector for WinOsInputInjector {
    fn inject_key(&mut self, ev: &KeyEvent) -> Result<(), OsError> {
        self.send_key(ev)
    }

    fn inject_mouse(&mut self, ev: &MouseEvent) -> Result<(), OsError> {
        self.send_mouse(ev)
    }

    fn emergency_releaser(&self) -> Arc<dyn EmergencyKeyReleaser> {
        OsHidSink::emergency_releaser(self)
    }

    fn privilege_status(&self) -> InputPrivilegeStatus {
        win_input_privilege_status()
    }
}

/// Computes Windows UIPI, `LocalSystem` (`S-1-5-18`), and interactive desktop
/// accessibility privilege summary.
pub fn win_input_privilege_status() -> InputPrivilegeStatus {
    let elevated = is_process_elevated();
    let local_system = is_local_system();
    let desktop_ok = probe_input_desktop_accessible().is_ok();
    let secure_desktop_blocked = !desktop_ok || !local_system;
    InputPrivilegeStatus {
        accessibility_granted: desktop_ok,
        uipi_elevated: elevated,
        secure_desktop_blocked,
        note: Some(WIN_UIPI_LIMITATION_NOTE.to_string()),
    }
}
