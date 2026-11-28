// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! Safe RAII dynamic library loader (`dlopen(RTLD_NOW | RTLD_LOCAL)` / `dlsym` /
//! `dlclose`) for Linux thin FFI adapters.
//!
//! Ensures ZERO compile-time linkage against Linux system `.so` files (`libva`,
//! `libX11`, `libXtst`, `libpipewire`, etc.) so cross-compilation from macOS
//! succeeds cleanly and missing runtime libraries return structured errors.

#![cfg(target_os = "linux")]

use std::ffi::{CStr, CString, c_void};

/// RAII handle owning a dynamically loaded shared object via `libc::dlopen`.
pub struct DynLib {
    handle: *mut c_void,
    name: String,
}

// SAFETY: A `dlopen` handle is process-global and `dlsym`/`dlclose` are thread-safe on glibc/musl.
unsafe impl Send for DynLib {}
unsafe impl Sync for DynLib {}

impl DynLib {
    /// Opens a shared library by SONAME using `RTLD_NOW | RTLD_LOCAL`.
    pub fn open(soname: &str) -> Result<Self, String> {
        let c_name = CString::new(soname)
            .map_err(|_| format!("invalid shared library name containing NUL: '{soname}'"))?;
        let handle = unsafe { libc::dlopen(c_name.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            let err = last_dlerror().unwrap_or_else(|| "unknown dlopen error".to_string());
            return Err(format!("dlopen('{soname}') failed: {err}"));
        }
        Ok(Self {
            handle,
            name: soname.to_string(),
        })
    }

    /// Attempts to open the first available shared library from `candidates`.
    pub fn open_any(candidates: &[&str]) -> Result<Self, String> {
        let mut last_err = String::from("no candidate library names provided");
        for &name in candidates {
            match Self::open(name) {
                Ok(lib) => return Ok(lib),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Resolves a raw symbol pointer via `dlsym`.
    pub fn symbol_raw(&self, symbol: &str) -> Result<*mut c_void, String> {
        let c_sym = CString::new(symbol)
            .map_err(|_| format!("invalid symbol name containing NUL: '{symbol}'"))?;
        let ptr = unsafe { libc::dlsym(self.handle, c_sym.as_ptr()) };
        if ptr.is_null() {
            let err = last_dlerror().unwrap_or_else(|| "symbol not found".to_string());
            return Err(format!(
                "dlsym('{}', '{symbol}') failed: {err}",
                self.name
            ));
        }
        Ok(ptr)
    }

    /// Resolves a typed function pointer from this library.
    ///
    /// # Safety
    /// Caller must ensure `T` matches the exact C ABI signature of `symbol`.
    pub unsafe fn symbol<T: Copy>(&self, symbol: &str) -> Result<T, String> {
        debug_assert_eq!(std::mem::size_of::<T>(), std::mem::size_of::<*mut c_void>());
        let ptr = self.symbol_raw(symbol)?;
        Ok(std::mem::transmute_copy(&ptr))
    }
}

impl Drop for DynLib {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                let _ = libc::dlclose(self.handle);
            }
            self.handle = std::ptr::null_mut();
        }
    }
}

fn last_dlerror() -> Option<String> {
    let err_ptr = unsafe { libc::dlerror() };
    if err_ptr.is_null() {
        return None;
    }
    let msg = unsafe { CStr::from_ptr(err_ptr) }
        .to_string_lossy()
        .into_owned();
    if msg.is_empty() {
        None
    } else {
        Some(msg)
    }
}
