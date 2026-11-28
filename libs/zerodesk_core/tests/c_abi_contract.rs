// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

#[cfg(unix)]
use std::ffi::CString;
use std::{
    env,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use zerodesk_core::{
    bridge::V2BridgeRuntime,
    ffi_abi::{
        register_runtime, zerodesk_v2_abi_version, zerodesk_v2_buffer_free, zerodesk_v2_destroy,
        zerodesk_v2_frame_info, zerodesk_v2_poll_event_json, zerodesk_v2_take_latest_frame,
        ZeroDeskFrameInfo, ZeroDeskOwnedBuffer, ZERODESK_ERR_BUFFER_TOO_SMALL,
        ZERODESK_ERR_INVALID_HANDLE, ZERODESK_OK, ZERODESK_V2_ABI_VERSION,
    },
    frame::PixelFormat,
};

fn find_cdylib_dir() -> PathBuf {
    let exe = env::current_exe().expect("current_exe");
    let deps_dir = exe.parent().expect("deps dir");
    let profile_dir = deps_dir.parent().unwrap_or(deps_dir);
    let lib_name = if cfg!(target_os = "macos") {
        "libzerodesk_core.dylib"
    } else if cfg!(target_os = "windows") {
        "zerodesk_core.dll"
    } else {
        "libzerodesk_core.so"
    };
    if profile_dir.join(lib_name).exists() {
        return profile_dir.to_path_buf();
    }
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let status = Command::new("cargo")
        .args(["build", "--lib", "--manifest-path"])
        .arg(manifest_dir.join("Cargo.toml"))
        .status()
        .expect("invoke cargo build --lib for cdylib");
    assert!(status.success(), "cargo build --lib failed");
    assert!(
        profile_dir.join(lib_name).exists(),
        "expected {} in {}",
        lib_name,
        profile_dir.display()
    );
    profile_dir.to_path_buf()
}

fn c_compiler_command(manifest_dir: &Path) -> Command {
    let target = if cfg!(target_os = "macos") && cfg!(target_arch = "aarch64") {
        "aarch64-apple-darwin"
    } else if cfg!(target_os = "macos") && cfg!(target_arch = "x86_64") {
        "x86_64-apple-darwin"
    } else if cfg!(target_os = "linux") && cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-gnu"
    } else {
        "x86_64-unknown-linux-gnu"
    };
    let compiler = cc::Build::new()
        .host(target)
        .target(target)
        .opt_level(0)
        .out_dir(env::temp_dir())
        .include(manifest_dir.join("include"))
        .get_compiler();
    compiler.to_command()
}

#[test]
fn compiled_c_abi_contract_against_live_cdylib() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("include");
    let c_src = manifest_dir.join("tests/abi_c/abi_contract_test.c");
    let lib_dir = find_cdylib_dir();

    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let bin_path = env::temp_dir().join(format!(
        "zerodesk_c_abi_contract_{}_{uniq}",
        std::process::id()
    ));

    let mut cmd = c_compiler_command(&manifest_dir);
    cmd.args(["-std=c11", "-Wall", "-Wextra", "-Werror"])
        .arg("-I")
        .arg(&include_dir)
        .arg(&c_src)
        .arg("-L")
        .arg(&lib_dir)
        .arg("-lzerodesk_core")
        .arg(format!("-Wl,-rpath,{}", lib_dir.display()))
        .arg("-o")
        .arg(&bin_path);

    let compile_out = cmd.output().expect("run C compiler for abi_contract_test.c");
    assert!(
        compile_out.status.success(),
        "C-ABI contract compile failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&compile_out.stdout),
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let run_out = Command::new(&bin_path)
        .output()
        .expect("execute compiled C-ABI contract binary");
    let _ = std::fs::remove_file(&bin_path);
    assert!(
        run_out.status.success(),
        "C-ABI contract runtime failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&run_out.stdout),
        String::from_utf8_lossy(&run_out.stderr)
    );
}

#[cfg(unix)]
#[test]
fn compiled_c_side_populated_frame_two_phase_and_canary_check() {
    assert_eq!(zerodesk_v2_abi_version(), ZERODESK_V2_ABI_VERSION);

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let include_dir = manifest_dir.join("include");
    let c_src = manifest_dir.join("tests/abi_c/abi_contract_test.c");
    let uniq = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let ext = if cfg!(target_os = "macos") {
        "dylib"
    } else {
        "so"
    };
    let dylib_path = env::temp_dir().join(format!(
        "libzerodesk_c_seeded_{}_{uniq}.{ext}",
        std::process::id()
    ));

    let mut cmd = c_compiler_command(&manifest_dir);
    cmd.args([
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-Wmissing-prototypes",
        "-Werror",
        "-DZERODESK_NO_MAIN",
        "-shared",
        "-fPIC",
    ])
    .arg("-I")
    .arg(&include_dir)
    .arg(&c_src)
    .arg("-o")
    .arg(&dylib_path);

    let compile_out = cmd.output().expect("compile C seeded-frame verifier dylib");
    assert!(
        compile_out.status.success(),
        "compile C seeded-frame verifier failed:\nstderr: {}",
        String::from_utf8_lossy(&compile_out.stderr)
    );

    let rt = Arc::new(V2BridgeRuntime::new().unwrap());
    let pixels: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(5).wrapping_add(11))
        .collect();
    rt.mailbox()
        .publish_raw(4, 4, 16, PixelFormat::Bgra8, 777, pixels.clone())
        .unwrap();
    let handle = register_runtime(rt);

    type VerifyFn = unsafe extern "C" fn(
        u64,
        u32,
        u32,
        u32,
        u32,
        *const u8,
        usize,
        unsafe extern "C" fn(u64, *mut ZeroDeskFrameInfo) -> i32,
        unsafe extern "C" fn(u64, *mut u8, usize, *mut ZeroDeskFrameInfo) -> i32,
        unsafe extern "C" fn(u64, *mut ZeroDeskOwnedBuffer) -> i32,
        unsafe extern "C" fn(ZeroDeskOwnedBuffer),
    ) -> i32;

    unsafe {
        let c_path = CString::new(dylib_path.to_str().unwrap()).unwrap();
        let lib = libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW);
        assert!(!lib.is_null(), "dlopen failed for seeded C verifier");
        let sym_name = CString::new("zerodesk_c_verify_seeded_frame").unwrap();
        let sym = libc::dlsym(lib, sym_name.as_ptr());
        assert!(!sym.is_null(), "dlsym zerodesk_c_verify_seeded_frame failed");
        let verify: VerifyFn = std::mem::transmute(sym);
        let rc = verify(
            handle,
            4,
            4,
            16,
            1,
            pixels.as_ptr(),
            pixels.len(),
            zerodesk_v2_frame_info,
            zerodesk_v2_take_latest_frame,
            zerodesk_v2_poll_event_json,
            zerodesk_v2_buffer_free,
        );
        libc::dlclose(lib);
        let _ = std::fs::remove_file(&dylib_path);
        assert_eq!(rc, 0, "C-side seeded frame contract verification failed");
    }

    assert_eq!(zerodesk_v2_destroy(handle), ZERODESK_OK);
    assert_eq!(zerodesk_v2_destroy(handle), ZERODESK_ERR_INVALID_HANDLE);
}

#[test]
fn cross_platform_ffi_populated_frame_two_phase_canary_and_video_frame_ready() {
    assert_eq!(zerodesk_v2_abi_version(), ZERODESK_V2_ABI_VERSION);

    let rt = Arc::new(V2BridgeRuntime::new().unwrap());
    // Publish two frames so dropped_ui_frames == 1 when taking latest.
    rt.mailbox()
        .publish_raw(4, 4, 16, PixelFormat::Bgra8, 100, vec![0x11; 64])
        .unwrap();
    let pixels: Vec<u8> = (0..64u8)
        .map(|i| i.wrapping_mul(7).wrapping_add(3))
        .collect();
    rt.mailbox()
        .publish_raw(4, 4, 16, PixelFormat::Bgra8, 777, pixels.clone())
        .unwrap();
    let handle = register_runtime(rt);

    unsafe {
        // 1. frame_info query
        let mut info = ZeroDeskFrameInfo::default();
        assert_eq!(zerodesk_v2_frame_info(handle, &mut info), ZERODESK_OK);
        assert_eq!(info.seq, 2);
        assert_eq!(info.width, 4);
        assert_eq!(info.height, 4);
        assert_eq!(info.stride, 16);
        assert_eq!(info.pixel_format, PixelFormat::Bgra8.as_u32());
        assert_eq!(info.byte_len, 64);
        assert_eq!(info.pts_ms, 777);

        // 2. out_cap == 0 size query -> ZERODESK_ERR_BUFFER_TOO_SMALL + required byte_len
        let mut q_info = ZeroDeskFrameInfo::default();
        assert_eq!(
            zerodesk_v2_take_latest_frame(handle, std::ptr::null_mut(), 0, &mut q_info),
            ZERODESK_ERR_BUFFER_TOO_SMALL
        );
        assert_eq!(q_info.byte_len, 64);

        // 3. Small canary buffer -> ZERODESK_ERR_BUFFER_TOO_SMALL + ZERO bytes overwritten
        let mut canary = [0xAAu8; 16];
        let mut s_info = ZeroDeskFrameInfo::default();
        assert_eq!(
            zerodesk_v2_take_latest_frame(handle, canary.as_mut_ptr(), canary.len(), &mut s_info),
            ZERODESK_ERR_BUFFER_TOO_SMALL
        );
        assert!(canary.iter().all(|&b| b == 0xAA));
        assert_eq!(s_info.byte_len, 64);

        // 4. Full exact copy -> ZERODESK_OK + exact pixels + pts_ms + dropped_ui_frames == 1
        let mut full = vec![0u8; 64];
        let mut f_info = ZeroDeskFrameInfo::default();
        assert_eq!(
            zerodesk_v2_take_latest_frame(handle, full.as_mut_ptr(), full.len(), &mut f_info),
            ZERODESK_OK
        );
        assert_eq!(full, pixels);
        assert_eq!(f_info.pts_ms, 777);
        assert_eq!(f_info.dropped_ui_frames, 1);

        // 5. On-demand VideoFrameReady synthesis via poll_event_json
        let mut ev = ZeroDeskOwnedBuffer::empty();
        assert_eq!(zerodesk_v2_poll_event_json(handle, &mut ev), ZERODESK_OK);
        let ev_str = std::str::from_utf8(std::slice::from_raw_parts(ev.ptr, ev.len)).unwrap();
        assert!(ev_str.contains("\"kind\":\"VideoFrameReady\""));
        zerodesk_v2_buffer_free(ev);
    }

    assert_eq!(zerodesk_v2_destroy(handle), ZERODESK_OK);
    assert_eq!(zerodesk_v2_destroy(handle), ZERODESK_ERR_INVALID_HANDLE);
}
