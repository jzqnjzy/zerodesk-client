// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

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
    // Integration test binaries live in `<target>/<profile>/deps/<test-bin>`.
    // Cargo places `libzerodesk_core.{dylib,so}` in `<target>/<profile>/`.
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
    // If `cargo test` hasn't built the cdylib yet (e.g. clean target with `--test`), build it now.
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

#[test]
fn c_abi_two_phase_frame_copy_buffer_too_small_and_video_frame_ready() {
    assert_eq!(zerodesk_v2_abi_version(), ZERODESK_V2_ABI_VERSION);

    let rt = Arc::new(V2BridgeRuntime::new().unwrap());
    let pixels: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(3).wrapping_add(1)).collect();
    rt.mailbox()
        .publish_raw(4, 4, 16, PixelFormat::Bgra8, 777, pixels.clone())
        .unwrap();
    let handle = register_runtime(rt);

    // Phase 1: query frame_info
    let mut info = ZeroDeskFrameInfo::default();
    assert_eq!(unsafe { zerodesk_v2_frame_info(handle, &mut info) }, ZERODESK_OK);
    assert_eq!(info.seq, 1);
    assert_eq!(info.width, 4);
    assert_eq!(info.height, 4);
    assert_eq!(info.stride, 16);
    assert_eq!(info.pixel_format, 1);
    assert_eq!(info.byte_len, 64);
    assert_eq!(info.pts_ms, 777);

    // Phase 2a: buffer-too-small returns ZERODESK_ERR_BUFFER_TOO_SMALL, writes required byte_len,
    // and leaves every single byte of out_buf untouched.
    let mut small_buf = [0xA5u8; 16];
    let mut req_info = ZeroDeskFrameInfo::default();
    assert_eq!(
        unsafe {
            zerodesk_v2_take_latest_frame(
                handle,
                small_buf.as_mut_ptr(),
                small_buf.len(),
                &mut req_info,
            )
        },
        ZERODESK_ERR_BUFFER_TOO_SMALL
    );
    assert_eq!(req_info.byte_len, 64);
    assert!(small_buf.iter().all(|&b| b == 0xA5));

    // Phase 2b: properly sized buffer copies exact pixels.
    let mut full_buf = vec![0u8; 64];
    let mut out_info = ZeroDeskFrameInfo::default();
    assert_eq!(
        unsafe {
            zerodesk_v2_take_latest_frame(
                handle,
                full_buf.as_mut_ptr(),
                full_buf.len(),
                &mut out_info,
            )
        },
        ZERODESK_OK
    );
    assert_eq!(full_buf, pixels);
    assert_eq!(out_info.dropped_ui_frames, 0);

    // On-demand synthesized VideoFrameReady event
    let mut ev_buf = ZeroDeskOwnedBuffer::empty();
    assert_eq!(
        unsafe { zerodesk_v2_poll_event_json(handle, &mut ev_buf) },
        ZERODESK_OK
    );
    let ev_str = unsafe { std::str::from_utf8(std::slice::from_raw_parts(ev_buf.ptr, ev_buf.len)).unwrap().to_string() };
    unsafe { zerodesk_v2_buffer_free(ev_buf) };
    assert!(ev_str.contains("\"kind\":\"VideoFrameReady\""));

    assert_eq!(zerodesk_v2_destroy(handle), ZERODESK_OK);
    assert_eq!(zerodesk_v2_destroy(handle), ZERODESK_ERR_INVALID_HANDLE);
}
