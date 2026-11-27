// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

use std::{env, path::PathBuf, process::Command};

fn try_pkg_config_opus() -> bool {
    let output = match Command::new("pkg-config").args(["--libs", "opus"]).output() {
        Ok(out) if out.status.success() => out,
        _ => return false,
    };
    let stdout = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let mut found_lib = false;
    for token in stdout.split_whitespace() {
        if let Some(dir) = token.strip_prefix("-L") {
            if !dir.is_empty() {
                println!("cargo:rustc-link-search=native={dir}");
            }
        } else if let Some(lib) = token.strip_prefix("-l") {
            if !lib.is_empty() {
                println!("cargo:rustc-link-lib={lib}");
                if lib == "opus" {
                    found_lib = true;
                }
            }
        }
    }
    found_lib
}

fn try_pkg_config_opus_libdir() -> Option<PathBuf> {
    let output = Command::new("pkg-config")
        .args(["--variable=libdir", "opus"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let dir = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if dir.is_empty() {
        None
    } else {
        Some(PathBuf::from(dir))
    }
}

fn try_link_static_opus() -> bool {
    let mut candidates: Vec<PathBuf> = Vec::new();
    if let Ok(prefix) = env::var("ZERODESK_LIBOPUS_PREFIX") {
        candidates.push(PathBuf::from(prefix).join("lib"));
    }
    if let Some(pc_dir) = try_pkg_config_opus_libdir() {
        candidates.push(pc_dir);
    }
    for dir in [
        "/opt/homebrew/opt/opus/lib",
        "/opt/homebrew/lib",
        "/usr/local/opt/opus/lib",
        "/usr/local/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/lib",
    ] {
        candidates.push(PathBuf::from(dir));
    }
    for dir in candidates {
        if dir.join("libopus.a").is_file() {
            println!("cargo:rustc-link-search=native={}", dir.display());
            println!("cargo:rustc-link-lib=static=opus");
            return true;
        }
    }
    false
}

fn link_macos_frameworks() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=CoreGraphics");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
        println!("cargo:rustc-link-lib=framework=Carbon");
        println!("cargo:rustc-link-lib=framework=AppKit");
    }
}

fn compile_macos_sck() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos")
        && env::var_os("CARGO_FEATURE_OS_SCK").is_some()
    {
        println!("cargo:rerun-if-changed=native/macos_sck.h");
        println!("cargo:rerun-if-changed=native/macos_sck.m");

        cc::Build::new()
            .file("native/macos_sck.m")
            .include("native")
            .flag("-fobjc-arc")
            .flag("-fobjc-arc-exceptions")
            .flag("-mmacosx-version-min=13.0")
            .flag("-Wall")
            .flag("-Wextra")
            .flag("-Werror")
            .compile("zerodesk_macos_sck");

        println!("cargo:rustc-link-lib=framework=ScreenCaptureKit");
        println!("cargo:rustc-link-lib=framework=CoreMedia");
        println!("cargo:rustc-link-lib=framework=CoreVideo");
        println!("cargo:rustc-link-lib=framework=CoreGraphics");
        println!("cargo:rustc-link-lib=framework=Foundation");
        println!("cargo:rustc-link-lib=framework=CoreAudio");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ZERODESK_LIBOPUS_PREFIX");
    println!("cargo:rerun-if-env-changed=ZERODESK_STATIC_CODECS");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    link_macos_frameworks();
    compile_macos_sck();

    let static_codecs = env::var("ZERODESK_STATIC_CODECS").as_deref() == Ok("1");
    if static_codecs {
        if try_link_static_opus() {
            return;
        }
        panic!("ZERODESK_STATIC_CODECS=1 requested, but libopus.a was not found in ZERODESK_LIBOPUS_PREFIX, pkg-config, or standard lib dirs");
    }

    if let Ok(prefix) = env::var("ZERODESK_LIBOPUS_PREFIX") {
        let lib_dir = PathBuf::from(&prefix).join("lib");
        if lib_dir.is_dir() {
            println!("cargo:rustc-link-search=native={}", lib_dir.display());
            println!("cargo:rustc-link-lib=opus");
            return;
        }
    }

    if try_pkg_config_opus() {
        return;
    }

    for candidate in [
        "/opt/homebrew/opt/opus/lib",
        "/opt/homebrew/lib",
        "/usr/local/opt/opus/lib",
        "/usr/local/lib",
        "/usr/lib/x86_64-linux-gnu",
        "/usr/lib/aarch64-linux-gnu",
        "/usr/lib",
    ] {
        let p = PathBuf::from(candidate);
        if p.join("libopus.dylib").exists()
            || p.join("libopus.so").exists()
            || p.join("libopus.a").exists()
        {
            println!("cargo:rustc-link-search=native={candidate}");
            println!("cargo:rustc-link-lib=opus");
            return;
        }
    }

    println!("cargo:rustc-link-lib=opus");
}
