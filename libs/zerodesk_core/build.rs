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

fn link_macos_frameworks() {
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rustc-link-lib=framework=CoreGraphics");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=ApplicationServices");
        println!("cargo:rustc-link-lib=framework=Carbon");
        println!("cargo:rustc-link-lib=framework=AppKit");
    }
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ZERODESK_LIBOPUS_PREFIX");
    println!("cargo:rerun-if-env-changed=PKG_CONFIG_PATH");

    link_macos_frameworks();

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
