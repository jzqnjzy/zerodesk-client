// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

//! `zerodesk-desktop` — Production headless/desktop CLI backed by `V2BridgeRuntime`.
//!
//! Subcommands:
//! - `os-selftest`: zero-write OS capability preflight (redacted JSON, exit 0)
//! - `bridge-stdio`: NDJSON stdin->`V2BridgeRuntime`->stdout event/reply bridge
//! - `host`: start desktop host session via `V2BridgeRuntime`
//! - `connect`: dial remote host via `V2BridgeRuntime`

// Standalone binary does not link `src/platform/macos.mm`, which provides `BackingScaleFactor`
// for `scrap::quartz::Display::scale()`.
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn BackingScaleFactor(display: u32) -> f32 {
    use std::ffi::c_void;
    #[link(name = "CoreGraphics", kind = "framework")]
    extern "C" {
        fn CGDisplayPixelsWide(display: u32) -> usize;
        fn CGDisplayCopyDisplayMode(display: u32) -> *const c_void;
        fn CGDisplayModeGetPixelWidth(mode: *const c_void) -> usize;
        fn CGDisplayModeRelease(mode: *const c_void);
    }
    unsafe {
        let mode = CGDisplayCopyDisplayMode(display);
        if mode.is_null() {
            return 1.0;
        }
        let pixel_w = CGDisplayModeGetPixelWidth(mode);
        CGDisplayModeRelease(mode);
        let point_w = CGDisplayPixelsWide(display);
        if point_w == 0 || pixel_w == 0 {
            1.0
        } else {
            (pixel_w as f32 / point_w as f32).max(1.0)
        }
    }
}

use std::{
    env,
    io::{self, BufRead, Write},
    process::ExitCode,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};
use zerodesk_core::{
    bridge::{V2BridgeRuntime, V2BridgeRuntimeOptions},
    os::{input::RealInputPermit, os_selftest},
};

fn flag_value(args: &[String], name: &str) -> Option<String> {
    let mut i = 0;
    while i < args.len() {
        if args[i] == name {
            return args.get(i + 1).cloned();
        }
        if let Some(rest) = args[i].strip_prefix(&format!("{name}=")) {
            return Some(rest.to_string());
        }
        i += 1;
    }
    None
}

fn has_flag(args: &[String], name: &str) -> bool {
    args.iter().any(|a| a == name)
}

fn build_runtime_from_flags(args: &[String]) -> Result<Arc<V2BridgeRuntime>, String> {
    let mut opts = V2BridgeRuntimeOptions {
        use_os_capture: has_flag(args, "--os-capture"),
        use_os_audio: has_flag(args, "--os-audio"),
        use_os_clipboard: has_flag(args, "--os-clipboard"),
        drop_udp_override: has_flag(args, "--drop-udp"),
        ..V2BridgeRuntimeOptions::default()
    };
    if has_flag(args, "--real-os-input") {
        let permit = RealInputPermit::from_explicit_opt_in(true).map_err(|e| e.to_string())?;
        opts.real_input_permit = Some(permit);
    }
    let rt = V2BridgeRuntime::with_options(opts)?;
    Ok(Arc::new(rt))
}

fn cmd_os_selftest() -> ExitCode {
    let report = os_selftest();
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            println!("{json}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("failed to serialize os-selftest report: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_bridge_stdio(args: &[String]) -> ExitCode {
    let rt = match build_runtime_from_flags(args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("bridge-stdio init failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_ev = Arc::clone(&stop);
    let rt_ev = Arc::clone(&rt);
    let stdout_lock = Arc::new(std::sync::Mutex::new(()));
    let stdout_ev = Arc::clone(&stdout_lock);

    let ev_thread = thread::spawn(move || {
        while !stop_ev.load(Ordering::Acquire) {
            if let Some(ev_json) = rt_ev.poll_event_json_timeout(Duration::from_millis(100)) {
                let _g = stdout_ev.lock().unwrap_or_else(|e| e.into_inner());
                let mut out = io::stdout().lock();
                let _ = writeln!(out, "{{\"stream\":\"event\",\"body\":{ev_json}}}");
                let _ = out.flush();
            }
        }
    });

    let stdin = io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let reply = rt.exec_json(trimmed);
        let _g = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut out = io::stdout().lock();
        let _ = writeln!(out, "{{\"stream\":\"reply\",\"body\":{reply}}}");
        let _ = out.flush();
    }

    stop.store(true, Ordering::Release);
    rt.destroy();
    let _ = ev_thread.join();
    ExitCode::SUCCESS
}

fn cmd_host(args: &[String]) -> ExitCode {
    let Some(cfg_path) = flag_value(args, "--config") else {
        eprintln!("usage: zerodesk-desktop host --config <path.json> [--os-capture] [--os-audio] [--os-clipboard] [--real-os-input]");
        return ExitCode::FAILURE;
    };
    let rt = match build_runtime_from_flags(args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("host init failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let load_cmd = serde_json::json!({ "v": 1, "cmd": "load_config", "path": cfg_path });
    let load_reply = rt.exec_json(&load_cmd.to_string());
    println!("{load_reply}");
    let load_val: serde_json::Value = serde_json::from_str(&load_reply).unwrap_or_default();
    if load_val["ok"].as_bool() != Some(true) {
        rt.destroy();
        return ExitCode::FAILURE;
    }

    let start_reply = rt.exec_json(r#"{"v":1,"cmd":"start_host"}"#);
    println!("{start_reply}");
    let auto_accept = has_flag(args, "--auto-accept");

    // Pump events until EOF/SIGINT/session termination.
    while let Some(ev_str) = rt.poll_event_json_timeout(Duration::from_secs(60)) {
        println!("{ev_str}");
        if auto_accept {
            if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&ev_str) {
                if ev["kind"].as_str() == Some("IncomingCall") {
                    if let Some(inc_id) = ev["payload"]["incoming_id"].as_str() {
                        let acc = serde_json::json!({
                            "v": 1,
                            "cmd": "accept_incoming",
                            "incoming_id": inc_id,
                        });
                        println!("{}", rt.exec_json(&acc.to_string()));
                    }
                }
            }
        }
    }
    rt.destroy();
    ExitCode::SUCCESS
}

fn cmd_connect(args: &[String]) -> ExitCode {
    let Some(cfg_path) = flag_value(args, "--config") else {
        eprintln!("usage: zerodesk-desktop connect --config <path.json> --target <32-hex-device-id>");
        return ExitCode::FAILURE;
    };
    let Some(target) = flag_value(args, "--target") else {
        eprintln!("connect requires --target <32-hex-device-id>");
        return ExitCode::FAILURE;
    };
    let rt = match build_runtime_from_flags(args) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("connect init failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    let load_cmd = serde_json::json!({ "v": 1, "cmd": "load_config", "path": cfg_path });
    let load_reply = rt.exec_json(&load_cmd.to_string());
    println!("{load_reply}");
    let load_val: serde_json::Value = serde_json::from_str(&load_reply).unwrap_or_default();
    if load_val["ok"].as_bool() != Some(true) {
        rt.destroy();
        return ExitCode::FAILURE;
    }

    let dial_cmd = serde_json::json!({
        "v": 1,
        "cmd": "dial",
        "target_device_id_hex": target,
    });
    println!("{}", rt.exec_json(&dial_cmd.to_string()));

    while let Some(ev_str) = rt.poll_event_json_timeout(Duration::from_secs(30)) {
        println!("{ev_str}");
        if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&ev_str) {
            if ev["kind"].as_str() == Some("SessionEnded") {
                break;
            }
        }
    }
    rt.destroy();
    ExitCode::SUCCESS
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("os-selftest") => cmd_os_selftest(),
        Some("bridge-stdio") => cmd_bridge_stdio(&args[2..]),
        Some("host") => cmd_host(&args[2..]),
        Some("connect") => cmd_connect(&args[2..]),
        _ => {
            eprintln!("usage: zerodesk-desktop <os-selftest|bridge-stdio|host|connect> [args...]");
            ExitCode::FAILURE
        }
    }
}
