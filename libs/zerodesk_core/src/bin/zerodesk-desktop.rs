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

static SIGNAL_STOP: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn handle_termination_signal(_sig: libc::c_int) {
    SIGNAL_STOP.store(true, Ordering::Release);
}

fn install_signal_handlers() {
    SIGNAL_STOP.store(false, Ordering::Release);
    #[cfg(unix)]
    unsafe {
        libc::signal(
            libc::SIGINT,
            handle_termination_signal as *const () as libc::sighandler_t,
        );
        libc::signal(
            libc::SIGTERM,
            handle_termination_signal as *const () as libc::sighandler_t,
        );
    }
}

/// RAII guard guaranteeing `V2BridgeRuntime::destroy()` always runs on every exit path.
struct RuntimeDropGuard(Arc<V2BridgeRuntime>);

impl RuntimeDropGuard {
    fn rt(&self) -> &Arc<V2BridgeRuntime> {
        &self.0
    }
}

impl Drop for RuntimeDropGuard {
    fn drop(&mut self) {
        self.0.destroy();
    }
}

fn write_stdout_line(line: &str) {
    let mut out = io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

fn write_stderr_line(line: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{line}");
}

/// Validates CLI flags strictly: rejects any unknown flag or missing value with exit code 2.
fn validate_flags(args: &[String], bool_flags: &[&str], value_flags: &[&str]) -> Result<(), String> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if bool_flags.contains(&arg) {
            i += 1;
            continue;
        }
        if value_flags.contains(&arg) {
            if i + 1 >= args.len() {
                return Err(format!("flag '{arg}' requires a value"));
            }
            i += 2;
            continue;
        }
        if let Some((flag, val)) = arg.split_once('=') {
            if value_flags.contains(&flag) {
                if val.is_empty() {
                    return Err(format!("flag '{flag}' requires a non-empty value"));
                }
                i += 1;
                continue;
            }
        }
        return Err(format!("unknown CLI flag or argument: '{arg}'"));
    }
    Ok(())
}

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

fn build_runtime_from_flags(args: &[String]) -> Result<RuntimeDropGuard, String> {
    let watchdog_report = flag_value(args, "--watchdog-report").map(std::path::PathBuf::from);
    let enable_watchdog = has_flag(args, "--hid-watchdog") || watchdog_report.is_some();
    let mut opts = V2BridgeRuntimeOptions {
        use_os_capture: has_flag(args, "--os-capture"),
        legacy_capture_fallback: has_flag(args, "--legacy-capture-fallback"),
        use_os_audio: has_flag(args, "--os-audio"),
        use_os_clipboard: has_flag(args, "--os-clipboard"),
        enable_hid_watchdog_subprocess: enable_watchdog,
        watchdog_report_path: watchdog_report,
        ..V2BridgeRuntimeOptions::default()
    };
    if has_flag(args, "--real-os-input") {
        let permit = RealInputPermit::from_explicit_opt_in(true).map_err(|e| e.to_string())?;
        opts.real_input_permit = Some(Arc::new(permit));
    }
    let rt = V2BridgeRuntime::with_options(opts)?;
    Ok(RuntimeDropGuard(Arc::new(rt)))
}

fn cmd_os_selftest(args: &[String]) -> ExitCode {
    if let Err(e) = validate_flags(args, &[], &[]) {
        write_stderr_line(&format!("os-selftest: {e}"));
        return ExitCode::from(2);
    }
    let report = os_selftest();
    match serde_json::to_string_pretty(&report) {
        Ok(json) => {
            write_stdout_line(&json);
            ExitCode::SUCCESS
        }
        Err(e) => {
            write_stderr_line(&format!("failed to serialize os-selftest report: {e}"));
            ExitCode::FAILURE
        }
    }
}

fn cmd_bridge_stdio(args: &[String]) -> ExitCode {
    if let Err(e) = validate_flags(
        args,
        &[
            "--os-capture",
            "--legacy-capture-fallback",
            "--os-audio",
            "--os-clipboard",
            "--hid-watchdog",
            "--real-os-input",
        ],
        &["--watchdog-report"],
    ) {
        write_stderr_line(&format!("bridge-stdio: {e}"));
        return ExitCode::from(2);
    }
    let guard = match build_runtime_from_flags(args) {
        Ok(g) => g,
        Err(e) => {
            write_stderr_line(&format!("bridge-stdio init failed: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let rt = Arc::clone(guard.rt());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_ev = Arc::clone(&stop);
    let rt_ev = Arc::clone(&rt);
    let stdout_lock = Arc::new(std::sync::Mutex::new(()));
    let stdout_ev = Arc::clone(&stdout_lock);

    let ev_thread = thread::spawn(move || {
        while !stop_ev.load(Ordering::Acquire) {
            if let Some(ev_json) = rt_ev.poll_event_json_timeout(Duration::from_millis(100)) {
                let _g = stdout_ev.lock().unwrap_or_else(|e| e.into_inner());
                write_stdout_line(&format!("{{\"stream\":\"event\",\"body\":{ev_json}}}"));
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
        write_stdout_line(&format!("{{\"stream\":\"reply\",\"body\":{reply}}}"));
    }

    // Strict ordered shutdown: stop event thread -> join -> drain residual events -> destroy runtime!
    stop.store(true, Ordering::Release);
    let _ = ev_thread.join();
    while let Some(ev_json) = rt.poll_event_json() {
        let _g = stdout_lock.lock().unwrap_or_else(|e| e.into_inner());
        write_stdout_line(&format!("{{\"stream\":\"event\",\"body\":{ev_json}}}"));
    }
    drop(guard);
    ExitCode::SUCCESS
}

fn cmd_host(args: &[String]) -> ExitCode {
    let bool_flags: &[&str] = &[
        "--os-capture",
        "--legacy-capture-fallback",
        "--os-audio",
        "--os-clipboard",
        "--hid-watchdog",
        "--real-os-input",
        #[cfg(feature = "e2e-fault-injection")]
        "--auto-accept",
    ];
    if let Err(e) = validate_flags(args, bool_flags, &["--config", "--watchdog-report"]) {
        write_stderr_line(&format!("host: {e}"));
        return ExitCode::from(2);
    }
    let Some(cfg_path) = flag_value(args, "--config") else {
        write_stderr_line(
            "usage: zerodesk-desktop host --config <path.json> [--os-capture] [--os-audio] [--os-clipboard] [--real-os-input]",
        );
        return ExitCode::from(2);
    };
    install_signal_handlers();
    let guard = match build_runtime_from_flags(args) {
        Ok(g) => g,
        Err(e) => {
            write_stderr_line(&format!("host init failed: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let rt = guard.rt();
    let load_cmd = serde_json::json!({ "v": 1, "cmd": "load_config", "path": cfg_path });
    let load_reply = rt.exec_json(&load_cmd.to_string());
    write_stdout_line(&load_reply);
    let load_val: serde_json::Value = serde_json::from_str(&load_reply).unwrap_or_default();
    if load_val["ok"].as_bool() != Some(true) {
        return ExitCode::FAILURE;
    }

    let start_reply = rt.exec_json(r#"{"v":1,"cmd":"start_host"}"#);
    write_stdout_line(&start_reply);
    let start_val: serde_json::Value = serde_json::from_str(&start_reply).unwrap_or_default();
    if start_val["ok"].as_bool() != Some(true) {
        return ExitCode::FAILURE;
    }

    #[cfg(feature = "e2e-fault-injection")]
    let auto_accept = has_flag(args, "--auto-accept");

    let mut failed = false;
    while !SIGNAL_STOP.load(Ordering::Acquire) {
        if let Some(ev_str) = rt.poll_event_json_timeout(Duration::from_millis(100)) {
            write_stdout_line(&ev_str);
            if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&ev_str) {
                if ev["kind"].as_str() == Some("CommandResult")
                    && ev["payload"]["cmd"].as_str() == Some("start_host")
                    && ev["payload"]["ok"].as_bool() == Some(false)
                {
                    failed = true;
                    break;
                }
                #[cfg(feature = "e2e-fault-injection")]
                if auto_accept && ev["kind"].as_str() == Some("IncomingCall") {
                    if let Some(inc_id) = ev["payload"]["incoming_id"].as_str() {
                        let acc = serde_json::json!({
                            "v": 1,
                            "cmd": "accept_incoming",
                            "incoming_id": inc_id,
                        });
                        write_stdout_line(&rt.exec_json(&acc.to_string()));
                    }
                }
            }
        }
    }
    if SIGNAL_STOP.load(Ordering::Acquire) {
        let _ = rt.exec_json(r#"{"v":1,"cmd":"stop_host"}"#);
    }
    drop(guard);
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn cmd_connect(args: &[String]) -> ExitCode {
    if let Err(e) = validate_flags(
        args,
        &["--os-audio", "--os-clipboard"],
        &["--config", "--target"],
    ) {
        write_stderr_line(&format!("connect: {e}"));
        return ExitCode::from(2);
    }
    let Some(cfg_path) = flag_value(args, "--config") else {
        write_stderr_line(
            "usage: zerodesk-desktop connect --config <path.json> --target <32-hex-device-id>",
        );
        return ExitCode::from(2);
    };
    let Some(target) = flag_value(args, "--target") else {
        write_stderr_line("connect requires --target <32-hex-device-id>");
        return ExitCode::from(2);
    };
    install_signal_handlers();
    let guard = match build_runtime_from_flags(args) {
        Ok(g) => g,
        Err(e) => {
            write_stderr_line(&format!("connect init failed: {e}"));
            return ExitCode::FAILURE;
        }
    };
    let rt = guard.rt();
    let load_cmd = serde_json::json!({ "v": 1, "cmd": "load_config", "path": cfg_path });
    let load_reply = rt.exec_json(&load_cmd.to_string());
    write_stdout_line(&load_reply);
    let load_val: serde_json::Value = serde_json::from_str(&load_reply).unwrap_or_default();
    if load_val["ok"].as_bool() != Some(true) {
        return ExitCode::FAILURE;
    }

    let dial_cmd = serde_json::json!({
        "v": 1,
        "cmd": "dial",
        "target_device_id_hex": target,
    });
    let dial_reply = rt.exec_json(&dial_cmd.to_string());
    write_stdout_line(&dial_reply);
    let dial_val: serde_json::Value = serde_json::from_str(&dial_reply).unwrap_or_default();
    if dial_val["ok"].as_bool() != Some(true) {
        return ExitCode::FAILURE;
    }

    let mut failed = false;
    while !SIGNAL_STOP.load(Ordering::Acquire) {
        if let Some(ev_str) = rt.poll_event_json_timeout(Duration::from_millis(100)) {
            write_stdout_line(&ev_str);
            if let Ok(ev) = serde_json::from_str::<serde_json::Value>(&ev_str) {
                if ev["kind"].as_str() == Some("CommandResult")
                    && ev["payload"]["cmd"].as_str() == Some("dial")
                    && ev["payload"]["ok"].as_bool() == Some(false)
                {
                    failed = true;
                    break;
                }
                if ev["kind"].as_str() == Some("SessionEnded") {
                    break;
                }
            }
        }
    }
    if SIGNAL_STOP.load(Ordering::Acquire) {
        let _ = rt.exec_json(r#"{"v":1,"cmd":"disconnect"}"#);
    }
    drop(guard);
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("os-selftest") => cmd_os_selftest(&args[2..]),
        Some("bridge-stdio") => cmd_bridge_stdio(&args[2..]),
        Some("host") => cmd_host(&args[2..]),
        Some("connect") => cmd_connect(&args[2..]),
        _ => {
            write_stderr_line(
                "usage: zerodesk-desktop <os-selftest|bridge-stdio|host|connect> [args...]",
            );
            ExitCode::from(2)
        }
    }
}
