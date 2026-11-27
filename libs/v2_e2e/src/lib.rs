// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (c) 2026 ZeroDesk Contributors

pub use zerodesk_core::bridge::{
    load_config_json, save_config_json, scan_json_for_secret_canaries, BridgeEvent, BridgeEventHub,
    BridgePersistedConfig, BridgeResponseEnvelope, BridgeSnapshot, BridgeState, PolicySummary,
    RedactedConfigView, RuntimeCommandEnvelope, RuntimeReplyEnvelope, V2BridgeController,
    V2BridgeRuntime, V2BridgeRuntimeOptions, VerifiedCallerDisplay, BRIDGE_ABI_VERSION,
    BRIDGE_EVENT_QUEUE_CAP,
};
pub use zerodesk_core::session::*;
pub use zerodesk_core::{bridge, ffi_abi, frame, os, session};

#[cfg(test)]
#[path = "../../scrap/build_env.rs"]
mod build_env;

#[cfg(test)]
mod scrap_build_env_tests {
    use super::build_env;

    use std::{
        ffi::OsString,
        fs,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[test]
    fn table_driven_zerodesk_link_vmaf_and_link_var_validation() {
        let valid_cases: &[(&str, Option<&str>, Option<bool>)] = &[
            ("ZERODESK_LINK_VMAF", None, None),
            ("ZERODESK_LINK_VMAF", Some(""), None),
            ("ZERODESK_LINK_VMAF", Some("0"), Some(false)),
            ("ZERODESK_LINK_VMAF", Some("1"), Some(true)),
        ];
        for &(name, val, expected) in valid_cases {
            assert_eq!(
                build_env::parse_zerodesk_link_flag(name, val),
                Ok(expected),
                "case ({name}, {val:?}) should succeed"
            );
        }

        let invalid_cases: &[(&str, &str)] = &[
            ("ZERODESK_LINK_VMAF", "true"),
            ("ZERODESK_LINK_VMAF", "false"),
            ("ZERODESK_LINK_VMAF", "yes"),
            ("ZERODESK_LINK_VMAF", "2"),
            ("ZERODESK_LINK_VMAF", "auto"),
            ("ZERODESK_LINK_VMAF", " 1"),
            ("ZERODESK_LINK_VMAF", "1 "),
            ("ZERODESK_LINK_TYPO", "1"),
            ("ZERODESK_LINK_VAMF", "0"),
            ("ZERODESK_LINK_FOO", ""),
        ];
        for &(name, val) in invalid_cases {
            let err = build_env::parse_zerodesk_link_flag(name, Some(val)).unwrap_err();
            assert!(
                err.contains(name),
                "expected clear diagnostic naming '{name}', got: {err}"
            );
            assert!(build_env::validate_all_zerodesk_link_vars_os([(
                OsString::from(name),
                OsString::from(val),
            )])
            .is_err());
        }

        // Valid known env vars plus unrelated env vars pass cleanly.
        let matched = build_env::validate_all_zerodesk_link_vars_os([
            (OsString::from("PATH"), OsString::from("/usr/bin")),
            (OsString::from("ZERODESK_LINK_VMAF"), OsString::from("1")),
        ])
        .unwrap();
        assert_eq!(matched, vec!["ZERODESK_LINK_VMAF".to_string()]);

        // Non-UTF-8 unrelated env vars are ignored without panicking; non-UTF-8 ZERODESK_LINK_* fails closed.
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStringExt;
            let non_utf8 = OsString::from_vec(vec![0xFF, 0xFE]);
            assert!(build_env::validate_all_zerodesk_link_vars_os([(
                OsString::from("UNRELATED_BIN_VAR"),
                non_utf8.clone(),
            )])
            .is_ok());
            assert!(build_env::validate_all_zerodesk_link_vars_os([(
                OsString::from("ZERODESK_LINK_VMAF"),
                non_utf8,
            )])
            .is_err());
        }
    }

    #[test]
    fn table_driven_libyuv_prefix_validation_and_homebrew_hint() {
        let uniq = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("zd-libyuv-test-{}-{uniq}", std::process::id()));
        let missing_all = root.join("missing_all");
        let missing_header = root.join("missing_header");
        let missing_lib = root.join("missing_lib");
        let complete = root.join("complete");

        fs::create_dir_all(missing_header.join("lib")).unwrap();
        fs::write(missing_header.join("lib/libyuv.a"), b"stub").unwrap();

        fs::create_dir_all(missing_lib.join("include")).unwrap();
        fs::write(missing_lib.join("include/libyuv.h"), b"// stub").unwrap();

        fs::create_dir_all(complete.join("lib")).unwrap();
        fs::create_dir_all(complete.join("include")).unwrap();
        fs::write(complete.join("lib/libyuv.a"), b"stub").unwrap();
        fs::write(complete.join("include/libyuv.h"), b"// stub").unwrap();

        for bad in [&missing_all, &missing_header, &missing_lib] {
            let err = build_env::validate_libyuv_prefix(bad).unwrap_err();
            assert!(err.contains("ZERODESK_LIBYUV_PREFIX"));
        }
        let (lib_dir, inc_dir) = build_env::validate_libyuv_prefix(&complete).unwrap();
        assert_eq!(lib_dir, complete.join("lib"));
        assert_eq!(inc_dir, complete.join("include"));

        let hint_missing =
            build_env::homebrew_missing_message("libyuv", Path::new("/opt/homebrew/Cellar/libyuv"), false);
        assert!(hint_missing.contains("ZERODESK_LIBYUV_PREFIX"));
        let hint_empty =
            build_env::homebrew_missing_message("libyuv", Path::new("/opt/homebrew/Cellar/libyuv"), true);
        assert!(hint_empty.contains("ZERODESK_LIBYUV_PREFIX"));
        let other_msg =
            build_env::homebrew_missing_message("libvpx", Path::new("/opt/homebrew/Cellar/libvpx"), false);
        assert!(!other_msg.contains("ZERODESK_LIBYUV_PREFIX"));

        let _ = fs::remove_dir_all(&root);
    }
}
