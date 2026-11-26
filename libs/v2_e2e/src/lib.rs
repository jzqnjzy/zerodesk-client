#[path = "../../../src/v2_session/mod.rs"]
pub mod v2_session;

pub use v2_session::*;

#[cfg(test)]
#[path = "../../scrap/build_env.rs"]
mod build_env;

#[cfg(test)]
mod scrap_build_env_tests {
    use super::build_env;

    use std::{
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
            ("ZERODESK_LINK_CUSTOM", Some("0"), Some(false)),
            ("ZERODESK_LINK_CUSTOM", Some("1"), Some(true)),
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
            ("ZERODESK_LINK_FOO", "on"),
        ];
        for &(name, val) in invalid_cases {
            let err = build_env::parse_zerodesk_link_flag(name, Some(val)).unwrap_err();
            assert!(
                err.contains(name) && err.contains(val),
                "expected clear diagnostic for ({name}, {val}), got: {err}"
            );
            assert!(build_env::validate_all_zerodesk_link_vars([(name, val)]).is_err());
        }

        assert!(build_env::validate_all_zerodesk_link_vars([
            ("PATH", "/usr/bin"),
            ("ZERODESK_LINK_VMAF", "1"),
            ("ZERODESK_LINK_OTHER", ""),
        ])
        .is_ok());
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
