use std::{
    ffi::{OsStr, OsString},
    path::{Path, PathBuf},
};

pub const KNOWN_ZERODESK_LINK_VARS: &[&str] = &["ZERODESK_LINK_VMAF"];

pub fn parse_zerodesk_link_flag(name: &str, value: Option<&str>) -> Result<Option<bool>, String> {
    if !KNOWN_ZERODESK_LINK_VARS.contains(&name) {
        return Err(format!(
            "Unknown ZERODESK_LINK_* environment variable '{name}': expected one of {:?}",
            KNOWN_ZERODESK_LINK_VARS
        ));
    }
    match value {
        None | Some("") => Ok(None),
        Some("0") => Ok(Some(false)),
        Some("1") => Ok(Some(true)),
        Some(other) => Err(format!(
            "Invalid {name}='{other}': expected unset/empty, \"0\", or \"1\" (no silent fallback)"
        )),
    }
}

fn is_zerodesk_link_os_key(key: &OsStr) -> bool {
    key.to_string_lossy().starts_with("ZERODESK_LINK_")
}

pub fn validate_all_zerodesk_link_vars_os<I>(vars: I) -> Result<Vec<String>, String>
where
    I: IntoIterator<Item = (OsString, OsString)>,
{
    let mut matched_keys = Vec::new();
    for (raw_key, raw_val) in vars {
        if !is_zerodesk_link_os_key(&raw_key) {
            continue;
        }
        let key = raw_key.to_str().ok_or_else(|| {
            format!(
                "Invalid non-UTF-8 ZERODESK_LINK_* environment variable name '{}'",
                raw_key.to_string_lossy()
            )
        })?;
        let val = raw_val.to_str().ok_or_else(|| {
            format!(
                "Invalid non-UTF-8 value for {key}: expected unset/empty, \"0\", or \"1\""
            )
        })?;
        let _ = parse_zerodesk_link_flag(key, Some(val))?;
        matched_keys.push(key.to_string());
    }
    Ok(matched_keys)
}

pub fn validate_libyuv_prefix(prefix: &Path) -> Result<(PathBuf, PathBuf), String> {
    let lib_dir = prefix.join("lib");
    let lib_archive = lib_dir.join("libyuv.a");
    let include_dir = prefix.join("include");
    let header = include_dir.join("libyuv.h");
    if !lib_archive.is_file() || !header.is_file() {
        return Err(format!(
            "ZERODESK_LIBYUV_PREFIX='{}' is invalid: expected both '{}' and '{}' to exist",
            prefix.display(),
            lib_archive.display(),
            header.display()
        ));
    }
    Ok((lib_dir, include_dir))
}

pub fn homebrew_missing_message(name: &str, path: &Path, empty_versions: bool) -> String {
    let hint = if name == "libyuv" {
        " You can also set ZERODESK_LIBYUV_PREFIX to a directory containing lib/libyuv.a and include/libyuv.h."
    } else {
        ""
    };
    if empty_versions {
        format!(
            "There's no installed version of {name} in /opt/homebrew/Cellar.{hint}"
        )
    } else {
        format!(
            "Could not find package in {}. Make sure your homebrew and package {name} are all installed.{hint}",
            path.display()
        )
    }
}
