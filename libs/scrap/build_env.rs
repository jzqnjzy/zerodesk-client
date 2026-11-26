use std::path::{Path, PathBuf};

pub fn parse_zerodesk_link_flag(name: &str, value: Option<&str>) -> Result<Option<bool>, String> {
    match value {
        None | Some("") => Ok(None),
        Some("0") => Ok(Some(false)),
        Some("1") => Ok(Some(true)),
        Some(other) => Err(format!(
            "Invalid {name}='{other}': expected unset/empty, \"0\", or \"1\" (no silent fallback)"
        )),
    }
}

pub fn validate_all_zerodesk_link_vars<'a, I>(vars: I) -> Result<(), String>
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    for (key, value) in vars {
        if key.starts_with("ZERODESK_LINK_") {
            let _ = parse_zerodesk_link_flag(key, Some(value))?;
        }
    }
    Ok(())
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
