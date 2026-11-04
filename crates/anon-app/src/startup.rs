//! Startup failure reporting.
//!
//! # Why this exists
//!
//! A GUI launch has no terminal. When the app fails before its window opens — an
//! unavailable keychain, an unreadable data directory, a malformed config — the only
//! evidence is a line on stderr that nobody sees. That is the "it never launched" report:
//! the process exited and left nothing behind to explain why.
//!
//! This module appends that failure to a log file beside the app's data and prints the
//! path, so a user who does have a terminal is told where to look.
//!
//! # Why a file rather than a dialog
//!
//! A dialog needs a window, and these failures happen before one exists. A file works in
//! every case, including the AppImage case where a file manager starts the process with no
//! console at all.

use std::io::Write;
use std::path::{Path, PathBuf};

/// The log file's name, inside the app data directory.
const LOG_NAME: &str = "startup.log";

/// The bundle identifier, matching `tauri.conf.json`.
///
/// Duplicated here because this module runs before Tauri can resolve paths, and a log
/// written to the wrong directory is a log nobody finds.
const IDENTIFIER: &str = "com.jaredch.tornel";

/// Record a startup failure, returning the path it was written to.
///
/// Never fails the caller: a diagnostic that can itself abort startup would be worse than
/// the silence it replaces.
pub fn record_failure(error: &dyn std::fmt::Display) -> Option<PathBuf> {
    let path = log_path()?;
    record_failure_to(&path, error);
    Some(path)
}

/// Append one failure line to `path`, creating the file and its directory.
///
/// Split from [`record_failure`] so the write can be tested without depending on the
/// ambient environment.
pub fn record_failure_to(path: &Path, error: &dyn std::fmt::Display) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    else {
        return;
    };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);
    let _ = writeln!(file, "[{timestamp}] startup failed: {error}");
}

/// Where the log lives, mirroring Tauri's `app_data_dir` resolution.
fn log_path() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("ANON_DATA_DIR") {
        let dir = PathBuf::from(dir);
        if !dir.as_os_str().is_empty() {
            return Some(dir.join(LOG_NAME));
        }
    }
    data_dir().map(|dir| dir.join(LOG_NAME))
}

#[cfg(target_os = "windows")]
fn data_dir() -> Option<PathBuf> {
    std::env::var_os("APPDATA").map(|base| PathBuf::from(base).join(IDENTIFIER))
}

#[cfg(target_os = "macos")]
fn data_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| {
        PathBuf::from(home)
            .join("Library/Application Support")
            .join(IDENTIFIER)
    })
}

#[cfg(all(unix, not(target_os = "macos")))]
fn data_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share")))
        .map(|base| base.join(IDENTIFIER))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_failure_is_appended_not_overwritten() {
        let dir = std::env::temp_dir().join(format!(
            "anon-startup-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = dir.join("startup.log");

        record_failure_to(&path, &"first failure");
        record_failure_to(&path, &"second failure");

        let contents = std::fs::read_to_string(&path).unwrap();
        assert!(
            contents.contains("first failure"),
            "the first line survives"
        );
        assert!(
            contents.contains("second failure"),
            "the second line is added"
        );
        assert_eq!(contents.lines().count(), 2, "one line per failure");

        std::fs::remove_dir_all(dir).unwrap();
    }
}
