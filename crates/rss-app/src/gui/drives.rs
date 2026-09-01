//! Drive enumeration for the start dialog (FR-1.1).
//!
//! Kept free of `unsafe`/FFI per SPEC.md §5.9: on Windows we probe the 26
//! drive-letter roots with `Path::exists` (cheap, and honest about mapped /
//! substituted drives); other platforms expose no drive concept and return
//! an empty list — the path field is the entry point there.

use std::path::PathBuf;

/// Roots of locally available drives (Windows: `C:\`, `D:\`, …). Empty on
/// non-Windows platforms, where the start dialog shows the path field only.
pub fn list_drives() -> Vec<PathBuf> {
    list_drives_impl()
}

#[cfg(windows)]
fn list_drives_impl() -> Vec<PathBuf> {
    (b'A'..=b'Z')
        .map(|letter| PathBuf::from(format!("{}:\\", letter as char)))
        .filter(|root| root.exists())
        .collect()
}

#[cfg(not(windows))]
fn list_drives_impl() -> Vec<PathBuf> {
    Vec::new()
}
