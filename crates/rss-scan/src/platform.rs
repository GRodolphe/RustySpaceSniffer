//! Platform-specific metadata extraction (SPEC.md §5.2, §5.4).
//!
//! The `cfg(windows)` branch is written against dua-core's native Windows
//! enumeration metadata plus `windows-sys`, but it is **not compile-tested on
//! this Linux host** — it must be validated by the first Windows CI run.
//! macOS is not covered (dua-core uses its own metadata type there); it is
//! out of scope for v1 (SPEC.md §N2).

use std::path::Path;

use rss_core::{filetime_from_unix, FileTime};

/// Platform-neutral metadata needed to build an `rss_core::NodeParams`.
pub(crate) struct MetaValues {
    /// Logical size (file length).
    pub logical: u64,
    /// Allocated size on disk, best-effort.
    pub allocated: u64,
    /// Hardlink identity `(device, inode)` / `(volume serial, file index)`,
    /// `Some` only when the entry is a file that may have multiple links
    /// (SPEC.md §5.2 dedup domain).
    pub hardlink_key: Option<(u64, u64)>,
    /// Creation time as Windows FILETIME.
    pub created: FileTime,
    /// Last access time as Windows FILETIME.
    pub accessed: FileTime,
    /// Last modification time as Windows FILETIME.
    pub modified: FileTime,
}

/// Convert a `SystemTime` result into a FILETIME, saturating to the Unix
/// epoch on error or pre-epoch times.
pub(crate) fn system_time_to_filetime(t: std::io::Result<std::time::SystemTime>) -> FileTime {
    let secs = match t {
        Ok(t) => match t.duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(e) => -i64::try_from(e.duration().as_secs()).unwrap_or(i64::MAX),
        },
        Err(_) => 0,
    };
    filetime_from_unix(secs)
}

#[cfg(unix)]
pub(crate) fn meta_values(_path: &Path, md: &std::fs::Metadata, is_file: bool) -> MetaValues {
    use std::os::unix::fs::MetadataExt;
    MetaValues {
        logical: md.len(),
        // True on-disk allocation (512-byte units, accounts for sparse
        // files) — the Unix equivalent of FileStandardInfo.AllocationSize.
        allocated: md.blocks().saturating_mul(512),
        // Only multi-link regular files enter the dedup set: every directory
        // has nlink > 1 on Unix, and single-link files can never collide.
        hardlink_key: (is_file && md.nlink() > 1).then(|| (md.dev(), md.ino())),
        // st_ctime is *change* time, not creation; `created()` yields btime
        // where the filesystem supports it and an error otherwise.
        created: system_time_to_filetime(md.created()),
        accessed: filetime_from_unix(md.atime()),
        modified: filetime_from_unix(md.mtime()),
    }
}

#[cfg(windows)]
pub(crate) fn meta_values(path: &Path, md: &dua_core::Metadata, is_file: bool) -> MetaValues {
    let logical = md.len();
    // dua-core's native enumeration already reads
    // FileStandardInfo.AllocationSize (correct for NTFS compression and
    // sparse ranges, §7.5); GetCompressedFileSizeW is the documented
    // fallback (§5.4) for entries that report no allocation.
    let allocated = match md.allocated_size() {
        0 if is_file && logical > 0 => compressed_file_size(path).unwrap_or(logical),
        allocated => allocated,
    };
    let modified = system_time_to_filetime(md.modified());
    MetaValues {
        logical,
        allocated,
        hardlink_key: if is_file { md.hard_link_id() } else { None },
        // TODO: dua-core's enumeration metadata exposes only mtime; fetch
        // created/accessed via GetFileInformationByHandleEx when the Windows
        // port is brought up (this branch cannot be compile-tested on Linux).
        created: modified,
        accessed: modified,
        modified,
    }
}

/// `GetCompressedFileSizeW` fallback for allocated size (SPEC.md §5.4).
///
/// Returns the on-disk size of a (possibly compressed/sparse) file, or
/// `None` on error.
#[cfg(windows)]
pub(crate) fn compressed_file_size(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::GetLastError;
    use windows_sys::Win32::Storage::FileSystem::GetCompressedFileSizeW;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut high: u32 = 0;
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string that outlives
    // the call, and `high` points to a valid writable u32 out-parameter.
    let low = unsafe { GetCompressedFileSizeW(wide.as_ptr(), &mut high) };
    if low == u32::MAX {
        // INVALID_FILE_SIZE is only an error when the last-error code is set.
        // SAFETY: thread-local last-error query, always safe to call.
        let err = unsafe { GetLastError() };
        if err != 0 {
            return None;
        }
    }
    Some((u64::from(high) << 32) | u64::from(low))
}
