//! Watcher backend selection (SPEC.md §5.4 fallback chain, FR-7.2/FR-7.3/
//! FR-7.7).
//!
//! Mirrors `rss_scan::select_engine`:
//!
//! | Condition                       | Watcher                        |
//! |---------------------------------|--------------------------------|
//! | NTFS + elevated                 | `UsnJournalWatcher`            |
//! | anything else local             | `RdcwWatcher`                  |
//! | network / UNC                   | unavailable (FR-7.7)           |
//!
//! On non-Windows hosts the only backend is [`RdcwWatcher`] (notify's
//! native platform watcher).

use std::path::Path;
#[cfg(windows)]
use std::path::PathBuf;

use crate::{RdcwWatcher, WatchError, Watcher};

/// Which backend [`select_watcher`] will use for a root path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WatcherChoice {
    /// NTFS USN change journal (elevated NTFS volumes only).
    UsnJournal,
    /// `notify`-based recursive directory watcher.
    Rdcw,
    /// Live updates unavailable — network/UNC path (FR-7.7). The app shows
    /// the "live updates unavailable — press F5 to rescan" affordance.
    Unavailable,
}

/// Classify `root` without constructing a watcher; useful for the settings
/// UI (FR-7.6) and for tests of the selection logic itself.
pub fn classify(root: &Path) -> WatcherChoice {
    classify_impl(root)
}

/// Construct the watcher for `root` per the SPEC.md §5.4 fallback chain.
///
/// Returns [`WatchError::NetworkUnsupported`] for network/UNC roots
/// (FR-7.7); all other errors are deferred to [`Watcher::start`].
pub fn select_watcher(root: &Path) -> Result<Box<dyn Watcher>, WatchError> {
    match classify(root) {
        WatcherChoice::Unavailable => Err(WatchError::NetworkUnsupported(root.to_path_buf())),
        #[cfg(windows)]
        WatcherChoice::UsnJournal => Ok(Box::new(crate::UsnJournalWatcher::new(root))),
        _ => Ok(Box::new(RdcwWatcher::new(root))),
    }
}

#[cfg(not(windows))]
fn classify_impl(_root: &Path) -> WatcherChoice {
    // UNC paths do not exist off Windows; notify's native backend
    // (inotify/FSEvents/kqueue) is always the right choice here.
    WatcherChoice::Rdcw
}

#[cfg(windows)]
fn classify_impl(root: &Path) -> WatcherChoice {
    if is_unc_path(root) {
        return WatcherChoice::Unavailable;
    }
    let Some(volume_root) = volume_root(root) else {
        return WatcherChoice::Rdcw;
    };
    if !is_ntfs_volume(&volume_root) {
        return WatcherChoice::Rdcw;
    }
    // Elevation probe: opening the volume for direct access requires admin
    // (SPEC.md §5.4 "attempt-open of \\.\X:").
    match crate::usn::open_volume(&volume_root) {
        Ok(_) => WatcherChoice::UsnJournal,
        Err(_) => WatcherChoice::Rdcw,
    }
}

#[cfg(windows)]
fn is_unc_path(path: &Path) -> bool {
    let s = path.as_os_str().to_string_lossy();
    // `\\?\C:\…` verbatim drive paths are local; `\\?\UNC\…` and plain
    // `\\server\share` are network (FR-7.7).
    let upper = s.to_uppercase();
    upper.starts_with("\\\\?\\UNC\\") || (s.starts_with("\\\\") && !upper.starts_with("\\\\?\\"))
}

/// Resolve the volume mount root ("C:\") for an arbitrary path.
#[cfg(windows)]
fn volume_root(path: &Path) -> Option<PathBuf> {
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use windows_sys::Win32::Storage::FileSystem::GetVolumePathNameW;

    let wide: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut buf = vec![0u16; 1024];
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string; `buf` is a
    // valid writable buffer of `buf.len()` UTF-16 code units.
    let ok = unsafe { GetVolumePathNameW(wide.as_ptr(), buf.as_mut_ptr(), buf.len() as u32) };
    if ok == 0 {
        return None;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    Some(PathBuf::from(std::ffi::OsString::from_wide(&buf[..len])))
}

/// Whether the volume's filesystem is NTFS (`lpFileSystemNameBuffer`,
/// SPEC.md §5.4).
#[cfg(windows)]
fn is_ntfs_volume(volume_root: &Path) -> bool {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetVolumeInformationW;

    let wide: Vec<u16> = volume_root
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();
    let mut fs_name = vec![0u16; 64];
    // SAFETY: both buffers are valid NUL-terminated/writable UTF-16
    // buffers of the stated sizes; the numeric out-params are null
    // (documented as optional).
    let ok = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if ok == 0 {
        return false;
    }
    let len = fs_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fs_name.len());
    String::from_utf16_lossy(&fs_name[..len]).eq_ignore_ascii_case("NTFS")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn local_paths_use_rdcw_off_windows() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(classify(dir.path()), WatcherChoice::Rdcw);
    }

    /// On Windows the choice depends on elevation + filesystem: elevated NTFS
    /// gets the USN journal (the correct answer per SPEC §5.5), everything
    /// else gets RDCW. Both are valid; only Unavailable would be wrong.
    #[cfg(windows)]
    #[test]
    fn local_paths_use_rdcw_or_usn_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        assert_ne!(classify(dir.path()), WatcherChoice::Unavailable);
    }

    #[cfg(not(windows))]
    #[test]
    fn select_returns_a_working_rdcw_for_local_paths() {
        let dir = tempfile::tempdir().unwrap();
        let watcher = select_watcher(dir.path()).unwrap();
        assert_eq!(watcher.kind(), crate::WatcherKind::Rdcw);
        assert_eq!(watcher.root(), dir.path());
    }

    #[cfg(windows)]
    #[test]
    fn select_returns_a_watcher_for_local_paths_on_windows() {
        let dir = tempfile::tempdir().unwrap();
        let watcher = select_watcher(dir.path()).unwrap();
        assert!(matches!(
            watcher.kind(),
            crate::WatcherKind::Rdcw | crate::WatcherKind::UsnJournal
        ));
        assert_eq!(watcher.root(), dir.path());
    }

    #[cfg(windows)]
    #[test]
    fn unc_paths_are_unavailable() {
        assert_eq!(
            classify(Path::new(r"\\server\share")),
            WatcherChoice::Unavailable
        );
        assert_eq!(
            classify(Path::new(r"\\?\UNC\server\share")),
            WatcherChoice::Unavailable
        );
        assert!(matches!(
            select_watcher(Path::new(r"\\server\share")),
            Err(WatchError::NetworkUnsupported(_))
        ));
    }
}
