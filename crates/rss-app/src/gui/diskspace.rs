//! Volume free/total space and drive-root detection (FR-3.13, FR-1.8).
//!
//! Uses `fs2` (safe wrappers over statvfs / GetDiskFreeSpaceExW) so rss-app
//! stays free of `unsafe` (SPEC.md §5.9).

use std::path::Path;

/// Total and available bytes of the volume holding a path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DiskSpace {
    pub total: u64,
    /// Available to the current user (statvfs `f_bavail` /
    /// `lpFreeBytesAvailableToCaller`).
    pub free: u64,
}

/// Query the volume holding `path`. `None` when the OS call fails (e.g. the
/// path vanished mid-scan).
pub fn disk_space(path: &Path) -> Option<DiskSpace> {
    let total = fs2::total_space(path).ok()?;
    let free = fs2::available_space(path).ok()?;
    (total > 0).then_some(DiskSpace { total, free })
}

/// Whether `path` is a volume/drive root — the only views that show the
/// FR-3.13 free-space and unknown-space elements.
pub fn is_volume_root(path: &Path) -> bool {
    is_volume_root_impl(path)
}

#[cfg(windows)]
fn is_volume_root_impl(path: &Path) -> bool {
    use std::path::Component;
    let mut components = path.components();
    matches!(components.next(), Some(Component::Prefix(_)))
        && matches!(components.next(), Some(Component::RootDir))
        && components.next().is_none()
}

#[cfg(not(windows))]
fn is_volume_root_impl(path: &Path) -> bool {
    path == Path::new("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_space_of_tmp() {
        let space = disk_space(std::path::Path::new("/tmp")).expect("/tmp has a volume");
        assert!(space.total > 0);
        assert!(space.free <= space.total);
    }

    #[cfg(not(windows))]
    #[test]
    fn volume_root_detection_unix() {
        assert!(is_volume_root(Path::new("/")));
        assert!(!is_volume_root(Path::new("/tmp")));
        assert!(!is_volume_root(Path::new("/home/user")));
    }
}
