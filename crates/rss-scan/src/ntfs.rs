//! Pure NTFS/Windows decision logic for the MFT fast path (SPEC.md §5.4,
//! FR-2.4/FR-2.5), separated from the cfg(windows) FFI so it can be
//! unit-tested on any host.

use rss_core::NodeFlags;

use crate::{EngineChoice, EnginePlan};

// Win32 file attribute bits (winnt.h), mirrored here so the mapping is
// testable without the windows-sys dependency.
const FILE_ATTRIBUTE_READONLY: u32 = 0x1;
const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x20;
const FILE_ATTRIBUTE_TEMPORARY: u32 = 0x100;
const FILE_ATTRIBUTE_SPARSE_FILE: u32 = 0x200;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;
const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;
const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
const FILE_ATTRIBUTE_NOT_CONTENT_INDEXED: u32 = 0x2000;
const FILE_ATTRIBUTE_ENCRYPTED: u32 = 0x4000;

/// Whether a Win32 attribute set describes a directory.
pub fn is_directory(file_attributes: u32) -> bool {
    file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
}

/// Whether a Win32 attribute set describes a reparse point (symlink,
/// junction, mount point, cloud placeholder).
pub fn is_reparse_point(file_attributes: u32) -> bool {
    file_attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

/// Map Win32 file attributes to `rss_core::NodeFlags` (SPEC.md §5.2
/// "Attributes").
pub fn node_flags_from_file_attributes(attrs: u32) -> NodeFlags {
    let mut flags = NodeFlags::default();
    let mut set = |bit: u32, flag: NodeFlags| {
        if attrs & bit != 0 {
            flags.insert(flag);
        }
    };
    set(FILE_ATTRIBUTE_ARCHIVE, NodeFlags::ARCHIVE);
    set(FILE_ATTRIBUTE_SYSTEM, NodeFlags::SYSTEM);
    set(FILE_ATTRIBUTE_READONLY, NodeFlags::READONLY);
    set(FILE_ATTRIBUTE_HIDDEN, NodeFlags::HIDDEN);
    set(FILE_ATTRIBUTE_COMPRESSED, NodeFlags::COMPRESSED);
    set(FILE_ATTRIBUTE_ENCRYPTED, NodeFlags::ENCRYPTED);
    set(FILE_ATTRIBUTE_OFFLINE, NodeFlags::OFFLINE);
    set(FILE_ATTRIBUTE_TEMPORARY, NodeFlags::TEMPORARY);
    set(FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, NodeFlags::NOT_INDEXED);
    set(FILE_ATTRIBUTE_SPARSE_FILE, NodeFlags::SPARSE);
    set(FILE_ATTRIBUTE_REPARSE_POINT, NodeFlags::REPARSE_POINT);
    flags
}

/// What kind of path a scan root is, for engine selection.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PathClass {
    /// A local drive-letter path (`C:\...`, `\\?\C:\...`); payload is the
    /// uppercased ASCII drive letter.
    Drive(u8),
    /// A UNC/network path (`\\server\share`, `\\?\UNC\...`) — walker only.
    Unc,
    /// Anything else (relative paths, device paths, empty) — walker only.
    Unsupported,
}

/// Classify a Windows path *by string shape* (no filesystem access), so the
/// logic is testable on any host. Both `/` and `\` separators are accepted.
pub fn classify_path(path: &str) -> PathClass {
    let is_sep = |b: u8| b == b'\\' || b == b'/';
    let bytes = path.as_bytes();

    // Verbatim prefixes: \\?\C:\... (drive) and \\?\UNC\server\share (UNC).
    if bytes.len() >= 4 && &bytes[..4] == b"\\\\?\\" {
        let rest = &path[4..];
        if rest.len() >= 4 && rest[..4].eq_ignore_ascii_case("UNC\\") {
            return PathClass::Unc;
        }
        return classify_drive(rest.as_bytes());
    }
    // Device paths (\\.\X:) are volume handles, not scan roots.
    if bytes.len() >= 4 && &bytes[..4] == b"\\\\.\\" {
        return PathClass::Unsupported;
    }
    // UNC: \\server\share or //server/share.
    if bytes.len() >= 2 && is_sep(bytes[0]) && is_sep(bytes[1]) {
        return PathClass::Unc;
    }
    classify_drive(bytes)
}

fn classify_drive(bytes: &[u8]) -> PathClass {
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        PathClass::Drive(bytes[0].to_ascii_uppercase())
    } else {
        PathClass::Unsupported
    }
}

/// For a [`PathClass::Drive`] path, return the path suffix after the drive
/// prefix with separators normalized to `\` and trailing separators trimmed
/// (e.g. `C:/Users/foo/` → `Users\foo`; `C:\` → empty string).
pub fn drive_suffix(path: &str) -> Option<String> {
    let after_prefix = match classify_path(path) {
        PathClass::Drive(_) => {
            let p = if path.len() >= 4 && &path.as_bytes()[..4] == b"\\\\?\\" {
                &path[4..]
            } else {
                path
            };
            &p[2..] // skip "X:"
        }
        _ => return None,
    };
    let trimmed = after_prefix.trim_matches(['\\', '/']);
    Some(trimmed.replace('/', "\\"))
}

/// Engine fallback decision (SPEC.md §5.4 table, FR-2.4/FR-2.5), given the
/// probed facts. Pure function: the cfg(windows) probes live in `crate::mft`.
pub fn decide_engine(class: PathClass, fs_name: Option<&str>, volume_openable: bool) -> EnginePlan {
    match (class, fs_name) {
        (PathClass::Drive(_), Some(fs)) if fs.eq_ignore_ascii_case("NTFS") => {
            if volume_openable {
                // NTFS + elevated → MFT fast path (FR-2.4).
                EnginePlan {
                    choice: EngineChoice::Mft,
                    mft_requires_elevation: false,
                }
            } else {
                // NTFS but the volume handle would not open → walk now,
                // offer "rescan as administrator" (FR-2.5).
                EnginePlan {
                    choice: EngineChoice::Walk,
                    mft_requires_elevation: true,
                }
            }
        }
        // FAT32/exFAT/ReFS/network/unknown → walker (ReFS has no MFT, §7.7).
        _ => EnginePlan {
            choice: EngineChoice::Walk,
            mft_requires_elevation: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_all_attribute_bits() {
        let flags = node_flags_from_file_attributes(
            FILE_ATTRIBUTE_READONLY
                | FILE_ATTRIBUTE_HIDDEN
                | FILE_ATTRIBUTE_SYSTEM
                | FILE_ATTRIBUTE_ARCHIVE
                | FILE_ATTRIBUTE_TEMPORARY
                | FILE_ATTRIBUTE_SPARSE_FILE
                | FILE_ATTRIBUTE_REPARSE_POINT
                | FILE_ATTRIBUTE_COMPRESSED
                | FILE_ATTRIBUTE_OFFLINE
                | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED
                | FILE_ATTRIBUTE_ENCRYPTED,
        );
        for f in [
            NodeFlags::READONLY,
            NodeFlags::HIDDEN,
            NodeFlags::SYSTEM,
            NodeFlags::ARCHIVE,
            NodeFlags::TEMPORARY,
            NodeFlags::SPARSE,
            NodeFlags::REPARSE_POINT,
            NodeFlags::COMPRESSED,
            NodeFlags::OFFLINE,
            NodeFlags::NOT_INDEXED,
            NodeFlags::ENCRYPTED,
        ] {
            assert!(flags.contains(f), "missing {f:?}");
        }
        assert!(is_directory(FILE_ATTRIBUTE_DIRECTORY));
        assert!(!is_directory(FILE_ATTRIBUTE_ARCHIVE));
        assert!(is_reparse_point(
            FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY
        ));
    }

    #[test]
    fn empty_attributes_map_to_no_flags() {
        let flags = node_flags_from_file_attributes(0);
        assert_eq!(flags, NodeFlags::default());
    }

    #[test]
    fn classifies_paths() {
        assert_eq!(classify_path(r"C:\"), PathClass::Drive(b'C'));
        assert_eq!(classify_path(r"c:\Users\me"), PathClass::Drive(b'C'));
        assert_eq!(classify_path("D:/data"), PathClass::Drive(b'D'));
        assert_eq!(classify_path(r"\\?\E:\long\path"), PathClass::Drive(b'E'));
        assert_eq!(classify_path(r"\\server\share"), PathClass::Unc);
        assert_eq!(classify_path("//server/share"), PathClass::Unc);
        assert_eq!(classify_path(r"\\?\UNC\server\share"), PathClass::Unc);
        assert_eq!(classify_path(r"\\.\C:"), PathClass::Unsupported);
        assert_eq!(classify_path("relative/path"), PathClass::Unsupported);
        assert_eq!(classify_path(""), PathClass::Unsupported);
    }

    #[test]
    fn extracts_drive_suffix() {
        assert_eq!(drive_suffix(r"C:\Users\me").as_deref(), Some(r"Users\me"));
        assert_eq!(drive_suffix("C:/Users/me/").as_deref(), Some(r"Users\me"));
        assert_eq!(drive_suffix(r"C:\").as_deref(), Some(""));
        assert_eq!(drive_suffix("C:").as_deref(), Some(""));
        assert_eq!(drive_suffix(r"\\?\D:\x").as_deref(), Some("x"));
        assert_eq!(drive_suffix(r"\\server\share"), None);
    }

    #[test]
    fn decides_engine_per_fallback_chain() {
        // NTFS + elevated → MFT.
        let plan = decide_engine(PathClass::Drive(b'C'), Some("NTFS"), true);
        assert_eq!(plan.choice, EngineChoice::Mft);
        assert!(!plan.mft_requires_elevation);
        // NTFS, not elevated → Walk + rescan-as-admin signal (FR-2.5).
        let plan = decide_engine(PathClass::Drive(b'C'), Some("NTFS"), false);
        assert_eq!(plan.choice, EngineChoice::Walk);
        assert!(plan.mft_requires_elevation);
        // Non-NTFS volumes → Walk, no signal (MFT does not exist there, §7.7).
        for fs in ["FAT32", "exFAT", "ReFS"] {
            let plan = decide_engine(PathClass::Drive(b'D'), Some(fs), true);
            assert_eq!(plan.choice, EngineChoice::Walk, "{fs}");
            assert!(!plan.mft_requires_elevation, "{fs}");
        }
        // UNC and unsupported paths → Walk.
        for class in [PathClass::Unc, PathClass::Unsupported] {
            let plan = decide_engine(class, None, false);
            assert_eq!(plan.choice, EngineChoice::Walk);
            assert!(!plan.mft_requires_elevation);
        }
        // Unknown filesystem (probe failed) → Walk.
        let plan = decide_engine(PathClass::Drive(b'C'), None, false);
        assert_eq!(plan.choice, EngineChoice::Walk);
    }
}
