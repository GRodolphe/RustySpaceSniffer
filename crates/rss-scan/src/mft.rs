//! `MftScanner`: the Stage A NTFS Master File Table fast path (SPEC.md §5.4,
//! FR-2.4). Windows only.
//!
//! **Status: compile-checked only.** Developed on Linux against
//! `x86_64-pc-windows-msvc` (`cargo check`/`cargo clippy`); it has never run.
//! The pure logic it relies on — USN record parsing (`crate::usn`), attribute
//! mapping and the engine fallback decision (`crate::ntfs`) — is unit-tested
//! on Linux. Runtime validation is the privilege-gated integration test in
//! `tests/mft.rs` (`#[ignore]`d by default; enable with `RSS_RUN_MFT_TESTS=1`
//! on an elevated Windows runner).
//!
//! Design (SPEC.md §5.4, Stage A):
//! 1. Open `\\.\X:` with `CreateFileW` (requires elevation — that is also the
//!    elevation probe used by the engine fallback chain).
//! 2. Enumerate every file record with `FSCTL_ENUM_USN_DATA`, requesting
//!    major versions 2–3 and parsing V2 **and** V3/V4 layouts via
//!    `MajorVersion` (the §5.4 version hazard; V4 range records are skipped).
//!    Only the FRN→ParentFRN map plus names/attributes are kept — no path
//!    resolution during enumeration.
//! 3. Second pass: `OpenFileById` + `GetFileInformationByHandle` /
//!    `GetFileInformationByHandleEx(FileStandardInfo)` for sizes, timestamps,
//!    and `NumberOfLinks` (hardlink-dedup input, §5.2).
//! 4. Paths are resolved afterwards via memoized parent-chain walks, and the
//!    subtree under the requested scan root is streamed as the same
//!    `ScanEvent::Upsert` stream the `WalkScanner` emits.
//!
//! Known Stage A limitations (documented per honesty requirements):
//! - `FSCTL_ENUM_USN_DATA` emits one record per file record segment; extra
//!   hardlink names are not reliably enumerable, so a file with
//!   `NumberOfLinks > 1` seen only once counts full size with no alias node.
//!   Duplicate-FRN records, when the OS does emit them, become 0-size
//!   `HARDLINK_ALIAS` nodes per §5.2.
//! - Enumeration continuation uses the 64-bit start FRN of
//!   `MFT_ENUM_DATA_V1`; on volumes with 128-bit file IDs whose high bits are
//!   set, continuation is u64-truncated by the API itself.
//! - NTFS ADS are not enumerated (Stage B / §7.4 territory).

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::Instant;

use rss_core::{NodeKind, NodeParams};
use rustc_hash::{FxHashMap, FxHashSet};
use windows_sys::Win32::Foundation::{
    CloseHandle, FILETIME, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ExtendedFileIdType, FileIdType, FileStandardInfo, GetFileInformationByHandle,
    GetFileInformationByHandleEx, GetVolumeInformationW, OpenFileById, BY_HANDLE_FILE_INFORMATION,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_NO_RECALL, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_ID_128, FILE_ID_DESCRIPTOR, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FILE_STANDARD_INFO, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::{FSCTL_ENUM_USN_DATA, MFT_ENUM_DATA_V1};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::ntfs::{self, PathClass};
use crate::usn;
use crate::{
    EnginePlan, ScanEngine, ScanError, ScanEvent, ScanOptions, ScanProblem, ScanSummary, Upsert,
};

/// FSCTL output buffer size. Must exceed the largest possible record
/// (names up to 255 UTF-16 code units fit comfortably).
const ENUM_BUFFER_SIZE: usize = 512 * 1024;
/// MFT record index of the volume root directory (`\`).
const ROOT_FILE_INDEX: u128 = 5;
/// Low 48 bits of a file reference number hold the MFT record index.
const FRN_INDEX_MASK: u128 = 0x0000_FFFF_FFFF_FFFF;
/// `ERROR_HANDLE_EOF`: enumeration has reached the end of the MFT.
const ERROR_HANDLE_EOF: i32 = 38;
/// Progress callback interval, in processed records.
const PROGRESS_RECORD_INTERVAL: u64 = 8192;
/// Depth cap for parent-chain path resolution (cycle guard for corrupt
/// maps; SPEC.md §5.7 uses the same bound for untrusted trees).
const MAX_PATH_DEPTH: usize = 512;

// ---------------------------------------------------------------------------
// Isolated FFI wrappers (all `unsafe` in this module lives here)
// ---------------------------------------------------------------------------

/// RAII wrapper for a Win32 handle.
struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: `self.0` is a valid handle owned by this wrapper, closed
        // exactly once here.
        unsafe { CloseHandle(self.0) };
    }
}

fn wide(s: &str) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    Path::new(s)
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn last_os_error(context: &str) -> ScanError {
    ScanError::VolumeError(format!("{context}: {}", std::io::Error::last_os_error()))
}

/// Open a volume handle (`\\.\X:`) for reading. Requires elevation; this is
/// also the elevation probe for the fallback chain (SPEC.md §5.4).
fn open_volume(letter: u8) -> Result<OwnedHandle, ScanError> {
    let path = format!("\\\\.\\{}:", letter as char);
    let wide = wide(&path);
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string that outlives
    // the call; null security attributes and template handle are allowed.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(last_os_error(&format!(
            "open volume {path} (elevation required, FR-2.4)"
        )));
    }
    Ok(OwnedHandle(handle))
}

/// Query a volume's filesystem name via `GetVolumeInformationW`
/// (`lpFileSystemNameBuffer`, SPEC.md §5.4).
fn volume_fs_name(letter: u8) -> Result<String, ScanError> {
    let root = format!("{}:\\", letter as char);
    let wide = wide(&root);
    let mut fs_buf = [0u16; 64];
    // SAFETY: all pointers are valid buffers of the stated sizes; unused
    // out-parameters are null, which the API allows.
    let ok = unsafe {
        GetVolumeInformationW(
            wide.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_buf.as_mut_ptr(),
            fs_buf.len() as u32,
        )
    };
    if ok == 0 {
        return Err(last_os_error(&format!("GetVolumeInformationW {root}")));
    }
    let len = fs_buf.iter().position(|&c| c == 0).unwrap_or(fs_buf.len());
    Ok(String::from_utf16_lossy(&fs_buf[..len]))
}

/// One `FSCTL_ENUM_USN_DATA` chunk. Returns the number of valid bytes in
/// `buf` (8 bytes continuation value + records), or `Ok(0)` at end of
/// enumeration (`ERROR_HANDLE_EOF`).
fn enum_usn_chunk(volume: HANDLE, start_frn: u64, buf: &mut [u8]) -> Result<usize, ScanError> {
    let input = MFT_ENUM_DATA_V1 {
        StartFileReferenceNumber: start_frn,
        LowUsn: 0,
        HighUsn: i64::MAX,
        MinMajorVersion: 2,
        MaxMajorVersion: 3,
    };
    let mut returned: u32 = 0;
    // SAFETY: `input` is a valid in-buffer of its exact size; `buf` is a
    // valid writable out-buffer of `buf.len()` bytes; `returned` is a valid
    // out-pointer; no overlapped I/O.
    let ok = unsafe {
        DeviceIoControl(
            volume,
            FSCTL_ENUM_USN_DATA,
            (&raw const input).cast::<c_void>(),
            size_of::<MFT_ENUM_DATA_V1>() as u32,
            buf.as_mut_ptr().cast::<c_void>(),
            buf.len() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        let err = std::io::Error::last_os_error();
        if err.raw_os_error() == Some(ERROR_HANDLE_EOF) {
            return Ok(0);
        }
        return Err(ScanError::VolumeError(format!(
            "FSCTL_ENUM_USN_DATA: {err}"
        )));
    }
    Ok(returned as usize)
}

/// Open a file by ID relative to the volume handle. Never follows reparse
/// points and never recalls cloud placeholders (SPEC.md §7.1/§7.2).
fn open_by_id(
    volume: HANDLE,
    frn_bytes: &[u8; 16],
    is_128_bit: bool,
) -> Result<OwnedHandle, std::io::Error> {
    let mut desc = FILE_ID_DESCRIPTOR {
        dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: FileIdType,
        Anonymous: unsafe { std::mem::zeroed() },
    };
    if is_128_bit {
        desc.Type = ExtendedFileIdType;
        desc.Anonymous.ExtendedFileId = FILE_ID_128 {
            Identifier: *frn_bytes,
        };
    } else {
        desc.Anonymous.FileId =
            i64::from_le_bytes(frn_bytes[..8].try_into().expect("slice of 8 bytes"));
    }
    // SAFETY: `desc` is a valid, fully initialized descriptor; `volume` is a
    // valid volume handle. Requesting zero access rights queries metadata
    // only.
    let handle = unsafe {
        OpenFileById(
            volume,
            &raw const desc,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_OPEN_NO_RECALL,
        )
    };
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }
    Ok(OwnedHandle(handle))
}

/// Sizes/timestamps/link count for one open file.
struct FileMeta {
    logical: u64,
    allocated: u64,
    links: u32,
    created: i64,
    accessed: i64,
    modified: i64,
}

fn filetime_to_i64(ft: FILETIME) -> i64 {
    ((u64::from(ft.dwHighDateTime) << 32) | u64::from(ft.dwLowDateTime)) as i64
}

/// Query sizes and timestamps: `GetFileInformationByHandle` for attributes/
/// times/logical size/`NumberOfLinks`, plus
/// `GetFileInformationByHandleEx(FileStandardInfo)` for `AllocationSize`
/// (compression- and sparse-correct, SPEC.md §5.4/§7.5).
fn query_file_meta(handle: HANDLE) -> Result<FileMeta, std::io::Error> {
    let mut basic = BY_HANDLE_FILE_INFORMATION::default();
    // SAFETY: `handle` is a valid open handle; `basic` is a valid writable
    // out-struct.
    if unsafe { GetFileInformationByHandle(handle, &raw mut basic) } == 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut standard = FILE_STANDARD_INFO::default();
    // SAFETY: `handle` is valid; `standard` is a valid writable buffer of
    // the exact size required by FileStandardInfo.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileStandardInfo,
            (&raw mut standard).cast::<c_void>(),
            size_of::<FILE_STANDARD_INFO>() as u32,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    let logical = (u64::from(basic.nFileSizeHigh) << 32) | u64::from(basic.nFileSizeLow);
    // Sparse files legitimately allocate less than their length; a zero
    // allocation for a non-empty file is a quirk — fall back to logical.
    let allocated = match u64::try_from(standard.AllocationSize).unwrap_or(0) {
        0 if logical > 0 => logical,
        a => a,
    };
    Ok(FileMeta {
        logical,
        allocated,
        links: basic.nNumberOfLinks,
        created: filetime_to_i64(basic.ftCreationTime),
        accessed: filetime_to_i64(basic.ftLastAccessTime),
        modified: filetime_to_i64(basic.ftLastWriteTime),
    })
}

// ---------------------------------------------------------------------------
// Engine planning (FR-2.5 fallback chain)
// ---------------------------------------------------------------------------

/// Probe the volume behind `root` and decide the engine (SPEC.md §5.4):
/// filesystem name via `GetVolumeInformationW`, elevation via a probe-open of
/// the volume handle. The decision itself is the pure, tested
/// [`ntfs::decide_engine`].
pub(crate) fn plan_engine(root: &Path) -> EnginePlan {
    let text = root.to_string_lossy();
    let class = ntfs::classify_path(&text);
    let (fs_name, volume_openable) = match class {
        PathClass::Drive(letter) => (volume_fs_name(letter).ok(), open_volume(letter).is_ok()),
        _ => (None, false),
    };
    ntfs::decide_engine(class, fs_name.as_deref(), volume_openable)
}

// ---------------------------------------------------------------------------
// MftScanner
// ---------------------------------------------------------------------------

/// Per-record data kept from the enumeration pass (pass 1).
struct MftRecord {
    parent_frn: u128,
    frn_bytes: [u8; 16],
    /// True for V3/V4 records (128-bit file IDs) — selects the
    /// `OpenFileById` descriptor variant.
    is_128_bit: bool,
    name: String,
    file_attributes: u32,
    /// Journal timestamp; only a fallback for the real timestamps.
    timestamp: i64,
}

impl From<usn::UsnRecord> for MftRecord {
    fn from(r: usn::UsnRecord) -> Self {
        Self {
            parent_frn: r.parent_frn,
            frn_bytes: r.frn_bytes,
            is_128_bit: r.major_version >= 3,
            name: r.name,
            file_attributes: r.file_attributes,
            timestamp: r.timestamp,
        }
    }
}

/// NTFS Master File Table scan engine (SPEC.md §5.4, FR-2.4). See the module
/// docs for the design, limitations, and compile-checked-only status.
pub struct MftScanner {
    /// FRNs already counted, for hardlink aliasing (§5.2).
    seen_frns: FxHashSet<u128>,
}

impl MftScanner {
    /// Create a scanner with an empty dedup set.
    pub fn new() -> Self {
        Self {
            seen_frns: FxHashSet::default(),
        }
    }
}

impl Default for MftScanner {
    fn default() -> Self {
        Self::new()
    }
}

/// Resolve a record's volume-relative path by walking the parent chain,
/// memoized per FRN. Returns `None` on cycles or excessive depth (corrupt
/// input guard).
fn path_of(
    frn: u128,
    records: &FxHashMap<u128, MftRecord>,
    cache: &mut FxHashMap<u128, Option<Rc<str>>>,
) -> Option<Rc<str>> {
    if let Some(cached) = cache.get(&frn) {
        return cached.clone();
    }
    // Walk up, collecting names, until a cached/unknown ancestor.
    let mut chain: Vec<(u128, &str)> = Vec::new();
    let mut cur = frn;
    let base: Option<Rc<str>> = loop {
        if let Some(cached) = cache.get(&cur) {
            break cached.clone();
        }
        match records.get(&cur) {
            Some(rec) => {
                chain.push((cur, rec.name.as_str()));
                if rec.parent_frn == cur || chain.len() > MAX_PATH_DEPTH {
                    // Self-parenting root or a cycle: stop here.
                    break Some(Rc::from(""));
                }
                cur = rec.parent_frn;
            }
            // Parent not in the map (volume root or outside enumeration).
            None => break Some(Rc::from("")),
        }
    };
    let mut path = base?.to_string();
    let mut result = None;
    for (f, name) in chain.iter().rev() {
        if !path.is_empty() {
            path.push('\\');
        }
        path.push_str(name);
        let rc: Rc<str> = Rc::from(path.as_str());
        cache.insert(*f, Some(rc.clone()));
        result = Some(rc);
    }
    result
}

/// Find the FRN of the requested scan root. `suffix` is the volume-relative
/// path (`""` for the volume root), compared case-insensitively (NTFS is
/// case-preserving but case-insensitive).
fn find_scan_root(
    records: &FxHashMap<u128, MftRecord>,
    cache: &mut FxHashMap<u128, Option<Rc<str>>>,
    suffix: &str,
) -> Option<u128> {
    if suffix.is_empty() {
        // Volume root: MFT record index 5, or a directory whose parent is
        // itself/unknown, as fallback.
        return records
            .keys()
            .find(|f| **f & FRN_INDEX_MASK == ROOT_FILE_INDEX)
            .copied()
            .or_else(|| {
                records
                    .iter()
                    .find(|(f, r)| {
                        ntfs::is_directory(r.file_attributes)
                            && (r.parent_frn == **f || !records.contains_key(&r.parent_frn))
                    })
                    .map(|(f, _)| *f)
            });
    }
    let suffix_lc = suffix.to_lowercase();
    records
        .keys()
        .find(|&&f| path_of(f, records, cache).is_some_and(|p| p.to_lowercase() == suffix_lc))
        .copied()
}

impl ScanEngine for MftScanner {
    fn scan(
        &mut self,
        root: &Path,
        opts: &ScanOptions,
        sink: &mut dyn FnMut(ScanEvent),
    ) -> Result<ScanSummary, ScanError> {
        self.seen_frns.clear();
        let started = Instant::now();

        // Wholesale-failure checks (SPEC.md §5.9), mirroring WalkScanner.
        match std::fs::symlink_metadata(root) {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ScanError::RootNotFound(root.to_path_buf()));
            }
            Err(e) => {
                return Err(ScanError::RootUnreadable {
                    path: root.to_path_buf(),
                    message: e.to_string(),
                });
            }
        }
        let root_text = root.to_string_lossy().into_owned();
        let letter = match ntfs::classify_path(&root_text) {
            PathClass::Drive(letter) => letter,
            _ => return Err(ScanError::NotALocalVolume(root.to_path_buf())),
        };
        let volume = open_volume(letter)?;

        let mut summary = ScanSummary {
            root: root.to_path_buf(),
            ..Default::default()
        };

        // ---- Pass 1: enumerate all records; build FRN→ParentFRN map ----
        // No path resolution here (SPEC.md §5.4: the key trick).
        let mut records: FxHashMap<u128, MftRecord> = FxHashMap::default();
        // Duplicate FRNs (extra hardlink names, when the OS emits them).
        let mut duplicates: Vec<MftRecord> = Vec::new();
        let mut buf = vec![0u8; ENUM_BUFFER_SIZE];
        let mut start_frn: u64 = 0;
        let mut enumerated: u64 = 0;
        loop {
            opts.wait_while_paused();
            if opts.is_cancelled() {
                summary.cancelled = true;
                break;
            }
            let n = enum_usn_chunk(volume.0, start_frn, &mut buf)?;
            if n == 0 {
                break; // ERROR_HANDLE_EOF: enumeration complete
            }
            let (next, parsed, skipped) = usn::parse_buffer(&buf[..n])
                .map_err(|e| ScanError::VolumeError(format!("USN record parse: {e}")))?;
            if skipped > 0 {
                summary.errors.push(ScanProblem {
                    path: None,
                    message: format!("skipped {skipped} unparseable USN record(s)"),
                });
            }
            for record in parsed {
                // V4 range-tracking records carry no name/attributes — they
                // are journal artifacts, not files.
                if record.major_version == 4 {
                    continue;
                }
                match records.entry(record.frn) {
                    std::collections::hash_map::Entry::Occupied(_) => {
                        duplicates.push(MftRecord::from(record));
                    }
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(MftRecord::from(record));
                    }
                }
            }
            enumerated += 1;
            if let Some(cb) = &opts.progress {
                if enumerated.is_multiple_of(PROGRESS_RECORD_INTERVAL) {
                    cb(summary.progress());
                }
            }
            // 8 bytes = continuation value only, no records → done.
            if n <= 8 || next == start_frn {
                break;
            }
            start_frn = next;
        }

        // ---- Pass 2: sizes/timestamps via OpenFileById ----
        let mut metas: FxHashMap<u128, FileMeta> = FxHashMap::default();
        let mut open_failures: FxHashMap<u128, String> = FxHashMap::default();
        for (i, (frn, record)) in records.iter().enumerate() {
            opts.wait_while_paused();
            if (i as u64).is_multiple_of(256) && opts.is_cancelled() {
                summary.cancelled = true;
                break;
            }
            match open_by_id(volume.0, &record.frn_bytes, record.is_128_bit)
                .and_then(|file| query_file_meta(file.0))
            {
                Ok(meta) => {
                    metas.insert(*frn, meta);
                }
                Err(e) => {
                    // Deleted between passes, or a kernel-only pseudo file:
                    // keep the node, note the failure (SPEC.md §5.9).
                    open_failures.insert(*frn, e.to_string());
                }
            }
        }

        // ---- Resolve paths and emit the requested subtree ----
        let mut children: FxHashMap<u128, Vec<u128>> = FxHashMap::default();
        for (&frn, record) in &records {
            children.entry(record.parent_frn).or_default().push(frn);
        }
        let suffix = ntfs::drive_suffix(&root_text).unwrap_or_default();
        let mut cache: FxHashMap<u128, Option<Rc<str>>> = FxHashMap::default();
        let Some(root_frn) = find_scan_root(&records, &mut cache, &suffix) else {
            return Err(ScanError::RootNotFound(root.to_path_buf()));
        };

        let display_root = root.to_path_buf();
        let mut stack: Vec<(u128, PathBuf, Option<PathBuf>)> =
            vec![(root_frn, display_root.clone(), None)];
        while let Some((frn, path, parent_path)) = stack.pop() {
            opts.wait_while_paused();
            if opts.is_cancelled() {
                summary.cancelled = true;
                break;
            }
            let Some(record) = records.get(&frn) else {
                continue;
            };
            let is_root_node = parent_path.is_none();
            let name = if is_root_node {
                root_text.clone()
            } else {
                record.name.clone()
            };
            let params = self.node_params(frn, record, metas.get(&frn), name);
            if let Some(message) = open_failures.get(&frn) {
                summary.errors.push(ScanProblem {
                    path: Some(path.clone()),
                    message: format!("OpenFileById failed: {message}"),
                });
            }
            summary.entries += 1;
            summary.files += u64::from(params.kind == NodeKind::File);
            summary.dirs += u64::from(params.kind == NodeKind::Directory);
            summary.logical_size += params.logical_size;
            summary.allocated_size += params.allocated_size;
            let is_dir = params.kind == NodeKind::Directory;
            sink(ScanEvent::Upsert(Upsert {
                parent_path: parent_path.clone(),
                path: path.clone(),
                params,
            }));
            if is_dir {
                if let Some(kids) = children.get(&frn) {
                    for &child in kids {
                        let child_path = path.join(&*records[&child].name);
                        stack.push((child, child_path, Some(path.clone())));
                    }
                }
            }
        }

        // Hardlink aliases: duplicate-FRN records under the scanned subtree
        // become 0-size HARDLINK_ALIAS nodes (§5.2). Their parents were
        // already emitted above, so the builder resolves them.
        let suffix_lc = suffix.to_lowercase();
        for dup in duplicates {
            opts.wait_while_paused();
            if opts.is_cancelled() {
                summary.cancelled = true;
                break;
            }
            let Some(parent_rel) = path_of(dup.parent_frn, &records, &mut cache) else {
                continue;
            };
            let parent_rel_lc = parent_rel.to_lowercase();
            let parent_display = if suffix_lc.is_empty() {
                display_root.join(&*parent_rel)
            } else if parent_rel_lc == suffix_lc {
                display_root.clone()
            } else if parent_rel_lc.starts_with(&format!("{suffix_lc}\\")) {
                // Byte offset is safe: the matched prefix is the lowercased
                // suffix; a non-ASCII case fold changing length simply fails
                // the prefix check above for that path.
                let Some(rest) = parent_rel.get(suffix.len() + 1..) else {
                    continue;
                };
                display_root.join(rest)
            } else {
                continue; // outside the scanned subtree
            };
            let mut params = self.node_params(0, &dup, None, dup.name.clone());
            // Second link to an already-counted file: zero size (§5.2).
            params.logical_size = 0;
            params.allocated_size = 0;
            params.flags.insert(rss_core::NodeFlags::HARDLINK_ALIAS);
            let path = parent_display.join(&*dup.name);
            summary.entries += 1;
            summary.files += u64::from(params.kind == NodeKind::File);
            sink(ScanEvent::Upsert(Upsert {
                parent_path: Some(parent_display),
                path,
                params,
            }));
        }

        if let Some(cb) = &opts.progress {
            cb(summary.progress());
        }
        summary.elapsed = started.elapsed();
        Ok(summary)
    }
}

impl MftScanner {
    /// Build node parameters for one record, applying the double-counting
    /// rules of SPEC.md §7.1 and the §5.2 hardlink dedup.
    fn node_params(
        &mut self,
        frn: u128,
        record: &MftRecord,
        meta: Option<&FileMeta>,
        name: String,
    ) -> NodeParams {
        let mut flags = ntfs::node_flags_from_file_attributes(record.file_attributes);
        let is_reparse = ntfs::is_reparse_point(record.file_attributes);
        let kind = if ntfs::is_directory(record.file_attributes) && !is_reparse {
            NodeKind::Directory
        } else {
            // Reparse points (symlinks/junctions) become marked file nodes,
            // matching WalkScanner; their targets appear at their real
            // location in a full-volume enumeration anyway.
            NodeKind::File
        };
        // Directories carry no own size (WalkScanner parity: aggregates are
        // platform-independent).
        let (mut logical, mut allocated) = if kind == NodeKind::Directory {
            (0, 0)
        } else {
            match meta {
                Some(m) => (m.logical, m.allocated),
                None => (0, 0),
            }
        };
        if kind == NodeKind::File
            && meta.is_some_and(|m| m.links > 1)
            && !self.seen_frns.insert(frn)
        {
            logical = 0;
            allocated = 0;
            flags.insert(rss_core::NodeFlags::HARDLINK_ALIAS);
        }
        let (created, accessed, modified) = match meta {
            Some(m) => (m.created, m.accessed, m.modified),
            // Fall back to the journal timestamp when the second pass could
            // not open the file (vanished mid-scan).
            None => (record.timestamp, record.timestamp, record.timestamp),
        };
        let mut params = NodeParams::named(name, kind)
            .sizes(logical, allocated)
            .flags(flags);
        params.created = created;
        params.accessed = accessed;
        params.modified = modified;
        params
    }
}
