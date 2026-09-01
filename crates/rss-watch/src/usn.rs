//! `UsnJournalWatcher` — NTFS USN change journal watcher (SPEC.md §5.5,
//! FR-7.2, FR-7.5).
//!
//! ⚠ **Windows-only, compile-checked but not run on the development host.**
//! This module is `cfg(windows)`-gated; on Linux it is verified exclusively
//! via `cargo check --target x86_64-pc-windows-msvc`. The first real run is
//! Windows CI; privilege-gated integration tests must be added there.
//!
//! Design (§5.5): at scan end the app snapshots the high-USN watermark via
//! [`UsnJournalWatcher::query_watermark`] and persists it (FR-10.5). On
//! start the watcher resumes `FSCTL_READ_USN_JOURNAL` from the persisted
//! cursor, polling with `ReturnOnlyOnClose = 1` so records arrive batched by
//! `USN_REASON_CLOSE` instead of churning per write. Journal wrap or a
//! journal-ID change makes the cursor unrecoverable →
//! [`WatchEvent::SubtreeDirty`] at the volume root, i.e. a full rescan
//! (FR-7.5).
//!
//! Records carry FRNs rather than paths; FRN → path resolution goes through
//! `OpenFileById` + `GetFinalPathNameByHandleW`. Records whose FRN can no
//! longer be resolved (e.g. parent directory also deleted) degrade to a
//! subtree-dirty rescan — events are never silently dropped.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use crossbeam_channel::Receiver;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, ExtendedFileIdType, FileIdType, GetFinalPathNameByHandleW, OpenFileById,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_128, FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::{
    FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL, READ_USN_JOURNAL_DATA_V0, USN_JOURNAL_DATA_V0,
    USN_REASON_BASIC_INFO_CHANGE, USN_REASON_CLOSE, USN_REASON_COMPRESSION_CHANGE,
    USN_REASON_DATA_EXTEND, USN_REASON_DATA_OVERWRITE, USN_REASON_DATA_TRUNCATION,
    USN_REASON_FILE_CREATE, USN_REASON_FILE_DELETE, USN_REASON_HARD_LINK_CHANGE,
    USN_REASON_NAMED_DATA_EXTEND, USN_REASON_NAMED_DATA_OVERWRITE,
    USN_REASON_NAMED_DATA_TRUNCATION, USN_REASON_RENAME_NEW_NAME, USN_REASON_RENAME_OLD_NAME,
    USN_RECORD_V2, USN_RECORD_V3,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use crate::coalesce::spawn_pump;
use crate::cursor::UsnCursor;
use crate::{PumpOptions, WatchError, WatchEvent, Watcher, WatcherKind};

/// Reasons we care about: anything that changes tree structure or size,
/// plus `CLOSE` so `ReturnOnlyOnClose` batches the record stream (§5.5).
const REASON_MASK: u32 = USN_REASON_DATA_OVERWRITE
    | USN_REASON_DATA_EXTEND
    | USN_REASON_DATA_TRUNCATION
    | USN_REASON_NAMED_DATA_OVERWRITE
    | USN_REASON_NAMED_DATA_EXTEND
    | USN_REASON_NAMED_DATA_TRUNCATION
    | USN_REASON_FILE_CREATE
    | USN_REASON_FILE_DELETE
    | USN_REASON_RENAME_OLD_NAME
    | USN_REASON_RENAME_NEW_NAME
    | USN_REASON_BASIC_INFO_CHANGE
    | USN_REASON_COMPRESSION_CHANGE
    | USN_REASON_HARD_LINK_CHANGE
    | USN_REASON_CLOSE;

/// Read buffer for `FSCTL_READ_USN_JOURNAL`.
const READ_BUF_SIZE: usize = 64 * 1024;

/// Poll blocking-wait timeout in seconds; bounds shutdown latency.
const POLL_TIMEOUT_SECS: u64 = 1;

/// RAII wrapper for a volume `HANDLE`. Windows handles are process-global
/// and may be used from any thread, so moving the owning wrapper across
/// threads is sound.
pub(crate) struct VolumeHandle(HANDLE);
unsafe impl Send for VolumeHandle {}

impl Drop for VolumeHandle {
    fn drop(&mut self) {
        // SAFETY: we own this handle and close it exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// Open `\\.\X:` for direct volume access (requires elevation, §5.4).
///
/// `volume_root` must be a drive-letter root like `C:\`; mount-point roots
/// are rejected (v1 scope). The `Err` path is what
/// `select::classify` uses as the elevation probe.
pub(crate) fn open_volume(volume_root: &Path) -> Result<VolumeHandle, WatchError> {
    let device = device_path_for(volume_root).ok_or_else(|| WatchError::UsnUnavailable {
        path: volume_root.to_path_buf(),
        message: "not a drive-letter volume root (e.g. C:\\)".into(),
    })?;
    let wide: Vec<u16> = device.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: `wide` is a valid NUL-terminated UTF-16 string; null security
    // attributes and template handle are documented as optional. Full share
    // mode is required so the volume stays usable by other processes.
    let handle = unsafe {
        CreateFileW(
            wide.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        // SAFETY: always safe; queries the thread-local last-error code.
        let err = unsafe { GetLastError() };
        return Err(WatchError::UsnUnavailable {
            path: volume_root.to_path_buf(),
            message: format!("opening {device} failed (Win32 error {err}); elevation required"),
        });
    }
    Ok(VolumeHandle(handle))
}

/// Map a drive-letter root (`C:\`) to its device path (`\\.\C:`).
fn device_path_for(volume_root: &Path) -> Option<String> {
    let s = volume_root.to_string_lossy();
    let mut chars = s.chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() || chars.next() != Some(':') {
        return None;
    }
    Some(format!("\\\\.\\{}:", letter.to_ascii_uppercase()))
}

/// `FSCTL_QUERY_USN_JOURNAL` on an open volume handle.
///
/// SAFETY contract for callers: none — all unsafe is contained here.
fn query_journal(volume: HANDLE) -> Result<USN_JOURNAL_DATA_V0, u32> {
    let mut out = USN_JOURNAL_DATA_V0::default();
    let mut returned: u32 = 0;
    // SAFETY: `out` is a valid writable `USN_JOURNAL_DATA_V0` of the stated
    // size; no input buffer and no overlapped I/O.
    let ok = unsafe {
        DeviceIoControl(
            volume,
            FSCTL_QUERY_USN_JOURNAL,
            std::ptr::null(),
            0,
            &mut out as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<USN_JOURNAL_DATA_V0>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        // SAFETY: always safe; queries the thread-local last-error code.
        return Err(unsafe { GetLastError() });
    }
    Ok(out)
}

/// A file reference number from a USN record: 64-bit (record V2) or
/// 128-bit (record V3/V4 — the §5.4 "version hazard").
#[derive(Clone, Copy)]
enum Frn {
    Id64(i64),
    Id128(FILE_ID_128),
}

/// One parsed USN record, borrowing its name from the read buffer.
struct RawRecord<'a> {
    reason: u32,
    frn: Frn,
    parent_frn: Frn,
    name: &'a [u16],
}

/// Iterate the records in a `FSCTL_READ_USN_JOURNAL` output buffer.
///
/// `buf` is the raw output (8-byte next-USN prefix followed by packed,
/// 8-byte-aligned records); `len` is the byte count returned by the ioctl.
/// Records with unknown major versions are skipped (never assumed to be V2,
/// per the §5.4 hazard note).
fn for_each_record(buf: &[u8], mut f: impl FnMut(RawRecord<'_>)) {
    let mut off = 8usize; // skip the returned next-USN prefix
    while off + std::mem::size_of::<u32>() + 4 <= buf.len() {
        // SAFETY: reads of RecordLength/MajorVersion stay in-bounds (checked
        // above); `buf` is 8-byte-aligned (allocated as u64s) and records
        // are 8-byte-aligned within it per the USN journal ABI.
        let (record_len, major) = unsafe {
            let base = buf.as_ptr().add(off);
            (
                std::ptr::read_unaligned(base as *const u32) as usize,
                std::ptr::read_unaligned(base.add(4) as *const u16),
            )
        };
        if record_len == 0 || record_len % 8 != 0 || off + record_len > buf.len() {
            // Records are 8-byte aligned and padded to 8-byte multiples per
            // the USN journal ABI; anything else is corruption — stop rather
            // than risk a misaligned parse.
            break;
        }
        let record = &buf[off..off + record_len];
        let parsed = match major {
            2 => parse_v2(record),
            3 => parse_v3(record),
            // MajorVersion 4 records are the extent-tracking variant (no file
            // name); nothing path-based can be derived — skip, and rely on
            // the journal-wrap safeguard for correctness.
            _ => None,
        };
        if let Some(rec) = parsed {
            f(rec);
        }
        off += record_len;
    }
}

/// Extract the record name (bounded by the record length).
fn record_name(record: &[u8], name_offset: usize, name_len: usize) -> Option<&[u16]> {
    let end = name_offset.checked_add(name_len)?;
    // FileNameOffset is even by construction (it follows the fixed-size
    // header); reject anything else rather than risk a misaligned cast.
    if end > record.len() || !name_offset.is_multiple_of(2) || !name_len.is_multiple_of(2) {
        return None;
    }
    let bytes = &record[name_offset..end];
    // SAFETY: `record` starts 8-byte-aligned within an 8-byte-aligned
    // buffer (records are 8-byte aligned per the USN journal ABI) and
    // `name_offset` is even (checked above), so the pointer is u16-aligned;
    // the slice is in-bounds (checked above).
    Some(unsafe { std::slice::from_raw_parts(bytes.as_ptr() as *const u16, name_len / 2) })
}

fn parse_v2(record: &[u8]) -> Option<RawRecord<'_>> {
    if record.len() < std::mem::size_of::<USN_RECORD_V2>() {
        return None;
    }
    // SAFETY: length checked above; the record is 8-byte aligned within an
    // 8-byte-aligned buffer, and `USN_RECORD_V2` is `repr(C)`.
    let r = unsafe { &*(record.as_ptr() as *const USN_RECORD_V2) };
    Some(RawRecord {
        reason: r.Reason,
        frn: Frn::Id64(r.FileReferenceNumber as i64),
        parent_frn: Frn::Id64(r.ParentFileReferenceNumber as i64),
        name: record_name(record, r.FileNameOffset as usize, r.FileNameLength as usize)?,
    })
}

fn parse_v3(record: &[u8]) -> Option<RawRecord<'_>> {
    if record.len() < std::mem::size_of::<USN_RECORD_V3>() {
        return None;
    }
    // SAFETY: length checked above; alignment as for `parse_v2`.
    let r = unsafe { &*(record.as_ptr() as *const USN_RECORD_V3) };
    Some(RawRecord {
        reason: r.Reason,
        frn: Frn::Id128(r.FileReferenceNumber),
        parent_frn: Frn::Id128(r.ParentFileReferenceNumber),
        name: record_name(record, r.FileNameOffset as usize, r.FileNameLength as usize)?,
    })
}

/// Resolve an FRN to a full path via `OpenFileById` +
/// `GetFinalPathNameByHandleW`. Returns `None` when the file is gone or the
/// id type is unsupported.
fn resolve_frn_path(volume: HANDLE, frn: Frn) -> Option<PathBuf> {
    let mut desc = FILE_ID_DESCRIPTOR {
        dwSize: std::mem::size_of::<FILE_ID_DESCRIPTOR>() as u32,
        ..FILE_ID_DESCRIPTOR::default()
    };
    match frn {
        Frn::Id64(id) => {
            desc.Type = FileIdType;
            desc.Anonymous = FILE_ID_DESCRIPTOR_0 { FileId: id };
        }
        Frn::Id128(id) => {
            desc.Type = ExtendedFileIdType;
            desc.Anonymous = FILE_ID_DESCRIPTOR_0 { ExtendedFileId: id };
        }
    }
    // SAFETY: `desc` is a valid FILE_ID_DESCRIPTOR; desired access 0 with
    // full share mode suffices for name queries and survives delete-pending
    // states; FILE_FLAG_BACKUP_SEMANTICS permits opening directories.
    let file = unsafe {
        OpenFileById(
            volume,
            &desc,
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null(),
            FILE_FLAG_BACKUP_SEMANTICS,
        )
    };
    if file.is_null() {
        return None;
    }
    struct FileGuard(HANDLE);
    impl Drop for FileGuard {
        fn drop(&mut self) {
            // SAFETY: we own this handle and close it exactly once.
            unsafe { CloseHandle(self.0) };
        }
    }
    let file = FileGuard(file);

    let mut buf = vec![0u16; 1024];
    loop {
        // SAFETY: `buf` is a valid writable UTF-16 buffer of the stated
        // length; flags 0 = VOLUME_NAME_DOS | FILE_NAME_NORMALIZED.
        let len =
            unsafe { GetFinalPathNameByHandleW(file.0, buf.as_mut_ptr(), buf.len() as u32, 0) };
        if len == 0 {
            return None;
        }
        if len as usize > buf.len() {
            buf.resize(len as usize + 1, 0);
            continue;
        }
        let raw = String::from_utf16_lossy(&buf[..len as usize]);
        // `GetFinalPathNameByHandleW` returns `\\?\C:\…`; strip the verbatim
        // prefix so the path composes with the rest of the model.
        let stripped = raw.strip_prefix("\\\\?\\").unwrap_or(&raw);
        return Some(PathBuf::from(stripped));
    }
}

/// Everything the reader thread needs. Owns the volume handle.
struct ReaderConfig {
    root: PathBuf,
    volume: VolumeHandle,
    cursor: Option<UsnCursor>,
    cursor_file: Option<PathBuf>,
    stop: Arc<AtomicBool>,
    raw_tx: crossbeam_channel::Sender<WatchEvent>,
}

/// NTFS USN change journal watcher (SPEC.md §5.5). Elevated NTFS only;
/// construct via [`crate::select_watcher`] or check feasibility with
/// [`UsnJournalWatcher::query_watermark`] first.
///
/// **Compile-checked only until Windows CI runs it** — see module docs.
pub struct UsnJournalWatcher {
    root: PathBuf,
    cursor: Option<UsnCursor>,
    cursor_file: Option<PathBuf>,
    opts: PumpOptions,
    out_tx: crossbeam_channel::Sender<WatchEvent>,
    out_rx: Receiver<WatchEvent>,
    running: Option<Running>,
}

struct Running {
    stop: Arc<AtomicBool>,
    reader: JoinHandle<()>,
    pump: JoinHandle<()>,
}

impl UsnJournalWatcher {
    /// Watch `root` starting from the journal's current position (no
    /// resume; changes before `start` are the scanner's job). The cursor is
    /// not persisted.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self::build(root.into(), None, None)
    }

    /// Watch `root` resuming from a persisted cursor (FR-7.2/FR-10.5).
    /// `cursor_file` is where updated cursors are saved (temp+rename).
    /// Journal wrap / ID change on resume yields a full-rescan signal
    /// ([`WatchEvent::SubtreeDirty`] at the root, FR-7.5) and tracking
    /// restarts from the live position.
    pub fn with_cursor(
        root: impl Into<PathBuf>,
        cursor: UsnCursor,
        cursor_file: impl Into<PathBuf>,
    ) -> Self {
        Self::build(root.into(), Some(cursor), Some(cursor_file.into()))
    }

    fn build(root: PathBuf, cursor: Option<UsnCursor>, cursor_file: Option<PathBuf>) -> Self {
        let (out_tx, out_rx) = crossbeam_channel::unbounded();
        UsnJournalWatcher {
            root,
            cursor,
            cursor_file,
            opts: PumpOptions::default(),
            out_tx,
            out_rx,
            running: None,
        }
    }

    /// Snapshot the journal's current high-water mark for `root` — call at
    /// scan end and persist via [`UsnCursor::save`] so the next run resumes
    /// exactly where the scan left off (§5.5, FR-7.2).
    pub fn query_watermark(root: &Path) -> Result<UsnCursor, WatchError> {
        let volume = open_volume(root)?;
        let journal = query_journal(volume.0).map_err(|e| WatchError::UsnUnavailable {
            path: root.to_path_buf(),
            message: format!("FSCTL_QUERY_USN_JOURNAL failed (Win32 error {e})"),
        })?;
        Ok(UsnCursor {
            journal_id: journal.UsnJournalID,
            next_usn: journal.NextUsn,
        })
    }

    /// Persist an updated cursor after a successful read batch.
    fn persist_cursor(cursor_file: &Option<PathBuf>, journal_id: u64, next_usn: i64) {
        if let Some(path) = cursor_file {
            // Best-effort: a lost cursor degrades to a full rescan, never to
            // incorrect results.
            let _ = UsnCursor {
                journal_id,
                next_usn,
            }
            .save(path);
        }
    }

    /// Reader thread main loop: blocking journal polls from the cursor.
    fn reader_main(cfg: ReaderConfig) {
        let ReaderConfig {
            root,
            volume,
            cursor,
            cursor_file,
            stop,
            raw_tx,
        } = cfg;
        let volume = volume.0;

        let mut journal = match query_journal(volume) {
            Ok(j) => j,
            Err(_) => {
                // No journal at all: the model gets a full-rescan signal and
                // this watcher stops — falling back to RDCW is the app's
                // decision (it owns the log console, FR-2.13).
                let _ = raw_tx.send(WatchEvent::SubtreeDirty(root.clone()));
                return;
            }
        };
        // Resume point: match the persisted cursor against the live journal.
        let mut start_usn = match cursor {
            Some(c) if c.journal_id != journal.UsnJournalID || c.next_usn < journal.FirstUsn => {
                // Journal recreated (ID change) or wrapped past our cursor:
                // the delta history is lost → full rescan (FR-7.5).
                let _ = raw_tx.send(WatchEvent::SubtreeDirty(root.clone()));
                journal.NextUsn
            }
            Some(c) => c.next_usn,
            None => journal.NextUsn,
        };

        // u64 backing store so record pointer casts are 8-byte aligned.
        let mut buf = vec![0u64; READ_BUF_SIZE / 8];
        while !stop.load(Ordering::Relaxed) {
            // Detect wrap / journal recreation between polls (FR-7.5).
            if let Ok(current) = query_journal(volume) {
                if current.UsnJournalID != journal.UsnJournalID || current.FirstUsn > start_usn {
                    let _ = raw_tx.send(WatchEvent::SubtreeDirty(root.clone()));
                    journal = current;
                    start_usn = current.NextUsn;
                }
            }

            let input = READ_USN_JOURNAL_DATA_V0 {
                StartUsn: start_usn,
                ReasonMask: REASON_MASK,
                ReturnOnlyOnClose: 1, // CLOSE-batched delivery (§5.5)
                Timeout: POLL_TIMEOUT_SECS,
                BytesToWaitFor: 1, // return as soon as anything is pending
                UsnJournalID: journal.UsnJournalID,
            };
            let mut returned: u32 = 0;
            // SAFETY: `input` is a valid read struct; `buf` is a writable
            // READ_BUF_SIZE-byte buffer; synchronous (no OVERLAPPED).
            let ok = unsafe {
                DeviceIoControl(
                    volume,
                    FSCTL_READ_USN_JOURNAL,
                    &input as *const _ as *const core::ffi::c_void,
                    std::mem::size_of::<READ_USN_JOURNAL_DATA_V0>() as u32,
                    buf.as_mut_ptr() as *mut core::ffi::c_void,
                    READ_BUF_SIZE as u32,
                    &mut returned,
                    std::ptr::null_mut(),
                )
            };
            if ok == 0 {
                // SAFETY: always safe; queries the thread-local last-error.
                let err = unsafe { GetLastError() };
                match err {
                    windows_sys::Win32::Foundation::ERROR_JOURNAL_ENTRY_DELETED
                    | windows_sys::Win32::Foundation::ERROR_JOURNAL_DELETE_IN_PROGRESS
                    | windows_sys::Win32::Foundation::ERROR_JOURNAL_NOT_ACTIVE => {
                        // Journal (or our place in it) is gone → full rescan,
                        // then re-anchor at the live position if possible.
                        let _ = raw_tx.send(WatchEvent::SubtreeDirty(root.clone()));
                        match query_journal(volume) {
                            Ok(j) => {
                                journal = j;
                                start_usn = j.NextUsn;
                            }
                            Err(_) => return, // volume gone; nothing more to do
                        }
                        continue;
                    }
                    // Unexpected persistent failure: escalate to a full
                    // rescan rather than dropping events silently (FR-7.4
                    // spirit), then stop — restarting the watcher is the
                    // app's decision.
                    _ => {
                        let _ = raw_tx.send(WatchEvent::SubtreeDirty(root.clone()));
                        return;
                    }
                }
            }
            let returned = returned as usize;
            if returned < 8 {
                continue; // pure timeout tick
            }
            // First 8 bytes of the output are the USN to continue from.
            let next_usn = buf[0] as i64;
            let bytes: &[u8] = unsafe {
                // SAFETY: `buf` is a u64 vec of READ_BUF_SIZE bytes and
                // `returned <= READ_BUF_SIZE` per the ioctl contract.
                std::slice::from_raw_parts(buf.as_ptr() as *const u8, returned)
            };
            for_each_record(bytes, |rec| {
                if let Some(event) = map_record(volume, &root, rec) {
                    let _ = raw_tx.send(event);
                }
            });
            if next_usn > start_usn {
                start_usn = next_usn;
                Self::persist_cursor(&cursor_file, journal.UsnJournalID, start_usn);
            }
        }
        Self::persist_cursor(&cursor_file, journal.UsnJournalID, start_usn);
    }
}

impl Watcher for UsnJournalWatcher {
    fn start(&mut self) -> Result<(), WatchError> {
        if self.running.is_some() {
            return Ok(());
        }
        let volume = open_volume(&self.root).map_err(|e| match e {
            // `open_volume` reports UsnUnavailable with the volume root; the
            // caller-facing root is the watch root.
            WatchError::UsnUnavailable { message, .. } => WatchError::UsnUnavailable {
                path: self.root.clone(),
                message,
            },
            other => other,
        })?;
        let (raw_tx, raw_rx) = crossbeam_channel::unbounded();
        let stop = Arc::new(AtomicBool::new(false));
        let cfg = ReaderConfig {
            root: self.root.clone(),
            volume,
            cursor: self.cursor,
            cursor_file: self.cursor_file.clone(),
            stop: Arc::clone(&stop),
            raw_tx,
        };
        let reader = std::thread::Builder::new()
            .name("rss-watch-usn".into())
            .spawn(move || Self::reader_main(cfg))
            .map_err(|e| WatchError::Internal(format!("failed to spawn reader thread: {e}")))?;
        let pump = spawn_pump(raw_rx, self.out_tx.clone(), self.opts.debounce);
        self.running = Some(Running { stop, reader, pump });
        Ok(())
    }

    fn stop(&mut self) -> Result<(), WatchError> {
        if let Some(running) = self.running.take() {
            running.stop.store(true, Ordering::Relaxed);
            running
                .reader
                .join()
                .map_err(|_| WatchError::Internal("USN reader thread panicked".into()))?;
            // The reader held the last raw sender; the pump has flushed and
            // exited by now.
            running
                .pump
                .join()
                .map_err(|_| WatchError::Internal("pump thread panicked".into()))?;
        }
        Ok(())
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn events(&self) -> Receiver<WatchEvent> {
        self.out_rx.clone()
    }

    fn kind(&self) -> WatcherKind {
        WatcherKind::UsnJournal
    }
}

impl Drop for UsnJournalWatcher {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Map one parsed USN record to a [`WatchEvent`], resolving FRNs to paths.
/// Returns `None` for records outside the watch root.
fn map_record(volume: HANDLE, root: &Path, rec: RawRecord<'_>) -> Option<WatchEvent> {
    // With ReturnOnlyOnClose every record carries CLOSE; skip anything that
    // somehow does not (defensive — partial records would churn the model).
    if rec.reason & USN_REASON_CLOSE == 0 {
        return None;
    }
    let deleted = rec.reason & (USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME) != 0;
    let name = String::from_utf16_lossy(rec.name);
    let path = match resolve_frn_path(volume, rec.parent_frn) {
        Some(parent) => parent.join(&*name),
        // The parent is gone too; for a file that still exists, resolve the
        // FRN directly (rename cases). If that fails we cannot name the
        // path — dirty the whole root; never drop the change silently.
        None => match resolve_frn_path(volume, rec.frn) {
            Some(path) => path,
            None => return Some(WatchEvent::SubtreeDirty(root.to_path_buf())),
        },
    };
    if !path.starts_with(root) {
        return None; // volume-wide journal, single-root watch
    }
    Some(if deleted {
        WatchEvent::Remove(path)
    } else {
        WatchEvent::Upsert(path)
    })
}
