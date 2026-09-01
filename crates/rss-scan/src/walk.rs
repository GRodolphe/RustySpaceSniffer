//! `WalkScanner`: the M1 scan engine — a parallel directory walk backed by
//! dua-core's work-stealing traversal (SPEC.md §5.4).

use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rss_core::{NodeFlags, NodeKind, NodeParams};
use rustc_hash::{FxHashMap, FxHashSet};

use crate::platform;
use crate::{ScanEngine, ScanError, ScanEvent, ScanOptions, ScanProblem, ScanSummary, Upsert};

/// Progress callback interval, in scanned entries.
const PROGRESS_ENTRY_INTERVAL: u64 = 4096;

/// Parallel filesystem-walk scan engine (SPEC.md §5.4, FR-2.5).
///
/// Properties:
/// - Symlinks/reparse points are **never followed**; the link itself is
///   counted as a marked file node (SPEC.md §7.1 — this is also the
///   reparse-cycle loop guard).
/// - Hardlinks are deduplicated per `(device, inode)` /
///   `(volume serial, file index)`: the first link counts full size, later
///   links become 0-size nodes flagged [`NodeFlags::HARDLINK_ALIAS`] (§5.2).
/// - Directories that cannot be opened become [`NodeKind::Unaccessible`]
///   nodes flagged [`NodeFlags::ACCESS_DENIED`] (FR-2.8).
/// - Directories carry no own size; their bytes come from their children, so
///   aggregates are identical across platforms.
pub struct WalkScanner {
    /// Seen hardlink identities, per scan (SPEC.md §5.2).
    seen_hardlinks: FxHashSet<(u64, u64)>,
}

impl WalkScanner {
    /// Create a scanner with an empty hardlink seen-set.
    pub fn new() -> Self {
        Self {
            seen_hardlinks: FxHashSet::default(),
        }
    }
}

impl Default for WalkScanner {
    fn default() -> Self {
        Self::new()
    }
}

impl ScanEngine for WalkScanner {
    fn scan(
        &mut self,
        root: &Path,
        opts: &ScanOptions,
        sink: &mut dyn FnMut(ScanEvent),
    ) -> Result<ScanSummary, ScanError> {
        self.seen_hardlinks.clear();
        let started = Instant::now();

        // A scan only fails wholesale when the root itself is unreadable
        // (SPEC.md §5.9).
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

        // dua-core reports directory-open failures as unattributed iterator
        // errors, so the descend predicate pre-probes each directory: a
        // failed probe prunes the subtree and records the path, letting the
        // consumer mark the corresponding node Unaccessible (FR-2.8).
        let denied: Arc<Mutex<FxHashMap<PathBuf, String>>> =
            Arc::new(Mutex::new(FxHashMap::default()));
        let descend = {
            let denied = Arc::clone(&denied);
            let cancel = opts.cancel.clone();
            move |entry: &dua_core::Entry| -> bool {
                if cancel.as_ref().is_some_and(|c| c.load(Ordering::Relaxed)) {
                    return false;
                }
                if entry.file_type.is_dir() {
                    match std::fs::read_dir(entry.path()) {
                        Ok(_) => {}
                        Err(e) => {
                            if let Ok(mut guard) = denied.lock() {
                                guard.insert(entry.path(), e.to_string());
                            }
                            return false;
                        }
                    }
                }
                true
            }
        };

        let threads = match opts.threads {
            0 => std::thread::available_parallelism().map_or(4, usize::from),
            n => n,
        };

        let mut summary = ScanSummary {
            root: root.to_path_buf(),
            ..Default::default()
        };
        let mut last_progress = 0u64;

        // ParentFirst guarantees a directory's entry is yielded before any of
        // its descendants, which the TreeBuilder relies on.
        let walk = dua_core::walk(
            root,
            threads,
            dua_core::Order::ParentFirst,
            dua_core::Options::default(),
            descend,
        );

        for item in walk {
            // FR-2.3: cooperative pause — block between events until
            // resumed; cancellation always wins.
            opts.wait_while_paused();
            if opts.is_cancelled() {
                // Do NOT break: dua-core's worker pool reports entry batches
                // over a bounded channel whose senders block when full, so
                // dropping the iterator early can deadlock the pool join in
                // `Walk::drop`. Keep draining (cheaply, without emitting)
                // until the iterator is exhausted instead.
                summary.cancelled = true;
                continue;
            }
            let entry = match item {
                Ok(entry) => entry,
                Err(e) => {
                    // Pathless walker error (a directory that failed between
                    // the descend probe and the actual read, or similar).
                    summary.errors.push(ScanProblem {
                        path: None,
                        message: e.to_string(),
                    });
                    continue;
                }
            };

            let path = entry.path();
            let is_root = entry.depth == 0;
            let parent_path = (!is_root).then(|| entry.parent_path.as_ref().to_path_buf());
            let denied_msg = denied.lock().ok().and_then(|mut guard| guard.remove(&path));

            if is_root {
                if let Some(message) = denied_msg {
                    return Err(ScanError::RootUnreadable { path, message });
                }
            }

            let name = if is_root {
                path.to_string_lossy().into_owned()
            } else {
                entry.file_name.to_string_lossy().into_owned()
            };

            let params = map_entry(
                &mut self.seen_hardlinks,
                &mut summary,
                &path,
                name,
                &entry,
                denied_msg,
            );

            summary.entries += 1;
            summary.files += u64::from(params.kind == NodeKind::File);
            summary.dirs += u64::from(params.kind == NodeKind::Directory);
            summary.logical_size += params.logical_size;
            summary.allocated_size += params.allocated_size;
            sink(ScanEvent::Upsert(Upsert {
                parent_path,
                path,
                params,
            }));

            if let Some(callback) = &opts.progress {
                if summary.entries - last_progress >= PROGRESS_ENTRY_INTERVAL {
                    last_progress = summary.entries;
                    callback(summary.progress());
                }
            }
        }
        // When the loop ends or breaks, dropping the moved `walk` stops and
        // joins the worker pool (dua-core).

        if let Some(callback) = &opts.progress {
            callback(summary.progress());
        }
        summary.elapsed = started.elapsed();
        Ok(summary)
    }
}

/// Map one walker entry to [`NodeParams`], applying the double-counting
/// rules of SPEC.md §7.1 and the FR-2.8 unaccessible marking.
fn map_entry(
    seen_hardlinks: &mut FxHashSet<(u64, u64)>,
    summary: &mut ScanSummary,
    path: &Path,
    name: String,
    entry: &dua_core::Entry,
    denied_msg: Option<String>,
) -> NodeParams {
    if let Some(message) = denied_msg {
        summary.unaccessible += 1;
        summary.errors.push(ScanProblem {
            path: Some(path.to_path_buf()),
            message,
        });
        return NodeParams::named(name, NodeKind::Unaccessible).flags(NodeFlags::ACCESS_DENIED);
    }

    let metadata = match &entry.metadata {
        Ok(metadata) => metadata,
        Err(e) => {
            summary.unaccessible += 1;
            summary.errors.push(ScanProblem {
                path: Some(path.to_path_buf()),
                message: e.to_string(),
            });
            return NodeParams::named(name, NodeKind::Unaccessible).flags(NodeFlags::ACCESS_DENIED);
        }
    };

    let meta = platform::meta_values(path, metadata, entry.file_type.is_file());

    let mut flags = NodeFlags::default();
    if entry.file_type.is_symlink() {
        // The link itself is counted; the target is never traversed (§7.1).
        flags.insert(NodeFlags::REPARSE_POINT);
    }

    let kind = if entry.file_type.is_dir() {
        NodeKind::Directory
    } else {
        NodeKind::File
    };

    // Directories carry no own size; their bytes come from their children so
    // that aggregates are platform-independent.
    let (mut logical, mut allocated) = if kind == NodeKind::Directory {
        (0, 0)
    } else {
        (meta.logical, meta.allocated)
    };

    if entry.file_type.is_file() {
        if let Some(key) = meta.hardlink_key {
            if !seen_hardlinks.insert(key) {
                // Second (or later) hardlink to an already-counted file: keep
                // the node visible but count zero bytes (§5.2, §7.1).
                logical = 0;
                allocated = 0;
                flags.insert(NodeFlags::HARDLINK_ALIAS);
            }
        }
    }

    let mut params = NodeParams::named(name, kind)
        .sizes(logical, allocated)
        .flags(flags);
    params.created = meta.created;
    params.accessed = meta.accessed;
    params.modified = meta.modified;
    params
}

/// Stat a single path into [`NodeParams`] (FR-7.1): used by the live-update
/// path to re-stat watcher-touched entries without a rescan.
///
/// Applies the same mapping rules as the walk (directories carry no own
/// size, symlinks count as marked file nodes whose targets are never
/// followed, access failures map to `Unaccessible`). Hardlink dedup is **not**
/// applied here — dedup is a per-scan seen-set, meaningless for a one-off
/// re-stat; a hardlink that newly becomes a second link may briefly
/// double-count until the next rescan (documented M4 limitation).
///
/// Returns `None` when the path vanished or cannot be statted (callers treat
/// that as a remove).
pub fn stat_entry(path: &Path) -> Option<NodeParams> {
    let md = std::fs::symlink_metadata(path).ok()?;
    let ft = md.file_type();
    let name = path.file_name().map_or_else(
        || path.to_string_lossy().into_owned(),
        |n| n.to_string_lossy().into_owned(),
    );

    let mut flags = NodeFlags::default();
    if ft.is_symlink() {
        flags.insert(NodeFlags::REPARSE_POINT);
    }
    let kind = if ft.is_dir() {
        NodeKind::Directory
    } else {
        NodeKind::File
    };
    let (logical, allocated) = if kind == NodeKind::Directory {
        (0, 0)
    } else {
        entry_sizes(path, &md, ft.is_file())
    };

    let mut params = NodeParams::named(name, kind)
        .sizes(logical, allocated)
        .flags(flags);
    params.created = platform::system_time_to_filetime(md.created());
    params.accessed = platform::system_time_to_filetime(md.accessed());
    params.modified = platform::system_time_to_filetime(md.modified());
    Some(params)
}

/// Own sizes for a non-directory entry from std metadata (cfg-split).
#[cfg(unix)]
fn entry_sizes(_path: &Path, md: &std::fs::Metadata, _is_file: bool) -> (u64, u64) {
    use std::os::unix::fs::MetadataExt;
    (md.len(), md.blocks().saturating_mul(512))
}

/// Windows: std metadata lacks allocated size; approximate it with
/// `GetCompressedFileSizeW` (SPEC.md §5.4's documented fallback). The next
/// full scan reconciles exact `AllocationSize` values.
#[cfg(windows)]
fn entry_sizes(path: &Path, md: &std::fs::Metadata, is_file: bool) -> (u64, u64) {
    let logical = md.len();
    let allocated = if is_file && logical > 0 {
        crate::platform::compressed_file_size(path).unwrap_or(logical)
    } else {
        logical
    };
    (logical, allocated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ScanOptions;
    use std::sync::atomic::AtomicBool;

    fn write_file(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
    }

    #[test]
    fn scans_nested_tree_with_sizes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("sub")).unwrap();
        write_file(&root.join("top.bin"), &[0u8; 100]);
        write_file(&root.join("sub/nested.bin"), &[0u8; 200]);

        let mut scanner = WalkScanner::new();
        let mut events = Vec::new();
        let summary = scanner
            .scan(root, &ScanOptions::default(), &mut |e| events.push(e))
            .unwrap();

        assert_eq!(summary.entries, 4); // root, sub, top.bin, nested.bin
        assert_eq!(summary.files, 2);
        assert_eq!(summary.dirs, 2);
        assert_eq!(summary.logical_size, 300);
        assert!(summary.allocated_size >= summary.logical_size);
        assert!(!summary.cancelled);
        assert_eq!(summary.errors.len(), 0);
        // Parent before child (ParentFirst order).
        let paths: Vec<_> = events
            .iter()
            .map(|e| match e {
                ScanEvent::Upsert(u) => u.path.clone(),
                _ => panic!("unexpected error event"),
            })
            .collect();
        let pos = |p: &str| paths.iter().position(|x| x.ends_with(p)).unwrap();
        assert!(pos("sub") < pos("sub/nested.bin"));
    }

    #[test]
    fn cancellation_returns_partial_summary() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..64 {
            write_file(&dir.path().join(format!("f{i}.bin")), &[0u8; 16]);
        }
        let cancel = Arc::new(AtomicBool::new(true)); // cancelled from the start
        let opts = ScanOptions {
            cancel: Some(cancel),
            ..Default::default()
        };
        let mut scanner = WalkScanner::new();
        let summary = scanner
            .scan(dir.path(), &opts, &mut |_| {})
            .expect("cancellation is not an error");
        assert!(summary.cancelled);
    }

    #[test]
    #[cfg(unix)]
    fn hardlink_aliases_count_zero() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        write_file(&root.join("orig.bin"), &[0u8; 500]);
        if std::fs::hard_link(root.join("orig.bin"), root.join("alias.bin")).is_err() {
            return; // filesystem does not support hardlinks
        }
        let mut scanner = WalkScanner::new();
        let mut events = Vec::new();
        let summary = scanner
            .scan(root, &ScanOptions::default(), &mut |e| events.push(e))
            .unwrap();

        assert_eq!(summary.logical_size, 500, "size counted exactly once");
        let aliases = events
            .iter()
            .filter(|e| match e {
                ScanEvent::Upsert(u) => u.params.flags.contains(NodeFlags::HARDLINK_ALIAS),
                _ => false,
            })
            .count();
        assert_eq!(aliases, 1);
    }

    #[test]
    #[cfg(unix)]
    fn symlinks_are_counted_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("real")).unwrap();
        write_file(&root.join("real/big.bin"), &[0u8; 10_000]);
        std::os::unix::fs::symlink("real", root.join("link")).unwrap();

        let mut scanner = WalkScanner::new();
        let summary = scanner
            .scan(root, &ScanOptions::default(), &mut |_| {})
            .unwrap();
        // link (a file node) + big.bin; the symlink target is not traversed.
        assert_eq!(summary.files, 2);
        assert_eq!(summary.logical_size, 10_000 + "real".len() as u64);
    }

    #[test]
    #[cfg(unix)]
    fn permission_denied_dir_becomes_unaccessible() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let locked = root.join("locked");
        std::fs::create_dir(&locked).unwrap();
        write_file(&locked.join("secret.bin"), &[1u8; 10]);
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Skip when the process can read the directory anyway (e.g. root).
        if std::fs::read_dir(&locked).is_ok() {
            return;
        }

        let mut scanner = WalkScanner::new();
        let mut events = Vec::new();
        let summary = scanner
            .scan(root, &ScanOptions::default(), &mut |e| events.push(e))
            .unwrap();
        assert_eq!(summary.unaccessible, 1);
        let node = events.iter().find_map(|e| match e {
            ScanEvent::Upsert(u) if u.path == locked => Some(u),
            _ => None,
        });
        let node = node.expect("locked dir must still be emitted");
        assert_eq!(node.params.kind, NodeKind::Unaccessible);
        assert!(node.params.flags.contains(NodeFlags::ACCESS_DENIED));
        assert_eq!(node.params.logical_size, 0);
    }

    #[test]
    fn pause_blocks_and_resume_completes() {
        let dir = tempfile::tempdir().unwrap();
        for i in 0..16 {
            write_file(&dir.path().join(format!("f{i}.bin")), &[0u8; 16]);
        }
        let pause = Arc::new(AtomicBool::new(true));
        let cancel = Arc::new(AtomicBool::new(false));
        let opts = ScanOptions {
            pause: Some(pause.clone()),
            cancel: Some(cancel.clone()),
            ..Default::default()
        };
        let root = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || WalkScanner::new().scan(&root, &opts, &mut |_| {}));
        // Paused: the scan must not complete while the flag is set.
        std::thread::sleep(std::time::Duration::from_millis(150));
        assert!(!handle.is_finished(), "paused scan must block");
        // Resume: the scan completes with all entries.
        pause.store(false, Ordering::Relaxed);
        let summary = handle.join().unwrap().unwrap();
        assert!(!summary.cancelled);
        assert_eq!(summary.files, 16);

        // A paused scan stays cancellable (FR-2.2 + FR-2.3).
        let pause = Arc::new(AtomicBool::new(true));
        let cancel = Arc::new(AtomicBool::new(false));
        let opts = ScanOptions {
            pause: Some(pause.clone()),
            cancel: Some(cancel.clone()),
            ..Default::default()
        };
        let root = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || WalkScanner::new().scan(&root, &opts, &mut |_| {}));
        std::thread::sleep(std::time::Duration::from_millis(50));
        cancel.store(true, Ordering::Relaxed);
        let summary = handle.join().unwrap().unwrap();
        assert!(summary.cancelled);
    }

    #[test]
    fn stat_entry_matches_walk_mapping() {
        let dir = tempfile::tempdir().unwrap();
        write_file(&dir.path().join("f.bin"), &[0u8; 100]);
        std::fs::create_dir(dir.path().join("d")).unwrap();

        let file = stat_entry(&dir.path().join("f.bin")).unwrap();
        assert_eq!(file.kind, NodeKind::File);
        assert_eq!(file.logical_size, 100);
        assert!(file.allocated_size >= file.logical_size);
        assert!(file.modified > 0);

        let dirp = stat_entry(&dir.path().join("d")).unwrap();
        assert_eq!(dirp.kind, NodeKind::Directory);
        assert_eq!(dirp.logical_size, 0);

        // Vanished paths yield None (callers treat as remove).
        assert!(stat_entry(&dir.path().join("gone.bin")).is_none());
    }

    /// Regression: cancelling mid-scan must not deadlock (dua-core's worker
    /// pool blocks on a bounded event channel; dropping the walk early hangs
    /// the pool join — the scanner drains instead).
    #[test]
    fn cancel_mid_scan_does_not_hang() {
        let dir = tempfile::tempdir().unwrap();
        for d in 0..40 {
            let sub = dir.path().join(format!("d{d:02}"));
            std::fs::create_dir_all(&sub).unwrap();
            for f in 0..100 {
                write_file(&sub.join(format!("f{f}.bin")), &[0u8; 64]);
            }
        }
        let cancel = Arc::new(AtomicBool::new(false));
        let opts = ScanOptions {
            cancel: Some(cancel.clone()),
            ..Default::default()
        };
        let root = dir.path().to_path_buf();
        let handle = std::thread::spawn(move || {
            let mut scanner = WalkScanner::new();
            scanner.scan(&root, &opts, &mut |_| {})
        });
        // Let the walk get going, then cancel mid-flight.
        std::thread::sleep(std::time::Duration::from_millis(2));
        cancel.store(true, Ordering::Relaxed);
        let summary = handle
            .join()
            .expect("cancelled scan thread must not hang")
            .expect("cancel is not an error");
        assert!(summary.cancelled);
    }

    #[test]
    fn missing_root_is_a_wholesale_error() {
        let mut scanner = WalkScanner::new();
        let err = scanner
            .scan(
                Path::new("/definitely/not/a/real/path/rss"),
                &ScanOptions::default(),
                &mut |_| {},
            )
            .unwrap_err();
        assert!(matches!(err, ScanError::RootNotFound(_)));
    }
}
