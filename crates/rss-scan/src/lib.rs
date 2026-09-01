//! Scanning engine for RustySpaceSniffer (SPEC.md §5.4).
//!
//! Provides the [`ScanEngine`] trait, the [`ScanEvent`] stream that engines
//! emit, the [`WalkScanner`] (parallel directory walk backed by `dua-core`),
//! the [`MftScanner`] NTFS fast path (cfg(windows), FR-2.4), and the
//! [`plan_engine`]/[`select_engine`] fallback chain (FR-2.5).
//!
//! Per-node scan errors (access denied, vanished entries) are **data, not
//! failures** (SPEC.md §5.9): they surface as [`ScanEvent::Error`] items and
//! `Unaccessible` nodes, and are collected in [`ScanSummary::errors`]. A scan
//! only fails wholesale with a [`ScanError`] when the root itself is
//! unreadable.

use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;

use rss_core::NodeParams;

mod builder;
#[cfg(windows)]
mod mft;
// Pure decision logic and USN record parsing for the MFT path. Compiled (and
// unit-tested) on every host, but only consumed by cfg(windows) code — hence
// the scoped allow on non-Windows.
#[cfg_attr(not(windows), allow(dead_code))]
mod ntfs;
mod platform;
#[cfg_attr(not(windows), allow(dead_code))]
mod usn;
mod walk;

pub use builder::TreeBuilder;
#[cfg(windows)]
pub use mft::MftScanner;
pub use walk::{stat_entry, WalkScanner};

/// A filesystem node discovered during a scan, streamed to the model.
#[derive(Clone, Debug)]
pub struct Upsert {
    /// Path of the containing directory; `None` for the scan root itself.
    pub parent_path: Option<PathBuf>,
    /// Full path of this entry.
    pub path: PathBuf,
    /// Node payload ready to insert into an `rss_core::Tree`.
    pub params: NodeParams,
}

/// A non-fatal scan problem (SPEC.md §5.9: per-node errors are data).
#[derive(Clone, Debug)]
pub struct ScanProblem {
    /// Affected path, or `None` when the underlying walker reported an error
    /// that could not be attributed to a concrete path (rare; directory-open
    /// races that slip past the `WalkScanner` pre-probe).
    pub path: Option<PathBuf>,
    /// Human-readable description (goes to the log console, FR-2.13).
    pub message: String,
}

/// Events streamed from a [`ScanEngine`] to the model (SPEC.md §5.4).
#[derive(Clone, Debug)]
pub enum ScanEvent {
    /// A node was discovered or updated.
    Upsert(Upsert),
    /// A non-fatal problem worth surfacing in the log console.
    Error(ScanProblem),
}

/// Point-in-time scan progress, handed to the [`ScanOptions::progress`]
/// callback.
#[derive(Clone, Copy, Debug, Default)]
pub struct ScanProgress {
    /// Total entries seen so far (files + directories + special nodes).
    pub entries: u64,
    /// Files seen so far (symlinks count as files).
    pub files: u64,
    /// Directories seen so far.
    pub dirs: u64,
    /// Sum of logical sizes of counted entries.
    pub logical_bytes: u64,
    /// Sum of allocated (on-disk) sizes of counted entries.
    pub allocated_bytes: u64,
}

/// Final outcome of a scan. Also returned for cancelled scans, which keep
/// their partial results (FR-2.2).
#[derive(Clone, Debug, Default)]
pub struct ScanSummary {
    /// Root path that was scanned.
    pub root: PathBuf,
    /// Total entries scanned (files + directories + special nodes).
    pub entries: u64,
    /// Files scanned (symlinks count as files).
    pub files: u64,
    /// Directories scanned.
    pub dirs: u64,
    /// Total logical bytes (hardlink aliases count 0, §5.2).
    pub logical_size: u64,
    /// Total allocated (on-disk) bytes.
    pub allocated_size: u64,
    /// Number of subtrees marked unaccessible (FR-2.8).
    pub unaccessible: u64,
    /// Non-fatal problems encountered while scanning.
    pub errors: Vec<ScanProblem>,
    /// True when the scan was cancelled via [`ScanOptions::cancel`].
    pub cancelled: bool,
    /// Wall-clock duration of the scan.
    pub elapsed: Duration,
}

impl ScanSummary {
    /// Snapshot of the running counters as a [`ScanProgress`].
    pub fn progress(&self) -> ScanProgress {
        ScanProgress {
            entries: self.entries,
            files: self.files,
            dirs: self.dirs,
            logical_bytes: self.logical_size,
            allocated_bytes: self.allocated_size,
        }
    }
}

/// Options controlling a scan.
#[derive(Default)]
pub struct ScanOptions {
    /// Follow symlinks/reparse points during traversal.
    ///
    /// Reserved for future use: the M1 walker **never** follows links
    /// (SPEC.md §7.1 — this is also the reparse-point loop guard) and ignores
    /// this flag.
    pub follow_links: bool,
    /// Worker threads for the parallel walk; `0` means
    /// `available_parallelism`.
    pub threads: usize,
    /// Cooperative cancellation flag. When set, the scan stops at the next
    /// event and returns a partial [`ScanSummary`] with `cancelled == true`.
    pub cancel: Option<Arc<AtomicBool>>,
    /// Cooperative pause flag (FR-2.3). While set, the scan blocks between
    /// events until the flag clears; cancellation still wins, so a paused
    /// scan can always be cancelled.
    pub pause: Option<Arc<AtomicBool>>,
    /// Progress callback, invoked on the scanner thread at throttled
    /// intervals (and once at the end). Interior mutability is the caller's
    /// business so the callback can be shared across threads.
    pub progress: Option<Arc<dyn Fn(ScanProgress) + Send + Sync>>,
}

impl ScanOptions {
    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .is_some_and(|c| c.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Whether the scan is paused (FR-2.3).
    pub fn is_paused(&self) -> bool {
        self.pause
            .as_ref()
            .is_some_and(|p| p.load(std::sync::atomic::Ordering::Relaxed))
    }

    /// Block while paused (FR-2.3), polling at a coarse interval.
    /// Cancellation always breaks the wait, so a paused scan stays
    /// cancellable. Returns immediately when no pause flag is configured.
    pub fn wait_while_paused(&self) {
        while self.is_paused() && !self.is_cancelled() {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}

/// Wholesale scan failure (SPEC.md §5.9 — only the root being unreadable
/// fails a scan outright).
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The scan root does not exist.
    #[error("scan root not found: {0}")]
    RootNotFound(PathBuf),
    /// The scan root exists but cannot be read (e.g. permission denied).
    #[error("scan root is unreadable: {path}: {message}")]
    RootUnreadable {
        /// The offending root path.
        path: PathBuf,
        /// OS error description.
        message: String,
    },
    /// The MFT scanner was asked to scan a path that is not on a local
    /// drive-letter volume (UNC, relative path, ...).
    #[error("not a local drive-letter volume path: {0}")]
    NotALocalVolume(PathBuf),
    /// A volume-level operation failed (volume open, FSCTL, record parse).
    #[error("volume operation failed: {0}")]
    VolumeError(String),
}

/// A scanning engine streams [`ScanEvent`]s for the subtree under a root
/// path (SPEC.md §5.4).
pub trait ScanEngine {
    /// Scan `root`, streaming events into `sink`. Returns a summary; on
    /// cancellation the summary is partial and flagged.
    fn scan(
        &mut self,
        root: &Path,
        opts: &ScanOptions,
        sink: &mut dyn FnMut(ScanEvent),
    ) -> Result<ScanSummary, ScanError>;
}

/// Which engine implementation [`select_engine`] picked for a path.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum EngineChoice {
    /// Parallel directory walk (`WalkScanner`) — correct everywhere.
    Walk,
    /// NTFS Master File Table enumeration (`MftScanner`) — milestone M5.
    Mft,
}

/// Result of the engine fallback chain for a path (SPEC.md §5.4, FR-2.5).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EnginePlan {
    /// The engine to use.
    pub choice: EngineChoice,
    /// True when the volume is NTFS but the MFT fast path needs elevation:
    /// the caller should offer "rescan as administrator" (FR-2.5).
    pub mft_requires_elevation: bool,
}

/// Plan the engine for `root` per the SPEC.md §5.4 fallback chain, probing
/// the volume filesystem and (on Windows) volume-handle accessibility.
///
/// Non-Windows hosts always get the walker.
pub fn plan_engine(root: &Path) -> EnginePlan {
    plan_engine_impl(root)
}

/// Pick the scan engine for `root`: `Mft` on NTFS volumes when elevated,
/// `Walk` otherwise. See [`plan_engine`] for the full decision.
pub fn select_engine(root: &Path) -> EngineChoice {
    plan_engine(root).choice
}

#[cfg(not(windows))]
fn plan_engine_impl(_root: &Path) -> EnginePlan {
    EnginePlan {
        choice: EngineChoice::Walk,
        mft_requires_elevation: false,
    }
}

#[cfg(windows)]
fn plan_engine_impl(root: &Path) -> EnginePlan {
    mft::plan_engine(root)
}

/// Scan `root` with the default engine and fold the event stream into an
/// `rss_core::Tree`. Convenience wrapper used by the CLI and tests.
pub fn scan_tree(
    root: &Path,
    opts: &ScanOptions,
) -> Result<(rss_core::Tree, ScanSummary), ScanError> {
    let mut engine = WalkScanner::new();
    let mut builder = TreeBuilder::new();
    let summary = engine.scan(root, opts, &mut |event| builder.apply(event))?;
    Ok((builder.into_tree(), summary))
}
