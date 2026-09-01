//! Live filesystem change watchers for RustySpaceSniffer (SPEC.md §5.5,
//! FR-7.1..FR-7.8).
//!
//! A single delta channel (crossbeam MPMC) feeds the model: every [`Watcher`]
//! implementation emits [`WatchEvent`]s on a shared [`Receiver`], with bursts
//! coalesced (debounced) before application so a flurry of raw OS
//! notifications collapses to a minimal set of tree patches.
//!
//! Two backends per the SPEC.md §5.4 fallback chain:
//!
//! - [`UsnJournalWatcher`] (cfg(windows) only): NTFS USN change journal,
//!   requires elevation. Cursor persisted per volume (FR-7.2, FR-10.5);
//!   journal wrap or journal-ID change flags a full rescan (FR-7.5).
//!   **Compile-checked only on this host — first real run is Windows CI.**
//! - [`RdcwWatcher`]: `notify`-crate watcher wrapping `ReadDirectoryChangesW`
//!   on Windows (inotify/FSEvents/kqueue elsewhere); correct on every
//!   filesystem. Backend buffer overflow becomes [`WatchEvent::SubtreeDirty`]
//!   so events are never silently dropped (FR-7.4).
//!
//! [`select_watcher`] picks the backend for a root path; network/UNC roots
//! report live updates as unavailable (FR-7.7) so the app can show the
//! "press F5 to rescan" affordance instead.

use std::path::PathBuf;
use std::time::Duration;

use crossbeam_channel::Receiver;

mod coalesce;
mod cursor;
mod rdcw;
mod select;

#[cfg(windows)]
mod usn;

pub use coalesce::DEFAULT_DEBOUNCE;
pub use cursor::UsnCursor;
pub use rdcw::RdcwWatcher;
pub use select::{classify, select_watcher, WatcherChoice};

#[cfg(windows)]
pub use usn::UsnJournalWatcher;

/// A filesystem change delivered to the model (SPEC.md §5.5).
///
/// Events are path-based: the model re-stats `Upsert` paths and drops
/// `Remove` paths, keeping the watcher decoupled from the tree structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchEvent {
    /// The path was created, modified, or renamed onto this location; the
    /// model should re-stat it (and its subtree, if it is a directory whose
    /// children may have changed).
    Upsert(PathBuf),
    /// The path was deleted or renamed away; the model should drop it and
    /// its whole subtree.
    Remove(PathBuf),
    /// The watch backend lost events for this subtree (RDCW buffer overflow
    /// `ERROR_NOTIFY_ENUM_DIR`, FR-7.4; USN journal wrap / journal-ID change,
    /// FR-7.5). The model must incrementally rescan it — events are never
    /// silently dropped. Emitted at the watch root for a full-volume rescan.
    SubtreeDirty(PathBuf),
}

impl WatchEvent {
    /// The path this event concerns.
    pub fn path(&self) -> &std::path::Path {
        match self {
            WatchEvent::Upsert(p) | WatchEvent::Remove(p) | WatchEvent::SubtreeDirty(p) => p,
        }
    }
}

/// Which watcher backend [`select_watcher`] picks for a root path
/// (mirrors `rss_scan::EngineChoice`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WatcherKind {
    /// NTFS USN change journal (`UsnJournalWatcher`, NTFS + elevated).
    UsnJournal,
    /// `notify`-based directory watcher (`RdcwWatcher`) — correct everywhere.
    Rdcw,
}

/// A live filesystem watcher for one scan root (SPEC.md §5.5).
///
/// Lifecycle: construct, [`Watcher::start`], drain [`Watcher::events`] from
/// the model thread, [`Watcher::stop`] (or drop) to release OS resources.
pub trait Watcher: Send {
    /// Start watching. Events produced from this point are delivered on the
    /// [`Watcher::events`] channel. Calling `start` on an already-started
    /// watcher is a no-op.
    fn start(&mut self) -> Result<(), WatchError>;

    /// Stop watching, flush any pending coalesced events, and join the
    /// pump thread. Also called by `Drop` (errors ignored there).
    fn stop(&mut self) -> Result<(), WatchError>;

    /// The root path this watcher covers.
    fn root(&self) -> &std::path::Path;

    /// The coalesced event stream (crossbeam MPMC — cheap to clone for
    /// additional consumers).
    fn events(&self) -> Receiver<WatchEvent>;

    /// Which backend this is (for logging / settings UI, FR-7.6).
    fn kind(&self) -> WatcherKind;
}

/// Wholesale watcher failures. Per-event backend errors are never fatal —
/// they surface as [`WatchEvent::SubtreeDirty`] instead (FR-7.4).
#[derive(Debug, thiserror::Error)]
pub enum WatchError {
    /// Live updates are unavailable on network/UNC paths (FR-7.7); the app
    /// should show the persistent "press F5 to rescan" affordance.
    #[error("live updates unavailable on network path: {0} (FR-7.7)")]
    NetworkUnsupported(PathBuf),
    /// The NTFS USN journal is unavailable for this root: not an NTFS
    /// volume, not elevated, or the journal is not active. Callers should
    /// fall back to [`RdcwWatcher`] (SPEC.md §5.4 chain).
    #[error("USN journal unavailable for {path}: {message}")]
    UsnUnavailable {
        /// The watch root.
        path: PathBuf,
        /// OS error description.
        message: String,
    },
    /// The watch root does not exist or cannot be watched at all.
    #[error("cannot watch {path}: {message}")]
    Backend {
        /// The watch root.
        path: PathBuf,
        /// OS error description.
        message: String,
    },
    /// An internal error (thread spawn, cursor I/O).
    #[error("watcher internal error: {0}")]
    Internal(String),
}

/// Options shared by watcher implementations.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PumpOptions {
    /// Quiet period after the last raw event before a pending batch is
    /// flushed downstream (SPEC.md §5.5 burst coalescing).
    pub debounce: Duration,
}

impl Default for PumpOptions {
    fn default() -> Self {
        PumpOptions {
            debounce: DEFAULT_DEBOUNCE,
        }
    }
}
