//! `RdcwWatcher` — the everywhere-correct watcher backend (SPEC.md §5.5,
//! FR-7.3).
//!
//! Built on the `notify` crate, which wraps `ReadDirectoryChangesW` on
//! Windows (the crate this watcher is named after) and inotify / FSEvents /
//! kqueue elsewhere. It watches the whole subtree under the root
//! recursively.
//!
//! Error/overflow handling (FR-7.4): any backend error or rescan flag from
//! `notify` is mapped to [`WatchEvent::SubtreeDirty`] so events are never
//! silently dropped; the model responds with an incremental rescan of the
//! affected subtree.

use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::Receiver;
use notify::event::{ModifyKind, RenameMode};
use notify::{Event, EventKind, RecursiveMode, Watcher as NotifyWatcher};

use crate::coalesce::spawn_pump;
use crate::{PumpOptions, WatchError, WatchEvent, Watcher, WatcherKind};

/// Recursive directory watcher backed by `notify`
/// (`ReadDirectoryChangesW` on Windows, inotify on Linux).
pub struct RdcwWatcher {
    root: PathBuf,
    opts: PumpOptions,
    out_tx: crossbeam_channel::Sender<WatchEvent>,
    out_rx: Receiver<WatchEvent>,
    /// `Some` while running. Dropping the backend closes the raw channel
    /// (its callback holds the only sender), which makes the pump flush and
    /// exit.
    backend: Option<notify::RecommendedWatcher>,
    pump: Option<JoinHandle<()>>,
}

impl RdcwWatcher {
    /// Create a watcher for `root`. The root is not validated until
    /// [`Watcher::start`].
    pub fn new(root: impl Into<PathBuf>) -> Self {
        let (out_tx, out_rx) = crossbeam_channel::unbounded();
        RdcwWatcher {
            root: root.into(),
            opts: PumpOptions::default(),
            out_tx,
            out_rx,
            backend: None,
            pump: None,
        }
    }

    /// Override the debounce window (mainly for tests). Has no effect once
    /// started.
    #[doc(hidden)]
    pub fn with_debounce(mut self, debounce: Duration) -> Self {
        self.opts.debounce = debounce;
        self
    }
}

impl Watcher for RdcwWatcher {
    fn start(&mut self) -> Result<(), WatchError> {
        if self.backend.is_some() {
            return Ok(());
        }
        let backend_err = |message: String| WatchError::Backend {
            path: self.root.clone(),
            message,
        };
        let (raw_tx, raw_rx) = crossbeam_channel::unbounded::<WatchEvent>();
        let root = self.root.clone();
        let mut backend = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
            match res {
                Ok(event) => {
                    for mapped in map_event(&event, &root) {
                        let _ = raw_tx.send(mapped);
                    }
                }
                // FR-7.4: backend errors mean events may have been lost —
                // dirty-mark the affected paths (the watch root when the
                // error is not attributable) and let the model rescan.
                Err(err) => {
                    if err.paths.is_empty() {
                        let _ = raw_tx.send(WatchEvent::SubtreeDirty(root.clone()));
                    } else {
                        for path in &err.paths {
                            let _ = raw_tx.send(WatchEvent::SubtreeDirty(path.clone()));
                        }
                    }
                }
            }
        })
        .map_err(|e| backend_err(e.to_string()))?;
        backend
            .watch(&self.root, RecursiveMode::Recursive)
            .map_err(|e| backend_err(e.to_string()))?;
        self.pump = Some(spawn_pump(raw_rx, self.out_tx.clone(), self.opts.debounce));
        self.backend = Some(backend);
        Ok(())
    }

    fn stop(&mut self) -> Result<(), WatchError> {
        // Dropping the backend drops the notify callback, the last raw
        // sender; the pump flushes its pending batch and exits.
        self.backend.take();
        if let Some(pump) = self.pump.take() {
            pump.join()
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
        WatcherKind::Rdcw
    }
}

impl Drop for RdcwWatcher {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

/// Map one raw `notify` event to zero or more [`WatchEvent`]s.
///
/// `root` is the fallback for rescan-flagged events that carry no paths
/// (a full-tree rescan is the only safe response, FR-7.4).
fn map_event(event: &Event, root: &Path) -> Vec<WatchEvent> {
    // Some platforms signal "events were lost; rescan everything" via a flag
    // rather than an error — treat it exactly like an overflow (FR-7.4).
    if event.need_rescan() {
        return if event.paths.is_empty() {
            vec![WatchEvent::SubtreeDirty(root.to_path_buf())]
        } else {
            event
                .paths
                .iter()
                .map(|p| WatchEvent::SubtreeDirty(p.clone()))
                .collect()
        };
    }
    let upserts = |paths: &[PathBuf]| paths.iter().cloned().map(WatchEvent::Upsert).collect();
    let removes = |paths: &[PathBuf]| paths.iter().cloned().map(WatchEvent::Remove).collect();
    match event.kind {
        EventKind::Create(_) => upserts(&event.paths),
        EventKind::Remove(_) => removes(&event.paths),
        EventKind::Modify(ModifyKind::Name(RenameMode::Both)) => {
            // Atomic rename reported with both paths: [from, to].
            if event.paths.len() == 2 {
                vec![
                    WatchEvent::Remove(event.paths[0].clone()),
                    WatchEvent::Upsert(event.paths[1].clone()),
                ]
            } else {
                // Malformed pair; fall back to existence probing.
                by_existence(&event.paths)
            }
        }
        EventKind::Modify(ModifyKind::Name(RenameMode::From)) => removes(&event.paths),
        EventKind::Modify(ModifyKind::Name(RenameMode::To)) => upserts(&event.paths),
        // Any-direction renames and vague kinds: probe the filesystem.
        EventKind::Modify(ModifyKind::Name(RenameMode::Any))
        | EventKind::Modify(ModifyKind::Any)
        | EventKind::Any => by_existence(&event.paths),
        // Data/metadata/other modifications: re-stat the path.
        EventKind::Modify(_) => upserts(&event.paths),
        // Access and unhandled kinds carry no size/tree information.
        EventKind::Access(_) | EventKind::Other => Vec::new(),
    }
}

/// For ambiguous events, decide upsert vs. remove by whether the path still
/// exists (SPEC.md §5.5 notes RDCW gives limited info for deleted items).
fn by_existence(paths: &[PathBuf]) -> Vec<WatchEvent> {
    paths
        .iter()
        .map(|p| {
            if p.try_exists().unwrap_or(false) {
                WatchEvent::Upsert(p.clone())
            } else {
                WatchEvent::Remove(p.clone())
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: EventKind, paths: &[&str]) -> Event {
        let mut e = Event::new(kind);
        for p in paths {
            e = e.add_path(PathBuf::from(p));
        }
        e
    }

    #[test]
    fn create_maps_to_upsert() {
        let e = ev(
            EventKind::Create(notify::event::CreateKind::File),
            &["/a/f"],
        );
        assert_eq!(
            map_event(&e, Path::new("/a")),
            vec![WatchEvent::Upsert(PathBuf::from("/a/f"))]
        );
    }

    #[test]
    fn remove_maps_to_remove() {
        let e = ev(
            EventKind::Remove(notify::event::RemoveKind::File),
            &["/a/f"],
        );
        assert_eq!(
            map_event(&e, Path::new("/a")),
            vec![WatchEvent::Remove(PathBuf::from("/a/f"))]
        );
    }

    #[test]
    fn rename_both_maps_to_remove_plus_upsert() {
        let e = ev(
            EventKind::Modify(ModifyKind::Name(RenameMode::Both)),
            &["/a/old", "/a/new"],
        );
        assert_eq!(
            map_event(&e, Path::new("/a")),
            vec![
                WatchEvent::Remove(PathBuf::from("/a/old")),
                WatchEvent::Upsert(PathBuf::from("/a/new")),
            ]
        );
    }

    #[test]
    fn rename_from_maps_to_remove_and_to_maps_to_upsert() {
        let from = ev(
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            &["/a/old"],
        );
        let to = ev(
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
            &["/a/new"],
        );
        assert_eq!(
            map_event(&from, Path::new("/a")),
            vec![WatchEvent::Remove(PathBuf::from("/a/old"))]
        );
        assert_eq!(
            map_event(&to, Path::new("/a")),
            vec![WatchEvent::Upsert(PathBuf::from("/a/new"))]
        );
    }

    #[test]
    fn data_modify_maps_to_upsert() {
        let e = ev(
            EventKind::Modify(ModifyKind::Data(notify::event::DataChange::Content)),
            &["/a/f"],
        );
        assert_eq!(
            map_event(&e, Path::new("/a")),
            vec![WatchEvent::Upsert(PathBuf::from("/a/f"))]
        );
    }

    #[test]
    fn access_events_are_ignored() {
        let e = ev(
            EventKind::Access(notify::event::AccessKind::Read),
            &["/a/f"],
        );
        assert!(map_event(&e, Path::new("/a")).is_empty());
    }

    #[test]
    fn rescan_flag_maps_to_subtree_dirty() {
        let e = ev(EventKind::Other, &[]).set_flag(notify::event::Flag::Rescan);
        assert_eq!(
            map_event(&e, Path::new("/a")),
            vec![WatchEvent::SubtreeDirty(PathBuf::from("/a"))]
        );
    }

    #[test]
    fn existence_probe_distinguishes_create_from_delete() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f");
        let path_str = file.to_str().unwrap();

        let e = ev(EventKind::Modify(ModifyKind::Any), &[path_str]);
        assert_eq!(
            map_event(&e, dir.path()),
            vec![WatchEvent::Remove(file.clone())]
        );

        std::fs::write(&file, b"x").unwrap();
        let e = ev(EventKind::Modify(ModifyKind::Any), &[path_str]);
        assert_eq!(map_event(&e, dir.path()), vec![WatchEvent::Upsert(file)]);
    }
}
