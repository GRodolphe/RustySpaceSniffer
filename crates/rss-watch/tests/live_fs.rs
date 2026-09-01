//! Integration tests: `RdcwWatcher` against a live tempfile tree (FR-7.1,
//! FR-7.4). These run on the Linux development host via notify's inotify
//! backend; the same code paths wrap `ReadDirectoryChangesW` on Windows.

use std::path::Path;
#[cfg(not(windows))]
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crossbeam_channel::Receiver;
#[cfg(not(windows))]
use rss_watch::{select_watcher, WatcherKind};
use rss_watch::{RdcwWatcher, WatchEvent, Watcher};

/// Generous per-phase ceiling so loaded CI machines don't flake.
const PHASE_TIMEOUT: Duration = Duration::from_secs(15);
/// How long the stream must be quiet before a phase is considered complete.
const QUIET: Duration = Duration::from_millis(700);

/// Collect events until `found` matches one, or the deadline passes.
fn collect_until(
    rx: &Receiver<WatchEvent>,
    timeout: Duration,
    mut found: impl FnMut(&WatchEvent) -> bool,
) -> Vec<WatchEvent> {
    let deadline = Instant::now() + timeout;
    let mut out = Vec::new();
    while let Ok(ev) = rx.recv_deadline(deadline) {
        let hit = found(&ev);
        out.push(ev);
        if hit {
            break;
        }
    }
    out
}

/// Drain events until the stream has been quiet for `quiet`.
fn drain_quiet(rx: &Receiver<WatchEvent>, quiet: Duration) -> Vec<WatchEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.recv_timeout(quiet) {
        out.push(ev);
    }
    out
}

fn is_upsert(ev: &WatchEvent, path: &Path) -> bool {
    matches!(ev, WatchEvent::Upsert(p) if p == path)
}

fn is_remove(ev: &WatchEvent, path: &Path) -> bool {
    matches!(ev, WatchEvent::Remove(p) if p == path)
}

#[test]
fn create_dir_and_file_produce_upserts() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let mut watcher = RdcwWatcher::new(&root);
    watcher.start().unwrap();
    let rx = watcher.events();

    // Create dir → upsert for the directory.
    let sub = root.join("sub");
    std::fs::create_dir(&sub).unwrap();
    let events = collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &sub));
    assert!(
        events.iter().any(|ev| is_upsert(ev, &sub)),
        "expected Upsert({sub:?}), got {events:?}"
    );

    // Write file inside → upsert for the file.
    let file = sub.join("f.txt");
    std::fs::write(&file, b"hello").unwrap();
    let events = collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &file));
    assert!(
        events.iter().any(|ev| is_upsert(ev, &file)),
        "expected Upsert({file:?}), got {events:?}"
    );

    watcher.stop().unwrap();
}

#[test]
fn burst_of_writes_coalesces_to_one_upsert() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let file = root.join("burst.txt");
    std::fs::write(&file, b"seed").unwrap();

    let mut watcher = RdcwWatcher::new(&root);
    watcher.start().unwrap();
    let rx = watcher.events();
    // Let the seed write drain out of the pipeline.
    let _ = collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &file));
    let _ = drain_quiet(&rx, QUIET);

    // A burst of writes: 30 rewrites, far faster than the debounce window.
    for _ in 0..30 {
        std::fs::write(&file, b"0123456789").unwrap();
    }

    let mut events = collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &file));
    events.extend(drain_quiet(&rx, QUIET));
    let upserts = events.iter().filter(|ev| is_upsert(ev, &file)).count();
    assert_eq!(
        upserts, 1,
        "burst must coalesce to exactly one Upsert({file:?}), got {events:?}"
    );

    watcher.stop().unwrap();
}

#[test]
fn delete_produces_remove() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let sub = root.join("victim");
    std::fs::create_dir(&sub).unwrap();
    let file = sub.join("gone.txt");
    std::fs::write(&file, b"bye").unwrap();

    let mut watcher = RdcwWatcher::new(&root);
    watcher.start().unwrap();
    let rx = watcher.events();
    let _ = collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &file));
    let _ = drain_quiet(&rx, QUIET);

    // Delete the file → remove event.
    std::fs::remove_file(&file).unwrap();
    let events = collect_until(&rx, PHASE_TIMEOUT, |ev| is_remove(ev, &file));
    assert!(
        events.iter().any(|ev| is_remove(ev, &file)),
        "expected Remove({file:?}), got {events:?}"
    );

    // Delete the now-empty directory → remove event for it too.
    std::fs::remove_dir(&sub).unwrap();
    let events = collect_until(&rx, PHASE_TIMEOUT, |ev| is_remove(ev, &sub));
    assert!(
        events.iter().any(|ev| is_remove(ev, &sub)),
        "expected Remove({sub:?}), got {events:?}"
    );

    watcher.stop().unwrap();
}

#[test]
fn rename_produces_remove_old_and_upsert_new() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let old = root.join("before.txt");
    std::fs::write(&old, b"rename me").unwrap();

    let mut watcher = RdcwWatcher::new(&root);
    watcher.start().unwrap();
    let rx = watcher.events();
    let _ = collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &old));
    let _ = drain_quiet(&rx, QUIET);

    let new = root.join("after.txt");
    std::fs::rename(&old, &new).unwrap();

    // Both halves of the rename must arrive (in either order, possibly as
    // one combined event or two backend events).
    let mut events = collect_until(&rx, PHASE_TIMEOUT, |ev| is_remove(ev, &old));
    events.extend(collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &new)));
    assert!(
        events.iter().any(|ev| is_remove(ev, &old)),
        "expected Remove({old:?}), got {events:?}"
    );
    assert!(
        events.iter().any(|ev| is_upsert(ev, &new)),
        "expected Upsert({new:?}), got {events:?}"
    );

    watcher.stop().unwrap();
}

#[test]
fn stop_flushes_pending_events() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let file = root.join("late.txt");
    std::fs::write(&file, b"seed").unwrap();

    let mut watcher = RdcwWatcher::new(&root);
    watcher.start().unwrap();
    let rx = watcher.events();
    let _ = collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &file));
    let _ = drain_quiet(&rx, QUIET);

    // Burst, then stop immediately — the pending batch must be flushed by
    // the pump before it exits, not lost.
    for _ in 0..10 {
        std::fs::write(&file, b"flush me").unwrap();
    }
    watcher.stop().unwrap();

    let events = drain_quiet(&rx, QUIET);
    assert!(
        events.iter().any(|ev| is_upsert(ev, &file)),
        "stop() must flush pending events, got {events:?}"
    );
}

#[test]
fn watching_a_missing_root_fails() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist");
    let mut watcher = RdcwWatcher::new(&missing);
    assert!(watcher.start().is_err());
}

/// Exercises select_watcher end-to-end with a live RDCW watcher. Unix-only:
/// on Windows an elevated NTFS runner correctly selects UsnJournal (SPEC
/// §5.5), and the USN watcher is compile-checked but not runtime-tested here —
/// the selection logic itself is covered by select.rs's unit tests.
#[cfg(not(windows))]
#[test]
fn select_watcher_picks_rdcw_for_local_paths() {
    let dir = tempfile::tempdir().unwrap();
    let mut watcher = select_watcher(dir.path()).unwrap();
    assert_eq!(watcher.kind(), WatcherKind::Rdcw);

    // The selected watcher is live, not just correctly labeled.
    watcher.start().unwrap();
    let rx = watcher.events();
    let file: PathBuf = dir.path().join("via-select.txt");
    std::fs::write(&file, b"x").unwrap();
    let events = collect_until(&rx, PHASE_TIMEOUT, |ev| is_upsert(ev, &file));
    assert!(
        events.iter().any(|ev| is_upsert(ev, &file)),
        "expected Upsert({file:?}), got {events:?}"
    );
    watcher.stop().unwrap();
}
