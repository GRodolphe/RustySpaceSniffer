//! Burst coalescing for the delta channel (SPEC.md §5.5).
//!
//! Raw backend events are pushed into a [`Coalescer`]; when the raw stream
//! has been quiet for `debounce` the pending set is flushed as a minimal
//! list of [`WatchEvent`]s, one per affected path. Merge rules (net effect
//! of a burst on a single path):
//!
//! - `Upsert` after anything → `Upsert` (the path exists now; re-stat it)
//! - `Remove` after `Upsert` → `Remove` (created and gone within the burst)
//! - `SubtreeDirty` sticks: it is never overwritten by `Upsert`/`Remove`
//!   (a lost-event rescan must not be downgraded, FR-7.4), and later
//!   `SubtreeDirty`s for the same path collapse into one.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Duration;

use crossbeam_channel::{Receiver, RecvTimeoutError, Sender};

use crate::WatchEvent;

/// Default debounce window: a burst is flushed after 100 ms of quiet
/// (SPEC.md §5.5 "bursts coalesced before application").
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(100);

/// Safety cap on the pending set: flush immediately once a batch grows this
/// large, so a pathological burst cannot queue unbounded paths before the
/// debounce window elapses.
const MAX_BATCH: usize = 4096;

/// Net effect of a burst on one path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Pending {
    Upsert,
    Remove,
    Dirty,
}

/// Accumulates raw events and merges them per path.
pub(crate) struct Coalescer {
    // BTreeMap so flush order is deterministic (path-sorted), which keeps
    // tests and downstream batch application reproducible.
    pending: BTreeMap<PathBuf, Pending>,
}

impl Coalescer {
    pub(crate) fn new() -> Self {
        Coalescer {
            pending: BTreeMap::new(),
        }
    }

    fn push(&mut self, event: WatchEvent) {
        let (path, kind) = match event {
            WatchEvent::Upsert(p) => (p, Pending::Upsert),
            WatchEvent::Remove(p) => (p, Pending::Remove),
            WatchEvent::SubtreeDirty(p) => (p, Pending::Dirty),
        };
        self.pending
            .entry(path)
            .and_modify(|existing| {
                *existing = match (*existing, kind) {
                    // Dirty sticks: never downgrade a lost-event rescan.
                    (Pending::Dirty, _) => Pending::Dirty,
                    // A rescan request arriving after Upsert/Remove covers it.
                    (_, Pending::Dirty) => Pending::Dirty,
                    // Latest net state wins for plain upsert/remove pairs.
                    (Pending::Upsert | Pending::Remove, Pending::Upsert) => Pending::Upsert,
                    (Pending::Upsert | Pending::Remove, Pending::Remove) => Pending::Remove,
                };
            })
            .or_insert(kind);
    }

    fn is_full(&self) -> bool {
        self.pending.len() >= MAX_BATCH
    }

    fn flush(&mut self) -> Vec<WatchEvent> {
        std::mem::take(&mut self.pending)
            .into_iter()
            .map(|(path, kind)| match kind {
                Pending::Upsert => WatchEvent::Upsert(path),
                Pending::Remove => WatchEvent::Remove(path),
                Pending::Dirty => WatchEvent::SubtreeDirty(path),
            })
            .collect()
    }
}

/// Spawn the coalescing pump thread: reads raw events from `raw`, debounces
/// them by `debounce`, and forwards merged batches to `out`. The thread
/// flushes and exits when `raw` disconnects (i.e. when the backend watcher
/// and every raw sender are dropped).
pub(crate) fn spawn_pump(
    raw: Receiver<WatchEvent>,
    out: Sender<WatchEvent>,
    debounce: Duration,
) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("rss-watch-pump".into())
        .spawn(move || pump_loop(raw, out, debounce))
        .expect("failed to spawn rss-watch pump thread")
}

fn flush_all(coalescer: &mut Coalescer, out: &Sender<WatchEvent>) {
    for event in coalescer.flush() {
        // The model may have gone away; dropping events at shutdown is fine.
        let _ = out.send(event);
    }
}

fn pump_loop(raw: Receiver<WatchEvent>, out: Sender<WatchEvent>, debounce: Duration) {
    let mut coalescer = Coalescer::new();
    loop {
        // Block for the first event of a burst.
        let first = match raw.recv() {
            Ok(event) => event,
            Err(_) => {
                flush_all(&mut coalescer, &out);
                return;
            }
        };
        coalescer.push(first);
        // Collect until the stream goes quiet for `debounce`.
        loop {
            match raw.recv_timeout(debounce) {
                Ok(event) => {
                    coalescer.push(event);
                    if coalescer.is_full() {
                        flush_all(&mut coalescer, &out);
                        break;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    flush_all(&mut coalescer, &out);
                    break;
                }
                Err(RecvTimeoutError::Disconnected) => {
                    flush_all(&mut coalescer, &out);
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn p(name: &str) -> PathBuf {
        PathBuf::from(name)
    }

    #[test]
    fn duplicate_upserts_collapse_to_one() {
        let mut c = Coalescer::new();
        for _ in 0..20 {
            c.push(WatchEvent::Upsert(p("/a/f.txt")));
        }
        assert_eq!(c.flush(), vec![WatchEvent::Upsert(p("/a/f.txt"))]);
    }

    #[test]
    fn upsert_after_remove_wins() {
        let mut c = Coalescer::new();
        c.push(WatchEvent::Remove(p("/a")));
        c.push(WatchEvent::Upsert(p("/a")));
        assert_eq!(c.flush(), vec![WatchEvent::Upsert(p("/a"))]);
    }

    #[test]
    fn remove_after_upsert_wins() {
        let mut c = Coalescer::new();
        c.push(WatchEvent::Upsert(p("/a")));
        c.push(WatchEvent::Remove(p("/a")));
        assert_eq!(c.flush(), vec![WatchEvent::Remove(p("/a"))]);
    }

    #[test]
    fn dirty_is_never_downgraded() {
        let mut c = Coalescer::new();
        c.push(WatchEvent::SubtreeDirty(p("/a")));
        c.push(WatchEvent::Upsert(p("/a")));
        c.push(WatchEvent::Remove(p("/a")));
        c.push(WatchEvent::SubtreeDirty(p("/a")));
        assert_eq!(c.flush(), vec![WatchEvent::SubtreeDirty(p("/a"))]);
    }

    #[test]
    fn dirty_subsumes_earlier_events() {
        let mut c = Coalescer::new();
        c.push(WatchEvent::Upsert(p("/a")));
        c.push(WatchEvent::SubtreeDirty(p("/a")));
        assert_eq!(c.flush(), vec![WatchEvent::SubtreeDirty(p("/a"))]);
    }

    #[test]
    fn distinct_paths_survive_and_flush_sorted() {
        let mut c = Coalescer::new();
        c.push(WatchEvent::Upsert(p("/b")));
        c.push(WatchEvent::Remove(p("/a")));
        c.push(WatchEvent::Upsert(p("/b")));
        assert_eq!(
            c.flush(),
            vec![WatchEvent::Remove(p("/a")), WatchEvent::Upsert(p("/b"))]
        );
    }

    #[test]
    fn pump_debounces_a_burst_into_one_event() {
        let (raw_tx, raw_rx) = crossbeam_channel::unbounded();
        let (out_tx, out_rx) = crossbeam_channel::unbounded();
        let pump = spawn_pump(raw_rx, out_tx, Duration::from_millis(50));

        for _ in 0..10 {
            raw_tx.send(WatchEvent::Upsert(p("/a/f.txt"))).unwrap();
        }
        drop(raw_tx); // closes the pump after flushing

        let event = out_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("pump must flush on close");
        assert_eq!(event, WatchEvent::Upsert(p("/a/f.txt")));
        // Nothing else: the burst coalesced to exactly one event.
        assert!(out_rx.recv_timeout(Duration::from_millis(300)).is_err());
        pump.join().unwrap();
    }

    #[test]
    fn pump_splits_quiet_separated_bursts() {
        let (raw_tx, raw_rx) = crossbeam_channel::unbounded();
        let (out_tx, out_rx) = crossbeam_channel::unbounded();
        let pump = spawn_pump(raw_rx, out_tx, Duration::from_millis(50));

        raw_tx.send(WatchEvent::Upsert(p("/a"))).unwrap();
        std::thread::sleep(Duration::from_millis(200)); // let the burst go quiet
        raw_tx.send(WatchEvent::Remove(p("/a"))).unwrap();
        drop(raw_tx);

        assert_eq!(
            out_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            WatchEvent::Upsert(p("/a"))
        );
        assert_eq!(
            out_rx.recv_timeout(Duration::from_secs(5)).unwrap(),
            WatchEvent::Remove(p("/a"))
        );
        pump.join().unwrap();
    }

    #[test]
    fn full_batch_flushes_immediately() {
        let mut c = Coalescer::new();
        for i in 0..MAX_BATCH {
            c.push(WatchEvent::Upsert(p(&format!("/f{i}"))));
        }
        assert!(c.is_full());
        assert_eq!(c.flush().len(), MAX_BATCH);
        assert!(!c.is_full());
    }
}
