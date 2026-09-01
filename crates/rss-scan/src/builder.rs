//! Folds a [`ScanEvent`] stream into an `rss_core::Tree`.
//!
//! Relies on the `ParentFirst` ordering of the walker (a directory's upsert
//! always precedes its descendants). Events whose parent is unknown are
//! counted in [`TreeBuilder::orphans`] and skipped rather than panicking —
//! scan input is untrusted-concurrent filesystem state.

use std::path::PathBuf;

use rss_core::{NodeId, NodeKind, Tree};
use rustc_hash::FxHashMap;

use crate::{ScanEvent, Upsert};

/// Incrementally builds an `rss_core::Tree` from streamed [`ScanEvent`]s.
#[derive(Default)]
pub struct TreeBuilder {
    tree: Tree,
    /// Directories seen so far, keyed by their full path, so children can
    /// find their parent node.
    dirs: FxHashMap<PathBuf, NodeId>,
    /// Upserts skipped because their parent directory was not in the tree.
    /// Should stay 0 for `ParentFirst` walks; nonzero values indicate an
    /// engine contract violation.
    pub orphans: u64,
}

impl TreeBuilder {
    /// Create an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply one scan event. Error events are ignored here (they are
    /// recorded in the `ScanSummary` by the engine).
    pub fn apply(&mut self, event: ScanEvent) {
        match event {
            ScanEvent::Upsert(upsert) => self.upsert(upsert),
            ScanEvent::Error(_) => {}
        }
    }

    fn upsert(&mut self, upsert: Upsert) {
        let is_dir = upsert.params.kind == NodeKind::Directory;
        let id = match upsert.parent_path {
            None => {
                if self.tree.is_empty() {
                    self.tree = Tree::with_root(upsert.params);
                    self.tree.root()
                } else {
                    self.orphans += 1;
                    None
                }
            }
            Some(parent) => match self.dirs.get(&parent).copied() {
                Some(parent_id) => Some(self.tree.add_child(parent_id, upsert.params)),
                None => {
                    self.orphans += 1;
                    None
                }
            },
        };
        if is_dir {
            if let Some(id) = id {
                self.dirs.insert(upsert.path, id);
            }
        }
    }

    /// Consume the builder and return the assembled tree.
    pub fn into_tree(self) -> Tree {
        self.tree
    }

    /// Borrow the tree built so far.
    pub fn tree(&self) -> &Tree {
        &self.tree
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::NodeParams;

    #[test]
    fn folds_upserts_into_tree_with_aggregates() {
        let mut b = TreeBuilder::new();
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: None,
            path: PathBuf::from("/r"),
            params: NodeParams::named("/r", NodeKind::Directory),
        }));
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: Some(PathBuf::from("/r")),
            path: PathBuf::from("/r/f.bin"),
            params: NodeParams::named("f.bin", NodeKind::File).sizes(100, 4096),
        }));
        assert_eq!(b.orphans, 0);
        let tree = b.into_tree();
        let root = tree.root().unwrap();
        assert_eq!(tree.node(root).agg_logical, 100);
        assert_eq!(tree.node(root).agg_files, 1);
        assert_eq!(tree.node(root).agg_dirs, 1);
    }

    #[test]
    fn counts_orphans_instead_of_panicking() {
        let mut b = TreeBuilder::new();
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: None,
            path: PathBuf::from("/r"),
            params: NodeParams::named("/r", NodeKind::Directory),
        }));
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: Some(PathBuf::from("/r/never-seen")),
            path: PathBuf::from("/r/never-seen/f.bin"),
            params: NodeParams::named("f.bin", NodeKind::File),
        }));
        assert_eq!(b.orphans, 1);
        assert_eq!(b.tree().len(), 1);
    }
}
