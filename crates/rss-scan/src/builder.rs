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
        let _ = self.apply_tracked(event);
    }

    /// Like [`TreeBuilder::apply`], but returns the id of the upserted node
    /// (`None` for errors and orphans). Used by the app to flash newly
    /// added/updated cells (FR-2.11).
    pub fn apply_tracked(&mut self, event: ScanEvent) -> Option<NodeId> {
        match event {
            ScanEvent::Upsert(upsert) => self.upsert(upsert),
            ScanEvent::Error(_) => None,
        }
    }

    fn upsert(&mut self, upsert: Upsert) -> Option<NodeId> {
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
        id
    }

    /// Consume the builder and return the assembled tree.
    pub fn into_tree(self) -> Tree {
        self.tree
    }

    /// Remove the subtree rooted at `id` from the tree and purge its entries
    /// from the directory map (live-update remove / subtree rescan, FR-7.x).
    /// Iterative: deep trees must not overflow the stack.
    pub fn remove_node(&mut self, id: NodeId) {
        let mut stack = vec![id];
        while let Some(cur) = stack.pop() {
            if self.tree.node(cur).kind == NodeKind::Directory {
                let path = self.tree.path(cur);
                self.dirs.remove(&path);
            }
            stack.extend(self.tree.children(cur));
        }
        self.tree.remove_subtree(id);
    }

    /// Rebuild a builder around an existing tree (e.g. a loaded snapshot or
    /// a completed scan), reconstructing the directory map from node paths so
    /// live updates and subtree rescans can keep folding into it.
    pub fn from_tree(tree: Tree) -> Self {
        let mut builder = Self {
            tree,
            ..Self::default()
        };
        let Some(root) = builder.tree.root() else {
            return builder;
        };
        // Root name is the scan root's full path (see WalkScanner); child
        // paths are parent path + name.
        let mut stack = vec![(root, builder.tree.path(root))];
        while let Some((id, path)) = stack.pop() {
            if builder.tree.node(id).kind == NodeKind::Directory {
                builder.dirs.insert(path.clone(), id);
            }
            for child in builder.tree.children(id) {
                let child_path = path.join(&*builder.tree.node(child).name);
                stack.push((child, child_path));
            }
        }
        builder
    }

    /// The directory map (path → node id) used to resolve upsert parents.
    /// Exposed for the live-update path (FR-7.x).
    pub fn dir_id(&self, path: &std::path::Path) -> Option<NodeId> {
        self.dirs.get(path).copied()
    }

    /// Borrow the tree built so far.
    pub fn tree(&self) -> &Tree {
        &self.tree
    }

    /// Borrow the tree mutably (live-update size/timestamp patches, FR-7.1).
    pub fn tree_mut(&mut self) -> &mut Tree {
        &mut self.tree
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
    fn remove_node_purges_dir_map() {
        let mut b = TreeBuilder::new();
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: None,
            path: PathBuf::from("/r"),
            params: NodeParams::named("/r", NodeKind::Directory),
        }));
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: Some(PathBuf::from("/r")),
            path: PathBuf::from("/r/d"),
            params: NodeParams::named("d", NodeKind::Directory),
        }));
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: Some(PathBuf::from("/r/d")),
            path: PathBuf::from("/r/d/f.bin"),
            params: NodeParams::named("f.bin", NodeKind::File).sizes(10, 10),
        }));
        let d = b.dir_id(std::path::Path::new("/r/d")).unwrap();
        b.remove_node(d);
        assert_eq!(b.dir_id(std::path::Path::new("/r/d")), None);
        let root = b.tree().root().unwrap();
        assert_eq!(b.tree().node(root).agg_logical, 0);
        assert_eq!(b.tree().node(root).agg_files, 0);
        // Re-adding under /r must not resolve the purged dir.
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: Some(PathBuf::from("/r")),
            path: PathBuf::from("/r/d"),
            params: NodeParams::named("d", NodeKind::Directory),
        }));
        assert_eq!(b.orphans, 0);
        assert_eq!(b.tree().children(root).count(), 1);
    }

    #[test]
    fn from_tree_rebuilds_dir_map() {
        let mut tree = Tree::with_root(NodeParams::named("/r", NodeKind::Directory));
        let root = tree.root().unwrap();
        let d = tree.add_child(root, NodeParams::named("d", NodeKind::Directory));
        tree.add_child(d, NodeParams::named("f.bin", NodeKind::File).sizes(5, 5));

        let mut b = TreeBuilder::from_tree(tree);
        assert_eq!(b.dir_id(std::path::Path::new("/r")), Some(root));
        assert_eq!(b.dir_id(std::path::Path::new("/r/d")), Some(d));
        // New events fold in against the rebuilt map.
        b.apply(ScanEvent::Upsert(Upsert {
            parent_path: Some(PathBuf::from("/r/d")),
            path: PathBuf::from("/r/d/g.bin"),
            params: NodeParams::named("g.bin", NodeKind::File).sizes(7, 7),
        }));
        assert_eq!(b.orphans, 0);
        assert_eq!(b.tree().node(root).agg_logical, 12);
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
