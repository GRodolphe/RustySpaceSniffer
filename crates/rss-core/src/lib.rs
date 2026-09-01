//! Core data model for RustySpaceSniffer (SPEC.md §5.2).
//!
//! Flat-arena tree with `u32` indices, parent pointers, sibling links, and
//! incrementally maintained size/file-count aggregates. Pure Rust, no platform
//! or GUI dependencies.
#![forbid(unsafe_code)]

/// Index into the tree arena.
pub type NodeId = u32;

/// 100-ns ticks since 1601-01-01 UTC (Windows FILETIME representation).
/// Cross-platform: non-Windows scanners convert from Unix time.
pub type FileTime = i64;

/// 100-ns intervals between 1601-01-01 and 1970-01-01.
const FILETIME_UNIX_EPOCH_DELTA: i64 = 116_444_736_000_000_000;

/// Convert seconds since the Unix epoch to a [`FileTime`].
pub fn filetime_from_unix(secs: i64) -> FileTime {
    secs * 10_000_000 + FILETIME_UNIX_EPOCH_DELTA
}

/// Convert a [`FileTime`] to seconds since the Unix epoch.
pub fn filetime_to_unix(ft: FileTime) -> i64 {
    (ft - FILETIME_UNIX_EPOCH_DELTA) / 10_000_000
}

/// What a node represents (SPEC.md §5.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum NodeKind {
    #[default]
    File,
    Directory,
    /// NTFS Alternate Data Stream attached to a host file.
    Ads,
    /// Free-space pseudo element (drive root views, FR-3.13).
    FreeSpace,
    /// Not-yet-scanned pseudo element shown during progressive scans (FR-2.9).
    UnknownSpace,
    /// Subtree that could not be read (FR-2.8).
    Unaccessible,
}

/// Temporary tag colors (FR-5.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Tag {
    Red,
    Yellow,
    Green,
    Blue,
}

/// File attribute + internal flags (SPEC.md §5.2 "Attributes").
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct NodeFlags(pub u32);

impl NodeFlags {
    pub const ARCHIVE: Self = Self(1 << 0);
    pub const SYSTEM: Self = Self(1 << 1);
    pub const READONLY: Self = Self(1 << 2);
    pub const HIDDEN: Self = Self(1 << 3);
    pub const COMPRESSED: Self = Self(1 << 4);
    pub const ENCRYPTED: Self = Self(1 << 5);
    pub const OFFLINE: Self = Self(1 << 6);
    pub const TEMPORARY: Self = Self(1 << 7);
    pub const NOT_INDEXED: Self = Self(1 << 8);
    pub const SPARSE: Self = Self(1 << 9);
    pub const ADS: Self = Self(1 << 10);
    // Internal flags.
    pub const REPARSE_POINT: Self = Self(1 << 16);
    pub const CLOUD_PLACEHOLDER: Self = Self(1 << 17);
    pub const ACCESS_DENIED: Self = Self(1 << 18);
    pub const HARDLINK_ALIAS: Self = Self(1 << 19);

    pub fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub fn insert(&mut self, other: Self) {
        self.0 |= other.0;
    }
}

/// Parameters for adding a node to a [`Tree`].
#[derive(Clone, Debug, Default)]
pub struct NodeParams {
    pub name: Box<str>,
    pub kind: NodeKind,
    pub flags: NodeFlags,
    pub tag: Option<Tag>,
    pub logical_size: u64,
    pub allocated_size: u64,
    pub ads_size: u64,
    pub created: FileTime,
    pub accessed: FileTime,
    pub modified: FileTime,
}

impl NodeParams {
    pub fn named(name: impl Into<String>, kind: NodeKind) -> Self {
        Self {
            name: name.into().into_boxed_str(),
            kind,
            ..Default::default()
        }
    }

    pub fn sizes(mut self, logical: u64, allocated: u64) -> Self {
        self.logical_size = logical;
        self.allocated_size = allocated;
        self
    }

    pub fn flags(mut self, flags: NodeFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn modified(mut self, modified: FileTime) -> Self {
        self.modified = modified;
        self
    }
}

/// A tree node. Own sizes are the element's own bytes; `agg_*` fields include
/// all descendants and are maintained incrementally by [`Tree`].
#[derive(Clone, Debug)]
pub struct Node {
    pub parent: Option<NodeId>,
    pub first_child: Option<NodeId>,
    pub next_sibling: Option<NodeId>,
    pub name: Box<str>,
    pub kind: NodeKind,
    pub flags: NodeFlags,
    pub tag: Option<Tag>,
    pub logical_size: u64,
    pub allocated_size: u64,
    pub ads_size: u64,
    pub agg_logical: u64,
    pub agg_allocated: u64,
    pub agg_files: u64,
    pub agg_dirs: u64,
    pub created: FileTime,
    pub accessed: FileTime,
    pub modified: FileTime,
}

impl Node {
    fn from_params(params: NodeParams) -> Self {
        let is_file = matches!(params.kind, NodeKind::File | NodeKind::Ads);
        let is_dir = params.kind == NodeKind::Directory;
        Self {
            parent: None,
            first_child: None,
            next_sibling: None,
            name: params.name,
            kind: params.kind,
            flags: params.flags,
            tag: params.tag,
            logical_size: params.logical_size,
            allocated_size: params.allocated_size,
            ads_size: params.ads_size,
            agg_logical: params.logical_size,
            agg_allocated: params.allocated_size + params.ads_size,
            agg_files: u64::from(is_file),
            agg_dirs: u64::from(is_dir),
            created: params.created,
            accessed: params.accessed,
            modified: params.modified,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.kind == NodeKind::Directory
    }
}

#[derive(Clone, Copy)]
struct Delta {
    logical: i128,
    allocated: i128,
    files: i128,
    dirs: i128,
}

impl Delta {
    fn negated(self) -> Self {
        Self {
            logical: -self.logical,
            allocated: -self.allocated,
            files: -self.files,
            dirs: -self.dirs,
        }
    }
}

/// Flat-arena tree. Removal is lazy: removed subtrees leave their arena slots
/// on a free list for reuse (a compaction pass is a post-v1 option).
#[derive(Clone, Debug, Default)]
pub struct Tree {
    arena: Vec<Node>,
    free: Vec<NodeId>,
    root: Option<NodeId>,
}

impl Tree {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a tree with a root node (typically a directory).
    pub fn with_root(params: NodeParams) -> Self {
        let mut tree = Self::new();
        let root = tree.alloc(Node::from_params(params));
        tree.root = Some(root);
        tree
    }

    pub fn root(&self) -> Option<NodeId> {
        self.root
    }

    /// Number of live nodes (excluding recycled free slots).
    pub fn len(&self) -> usize {
        self.arena.len() - self.free.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.arena[id as usize]
    }

    pub fn node_mut(&mut self, id: NodeId) -> &mut Node {
        &mut self.arena[id as usize]
    }

    fn alloc(&mut self, node: Node) -> NodeId {
        if let Some(id) = self.free.pop() {
            self.arena[id as usize] = node;
            id
        } else {
            let id = u32::try_from(self.arena.len())
                .expect("tree exceeds u32 node capacity (SPEC.md §5.2 scope limit)");
            self.arena.push(node);
            id
        }
    }

    fn delta_of(&self, id: NodeId) -> Delta {
        let n = self.node(id);
        Delta {
            logical: n.agg_logical as i128,
            allocated: n.agg_allocated as i128,
            files: n.agg_files as i128,
            dirs: n.agg_dirs as i128,
        }
    }

    /// Apply `delta` to `from` and all its ancestors, O(depth).
    fn propagate(&mut self, from: NodeId, delta: Delta) {
        let mut cur = Some(from);
        while let Some(id) = cur {
            let n = &mut self.arena[id as usize];
            n.agg_logical = (n.agg_logical as i128 + delta.logical) as u64;
            n.agg_allocated = (n.agg_allocated as i128 + delta.allocated) as u64;
            n.agg_files = (n.agg_files as i128 + delta.files) as u64;
            n.agg_dirs = (n.agg_dirs as i128 + delta.dirs) as u64;
            cur = n.parent;
        }
    }

    /// Add a child node under `parent`, propagating its aggregates to all
    /// ancestors.
    pub fn add_child(&mut self, parent: NodeId, params: NodeParams) -> NodeId {
        let mut node = Node::from_params(params);
        node.parent = Some(parent);
        node.next_sibling = self.arena[parent as usize].first_child;
        let id = self.alloc(node);
        self.arena[parent as usize].first_child = Some(id);
        self.propagate(parent, self.delta_of(id));
        id
    }

    /// Adjust a node's own sizes (e.g. a file updated by a live watcher) and
    /// propagate the delta to the node itself and all ancestors.
    pub fn set_own_sizes(&mut self, id: NodeId, logical: u64, allocated: u64, ads: u64) {
        let n = self.node(id);
        let delta = Delta {
            logical: logical as i128 - n.logical_size as i128,
            allocated: (allocated + ads) as i128 - (n.allocated_size + n.ads_size) as i128,
            files: 0,
            dirs: 0,
        };
        let n = self.node_mut(id);
        n.logical_size = logical;
        n.allocated_size = allocated;
        n.ads_size = ads;
        self.propagate(id, delta);
    }

    /// Remove a subtree, propagating negative deltas to ancestors. Arena slots
    /// are recycled; ids inside the removed subtree must not be used again.
    pub fn remove_subtree(&mut self, id: NodeId) {
        let delta = self.delta_of(id).negated();
        match self.node(id).parent {
            Some(parent) => {
                self.unlink_child(parent, id);
                self.propagate(parent, delta);
            }
            None => self.root = None,
        }
        // Recycle the whole subtree.
        let mut stack = vec![id];
        while let Some(cur) = stack.pop() {
            let mut child = self.arena[cur as usize].first_child;
            while let Some(c) = child {
                stack.push(c);
                child = self.arena[c as usize].next_sibling;
            }
            self.free.push(cur);
        }
    }

    fn unlink_child(&mut self, parent: NodeId, id: NodeId) {
        let first = self.arena[parent as usize].first_child;
        if first == Some(id) {
            self.arena[parent as usize].first_child = self.arena[id as usize].next_sibling;
            return;
        }
        let mut cur = first;
        while let Some(c) = cur {
            let next = self.arena[c as usize].next_sibling;
            if next == Some(id) {
                self.arena[c as usize].next_sibling = self.arena[id as usize].next_sibling;
                return;
            }
            cur = next;
        }
    }

    /// Iterate over the children of `parent`.
    pub fn children(&self, parent: NodeId) -> Children<'_> {
        Children {
            arena: &self.arena,
            next: self.node(parent).first_child,
        }
    }

    /// Path components from the root down to `id` (root first).
    pub fn path_components(&self, id: NodeId) -> Vec<&str> {
        let mut parts = Vec::new();
        let mut cur = Some(id);
        while let Some(c) = cur {
            let n = self.node(c);
            parts.push(&*n.name);
            cur = n.parent;
        }
        parts.reverse();
        parts
    }

    /// Filesystem path of `id` (root name is the first component).
    pub fn path(&self, id: NodeId) -> std::path::PathBuf {
        self.path_components(id).iter().collect()
    }
}

/// Iterator over a node's children.
pub struct Children<'a> {
    arena: &'a [Node],
    next: Option<NodeId>,
}

impl Iterator for Children<'_> {
    type Item = NodeId;

    fn next(&mut self) -> Option<NodeId> {
        let id = self.next?;
        self.next = self.arena[id as usize].next_sibling;
        Some(id)
    }
}

#[cfg(test)]
mod tests;
