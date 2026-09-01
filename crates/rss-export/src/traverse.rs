//! Shared traversal helpers for the exporters.

use rss_core::{NodeId, NodeKind, Tree};

use crate::SizeMode;

/// Children of `parent` ordered by descending size per `mode`. The sort is
/// stable, so equal-sized siblings keep the tree's child order.
pub(crate) fn sorted_children(tree: &Tree, parent: NodeId, mode: SizeMode) -> Vec<NodeId> {
    let key = |id: NodeId| {
        let n = tree.node(id);
        match mode {
            SizeMode::Allocated => n.agg_allocated,
            SizeMode::Logical => n.agg_logical,
        }
    };
    let mut children: Vec<NodeId> = tree.children(parent).collect();
    children.sort_by_key(|&id| std::cmp::Reverse(key(id)));
    children
}

/// Lowercase string form of a node kind, used in the `kind` column/field.
pub(crate) fn kind_str(kind: NodeKind) -> &'static str {
    match kind {
        NodeKind::File => "file",
        NodeKind::Directory => "directory",
        NodeKind::Ads => "ads",
        NodeKind::FreeSpace => "free_space",
        NodeKind::UnknownSpace => "unknown_space",
        NodeKind::Unaccessible => "unaccessible",
    }
}
