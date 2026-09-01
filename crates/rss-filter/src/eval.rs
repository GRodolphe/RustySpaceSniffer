//! Filter evaluation over an `rss-core` tree (SPEC.md §5.6 steps 2–3).
//!
//! [`Filter::matches`] is the raw per-node pass/fail, combining conditions
//! exactly per FR-4.10:
//!
//! - inclusion conditions — non-negated file masks, folder masks, tags, and
//!   classes — are OR-ed together (one match is enough);
//! - exclusion conditions — negated masks, folder masks, tags, classes, and
//!   attributes — are AND-ed (matching any single one excludes the node);
//! - all other conditions (size, age, non-negated attributes) are AND-ed.
//!
//! [`evaluate`] lifts that to the tri-state [`FilterVerdict`] (FR-4.11).

use rss_core::{FileTime, NodeId, Tree};

use crate::ast::{AgeField, ConditionKind, SizeMetric, TagSet};
use crate::glob::glob_match;
use crate::Filter;

/// Tri-state outcome of evaluating a filter against one node (FR-4.11, §5.6).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum FilterVerdict {
    /// The node itself passes all filter conditions.
    Visible,
    /// The node fails the filter, but at least one node in its subtree
    /// passes; it stays on the map as dimmed context leading to the matches.
    Dimmed,
    /// The node fails the filter and nothing in its subtree passes.
    Hidden,
}

/// Evaluate `filter` against node `id` of `tree` (SPEC.md §5.6 step 2).
///
/// `now` is the reference time for age conditions (FR-4.5); ages are computed
/// at evaluation time, so a filter never needs reparsing as time passes.
///
/// # Verdict semantics (documented judgment call)
///
/// FR-4.11 specifies that filtered-out elements are dimmed in place
/// (toggleable to hard-hide) but leaves the exact dimmed/hidden split open.
/// Here `Dimmed` marks failing nodes that must remain visible as containers
/// of matching descendants, and `Hidden` marks failing nodes whose whole
/// subtree fails. A renderer in the default FR-4.11 mode paints both dimmed
/// (30% opacity + desaturation); in hard-hide mode it can skip `Hidden`
/// subtrees entirely without evaluating their children.
///
/// # Performance
///
/// `Dimmed`/`Hidden` resolution scans the subtree below `id`, and folder
/// masks (FR-4.3) and tag inheritance (FR-5.2) walk the parent chain on every
/// call. Per-directory caching of ancestor matching and of subtree results is
/// a documented later optimization (§5.6); correctness does not depend on it.
pub fn evaluate(tree: &Tree, id: NodeId, filter: &Filter, now: FileTime) -> FilterVerdict {
    if filter.matches(tree, id, now) {
        return FilterVerdict::Visible;
    }
    if subtree_has_match(tree, id, filter, now) {
        FilterVerdict::Dimmed
    } else {
        FilterVerdict::Hidden
    }
}

impl Filter {
    /// Raw pass/fail of the filter against a single node, combining
    /// conditions per FR-4.10 (see module docs).
    pub fn matches(&self, tree: &Tree, id: NodeId, now: FileTime) -> bool {
        let mut inclusion_seen = false;
        let mut inclusion_hit = false;
        for cond in self.conditions() {
            match &cond.kind {
                // Inclusion group (OR-ed): masks, folder masks, tags, classes.
                ConditionKind::FileMask { negated: false, .. }
                | ConditionKind::FolderMask { negated: false, .. }
                | ConditionKind::Tag { negated: false, .. }
                | ConditionKind::Class { negated: false, .. } => {
                    inclusion_seen = true;
                    inclusion_hit = inclusion_hit || condition_matches(tree, id, &cond.kind, now);
                }
                // Exclusions (AND-ed): a single match excludes the node.
                ConditionKind::FileMask { negated: true, .. }
                | ConditionKind::FolderMask { negated: true, .. }
                | ConditionKind::Tag { negated: true, .. }
                | ConditionKind::Class { negated: true, .. }
                | ConditionKind::Attr { negated: true, .. } => {
                    if condition_matches(tree, id, &cond.kind, now) {
                        return false;
                    }
                }
                // All other conditions (AND-ed).
                ConditionKind::Size { .. }
                | ConditionKind::Age { .. }
                | ConditionKind::Attr { negated: false, .. } => {
                    if !condition_matches(tree, id, &cond.kind, now) {
                        return false;
                    }
                }
            }
        }
        !inclusion_seen || inclusion_hit
    }
}

/// Whether the subtree below `id` (exclusive) contains any node passing the
/// filter. Recursion depth equals the tree depth below `id`.
fn subtree_has_match(tree: &Tree, id: NodeId, filter: &Filter, now: FileTime) -> bool {
    tree.children(id)
        .any(|c| filter.matches(tree, c, now) || subtree_has_match(tree, c, filter, now))
}

fn condition_matches(tree: &Tree, id: NodeId, kind: &ConditionKind, now: FileTime) -> bool {
    let node = tree.node(id);
    match kind {
        ConditionKind::FileMask { pattern, .. } => glob_match(pattern, &node.name),
        ConditionKind::FolderMask { pattern, .. } => {
            // FR-4.3: matches if the node itself (when a directory) or any
            // ancestor directory name matches. Walks the parent chain per
            // call; per-directory caching is a later optimization (§5.6).
            let mut cur = Some(id);
            while let Some(c) = cur {
                let n = tree.node(c);
                if n.is_dir() && glob_match(pattern, &n.name) {
                    return true;
                }
                cur = n.parent;
            }
            false
        }
        ConditionKind::Size { metric, op, bytes } => {
            // Own sizes, not aggregates (§5.2): directories therefore rarely
            // pass size conditions and appear as dimmed context instead.
            let value = match metric {
                SizeMetric::Disk => node.allocated_size,
                SizeMetric::Logical => node.logical_size,
            };
            op.apply(value, *bytes)
        }
        ConditionKind::Age { field, op, seconds } => {
            let ts = match field {
                AgeField::Creation => node.created,
                AgeField::Modify => node.modified,
                AgeField::Access => node.accessed,
            };
            // FILETIME ticks are 100 ns; future timestamps clamp to age 0.
            let age_secs = now.saturating_sub(ts).max(0) as u64 / 10_000_000;
            op.apply(age_secs, *seconds)
        }
        ConditionKind::Tag { expr, .. } => expr.matches(effective_tags(tree, id)),
        ConditionKind::Attr { tests, .. } => tests.iter().all(|t| t.matches(node.flags)),
        ConditionKind::Class { extensions, .. } => match node.name.rsplit_once('.') {
            Some((_, ext)) => {
                !ext.is_empty() && extensions.iter().any(|e| e.eq_ignore_ascii_case(ext))
            }
            None => false,
        },
    }
}

/// FR-5.2: a node's own tag plus all ancestor tags count for filtering.
fn effective_tags(tree: &Tree, id: NodeId) -> TagSet {
    let mut set = TagSet::EMPTY;
    let mut cur = Some(id);
    while let Some(c) = cur {
        let n = tree.node(c);
        if let Some(tag) = n.tag {
            set.insert(tag);
        }
        cur = n.parent;
    }
    set
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::FileClass;
    use rss_core::{filetime_from_unix, NodeFlags, NodeKind, NodeParams, Tag};
    use std::collections::HashMap;

    const DAY_TICKS: i64 = 86_400 * 10_000_000;

    fn now() -> FileTime {
        filetime_from_unix(1_800_000_000)
    }

    fn days_ago(d: i64) -> FileTime {
        now() - d * DAY_TICKS
    }

    /// Test tree:
    /// ```text
    /// C:\                          (dir)
    /// ├── photos\                  (dir)
    /// │   ├── a.jpg                2 MiB, modified 60 d ago
    /// │   └── b.txt                10 B,  modified 10 d ago
    /// ├── temp\                    (dir, tagged red)
    /// │   └── c.gif                200 KiB, modified 5 d ago
    /// ├── internet cache\          (dir)
    /// │   └── page.html            1000 B
    /// ├── big.bin                  5 MiB, modified 400 d ago, tagged yellow
    /// ├── hid.dat                  100 B, hidden attribute
    /// └── song.mp3                 3 MiB
    /// ```
    struct Fixture {
        tree: Tree,
        ids: HashMap<&'static str, NodeId>,
        classes: Vec<FileClass>,
    }

    fn fixture() -> Fixture {
        let mut tree = Tree::with_root(NodeParams::named("C:", NodeKind::Directory));
        let root = tree.root().unwrap();
        let mut ids = HashMap::new();
        ids.insert("root", root);

        let photos = tree.add_child(root, NodeParams::named("photos", NodeKind::Directory));
        ids.insert("photos", photos);
        ids.insert(
            "a.jpg",
            tree.add_child(
                photos,
                NodeParams::named("a.jpg", NodeKind::File)
                    .sizes(2 << 20, 2 << 20)
                    .modified(days_ago(60)),
            ),
        );
        ids.insert(
            "b.txt",
            tree.add_child(
                photos,
                NodeParams::named("b.txt", NodeKind::File)
                    .sizes(10, 10)
                    .modified(days_ago(10)),
            ),
        );

        let temp = tree.add_child(
            root,
            NodeParams {
                name: "temp".into(),
                kind: NodeKind::Directory,
                tag: Some(Tag::Red),
                ..Default::default()
            },
        );
        ids.insert("temp", temp);
        ids.insert(
            "c.gif",
            tree.add_child(
                temp,
                NodeParams::named("c.gif", NodeKind::File)
                    .sizes(200 * 1024, 200 * 1024)
                    .modified(days_ago(5)),
            ),
        );

        let inet = tree.add_child(
            root,
            NodeParams::named("internet cache", NodeKind::Directory),
        );
        ids.insert("internet cache", inet);
        ids.insert(
            "page.html",
            tree.add_child(
                inet,
                NodeParams::named("page.html", NodeKind::File)
                    .sizes(1000, 1000)
                    .modified(days_ago(1)),
            ),
        );

        ids.insert(
            "big.bin",
            tree.add_child(
                root,
                NodeParams {
                    tag: Some(Tag::Yellow),
                    accessed: days_ago(500),
                    ..NodeParams::named("big.bin", NodeKind::File)
                        .sizes(5 << 20, 5 << 20)
                        .modified(days_ago(400))
                },
            ),
        );
        ids.insert(
            "hid.dat",
            tree.add_child(
                root,
                NodeParams::named("hid.dat", NodeKind::File)
                    .sizes(100, 100)
                    .flags(NodeFlags::HIDDEN)
                    .modified(days_ago(1)),
            ),
        );
        ids.insert(
            "song.mp3",
            tree.add_child(
                root,
                NodeParams::named("song.mp3", NodeKind::File)
                    .sizes(3 << 20, 3 << 20)
                    .modified(days_ago(2)),
            ),
        );

        let classes = vec![
            FileClass::new("Audio/Music", ["mp3", "wav"]),
            FileClass::new("Images", ["jpg", "gif"]),
        ];
        Fixture { tree, ids, classes }
    }

    impl Fixture {
        fn id(&self, name: &str) -> NodeId {
            self.ids[name]
        }

        /// Parse `filter` (asserting it is well-formed) and evaluate `name`.
        fn verdict(&self, filter: &str, name: &str) -> FilterVerdict {
            let f = Filter::parse(filter, &self.classes);
            assert!(
                f.warnings().is_empty(),
                "unexpected warnings for {filter:?}: {:?}",
                f.warnings()
            );
            evaluate(&self.tree, self.id(name), &f, now())
        }

        fn matches(&self, filter: &str, name: &str) -> bool {
            let f = Filter::parse(filter, &self.classes);
            assert!(
                f.warnings().is_empty(),
                "unexpected warnings for {filter:?}: {:?}",
                f.warnings()
            );
            f.matches(&self.tree, self.id(name), now())
        }
    }

    #[test]
    fn empty_filter_shows_everything() {
        let fx = fixture();
        for name in [
            "root", "photos", "a.jpg", "b.txt", "temp", "c.gif", "big.bin",
        ] {
            assert_eq!(fx.verdict("", name), FilterVerdict::Visible, "{name}");
        }
    }

    #[test]
    fn file_mask_verdicts() {
        let fx = fixture();
        assert_eq!(fx.verdict("*.jpg", "a.jpg"), FilterVerdict::Visible);
        assert_eq!(fx.verdict("*.jpg", "b.txt"), FilterVerdict::Hidden);
        // Containers of matches stay as dimmed context; others are hidden.
        assert_eq!(fx.verdict("*.jpg", "photos"), FilterVerdict::Dimmed);
        assert_eq!(fx.verdict("*.jpg", "root"), FilterVerdict::Dimmed);
        assert_eq!(fx.verdict("*.jpg", "temp"), FilterVerdict::Hidden);
    }

    #[test]
    fn folder_mask_ancestor_matching() {
        let fx = fixture();
        assert_eq!(fx.verdict("\\temp", "c.gif"), FilterVerdict::Visible);
        assert_eq!(fx.verdict("\\temp", "temp"), FilterVerdict::Visible);
        assert_eq!(fx.verdict("\\temp", "photos"), FilterVerdict::Hidden);
        assert_eq!(fx.verdict("\\temp", "root"), FilterVerdict::Dimmed);
        // Wildcard folder mask from the manual (FR-4.3).
        assert_eq!(
            fx.verdict("\\*internet*", "page.html"),
            FilterVerdict::Visible
        );
        assert_eq!(fx.verdict("\\*internet*", "a.jpg"), FilterVerdict::Hidden);
        // Negated folder mask.
        assert_eq!(fx.verdict("|\\temp", "c.gif"), FilterVerdict::Hidden);
        assert_eq!(fx.verdict("|\\temp", "a.jpg"), FilterVerdict::Visible);
    }

    #[test]
    fn tags_and_inheritance() {
        let fx = fixture();
        // FR-5.2: children inherit ancestor tags for filtering.
        assert_eq!(fx.verdict(":red", "temp"), FilterVerdict::Visible);
        assert_eq!(fx.verdict(":red", "c.gif"), FilterVerdict::Visible);
        assert_eq!(fx.verdict(":red", "a.jpg"), FilterVerdict::Hidden);
        assert_eq!(fx.verdict(":all", "big.bin"), FilterVerdict::Visible);
        // 2.x expression: red or green, but not blue.
        assert_eq!(
            fx.verdict(":tag:red+green-b", "c.gif"),
            FilterVerdict::Visible
        );
        assert_eq!(
            fx.verdict(":tag:red+green-b", "big.bin"),
            FilterVerdict::Hidden
        );
        // Negated legacy tag.
        assert_eq!(fx.verdict("|:yellow", "a.jpg"), FilterVerdict::Visible);
        assert_eq!(fx.verdict("|:yellow", "big.bin"), FilterVerdict::Hidden);
    }

    #[test]
    fn size_conditions() {
        let fx = fixture();
        assert_eq!(fx.verdict(">1mb", "a.jpg"), FilterVerdict::Visible); // 2 MiB
        assert_eq!(fx.verdict(">1mb", "c.gif"), FilterVerdict::Hidden); // 200 KiB
        assert_eq!(fx.verdict("<1kb", "b.txt"), FilterVerdict::Visible);
        assert_eq!(
            fx.verdict("filesize>4mb", "big.bin"),
            FilterVerdict::Visible
        );
        // Directories use their own (near-zero) sizes, so they fail and show
        // as dimmed context.
        assert_eq!(fx.verdict(">1mb", "root"), FilterVerdict::Dimmed);
    }

    #[test]
    fn age_conditions() {
        let fx = fixture();
        assert_eq!(fx.verdict(">1year", "big.bin"), FilterVerdict::Visible); // 400 d
        assert_eq!(fx.verdict(">1year", "a.jpg"), FilterVerdict::Hidden); // 60 d
        assert_eq!(fx.verdict("<3months", "a.jpg"), FilterVerdict::Visible);
        assert_eq!(fx.verdict("<1months", "a.jpg"), FilterVerdict::Hidden);
        assert_eq!(fx.verdict("a>1year", "big.bin"), FilterVerdict::Visible); // access 500 d
        assert_eq!(fx.verdict("m<1weeks", "c.gif"), FilterVerdict::Visible); // 5 d
    }

    #[test]
    fn attr_conditions() {
        let fx = fixture();
        assert_eq!(fx.verdict(":attr:+h", "hid.dat"), FilterVerdict::Visible);
        assert_eq!(fx.verdict(":attr:+h", "a.jpg"), FilterVerdict::Hidden);
        // Manual example shape: must-be-set AND must-be-clear.
        assert_eq!(fx.verdict(":attr:-ro,h", "hid.dat"), FilterVerdict::Visible);
        assert_eq!(fx.verdict(":attr:+a,h", "hid.dat"), FilterVerdict::Hidden);
        // Negated attr acts as an exclusion.
        assert_eq!(fx.verdict("|:attr:h", "a.jpg"), FilterVerdict::Visible);
        assert_eq!(fx.verdict("|:attr:h", "hid.dat"), FilterVerdict::Hidden);
    }

    #[test]
    fn class_conditions() {
        let fx = fixture();
        assert_eq!(
            fx.verdict(":class:Audio/Music", "song.mp3"),
            FilterVerdict::Visible
        );
        assert_eq!(
            fx.verdict(":class:Audio/Music", "a.jpg"),
            FilterVerdict::Hidden
        );
        assert_eq!(
            fx.verdict("|:class:Audio/Music", "a.jpg"),
            FilterVerdict::Visible
        );
        assert_eq!(
            fx.verdict("|:class:Audio/Music", "song.mp3"),
            FilterVerdict::Hidden
        );
    }

    /// Canonical manual example end to end: `*.jpg;>1mb;<3months;|:yellow`.
    #[test]
    fn canonical_manual_example_end_to_end() {
        let fx = fixture();
        // a.jpg: 2 MiB, 60 days old, untagged -> visible.
        assert_eq!(
            fx.verdict("*.jpg;>1mb;<3months;|:yellow", "a.jpg"),
            FilterVerdict::Visible
        );
        // big.bin: not a jpg, too old, and tagged yellow -> hidden.
        assert_eq!(
            fx.verdict("*.jpg;>1mb;<3months;|:yellow", "big.bin"),
            FilterVerdict::Hidden
        );
        // c.gif: not a jpg -> hidden; its parent temp has no matches.
        assert_eq!(
            fx.verdict("*.jpg;>1mb;<3months;|:yellow", "temp"),
            FilterVerdict::Hidden
        );
        assert_eq!(
            fx.verdict("*.jpg;>1mb;<3months;|:yellow", "photos"),
            FilterVerdict::Dimmed
        );
    }

    /// Truth table for the FR-4.10 combination rules: inclusion masks, tags
    /// and classes are OR-ed; exclusion masks are AND-ed; every other
    /// condition type is AND-ed.
    #[cfg(test)]
    mod truth_table {
        use super::*;

        /// Each row is `(filter, node, expected passes)`.
        #[test]
        fn fr_4_10_combinations() {
            let fx = fixture();
            let cases: &[(&str, &str, bool)] = &[
                // Two inclusion masks are OR-ed.
                ("*.jpg;*.gif", "a.jpg", true),
                ("*.jpg;*.gif", "c.gif", true),
                ("*.jpg;*.gif", "b.txt", false),
                // Inclusion mask OR tag.
                ("*.jpg;:red", "a.jpg", true),
                ("*.jpg;:red", "c.gif", true), // red inherited from `temp`
                ("*.jpg;:red", "b.txt", false),
                // Inclusion mask OR class.
                ("*.jpg;:class:Audio/Music", "a.jpg", true),
                ("*.jpg;:class:Audio/Music", "song.mp3", true),
                ("*.jpg;:class:Audio/Music", "b.txt", false),
                // Tag OR class, no mask involved.
                (":red;:class:Audio/Music", "c.gif", true),
                (":red;:class:Audio/Music", "song.mp3", true),
                (":red;:class:Audio/Music", "a.jpg", false),
                // Exclusion masks are AND-ed: each one excludes on its own.
                ("|*.jpg;|*.gif", "a.jpg", false),
                ("|*.jpg;|*.gif", "c.gif", false),
                ("|*.jpg;|*.gif", "b.txt", true),
                // Inclusion AND exclusion.
                ("*.jpg;|a*", "a.jpg", false),
                ("*.gif;|a*", "c.gif", true),
                // Size/age conditions AND with the inclusion group and with
                // each other.
                ("*.jpg;>1mb", "a.jpg", true),
                ("*.jpg;>3mb", "a.jpg", false),
                ("*.jpg;<3months", "a.jpg", true),
                ("*.jpg;>1mb;<3months", "a.jpg", true),
                ("*.jpg;>1mb;<1months", "a.jpg", false), // 60 d > 30 d
                (">1mb;<3months", "a.jpg", true),        // no inclusion group
                (">1mb;<3months", "big.bin", false),     // 400 d old
                // Attribute conditions AND with everything else.
                (":attr:+h;>50b", "hid.dat", true),
                (":attr:+h;>500b", "hid.dat", false),
                // Canonical manual example: mask AND size AND age AND NOT tag.
                ("*.jpg;>1mb;<3months;|:yellow", "a.jpg", true),
                ("*.jpg;>1mb;<3months;|:yellow", "big.bin", false),
                // Negated tag exclusion on its own.
                ("|:yellow", "a.jpg", true),
                ("|:yellow", "big.bin", false),
            ];
            for (filter, node, expected) in cases {
                assert_eq!(
                    fx.matches(filter, node),
                    *expected,
                    "filter `{filter}` on node `{node}`"
                );
            }
        }
    }
}
