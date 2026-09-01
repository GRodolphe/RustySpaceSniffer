//! Recycle-bin deletion (SPEC.md §4.6, FR-6.4) and the [`DeletePlan`] the
//! confirmation dialog is built from.
//!
//! Deletion goes through the OS trash/recycle facility via the `trash` crate
//! — never a permanent delete (SPEC.md §9.3). Failures are collected **per
//! item**: one path that refuses to be trashed does not stop the rest of the
//! batch.
//!
//! Integration note (rss-app): build a [`DeletePlan`] from the current
//! selection, render the confirmation dialog from it (item list, true total,
//! filter-hiding warning per FR-6.4b), then call [`execute_plan`] on a worker
//! thread with a progress callback that drives the running freed-space
//! counter (FR-6.4c).

use std::path::{Path, PathBuf};

/// One entry selected for deletion.
#[derive(Clone, Debug)]
pub struct DeleteItem {
    /// Filesystem path handed to the recycle-bin API.
    pub path: PathBuf,
    /// True total bytes that deleting this item will free (allocated size of
    /// the whole subtree), regardless of what the active filter displays.
    pub total_bytes: u64,
    /// True when an active filter hides part of this item's contents
    /// (FR-6.4b). Computed by the caller — only rss-app knows the filter
    /// evaluation; rss-shell never interprets filters.
    pub hidden_by_filter: bool,
}

/// What a delete confirmation dialog needs (FR-6.4): the item list, the true
/// total that will be freed, and whether any filter-hidden content is about
/// to be deleted.
#[derive(Clone, Debug, Default)]
pub struct DeletePlan {
    items: Vec<DeleteItem>,
    total_bytes: u64,
}

impl DeletePlan {
    /// Build a plan from pre-resolved items.
    pub fn new(items: Vec<DeleteItem>) -> Self {
        let total_bytes = items.iter().map(|i| i.total_bytes).sum();
        Self { items, total_bytes }
    }

    /// Build a plan from a scanned tree: resolves each selected node to its
    /// filesystem path and takes the node's allocated-size aggregate as the
    /// true total. The filter-hiding flag is caller-computed (the caller owns
    /// the `rss-filter` evaluation), paired with each [`rss_core::NodeId`].
    pub fn from_tree(tree: &rss_core::Tree, selection: &[(rss_core::NodeId, bool)]) -> Self {
        let items = selection
            .iter()
            .map(|&(id, hidden_by_filter)| DeleteItem {
                path: tree.path(id),
                total_bytes: tree.node(id).agg_allocated,
                hidden_by_filter,
            })
            .collect();
        Self::new(items)
    }

    /// The items that will be deleted, in selection order.
    pub fn items(&self) -> &[DeleteItem] {
        &self.items
    }

    /// Number of top-level items in the plan.
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// True when the plan contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// True total bytes the deletion will free (FR-6.4b: the *true* total,
    /// including anything an active filter hides from view).
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// True when any item has filter-hidden contents; the confirmation dialog
    /// must warn explicitly in that case (FR-6.4b).
    pub fn has_filter_hidden_content(&self) -> bool {
        self.items.iter().any(|i| i.hidden_by_filter)
    }

    /// Items with filter-hidden contents, for the dialog's warning section.
    pub fn hidden_items(&self) -> impl Iterator<Item = &DeleteItem> {
        self.items.iter().filter(|i| i.hidden_by_filter)
    }
}

/// A single path that could not be moved to the recycle bin.
#[derive(Debug, thiserror::Error)]
#[error("could not move to the recycle bin: {}", path.display())]
pub struct DeleteFailure {
    /// The path that failed.
    pub path: PathBuf,
    /// Underlying error from the OS trash facility.
    #[source]
    pub source: trash::Error,
}

/// One or more items of a batch could not be trashed. Items not listed here
/// were deleted successfully (per-item error collection, FR-6.4).
#[derive(Debug, thiserror::Error)]
#[error("{} item(s) could not be moved to the recycle bin", .failures.len())]
pub struct DeleteError {
    /// Per-item failures, in input order.
    pub failures: Vec<DeleteFailure>,
}

/// Move every path in `paths` to the OS recycle bin / trash.
///
/// Each path is deleted individually so one failure does not abort the batch;
/// all failures are collected into [`DeleteError`]. Returns `Ok(())` when
/// every path was deleted.
///
/// On Windows the `trash` crate shows the shell's own recycle-bin progress UI
/// per call; for batch deletes prefer [`execute_plan`], which reports
/// progress between items.
pub fn delete_to_recycle_bin<I, P>(paths: I) -> Result<(), DeleteError>
where
    I: IntoIterator<Item = P>,
    P: AsRef<Path>,
{
    let mut failures = Vec::new();
    for path in paths {
        let path = path.as_ref();
        if let Err(source) = trash::delete(path) {
            failures.push(DeleteFailure {
                path: path.to_path_buf(),
                source,
            });
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(DeleteError { failures })
    }
}

/// Execute a [`DeletePlan`]: trash each item in order, invoking
/// `on_progress` with the item after each successful delete.
///
/// The progress callback is what drives the confirmation dialog's running
/// freed-space counter (FR-6.4c): accumulate `item.total_bytes` per call.
/// Deletion continues past failures; all of them are reported in the
/// returned [`DeleteError`].
pub fn execute_plan(
    plan: &DeletePlan,
    mut on_progress: impl FnMut(&DeleteItem),
) -> Result<(), DeleteError> {
    let mut failures = Vec::new();
    for item in &plan.items {
        match trash::delete(&item.path) {
            Ok(()) => on_progress(item),
            Err(source) => failures.push(DeleteFailure {
                path: item.path.clone(),
                source,
            }),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(DeleteError { failures })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a temp tree where the platform trash applies. On Unix the
    /// freedesktop "home trash" only applies on the home filesystem (the trash
    /// crate picks a trash folder per mount point), so use $HOME; on Windows
    /// the Recycle Bin works per-drive, so a plain tempdir is fine.
    fn home_tempdir() -> tempfile::TempDir {
        #[cfg(windows)]
        {
            tempfile::tempdir().expect("create tempdir")
        }
        #[cfg(not(windows))]
        {
            let home = std::env::var_os("HOME").expect("HOME must be set for trash tests");
            tempfile::tempdir_in(home).expect("create tempdir under $HOME")
        }
    }

    #[test]
    fn deletes_file_and_directory_tree() {
        let dir = home_tempdir();
        let file = dir.path().join("note.txt");
        std::fs::write(&file, b"hello").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("inner.bin"), vec![0u8; 4096]).unwrap();

        delete_to_recycle_bin([&file, &sub]).unwrap();

        assert!(!file.exists(), "file should be gone after trashing");
        assert!(
            !sub.exists(),
            "directory tree should be gone after trashing"
        );
        // The parent temp dir itself is still there.
        assert!(dir.path().exists());
    }

    #[test]
    fn collects_per_item_errors_and_continues() {
        let dir = home_tempdir();
        let good = dir.path().join("good.txt");
        std::fs::write(&good, b"x").unwrap();
        let missing = dir.path().join("does-not-exist.txt");

        let err = delete_to_recycle_bin([&missing, &good]).unwrap_err();

        assert_eq!(err.failures.len(), 1);
        assert_eq!(err.failures[0].path, missing);
        // The batch continued past the failure.
        assert!(!good.exists(), "later items are still deleted");
    }

    #[test]
    fn plan_computes_true_total_and_hidden_flag() {
        let plan = DeletePlan::new(vec![
            DeleteItem {
                path: PathBuf::from("/a/big"),
                total_bytes: 1000,
                hidden_by_filter: false,
            },
            DeleteItem {
                path: PathBuf::from("/a/filtered"),
                total_bytes: 250,
                hidden_by_filter: true,
            },
        ]);
        assert_eq!(plan.len(), 2);
        assert!(!plan.is_empty());
        assert_eq!(plan.total_bytes(), 1250);
        assert!(plan.has_filter_hidden_content());
        assert_eq!(plan.hidden_items().count(), 1);
        assert_eq!(plan.hidden_items().next().unwrap().total_bytes, 250);
    }

    #[test]
    fn empty_plan_is_noop() {
        let plan = DeletePlan::default();
        assert!(plan.is_empty());
        assert_eq!(plan.total_bytes(), 0);
        assert!(!plan.has_filter_hidden_content());
        execute_plan(&plan, |_| panic!("no items, no progress")).unwrap();
        delete_to_recycle_bin(Vec::<&Path>::new()).unwrap();
    }

    #[test]
    fn execute_plan_reports_progress_for_freed_counter() {
        let dir = home_tempdir();
        let a = dir.path().join("a.txt");
        let b = dir.path().join("b.txt");
        std::fs::write(&a, b"aa").unwrap();
        std::fs::write(&b, b"bbb").unwrap();

        let plan = DeletePlan::new(vec![
            DeleteItem {
                path: a.clone(),
                total_bytes: 2,
                hidden_by_filter: false,
            },
            DeleteItem {
                path: b.clone(),
                total_bytes: 3,
                hidden_by_filter: false,
            },
        ]);

        let mut freed = 0u64;
        execute_plan(&plan, |item| freed += item.total_bytes).unwrap();

        assert_eq!(freed, 5, "progress callback accumulates the freed bytes");
        assert!(!a.exists() && !b.exists());
    }

    #[test]
    fn plan_from_tree_uses_aggregate_allocated_size() {
        let mut tree = rss_core::Tree::with_root(rss_core::NodeParams::named(
            "root",
            rss_core::NodeKind::Directory,
        ));
        let root = tree.root().unwrap();
        let file = tree.add_child(
            root,
            rss_core::NodeParams::named("f.bin", rss_core::NodeKind::File).sizes(100, 4096),
        );
        let plan = DeletePlan::from_tree(&tree, &[(file, true)]);
        assert_eq!(plan.total_bytes(), 4096);
        assert!(plan.has_filter_hidden_content());
        assert_eq!(
            plan.items()[0].path,
            std::path::Path::new("root").join("f.bin")
        );
    }
}
