//! File operations (SPEC.md §4.6): the right-click context menu's data
//! plumbing and the FR-6.4 delete-to-recycle-bin confirmation dialog state.
//! UI rendering lives in `mod.rs`; this module holds the logic so kittest
//! can drive it headlessly.

use std::path::PathBuf;

use rss_core::NodeId;
use rss_filter::FilterVerdict;
use rss_shell::DeletePlan;

use super::view::ScanView;

/// State of the delete confirmation dialog (FR-6.4).
pub struct DeleteDialog {
    /// What will be deleted (item list, true total, filter-hiding flags).
    pub plan: DeletePlan,
    /// Node ids being deleted (for the post-delete model fixup).
    pub nodes: Vec<NodeId>,
    /// Bytes freed so far (FR-6.4c running counter).
    pub freed: u64,
    /// Set once the worker thread starts.
    pub running: bool,
    /// Worker completion: Ok, or per-item failure messages.
    pub result: Option<Result<(), Vec<String>>>,
    /// Channel receiving worker progress.
    pub rx: Option<crossbeam_channel::Receiver<DeleteMsg>>,
    /// Set once the post-delete rescan has been triggered.
    pub rescanned: bool,
}

/// Progress from the delete worker thread.
pub enum DeleteMsg {
    /// One item was trashed; carries its freed bytes.
    Freed(u64),
    /// The batch finished.
    Done(Result<(), Vec<String>>),
}

/// Build the FR-6.4 confirmation plan for the selected node: the item list,
/// the true total (allocated aggregate, regardless of the filter), and the
/// filter-hiding flag (true when the active filter hides any part of the
/// subtree).
pub fn delete_plan_for(view: &ScanView, id: NodeId) -> DeleteDialog {
    // FR-6.4b: warn when an active filter hides part of the contents.
    let hidden = view.has_active_filter() && subtree_has_filtered_out(view, id);
    let plan = DeletePlan::from_tree(view.tree(), &[(id, hidden)]);
    DeleteDialog {
        plan,
        nodes: vec![id],
        freed: 0,
        running: false,
        result: None,
        rx: None,
        rescanned: false,
    }
}

/// Whether any node in the subtree is dimmed or hidden by the filter.
fn subtree_has_filtered_out(view: &ScanView, id: NodeId) -> bool {
    let mut stack = vec![id];
    while let Some(cur) = stack.pop() {
        if view.verdict(cur) != FilterVerdict::Visible {
            return true;
        }
        stack.extend(view.tree().children(cur));
    }
    false
}

/// Execute the plan on a worker thread, reporting freed bytes per item
/// (FR-6.4c) and the batch outcome.
pub fn start_delete(dialog: &mut DeleteDialog) {
    let (tx, rx) = crossbeam_channel::unbounded();
    dialog.rx = Some(rx);
    dialog.running = true;
    let plan = dialog.plan.clone();
    std::thread::Builder::new()
        .name("rss-delete".to_string())
        .spawn(move || {
            let result = rss_shell::execute_plan(&plan, |item| {
                let _ = tx.send(DeleteMsg::Freed(item.total_bytes));
            })
            .map_err(|err| {
                err.failures
                    .iter()
                    .map(|f| f.to_string())
                    .collect::<Vec<_>>()
            });
            let _ = tx.send(DeleteMsg::Done(result));
        })
        .expect("spawn delete worker");
}

/// Poll the delete worker (called once per frame while the dialog runs).
pub fn poll_delete(dialog: &mut DeleteDialog) {
    let Some(rx) = &dialog.rx else { return };
    while let Ok(msg) = rx.try_recv() {
        match msg {
            DeleteMsg::Freed(bytes) => dialog.freed += bytes,
            DeleteMsg::Done(result) => dialog.result = Some(result),
        }
    }
}

/// Paths of the parents of deleted nodes — the post-delete rescan targets.
pub fn rescan_targets(view: &ScanView, nodes: &[NodeId]) -> Vec<PathBuf> {
    nodes
        .iter()
        .filter_map(|&id| view.tree().node(id).parent)
        .map(|parent| view.tree().path(parent))
        .collect()
}
