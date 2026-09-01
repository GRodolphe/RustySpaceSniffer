//! Export and snapshot actions (SPEC.md §4.8): template/CSV/JSON export of
//! the active view's current zoom (FR-8.1) and `.rssnap` snapshot save/load
//! (FR-8.7). Pure logic, no egui — the dialogs live in `mod.rs`.

use std::io::Write;
use std::path::{Path, PathBuf};

use rss_core::filetime_from_unix;
use rss_export::{builtin_templates, export_csv_with, export_json_with, render_template};
use rss_export::{ExportOptions, ScanMetadata, Snapshot, TemplateContext};

use super::view::ScanView;

/// What the export dialog can produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExportKind {
    /// A named export template (FR-8.2); index into [`builtin_templates`].
    Template(usize),
    /// Flat CSV (FR-8.4).
    Csv,
    /// Nested JSON (FR-8.5).
    Json,
}

impl ExportKind {
    /// Human label for the export menu.
    pub fn label(&self) -> String {
        match self {
            ExportKind::Template(i) => builtin_templates().get(*i).map_or_else(
                || "Template".to_string(),
                |t| format!("Template: {}", t.name),
            ),
            ExportKind::Csv => "CSV".to_string(),
            ExportKind::Json => "JSON".to_string(),
        }
    }

    /// Default file extension for the save dialog.
    pub fn extension(&self) -> &'static str {
        match self {
            ExportKind::Template(_) => "txt",
            ExportKind::Csv => "csv",
            ExportKind::Json => "json",
        }
    }
}

/// Export the view's current zoom subtree (FR-8.1) to `writer`.
pub fn export_view(
    view: &ScanView,
    kind: &ExportKind,
    writer: impl Write,
) -> Result<(), rss_export::ExportError> {
    let options = ExportOptions {
        size_mode: view.size_mode,
    };
    match kind {
        ExportKind::Template(i) => {
            let template = builtin_templates()
                .into_iter()
                .nth(*i)
                .unwrap_or_else(rss_export::ExportTemplate::grouped_by_folder);
            let now = filetime_from_unix(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| d.as_secs() as i64),
            );
            let context = TemplateContext {
                filter: (!view.filter_text.is_empty()).then_some(view.filter_text.as_str()),
                now,
            };
            render_template(view.tree(), view.zoom, &template, &context, writer)
        }
        ExportKind::Csv => export_csv_with(view.tree(), view.zoom, options, writer),
        ExportKind::Json => export_json_with(view.tree(), view.zoom, options, writer),
    }
}

/// Build a snapshot of the view (tree + tags + filter + zoom path + scan
/// metadata, FR-8.7) and encode it to `writer`.
pub fn save_snapshot(
    view: &ScanView,
    tool_version: &str,
    writer: impl Write,
) -> Result<(), rss_export::SnapshotError> {
    let mut snapshot = Snapshot::new(view.tree().clone(), scan_metadata(view, tool_version));
    snapshot.filter = view.filter_text.clone();
    // Zoom path: components below the root (the root name is the scan root's
    // full path; `Snapshot::zoom_root` matches child names).
    snapshot.zoom_path = view
        .breadcrumb()
        .iter()
        .skip(1)
        .map(|&id| view.tree().node(id).name.to_string())
        .collect();
    snapshot.write_to(writer)
}

fn scan_metadata(view: &ScanView, tool_version: &str) -> ScanMetadata {
    let (started, finished) = view
        .summary
        .as_ref()
        .map(|s| {
            let end = std::time::SystemTime::now();
            let start = end - s.elapsed;
            (
                filetime_from_unix(
                    start
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs() as i64),
                ),
                filetime_from_unix(
                    end.duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs() as i64),
                ),
            )
        })
        .unwrap_or((0, 0));
    ScanMetadata {
        tool_version: tool_version.to_string(),
        volume_serial: 0, // unknown off the MFT path
        started,
        finished,
    }
}

/// Load a `.rssnap` snapshot into a fresh, read-only view (FR-8.7: no live
/// link — no watcher is started for it). `source` is the snapshot file,
/// shown as the view's framing.
pub fn load_snapshot(path: &Path) -> Result<ScanView, rss_export::SnapshotError> {
    let snapshot = Snapshot::read_from(&mut std::fs::File::open(path)?)?;
    view_from_snapshot(snapshot, path)
}

/// Build the read-only view for a decoded snapshot.
fn view_from_snapshot(
    snapshot: Snapshot,
    source: &Path,
) -> Result<ScanView, rss_export::SnapshotError> {
    let root = snapshot
        .tree
        .root()
        .ok_or(rss_export::SnapshotError::EmptyTree)?;
    let zoom = snapshot.zoom_root();
    let filter = snapshot.filter.clone();
    // The view's scan path is the snapshot's original scan root (the tree
    // root's name is the full scanned path).
    let scan_path = PathBuf::from(&*snapshot.tree.node(root).name);
    let mut view = ScanView::new(
        snapshot.tree,
        root,
        scan_path,
        rss_scan::ScanSummary::default(),
    );
    view.filter_text = filter;
    view.snapshot_source = Some(source.to_path_buf());
    if let Some(zoom) = zoom {
        view.zoom_to_silent(zoom);
    }
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::{NodeKind, NodeParams, Tag, Tree};

    fn sample_view() -> ScanView {
        let mut tree = Tree::with_root(NodeParams::named("/r", NodeKind::Directory));
        let root = tree.root().unwrap();
        let mut tagged = NodeParams::named("f.bin", NodeKind::File).sizes(64, 4096);
        tagged.tag = Some(Tag::Red);
        tree.add_child(root, tagged);
        let d = tree.add_child(root, NodeParams::named("sub", NodeKind::Directory));
        tree.add_child(
            d,
            NodeParams::named("g.bin", NodeKind::File).sizes(32, 4096),
        );
        let mut view = ScanView::new(
            tree,
            root,
            PathBuf::from("/r"),
            rss_scan::ScanSummary::default(),
        );
        view.filter_text = "*.bin".to_string();
        view
    }

    #[test]
    fn template_export_states_view_and_filter() {
        let view = sample_view();
        let mut out = Vec::new();
        export_view(&view, &ExportKind::Template(0), &mut out).unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Grouped by folder"));
        assert!(text.contains("# filter: *.bin"));
        assert!(text.contains("f.bin"));
    }

    #[test]
    fn csv_and_json_export_still_work() {
        let view = sample_view();
        let mut out = Vec::new();
        export_view(&view, &ExportKind::Csv, &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("f.bin"));
        let mut out = Vec::new();
        export_view(&view, &ExportKind::Json, &mut out).unwrap();
        assert!(String::from_utf8(out).unwrap().contains("\"f.bin\""));
    }

    /// FR-8.7 + FR-5.3: snapshot round-trip carries tree, tags, filter and
    /// zoom path; the loaded view is read-only (no scan, no watcher).
    #[test]
    fn snapshot_round_trip_preserves_view_state() {
        let mut view = sample_view();
        let sub = view.find_by_path(Path::new("/r/sub")).unwrap();
        view.navigate_to(sub);

        let mut bytes = Vec::new();
        save_snapshot(&view, "0.1.0-test", &mut bytes).unwrap();
        let snapshot = Snapshot::decode(&bytes).unwrap();
        assert_eq!(snapshot.filter, "*.bin");
        assert_eq!(snapshot.zoom_path, vec!["sub"]);
        // Tags survive (FR-5.3).
        let f = snapshot
            .tree
            .children(snapshot.tree.root().unwrap())
            .find(|&c| &*snapshot.tree.node(c).name == "f.bin")
            .unwrap();
        assert_eq!(snapshot.tree.node(f).tag, Some(Tag::Red));
    }

    #[test]
    fn load_snapshot_builds_read_only_view() {
        let view = sample_view();
        let mut bytes = Vec::new();
        save_snapshot(&view, "0.1.0-test", &mut bytes).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("view.rssnap");
        std::fs::write(&file, &bytes).unwrap();

        let loaded = load_snapshot(&file).unwrap();
        assert_eq!(loaded.filter_text, "*.bin");
        assert_eq!(loaded.snapshot_source.as_deref(), Some(file.as_path()));
        assert!(!loaded.scanning, "snapshots have no live link (FR-8.7)");
        assert_eq!(loaded.tree().len(), view.tree().len());
    }
}
