//! Headless GUI tests with `egui_kittest` (SPEC.md §10.4):
//! start dialog on launch, scanning a tempfile tree populates the treemap,
//! and zoom navigation (double-click, breadcrumb, keyboard) works.

use std::path::{Path, PathBuf};
use std::time::Duration;

use egui_kittest::{kittest::Queryable, Harness};
use rss_app::gui::RssApp;
use rss_core::{NodeKind, NodeParams, Tree};

fn make_harness() -> Harness<'static, RssApp> {
    // Small step_dt: kittest runs one frame per queued event, so a
    // double-click's two clicks span 6 frames — they must stay within
    // egui's 0.3 s double-click window.
    Harness::builder()
        .with_step_dt(0.05)
        .build_eframe(|_cc| RssApp::new())
}

/// Step the harness until `pred` holds, giving background threads real time
/// between frames. Panics after ~5 s without the condition being met.
fn wait_until(harness: &mut Harness<'_, RssApp>, mut pred: impl FnMut(&RssApp) -> bool) {
    for _ in 0..1000 {
        harness.step();
        if pred(harness.state()) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    panic!("condition not met within the step budget");
}

/// Synthetic on-disk tree: `root/` with `big.bin` (100 KiB), `small.bin`
/// (1 KiB) and a subdirectory `sub/` containing `nested.bin` (10 KiB).
fn make_tree(base: &Path) -> PathBuf {
    let root = base.join("root");
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("big.bin"), vec![0xABu8; 100 * 1024]).unwrap();
    std::fs::write(root.join("small.bin"), vec![0xCDu8; 1024]).unwrap();
    std::fs::write(root.join("sub/nested.bin"), vec![0xEFu8; 10 * 1024]).unwrap();
    root
}

/// Scan `root` through the app's real background-scan path and wait for the
/// view to be attached.
fn scan_and_wait(harness: &mut Harness<'_, RssApp>, root: PathBuf) {
    harness.state_mut().start_scan(root);
    wait_until(harness, |app| !app.is_scanning());
    assert!(harness.state().view().is_some(), "scan produced a view");
    harness.run_steps(2);
}

#[test]
fn start_dialog_appears_on_launch() {
    let mut harness = make_harness();
    harness.run_ok();

    // §4.1 start dialog: path entry + scan action.
    harness.get_by_label_contains("choose what to scan");
    harness.get_by_label("Scan");
    harness.get_by_label("Browse…");
    // Chrome skeleton is already up behind the dialog (FR-11.1).
    harness.get_by_label("New scan…");
    harness.get_by_label_contains("press Ctrl+N");
}

#[test]
fn start_dialog_path_field_scans_on_enter() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();

    let field = harness.get_by_role(accesskit::Role::TextInput);
    field.click(); // focuses the field
    field.type_text(&root.display().to_string());
    harness.key_press(egui::Key::Enter);

    wait_until(&mut harness, |app| app.view().is_some());
    assert_eq!(
        harness.state().view().unwrap().scan_path,
        root,
        "the start dialog path drove the scan"
    );
}

#[test]
fn scan_populates_treemap() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    // Treemap cells carry the node names as accessibility labels.
    harness.get_by_label("big.bin");
    harness.get_by_label("sub");
    // Preview level: the grandchild is rendered inside `sub`.
    harness.get_by_label("nested.bin");

    // Status bar shows the totals of the scanned tree (§4.3 FR-3.12).
    let state = harness.state();
    let view = state.view().unwrap();
    let root_node = view.tree().node(view.root);
    assert_eq!(root_node.agg_files, 3);
    assert_eq!(root_node.agg_dirs, 2); // root + sub
    assert!(root_node.agg_allocated >= root_node.agg_logical);
    harness.get_by_label_contains("3 files, 2 dirs");
}

#[test]
fn single_click_selects_and_double_click_zooms() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    let sub_id = find_child(&harness, "sub");
    let big_id = find_child(&harness, "big.bin");

    // Single click selects (FR-3.4).
    harness.get_by_label("big.bin").click();
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().selected, Some(big_id));

    // Double click zooms into a folder (FR-3.5). Both clicks are queued
    // before the next frame, so egui sees them as a double click.
    harness.get_by_label("sub").click();
    harness.get_by_label("sub").click();
    harness.run_steps(2);
    let view = harness.state().view().unwrap();
    assert_eq!(view.zoom, sub_id, "double-click zoomed into `sub`");
    assert_eq!(view.selected, None, "zoom clears the selection");
    assert!(view.can_go_back());
}

#[test]
fn back_forward_keyboard_and_breadcrumb_navigation() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    let root_id = harness.state().view().unwrap().root;
    // The root node is named with its full scanned path.
    let root_name = harness
        .state()
        .view()
        .unwrap()
        .tree()
        .node(root_id)
        .name
        .to_string();
    let sub_id = find_child(&harness, "sub");
    harness.state_mut().view_mut().unwrap().navigate_to(sub_id);
    harness.run_steps(2);

    // Breadcrumb bar (FR-3.7) shows root › sub; clicking the root crumb
    // navigates back to it.
    harness.get_by_label("sub"); // crumb of the current zoom (disabled button)
    harness.get_by_label(&root_name).click();
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().zoom, root_id);
    // Breadcrumb clicks are plain navigations: the forward stack is cleared
    // (browser semantics), the back stack remembers `sub`.
    assert!(harness.state().view().unwrap().can_go_back());

    // BACKSPACE / SHIFT+BACKSPACE (FR-3.6).
    harness.state_mut().view_mut().unwrap().navigate_to(sub_id);
    harness.run_steps(2);
    harness.key_press(egui::Key::Backspace);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().zoom, root_id);
    harness.key_press_modifiers(egui::Modifiers::SHIFT, egui::Key::Backspace);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().zoom, sub_id);

    // CTRL+UP zooms out one level, CTRL+HOME jumps to the view root.
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::ArrowUp);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().zoom, root_id);
    harness.state_mut().view_mut().unwrap().navigate_to(sub_id);
    harness.run_steps(2);
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::Home);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().zoom, root_id);
}

#[test]
fn hover_tooltip_shows_sizes_and_dates() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    // FR-3.8: hover tooltip with name, sizes, dates, children count.
    let cell = harness.get_by_label("sub");
    cell.hover();
    // Let egui's tooltip delay (0.3 s) elapse across several frames.
    for _ in 0..12 {
        harness.step();
    }
    harness.get_by_label_contains("On-disk size:");
    harness.get_by_label_contains("Logical size:");
    harness.get_by_label_contains("Modified:");
    harness.get_by_label_contains("Children: 1");
}

#[test]
fn ctrl_n_reopens_start_dialog() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    // FR-1.6: CTRL+N reopens the start dialog from any view.
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::N);
    harness.run_steps(2);
    harness.get_by_label_contains("choose what to scan");
}

/// Find a direct child of the current zoom by name.
fn find_child(harness: &Harness<'_, RssApp>, name: &str) -> rss_core::NodeId {
    let view = harness.state().view().unwrap();
    view.tree()
        .children(view.zoom)
        .find(|&id| &*view.tree().node(id).name == name)
        .unwrap_or_else(|| panic!("no child named {name}"))
}

/// Deterministic tree for renderer unit coverage that does not depend on
/// filesystem allocation behavior (zero-size files must be culled, FR-3.2).
#[test]
fn zero_size_files_are_hidden_but_counted() {
    let mut tree = Tree::with_root(NodeParams::named("root", NodeKind::Directory));
    let root = tree.root().unwrap();
    tree.add_child(
        root,
        NodeParams::named("real.bin", NodeKind::File).sizes(1024, 1024),
    );
    tree.add_child(root, NodeParams::named("empty.bin", NodeKind::File));

    let mut harness = make_harness();
    harness.run_ok();
    // Inject the tree directly as if a scan had completed.
    let summary = rss_scan::ScanSummary::default();
    harness
        .state_mut()
        .attach_tree(tree, root, "root".into(), summary);
    harness.run_steps(2);

    harness.get_by_label("real.bin");
    assert!(
        harness.query_by_label("empty.bin").is_none(),
        "zero-size files occupy zero area and are never displayed (FR-3.2)"
    );
    // …but they remain counted in the model and the status bar.
    harness.get_by_label_contains("2 files");
}

// ---------------------------------------------------------------------
// M3: filters & tags (SPEC.md §4.4, §4.5)
// ---------------------------------------------------------------------

use rss_app::gui::ColorStyle;
use rss_core::Tag;
use rss_filter::FilterVerdict;

/// Deterministic tree for filter/tag tests:
/// `root/` with `a.jpg` (100), `b.txt` (200) and `pics/` holding `c.jpg` (300).
fn filter_tree() -> (Tree, rss_core::NodeId) {
    let mut tree = Tree::with_root(NodeParams::named("root", NodeKind::Directory));
    let root = tree.root().unwrap();
    tree.add_child(
        root,
        NodeParams::named("a.jpg", NodeKind::File).sizes(100, 100),
    );
    tree.add_child(
        root,
        NodeParams::named("b.txt", NodeKind::File).sizes(200, 200),
    );
    let pics = tree.add_child(root, NodeParams::named("pics", NodeKind::Directory));
    tree.add_child(
        pics,
        NodeParams::named("c.jpg", NodeKind::File).sizes(300, 300),
    );
    (tree, root)
}

/// Attach a synthetic tree and run a couple of frames (the first frame syncs
/// the view's derived filter state).
fn attach_and_settle(harness: &mut Harness<'_, RssApp>, tree: Tree, root: rss_core::NodeId) {
    harness
        .state_mut()
        .attach_tree(tree, root, "root".into(), rss_scan::ScanSummary::default());
    harness.run_steps(2);
}

/// Find a node by name anywhere in the current view's tree.
fn find_node(harness: &Harness<'_, RssApp>, name: &str) -> rss_core::NodeId {
    let view = harness.state().view().unwrap();
    let mut stack = vec![view.root];
    while let Some(id) = stack.pop() {
        if &*view.tree().node(id).name == name {
            return id;
        }
        stack.extend(view.tree().children(id));
    }
    panic!("no node named {name}");
}

/// Type into the toolbar filter field (the only text input once a view is
/// attached) and let the verdict pass run.
fn type_filter(harness: &mut Harness<'_, RssApp>, text: &str) {
    {
        let field = harness.get_by_role(accesskit::Role::TextInput);
        field.click();
        field.type_text(text);
    }
    harness.run_steps(2);
}

#[test]
fn filter_dims_nonmatching_cells_and_never_rescans() {
    let (tree, root) = filter_tree();
    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);

    let (a_jpg, b_txt, pics) = (
        find_node(&harness, "a.jpg"),
        find_node(&harness, "b.txt"),
        find_node(&harness, "pics"),
    );

    type_filter(&mut harness, "*.jpg");

    // FR-4.11 tri-state: matches visible, containers dimmed, rest hidden.
    let view = harness.state().view().unwrap();
    assert_eq!(view.verdict(a_jpg), FilterVerdict::Visible);
    assert_eq!(view.verdict(b_txt), FilterVerdict::Hidden);
    assert_eq!(view.verdict(pics), FilterVerdict::Dimmed); // contains c.jpg
    assert_eq!(view.verdict(view.root), FilterVerdict::Dimmed);
    assert!(view.filter_warnings().is_empty());

    // Dim mode keeps every cell on the map.
    harness.get_by_label("b.txt");
    harness.get_by_label("pics");

    // FR-4.1: filtering never rescans and never touches the model.
    assert!(!harness.state().is_scanning());
    let view = harness.state().view().unwrap();
    assert_eq!(view.tree().node(view.root).agg_logical, 600);
}

#[test]
fn filter_hard_hide_removes_hidden_cells() {
    let (tree, root) = filter_tree();
    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);
    type_filter(&mut harness, "*.jpg");

    // FR-4.11 toggle: dim (default) -> hard-hide.
    harness.get_by_label("b.txt"); // dimmed but present
    harness.get_by_label("Filtered: dim").click();
    harness.run_steps(2);

    assert!(harness.state().view().unwrap().hard_hide_filtered);
    assert!(
        harness.query_by_label("b.txt").is_none(),
        "hard-hidden cells leave the layout"
    );
    // Dimmed containers of matches stay.
    harness.get_by_label("pics");
    harness.get_by_label("c.jpg");

    // Toggle back to dim: the cell reappears.
    harness.get_by_label("Filtered: hide").click();
    harness.run_steps(2);
    harness.get_by_label("b.txt");
}

#[test]
fn filter_parse_warning_is_inline() {
    let (tree, root) = filter_tree();
    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);

    type_filter(&mut harness, ":class:Nope");

    // FR-4.13: an inline warning in the toolbar (no modal dialog).
    let warning = harness.get_by_label("⚠ filter");
    warning.hover();
    for _ in 0..12 {
        harness.step();
    }
    // The tooltip quotes the offending condition by its span.
    harness.get_by_label_contains("`:class:Nope`");

    // Fail-open: the bad condition is dropped, everything stays visible.
    let view = harness.state().view().unwrap();
    assert!(!view.filter_warnings().is_empty());
    assert_eq!(
        view.verdict(find_node(&harness, "b.txt")),
        FilterVerdict::Visible
    );
}

#[test]
fn tag_shortcuts_update_model_and_render() {
    let (tree, root) = filter_tree();
    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);

    let a_jpg = find_node(&harness, "a.jpg");
    let b_txt = find_node(&harness, "b.txt");

    // Select a.jpg, then CTRL+2 tags it yellow (FR-5.1).
    harness.get_by_label("a.jpg").click();
    harness.run_steps(2);
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::Num2);
    harness.run_steps(2);
    assert_eq!(
        harness.state().view().unwrap().tree().node(a_jpg).tag,
        Some(Tag::Yellow)
    );

    // Bare digits tag too, while no text field has focus (FR-5.1).
    harness.key_press(egui::Key::Num1);
    harness.run_steps(2);
    assert_eq!(
        harness.state().view().unwrap().tree().node(a_jpg).tag,
        Some(Tag::Red),
        "a different tag replaces the previous one"
    );

    // Same tag key again clears it (toggle).
    harness.key_press(egui::Key::Num1);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().tree().node(a_jpg).tag, None);

    // Tag two nodes, then CTRL+0 clears everything under the zoom.
    harness.key_press(egui::Key::Num1); // a.jpg still selected -> red
    harness.get_by_label("b.txt").click();
    harness.run_steps(2);
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::Num3);
    harness.run_steps(2);
    {
        let view = harness.state().view().unwrap();
        assert_eq!(view.tree().node(a_jpg).tag, Some(Tag::Red));
        assert_eq!(view.tree().node(b_txt).tag, Some(Tag::Green));
    }
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::Num0);
    harness.run_steps(2);
    {
        let view = harness.state().view().unwrap();
        assert_eq!(view.tree().node(a_jpg).tag, None);
        assert_eq!(view.tree().node(b_txt).tag, None);
    }
}

#[test]
fn color_style_toggles_with_ctrl_t_and_toolbar() {
    let (tree, root) = filter_tree();
    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);

    assert_eq!(
        harness.state().view().unwrap().color_style,
        ColorStyle::Flat
    );
    harness.get_by_label("Colors: flat");

    // CTRL+T toggles (FR-5.4).
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::T);
    harness.run_steps(2);
    assert_eq!(
        harness.state().view().unwrap().color_style,
        ColorStyle::FileClasses
    );
    harness.get_by_label("Colors: classes");

    // The toolbar button toggles back.
    harness.get_by_label("Colors: classes").click();
    harness.run_steps(2);
    assert_eq!(
        harness.state().view().unwrap().color_style,
        ColorStyle::Flat
    );
}

/// FR-4.12: filtered-out elements remain in the model and in exports.
#[test]
fn filtered_elements_stay_in_aggregates_and_exports() {
    let (tree, root) = filter_tree();
    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);
    type_filter(&mut harness, "*.jpg");

    // Status bar totals still count hidden elements.
    harness.get_by_label_contains("3 files, 2 dirs");
    harness.get_by_label_contains("600");

    // Exports run on the model and include filter-hidden nodes.
    let view = harness.state().view().unwrap();
    let mut csv = Vec::new();
    rss_export::export_csv(view.tree(), view.root, &mut csv).unwrap();
    let csv = String::from_utf8(csv).unwrap();
    assert!(csv.contains("b.txt"), "hidden node stays in the export");
    assert!(csv.contains("c.jpg"), "dimmed subtree stays in the export");
}

// ---------------------------------------------------------------------
// M4: live scanning UX (SPEC.md §4.2, FR-3.10..FR-3.17, FR-7.x)
// ---------------------------------------------------------------------

/// A tree big enough to scan in bursts: 160 dirs x 150 files (24161
/// entries, well past the scanner's 4096-entry progress interval).
const BIG_TREE_ENTRIES: usize = 1 + 160 + 160 * 150;

fn make_big_tree(base: &Path) -> PathBuf {
    let root = base.join("big");
    for d in 0..160 {
        let dir = root.join(format!("d{d:03}"));
        std::fs::create_dir_all(&dir).unwrap();
        for f in 0..150 {
            std::fs::write(dir.join(format!("f{f:03}.bin")), [0u8; 64]).unwrap();
        }
    }
    root
}

/// FR-2.1/FR-2.3: progressive population renders mid-scan; pause freezes the
/// scan deterministically. Synthetic events are driven through the real scan
/// channel (`debug_stream_root_event`) while a real scan stays parked, so the
/// test does not depend on wall-clock race windows.
#[test]
fn progressive_population_mid_scan() {
    use rss_core::{NodeKind, NodeParams};
    use rss_scan::{ScanEvent, Upsert};

    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("prog");
    std::fs::create_dir_all(&root).unwrap();

    let mut harness = make_harness();
    harness.run_ok();
    harness.state_mut().start_scan_paused(root.clone());

    // Paused from the start: the scan thread is blocked — nothing folds.
    harness.run_steps(4);
    assert!(harness.state().is_scanning());
    assert!(harness.state().root_scan_paused());
    assert!(!harness.state().view().unwrap().has_root());

    let upsert = |parent: Option<PathBuf>, path: PathBuf, params: NodeParams| {
        ScanEvent::Upsert(Upsert {
            parent_path: parent,
            path,
            params,
        })
    };
    // Batch 1: root only.
    harness.state_mut().debug_stream_root_event(upsert(
        None,
        root.clone(),
        NodeParams::named(root.to_string_lossy(), NodeKind::Directory),
    ));
    harness.run_steps(2);
    let view = harness.state().view().unwrap();
    assert!(view.has_root());
    assert_eq!(view.tree().len(), 1, "only the root folded so far");

    // Batch 2: a standalone file, mid-scan.
    harness.state_mut().debug_stream_root_event(upsert(
        Some(root.clone()),
        root.join("first.bin"),
        NodeParams::named("first.bin", NodeKind::File).sizes(100, 4096),
    ));
    // Step past the FR-3.16 layout tick (250 ms) so the new cell relayouts.
    harness.run_steps(8);
    harness.get_by_label("first.bin");
    assert!(harness.state().is_scanning(), "scan still parked");

    // Batch 3: a directory with a file in it (ParentFirst order).
    harness.state_mut().debug_stream_root_event(upsert(
        Some(root.clone()),
        root.join("d0"),
        NodeParams::named("d0", NodeKind::Directory),
    ));
    harness.state_mut().debug_stream_root_event(upsert(
        Some(root.join("d0")),
        root.join("d0/f.bin"),
        NodeParams::named("f.bin", NodeKind::File).sizes(100, 4096),
    ));
    harness.run_steps(8);
    harness.get_by_label("d0");
    harness.get_by_label("f.bin"); // preview level inside d0

    // The partial tree is navigable mid-scan (FR-2.1): zoom into d0.
    let d0 = find_child(&harness, "d0");
    harness.state_mut().view_mut().unwrap().navigate_to(d0);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().zoom, d0);

    // Resume: the real (tiny) scan completes and replaces the model.
    harness.state_mut().set_root_scan_paused(false);
    wait_until(&mut harness, |app| !app.is_scanning());
}

/// FR-2.2/FR-2.3 with the real scanner: a paused big scan grows in bursts
/// and cancelling leaves a browsable partial tree.
#[test]
fn pause_and_cancel_real_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_big_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    harness.state_mut().start_scan_paused(root);

    // Paused from the start: no events fold while the flag is set.
    harness.run_steps(4);
    assert!(harness.state().is_scanning());
    assert_eq!(harness.state().view().unwrap().tree().len(), 0);

    // Resume; the scan threads along. Cancel as soon as a chunk has folded
    // (mid-scan on any machine: 24k entries take tens of ms).
    harness.state_mut().set_root_scan_paused(false);
    let start = std::time::Instant::now();
    loop {
        harness.step();
        if harness.state().view().unwrap().tree().len() >= 1000 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "scan did not progress"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    harness.state_mut().cancel_scan();
    wait_until(&mut harness, |app| !app.is_scanning());

    let view = harness.state().view().unwrap();
    let summary = view.summary.as_ref().expect("finished scan has a summary");
    let len = view.tree().len();
    assert!(len > 1, "partial tree is browsable");
    if summary.cancelled {
        assert!(
            len < BIG_TREE_ENTRIES,
            "cancelled scan kept a partial tree: {len}"
        );
    }
    // The treemap rendered the (partial) model.
    assert!(
        view.layout_cache
            .as_ref()
            .is_some_and(|c| !c.top.is_empty()),
        "treemap renders the partial model"
    );
}

/// FR-7.8: F5 rescans the view and picks up filesystem changes.
#[test]
fn f5_rescan_picks_up_fs_changes() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root.clone());

    assert!(harness.query_by_label("late.bin").is_none());
    std::fs::write(root.join("late.bin"), [7u8; 2048]).unwrap();

    harness.key_press(egui::Key::F5);
    // Let the key event process, then wait out the rescan.
    harness.run_steps(3);
    wait_until(&mut harness, |app| !app.is_scanning());
    harness.run_steps(2);
    harness.get_by_label("late.bin");
}

/// FR-7.1/FR-7.4: injected watcher events patch the live tree (upsert with
/// flash, remove, subtree-dirty rescan).
#[test]
fn watcher_events_update_tree() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root.clone());

    // Upsert of a new file patches it in, flashing the cell (FR-2.11).
    let new_file = root.join("sub").join("watched.bin");
    std::fs::write(&new_file, [3u8; 4096]).unwrap();
    harness
        .state_mut()
        .inject_watch_event(rss_watch::WatchEvent::Upsert(new_file.clone()));
    harness.run_steps(2);
    let view = harness.state().view().unwrap();
    let id = view.find_by_path(&new_file).expect("upserted node");
    assert!(view.flash_alpha(id, 0.0).is_some(), "new cell flashes");
    harness.get_by_label("watched.bin");

    // Flash toggle off: further changes do not flash (FR-2.11 toggle).
    harness.get_by_label("Flash: on").click();
    harness.run_steps(2);
    let other = root.join("sub").join("watched2.bin");
    std::fs::write(&other, [4u8; 1024]).unwrap();
    harness
        .state_mut()
        .inject_watch_event(rss_watch::WatchEvent::Upsert(other.clone()));
    harness.run_steps(2);
    let view = harness.state().view().unwrap();
    let id2 = view.find_by_path(&other).expect("upserted node");
    assert!(view.flash_alpha(id2, 0.0).is_none(), "flash disabled");
    harness.get_by_label("Flash: off").click(); // re-enable
    harness.run_steps(2);

    // Remove drops the node.
    harness
        .state_mut()
        .inject_watch_event(rss_watch::WatchEvent::Remove(new_file.clone()));
    harness.run_steps(2);
    assert!(harness
        .state()
        .view()
        .unwrap()
        .find_by_path(&new_file)
        .is_none());

    // SubtreeDirty on a directory triggers an incremental rescan (FR-7.4)
    // that picks up contents that arrived after the original scan.
    let sub2 = root.join("sub2");
    std::fs::create_dir(&sub2).unwrap();
    std::fs::write(sub2.join("deep.bin"), [9u8; 512]).unwrap();
    harness
        .state_mut()
        .inject_watch_event(rss_watch::WatchEvent::SubtreeDirty(sub2.clone()));
    wait_until(&mut harness, |app| {
        app.view()
            .is_some_and(|v| v.find_by_path(&sub2.join("deep.bin")).is_some())
    });
    harness.run_steps(2);
    harness.get_by_label("sub2");
}

/// FR-3.13: drive-root views show the free-space element (CTRL+F toggles),
/// excluded from zoomed views.
#[test]
fn free_space_element_at_drive_root() {
    // Platform volume root: "/" on Unix, "C:\" on Windows (the CI runner's
    // temp and work dirs live on C:).
    #[cfg(not(windows))]
    let root_path = "/";
    #[cfg(windows)]
    let root_path = "C:\\";
    let mut tree = Tree::with_root(NodeParams::named(root_path, NodeKind::Directory));
    let root = tree.root().unwrap();
    tree.add_child(
        root,
        NodeParams::named("usr", NodeKind::Directory).sizes(1 << 30, 1 << 30),
    );

    let mut harness = make_harness();
    harness.run_ok();
    harness.state_mut().attach_tree(
        tree,
        root,
        root_path.into(),
        rss_scan::ScanSummary::default(),
    );
    harness.run_steps(3); // sync fetches real drive space for "/"

    let view = harness.state().view().unwrap();
    assert!(view.is_drive_view);
    assert!(view.drive_space.is_some(), "fs2 volume query works");
    harness.get_by_label("Free space");

    // CTRL+F hides the element (FR-3.13).
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::F);
    harness.run_steps(2);
    assert!(harness.query_by_label("Free space").is_none());
    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::F);
    harness.run_steps(2);
    harness.get_by_label("Free space");

    // Zoomed views exclude it (FR-3.13 proportion distortion rule).
    let usr = find_child(&harness, "usr");
    harness.state_mut().view_mut().unwrap().navigate_to(usr);
    harness.run_steps(2);
    assert!(harness.query_by_label("Free space").is_none());
}

/// FR-1.7: one scan per path opens one view per viewport, listed in the
/// Windows menu.
#[test]
fn multi_view_opens_viewport_per_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let r1 = tmp.path().join("one");
    let r2 = tmp.path().join("two");
    std::fs::create_dir_all(&r1).unwrap();
    std::fs::create_dir_all(&r2).unwrap();
    std::fs::write(r1.join("one.bin"), [1u8; 4096]).unwrap();
    std::fs::write(r2.join("two.bin"), [2u8; 4096]).unwrap();

    let mut harness = make_harness();
    harness.run_ok();
    harness.state_mut().open_scans(vec![r1.clone(), r2.clone()]);
    wait_until(&mut harness, |app| !app.is_scanning());
    harness.run_steps(2);

    assert_eq!(harness.state().view_count(), 2);
    assert_eq!(harness.state().view_path(0), Some(r1.as_path()));
    assert_eq!(harness.state().view_path(1), Some(r2.as_path()));
    harness.get_by_label("one.bin"); // root viewport
                                     // The second view renders in its (embedded) viewport.
    harness.get_by_label("two.bin");

    // FR-1.7: the Windows menu lists the views (one menu per viewport —
    // click the root viewport's). The second view's breadcrumb already
    // carries its path label; opening the menu adds the menu item.
    let label = r2.display().to_string();
    let before = harness.get_all_by_label(&label).count();
    {
        let menus: Vec<_> = harness.get_all_by_label("Windows").collect();
        assert_eq!(menus.len(), 2, "one Windows menu per view");
        menus[0].click();
    }
    harness.run_steps(2);
    let after = harness.get_all_by_label(&label).count();
    assert!(after > before, "Windows menu lists the second view");
}

/// FR-3.10: zoom transitions animate (and instant mode skips animation).
#[test]
fn zoom_animation_lifecycle() {
    let (tree, root) = filter_tree();
    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);

    let pics = find_node(&harness, "pics");
    {
        let view = harness.state_mut().view_mut().unwrap();
        view.navigate_from_rect(pics, rss_treemap::Rect::new(10.0, 10.0, 100.0, 80.0));
    }
    harness.step();
    assert!(
        harness.state().view().unwrap().anim_active(),
        "animation running after zoom"
    );
    // 150 ms at 50 ms/frame: done after ~5 frames.
    harness.run_steps(8);
    assert!(!harness.state().view().unwrap().anim_active());

    // Instant mode: no animation at all.
    {
        let view = harness.state_mut().view_mut().unwrap();
        view.zoom_anim_ms = 0;
        view.navigate_to(view.root);
    }
    harness.step();
    assert!(!harness.state().view().unwrap().anim_active());
}

/// FR-3.14: CTRL+`+` raises the display-depth limit, revealing deeper
/// preview levels.
#[test]
fn display_depth_ctrl_plus() {
    let mut tree = Tree::with_root(NodeParams::named("root", NodeKind::Directory));
    let root = tree.root().unwrap();
    let a = tree.add_child(root, NodeParams::named("a", NodeKind::Directory));
    let b = tree.add_child(a, NodeParams::named("b", NodeKind::Directory));
    tree.add_child(
        b,
        NodeParams::named("deep.bin", NodeKind::File).sizes(1000, 1000),
    );

    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);

    assert_eq!(harness.state().view().unwrap().display_depth, 1);
    harness.get_by_label("b"); // one preview level
    assert!(
        harness.query_by_label("deep.bin").is_none(),
        "beyond the depth limit"
    );

    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::Plus);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().display_depth, 2);
    harness.get_by_label("deep.bin");

    harness.key_press_modifiers(egui::Modifiers::CTRL, egui::Key::Minus);
    harness.run_steps(2);
    assert!(harness.query_by_label("deep.bin").is_none());
}

/// FR-3.11: the viewable-percent bar reflects the zoom fraction.
#[test]
fn viewable_percent_bar_tracks_zoom() {
    let (tree, root) = filter_tree();
    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);

    harness.get_by_label("Viewable: 100%");
    let pics = find_node(&harness, "pics"); // 300 of 600 bytes
    harness.state_mut().view_mut().unwrap().navigate_to(pics);
    harness.run_steps(2);
    harness.get_by_label("Viewable: 50%");
}

// ---------------------------------------------------------------------
// M7: export & snapshots in the GUI (SPEC.md §4.8)
// ---------------------------------------------------------------------

#[test]
fn export_menu_lists_templates_csv_json_and_snapshot() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    harness.get_by_label("Export").click();
    harness.run_steps(2);
    harness.get_by_label("Template: Grouped by folder");
    harness.get_by_label("CSV");
    harness.get_by_label("JSON");
    harness.get_by_label("Save snapshot (.rssnap)");
}

/// FR-8.7/FR-5.3: save the view as `.rssnap`, load it back as a read-only
/// view with filter and zoom restored (driven through the app methods the
/// dialogs call).
#[test]
fn snapshot_save_load_cycle() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    // Set a filter and a zoom to carry into the snapshot.
    type_filter(&mut harness, "*.bin");
    let sub = find_child(&harness, "sub");
    harness.state_mut().view_mut().unwrap().navigate_to(sub);
    harness.run_steps(2);

    let snap = tmp.path().join("view.rssnap");
    harness.state_mut().save_root_snapshot(&snap).unwrap();

    // Load into a fresh app: read-only view, filter + zoom restored.
    let mut harness2 = make_harness();
    harness2.run_ok();
    harness2.state_mut().load_snapshot(&snap);
    harness2.run_steps(2);
    let view = harness2.state().view().expect("snapshot view loaded");
    assert_eq!(view.snapshot_source.as_deref(), Some(snap.as_path()));
    assert!(!harness2.state().is_scanning());
    assert_eq!(view.filter_text, "*.bin");
    let zoom_name = view.tree().node(view.zoom).name.clone();
    assert_eq!(&*zoom_name, "sub", "zoom path restored");
}

/// FR-1.5: the start dialog has a Snapshots tab that loads .rssnap files.
#[test]
fn start_dialog_snapshots_tab_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    // Produce a snapshot from a scanned app…
    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);
    let snap = tmp.path().join("view.rssnap");
    harness.state_mut().save_root_snapshot(&snap).unwrap();

    // …and load it in a fresh app via the Snapshots tab.
    let mut harness = make_harness();
    harness.run_ok();
    harness.get_by_label("Snapshots").click();
    harness.run_steps(2);
    {
        let field = harness.get_by_role(accesskit::Role::TextInput);
        field.click();
        field.type_text(&snap.display().to_string());
    }
    harness.get_by_label("Load").click();
    wait_until(&mut harness, |app| app.view_count() == 1);
    harness.run_steps(2);
    let view = harness.state().view().unwrap();
    assert_eq!(view.snapshot_source.as_deref(), Some(snap.as_path()));
    harness.get_by_label("nested.bin"); // snapshot contents render
}

// ---------------------------------------------------------------------
// M8: file operations (SPEC.md §4.6)
// ---------------------------------------------------------------------

/// FR-6.x: right-click on a cell opens the context menu.
#[test]
fn context_menu_on_right_click() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    harness.get_by_label("big.bin").click_secondary();
    harness.run_steps(2);
    harness.get_by_label("Open");
    harness.get_by_label("Open containing folder");
    harness.get_by_label("Delete to Recycle Bin…");
    #[cfg(windows)]
    harness.get_by_label("Windows shell menu");
}

/// FR-6.4: the confirmation dialog lists items with the true total, warns
/// when a filter hides content, and deleting updates the model.
#[test]
fn delete_dialog_content_and_execution() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root.clone());

    // A filter that hides part of the tree (FR-6.4b warning).
    type_filter(&mut harness, "*.nothing-matches");

    harness.get_by_label("big.bin").click_secondary();
    harness.run_steps(2);
    harness.get_by_label("Delete to Recycle Bin…").click();
    harness.run_steps(2);

    // Dialog content: item path (also a treemap cell — hence ≥ 2 matches),
    // true total, filter-hiding warning.
    assert!(harness.get_all_by_label_contains("big.bin").count() >= 2);
    harness.get_by_label_contains("Total:");
    harness.get_by_label_contains("An active filter hides part of the contents");

    // Execute: the file is trashed, the counter completes, and the model
    // loses the node after the parent rescan.
    harness.get_by_label("Move to Recycle Bin").click();
    wait_until(&mut harness, |app| {
        app.view()
            .is_some_and(|v| v.find_by_path(&root.join("big.bin")).is_none())
    });
    harness.run_steps(2);
    assert!(!root.join("big.bin").exists(), "file was trashed");
    harness.get_by_label_contains("Done.");
    harness.get_by_label("Close").click();
    harness.run_steps(2);
}

// ---------------------------------------------------------------------
// M9: settings, theming, log console (SPEC.md §4.10, §4.11, FR-2.13)
// ---------------------------------------------------------------------

/// FR-11.4/FR-11.9: theme switching is instant and re-palettes the views.
#[test]
fn theme_switch_recolors_views_instantly() {
    use rss_app::gui::ThemeSetting;
    let (tree, root) = filter_tree();

    let mut harness = make_harness();
    harness.run_ok();
    attach_and_settle(&mut harness, tree, root);

    // Default: System theme; the kittest harness reports Dark.
    let dark_file = harness.state().view().unwrap().flat_colors.file;

    harness.state_mut().set_theme(ThemeSetting::Light);
    harness.run_steps(2);
    let light_file = harness.state().view().unwrap().flat_colors.file;
    assert_ne!(dark_file, light_file, "palette switched without a restart");

    harness.state_mut().set_theme(ThemeSetting::Dark);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().flat_colors.file, dark_file);

    // And back to following the system.
    harness.state_mut().set_theme(ThemeSetting::System);
    harness.run_steps(2);
    assert_eq!(harness.state().view().unwrap().flat_colors.file, dark_file);
}

/// FR-10.1/FR-11.9: settings changes through the dialog persist to the
/// config file.
#[test]
fn settings_dialog_persists_theme() {
    use rss_app::gui::{Config, ThemeSetting};
    let tmp = tempfile::tempdir().unwrap();
    let config_path = tmp.path().join("RustySpaceSniffer.toml");

    let mut harness = make_harness();
    harness
        .state_mut()
        .config_for_test(Config::default(), Some(config_path.clone()));
    harness.run_ok();

    harness.get_by_label("Settings").click();
    harness.run_steps(2);
    harness.get_by_label("Light").click();
    harness.run_steps(2);

    let text = std::fs::read_to_string(&config_path).expect("config written");
    assert!(text.contains("theme = \"light\""), "persisted: {text}");
    let parsed = Config::parse(&text).unwrap();
    assert_eq!(parsed.theme, ThemeSetting::Light);
}

/// FR-2.13: the log console lists scan problems.
#[test]
fn log_console_lists_scan_problems() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());
    let locked = root.join("locked");
    std::fs::create_dir(&locked).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    // Skip when the process can read the directory anyway (e.g. root).
    if std::fs::read_dir(&locked).is_ok() {
        return;
    }

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    harness.get_by_label("Log").click();
    harness.run_steps(2);
    // The treemap cell and the log line both carry the name.
    assert!(harness.get_all_by_label_contains("locked").count() >= 2);
}

/// §8.2: every interactive element exposes an accessibility label.
#[test]
fn accessibility_labels_on_all_interactive_widgets() {
    let tmp = tempfile::tempdir().unwrap();
    let root = make_tree(tmp.path());

    let mut harness = make_harness();
    harness.run_ok();
    scan_and_wait(&mut harness, root);

    let unlabeled = harness
        .query_all_by(|node: &egui_kittest::kittest::AccessKitNode| {
            let interactive = matches!(
                node.role(),
                accesskit::Role::Button | accesskit::Role::MenuItem | accesskit::Role::TextInput
            );
            let named = node.label().is_some_and(|l: String| !l.is_empty())
                || node.labelled_by().next().is_some();
            interactive && !named
        })
        .count();
    assert_eq!(unlabeled, 0, "widgets without an accessibility label");

    // Treemap cells are labeled with the node name (§8.2 list fallback).
    harness.get_by_label("big.bin");
}
