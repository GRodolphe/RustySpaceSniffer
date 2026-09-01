//! Per-view state: the scanned tree plus zoom/navigation/selection, the
//! filter state (M3, FR-4.x), tagging (FR-5.1/5.2), the per-view color style
//! (FR-5.4), and the M4 live-scanning state (progress, flash-on-change,
//! free/unknown space elements, display depth, zoom animation, layout
//! cache).
//!
//! This is the model half of the app (SPEC.md §5.3: the scene is recomputed
//! each frame from `(tree, zoom node, filter, colors, style)` — the first
//! four live here). It uses egui only for `Color32` (palette data) so watcher
//! wiring (FR-7.x) and tests can drive it headlessly.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rss_core::{NodeId, NodeKind, Tag, Tree};
use rss_export::SizeMode;
use rss_filter::{Filter, FilterVerdict, ParseWarning};
use rss_scan::{ScanEvent, ScanProgress, ScanSummary, TreeBuilder, Upsert};
use rss_treemap::Rect as TmRect;
use rss_watch::WatchEvent;

use super::defaults::{self, ClassStyle};
use super::diskspace::{self, DiskSpace};

/// Treemap color style (FR-5.4), toggled per view with CTRL+T.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum ColorStyle {
    /// Base color per element kind, darkened by nesting depth.
    #[default]
    Flat,
    /// Files colored by their file class (extension list, first match wins);
    /// folders keep the flat folder color.
    FileClasses,
}

/// Sentinel cell id for the FR-3.13 free-space element (never a real node).
pub const FREE_SPACE_ID: NodeId = u32::MAX - 1;
/// Sentinel cell id for the not-yet-scanned space element (FR-2.9).
pub const UNKNOWN_SPACE_ID: NodeId = u32::MAX;

/// How long a changed cell flashes (FR-2.11).
pub const FLASH_SECS: f64 = 0.7;
/// During a progressive scan the layout is recomputed at most this often
/// (FR-3.16: ~4 Hz, anti-"boiling treemap").
pub const LAYOUT_TICK_SECS: f64 = 0.25;
/// During a progressive scan with an active filter, verdicts are recomputed
/// at most this often (a full verdict pass is O(tree)).
const VERDICT_TICK: Duration = Duration::from_millis(500);
/// Drive-space refresh interval (FR-1.8 progress / FR-3.13 elements).
const DISKSPACE_TICK: Duration = Duration::from_secs(2);

/// A pending zoom animation (FR-3.10).
#[derive(Clone, Copy, Debug)]
pub enum AnimKind {
    /// Zoom-in: the new content grows out of this rect (pre-zoom
    /// coordinates).
    FromRect(TmRect),
    /// Zoom-out/back: the new layout starts blown up from this node's cell
    /// (resolved against the first layout of the new zoom).
    FromNode(NodeId),
}

#[derive(Clone, Copy, Debug)]
struct AnimState {
    kind: AnimKind,
    /// egui time when the animation started; `None` until the renderer's
    /// first frame with the new layout.
    start: Option<f64>,
}

/// Cached layout of the zoom node's children plus preview levels
/// (FR-3.16): during a progressive scan the cache is reused for
/// [`LAYOUT_TICK_SECS`] so cells do not reshuffle every frame.
pub struct LayoutCache {
    pub zoom: NodeId,
    pub container: TmRect,
    pub epoch: u64,
    pub model_epoch: u64,
    pub order: rss_treemap::Order,
    pub time: f64,
    /// Placed cells of the zoom node's children.
    pub top: Vec<(NodeId, TmRect)>,
    /// Placed children per expanded directory (preview levels).
    pub subs: HashMap<NodeId, Vec<(NodeId, TmRect)>>,
}

/// Outcome of applying a watcher event to the view (FR-7.x).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WatchOutcome {
    /// The tree was patched in place (flash the cell).
    Applied,
    /// The event was irrelevant to this tree (unknown path, vanished entry).
    Ignored,
    /// The subtree must be incrementally rescanned (new directory contents,
    /// watcher buffer overflow — FR-7.4).
    RescanSubtree(PathBuf),
    /// The whole view must be rescanned (root removed/dirty, FR-7.5).
    RescanFull,
}

/// One treemap view over a scanned (or scanning) tree. M4: views live in
/// separate viewports (FR-1.7), each with its own scan and watcher.
pub struct ScanView {
    /// Live model: streamed scan events fold into this builder (FR-2.1).
    builder: TreeBuilder,
    /// Node representing the scan root (breadcrumb anchor / CTRL+HOME).
    /// Valid: a view is created when the root upsert arrives.
    pub root: NodeId,
    /// Currently zoomed node; its children fill the treemap area.
    pub zoom: NodeId,
    /// Back/forward navigation history (FR-3.6).
    back: Vec<NodeId>,
    forward: Vec<NodeId>,
    /// Single-click selection (FR-3.4).
    pub selected: Option<NodeId>,
    /// The path that was scanned (title bar, F5 rescan).
    pub scan_path: PathBuf,
    /// Set for views loaded from a `.rssnap` snapshot: the snapshot file,
    /// shown as the view's framing (FR-8.7). Snapshot views have no live
    /// filesystem link (no watcher, no rescan).
    pub snapshot_source: Option<PathBuf>,
    /// Summary of the scan that produced this tree; `None` while scanning.
    pub summary: Option<ScanSummary>,
    /// Live scan counters (updated by progress messages, FR-3.12).
    pub progress: ScanProgress,
    /// True while this view's scan is running (set by the app shell).
    pub scanning: bool,
    /// Filter field contents (FR-4.1). Parsed lazily by [`Self::sync`];
    /// changing the text never triggers a rescan.
    pub filter_text: String,
    /// Which size the treemap areas are proportional to (SPEC.md §5.2:
    /// allocated by default, per-view toggle).
    pub size_mode: SizeMode,
    /// Per-view color style (FR-5.4).
    pub color_style: ColorStyle,
    /// FR-4.11 treatment of filtered-out elements: dimmed in place
    /// (`false`, the default) or hard-hidden (`true`).
    pub hard_hide_filtered: bool,
    /// File classes for `:class:` filter conditions (FR-4.8) and the File
    /// Classes color style (FR-5.4). Colors follow the active theme
    /// (FR-11.5); M9 persists user customizations per theme.
    pub class_styles: Vec<ClassStyle>,
    /// Flat-style base colors for the active theme (FR-11.5).
    pub flat_colors: defaults::FlatColors,
    /// Tag border colors for the active theme (red/yellow/green/blue).
    pub tag_colors: [egui::Color32; 4],
    /// Level-contrast factor for the active theme (FR-11.6: dark lightens
    /// by depth, light darkens).
    pub level_contrast: f32,
    /// Parsed filter cache: the text it was parsed from plus the result.
    filter_cache: Option<(String, Filter)>,
    /// Cached per-node filter verdicts (empty = no active filter, everything
    /// visible).
    verdicts: Vec<FilterVerdict>,
    /// True when `verdicts` must be recomputed.
    verdicts_dirty: bool,
    /// Throttling for the verdict pass while scanning.
    last_verdict_pass: Option<Instant>,
    /// FR-2.11 flash-on-change toggle.
    pub flash_enabled: bool,
    /// Cells flashing until the given egui time.
    flash_marks: HashMap<NodeId, f64>,
    /// Nodes changed since the last rendered frame (flash input).
    changed: Vec<NodeId>,
    /// FR-3.13: show the free-space element at drive-root views (CTRL+F).
    pub show_free_space: bool,
    /// FR-2.9/FR-3.13: show the not-yet-scanned element during drive scans
    /// (CTRL+U).
    pub show_unknown: bool,
    /// Whether this view scans a volume root (gates the FR-3.13 elements).
    pub is_drive_view: bool,
    /// Cached drive space for the scanned volume.
    pub drive_space: Option<DiskSpace>,
    drive_space_fetched: Option<Instant>,
    /// Display-depth limit: levels below the zoom node whose cells are laid
    /// out (CTRL+`+` / CTRL+`-`, FR-3.14).
    pub display_depth: u32,
    /// Zoom animation duration in milliseconds (FR-3.10; 0 = instant).
    pub zoom_anim_ms: u64,
    anim: Option<AnimState>,
    /// Bumped whenever layout inputs other than sizes change (filter,
    /// hard-hide, size mode, display depth); part of the layout cache key.
    pub layout_epoch: u64,
    /// Bumped on every model mutation (scan event, watcher patch). The
    /// layout cache keys on it; while scanning, the FR-3.16 tick overrides
    /// it so the map does not boil.
    pub model_epoch: u64,
    /// Set by user-initiated view changes: the next layout is a full
    /// [`rss_treemap::Order::Sorted`] pass even mid-scan (FR-3.16).
    pub resort_once: bool,
    /// Layout cache (FR-3.16), owned by the view, written by the renderer.
    pub layout_cache: Option<LayoutCache>,
}

impl ScanView {
    /// Create a view over a complete tree (attach path: tests, M7 snapshot
    /// loading — FR-8.7).
    pub fn new(tree: Tree, root: NodeId, scan_path: PathBuf, summary: ScanSummary) -> Self {
        let mut view = Self::for_scan(scan_path);
        view.builder = TreeBuilder::from_tree(tree);
        view.root = root;
        view.zoom = root;
        view.summary = Some(summary);
        view.scanning = false;
        view
    }

    /// Create an empty view that a progressive scan folds into (FR-2.1).
    /// `root`/`zoom` are set when the scan root's upsert arrives.
    pub fn for_scan(scan_path: PathBuf) -> Self {
        Self {
            builder: TreeBuilder::new(),
            root: 0,
            zoom: 0,
            back: Vec::new(),
            forward: Vec::new(),
            selected: None,
            is_drive_view: diskspace::is_volume_root(&scan_path),
            scan_path,
            snapshot_source: None,
            summary: None,
            progress: ScanProgress::default(),
            scanning: true,
            filter_text: String::new(),
            size_mode: SizeMode::Allocated,
            color_style: ColorStyle::Flat,
            hard_hide_filtered: false,
            class_styles: defaults::file_class_styles(),
            flat_colors: defaults::palette(true).flat,
            tag_colors: defaults::palette(true).tags,
            level_contrast: defaults::palette(true).level_contrast,
            filter_cache: None,
            verdicts: Vec::new(),
            verdicts_dirty: true,
            last_verdict_pass: None,
            flash_enabled: true,
            flash_marks: HashMap::new(),
            changed: Vec::new(),
            show_free_space: true,
            show_unknown: true,
            drive_space: None,
            drive_space_fetched: None,
            display_depth: 1,
            zoom_anim_ms: 150,
            anim: None,
            layout_epoch: 0,
            model_epoch: 0,
            resort_once: false,
            layout_cache: None,
        }
    }

    /// The scanned tree (live while scanning).
    pub fn tree(&self) -> &Tree {
        self.builder.tree()
    }

    /// Whether the model has its root node yet (false only in the first
    /// frames of a fresh scan).
    pub fn has_root(&self) -> bool {
        self.tree().root().is_some()
    }

    /// Fold one streamed scan event into the live model (FR-2.1). The root
    /// upsert initializes `root`/`zoom`.
    pub fn apply_scan_event(&mut self, event: ScanEvent) {
        let is_root_upsert = matches!(&event, ScanEvent::Upsert(u) if u.parent_path.is_none());
        if let Some(id) = self.builder.apply_tracked(event) {
            if is_root_upsert {
                self.root = id;
                self.zoom = id;
            }
            self.model_changed(id);
        }
    }

    /// Reset the model for a fresh (re)scan; the new root upsert re-anchors
    /// the view. Called when the first event of a rescan arrives so the old
    /// tree stays visible until then (no flicker).
    pub fn begin_fresh_scan(&mut self) {
        self.builder = TreeBuilder::new();
        self.back.clear();
        self.forward.clear();
        self.selected = None;
        self.summary = None;
        self.flash_marks.clear();
        self.layout_cache = None;
        self.verdicts_dirty = true;
        self.model_epoch += 1;
    }

    /// Bookkeeping shared by scan and watcher mutations.
    fn model_changed(&mut self, id: NodeId) {
        if self.flash_enabled && self.changed.len() < 4096 {
            self.changed.push(id);
        }
        self.verdicts_dirty = true;
        self.model_epoch += 1;
    }

    /// Apply a live-update event (FR-7.1). Pure model operation — the app
    /// shell turns [`WatchOutcome::RescanSubtree`]/[`WatchOutcome::RescanFull`]
    /// into actual scans.
    pub fn apply_watch_event(&mut self, event: &WatchEvent) -> WatchOutcome {
        match event {
            WatchEvent::Upsert(path) => self.watch_upsert(path),
            WatchEvent::Remove(path) => self.watch_remove(path),
            WatchEvent::SubtreeDirty(path) => {
                if path == &self.scan_path {
                    WatchOutcome::RescanFull
                } else {
                    WatchOutcome::RescanSubtree(path.clone())
                }
            }
        }
    }

    fn watch_upsert(&mut self, path: &Path) -> WatchOutcome {
        if let Some(id) = self.find_by_path(path) {
            // Existing entry: re-stat it in place (FR-7.1).
            match rss_scan::stat_entry(path) {
                Some(params) => {
                    {
                        let tree = self.builder.tree_mut();
                        tree.set_own_sizes(
                            id,
                            params.logical_size,
                            params.allocated_size,
                            params.ads_size,
                        );
                        let node = tree.node_mut(id);
                        node.flags = params.flags;
                        node.created = params.created;
                        node.accessed = params.accessed;
                        node.modified = params.modified;
                    }
                    self.model_changed(id);
                    WatchOutcome::Applied
                }
                // Vanished between event and stat: treat as removal.
                None => self.watch_remove(path),
            }
        } else {
            // New entry: insert under its parent. A new directory needs a
            // subtree rescan for its contents.
            let Some(parent) = path.parent() else {
                return WatchOutcome::Ignored;
            };
            let Some(params) = rss_scan::stat_entry(path) else {
                return WatchOutcome::Ignored;
            };
            let is_dir = params.kind == NodeKind::Directory;
            let id = self.builder.apply_tracked(ScanEvent::Upsert(Upsert {
                parent_path: Some(parent.to_path_buf()),
                path: path.to_path_buf(),
                params,
            }));
            match id {
                Some(id) => {
                    self.model_changed(id);
                    if is_dir {
                        WatchOutcome::RescanSubtree(path.to_path_buf())
                    } else {
                        WatchOutcome::Applied
                    }
                }
                None => WatchOutcome::Ignored,
            }
        }
    }

    fn watch_remove(&mut self, path: &Path) -> WatchOutcome {
        let Some(id) = self.find_by_path(path) else {
            return WatchOutcome::Ignored;
        };
        if id == self.root {
            // The scan root itself vanished: only a full rescan can tell.
            return WatchOutcome::RescanFull;
        }
        self.drop_subtree(id);
        WatchOutcome::Applied
    }

    /// Remove a subtree, fixing zoom/selection/history that point into it.
    /// Used by watcher removals and by subtree rescans (FR-7.4).
    pub fn drop_subtree(&mut self, id: NodeId) {
        let mut doomed = std::collections::HashSet::new();
        let mut stack = vec![id];
        while let Some(cur) = stack.pop() {
            doomed.insert(cur);
            stack.extend(self.tree().children(cur));
        }
        if doomed.contains(&self.zoom) {
            self.zoom = self.tree().node(id).parent.unwrap_or(self.root);
        }
        if self.selected.is_some_and(|s| doomed.contains(&s)) {
            self.selected = None;
        }
        self.back.retain(|b| !doomed.contains(b));
        self.forward.retain(|f| !doomed.contains(f));
        self.flash_marks.retain(|f, _| !doomed.contains(f));
        self.builder.remove_node(id);
        self.verdicts_dirty = true;
        self.layout_epoch += 1;
        self.model_epoch += 1;
    }

    /// Find a node by its filesystem path (walks from the scan root by
    /// components). `None` for paths outside the scan root.
    pub fn find_by_path(&self, path: &Path) -> Option<NodeId> {
        if !self.has_root() {
            return None;
        }
        if path == self.scan_path {
            return Some(self.root);
        }
        let rel = path.strip_prefix(&self.scan_path).ok()?;
        let mut cur = self.root;
        'descend: for comp in rel.components() {
            let name = comp.as_os_str().to_string_lossy();
            for child in self.tree().children(cur) {
                if *self.tree().node(child).name == *name {
                    cur = child;
                    continue 'descend;
                }
            }
            return None;
        }
        Some(cur)
    }

    /// Bring the derived state (parsed filter, verdict cache, drive space)
    /// up to date. Called once per frame before rendering. Never touches the
    /// scan — filters are pure functions of the already-scanned tree
    /// (FR-4.1).
    pub fn sync(&mut self) {
        let stale = self
            .filter_cache
            .as_ref()
            .is_none_or(|(text, _)| *text != self.filter_text);
        if stale {
            let classes: Vec<rss_filter::FileClass> = self
                .class_styles
                .iter()
                .map(|style| style.class.clone())
                .collect();
            let filter = Filter::parse(&self.filter_text, &classes);
            self.filter_cache = Some((self.filter_text.clone(), filter));
            self.verdicts_dirty = true;
        }
        if self.verdicts_dirty {
            // A verdict pass is O(tree); while scanning, throttle it — the
            // dim state may lag the live model by a fraction of a second.
            let due = self
                .last_verdict_pass
                .is_none_or(|t| t.elapsed() >= VERDICT_TICK);
            if !self.scanning || due {
                self.verdicts_dirty = false;
                self.last_verdict_pass = Some(Instant::now());
                let filter = &self.filter_cache.as_ref().expect("synced above").1;
                self.verdicts = compute_verdicts(self.tree(), self.root, filter);
            }
        }
        // Drive space for the FR-3.13 elements / FR-1.8 progress.
        if self.is_drive_view
            && self
                .drive_space_fetched
                .is_none_or(|t| t.elapsed() >= DISKSPACE_TICK)
        {
            self.drive_space_fetched = Some(Instant::now());
            self.drive_space = diskspace::disk_space(&self.scan_path);
        }
    }

    /// Bytes of the scanned volume that are not yet accounted for
    /// (FR-2.9): total minus free minus scanned-so-far. Only meaningful for
    /// drive views while scanning.
    pub fn unknown_bytes(&self) -> u64 {
        self.drive_space.map_or(0, |ds| {
            ds.total
                .saturating_sub(ds.free)
                .saturating_sub(self.progress.allocated_bytes)
        })
    }

    /// Non-fatal filter parse warnings, with spans into `filter_text`
    /// (FR-4.13). Empty when the filter is well-formed. Only meaningful after
    /// [`Self::sync`].
    pub fn filter_warnings(&self) -> &[ParseWarning] {
        self.filter_cache
            .as_ref()
            .map_or(&[], |(_, filter)| filter.warnings())
    }

    /// Whether a non-empty, condition-bearing filter is active.
    pub fn has_active_filter(&self) -> bool {
        self.filter_cache
            .as_ref()
            .is_some_and(|(_, filter)| !filter.is_empty())
    }

    /// The parsed filter, after [`Self::sync`]. `None` before the first sync.
    pub fn filter(&self) -> Option<&Filter> {
        self.filter_cache.as_ref().map(|(_, filter)| filter)
    }

    /// The filter verdict for a node (FR-4.11 tri-state). Everything is
    /// [`FilterVerdict::Visible`] when no filter is active.
    pub fn verdict(&self, id: NodeId) -> FilterVerdict {
        self.verdicts
            .get(id as usize)
            .copied()
            .unwrap_or(FilterVerdict::Visible)
    }

    /// Toggle `tag` on node `id` (FR-5.1: the same tag again clears it, a
    /// different tag replaces it). Tags feed tag filters (FR-4.6), so the
    /// verdict cache is invalidated.
    pub fn toggle_tag(&mut self, id: NodeId, tag: Tag) {
        let node = self.builder.tree_mut().node_mut(id);
        node.tag = if node.tag == Some(tag) {
            None
        } else {
            Some(tag)
        };
        self.verdicts_dirty = true;
    }

    /// Toggle `tag` on the current selection (CTRL+1..4 / bare 1..4);
    /// no-op without a selection.
    pub fn toggle_selected_tag(&mut self, tag: Tag) {
        if let Some(id) = self.selected {
            self.toggle_tag(id, tag);
        }
    }

    /// Clear all tags in the subtree under `id`, including filter-hidden
    /// elements (CTRL+0; FR-5.1/FR-4.12). Iterative: deep trees must not be
    /// able to overflow the stack.
    pub fn clear_tags_below(&mut self, id: NodeId) {
        let mut stack = vec![id];
        while let Some(cur) = stack.pop() {
            self.builder.tree_mut().node_mut(cur).tag = None;
            stack.extend(self.tree().children(cur));
        }
        self.verdicts_dirty = true;
    }

    /// Navigate to `id`, pushing the current zoom onto the back stack
    /// (FR-3.6). Animates from the old zoom node's cell (FR-3.10).
    pub fn navigate_to(&mut self, id: NodeId) {
        if id == self.zoom {
            return;
        }
        let from = self.zoom;
        self.back.push(self.zoom);
        self.forward.clear();
        self.zoom = id;
        self.selected = None;
        self.start_anim(AnimKind::FromNode(from));
    }

    /// Double-click zoom (FR-3.5): navigate to `id`, animating the new
    /// content growing out of the clicked cell's rect (FR-3.10).
    pub fn navigate_from_rect(&mut self, id: NodeId, rect: TmRect) {
        if id == self.zoom {
            return;
        }
        self.back.push(self.zoom);
        self.forward.clear();
        self.zoom = id;
        self.selected = None;
        self.start_anim(AnimKind::FromRect(rect));
    }

    /// Set the zoom without touching history or animation (snapshot load,
    /// FR-8.7).
    pub fn zoom_to_silent(&mut self, id: NodeId) {
        self.zoom = id;
        self.selected = None;
    }

    fn start_anim(&mut self, kind: AnimKind) {
        self.anim = (self.zoom_anim_ms > 0).then_some(AnimState { kind, start: None });
        self.resort_once = true; // user-initiated view change (FR-3.16)
    }

    /// Current zoom-animation transform for the full content `area`, as
    /// `(scale, [dx, dy])`. `None` when not animating. `FromNode` animations
    /// are resolved against the layout cache.
    pub fn anim_transform(&self, area: TmRect, now: f64) -> Option<(f32, [f32; 2])> {
        let anim = self.anim?;
        let start = anim.start?;
        let t = ((now - start) * 1000.0 / self.zoom_anim_ms as f64).min(1.0);
        // Smoothstep easing.
        let p = (t * t * (3.0 - 2.0 * t)) as f32;
        let src = match anim.kind {
            AnimKind::FromRect(rect) => rect,
            AnimKind::FromNode(id) => self.layout_cell_rect(id)?,
        };
        // Content compressed into `src` at p=0, identity at p=1.
        let s0 = (src.w / area.w).min(src.h / area.h);
        if s0 <= 0.0 || !s0.is_finite() {
            return None;
        }
        let scale = s0 + (1.0 - s0) * p;
        let dx0 = src.x - area.x * s0;
        let dy0 = src.y - area.y * s0;
        Some((scale, [dx0 * (1.0 - p), dy0 * (1.0 - p)]))
    }

    /// The laid-out rect of a cell from the cache (any level).
    fn layout_cell_rect(&self, id: NodeId) -> Option<TmRect> {
        let cache = self.layout_cache.as_ref()?;
        cache
            .top
            .iter()
            .chain(cache.subs.values().flatten())
            .find(|(cid, _)| *cid == id)
            .map(|(_, r)| *r)
    }

    /// Mark the animation started (renderer, first frame with new layout).
    pub fn begin_anim(&mut self, now: f64) {
        if let Some(anim) = &mut self.anim {
            if anim.start.is_none() {
                anim.start = Some(now);
            }
        }
    }

    /// Whether a zoom animation is pending or playing (tests, shell repaint
    /// decisions).
    pub fn anim_active(&self) -> bool {
        self.anim.is_some()
    }

    /// Whether a zoom animation is currently playing.
    pub fn is_animating(&self, now: f64) -> bool {
        match self.anim {
            Some(anim) => match anim.start {
                None => true,
                Some(start) => (now - start) * 1000.0 < self.zoom_anim_ms as f64,
            },
            None => false,
        }
    }

    /// End the animation, if any (renderer, when the duration elapsed).
    pub fn end_anim(&mut self) {
        self.anim = None;
    }

    /// Flash bookkeeping: move this frame's changed nodes into the flash
    /// map, prune expired marks (FR-2.11). Returns true while any flash is
    /// still visible (the shell keeps repainting, FR-3.17 exception).
    pub fn update_flashes(&mut self, now: f64) -> bool {
        let until = now + FLASH_SECS;
        for id in self.changed.drain(..) {
            self.flash_marks.insert(id, until);
        }
        self.flash_marks.retain(|_, u| *u > now);
        !self.flash_marks.is_empty()
    }

    /// Flash alpha (0..1) for a cell, if it is currently flashing.
    pub fn flash_alpha(&self, id: NodeId, now: f64) -> Option<f32> {
        let until = *self.flash_marks.get(&id)?;
        let remaining = ((until - now) / FLASH_SECS).clamp(0.0, 1.0);
        Some((remaining * 0.6) as f32)
    }

    /// Adjust the display-depth limit (CTRL+`+` / CTRL+`-`, FR-3.14).
    pub fn adjust_display_depth(&mut self, delta: i32) {
        self.display_depth = (self.display_depth as i32 + delta).clamp(1, 8) as u32;
        self.layout_epoch += 1;
    }

    pub fn can_go_back(&self) -> bool {
        !self.back.is_empty()
    }

    pub fn can_go_forward(&self) -> bool {
        !self.forward.is_empty()
    }

    pub fn go_back(&mut self) {
        if let Some(prev) = self.back.pop() {
            let from = self.zoom;
            self.forward.push(self.zoom);
            self.zoom = prev;
            self.selected = None;
            self.start_anim(AnimKind::FromNode(from));
        }
    }

    pub fn go_forward(&mut self) {
        if let Some(next) = self.forward.pop() {
            let from = self.zoom;
            self.back.push(self.zoom);
            self.zoom = next;
            self.selected = None;
            self.start_anim(AnimKind::FromNode(from));
        }
    }

    /// Zoom out one level (CTRL+UP, FR-3.6). No-op at the scan root.
    pub fn zoom_out_one(&mut self) {
        if let Some(parent) = self.tree().node(self.zoom).parent {
            self.navigate_to(parent);
        }
    }

    /// Jump back to the view root (CTRL+HOME, FR-3.6).
    pub fn zoom_home(&mut self) {
        self.navigate_to(self.root);
    }

    /// Breadcrumb trail (FR-3.7): nodes from the scan root down to the
    /// current zoom, root first.
    pub fn breadcrumb(&self) -> Vec<NodeId> {
        let mut trail = Vec::new();
        let mut cur = Some(self.zoom);
        while let Some(id) = cur {
            trail.push(id);
            cur = self.tree().node(id).parent;
        }
        trail.reverse();
        trail
    }

    /// The tag border color for the active theme (FR-5.1/FR-11.5).
    pub fn tag_color(&self, tag: Tag) -> egui::Color32 {
        match tag {
            Tag::Red => self.tag_colors[0],
            Tag::Yellow => self.tag_colors[1],
            Tag::Green => self.tag_colors[2],
            Tag::Blue => self.tag_colors[3],
        }
    }

    /// Apply a theme palette (FR-11.5): flat colors, tag colors, class
    /// colors, level contrast.
    pub fn apply_palette(&mut self, palette: &defaults::Palette) {
        self.flat_colors = palette.flat.clone();
        self.tag_colors = palette.tags;
        self.level_contrast = palette.level_contrast;
        for (style, themed) in self.class_styles.iter_mut().zip(palette.classes.iter()) {
            style.color = themed.color;
        }
    }

    /// The size a node's treemap area is proportional to under the current
    /// [`SizeMode`] (aggregates include the whole subtree — filtered-out
    /// elements keep counting, FR-4.12).
    pub fn size_of(&self, id: NodeId) -> u64 {
        let node = self.tree().node(id);
        match self.size_mode {
            SizeMode::Allocated => node.agg_allocated,
            SizeMode::Logical => node.agg_logical,
        }
    }
}

/// Bottom-up filter verdicts for the whole tree (SPEC.md §5.6).
///
/// Equivalent to running `rss_filter::evaluate` on every node (a failing
/// node is `Dimmed` iff some node in its subtree matches), but computed in a
/// single iterative post-order pass instead of per-cell subtree rescans —
/// and with no recursion, so deep trees cannot overflow the stack.
///
/// Returns an empty vector for an empty filter (everything visible).
fn compute_verdicts(tree: &Tree, root: NodeId, filter: &Filter) -> Vec<FilterVerdict> {
    if filter.is_empty() || tree.root().is_none() {
        return Vec::new();
    }
    // Ages are computed against the current time (FR-4.5).
    let now = rss_core::filetime_from_unix(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64),
    );

    // Iterative post-order traversal: children are visited before parents.
    let mut post_order = Vec::new();
    let mut max_id = root;
    let mut stack = vec![(root, false)];
    while let Some((id, processed)) = stack.pop() {
        if processed {
            post_order.push(id);
            continue;
        }
        max_id = max_id.max(id);
        stack.push((id, true));
        for child in tree.children(id) {
            stack.push((child, false));
        }
    }

    let mut verdicts = vec![FilterVerdict::Hidden; max_id as usize + 1];
    for id in post_order {
        verdicts[id as usize] = if filter.matches(tree, id, now) {
            FilterVerdict::Visible
        } else if tree
            .children(id)
            .any(|c| verdicts[c as usize] != FilterVerdict::Hidden)
        {
            // A matching descendant exists: keep the node as dimmed context.
            FilterVerdict::Dimmed
        } else {
            FilterVerdict::Hidden
        };
    }
    verdicts
}

#[cfg(test)]
mod tests {
    use super::*;
    use rss_core::{NodeKind, NodeParams};

    /// Small deterministic tree: root(dir) with files a(100), b(300) and
    /// subdir d with file c(600).
    pub fn sample_tree() -> (Tree, NodeId, NodeId, NodeId, NodeId, NodeId) {
        let mut tree = Tree::with_root(NodeParams::named("root", NodeKind::Directory));
        let root = tree.root().unwrap();
        let a = tree.add_child(
            root,
            NodeParams::named("a.bin", NodeKind::File).sizes(100, 100),
        );
        let b = tree.add_child(
            root,
            NodeParams::named("b.bin", NodeKind::File).sizes(300, 300),
        );
        let d = tree.add_child(root, NodeParams::named("d", NodeKind::Directory));
        let c = tree.add_child(
            d,
            NodeParams::named("c.bin", NodeKind::File).sizes(600, 600),
        );
        (tree, root, a, b, d, c)
    }

    fn sample_view() -> ScanView {
        let (tree, root, ..) = sample_tree();
        ScanView::new(tree, root, PathBuf::from("root"), ScanSummary::default())
    }

    /// Find a node by name anywhere under the root.
    fn find(view: &ScanView, name: &str) -> NodeId {
        let mut stack = vec![view.root];
        while let Some(id) = stack.pop() {
            if &*view.tree().node(id).name == name {
                return id;
            }
            stack.extend(view.tree().children(id));
        }
        panic!("no node named {name}");
    }

    #[test]
    fn navigation_history_round_trip() {
        let (tree, root, _a, _b, d, _c) = sample_tree();
        let summary = ScanSummary::default();
        let mut view = ScanView::new(tree, root, PathBuf::from("root"), summary);

        assert_eq!(view.zoom, root);
        assert!(!view.can_go_back() && !view.can_go_forward());

        view.navigate_to(d);
        assert_eq!(view.zoom, d);
        assert!(view.can_go_back());

        view.go_back();
        assert_eq!(view.zoom, root);
        assert!(view.can_go_forward());

        view.go_forward();
        assert_eq!(view.zoom, d);

        // A fresh navigation clears the forward stack.
        view.go_back();
        view.navigate_to(d);
        assert!(!view.can_go_forward());

        // Breadcrumbs and zoom-out.
        let trail = view.breadcrumb();
        assert_eq!(trail, vec![root, d]);
        view.zoom_out_one();
        assert_eq!(view.zoom, root);
        view.zoom_out_one(); // no-op at root, does not panic
        assert_eq!(view.zoom, root);

        view.navigate_to(d);
        view.zoom_home();
        assert_eq!(view.zoom, root);
    }

    #[test]
    fn verdicts_update_with_filter_text() {
        let mut view = sample_view();
        let (a, b, d, c) = (
            find(&view, "a.bin"),
            find(&view, "b.bin"),
            find(&view, "d"),
            find(&view, "c.bin"),
        );

        view.filter_text = "*.jpg".to_string(); // nothing matches
        view.sync();
        assert!(view.has_active_filter());
        for id in [a, b, d, c, view.root] {
            assert_eq!(view.verdict(id), FilterVerdict::Hidden);
        }

        view.filter_text = "*.bin".to_string(); // every file matches
        view.sync();
        assert_eq!(view.verdict(a), FilterVerdict::Visible);
        assert_eq!(view.verdict(b), FilterVerdict::Visible);
        assert_eq!(view.verdict(c), FilterVerdict::Visible);
        assert_eq!(view.verdict(d), FilterVerdict::Dimmed); // contains c.bin
        assert_eq!(view.verdict(view.root), FilterVerdict::Dimmed);

        view.filter_text = String::new();
        view.sync();
        assert!(!view.has_active_filter());
        for id in [a, b, d, c, view.root] {
            assert_eq!(view.verdict(id), FilterVerdict::Visible);
        }
    }

    /// Cross-check the bottom-up verdict pass against `rss_filter::evaluate`
    /// node by node for a mix of mask, size, age and tag filters.
    #[test]
    fn verdicts_match_rss_filter_evaluate() {
        let mut view = sample_view();
        let ids: Vec<NodeId> = {
            let mut ids = Vec::new();
            let mut stack = vec![view.root];
            while let Some(id) = stack.pop() {
                ids.push(id);
                stack.extend(view.tree().children(id));
            }
            ids
        };
        for filter_text in ["*.bin;>150b", "c.?in", ">1kb", "|*.bin", ":red"] {
            view.filter_text = filter_text.to_string();
            view.sync();
            let filter = Filter::parse(filter_text, &[]);
            assert!(filter.warnings().is_empty());
            let now = rss_core::filetime_from_unix(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64,
            );
            for &id in &ids {
                assert_eq!(
                    view.verdict(id),
                    rss_filter::evaluate(view.tree(), id, &filter, now),
                    "filter {filter_text:?}, node {id}"
                );
            }
        }
    }

    #[test]
    fn tags_toggle_and_clear() {
        let mut view = sample_view();
        let a = find(&view, "a.bin");
        let c = find(&view, "c.bin");

        view.selected = Some(a);
        view.toggle_selected_tag(Tag::Red);
        assert_eq!(view.tree().node(a).tag, Some(Tag::Red));
        // A different tag replaces.
        view.toggle_selected_tag(Tag::Blue);
        assert_eq!(view.tree().node(a).tag, Some(Tag::Blue));
        // The same tag again clears (FR-5.1 toggle).
        view.toggle_selected_tag(Tag::Blue);
        assert_eq!(view.tree().node(a).tag, None);

        // No selection: no-op.
        view.selected = None;
        view.toggle_selected_tag(Tag::Green);
        assert_eq!(view.tree().node(a).tag, None);

        // CTRL+0 clears everything under the zoom, across nesting levels.
        view.toggle_tag(a, Tag::Red);
        view.toggle_tag(c, Tag::Green);
        view.clear_tags_below(view.zoom);
        assert_eq!(view.tree().node(a).tag, None);
        assert_eq!(view.tree().node(c).tag, None);
    }

    #[test]
    fn tag_filter_verdicts_follow_tag_changes() {
        let mut view = sample_view();
        let a = find(&view, "a.bin");

        view.filter_text = ":red".to_string();
        view.sync();
        assert_eq!(view.verdict(a), FilterVerdict::Hidden);

        view.toggle_tag(a, Tag::Red);
        view.sync(); // verdicts invalidated by the tag change
        assert_eq!(view.verdict(a), FilterVerdict::Visible);
    }

    /// FR-2.1: a view folds streamed events progressively and stays navigable
    /// mid-scan.
    #[test]
    fn progressive_events_build_a_navigable_tree() {
        let mut view = ScanView::for_scan(PathBuf::from("/scan"));
        let upsert = |parent: Option<&str>, path: &str, params: NodeParams| {
            ScanEvent::Upsert(Upsert {
                parent_path: parent.map(PathBuf::from),
                path: PathBuf::from(path),
                params,
            })
        };
        view.apply_scan_event(upsert(
            None,
            "/scan",
            NodeParams::named("/scan", NodeKind::Directory),
        ));
        assert_eq!(view.tree().root(), Some(view.root));
        view.apply_scan_event(upsert(
            Some("/scan"),
            "/scan/d",
            NodeParams::named("d", NodeKind::Directory),
        ));
        // Navigable after two events, before the scan is done.
        let d = view.find_by_path(Path::new("/scan/d")).unwrap();
        view.navigate_to(d);
        assert_eq!(view.zoom, d);
        view.apply_scan_event(upsert(
            Some("/scan/d"),
            "/scan/d/f.bin",
            NodeParams::named("f.bin", NodeKind::File).sizes(50, 50),
        ));
        assert_eq!(view.tree().node(view.root).agg_logical, 50);
        view.go_back();
        assert_eq!(view.zoom, view.root);
    }

    /// FR-7.1/7.4/7.5: watcher upserts patch the tree; removals drop
    /// subtrees and fix navigation state; dirty subtrees ask for rescans.
    #[test]
    fn watch_events_patch_the_tree() {
        let mut view = sample_view();
        let d = find(&view, "d");
        let c = find(&view, "c.bin");

        // New file under d that does not exist on disk: stat fails, ignored.
        let outcome = view.apply_watch_event(&WatchEvent::Upsert(PathBuf::from("root/d/new.bin")));
        assert_eq!(outcome, WatchOutcome::Ignored);

        // Upsert of an existing but on-disk-vanished entry is a removal.
        let outcome = view.apply_watch_event(&WatchEvent::Upsert(PathBuf::from("root/a.bin")));
        assert_eq!(outcome, WatchOutcome::Applied);
        assert!(view.find_by_path(Path::new("root/a.bin")).is_none());

        // Removal of a directory fixes zoom/selection/history.
        view.selected = Some(c);
        view.navigate_to(d);
        let outcome = view.apply_watch_event(&WatchEvent::Remove(PathBuf::from("root/d")));
        assert_eq!(outcome, WatchOutcome::Applied);
        assert_eq!(view.zoom, view.root, "zoom falls back to the parent");
        assert_eq!(view.selected, None);
        // The back stack held [root] (from navigate_to); the removed d must
        // be purged from it. Going back lands on root — never a recycled id.
        view.go_back();
        assert_eq!(view.zoom, view.root);
        assert!(!view.can_go_back());
        assert_eq!(view.tree().node(view.root).agg_logical, 300); // b.bin left

        // Root removal asks for a full rescan.
        let outcome = view.apply_watch_event(&WatchEvent::Remove(PathBuf::from("root")));
        assert_eq!(outcome, WatchOutcome::RescanFull);

        // SubtreeDirty at a subpath asks for a subtree rescan; at the root,
        // a full rescan (FR-7.4/7.5).
        let outcome =
            view.apply_watch_event(&WatchEvent::SubtreeDirty(PathBuf::from("root/b.bin")));
        assert_eq!(
            outcome,
            WatchOutcome::RescanSubtree(PathBuf::from("root/b.bin"))
        );
        let outcome = view.apply_watch_event(&WatchEvent::SubtreeDirty(PathBuf::from("root")));
        assert_eq!(outcome, WatchOutcome::RescanFull);
    }

    /// FR-2.11: flashes track changed nodes and expire; the toggle works.
    #[test]
    fn flash_marks_expire() {
        let mut view = ScanView::for_scan(PathBuf::from("/scan"));
        view.apply_scan_event(ScanEvent::Upsert(Upsert {
            parent_path: None,
            path: PathBuf::from("/scan"),
            params: NodeParams::named("/scan", NodeKind::Directory),
        }));
        assert!(view.update_flashes(10.0));
        assert!(view.flash_alpha(view.root, 10.1).is_some());
        // After the flash duration, marks are gone.
        assert!(!view.update_flashes(10.0 + FLASH_SECS + 0.1));
        assert!(view.flash_alpha(view.root, 20.0).is_none());

        // Disabled flash: no marks collected.
        view.flash_enabled = false;
        view.apply_scan_event(ScanEvent::Upsert(Upsert {
            parent_path: Some(PathBuf::from("/scan")),
            path: PathBuf::from("/scan/f.bin"),
            params: NodeParams::named("f.bin", NodeKind::File).sizes(1, 1),
        }));
        assert!(!view.update_flashes(30.0));
    }

    /// FR-3.10: the zoom-animation transform interpolates from the source
    /// rect to identity; duration 0 means instant.
    #[test]
    fn zoom_animation_transform() {
        let mut view = sample_view();
        let d = find(&view, "d");
        view.zoom_anim_ms = 100;
        view.navigate_from_rect(d, TmRect::new(10.0, 20.0, 50.0, 25.0));
        assert!(view.is_animating(0.0));
        view.begin_anim(0.0);

        let area = TmRect::new(0.0, 0.0, 200.0, 100.0);
        let (s0, _) = view.anim_transform(area, 0.0).unwrap();
        // At t=0 the content is compressed into the cell rect.
        assert!((s0 - 0.25).abs() < 1e-3, "scale {s0}");
        let (s1, [dx1, dy1]) = view.anim_transform(area, 0.1).unwrap();
        assert!((s1 - 1.0).abs() < 1e-3);
        assert!((dx1.abs() + dy1.abs()) < 1e-3);
        assert!(!view.is_animating(0.15));

        // Instant mode: no animation.
        view.zoom_anim_ms = 0;
        view.navigate_to(view.root);
        assert!(!view.is_animating(0.0));
        assert!(view.anim_transform(area, 0.0).is_none());
    }
}
