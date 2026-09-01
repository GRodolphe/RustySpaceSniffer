//! The eframe/egui application shell (SPEC.md §4.1, §4.2, §4.3, §5.1, §5.8).
//!
//! Chrome anatomy follows FR-11.1 (SpaceSniffer parity): a toolbar strip
//! (new scan, back/forward, up, root, rescan, pause, filter field, display
//! depth, flash/dim/color/size toggles) above a breadcrumb bar, a
//! window-filling treemap, and a bottom status bar. Styling is plain egui;
//! theming is M9.
//!
//! M4 structure: the app owns a list of [`ViewEntry`]s — entry 0 lives in
//! the root viewport, further scans open one egui viewport (OS window on
//! desktop, embedded window in tests) per view (FR-1.4/FR-1.7). Each entry
//! owns a [`ScanView`] (the live model), an optional background scan, and an
//! optional filesystem watcher (FR-7.x). Scan threads stream `ScanEvent`s
//! over a crossbeam channel; the UI thread folds them into the view's
//! `TreeBuilder` with a per-frame budget (FR-2.1, FR-2.10).

mod config;
mod defaults;
mod diskspace;
mod drives;
mod export;
mod fileops;
mod treemap;
mod view;

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use egui::{Align2, Key, Modifiers, RichText, Ui};
use rss_core::Tag;
use rss_scan::{ScanEngine, ScanEvent, ScanOptions, ScanProgress, ScanSummary, WalkScanner};
use rss_watch::Watcher;

pub use config::{Config, ThemeSetting};
pub use export::ExportKind;
pub use view::{ColorStyle, ScanView, WatchOutcome};

use treemap::TreemapCmd;

/// Per-frame budget for folding scan events into a view's model — the UI
/// stays responsive and the scanner never blocks on the UI (FR-2.10).
const DRAIN_BUDGET: Duration = Duration::from_millis(6);
/// Cap on watcher events applied per frame.
const WATCH_BUDGET: usize = 512;

/// Messages from a background scan thread to its view (SPEC.md §5.8: plain
/// threads + channels, no tokio).
enum ScanMsg {
    /// Throttled progress tick from the scanner (FR-3.12).
    Progress(ScanProgress),
    /// A streamed scan event (progressive population, FR-2.1).
    Event(ScanEvent),
    /// The full (re)scan finished; partial on cancel (FR-2.2).
    Finished(Result<ScanSummary, rss_scan::ScanError>),
    /// An incremental subtree rescan finished (FR-7.4).
    SubtreeFinished(PathBuf, Result<ScanSummary, rss_scan::ScanError>),
}

/// Handle to a running background scan.
struct RunningScan {
    cancel: Arc<AtomicBool>,
    pause: Arc<AtomicBool>,
}

/// One view: a live model plus its scan and watcher (§5.8).
struct ViewEntry {
    /// The live model; exists from the moment the scan starts (progressive
    /// population folds into it, FR-2.1).
    view: ScanView,
    scan: Option<RunningScan>,
    watcher: Option<Box<dyn Watcher>>,
    /// FR-7.7 affordance when live updates are unavailable.
    watch_notice: Option<String>,
    tx: crossbeam_channel::Sender<ScanMsg>,
    rx: crossbeam_channel::Receiver<ScanMsg>,
    /// The viewport this view lives in (`ViewportId::ROOT` for entry 0).
    viewport: egui::ViewportId,
    /// False after the viewport's window was closed.
    open: bool,
    /// False until the entry's first scan starts (a pristine root entry is
    /// reused by the first start-dialog scan).
    ever_scanned: bool,
    /// The next scan-root upsert resets the model (set by F5 rescan, so the
    /// old tree stays visible until fresh data arrives).
    pending_fresh: bool,
}

impl ViewEntry {
    fn new(viewport: egui::ViewportId) -> Self {
        let (tx, rx) = crossbeam_channel::unbounded();
        Self {
            view: ScanView::for_scan(PathBuf::new()),
            scan: None,
            watcher: None,
            watch_notice: None,
            tx,
            rx,
            viewport,
            open: true,
            ever_scanned: false,
            pending_fresh: false,
        }
    }

    fn completed(view: ScanView) -> Self {
        let mut entry = Self::new(egui::ViewportId::ROOT);
        entry.view = view;
        entry.ever_scanned = true;
        entry
    }
}

/// Start-dialog state (§4.1): two tabs — "Drives or Paths" and
/// "Snapshots" (FR-1.5).
struct StartDialog {
    open: bool,
    path: String,
    snapshot_path: String,
    snapshots_tab: bool,
    error: Option<String>,
}

/// The application (SPEC.md §5.1).
pub struct RssApp {
    entries: Vec<ViewEntry>,
    start: StartDialog,
    drives: Vec<PathBuf>,
    /// One-shot notice for the status bar (e.g. scan failures).
    notice: Option<String>,
    /// Captured each frame; handed to scan threads for repaint wakeups.
    ctx: Option<egui::Context>,
    /// The FR-6.4 delete confirmation dialog, when open.
    delete_dialog: Option<fileops::DeleteDialog>,
    /// Persisted settings (FR-10.1).
    config: Config,
    /// The config file path in use (first existing/writable candidate).
    config_path: Option<PathBuf>,
    /// Settings dialog visibility (M9).
    settings_open: bool,
    /// Log console visibility (FR-2.13).
    log_open: bool,
    /// The theme variant the palettes were last applied with.
    applied_dark: Option<bool>,
}

impl Default for RssApp {
    fn default() -> Self {
        Self::new()
    }
}

impl RssApp {
    pub fn new() -> Self {
        let (config, config_path) = config::load();
        Self {
            config,
            config_path,
            entries: Vec::new(),
            start: StartDialog {
                open: true,
                path: String::new(),
                snapshot_path: String::new(),
                snapshots_tab: false,
                error: None,
            },
            drives: drives::list_drives(),
            notice: None,
            ctx: None,
            delete_dialog: None,
            settings_open: false,
            log_open: false,
            applied_dark: None,
        }
    }

    /// Create the app with an explicit config (tests); production uses
    /// [`RssApp::new`] which loads the persisted one.
    pub fn with_config(config: Config, config_path: Option<PathBuf>) -> Self {
        let mut app = Self::new();
        app.config = config;
        app.config_path = config_path;
        app
    }

    /// Replace the config (and its target path) after construction — tests
    /// only; production builds it via [`RssApp::with_config`].
    #[doc(hidden)]
    pub fn config_for_test(&mut self, config: Config, path: Option<PathBuf>) {
        self.config = config;
        self.config_path = path;
        self.applied_dark = None; // force palette re-application
    }

    /// The current theme setting (FR-11.4).
    pub fn theme_setting(&self) -> ThemeSetting {
        self.config.theme
    }

    /// Set the theme (FR-11.9: applies instantly and persists).
    pub fn set_theme(&mut self, theme: ThemeSetting) {
        self.config.theme = theme;
        self.save_config();
    }

    /// Persist the config; FR-10.3: unwritable location → status notice.
    fn save_config(&mut self) {
        let saved = config::save(&self.config, self.config_path.as_deref());
        match saved {
            Some(path) => self.config_path = Some(path),
            None => {
                self.notice =
                    Some("settings are not saved (no writable config location)".to_string());
            }
        }
    }

    /// The root viewport's view, if a scan has started there.
    pub fn view(&self) -> Option<&ScanView> {
        self.entries.first().map(|e| &e.view)
    }

    /// Mutable access to the root viewport's view (tests, later milestones).
    pub fn view_mut(&mut self) -> Option<&mut ScanView> {
        self.entries.first_mut().map(|e| &mut e.view)
    }

    /// Number of open views (FR-1.7).
    pub fn view_count(&self) -> usize {
        self.entries.len()
    }

    /// The scan path of view `i` (for the Windows menu and tests).
    pub fn view_path(&self, i: usize) -> Option<&Path> {
        self.entries.get(i).map(|e| e.view.scan_path.as_path())
    }

    /// Whether any view's scan is running.
    pub fn is_scanning(&self) -> bool {
        self.entries.iter().any(|e| e.scan.is_some())
    }

    /// Attach an already-built tree as the root view, bypassing the scan
    /// thread. Used by headless UI tests; M7 snapshot loading uses the same
    /// seam (loaded snapshots have no live link, FR-8.7).
    pub fn attach_tree(
        &mut self,
        tree: rss_core::Tree,
        root: rss_core::NodeId,
        scan_path: PathBuf,
        summary: ScanSummary,
    ) {
        self.start.open = false;
        self.entries.clear();
        self.entries.push(ViewEntry::completed(ScanView::new(
            tree, root, scan_path, summary,
        )));
        self.apply_config_defaults_to_entry(0);
    }

    /// Start scanning `path`; the first scan reuses the root viewport, later
    /// scans open one viewport per path (FR-1.4/FR-1.7).
    pub fn start_scan(&mut self, path: PathBuf) {
        self.open_scans(vec![path]);
    }

    /// Start a scan that is born paused (FR-2.3 test/debug hook).
    #[doc(hidden)]
    pub fn start_scan_paused(&mut self, path: PathBuf) {
        self.open_scans(vec![path]);
        self.set_root_scan_paused(true);
    }

    /// Pause/resume the root view's scan (FR-2.3). No-op when idle.
    pub fn set_root_scan_paused(&mut self, paused: bool) {
        if let Some(scan) = self.entries.first_mut().and_then(|e| e.scan.as_ref()) {
            scan.pause.store(paused, Ordering::Relaxed);
        }
    }

    /// Whether the root view's scan is paused.
    pub fn root_scan_paused(&self) -> bool {
        self.entries
            .first()
            .and_then(|e| e.scan.as_ref())
            .is_some_and(|s| s.pause.load(Ordering::Relaxed))
    }

    /// Inject a watcher event into the root view, driving the same code path
    /// as the watcher drain (FR-7.x). Tests use this instead of relying on
    /// OS filesystem notifications.
    pub fn inject_watch_event(&mut self, event: rss_watch::WatchEvent) {
        if self.entries.is_empty() {
            return;
        }
        let outcome = self.entries[0].view.apply_watch_event(&event);
        match outcome {
            WatchOutcome::RescanSubtree(path) => self.rescan_subtree(0, path),
            WatchOutcome::RescanFull => self.rescan_entry(0),
            _ => {}
        }
    }

    /// Feed a scan event through the root view's scan channel — the same
    /// path the scan thread's sink uses. Tests use this to drive the
    /// progressive-population path deterministically (FR-2.1).
    #[doc(hidden)]
    pub fn debug_stream_root_event(&mut self, event: ScanEvent) {
        if let Some(entry) = self.entries.first() {
            let _ = entry.tx.send(ScanMsg::Event(event));
        }
    }

    /// Export the root view's current zoom to `dest` (FR-8.1). Errors are
    /// also shown in the status bar.
    pub fn export_root_view(
        &mut self,
        kind: &ExportKind,
        dest: &Path,
    ) -> Result<(), rss_export::ExportError> {
        let Some(entry) = self.entries.first() else {
            return Ok(());
        };
        let result = std::fs::File::create(dest)
            .map_err(rss_export::ExportError::from)
            .and_then(|mut f| export::export_view(&entry.view, kind, &mut f));
        if let Err(err) = &result {
            self.notice = Some(format!("export failed: {err}"));
        }
        result
    }

    /// Ask for a destination file and export the view's current zoom.
    fn export_dialog(&mut self, idx: usize, kind: ExportKind) {
        let default_name = format!("report.{}", kind.extension());
        if let Some(dest) = rfd::FileDialog::new()
            .set_file_name(&default_name)
            .save_file()
        {
            if idx == 0 {
                let _ = self.export_root_view(&kind, &dest);
            }
        }
    }

    /// Save the root view as a `.rssnap` snapshot (FR-8.7).
    pub fn save_root_snapshot(&mut self, dest: &Path) -> Result<(), rss_export::SnapshotError> {
        let Some(entry) = self.entries.first() else {
            return Ok(());
        };
        let result = std::fs::File::create(dest)
            .map_err(rss_export::SnapshotError::from)
            .and_then(|mut f| {
                export::save_snapshot(&entry.view, env!("CARGO_PKG_VERSION"), &mut f)
            });
        if let Err(err) = &result {
            self.notice = Some(format!("snapshot save failed: {err}"));
        }
        result
    }

    /// Load a `.rssnap` snapshot as a read-only view (FR-8.7): no scan, no
    /// watcher. Reuses the pristine root viewport, else opens a new one.
    pub fn load_snapshot(&mut self, path: &Path) {
        match export::load_snapshot(path) {
            Ok(view) => {
                self.start.open = false;
                let idx = match self.entries.first() {
                    Some(entry) if entry.ever_scanned => self.push_entry(),
                    Some(_) => 0,
                    None => {
                        self.entries.push(ViewEntry::new(egui::ViewportId::ROOT));
                        0
                    }
                };
                self.entries[idx].view = view;
                self.entries[idx].ever_scanned = true;
                self.apply_config_defaults_to_entry(idx);
                let entry = &mut self.entries[idx];
                entry.scan = None;
                entry.watcher = None; // snapshots have no live link (FR-8.7)
            }
            Err(err) => {
                self.notice = Some(format!("snapshot load failed: {err}"));
            }
        }
    }

    /// Open one scan per path (FR-1.7).
    pub fn open_scans(&mut self, paths: Vec<PathBuf>) {
        self.start.open = false;
        for path in paths {
            let idx = match self.entries.first() {
                // A pristine root entry hosts the very first scan.
                Some(entry) if entry.ever_scanned => self.push_entry(),
                Some(_) => 0,
                None => {
                    self.entries.push(ViewEntry::new(egui::ViewportId::ROOT));
                    0
                }
            };
            self.start_entry_scan(idx, path, true);
        }
    }

    /// Append a new viewport entry and return its index.
    fn push_entry(&mut self) -> usize {
        let idx = self.entries.len();
        let viewport = egui::ViewportId::from_hash_of(("rss-view", idx));
        self.entries.push(ViewEntry::new(viewport));
        idx
    }

    /// Apply the persisted config defaults to an entry's view (FR-10.1):
    /// palette for the active theme, flash toggle, zoom animation, display
    /// depth.
    fn apply_config_defaults_to_entry(&mut self, idx: usize) {
        let palette = defaults::palette(self.applied_dark.unwrap_or(true));
        let view = &mut self.entries[idx].view;
        view.apply_palette(&palette);
        if let Some(flash) = self.config.flash_enabled {
            view.flash_enabled = flash;
        }
        if let Some(anim) = self.config.zoom_anim_ms {
            view.zoom_anim_ms = anim;
        }
        if let Some(depth) = self.config.display_depth {
            view.display_depth = depth;
        }
    }

    /// (Re)scan `path` in entry `idx` on a background thread (FR-2.1).
    /// `fresh` resets the model once new data arrives; a rescan keeps the
    /// old tree visible until then.
    fn start_entry_scan(&mut self, idx: usize, path: PathBuf, fresh: bool) {
        self.apply_config_defaults_to_entry(idx);
        let entry = &mut self.entries[idx];
        if let Some(scan) = &entry.scan {
            scan.cancel.store(true, Ordering::Relaxed);
        }
        entry.watcher = None; // the old watcher dies with the old scan
        entry.watch_notice = None;
        let cancel = Arc::new(AtomicBool::new(false));
        let pause = Arc::new(AtomicBool::new(false));
        let tx = entry.tx.clone();
        let thread_ctx = self.ctx.clone();
        let thread_path = path.clone();
        let cancel2 = cancel.clone();
        let pause2 = pause.clone();
        let spawned = std::thread::Builder::new()
            .name(format!("rss-scan {}", path.display()))
            .spawn(move || {
                let progress_tx = tx.clone();
                let progress_ctx = thread_ctx.clone();
                let progress: Arc<dyn Fn(ScanProgress) + Send + Sync> =
                    Arc::new(move |p: ScanProgress| {
                        let _ = progress_tx.send(ScanMsg::Progress(p));
                        if let Some(ctx) = &progress_ctx {
                            ctx.request_repaint();
                        }
                    });
                let opts = ScanOptions {
                    cancel: Some(cancel2),
                    pause: Some(pause2),
                    progress: Some(progress),
                    ..Default::default()
                };
                let event_tx = tx.clone();
                let result = WalkScanner::new().scan(&thread_path, &opts, &mut |event| {
                    let _ = event_tx.send(ScanMsg::Event(event));
                });
                let _ = tx.send(ScanMsg::Finished(result));
                if let Some(ctx) = &thread_ctx {
                    ctx.request_repaint();
                }
            });
        let entry = &mut self.entries[idx];
        match spawned {
            Ok(_handle) => {
                entry.scan = Some(RunningScan { cancel, pause });
                entry.view.scanning = true;
                entry.view.scan_path = path;
                entry.view.is_drive_view = diskspace::is_volume_root(&entry.view.scan_path);
                entry.pending_fresh |= fresh;
                entry.ever_scanned = true;
                if fresh && !entry.view.has_root() {
                    // Nothing on screen yet: reset immediately.
                    entry.view.begin_fresh_scan();
                    entry.pending_fresh = false;
                }
            }
            Err(err) => {
                self.notice = Some(format!("could not start scan thread: {err}"));
            }
        }
    }

    /// Full rescan of entry `idx` (F5, FR-7.8).
    pub fn rescan_entry(&mut self, idx: usize) {
        let path = self.entries[idx].view.scan_path.clone();
        if path.as_os_str().is_empty() {
            return;
        }
        self.start_entry_scan(idx, path, true);
    }

    /// Incremental rescan of one subtree (FR-7.4): the old subtree is
    /// dropped and a background walk refills it into the live model.
    fn rescan_subtree(&mut self, idx: usize, path: PathBuf) {
        let entry = &mut self.entries[idx];
        if let Some(id) = entry.view.find_by_path(&path) {
            if id != entry.view.root {
                entry.view.drop_subtree(id);
            }
        }
        let tx = entry.tx.clone();
        let parent = path.parent().map(Path::to_path_buf);
        let dir_name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| path.to_string_lossy().into_owned());
        let thread_path = path.clone();
        let _ = std::thread::Builder::new()
            .name(format!("rss-rescan {}", path.display()))
            .spawn(move || {
                let opts = ScanOptions::default();
                let result = WalkScanner::new().scan(&thread_path, &opts, &mut |event| {
                    // Re-root the subtree scan under the existing parent.
                    let event = match event {
                        ScanEvent::Upsert(mut u) if u.parent_path.is_none() => {
                            u.parent_path = parent.clone();
                            u.params.name = dir_name.clone().into_boxed_str();
                            ScanEvent::Upsert(u)
                        }
                        other => other,
                    };
                    let _ = tx.send(ScanMsg::Event(event));
                });
                let _ = tx.send(ScanMsg::SubtreeFinished(thread_path, result));
            });
    }

    /// Cancel the root view's scan, if any (FR-2.2). Partial results stay
    /// browsable.
    pub fn cancel_scan(&mut self) {
        for entry in &self.entries {
            if let Some(scan) = &entry.scan {
                scan.cancel.store(true, Ordering::Relaxed);
            }
        }
    }

    /// Start the live-update watcher for a finished view (FR-7.1). Failures
    /// surface as the FR-7.7 "press F5 to rescan" affordance.
    fn start_watcher(&mut self, idx: usize) {
        let entry = &mut self.entries[idx];
        if !entry.view.has_root() {
            return;
        }
        // FR-7.6: change tracking is toggleable (applies to scans started
        // after the change — FR-10.4).
        if self.config.watch_enabled == Some(false) {
            entry.watch_notice =
                Some("live updates disabled in settings — press F5 to rescan".to_string());
            return;
        }
        match rss_watch::select_watcher(&entry.view.scan_path) {
            Ok(mut watcher) => match watcher.start() {
                Ok(()) => entry.watcher = Some(watcher),
                Err(err) => {
                    entry.watch_notice = Some(format!(
                        "live updates unavailable ({err}) — press F5 to rescan"
                    ));
                }
            },
            Err(err) => {
                entry.watch_notice = Some(format!(
                    "live updates unavailable ({err}) — press F5 to rescan"
                ));
            }
        }
    }

    /// Drain scan messages and watcher events for one entry, with a
    /// per-frame budget (FR-2.10).
    fn drain_entry(&mut self, idx: usize) {
        let deadline = Instant::now() + DRAIN_BUDGET;
        let mut rescans: Vec<WatchOutcome> = Vec::new();
        let mut scan_finished = false;
        {
            let entry = &mut self.entries[idx];
            while let Ok(msg) = entry.rx.try_recv() {
                match msg {
                    ScanMsg::Progress(p) => entry.view.progress = p,
                    ScanMsg::Event(event) => {
                        let is_root =
                            matches!(&event, ScanEvent::Upsert(u) if u.parent_path.is_none());
                        if entry.pending_fresh && is_root {
                            entry.view.begin_fresh_scan();
                            entry.pending_fresh = false;
                        }
                        entry.view.apply_scan_event(event);
                    }
                    ScanMsg::Finished(result) => {
                        entry.scan = None;
                        entry.view.scanning = false;
                        match result {
                            Ok(summary) => {
                                entry.view.summary = Some(summary);
                                // Full re-sort once the scan settles (FR-3.16).
                                entry.view.resort_once = true;
                                // Live updates kick in once the scan completes
                                // (FR-7.1); starting the watcher mid-scan would
                                // duplicate scan upserts.
                                scan_finished = true;
                            }
                            Err(err) => {
                                self.notice = Some(format!("scan failed: {err}"));
                            }
                        }
                    }
                    ScanMsg::SubtreeFinished(path, result) => {
                        if let Err(err) = result {
                            self.notice = Some(format!(
                                "subtree rescan of {} failed: {err}",
                                path.display()
                            ));
                        }
                    }
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
            entry.view.scanning = entry.scan.is_some();

            // Watcher events (FR-7.1).
            if let Some(watcher) = &entry.watcher {
                let rx = watcher.events();
                for _ in 0..WATCH_BUDGET {
                    let Ok(event) = rx.try_recv() else { break };
                    rescans.push(entry.view.apply_watch_event(&event));
                }
            }
        }
        if scan_finished {
            self.start_watcher(idx);
        }
        for outcome in rescans {
            match outcome {
                WatchOutcome::RescanSubtree(path) => self.rescan_subtree(idx, path),
                WatchOutcome::RescanFull => self.rescan_entry(idx),
                _ => {}
            }
        }
    }

    /// Handle folders dropped onto the window (FR-1.3/FR-1.4): onto the
    /// start dialog fills the path field; onto a view opens one new view per
    /// dropped folder.
    fn handle_dropped_files(&mut self, ui: &Ui) {
        let paths: Vec<PathBuf> = ui.input(|i| {
            i.raw
                .dropped_files
                .iter()
                .map(|f| f.path().to_path_buf())
                .collect()
        });
        if paths.is_empty() {
            return;
        }
        // FR-1.5: a dropped .rssnap loads as a read-only view.
        let (snapshots, folders): (Vec<_>, Vec<_>) = paths
            .into_iter()
            .partition(|p| p.extension().is_some_and(|e| e == "rssnap"));
        if let Some(snapshot) = snapshots.first() {
            self.load_snapshot(snapshot);
        }
        let paths = folders;
        if paths.is_empty() {
            return;
        }
        if self.entries.is_empty() && self.start.open {
            self.start.path = paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(";");
        } else {
            self.open_scans(paths);
        }
    }

    /// Keyboard shortcuts (FR-3.6 navigation, FR-5.1 tags, FR-3.13/FR-3.14
    /// toggles) for the root viewport's view. Navigation shortcuts are
    /// inactive while a text field has keyboard focus; tag shortcuts stay
    /// active regardless (SpaceSniffer parity).
    fn handle_keys(&mut self, ui: &mut Ui) {
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::N)) {
            self.start.open = true;
        }
        if self.start.open && ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Escape)) {
            // FR-1.6: ESC closes the start dialog; with nothing scanned yet
            // it quits the app (SpaceSniffer parity).
            self.start.open = false;
            if self.entries.is_empty() {
                ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
            }
        }

        if self.start.open {
            return;
        }
        let Some(entry) = self.entries.first_mut() else {
            return;
        };
        let view = &mut entry.view;

        // FR-5.1: CTRL+1..4 (or bare 1..4 while no text field is focused)
        // toggles a tag on the selection; CTRL+0 clears all tags under the
        // current zoom, including filter-hidden elements (FR-4.12).
        let keyboard_free = !ui.ctx().egui_wants_keyboard_input();
        let tag_keys = [
            (Key::Num1, Tag::Red),
            (Key::Num2, Tag::Yellow),
            (Key::Num3, Tag::Green),
            (Key::Num4, Tag::Blue),
        ];
        for (key, tag) in tag_keys {
            let pressed = ui.input_mut(|i| i.consume_key(Modifiers::CTRL, key))
                || (keyboard_free && ui.input_mut(|i| i.consume_key(Modifiers::NONE, key)));
            if pressed {
                view.toggle_selected_tag(tag);
            }
        }
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::Num0)) {
            let zoom = view.zoom;
            view.clear_tags_below(zoom);
        }

        // FR-7.8: F5 rescans the view; CTRL+F5 rescans the zoom subtree.
        if ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::F5)) {
            self.rescan_entry(0);
            return;
        }
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::F5)) {
            let entry = &mut self.entries[0];
            if entry.view.has_root() {
                let path = entry.view.tree().path(entry.view.zoom);
                self.rescan_subtree(0, path);
            }
            return;
        }

        if ui.ctx().egui_wants_keyboard_input() {
            return;
        }
        let view = &mut self.entries[0].view;
        if ui.input_mut(|i| i.consume_key(Modifiers::NONE, Key::Backspace)) {
            view.go_back();
        }
        if ui.input_mut(|i| i.consume_key(Modifiers::SHIFT, Key::Backspace)) {
            view.go_forward();
        }
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::ArrowUp)) {
            view.zoom_out_one();
        }
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::Home)) {
            view.zoom_home();
        }
        // FR-5.4: toggle the color style per view.
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::T)) {
            view.color_style = match view.color_style {
                ColorStyle::Flat => ColorStyle::FileClasses,
                ColorStyle::FileClasses => ColorStyle::Flat,
            };
        }
        // FR-3.13: free-space / unknown-space element toggles.
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::F)) {
            view.show_free_space = !view.show_free_space;
            view.layout_epoch += 1;
        }
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::U)) {
            view.show_unknown = !view.show_unknown;
            view.layout_epoch += 1;
        }
        // FR-3.14: display-depth limit.
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::Plus)) {
            view.adjust_display_depth(1);
        }
        if ui.input_mut(|i| i.consume_key(Modifiers::CTRL, Key::Minus)) {
            view.adjust_display_depth(-1);
        }
    }

    fn toolbar(&mut self, ui: &mut Ui, idx: usize) {
        // Wrapped: the full control set must stay reachable in narrow
        // windows (and small test harnesses).
        ui.horizontal_wrapped(|ui| {
            if ui
                .button("New scan…")
                .on_hover_text("Open the start dialog (Ctrl+N)")
                .clicked()
            {
                self.start.open = true;
            }

            // FR-1.7: window list (one view per viewport).
            if self.entries.len() > 1 {
                let titles: Vec<(usize, egui::ViewportId, String)> = self
                    .entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| (i, e.viewport, e.view.scan_path.display().to_string()))
                    .collect();
                ui.menu_button("Windows", |ui| {
                    for (i, viewport, title) in &titles {
                        if ui.button(title).clicked() {
                            ui.ctx()
                                .send_viewport_cmd_to(*viewport, egui::ViewportCommand::Focus);
                            let _ = i;
                            ui.close();
                        }
                    }
                });
            }

            let (can_back, can_fwd, can_up) = {
                let v = &self.entries[idx].view;
                (
                    v.can_go_back(),
                    v.can_go_forward(),
                    v.has_root() && v.zoom != v.root,
                )
            };
            if ui
                .add_enabled(can_back, egui::Button::new("◀ Back"))
                .on_hover_text("Backspace")
                .clicked()
            {
                self.entries[idx].view.go_back();
            }
            if ui
                .add_enabled(can_fwd, egui::Button::new("Fwd ▶"))
                .on_hover_text("Shift+Backspace")
                .clicked()
            {
                self.entries[idx].view.go_forward();
            }
            if ui
                .add_enabled(can_up, egui::Button::new("Up"))
                .on_hover_text("Zoom out one level (Ctrl+Up)")
                .clicked()
            {
                self.entries[idx].view.zoom_out_one();
            }
            if ui
                .add_enabled(can_back || can_up, egui::Button::new("Root"))
                .on_hover_text("Jump to the view root (Ctrl+Home)")
                .clicked()
            {
                self.entries[idx].view.zoom_home();
            }

            ui.separator();

            let scanning = self.entries[idx].scan.is_some();
            let has_scan = self.entries[idx].ever_scanned;
            if ui
                .add_enabled(has_scan && !scanning, egui::Button::new("Rescan"))
                .on_hover_text("Scan the view root again (F5)")
                .clicked()
            {
                self.rescan_entry(idx);
            }
            if scanning {
                // FR-2.3: pause/resume.
                let paused = self.entries[idx]
                    .scan
                    .as_ref()
                    .is_some_and(|s| s.pause.load(Ordering::Relaxed));
                let label = if paused { "Resume" } else { "Pause" };
                if ui
                    .button(label)
                    .on_hover_text("Pause/resume the scan (FR-2.3)")
                    .clicked()
                {
                    if let Some(scan) = &self.entries[idx].scan {
                        scan.pause.store(!paused, Ordering::Relaxed);
                    }
                }
                if ui
                    .button("Cancel")
                    .on_hover_text("Cancel the scan; partial results stay browsable")
                    .clicked()
                {
                    if let Some(scan) = &self.entries[idx].scan {
                        scan.cancel.store(true, Ordering::Relaxed);
                    }
                }
            }

            ui.separator();

            if ui
                .button("Log")
                .on_hover_text("Scan log console (FR-2.13)")
                .clicked()
            {
                self.log_open = !self.log_open;
            }
            if ui.button("Settings").clicked() {
                self.settings_open = !self.settings_open;
            }

            ui.separator();

            // FR-8.x: export the current zoom + save a snapshot.
            let has_view = self.entries[idx].view.has_root();
            ui.add_enabled_ui(has_view, |ui| {
                ui.menu_button("Export", |ui| {
                    for (i, template) in rss_export::builtin_templates().iter().enumerate() {
                        if ui.button(format!("Template: {}", template.name)).clicked() {
                            self.export_dialog(idx, ExportKind::Template(i));
                            ui.close();
                        }
                    }
                    if ui.button("CSV").clicked() {
                        self.export_dialog(idx, ExportKind::Csv);
                        ui.close();
                    }
                    if ui.button("JSON").clicked() {
                        self.export_dialog(idx, ExportKind::Json);
                        ui.close();
                    }
                    ui.separator();
                    if ui
                        .button("Save snapshot (.rssnap)")
                        .on_hover_text("Save tree + tags + filter + zoom (FR-8.7)")
                        .clicked()
                    {
                        if let Some(dest) = rfd::FileDialog::new()
                            .add_filter("RustySpaceSniffer snapshot", &["rssnap"])
                            .set_file_name("view.rssnap")
                            .save_file()
                        {
                            let _ = self.save_root_snapshot(&dest);
                        }
                        ui.close();
                    }
                });
            });

            ui.separator();

            // FR-4.1: one filter field per view; changing it re-evaluates
            // the already-scanned tree and never rescans.
            let view = &mut self.entries[idx].view;
            let filter_label = ui.label("Filter:");
            ui.add(
                egui::TextEdit::singleline(&mut view.filter_text)
                    .hint_text("e.g. *.jpg;>1mb;<3months")
                    .desired_width(160.0),
            )
            .labelled_by(filter_label.id);
            // FR-4.13: inline parse warnings, no modal dialog. The tooltip
            // quotes each offending condition by its span.
            let warnings: Vec<String> = view
                .filter_warnings()
                .iter()
                .map(|w| {
                    let excerpt = view
                        .filter_text
                        .get(w.span.start..w.span.end)
                        .unwrap_or_default()
                        .to_string();
                    format!("`{excerpt}`: {}", w.message)
                })
                .collect();
            if !warnings.is_empty() {
                // Non-wrapping label: in the wrapped toolbar a plain
                // `ui.label` would expand to the full row width and
                // swallow hover meant for neighbors.
                ui.add(
                    egui::Label::new(RichText::new("⚠ filter").color(ui.visuals().warn_fg_color))
                        .wrap_mode(egui::TextWrapMode::Extend),
                )
                .on_hover_ui(|ui| {
                    for warning in &warnings {
                        ui.label(warning);
                    }
                });
            }

            // FR-4.11: dim-in-place (default) vs hard-hide toggle.
            let dim_label = if view.hard_hide_filtered {
                "Filtered: hide"
            } else {
                "Filtered: dim"
            };
            if ui
                .add_enabled(view.has_active_filter(), egui::Button::new(dim_label))
                .on_hover_text("Filtered-out elements: dimmed in place vs hard-hidden (FR-4.11)")
                .clicked()
            {
                view.hard_hide_filtered = !view.hard_hide_filtered;
                view.layout_epoch += 1;
            }

            // FR-5.4: per-view color style toggle (CTRL+T).
            let style_label = match view.color_style {
                ColorStyle::Flat => "Colors: flat",
                ColorStyle::FileClasses => "Colors: classes",
            };
            if ui
                .button(style_label)
                .on_hover_text("Toggle color style (Ctrl+T, FR-5.4)")
                .clicked()
            {
                view.color_style = match view.color_style {
                    ColorStyle::Flat => ColorStyle::FileClasses,
                    ColorStyle::FileClasses => ColorStyle::Flat,
                };
            }

            let mode_label = match view.size_mode {
                rss_export::SizeMode::Allocated => "Size: on-disk",
                rss_export::SizeMode::Logical => "Size: logical",
            };
            if ui
                .button(mode_label)
                .on_hover_text("Toggle treemap size basis (SPEC.md §5.2)")
                .clicked()
            {
                view.size_mode = match view.size_mode {
                    rss_export::SizeMode::Allocated => rss_export::SizeMode::Logical,
                    rss_export::SizeMode::Logical => rss_export::SizeMode::Allocated,
                };
                view.layout_epoch += 1;
            }

            // FR-3.14: display-depth limit (CTRL+ + / CTRL+ -).
            ui.label("Depth:");
            if ui.button("-").on_hover_text("Ctrl+-").clicked() {
                view.adjust_display_depth(-1);
            }
            ui.label(view.display_depth.to_string());
            if ui.button("+").on_hover_text("Ctrl++").clicked() {
                view.adjust_display_depth(1);
            }

            // FR-2.11: flash-on-change toggle.
            let flash_label = if view.flash_enabled {
                "Flash: on"
            } else {
                "Flash: off"
            };
            if ui
                .button(flash_label)
                .on_hover_text("Flash newly scanned/modified elements (FR-2.11)")
                .clicked()
            {
                view.flash_enabled = !view.flash_enabled;
            }
        });
    }

    fn breadcrumb_bar(&mut self, ui: &mut Ui, idx: usize) {
        let view = &self.entries[idx].view;
        if !view.has_root() {
            return;
        }
        let trail = view.breadcrumb();
        let names: Vec<String> = trail
            .iter()
            .map(|&id| view.tree().node(id).name.to_string())
            .collect();
        ui.horizontal_wrapped(|ui| {
            ui.label("Path:");
            let last = trail.len().saturating_sub(1);
            let mut clicked = None;
            for (i, (id, name)) in trail.iter().zip(names.iter()).enumerate() {
                let button = egui::Button::new(name).small();
                // The crumb of the current zoom is shown but disabled.
                if ui.add_enabled(i != last, button).clicked() {
                    clicked = Some(*id);
                }
                if i != last {
                    ui.label(RichText::new("›").weak());
                }
            }
            if let Some(id) = clicked {
                self.entries[idx].view.navigate_to(id);
            }
        });
    }

    fn status_bar(&mut self, ui: &mut Ui, idx: usize) {
        let entry = &self.entries[idx];
        let view = &entry.view;
        ui.horizontal(|ui| {
            if entry.scan.is_some() {
                let p = view.progress;
                let paused = entry
                    .scan
                    .as_ref()
                    .is_some_and(|s| s.pause.load(Ordering::Relaxed));
                // FR-3.12: scan % where the total is known (drive scans).
                let percent = view.drive_space.and_then(|ds| {
                    let used = ds.total.saturating_sub(ds.free);
                    (used > 0).then(|| p.allocated_bytes as f64 / used as f64)
                });
                let mut text = format!(
                    "Scanning {} — {} entries ({} files, {} dirs), {}",
                    view.scan_path.display(),
                    p.entries,
                    p.files,
                    p.dirs,
                    crate::fmt::format_bytes(p.allocated_bytes),
                );
                if let Some(percent) = percent {
                    text += &format!(" — {:.0}%", percent * 100.0);
                }
                if paused {
                    text += " — paused";
                }
                ui.label(text);
                return;
            }
            if !view.has_root() {
                ui.label("No scan — press Ctrl+N or drop a folder to begin.");
                return;
            }
            let node = view.tree().node(view.zoom);
            ui.label(format!(
                "{} — {} files, {} dirs, {} on-disk / {} logical",
                view.tree().path(view.zoom).display(),
                node.agg_files,
                node.agg_dirs,
                crate::fmt::format_bytes(node.agg_allocated),
                crate::fmt::format_bytes(node.agg_logical),
            ));
            // FR-1.8: free space of the scanned drive.
            if view.is_drive_view {
                if let Some(ds) = view.drive_space {
                    ui.separator();
                    ui.label(format!("Free: {}", crate::fmt::format_bytes(ds.free)));
                }
            }
            if let Some(sel) = view.selected {
                ui.separator();
                ui.label(format!("Selected: {}", view.tree().path(sel).display()));
            }
            if let Some(summary) = &view.summary {
                if !summary.errors.is_empty() {
                    ui.separator();
                    ui.label(
                        RichText::new(format!("{} scan problem(s)", summary.errors.len()))
                            .color(ui.visuals().warn_fg_color),
                    );
                }
            }
            // FR-7.7: persistent affordance when live updates are down.
            if let Some(notice) = &entry.watch_notice {
                ui.separator();
                ui.label(RichText::new(notice).color(ui.visuals().warn_fg_color));
            }
            if let Some(notice) = &self.notice {
                ui.separator();
                ui.label(RichText::new(notice).weak());
            }
        });
    }

    fn start_dialog(&mut self, ui: &Ui) {
        if !self.start.open {
            return;
        }
        let mut open = true;
        let mut scan_request: Vec<PathBuf> = Vec::new();
        let mut load_request: Option<PathBuf> = None;
        egui::Window::new("RustySpaceSniffer — choose what to scan")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .anchor(Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ui.ctx(), |ui| {
                // FR-1.1: two tabs — "Drives or Paths" and "Snapshots".
                ui.horizontal(|ui| {
                    ui.selectable_label(
                        !self.start.snapshots_tab,
                        RichText::new("Drives or Paths").strong(),
                    )
                    .clicked()
                    .then(|| self.start.snapshots_tab = false);
                    if ui
                        .selectable_label(
                            self.start.snapshots_tab,
                            RichText::new("Snapshots").strong(),
                        )
                        .clicked()
                    {
                        self.start.snapshots_tab = true;
                    }
                });
                ui.separator();

                if !self.start.snapshots_tab {
                    if !self.drives.is_empty() {
                        ui.label("Drives:");
                        ui.horizontal_wrapped(|ui| {
                            for drive in &self.drives {
                                if ui.button(drive.display().to_string()).clicked() {
                                    self.start.path = drive.display().to_string();
                                }
                            }
                        });
                        ui.separator();
                    }
                    let path_label = ui.label("Path to scan (separate multiple paths with ';'):");
                    let field = ui
                        .add(
                            egui::TextEdit::singleline(&mut self.start.path)
                                .hint_text("e.g. C:\\ or /home/you")
                                .desired_width(360.0),
                        )
                        .labelled_by(path_label.id);
                    // Enter submits (FR-1.1 path field behavior).
                    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                    if field.changed() {
                        self.start.error = None;
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Browse…").clicked() {
                            if let Some(dir) = rfd::FileDialog::new().pick_folder() {
                                self.start.path = dir.display().to_string();
                            }
                        }
                        if ui.button("Scan").clicked() || enter {
                            let paths = split_paths(&self.start.path);
                            if paths.is_empty() {
                                self.start.error = Some("enter a path to scan".to_string());
                            } else {
                                scan_request = paths;
                            }
                        }
                    });
                } else {
                    // FR-1.5: load a .rssnap snapshot.
                    let snapshot_label = ui.label("Snapshot file (.rssnap):");
                    let field = ui
                        .add(
                            egui::TextEdit::singleline(&mut self.start.snapshot_path)
                                .hint_text("path/to/view.rssnap")
                                .desired_width(360.0),
                        )
                        .labelled_by(snapshot_label.id);
                    let enter = field.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter));
                    if field.changed() {
                        self.start.error = None;
                    }
                    ui.horizontal(|ui| {
                        if ui.button("Browse…").clicked() {
                            if let Some(file) = rfd::FileDialog::new()
                                .add_filter("RustySpaceSniffer snapshot", &["rssnap"])
                                .pick_file()
                            {
                                self.start.snapshot_path = file.display().to_string();
                            }
                        }
                        if ui.button("Load").clicked() || enter {
                            let path = self.start.snapshot_path.trim();
                            if path.is_empty() {
                                self.start.error = Some("enter a snapshot path".to_string());
                            } else {
                                load_request = Some(PathBuf::from(path));
                            }
                        }
                    });
                    ui.label(
                        RichText::new(
                            "Loaded snapshots are read-only views with no live filesystem link.",
                        )
                        .weak()
                        .small(),
                    );
                }
                if let Some(err) = &self.start.error {
                    ui.label(RichText::new(err).color(ui.visuals().error_fg_color));
                }
                ui.label(
                    RichText::new("Drag a folder here to fill the path field. ESC closes.")
                        .weak()
                        .small(),
                );
            });
        // Window close button behaves like ESC.
        if !open {
            self.start.open = false;
        }
        if !scan_request.is_empty() {
            self.start.open = false;
            self.open_scans(scan_request);
        }
        if let Some(path) = load_request {
            self.start.open = false;
            self.load_snapshot(&path);
        }
    }

    /// Apply a treemap interaction (selection, zoom, context-menu actions).
    fn dispatch_treemap_cmd(&mut self, idx: usize, cmd: TreemapCmd) {
        match cmd {
            TreemapCmd::Select(id) => self.entries[idx].view.selected = Some(id),
            TreemapCmd::Zoom(id, rect) => self.entries[idx].view.navigate_from_rect(id, rect),
            TreemapCmd::Open(id) => {
                let path = self.entries[idx].view.tree().path(id);
                if let Err(err) = open::that_detached(&path) {
                    self.notice = Some(format!("open failed: {err}"));
                }
            }
            TreemapCmd::OpenContaining(id) => {
                // FR-6.3: reveal in the file manager.
                let path = self.entries[idx].view.tree().path(id);
                if let Err(err) = rss_shell::open_containing_folder(&path) {
                    self.notice = Some(format!("open containing folder failed: {err}"));
                }
            }
            TreemapCmd::Delete(id) => {
                // FR-6.4: build the confirmation plan (item list, true
                // total, filter-hiding warning).
                self.delete_dialog = Some(fileops::delete_plan_for(&self.entries[idx].view, id));
            }
            TreemapCmd::ShellMenu(id) => {
                self.spawn_shell_menu(self.entries[idx].view.tree().path(id));
            }
        }
    }

    /// FR-6.1/FR-6.2: the real Windows shell context menu on a watchdogged
    /// worker thread (cfg(windows); the item only exists there).
    #[cfg(windows)]
    fn spawn_shell_menu(&mut self, path: PathBuf) {
        use rss_shell::DEFAULT_WATCHDOG_TIMEOUT;
        let invocation = rss_shell::spawn_shell_context_menu(
            &path,
            std::ptr::null_mut(), // no owner HWND plumbing yet
            0,
            0,
        );
        // Drive the two-phase protocol off the UI thread: watchdog on
        // wait_ready, no timeout after Ready (see rss-shell docs).
        std::thread::spawn(move || {
            let _ = invocation
                .wait_ready(DEFAULT_WATCHDOG_TIMEOUT)
                .and_then(|()| invocation.wait_finished());
        });
    }

    #[cfg(not(windows))]
    fn spawn_shell_menu(&mut self, _path: PathBuf) {}

    /// FR-6.4: the delete confirmation dialog — item list, true total,
    /// explicit filter-hiding warning, running freed-space counter.
    fn delete_dialog_ui(&mut self, ui: &Ui) {
        let Some(dialog) = &mut self.delete_dialog else {
            return;
        };
        fileops::poll_delete(dialog);

        let mut open = true;
        let mut confirmed = false;
        let mut close_requested = false;
        egui::Window::new("Confirm deletion")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ui.ctx(), |ui| {
                ui.label("The following will be moved to the Recycle Bin:");
                for item in dialog.plan.items() {
                    ui.label(format!(
                        "{} — {}",
                        item.path.display(),
                        crate::fmt::format_bytes(item.total_bytes)
                    ));
                }
                ui.label(format!(
                    "Total: {}",
                    crate::fmt::format_bytes(dialog.plan.total_bytes())
                ));
                if dialog.plan.has_filter_hidden_content() {
                    ui.label(
                        RichText::new(
                            "⚠ An active filter hides part of the contents — the true total above includes everything that will be deleted.",
                        )
                        .color(ui.visuals().warn_fg_color),
                    );
                }
                if dialog.running {
                    ui.label(format!(
                        "Freed {} of {}",
                        crate::fmt::format_bytes(dialog.freed),
                        crate::fmt::format_bytes(dialog.plan.total_bytes())
                    ));
                }
                if let Some(result) = &dialog.result {
                    match result {
                        Ok(()) => {
                            ui.label("Done.".to_string());
                        }
                        Err(failures) => {
                            for failure in failures {
                                ui.label(
                                    RichText::new(failure).color(ui.visuals().error_fg_color),
                                );
                            }
                        }
                    }
                }
                ui.horizontal(|ui| {
                    let done = dialog.result.is_some();
                    if done {
                        if ui.button("Close").clicked() {
                            close_requested = true;
                        }
                    } else {
                        if ui
                            .add_enabled(!dialog.running, egui::Button::new("Move to Recycle Bin"))
                            .clicked()
                        {
                            confirmed = true;
                        }
                        if ui
                            .add_enabled(!dialog.running, egui::Button::new("Cancel"))
                            .clicked()
                        {
                            close_requested = true;
                        }
                    }
                });
            });

        if confirmed {
            if let Some(dialog) = &mut self.delete_dialog {
                fileops::start_delete(dialog);
            }
        }
        // Deletion finished: rescan the parents once so the model reflects
        // the freed space (the watcher does this too when live updates are
        // available); the dialog stays open until the user dismisses it.
        let mut rescan_targets = Vec::new();
        if let Some(dialog) = &self.delete_dialog {
            if dialog.result.is_some() && !dialog.rescanned {
                let nodes = dialog.nodes.clone();
                rescan_targets = fileops::rescan_targets(&self.entries[0].view, &nodes);
            }
        }
        if !rescan_targets.is_empty() {
            if let Some(dialog) = &mut self.delete_dialog {
                dialog.rescanned = true;
            }
            for target in rescan_targets {
                self.rescan_subtree(0, target);
            }
        }
        if !open || close_requested {
            self.delete_dialog = None;
        }
    }

    /// The chrome of one view (toolbar, breadcrumbs, treemap, status bar) —
    /// used for the root viewport and for every extra viewport (FR-1.7).
    fn view_chrome(&mut self, ui: &mut Ui, idx: usize) {
        egui::Panel::top("toolbar").show(ui, |ui| {
            self.toolbar(ui, idx);
            ui.separator();
            self.breadcrumb_bar(ui, idx);
        });
        egui::Panel::bottom("status").show(ui, |ui| {
            self.status_bar(ui, idx);
        });
        egui::CentralPanel::default().show(ui, |ui| {
            let mut cmds = Vec::new();
            {
                let view = &mut self.entries[idx].view;
                if view.has_root() {
                    cmds = treemap::show(ui, view);
                } else {
                    ui.centered_and_justified(|ui| {
                        ui.label("Scanning…");
                    });
                }
            }
            for cmd in cmds {
                self.dispatch_treemap_cmd(idx, cmd);
            }
        });
    }

    /// Apply the configured theme (FR-11.4/FR-11.9): egui's theme preference
    /// (its `sync_window_theme` also drives the native window frame on
    /// Windows via winit), plus our per-theme treemap palettes (FR-11.5).
    fn apply_theme(&mut self, ctx: &egui::Context) {
        ctx.set_theme(match self.config.theme {
            ThemeSetting::System => egui::ThemePreference::System,
            ThemeSetting::Light => egui::ThemePreference::Light,
            ThemeSetting::Dark => egui::ThemePreference::Dark,
        });
        let dark = match self.config.theme {
            ThemeSetting::Dark => true,
            ThemeSetting::Light => false,
            // egui-winit feeds the OS theme; default to dark when unknown.
            ThemeSetting::System => ctx.system_theme().is_none_or(|t| t == egui::Theme::Dark),
        };
        if self.applied_dark != Some(dark) {
            self.applied_dark = Some(dark);
            let palette = defaults::palette(dark);
            for entry in &mut self.entries {
                entry.view.apply_palette(&palette);
            }
        }
    }

    /// The settings dialog (M9, FR-10.x). Changes apply instantly and
    /// persist to the config file (FR-11.9).
    fn settings_dialog(&mut self, ui: &Ui) {
        if !self.settings_open {
            return;
        }
        let mut open = true;
        let mut changed = false;
        egui::Window::new("Settings")
            .open(&mut open)
            .collapsible(false)
            .show(ui.ctx(), |ui| {
                ui.label(RichText::new("Theme").strong());
                ui.horizontal(|ui| {
                    for theme in [
                        ThemeSetting::System,
                        ThemeSetting::Light,
                        ThemeSetting::Dark,
                    ] {
                        if ui
                            .selectable_label(self.config.theme == theme, theme.label())
                            .clicked()
                        {
                            self.config.theme = theme;
                            changed = true;
                        }
                    }
                });
                ui.separator();

                let mut flash = self.config.flash_enabled.unwrap_or(true);
                if ui
                    .checkbox(&mut flash, "Flash newly scanned/modified elements")
                    .on_hover_text("FR-2.11")
                    .clicked()
                {
                    self.config.flash_enabled = Some(flash);
                    for entry in &mut self.entries {
                        entry.view.flash_enabled = flash;
                    }
                    changed = true;
                }

                let mut anim = self.config.zoom_anim_ms.unwrap_or(150);
                ui.horizontal(|ui| {
                    ui.label("Zoom animation (ms, 0 = instant):");
                    if ui.add(egui::Slider::new(&mut anim, 0..=500)).changed() {
                        self.config.zoom_anim_ms = Some(anim);
                        for entry in &mut self.entries {
                            entry.view.zoom_anim_ms = anim;
                        }
                        changed = true;
                    }
                });

                let mut depth = self.config.display_depth.unwrap_or(1);
                ui.horizontal(|ui| {
                    ui.label("Display depth:");
                    if ui
                        .add(egui::Slider::new(&mut depth, 1..=8))
                        .on_hover_text("FR-3.14")
                        .changed()
                    {
                        self.config.display_depth = Some(depth);
                        for entry in &mut self.entries {
                            entry.view.display_depth = depth;
                        }
                        changed = true;
                    }
                });

                ui.separator();
                let mut watch = self.config.watch_enabled.unwrap_or(true);
                if ui
                    .checkbox(&mut watch, "Live updates (file watching)")
                    .on_hover_text("FR-7.6 — applies to scans started after the change")
                    .clicked()
                {
                    self.config.watch_enabled = Some(watch);
                    changed = true;
                }

                #[cfg(windows)]
                {
                    ui.separator();
                    let registered = rss_shell::explorer_context_menu_registered();
                    let mut enabled = registered;
                    if ui
                        .checkbox(&mut enabled, r#"Explorer: "Scan with RustySpaceSniffer""#)
                        .on_hover_text("Per-user HKCU entry; no admin needed (SPEC.md §3)")
                        .clicked()
                    {
                        let result = if enabled {
                            std::env::current_exe()
                                .map_err(|e| e.to_string())
                                .and_then(|exe| {
                                    rss_shell::register_explorer_context_menu(&exe)
                                        .map_err(|e| e.to_string())
                                })
                        } else {
                            rss_shell::unregister_explorer_context_menu().map_err(|e| e.to_string())
                        };
                        if let Err(err) = result {
                            self.notice = Some(format!("Explorer integration: {err}"));
                        }
                    }
                }

                ui.separator();
                ui.label(
                    RichText::new("Settings are saved on change.")
                        .weak()
                        .small(),
                );
            });
        if changed {
            // FR-10.2: the current window size is persisted alongside.
            self.config.window_size = Some((
                ui.ctx().content_rect().width(),
                ui.ctx().content_rect().height(),
            ));
            self.save_config();
        }
        self.settings_open = open;
    }

    /// The log console (FR-2.13): scan errors/warnings per view.
    fn log_console(&mut self, ui: &Ui) {
        if !self.log_open {
            return;
        }
        let mut open = true;
        egui::Window::new("Log")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .show(ui.ctx(), |ui| {
                egui::ScrollArea::vertical().show(ui, |ui| {
                    let mut any = false;
                    for entry in &self.entries {
                        if let Some(summary) = &entry.view.summary {
                            for problem in &summary.errors {
                                any = true;
                                match &problem.path {
                                    Some(path) => {
                                        ui.label(format!("{}: {}", path.display(), problem.message))
                                    }
                                    None => ui.label(&problem.message),
                                };
                            }
                        }
                        if let Some(notice) = &entry.watch_notice {
                            any = true;
                            ui.label(notice);
                        }
                    }
                    if !any {
                        ui.weak("No scan problems recorded.");
                    }
                });
            });
        self.log_open = open;
    }

    /// Whole-window contents; called from `eframe::App::ui`. Kept separate so
    /// tests can drive it through `egui_kittest` without a windowing system.
    pub fn ui_content(&mut self, ui: &mut Ui) {
        self.ctx = Some(ui.ctx().clone());
        self.apply_theme(ui.ctx());

        // Fold scan events and watcher deltas into every view (FR-2.1,
        // FR-7.1), then re-sync derived state (filters, drive space).
        let mut any_scanning = false;
        for idx in 0..self.entries.len() {
            self.drain_entry(idx);
            let entry = &mut self.entries[idx];
            entry.view.sync();
            any_scanning |= entry.scan.is_some();
        }

        self.handle_dropped_files(ui);
        self.handle_keys(ui);

        if self.entries.is_empty() {
            // No view yet: bare chrome + a hint.
            egui::Panel::top("toolbar").show(ui, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .button("New scan…")
                        .on_hover_text("Open the start dialog (Ctrl+N)")
                        .clicked()
                    {
                        self.start.open = true;
                    }
                    if ui
                        .button("Log")
                        .on_hover_text("Scan log console (FR-2.13)")
                        .clicked()
                    {
                        self.log_open = !self.log_open;
                    }
                    if ui.button("Settings").clicked() {
                        self.settings_open = !self.settings_open;
                    }
                });
            });
            egui::Panel::bottom("status").show(ui, |ui| {
                ui.label("No scan — press Ctrl+N or drop a folder to begin.");
            });
            egui::CentralPanel::default().show(ui, |ui| {
                ui.centered_and_justified(|ui| {
                    ui.label("No scan loaded.");
                });
            });
        } else {
            self.view_chrome(ui, 0);
        }

        // FR-1.7: one viewport per additional view (embedded windows in
        // tests, OS windows on desktop).
        let mut idx = 1;
        while idx < self.entries.len() {
            if !self.entries[idx].open {
                idx += 1;
                continue;
            }
            let viewport = self.entries[idx].viewport;
            let title = format!(
                "RustySpaceSniffer — {}",
                self.entries[idx].view.scan_path.display()
            );
            ui.ctx().show_viewport_immediate(
                viewport,
                egui::ViewportBuilder::default().with_title(title),
                |ui, _class| {
                    if ui.input(|i| i.viewport().close_requested()) {
                        self.entries[idx].open = false;
                        return;
                    }
                    self.view_chrome(ui, idx);
                },
            );
            idx += 1;
        }
        // Drop closed views (cancelling their scans and watchers).
        if self.entries.iter().any(|e| !e.open) {
            for entry in &mut self.entries {
                if !entry.open {
                    if let Some(scan) = &entry.scan {
                        scan.cancel.store(true, Ordering::Relaxed);
                    }
                    entry.watcher = None;
                }
            }
            self.entries.retain(|e| e.open);
        }

        self.start_dialog(ui);
        self.delete_dialog_ui(ui);
        self.settings_dialog(ui);
        self.log_console(ui);

        // Poll progress while any scan runs; stay fully reactive otherwise
        // (FR-3.17: ~0% CPU when idle and not scanning). Animations and
        // flashes request their own repaints in the renderer.
        let delete_running = self
            .delete_dialog
            .as_ref()
            .is_some_and(|d| d.running && d.result.is_none());
        if any_scanning || delete_running {
            ui.ctx().request_repaint_after(Duration::from_millis(100));
        }
    }
}

/// All paths of a `;`-separated start-dialog entry (FR-1.2/FR-1.7).
fn split_paths(input: &str) -> Vec<PathBuf> {
    input
        .split(';')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .collect()
}

impl eframe::App for RssApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.ui_content(ui);
    }
}

/// Launch the GUI (used when `rss` is invoked without a subcommand).
pub fn run_gui() -> anyhow::Result<()> {
    let (config, config_path) = config::load();
    let mut viewport = egui::ViewportBuilder::default();
    if let Some((w, h)) = config.window_size {
        viewport = viewport.with_inner_size([w, h]);
    }
    let options = eframe::NativeOptions {
        viewport,
        ..Default::default()
    };
    eframe::run_native(
        "RustySpaceSniffer",
        options,
        Box::new(|_cc| Ok(Box::new(RssApp::with_config(config, config_path)))),
    )
    .map_err(|err| anyhow::anyhow!("failed to start the GUI: {err}"))
}
