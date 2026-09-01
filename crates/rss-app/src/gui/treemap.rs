//! Treemap rendering and interaction (SPEC.md §5.3, §4.3, §4.4, §4.5).
//!
//! Follows the §5.3 rendering rules (Fopull lessons):
//!
//! - Only the zoomed node's **children plus preview levels** up to the
//!   display-depth limit (FR-3.14) are laid out per frame — cell count is
//!   bounded by the window size, not the tree size.
//! - Cells whose short side drops below ~3 px are culled **together with
//!   their whole subtree** before recursing ([`CULL_SHORT_SIDE`]).
//! - Layout results are cached on the view (FR-3.16): during a progressive
//!   scan the cache is reused for [`LAYOUT_TICK_SECS`] with
//!   [`Order::StableOrder`] — no "boiling treemap" — while user-initiated
//!   view changes force a fresh [`Order::Sorted`] pass. Layout runs on the
//!   UI thread between repaint ticks; the scanner never waits on it
//!   (FR-2.10).
//! - Areas are strictly proportional to the node's aggregate size
//!   (FR-3.1); zero-size elements get zero area and are hidden by
//!   `rss-treemap` itself (FR-3.2) while remaining in model/exports.
//! - Directories render with a header strip carrying the folder name, with
//!   children nested inside (FR-3.3).
//! - Filtered-out elements are dimmed in place (30 % opacity +
//!   desaturation) or hard-hidden, per the view's FR-4.11 toggle; hidden
//!   cells are dropped from the layout entirely (their bytes still count in
//!   aggregates, FR-4.12 — the map no longer shows them, the model keeps
//!   them).
//! - Tagged cells get a tag-colored border; only the element's own tag is
//!   drawn (FR-5.2). Changed cells flash briefly (FR-2.11).
//! - Zoom transitions animate via a visual transform (FR-3.10); cells are
//!   non-interactive while it plays because egui's visual-only transform
//!   does not remap input.
//! - Drive-root views show free-space and not-yet-scanned pseudo elements
//!   (FR-3.13/FR-2.9); a thin viewable-percent bar sits at the left edge
//!   (FR-3.11).
//!
//! Interaction model: files and preview-level cells react on their whole
//! rectangle; a directory with visible children reacts on its **header
//! strip** (SpaceSniffer convention), so nested cells never occlude their
//! parent's hit area. The scene is fully recomputed every frame; no scene
//! graph is retained.

use std::collections::HashMap;

use egui::{
    ecolor::Hsva, emath::TSTransform, Align2, Color32, FontId, Pos2, Rect, Response, Sense, Stroke,
    StrokeKind, Ui, WidgetInfo, WidgetType,
};
use rss_core::{NodeId, NodeKind};
use rss_filter::{glob_match, ConditionKind, FilterVerdict};
use rss_treemap::{layout, Item, Order, Rect as TmRect};

use super::defaults;
use super::view::{
    ColorStyle, LayoutCache, ScanView, FREE_SPACE_ID, LAYOUT_TICK_SECS, UNKNOWN_SPACE_ID,
};
use crate::fmt::{format_bytes, format_filetime};

/// Height of a folder's header strip (FR-3.3).
const HEADER_H: f32 = 18.0;
/// Cells with a short side below this are culled with their subtree (§5.3).
const CULL_SHORT_SIDE: f32 = 3.0;
/// FR-4.11 dim treatment: filtered-out cells are painted at 30 % opacity.
const DIM_OPACITY: f32 = 0.3;
/// FR-4.11 dim treatment: desaturation factor (30 % of the saturation).
const DIM_SATURATION: f32 = 0.3;
/// Width of the viewable-percent bar at the left edge (FR-3.11).
const VIEWABLE_BAR_W: f32 = 4.0;

/// Interactions reported by the treemap back to the app, which applies them
/// to the view (keeping this module free of view mutation).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TreemapCmd {
    /// Single-click selection (FR-3.4).
    Select(NodeId),
    /// Double-click zoom into a folder (FR-3.5), animating from the cell's
    /// rect (FR-3.10).
    Zoom(NodeId, TmRect),
    /// Context-menu action: open the element with its default app.
    Open(NodeId),
    /// Context-menu action: reveal the element in the file manager (FR-6.3).
    OpenContaining(NodeId),
    /// Context-menu action: delete to the recycle bin (FR-6.4, with the
    /// confirmation dialog).
    Delete(NodeId),
    /// Context-menu action: the real Windows shell context menu (FR-6.1).
    #[cfg_attr(not(windows), allow(dead_code))]
    ShellMenu(NodeId),
}

/// Render the treemap for `view`'s current zoom into `ui` and return the
/// interactions that occurred this frame.
pub fn show(ui: &mut Ui, view: &mut ScanView) -> Vec<TreemapCmd> {
    let mut cmds = Vec::new();
    let now = ui.input(|i| i.time);

    let rect = ui.available_rect_before_wrap();
    // Claim the whole area so panel space allocation stays stable.
    let _bg = ui.allocate_rect(rect, Sense::hover());
    ui.painter()
        .rect_filled(rect, 0.0, ui.visuals().extreme_bg_color);

    if !view.has_root() {
        // The root upsert has not arrived yet (first frames of a scan).
        ui.painter().text(
            rect.center(),
            Align2::CENTER_CENTER,
            "Scanning…",
            FontId::proportional(14.0),
            ui.visuals().weak_text_color(),
        );
        return cmds;
    }

    // FR-3.16: stable order + throttled cache reuse while scanning; a
    // user-initiated view change (resort_once) forces a fresh sorted pass.
    let order = if view.scanning && !view.resort_once {
        Order::StableOrder
    } else {
        Order::Sorted
    };
    view.resort_once = false;
    ensure_layout(view, to_layout(rect), order, now);

    // FR-3.10: zoom animation. While it plays, cells are not interactive
    // (the transform is visual-only; hit targets would not match).
    let animating = view.is_animating(now);
    let transform = if animating {
        view.begin_anim(now);
        view.anim_transform(to_layout(rect), now)
            .map(|(scale, [dx, dy])| TSTransform {
                translation: egui::vec2(dx, dy),
                scaling: scale,
            })
    } else {
        view.end_anim();
        None
    };

    // FR-2.11: move this frame's changed nodes into the flash map.
    let flashes_active = view.update_flashes(now);

    // Draw from the layout cache (cloned out so `view` stays borrowable).
    let (top, subs) = {
        let cache = view.layout_cache.as_ref().expect("layout ensured");
        (cache.top.clone(), cache.subs.clone())
    };
    let mut draw = |ui: &mut Ui, view: &ScanView| {
        for &(id, cell) in &top {
            draw_cell(
                ui,
                view,
                &subs,
                id,
                from_layout(cell),
                0,
                animating,
                now,
                &mut cmds,
            );
        }
    };
    match transform {
        Some(t) => {
            ui.with_visual_transform(t, |ui| draw(ui, view));
        }
        None => draw(ui, view),
    }

    // FR-3.11: viewable-percent bar at the left edge.
    viewable_percent_bar(ui, view, rect);

    // Animations and flashes need continuous repaints (FR-3.17 exception).
    if animating || flashes_active {
        ui.ctx().request_repaint();
    }
    cmds
}

/// Compute or reuse the cached layout (FR-3.16).
fn ensure_layout(view: &mut ScanView, container: TmRect, order: Order, now: f64) {
    let reuse = view.layout_cache.as_ref().is_some_and(|c| {
        c.zoom == view.zoom
            && c.epoch == view.layout_epoch
            && c.order == order
            && rects_match(c.container, container)
            && (c.model_epoch == view.model_epoch
                // While scanning, reuse the cache for a tick even though
                // the model changed (anti-boiling, FR-3.16).
                || (view.scanning && now - c.time < LAYOUT_TICK_SECS))
    });
    if reuse {
        return;
    }

    let mut cache = LayoutCache {
        zoom: view.zoom,
        container,
        epoch: view.layout_epoch,
        model_epoch: view.model_epoch,
        order,
        time: now,
        top: Vec::new(),
        subs: HashMap::new(),
    };
    compute_level(
        view,
        view.zoom,
        container,
        order,
        0,
        &mut cache.top,
        &mut cache.subs,
    );
    view.layout_cache = Some(cache);
}

fn rects_match(a: TmRect, b: TmRect) -> bool {
    (a.x - b.x).abs() < 0.5
        && (a.y - b.y).abs() < 0.5
        && (a.w - b.w).abs() < 0.5
        && (a.h - b.h).abs() < 0.5
}

/// Lay out one level; recurse into directories up to the display-depth
/// limit (FR-3.14), culling sub-3 px cells with their subtrees (§5.3).
/// `placed`/`subs` receive the results (pure `rss-treemap` rects).
fn compute_level(
    view: &ScanView,
    id: NodeId,
    container: TmRect,
    order: Order,
    depth: u32,
    placed: &mut Vec<(NodeId, TmRect)>,
    subs: &mut HashMap<NodeId, Vec<(NodeId, TmRect)>>,
) {
    let items = layout_items(view, id);
    let cells = layout(container, &items, order);
    for cell in cells {
        let rect = cell.rect;
        if rect.w.min(rect.h) < CULL_SHORT_SIDE {
            continue; // culled with its subtree (§5.3)
        }
        placed.push((cell.id, rect));
        // FR-3.13 pseudo elements are leaves.
        if cell.id == FREE_SPACE_ID || cell.id == UNKNOWN_SPACE_ID {
            continue;
        }
        let is_dir = view.tree().node(cell.id).kind == NodeKind::Directory;
        if is_dir && depth < view.display_depth && rect.h > HEADER_H + 8.0 {
            let content = TmRect::new(
                rect.x + 1.0,
                rect.y + HEADER_H,
                (rect.w - 2.0).max(0.0),
                (rect.h - HEADER_H - 1.0).max(0.0),
            );
            let mut child_placed = Vec::new();
            compute_level(
                view,
                cell.id,
                content,
                order,
                depth + 1,
                &mut child_placed,
                subs,
            );
            subs.insert(cell.id, child_placed);
        }
    }
}

/// Layout inputs for one level: the children of `id`, weighted by the
/// view's size mode, plus the FR-3.13 pseudo elements at drive-root views.
fn layout_items(view: &ScanView, id: NodeId) -> Vec<Item<NodeId>> {
    let mut items: Vec<Item<NodeId>> = view
        .tree()
        .children(id)
        .filter(|&child| !(view.hard_hide_filtered && view.verdict(child) == FilterVerdict::Hidden))
        .map(|child| Item {
            id: child,
            weight: view.size_of(child) as f64,
        })
        .collect();
    // FR-3.13: free space and not-yet-scanned elements at the drive-root
    // view only (excluded from zoomed views to avoid proportion distortion).
    if id == view.root && view.is_drive_view && view.zoom == view.root {
        if let Some(ds) = view.drive_space {
            if view.show_free_space && ds.free > 0 {
                items.push(Item {
                    id: FREE_SPACE_ID,
                    weight: ds.free as f64,
                });
            }
            let unknown = view.unknown_bytes();
            if view.scanning && view.show_unknown && unknown > 0 {
                items.push(Item {
                    id: UNKNOWN_SPACE_ID,
                    weight: unknown as f64,
                });
            }
        }
    }
    items
}

#[allow(clippy::too_many_arguments)]
fn draw_cell(
    ui: &mut Ui,
    view: &ScanView,
    subs: &HashMap<NodeId, Vec<(NodeId, TmRect)>>,
    id: NodeId,
    rect: Rect,
    depth: u32,
    animating: bool,
    now: f64,
    cmds: &mut Vec<TreemapCmd>,
) {
    if rect.width().min(rect.height()) < CULL_SHORT_SIDE {
        return;
    }
    // FR-3.13 pseudo elements: plain colored cells with a tooltip.
    if id == FREE_SPACE_ID || id == UNKNOWN_SPACE_ID {
        draw_pseudo_cell(ui, view, id, rect);
        return;
    }

    let node = view.tree().node(id);

    let verdict = view.verdict(id);
    let dimmed = view.has_active_filter() && verdict != FilterVerdict::Visible;

    let fill = cell_color(view, id, depth);
    let fill = if dimmed { dim(fill) } else { fill };
    let border = Stroke::new(1.0, ui.visuals().window_stroke().color);
    let child_rects = subs.get(&id);
    let show_children = child_rects.is_some_and(|c| !c.is_empty());

    if show_children {
        // FR-3.3: header strip with the folder name, children nested inside.
        // The header strip is the folder's hit area; children get their own.
        let header = Rect::from_min_size(rect.min, egui::vec2(rect.width(), HEADER_H));
        if !animating {
            interact_cell(ui, view, id, header, cmds);
        }

        let painter = ui.painter().with_clip_rect(rect);
        painter.rect_filled(rect, 0.0, fill.gamma_multiply(0.45));
        painter.rect_filled(header, 0.0, fill);
        let text_color = if dimmed {
            ui.visuals().weak_text_color()
        } else {
            defaults::contrast_text(fill)
        };
        // FR-4.3: folder names matching an inclusion folder mask render
        // bold. egui's default fonts ship no bold face (M9 font work), so
        // faux-bold: paint twice with a sub-pixel x offset.
        let bold = folder_mask_bold(view, id);
        let text_pos = Pos2::new(header.min.x + 4.0, header.center().y);
        let font = FontId::proportional(12.0);
        painter.text(
            text_pos,
            Align2::LEFT_CENTER,
            &*node.name,
            font.clone(),
            text_color,
        );
        if bold {
            painter.text(
                text_pos + egui::vec2(0.5, 0.0),
                Align2::LEFT_CENTER,
                &*node.name,
                font,
                text_color,
            );
        }

        for &(cid, crect) in child_rects.expect("checked above") {
            draw_cell(
                ui,
                view,
                subs,
                cid,
                from_layout(crect),
                depth + 1,
                animating,
                now,
                cmds,
            );
        }
        ui.painter()
            .rect_stroke(rect, 0.0, border, StrokeKind::Inside);
    } else {
        if !animating {
            interact_cell(ui, view, id, rect, cmds);
        }

        let painter = ui.painter().with_clip_rect(rect);
        painter.rect_filled(rect, 0.0, fill);
        painter.rect_stroke(rect, 0.0, border, StrokeKind::Inside);
        // Name label when the cell is big enough to hold it.
        if rect.width() > 30.0 && rect.height() > 14.0 {
            painter.text(
                Pos2::new(rect.min.x + 3.0, rect.min.y + 7.0),
                Align2::LEFT_CENTER,
                &*node.name,
                FontId::proportional(11.0),
                if dimmed {
                    ui.visuals().weak_text_color()
                } else {
                    defaults::contrast_text(fill)
                },
            );
        }
    }

    // FR-2.11: flash newly added/updated cells.
    if let Some(alpha) = view.flash_alpha(id, now) {
        ui.painter().with_clip_rect(rect).rect_filled(
            rect,
            0.0,
            Color32::WHITE.gamma_multiply(alpha),
        );
    }

    // FR-5.2: the element's own tag gets a tag-colored border (children
    // inherit tags for filtering, but only the own tag is drawn).
    if let Some(tag) = node.tag {
        ui.painter().rect_stroke(
            rect.shrink(1.0),
            0.0,
            Stroke::new(2.0, view.tag_color(tag)),
            StrokeKind::Inside,
        );
    }

    // FR-3.4: the selected element gets a bright outline (the drop-shadow
    // styling is M9 polish).
    if view.selected == Some(id) {
        ui.painter().rect_stroke(
            rect.shrink(1.0),
            0.0,
            Stroke::new(2.0, Color32::WHITE),
            StrokeKind::Inside,
        );
    }
}

/// FR-3.13 pseudo elements (free space / not-yet-scanned): plain colored,
/// hoverable cells — not part of the model, so no selection/zoom/tags.
fn draw_pseudo_cell(ui: &mut Ui, view: &ScanView, id: NodeId, rect: Rect) {
    let flat = &view.flat_colors;
    let (label, color, bytes) = if id == FREE_SPACE_ID {
        (
            "Free space",
            flat.free_space,
            view.drive_space.map_or(0, |ds| ds.free),
        )
    } else {
        ("Not yet scanned", flat.unknown_space, view.unknown_bytes())
    };
    let response = ui.interact(rect, ui.id().with(("cell", id)), Sense::hover());
    response.widget_info(|| WidgetInfo::labeled(WidgetType::Other, ui.is_enabled(), label));
    response.clone().on_hover_ui(|ui| {
        ui.strong(label);
        ui.label(format_bytes(bytes));
    });
    let painter = ui.painter().with_clip_rect(rect);
    painter.rect_filled(rect, 0.0, color);
    painter.rect_stroke(
        rect,
        0.0,
        Stroke::new(1.0, ui.visuals().window_stroke().color),
        StrokeKind::Inside,
    );
    if rect.width() > 60.0 && rect.height() > 14.0 {
        painter.text(
            Pos2::new(rect.min.x + 3.0, rect.min.y + 7.0),
            Align2::LEFT_CENTER,
            label,
            FontId::proportional(11.0),
            ui.visuals().weak_text_color(),
        );
    }
}

/// Register the interactive part of a cell and report clicks. The widget is
/// labeled with the node name so accessibility tools and UI tests can find
/// every visible element.
fn interact_cell(ui: &mut Ui, view: &ScanView, id: NodeId, rect: Rect, cmds: &mut Vec<TreemapCmd>) {
    let node = view.tree().node(id);
    let response = ui.interact(rect, ui.id().with(("cell", id)), Sense::click());
    response.widget_info(|| {
        WidgetInfo::labeled(WidgetType::Other, ui.is_enabled(), node.name.to_string())
    });
    tooltip(&response, view, id);
    // FR-6.x: right-click opens our own egui context menu immediately; the
    // real Windows shell menu is one item in it (FR-6.1/FR-6.2 — the shell
    // menu runs on a watchdogged worker thread and can never freeze the UI).
    response.context_menu(|ui| {
        if ui.button("Open").clicked() {
            cmds.push(TreemapCmd::Open(id));
            ui.close();
        }
        if ui.button("Open containing folder").clicked() {
            cmds.push(TreemapCmd::OpenContaining(id));
            ui.close();
        }
        #[cfg(windows)]
        if ui.button("Windows shell menu").clicked() {
            cmds.push(TreemapCmd::ShellMenu(id));
            ui.close();
        }
        ui.separator();
        if ui.button("Delete to Recycle Bin…").clicked() {
            cmds.push(TreemapCmd::Delete(id));
            ui.close();
        }
    });
    if response.clicked() {
        cmds.push(TreemapCmd::Select(id));
    }
    // triple_clicked counts as an ongoing double-click gesture: egui's
    // triple-click detection compares against a single stored click position,
    // so clicking element A and then quickly double-clicking B would
    // otherwise misreport the second click on B as a triple click.
    let double_clicked = response.double_clicked() || response.triple_clicked();
    if node.kind == NodeKind::Directory && double_clicked {
        cmds.push(TreemapCmd::Zoom(id, to_layout(rect)));
    }
}

/// FR-3.11: thin bar at the left edge showing what fraction of the scanned
/// media the current zoom represents.
fn viewable_percent_bar(ui: &mut Ui, view: &ScanView, area: Rect) {
    let total = view.size_of(view.root);
    if total == 0 {
        return;
    }
    let fraction = (view.size_of(view.zoom) as f32 / total as f32).clamp(0.0, 1.0);
    let bar = Rect::from_min_size(area.min, egui::vec2(VIEWABLE_BAR_W, area.height()));
    let response = ui.interact(bar, ui.id().with("viewable-percent"), Sense::hover());
    response.widget_info(|| {
        WidgetInfo::labeled(
            WidgetType::Other,
            ui.is_enabled(),
            format!("Viewable: {:.0}%", fraction * 100.0),
        )
    });
    let painter = ui.painter();
    painter.rect_filled(
        bar,
        0.0,
        ui.visuals().window_stroke().color.gamma_multiply(0.3),
    );
    let fill_h = bar.height() * fraction;
    let fill = Rect::from_min_size(
        Pos2::new(bar.min.x, bar.max.y - fill_h),
        egui::vec2(VIEWABLE_BAR_W, fill_h),
    );
    painter.rect_filled(fill, 0.0, ui.visuals().selection.stroke.color);
    response.clone().on_hover_ui(|ui| {
        ui.label(format!("Zoom shows {:.1}% of the scan", fraction * 100.0));
    });
}

/// FR-4.3: whether a directory's own name matches an inclusion folder mask
/// of the active filter (such names render bold).
fn folder_mask_bold(view: &ScanView, id: NodeId) -> bool {
    let node = view.tree().node(id);
    if node.kind != NodeKind::Directory {
        return false;
    }
    let Some(filter) = view.filter() else {
        return false;
    };
    filter.conditions().iter().any(|cond| {
        matches!(
            &cond.kind,
            ConditionKind::FolderMask { pattern, negated: false }
                if glob_match(pattern, &node.name)
        )
    })
}

/// Base color for a cell under the view's color style (FR-5.4) and theme
/// palette (FR-11.5), shaded by nesting depth with the theme's level
/// contrast (FR-11.6).
fn cell_color(view: &ScanView, id: NodeId, depth: u32) -> Color32 {
    let node = view.tree().node(id);
    let flat = &view.flat_colors;
    let base = match view.color_style {
        ColorStyle::Flat => match node.kind {
            NodeKind::Directory => flat.folder,
            NodeKind::FreeSpace => flat.free_space,
            NodeKind::UnknownSpace | NodeKind::Unaccessible => flat.unknown_space,
            NodeKind::File | NodeKind::Ads => flat.file,
        },
        ColorStyle::FileClasses => {
            if node.kind == NodeKind::Directory {
                flat.folder
            } else {
                // First matching class wins (FR-5.4).
                let ext = node.name.rsplit_once('.').map(|(_, ext)| ext);
                ext.and_then(|ext| {
                    view.class_styles
                        .iter()
                        .find(|style| {
                            style
                                .class
                                .extensions
                                .iter()
                                .any(|e| e.eq_ignore_ascii_case(ext))
                        })
                        .map(|style| style.color)
                })
                .unwrap_or(flat.file)
            }
        }
    };
    base.gamma_multiply(view.level_contrast.powi(depth as i32))
}

/// FR-4.11 dim treatment: 30 % opacity plus desaturation.
fn dim(color: Color32) -> Color32 {
    let hsva = Hsva::from(color);
    Color32::from(Hsva {
        s: hsva.s * DIM_SATURATION,
        a: hsva.a * DIM_OPACITY,
        ..hsva
    })
}

/// Hover tooltip (FR-3.8): name, path, logical + on-disk size, the three
/// timestamps, and the first-level children count for directories.
fn tooltip(response: &Response, view: &ScanView, id: NodeId) {
    let node = view.tree().node(id);
    response.clone().on_hover_ui(|ui| {
        ui.strong(&*node.name);
        ui.label(view.tree().path(id).display().to_string());
        ui.label(format!("Logical size: {}", format_bytes(node.agg_logical)));
        ui.label(format!(
            "On-disk size: {}",
            format_bytes(node.agg_allocated)
        ));
        ui.label(format!("Created:  {}", format_filetime(node.created)));
        ui.label(format!("Modified: {}", format_filetime(node.modified)));
        ui.label(format!("Accessed: {}", format_filetime(node.accessed)));
        if node.kind == NodeKind::Directory {
            ui.label(format!(
                "Children: {} ({} files, {} dirs total)",
                view.tree().children(id).count(),
                node.agg_files,
                node.agg_dirs
            ));
        }
    });
}

fn to_layout(rect: Rect) -> TmRect {
    TmRect::new(rect.min.x, rect.min.y, rect.width(), rect.height())
}

fn from_layout(rect: TmRect) -> Rect {
    Rect::from_min_size(
        Pos2::new(rect.x, rect.y),
        egui::vec2(rect.w.max(0.0), rect.h.max(0.0)),
    )
}
