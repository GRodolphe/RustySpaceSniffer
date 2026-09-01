# RustySpaceSniffer — Technical Specification

**Status:** Draft v0.1 (pre-implementation)
**Date:** 2026-09-01
**Project type:** Open-source clean-room re-creation of SpaceSniffer for Windows, written in Rust
**License:** MIT OR Apache-2.0 (dual, standard Rust practice)

---

## 1. Overview

RustySpaceSniffer is an open-source re-creation of **SpaceSniffer**, the freeware
Windows disk-space analyzer whose signature feature is an interactive, zoomable
**treemap visualization** that populates live while the disk is being scanned.

SpaceSniffer (by Uderzo Software, https://www.uderzo.it/main_products/space_sniffer/)
is closed-source freeware distributed as a single portable x64 executable (~2.9 MiB).
Its latest release per the official release-notes page is **2.2.0.27**. It is widely
praised for its treemap-as-primary-interface with live drill-down, but it suffers
from well-documented problems:

- **Closed source.** Users explicitly and repeatedly wish it were open; this also
  blocks community fixes, ports, and trustworthy distribution.
- **Trust/distribution problems.** No official hash/signature culture; many shady
  mirror and repack sites; past AV false positives (UPX packing, removed) and past
  privilege requests (SeBackupPrivilege) that trip anti-malware.
- **A parsing CVE.** CVE-2026-26738 is a stack buffer overflow when parsing crafted
  `.sns` snapshot files; release 2.1.0.21 separately "addressed hacked SNF file
  loading vulnerability." Snapshot parsing is a proven attack surface.
- **Slow scanning** relative to MFT-reading tools (WizTree); SpaceSniffer's own tips
  page advises minimizing the window to speed up scanning — the UI is in the scan's
  hot path.
- **Read-only by design.** No in-app file operations; deletion is only possible
  indirectly via the Explorer shell context menu, which has caused real-world
  freezes when third-party shell extensions misbehave.
- **Historical quality issues**: decade-long high-DPI/blurry-text complaints (fixed
  only in 2.0.3.12), "Unaccessible space" when run unprivileged, tooltip cropping
  at >100% zoom (fixed 2.2.0.27), English-only UI.

### 1.1 Vision statement

> A single portable Windows executable, written in Rust, that reproduces
> SpaceSniffer's interactive treemap experience — live scanning, drill-down,
> filters, tagging — while fixing its known weaknesses: open source with
> reproducible signed builds, WizTree-class MFT scanning speed on NTFS, a
> hardened snapshot format, safe in-app deletion, a true headless console mode,
> and high-DPI/dark-mode correctness from day one.

This is a **clean-room** re-creation: feature behavior is specified from
SpaceSniffer's public documentation (user manual, release notes, tips page) and
observable behavior. No SpaceSniffer code, assets, or reverse-engineered binaries
are used. The one exception is the third-party-published reverse engineering of
the `.sns` file format, which we reference only as a cautionary design example —
RustySpaceSniffer does **not** implement `.sns` compatibility (see §4.8).

### 1.2 Relationship to the original

We aim for **feature parity** with SpaceSniffer 2.2.0.27 where behavior is
documented, plus a small set of well-justified differentiators (§13). Where
SpaceSniffer's behavior is documented, this spec cites it as the baseline; where
the research could not verify behavior (e.g. its internal layout algorithm, ADS
rendering), this spec says so explicitly and makes a reasoned choice.

---

## 2. Goals & Non-Goals

### 2.1 Goals (v1)

- **G1.** Single portable x64 Windows `.exe` — no installer, no runtime
  dependencies, no registry writes; runs from a USB stick, like the original.
- **G2.** Interactive squarified treemap with drill-down zoom, breadcrumb-style
  back/forward navigation, hover tooltips, and smooth zoom animation.
- **G3.** Live view during scan: the treemap populates progressively and is fully
  navigable mid-scan; the scan is never blocked by rendering.
- **G4.** SpaceSniffer-compatible filter syntax (name globs, folder masks, size,
  age, tags, attributes, file classes), applied per-view, non-destructively.
- **G5.** Tagging (4 colors) and coloring (flat colors + user-editable file
  classes).
- **G6.** Fast scanning: direct NTFS MFT read when elevated, parallel walker
  fallback everywhere else.
- **G7.** Live updates: filesystem change watching during and after scan.
- **G8.** Console / command-line mode: GUI-driven automation compatible with
  SpaceSniffer's command set (`scan`/`load`/`filter`/`export`/`save`/`autoclose`)
  **plus** a true headless mode (scan → export → stdout/exit code) that
  SpaceSniffer never had.
- **G9.** Export: text reports via a template engine, CSV/JSON, and snapshot
  save/load in a new, hardened binary format.
- **G10.** File operations: Explorer shell context menu (parity) plus safe
  delete-to-recycle-bin with confirmation (beyond parity).
- **G11.** High-DPI aware, dark/light theme following the system, Unicode
  everywhere.
- **G12.** Signed release binaries with published checksums; winget/scoop
  distribution.

### 2.2 Non-goals (v1)

- **N1.** 32-bit Windows builds. (SpaceSniffer itself went x64-only in 2.0.1.4.)
- **N2.** Non-Windows platforms. The scanning fast paths (MFT, USN journal,
  ReadDirectoryChangesExW) and shell integration are Windows-specific by design.
  *Stretch goal only:* if the crate architecture (§5) keeps platform code behind
  traits as planned, a Linux/macOS port becomes feasible later — but no v1 effort
  is spent on it.
- **N3.** Replacing TreeSize Pro. No NTFS permissions/ownership views, no email
  reporting, no scheduled enterprise reporting, no Excel export.
- **N4.** Duplicate-file detection, session/growth comparison, treemap PNG export.
  All three are proven differentiators from competitors (§13) but are explicitly
  deferred past v1 to keep scope bounded.
- **N5.** `.sns` / `.snf` file compatibility with SpaceSniffer. The format is
  undocumented (third-party reverse-engineered only) and is the subject of
  CVE-2026-26738; we define our own format (§4.8).
- **N6.** A TUI companion. (`diskonaut`/`dua-cli` already cover terminal UX; the
  headless CLI covers scripting.)
- **N7.** Charts other than the treemap (no sunburst, no bar charts).
- **N8.** Cloud sync, auto-updaters, telemetry, or any background network access.

---

## 3. Target Platform & Packaging

| Item | Decision |
|---|---|
| OS | Windows 10 (1703+) and Windows 11, x86-64 only |
| Rationale for floor | `ReadDirectoryChangesExW` extended info requires Win10 1703; below that the watcher degrades to `ReadDirectoryChangesW` (see §5.5). SpaceSniffer supports Win7 x64; we trade Win7/8 support for the extended-info watcher and a modern toolchain. |
| Form factor | One statically linked `.exe`, distributed as a `.zip`; optional MSIX/winget/scoop packaging that wraps the same binary |
| Installer | None |
| Registry | Never written by the app itself |
| Admin rights | Not required to run. Elevation unlocks MFT scanning + USN journal (§5.4). Offer "rescan as administrator" via `ShellExecuteW("runas")` self-relaunch — mirroring the research recommendation of an *optional* `requireAdministrator` flow rather than a mandatory manifest |
| Config location | Single TOML file `RustySpaceSniffer.toml` **in the same folder as the exe** (SpaceSniffer parity: one plain config file next to the binary, no registry). If the exe directory is not writable (e.g. Program Files, read-only media), fall back to `%APPDATA%\RustySpaceSniffer\config.toml`; if neither is writable, run non-persistent **with a status-bar notice** (we deliberately do not copy SpaceSniffer's silent-failure behavior). |
| Explorer integration | Optional, user-invoked: a settings toggle generates/removes a per-user `HKCU` "Scan with RustySpaceSniffer" context-menu entry invoking `RustySpaceSniffer.exe scan "%1"` — the documented SpaceSniffer `.reg` recipe, made one-click and per-user so no admin is needed |
| Binary size budget | ≤ 15 MB release build (egui+wgpu measured ~12.5 MB unstripped in the ecosystem study; `strip` + `lto` + `opt-level="z"` typically lands at 4–8 MB). SpaceSniffer's ~2.9 MiB is aspirational, not a v1 requirement. |
| Subsystem | `#![windows_subsystem = "windows"]` for the GUI binary; console attachment handled dynamically for CLI mode (§4.9) |

---

## 4. Functional Requirements

Priorities use MoSCoW: **Must** / **Should** / **Could** / **Won't** (won't-for-v1).

### 4.1 Start dialog & scan sources

Baseline: SpaceSniffer's start dialog has two tabs — "Drives or Paths" (media
icons + path field; multiple paths separated by `;`; browse button; drag & drop of
a folder fills the path field; ESC closes; CTRL+N reopens from the main window)
and "Snapshots" (load snapshot files).

| ID | Requirement | Priority |
|---|---|---|
| FR-1.1 | On startup show a start dialog listing available drives (with media-type icons and free space) and a path entry field | Must |
| FR-1.2 | Path field accepts local paths (`C:\`, `D:\Data`), multiple paths separated by `;`, and UNC/network paths (`\\server\share`), including Samba shares | Must |
| FR-1.3 | Dragging a folder onto the start dialog fills the path field | Must |
| FR-1.4 | Dragging one or more folders **onto the main window** opens one new view per dropped folder, bypassing the start dialog (SpaceSniffer parity; egui has built-in drag & drop) | Must |
| FR-1.5 | Snapshots tab lists/loads `.rssnap` snapshot files (our format, §4.8) | Must |
| FR-1.6 | ESC closes the start dialog; CTRL+N reopens it from any view | Must |
| FR-1.7 | Multiple paths in one start action open one view per path (SpaceSniffer behavior; no tabs — separate floating windows via egui multi-viewport, listed in a "Windows" menu) | Should |
| FR-1.8 | Each view's window title shows the scanned drive's free space and, for drive scans, scan progress percentage (SpaceSniffer parity) | Should |
| FR-1.9 | Import of `du`-style text output as a scan source | Could (the SpaceSniffer manual claims `du` input support; low value for our users) |
| FR-1.10 | Loading SpaceSniffer `.sns` files | Won't (undocumented format, CVE history — §N5) |

### 4.2 Scanning engine

Baseline: SpaceSniffer scans multithreaded; the treemap populates progressively
and is navigable mid-scan; elements flash when newly scanned or externally
modified (flash toggleable since 2.0.5.18); multiple views over the same media
share one physical scan ("smart cache"); a "sub-scan" can force-complete a zoomed
subtree; minimizing the window speeds scanning (we consider that a bug to fix, not
a feature to copy).

| ID | Requirement | Priority |
|---|---|---|
| FR-2.1 | Scanning is asynchronous: the treemap updates progressively (throttled to UI-friendly ticks, ~4–10 Hz) and remains fully navigable while scanning | Must |
| FR-2.2 | Scan can be **cancelled** at any time; partial results remain browsable | Must |
| FR-2.3 | Scan can be **paused and resumed** | Should |
| FR-2.4 | On NTFS volumes when elevated, use the MFT fast path (§5.4): full-volume enumeration in seconds | Must |
| FR-2.5 | On non-NTFS volumes (FAT32/exFAT/ReFS/network) or when unelevated, use the parallel walker (§5.4). Detect volume filesystem via `GetVolumeInformationW`; offer "rescan as administrator" when MFT was available but skipped | Must |
| FR-2.6 | Multiple views over the same media share one physical scan (cache keyed by volume+path); duplicate scans with different filters cost zero rescans | Should |
| FR-2.7 | While zoomed, a "scan this subtree now" sub-scan force-completes that branch without waiting for the master scan (one active sub-scan per view) | Could |
| FR-2.8 | **Unaccessible space**: subtrees that cannot be read (permission denied, e.g. `System Volume Information` in walk mode) are accounted as a distinct category and surfaced on the map, not silently dropped | Must |
| FR-2.9 | **Unknown/not-yet-scanned space**: during a drive scan, unscanned portions are represented so proportions remain meaningful mid-scan (SpaceSniffer: CTRL+U toggles the element) | Should |
| FR-2.10 | Rendering must never throttle scanning (the anti-"minimize to scan faster" requirement); scan throughput with the window visible ≥ 95% of throughput with it hidden | Must |
| FR-2.11 | Newly scanned or externally modified elements flash briefly; the flash is toggleable in settings | Should |
| FR-2.12 | Request `SeBackupPrivilege` at startup when available (read-protected folders in walk mode); degrade gracefully and honestly when not granted. Document the AV-false-positive risk in the README | Should |
| FR-2.13 | A log console (dismissible panel) records scan errors/warnings with per-entry hints (SpaceSniffer parity) | Should |

### 4.3 Treemap visualization & interaction

Baseline: SpaceSniffer renders a classic Shneiderman treemap (used with his
permission): rectangles sized proportionally to element size, folders nest
children recursively up to a configurable display-depth limit (CTRL+`+` / CTRL+`-`
or toolbar buttons). Its exact internal layout algorithm is **unverifiable**
(closed source); visually it resembles squarified/binary-split output. Our choice
of squarified is specified in §6.2.

| ID | Requirement | Priority |
|---|---|---|
| FR-3.1 | Rectangle areas are strictly proportional to element sizes. **No minimum cell size** in the layout — that would make the treemap a lie (Fopull lesson); sub-pixel elements are hidden by the renderer but still counted, aggregated, and exportable (SpaceSniffer behaves the same way) | Must |
| FR-3.2 | Zero-byte files occupy zero area and are never displayed (SpaceSniffer parity) | Must |
| FR-3.3 | Folders render with a header strip (title bar) containing the folder name; child area is nested inside (SpaceSniffer/SpaceMonger convention) | Must |
| FR-3.4 | Single left-click selects an element and highlights it with a drop shadow so it can be tracked during live re-layout (SpaceSniffer parity) | Must |
| FR-3.5 | Double-click zooms a folder to fill the view | Must |
| FR-3.6 | Browser-like navigation: back/forward toolbar buttons, BACKSPACE / SHIFT+BACKSPACE, hardware browser back/forward/home keys, CTRL+UP (zoom out one level), CTRL+HOME (jump to view root). Navigation shortcuts are inactive while the filter field has focus, except tag shortcuts (SpaceSniffer parity) | Must |
| FR-3.7 | Breadcrumb bar shows the current zoom path; each crumb is clickable | Should (SpaceSniffer uses back/forward rather than visible breadcrumbs; we add the bar as a cheap usability win) |
| FR-3.8 | Hover tooltip shows: name, logical and on-disk size, creation/modify/access dates and ages (toggleable), first-level children count. Tooltip positioning must handle screen edges and >100% display zoom (SpaceSniffer had a cropping bug here until 2.2.0.27) | Must |
| FR-3.9 | Hover highlight with configurable "halo levels" (highlight N ancestor levels); optional mouse-trail effect | Could |
| FR-3.10 | Zoom is animated (configurable duration, including "instant"). Animation interpolates layouts (DynaZoom-style); a cheaper cross-fade between pre/post zoom frames is the fallback | Should |
| FR-3.11 | Viewable-percent bar (thin bar at the left edge) shows what fraction of the scanned media the current zoom represents (SpaceSniffer parity) | Should |
| FR-3.12 | Progress indicator shows scan % (drive scans, where the total is known), filter progress, or a plain status message otherwise (SpaceSniffer parity) | Must |
| FR-3.13 | Drive scans at root view show a **free space** element (CTRL+F toggles) and the unknown/unaccessible elements (CTRL+U); both are excluded from zoomed views to avoid proportion distortion (SpaceSniffer parity) | Must |
| FR-3.14 | Configurable display-depth limit (CTRL+`+` / CTRL+`-` and toolbar buttons); children beyond the limit are aggregated into their visible ancestor | Must |
| FR-3.15 | Configurable geometry: font size, minimum element pixels (renderer-side hiding threshold), target aspect proportions, initial detail level, sort-by-size toggle (big items top-left) | Should |
| FR-3.16 | During a progressive scan the layout uses a **stable ordering** (no per-tick re-sorting) with throttled re-layout (~2–4 Hz), to avoid the "boiling treemap" that sorted squarified produces under changing data; full re-sort on user-initiated view changes | Must |
| FR-3.17 | Idle frame-rate reduction: when the user is idle and no scan is active, stop repainting (egui reactive repaint ≈ 0% CPU idle) | Must |
| FR-3.18 | Alternate shading of folders by age | Could (listed in the competitive baseline) |

### 4.4 Filtering

Baseline (SpaceSniffer filter field, per-view, non-destructive): conditions are
separated by `;`; filters apply to the **view, not the scan** — changing filters
mid-scan never rescans; bad filters produce a warning. Combination rules:
**file masks + tags + class conditions are OR-ed together; exclusion masks are
AND-ed; all other condition types are AND-ed.** Canonical example from the manual:
`*.jpg;>1mb;<3months;|:yellow`.

| ID | Requirement | Priority |
|---|---|---|
| FR-4.1 | Each view has a filter field; filters are evaluated against the already-scanned tree and never trigger a rescan | Must |
| FR-4.2 | **File mask**: `*` and `?` wildcards; leading `|` negates (`|*.jpg` = everything but JPEGs) | Must |
| FR-4.3 | **Folder mask**: prefix with `\` (e.g. `\temp`, `|\temp`, `\*internet*`); matches if any ancestor folder at any depth matches; matching folder names render **bold** on inclusion filters | Must |
| FR-4.4 | **Size**: `(disksize|clustersize|filesize|logicalsize|size)[<|>][n][b|kb|mb|gb|tb]`; default is disk (allocated) size; binary units (kb = 1024 b). Example: `>100kb` | Must |
| FR-4.5 | **Age**: `(creation|modify|access)[<|>][n][seconds|minutes|hours|days|weeks|months|years]`; default is modify date. Examples: `a>1year`, `<3months` | Must |
| FR-4.6 | **Tags**: legacy syntax `:red`/`:r`/`:1`…`:all`/`:a`, negation `|:red`; and the 2.x syntax `:tag:`/`:tags:` with `+`/`-` combinations, e.g. `:tag:red+green-b`, `|:tag:1,3,-red` | Must |
| FR-4.7 | **Attributes**: `:attr:`/`:attrs:` with archive/system/readonly/hidden/compressed/encrypted/offline/temporary/notindexed/sparse/ads, with combos like `:attr:+a-ro,h` | Should |
| FR-4.8 | **File classes**: `:class:Audio/Music` expands to that class's extension list (case-insensitive); negatable | Should |
| FR-4.9 | Fuzzy keyword matching (SpaceSniffer accepts `disksize`/`disk`/`dsk`/`dsksz` and even spaced forms like `size > 10 mb`); we accept the documented aliases and unambiguous prefixes; ambiguous input produces a specific warning, not silent misinterpretation | Should |
| FR-4.10 | Combination semantics exactly as documented: masks+tags+classes OR-ed; exclusion masks AND-ed; other conditions AND-ed | Must |
| FR-4.11 | Filtered-out elements are **dimmed (gray-out)** in place rather than only hidden, per SpaceSniffer 2.0.1.4 behavior. *Note: the exact visual treatment is inferred from release-note wording and not documented; we choose dim-to-30%-opacity + desaturation, toggleable to hard-hide.* | Must |
| FR-4.12 | Filtered-out elements remain in the model and in exports (exports state whether the filter was applied); tag operations (CTRL+0 clear) still affect filter-hidden elements (SpaceSniffer parity) | Must |
| FR-4.13 | Filter syntax errors produce an inline warning in the filter field (no modal dialog) | Must |
| FR-4.14 | The filter passed via CLI (`filter` command) appears in the view's filter field (SpaceSniffer parity) | Must |

### 4.5 Tagging & coloring

| ID | Requirement | Priority |
|---|---|---|
| FR-5.1 | Four temporary tag colors — red/yellow/green/blue — via CTRL+1..4 (bare 1..4 when the filter box is unfocused); toggle on/off; CTRL+0 clears all tags under the current zoom including filter-hidden elements (SpaceSniffer parity) | Must |
| FR-5.2 | Tags apply to files **and folders**; children inherit ancestor tags for filtering, but only the element's own tag is drawn (SpaceSniffer parity, to avoid clutter) | Must |
| FR-5.3 | Tags are memory-only, lost when views close, but **persisted in snapshots** (SpaceSniffer parity — snapshot sharing carries tags) | Must |
| FR-5.4 | Two color styles, toggled per view (CTRL+T / toolbar): **Flat Colors** (user-chosen base colors for drive/folder/file/free-space/unknown-space, darkened by nesting depth via "Level contrast") and **File Classes** (user-defined classes: name + `;`-separated extension list + color; first match wins; sensible defaults ship for multimedia/archives/etc.). All colors are per-theme (FR-11.5) | Must |
| FR-5.5 | Look settings: level contrast, border contrast ("gummy" to "hard edge"), halo levels, hover highlight, drop shadow, mouse trail (SpaceSniffer parity) | Should |

### 4.6 File operations

Baseline: SpaceSniffer has **no built-in file operations**; right-click opens the
real Windows Explorer shell context menu; the app is otherwise read-only, and its
manual warns that deleting a filtered folder through the shell deletes
**everything**, not just visible items. The shell-menu dependency has caused
real-world freezes (misbehaving third-party shell extensions). We keep parity and
add one carefully-scoped native operation.

| ID | Requirement | Priority |
|---|---|---|
| FR-6.1 | Right-click on any element opens the Windows Explorer shell context menu for that item (open/rename/delete/properties via the shell) | Must |
| FR-6.2 | The shell menu is invoked on a worker thread with a watchdog; a hung shell extension must not freeze the UI (fix for the documented SpaceSniffer freeze class) | Should |
| FR-6.3 | "Open containing folder in Explorer" command | Should |
| FR-6.4 | **Delete to Recycle Bin**, in-app, with a confirmation dialog that (a) lists what will be deleted, (b) warns explicitly when an active filter hides part of a folder's contents and states the true total, and (c) shows a running freed-space counter. Multi-stage confirmation model follows dua-cli's proven pattern. No permanent (shift-delete) option in v1 | Should (beyond parity; the single most-requested operation) |
| FR-6.5 | No other mutating file operations (rename/move/cleaners) | Won't-for-v1 |

### 4.7 Live updates

Baseline: SpaceSniffer listens to OS file-system change events and updates the map
in real time; tracking continues even if you start and immediately stop a scan;
the detector can be disabled in config (requires restart); notifications do not
work on network drives (manual rescan needed there).

| ID | Requirement | Priority |
|---|---|---|
| FR-7.1 | During and after a scan, filesystem changes (create/delete/rename/resize) update the tree and treemap in near-real-time, with modified elements flashing | Must |
| FR-7.2 | On NTFS volumes when elevated, use the **USN change journal** (cursor persisted per volume; survives app restarts) | Must |
| FR-7.3 | Everywhere else (FAT32/exFAT/ReFS/network/unelevated), use `ReadDirectoryChangesExW` (extended info, Win10 1703+) on the currently visible subtrees | Must |
| FR-7.4 | Watcher buffer overflow (`ERROR_NOTIFY_ENUM_DIR`) marks the affected subtree dirty and triggers an incremental rescan of that subtree — events are never silently dropped | Must |
| FR-7.5 | USN journal wrap or journal-ID change triggers a full rescan of the volume | Must |
| FR-7.6 | Change tracking is toggleable in settings (default on) | Should |
| FR-7.7 | Network/UNC scans show a persistent "live updates unavailable — press F5 to rescan" affordance (SpaceSniffer documents this limitation; we surface it instead of hiding it) | Should |
| FR-7.8 | Manual rescan (F5) of the full view or of the current zoom subtree | Must |

### 4.8 Export & snapshots

Baseline: SpaceSniffer's export module operates on the **current zoom + current
filter** of the active view. Two output kinds: `.sns` binary snapshots (full dump
including tags; reloadable; no live link after load) and **text reports** via a
template mini-language (header/detail/footer sections; `<%tags%>`; `{commands}`
incl. `{if}` conditionals; named, shareable configurations such as the built-in
"Grouped by folder"; can emit HTML or batch files).

**The snapshot format lesson.** SpaceSniffer's `.sns` format is undocumented
(third-party reverse engineering describes little-endian records: folder open
`0x0203`, file open `0x0202`, close `0x0100`; u32 name length + Base64-encoded
UTF-8 name; u64 logical size; u64 padding; 3×u64 timestamps) and has a real CVE:
**CVE-2026-26738**, a stack buffer overflow when parsing crafted `.sns` files, plus
a separately patched "hacked SNF file loading" vulnerability in 2.1.0.21. We
therefore design a **new format** whose parser is length-checked end to end.

| ID | Requirement | Priority |
|---|---|---|
| FR-8.1 | Export operates on the active view's current zoom + filter, and states so in the output header | Must |
| FR-8.2 | Text report export via a template engine compatible with SpaceSniffer's documented mini-language: header/detail/footer sections; literal passthrough; `<%tag%>` placeholders (`<%pathfile%>`, `<%path%>`, `<%file%>`, `<%fileext%>`, `<%size%>`, `<%sizebytes%>`, `<%disksizebytes%>`, `<%filemodifydate%>`, `<%age%>`, `<%isfile%>`/`<%isfolder%>`/`<%iscontainer%>`, `<%nestinglevel%>`, counters); `{commands}` (`{&br}`, `{&tab}`, `{leftpad}`, `{rightpad}`, `{nest}`, `{script}`, `{if…}`); named, shareable configurations; block sorting (folders-first/files-first/none) + fine sorting + descending flag | Must |
| FR-8.3 | Ship built-in export configurations including one named **"Grouped by folder"** (SpaceSniffer CLI examples reference this exact name; keeping it eases migration of user scripts) | Must |
| FR-8.4 | CSV export (one row per node, header row, UTF-8 with BOM for Excel) | Must |
| FR-8.5 | JSON export (full subtree with sizes, dates, attributes, ADS detail) | Should |
| FR-8.6 | Clipboard copy of an indented tree-text rendering of the current view (WizTree-style; cheap and constantly requested) | Could |
| FR-8.7 | Snapshot save/load in **`.rssnap`**, our own binary format (§5.7): full tree state including tags, filter, zoom path, and scan metadata. Loaded snapshots open "framed" with the snapshot filename and have no live link to the filesystem (SpaceSniffer parity) | Must |
| FR-8.8 | `.rssnap` parser hardening: strict length-checked parsing throughout; every length field validated against remaining buffer before allocation; allocation caps; recursion depth cap; whole-file checksum; versioned header with magic bytes (details §5.7, §9) | Must |
| FR-8.9 | Export templates may emit batch files for bulk file operations (SpaceSniffer officially suggests this). We ship **no** batch-emitting presets by default | Could |
| FR-8.10 | Snapshot comparison ("what changed since") | Won't-for-v1 (deferred; §N4) |

### 4.9 Console / command-line mode

Baseline (SpaceSniffer manual ch. 11): `help`, `scan "<path>"` (multiple `;`-separated
paths, one view each), `load "<file>"`, `filter "<filter>"` (applies to the
**preceding** scan/load), `export "<config name>" "<dest file>"` (auto-export at
scan end; config name case-sensitive), `save "<path>"` (implicit `.sns`), `autoclose`
(quit after all exports; deactivated by any interactive filter/stop). Exports are
serialized to avoid disk thrashing. **SpaceSniffer's CLI still opens the GUI** —
there is no documented true headless mode; its 2.0.3.12 "meta-commands" are not
documented anywhere public (unverified). We implement parity plus a real headless
mode.

| ID | Requirement | Priority |
|---|---|---|
| FR-9.1 | GUI automation commands with SpaceSniffer-compatible semantics: `scan`, `load`, `filter`, `export`, `save`, `autoclose`, `help`; same ordering rules (filter binds to the preceding scan/load; exports run after all scans complete, serialized) | Must |
| FR-9.2 | **Headless mode**: `--headless` (or `console` subcommand) performs scan + export with no window, writes the report to file or stdout, and exits with a meaningful exit code (0 ok, 1 scan errors, 2 usage error). This is the automation/Task-Scheduler story TreeSize charges for and SpaceSniffer lacks | Must |
| FR-9.3 | In headless mode the binary attaches to the parent console when present (`AttachConsole`) so output appears in the invoking terminal despite the GUI subsystem flag | Must |
| FR-9.4 | CLI accepts the same filter strings as the GUI filter field | Must |
| FR-9.5 | CLI flags mirror the GUI scan options: `--no-ads`, `--no-watch`, `--logical` (use logical instead of allocated size), `--elevated` (relaunch as admin for MFT) | Should |
| FR-9.6 | SpaceSniffer's undocumented 2.x meta-commands | Won't (unverifiable — see §14) |

### 4.10 Settings & persistence

| ID | Requirement | Priority |
|---|---|---|
| FR-10.1 | All settings persist in the single TOML config file (§3): look settings, geometry, filter-field history, file-class definitions, export configurations, watcher/ADS toggles, window positions | Must |
| FR-10.2 | Config is human-editable; unknown keys are preserved on save (forward compatibility) | Should |
| FR-10.3 | If config cannot be saved, the app runs non-persistent and shows a status notice (§3) | Must |
| FR-10.4 | Settings changes that require restart (e.g. watcher disable, per SpaceSniffer parity) are labeled as such | Should |
| FR-10.5 | Per-volume persisted state (USN journal cursors) lives in a separate machine-local state file, not the portable config, so the config remains shareable between machines | Should |

### 4.11 Look & feel, theming, and dark mode

Baseline: reproduce SpaceSniffer's **recognizable layout and interaction
vocabulary** — a toolbar strip above a window-filling treemap, folder header
strips with names, the filter field on the toolbar, status/progress bar at the
bottom, viewable-percent bar at the left edge — but rendered with a **modern,
flat, Fluent-aligned visual language** instead of SpaceSniffer's 2009-era
chrome, and fully themed with a first-class **dark mode** (SpaceSniffer has
none; WinDirStat 2.x added one and users notice).

| ID | Requirement | Priority |
|---|---|---|
| FR-11.1 | **Chrome layout parity**: same chrome anatomy as SpaceSniffer — icon toolbar (new scan, back/forward, zoom in/out, rescan, display-depth, color style, settings), filter field, bottom status bar, left viewable-percent bar. A SpaceSniffer user must orient instantly | Must |
| FR-11.2 | **Modernized visuals**: flat Fluent-ish styling (egui's default aesthetic, tuned); redrawn vector icons that keep SpaceSniffer's icon *semantics* but are DPI-crisp at any scaling; Segoe UI as UI font; consistent spacing grid; subtle shadows and the FR-3.10 zoom animation for polish | Must |
| FR-11.3 | **Treemap rendering fidelity**: folder header strips, recursive nesting, hover highlight, selection drop shadow, and flash-on-change all read visually as SpaceSniffer — clean 1 px borders, anti-aliased text, no legacy "gummy" default (border contrast defaults to a flat, hard-edge look; the old styles remain configurable per FR-5.5) | Must |
| FR-11.4 | **Dark mode**: three-way setting — *System* (default) / *Light* / *Dark*. *System* follows the Windows app theme and reacts live to theme changes (no restart); the window title bar follows the theme via `DwmSetWindowAttribute(DWMWA_USE_IMMERSIVE_DARK_MODE)` | Must |
| FR-11.5 | **Per-theme palettes**: every color has a dark and a light variant — chrome, treemap flat colors (FR-5.4), file-class colors, the four tag colors, free/unknown/unaccessible elements, filter dim treatment (FR-4.11), flash highlight. User color customizations are stored per theme so switching themes never produces an unreadable map | Must |
| FR-11.6 | **Theme-aware treemap shading**: in dark theme, nesting-depth contrast and border/halo colors adapt (lighten-by-depth instead of darken-by-depth) so the map stays legible; defaults are tuned per theme, not a mechanical inversion | Should |
| FR-11.7 | **Contrast**: text and essential cues meet WCAG AA (≥ 4.5:1) against their backgrounds in both themes; verified for the shipped default palettes in the §10.4 UI tests | Must |
| FR-11.8 | **Consistent theming everywhere**: dialogs, tooltips, context menus, start dialog, and log console are themed; no unthemed white flash at startup or when opening windows | Must |
| FR-11.9 | Theme switching is instant (no restart) and persisted in the config file (FR-10.1) | Must |
| FR-11.10 | Optional accent color taken from the Windows system accent (`DwmGetColorizationColor` / `UISettings`) for selection and focus cues | Could |

---

## 5. Architecture

### 5.1 Workspace layout

A Cargo workspace. The split follows the proven Fopull/Storage Sifter reference
architecture (`scanner` / `treemap` / `app`) extended with the modules our feature
set needs. Crates are small, single-purpose, and individually testable.

| Crate | Role | Key constraints |
|---|---|---|
| `rss-core` | Core data model: tree of nodes, sizes, timestamps, attributes, ADS, tags; filter AST; snapshot model. **Zero platform dependencies, zero GUI dependencies** | Pure Rust, `#![forbid(unsafe_code)]`, heavy unit tests |
| `rss-filter` | Filter parser (SpaceSniffer-compatible DSL) and evaluator over `rss-core` nodes | Pure Rust, fuzz-tested |
| `rss-treemap` | Squarified layout: pure geometry, zero deps (~200–400 lines) | Testable against the paper's worked example; no rendering code |
| `rss-scan` | Scanning engine: `ScanEngine` trait, `MftScanner`, `WalkScanner`, volume detection, privilege checks | Windows-only; isolated `unsafe` FFI |
| `rss-watch` | Live updates: `Watcher` trait, `UsnJournalWatcher`, `RdcwWatcher`, delta channel, coalescing | Windows-only |
| `rss-export` | Template engine, CSV/JSON writers, snapshot (de)serialization | Pure Rust except file I/O; parser fuzz-tested |
| `rss-shell` | Shell integration: Explorer context menu, recycle-bin delete, open-containing-folder, self-elevation | Windows-only; all shell calls on worker threads |
| `rss-app` | GUI: eframe/egui application, views, settings dialogs, drag & drop, CLI parsing and dispatch (GUI + headless modes) | Depends on all of the above |
| `rss` (bin) | Thin `main.rs` produced from `rss-app` | Single portable exe |

Platform-specific code is confined to `rss-scan`, `rss-watch`, and `rss-shell`,
each behind a trait; this is what keeps the cross-platform stretch goal (§N2)
plausible without costing v1 anything.

### 5.2 Core data model (`rss-core`)

- **Flat arena tree**: `Vec<Node>` with `u32` indices and parent pointers
  (Fopull-proven; supports >4B nodes concern is out of scope — SpaceSniffer-class
  volumes are ≤ tens of millions of entries; a u32 arena covers 4.29e9).
  Deletion/update propagates size deltas up ancestors in O(depth) with no rebuild.
- **Node** = file | directory | ADS-holder | special (free space, unknown,
  unaccessible, cloud placeholder category marker).
- **Size bookkeeping**: every node stores
  - `logical_size` (file length),
  - `allocated_size` (true size on disk: `FileStandardInfo.AllocationSize` on the
    walk path; `$DATA` AllocatedSize on the MFT path — correct for NTFS
    compression and sparse ranges "for free"),
  - `ads_size` (sum of named alternate data streams; rolled into the host file's
    displayed size by default, with drill-down detail — the research-recommended
    default),
  - child aggregates maintained incrementally.
  The treemap sizes elements by **allocated size by default** (matching
  SpaceSniffer's filter default of disk size); a per-view toggle switches to
  logical size.
- **Hardlink dedup**: a seen-set of file identities — `(volume_serial, FRN)` on
  the MFT path; `(volume_serial, file_index)` via
  `GetFileInformationByHandleEx(FileIdInfo)` (128-bit file IDs) on the walk path.
  First occurrence counts full size; subsequent links count as 0-byte aliases
  (marked, not hidden). Uses `rustc-hash::FxHashSet`.
- **Timestamps**: creation/access/modify as Windows FILETIME; ages computed at
  filter evaluation time.
- **Attributes**: the full set needed by the `:attr:` filter (archive, system,
  readonly, hidden, compressed, encrypted, offline, temporary, notindexed,
  sparse) plus internal flags: reparse point (+tag), cloud placeholder, resident-
  in-MFT, access-denied, hardlink-alias.

### 5.3 Rendering model

Immediate-mode redraw, per the research synthesis: the scene is fully recomputed
each frame from `(tree, zoom node, filter, colors, style)`; culling makes this
cheap. The only retained state is: glyph caches (automatic in egui), layout
results between data-change ticks, and window/swapchain resources. No scene
graph.

Key rules (Fopull lessons, adopted verbatim):

- **Never lay out the whole tree per frame.** Layout only the children of the
  zoomed node plus 1–2 preview levels — tens to hundreds of cells, bounded by
  window size, not tree size.
- **Cull before recursion**: a cell whose short side < ~3 px is skipped along
  with its entire subtree.
- Layout runs on the UI thread between repaint ticks (it is microseconds at these
  cell counts); the scanner never waits on it (FR-2.10).

### 5.4 Scanning engine (`rss-scan`)

Trait:

```rust
trait ScanEngine {
    fn scan(&mut self, root: &Path, opts: &ScanOptions,
            sink: &mut dyn FnMut(ScanEvent)) -> Result<ScanSummary>;
}
```

`ScanEvent` = upserts/deletes streamed to the model; the model coalesces them into
throttled UI ticks.

**Engine selection (fallback chain from the research):**

| Condition | Engine | Watcher |
|---|---|---|
| NTFS + elevated | `MftScanner` | `UsnJournalWatcher` |
| NTFS, not elevated | `WalkScanner` (offer elevate-and-rescan) | `RdcwWatcher` |
| FAT32 / exFAT / network / ReFS | `WalkScanner` | `RdcwWatcher` (network: unavailable, FR-7.7) |

Volume detection via `GetVolumeInformationW` (`lpFileSystemNameBuffer`); elevation
check via attempt-open of `\\.\X:` (or `GetTokenInformation(TokenElevation)`).

**`MftScanner`** — two implementation stages, both behind the same trait:

1. *Stage A (v1):* `FSCTL_ENUM_USN_DATA` via `DeviceIoControl` on a volume handle
   (`CreateFileW("\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ|FILE_SHARE_WRITE)`).
   Yields `USN_RECORD_V2`/`V4` records: FRN, ParentFRN, attributes, name — **no
   size**. Build the FRN→ParentFRN map in memory (no path resolution during scan —
   the key trick), then fetch sizes in a second pass: `OpenFileById` +
   `GetFileInformationByHandleEx(FileStandardInfo)` gives `AllocationSize` and
   `NumberOfLinks` (hardlink dedup input). **Version hazard:** on Win10+ volumes
   with 128-bit file IDs, records arrive as `USN_RECORD_V3`/`V4` with a different
   layout — switch on `MajorVersion`; never assume V2.
2. *Stage B (post-v1 option):* raw `$MFT` parse (via `FSCTL_GET_RETRIEVAL_POINTERS`
   to locate extents) using the `mft` crate — non-resident `$DATA` headers carry
   AllocatedSize directly (compression/sparse-correct), plus all ADS natively.
   This removes the second pass. Deferred from v1 because Stage A is sufficient
   for the performance target and less code to audit.

`FSCTL_GET_NTFS_VOLUME_DATA` provides cluster size and MFT extent info for
progress estimation and size-on-disk rounding.

**`WalkScanner`** — parallel directory walk with `dua-core` (the maintained
successor to `jwalk`; engine of `dua-cli`). Per-entry metadata uses
`GetFileInformationByHandleEx(FileStandardInfo)` where possible (one call yields
AllocationSize + NumberOfLinks); `GetCompressedFileSizeW` as fallback. With
`SeBackupPrivilege` granted, open directories with `FILE_FLAG_BACKUP_SEMANTICS`
to bypass ACLs; without it, access-denied subtrees are marked `<access denied>`
and accounted as unaccessible space (FR-2.8). Parallelism is scaled to the device:
research notes parallel walking mainly helps SSDs while HDD head seeking
dominates, and SpaceSniffer itself tried and **removed** an experimental
concurrent-folder scan for lack of benefit — so worker count is conservative on
rotational media.

### 5.5 Live-update design (`rss-watch`)

Single delta channel (crossbeam MPMC) feeding the model; bursts coalesced before
application.

- **`UsnJournalWatcher`** (NTFS+admin): at scan end record the high-USN watermark
  from `FSCTL_QUERY_USN_JOURNAL`; poll `FSCTL_READ_USN_JOURNAL` from the last USN
  (supports blocking wait via `BytesToWaitFor`/`Timeout`). Filter on
  `USN_REASON_CLOSE`-batched reasons to avoid churn. Records carry FRNs, so they
  patch the FRN-keyed map directly — the natural companion to the MFT scan.
  Journal wrap or journal-ID change → flag full rescan (FR-7.5). Cursor persisted
  per volume (FR-10.5) so tracking survives restarts.
- **`RdcwWatcher`**: `notify` crate (v8.x) wrapping `ReadDirectoryChangesW`, or
  direct `ReadDirectoryChangesExW` with `ReadDirectoryNotifyExtendedInformation`
  (Win10 1703+) to get `FILE_NOTIFY_EXTENDED_INFORMATION` with 128-bit
  `FileId`/`ParentFileId` — much better for tree patching than names alone.
  Watches the volume root when cheap, else the currently visible subtrees.
  `ERROR_NOTIFY_ENUM_DIR` (buffer overflow) → dirty-mark + incremental subtree
  rescan (FR-7.4); events are never silently dropped. Known RDCW hazards handled:
  mixed long/8.3 short filenames, limited info for deleted items.

### 5.6 Filtering pipeline (`rss-filter`)

1. **Parse** filter string → AST (conditions split on `;`; per-condition parser
   for masks / folder masks / size / age / tags / attrs / classes; fuzzy alias
   table). Parse errors collected with spans for the inline warning UI.
2. **Evaluate** per node → `visible | dimmed | hidden` tri-state (FR-4.11), plus
   folder-mask ancestor matching cached per directory.
3. **Combine** per the documented rules (FR-4.10).
4. Result feeds the renderer (dimming) and the exporter (inclusion) without
   touching the model — filters are pure functions of (tree, filter, tags).

### 5.7 Snapshot format `.rssnap` (`rss-export`)

New binary format, designed against the CVE-2026-26738 lesson:

- Header: 8-byte magic `RSSNAP\0`, u16 format version, u16 header length, u32
  flags, u64 total payload length, u32 CRC32 of header.
- Payload: sequence of length-prefixed records (varint type tag + u32 length +
  bytes). Strings are raw UTF-8 (no Base64 games like `.sns`); every length is
  checked against remaining buffer **before** any allocation; per-record and
  total allocation caps; tree-depth cap (e.g. 512) enforced iteratively, never by
  recursion into untrusted depth.
- Trailer: CRC64 of the whole payload; load fails closed on mismatch.
- Contains: node stream (names, sizes, timestamps, attributes, FRN if known),
  tags, the active filter string, zoom path, scan metadata (tool version, volume
  serial, timestamps). No executable content, no embedded templates.
- Serde-free hand-rolled reader/writer (the format is small; fewer deps, easier
  audit). Fuzz target `rssnap_parse` runs in CI (§10).

### 5.8 Threading / async model

No tokio; plain threads + channels suffice and keep the binary lean.

- **Scanner threads** (rayon pool inside `dua-core`, plus the MFT reader thread)
  → stream `ScanEvent`s over a crossbeam channel.
- **Model owner**: one dedicated thread (or the UI thread with pumped messages)
  owns the tree, applies scan/watch deltas, maintains aggregates.
- **Watcher threads** (1 per active watcher) → same delta channel.
- **UI thread**: egui/eframe; reads a read-locked snapshot of the visible subtree
  per repaint; `request_repaint` on data ticks and during animations only
  (reactive repaint → ~0% CPU idle, FR-3.17).
- **Shell operations** (context menu, recycle-bin delete) on worker threads with
  watchdog (FR-6.2).

### 5.9 Error handling strategy

- `anyhow::Result` at application boundaries; `thiserror` typed errors inside
  libraries (`rss-scan`, `rss-watch`, `rss-export`).
- Per-node scan errors (access denied, path too long, recall hazards) are **data,
  not failures**: recorded on the node / in the unaccessible-space accounting and
  listed in the log console (FR-2.13). A scan only *fails* wholesale when the root
  is unreadable.
- No panics across FFI boundaries; all Win32 calls checked; `unsafe` confined to
  `rss-scan`/`rss-watch`/`rss-shell` with `#![deny(unsafe_code)]` elsewhere.

---

## 6. Technology Choices

Decision-record format. Where the research left a question open, the choice is
marked *(judgment call)*.

### 6.1 GUI framework — egui + eframe

- **Decision:** `egui`/`eframe` (wgpu backend), with `rfd` for native file dialogs.
- **Options considered:** iced, Slint, Tauri 2, winit+wgpu custom UI, fltk-rs,
  native-windows-gui, gpui.
- **Rationale (per research report 2):**
  1. The treemap is a native egui workload — axis-aligned rectangles + clipped
     labels + hover + animated zoom are epaint's bread and butter;
     `egui::PaintCallback` with the egui-wgpu backend is in reserve if a
     full-overview mode ever needs >100k rects.
  2. Fully static single x64 exe, no runtime, no WebView2 caveat — matches the
     portability requirement exactly.
  3. Clean MIT/Apache-2.0 license — no Slint-style attribution/GPL entanglement.
  4. Best maturity in pure-Rust GUI: AccessKit-based Windows UIA accessibility on
     by default, `egui_kittest` headless UI test harness, funded maintenance.
  5. Built-in multi-viewport (one OS window per view, FR-1.7) and drag & drop
     (FR-1.3/1.4).
- **Trade-offs accepted (stated honestly):**
  - *Not native-looking.* Custom-drawn chrome; mitigated by system dark/light
    theme, `rfd` native dialogs, and flat Fluent-ish styling. For a utility this
    is acceptable (SpaceSniffer itself is custom-drawn).
  - *No system font fallback.* We ship one embedded font and additionally try to
    load `C:\Windows\Fonts\segoeui.ttf` at runtime; document the fallback chain.
  - *No native menubar* (egui issue #3411 open) — we use in-window menus.
  - *Version churn*: egui ships 2–4 breaking minors/year; we pin versions and
    budget upgrade time. Version numbers in the research came from one
    third-party ecosystem study plus crates.io — re-verify at dependency-pinning
    time.
- **Rejected:** Tauri (breaks portable-exe via WebView2 runtime dependency);
  NWG (dormant upstream); winit+wgpu DIY (building toolbar/filter/settings chrome
  from scratch dwarfs the canvas benefit); gpui (no shipped widgets, Zed-coupled
  roadmap, stalled crates.io cadence); iced (credible #2 with the nicest canvas
  API, but no accessibility in stable and bus-factor-1 release cadence); Slint
  (weakest GPU-canvas fit of the bunch; license friction).

### 6.2 Treemap layout algorithm — squarified, own implementation

- **Decision:** hand-written squarified treemap (Bruls, Huizing, van Wijk, 1999)
  in `rss-treemap`, ~200–400 lines, dependency-free, with a **stable-ordering
  mode** for progressive scans.
- **Options considered:** slice-and-dice, SpaceMonger binary-split / pivot,
  ordered/strip treemaps, cushion treemaps, stable-treemap research variants, the
  `treemap` crate.
- **Rationale (per research report 1):**
  - Squarified is the de-facto standard for disk-usage tools (WizTree, KDirStat
    successors; Storage Sifter, a Rust/wgpu disk treemap, uses it explicitly) and
    gives near-1 aspect ratios, which is what makes sizes comparable by eye.
  - Slice-and-dice produces unclickable slivers — rejected.
  - The known squarified weakness — poor layout stability under progressive data
    (re-sorting makes rectangles jump) — is mitigated per the research: stable
    child ordering during scan ticks, throttled re-layout, cross-fade/animated
    transitions, layout only the visible branch (FR-3.16).
  - What SpaceSniffer itself uses is **unverifiable** (closed source; visually
    squarified-like, no cushions). We match the observable output style: flat
    colored blocks with borders and per-folder header strips.
  - The `treemap` crate (0.3.2) is unmaintained since Feb 2019 with community-
    documented edge-case quirks; the algorithm is 30 lines and we need custom
    hooks (header strips, culling callbacks, stable-order toggle) — writing our
    own is the research-recommended path. The paper's worked example becomes a
    unit test.
- **Rejected:** cushions (not SpaceSniffer's look; possible optional shader
  later); strip/ordered (worse aspect ratios; stability is solved by ordering
  mode instead); SpaceMonger binary-split (fine alternative, no advantage over
  squarified for our hooks).

### 6.3 Rendering approach — egui painter, wgpu callback in reserve

- **Decision:** draw via egui's `Painter` (epaint tessellation); reserve
  `egui::PaintCallback` + custom wgpu instanced-rect pipeline for a future
  full-overview mode.
- **Options considered:** Direct2D via windows-rs, pure wgpu, femtovg/lyon/vello.
- **Rationale (per reports 1 and 2):** with pre-recursion culling and
  drill-down-only layout, per-frame rect counts are in the hundreds-to-thousands —
  comfortably inside epaint's CPU tessellation budget (tens of thousands OK;
  hundreds of thousands not — and we never need that). This avoids owning
  shader/pipeline/device-loss complexity in v1.
- **Rejected for v1:** Direct2D sprite batches (native look, smallest binary, but
  COM ceremony and we forfeit egui's widget stack); pure wgpu (best throughput,
  but we would own text layout); femtovg (per-frame CPU tessellation is its cost
  center; wgpu backend status in flux); vello/lyon (overkill for axis-aligned
  rects).

### 6.4 Scanner & watcher crates

- **Decision:**
  - FFI: `windows-sys` (features: `Win32_Storage_FileSystem`, `Win32_System_IO`,
    `Win32_System_Ioctl`, `Win32_Security`, `Win32_System_Threading`) for the
    three DeviceIoControl calls + handle APIs directly. The research explicitly
    endorses owning this modest FFI surface.
  - Parallel walk: `dua-core`.
  - Watch fallback: `notify` v8.x.
  - Hardlink dedup sets: `rustc-hash`.
- **Options considered:** `usn-journal-rs` 0.4.1 (safe wrappers for exactly our
  FSCTLs, but young — ~15k downloads — and its ReFS claims are unverified; the
  research says *vet before depending*); `walkdir` (single-threaded — too slow as
  the main fallback); `ignore` (gitignore semantics we don't need); `jwalk` (its
  own README now redirects to `dua-core`); `mft`/`ntfs` crates (Stage B option,
  §5.4); `filesize` crate (stale since 2020; the `GetCompressedFileSizeW` FFI is
  one line to own).
- **Rationale:** minimal, auditable dependency surface on the privileged code
  path; the walking path rides a maintained, production-proven engine.

### 6.5 Config format — TOML

- **Decision:** one TOML file (`toml` + `serde` for (de)serialization).
- **Options considered:** XML (SpaceSniffer parity), JSON, RON.
- **Rationale:** SpaceSniffer uses one plain XML file next to the exe; the
  *behavior* we copy is "single human-editable file, no registry", not the
  syntax. TOML is the Rust ecosystem's config idiom (dua-cli uses it), has the
  best human-editing ergonomics of the options, and preserves-unknown-keys is
  easy via a `toml::Value` catch-all (FR-10.2). *(Judgment call: deviates from
  SpaceSniffer's XML; zero functional impact.)*

### 6.6 Snapshot format — custom `.rssnap`

- **Decision:** custom length-checked binary format (§5.7), hand-rolled
  reader/writer.
- **Options considered:** SpaceSniffer `.sns` (rejected: undocumented, CVE
  history); JSON/zstd (self-describing but ~3–5x larger and slower for
  million-node trees; JSON remains available as an *export*); postcard/bincode
  (compact, but schema evolution and auditability are worse than an explicit
  versioned format, and the whole point is a parser we can reason about).
- **Rationale:** the format is attack surface (§9); an explicit, versioned,
  checksummed, allocation-capped format with a fuzz target is the direct answer
  to CVE-2026-26738.

### 6.7 Dependency table

| Crate | Version band* | Role |
|---|---|---|
| `egui`, `eframe` | 0.3x (pin; re-verify current) | GUI framework, wgpu backend |
| `rfd` | latest | Native file dialogs |
| `egui_kittest` | matching egui | Headless UI tests |
| `windows-sys` | 0.6x | Win32 FFI: DeviceIoControl, handles, privileges, shell |
| `dua-core` | 2.4x | Parallel filesystem traversal (WalkScanner) |
| `notify` | 8.x | ReadDirectoryChangesW wrapper (RdcwWatcher) |
| `rayon` | 1.x | Parallelism inside walk/pipeline |
| `crossbeam-channel` | 0.5 | Delta/event channels |
| `rustc-hash` | 3.x | Fast hash sets (hardlink dedup) |
| `serde`, `toml` | 1.x / 0.8x | Config (de)serialization |
| `serde_json` | 1.x | JSON export |
| `csv` | 1.x | CSV export |
| `thiserror` | 2.x | Library error types |
| `anyhow` | 1.x | Application error boundaries |
| `trash` | 5.x | Recycle-bin deletion (FR-6.4) |
| `parking_lot` | 0.12 | Cheap read-locked tree snapshots for the UI |
| `clap` | 4.x | CLI parsing (GUI commands + headless flags) |
| `crc32fast`, `crc64fast` | latest | Snapshot header/payload checksums |
| `arbitrary`, `cargo-fuzz` | dev-only | Fuzz targets (filter parser, `.rssnap` parser) |
| `criterion` | dev-only | Benchmarks (layout, scanner throughput) |
| `tempfile` / `assert_fs` | dev-only | Synthetic filesystem test harness |

\* Version bands intentionally loose here: the research warns its numbers come
from one third-party study and fast-moving lines (egui minors break; wgpu moved
past 0.x versioning). Pin exact versions at implementation time and record them
in `Cargo.lock`.

---

## 7. Correctness & Edge Cases

This section is the contract for the "hard parts." Each rule names the mechanism
and the observable behavior.

### 7.1 Double-counting rules

| Case | Rule |
|---|---|
| **Hardlinks** | Dedupe by `(volume_serial, FRN/file_index)` (§5.2). Size counted once per file identity; subsequent links render as marked 0-byte aliases. `NumberOfLinks` > 1 from `FileStandardInfo` flags candidates on the walk path; the MFT path gets FRNs natively. |
| **Junctions / symlinks / reparse points** | **Never followed during scanning.** Detected via `FILE_ATTRIBUTE_REPARSE_POINT`; tag inspected via `FSCTL_GET_REPARSE_POINT` (`IO_REPARSE_TAG_MOUNT_POINT` vs `IO_REPARSE_TAG_SYMLINK` vs cloud tags). This is also the loop guard: the classic `AppData\Local\Application Data` junction cycle must be impossible by construction. (SpaceSniffer only fixed its reparse-point infinite loop in 2.2.0.27 — we get it right from day one.) The reparse point itself is shown as a 0-size marked node. |
| **Mounted volumes** (junctions that are volume mount points) | Crossing a mount point is a legitimate scan-boundary decision: a settings option "follow mounted volumes" (default **off** — stay on one filesystem, matching the `(volume_serial, …)` dedup domain) governs it |
| **Reparse-point cycles** | Even with follow-links off, any future code path that resolves links must carry a visited-set of `(volume, FRN)` per traversal |

### 7.2 Cloud files / OneDrive placeholders

- Detect via reparse tags `IO_REPARSE_TAG_CLOUD*` and attributes
  `FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS` / `RECALL_ON_OPEN` / `OFFLINE`.
- **Never open file content of placeholders** — metadata-only enumeration is safe;
  opening content can trigger background downloads of terabytes. Any open must
  use `FILE_FLAG_OPEN_NO_RECALL`. (Research note: the exact flag/tag constants
  were cited from memory of `winnt.h` plus secondary sources — verify against the
  SDK headers before coding.)
- Sizes: logical size ≠ disk usage for placeholders; the on-disk occupancy (~0)
  comes from allocated size, which the MFT `$DATA` AllocatedSize handles correctly.
- UI: a distinct "cloud / online-only" visual category, so users do not see
  OneDrive "using" 200 GB that is not local (research-flagged real-world hate).
- SpaceSniffer 2.2.0.27's release notes mention improved offline-file
  performance — evidence this class matters in practice.

### 7.3 Permission-denied folders

- Walk mode without `SeBackupPrivilege`: `System Volume Information`, other users'
  profiles, etc. → access denied. Mark the node `<access denied>`, keep the
  partial subtree, roll the remainder into the view's **unaccessible space**
  accounting (FR-2.8), log with a hint ("rescan as administrator").
- MFT mode is immune (kernel returns every record including SVI) — document this
  in the README as a **privacy-relevant** behavior: elevated scans see everything.

### 7.4 Alternate Data Streams

- Enumerate via `FindFirstStreamW`/`FindNextStreamW` (walk path); free from the
  MFT parse (Stage B). ADS scanning is opt-in per drive (SpaceSniffer parity; it
  slows scans) with auto-detection on NTFS and no-op elsewhere.
- Default accounting: ADS bytes roll into the owning file's size; drill-down
  shows per-stream detail (name + size, e.g. `:Zone.Identifier`).
- How SpaceSniffer renders ADS in the treemap is **not documented** (research
  could not verify); our choice: ADS as child boxes of the host file at drill-in,
  marked distinctly. *(Judgment call.)*
- Filterable via `:attr:ads` (FR-4.7).

### 7.5 Compressed / sparse / resident files

- Primary metric is `AllocationSize` (true size on disk), which already accounts
  for NTFS compression and sparse ranges — free on the MFT path, one call
  (`FileStandardInfo`) on the walk path; `GetCompressedFileSizeW` as fallback.
- `FSCTL_GET_RETRIEVAL_POINTERS` is *not* used (fails for tiny resident files,
  which live inside the MFT record with zero clusters allocated).
- Both logical and allocated sizes are stored (§5.2) and switchable per view —
  like WizTree/TreeSize.

### 7.6 Very long paths

- All filesystem access uses the `\\?\` extended-length prefix, so paths > MAX_PATH
  work end to end (scan, filters, export, delete-to-bin where the shell API
  allows). SpaceSniffer's release notes list long-path fixes — a known trap.

### 7.7 Non-NTFS volumes

- FAT32/exFAT: walker path; no USN journal; allocated size from the filesystem;
  no ADS (option no-ops); cluster-aware disk size.
- **ReFS: has no MFT** — `FSCTL_ENUM_USN_DATA` is NTFS-only. Relevant because
  Windows 11 Dev Drives are ReFS. Walker + RDCW.
- Network/SMB: walker + no change notifications (FR-7.7). Cluster size retrieved
  "where available" (SpaceSniffer documents the same caveat).

### 7.8 Miscellany

- **8.3 short filenames** may appear in RDCW events; normalization before matching
  against tree paths.
- **Zero-byte files**: stored (filterable, exportable), never rendered (FR-3.2).
- **Scan boundary races**: files created/deleted mid-scan between the walker and
  the watcher are reconciled by the watcher deltas; the model tolerates
  delete-of-unknown and create-of-known events idempotently.

---

## 8. Non-Functional Requirements

### 8.1 Performance targets

| Metric | Target | Basis |
|---|---|---|
| MFT scan of a 1M-file NTFS volume, elevated, warm cache | ≤ 10 s to fully populated tree | WizTree-class expectation ("1 TB SSD in seconds"; the 46x claim is vendor marketing — treat as directional); MFT enumeration is one sequential read at hundreds of thousands of entries/s |
| Walk scan throughput, NVMe, parallel | ≥ 50k entries/s | Research range 50–150k entries/s for parallel walkers on NVMe |
| UI frame rate with ≤ 5,000 visible rects | 60 fps during animation; layout+paint < 8 ms | epaint handles tens of thousands; culling keeps us far below |
| Layout recomputation for visible branch | < 1 ms | hundreds of cells, O(n log n) squarified |
| Memory, 1M-node tree | ≤ 500 MB | dua-cli reports ~60 MB per 1M entries for a leaner node struct; we budget generously for richer nodes + GUI |
| Idle CPU | ~0% (reactive repaint) | egui behavior, FR-3.17 |
| Scan throughput penalty with window visible | ≤ 5% | FR-2.10 |
| Cold binary size | ≤ 15 MB | §3 |

These are **targets, not verified measurements** — the research benchmarked
nothing itself; figures derive from vendor/secondary claims and must be validated
by the benchmark suite (§10) before any marketing claim is made.

### 8.2 Accessibility

- AccessKit-based Windows UIA exposure (on by default in egui): screen readers get
  names/roles for chrome; the treemap canvas exposes a navigable list fallback of
  the visible level (sorted by size) so the data is not graphics-only.
- Keyboard-operable everything: all zoom/nav/filter/tag actions have shortcuts
  (§4.3, SpaceSniffer's set is the baseline).
- Respect system text scaling; minimum contrast ratios for both theme palettes
  (FR-11.7);
  color-independent cues (borders/patterns) for tags in addition to hue.

### 8.3 Internationalization

- Unicode-correct everywhere (paths, names, filters) — non-negotiable.
- UI strings externalized (fluent or a simple key-value map) so translations are
  possible; **ships English-only in v1** (SpaceSniffer parity) with i18n as a
  post-v1 community feature. *(Judgment call: research confirms SpaceSniffer is
  English-only; we keep strings externalized but do not commit to translations.)*

### 8.4 DPI awareness

- Per-Monitor-V2 DPI awareness from day one; correct behavior at >100% scaling and
  across mixed-DPI monitors (SpaceSniffer's DPI bugs were decade-long complaints,
  fixed only in 2.0.3.12; its tooltip edge-cropping at >100% zoom was fixed only
  in 2.2.0.27 — both covered by FR-3.8 tests).

---

## 9. Security & Robustness

1. **Snapshot parsing hardening** (the CVE-2026-26738 lesson): the `.rssnap`
   parser is length-checked end to end — every length validated against remaining
   bytes *before* allocation, allocation caps, depth caps, iterative (non-recursive)
   decoding of untrusted depth, whole-payload checksum, versioned magic header
   (§5.7). The parser is a permanent `cargo-fuzz` target and must survive
   24 h of CI fuzzing with zero crashes before each release. Loaded snapshots are
   never given a live filesystem link (FR-8.7), so a hostile snapshot cannot
   trigger file operations.
2. **No network access** except an explicit user-invoked update check (off by
   default; also the donate/about links). No telemetry, no auto-update, no
   background connections. Enforced by code review + a CI check that the
   dependency tree contains no HTTP client crates outside an optional
   `update-check` feature.
3. **Safe-delete defaults**: deletion is recycle-bin only, always confirmed, with
   the filter-hiding warning (FR-6.4). The app is otherwise read-only; the only
   filesystem writes are the config file and explicit exports/snapshots
   (SpaceSniffer parity).
4. **Privilege minimization**: runs unelevated by default; elevation is
   user-initiated per scan (FR-2.5). `SeBackupPrivilege` is requested only when
   needed and its AV-false-positive risk is documented (SpaceSniffer's history).
5. **Shell-integration robustness**: all shell menu invocations on worker threads
   with watchdog timeout (FR-6.2) — the misbehaving-shell-extension freeze is a
   documented SpaceSniffer bug class.
6. **Distribution trust**: signed release binaries + published SHA-256 checksums +
   reproducible-build instructions + winget/scoop manifests — the direct answer
   to SpaceSniffer's mirror-malware ecosystem. Implemented by the tag-triggered
   release pipeline (§11.2).
7. **No unsafe outside the FFI crates** (§5.9); `#![forbid(unsafe_code)]` in
   `rss-core`, `rss-filter`, `rss-treemap`, `rss-export`.
8. **Template engine containment**: export templates can emit batch files
   (FR-8.9, SpaceSniffer parity) but ship no such presets, and the export dialog
   shows the resolved output path prominently.

---

## 10. Testing Strategy

### 10.1 Unit tests

- **Treemap layout math** (`rss-treemap`): the squarified paper's worked example
  as a golden test; property tests — total area conservation, no overlaps, aspect
  ratios bounded, strict proportionality (FR-3.1), culling never drops area from
  aggregates; stable-ordering mode: identical relative order across ticks when
  inputs change monotonically.
- **Filter parser** (`rss-filter`): every documented construct from §4.4 with
  positive/negative cases (canonical examples from the SpaceSniffer manual:
  `*.jpg;>1mb;<3months;|:yellow`, `*.jpg;*.gif;>100kb;<6months`, `:tag:red+green-b`,
  `:attr:+a-ro,h`, `\*internet*`); fuzzy-alias acceptance; combination-semantics
  truth tables (FR-4.10); malformed-input warnings with spans.
- **Snapshot round-trip** (`rss-export`): model → bytes → model identity,
  including tags/filters; corrupted/truncated/adversarial inputs must fail closed
  with typed errors (never panic).
- **Size bookkeeping**: aggregate maintenance under streamed upserts/deletes;
  hardlink dedup; ADS roll-up; unaccessible-space accounting.

### 10.2 Golden-tree fixture tests

Checked-in synthetic trees (JSON fixtures) → built model → exported text/CSV/JSON
must byte-match golden outputs. Fixtures cover: hardlinks, junctions, ADS,
cloud placeholders, access-denied nodes, zero-byte files, deep nesting, long
paths, unicode names.

### 10.3 Synthetic filesystem harness (integration, Windows CI)

- `tempfile`-based generated trees with controlled sizes/timestamps; junctions
  and symlinks created via `mklink`-equivalent APIs; files with ADS
  (`file.txt:stream`); compressed and sparse files (`FSCTL_SET_COMPRESSION`,
  `FSCTL_SET_SPARSE`); > MAX_PATH paths; ACL-denied subdirectories.
- Assert scanned model matches ground truth (sizes within cluster rounding).
- Live-update tests: perform mutations during/after scan, assert the model
  converges, assert `ERROR_NOTIFY_ENUM_DIR` injection triggers subtree rescan.
- A looped-junction tree asserts the scan terminates (reparse-point regression
  test — the SpaceSniffer 2.2.0.27 bug class).

### 10.4 UI tests

- `egui_kittest` headless harness: start-dialog flows, filter application,
  zoom/back navigation, tag toggles, delete confirmation dialog content
  (including the filter-hiding warning).

### 10.5 Fuzzing

- `cargo-fuzz` targets: `filter_parse`, `rssnap_parse`, `template_render`.
  `rssnap_parse` gate for release per §9.1.

### 10.6 Benchmarks (`criterion` + scripted harness)

- Squarified layout throughput at 10²/10³/10⁴ cells; per-frame paint cost at
  increasing visible-rect counts.
- Scanner throughput: synthetic 100k/1M-file trees on NTFS (walk path and, on an
  elevated CI runner, the MFT path) — validates §8.1 targets before release
  claims.
- Memory high-water mark for a 1M-node tree.

---

## 11. CI/CD & Release Automation

All automation runs on **GitHub Actions** (the project lives on GitHub). Two
pipelines: a continuous-integration pipeline on every push/PR, and a
tag-triggered release pipeline that builds and publishes the release
automatically.

### 11.1 Continuous integration (`.github/workflows/ci.yml`)

Trigger: push to `main`, every pull request.

| Job | Content |
|---|---|
| `fmt` | `cargo fmt --all -- --check` |
| `clippy` | `cargo clippy --workspace --all-targets -- -D warnings` |
| `test` | `cargo test --workspace` on `windows-latest` (x86_64-pc-windows-msvc); the pure-logic crates (`rss-core`, `rss-filter`, `rss-treemap`, `rss-export`) also tested on `ubuntu-latest` to keep them platform-clean |
| `integration` | Synthetic-filesystem harness (§10.3) and `egui_kittest` UI tests (§10.4) on `windows-latest`. Privilege-gated tests (MFT path, USN journal, ACL-denied dirs) are marked and run only when the runner has admin rights; the suite must skip — not fail — otherwise |
| `fuzz-smoke` | Each `cargo-fuzz` target (§10.5) runs a short bounded session (~5 min) to catch trivial regressions |
| `deny` | `cargo-deny` license/advisory/ban checks; plus the §9.2 rule enforced as a script: the dependency tree must contain no HTTP client crates outside the optional `update-check` feature |
| `msrv` | Build with the MSRV declared in `rust-toolchain.toml` |

Rules: `rust-toolchain.toml` pins the toolchain; `Swatinem/rust-cache` caches
cargo artifacts; Dependabot (or Renovate) keeps GitHub Actions and crates
current, with a weekly `cargo audit` advisory check.

### 11.2 Tag-triggered release (`.github/workflows/release.yml`)

Trigger: push of a tag matching `v*.*.*` (e.g. `v1.0.0`). Pushing the tag is the
entire release action — no manual build steps.

1. **Guard.** The workflow verifies the tag equals the workspace version in
   `Cargo.toml` (`v1.2.3` ↔ `version = "1.2.3"`); mismatch aborts the release.
   Tags with a pre-release suffix (`-rc.N`, `-beta.N`) produce a GitHub
   *pre-release*.
2. **Full gate.** The complete CI suite re-runs on the tagged commit, including
   the benchmark suite (§10.6) whose results are archived as a workflow
   artifact. A release is never cut from an untested tree.
3. **Build.** `cargo build --release` on `windows-latest` with the release
   profile from §3 (`lto`, `opt-level="z"`, `strip`), producing the single
   portable `RustySpaceSniffer.exe`. The workflow asserts the binary size
   against the §3 budget (warn, not fail, if exceeded).
4. **Package.** Zip the exe (`RustySpaceSniffer-vX.Y.Z-windows-x64.zip`);
   generate `SHA256SUMS.txt` covering the zip and the bare exe.
5. **Sign.** Authenticode-sign the exe via `signtool` with a certificate held in
   GitHub Secrets (or a cloud HSM/OIDC signing service); plus keyless
   Sigstore/`cosign sign-blob` signatures so users without the cert chain can
   still verify provenance. Unsigned fallback: if no cert is configured yet, the
   release still ships with checksums + Sigstore only, and the gap is stated in
   the release notes — this directly serves the §9.6 distribution-trust goal.
6. **Publish.** Create the GitHub Release via `gh release create` (or
   `softprops/action-gh-release`): zip, bare exe, `SHA256SUMS.txt`, signatures,
   and generated release notes (conventional-commit based). Minimal workflow
   permissions (`contents: write` only on the release job; `GITHUB_TOKEN`
   otherwise read-only).
7. **Distribute (post-v1).** Submit/update winget and scoop manifests from the
   published checksums (§9.6). Manual or semi-automated at first; never blocks
   the GitHub Release.

### 11.3 Fuzz release gate (`.github/workflows/fuzz.yml`)

The §9.1 requirement — 24 h of `rssnap_parse` fuzzing with zero crashes before
release — runs as a scheduled nightly workflow plus a pre-release gate: a
release-candidate tag (`-rc.N`) triggers the long fuzz run; the final tag may
only be pushed after the gate is green (enforced socially/branch-protection,
since Actions cannot block a tag push itself).

### 11.4 Environment constraints

- **Elevation:** `windows-latest` hosted runners run with admin rights, so
  MFT/USN tests can execute there; they must still detect capability and skip
  cleanly for forks/self-hosted runners without elevation.
- **Benchmarks on CI** are informational only (noisy shared runners); §8.1
  release claims require a controlled-machine run per §10.6.
- **Self-hosted runner** (a real Windows machine with NTFS data volumes) is a
  post-v1 option for realistic 1M-file scan benchmarks and elevated coverage.

---

## 12. Milestones / Roadmap

Each milestone ends with verifiable exit criteria; order is dependency-driven.

| Milestone | Scope | Exit criteria (all must pass) |
|---|---|---|
| **M1 — Skeleton scanner + CLI** | Workspace; `rss-core` model; `WalkScanner` (dua-core); headless CLI with CSV/JSON export; synthetic-tree test harness | `rss --headless scan <dir> --export csv out.csv` produces correct aggregates vs ground truth on the synthetic harness; unit tests green |
| **M2 — Treemap core** | `rss-treemap` squarified + stable-order mode; minimal egui app rendering a scanned tree; zoom/nav; hover tooltips | Paper worked-example test green; area-conservation property tests green; manual smoke: scan a real drive, drill down, navigate back |
| **M3 — Filters & tags** | `rss-filter` full DSL; filter field UI with inline warnings; dim-out treatment; tagging + tag filters; flat/file-class coloring | Filter unit tests incl. combination truth tables green; kittest: type filter, see dimming; tags persist in model |
| **M4 — Live scanning UX** | Progressive population with throttled ticks; cancel/pause/resume; flash-on-change; viewable-percent bar; free/unknown space elements; multi-view windows; drag & drop | Scan of a large drive is navigable mid-scan with 60 fps; cancel leaves a browsable partial tree; FR-2.10 benchmark within 5% |
| **M5 — MFT fast path + elevation** | `MftScanner` Stage A; volume/elevation detection + fallback chain; "rescan as administrator" | On elevated NTFS: 1M-file volume ≤ 10 s; unelevated run degrades gracefully with the elevate affordance |
| **M6 — Live updates** | `RdcwWatcher` + overflow handling; `UsnJournalWatcher` with persisted cursor; idempotent delta application | Integration tests: mutations reflected during/after scan; overflow injection triggers subtree rescan; journal wrap triggers full rescan |
| **M7 — Export & snapshots** | Template engine (SpaceSniffer-compatible subset per FR-8.2); built-in configs incl. "Grouped by folder"; `.rssnap` save/load with hardened parser; fuzz target wired | Golden export fixtures byte-match; round-trip tests green; fuzz smoke run clean; `SpaceSniffer.exe`-style CLI automation examples work: `rss scan c:\ filter *.jpg export "Grouped by folder" out.txt autoclose` |
| **M8 — File ops & shell** | Explorer context menu (watchdogged); open-containing-folder; recycle-bin delete with confirmation + filter warning; Explorer context-menu registration toggle | kittest for dialog content; manual: shell menu works with a known-bad-extension simulation not freezing UI; delete lands in Recycle Bin |
| **M9 — Polish & hardening** | Settings UI + TOML persistence; dark/light; DPI tests at 125/150/200%; log console; accessibility pass (UIA tree); performance benchmark suite run; security review of `unsafe`; release packaging per §11 (CI pipeline, tag-triggered release, signing, checksums) | §8.1 targets measured and recorded; 24 h fuzz clean; a11y checklist complete; v1.0.0 tagged |

Post-v1 (tracked, not scheduled): MFT Stage B raw parse, duplicate detection,
snapshot comparison, treemap PNG export, translations, cross-platform exploration
(§N2 stretch).

---

## 13. Competitive Baseline & Differentiators

### 13.1 Baseline (from research report 4)

| Tool | License | Scan method | Speed | Visualization |
|---|---|---|---|---|
| **SpaceSniffer** | freeware (closed) | live traversal | medium | dynamic zoomable treemap — best-in-class interaction |
| **WizTree** | freemium | **MFT** (admin), walk fallback | extreme | list + secondary treemap |
| **WinDirStat** | GPL (open) | traversal (+MFT option in 2.x) | slow → improved | static cushion treemap |
| **TreeSize Free/Pro** | freemium | traversal | medium | list + bars + treemap; Pro = automation |

SpaceSniffer's moat is the treemap-as-primary-interface with live drill-down; its
weakness is scan speed vs MFT readers. WinDirStat 2.x (late 2024) closed the
feature gap substantially: multithreaded scanning, MFT option, dark mode,
duplicate detection, hardlink tracking, ARM64, fs watching, scan export — and it
has winget/choco/scoop/Store distribution hygiene that SpaceSniffer lacks.

Rust prior art: `dua-cli` (mature TUI, ~60 MB RAM per 1M entries, proven
multi-stage deletion UX), `diskonaut` (TUI treemap, unmaintained-ish),
`dirstat-rs` (self-reported benchmarks, unmaintained), `spaceman` (GTK4 GPU
treemap with live-scan display — validates the design), `squirreldisk` (Tauri
sunburst; author regrets the architecture). **Confirmed gap: no mature,
maintained, Windows-first GUI treemap analyzer exists in Rust.** The niche is
open.

### 13.2 Differentiators we adopt

1. **Open source (MIT/Apache-2.0)** — the single biggest wedge: users explicitly
   wish SpaceSniffer were open; WizTree is closed; WinDirStat is copyleft. Also
   unlocks winget/scoop/Store distribution.
2. **MFT-direct scanning with automatic elevation fallback** (§5.4) —
   SpaceSniffer's biggest weakness, fixed.
3. **Safe in-app deletion** (FR-6.4) — fixes the read-only limitation and the
   fragile shell-menu dependency.
4. **True headless CLI** (FR-9.2) — TreeSize charges for this; SpaceSniffer's is
   half-GUI.
5. **Rendering that never slows the scan** (FR-2.10) — no "minimize the window
   to scan faster" embarrassment.
6. **Hardened snapshot format + signed reproducible releases** (§9) — direct
   answer to CVE-2026-26738 and the mirror-malware ecosystem.
7. **Dark mode + high-DPI from day one** (§4.11, §8.4).

Deferred differentiators (post-v1, §N4): duplicate detection, snapshot/growth
comparison, treemap PNG export, ARM64 build.

---

## 14. Open Questions

Items the research could not verify, or that need a decision from the maintainer:

1. **SpaceSniffer meta-commands** (added in 2.0.3.12): documented only inside the
   app's built-in help; not found anywhere online. Compatibility is impossible to
   specify; FR-9.6 marks them Won't. If a maintainer with a Windows box runs
   `SpaceSniffer.exe help`, we can revisit.
2. **SpaceSniffer's internal layout algorithm**: unverifiable (closed source). We
   chose squarified for output-quality parity (§6.2); exact visual twinship is not
   a goal.
3. **SpaceSniffer's filter gray-out exact visuals**: inferred from a 2.0.1.4
   release-note wording only. We chose dim-to-30% + desaturate (FR-4.11); a side-
   by-side behavioral check on Windows could refine this.
4. **ADS rendering in SpaceSniffer**: undocumented. Our child-boxes choice is a
   judgment call (§7.4).
5. **Crate versions**: GUI/binary-size figures come from a single third-party
   ecosystem study (GoldStrikeArch) plus crates.io pages; egui's 0.36.x API
   stability vs 0.35 was not verified in depth; wgpu's post-0.x versioning moved
   fast. Pin and read release notes at implementation time (§6.7).
6. **`usn-journal-rs` maturity**: young crate (~15k downloads) with unverified
   ReFS claims. Currently avoided (we own the FFI); re-evaluate if the FFI
   surface grows.
7. **Performance figures**: WizTree's "46x faster" is marketing; `dirstat-rs`
   benchmarks are self-reported; no research benchmark ran on real hardware.
   §8.1 targets must be validated by §10.6 before appearing in any README claim.
8. **Maintenance status of `diskonaut`/`spaceman`/`piet`/`femtovg` wgpu backend**:
   flagged by the research as needing re-check; none are dependencies, so this is
   informational only.
9. **Icon/branding**: "RustySpaceSniffer" name and any logo need a trademark
   sanity check; SpaceSniffer's name/assets are not reusable. Visual identity is
   out of scope for this spec.
10. **Elevated-scan privacy disclosure wording**: MFT scans bypass ACLs by design
    (§7.3); the exact README/privacy wording needs a maintainer decision.

---

## 15. References

**SpaceSniffer (primary sources):**

- Official site — https://www.uderzo.it/main_products/space_sniffer/
- Features page — https://www.uderzo.it/main_products/space_sniffer/features.html
- Release notes (latest 2.2.0.27) — https://www.uderzo.it/main_products/space_sniffer/release_notes.html
- Tips & tricks — https://www.uderzo.it/main_products/space_sniffer/tips_and_tricks.html
- User Manual v2.0.3.12 (PDF) — https://static.nebula-soft.com/CSEC-TOOL/Windows/SpaceSniffer/2.0.3.12/SpaceSniffer%20User%20Manual.pdf
- Wikipedia: SpaceSniffer — https://en.wikipedia.org/wiki/SpaceSniffer
- CVE-2026-26738 (`.sns` stack buffer overflow) — https://www.sentinelone.com/vulnerability-database/cve-2026-26738/
- `.sns` format reverse engineering (third-party, unofficial) — https://zhkgo.github.io/2024/04/30/snsData/
- Rarst.net review — https://www.rarst.net/software/spacesniffer/

**Treemap algorithms & rendering:**

- Bruls, Huizing, van Wijk, "Squarified Treemaps" — https://www.win.tue.nl/~vanwijk/stm.pdf
- Shneiderman & Wattenberg, "Ordered Treemap Layouts" — https://www.cs.umd.edu/users/ben/papers/Shneiderman2001Ordered.pdf
- Bederson, Shneiderman, Wattenberg, "Ordered and Quantum Treemaps" — https://www.cs.umd.edu/~ben//papers/Bederson2002Ordered.pdf
- Sondag, Speckmann, Verbeek, "Stable Treemaps via Local Moves" (+ reference code) — https://github.com/tue-alga/TreemapComparison
- Vernier et al., "Quantitative Comparison of Time-Dependent Treemaps" (EuroVis 2020) — https://webspace.science.uu.nl/~telea001/uploads/PAPERS/EuroVis20/paper2.pdf
- van Wijk & van de Wetering, "Cushion Treemaps" — https://ics.uci.edu/~kobsa/courses/ICS280/InfoViz99/00801860.pdf
- Werkema, "SpaceMonger treemapping redux" (binary-split algorithm + ReadDirectoryChangesW design) — https://www.werkema.com/2019/03/05/spacemonger-treemapping-redux/
- Fopull, "Why we wrote a GPU disk treemap in Rust" (architecture reference) — https://fopull.com/guides/gpu-disk-treemap-rust-wgpu

**Rust GUI:**

- rust-gui-desktop-ecosystem-state study — https://github.com/GoldStrikeArch/rust-gui-desktop-ecosystem-state/blob/main/report/data/stack-rows.md
- eframe CHANGELOG — https://github.com/emilk/egui/blob/main/crates/eframe/CHANGELOG.md
- Slint wgpu-backend issue — https://github.com/slint-ui/slint/issues/10587
- Tauri Windows installer docs — https://v2.tauri.app/distribute/windows-installer/
- fltk-rs FAQ — https://fltk-rs.github.io/fltk-rs/FAQ.html
- native-windows-gui repo — https://github.com/gabdube/native-windows-gui
- gpui extraction discussion — https://github.com/zed-industries/zed/discussions/30515

**Windows scanning & live updates:**

- USN_RECORD_V2 (MS docs) — https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ns-winioctl-usn_record_v2
- FSCTL_ENUM_USN_DATA (MS docs; NTFS-only) — https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl_fsctl_enum_usn_data
- USN_RECORD_V3/V4 discussion — https://stackoverflow.com/questions/45696192/enumerating-the-ntfs-mft-fsctl-enum-usn-data-and-usn-record-v3-support
- usn-journal-rs — https://github.com/wangfu91/usn-journal-rs
- GetCompressedFileSizeW — https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getcompressedfilesizew
- File Streams (ADS) — https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams
- Old New Thing on ReadDirectoryChangesW deleted-item info — https://devblogs.microsoft.com/oldnewthing/20260306-00/?p=112116
- Cloud-file attribute constants listing (impacket) — https://sources.debian.org/src/impacket/0.13.0-2/examples/attrib.py/
- WizTree, "How is WizTree faster than other disk analyzers" — https://wiztree.co.uk/2024/10/02/how-is-wiztree-faster-than-other-disk-analyzers/
- windows-canvas helper (experimental) — https://github.com/microsoft/windows-rs/blob/master/docs/crates/windows-canvas.md

**CI/CD & release automation:**

- GitHub Actions workflow syntax — https://docs.github.com/en/actions/writing-workflows/workflow-syntax-for-github-actions
- softprops/action-gh-release — https://github.com/softprops/action-gh-release
- Sigstore `cosign sign-blob` (keyless signing) — https://docs.sigstore.dev/cosign/signing/signing_with_blobs/
- cargo-deny — https://github.com/EmbarkStudios/cargo-deny
- Swatinem/rust-cache — https://github.com/Swatinem/rust-cache
- winget-pkgs manifest submission — https://github.com/microsoft/winget-pkgs

**Competitive landscape:**

- WinDirStat site + CHANGELOG — https://windirstat.net/ , https://github.com/windirstat/windirstat/blob/master/CHANGELOG.md
- WizTree guides — https://diskanalyzer.com/guide
- TreeSize editions — https://www.jam-software.com/treesize/editions.shtml
- TreeSize scheduler/manual — https://manuals.jam-software.de/treesize/EN/scheduler_export_tab.html
- dua-cli — https://github.com/Byron/dua-cli
- diskonaut — https://github.com/imsnif/diskonaut
- dirstat-rs — https://github.com/scullionw/dirstat-rs
- spaceman — https://github.com/salihgerdan/spaceman
- squirreldisk — https://github.com/adileo/squirreldisk
- pinkbin (crate shopping list: jwalk, ntfs, globset, trash-rs, d3-hierarchy) — https://github.com/cccyd2003-qwq/pinkbin
- 4-way comparison (Chinese) — https://www.cnblogs.com/pcdoctor/p/22182960
- Slant: WinDirStat vs SpaceSniffer — https://www.slant.co/versus/7500/16726/~windirstat_vs_spacesniffer
- Hardlink double-counting user report (Synology) — https://community.synology.com/enu/forum/1/post/129217
- Shell-extension freeze report (CSDN) — https://blog.csdn.net/binweisili/article/details/148401312
- "SpaceSniffer abandoned" (Microsoft Store WinDirStat listing); open-source wishes — https://popeen.com/2025/01/17/reclaim-lost-space-on-your-drive-with-spacesniffer/ , https://github.com/Ayx03/SpaceSniffer
- 4DDiG comparison — https://4ddig.tenorshare.com/remove-duplicates/best-disk-space-analyzer.html

---

*End of specification.*
