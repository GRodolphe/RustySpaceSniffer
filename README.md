# RustySpaceSniffer

An open-source re-creation of [SpaceSniffer](https://en.wikipedia.org/wiki/SpaceSniffer)
for Windows, written in Rust: a disk-space analyzer whose primary interface is
an interactive, zoomable **treemap** that populates live while the disk is
being scanned.

Clean-room re-creation from SpaceSniffer's public documentation and observable
behavior — no original code or assets. The full design is specified in
[SPEC.md](SPEC.md).

## Status

All v1 milestones (M1–M9, [SPEC.md §12](SPEC.md)) are implemented:

| Milestone | Scope | Status |
|---|---|---|
| M1 | Workspace, core model, walk scanner, filter DSL, CSV/JSON export, headless CLI | Done |
| M2 | Treemap core + egui GUI shell (zoom/nav/tooltips/breadcrumbs) | Done |
| M3 | Filters & tags UI (SpaceSniffer filter DSL, dim/hide, CTRL+1..4 tags, color styles) | Done |
| M4 | Live scanning UX (progressive population, pause/resume/cancel, flash, multi-view, zoom animation, live watcher updates) | Done |
| M5 | MFT fast path + elevation detection (cfg(windows); compile-checked, runtime validation pending on Windows CI) | Done |
| M6 | Live updates (ReadDirectoryChangesW via notify; USN journal watcher, cfg(windows)) | Done |
| M7 | Export templates ("Grouped by folder"), hardened `.rssnap` snapshots, CLI meta-commands | Done |
| M8 | File ops (shell context menu, recycle-bin delete with filter-warning dialog) | Done |
| M9 | Settings + TOML persistence, dark/light themes with per-theme palettes, log console, accessibility pass | Done |

Feature highlights: single portable `.exe` (release pipeline ready), SpaceSniffer-compatible filter
syntax (`*.jpg;>1mb;<3months;|:yellow`), dark mode, MFT-direct scanning on
NTFS (elevated), safe in-app deletion, and a true headless CLI.

## Building

Requires a stable Rust toolchain. Target platform is Windows 10/11 x64; the
pure-logic crates (`rss-core`, `rss-treemap`, `rss-filter`, `rss-export`) and
the walk scanner also build and run on Linux/macOS.

```sh
cargo build --workspace
cargo test --workspace
```

## Usage

Launch with no arguments for the GUI:

```sh
rss
```

Headless scanning and export:

```sh
# Scan a path and export CSV / JSON
rss scan C:\Users\you --export csv --out report.csv
rss --headless scan /some/dir --export json report.json

# SpaceSniffer-style meta-command form (filter + named export template)
rss scan C:\Users\you filter "*.jpg;>1mb" export "Grouped by folder" report.txt autoclose
```

## CI/CD

- **CI** (`.github/workflows/ci.yml`): fmt, clippy, and tests on every push/PR,
  on `windows-latest` (also the first compile check of the `cfg(windows)` FFI
  code) plus `ubuntu-latest` for the platform-clean crates.
- **Release** (`.github/workflows/release.yml`): pushing a `v*.*.*` tag builds
  the release binary on Windows, packages the portable zip with SHA-256
  checksums, and publishes a GitHub Release. The tag must match the workspace
  version in `Cargo.toml`. Details in [SPEC.md §11](SPEC.md).

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option.
