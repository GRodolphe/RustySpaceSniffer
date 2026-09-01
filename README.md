# RustySpaceSniffer

An open-source re-creation of [SpaceSniffer](https://en.wikipedia.org/wiki/SpaceSniffer)
for Windows, written in Rust: a disk-space analyzer whose primary interface is
an interactive, zoomable **treemap** that populates live while the disk is
being scanned.

Clean-room re-creation from SpaceSniffer's public documentation and observable
behavior — no original code or assets. The full design is specified in
[SPEC.md](SPEC.md).

## Status

Early development. Milestone **M1** is complete (see
[SPEC.md §12](SPEC.md) for the roadmap):

| Milestone | Scope | Status |
|---|---|---|
| M1 | Workspace, core model, walk scanner, filter DSL, CSV/JSON export, headless CLI | Done |
| M2 | Treemap core + egui GUI shell | Next |
| M3 | Filters & tags in the UI | Planned |
| M4 | Live scanning UX (progressive, cancel/pause, multi-view) | Planned |
| M5 | MFT fast path (WizTree-class NTFS scanning) + elevation | Planned |
| M6 | Live updates (USN journal / ReadDirectoryChangesExW) | Planned |
| M7 | Export templates + hardened `.rssnap` snapshots | Planned |
| M8 | File operations (shell menu, recycle-bin delete) | Planned |
| M9 | Polish: dark mode, DPI, accessibility, release packaging | Planned |

Planned highlights: single portable `.exe`, SpaceSniffer-compatible filter
syntax (`*.jpg;>1mb;<3months;|:yellow`), dark mode, MFT-direct scanning on
NTFS, safe in-app deletion, and a true headless CLI.

## Building

Requires a stable Rust toolchain. Target platform is Windows 10/11 x64; the
pure-logic crates (`rss-core`, `rss-treemap`, `rss-filter`, `rss-export`) and
the walk scanner also build and run on Linux/macOS.

```sh
cargo build --workspace
cargo test --workspace
```

## CLI usage (M1)

```sh
# Scan a path and export CSV / JSON
rss scan C:\Users\you --export csv --out report.csv
rss --headless scan /some/dir --export json report.json
```

The GUI arrives with milestone M2.

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
