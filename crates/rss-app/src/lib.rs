//! RustySpaceSniffer application crate (SPEC.md §5.1).
//!
//! Owns CLI parsing/dispatch ([`cli`]) and the eframe/egui GUI ([`gui`]);
//! produces the `rss` binary via the thin `src/main.rs`.
//!
//! - `rss` with no arguments opens the GUI start dialog (§4.1).
//! - `rss scan <path> --export csv|json --out <file>` runs headless and
//!   exports (FR-9.2); exit codes: 0 ok, 1 scan/export error, 2 usage error.

pub mod cli;
pub mod cli_meta;
pub mod fmt;
pub mod gui;
