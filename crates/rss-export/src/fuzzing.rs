//! Fuzz-target entry points shared between `cargo fuzz` and plain unit tests.
//!
//! The functions here are the whole body of the `cargo-fuzz` targets in
//! `fuzz/fuzz_targets/` (SPEC.md §9.1: the `.rssnap` parser is a permanent
//! fuzz target). Keeping them in the library lets the unit tests feed them
//! garbage without a nightly toolchain. They must never panic, whatever the
//! input.
#![forbid(unsafe_code)]

use rss_core::{NodeKind, NodeParams, Tree};

use crate::snapshot::Snapshot;
use crate::template::{BlockSort, ExportTemplate, SortField, TemplateContext};

/// Fuzz entry for the `.rssnap` parser: decode arbitrary bytes.
pub fn rssnap_parse(data: &[u8]) {
    let _ = Snapshot::decode(data);
}

/// Fuzz entry for the template engine: interpret arbitrary bytes as template
/// sections plus option bits and render a small fixed tree. Both well-formed
/// and malformed templates must only ever produce `Ok`/`Err`, never a panic.
pub fn template_render(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    // Split the input into three section texts at the first two newlines and
    // derive the sorting options from the byte value sum.
    let mut parts = text.splitn(3, '\n');
    let header = parts.next().unwrap_or("").to_string();
    let detail = parts.next().unwrap_or("").to_string();
    let footer = parts.next().unwrap_or("").to_string();
    let sum: u32 = data.iter().map(|&b| u32::from(b)).sum();
    let template = ExportTemplate {
        name: "fuzz".to_string(),
        header,
        detail,
        footer,
        block_sort: match sum % 3 {
            0 => BlockSort::FoldersFirst,
            1 => BlockSort::FilesFirst,
            _ => BlockSort::None,
        },
        sort: match (sum / 3) % 5 {
            0 => SortField::Name,
            1 => SortField::Extension,
            2 => SortField::Size,
            3 => SortField::DiskSize,
            _ => SortField::ModifyDate,
        },
        descending: sum.is_multiple_of(2),
    };

    let mut tree = Tree::with_root(NodeParams::named("root", NodeKind::Directory));
    let root = tree.root().expect("with_root sets a root");
    let dir = tree.add_child(
        root,
        NodeParams::named("sub dir", NodeKind::Directory).sizes(0, 4096),
    );
    tree.add_child(
        dir,
        NodeParams::named("data-ユニコード.bin", NodeKind::File).sizes(2048, 4096),
    );
    tree.add_child(
        root,
        NodeParams::named("big.exe", NodeKind::File).sizes(1_000_000, 1_048_576),
    );

    let context = TemplateContext {
        filter: None,
        now: rss_core::filetime_from_unix(1_700_000_000),
    };
    let _ = crate::template::render_template(&tree, root, &template, &context, Vec::new());
}
