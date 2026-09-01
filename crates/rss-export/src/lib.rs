//! Export of a scanned tree: flat CSV (FR-8.4), nested JSON (FR-8.5), text
//! reports via a SpaceSniffer-compatible template engine (FR-8.2/FR-8.3), and
//! the `.rssnap` binary snapshot format (FR-8.7/FR-8.8), per SPEC.md §4.8 and
//! §5.7.
//!
//! The CSV/JSON exporters walk the subtree rooted at a given node
//! depth-first, with siblings ordered by descending size (allocated by
//! default, see [`SizeMode`]). Reported sizes and counts are the node's
//! aggregates (`agg_*` in `rss-core`), so directories report their whole
//! subtree and the allocated size includes NTFS Alternate Data Stream bytes.
//!
//! The template engine ([`render_template`], [`ExportTemplate`]) implements a
//! safe, side-effect-free subset of SpaceSniffer's export mini-language; the
//! snapshot module ([`Snapshot`]) provides save/load of a full tree including
//! tags (FR-5.3), the view's filter string, zoom path, and scan metadata,
//! with a hardened, allocation-capped, checksummed parser (SPEC.md §9.1).
#![forbid(unsafe_code)]

mod csv_export;
mod error;
pub mod fuzzing;
mod json_export;
mod snapshot;
mod template;
mod time;
mod traverse;

use std::io::Write;

use rss_core::{NodeId, Tree};

pub use error::ExportError;
pub use snapshot::{ScanMetadata, Snapshot, SnapshotError};
pub use template::{
    age_string, builtin_templates, find_builtin_template, human_size, render_template, BlockSort,
    ExportTemplate, SortField, TemplateContext, TemplateError,
};

/// Which size the export sorts siblings by and treats as primary.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SizeMode {
    /// Allocated (on-disk) size, including ADS bytes. This is the default,
    /// matching SpaceSniffer's primary view.
    #[default]
    Allocated,
    /// Logical (apparent) file size.
    Logical,
}

/// Options shared by all exporters.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct ExportOptions {
    /// Size used to order siblings (default: [`SizeMode::Allocated`]).
    pub size_mode: SizeMode,
}

/// Export the subtree rooted at `root` as CSV (one row per node, header row,
/// depth-first, siblings by descending size) using default options.
///
/// The output is UTF-8 and starts with a BOM so Excel opens it correctly
/// (FR-8.4); records are CRLF-terminated per RFC 4180. Fields containing
/// commas, quotes, or newlines are quoted per RFC 4180. Timestamps are
/// RFC 3339 UTC.
///
/// Columns: `path`, `name`, `kind`, `logical_size`, `allocated_size`,
/// `files`, `dirs`, `modified`.
pub fn export_csv(tree: &Tree, root: NodeId, writer: impl Write) -> Result<(), ExportError> {
    export_csv_with(tree, root, ExportOptions::default(), writer)
}

/// Like [`export_csv`], with explicit [`ExportOptions`].
pub fn export_csv_with(
    tree: &Tree,
    root: NodeId,
    options: ExportOptions,
    writer: impl Write,
) -> Result<(), ExportError> {
    validate_root(tree, root)?;
    csv_export::export(tree, root, options, writer)
}

/// Export the subtree rooted at `root` as a nested, pretty-printed JSON
/// document using default options.
///
/// Each node object carries the same fields as the CSV columns
/// (`name`, `path`, `kind`, `logical_size`, `allocated_size`, `files`,
/// `dirs`, `modified`) plus a `children` array (empty for leaf nodes).
/// Sizes are in bytes; `modified` is RFC 3339 UTC. Output is UTF-8.
pub fn export_json(tree: &Tree, root: NodeId, writer: impl Write) -> Result<(), ExportError> {
    export_json_with(tree, root, ExportOptions::default(), writer)
}

/// Like [`export_json`], with explicit [`ExportOptions`].
pub fn export_json_with(
    tree: &Tree,
    root: NodeId,
    options: ExportOptions,
    writer: impl Write,
) -> Result<(), ExportError> {
    validate_root(tree, root)?;
    json_export::export(tree, root, options, writer)
}

/// Conservative validity check: `NodeId`s handed out by a live tree are
/// always below its live-node count, so anything at or above it cannot refer
/// to a live node. (A stale id below the count cannot be detected through
/// `Tree`'s public API.)
fn validate_root(tree: &Tree, root: NodeId) -> Result<(), ExportError> {
    if root as usize >= tree.len() {
        return Err(ExportError::InvalidRoot(root));
    }
    Ok(())
}
