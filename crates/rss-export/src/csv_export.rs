//! Flat CSV export (FR-8.4).

use std::io::Write;
use std::path::Path;

use csv::{Terminator, WriterBuilder};
use rss_core::{NodeId, Tree};

use crate::time::format_rfc3339;
use crate::traverse::{kind_str, sorted_children};
use crate::{ExportError, ExportOptions};

/// UTF-8 BOM, written first so Excel detects the encoding (FR-8.4).
const BOM: &[u8] = b"\xEF\xBB\xBF";

const HEADER: [&str; 8] = [
    "path",
    "name",
    "kind",
    "logical_size",
    "allocated_size",
    "files",
    "dirs",
    "modified",
];

pub(crate) fn export(
    tree: &Tree,
    root: NodeId,
    options: ExportOptions,
    mut writer: impl Write,
) -> Result<(), ExportError> {
    writer.write_all(BOM)?;
    let mut wtr = WriterBuilder::new()
        .terminator(Terminator::CRLF)
        .from_writer(writer);
    wtr.write_record(HEADER)?;

    // Iterative pre-order DFS. Paths are carried along the stack (one join
    // per node) instead of recomputed from the parents, which would make
    // deep trees quadratic. Children are pushed in reverse so they pop in
    // sorted order.
    let root_path = tree.path(root).to_string_lossy().into_owned();
    let mut stack = vec![(root, root_path)];
    while let Some((id, path)) = stack.pop() {
        let node = tree.node(id);
        wtr.write_record([
            path.clone(),
            node.name.to_string(),
            kind_str(node.kind).to_string(),
            node.agg_logical.to_string(),
            node.agg_allocated.to_string(),
            node.agg_files.to_string(),
            node.agg_dirs.to_string(),
            format_rfc3339(node.modified),
        ])?;
        let children = sorted_children(tree, id, options.size_mode);
        stack.extend(children.into_iter().rev().map(|child| {
            let child_path = Path::new(&path)
                .join(&*tree.node(child).name)
                .to_string_lossy()
                .into_owned();
            (child, child_path)
        }));
    }

    wtr.flush()?;
    Ok(())
}
