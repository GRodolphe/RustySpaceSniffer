//! Nested JSON export (FR-8.5).

use std::io::Write;
use std::path::Path;

use rss_core::{NodeId, Tree};
use serde::Serialize;

use crate::time::format_rfc3339;
use crate::traverse::{kind_str, sorted_children};
use crate::{ExportError, ExportOptions};

/// Serializable form of one node and its subtree.
#[derive(Serialize)]
struct JsonNode {
    name: String,
    path: String,
    kind: &'static str,
    logical_size: u64,
    allocated_size: u64,
    files: u64,
    dirs: u64,
    modified: String,
    children: Vec<JsonNode>,
}

impl JsonNode {
    fn leaf(tree: &Tree, id: NodeId, path: String) -> Self {
        let node = tree.node(id);
        Self {
            name: node.name.to_string(),
            path,
            kind: kind_str(node.kind),
            logical_size: node.agg_logical,
            allocated_size: node.agg_allocated,
            files: node.agg_files,
            dirs: node.agg_dirs,
            modified: format_rfc3339(node.modified),
            children: Vec::new(),
        }
    }
}

/// Build the nested document iteratively (explicit stack, so deep trees do
/// not overflow the call stack while walking). Paths are carried along the
/// stack (one join per node) instead of recomputed from the parents, which
/// would make deep trees quadratic. `pending` holds nodes whose children are
/// still being collected into the top of `child_lists`.
fn build_tree(tree: &Tree, root: NodeId, options: ExportOptions) -> JsonNode {
    enum Event {
        Enter(NodeId, String),
        Exit,
    }

    let root_path = tree.path(root).to_string_lossy().into_owned();
    let mut events = vec![Event::Enter(root, root_path)];
    let mut pending: Vec<JsonNode> = Vec::new();
    let mut child_lists: Vec<Vec<JsonNode>> = vec![Vec::new()];

    while let Some(event) = events.pop() {
        match event {
            Event::Enter(id, path) => {
                events.push(Event::Exit);
                pending.push(JsonNode::leaf(tree, id, path.clone()));
                child_lists.push(Vec::new());
                let children = sorted_children(tree, id, options.size_mode);
                events.extend(children.into_iter().rev().map(|child| {
                    let child_path = Path::new(&path)
                        .join(&*tree.node(child).name)
                        .to_string_lossy()
                        .into_owned();
                    Event::Enter(child, child_path)
                }));
            }
            Event::Exit => {
                let mut node = pending.pop().expect("Exit without Enter");
                node.children = child_lists.pop().expect("Exit without child list");
                child_lists
                    .last_mut()
                    .expect("root Exit without parent list")
                    .push(node);
            }
        }
    }

    debug_assert!(pending.is_empty() && child_lists.len() == 1);
    child_lists
        .pop()
        .and_then(|mut roots| roots.pop())
        .expect("root node was built")
}

pub(crate) fn export(
    tree: &Tree,
    root: NodeId,
    options: ExportOptions,
    mut writer: impl Write,
) -> Result<(), ExportError> {
    let document = build_tree(tree, root, options);
    serde_json::to_writer_pretty(&mut writer, &document)?;
    writer.write_all(b"\n")?;
    Ok(())
}
