//! Text report export via a template engine implementing a safe subset of
//! SpaceSniffer's export mini-language (FR-8.2/FR-8.3, SPEC.md §4.8).
//!
//! A template ([`ExportTemplate`]) has three text sections — `header`,
//! `detail`, `footer` — plus sorting options. The header and footer are
//! rendered once around the report; the detail section is rendered once per
//! node, depth-first. Literal text passes through unchanged. `<%name%>`
//! placeholders substitute per-node values:
//!
//! | Placeholder | Value |
//! |---|---|
//! | `<%pathfile%>` | full path including the file name |
//! | `<%path%>` | parent folder path (empty for the export root) |
//! | `<%file%>` | file name |
//! | `<%fileext%>` | file extension, without the dot |
//! | `<%size%>` | human-readable logical size (e.g. `1.5 MB`) |
//! | `<%sizebytes%>` | logical size in bytes |
//! | `<%disksize%>` | human-readable allocated (on-disk) size |
//! | `<%disksizebytes%>` | allocated size in bytes |
//! | `<%filemodifydate%>` | last-modified time, RFC 3339 UTC |
//! | `<%age%>` | age relative to [`TemplateContext::now`] (e.g. `3d`) |
//! | `<%isfile%>` / `<%isfolder%>` / `<%iscontainer%>` | `1` or `0` |
//! | `<%nestinglevel%>` | depth below the export root (root = 0) |
//! | `<%counter%>` | 1-based running count of all rendered nodes |
//! | `<%filecounter%>` / `<%foldercounter%>` | per-kind running counts |
//!
//! `{commands}`:
//!
//! - `{&br}` line break, `{&tab}` tab
//! - `{leftpad N}` / `{rightpad N}` pad the next placeholder's value with
//!   spaces to a width of `N` characters (Unicode-aware, `N` <= 4096)
//! - `{nest}` / `{nest N}` emit `N` (default 2) spaces per nesting level
//! - `{if isfile}` / `{if !isfolder}` … `{else}` … `{endif}` conditionals
//!   over the three boolean placeholders (nesting allowed, capped)
//! - `{{` renders a literal `{`
//! - `{script …}` is *recognized but never executed* (no code execution,
//!   SPEC.md §9.8) — it is a typed [`TemplateError::UnsupportedCommand`]
//!
//! Unknown placeholders/commands and malformed sections are typed errors
//! carrying the byte span in the offending section. Placeholders valid in the
//! detail section resolve against the export root when used in header/footer.
//!
//! Deliberate deviations from SpaceSniffer's full language (documented subset
//! per assignment): `{if}` uses `{if name}…{else}…{endif}` instead of the
//! historical expression form, and `{script}` is rejected rather than run.

use std::fmt::Write as _;
use std::io::Write;
use std::ops::Range;

use rss_core::{filetime_to_unix, FileTime, NodeId, NodeKind, Tree};

use crate::time::format_rfc3339;
use crate::ExportError;

/// Maximum pad width accepted by `{leftpad N}` / `{rightpad N}`.
pub const MAX_PAD_WIDTH: usize = 4096;
/// Maximum spaces per nesting level accepted by `{nest N}`.
pub const MAX_NEST_WIDTH: usize = 64;
/// Maximum nesting depth of `{if}` blocks.
pub const MAX_IF_DEPTH: usize = 32;

/// Errors produced by template rendering. Spans are byte ranges in the text
/// of the offending section.
#[derive(Debug, thiserror::Error)]
pub enum TemplateError {
    /// A `<%name%>` placeholder uses an unknown name.
    #[error("unknown placeholder <%{name}%> in {section} section at bytes {span:?}")]
    UnknownPlaceholder {
        /// The placeholder name (without `<%`/`%>`).
        name: String,
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range covering `<%…%>`.
        span: Range<usize>,
    },
    /// A `<%` without a closing `%>`.
    #[error("unterminated placeholder in {section} section at bytes {span:?}")]
    UnterminatedPlaceholder {
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range from `<%` to the end of the section.
        span: Range<usize>,
    },
    /// A `{name …}` command uses an unknown name.
    #[error("unknown command {{{name}}} in {section} section at bytes {span:?}")]
    UnknownCommand {
        /// The command text (without braces).
        name: String,
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range covering `{…}`.
        span: Range<usize>,
    },
    /// A command argument failed to parse.
    #[error("invalid argument for {{{command}}} in {section} section at bytes {span:?}: {reason}")]
    InvalidCommandArg {
        /// The command name.
        command: &'static str,
        /// Why the argument is invalid.
        reason: String,
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range covering `{…}`.
        span: Range<usize>,
    },
    /// A recognized command this engine deliberately does not implement
    /// (`{script …}` — no code execution, SPEC.md §9.8).
    #[error(
        "unsupported command {{{name}}} in {section} section at bytes {span:?} (no code execution)"
    )]
    UnsupportedCommand {
        /// The command name.
        name: String,
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range covering `{…}`.
        span: Range<usize>,
    },
    /// A `{` without a closing `}`.
    #[error("unterminated command in {section} section at bytes {span:?}")]
    UnterminatedCommand {
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range from `{` to the end of the section.
        span: Range<usize>,
    },
    /// `{else}` or `{endif}` without a matching `{if}`.
    #[error("unmatched {{{command}}} in {section} section at bytes {span:?}")]
    UnmatchedConditional {
        /// `else` or `endif`.
        command: &'static str,
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range covering `{…}`.
        span: Range<usize>,
    },
    /// An `{if}` without a matching `{endif}`.
    #[error("{{if …}} in {section} section at bytes {span:?} has no matching {{endif}}")]
    MissingEndif {
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range covering the opening `{if …}`.
        span: Range<usize>,
    },
    /// `{if}` blocks nested deeper than the cap.
    #[error("{{if}} blocks nested deeper than {MAX_IF_DEPTH} in {section} section")]
    ConditionalNestingTooDeep {
        /// Section the error occurred in.
        section: &'static str,
    },
    /// An `{if}` condition that is not a (possibly negated) boolean
    /// placeholder name.
    #[error("invalid {{if}} condition in {section} section at bytes {span:?}: {reason}")]
    InvalidCondition {
        /// Why the condition is invalid.
        reason: String,
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range covering `{if …}`.
        span: Range<usize>,
    },
    /// A pad command whose value never got a placeholder to attach to.
    #[error(
        "dangling {{{command}}} in {section} section at bytes {span:?} (no placeholder follows)"
    )]
    DanglingPad {
        /// `leftpad` or `rightpad`.
        command: &'static str,
        /// Section the error occurred in.
        section: &'static str,
        /// Byte range covering the pad command.
        span: Range<usize>,
    },
}

/// How sibling blocks are grouped before fine sorting (FR-8.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BlockSort {
    /// Folders (and container pseudo-nodes) first, then files.
    #[default]
    FoldersFirst,
    /// Files first, then folders.
    FilesFirst,
    /// No block grouping; fine sorting only.
    None,
}

/// The per-node key used for fine sorting within a block (FR-8.2).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum SortField {
    /// File name, case-insensitive.
    #[default]
    Name,
    /// File extension, case-insensitive.
    Extension,
    /// Logical size.
    Size,
    /// Allocated (on-disk) size.
    DiskSize,
    /// Last-modified time.
    ModifyDate,
}

/// A named, shareable export configuration (FR-8.2).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ExportTemplate {
    /// Configuration name, referenced by `export "<config name>"` in the CLI.
    pub name: String,
    /// Rendered once at the top of the report (after the FR-8.1 prologue).
    pub header: String,
    /// Rendered once per node, depth-first.
    pub detail: String,
    /// Rendered once at the bottom of the report.
    pub footer: String,
    /// Block grouping applied to siblings.
    pub block_sort: BlockSort,
    /// Fine sort key within a block.
    pub sort: SortField,
    /// Reverse the fine sort (block grouping still applies).
    pub descending: bool,
}

/// View state the report must state in its output header (FR-8.1).
#[derive(Clone, Copy, Debug, Default)]
pub struct TemplateContext<'a> {
    /// The view's active filter string, if any. Stated in the output header
    /// (FR-8.1); filtered-out elements remain in the export (FR-4.12), so no
    /// node is ever dropped here.
    pub filter: Option<&'a str>,
    /// Reference time for `<%age%>` (FILETIME ticks).
    pub now: FileTime,
}

impl ExportTemplate {
    /// The built-in **"Grouped by folder"** configuration (FR-8.3), named
    /// exactly as in SpaceSniffer's CLI examples so user scripts migrate.
    pub fn grouped_by_folder() -> Self {
        Self {
            name: "Grouped by folder".to_string(),
            header: "Grouped by folder report{&br}{&br}".to_string(),
            detail: "{leftpad 12}<%size%> {nest 2}<%file%>{&br}".to_string(),
            footer: "{&br}<%counter%> elements, <%foldercounter%> folders, \
                     <%filecounter%> files{&br}"
                .to_string(),
            block_sort: BlockSort::FoldersFirst,
            sort: SortField::Name,
            descending: false,
        }
    }

    /// A minimal built-in listing every element's full path and size.
    pub fn plain_list() -> Self {
        Self {
            name: "Plain list".to_string(),
            header: "Path{&tab}Size (bytes){&tab}Size on disk (bytes){&br}".to_string(),
            detail: "<%pathfile%>{&tab}<%sizebytes%>{&tab}<%disksizebytes%>{&br}".to_string(),
            footer: String::new(),
            block_sort: BlockSort::None,
            sort: SortField::Name,
            descending: false,
        }
    }
}

/// The built-in export configurations shipped with the app (FR-8.3).
pub fn builtin_templates() -> Vec<ExportTemplate> {
    vec![
        ExportTemplate::grouped_by_folder(),
        ExportTemplate::plain_list(),
    ]
}

/// Look up a built-in configuration by name (case-insensitive).
pub fn find_builtin_template(name: &str) -> Option<ExportTemplate> {
    builtin_templates()
        .into_iter()
        .find(|t| t.name.eq_ignore_ascii_case(name))
}

/// Render the subtree rooted at `root` (the view's current zoom) with
/// `template` to `writer` (FR-8.1/FR-8.2). The output is UTF-8 and starts
/// with a prologue stating the template name, the exported view path, and
/// the active filter (FR-8.1).
pub fn render_template(
    tree: &Tree,
    root: NodeId,
    template: &ExportTemplate,
    context: &TemplateContext<'_>,
    mut writer: impl Write,
) -> Result<(), ExportError> {
    if root as usize >= tree.len() {
        return Err(ExportError::InvalidRoot(root));
    }

    // FR-8.1: state the zoom and the filter in the output header.
    let view_path = tree.path(root).to_string_lossy().into_owned();
    let mut prologue = String::new();
    let _ = writeln!(
        prologue,
        "# RustySpaceSniffer export (template: {})",
        template.name
    );
    let _ = writeln!(prologue, "# view: {view_path}");
    let _ = writeln!(prologue, "# filter: {}", context.filter.unwrap_or("none"));
    writer.write_all(prologue.as_bytes())?;

    let mut renderer = Renderer {
        tree,
        now: context.now,
        counters: Counters::default(),
    };

    let header = renderer.render_section(&template.header, "header", root, 0, 0)?;
    writer.write_all(header.as_bytes())?;

    // Iterative pre-order walk; children pushed in reverse so they pop in
    // sorted order.
    let mut stack = vec![(root, 0usize)];
    while let Some((id, depth)) = stack.pop() {
        renderer.counters.count_node(tree.node(id).kind);
        let line = renderer.render_section(&template.detail, "detail", id, depth, 0)?;
        writer.write_all(line.as_bytes())?;
        let children = ordered_children(tree, id, template);
        stack.extend(children.into_iter().rev().map(|c| (c, depth + 1)));
    }

    let footer = renderer.render_section(&template.footer, "footer", root, 0, 0)?;
    writer.write_all(footer.as_bytes())?;
    writer.flush()?;
    Ok(())
}

#[derive(Default)]
struct Counters {
    element: u64,
    file: u64,
    folder: u64,
}

impl Counters {
    fn count_node(&mut self, kind: NodeKind) {
        self.element += 1;
        if is_file_kind(kind) {
            self.file += 1;
        }
        if is_folder_kind(kind) {
            self.folder += 1;
        }
    }
}

fn is_file_kind(kind: NodeKind) -> bool {
    matches!(kind, NodeKind::File | NodeKind::Ads)
}

fn is_folder_kind(kind: NodeKind) -> bool {
    kind == NodeKind::Directory
}

fn is_container_kind(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::FreeSpace | NodeKind::UnknownSpace | NodeKind::Unaccessible
    )
}

/// Children of `parent` ordered per the template's block sort, fine sort, and
/// descending flag. The sort is stable, so ties keep the tree's child order.
fn ordered_children(tree: &Tree, parent: NodeId, template: &ExportTemplate) -> Vec<NodeId> {
    let block_rank = |id: NodeId| {
        let folderish = !is_file_kind(tree.node(id).kind);
        match template.block_sort {
            BlockSort::None => 0,
            BlockSort::FoldersFirst => u8::from(!folderish),
            BlockSort::FilesFirst => u8::from(folderish),
        }
    };
    let mut children: Vec<NodeId> = tree.children(parent).collect();
    children.sort_by(|&a, &b| {
        block_rank(a).cmp(&block_rank(b)).then_with(|| {
            let ord = sort_key(tree, a, template.sort).cmp(&sort_key(tree, b, template.sort));
            if template.descending {
                ord.reverse()
            } else {
                ord
            }
        })
    });
    children
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum SortKey {
    Num(u64),
    Text(String),
}

fn sort_key(tree: &Tree, id: NodeId, field: SortField) -> SortKey {
    let node = tree.node(id);
    match field {
        SortField::Name => SortKey::Text(node.name.to_lowercase()),
        SortField::Extension => SortKey::Text(extension_of(&node.name).to_lowercase()),
        SortField::Size => SortKey::Num(node.agg_logical),
        SortField::DiskSize => SortKey::Num(node.agg_allocated),
        SortField::ModifyDate => SortKey::Num(node.modified.max(0) as u64),
    }
}

/// Extension without the dot, using `Path` semantics (dotfiles have none).
fn extension_of(name: &str) -> &str {
    std::path::Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
}

/// Human-readable size, base 1024 (e.g. `512 B`, `1.5 MB`).
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Human-readable age of `modified` relative to `now` (e.g. `45s`, `3d`,
/// `2mo`, `1y`). Negative ages (clock skew) render as `0s`.
pub fn age_string(now: FileTime, modified: FileTime) -> String {
    let secs = filetime_to_unix(now)
        .saturating_sub(filetime_to_unix(modified))
        .max(0) as u64;
    const MINUTE: u64 = 60;
    const HOUR: u64 = 60 * MINUTE;
    const DAY: u64 = 24 * HOUR;
    const MONTH: u64 = 30 * DAY;
    const YEAR: u64 = 365 * DAY;
    if secs >= YEAR {
        format!("{}y", secs / YEAR)
    } else if secs >= MONTH {
        format!("{}mo", secs / MONTH)
    } else if secs >= DAY {
        format!("{}d", secs / DAY)
    } else if secs >= HOUR {
        format!("{}h", secs / HOUR)
    } else if secs >= MINUTE {
        format!("{}m", secs / MINUTE)
    } else {
        format!("{secs}s")
    }
}

struct Renderer<'a> {
    tree: &'a Tree,
    now: FileTime,
    counters: Counters,
}

struct PendingPad {
    right: bool,
    width: usize,
    span: Range<usize>,
}

impl Renderer<'_> {
    /// Render one section's text for `id` at `depth`. `if_depth` tracks
    /// `{if}` nesting during the recursive branch expansion.
    fn render_section(
        &mut self,
        text: &str,
        section: &'static str,
        id: NodeId,
        depth: usize,
        if_depth: usize,
    ) -> Result<String, TemplateError> {
        let bytes = text.as_bytes();
        let mut out = String::new();
        let mut pad: Option<PendingPad> = None;
        let mut i = 0;
        let mut literal_start = 0;

        macro_rules! flush_literal {
            ($end:expr) => {
                if literal_start < $end {
                    let literal = &text[literal_start..$end];
                    if let Some(p) = &pad {
                        // Whitespace between a pad command and its placeholder
                        // is emitted without consuming the pad; anything else
                        // means the pad has nothing to attach to.
                        if !literal.trim().is_empty() {
                            return Err(TemplateError::DanglingPad {
                                command: if p.right { "rightpad" } else { "leftpad" },
                                section,
                                span: p.span.clone(),
                            });
                        }
                    }
                    out.push_str(literal);
                }
            };
        }

        while i < bytes.len() {
            if bytes[i..].starts_with(b"<%") {
                flush_literal!(i);
                let span = placeholder_span(text, i, section)?;
                let name = &text[i + 2..span.end - 2];
                let mut value = self.placeholder(name, section, span.clone(), id, depth)?;
                if let Some(p) = pad.take() {
                    value = apply_pad(value, &p);
                }
                out.push_str(&value);
                i = span.end;
                literal_start = i;
            } else if bytes[i] == b'{' {
                if bytes[i..].starts_with(b"{{") {
                    flush_literal!(i);
                    out.push('{');
                    i += 2;
                    literal_start = i;
                    continue;
                }
                flush_literal!(i);
                let span = command_span(text, i, section)?;
                let body = text[i + 1..span.end - 1].trim();
                i = self.command(
                    text, body, &span, section, id, depth, if_depth, &mut out, &mut pad,
                )?;
                literal_start = i;
            } else {
                i += 1;
            }
        }
        flush_literal!(bytes.len());
        if let Some(p) = pad {
            return Err(TemplateError::DanglingPad {
                command: if p.right { "rightpad" } else { "leftpad" },
                section,
                span: p.span,
            });
        }
        Ok(out)
    }

    /// Handle one `{command}`. Returns the index right after the consumed
    /// text (past the command itself, or past the whole `{if}…{endif}` block).
    #[allow(clippy::too_many_arguments)]
    fn command(
        &mut self,
        text: &str,
        body: &str,
        span: &Range<usize>,
        section: &'static str,
        id: NodeId,
        depth: usize,
        if_depth: usize,
        out: &mut String,
        pad: &mut Option<PendingPad>,
    ) -> Result<usize, TemplateError> {
        let after = span.end;
        let mut words = body.split_whitespace();
        let head = words.next().unwrap_or("");
        match head {
            "&br" => out.push('\n'),
            "&tab" => out.push('\t'),
            "leftpad" | "rightpad" => {
                let command: &'static str = if head == "rightpad" {
                    "rightpad"
                } else {
                    "leftpad"
                };
                let width = parse_width(command, words.next(), section, span)?;
                if pad.is_some() {
                    return Err(TemplateError::DanglingPad {
                        command,
                        section,
                        span: span.clone(),
                    });
                }
                *pad = Some(PendingPad {
                    right: head == "rightpad",
                    width,
                    span: span.clone(),
                });
            }
            "nest" => {
                let width = match words.next() {
                    None => 2,
                    arg => parse_width("nest", arg, section, span)?,
                };
                if width > MAX_NEST_WIDTH {
                    return Err(TemplateError::InvalidCommandArg {
                        command: "nest",
                        reason: format!("width {width} exceeds the cap of {MAX_NEST_WIDTH}"),
                        section,
                        span: span.clone(),
                    });
                }
                for _ in 0..depth * width {
                    out.push(' ');
                }
            }
            "script" => {
                return Err(TemplateError::UnsupportedCommand {
                    name: body.to_string(),
                    section,
                    span: span.clone(),
                });
            }
            "if" => return self.conditional(text, span, section, id, depth, if_depth, out, pad),
            "else" => {
                return Err(TemplateError::UnmatchedConditional {
                    command: "else",
                    section,
                    span: span.clone(),
                });
            }
            "endif" => {
                return Err(TemplateError::UnmatchedConditional {
                    command: "endif",
                    section,
                    span: span.clone(),
                });
            }
            _ => {
                return Err(TemplateError::UnknownCommand {
                    name: body.to_string(),
                    section,
                    span: span.clone(),
                });
            }
        }
        Ok(after)
    }

    /// Render an `{if cond}…{else}…{endif}` block starting at `span`.
    #[allow(clippy::too_many_arguments)]
    fn conditional(
        &mut self,
        text: &str,
        span: &Range<usize>,
        section: &'static str,
        id: NodeId,
        depth: usize,
        if_depth: usize,
        out: &mut String,
        pad: &mut Option<PendingPad>,
    ) -> Result<usize, TemplateError> {
        if if_depth >= MAX_IF_DEPTH {
            return Err(TemplateError::ConditionalNestingTooDeep { section });
        }
        let condition_text = text[span.clone()]
            .trim_start_matches("{if")
            .trim_end_matches('}');
        let (name, negated) = match condition_text.trim().strip_prefix('!') {
            Some(rest) => (rest.trim(), true),
            None => (condition_text.trim(), false),
        };
        let known = matches!(name, "isfile" | "isfolder" | "iscontainer");
        if !known {
            return Err(TemplateError::InvalidCondition {
                reason: format!(
                    "expected one of isfile, isfolder, iscontainer (optionally negated with `!`), got `{name}`"
                ),
                section,
                span: span.clone(),
            });
        }
        let kind = self.tree.node(id).kind;
        let mut value = match name {
            "isfile" => is_file_kind(kind),
            "isfolder" => is_folder_kind(kind),
            _ => is_container_kind(kind),
        };
        if negated {
            value = !value;
        }

        // Find the matching {else}/{endif} at this nesting level.
        let (then_range, else_range, end) = find_conditional_parts(text, span.end, section, span)?;

        let branch = match (value, &else_range) {
            (true, _) => Some(then_range),
            (false, Some(else_range)) => Some(else_range.clone()),
            (false, None) => None,
        };
        if let Some(branch) = branch {
            let rendered = self.render_section(&text[branch], section, id, depth, if_depth + 1)?;
            // An {if} body may carry a pad of its own; it must not leak one
            // into the surrounding text and vice versa.
            if pad.is_some() {
                let p = pad.take().expect("checked above");
                return Err(TemplateError::DanglingPad {
                    command: if p.right { "rightpad" } else { "leftpad" },
                    section,
                    span: p.span,
                });
            }
            out.push_str(&rendered);
        }
        Ok(end)
    }

    /// Evaluate a `<%name%>` placeholder for `id` at `depth`.
    fn placeholder(
        &self,
        name: &str,
        section: &'static str,
        span: Range<usize>,
        id: NodeId,
        depth: usize,
    ) -> Result<String, TemplateError> {
        let node = self.tree.node(id);
        let value = match name {
            "pathfile" => self.tree.path(id).to_string_lossy().into_owned(),
            "path" => match node.parent {
                Some(parent) => self.tree.path(parent).to_string_lossy().into_owned(),
                None => String::new(),
            },
            "file" => node.name.to_string(),
            "fileext" => extension_of(&node.name).to_string(),
            "size" => human_size(node.agg_logical),
            "sizebytes" => node.agg_logical.to_string(),
            "disksize" => human_size(node.agg_allocated),
            "disksizebytes" => node.agg_allocated.to_string(),
            "filemodifydate" => format_rfc3339(node.modified),
            "age" => age_string(self.now, node.modified),
            "isfile" => bool_str(is_file_kind(node.kind)),
            "isfolder" => bool_str(is_folder_kind(node.kind)),
            "iscontainer" => bool_str(is_container_kind(node.kind)),
            "nestinglevel" => depth.to_string(),
            "counter" => self.counters.element.to_string(),
            "filecounter" => self.counters.file.to_string(),
            "foldercounter" => self.counters.folder.to_string(),
            _ => {
                return Err(TemplateError::UnknownPlaceholder {
                    name: name.to_string(),
                    section,
                    span,
                });
            }
        };
        Ok(value)
    }
}

fn bool_str(value: bool) -> String {
    if value { "1" } else { "0" }.to_string()
}

fn apply_pad(value: String, pad: &PendingPad) -> String {
    let width = value.chars().count();
    if width >= pad.width {
        return value;
    }
    let padding = " ".repeat(pad.width - width);
    if pad.right {
        format!("{value}{padding}")
    } else {
        format!("{padding}{value}")
    }
}

fn parse_width(
    command: &'static str,
    arg: Option<&str>,
    section: &'static str,
    span: &Range<usize>,
) -> Result<usize, TemplateError> {
    let invalid = |reason: String| TemplateError::InvalidCommandArg {
        command,
        reason,
        section,
        span: span.clone(),
    };
    let Some(arg) = arg else {
        return Err(invalid("missing width argument".to_string()));
    };
    let width: usize = arg
        .parse()
        .map_err(|_| invalid(format!("`{arg}` is not a non-negative integer")))?;
    if command != "nest" && width > MAX_PAD_WIDTH {
        return Err(invalid(format!(
            "width {width} exceeds the cap of {MAX_PAD_WIDTH}"
        )));
    }
    Ok(width)
}

/// Byte range of the `<%…%>` starting at `start` (which indexes the `<`).
fn placeholder_span(
    text: &str,
    start: usize,
    section: &'static str,
) -> Result<Range<usize>, TemplateError> {
    match text[start + 2..].find("%>") {
        Some(rel) => Ok(start..start + 2 + rel + 2),
        None => Err(TemplateError::UnterminatedPlaceholder {
            section,
            span: start..text.len(),
        }),
    }
}

/// Byte range of the `{…}` starting at `start` (which indexes the `{`).
fn command_span(
    text: &str,
    start: usize,
    section: &'static str,
) -> Result<Range<usize>, TemplateError> {
    match text[start + 1..].find('}') {
        Some(rel) => Ok(start..start + 1 + rel + 1),
        None => Err(TemplateError::UnterminatedCommand {
            section,
            span: start..text.len(),
        }),
    }
}

/// The parts of an `{if}…{else}…{endif}` block: then-branch range,
/// else-branch range, and the index just past `{endif}`.
type ConditionalParts = (Range<usize>, Option<Range<usize>>, usize);

/// Starting after an `{if …}` (at `from`), find the `{else}` (if any) and the
/// matching `{endif}` at the same nesting level.
fn find_conditional_parts(
    text: &str,
    from: usize,
    section: &'static str,
    if_span: &Range<usize>,
) -> Result<ConditionalParts, TemplateError> {
    let mut depth = 0usize;
    let mut else_at: Option<Range<usize>> = None;
    let mut i = from;
    while i < text.len() {
        if text.as_bytes()[i] == b'{' && !text[i..].starts_with("{{") {
            let span = command_span(text, i, section)?;
            let body = text[span.start + 1..span.end - 1].trim();
            let head = body.split_whitespace().next().unwrap_or("");
            match head {
                "if" => depth += 1,
                "endif" => {
                    if depth == 0 {
                        let then = from..else_at.as_ref().map_or(span.start, |e| e.start);
                        let else_range = else_at.map(|e| e.end..span.start);
                        return Ok((then, else_range, span.end));
                    }
                    depth -= 1;
                }
                "else" if depth == 0 && else_at.is_none() => else_at = Some(span.clone()),
                _ => {}
            }
            i = span.end;
        } else {
            i += 1;
        }
    }
    Err(TemplateError::MissingEndif {
        section,
        span: if_span.clone(),
    })
}
