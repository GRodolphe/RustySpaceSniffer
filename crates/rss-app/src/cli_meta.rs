//! SpaceSniffer-style CLI automation (SPEC.md §4.9, FR-9.1): chained bare
//! keyword commands, e.g.
//!
//! ```text
//! rss scan c:\ filter *.jpg export "Grouped by folder" out.txt autoclose
//! rss --headless load view.rssnap filter :red export "Plain list" red.txt
//! ```
//!
//! Grammar: `scan <path>` / `load <file>` start a subject; `filter <expr>`
//! binds to the preceding scan/load; `export <config> <dest>` renders with a
//! named export configuration (case-sensitive, FR-9.1) after the scan
//! completes; `save <path>` writes a `.rssnap` snapshot; `autoclose` quits
//! after all exports; `help` prints the grammar.
//!
//! M7 executes the chain headlessly (FR-9.2): exports are serialized by
//! construction. GUI-driven automation (each `scan` opening a view) is a
//! documented deviation — the same command set will dispatch to viewports in
//! a later milestone.
//!
//! The form is distinguished from the M1 clap form (`rss scan <path>
//! --export csv out.csv`) by bare keyword tokens; see [`is_meta_form`].

use std::path::PathBuf;
use std::process::ExitCode;

use rss_core::Tree;
use rss_export::Snapshot;

/// Bare keywords of the meta-command grammar.
const KEYWORDS: [&str; 6] = ["scan", "load", "filter", "export", "save", "autoclose"];

/// Whether `args` (without argv[0]) use the meta-command form: `load` is
/// always meta; `scan` is meta when a bare keyword follows the path;
/// `help`/`autoclose` alone are meta. The M1 form (`--export csv`) never
/// contains bare keywords.
pub fn is_meta_form(args: &[String]) -> bool {
    let args = strip_global_flags(args);
    match args.first().map(String::as_str) {
        Some("load") | Some("help") | Some("autoclose") => true,
        Some("scan") => args.len() >= 3 && args[2..].iter().any(|a| KEYWORDS.contains(&a.as_str())),
        _ => false,
    }
}

fn strip_global_flags(args: &[String]) -> &[String] {
    let mut rest = args;
    while matches!(
        rest.first().map(String::as_str),
        Some("--headless") | Some("--console")
    ) {
        rest = &rest[1..];
    }
    rest
}

/// One parsed meta command.
enum Cmd {
    Scan(PathBuf),
    Load(PathBuf),
    Filter(String),
    Export { config: String, dest: PathBuf },
    Save(PathBuf),
    Autoclose,
}

fn parse(args: &[String]) -> Result<Vec<Cmd>, String> {
    let args = strip_global_flags(args);
    let mut cmds = Vec::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "scan" => {
                let path = args.get(i + 1).ok_or("scan: missing <path>")?;
                cmds.push(Cmd::Scan(PathBuf::from(path)));
                i += 2;
            }
            "load" => {
                let file = args.get(i + 1).ok_or("load: missing <file>")?;
                cmds.push(Cmd::Load(PathBuf::from(file)));
                i += 2;
            }
            "filter" => {
                let expr = args.get(i + 1).ok_or("filter: missing <expr>")?;
                cmds.push(Cmd::Filter(expr.clone()));
                i += 2;
            }
            "export" => {
                let config = args.get(i + 1).ok_or("export: missing <config name>")?;
                let dest = args.get(i + 2).ok_or("export: missing <dest file>")?;
                cmds.push(Cmd::Export {
                    config: config.clone(),
                    dest: PathBuf::from(dest),
                });
                i += 3;
            }
            "save" => {
                let path = args.get(i + 1).ok_or("save: missing <path>")?;
                cmds.push(Cmd::Save(PathBuf::from(path)));
                i += 2;
            }
            "autoclose" => {
                cmds.push(Cmd::Autoclose);
                i += 1;
            }
            other => return Err(format!("unknown command `{other}` (try `rss help`)")),
        }
    }
    Ok(cmds)
}

const HELP: &str = "\
RustySpaceSniffer command line (SPEC.md §4.9)

GUI:        rss                                (opens the start dialog)
Headless:   rss [--headless] scan <PATH> --export csv|json [--out <FILE>|OUT]
Automation: rss [scan <PATH> | load <FILE.rssnap>]
                [filter \"<EXPR>\"]               (binds to the preceding scan/load)
                [export \"<CONFIG NAME>\" <DEST>] (named config, case-sensitive)
                [save <PATH.rssnap>]
                [autoclose]                     (quit after all exports)

Built-in export configurations: Grouped by folder, Plain list
Exit codes: 0 ok, 1 scan/export error, 2 usage error.";

/// A scanned or loaded subject that filter/export/save bind to.
struct Subject {
    tree: Tree,
    root: rss_core::NodeId,
    filter: String,
}

/// Execute the meta-command chain headlessly (FR-9.2 exit codes).
pub fn run(args: &[String]) -> ExitCode {
    let cmds = match parse(args) {
        Ok(cmds) => cmds,
        Err(err) => {
            eprintln!("rss: {err}");
            return ExitCode::from(2);
        }
    };
    if cmds.is_empty() || args.first().is_some_and(|a| a == "help") {
        println!("{HELP}");
        return ExitCode::SUCCESS;
    }
    match execute(&cmds) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("rss: error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn execute(cmds: &[Cmd]) -> anyhow::Result<()> {
    let mut subject: Option<Subject> = None;
    for cmd in cmds {
        match cmd {
            Cmd::Scan(path) => {
                let opts = rss_scan::ScanOptions::default();
                let (tree, summary) = rss_scan::scan_tree(path, &opts)
                    .map_err(|e| anyhow::anyhow!("scan failed: {e}"))?;
                eprintln!(
                    "rss: scanned {} entries ({}) in {:.2?}",
                    summary.entries,
                    crate::fmt::format_bytes(summary.allocated_size),
                    summary.elapsed
                );
                let root = tree
                    .root()
                    .ok_or_else(|| anyhow::anyhow!("scan produced no root node"))?;
                subject = Some(Subject {
                    tree,
                    root,
                    filter: String::new(),
                });
            }
            Cmd::Load(file) => {
                let snapshot = Snapshot::read_from(&mut std::fs::File::open(file)?)?;
                let root = snapshot
                    .tree
                    .root()
                    .ok_or(rss_export::SnapshotError::EmptyTree)?;
                subject = Some(Subject {
                    tree: snapshot.tree,
                    root,
                    filter: snapshot.filter.clone(),
                });
            }
            Cmd::Filter(expr) => {
                let Some(subject) = &mut subject else {
                    return Err(anyhow::anyhow!("filter must follow a scan or load command"));
                };
                // Validate now so a bad filter fails loudly (FR-4.13), not
                // silently at export time.
                let filter = rss_filter::Filter::parse(expr, &[]);
                for warning in filter.warnings() {
                    eprintln!("rss: filter warning: {warning}");
                }
                subject.filter = expr.clone();
            }
            Cmd::Export { config, dest } => {
                let Some(subject) = &subject else {
                    return Err(anyhow::anyhow!("export must follow a scan or load command"));
                };
                // FR-9.1: the config name is case-sensitive.
                let template = rss_export::builtin_templates()
                    .into_iter()
                    .find(|t| t.name == *config)
                    .ok_or_else(|| {
                        anyhow::anyhow!("unknown export configuration `{config}` (see `rss help`)")
                    })?;
                let now = rss_core::filetime_from_unix(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| d.as_secs() as i64),
                );
                let context = rss_export::TemplateContext {
                    filter: (!subject.filter.is_empty()).then_some(subject.filter.as_str()),
                    now,
                };
                let mut out = std::fs::File::create(dest)?;
                rss_export::render_template(
                    &subject.tree,
                    subject.root,
                    &template,
                    &context,
                    &mut out,
                )?;
                eprintln!("rss: exported `{}` to {}", config, dest.display());
            }
            Cmd::Save(path) => {
                let Some(subject) = &subject else {
                    return Err(anyhow::anyhow!("save must follow a scan or load command"));
                };
                let mut snapshot = Snapshot::new(
                    subject.tree.clone(),
                    rss_export::ScanMetadata {
                        tool_version: env!("CARGO_PKG_VERSION").to_string(),
                        volume_serial: 0,
                        started: 0,
                        finished: 0,
                    },
                );
                snapshot.filter = subject.filter.clone();
                snapshot.write_to(&mut std::fs::File::create(path)?)?;
                eprintln!("rss: saved snapshot to {}", path.display());
            }
            Cmd::Autoclose => {} // headless runs exit after exports anyway
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn meta_form_detection() {
        assert!(is_meta_form(&args("load view.rssnap")));
        assert!(is_meta_form(&args(
            "scan c:\\ filter *.jpg export G out.txt"
        )));
        assert!(is_meta_form(&args("help")));
        // M1 clap form: dashed flags, no bare keywords.
        assert!(!is_meta_form(&args("scan /tmp --export csv out.csv")));
        assert!(!is_meta_form(&args("scan /tmp --export csv")));
        assert!(!is_meta_form(&args("scan /tmp")));
        assert!(!is_meta_form(&args("--headless")));
    }

    #[test]
    fn parse_errors_are_usage_errors() {
        assert!(parse(&args("scan")).is_err());
        assert!(parse(&args("export name out")).is_ok()); // binds at exec time
        assert!(parse(&args("bogus")).is_err());
        assert!(parse(&args("scan /tmp export name")).is_err()); // missing dest
    }
}
