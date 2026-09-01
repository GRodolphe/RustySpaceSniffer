//! `rss` command-line parsing and dispatch (SPEC.md §4.9, §5.1).
//!
//! Migrated from the M1 `rss-cli` crate in M2. Dispatch rule:
//!
//! - `rss` (no arguments) opens the GUI start dialog (§4.1).
//! - `rss scan <PATH> --export csv|json [--out <FILE> | OUT]` runs headless
//!   with the `WalkScanner` and exports the resulting tree. Exit codes:
//!   0 on success, 1 on scan/export error, 2 on usage error (clap).
//! - `rss --headless` without a subcommand is a usage error (exit 2).
//!
//! The GUI automation command set (`load`/`filter`/`save`/`autoclose`,
//! FR-9.1) and console attachment (FR-9.3) arrive in later milestones.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use rss_export::{ExportOptions, SizeMode};

use crate::fmt::format_bytes;

#[derive(Parser)]
#[command(
    name = "rss",
    version,
    about = "RustySpaceSniffer — disk space treemap analyzer"
)]
struct Cli {
    /// Run without a GUI (FR-9.2). Currently only meaningful together with a
    /// subcommand; `rss` with no arguments always opens the GUI.
    #[arg(long, global = true)]
    headless: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a directory tree and export the result.
    Scan {
        /// Root path to scan.
        path: PathBuf,

        /// Export format.
        #[arg(long, value_enum)]
        export: ExportFormat,

        /// Output file for the export.
        #[arg(long, value_name = "FILE")]
        out: Option<PathBuf>,

        /// Output file (positional form; supports the SPEC.md §12 M1 syntax
        /// `rss scan <dir> --export csv out.csv`).
        #[arg(value_name = "OUT", conflicts_with = "out")]
        out_file: Option<PathBuf>,

        /// Report logical instead of allocated sizes (reserved, FR-9.5).
        /// Both sizes are always exported, so this flag currently only
        /// affects the human summary and sibling ordering.
        #[arg(long)]
        logical: bool,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ExportFormat {
    /// CSV: one row per node, header row, UTF-8 with BOM (FR-8.4).
    Csv,
    /// JSON: full subtree with sizes and dates (FR-8.5).
    Json,
}

/// Binary entry point: parse argv and dispatch to the GUI or a headless
/// subcommand.
pub fn main_entry() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    // SpaceSniffer-style meta-command form (FR-9.1), e.g.
    // `rss scan c:\ filter *.jpg export "Grouped by folder" out.txt autoclose`.
    // Distinguished from the M1 clap form by bare keyword tokens.
    if crate::cli_meta::is_meta_form(&args) {
        return crate::cli_meta::run(&args);
    }
    let cli = Cli::parse();
    match cli.command {
        None => {
            if cli.headless {
                // FR-9.2: headless with nothing to do is a usage error.
                eprintln!(
                    "rss: --headless requires a subcommand, e.g. \
                     `rss --headless scan <PATH> --export csv --out <FILE>`"
                );
                ExitCode::from(2)
            } else if let Err(err) = crate::gui::run_gui() {
                eprintln!("rss: error: {err:#}");
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            }
        }
        Some(command) => match run(command) {
            Ok(()) => ExitCode::SUCCESS,
            Err(err) => {
                eprintln!("rss: error: {err:#}");
                ExitCode::from(1)
            }
        },
    }
}

fn run(command: Commands) -> anyhow::Result<()> {
    match command {
        Commands::Scan {
            path,
            export,
            out,
            out_file,
            logical,
        } => {
            let out = match out.or(out_file) {
                Some(out) => out,
                None => {
                    // Usage error (exit code 2), not a scan error.
                    eprintln!("rss: missing output file — pass --out <FILE> or a positional OUT");
                    std::process::exit(2);
                }
            };
            scan_and_export(&path, &out, export, logical)
        }
    }
}

fn scan_and_export(
    path: &std::path::Path,
    out: &std::path::Path,
    format: ExportFormat,
    logical: bool,
) -> anyhow::Result<()> {
    let opts = rss_scan::ScanOptions::default();
    let (tree, summary) = rss_scan::scan_tree(path, &opts).context("scan failed")?;

    let root = tree
        .root()
        .context("scan produced no root node (cancelled before the first entry?)")?;
    // --logical switches the exporters' primary size (sibling ordering) as
    // well as the summary label; both size columns are always exported.
    let export_options = ExportOptions {
        size_mode: if logical {
            SizeMode::Logical
        } else {
            SizeMode::Allocated
        },
    };
    let mut out_file = std::fs::File::create(out)
        .with_context(|| format!("cannot create output file: {}", out.display()))?;
    match format {
        ExportFormat::Csv => {
            rss_export::export_csv_with(&tree, root, export_options, &mut out_file)
        }
        ExportFormat::Json => {
            rss_export::export_json_with(&tree, root, export_options, &mut out_file)
        }
    }
    .with_context(|| format!("export failed: {}", out.display()))?;

    // Human summary goes to stderr; stdout stays clean for piping (FR-9.2).
    let sizes = if logical {
        format!("{} logical total", format_bytes(summary.logical_size))
    } else {
        format!(
            "{} allocated / {} logical total",
            format_bytes(summary.allocated_size),
            format_bytes(summary.logical_size)
        )
    };
    let secs = summary.elapsed.as_secs_f64();
    let throughput = if secs > 0.0 {
        summary.entries as f64 / secs
    } else {
        summary.entries as f64
    };
    eprintln!(
        "rss: scanned {} entries ({} files, {} dirs, {} unaccessible) in {:.2?} — \
         {} ({:.0} entries/s){}",
        summary.entries,
        summary.files,
        summary.dirs,
        summary.unaccessible,
        summary.elapsed,
        sizes,
        throughput,
        if summary.cancelled {
            " [cancelled]"
        } else {
            ""
        },
    );
    if !summary.errors.is_empty() {
        eprintln!("rss: {} non-fatal scan problem(s):", summary.errors.len());
        for problem in &summary.errors {
            match &problem.path {
                Some(p) => eprintln!("  {}: {}", p.display(), problem.message),
                None => eprintln!("  {}", problem.message),
            }
        }
    }
    Ok(())
}
