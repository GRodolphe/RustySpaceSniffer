//! `rss` — RustySpaceSniffer headless CLI (SPEC.md §4.9, FR-9.2).
//!
//! M1 scope (SPEC.md §12): `rss scan <PATH> --export csv|json --out <FILE>`
//! scans with the `WalkScanner` and exports the resulting tree. Exit codes:
//! 0 on success, 1 on scan/export error, 2 on usage error (clap).
//!
//! The GUI automation command set (`load`/`filter`/`save`/`autoclose`) and
//! console attachment (FR-9.3) arrive with `rss-app` in later milestones.

use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Context;
use clap::{Parser, Subcommand, ValueEnum};
use rss_export::{ExportOptions, SizeMode};

#[derive(Parser)]
#[command(
    name = "rss",
    version,
    about = "RustySpaceSniffer — disk space treemap analyzer (M1 headless CLI)"
)]
struct Cli {
    /// Run without a GUI (accepted for forward compatibility with FR-9.2;
    /// the M1 CLI is always headless).
    #[arg(long, global = true)]
    headless: bool,

    #[command(subcommand)]
    command: Commands,
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
        /// affects the human summary.
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("rss: error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let _headless = cli.headless; // M1 is always headless; flag is forward-compat.
    match cli.command {
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

/// Human-readable binary-unit size (1024-based, matching the FR-4.4 units).
fn format_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
