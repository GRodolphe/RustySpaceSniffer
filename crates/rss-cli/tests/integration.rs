//! End-to-end integration tests (SPEC.md §10.3, §12 M1):
//! a synthetic filesystem tree is scanned with the WalkScanner and compared
//! against independently computed ground truth, and the `rss` binary is run
//! as a subprocess to validate the CLI + CSV export path.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use rss_core::{NodeFlags, NodeId, NodeKind, Tree};

/// Independently computed ground truth for the synthetic tree, using the
/// mapping rules of SPEC.md §5.2/§7.1 (sequential std::fs walk — a
/// deliberately different implementation from the parallel scanner).
#[derive(Default)]
struct Truth {
    logical: u64,
    allocated: u64,
    files: u64,
    dirs: u64,
    aliases: u64,
}

#[cfg(unix)]
fn measure(root: &Path) -> Truth {
    let mut truth = Truth::default();
    let mut seen: HashSet<(u64, u64)> = HashSet::new();
    fn visit(path: &Path, truth: &mut Truth, seen: &mut HashSet<(u64, u64)>) {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::symlink_metadata(path).unwrap();
        let ft = md.file_type();
        if ft.is_dir() {
            truth.dirs += 1; // directories carry no own size
            for entry in std::fs::read_dir(path).unwrap() {
                visit(&entry.unwrap().path(), truth, seen);
            }
        } else {
            truth.files += 1; // symlinks count as files; targets not followed
            let mut logical = md.len();
            let mut allocated = md.blocks() * 512;
            if ft.is_file() && md.nlink() > 1 && !seen.insert((md.dev(), md.ino())) {
                truth.aliases += 1;
                logical = 0;
                allocated = 0;
            }
            truth.logical += logical;
            truth.allocated += allocated;
        }
    }
    visit(root, &mut truth, &mut seen);
    truth
}

/// Build the synthetic tree. Returns paths of interest.
fn build_synthetic_tree(base: &Path) -> TreeFixture {
    let root = base.join("root");
    std::fs::create_dir_all(root.join("a")).unwrap();
    std::fs::create_dir_all(root.join("b/deep")).unwrap();
    std::fs::write(root.join("top.bin"), b"abc").unwrap();
    std::fs::write(root.join("a/a1.bin"), vec![0u8; 1000]).unwrap();
    std::fs::write(root.join("a/a2.bin"), vec![0u8; 2000]).unwrap();
    std::fs::write(root.join("b/deep/d.bin"), vec![0u8; 4103]).unwrap();

    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("a", root.join("link_to_a")).unwrap();
        // Hardlinks are best-effort: some filesystems disallow them.
        let _ = std::fs::hard_link(root.join("top.bin"), root.join("alias.bin"));
    }

    TreeFixture { root }
}

struct TreeFixture {
    root: PathBuf,
}

/// Find a node by its file name (first match, depth-first).
fn find_by_name(tree: &Tree, name: &str) -> Option<NodeId> {
    let mut stack: Vec<NodeId> = tree.root().into_iter().collect();
    while let Some(id) = stack.pop() {
        if &*tree.node(id).name == name {
            return Some(id);
        }
        stack.extend(tree.children(id));
    }
    None
}

#[test]
#[cfg(unix)]
fn walk_scan_matches_ground_truth() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = build_synthetic_tree(tmp.path());
    let truth = measure(&fixture.root);

    let (tree, summary) =
        rss_scan::scan_tree(&fixture.root, &rss_scan::ScanOptions::default()).unwrap();
    let root = tree.root().unwrap();
    let node = tree.node(root);

    // Logical aggregates must match exactly; allocated aggregates use the
    // same st_blocks*512 rule, so they too are exact (well within cluster
    // rounding).
    assert_eq!(node.agg_logical, truth.logical, "logical aggregate");
    assert_eq!(node.agg_allocated, truth.allocated, "allocated aggregate");
    assert!(
        node.agg_allocated >= node.agg_logical,
        "allocated must cover logical (cluster rounding)"
    );
    assert_eq!(node.agg_files, truth.files, "file count");
    assert_eq!(node.agg_dirs, truth.dirs, "dir count");
    assert_eq!(summary.entries, truth.files + truth.dirs);
    assert!(!summary.cancelled);
    assert!(
        summary.errors.is_empty(),
        "unexpected scan errors: {:?}",
        summary.errors
    );

    // Hardlink: exactly one of the two links is a 0-size alias; which one is
    // nondeterministic (parallel walk order).
    assert_eq!(truth.aliases, 1, "fixture expected one hardlink alias");
    let links: Vec<_> = ["top.bin", "alias.bin"]
        .iter()
        .map(|name| find_by_name(&tree, name).expect("link node"))
        .collect();
    let aliases: Vec<_> = links
        .iter()
        .filter(|id| tree.node(**id).flags.contains(NodeFlags::HARDLINK_ALIAS))
        .collect();
    assert_eq!(aliases.len(), 1, "exactly one hardlink alias");
    assert_eq!(tree.node(*aliases[0]).logical_size, 0);
    assert_eq!(tree.node(*aliases[0]).allocated_size, 0);
    let primary = links.iter().find(|id| *id != aliases[0]).unwrap();
    assert_eq!(
        tree.node(*primary).logical_size,
        3,
        "first link counts full size"
    );

    // Symlink: counted as a marked file node, target never traversed.
    let link = find_by_name(&tree, "link_to_a").expect("link_to_a node");
    let link_node = tree.node(link);
    assert_eq!(link_node.kind, NodeKind::File);
    assert!(link_node.flags.contains(NodeFlags::REPARSE_POINT));
    assert_eq!(link_node.logical_size, 1, "link target string length");
    assert!(
        find_by_name(&tree, "link_to_a")
            .map(|id| tree.children(id).next().is_none())
            .unwrap_or(false),
        "symlink must have no children"
    );
}

#[test]
fn cli_scan_csv_export() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = build_synthetic_tree(tmp.path());
    let out = tmp.path().join("report.csv");

    let status = Command::new(env!("CARGO_BIN_EXE_rss"))
        .args([
            "scan".as_ref(),
            fixture.root.as_os_str(),
            "--export".as_ref(),
            "csv".as_ref(),
            "--out".as_ref(),
            out.as_os_str(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "csv export must exit 0");

    let bytes = std::fs::read(&out).unwrap();
    assert!(
        bytes.starts_with(b"\xEF\xBB\xBF"),
        "CSV must start with a UTF-8 BOM (FR-8.4)"
    );
    let text = String::from_utf8(bytes).unwrap();
    assert!(
        text.contains("\r\n"),
        "CSV records must be CRLF-terminated (RFC 4180)"
    );
    // str::lines strips the \r of CRLF endings.
    let mut lines = text.lines();
    assert_eq!(
        lines.next().unwrap(),
        "\u{feff}path,name,kind,logical_size,allocated_size,files,dirs,modified"
    );
    let rows: Vec<&str> = lines.collect();
    let find = |name: &str| {
        rows.iter()
            .find(|row| row.split(',').next().is_some_and(|p| p.ends_with(name)))
            .copied()
            .unwrap_or_else(|| panic!("no CSV row for {name}; rows: {rows:?}"))
    };
    // a/a1.bin: logical size 1000.
    let row = find("a1.bin");
    let fields: Vec<&str> = row.split(',').collect();
    assert_eq!(fields[2], "file");
    assert_eq!(fields[3], "1000");
    // Directory "a" aggregates a1.bin + a2.bin = 3000 logical bytes.
    let row = find("/a");
    let fields: Vec<&str> = row.split(',').collect();
    assert_eq!(fields[2], "directory");
    assert_eq!(fields[3], "3000");
}

#[test]
fn cli_spec_form_with_headless_flag_and_json() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = build_synthetic_tree(tmp.path());
    let out = tmp.path().join("report.json");

    // SPEC.md §12 M1 syntax: `rss --headless scan <dir> --export json out.json`.
    let status = Command::new(env!("CARGO_BIN_EXE_rss"))
        .args([
            "--headless".as_ref(),
            "scan".as_ref(),
            fixture.root.as_os_str(),
            "--export".as_ref(),
            "json".as_ref(),
            out.as_os_str(),
        ])
        .status()
        .unwrap();
    assert!(status.success(), "spec-form json export must exit 0");

    let text = std::fs::read_to_string(&out).unwrap();
    // rss-export emits pretty-printed JSON with RFC 3339 timestamps.
    assert!(text.contains("\"kind\": \"directory\""));
    assert!(text.contains("\"logical_size\": 1000"));
    assert!(text.contains("\"modified\": \""));
    assert_eq!(text.matches('{').count(), text.matches('}').count());
    assert_eq!(text.matches('[').count(), text.matches(']').count());
}

#[test]
fn cli_exit_codes() {
    let tmp = tempfile::tempdir().unwrap();
    let fixture = build_synthetic_tree(tmp.path());

    // Usage error (missing required args) -> 2.
    let status = Command::new(env!("CARGO_BIN_EXE_rss"))
        .arg("scan")
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));

    // Usage error (no output file) -> 2.
    let status = Command::new(env!("CARGO_BIN_EXE_rss"))
        .args([
            "scan".as_ref(),
            fixture.root.as_os_str(),
            "--export".as_ref(),
            "csv".as_ref(),
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(2));

    // Scan error (root does not exist) -> 1.
    let status = Command::new(env!("CARGO_BIN_EXE_rss"))
        .args([
            "scan".as_ref(),
            tmp.path().join("no/such/dir").as_os_str(),
            "--export".as_ref(),
            "csv".as_ref(),
            "--out".as_ref(),
            tmp.path().join("x.csv").as_os_str(),
        ])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(1));
}
