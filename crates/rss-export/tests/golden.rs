//! Golden-fixture tests (SPEC.md §10.2): synthetic trees built with rss-core
//! (no filesystem), byte-exact CSV output, JSON round-trip structure.
//!
//! Fixture coverage for M1: unicode names, zero-byte files, commas/quotes in
//! names, ADS roll-up into allocated size, depth-first sibling ordering by
//! descending size.

use rss_core::{filetime_from_unix, NodeKind, NodeParams, Tree};
use rss_export::{export_csv, export_csv_with, export_json, ExportOptions, SizeMode};

const T0: i64 = 1_700_000_000; // 2023-11-14T22:13:20Z

/// Build the golden fixture tree (all sibling sizes distinct, so the expected
/// order does not depend on tie-breaking):
///
/// ```text
/// root/                            (dir)
/// ├── big.bin                      10_000 logical / 16_384 allocated
/// ├── ユニコード/                   (dir)
/// │   └── データ.bin                2_048 / 8_192
/// └── docs/                        (dir)
///     ├── report,final.txt          1_000 / 4_096
///     └── say "hi".txt              0 / 0 (zero-byte)
/// ```
fn golden_tree() -> (Tree, rss_core::NodeId) {
    let mut tree = Tree::with_root(
        NodeParams::named("root", NodeKind::Directory).modified(filetime_from_unix(T0)),
    );
    let root = tree.root().unwrap();

    let docs = tree.add_child(
        root,
        NodeParams::named("docs", NodeKind::Directory).modified(filetime_from_unix(T0 + 200)),
    );
    tree.add_child(
        docs,
        NodeParams::named("report,final.txt", NodeKind::File)
            .sizes(1_000, 4_096)
            .modified(filetime_from_unix(T0 + 300)),
    );
    tree.add_child(
        docs,
        NodeParams::named("say \"hi\".txt", NodeKind::File)
            .sizes(0, 0)
            .modified(filetime_from_unix(T0 + 400)),
    );

    let unicode = tree.add_child(
        root,
        NodeParams::named("ユニコード", NodeKind::Directory).modified(filetime_from_unix(T0 + 500)),
    );
    tree.add_child(
        unicode,
        NodeParams::named("データ.bin", NodeKind::File)
            .sizes(2_048, 8_192)
            .modified(filetime_from_unix(T0 + 600)),
    );

    tree.add_child(
        root,
        NodeParams::named("big.bin", NodeKind::File)
            .sizes(10_000, 16_384)
            .modified(filetime_from_unix(T0 + 100)),
    );

    (tree, root)
}

const GOLDEN_CSV: &str =
    "\u{FEFF}path,name,kind,logical_size,allocated_size,files,dirs,modified\r\n\
root,root,directory,13048,28672,4,3,2023-11-14T22:13:20Z\r\n\
root/big.bin,big.bin,file,10000,16384,1,0,2023-11-14T22:15:00Z\r\n\
root/ユニコード,ユニコード,directory,2048,8192,1,1,2023-11-14T22:21:40Z\r\n\
root/ユニコード/データ.bin,データ.bin,file,2048,8192,1,0,2023-11-14T22:23:20Z\r\n\
root/docs,docs,directory,1000,4096,2,1,2023-11-14T22:16:40Z\r\n\
\"root/docs/report,final.txt\",\"report,final.txt\",file,1000,4096,1,0,2023-11-14T22:18:20Z\r\n\
\"root/docs/say \"\"hi\"\".txt\",\"say \"\"hi\"\".txt\",file,0,0,1,0,2023-11-14T22:20:00Z\r\n";

#[test]
fn csv_byte_exact_golden() {
    let (tree, root) = golden_tree();
    let mut out = Vec::new();
    export_csv(&tree, root, &mut out).unwrap();
    let actual = String::from_utf8(out).unwrap();
    assert_eq!(actual, GOLDEN_CSV);
}

#[test]
fn csv_size_mode_logical_changes_sibling_order() {
    let (tree, root) = golden_tree();
    let mut out = Vec::new();
    export_csv_with(
        &tree,
        root,
        ExportOptions {
            size_mode: SizeMode::Logical,
        },
        &mut out,
    )
    .unwrap();
    let text = String::from_utf8(out).unwrap();
    let rows: Vec<&str> = text.lines().collect();
    // Logical sizes: big.bin 10_000, ユニコード 2_048, docs 1_000.
    // Row 0 is the header, row 1 the root.
    assert!(rows[2].starts_with("root/big.bin,"));
    assert!(rows[3].starts_with("root/ユニコード,"));
    assert!(rows[5].starts_with("root/docs,"));
}

#[test]
fn sibling_ties_keep_tree_child_order() {
    // The sort is stable: equal-sized siblings keep the order the tree's
    // child iterator yields (most recently added first).
    let mut tree = Tree::with_root(NodeParams::named("root", NodeKind::Directory));
    let root = tree.root().unwrap();
    for name in ["a", "b", "c"] {
        tree.add_child(
            root,
            NodeParams::named(name, NodeKind::File).sizes(100, 100),
        );
    }
    let mut out = Vec::new();
    export_csv(&tree, root, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let names: Vec<&str> = text
        .lines()
        .skip(2) // header + root
        .map(|row| row.split(',').nth(1).unwrap())
        .collect();
    assert_eq!(names, ["c", "b", "a"]);
}

#[test]
fn csv_allocated_size_includes_ads() {
    let mut tree = Tree::with_root(NodeParams::named("root", NodeKind::Directory));
    let root = tree.root().unwrap();
    let mut params = NodeParams::named("streamed.dat", NodeKind::File);
    params.logical_size = 4_096;
    params.allocated_size = 4_096;
    params.ads_size = 2_048;
    tree.add_child(root, params);

    let mut out = Vec::new();
    export_csv(&tree, root, &mut out).unwrap();
    let text = String::from_utf8(out).unwrap();
    let row = text.lines().nth(2).unwrap();
    // allocated_size = 4_096 own + 2_048 ADS = 6_144. A default-constructed
    // FileTime of 0 is the FILETIME epoch, 1601-01-01.
    assert_eq!(
        row,
        "root/streamed.dat,streamed.dat,file,4096,6144,1,0,1601-01-01T00:00:00Z"
    );
}

#[test]
fn json_round_trip_structure() {
    let (tree, root) = golden_tree();
    let mut out = Vec::new();
    export_json(&tree, root, &mut out).unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();

    // Root fields.
    assert_eq!(doc["name"], "root");
    assert_eq!(doc["path"], "root");
    assert_eq!(doc["kind"], "directory");
    assert_eq!(doc["logical_size"], 13_048);
    assert_eq!(doc["allocated_size"], 28_672);
    assert_eq!(doc["files"], 4);
    assert_eq!(doc["dirs"], 3);
    assert_eq!(doc["modified"], "2023-11-14T22:13:20Z");

    // Children sorted by descending allocated size.
    let children = doc["children"].as_array().unwrap();
    let names: Vec<&str> = children
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["big.bin", "ユニコード", "docs"]);

    // Nested structure; comma/quote and unicode names intact.
    let docs = &children[2];
    assert_eq!(docs["path"], "root/docs");
    let docs_children = docs["children"].as_array().unwrap();
    let docs_names: Vec<&str> = docs_children
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(docs_names, ["report,final.txt", "say \"hi\".txt"]);
    assert_eq!(docs_children[1]["logical_size"], 0);
    assert_eq!(docs_children[1]["allocated_size"], 0);

    let data = &children[1]["children"][0];
    assert_eq!(data["name"], "データ.bin");
    assert_eq!(data["path"], "root/ユニコード/データ.bin");
    assert_eq!(data["children"].as_array().unwrap().len(), 0);
}

#[test]
fn json_size_mode_logical_changes_sibling_order() {
    let (tree, root) = golden_tree();
    let mut out = Vec::new();
    rss_export::export_json_with(
        &tree,
        root,
        ExportOptions {
            size_mode: SizeMode::Logical,
        },
        &mut out,
    )
    .unwrap();
    let doc: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let children = doc["children"].as_array().unwrap();
    let names: Vec<&str> = children
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["big.bin", "ユニコード", "docs"]);
}

#[test]
fn invalid_root_is_typed_error() {
    let (tree, _root) = golden_tree();
    let err = export_csv(&tree, 999, Vec::new()).unwrap_err();
    assert!(matches!(err, rss_export::ExportError::InvalidRoot(999)));

    let empty = Tree::new();
    let err = export_json(&empty, 0, Vec::new()).unwrap_err();
    assert!(matches!(err, rss_export::ExportError::InvalidRoot(0)));
}

#[test]
fn deep_nesting_does_not_overflow() {
    // A 5k-deep chain: iterative traversal and path building must not
    // overflow the call stack or blow up quadratically.
    let mut tree = Tree::with_root(NodeParams::named("d", NodeKind::Directory));
    let mut parent = tree.root().unwrap();
    for _ in 1..5_000 {
        parent = tree.add_child(parent, NodeParams::named("d", NodeKind::Directory));
    }
    let root = tree.root().unwrap();
    // Run on a thread with a large stack: our traversal is iterative, but
    // serde_json's serializer and the nested document's Drop glue recurse
    // once per nesting level.
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let mut csv_out = Vec::new();
            export_csv(&tree, root, &mut csv_out).unwrap();
            assert_eq!(csv_out.iter().filter(|&&b| b == b'\n').count(), 5_001);
            let mut json_out = Vec::new();
            export_json(&tree, root, &mut json_out).unwrap();
            assert!(json_out.starts_with(b"{"));
        })
        .unwrap()
        .join()
        .unwrap();
}
