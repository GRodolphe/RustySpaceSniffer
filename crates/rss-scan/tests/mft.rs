//! Privilege-gated MFT integration test (SPEC.md §5.4, FR-2.4; §11.4).
//!
//! Requires: Windows, an NTFS system volume, and elevation (volume-handle
//! open). The test is `#[ignore]`d by default; on an elevated Windows runner
//! run it explicitly with:
//!
//! ```text
//! set RSS_RUN_MFT_TESTS=1
//! cargo test -p rss-scan --test mft -- --ignored
//! ```
//!
//! It scans a synthetic temp tree with both the `MftScanner` and the
//! `WalkScanner` and asserts the two engines agree on the logical aggregate
//! and file/dir counts (allocated sizes may legitimately differ: the walker
//! reports the tempdir FS view, the MFT reports AllocationSize).

#![cfg(windows)]

use std::path::Path;

use rss_scan::{MftScanner, ScanEngine, ScanEvent, ScanOptions, WalkScanner};

fn mft_tests_enabled() -> bool {
    std::env::var_os("RSS_RUN_MFT_TESTS").is_some_and(|v| v == "1")
}

fn build_tree(root: &Path) {
    std::fs::create_dir_all(root.join("a/deep")).unwrap();
    std::fs::write(root.join("top.bin"), b"abc").unwrap();
    std::fs::write(root.join("a/a1.bin"), vec![0u8; 1000]).unwrap();
    std::fs::write(root.join("a/deep/d.bin"), vec![0u8; 4103]).unwrap();
}

#[test]
#[ignore = "privilege-gated: needs elevated Windows + NTFS; enable with RSS_RUN_MFT_TESTS=1"]
fn mft_scan_matches_walk_on_logical_aggregates() {
    if !mft_tests_enabled() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().join("root");
    build_tree(&root);

    let mut mft = MftScanner::new();
    let mut mft_events = 0u64;
    let mft_summary = mft
        .scan(&root, &ScanOptions::default(), &mut |e| {
            if matches!(e, ScanEvent::Upsert(_)) {
                mft_events += 1;
            }
        })
        .expect("MFT scan failed (running elevated on an NTFS volume?)");

    let mut walk = WalkScanner::new();
    let walk_summary = walk
        .scan(&root, &ScanOptions::default(), &mut |_| {})
        .unwrap();

    assert!(!mft_summary.cancelled);
    assert!(
        mft_summary.errors.is_empty(),
        "unexpected MFT scan errors: {:?}",
        mft_summary.errors
    );
    // Same tree, same logical bytes and entry counts.
    assert_eq!(mft_summary.logical_size, walk_summary.logical_size);
    assert_eq!(mft_summary.files, walk_summary.files);
    assert_eq!(mft_summary.dirs, walk_summary.dirs);
    assert_eq!(mft_summary.entries, walk_summary.entries);
    assert_eq!(mft_events, mft_summary.entries);
    assert!(mft_summary.allocated_size >= mft_summary.logical_size);
}

#[test]
#[ignore = "privilege-gated: needs elevated Windows + NTFS; enable with RSS_RUN_MFT_TESTS=1"]
fn mft_scan_rejects_nonexistent_root() {
    if !mft_tests_enabled() {
        return;
    }
    let mut mft = MftScanner::new();
    let err = mft
        .scan(
            Path::new(r"C:\definitely\not\a\real\rss-path"),
            &ScanOptions::default(),
            &mut |_| {},
        )
        .unwrap_err();
    assert!(matches!(err, rss_scan::ScanError::RootNotFound(_)));
}
