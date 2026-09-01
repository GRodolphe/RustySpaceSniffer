//! `.rssnap` snapshot tests (SPEC.md §5.7, §9.1, §10.1): round-trip identity
//! (model → bytes → model, including tags, filter string, zoom path, unicode
//! names), fail-closed typed errors on truncated/corrupted/bit-flipped input,
//! cap enforcement, and a garbage-feeding smoke run of the fuzz entry point
//! (the same function the `rssnap_parse` cargo-fuzz target calls).

use rss_core::{filetime_from_unix, NodeFlags, NodeId, NodeKind, NodeParams, Tag, Tree};
use rss_export::{ScanMetadata, Snapshot, SnapshotError};

const T0: i64 = 1_700_000_000; // 2023-11-14T22:13:20Z

/// A tree exercising every serialized field: all node kinds, all tag colors,
/// flags, ADS bytes, unicode names, distinct timestamps.
fn sample_tree() -> (Tree, NodeId) {
    let mut tree = Tree::with_root(
        NodeParams::named("root", NodeKind::Directory)
            .modified(filetime_from_unix(T0))
            .flags(NodeFlags::ARCHIVE),
    );
    let root = tree.root().unwrap();

    let docs = tree.add_child(
        root,
        NodeParams {
            tag: Some(Tag::Red),
            ..NodeParams::named("döcs", NodeKind::Directory).modified(filetime_from_unix(T0 + 10))
        },
    );
    tree.add_child(
        docs,
        NodeParams {
            tag: Some(Tag::Blue),
            ads_size: 512,
            created: filetime_from_unix(T0 - 1000),
            accessed: filetime_from_unix(T0 - 500),
            ..NodeParams::named("report (final), v2.txt", NodeKind::File)
                .sizes(1_000, 4_096)
                .modified(filetime_from_unix(T0 + 20))
                .flags(NodeFlags::READONLY)
        },
    );

    let uni = tree.add_child(
        root,
        NodeParams {
            tag: Some(Tag::Green),
            ..NodeParams::named("ユニコード", NodeKind::Directory)
        },
    );
    tree.add_child(
        uni,
        NodeParams::named("データ.bin", NodeKind::File)
            .sizes(2_048, 8_192)
            .modified(filetime_from_unix(T0 + 30)),
    );
    tree.add_child(
        uni,
        NodeParams::named("stream:ads", NodeKind::Ads).sizes(128, 512),
    );

    tree.add_child(
        root,
        NodeParams {
            tag: Some(Tag::Yellow),
            ..NodeParams::named("big file, with \"quotes\".bin", NodeKind::File)
                .sizes(10_000, 16_384)
        },
    );
    tree.add_child(
        root,
        NodeParams::named("free", NodeKind::FreeSpace).sizes(1 << 30, 1 << 30),
    );
    tree.add_child(
        root,
        NodeParams::named("denied", NodeKind::Unaccessible).flags(NodeFlags::ACCESS_DENIED),
    );

    (tree, root)
}

fn sample_snapshot() -> Snapshot {
    let (tree, _root) = sample_tree();
    let mut snap = Snapshot::new(
        tree,
        ScanMetadata {
            tool_version: "0.1.0-test".to_string(),
            volume_serial: 0xDEAD_BEEF,
            started: filetime_from_unix(T0),
            finished: filetime_from_unix(T0 + 60),
        },
    );
    snap.filter = "*.jpg;>1mb;|:yellow".to_string();
    snap.zoom_path = vec!["döcs".to_string()];
    snap
}

/// Iterative structural comparison of two trees (both iterate children in
/// the same order when the sibling order matches).
fn assert_trees_equal(a: &Tree, b: &Tree) {
    assert_eq!(a.len(), b.len(), "live node count");
    let mut stack = vec![(a.root(), b.root())];
    while let Some((x, y)) = stack.pop() {
        match (x, y) {
            (None, None) => {}
            (Some(x), Some(y)) => {
                let (nx, ny) = (a.node(x), b.node(y));
                assert_eq!(nx.name, ny.name, "name of {x}/{y}");
                assert_eq!(nx.kind, ny.kind);
                assert_eq!(nx.flags, ny.flags);
                assert_eq!(nx.tag, ny.tag);
                assert_eq!(nx.logical_size, ny.logical_size);
                assert_eq!(nx.allocated_size, ny.allocated_size);
                assert_eq!(nx.ads_size, ny.ads_size);
                assert_eq!(nx.agg_logical, ny.agg_logical);
                assert_eq!(nx.agg_allocated, ny.agg_allocated);
                assert_eq!(nx.agg_files, ny.agg_files);
                assert_eq!(nx.agg_dirs, ny.agg_dirs);
                assert_eq!(nx.created, ny.created);
                assert_eq!(nx.accessed, ny.accessed);
                assert_eq!(nx.modified, ny.modified);
                let cx: Vec<_> = a.children(x).collect();
                let cy: Vec<_> = b.children(y).collect();
                assert_eq!(cx.len(), cy.len(), "child count of {x}/{y}");
                stack.extend(cx.into_iter().zip(cy).map(|(a, b)| (Some(a), Some(b))));
            }
            _ => panic!("root presence mismatch"),
        }
    }
}

// ---- helpers to hand-craft valid and corrupt `.rssnap` byte streams ----

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn record(tag: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    put_varint(&mut out, tag);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn meta_record() -> Vec<u8> {
    let mut body = Vec::new();
    put_str(&mut body, "test");
    body.extend_from_slice(&42u64.to_le_bytes());
    body.extend_from_slice(&1i64.to_le_bytes());
    body.extend_from_slice(&2i64.to_le_bytes());
    record(1, &body)
}

fn filter_record(filter: &str) -> Vec<u8> {
    let mut body = Vec::new();
    put_str(&mut body, filter);
    record(2, &body)
}

fn zoom_record(components: &[&str]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&(components.len() as u32).to_le_bytes());
    for c in components {
        put_str(&mut body, c);
    }
    record(3, &body)
}

/// A minimal node record body: file named `name`, no children.
fn node_record(name: &str, children: u32) -> Vec<u8> {
    let mut body = Vec::new();
    body.push(0); // kind: file
    body.push(0); // tag: none
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes()); // flags
    body.extend_from_slice(&1u64.to_le_bytes()); // logical
    body.extend_from_slice(&1u64.to_le_bytes()); // allocated
    body.extend_from_slice(&0u64.to_le_bytes()); // ads
    body.extend_from_slice(&0i64.to_le_bytes()); // created
    body.extend_from_slice(&0i64.to_le_bytes()); // accessed
    body.extend_from_slice(&0i64.to_le_bytes()); // modified
    body.extend_from_slice(&children.to_le_bytes());
    put_str(&mut body, name);
    record(4, &body)
}

/// Wrap a payload in a header and trailer with correct checksums.
fn wrap_payload(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(b"RSSNAP\0\0");
    out.extend_from_slice(&1u16.to_le_bytes()); // version
    out.extend_from_slice(&28u16.to_le_bytes()); // header len
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    let crc32 = crc32fast::hash(&out);
    out.extend_from_slice(&crc32.to_le_bytes());
    out.extend_from_slice(payload);
    let mut crc64 = crc64fast::Digest::new();
    crc64.write(payload);
    out.extend_from_slice(&crc64.sum64().to_le_bytes());
    out
}

/// The smallest valid snapshot: meta + filter + zoom + one root node.
fn minimal_snapshot() -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.extend(node_record("root", 0));
    wrap_payload(&payload)
}

// ---- round-trip tests ----

#[test]
fn round_trip_identity() {
    let snap = sample_snapshot();
    let bytes = snap.encode().unwrap();
    let loaded = Snapshot::decode(&bytes).unwrap();

    assert_trees_equal(&snap.tree, &loaded.tree);
    assert_eq!(snap.filter, loaded.filter);
    assert_eq!(snap.zoom_path, loaded.zoom_path);
    assert_eq!(snap.meta, loaded.meta);

    // The zoom path resolves to the node with the same path.
    let zoom = loaded.zoom_root().unwrap();
    assert_eq!(&*loaded.tree.node(zoom).name, "döcs");
}

#[test]
fn round_trip_is_byte_stable() {
    let snap = sample_snapshot();
    let bytes = snap.encode().unwrap();
    let reloaded = Snapshot::decode(&bytes).unwrap().encode().unwrap();
    assert_eq!(bytes, reloaded, "decode(encode(x)).encode() == encode(x)");
}

#[test]
fn round_trip_root_only_tree() {
    let tree = Tree::with_root(NodeParams::named("only", NodeKind::Directory));
    let snap = Snapshot::new(
        tree,
        ScanMetadata {
            tool_version: String::new(),
            volume_serial: 0,
            started: 0,
            finished: 0,
        },
    );
    let loaded = Snapshot::decode(&snap.encode().unwrap()).unwrap();
    assert_trees_equal(&snap.tree, &loaded.tree);
    assert_eq!(loaded.filter, "");
    assert!(loaded.zoom_path.is_empty());
    assert_eq!(loaded.zoom_root(), loaded.tree.root());
}

#[test]
fn round_trip_deep_and_wide() {
    let mut tree = Tree::with_root(NodeParams::named("root", NodeKind::Directory));
    let mut parent = tree.root().unwrap();
    for i in 0..300 {
        parent = tree.add_child(
            parent,
            NodeParams::named(format!("level-{i}"), NodeKind::Directory),
        );
        for j in 0..5 {
            tree.add_child(
                parent,
                NodeParams::named(format!("file-{j}"), NodeKind::File).sizes(j as u64, j as u64),
            );
        }
    }
    let snap = Snapshot::new(
        tree,
        ScanMetadata {
            tool_version: "t".into(),
            volume_serial: 0,
            started: 0,
            finished: 0,
        },
    );
    let loaded = Snapshot::decode(&snap.encode().unwrap()).unwrap();
    assert_trees_equal(&snap.tree, &loaded.tree);
}

#[test]
fn round_trip_io_helpers() {
    let snap = sample_snapshot();
    let mut file = tempfile::tempfile().unwrap();
    snap.write_to(&mut file).unwrap();
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0)).unwrap();
    let loaded = Snapshot::read_from(&mut file).unwrap();
    assert_trees_equal(&snap.tree, &loaded.tree);
}

#[test]
fn encode_empty_tree_is_typed_error() {
    let snap = Snapshot::new(
        Tree::new(),
        ScanMetadata {
            tool_version: String::new(),
            volume_serial: 0,
            started: 0,
            finished: 0,
        },
    );
    assert!(matches!(snap.encode(), Err(SnapshotError::EmptyTree)));
}

// ---- header/trailer corruption ----

#[test]
fn empty_and_short_inputs_are_typed_errors() {
    assert!(matches!(
        Snapshot::decode(&[]),
        Err(SnapshotError::TooShort { .. })
    ));
    for len in 1..36 {
        assert!(
            matches!(
                Snapshot::decode(&vec![0u8; len]),
                Err(SnapshotError::TooShort { .. } | SnapshotError::BadMagic)
            ),
            "len {len}"
        );
    }
}

#[test]
fn bad_magic() {
    let mut bytes = minimal_snapshot();
    bytes[0] = b'X';
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::BadMagic)
    ));
}

#[test]
fn unsupported_version() {
    let mut bytes = minimal_snapshot();
    bytes[8..10].copy_from_slice(&2u16.to_le_bytes());
    // Fix the header CRC so the version check is what fires... actually the
    // version is checked before the CRC, so no fixup needed.
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::UnsupportedVersion(2))
    ));
}

#[test]
fn bad_header_length() {
    let mut bytes = minimal_snapshot();
    bytes[10..12].copy_from_slice(&20u16.to_le_bytes());
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::BadHeaderLength(20))
    ));
}

#[test]
fn unsupported_flags() {
    let mut bytes = minimal_snapshot();
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::UnsupportedFlags(1))
    ));
}

#[test]
fn header_crc_mismatch() {
    let mut bytes = minimal_snapshot();
    // Corrupt the stored header CRC32 (last 4 header bytes).
    bytes[27] ^= 0x01;
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::HeaderCrcMismatch { .. })
    ));
}

#[test]
fn payload_too_large() {
    let mut bytes = minimal_snapshot();
    // Announce a 2 GiB payload and fix the header CRC so the cap check fires.
    bytes[16..24].copy_from_slice(&(2u64 << 30).to_le_bytes());
    let crc = crc32fast::hash(&bytes[..24]);
    bytes[24..28].copy_from_slice(&crc.to_le_bytes());
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::PayloadTooLarge(_))
    ));
}

#[test]
fn payload_length_mismatch_on_appended_garbage() {
    let mut bytes = minimal_snapshot();
    bytes.extend_from_slice(b"garbage");
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::PayloadLengthMismatch { .. })
    ));
}

#[test]
fn payload_crc_mismatch() {
    let mut bytes = minimal_snapshot();
    // Flip a payload byte (header is 28 bytes).
    bytes[30] ^= 0x40;
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::PayloadCrcMismatch { .. })
    ));
}

#[test]
fn truncation_never_panics_and_always_errors() {
    let bytes = sample_snapshot().encode().unwrap();
    for len in 0..bytes.len() {
        assert!(
            Snapshot::decode(&bytes[..len]).is_err(),
            "truncated to {len} bytes must fail"
        );
    }
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let bytes = minimal_snapshot();
    for i in 0..bytes.len() {
        for bit in 0..8 {
            let mut mutated = bytes.clone();
            mutated[i] ^= 1 << bit;
            assert!(
                Snapshot::decode(&mutated).is_err(),
                "bit flip at byte {i} bit {bit} must fail (checksumming is whole-file)"
            );
        }
    }
}

// ---- record-stream corruption ----

#[test]
fn unknown_record_type() {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.extend(record(99, b"x"));
    payload.extend(node_record("root", 0));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(
        err,
        SnapshotError::UnknownRecordType { tag: 99, .. }
    ));
}

#[test]
fn record_overrun_is_checked_before_read() {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    // Node record announcing 1000 bytes with only a few remaining.
    payload.push(4); // type tag
    payload.extend_from_slice(&1000u32.to_le_bytes());
    payload.extend_from_slice(b"tiny");
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::RecordOverrun { .. }));
}

#[test]
fn record_length_cap() {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.push(4);
    payload.extend_from_slice(&(65u32 << 20).to_le_bytes()); // 65 MiB > 64 MiB cap
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::RecordTooLarge { .. }));
}

#[test]
fn malformed_varint() {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    // 11 continuation bytes: not a valid u64 LEB128.
    payload.extend(std::iter::repeat_n(0x80, 11));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::MalformedVarint(_)));
}

#[test]
fn missing_meta_record() {
    let mut payload = Vec::new();
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.extend(node_record("root", 0));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::MissingRecord("meta")));
}

#[test]
fn duplicate_meta_record() {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.extend(node_record("root", 0));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::DuplicateRecord("meta")));
}

#[test]
fn nodes_before_zoom_path_rejected() {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(node_record("root", 0));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::MissingRecord(_)));
}

#[test]
fn trailing_bytes_in_record() {
    let mut body = Vec::new();
    put_str(&mut body, "test");
    body.extend_from_slice(&42u64.to_le_bytes());
    body.extend_from_slice(&1i64.to_le_bytes());
    body.extend_from_slice(&2i64.to_le_bytes());
    body.push(0); // one unexplained trailing byte
    let mut payload = record(1, &body);
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.extend(node_record("root", 0));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(
        err,
        SnapshotError::TrailingBytes {
            record: "meta",
            len: 1,
            ..
        }
    ));
}

#[test]
fn string_length_cap_checked_before_allocation() {
    // Filter record announcing a 2 MiB string (cap 1 MiB) in a tiny record.
    let mut body = Vec::new();
    body.extend_from_slice(&(2u32 << 20).to_le_bytes());
    body.extend_from_slice(b"nope");
    let mut payload = meta_record();
    payload.extend(record(2, &body));
    payload.extend(zoom_record(&[]));
    payload.extend(node_record("root", 0));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(
        err,
        SnapshotError::StringTooLong {
            field: "filter",
            ..
        }
    ));
}

#[test]
fn invalid_utf8_name() {
    let mut body = Vec::new();
    body.push(0); // kind file
    body.push(0); // tag none
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&[0u8; 52]); // flags(4) + sizes(3*8) + times(3*8)
    body.extend_from_slice(&0u32.to_le_bytes()); // children
    body.extend_from_slice(&1u32.to_le_bytes()); // name len
    body.push(0xFF); // invalid UTF-8
    let mut payload = meta_record();
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.extend(record(4, &body));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(
        err,
        SnapshotError::InvalidUtf8 { field: "name", .. }
    ));
}

#[test]
fn invalid_node_kind_and_tag() {
    for (kind, tag) in [(42u8, 0u8), (0, 9)] {
        let mut body = Vec::new();
        body.push(kind);
        body.push(tag);
        body.extend_from_slice(&0u16.to_le_bytes());
        body.extend_from_slice(&[0u8; 52]); // flags(4) + sizes(3*8) + times(3*8)
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u32.to_le_bytes());
        let mut payload = meta_record();
        payload.extend(filter_record(""));
        payload.extend(zoom_record(&[]));
        payload.extend(record(4, &body));
        let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
        if kind == 42 {
            assert!(matches!(
                err,
                SnapshotError::InvalidNodeKind { kind: 42, .. }
            ));
        } else {
            assert!(matches!(err, SnapshotError::InvalidTag { tag: 9, .. }));
        }
    }
}

#[test]
fn declared_children_missing() {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.extend(node_record("root", 1)); // declares one child, none follows
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::MalformedNodeStream(_)));
}

#[test]
fn second_root_rejected() {
    let mut payload = Vec::new();
    payload.extend(meta_record());
    payload.extend(filter_record(""));
    payload.extend(zoom_record(&[]));
    payload.extend(node_record("root", 0));
    payload.extend(node_record("second", 0));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::MalformedNodeStream(_)));
}

#[test]
fn depth_cap_enforced_iteratively() {
    // 600-deep chain encodes fine (encoder input is trusted); the decoder
    // must reject it at the 512 depth cap without unbounded recursion.
    let mut tree = Tree::with_root(NodeParams::named("d", NodeKind::Directory));
    let mut parent = tree.root().unwrap();
    for _ in 0..600 {
        parent = tree.add_child(parent, NodeParams::named("d", NodeKind::Directory));
    }
    let snap = Snapshot::new(
        tree,
        ScanMetadata {
            tool_version: String::new(),
            volume_serial: 0,
            started: 0,
            finished: 0,
        },
    );
    let bytes = snap.encode().unwrap();
    assert!(matches!(
        Snapshot::decode(&bytes),
        Err(SnapshotError::DepthCapExceeded)
    ));
}

#[test]
fn zoom_path_component_cap_checked_before_allocation() {
    let mut body = Vec::new();
    body.extend_from_slice(&10_000_000u32.to_le_bytes()); // > 4096 cap
    let mut payload = meta_record();
    payload.extend(filter_record(""));
    payload.extend(record(3, &body));
    payload.extend(node_record("root", 0));
    let err = Snapshot::decode(&wrap_payload(&payload)).unwrap_err();
    assert!(matches!(err, SnapshotError::ZoomTooDeep(10_000_000)));
}

// ---- fuzz-entry smoke test (same code as the cargo-fuzz target) ----

/// Deterministic xorshift so the test is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

#[test]
fn rssnap_parse_garbage_never_panics() {
    let mut rng = Rng(0x1234_5678_9abc_def0);
    // Pure garbage of varying lengths.
    for _ in 0..2_000 {
        let len = (rng.next() % 600) as usize;
        let mut buf = vec![0u8; len];
        for b in &mut buf {
            *b = rng.next() as u8;
        }
        rss_export::fuzzing::rssnap_parse(&buf);
    }
    // Mutations of a valid snapshot: random byte flips and truncations.
    let valid = sample_snapshot().encode().unwrap();
    for _ in 0..2_000 {
        let mut buf = valid.clone();
        match rng.next() % 3 {
            0 => {
                let flips = (rng.next() % 8 + 1) as usize;
                for _ in 0..flips {
                    let i = (rng.next() as usize) % buf.len();
                    buf[i] ^= rng.next() as u8;
                }
            }
            1 => {
                buf.truncate((rng.next() as usize) % buf.len());
            }
            _ => {
                let i = (rng.next() as usize) % buf.len();
                buf.insert(i, rng.next() as u8);
            }
        }
        rss_export::fuzzing::rssnap_parse(&buf);
    }
    // Decoding must succeed on a prefix that happens to be the full file.
    assert!(Snapshot::decode(&valid).is_ok());
}
