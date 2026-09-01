//! `.rssnap` binary snapshot format (SPEC.md §5.7, FR-8.7/FR-8.8).
//!
//! Layout (all integers little-endian):
//!
//! ```text
//! Header (28 bytes in v1):
//!   [0..8]   magic "RSSNAP\0"
//!   [8..10]  u16 format version (1)
//!   [10..12] u16 header length in bytes (>= 28, room for future extension)
//!   [12..16] u32 flags (must be 0 in v1)
//!   [16..24] u64 total payload length in bytes
//!   [24..28] u32 CRC32 (crc32fast) of header bytes [0..header_len-4]
//! Payload: sequence of records, each `varint type_tag + u32 length + bytes`:
//!   1 = Meta      (tool version, volume serial, scan start/finish FileTimes)
//!   2 = Filter    (the view's active filter string, may be empty)
//!   3 = ZoomPath  (component count + length-prefixed UTF-8 names)
//!   4 = Node      (fixed-size fields + length-prefixed UTF-8 name)
//!   Meta, Filter, ZoomPath appear exactly once, in this order, before the
//!   node records. The first node record is the root; children follow in
//!   pre-order, each node announcing its child count.
//! Trailer: u64 CRC64 (crc64fast, CRC-64/XZ) of the whole payload.
//! ```
//!
//! Parser hardening per SPEC.md §9.1 (the CVE-2026-26738 lesson): every length
//! is validated against the remaining buffer *before* any allocation, record
//! and total allocation caps apply, tree depth is capped and decoded
//! iteratively (never by recursion into untrusted depth), and the whole
//! payload is checksummed. The parser never panics on adversarial input; all
//! failures are typed [`SnapshotError`]s and loading fails closed.

use std::io::Write;

use rss_core::{FileTime, NodeFlags, NodeId, NodeKind, NodeParams, Tag, Tree};

/// Magic bytes at the start of every `.rssnap` file (SPEC.md §5.7: 8-byte
/// magic `RSSNAP\0`; padded to 8 bytes with a second NUL).
pub const MAGIC: &[u8; 8] = b"RSSNAP\0\0";
/// The only format version this crate reads and writes.
pub const FORMAT_VERSION: u16 = 1;

const HEADER_LEN: u16 = 28;
const MIN_HEADER_LEN: u16 = 28;
const MAX_HEADER_LEN: u16 = 4096;
const TRAILER_LEN: usize = 8;

/// Cap on the total payload length announced in the header.
pub const MAX_PAYLOAD_LEN: u64 = 1 << 30; // 1 GiB
/// Cap on a single record's length.
pub const MAX_RECORD_LEN: u32 = 64 << 20; // 64 MiB
/// Cap on a node name's UTF-8 length.
pub const MAX_NAME_LEN: usize = 64 << 10; // 64 KiB
/// Cap on free-form strings (filter, tool version).
pub const MAX_STRING_LEN: usize = 1 << 20; // 1 MiB
/// Cap on the number of zoom-path components.
pub const MAX_ZOOM_COMPONENTS: u32 = 4096;
/// Cap on tree depth; enforced iteratively during decode.
pub const MAX_DEPTH: usize = 512;
/// Cap on the total number of node records.
pub const MAX_NODES: u64 = 50_000_000;

mod record_type {
    pub const META: u64 = 1;
    pub const FILTER: u64 = 2;
    pub const ZOOM_PATH: u64 = 3;
    pub const NODE: u64 = 4;
}

/// Errors produced by `.rssnap` save/load. Every corruption of the input maps
/// to a typed variant; the parser never panics.
#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    /// Writing to or reading from an I/O sink failed.
    #[error("I/O error during snapshot handling: {0}")]
    Io(#[from] std::io::Error),
    /// The buffer is shorter than the smallest possible snapshot.
    #[error("snapshot too short: {len} bytes, need at least {need}")]
    TooShort {
        /// Bytes actually available.
        len: usize,
        /// Bytes required to proceed.
        need: usize,
    },
    /// The leading 8 bytes are not `RSSNAP\0`.
    #[error("bad magic bytes (not an .rssnap file)")]
    BadMagic,
    /// The format version is not supported by this build.
    #[error("unsupported snapshot format version {0}")]
    UnsupportedVersion(u16),
    /// The header length field is out of range.
    #[error("invalid header length {0}")]
    BadHeaderLength(u16),
    /// v1 requires the flags field to be zero.
    #[error("unsupported header flags 0x{0:08x}")]
    UnsupportedFlags(u32),
    /// The header CRC32 does not match the header bytes.
    #[error("header CRC32 mismatch: stored 0x{stored:08x}, computed 0x{computed:08x}")]
    HeaderCrcMismatch {
        /// CRC stored in the header.
        stored: u32,
        /// CRC computed over the header bytes.
        computed: u32,
    },
    /// The payload length announced in the header exceeds the cap.
    #[error("payload length {0} exceeds cap of {MAX_PAYLOAD_LEN} bytes")]
    PayloadTooLarge(u64),
    /// The payload length in the header does not match the file size.
    #[error("payload length mismatch: header announces {announced} bytes, file holds {actual}")]
    PayloadLengthMismatch {
        /// Length from the header.
        announced: u64,
        /// Length derived from the buffer size.
        actual: u64,
    },
    /// The trailing CRC64 does not match the payload bytes.
    #[error("payload CRC64 mismatch: stored 0x{stored:016x}, computed 0x{computed:016x}")]
    PayloadCrcMismatch {
        /// CRC stored in the trailer.
        stored: u64,
        /// CRC computed over the payload.
        computed: u64,
    },
    /// A record type tag varint is malformed (truncated or overlong).
    #[error("malformed varint at payload offset {0}")]
    MalformedVarint(usize),
    /// A record type tag is not known to format version 1.
    #[error("unknown record type {tag} at payload offset {offset}")]
    UnknownRecordType {
        /// Payload offset of the record's type tag.
        offset: usize,
        /// The unknown type tag value.
        tag: u64,
    },
    /// A record length exceeds the per-record cap.
    #[error("record at payload offset {offset} is {len} bytes, exceeding the {cap}-byte cap")]
    RecordTooLarge {
        /// Payload offset of the record's type tag.
        offset: usize,
        /// Announced record length.
        len: u32,
        /// The per-record cap.
        cap: u32,
    },
    /// A record length exceeds the bytes remaining in the payload.
    #[error("record at payload offset {offset} announces {len} bytes, only {remaining} remain")]
    RecordOverrun {
        /// Payload offset of the record's type tag.
        offset: usize,
        /// Announced record length.
        len: u32,
        /// Bytes left in the payload.
        remaining: usize,
    },
    /// A record ends before one of its fields is complete.
    #[error("{record} record at payload offset {offset}: truncated while reading {field}")]
    TruncatedField {
        /// Record kind name.
        record: &'static str,
        /// Payload offset of the record's type tag.
        offset: usize,
        /// Field that could not be read.
        field: &'static str,
    },
    /// A record has bytes left over after all its fields were read.
    #[error("{record} record at payload offset {offset} has {len} trailing bytes")]
    TrailingBytes {
        /// Record kind name.
        record: &'static str,
        /// Payload offset of the record's type tag.
        offset: usize,
        /// Number of unexplained bytes.
        len: usize,
    },
    /// A length-prefixed string exceeds its cap.
    #[error("string field {field} announces {len} bytes, exceeding the {cap}-byte cap")]
    StringTooLong {
        /// Field name.
        field: &'static str,
        /// Announced length.
        len: usize,
        /// The cap.
        cap: usize,
    },
    /// A string field is not valid UTF-8.
    #[error("string field {field} in record at payload offset {offset} is not valid UTF-8")]
    InvalidUtf8 {
        /// Payload offset of the record's type tag.
        offset: usize,
        /// Field name.
        field: &'static str,
    },
    /// A node kind discriminant is not defined in format version 1.
    #[error("node record at payload offset {offset}: invalid node kind {kind}")]
    InvalidNodeKind {
        /// Payload offset of the record's type tag.
        offset: usize,
        /// The invalid discriminant.
        kind: u8,
    },
    /// A tag discriminant is not defined in format version 1.
    #[error("node record at payload offset {offset}: invalid tag {tag}")]
    InvalidTag {
        /// Payload offset of the record's type tag.
        offset: usize,
        /// The invalid discriminant.
        tag: u8,
    },
    /// The tree nesting announced by the records exceeds the depth cap.
    #[error("node tree exceeds the depth cap of {MAX_DEPTH}")]
    DepthCapExceeded,
    /// The node records exceed the node-count cap.
    #[error("node count exceeds the cap of {cap}")]
    NodeCountExceeded {
        /// The cap.
        cap: u64,
    },
    /// The node records do not form one well-nested tree.
    #[error("malformed node stream: {0}")]
    MalformedNodeStream(&'static str),
    /// A singleton record appears more than once.
    #[error("duplicate {0} record")]
    DuplicateRecord(&'static str),
    /// A mandatory record is missing or out of order.
    #[error("missing or out-of-order record: expected {0}")]
    MissingRecord(&'static str),
    /// The zoom path announces more components than the cap allows.
    #[error("zoom path announces {0} components, exceeding the cap of {MAX_ZOOM_COMPONENTS}")]
    ZoomTooDeep(u32),
    /// A snapshot cannot be encoded without a root node.
    #[error("cannot encode a snapshot of a tree without a root")]
    EmptyTree,
}

/// Scan metadata stored in the snapshot (SPEC.md §5.7: "tool version, volume
/// serial, timestamps").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScanMetadata {
    /// Version of the tool that produced the scan (e.g. `env!("CARGO_PKG_VERSION")`).
    pub tool_version: String,
    /// Volume serial number of the scanned volume; 0 when unknown (non-Windows
    /// scans, or snapshot hand-crafted in tests).
    pub volume_serial: u64,
    /// When the scan started (FILETIME ticks).
    pub started: FileTime,
    /// When the scan finished (FILETIME ticks).
    pub finished: FileTime,
}

/// A full saved view state: the scanned tree (including per-node tags,
/// FR-5.3), the view's active filter string, its zoom path, and scan
/// metadata (FR-8.7).
#[derive(Clone, Debug)]
pub struct Snapshot {
    /// The complete scanned tree. Aggregates (`agg_*`) are recomputed on load.
    pub tree: Tree,
    /// The view's active filter string (empty when no filter was set).
    pub filter: String,
    /// Zoom path as name components below the tree root (empty = root view).
    pub zoom_path: Vec<String>,
    /// Scan metadata.
    pub meta: ScanMetadata,
}

impl Snapshot {
    /// Create a snapshot of `tree` with the given scan metadata, an empty
    /// filter string, and the root as the zoom target.
    pub fn new(tree: Tree, meta: ScanMetadata) -> Self {
        Self {
            tree,
            filter: String::new(),
            zoom_path: Vec::new(),
            meta,
        }
    }

    /// Encode the snapshot to `.rssnap` bytes.
    pub fn encode(&self) -> Result<Vec<u8>, SnapshotError> {
        let mut payload = Vec::new();
        self.encode_payload(&mut payload)?;

        let payload_len = u64::try_from(payload.len()).expect("payload length fits u64");
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(SnapshotError::PayloadTooLarge(payload_len));
        }
        let mut crc64 = crc64fast::Digest::new();
        crc64.write(&payload);

        let mut out = Vec::with_capacity(HEADER_LEN as usize + payload.len() + TRAILER_LEN);
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
        out.extend_from_slice(&HEADER_LEN.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes()); // flags
        out.extend_from_slice(&payload_len.to_le_bytes());
        let header_crc = crc32fast::hash(&out);
        out.extend_from_slice(&header_crc.to_le_bytes());
        debug_assert_eq!(out.len(), HEADER_LEN as usize);
        out.extend_from_slice(&payload);
        out.extend_from_slice(&crc64.sum64().to_le_bytes());
        Ok(out)
    }

    /// Encode the snapshot and write it to `writer`.
    pub fn write_to(&self, mut writer: impl Write) -> Result<(), SnapshotError> {
        writer.write_all(&self.encode()?)?;
        Ok(())
    }

    /// Decode a snapshot from `.rssnap` bytes. Fails closed: any corruption,
    /// truncation, cap violation, or checksum mismatch is a typed error.
    pub fn decode(bytes: &[u8]) -> Result<Self, SnapshotError> {
        decode(bytes)
    }

    /// Decode a snapshot from a reader (reads it fully into memory first).
    pub fn read_from(mut reader: impl std::io::Read) -> Result<Self, SnapshotError> {
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        Self::decode(&bytes)
    }

    /// Resolve [`Snapshot::zoom_path`] against the loaded tree. Returns the
    /// tree root for an empty zoom path, and `None` when a component no
    /// longer matches (e.g. a hand-edited snapshot).
    pub fn zoom_root(&self) -> Option<NodeId> {
        let mut cur = self.tree.root()?;
        for component in &self.zoom_path {
            cur = self
                .tree
                .children(cur)
                .find(|&c| &*self.tree.node(c).name == component)?;
        }
        Some(cur)
    }

    fn encode_payload(&self, out: &mut Vec<u8>) -> Result<(), SnapshotError> {
        let root = self.tree.root().ok_or(SnapshotError::EmptyTree)?;

        // Meta record.
        let mut rec = Vec::new();
        put_str(&mut rec, &self.meta.tool_version);
        rec.extend_from_slice(&self.meta.volume_serial.to_le_bytes());
        rec.extend_from_slice(&self.meta.started.to_le_bytes());
        rec.extend_from_slice(&self.meta.finished.to_le_bytes());
        put_record(out, record_type::META, &rec)?;

        // Filter record (the view's active filter string, FR-8.7).
        rec.clear();
        put_str(&mut rec, &self.filter);
        put_record(out, record_type::FILTER, &rec)?;

        // Zoom path record.
        if self.zoom_path.len() > MAX_ZOOM_COMPONENTS as usize {
            return Err(SnapshotError::ZoomTooDeep(self.zoom_path.len() as u32));
        }
        rec.clear();
        rec.extend_from_slice(&(self.zoom_path.len() as u32).to_le_bytes());
        for component in &self.zoom_path {
            put_str(&mut rec, component);
        }
        put_record(out, record_type::ZOOM_PATH, &rec)?;

        // Node records, pre-order. Children are emitted in reverse of the
        // tree's iteration order because `Tree::add_child` prepends; loading
        // then restores the original sibling order exactly. The walk is
        // iterative so deep trees cannot overflow the call stack.
        let root_children = child_count(&self.tree, root);
        put_node(out, &self.tree, root, root_children);
        let mut stack: Vec<std::iter::Rev<std::vec::IntoIter<NodeId>>> = Vec::new();
        stack.push(children_rev(&self.tree, root));
        while let Some(iter) = stack.last_mut() {
            match iter.next() {
                Some(child) => {
                    let n = child_count(&self.tree, child);
                    put_node(out, &self.tree, child, n);
                    if n > 0 {
                        stack.push(children_rev(&self.tree, child));
                    }
                }
                None => {
                    stack.pop();
                }
            }
        }
        Ok(())
    }
}

fn child_count(tree: &Tree, id: NodeId) -> usize {
    tree.children(id).count()
}

fn children_rev(tree: &Tree, id: NodeId) -> std::iter::Rev<std::vec::IntoIter<NodeId>> {
    let children: Vec<NodeId> = tree.children(id).collect();
    children.into_iter().rev()
}

/// Fixed part of a node record: kind(1) + tag(1) + reserved(2) + flags(4) +
/// sizes(3*8) + times(3*8) + child_count(4) + name_len(4).
const NODE_FIXED_LEN: usize = 64;

fn put_node(out: &mut Vec<u8>, tree: &Tree, id: NodeId, children: usize) {
    let node = tree.node(id);
    let mut rec = Vec::with_capacity(NODE_FIXED_LEN + node.name.len());
    rec.push(kind_to_u8(node.kind));
    rec.push(tag_to_u8(node.tag));
    rec.extend_from_slice(&0u16.to_le_bytes()); // reserved
    rec.extend_from_slice(&node.flags.0.to_le_bytes());
    rec.extend_from_slice(&node.logical_size.to_le_bytes());
    rec.extend_from_slice(&node.allocated_size.to_le_bytes());
    rec.extend_from_slice(&node.ads_size.to_le_bytes());
    rec.extend_from_slice(&node.created.to_le_bytes());
    rec.extend_from_slice(&node.accessed.to_le_bytes());
    rec.extend_from_slice(&node.modified.to_le_bytes());
    rec.extend_from_slice(&(children as u32).to_le_bytes());
    put_str(&mut rec, &node.name);
    // Node records are built from in-memory trees, so the length always fits
    // (names are bounded by available memory, far below the u32 limit).
    put_record(out, record_type::NODE, &rec).expect("node record length fits u32");
}

fn put_str(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(&(s.len() as u32).to_le_bytes());
    out.extend_from_slice(s.as_bytes());
}

fn put_record(out: &mut Vec<u8>, tag: u64, payload: &[u8]) -> Result<(), SnapshotError> {
    let len = u32::try_from(payload.len()).map_err(|_| SnapshotError::RecordTooLarge {
        offset: out.len(),
        len: u32::MAX,
        cap: MAX_RECORD_LEN,
    })?;
    put_varint(out, tag);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(payload);
    Ok(())
}

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

fn kind_to_u8(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::File => 0,
        NodeKind::Directory => 1,
        NodeKind::Ads => 2,
        NodeKind::FreeSpace => 3,
        NodeKind::UnknownSpace => 4,
        NodeKind::Unaccessible => 5,
    }
}

fn kind_from_u8(value: u8, offset: usize) -> Result<NodeKind, SnapshotError> {
    Ok(match value {
        0 => NodeKind::File,
        1 => NodeKind::Directory,
        2 => NodeKind::Ads,
        3 => NodeKind::FreeSpace,
        4 => NodeKind::UnknownSpace,
        5 => NodeKind::Unaccessible,
        kind => return Err(SnapshotError::InvalidNodeKind { offset, kind }),
    })
}

fn tag_to_u8(tag: Option<Tag>) -> u8 {
    match tag {
        None => 0,
        Some(Tag::Red) => 1,
        Some(Tag::Yellow) => 2,
        Some(Tag::Green) => 3,
        Some(Tag::Blue) => 4,
    }
}

fn tag_from_u8(value: u8, offset: usize) -> Result<Option<Tag>, SnapshotError> {
    Ok(match value {
        0 => None,
        1 => Some(Tag::Red),
        2 => Some(Tag::Yellow),
        3 => Some(Tag::Green),
        4 => Some(Tag::Blue),
        tag => return Err(SnapshotError::InvalidTag { offset, tag }),
    })
}

/// Bounds-checked cursor over a byte slice. Every read validates the length
/// against the remaining bytes *before* slicing (and thus before any
/// allocation happens at the call site).
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.remaining() {
            return None;
        }
        let slice = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(slice)
    }

    fn read_varint(&mut self, offset: usize) -> Result<u64, SnapshotError> {
        let mut value: u64 = 0;
        let mut shift: u32 = 0;
        loop {
            let Some(&byte) = self.buf.get(self.pos) else {
                return Err(SnapshotError::MalformedVarint(offset));
            };
            self.pos += 1;
            // A 10th byte may only contribute the single top bit.
            if shift == 63 && byte > 1 {
                return Err(SnapshotError::MalformedVarint(offset));
            }
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err(SnapshotError::MalformedVarint(offset));
            }
        }
    }
}

/// Cursor over a single record's payload; errors carry the record's absolute
/// payload offset for diagnostics.
struct RecordReader<'a> {
    inner: Reader<'a>,
    record: &'static str,
    offset: usize,
}

impl<'a> RecordReader<'a> {
    fn new(buf: &'a [u8], record: &'static str, offset: usize) -> Self {
        Self {
            inner: Reader::new(buf),
            record,
            offset,
        }
    }

    fn truncated<T>(&self, field: &'static str) -> Result<T, SnapshotError> {
        Err(SnapshotError::TruncatedField {
            record: self.record,
            offset: self.offset,
            field,
        })
    }

    fn read_u8(&mut self, field: &'static str) -> Result<u8, SnapshotError> {
        match self.inner.take(1) {
            Some(b) => Ok(b[0]),
            None => self.truncated(field),
        }
    }

    fn read_array<const N: usize>(
        &mut self,
        field: &'static str,
    ) -> Result<[u8; N], SnapshotError> {
        match self.inner.take(N) {
            Some(b) => Ok(b.try_into().expect("slice length matches array length")),
            None => self.truncated(field),
        }
    }

    fn read_u16(&mut self, field: &'static str) -> Result<u16, SnapshotError> {
        Ok(u16::from_le_bytes(self.read_array::<2>(field)?))
    }

    fn read_u32(&mut self, field: &'static str) -> Result<u32, SnapshotError> {
        Ok(u32::from_le_bytes(self.read_array::<4>(field)?))
    }

    fn read_u64(&mut self, field: &'static str) -> Result<u64, SnapshotError> {
        Ok(u64::from_le_bytes(self.read_array::<8>(field)?))
    }

    fn read_i64(&mut self, field: &'static str) -> Result<i64, SnapshotError> {
        Ok(i64::from_le_bytes(self.read_array::<8>(field)?))
    }

    /// Read a u32-length-prefixed UTF-8 string. The announced length is
    /// checked against the cap and against the remaining bytes *before* the
    /// string is allocated.
    fn read_string(&mut self, field: &'static str, cap: usize) -> Result<String, SnapshotError> {
        let len = self.read_u32(field)? as usize;
        if len > cap {
            return Err(SnapshotError::StringTooLong { field, len, cap });
        }
        let Some(bytes) = self.inner.take(len) else {
            return self.truncated(field);
        };
        let s = std::str::from_utf8(bytes).map_err(|_| SnapshotError::InvalidUtf8 {
            offset: self.offset,
            field,
        })?;
        Ok(s.to_owned())
    }

    fn finish(&self) -> Result<(), SnapshotError> {
        let left = self.inner.remaining();
        if left > 0 {
            return Err(SnapshotError::TrailingBytes {
                record: self.record,
                offset: self.offset,
                len: left,
            });
        }
        Ok(())
    }
}

fn decode(bytes: &[u8]) -> Result<Snapshot, SnapshotError> {
    // ---- Header ----
    let min_len = HEADER_LEN as usize + TRAILER_LEN;
    if bytes.len() < min_len {
        return Err(SnapshotError::TooShort {
            len: bytes.len(),
            need: min_len,
        });
    }
    if &bytes[..8] != MAGIC {
        return Err(SnapshotError::BadMagic);
    }
    let version = u16::from_le_bytes(bytes[8..10].try_into().expect("slice is 2 bytes"));
    if version != FORMAT_VERSION {
        return Err(SnapshotError::UnsupportedVersion(version));
    }
    let header_len = u16::from_le_bytes(bytes[10..12].try_into().expect("slice is 2 bytes"));
    if !(MIN_HEADER_LEN..=MAX_HEADER_LEN).contains(&header_len) {
        return Err(SnapshotError::BadHeaderLength(header_len));
    }
    let header_len = header_len as usize;
    if bytes.len() < header_len + TRAILER_LEN {
        return Err(SnapshotError::TooShort {
            len: bytes.len(),
            need: header_len + TRAILER_LEN,
        });
    }
    let flags = u32::from_le_bytes(bytes[12..16].try_into().expect("slice is 4 bytes"));
    if flags != 0 {
        return Err(SnapshotError::UnsupportedFlags(flags));
    }
    let payload_len = u64::from_le_bytes(bytes[16..24].try_into().expect("slice is 8 bytes"));
    let stored_crc32 = u32::from_le_bytes(
        bytes[header_len - 4..header_len]
            .try_into()
            .expect("slice is 4 bytes"),
    );
    let computed_crc32 = crc32fast::hash(&bytes[..header_len - 4]);
    if stored_crc32 != computed_crc32 {
        return Err(SnapshotError::HeaderCrcMismatch {
            stored: stored_crc32,
            computed: computed_crc32,
        });
    }

    // ---- Payload + trailer ----
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(SnapshotError::PayloadTooLarge(payload_len));
    }
    let actual_payload_len = (bytes.len() - header_len - TRAILER_LEN) as u64;
    if payload_len != actual_payload_len {
        return Err(SnapshotError::PayloadLengthMismatch {
            announced: payload_len,
            actual: actual_payload_len,
        });
    }
    let payload = &bytes[header_len..header_len + payload_len as usize];
    let stored_crc64 = u64::from_le_bytes(
        bytes[bytes.len() - TRAILER_LEN..]
            .try_into()
            .expect("slice is 8 bytes"),
    );
    let mut crc64 = crc64fast::Digest::new();
    crc64.write(payload);
    let computed_crc64 = crc64.sum64();
    if stored_crc64 != computed_crc64 {
        return Err(SnapshotError::PayloadCrcMismatch {
            stored: stored_crc64,
            computed: computed_crc64,
        });
    }

    // ---- Records ----
    decode_payload(payload)
}

/// Decode the record stream. Singleton records (Meta, Filter, ZoomPath) must
/// appear exactly once and in order; then node records build the tree
/// iteratively with a depth cap.
fn decode_payload(payload: &[u8]) -> Result<Snapshot, SnapshotError> {
    let mut reader = Reader::new(payload);
    let mut meta: Option<ScanMetadata> = None;
    let mut filter: Option<String> = None;
    let mut zoom_path: Option<Vec<String>> = None;

    let mut tree: Option<Tree> = None;
    // Stack of (parent id, remaining declared children) for open levels.
    let mut pending: Vec<(NodeId, u32)> = Vec::new();
    let mut node_count: u64 = 0;

    while reader.remaining() > 0 {
        let offset = reader.pos;
        let tag = reader.read_varint(offset)?;
        let len = reader
            .take(4)
            .map(|b| u32::from_le_bytes(b.try_into().expect("slice is 4 bytes")))
            .ok_or(SnapshotError::TruncatedField {
                record: "record header",
                offset,
                field: "length",
            })?;
        if len > MAX_RECORD_LEN {
            return Err(SnapshotError::RecordTooLarge {
                offset,
                len,
                cap: MAX_RECORD_LEN,
            });
        }
        let remaining = reader.remaining();
        if len as usize > remaining {
            return Err(SnapshotError::RecordOverrun {
                offset,
                len,
                remaining,
            });
        }
        let body = reader.take(len as usize).expect("length checked above");

        match tag {
            record_type::META => {
                if meta.is_some() {
                    return Err(SnapshotError::DuplicateRecord("meta"));
                }
                if filter.is_some() || zoom_path.is_some() || tree.is_some() {
                    return Err(SnapshotError::MissingRecord("meta before other records"));
                }
                meta = Some(decode_meta(body, offset)?);
            }
            record_type::FILTER => {
                if filter.is_some() {
                    return Err(SnapshotError::DuplicateRecord("filter"));
                }
                if meta.is_none() {
                    return Err(SnapshotError::MissingRecord("meta"));
                }
                if zoom_path.is_some() || tree.is_some() {
                    return Err(SnapshotError::MissingRecord("filter before zoom/nodes"));
                }
                let mut rec = RecordReader::new(body, "filter", offset);
                filter = Some(rec.read_string("filter", MAX_STRING_LEN)?);
                rec.finish()?;
            }
            record_type::ZOOM_PATH => {
                if zoom_path.is_some() {
                    return Err(SnapshotError::DuplicateRecord("zoom path"));
                }
                if meta.is_none() || filter.is_none() {
                    return Err(SnapshotError::MissingRecord("meta/filter"));
                }
                if tree.is_some() {
                    return Err(SnapshotError::MissingRecord("zoom path before nodes"));
                }
                zoom_path = Some(decode_zoom_path(body, offset)?);
            }
            record_type::NODE => {
                if meta.is_none() || filter.is_none() || zoom_path.is_none() {
                    return Err(SnapshotError::MissingRecord("meta/filter/zoom path"));
                }
                node_count += 1;
                if node_count > MAX_NODES {
                    return Err(SnapshotError::NodeCountExceeded { cap: MAX_NODES });
                }
                let (params, children) = decode_node(body, offset)?;
                let id = add_node(&mut tree, &mut pending, params)?;
                if children > 0 {
                    if pending.len() >= MAX_DEPTH {
                        return Err(SnapshotError::DepthCapExceeded);
                    }
                    pending.push((id, children));
                }
            }
            tag => return Err(SnapshotError::UnknownRecordType { offset, tag }),
        }
    }

    pop_exhausted(&mut pending);
    if !pending.is_empty() {
        return Err(SnapshotError::MalformedNodeStream(
            "node declared more children than the stream provides",
        ));
    }
    let tree = tree.ok_or(SnapshotError::MissingRecord("node"))?;
    Ok(Snapshot {
        tree,
        filter: filter.expect("checked above"),
        zoom_path: zoom_path.expect("checked above"),
        meta: meta.expect("checked above"),
    })
}

/// Drop levels whose declared children have all been read.
fn pop_exhausted(pending: &mut Vec<(NodeId, u32)>) {
    while let Some(&(_, 0)) = pending.last() {
        pending.pop();
    }
}

/// Attach a decoded node to the tree under construction, validating the
/// declared nesting iteratively.
fn add_node(
    tree: &mut Option<Tree>,
    pending: &mut Vec<(NodeId, u32)>,
    params: NodeParams,
) -> Result<NodeId, SnapshotError> {
    pop_exhausted(pending);
    match tree {
        None => {
            // First node record is the root; `pending` is empty here.
            let fresh = Tree::with_root(params);
            let id = fresh.root().expect("with_root sets a root");
            *tree = Some(fresh);
            Ok(id)
        }
        Some(tree) => match pending.last_mut() {
            Some((parent, remaining)) => {
                *remaining -= 1;
                Ok(tree.add_child(*parent, params))
            }
            None => Err(SnapshotError::MalformedNodeStream(
                "second root node record",
            )),
        },
    }
}

fn decode_meta(body: &[u8], offset: usize) -> Result<ScanMetadata, SnapshotError> {
    let mut rec = RecordReader::new(body, "meta", offset);
    let tool_version = rec.read_string("tool_version", MAX_STRING_LEN)?;
    let volume_serial = rec.read_u64("volume_serial")?;
    let started = rec.read_i64("started")?;
    let finished = rec.read_i64("finished")?;
    rec.finish()?;
    Ok(ScanMetadata {
        tool_version,
        volume_serial,
        started,
        finished,
    })
}

fn decode_zoom_path(body: &[u8], offset: usize) -> Result<Vec<String>, SnapshotError> {
    let mut rec = RecordReader::new(body, "zoom path", offset);
    let count = rec.read_u32("component_count")?;
    // Checked against the cap before any allocation proportional to it.
    if count > MAX_ZOOM_COMPONENTS {
        return Err(SnapshotError::ZoomTooDeep(count));
    }
    let mut components = Vec::new();
    for _ in 0..count {
        components.push(rec.read_string("component", MAX_NAME_LEN)?);
    }
    rec.finish()?;
    Ok(components)
}

fn decode_node(body: &[u8], offset: usize) -> Result<(NodeParams, u32), SnapshotError> {
    let mut rec = RecordReader::new(body, "node", offset);
    let kind = kind_from_u8(rec.read_u8("kind")?, offset)?;
    let tag = tag_from_u8(rec.read_u8("tag")?, offset)?;
    let reserved = rec.read_u16("reserved")?;
    if reserved != 0 {
        return Err(SnapshotError::MalformedNodeStream(
            "non-zero reserved field in node record",
        ));
    }
    let flags = NodeFlags(rec.read_u32("flags")?);
    let logical_size = rec.read_u64("logical_size")?;
    let allocated_size = rec.read_u64("allocated_size")?;
    let ads_size = rec.read_u64("ads_size")?;
    let created = rec.read_i64("created")?;
    let accessed = rec.read_i64("accessed")?;
    let modified = rec.read_i64("modified")?;
    let children = rec.read_u32("child_count")?;
    let name = rec.read_string("name", MAX_NAME_LEN)?;
    rec.finish()?;
    let params = NodeParams {
        name: name.into_boxed_str(),
        kind,
        flags,
        tag,
        logical_size,
        allocated_size,
        ads_size,
        created,
        accessed,
        modified,
    };
    Ok((params, children))
}
