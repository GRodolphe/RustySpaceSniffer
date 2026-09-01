//! USN record parsing for the MFT fast path (SPEC.md §5.4).
//!
//! Pure byte-level parsing with no platform dependencies so it can be
//! unit-tested on any host. Every length field is validated against the
//! remaining buffer before use — the CVE-2026-26738 lesson (SPEC.md §9.1):
//! never trust a length read from untrusted bytes.
//!
//! Handles the §5.4 version hazard: `USN_RECORD_V2` (64-bit FRNs) and
//! `USN_RECORD_V3` (128-bit FRNs, Win10+ volumes with extended file IDs) are
//! parsed fully; `USN_RECORD_V4` (range-tracking records, no name/timestamps)
//! is parsed into a nameless record so the enumeration never chokes on it.

/// `USN_RECORD_V2` fixed header size (up to and including FileNameOffset).
pub const V2_HEADER_SIZE: usize = 60;
/// `USN_RECORD_V3` fixed header size (128-bit FRNs).
pub const V3_HEADER_SIZE: usize = 76;
/// `USN_RECORD_V4` fixed header size (no name, no timestamps).
pub const V4_HEADER_SIZE: usize = 64;

/// One parsed USN record from an `FSCTL_ENUM_USN_DATA` buffer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UsnRecord {
    /// File reference number (V2 values widened to 128 bits).
    pub frn: u128,
    /// Parent directory's file reference number.
    pub parent_frn: u128,
    /// Raw FRN bytes, preserved for `OpenFileById` (`FileIdType` vs
    /// `ExtendedFileIdType` is decided from `major_version`).
    pub frn_bytes: [u8; 16],
    /// Journal timestamp as Windows FILETIME (0 for V4 range records).
    pub timestamp: i64,
    /// Win32 file attributes (0 for V4 range records).
    pub file_attributes: u32,
    /// File name decoded from UTF-16 (empty for V4 range records).
    pub name: String,
    /// Record major version (2, 3, or 4).
    pub major_version: u16,
}

/// USN record parse failure. All variants mean "stop parsing this buffer" —
/// records are length-chained, so resynchronization is impossible.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum UsnParseError {
    /// Declared record length exceeds the bytes left in the buffer.
    #[error("record length {record_len} exceeds remaining buffer ({remaining} bytes)")]
    Truncated {
        /// Declared record length.
        record_len: usize,
        /// Bytes actually remaining.
        remaining: usize,
    },
    /// Record length is smaller than the smallest possible header.
    #[error("record length too small: {0}")]
    LengthTooSmall(u32),
    /// Unknown `MajorVersion` — never assume a layout we have not parsed.
    #[error("unsupported USN record major version {0}")]
    UnsupportedVersion(u16),
    /// File name offset/length point outside the record.
    #[error("file name field out of bounds")]
    NameOutOfBounds,
}

fn u16_at(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes(buf[off..off + 2].try_into().expect("bounds checked"))
}

fn u32_at(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().expect("bounds checked"))
}

fn i64_at(buf: &[u8], off: usize) -> i64 {
    i64::from_le_bytes(buf[off..off + 8].try_into().expect("bounds checked"))
}

fn decode_name(buf: &[u8]) -> String {
    String::from_utf16_lossy(
        &buf.chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect::<Vec<u16>>(),
    )
}

/// Parse the record at the start of `buf`.
///
/// Returns `Ok(None)` for zero padding after the last record, `Ok(Some((record,
/// bytes_consumed)))` for a valid record, and `Err` for malformed input.
pub fn parse_one(buf: &[u8]) -> Result<Option<(UsnRecord, usize)>, UsnParseError> {
    if buf.len() < 4 {
        // A short all-zero tail is padding; anything else is corruption.
        return if buf.iter().all(|&b| b == 0) {
            Ok(None)
        } else {
            Err(UsnParseError::Truncated {
                record_len: 4,
                remaining: buf.len(),
            })
        };
    }
    let record_len = u32_at(buf, 0) as usize;
    if record_len == 0 {
        return Ok(None); // zero padding after the last record
    }
    if record_len > buf.len() {
        return Err(UsnParseError::Truncated {
            record_len,
            remaining: buf.len(),
        });
    }
    if record_len < 8 {
        return Err(UsnParseError::LengthTooSmall(record_len as u32));
    }
    let rec = &buf[..record_len];
    let major = u16_at(rec, 4);

    let name_field = |rec: &[u8], header: usize, len_off: usize, off_off: usize| {
        let name_len = u16_at(rec, len_off) as usize;
        let name_off = u16_at(rec, off_off) as usize;
        if name_off < header
            || name_off
                .checked_add(name_len)
                .is_none_or(|end| end > rec.len())
        {
            return Err(UsnParseError::NameOutOfBounds);
        }
        Ok(decode_name(&rec[name_off..name_off + name_len]))
    };

    let record = match major {
        2 => {
            if record_len < V2_HEADER_SIZE {
                return Err(UsnParseError::LengthTooSmall(record_len as u32));
            }
            let frn = u64::from_le_bytes(rec[8..16].try_into().expect("bounds checked"));
            let mut frn_bytes = [0u8; 16];
            frn_bytes[..8].copy_from_slice(&frn.to_le_bytes());
            UsnRecord {
                frn: u128::from(frn),
                parent_frn: u128::from(u64::from_le_bytes(
                    rec[16..24].try_into().expect("bounds checked"),
                )),
                frn_bytes,
                timestamp: i64_at(rec, 32),
                file_attributes: u32_at(rec, 52),
                name: name_field(rec, V2_HEADER_SIZE, 56, 58)?,
                major_version: 2,
            }
        }
        3 => {
            if record_len < V3_HEADER_SIZE {
                return Err(UsnParseError::LengthTooSmall(record_len as u32));
            }
            let mut frn_bytes = [0u8; 16];
            frn_bytes.copy_from_slice(&rec[8..24]);
            let mut parent_bytes = [0u8; 16];
            parent_bytes.copy_from_slice(&rec[24..40]);
            UsnRecord {
                frn: u128::from_le_bytes(frn_bytes),
                parent_frn: u128::from_le_bytes(parent_bytes),
                frn_bytes,
                timestamp: i64_at(rec, 48),
                file_attributes: u32_at(rec, 68),
                name: name_field(rec, V3_HEADER_SIZE, 72, 74)?,
                major_version: 3,
            }
        }
        4 => {
            // Range-tracking record: no timestamps, attributes, or name.
            if record_len < V4_HEADER_SIZE {
                return Err(UsnParseError::LengthTooSmall(record_len as u32));
            }
            let mut frn_bytes = [0u8; 16];
            frn_bytes.copy_from_slice(&rec[8..24]);
            let mut parent_bytes = [0u8; 16];
            parent_bytes.copy_from_slice(&rec[24..40]);
            UsnRecord {
                frn: u128::from_le_bytes(frn_bytes),
                parent_frn: u128::from_le_bytes(parent_bytes),
                frn_bytes,
                timestamp: 0,
                file_attributes: 0,
                name: String::new(),
                major_version: 4,
            }
        }
        other => return Err(UsnParseError::UnsupportedVersion(other)),
    };
    Ok(Some((record, record_len)))
}

/// Parse one `FSCTL_ENUM_USN_DATA` output buffer.
///
/// Returns `(next_start_frn, records, skipped)`: `next_start_frn` is the
/// continuation value in the buffer's first 8 bytes, `records` the parsed
/// records, `skipped` the number of trailing records dropped because parsing
/// failed mid-buffer (a parse error stops the buffer — records are
/// length-chained — but earlier records remain usable).
pub fn parse_buffer(buf: &[u8]) -> Result<(u64, Vec<UsnRecord>, usize), UsnParseError> {
    if buf.len() < 8 {
        return Err(UsnParseError::Truncated {
            record_len: 8,
            remaining: buf.len(),
        });
    }
    let next_start = u64::from_le_bytes(buf[0..8].try_into().expect("bounds checked"));
    let mut records = Vec::new();
    let mut rest = &buf[8..];
    loop {
        match parse_one(rest) {
            Ok(None) => break,
            Ok(Some((record, consumed))) => {
                records.push(record);
                rest = &rest[consumed..];
            }
            Err(_) => {
                // One unparseable record invalidates the remainder of the
                // buffer (length-chained); keep what we have and report.
                return Ok((next_start, records, 1));
            }
        }
    }
    Ok((next_start, records, 0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_u16(buf: &mut Vec<u8>, v: u16) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_u64(buf: &mut Vec<u8>, v: u64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }
    fn push_i64(buf: &mut Vec<u8>, v: i64) {
        buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Build a V2 record with the given fields.
    fn v2_record(frn: u64, parent: u64, attrs: u32, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = name_utf16.len() * 2;
        let record_len = (V2_HEADER_SIZE + name_bytes) as u32;
        let mut b = Vec::new();
        push_u32(&mut b, record_len);
        push_u16(&mut b, 2); // major
        push_u16(&mut b, 0); // minor
        push_u64(&mut b, frn);
        push_u64(&mut b, parent);
        push_u64(&mut b, 12345); // usn
        push_i64(&mut b, 0x01D8_0000_0000_0000); // timestamp
        push_u32(&mut b, 0x80); // reason
        push_u32(&mut b, 0); // source info
        push_u32(&mut b, 0); // security id
        push_u32(&mut b, attrs);
        push_u16(&mut b, name_bytes as u16);
        push_u16(&mut b, V2_HEADER_SIZE as u16);
        assert_eq!(b.len(), V2_HEADER_SIZE);
        for u in name_utf16 {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b
    }

    /// Build a V3 record (128-bit FRNs).
    fn v3_record(frn: u128, parent: u128, attrs: u32, name: &str) -> Vec<u8> {
        let name_utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes = name_utf16.len() * 2;
        let record_len = (V3_HEADER_SIZE + name_bytes) as u32;
        let mut b = Vec::new();
        push_u32(&mut b, record_len);
        push_u16(&mut b, 3);
        push_u16(&mut b, 0);
        b.extend_from_slice(&frn.to_le_bytes());
        b.extend_from_slice(&parent.to_le_bytes());
        push_u64(&mut b, 999);
        push_i64(&mut b, 42);
        push_u32(&mut b, 0);
        push_u32(&mut b, 0);
        push_u32(&mut b, 0);
        push_u32(&mut b, attrs);
        push_u16(&mut b, name_bytes as u16);
        push_u16(&mut b, V3_HEADER_SIZE as u16);
        assert_eq!(b.len(), V3_HEADER_SIZE);
        for u in name_utf16 {
            b.extend_from_slice(&u.to_le_bytes());
        }
        b
    }

    #[test]
    fn parses_v2_record() {
        let buf = v2_record(0x0005_0000_0000_0005, 0x0001_0000_0000_0001, 0x10, "dir");
        let (rec, consumed) = parse_one(&buf).unwrap().unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(rec.major_version, 2);
        assert_eq!(rec.frn, 0x0005_0000_0000_0005u128);
        assert_eq!(rec.parent_frn, 0x0001_0000_0000_0001u128);
        assert_eq!(rec.file_attributes, 0x10);
        assert_eq!(rec.name, "dir");
        assert_eq!(&rec.frn_bytes[..8], &0x0005_0000_0000_0005u64.to_le_bytes());
    }

    #[test]
    fn parses_v3_record_with_128bit_frn() {
        let frn = 0xABCD_EF01_2345_6789_0005_0000_0000_0005u128;
        let buf = v3_record(frn, 7u128, 0x20, "f.bin");
        let (rec, _) = parse_one(&buf).unwrap().unwrap();
        assert_eq!(rec.major_version, 3);
        assert_eq!(rec.frn, frn);
        assert_eq!(rec.parent_frn, 7);
        assert_eq!(rec.name, "f.bin");
        assert_eq!(rec.frn_bytes, frn.to_le_bytes());
    }

    #[test]
    fn parses_v4_record_as_nameless() {
        let mut b = Vec::new();
        push_u32(&mut b, V4_HEADER_SIZE as u32);
        push_u16(&mut b, 4);
        push_u16(&mut b, 0);
        b.extend_from_slice(&9u128.to_le_bytes()); // frn
        b.extend_from_slice(&5u128.to_le_bytes()); // parent
        push_u64(&mut b, 1); // usn
        push_u32(&mut b, 0); // reason
        push_u32(&mut b, 0); // source info
        push_u32(&mut b, 0); // remaining extents
        push_u16(&mut b, 0); // number of extents
        push_u16(&mut b, 0); // extent size
        assert_eq!(b.len(), V4_HEADER_SIZE);
        let (rec, consumed) = parse_one(&b).unwrap().unwrap();
        assert_eq!(consumed, V4_HEADER_SIZE);
        assert_eq!(rec.major_version, 4);
        assert_eq!(rec.frn, 9);
        assert!(rec.name.is_empty());
        assert_eq!(rec.file_attributes, 0);
    }

    #[test]
    fn rejects_truncated_record() {
        let mut buf = v2_record(1, 1, 0, "abcdef");
        buf.truncate(buf.len() - 2); // declared length now exceeds the buffer
        assert!(matches!(
            parse_one(&buf),
            Err(UsnParseError::Truncated { .. })
        ));
    }

    #[test]
    fn rejects_unsupported_major_version() {
        let mut buf = v2_record(1, 1, 0, "x");
        buf[4] = 9; // MajorVersion = 9
        assert_eq!(parse_one(&buf), Err(UsnParseError::UnsupportedVersion(9)));
    }

    #[test]
    fn rejects_out_of_bounds_name() {
        let mut buf = v2_record(1, 1, 0, "ok");
        // Point FileNameOffset way past the record.
        let off = 58;
        buf[off] = 0xFF;
        buf[off + 1] = 0x7F;
        assert_eq!(parse_one(&buf), Err(UsnParseError::NameOutOfBounds));
    }

    #[test]
    fn zero_padding_ends_the_buffer() {
        assert_eq!(parse_one(&[0, 0, 0]), Ok(None));
        assert_eq!(parse_one(&[0; 16]), Ok(None));
    }

    #[test]
    fn parse_buffer_reads_header_and_records() {
        let mut buf = Vec::new();
        push_u64(&mut buf, 0xBEEF); // continuation FRN
        let r1 = v2_record(5, 5, 0x10, "root");
        let r2 = v3_record(6, 5, 0x20, "child.txt");
        buf.extend_from_slice(&r1);
        buf.extend_from_slice(&r2);
        let (next, records, skipped) = parse_buffer(&buf).unwrap();
        assert_eq!(next, 0xBEEF);
        assert_eq!(skipped, 0);
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].name, "root");
        assert_eq!(records[1].name, "child.txt");
        assert_eq!(records[1].parent_frn, 5);
    }

    #[test]
    fn parse_buffer_keeps_good_records_before_a_bad_one() {
        let mut buf = Vec::new();
        push_u64(&mut buf, 0);
        buf.extend_from_slice(&v2_record(5, 5, 0x10, "good"));
        buf.extend_from_slice(&[1, 2, 3]); // corrupt tail
        let (_, records, skipped) = parse_buffer(&buf).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(skipped, 1);
    }
}
