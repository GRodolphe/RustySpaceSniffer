//! Persisted USN journal cursor (FR-7.2, FR-10.5).
//!
//! The cursor is the journal identity plus the next USN to read; persisting
//! it per volume lets change tracking survive app restarts. The encoding is
//! a fixed 16-byte little-endian record so it is trivially auditable and
//! round-trips on any platform (unit-tested on Linux even though only the
//! Windows watcher uses it).

use std::io;
use std::path::Path;

/// A resumable position in an NTFS USN change journal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UsnCursor {
    /// `USN_JOURNAL_DATA_V0.UsnJournalID` — identifies the journal instance.
    /// A mismatch on resume means the journal was deleted/recreated and a
    /// full rescan is required (FR-7.5).
    pub journal_id: u64,
    /// Next USN to read (`USN_JOURNAL_DATA_V0.NextUsn` at watermark time).
    pub next_usn: i64,
}

impl UsnCursor {
    /// Encoded length in bytes.
    pub const LEN: usize = 16;

    /// Serialize to the fixed 16-byte little-endian record.
    pub fn encode(self) -> [u8; Self::LEN] {
        let mut out = [0u8; Self::LEN];
        out[..8].copy_from_slice(&self.journal_id.to_le_bytes());
        out[8..].copy_from_slice(&self.next_usn.to_le_bytes());
        out
    }

    /// Parse a record produced by [`UsnCursor::encode`].
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        let (id, usn) = bytes.split_at_checked(8)?;
        Some(UsnCursor {
            journal_id: u64::from_le_bytes(id.try_into().ok()?),
            next_usn: i64::from_le_bytes(usn.try_into().ok()?),
        })
    }

    /// Load a persisted cursor; `Ok(None)` when no cursor was saved yet.
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Self::decode(&bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Persist the cursor (atomic via write-to-temp + rename, so a crash
    /// mid-write cannot leave a half-written cursor).
    pub fn save(self, path: &Path) -> io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, self.encode())?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_round_trip() {
        let cursor = UsnCursor {
            journal_id: 0x0123_4567_89ab_cdef,
            next_usn: -0x1234_5678, // negative USNs are legal to encode
        };
        assert_eq!(UsnCursor::decode(&cursor.encode()), Some(cursor));
    }

    #[test]
    fn decode_rejects_truncated_records() {
        assert_eq!(UsnCursor::decode(&[0u8; 0]), None);
        assert_eq!(UsnCursor::decode(&[0u8; 8]), None);
        assert_eq!(UsnCursor::decode(&[0u8; 15]), None);
    }

    #[test]
    fn save_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.bin");
        assert_eq!(UsnCursor::load(&path).unwrap(), None);

        let cursor = UsnCursor {
            journal_id: 42,
            next_usn: 1_000_000,
        };
        cursor.save(&path).unwrap();
        assert_eq!(UsnCursor::load(&path).unwrap(), Some(cursor));
        // The temp file must not linger after the rename.
        assert!(!path.with_extension("tmp").exists());
    }
}
