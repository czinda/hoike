use byteorder::{BigEndian, ByteOrder};
use memmap2::MmapOptions;
use std::fs::File;
use std::path::Path;

use crate::error::{AhuError, Result};
use crate::header::{FileHeader, HEADER_SIZE};
use crate::index::{IndexFlags, INDEX_RECORD_SIZE};
use crate::manifest::Manifest;

/// A memory-mapped ahu bundle for zero-copy serving at scale.
///
/// Uses MAP_PRIVATE (copy-on-write) so the process is isolated from
/// any subsequent modifications to the file on disk. The OS demand-pages
/// only the regions actually accessed — a 45 GB bundle uses ~200 MB RSS
/// under typical access patterns.
///
/// The index is searched via binary search directly in the mapped region.
/// Response bytes are returned as slices into the mapping — no allocation.
pub struct MmapBundle {
    mmap: memmap2::Mmap,
    pub header: FileHeader,
    pub manifest: Manifest,
    manifest_start: usize,
    manifest_end: usize,
    seal_start: usize,
    seal_end: usize,
    index_offset: usize,
    index_count: usize,
    data_offset: usize,
    data_length: usize,
}

impl MmapBundle {
    /// Open a bundle file with MAP_PRIVATE (copy-on-write).
    ///
    /// # Safety
    ///
    /// Uses `unsafe` for the mmap syscall. MAP_PRIVATE ensures isolation
    /// from disk modifications. The file size is validated against header
    /// offsets before any section is accessed.
    pub fn open(path: &Path) -> Result<Self> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        let file_size = metadata.len();

        if (file_size as usize) < HEADER_SIZE {
            return Err(AhuError::HeaderOutOfBounds {
                field: "file",
                offset: 0,
                length: HEADER_SIZE as u64,
                file_size,
            });
        }

        // SAFETY: MAP_PRIVATE (map_copy) ensures copy-on-write isolation.
        // File size is validated before any offset access.
        let mmap = unsafe {
            MmapOptions::new()
                .map_copy_read_only(&file)
                .map_err(AhuError::Io)?
        };

        let header = FileHeader::read_from(&mut &mmap[..HEADER_SIZE])?;
        header.validate_bounds(file_size)?;

        let manifest_start = header.manifest_offset as usize;
        let manifest_end = manifest_start + header.manifest_length as usize;
        let manifest = Manifest::from_cbor(&mmap[manifest_start..manifest_end])?;

        let seal_start = header.seal_offset as usize;
        let seal_end = seal_start + header.seal_length as usize;

        let index_offset = header.index_offset as usize;
        let index_length = header.index_length as usize;

        if index_length % INDEX_RECORD_SIZE != 0 {
            return Err(AhuError::IndexSizeMismatch {
                size: index_length as u64,
                record_size: INDEX_RECORD_SIZE,
            });
        }
        let index_count = index_length / INDEX_RECORD_SIZE;

        let data_offset = header.data_offset as usize;
        let data_length = header.data_length as usize;

        Ok(MmapBundle {
            mmap,
            header,
            manifest,
            manifest_start,
            manifest_end,
            seal_start,
            seal_end,
            index_offset,
            index_count,
            data_offset,
            data_length,
        })
    }

    /// Look up an entry by its entry key (SHA-256 of DER CertID).
    /// Returns the default (discriminator=0) entry.
    pub fn lookup(&self, entry_key: &[u8; 32]) -> Option<&[u8]> {
        let idx = self.binary_search_disc(entry_key, 0)?;
        self.entry_at_mmap(idx)
    }

    /// Look up the best-matching entry given preferred discriminators.
    pub fn lookup_preferred(&self, entry_key: &[u8; 32], preferences: &[u16]) -> Option<&[u8]> {
        for &disc in preferences {
            if let Some(idx) = self.binary_search_disc(entry_key, disc) {
                return self.entry_at_mmap(idx);
            }
        }
        if !preferences.contains(&0) {
            if let Some(idx) = self.binary_search_disc(entry_key, 0) {
                return self.entry_at_mmap(idx);
            }
        }
        None
    }

    fn entry_at_mmap(&self, idx: usize) -> Option<&[u8]> {
        let (offset, length, flags, _disc) = self.read_record_fields(idx);
        if flags.contains(IndexFlags::TOMBSTONE) {
            return None;
        }
        let start = self.data_offset + offset as usize;
        let end = start + length as usize;
        if end > self.data_offset + self.data_length {
            return None;
        }
        Some(&self.mmap[start..end])
    }

    /// Binary search for `(entry_key, discriminator)` in the mmap'd index.
    fn binary_search_disc(&self, entry_key: &[u8; 32], disc: u16) -> Option<usize> {
        let mut lo = 0usize;
        let mut hi = self.index_count;

        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let key = self.read_entry_key(mid);
            let mid_disc = self.read_discriminator(mid);

            match key.cmp(entry_key).then(mid_disc.cmp(&disc)) {
                std::cmp::Ordering::Equal => return Some(mid),
                std::cmp::Ordering::Less => lo = mid + 1,
                std::cmp::Ordering::Greater => hi = mid,
            }
        }
        None
    }

    /// Read the 32-byte entry key at index position `n`.
    #[inline]
    fn read_entry_key(&self, n: usize) -> &[u8; 32] {
        let offset = self.index_offset + n * INDEX_RECORD_SIZE;
        self.mmap[offset..offset + 32]
            .try_into()
            .expect("slice is exactly 32 bytes")
    }

    /// Read discriminator (u16) at bytes 46-47 of record `n`.
    #[inline]
    fn read_discriminator(&self, n: usize) -> u16 {
        let base = self.index_offset + n * INDEX_RECORD_SIZE;
        BigEndian::read_u16(&self.mmap[base + 46..base + 48])
    }

    /// Read data_offset (u64), data_length (u32), flags (u16), discriminator (u16) from record `n`.
    #[inline]
    fn read_record_fields(&self, n: usize) -> (u64, u32, IndexFlags, u16) {
        let base = self.index_offset + n * INDEX_RECORD_SIZE;
        let data_offset = BigEndian::read_u64(&self.mmap[base + 32..base + 40]);
        let data_length = BigEndian::read_u32(&self.mmap[base + 40..base + 44]);
        let flags_raw = BigEndian::read_u16(&self.mmap[base + 44..base + 46]);
        let flags = IndexFlags::from_bits_truncate(flags_raw);
        let discriminator = BigEndian::read_u16(&self.mmap[base + 46..base + 48]);
        (data_offset, data_length, flags, discriminator)
    }

    /// Get the raw manifest bytes (slice into mmap).
    pub fn manifest_bytes(&self) -> &[u8] {
        &self.mmap[self.manifest_start..self.manifest_end]
    }

    /// Get the raw seal bytes (slice into mmap).
    pub fn seal_bytes(&self) -> &[u8] {
        &self.mmap[self.seal_start..self.seal_end]
    }

    /// Number of index records.
    pub fn entry_count(&self) -> usize {
        self.index_count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle::BundleBuilder;
    use crate::manifest::*;
    use sha2::{Digest, Sha256};
    use uuid::Uuid;

    fn build_test_bundle(n: usize) -> Vec<u8> {
        let manifest = Manifest {
            format_version: 1,
            bundle_id: Uuid::nil(),
            producer_id: "mmap-test".into(),
            created_at: 1700000000,
            bundle_type: BundleType::Full,
            ca_scopes: vec![CaScope {
                hash_algorithm: vec![0x01],
                issuer_name_hash: vec![0xAA; 32],
                issuer_key_hash: vec![0xBB; 32],
                epoch: 1,
                responder_id: ResponderId {
                    id_type: ResponderIdType::ByKey,
                    value: vec![0xCC; 20],
                },
                responder_chain: None,
                signature_algorithm: vec![0x02],
                completeness: Completeness::AuthoritativeComplete,
            }],
            window: Window {
                produced_at: 1700000000,
                this_update_min: 1700000000,
                next_update_min: 1700086400,
                next_update_max: 1700093600,
            },
            integrity: Integrity {
                index_digest: [0; 32],
                data_digest: [0; 32],
            },
            entry_count: 0,
            continuity: Continuity {
                prev_manifest_digest: None,
                base_manifest_digest: None,
                chain_length: 0,
            },
            shard: None,
            compression: None,
            extensions: None,
        };

        let mut builder = BundleBuilder::new(manifest);
        for i in 0..n {
            let certid = format!("test-certid-{i:08}");
            let entry_key = crate::index::compute_entry_key(certid.as_bytes());
            let response = format!("response-{i:08}").into_bytes();
            builder.add_entry(entry_key, response);
        }

        builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap()
    }

    #[test]
    fn mmap_lookup_matches_heap() {
        let bytes = build_test_bundle(50);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ahu");
        std::fs::write(&path, &bytes).unwrap();

        let heap_bundle = crate::Bundle::from_bytes(&bytes).unwrap();
        let mmap_bundle = MmapBundle::open(&path).unwrap();

        assert_eq!(mmap_bundle.entry_count(), heap_bundle.index.len());

        for i in 0..50 {
            let certid = format!("test-certid-{i:08}");
            let entry_key = crate::index::compute_entry_key(certid.as_bytes());

            let heap_result = heap_bundle.lookup(&entry_key);
            let mmap_result = mmap_bundle.lookup(&entry_key);

            assert_eq!(heap_result, mmap_result, "mismatch at entry {i}");
        }
    }

    #[test]
    fn mmap_missing_key_returns_none() {
        let bytes = build_test_bundle(10);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ahu");
        std::fs::write(&path, &bytes).unwrap();

        let bundle = MmapBundle::open(&path).unwrap();
        let missing = [0xFF; 32];
        assert!(bundle.lookup(&missing).is_none());
    }

    #[test]
    fn mmap_manifest_and_seal_accessible() {
        let bytes = build_test_bundle(5);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ahu");
        std::fs::write(&path, &bytes).unwrap();

        let bundle = MmapBundle::open(&path).unwrap();
        assert!(!bundle.manifest_bytes().is_empty());
        assert!(!bundle.seal_bytes().is_empty());
        assert_eq!(bundle.manifest.producer_id, "mmap-test");
    }
}
