use sha2::{Digest, Sha256};
use std::io::Cursor;
use std::path::Path;

use crate::error::{AhuError, Result};
use crate::header::{FileHeader, HEADER_SIZE};
use crate::index::{INDEX_RECORD_SIZE, IndexRecord};
use crate::manifest::Manifest;

/// A parsed ahu bundle, loaded into memory.
#[derive(Debug)]
pub struct Bundle {
    pub header: FileHeader,
    pub manifest: Manifest,
    pub manifest_bytes: Vec<u8>,
    pub seal_bytes: Vec<u8>,
    pub index: Vec<IndexRecord>,
    pub data: Vec<u8>,
}

impl Bundle {
    /// Read a bundle from a file path.
    pub fn from_file(path: &Path) -> Result<Self> {
        let data = std::fs::read(path)?;
        Self::from_bytes(&data)
    }

    /// Read a bundle from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let file_size = bytes.len() as u64;
        let mut cursor = Cursor::new(bytes);

        let header = FileHeader::read_from(&mut cursor)?;
        header.validate_bounds(file_size)?;

        let manifest_bytes =
            Self::read_section(bytes, header.manifest_offset, header.manifest_length as u64)?;
        let manifest = Manifest::from_cbor(&manifest_bytes)?;

        let seal_bytes = Self::read_section(bytes, header.seal_offset, header.seal_length as u64)?;

        let index_bytes = Self::read_section(bytes, header.index_offset, header.index_length)?;
        let index = Self::parse_index(&index_bytes)?;

        let data = Self::read_section(bytes, header.data_offset, header.data_length)?;

        Ok(Bundle {
            header,
            manifest,
            manifest_bytes,
            seal_bytes,
            index,
            data,
        })
    }

    /// Serialize the already parsed sections without changing the signed manifest.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut index = Vec::new();
        for record in &self.index {
            record.write_to(&mut index)?;
        }
        let mut header = self.header.clone();
        header.manifest_offset = HEADER_SIZE as u64;
        header.manifest_length = u32::try_from(self.manifest_bytes.len())
            .map_err(|_| AhuError::InvalidOperation("manifest too large".into()))?;
        header.seal_offset = header.manifest_offset + u64::from(header.manifest_length);
        header.seal_length = u32::try_from(self.seal_bytes.len())
            .map_err(|_| AhuError::InvalidOperation("seal too large".into()))?;
        header.index_offset = header.seal_offset + u64::from(header.seal_length);
        header.index_length = index.len() as u64;
        header.data_offset = header
            .index_offset
            .checked_add(header.index_length)
            .ok_or_else(|| AhuError::InvalidOperation("bundle too large".into()))?;
        header.data_length = self.data.len() as u64;
        let mut out = Vec::new();
        header.write_to(&mut out)?;
        out.extend_from_slice(&self.manifest_bytes);
        out.extend_from_slice(&self.seal_bytes);
        out.extend_from_slice(&index);
        out.extend_from_slice(&self.data);
        Ok(out)
    }

    /// Look up an entry by its entry key (SHA-256 of DER CertID).
    /// Returns the default (discriminator=0) entry.
    pub fn lookup(&self, entry_key: &[u8; 32]) -> Option<&[u8]> {
        let idx = crate::index::binary_search(&self.index, entry_key)?;
        self.entry_at(idx)
    }

    /// Look up the best-matching entry given a list of preferred discriminators.
    pub fn lookup_preferred(&self, entry_key: &[u8; 32], preferences: &[u16]) -> Option<&[u8]> {
        let idx = crate::index::binary_search_preferred(&self.index, entry_key, preferences)?;
        self.entry_at(idx)
    }

    pub fn entry_at(&self, idx: usize) -> Option<&[u8]> {
        let record = self.index.get(idx)?;
        if record.is_tombstone() {
            return None;
        }
        let start = usize::try_from(record.data_offset).ok()?;
        let length = usize::try_from(record.data_length).ok()?;
        let end = start.checked_add(length)?;
        self.data.get(start..end)
    }

    /// Get the raw response bytes for an index record.
    pub fn entry_bytes(&self, record: &IndexRecord) -> Option<&[u8]> {
        if record.is_tombstone() {
            return None;
        }
        let start = usize::try_from(record.data_offset).ok()?;
        let length = usize::try_from(record.data_length).ok()?;
        let end = start.checked_add(length)?;
        self.data.get(start..end)
    }

    fn read_section(bytes: &[u8], offset: u64, length: u64) -> Result<Vec<u8>> {
        let range = usize::try_from(offset).ok().and_then(|start| {
            usize::try_from(length)
                .ok()
                .and_then(|len| start.checked_add(len).map(|end| start..end))
        });
        range
            .and_then(|r| bytes.get(r))
            .map(<[u8]>::to_vec)
            .ok_or(AhuError::HeaderOutOfBounds {
                field: "section",
                offset,
                length,
                file_size: bytes.len() as u64,
            })
    }

    fn parse_index(index_bytes: &[u8]) -> Result<Vec<IndexRecord>> {
        if index_bytes.len() % INDEX_RECORD_SIZE != 0 {
            return Err(AhuError::IndexSizeMismatch {
                size: index_bytes.len() as u64,
                record_size: INDEX_RECORD_SIZE,
            });
        }

        let count = index_bytes.len() / INDEX_RECORD_SIZE;
        let mut records = Vec::with_capacity(count);
        let mut cursor = Cursor::new(index_bytes);

        for _ in 0..count {
            records.push(IndexRecord::read_from(&mut cursor)?);
        }
        Ok(records)
    }
}

/// Builder for constructing ahu bundles.
pub struct BundleBuilder {
    pub manifest: Manifest,
    entries: Vec<(IndexRecord, Vec<u8>)>,
}

impl BundleBuilder {
    pub fn new(manifest: Manifest) -> Self {
        BundleBuilder {
            manifest,
            entries: Vec::new(),
        }
    }

    /// Add an entry. `certid_der` is the DER encoding of the CertID;
    /// `response_der` is the complete DER-encoded OCSPResponse.
    pub fn add_entry(&mut self, entry_key: [u8; 32], response_der: Vec<u8>) {
        self.add_entry_with_discriminator(entry_key, 0, response_der);
    }

    pub fn add_entry_with_discriminator(
        &mut self,
        entry_key: [u8; 32],
        discriminator: u16,
        response_der: Vec<u8>,
    ) {
        self.entries.push((
            IndexRecord {
                entry_key,
                data_offset: 0,
                data_length: response_der.len() as u32,
                flags: crate::index::IndexFlags::empty(),
                discriminator,
            },
            response_der,
        ));
    }

    /// Add a dual-CertID entry: one response payload indexed under two keys.
    ///
    /// Both records carry the full payload so that sorting doesn't break
    /// the pairing. During build, we deduplicate by data content so the
    /// payload is stored only once in the data section.
    pub fn add_dual_entry(
        &mut self,
        entry_key_1: [u8; 32],
        entry_key_2: [u8; 32],
        response_der: Vec<u8>,
    ) {
        self.add_dual_entry_with_discriminator(entry_key_1, entry_key_2, response_der, 0);
    }

    pub fn add_dual_entry_with_discriminator(
        &mut self,
        entry_key_1: [u8; 32],
        entry_key_2: [u8; 32],
        response_der: Vec<u8>,
        discriminator: u16,
    ) {
        let len = response_der.len() as u32;
        let flags = crate::index::IndexFlags::ALIAS | crate::index::IndexFlags::MULTI;
        self.entries.push((
            IndexRecord {
                entry_key: entry_key_1,
                data_offset: 0,
                data_length: len,
                flags,
                discriminator,
            },
            response_der.clone(),
        ));
        self.entries.push((
            IndexRecord {
                entry_key: entry_key_2,
                data_offset: 0,
                data_length: len,
                flags,
                discriminator,
            },
            response_der,
        ));
    }

    /// Add a tombstone (delta only). The discriminator must match the
    /// target record's discriminator to suppress the correct algorithm variant.
    pub fn add_tombstone(&mut self, entry_key: [u8; 32], discriminator: u16) {
        self.entries.push((
            IndexRecord {
                entry_key,
                data_offset: 0,
                data_length: 0,
                flags: crate::index::IndexFlags::TOMBSTONE,
                discriminator,
            },
            Vec::new(),
        ));
    }

    /// Build the bundle. `seal_fn` is called with the manifest bytes and
    /// must return a CMS SignedData (detached) as DER bytes.
    pub fn build<F>(mut self, seal_fn: F) -> Result<Vec<u8>>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>>,
    {
        // Sort entries by (key, discriminator), resolving alias data sharing.
        self.entries
            .sort_by_key(|a| (a.0.entry_key, a.0.discriminator));

        // Build data section and fix up offsets.
        // For ALIAS entries, deduplicate identical payloads so the data
        // is stored once even though two index records point at it.
        let mut data_section = Vec::new();
        let mut index_records = Vec::with_capacity(self.entries.len());
        let mut payload_offsets: std::collections::HashMap<[u8; 32], (u64, u32)> =
            std::collections::HashMap::new();

        for (mut record, payload) in self.entries {
            if record.is_tombstone() {
                record.data_offset = 0;
                record.data_length = 0;
                index_records.push(record);
                continue;
            }

            if record.is_alias() {
                let digest: [u8; 32] = Sha256::digest(&payload).into();
                if let Some(&(offset, len)) = payload_offsets.get(&digest) {
                    record.data_offset = offset;
                    record.data_length = len;
                    index_records.push(record);
                    continue;
                }
                let offset = data_section.len() as u64;
                let len = payload.len() as u32;
                data_section.extend_from_slice(&payload);
                payload_offsets.insert(digest, (offset, len));
                record.data_offset = offset;
                record.data_length = len;
            } else {
                let offset = data_section.len() as u64;
                record.data_offset = offset;
                record.data_length = payload.len() as u32;
                data_section.extend_from_slice(&payload);
            }

            index_records.push(record);
        }

        // Build index section.
        let mut index_section = Vec::with_capacity(index_records.len() * INDEX_RECORD_SIZE);
        for record in &index_records {
            record.write_to(&mut index_section)?;
        }

        // Compute integrity digests.
        let index_digest: [u8; 32] = Sha256::digest(&index_section).into();
        let data_digest: [u8; 32] = Sha256::digest(&data_section).into();

        // Update manifest with computed values.
        self.manifest.integrity.index_digest = index_digest;
        self.manifest.integrity.data_digest = data_digest;
        self.manifest.entry_count = index_records.len() as u64;

        // Encode manifest to deterministic CBOR.
        let manifest_bytes = self.manifest.to_cbor();

        // Generate seal over manifest.
        let seal_bytes = seal_fn(&manifest_bytes)?;

        // Compute section layout.
        let manifest_offset = HEADER_SIZE as u64;
        let manifest_length = manifest_bytes.len() as u32;
        let seal_offset = manifest_offset + manifest_length as u64;
        let seal_length = seal_bytes.len() as u32;
        let index_offset = seal_offset + seal_length as u64;
        let index_length = index_section.len() as u64;
        let data_offset = index_offset + index_length;
        let data_length = data_section.len() as u64;

        let header = FileHeader {
            format_major: crate::header::FORMAT_MAJOR,
            format_minor: crate::header::FORMAT_MINOR,
            manifest_offset,
            manifest_length,
            seal_offset,
            seal_length,
            index_offset,
            index_length,
            data_offset,
            data_length,
        };

        // Write the complete bundle.
        let total_size = data_offset as usize + data_section.len();
        let mut output = Vec::with_capacity(total_size);
        header.write_to(&mut output)?;
        output.extend_from_slice(&manifest_bytes);
        output.extend_from_slice(&seal_bytes);
        output.extend_from_slice(&index_section);
        output.extend_from_slice(&data_section);

        Ok(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::*;
    use uuid::Uuid;

    fn test_manifest() -> Manifest {
        Manifest {
            format_version: 1,
            bundle_id: Uuid::nil(),
            producer_id: "test".into(),
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
        }
    }

    #[test]
    fn build_and_read_empty_bundle() {
        let manifest = test_manifest();
        let builder = BundleBuilder::new(manifest);

        let bytes = builder
            .build(|manifest_bytes| {
                // Dummy seal: just echo the manifest hash as a "seal"
                Ok(Sha256::digest(manifest_bytes).to_vec())
            })
            .unwrap();

        let bundle = Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle.index.len(), 0);
        assert_eq!(bundle.manifest.entry_count, 0);
        assert_eq!(bundle.manifest.producer_id, "test");
    }

    #[test]
    fn build_and_lookup() {
        let manifest = test_manifest();
        let mut builder = BundleBuilder::new(manifest);

        let fake_certid = b"fake-certid-for-testing-1234567";
        let entry_key = crate::index::compute_entry_key(fake_certid);
        let response = b"fake-ocsp-response-bytes".to_vec();

        builder.add_entry(entry_key, response.clone());

        let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();

        let bundle = Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle.index.len(), 1);
        assert_eq!(bundle.manifest.entry_count, 1);

        let found = bundle.lookup(&entry_key).expect("entry should be found");
        assert_eq!(found, &response[..]);

        let missing = [0xFF; 32];
        assert!(bundle.lookup(&missing).is_none());
    }

    #[test]
    fn entries_are_sorted() {
        let manifest = test_manifest();
        let mut builder = BundleBuilder::new(manifest);

        // Add in reverse order.
        let key_b = [0xBB; 32];
        let key_a = [0xAA; 32];

        builder.add_entry(key_b, b"response-b".to_vec());
        builder.add_entry(key_a, b"response-a".to_vec());

        let bytes = builder.build(|m| Ok(Sha256::digest(m).to_vec())).unwrap();

        let bundle = Bundle::from_bytes(&bytes).unwrap();
        assert_eq!(bundle.index[0].entry_key, key_a);
        assert_eq!(bundle.index[1].entry_key, key_b);
    }
}
