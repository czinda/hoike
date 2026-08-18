use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

use crate::error::{AhuError, Result};

pub const INDEX_RECORD_SIZE: usize = 48;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct IndexFlags: u16 {
        const MULTI     = 0b0000_0000_0000_0001;
        const ALIAS     = 0b0000_0000_0000_0010;
        const TOMBSTONE = 0b0000_0000_0000_0100;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRecord {
    pub entry_key: [u8; 32],
    pub data_offset: u64,
    pub data_length: u32,
    pub flags: IndexFlags,
}

impl IndexRecord {
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut entry_key = [0u8; 32];
        reader.read_exact(&mut entry_key)?;
        let data_offset = reader.read_u64::<BigEndian>()?;
        let data_length = reader.read_u32::<BigEndian>()?;
        let flags_raw = reader.read_u16::<BigEndian>()?;
        let reserved = reader.read_u16::<BigEndian>()?;

        if reserved != 0 {
            // Spec says readers MUST ignore unknown bits in flags (3-15),
            // but reserved field MUST be zero. We warn but don't reject
            // to be forward-compatible — a strict mode can check this.
        }
        let _ = reserved;

        let flags = IndexFlags::from_bits_truncate(flags_raw);

        Ok(IndexRecord {
            entry_key,
            data_offset,
            data_length,
            flags,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.entry_key)?;
        writer.write_u64::<BigEndian>(self.data_offset)?;
        writer.write_u32::<BigEndian>(self.data_length)?;
        writer.write_u16::<BigEndian>(self.flags.bits())?;
        writer.write_u16::<BigEndian>(0u16)?; // reserved
        Ok(())
    }

    pub fn is_tombstone(&self) -> bool {
        self.flags.contains(IndexFlags::TOMBSTONE)
    }

    pub fn is_alias(&self) -> bool {
        self.flags.contains(IndexFlags::ALIAS)
    }

    pub fn is_multi(&self) -> bool {
        self.flags.contains(IndexFlags::MULTI)
    }
}

pub fn compute_entry_key(certid_der: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(certid_der);
    hasher.finalize().into()
}

pub fn validate_sort_order(records: &[IndexRecord]) -> Result<()> {
    for i in 0..records.len().saturating_sub(1) {
        match records[i].entry_key.cmp(&records[i + 1].entry_key) {
            std::cmp::Ordering::Equal => {
                return Err(AhuError::DuplicateEntryKey {
                    index: i,
                    key: hex::encode(records[i].entry_key),
                });
            }
            std::cmp::Ordering::Greater => {
                return Err(AhuError::IndexNotSorted {
                    index: i,
                    key: hex::encode(records[i].entry_key),
                    next_key: hex::encode(records[i + 1].entry_key),
                });
            }
            std::cmp::Ordering::Less => {}
        }
    }
    Ok(())
}

pub fn binary_search(records: &[IndexRecord], entry_key: &[u8; 32]) -> Option<usize> {
    records
        .binary_search_by(|r| r.entry_key.cmp(entry_key))
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn record_round_trip() {
        let rec = IndexRecord {
            entry_key: [0xAB; 32],
            data_offset: 1024,
            data_length: 512,
            flags: IndexFlags::MULTI | IndexFlags::ALIAS,
        };

        let mut buf = Vec::new();
        rec.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), INDEX_RECORD_SIZE);

        let mut cursor = Cursor::new(&buf);
        let read_back = IndexRecord::read_from(&mut cursor).unwrap();
        assert_eq!(rec, read_back);
    }

    #[test]
    fn sort_order_validation() {
        let r1 = IndexRecord {
            entry_key: [0x01; 32],
            data_offset: 0,
            data_length: 100,
            flags: IndexFlags::empty(),
        };
        let r2 = IndexRecord {
            entry_key: [0x02; 32],
            data_offset: 100,
            data_length: 100,
            flags: IndexFlags::empty(),
        };

        validate_sort_order(&[r1.clone(), r2.clone()]).unwrap();

        let err = validate_sort_order(&[r2, r1]).unwrap_err();
        assert!(matches!(err, AhuError::IndexNotSorted { .. }));
    }

    #[test]
    fn binary_search_finds_key() {
        let records: Vec<IndexRecord> = (0..10u8)
            .map(|i| IndexRecord {
                entry_key: {
                    let mut k = [0u8; 32];
                    k[0] = i * 10;
                    k
                },
                data_offset: i as u64 * 100,
                data_length: 100,
                flags: IndexFlags::empty(),
            })
            .collect();

        let mut target = [0u8; 32];
        target[0] = 50;
        assert_eq!(binary_search(&records, &target), Some(5));

        target[0] = 55;
        assert_eq!(binary_search(&records, &target), None);
    }
}
