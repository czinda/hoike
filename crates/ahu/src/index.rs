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

/// Algorithm discriminator for dual-algorithm bundles.
///
/// In single-algorithm bundles, all records have discriminator 0 (default).
/// In dual-algorithm bundles, the classical response uses 0 and the
/// post-quantum variant uses the algorithm-specific value.
pub const ALG_DISC_DEFAULT: u16 = 0;
pub const ALG_DISC_ML_DSA_44: u16 = 2;
pub const ALG_DISC_ML_DSA_65: u16 = 3;
pub const ALG_DISC_ML_DSA_87: u16 = 4;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexRecord {
    pub entry_key: [u8; 32],
    pub data_offset: u64,
    pub data_length: u32,
    pub flags: IndexFlags,
    pub discriminator: u16,
}

impl IndexRecord {
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut entry_key = [0u8; 32];
        reader.read_exact(&mut entry_key)?;
        let data_offset = reader.read_u64::<BigEndian>()?;
        let data_length = reader.read_u32::<BigEndian>()?;
        let flags_raw = reader.read_u16::<BigEndian>()?;
        let discriminator = reader.read_u16::<BigEndian>()?;
        let flags = IndexFlags::from_bits_truncate(flags_raw);

        Ok(IndexRecord {
            entry_key,
            data_offset,
            data_length,
            flags,
            discriminator,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&self.entry_key)?;
        writer.write_u64::<BigEndian>(self.data_offset)?;
        writer.write_u32::<BigEndian>(self.data_length)?;
        writer.write_u16::<BigEndian>(self.flags.bits())?;
        writer.write_u16::<BigEndian>(self.discriminator)?;
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
        let key_ord = records[i].entry_key.cmp(&records[i + 1].entry_key);
        match key_ord {
            std::cmp::Ordering::Greater => {
                return Err(AhuError::IndexNotSorted {
                    index: i,
                    key: hex::encode(records[i].entry_key),
                    next_key: hex::encode(records[i + 1].entry_key),
                });
            }
            std::cmp::Ordering::Equal => {
                match records[i].discriminator.cmp(&records[i + 1].discriminator) {
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
            std::cmp::Ordering::Less => {}
        }
    }
    Ok(())
}

/// Search for a record with the given key and discriminator 0 (default).
pub fn binary_search(records: &[IndexRecord], entry_key: &[u8; 32]) -> Option<usize> {
    binary_search_with_discriminator(records, entry_key, ALG_DISC_DEFAULT)
}

/// Search for a record with the given key and specific discriminator.
pub fn binary_search_with_discriminator(
    records: &[IndexRecord],
    entry_key: &[u8; 32],
    discriminator: u16,
) -> Option<usize> {
    records
        .binary_search_by(|r| {
            r.entry_key
                .cmp(entry_key)
                .then(r.discriminator.cmp(&discriminator))
        })
        .ok()
}

/// Search for the best-matching record given a list of preferred discriminators.
/// Tries each discriminator in order; returns the first hit. Falls back to
/// discriminator 0 if none of the preferences match.
pub fn binary_search_preferred(
    records: &[IndexRecord],
    entry_key: &[u8; 32],
    preferences: &[u16],
) -> Option<usize> {
    for &disc in preferences {
        if let Some(idx) = binary_search_with_discriminator(records, entry_key, disc) {
            return Some(idx);
        }
    }
    if !preferences.contains(&ALG_DISC_DEFAULT) {
        binary_search_with_discriminator(records, entry_key, ALG_DISC_DEFAULT)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn rec(key_byte: u8, disc: u16) -> IndexRecord {
        IndexRecord {
            entry_key: {
                let mut k = [0u8; 32];
                k[0] = key_byte;
                k
            },
            data_offset: 0,
            data_length: 100,
            flags: IndexFlags::empty(),
            discriminator: disc,
        }
    }

    #[test]
    fn record_round_trip() {
        let r = IndexRecord {
            entry_key: [0xAB; 32],
            data_offset: 1024,
            data_length: 512,
            flags: IndexFlags::MULTI | IndexFlags::ALIAS,
            discriminator: 0,
        };

        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), INDEX_RECORD_SIZE);

        let mut cursor = Cursor::new(&buf);
        let read_back = IndexRecord::read_from(&mut cursor).unwrap();
        assert_eq!(r, read_back);
    }

    #[test]
    fn record_round_trip_with_discriminator() {
        let r = IndexRecord {
            entry_key: [0xCD; 32],
            data_offset: 2048,
            data_length: 256,
            flags: IndexFlags::empty(),
            discriminator: ALG_DISC_ML_DSA_87,
        };

        let mut buf = Vec::new();
        r.write_to(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let read_back = IndexRecord::read_from(&mut cursor).unwrap();
        assert_eq!(r, read_back);
        assert_eq!(read_back.discriminator, ALG_DISC_ML_DSA_87);
    }

    #[test]
    fn sort_order_validation() {
        let r1 = rec(0x01, 0);
        let r2 = rec(0x02, 0);

        validate_sort_order(&[r1.clone(), r2.clone()]).unwrap();

        let err = validate_sort_order(&[r2, r1]).unwrap_err();
        assert!(matches!(err, AhuError::IndexNotSorted { .. }));
    }

    #[test]
    fn sort_order_same_key_different_discriminators() {
        let r1 = rec(0x01, 0);
        let r2 = rec(0x01, ALG_DISC_ML_DSA_87);
        validate_sort_order(&[r1, r2]).unwrap();
    }

    #[test]
    fn sort_order_same_key_same_discriminator_rejected() {
        let r1 = rec(0x01, ALG_DISC_ML_DSA_87);
        let r2 = rec(0x01, ALG_DISC_ML_DSA_87);
        let err = validate_sort_order(&[r1, r2]).unwrap_err();
        assert!(matches!(err, AhuError::DuplicateEntryKey { .. }));
    }

    #[test]
    fn sort_order_same_key_wrong_discriminator_order() {
        let r1 = rec(0x01, ALG_DISC_ML_DSA_87);
        let r2 = rec(0x01, 0);
        let err = validate_sort_order(&[r1, r2]).unwrap_err();
        assert!(matches!(err, AhuError::IndexNotSorted { .. }));
    }

    #[test]
    fn binary_search_finds_key() {
        let records: Vec<IndexRecord> = (0..10u8).map(|i| rec(i * 10, 0)).collect();

        let mut target = [0u8; 32];
        target[0] = 50;
        assert_eq!(binary_search(&records, &target), Some(5));

        target[0] = 55;
        assert_eq!(binary_search(&records, &target), None);
    }

    #[test]
    fn binary_search_with_discriminator_finds_variant() {
        let records = vec![rec(0x01, 0), rec(0x01, ALG_DISC_ML_DSA_87), rec(0x02, 0)];

        let mut key = [0u8; 32];
        key[0] = 0x01;

        assert_eq!(binary_search(&records, &key), Some(0));
        assert_eq!(
            binary_search_with_discriminator(&records, &key, ALG_DISC_ML_DSA_87),
            Some(1)
        );
        assert_eq!(
            binary_search_with_discriminator(&records, &key, ALG_DISC_ML_DSA_44),
            None
        );
    }

    #[test]
    fn binary_search_preferred_tries_in_order() {
        let records = vec![
            rec(0x01, 0),
            rec(0x01, ALG_DISC_ML_DSA_87),
            rec(0x02, 0),
            rec(0x02, ALG_DISC_ML_DSA_87),
        ];

        let mut key = [0u8; 32];
        key[0] = 0x01;

        assert_eq!(
            binary_search_preferred(&records, &key, &[ALG_DISC_ML_DSA_87]),
            Some(1)
        );
        assert_eq!(
            binary_search_preferred(&records, &key, &[ALG_DISC_ML_DSA_44, ALG_DISC_ML_DSA_87]),
            Some(1)
        );
        // Falls back to default when preference not found
        assert_eq!(
            binary_search_preferred(&records, &key, &[ALG_DISC_ML_DSA_44]),
            Some(0)
        );
        // Empty preferences → default
        assert_eq!(binary_search_preferred(&records, &key, &[]), Some(0));
    }
}
