use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Read, Write};

use crate::error::{AhuError, Result};

pub const MAGIC: [u8; 4] = [0x41, 0x48, 0x55, 0x31]; // "AHU1"
pub const HEADER_SIZE: usize = 64;
pub const FORMAT_MAJOR: u16 = 0;
pub const FORMAT_MINOR: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHeader {
    pub format_major: u16,
    pub format_minor: u16,
    pub manifest_offset: u64,
    pub manifest_length: u32,
    pub seal_offset: u64,
    pub seal_length: u32,
    pub index_offset: u64,
    pub index_length: u64,
    pub data_offset: u64,
    pub data_length: u64,
}

impl FileHeader {
    pub fn read_from<R: Read>(reader: &mut R) -> Result<Self> {
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic)?;
        if magic != MAGIC {
            return Err(AhuError::BadMagic { found: magic });
        }

        let format_major = reader.read_u16::<BigEndian>()?;
        if format_major != FORMAT_MAJOR {
            let format_minor = reader.read_u16::<BigEndian>()?;
            return Err(AhuError::UnsupportedVersion {
                major: format_major,
                minor: format_minor,
            });
        }
        let format_minor = reader.read_u16::<BigEndian>()?;

        Ok(FileHeader {
            format_major,
            format_minor,
            manifest_offset: reader.read_u64::<BigEndian>()?,
            manifest_length: reader.read_u32::<BigEndian>()?,
            seal_offset: reader.read_u64::<BigEndian>()?,
            seal_length: reader.read_u32::<BigEndian>()?,
            index_offset: reader.read_u64::<BigEndian>()?,
            index_length: reader.read_u64::<BigEndian>()?,
            data_offset: reader.read_u64::<BigEndian>()?,
            data_length: reader.read_u64::<BigEndian>()?,
        })
    }

    pub fn write_to<W: Write>(&self, writer: &mut W) -> Result<()> {
        writer.write_all(&MAGIC)?;
        writer.write_u16::<BigEndian>(self.format_major)?;
        writer.write_u16::<BigEndian>(self.format_minor)?;
        writer.write_u64::<BigEndian>(self.manifest_offset)?;
        writer.write_u32::<BigEndian>(self.manifest_length)?;
        writer.write_u64::<BigEndian>(self.seal_offset)?;
        writer.write_u32::<BigEndian>(self.seal_length)?;
        writer.write_u64::<BigEndian>(self.index_offset)?;
        writer.write_u64::<BigEndian>(self.index_length)?;
        writer.write_u64::<BigEndian>(self.data_offset)?;
        writer.write_u64::<BigEndian>(self.data_length)?;
        Ok(())
    }

    pub fn validate_bounds(&self, file_size: u64) -> Result<()> {
        let check = |field: &'static str, offset: u64, length: u64| -> Result<()> {
            if offset.checked_add(length).is_none_or(|end| end > file_size) {
                return Err(AhuError::HeaderOutOfBounds {
                    field,
                    offset,
                    length,
                    file_size,
                });
            }
            Ok(())
        };

        check(
            "manifest",
            self.manifest_offset,
            self.manifest_length as u64,
        )?;
        check("seal", self.seal_offset, self.seal_length as u64)?;
        check("index", self.index_offset, self.index_length)?;
        check("data", self.data_offset, self.data_length)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn round_trip() {
        let header = FileHeader {
            format_major: FORMAT_MAJOR,
            format_minor: FORMAT_MINOR,
            manifest_offset: 64,
            manifest_length: 256,
            seal_offset: 320,
            seal_length: 512,
            index_offset: 832,
            index_length: 4800,
            data_offset: 5632,
            data_length: 102400,
        };

        let mut buf = Vec::new();
        header.write_to(&mut buf).unwrap();
        assert_eq!(buf.len(), HEADER_SIZE);

        let mut cursor = Cursor::new(&buf);
        let read_back = FileHeader::read_from(&mut cursor).unwrap();
        assert_eq!(header, read_back);
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = [0x00u8; HEADER_SIZE];
        let mut cursor = Cursor::new(&buf);
        let err = FileHeader::read_from(&mut cursor).unwrap_err();
        assert!(matches!(err, AhuError::BadMagic { .. }));
    }
}
