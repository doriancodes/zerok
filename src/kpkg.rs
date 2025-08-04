use anyhow::{Context, Result};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug)]
pub struct KpkgHeader {
    pub version: u16,
    pub manifest_size: u32,
    pub binary_size: u64,
    pub binary_offset: u64,
    pub manifest_offset: u64,
}

impl KpkgHeader {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = vec![];
        buf.extend(b"KPKG");
        buf.extend(&self.version.to_le_bytes());
        buf.extend(&self.manifest_size.to_le_bytes());
        buf.extend(&self.binary_size.to_le_bytes());
        buf.extend(&self.binary_offset.to_le_bytes());
        buf.extend(&self.manifest_offset.to_le_bytes());
        buf.resize(40, 0); // pad to 40 bytes
        buf
    }
}

impl KpkgHeader {
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        if &buf[0..4] != b"KPKG" {
            anyhow::bail!("Invalid KPKG magic header");
        }
        Ok(Self {
            version: u16::from_le_bytes([buf[4], buf[5]]),
            manifest_size: u32::from_le_bytes(buf[6..10].try_into()?),
            binary_size: u64::from_le_bytes(buf[10..18].try_into()?),
            binary_offset: u64::from_le_bytes(buf[18..26].try_into()?),
            manifest_offset: u64::from_le_bytes(buf[26..34].try_into()?),
        })
    }
}

#[derive(Debug)]
pub struct KpkgFile {
    pub header: KpkgHeader,
    pub manifest: String,
    pub binary: Vec<u8>,
}

impl KpkgFile {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file =
            File::open(&path).with_context(|| format!("Failed to open {:?}", path.as_ref()))?;

        let mut header_buf = [0u8; 40];
        file.read_exact(&mut header_buf)?;
        let header = KpkgHeader::from_bytes(&header_buf)?;

        file.seek(SeekFrom::Start(header.manifest_offset))?;
        let mut manifest_buf = vec![0u8; header.manifest_size as usize];
        file.read_exact(&mut manifest_buf)?;
        let manifest = String::from_utf8(manifest_buf)?;

        file.seek(SeekFrom::Start(header.binary_offset))?;
        let mut binary_buf = vec![0u8; header.binary_size as usize];
        file.read_exact(&mut binary_buf)?;

        Ok(Self {
            header,
            manifest,
            binary: binary_buf,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_kpkgfile_load_valid() -> Result<()> {
        let manifest = br#"
name = "demo"
version = "0.1.0"
[capabilities.memory]
max_bytes = 1024
"#;
        let binary = b"\x7fELF...";

        let header_size = 40u16;
        let manifest_offset = header_size as u64;
        let manifest_size = manifest.len() as u32;
        let binary_offset = manifest_offset + manifest_size as u64;
        let binary_size = binary.len() as u64;

        let mut header = vec![];
        header.extend(b"KPKG");
        header.extend(&header_size.to_le_bytes());
        header.extend(&manifest_size.to_le_bytes());
        header.extend(&binary_size.to_le_bytes());
        header.extend(&binary_offset.to_le_bytes());
        header.extend(&manifest_offset.to_le_bytes());
        header.resize(40, 0);

        let mut file = NamedTempFile::new()?;
        file.write_all(&header)?;
        file.write_all(manifest)?;
        file.write_all(binary)?;
        file.flush()?;

        let parsed = KpkgFile::load(file.path())?;
        assert_eq!(parsed.manifest.contains("demo"), true);
        assert_eq!(parsed.binary.len(), binary.len());
        Ok(())
    }
}
