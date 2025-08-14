use crate::kpkg::KpkgFile;
use anyhow::Result;
use std::path::PathBuf;

pub fn inspect(path: PathBuf) -> Result<()> {
    let kpkg = KpkgFile::load(&path)?;

    println!("KPKG v{}", kpkg.header.version);
    println!(
        "Manifest: offset={}, size={}",
        kpkg.header.manifest_offset, kpkg.header.manifest_size
    );
    println!(
        "Binary:   offset={}, size={}",
        kpkg.header.binary_offset, kpkg.header.binary_size
    );

    println!("\nManifest Content:\n{}\n", kpkg.manifest);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kpkg::KpkgHeader;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_inspect_output() -> anyhow::Result<()> {
        let manifest = br#"
name = "testapp"
version = "0.1.0"
"#;
        let binary = b"\x7fELF...";

        let header_size = 40u64;
        let manifest_offset = header_size;
        let manifest_size = manifest.len() as u32;
        let binary_offset = manifest_offset + manifest_size as u64;
        let binary_size = binary.len() as u64;

        let header = KpkgHeader {
            version: 1,
            manifest_size,
            binary_size,
            binary_offset,
            manifest_offset,
        };

        let mut file = NamedTempFile::new()?;
        file.write_all(&header.to_bytes())?;
        file.write_all(manifest)?;
        file.write_all(binary)?;
        file.flush()?;

        // Run inspect — just check it doesn't return an error
        inspect(file.path().to_path_buf())
    }
}
