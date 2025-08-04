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
