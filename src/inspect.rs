use crate::manifest;
use anyhow::{Context, Result};
use std::{fs, path::Path};

pub fn inspect<P: AsRef<Path>>(path: P) -> Result<()> {
    let bytes =
        fs::read(&path).with_context(|| format!("failed to read {}", path.as_ref().display()))?;
    let manifest = manifest::parse_manifest(&bytes)?;
    println!("Manifest is valid");
    println!("\nManifest Content:\n{}\n", manifest);
    Ok(())
}
