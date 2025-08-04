use crate::kpkg::KpkgHeader;
use anyhow::{Context, Result};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

/// Options for the `zerok package` subcommand
#[derive(Debug, Clone)]
pub struct PackageOptions {
    pub input: PathBuf,
    pub output: PathBuf,
}

pub fn package(opts: PackageOptions) -> Result<()> {
    let binary_path = opts.input.join("binary");
    let manifest_path = opts.input.join(".kpkg.toml");

    let binary = fs::read(&binary_path)
        .with_context(|| format!("Failed to read binary at {:?}", binary_path))?;
    let manifest = fs::read(&manifest_path)
        .with_context(|| format!("Failed to read manifest at {:?}", manifest_path))?;

    let header = KpkgHeader {
        version: 1,
        manifest_size: manifest.len() as u32,
        binary_size: binary.len() as u64,
        manifest_offset: 40,
        binary_offset: 40 + manifest.len() as u64,
    };

    let mut file = File::create(&opts.output)?;
    file.write_all(&header.to_bytes())?;
    file.write_all(&manifest)?;
    file.write_all(&binary)?;
    file.flush()?;

    println!("Created .kpkg file at {}", opts.output.display());
    Ok(())
}
