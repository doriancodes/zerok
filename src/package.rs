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

/// Implements the packaging logic
pub fn package(opts: PackageOptions) -> Result<()> {
    let binary_path = opts.input.join("binary");
    let manifest_path = opts.input.join(".kpkg.toml");

    let binary = fs::read(&binary_path)
        .with_context(|| format!("Failed to read binary at {:?}", binary_path))?;
    let manifest = fs::read(&manifest_path)
        .with_context(|| format!("Failed to read manifest at {:?}", manifest_path))?;

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

    let mut file = File::create(&opts.output)?;
    file.write_all(&header)?;
    file.write_all(&manifest)?;
    file.write_all(&binary)?;
    file.flush()?;

    println!("Created .kpkg file at {}", opts.output.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn dummy_manifest() -> Vec<u8> {
        r#"
            name = "testapp"
            version = "0.1.0"

            [capabilities.memory]
            max_bytes = 4096
        "#
        .as_bytes()
        .to_vec()
    }

    fn dummy_binary() -> Vec<u8> {
        b"\x7fELF...dummy".to_vec()
    }

    #[test]
    fn test_package_creates_file() {
        let dir = tempdir().unwrap();
        let input_dir = dir.path().join("input");
        fs::create_dir(&input_dir).unwrap();

        fs::write(input_dir.join("binary"), dummy_binary()).unwrap();
        fs::write(input_dir.join(".kpkg.toml"), dummy_manifest()).unwrap();

        let output = dir.path().join("test.kpkg");
        let opts = PackageOptions {
            input: input_dir,
            output: output.clone(),
        };

        package(opts).expect("packaging should succeed");

        let output_data = fs::read(&output).expect("should have created kpkg file");
        assert!(output_data.starts_with(b"KPKG"), "missing magic header");
        assert!(
            output_data.len() > 40,
            "header should be followed by content"
        );
    }

    #[test]
    fn test_invalid_input_directory() {
        let opts = PackageOptions {
            input: PathBuf::from("/nonexistent"),
            output: PathBuf::from("/tmp/should_not_exist.kpkg"),
        };

        let result = package(opts);
        assert!(result.is_err(), "should fail on nonexistent input path");
    }
}
