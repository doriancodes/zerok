use crate::kpkg::{KpkgHeader, parse_manifest};
use anyhow::{Context, Result, bail};
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

    let _manifest = parse_manifest(&manifest)?;
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::{NamedTempFile, tempdir};

    fn write_file(path: &PathBuf, bytes: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, bytes).unwrap();
    }

    fn read_all(path: &PathBuf) -> Vec<u8> {
        let mut f = File::open(path).unwrap();
        let mut buf = Vec::new();
        f.read_to_end(&mut buf).unwrap();
        buf
    }

    #[test]
    fn package_writes_correct_layout_and_header() {
        // Arrange: temp input dir with manifest + binary
        let dir = tempdir().unwrap();
        let input = dir.path().join("in");
        std::fs::create_dir_all(&input).unwrap();

        let manifest_bytes = br#"
name = "demo"
version = "0.1.0"
"#;
        let binary_bytes = b"\x7fELF\x02\x01\x01...fake-binary...";

        let manifest_path = input.join(".kpkg.toml");
        let binary_path = input.join("binary");
        write_file(&manifest_path, manifest_bytes);
        write_file(&binary_path, binary_bytes);

        // Output file path
        let out_file = NamedTempFile::new().unwrap();
        let output = PathBuf::from(out_file.path());

        // Act
        let opts = PackageOptions {
            input: input.clone(),
            output: output.clone(),
        };
        package(opts).expect("package() should succeed");

        // Assert: file exists and size matches header + manifest + binary
        let out_bytes = read_all(&output);
        let expected_total_len = 40 + manifest_bytes.len() + binary_bytes.len();
        assert_eq!(
            out_bytes.len(),
            expected_total_len,
            "unexpected total output size"
        );

        // First 40 bytes are header; then manifest; then binary
        let (header_buf, rest) = out_bytes.split_at(40);
        let (manifest_out, binary_out) = rest.split_at(manifest_bytes.len());

        assert_eq!(manifest_out, manifest_bytes, "manifest payload mismatch");
        assert_eq!(binary_out, binary_bytes, "binary payload mismatch");

        // Header correctness: construct the expected header and compare bytes
        let expected_header = KpkgHeader {
            version: 1,
            manifest_size: manifest_bytes.len() as u32,
            binary_size: binary_bytes.len() as u64,
            manifest_offset: 40,
            binary_offset: 40 + manifest_bytes.len() as u64,
        };
        let expected_header_bytes = expected_header.to_bytes();
        assert_eq!(
            header_buf,
            expected_header_bytes.as_slice(),
            "header bytes mismatch"
        );
    }

    #[test]
    fn package_errors_when_manifest_is_empty() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("in");
        std::fs::create_dir_all(&input).unwrap();

        // Empty manifest + empty binary
        let manifest_bytes: &[u8] = b"";
        let binary_bytes: &[u8] = b"";

        write_file(&input.join(".kpkg.toml"), manifest_bytes);
        write_file(&input.join("binary"), binary_bytes);

        let out_file = NamedTempFile::new().unwrap();
        let output = PathBuf::from(out_file.path());

        let opts = PackageOptions {
            input: input.clone(),
            output: output.clone(),
        };
        let err = package(opts).expect_err("empty manifest must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Manifest is empty") || msg.contains("Manifest"),
            "got: {msg}"
        );
    }

    #[test]
    fn package_errors_when_manifest_is_whitespace() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("in");
        std::fs::create_dir_all(&input).unwrap();

        write_file(&input.join(".kpkg.toml"), b"   \n\t ");
        write_file(&input.join("binary"), b"\x00");

        let out_file = NamedTempFile::new().unwrap();
        let output = PathBuf::from(out_file.path());

        let opts = PackageOptions { input, output };
        let err = package(opts).expect_err("whitespace-only manifest must error");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Manifest is empty") || msg.contains("Manifest"),
            "got: {msg}"
        );
    }

    #[test]
    fn package_errors_when_manifest_missing() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("in");
        std::fs::create_dir_all(&input).unwrap();

        // Only binary present
        write_file(&input.join("binary"), b"\x00\x01binary");

        let out_file = NamedTempFile::new().unwrap();
        let output = PathBuf::from(out_file.path());

        let opts = PackageOptions {
            input: input.clone(),
            output: output.clone(),
        };
        let err = package(opts).expect_err("should error when manifest is missing");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to read manifest"),
            "error should include context about missing manifest; got: {msg}"
        );
    }

    #[test]
    fn package_errors_when_binary_missing() {
        let dir = tempdir().unwrap();
        let input = dir.path().join("in");
        std::fs::create_dir_all(&input).unwrap();

        // Only manifest present
        write_file(&input.join(".kpkg.toml"), b"name = 'demo'\n");

        let out_file = NamedTempFile::new().unwrap();
        let output = PathBuf::from(out_file.path());

        let opts = PackageOptions {
            input: input.clone(),
            output: output.clone(),
        };
        let err = package(opts).expect_err("should error when binary is missing");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Failed to read binary"),
            "error should include context about missing binary; got: {msg}"
        );
    }
}
