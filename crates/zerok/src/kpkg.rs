use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Error, Formatter};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

// === Manifest schema ===
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    name: String,
    version: String,
    #[serde(default)]
    capabilities: Capabilities,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct Capabilities {
    #[serde(default)]
    memory: Option<Memory>,
    #[serde(default)]
    files: Option<Files>,
    #[serde(default)]
    network: Option<Network>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Memory {
    max_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct Files {
    #[serde(default)]
    read: Option<FileRead>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FileRead {
    paths: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
struct Network {
    #[serde(default)]
    connect: Option<Connect>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Connect {
    hosts: Vec<String>,
}

impl Display for Manifest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::result::Result<(), Error> {
        match toml::to_string(self) {
            Ok(s) => write!(f, "{}", s),
            Err(_) => Err(Error),
        }
    }
}

pub fn parse_manifest(bytes: &[u8]) -> Result<Manifest> {
    // empty / whitespace-only guard (keeps a nice error)
    if bytes.is_empty() || bytes.iter().all(|b| b.is_ascii_whitespace()) {
        bail!("Manifest is empty");
    }

    // UTF-8
    let s = std::str::from_utf8(bytes).context("Manifest is not valid UTF-8")?;

    // TOML -> struct
    let manifest: Manifest = toml::from_str(s)
        .context("Manifest TOML is invalid or does not match the expected schema")?;

    // basic required-field checks (adjust to your rules)
    if manifest.name.trim().is_empty() {
        bail!("Manifest: 'name' must be non-empty");
    }
    if manifest.version.trim().is_empty() {
        bail!("Manifest: 'version' must be non-empty");
    }

    Ok(manifest)
}
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

fn validate_header(h: &KpkgHeader) -> anyhow::Result<()> {
    use anyhow::bail;
    if h.manifest_offset != 40 {
        bail!("Invalid manifest_offset");
    }
    if h.binary_offset != 40 + h.manifest_size as u64 {
        bail!("Invalid binary_offset");
    }
    // sizes fit in file will be checked by read_exact failing,
    // but we can still bound them reasonably:
    const MAX_MANIFEST: u64 = 1 << 20; // 1 MiB (evtl. adjust)
    const MAX_BINARY: u64 = 1 << 32; // 4 GiB (evtl. adjust)
    if h.manifest_size as u64 > MAX_MANIFEST {
        bail!("manifest too large");
    }
    if h.binary_size > MAX_BINARY {
        bail!("binary too large");
    }
    Ok(())
}

#[derive(Debug)]
pub struct KpkgFile {
    pub header: KpkgHeader,
    pub manifest: Manifest,
    pub binary: Vec<u8>,
}

impl KpkgFile {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut file =
            File::open(&path).with_context(|| format!("Failed to open {:?}", path.as_ref()))?;

        let mut header_buf = [0u8; 40];
        file.read_exact(&mut header_buf)?;
        let header = KpkgHeader::from_bytes(&header_buf)?;

        validate_header(&header)?;

        file.seek(SeekFrom::Start(header.manifest_offset))?;
        let mut manifest_buf = vec![0u8; header.manifest_size as usize];
        file.read_exact(&mut manifest_buf)?;
        let manifest_str = String::from_utf8(manifest_buf)?;
        let manifest: Manifest = toml::from_str(&manifest_str)
            .context("Manifest TOML is invalid or does not match the expected schema")?;

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

    fn write_kpkg(manifest: &[u8], binary: &[u8]) -> NamedTempFile {
        let header = KpkgHeader {
            version: 1,
            manifest_size: manifest.len() as u32,
            binary_size: binary.len() as u64,
            manifest_offset: 40,
            binary_offset: 40 + manifest.len() as u64,
        }
        .to_bytes();

        let mut file = NamedTempFile::new().expect("tmp file");
        file.write_all(&header).unwrap();
        file.write_all(manifest).unwrap();
        file.write_all(binary).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_kpkgfile_load_valid() -> Result<()> {
        let manifest = br#"
name = "demo"
version = "0.1.0"

[capabilities.memory]
max_bytes = 1024
"#;
        let binary = b"\x7fELF...";

        let file = write_kpkg(manifest, binary);

        let parsed = KpkgFile::load(file.path())?;
        assert_eq!(parsed.header.version, 1);
        assert_eq!(parsed.binary.len(), binary.len());

        // Manifest parsed correctly
        assert_eq!(parsed.manifest.name, "demo");
        assert_eq!(parsed.manifest.version, "0.1.0");
        assert!(parsed.manifest.capabilities.memory.as_ref().is_some());
        assert_eq!(
            parsed
                .manifest
                .capabilities
                .memory
                .as_ref()
                .unwrap()
                .max_bytes,
            1024
        );
        Ok(())
    }

    #[test]
    fn header_roundtrip_to_from_bytes() -> Result<()> {
        let hdr = KpkgHeader {
            version: 42,
            manifest_size: 123,
            binary_size: 4567,
            manifest_offset: 40,
            binary_offset: 40 + 123,
        };
        let bytes = hdr.to_bytes();
        assert_eq!(bytes.len(), 40, "header must be 40 bytes");

        let decoded = KpkgHeader::from_bytes(&bytes)?;
        assert_eq!(decoded.version, hdr.version);
        assert_eq!(decoded.manifest_size, hdr.manifest_size);
        assert_eq!(decoded.binary_size, hdr.binary_size);
        assert_eq!(decoded.manifest_offset, hdr.manifest_offset);
        assert_eq!(decoded.binary_offset, hdr.binary_offset);
        Ok(())
    }

    #[test]
    fn kpkgfile_load_rejects_invalid_magic() {
        let manifest = br#"name = "x"\nversion = "0.1.0""#;
        let binary = b"\x7fELF...";

        // Build a valid header then corrupt the magic
        let mut header = KpkgHeader {
            version: 1,
            manifest_size: manifest.len() as u32,
            binary_size: binary.len() as u64,
            manifest_offset: 40,
            binary_offset: 40 + manifest.len() as u64,
        }
        .to_bytes();
        header[0..4].copy_from_slice(b"XXXX"); // bad magic

        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&header).unwrap();
        file.write_all(manifest).unwrap();
        file.write_all(binary).unwrap();
        file.flush().unwrap();

        let err = KpkgFile::load(file.path()).expect_err("should fail on bad magic");
        let msg = format!("{err:#}");
        assert!(msg.contains("Invalid KPKG magic header"), "got: {msg}");
    }

    #[test]
    fn kpkgfile_load_rejects_invalid_toml() {
        // Missing closing quote -> invalid TOML
        let manifest = b"name = \"demo\nversion = \"0.1.0\"\n";
        let binary = b"\x7fELF...";

        let file = write_kpkg(manifest, binary);

        let err = KpkgFile::load(file.path()).expect_err("should fail on invalid TOML");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("Manifest TOML is invalid"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn manifest_display_serializes_to_toml() {
        // Build a Manifest and ensure Display prints valid TOML we can parse back
        let manifest = Manifest {
            name: "myapp".into(),
            version: "0.1.0".into(),
            capabilities: Capabilities {
                memory: Some(Memory {
                    max_bytes: 8_388_608,
                }),
                files: Some(Files {
                    read: Some(FileRead {
                        paths: vec!["/etc/config".into()],
                    }),
                }),
                network: Some(Network {
                    connect: Some(Connect {
                        hosts: vec!["api.example.com:443".into()],
                    }),
                }),
                ..Default::default()
            },
        };

        let s = format!("{}", manifest);
        // Contains key pieces
        assert!(s.contains(r#"name = "myapp""#));
        assert!(s.contains(r#"version = "0.1.0""#));
        assert!(s.contains("[capabilities.memory]"));
        assert!(s.contains("max_bytes = 8388608"));
        assert!(s.contains("[capabilities.files.read]"));
        assert!(s.contains(r#"paths = ["/etc/config"]"#));
        assert!(s.contains("[capabilities.network.connect]"));

        // Parse back to ensure it's valid TOML with same important data
        let parsed_back: Manifest = toml::from_str(&s).expect("displayed TOML parses");
        assert_eq!(parsed_back.name, "myapp");
        assert_eq!(parsed_back.version, "0.1.0");
        assert_eq!(
            parsed_back.capabilities.memory.unwrap().max_bytes,
            8_388_608
        );
        assert_eq!(
            parsed_back.capabilities.files.unwrap().read.unwrap().paths,
            vec!["/etc/config".to_string()]
        );
        assert_eq!(
            parsed_back
                .capabilities
                .network
                .unwrap()
                .connect
                .unwrap()
                .hosts,
            vec!["api.example.com:443".to_string()]
        );
    }

    #[test]
    fn kpkgfile_rejects_overlapping_offsets() {
        use tempfile::NamedTempFile;
        // craft header with wrong binary_offset
        let manifest = br#"name="a"
    version="0.1.0"
    "#;
        let bin = b"bin";
        let hdr = KpkgHeader {
            version: 1,
            manifest_size: manifest.len() as u32,
            binary_size: bin.len() as u64,
            manifest_offset: 40,
            binary_offset: 41, // WRONG: should be 40 + manifest_size
        }
        .to_bytes();

        // valid magic but bad offset
        let mut f = NamedTempFile::new().unwrap();
        use std::io::Write;
        f.write_all(&hdr).unwrap();
        f.write_all(manifest).unwrap();
        f.write_all(bin).unwrap();

        let err = crate::kpkg::KpkgFile::load(f.path()).unwrap_err();
        assert!(format!("{err:#}").contains("Invalid binary_offset"));
    }

    #[test]
    fn kpkgfile_rejects_truncated_payloads() {
        let manifest = br#"name="a"
    version="0.1.0"
    "#;
        // header says 100 bytes binary but provide less
        let hdr = KpkgHeader {
            version: 1,
            manifest_size: manifest.len() as u32,
            binary_size: 100,
            manifest_offset: 40,
            binary_offset: 40 + manifest.len() as u64,
        }
        .to_bytes();
        let mut f = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        f.write_all(&hdr).unwrap();
        f.write_all(manifest).unwrap();
        f.write_all(b"tiny").unwrap();
        let err = crate::kpkg::KpkgFile::load(f.path()).unwrap_err();
        assert!(
            format!("{err:#}").contains("failed to fill whole buffer")
                || format!("{err:#}").contains("unexpected EOF")
        );
    }
}

#[cfg(test)]
mod prop {
    use super::*;
    use proptest::prelude::*;
    use proptest::{collection::vec, option, string::string_regex};

    // --- Strategies ---------------------------------------------------------

    fn s_name() -> impl Strategy<Value = String> {
        // simple, stable app names
        string_regex("[a-zA-Z][a-zA-Z0-9_-]{0,31}").unwrap()
    }

    fn s_version() -> impl Strategy<Value = String> {
        // semver-ish "X.Y.Z" (no prerelease/build for now)
        (0u8..=20, 0u8..=20, 0u8..=20).prop_map(|(a, b, c)| format!("{a}.{b}.{c}"))
    }

    fn s_path() -> impl Strategy<Value = String> {
        // a few path segments like "/etc/conf", "/a/b", etc.
        vec(string_regex("[a-zA-Z0-9._-]{1,8}").unwrap(), 1..5)
            .prop_map(|segs| format!("/{}", segs.join("/")))
    }

    fn s_host() -> impl Strategy<Value = String> {
        // "api.example.com:443" style
        (
            string_regex("[a-z]{1,10}(?:-[a-z0-9]{1,6})?").unwrap(),
            string_regex("(?:[a-z0-9]{1,10}\\.){1,3}[a-z]{2,6}").unwrap(),
            1u16..=65535,
        )
            .prop_map(|(sub, dom, port)| format!("{sub}.{dom}:{port}"))
    }

    fn s_capabilities() -> impl Strategy<Value = Capabilities> {
        let mem = option::of((1u64..=16_000_000u64).prop_map(|max| Memory { max_bytes: max }));
        let files = option::of(
            option::of(vec(s_path(), 1..5).prop_map(|paths| FileRead { paths }))
                .prop_map(|read| Files { read }),
        );
        let net = option::of(
            option::of(vec(s_host(), 1..5).prop_map(|hosts| Connect { hosts }))
                .prop_map(|connect| Network { connect }),
        );
        (mem, files, net).prop_map(|(memory, files, network)| Capabilities {
            memory,
            files,
            network,
        })
    }

    fn s_manifest_struct() -> impl Strategy<Value = Manifest> {
        (s_name(), s_version(), s_capabilities()).prop_map(|(name, version, capabilities)| {
            Manifest {
                name,
                version,
                capabilities,
            }
        })
    }

    // --- Property tests -----------------------------------------------------

    proptest! {
        #[test]
        fn parse_manifest_roundtrips_for_valid_inputs(m in s_manifest_struct()) {
            // Serialize the random struct to TOML, then parse with the real parser
            let toml_str = toml::to_string(&m).expect("serialize to TOML");
            let parsed = parse_manifest(toml_str.as_bytes()).expect("parse_manifest");

            // Check key fields survived the round-trip (Display may reorder, so compare values)
            prop_assert_eq!(parsed.name, m.name);
            prop_assert_eq!(parsed.version, m.version);

            // Memory (Option) equivalence
            prop_assert_eq!(
                parsed.capabilities.memory.as_ref().map(|x| x.max_bytes),
                m.capabilities.memory.as_ref().map(|x| x.max_bytes)
            );

            // Files.read.paths equivalence (if present)
            prop_assert_eq!(
                parsed.capabilities.files.as_ref()
                    .and_then(|f| f.read.as_ref())
                    .map(|r| r.paths.clone()),
                m.capabilities.files.as_ref()
                    .and_then(|f| f.read.as_ref())
                    .map(|r| r.paths.clone())
            );

            // Network.connect.hosts equivalence (if present)
            prop_assert_eq!(
                parsed.capabilities.network.as_ref()
                    .and_then(|n| n.connect.as_ref())
                    .map(|c| c.hosts.clone()),
                m.capabilities.network.as_ref()
                    .and_then(|n| n.connect.as_ref())
                    .map(|c| c.hosts.clone())
            );
        }
    }

    proptest! {
        #[test]
        fn parse_manifest_rejects_non_utf8_bytes(b in any::<Vec<u8>>().prop_filter("non-empty non-utf8", |v| {
            !v.is_empty() && std::str::from_utf8(v).is_err()
        })) {
            let err = parse_manifest(&b).expect_err("should reject non-UTF8");
            let msg = format!("{err:#}");
            prop_assert!(msg.contains("not valid UTF-8"));
        }
    }

    proptest! {
        #[test]
        fn parse_manifest_rejects_whitespace_only(ws in "[ \\t\\n\\r]{1,64}") {
            let err = parse_manifest(ws.as_bytes()).expect_err("should reject whitespace-only");
            let msg = format!("{err:#}");
            prop_assert!(msg.contains("Manifest is empty"));
        }
    }

    proptest! {
        #[test]
        fn parse_manifest_rejects_unknown_fields(m in s_manifest_struct(), extra_key in string_regex("[a-zA-Z][a-zA-Z0-9_]{0,8}").unwrap()) {
            // Serialize valid manifest then append an unknown top-level key
            let mut s = toml::to_string(&m).expect("serialize");
            // Avoid colliding with existing keys
            let extra = if ["name","version","capabilities"].contains(&extra_key.as_str()) {
                "extra_field".to_string()
            } else {
                extra_key
            };
            s.push_str(&format!("\n{extra} = true\n"));

            let err = parse_manifest(s.as_bytes()).expect_err("deny_unknown_fields should reject");
            let msg = format!("{err:#}");
            prop_assert!(msg.contains("unknown field") || msg.contains("expected schema"));
        }
    }

    #[test]
    fn parse_manifest_rejects_empty_name_or_version() {
        // Empty name
        let bad = br#"
name = ""
version = "0.1.0"
"#;
        let err = parse_manifest(bad).unwrap_err();
        assert!(format!("{err:#}").contains("'name' must be non-empty"));

        // Empty version
        let bad = br#"
name = "demo"
version = ""
"#;
        let err = parse_manifest(bad).unwrap_err();
        assert!(format!("{err:#}").contains("'version' must be non-empty"));
    }

    proptest! {
        #[test]
        fn header_roundtrip_random(
            version in 0u16..=u16::MAX,
            msize  in 0u32..=1_000_000u32,
            bsize  in 0u64..=10_000_000u64,
        ) {
            let h = KpkgHeader {
                version,
                manifest_size: msize,
                binary_size: bsize,
                manifest_offset: 40,
                binary_offset: 40 + msize as u64,
            };
            let bytes = h.to_bytes();
            prop_assert_eq!(bytes.len(), 40);
            let h2 = KpkgHeader::from_bytes(&bytes).unwrap();
            prop_assert_eq!(h2.version, h.version);
            prop_assert_eq!(h2.manifest_size, h.manifest_size);
            prop_assert_eq!(h2.binary_size, h.binary_size);
            prop_assert_eq!(h2.manifest_offset, h.manifest_offset);
            prop_assert_eq!(h2.binary_offset, h.binary_offset);
        }
    }
}
