use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Error, Formatter};

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
}
