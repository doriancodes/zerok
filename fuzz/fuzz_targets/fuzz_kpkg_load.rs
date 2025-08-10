#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// A semi-structured .kpkg builder so we hit deeper code more often than with pure bytes.
#[derive(Arbitrary, Debug)]
struct ManifestArb {
    // keep small to avoid huge allocations
    name: String,
    version: String,
    #[arbitrary(with = gen_bool)]
    with_mem: bool,
    mem_max: u32,
}

fn gen_bool(u: &mut arbitrary::Unstructured<'_>) -> arbitrary::Result<bool> {
    Ok(u.int_in_range(0..=1)? == 1)
}

fuzz_target!(|input: (ManifestArb, Vec<u8>)| {
    let (m, bin) = input;

    // Construct a TOML manifest (sometimes intentionally malformed)
    let manifest_toml = if m.name.is_empty() || m.version.is_empty() {
        // malformed top-level to exercise parse errors
        format!("name = \"{}\"", m.name.replace('"', ""))
    } else {
        let mut s = format!(
            "name = {:?}\nversion = {:?}\n",
            m.name.replace('\n', " "),
            m.version.replace('\n', " ")
        );
        if m.with_mem {
            s.push_str(&format!(
                "[capabilities.memory]\nmax_bytes = {}\n",
                m.mem_max
            ));
        }
        s
    };
    let manifest_bytes = manifest_toml.as_bytes();

    // Build a header (sometimes inconsistent) to exercise header checks + IO reads
    let manifest_size = manifest_bytes.len() as u32;
    let binary_size = (bin.len() % 1_000_000) as u64; // cap to keep it small
    let header = zerok::kpkg::KpkgHeader {
        version: 1,
        manifest_size,
        binary_size,
        manifest_offset: 40,
        binary_offset: 40 + manifest_size as u64,
    }
    .to_bytes();

    // Compose the file: header | manifest | maybe truncated binary (another class of bug)
    let mut file = Vec::with_capacity(40 + manifest_bytes.len() + bin.len());
    file.extend_from_slice(&header);
    file.extend_from_slice(manifest_bytes);
    // Intentionally sometimes cut the binary short to trigger EOF paths
    let cut = bin.len().saturating_sub(bin.len() % 7); // pseudo-random cut
    file.extend_from_slice(&bin[..cut]);

    // Expectation: never panic. Should either load OK or return Err cleanly.
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), &file).unwrap();
    let _ = zerok::kpkg::KpkgFile::load(tmp.path());
});
