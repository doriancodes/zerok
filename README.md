# zerok

[![CI](https://github.com/doriancodes/zerok/actions/workflows/ci.yml/badge.svg)](https://github.com/doriancodes/zerok/actions/workflows/ci.yml)


`zerok` is a command-line tool for creating secure, verifiable `.kpkg` packages based on a kernel-level capability model. It is part of the **k0** runtime ecosystem — a minimal, declarative execution layer designed around "zero trust for binaries."

## Documentation

Check the [documentation](https://doriancodes.github.io/zerok/) for more details

## Features

- Capability-based security via `.kpkg.toml`
- Simple binary packaging with embedded manifest
- Designed for integration with CI/CD, secure packaging, and runtime enforcement
- Flat binary format with `KPKG` magic header
- Unit tested, modular CLI with subcommands

## Usage

Create a `.kpkg` file from a folder with `binary` and `.kpkg.toml`:

```bash
zerok package --input ./project --output myapp.kpkg
```
Generate a key pair
```bash
zerok gen-key --private ed25519.key --public ed25519.pub
```
Sign the package
```bash
zerok sign --path myapp.kpkg --key ed25519.key
```
Verify the signature
```bash
zerok verify \
  --path myapp.kpkg \
  --pubkey ed25519.pub \
  --signature signature.sig
```
Inspect the package
```bash
zerok inspect --path myapp.kpkg
```
## Manifest Format
A .kpkg.toml file might look like:

```toml
name = "myapp"
version = "0.1.0"

[capabilities.memory]
max_bytes = 8388608

[capabilities.files.read]
paths = ["/etc/config"]

[capabilities.network.connect]
hosts = ["api.example.com:443"]
```

| Field Name        | Offset (bytes) | Size (bytes) | Description                           |
| ----------------- | -------------- | ------------ | ------------------------------------- |
| `magic`           | 0–3            | 4            | ASCII `"KPKG"` — file identifier      |
| `version`         | 4–5            | 2            | Format version (e.g. `1`)             |
| `manifest_size`   | 6–9            | 4            | Length of the manifest in bytes       |
| `binary_size`     | 10–17          | 8            | Length of the binary payload in bytes |
| `binary_offset`   | 18–25          | 8            | Start offset of the binary data       |
| `manifest_offset` | 26–33          | 8            | Start offset of the manifest data     |
| (padding)         | 34–39          | 6            | Reserved for future use               |

## Fuzzing

Make sure that you have cargo-fuzz

```bash
# install cargo-fuzz
cargo install cargo-fuzz

# manifest parser
cargo fuzz run fuzz_parse_manifest

# .kpkg loader
cargo fuzz run fuzz_kpkg_load
```

## Roadmap
- .meta.toml inclusion
- Integration with Microkit/seL4
