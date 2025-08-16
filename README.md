# zerok

[![CI](https://github.com/doriancodes/zerok/actions/workflows/ci.yml/badge.svg)](https://github.com/doriancodes/zerok/actions/workflows/ci.yml)

`zerok` is a command-line tool for analyzing and validating capability manifests.
It is part of the **k0** runtime ecosystem — a minimal, declarative execution layer designed around "zero trust for binaries."

## Documentation

Check the [documentation](https://doriancodes.github.io/zerok/) for more details.

## Features

- **Audit**: analyze ELF binaries or syscall traces to suggest capability manifests.
- **Inspect**: validate an existing manifest file for correctness.

## Usage

Audit a binary:
```bash
zerok audit elf ./mybinary
```

Inspect (validate) a manifest:
```bash
zerok inspect ./manifest.toml
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

## Development

## Workspace Structure & Build

This repository is organized as a [Cargo workspace](https://doc.rust-lang.org/book/ch14-03-cargo-workspaces.html) containing multiple crates:

- zerok → CLI for auditing and manifest validation
- zerok-core → shared types and helpers

Build commands:

```bash
# Build everything in the workspace
cargo build --workspace

# Build only the main CLI
cargo build -p zerok

```

Run commands:

```bash
# Run the main CLI
cargo run -p zerok -- --help
```

### Fuzzing

Make sure that you have cargo-fuzz

```bash
# install cargo-fuzz
cargo install cargo-fuzz

# manifest parser
cargo fuzz run fuzz_parse_manifest
```

## Roadmap
- More advanced static analysis for ELF binaries
- Integration with syscall trace auditing
- Expanded manifest schema checks
- .meta.toml inclusion
- Integration with Microkit/seL4
