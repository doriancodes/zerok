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

```bash
zerok inspect <MANIFEST>
zerok audit elf <ELF_PATH> [--json FILE] [--manifest FILE]
zerok audit trace <TRACE_LOG> [--strict] [--json FILE] [--manifest FILE]
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
