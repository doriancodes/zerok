
# zerok

`zerok` is a command-line tool for creating secure, verifiable `.kpkg` packages based on a kernel-level capability model. It is part of the **k0** runtime ecosystem — a minimal, declarative execution layer designed around "zero trust for binaries."

## Features

- Capability-based security via `.kpkg.toml`
- Simple binary packaging with embedded manifest
- Designed for integration with CI/CD, secure packaging, and runtime enforcement
- Flat binary format with `KPKG` magic header
- Unit tested, modular CLI with subcommands

## Example

Create a `.kpkg` file from a folder with `binary` and `.kpkg.toml`:

```bash
zerok package --input ./project --output myapp.kpkg
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
## Roadmap
- verify and inspect subcommands
- Digital signature support
- .meta.toml inclusion
- Integration with Microkit/seL4
