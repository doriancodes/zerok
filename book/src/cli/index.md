# CLI Reference

`zerok` is a command-line tool for building, signing, verifying, and inspecting `.kpkg` packages.

This section documents each subcommand with its purpose, required arguments, and examples. For authoritative flags in your build, run:

```bash
zerok --help
zerok <subcommand> --help
```
## Subcommands

- `package` — build a .kpkg from a folder containing a binary and .kpkg.toml.
- `gen-key`— generate an Ed25519 key pair for signing and verification.
- `sign` — produce a detached signature for a .kpkg using a private key.
- `verify` — verify a .kpkg against a public key + signature.
- `inspect` — print human-readable info about a .kpkg (header + manifest).
