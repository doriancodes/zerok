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
