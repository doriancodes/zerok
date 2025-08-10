import os, struct, pathlib, sys

# --- helpers ---
def w(path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def toml(s: str) -> bytes:
    return s.encode("utf-8")

def kpkg_bytes(manifest: bytes, binary: bytes, *, magic=b"KPKG", version=1,
               manifest_offset=40, binary_offset=None,
               manifest_size=None, binary_size=None,
               pad_to=40) -> bytes:
    if manifest_size is None: manifest_size = len(manifest)
    if binary_size   is None: binary_size   = len(binary)
    if binary_offset is None: binary_offset = manifest_offset + manifest_size
    # header: magic(4) | version(u16) | manifest_size(u32) | binary_size(u64) | binary_offset(u64) | manifest_offset(u64) | pad to 40
    hdr = bytearray()
    hdr += magic
    hdr += struct.pack("<H", version)
    hdr += struct.pack("<I", manifest_size)
    hdr += struct.pack("<Q", binary_size)
    hdr += struct.pack("<Q", binary_offset)
    hdr += struct.pack("<Q", manifest_offset)
    while len(hdr) < pad_to: hdr += b"\x00"
    return bytes(hdr) + manifest + binary

root = pathlib.Path(".")
p_manifest = root / "fuzz/corpus/fuzz_parse_manifest"
p_kpkg     = root / "fuzz/corpus/fuzz_kpkg_load"
p_manifest.mkdir(parents=True, exist_ok=True)
p_kpkg.mkdir(parents=True, exist_ok=True)

# -------- fuzz_parse_manifest seeds --------
w(p_manifest / "valid_minimal.toml", toml(
    'name = "demo"\n'
    'version = "0.1.0"\n'
))

w(p_manifest / "valid_full.toml", toml(
    'name = "myapp"\n'
    'version = "0.1.0"\n'
    '\n'
    '[capabilities.memory]\n'
    'max_bytes = 8388608\n'
    '\n'
    '[capabilities.files.read]\n'
    'paths = ["/etc/config"]\n'
    '\n'
    '[capabilities.network.connect]\n'
    'hosts = ["api.example.com:443"]\n'
))

# whitespace-only (should be rejected as empty)
w(p_manifest / "whitespace_only.toml", b"  \n\t  \n")

# invalid TOML syntax
w(p_manifest / "invalid_syntax.toml", toml('name = "demo\nversion = "0.1.0"\n'))

# unknown top-level key (relies on deny_unknown_fields)
w(p_manifest / "unknown_top_level.toml", toml(
    'extra = true\n'
    'name = "demo"\n'
    'version = "0.1.0"\n'
))

# nested unknown key under a table
w(p_manifest / "unknown_nested.toml", toml(
    'name = "demo"\n'
    'version = "0.1.0"\n'
    '\n'
    '[capabilities.files]\n'
    'bogus = 123\n'
))

# non-UTF8 bytes
w(p_manifest / "non_utf8.bin", b"\xff\xfe\xfa\x00\xff")

# empty file
w(p_manifest / "empty.toml", b"")


# -------- fuzz_kpkg_load seeds --------
# minimal valid kpkg (manifest minimal, tiny binary)
manifest_min = toml('name = "demo"\nversion = "0.1.0"\n')
binary_min   = b"\x7fELF"  # tiny placeholder
w(p_kpkg / "valid_minimal.kpkg", kpkg_bytes(manifest_min, binary_min))

# valid with capabilities
manifest_full = toml(
    'name = "myapp"\n'
    'version = "0.1.0"\n'
    '\n'
    '[capabilities.memory]\n'
    'max_bytes = 1024\n'
)
w(p_kpkg / "valid_with_caps.kpkg", kpkg_bytes(manifest_full, b"\x7fELF..."))

# bad magic
w(p_kpkg / "invalid_magic.kpkg", kpkg_bytes(manifest_min, binary_min, magic=b"XXXX"))

# overlapping offsets (binary_offset too small)
w(p_kpkg / "bad_offsets_overlap.kpkg", kpkg_bytes(
    manifest_min, b"BIN",
    binary_offset=41  # wrong: should be 40 + manifest_size
))

# truncated binary (header claims 100 bytes, provide only a few)
w(p_kpkg / "truncated_binary.kpkg", kpkg_bytes(
    manifest_min, b"tiny",
    binary_size=100
))

# huge manifest size claim (causes EOF during manifest read)
w(p_kpkg / "huge_manifest_size.kpkg", kpkg_bytes(
    b"just-a-bit", b"BIN",
    manifest_size=10_000_000  # unrealistic size
))

# invalid TOML in manifest (parse should fail)
w(p_kpkg / "invalid_manifest_toml.kpkg", kpkg_bytes(
    b'name = "broken\nversion="0.1.0"', b"BIN"
))

# zero sizes (empty manifest + empty binary) -> should fail on manifest empty
w(p_kpkg / "zero_sizes.kpkg", kpkg_bytes(
    b"", b"", manifest_size=0, binary_size=0
))

# extra trailing bytes after binary (not referenced by header)
extra = kpkg_bytes(manifest_min, binary_min) + b"TRAILING"
w(p_kpkg / "trailing_data.kpkg", extra)

print("Seed corpora written to:")
print(f" - {p_manifest}")
print(f" - {p_kpkg}")
