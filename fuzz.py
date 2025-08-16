import pathlib

# --- helpers ---
def w(path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)

def toml(s: str) -> bytes:
    return s.encode("utf-8")

root = pathlib.Path(".")
p_manifest = root / "fuzz/corpus/fuzz_parse_manifest"
p_manifest.mkdir(parents=True, exist_ok=True)

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

print("Seed corpora written to:")
print(f" - {p_manifest}")
