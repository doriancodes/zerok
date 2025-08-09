# Design

## Capability pipeline

 
```bash

┌────────────┐      ┌───────────┐      ┌────────────────┐      ┌──────────────────┐
│  .kpkg     │ ───▶ │ Verifier  │ ───▶ │ Policy Compiler │ ───▶ │ seL4 Objects     │
│ (flat file)│      │ (sig+hash)│      │ (.kpkg.toml →  │      │ (CSpace/VSpace,  │
│ hdr+bin+mf │      └───────────┘      │  caps & limits) │      │ endpoints, frames)│
└────────────┘                         └────────────────┘      └────────┬─────────┘
                                                                          │
                                                             ┌────────────▼────────────┐
                                                             │  Loader / Spawner       │
                                                             │  (map ELF, populate     │
                                                             │   CSpace, set TCB)      │
                                                             └────────────┬────────────┘
                                                                          │
                                                       ┌──────────────────▼──────────────────┐
                                                       │           Target Process            │
                                                       │   (runs with ONLY issued caps)      │
                                                       └───────────────┬─────────────────────┘
                                                                       │ capability invocations
                                                     ┌─────────────────▼──────────────────┐
                                                     │  seL4 Kernel (formally verified)  │
                                                     │  (auth checks, isolation, faults) │
                                                     └───────────────┬────────────────────┘
                                                                     │ faults/denials
                                                ┌────────────────────▼────────────────────┐
                                                │   Auditor (logs, traces, attest)       │
                                                │  (CI export, JSON, capability diffs)   │
                                                └─────────────────────────────────────────┘
```

## Zerok/sel4 mapping

```bash

[capabilities.memory.max_bytes]  → untyped → frames → mapped into VSpace
[capabilities.files.read.paths]  → endpoint cap to FileSrv(ns="/etc/config" only)
[capabilities.network.connect]   → endpoint cap to NetSrv(allowlist={IP:port}, TLS reqs)
[capabilities.ipc.*]             → explicit endpoint caps to listed services only
[capabilities.exec.spawn]        → (optional) guarded spawn service; absent by default
```

## CSpace layout example (tight process)
```bash
 
Slot  Cap
----  ------------------------------------------------------------
0     CNode (self)
1     TCB (self)
2     VSpace root (page directory)
3     Reply cap (runtime-internal)
4     Endpoint: FileSrv("/etc/config" RO only)
5     Endpoint: NetSrv({203.0.113.10:443, 2001:db8::1:443}, TLS=yes, SPKI pin=…)
6     Timer (optional deterministic time server)
7     DebugLog (write-only, rate-limited)
8..n  (empty; anything else triggers a cap fault)
```

## Spawn timeline (deterministic)

```bash
1) Parse header → verify signature → hash whole file (hdr+manifest+bin)
2) Resolve DNS at compile time → IP set baked into NetSrv cap
3) Canonicalize file paths against FileSrv namespace
4) Allocate exactly N bytes untyped → frames → map code/rodata/stack/heap
5) Populate CSpace with ONLY the caps implied by the manifest
6) Start TCB at entrypoint; block all env vars / RPATH / dlopen unless declared
7) On any unauthorized action → kernel raises fault → Auditor records event

```
## Example Audit log

```bash

{
  "pkg": {"name":"myapp","version":"0.1.0","hash":"sha256:…"},
  "host": {"platform":"seL4","loader_rev":"zerok-0.3.0"},
  "run_id": "2025-08-09T12:34:56Z-7f9c",
  "events": [
    {
      "ts":"2025-08-09T12:35:01.234Z",
      "type":"cap_deny",
      "syscall":"openat",
      "target":"/etc/shadow",
      "policy":"files.read",
      "ip":"0x4012aa",
      "tid":1
    },
    {
      "ts":"2025-08-09T12:35:03.008Z",
      "type":"net_connect",
      "dest":"203.0.113.10:443",
      "tls":{"sni":"api.example.com","spki_pin_ok":true}
    }
  ],
  "resources":{"max_rss":7340032,"mapped_bytes":8388608,"cpu_ms":1234},
  "exit":{"code":0,"reason":"clean"}
}
```
