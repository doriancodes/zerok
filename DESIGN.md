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
| Dimension                 | **`.kpkg` runner**                                                   | **Docker/OCI**                                                | **Flatpak**                                                                    |
| ------------------------- | -------------------------------------------------------------------- | ------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| **Trust model**           | **Zero-trust by default**; binary + capabilities are signed together | Trusts image + runtime flags set at deploy time               | Trusts app + portal permissions; sandbox policy partly runtime/desktop-managed |
| **Policy source**         | **Inside the artifact** (`.kpkg.toml`, signed)                       | External runtime config (CLI flags, YAML, admission policies) | Manifest + permissions in Flatpak metadata; enforced by portals/sandbox        |
| **Enforcement default**   | **Deny-by-default**; only declared caps allowed                      | Permissive unless you add seccomp, AppArmor, RO mounts, etc.  | User-mediated permissions; portals restrict sensitive ops                      |
| **Crypto binding**        | **Binary + manifest** are cryptographically bound                    | Image is signed (optionally), runtime policy is not           | App metadata can be signed; runtime permissions separate                       |
| **Daemon required**       | **No** (single user-space binary)                                    | **Yes** (dockerd/containerd/cri-o)                            | Uses Flatpak/OSTree services                                                   |
| **Root requirements**     | Works rootless (user namespaces, Landlock, cgroups v2)               | Root/privileged helpers common; rootless improving but uneven | Desktop user level; system services handle mounts/sandbox                      |
| **Filesystem model**      | Optional: none (memfd exec) or tiny RO rootfs; selective bind-ins    | Layered rootfs; broad FS by default unless restricted         | OSTree runtime + RO app; portals for host access                               |
| **Syscall control**       | **Per-pkg seccomp** from manifest (strict allowlist)                 | Profiles exist but often generic; opt-in                      | Bubblewrap profile; not per-app declarative in the artifact                    |
| **File access**           | **Manifest → Landlock/RO binds**                                     | Mounts/volumes via runtime flags                              | Portals (user prompts) + predefined dirs                                       |
| **Network control**       | **Manifest → block/allowlist** (seccomp user-notif or cgroup BPF)    | Typically open; network policies external (CNI/K8s)           | Portals and sandbox rules; coarse-grained                                      |
| **Resource limits**       | **Manifest → cgroups/rlimits**                                       | cgroups via flags/compose/K8s manifests                       | Limited; desktop-oriented QoS                                                  |
| **Portability of policy** | **High**: policy ships with the app                                  | **Low–Medium**: policy lives outside the image                | **Medium**: metadata ships, but enforcement depends on host                    |
| **Startup overhead**      | **Very low** (no image pull/unpack; direct `exec`)                   | Medium (image pull/unpack; shim)                              | Medium (runtime setup, portals)                                                |
| **Attestation story**     | **Strong**: one signed blob = code + caps                            | Split: signed image + separate runtime config                 | Signed app + separate runtime decisions                                        |
| **Target domain**         | **Security-first CLI/services, CI/CD, prod hardening**               | General purpose packaging & deployment                        | Desktop apps, UX-friendly isolation                                            |

```bash
          ┌──────────────────────────────┐
          │  zerok (main process, MT)    │
          │------------------------------│
          │ - Parse & verify .kpkg       │
          │ - Build sandbox plan         │
          │ - Open staging dirfd         │
          │ - Create socketpair          │
          │ - Spawn helper (posix_spawn) │
          └──────────────┬───────────────┘
                         │ control FD + plan
                         ▼
          ┌──────────────────────────────┐
          │ zerok-launcher (helper, ST)  │
          │------------------------------│
          │ 1. Receive plan + dirfd      │
          │ 2. Stage binary:             │
          │    - O_TMPFILE + linkat       │
          │      (or tmp + rename)        │
          │ 3. Apply sandbox:             │
          │    - prctl(NO_NEW_PRIVS)      │
          │    - unshare namespaces       │
          │    - setup mounts/binds       │
          │    - join cgroups             │
          │    - install Landlock         │
          │    - load seccomp              │
          │    - drop caps / setuid        │
          │ 4. Signal "READY" to parent   │
          │ 5. execve(path)               │
          └──────────────┬───────────────┘
                         │ exec replaces process
                         ▼
          ┌──────────────────────────────┐
          │     Target binary (.kpkg)    │
          │   Running under sandbox      │
          │   Path visible to audit/AV   │
          └──────────────────────────────┘

Parent stays alive:
- Supervises child
- Forwards signals
- Unlinks staged binary after exec
- Logs run receipt
```
Legend:
- MT = multithreaded
- ST = single-threaded
- O_TMPFILE+linkat ensures atomic staging with a real audit-visible path
- Parent never forks → MT safety preserved
- Helper does all kernel capability setup before execve

[pipeline img]()
1. parent spawns helper (passes FD3 + optional dirfd)
2. parent sends plan
3. helper stages via O_TMPFILE+linkat (or tmp+rename)
4. helper applies sandbox (prctl, unshare, mounts, cgroups, Landlock, seccomp, drop caps/uids)
5. helper signals READY
6. helper execve(path)
7. kernel starts target binary
8. parent supervises & unlinks on exit, writes run receipt
9. parent collects status / forwards signals
