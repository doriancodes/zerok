# Security

zerok is designed for high-assurance, least-privilege execution of packaged applications on an seL4-based runtime.
The following security controls are built in from the package creation stage through runtime execution.

1. End-to-End Provenance & Integrity
- Full-file signatures — the entire .kpkg (header + manifest + binary) is signed, preventing tampering or partial-file attacks
- Immutable manifests — manifest contents are part of the signed region, so capability grants cannot be modified without invalidating the signature.
- Anti-trailing-data enforcement — strict EOF check ensures no hidden payloads are appended after the signed content.
- Anti-rollback support — optional monotonically increasing epoch or version check to block downgrades to vulnerable builds.

2. Manifest-Driven Least Privilege
- Deny-by-default — zero capabilities unless explicitly declared in the manifest.
- Fine-grained capability model:
  - Filesystem: restrict by exact paths, no wildcards unless explicitly approved, symlink escape prevention.
  - Network: TLS enforced by default, optional SPKI pinning, explicit hostname/port declarations, UDP disabled unless requested.
  - Execution: spawning processes or loading shared libraries is disabled unless permitted.
  - Time/RNG: control precision of timers, select deterministic or cryptographically secure RNG providers.
- deny_unknown_fields manifest parsing — unrecognized fields at any level cause package load failure, preventing silent config drift.

3. Determinism & Reproducibility
- Reproducible packaging — identical source + manifest = identical .kpkg file (byte-for-byte).
- Fixed scheduling & resource quotas — ensures predictable runtime behavior across deployments.

4. Runtime Containment
- seL4 capability enforcement — loader grants only declared resources; no ambient authority.
- Isolated address spaces — CSpace/VSpace separation for each package.
- No container overhead — security isolation is kernel-enforced rather than namespace-based.

5. Resource Control & DoS Mitigation
- Memory caps — fixed RSS and total mapping limits.
- CPU quotas — fixed time-slice and jitter settings to control compute usage.
- I/O rate-limiting — (planned) per-package read/write/transfer ceilings.

6. Auditability
- High-signal logs — all denials, resource limit hits, and faults are logged.
- Tamper-resistant log chain — append-only, hash-chained log segments.
-  Remote log shipping — optional push to a secure collector for post-incident review.

7. Secure Update Path
- Signature verification on all updates — no unsigned or tampered .kpkg accepted.
- Optional staged rollouts — support for A/B updates and rollback prevention.

8. Attack Surface Reduction
- No dynamic linking by default — prevents RPATH/DLL hijack attacks.
- Minimal TCB — only loader/verifier, seL4 kernel, and declared service processes are in the trust base.
- HSM integration — for secure key storage and signing.
