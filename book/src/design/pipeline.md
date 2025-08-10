# Capability Pipeline

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
