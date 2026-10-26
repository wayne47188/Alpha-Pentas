# Deferred Decisions, Pending Validation and Delivery Roadmap

Design ADR-001–012 are accepted as baseline decisions, **not completed implementations**.

## Deferred design
- ADR-013: legacy operating system compatibility, particularly Windows Server 2008 R2, common legacy Linux variants and supported Go toolchains.
- ADR-014: on-demand plugin distribution; the initial release synchronizes approved, compatible packages but activates only on authorized tasks.
- Future: WASM plugin runtime; UDP proxying and network layer tunnelling; automated multi-hop routing; independent build farm and public plugin marketplace.

## MVP decisions requiring empirical validation
1. Quorum and membership-change safety: crash/restart, split-brain, fencing across domains.
2. Peer roster expiry / offline authority bounds / revocation delivery.
3. Spool quota and TTL (starting candidates: 32 MiB RAM, 256 MiB encrypted disk, 24 h); validate on target hosts.
4. Certificate lifetime and rotation (initial 7 days / rotate 48 hours early).
5. Signed package reproducibility, Python portability, plugin memory/CPU limits.
6. Report schema mapping to the existing report system.
7. API and visualization load: 50 connected agents, log burst and virtualized table latency.
8. Governance of third-party code and Apache-2.0 compatibility.

## Initial implementation batches
- P0: protocol definitions, security model, build, unit tests, tenant/project schema.
- P1: manager + engine connectivity, enrollment, heartbeat, audit and durable evidence.
- P2: agent election, signed peer membership and reliability/fault injection.
- P3: plugin registry, packages, signatures, Go/Python SDK and example extensions.
- P4: React workbench, CLI, report integration, documentation and open release gates.

## Explicit constraints
- No database or unrestricted local storage on Engine.
- No guarantee of lossless delivery with bounded buffers.
- No unverified claims of cross-platform support, proxy traversal or secure isolation.
- No deployment outside a written authorized engagement scope.
