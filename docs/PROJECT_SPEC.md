# Alpha Pentas — Project Specification v0.1

Status: design baseline (2026-10-26); implementation not started.

## Product vision
Open-source, extensible endpoint operations and **authorized** security-assessment framework. Core and plugins are open-source. Public SDK should enable external contributors without patching the engine.

## Stack
- React + TypeScript: interactive console with paginated/virtualized event tables, live updates and task/evidence views.
- Go Manager: API, identity, coordination, task management, plugin registry, evidence validation, operator audit.
- Go Agent: a single lightweight binary; consistent core, optional plugin processes, peer networking; target initially 50 agents.
- Go CLI: first-class operator interface.
- Protobuf contracts, gRPC bidirectional streaming over HTTP/2 TLS; local gRPC IPC for plugins.
- PostgreSQL as authoritative structured store; S3-compatible artifact store. No database inside Engine.
- Interoperability with existing report system using versioned JSON and REST adapters.

## Functional requirements
1. Offline package delivery; first activation enrolls over authenticated transport.
2. Agent registration uses one-time token, unique key pair and X.509 mTLS.
3. Agent discovery uses signed manager membership lists with bounded cache.
4. Connectivity-domain leader elections are autonomous; election and route selection are separate concerns.
5. Relay messaging preserves source identity; distinguish relay receipt from manager durable acknowledgement.
6. Evidence and system-event collection, operator audit and verifiable custody.
7. Bounded in-memory buffering plus encrypted file spool for link interruption, without embedded DB.
8. Cross-language plugins using process + RPC, signed bundles, self-contained dependencies, approved whole-catalog sync and on-demand execution.
9. SOCKS5 TCP session functionality is scoped to authorized engagements with audit, limits and emergency stop.
10. Report import/export, findings and evidence linkage.

## MVP milestones
- P0: protobuf schemas, enrollment and security policy, CI and threat model.
- P1: manager/engine handshake, console and CLI, core audit and central persistence.
- P2: identity lifecycle, leader election validation and signed peer roster.
- P3: plugin SDK examples (Go and Python), signed releases and rollback.
- P4: system events, evidence ingestion and report integration.
- P5: full fault-injection and 50-agent resource validation; release readiness.

## Non-goals of initial release
Legacy OS certification, automated multi-hop routing, UDP/TUN, WASM runtime, on-demand plugin download, and unrestricted plugin execution. Do not treat designs as implemented features.

## Open source
Apache-2.0 is the *candidate* license only. Inventory any reused source, notices and GPL/AGPL compatibility before declaring final licensing.
