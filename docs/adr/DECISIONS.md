# Architecture Decision Register — 2026-10-26

All decisions below are design decisions, **not implemented or tested capabilities**.

| ADR | Status | Decision |
|---|---|---|
| 001 Transport | Accepted | gRPC bidirectional streaming, HTTP/2, TLS; preserve transport abstraction |
| 002 Identity | Accepted | Single-use enrollment token; unique Agent ID, device key and X.509 mTLS; 7-day initial certificate policy; rotate 48 hours before expiry; expiry requires fresh enrollment |
| 003 Election | Accepted | Autonomous domain-scoped election; default three voters, quorum 2/3; versioned membership and fencing; Leader and route roles separated |
| 004 Peer / Relay | Accepted | Signed Manager peer roster with bounded cache, per-peer mTLS, origin identity, relay/final ACK distinction, dedup; Agent no embedded SQL; limited encrypted file spool |
| 005 Plugin | Accepted | Hybrid capabilities, process + local RPC, Go/Python SDK, protobuf contract, approved packaged dependencies, signature verification, whole-catalog sync and on-demand execution |
| 006 Audit / Evidence | Accepted | Separate operator audit, endpoint events and transport receipts; source attribution, SHA-256, signatures, custody metadata, central durable acknowledgement, append-only audit |
| 007 Storage | Accepted | PostgreSQL for relational metadata and audit; S3-compatible object store for binaries; evaluate indexing separately instead of prematurely introducing NoSQL |
| 008 SOCKS5 | Accepted | Authenticated operator-facing TCP session service, project scope controls, bounded sessions, per-session audit and cancellation; no UDP/TUN in MVP |
| 009 Console | Accepted | React + TypeScript with paginated history, virtualized logs, streamed deltas, stable API contracts and explicit performance tests |
| 010 Open Source | Accepted conditionally | Apache-2.0 license candidate, publisher provenance, signed releases, contributor governance; third-party source license audit required |
| 011 Reports | Accepted | Versioned JSON schemas, typed finding/asset/evidence association, idempotent REST integration with existing report engine |
| 012 Operations | Accepted | Isolated deployments, backup/restore, CA/key rotation, scoped RBAC, secret handling, incident response and reversible updates |
| 013 Legacy OS | Deferred | Prove Windows Server 2008 R2 and legacy Linux compatibility separately |
| 014 Plugin delivery | Deferred | On-demand distribution after initial approved full-catalog synchronization |

## Engineering cautions
- A short leader lease without a proven quorum/fencing implementation is not sufficient for split-brain safety.
- mTLS authenticates keys, not endpoint cleanliness or operator authority.
- In-memory buffers plus file spool cannot guarantee lossless data collection across overflow, power loss or key loss.
- A separate plugin process is **not** inherently an OS security sandbox.
- A 443 listener does not imply egress or enterprise proxy compatibility.
- No prebuilt third-party C2 tool is the platform core; borrowed source requires license and security review.
