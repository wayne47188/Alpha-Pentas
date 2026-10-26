# Security, Validation & Release Gates

## Threat model
Assume potentially compromised endpoints; untrusted plugins; malicious or out-of-date peer rosters; relay outage; lost ACK; revoked identities; corrupted spool; operator error; compromised publisher credentials; network partitions; cross-tenant data access.

## Required controls
- Device-specific mTLS keys; one-time project-bound token enrollment, atomic consumption; expiry/re-enrollment and revocation with active-session termination.
- Sign and version peer rosters; verify tenant/project scope and message origin.
- Fencing for coordinated operations; never treat a higher Term field alone as proof.
- Operator authorization, approved engagement scope, session TTL, audit and immediate stop facilities.
- Plugin manifest/capability validation, detached publisher signatures, staged activation, privilege reduction and rollback.
- Server-side durable, append-only operator audit and evidence custody with object hashes. Endpoint signatures do not prove endpoint integrity.
- Encrypted bounded local file buffer (candidate: AES-256-GCM) with per-device protected keys, quotas and gap reporting.

## Fault-injection tests
1. Multiple simultaneous enrollments against same token; crash during CSR enrollment.
2. Certificate revocation during established gRPC streaming; re-enrollment after expiration.
3. Three-voter network partition; stale leader fencing; restart and membership replacement.
4. Relay receipt acknowledged but manager commit fails; final ACK lost after successful commit.
5. Encrypted spool corruption, disk full, unexpected kill, key loss, interrupted replay.
6. Malicious unsigned plugin, mismatched SDK contract, crash and rollback.
7. 50-agent load on 2 vCPU/8-GiB reference host; evaluate throughput, CPU, RSS, spool I/O, latency, UI P95.
8. Tenant/project scope isolation; evidence export/import round-trip with existing reporting system.
9. Backup recovery, credential rotation, audit-chain integrity, emergency stop.

## Release criterion
No claim of secure consensus, no-loss delivery or legacy OS support until evidence from reproducible automated tests exists. Open source license selected after third-party audit.
