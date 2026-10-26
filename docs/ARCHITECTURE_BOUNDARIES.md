# Architecture Boundaries and Dependency Direction

## Components
- **Manager**: authorization, enrollment, certificate records, task lifecycle, evidence/audit persistence and APIs.
- **Agent**: device identity, authorized transport, bounded spool and sandboxed plugin supervision; no relational database or CA private keys.
- **Console / CLI**: authenticated operator clients; never bypass Manager authorization.
- **Protocol**: versioned, language-neutral schemas; avoid exposing internal DB structures.
- **Plugin SDK**: stable extension contracts and capability declarations.

## Recommended Go layering
`domain` (entities/invariants) ← `application` (use cases/ports) ← `adapters` (Postgres, CA, network) ← `cmd` (assembly). Depend on narrow interfaces defined where consumed; avoid circular imports. Keep state-changing transactions in the application boundary with explicit rollback and idempotent recovery strategy.

## Ownership rules
Central identity/audit records are authoritative only after durable commit. External signing must not occur under unbounded database row locks. Roster and route decisions are distinct from election membership. Treat all Agent-reported data as untrusted until authenticated and validated.

## Refactoring acceptance
Move by behavior-preserving changes and tests. No sweeping folder rename without compilation checks, package dependency review and API compatibility verification.
