# Development Standards — Alpha Pentas

## Architecture
- Keep Go dependencies directional: domain types must not depend on transport or persistence; application orchestrates operations; infrastructure implements adapters.
- Agent does not embed Manager SQL or CA private keys.
- Separate transport acknowledgment from durable Manager acknowledgment.
- Define tenant and project authorization at every data boundary.
- Version public protocol contracts and document compatibility.

## Go
- Enforce gofmt, go vet, race tests and a pinned lint profile.
- Propagate context and deadlines; use typed errors and narrow transaction scopes.
- Avoid hidden mutable globals, unchecked errors and external signing under long-lived DB locks.
- Use table-driven tests for validation, contention, expiry, rollback, retry and replay.

## React and TypeScript
- Use strict TypeScript; document UI empty/loading/error states and accessibility.
- Typed APIs, paginated records and virtualized large datasets.
- Commit dependency lockfiles; use npm ci in CI.

## PostgreSQL
- Use ordered, immutable migrations and enforce foreign keys.
- Test migrations and critical transactional invariants on disposable databases.
- Keep database dependencies out of Agent.

## Security
- Document authorization scopes and threat models for sensitive capabilities.
- Do not log raw enrollment tokens, signing keys or customer evidence secrets.
- Protect CA keys independently and enforce runtime plugin isolation at OS boundaries.

## Definition of Done
Code should meet acceptance criteria, pass relevant automated checks, include adequate tests and documentation, address security implications, and provide migration / rollback notes where necessary.
