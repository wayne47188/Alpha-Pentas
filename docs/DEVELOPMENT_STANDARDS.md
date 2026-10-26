# Development Standards — Alpha Pentas

## Architecture
- Keep Go dependencies directional: domain types contain no transport or persistence dependencies; application orchestrates operations; infrastructure implements adapters; API/gRPC expose bounded surfaces.
- Agent never embeds Manager SQL or CA private keys.
- Separate transport ACK and Manager durable ACK. Tenant/project authorization precedes data access.
- Keep public protocol versions explicit and minimize backwards-incompatible changes.

## Go
- gofmt; go vet; race detector; golangci-lint profile to be introduced with pinned version.
- Context propagation, deadlines, typed errors, explicit transaction boundaries and idempotency strategy.
- Avoid hidden mutable globals, unchecked errors, long-lived DB locks around external signing operations.
- Test success, validation, contention, expiry, rollback and replay for stateful methods.
- Favor table-driven tests; do not make network calls in unit tests.

## React / TypeScript
- Strict TS, no implicit any; accessible semantic controls; loading, empty and error states.
- Typed APIs and incremental data; avoid client-side megabyte event arrays.
- Commit lockfiles and use npm ci in CI; test frontend behavior.

## Database and migrations
- Immutable, ordered migrations, forward-only rollout on shared environments.
- Required referential integrity, tenant isolation and indexes justified by query workload.
- Apply migrations to disposable DB in CI; verify concurrency and failure recovery.
- No database access on Agent.

## Security
- Write authorization scopes and threat model for any new sensitive capability.
- Never log raw enrollment tokens, signing keys, customer data or evidence secrets.
- Signing keys protected separately from services; no self-signed production shortcuts.
- Verify privileges at API and DB boundaries; isolated plugins need OS enforcement.

## Documentation
- Every feature includes the reason, threat model implications, interfaces, tests and rollback plan.
- Keep status honest: design vs implemented vs integrated vs CI passing vs production-ready.

## Definition of Done
A change is DONE only when code is reviewed to the current project phase, formatting and lint checks pass, unit and relevant integration tests pass, docs and migration plans are updated, and security implications are addressed. In Phase A, independent human approval is **not mandatory**. In Phase B, it becomes mandatory.
