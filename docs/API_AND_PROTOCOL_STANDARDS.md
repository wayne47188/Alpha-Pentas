# API, Protocol and Compatibility Standards

## Contract rules
- REST uses versioned paths (`/api/v1`), JSON schemas and documented status/error codes.
- Protobuf uses stable package versions (`alpha.v1`); do not reuse field numbers, reserve deleted fields, and document semantic changes.
- Every state-changing request needs a trace/correlation ID; retries use documented idempotency keys where needed.
- Reject unknown authority, mixed-tenant references, oversized payloads and invalid UUIDs at the boundary.
- Establish pagination and ordering for collections; avoid unbounded log/event responses.

## Error semantics
Errors identify category (validation, unauthenticated, forbidden, conflict, rate-limited, unavailable, internal) without leaking credentials or private topology. Use safe public messages and correlation IDs; detailed logs remain server-side with redaction.

## Agent and Manager compatibility
Document a supported protocol range and feature negotiation before rolling upgrades. Reject unsafe downgrade. Version certificates, plugin manifests and report interchange separately. Compatibility claims require contract and matrix tests.

## Data delivery
Distinct transport receipt, relay receipt and durable Manager acknowledgment. Bind origin identity, digest, project and sequence. Dedupe server-side and report gaps; never claim exactly-once semantics with bounded offline spooling.

## Change management
Breaking changes require architecture review, version strategy, tests, rollout plan, and migration notes. API docs must reflect implemented behavior, not proposals.
