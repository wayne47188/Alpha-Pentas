# Testing Strategy

## Test pyramid
1. **Unit**: deterministic domain behavior, validation, error paths; no external services.
2. **Component**: application services with controlled fakes for clock, signer, repository and authorization.
3. **Integration**: actual PostgreSQL migrations, concurrent registration, rollback and recovery; isolated test database per job.
4. **Contract**: backward compatibility of protobuf/API payloads and published plugin SDK.
5. **End-to-end**: real Manager/Agent mTLS enrollment against ephemeral CA, revocation and restart.
6. **Security**: negative authorization, cross-tenant isolation, malformed CSR, token replay, expiration, key rotation and compromised plugin.
7. **Resilience**: partitions, process crash, disk exhaustion, signer outage and lost acknowledgments.
8. **Load**: agent capacity, latency, memory and database contention with reproducible thresholds.

## Required test cases
For every state-changing operation cover: success; invalid input; unauthorized caller; wrong tenant/project; expiry; concurrency; repeat/replay; partial failure; timeout/cancellation; durable restart. Ensure tests exercise real application methods, not merely similar SQL statements.

## CI gates
- Go formatting check must be read-only; go vet, race-enabled unit tests, static analysis.
- React strict TypeScript build, lint, component tests and dependency lockfile.
- PostgreSQL real integration with migrations, schema consistency and application code.
- Secret scan, dependency vulnerability scan and CodeQL where feasible.
- Report coverage trends, but do not use a single coverage percentage as proof of security.

## Quality evidence
Every pull request identifies changed behavior, test commands, actual results, and untested risks. Flaky tests are bugs; do not hide failures by unconditional retries. Publish redacted artifacts and traces only.

## Environment
Never point CI at production or customer data. Use disposable credentials and explicit DB host checks. Fix external dependencies and tool versions for repeatable results. All e2e testing uses isolated authorized fixtures.
