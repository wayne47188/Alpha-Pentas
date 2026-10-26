# Existing Code Quality Audit (pending execution)

Do not continue adding functional scope until this audit is completed with concrete evidence.

## Audit inventory
- Go manager / agent / CLI: formatting, error semantics, HTTP server shutdown and exposure.
- Enrollment in-memory / SQL stores, claim, CSR validation and issuer.
- PostgreSQL migrations 0001–0003: constraints, transactions, replay, uniqueness and certificate overlap.
- Protocol protobuf compatibility and generated code requirements.
- React build/toolchain lockfiles and quality checks.
- GitHub Actions behavior, dependencies/permissions and integration tests.

## Initial findings to verify
- **High:** issuance of a certificate while holding DB transaction/row lock; potential contention and signer latency.
- **High:** some enrollment paths are not integrated with an authenticated, authorized API. They MUST NOT be exposed.
- **High:** a claim ID must never grant authority to retrieve certificate bytes.
- **Medium:** loss-of-response idempotency and token claim replay recovery are incomplete.
- **Medium:** committed Go formatting is not consistently normalized; current CI may mask violations.
- **Medium:** frontend lockfile and reproducible build missing.
- **Medium:** integration shell script verifies simplified SQL, not complete Go service methods.
- **Medium:** certificates and revocation have no live transport enforcement yet.

For each finding record source file/line, impact, reproduction, proposed fix, regression test, severity and owner. No claim of verified findings until evidence is collected.
