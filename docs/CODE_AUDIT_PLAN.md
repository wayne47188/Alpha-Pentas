# Existing Code Quality Audit

Audit existing implementation before expanding the feature surface.

## Inventory
- Manager, Agent and CLI: formatting, cancellation, timeout and error handling.
- In-memory and PostgreSQL enrollment stores, claim and certificate issuance.
- Migration 0001–0003: constraints, concurrency, rollback and replay.
- Protobuf contract and compatibility handling.
- React dependencies and reproducible build.
- GitHub Actions integrity, workflow permissions and real integration coverage.

## Items requiring verification
- Signing operations performed while holding a database row lock.
- Absence of authenticated authorization on enrollment exposure paths.
- Claim IDs must not be treated as bearer authorization for public certificates.
- Incomplete retry / recovery behavior after connection loss.
- Inconsistent Go formatting and missing frontend lockfile.
- Shell SQL test does not directly exercise Go service methods.
- Certificate revocation has not been integrated into live transport.

For each confirmed finding, record affected path and line, severity, impact, test reproduction, proposed remediation and owner. Do not label suspected findings as verified without evidence.
