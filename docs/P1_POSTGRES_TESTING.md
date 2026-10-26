# P1 PostgreSQL Integration Test

This suite executes real PostgreSQL transactions rather than mocks. It exercises the migration chain and the SQL invariants behind enrollment.

Run on a **disposable** PostgreSQL database:

```bash
export DATABASE_URL="postgresql://alpha:alpha@127.0.0.1:5432/alpha_ci?sslmode=disable"
bash tests/integration/enrollment_postgres.sh
```

Tests:
- Apply identity/claim/certificate migrations 0001–0003.
- Launch 32 competing transaction attempts against one token; exactly one Agent and one claim should be persisted.
- Cause a duplicate-Agent error in a transaction and confirm token consumption rolls back.
- Reject project mismatch and expired tokens by DB-condition checks.

**Scope:** These are PostgreSQL-level integration tests. They do not yet invoke the Go `SQLStore.Claim` function, use a real CSR, or prove certificate issuance/revocation/mTLS. The script deliberately uses fixed test UUIDs, so it must only target an isolated disposable DB. Production must enforce authorization before beginning a transaction. Next CI step is a Go-level PostgreSQL driver integration test covering the precise Go methods and signer failure recovery.

Do not set a real production connection string in CI or run this script against live Manager data.
