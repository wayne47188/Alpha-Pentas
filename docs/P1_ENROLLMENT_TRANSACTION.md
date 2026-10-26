# P1 Enrollment Transaction — Implementation Status

## Current implementation

Manager has a PostgreSQL-backed token ledger plus an **atomic claim transaction** in `manager/internal/enrollment/claim.go`:

1. Trusted API layer checks authenticated operator / authorized project, agent-generated key ownership and CSR proof-of-possession (NOT YET IMPLEMENTED).
2. `Claim` updates a matching, unconsumed, unexpired enrollment token using a DB-clock conditional UPDATE.
3. In the same transaction it creates an Agent in `pending` and a claim with CSR digest and `pending` state.
4. Any failed insert rolls the transaction back: token stays available if transaction aborts.
5. A separate future issuer worker must validate CSR and issue a short-lived cert. `FindClaim` enables status inspection for an authorized recovery workflow.

## Important limits
- Never expose `Claim` as a public endpoint directly. It does not independently verify CSR cryptographic signatures or role/project authorization.
- This version doesn't support idempotent replay after a **successful** claim commit when the response is lost; design recovery requires a narrowly scoped opaque receipt/proof bound to the CSR key, or a separately authenticated support flow. Do not accept claim ID as bearer authorization.
- Certificate signing/issuance, HSM or offline CA, audit events, rollback-after-issuance design, and distributed database integration tests are pending.
- No certificate/private key is ever generated or stored by this prototype.
- Migration 0002 requires 0001. Run database migrations using a controlled release process.
- SQLite and other embedded databases are not part of the endpoint Agent.

## Next validation gate

Postgres integration test with real DB: 32 concurrent claims on one token, exactly one success; verify rollback on Agent ID collision, project mismatch and expired token; verify restart/retry recovery. Then implement CSR verification and issuance state transition in a separate service.
