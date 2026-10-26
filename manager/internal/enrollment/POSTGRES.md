# PostgreSQL token ledger (P1 increment)

The in-memory Store remains for isolated unit tests. SQLStore is the first central persistence adapter. It operates over an injected `*sql.DB`; no SQL dependencies are added to the Agent.

- `IssueToken`: 256-bit token generation; only SHA-256 digest stored; database-clock TTL.
- `ConsumeToken`: single conditional `UPDATE ... RETURNING`, atomic across concurrent Manager instances.
- A wrong-project, expired or already-used token does not grant enrollment.
- Requires `manager/migrations/0001_identity.up.sql`, externally configured `database/sql` PostgreSQL driver, TLS database connectivity, and migrations.

## Explicit limitations
This is **not a deployed enrollment endpoint**. Real onboarding must bind a CSR to an authorized project and use a single transaction linking token consumption, Agent record creation and issuance intent. If token consumption succeeds but certificate issuance fails, the workflow needs an idempotent resume/claim record; blindly issuing a new token could create duplicate identities. Management authorization and operator audit are not implemented here.

Production work remains: dependency/driver pinning, encrypted DB transport, integration tests against a real PostgreSQL instance, issuance transaction, PKI, revocation and rotation, metrics and abuse throttles.
