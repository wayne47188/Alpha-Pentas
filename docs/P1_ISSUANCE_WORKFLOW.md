# P1 Certificate Issuance — Leased State Machine

The issuance flow is now a short-transaction lease reservation followed by signing **outside database transactions** and a short fenced finalization transaction.

## State transitions
- `pending -> issuing`: atomic conditional `UPDATE ... RETURNING`; assigns random UUID lease owner, sets 45-second expiry and increments attempt counter.
- `issuing -> issued`: after successful signing, revalidate unexpired matching lease while holding a short row lock; persist certificate, bind certificate to claim, mark Agent active; commit atomically.
- `issuing -> pending`: signing error releases the lease if the same worker still owns it; cleanup uses a bounded independent context.
- `issuing -> issuing`: a new worker may acquire an **expired** lease; previous worker is fenced from committing, though its cryptographic signature operation may still finish.
- `issued`: a request with the same CSR can retrieve the saved public certificate if it remains valid and not revoked, subject to caller authorization at application/API layers.

## Limitations and required tests
1. The current lease is fixed at 45 seconds with no renewal. Slow signing can waste work and cause retries; bounded signing time and lease renewal need explicit design.
2. Out-of-band CA signer cannot be rolled back: a signed-but-uncommitted certificate may exist. Only database-committed certificates must be accepted by transport identity policy; CA serial/fingerprint revocation handling remains required.
3. Public receipt retrieval is **not** an authorization mechanism. The call site must verify operator/project/Agent binding; this method must not become a directly exposed endpoint.
4. PostgreSQL contention, worker termination, signer failure, takeover and clock/lease expiry races require end-to-end integration tests.
5. CA rotation, revocation and trusted transport enforcement remain unfinished.

Migrations 0001–0004 are required. No production-readiness claim until the above tests pass.
