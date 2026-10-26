# Enrollment token prototype (P1)

This module generates 256-bit one-time secrets, stores only SHA-256 digests, binds tokens to project IDs, checks expiry, and atomically claims tokens **within a single process**. Tests cover reuse, wrong project, expiry and concurrent redemption.

**Not production-ready.** No network endpoint, certificate issuance or agent enrollment is enabled. Restarting a Manager loses the in-memory ledger. The next implementation must add transactional durable storage, operator RBAC, proof-of-possession CSR validation, independent CA, strict server trust bootstrapping, audit trail and interrupted-enrollment recovery. Never ship a generic agent binary containing shared enrollment secrets.

Local test: `go test ./manager/internal/enrollment -race`.
