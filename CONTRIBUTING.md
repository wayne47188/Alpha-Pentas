# Contributing to Alpha Pentas

Thanks for helping build a maintainable, auditable and authorized security assessment platform.

## Workflow
1. Read the project spec, ADRs, SECURITY.md and open Issues. Discuss API or security-boundary changes before implementing.
2. Fork the project (external contributors) or create a topic branch (maintainers), e.g. `feat/agent-enrollment`.
3. Keep changes focused. Add behavior tests and update docs. Run formatting, Go tests, vet, and console build.
4. Open a **draft PR** against `main` with the template completed. Do not push directly to `main`.
5. Resolve CI failures and review feedback, then request approval. Prefer squash merge for a single coherent change.
6. Never include live credentials, target secrets, customer data or unauthorized testing results.

## Local checks
```bash
gofmt -w manager agent cli
go vet ./...
go test -race -count=1 ./...
cd console && npm install && npm run build
```
The console dependency lockfile is not yet committed; the CI temporary install step must be replaced by `npm ci` in a follow-up PR.

## Quality expectations
- Explicit API/domain/infrastructure boundaries; no unreviewed privileged execution paths.
- Documented error handling, cancellation, retries, timeout and idempotency where relevant.
- Tests for success, failure and concurrency cases; database integration for transaction changes.
- No success claims unless CI and relevant integration suites pass.
- Breaking protocol or schema changes require versioning and migration notes.
- Security-sensitive changes require focused threat-model review.

## Merge governance
GitHub Ruleset / branch protection should require this repository's GitHub Actions checks, 1+ independent approval, resolved conversations, no force-pushes and no bypass. These settings must be enabled by a repository administrator; a YAML file alone cannot enforce them.
