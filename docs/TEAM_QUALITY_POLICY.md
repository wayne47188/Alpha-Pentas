# GitHub Quality and Merge Policy

GitHub Actions validates every Pull Request targeting `main` and changes pushed to `main`.

## CI checks
- Go: formatting, vet and race-enabled tests.
- PostgreSQL: schema and transaction invariants.
- Console: TypeScript build.
- Security: secret scanning.

## GitHub repository configuration
Repository administrators can enforce successful status checks, review approvals, resolution of conversations and force-push restrictions using branch rulesets. Configure required check names only after workflow checks have run and their status names are known.

## Current technical debt
- Existing Go source has not been normalized to gofmt.
- Console lacks committed lockfile; replace temporary npm install with npm ci.
- PostgreSQL shell checks SQL invariants, not the Go service transaction.
- Pin GitHub Actions dependencies to audited commit SHAs.
- Add dependency scanning, CodeQL and coverage reporting after baseline validation.
- Remove overlapping legacy workflow when CI definitions are consolidated.

These are actionable engineering gaps, not evidence of a passing pipeline.
