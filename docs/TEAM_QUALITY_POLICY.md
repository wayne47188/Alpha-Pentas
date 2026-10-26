# GitHub Quality and Merge Policy

## Required repository configuration (admin action)
Open Settings → Rules → Rulesets and create an active branch ruleset targeting `main`:

- Require pull request before merging (at least one approval).
- Dismiss stale approvals after new commits and require conversation resolution.
- Require status checks: `Go / format, vet, test`, `PostgreSQL / schema invariants`, `Console / typecheck and build`, `Supply chain / secret scan` (confirm exact emitted context names first).
- Block force pushes and branch deletion.
- Avoid broad administrator bypasses and disallow self-approval where governance permits.
- Consider merge queue after checks are stable.

A GitHub workflow cannot itself enforce branch protection. The connected GitHub integration in this environment has no exposed ruleset-write action; an admin must enable it in Settings.

## CI quality gates
`.github/workflows/quality-gates.yml` triggers on PRs to `main`, pushes to `main` and manual dispatch. It checks Go formatting (read-only), vet, race tests, PostgreSQL invariants, console build and Gitleaks.

## Existing technical debt / before enforcing required checks
1. Previous Go source has not been normalized to gofmt; the new read-only formatting gate may fail.
2. Console is missing a committed package lock; a temporary npm install step is used. Commit a lockfile and switch to `npm ci`.
3. PostgreSQL script is a low-level invariant test, not the real Go enrollment/issuance integration. Replace or augment it with application-level tests.
4. Supply-chain actions should be pinned to audited full commit SHAs.
5. Add dependency review, CodeQL, fuzzing and coverage after project bootstrapping.
6. Existing `go-ci.yml` remains a legacy overlapping workflow; remove or replace through a reviewed follow-up PR.

**Do not enable mandatory checks until the pipeline names are confirmed and known baseline failures have been fixed.** This PR is intentionally an incremental governance starting point, not proof the codebase currently passes.
