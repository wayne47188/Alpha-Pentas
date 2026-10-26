# Governance rollout policy

## Phase A — internal development (current)
- **Do not require human PR approvals or mandatory branch protection** while the original maintainers are actively bootstrapping Alpha Pentas.
- Prefer focused feature branches and PRs for reviewable change sets, but approvals are optional. CI failures are not waived as proof of quality; a red CI run blocks any claim of release-readiness.
- Changes on main should remain traceable. No secrets, real target data or destructive rewrites.
- Keep documentation, tests and security boundaries current with each feature.

## Phase B — external contributors / public collaboration (future)
**Release gate / maintainer reminder: BEFORE announcing that external contributions are accepted**, explicitly remind the project owner to enable GitHub rulesets on `main`:
1. Require PR, at least one independent approval, dismiss stale approvals, resolve conversations.
2. Require stable verified CI status checks (Go, React, PostgreSQL, security).
3. Disallow force-push and branch deletion, limit bypass permissions.
4. Enable private vulnerability reporting and dependency/security alerts.
5. Publish CONTRIBUTING.md, CODE_OF_CONDUCT.md, SECURITY.md, contribution/license policy, release process and support matrix.
6. Run baseline QA audit and block release if high-severity findings remain.

The repository may be public during Phase A; 'public visibility' alone does **not** mean external contribution is open.

## Tracking
Check `docs/OPEN_SOURCE_READINESS.md` before each public announcement or tagged release. The migration from Phase A to B requires an explicit maintainer decision and should be recorded in an ADR/issue.
