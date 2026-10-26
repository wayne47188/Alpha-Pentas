# Open-source launch checklist

**Current phase:** A — internal development, human review / protection enforcement deferred.

## Reminder to maintainers
Before announcing public contribution support or shipping the first stable public release, **enable required reviewers, branch ruleset protections and required CI checks**. The team deliberately postponed these restrictions during active in-house development. Do not forget this gate.

## Mandatory checks before opening contributions
- [ ] `main` ruleset: require PR and independent approval.
- [ ] Require successfully exercised CI checks, including Go, UI and PostgreSQL integration.
- [ ] Protect from force pushes, stale approvals, unreviewed bypass.
- [ ] Enable security advisory/private vulnerability reporting and Dependabot alerts.
- [ ] Verify license and third-party notice/attribution.
- [ ] CONTRIBUTING, CODE_OF_CONDUCT, SECURITY, issue templates, PR template and CODEOWNERS (correct ownership).
- [ ] Reproducible dependencies and SBOM, signed provenance/release artifacts.
- [ ] Threat model, security assessment, verified documentation and supported OS matrix.
- [ ] Address all critical/high findings and confirm backup/CA/key lifecycle.
- [ ] Document public release changelog, maintainer response SLAs, support channels.

This file is a release gate; checking boxes must be backed by GitHub configuration and evidence, not documentation alone.
