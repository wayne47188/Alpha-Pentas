# Release Engineering

## Versioning
Use Semantic Versioning for releases once public contracts stabilize. Until then, mark `0.x` releases experimental and list breaking changes. Maintain a changelog with security-impact descriptions that do not expose unpatched vulnerabilities.

## Build integrity
- Build Manager, Agent, CLI and Console from a pinned toolchain and committed dependency locks.
- CI must verify formatting, linting, unit/integration tests, build, vulnerability and secret scans.
- Release artifacts include platform/architecture identifiers, SHA-256 checksums, SBOM, signatures and provenance.
- Sign builds using a protected identity; store no signing keys in repository or workflow source.
- Verify third-party license compatibility and attributions before publication.

## Deployment and rollback
- Publish upgrade prerequisites, migrations, compatibility range, CA and key handling, backout plan and health checks.
- Production schema migrations are reviewed and backed up before execution. Avoid destructive rollback of live data.
- Agent upgrades are staged; do not force a fleet-wide upgrade without version compatibility and emergency-stop procedures.

## Release acceptance
No release if blocking tests are red, known exploitable vulnerabilities remain unmitigated, or required cryptographic/authorization controls lack verification. Publish supported platforms only after real build and integration validation.
