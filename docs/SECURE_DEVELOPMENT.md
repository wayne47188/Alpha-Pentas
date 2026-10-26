# Secure Development Requirements

## Trust boundaries
Operator API, Manager services, plugin process, transport, relay and Agent each have separate trust domains. Explicit authorization is required before crossing domain or tenant boundaries. mTLS verifies possession of a key; it does not authorize an operation by itself.

## Identity lifecycle
- Enrollment token is single-use, project-scoped, short-lived and never logged raw.
- Agent keys are generated and held on Agent; CSR proof of possession precedes enrollment claim.
- Issuance binds validated CSR digest to a durable, authorized claim; retries cannot grant identity using only a guessable claim ID.
- Certificate verification checks trusted CA, EKU, namespace identity, validity and revocation state. Renewal and revocation are tested under active sessions.

## Secrets and evidence
No tokens/keys/customer evidence in logs or CI artifacts. Encrypt confidential evidence at rest and in transit. Use least-privilege storage access, signed provenance metadata, retention policy and deletion workflows.

## Plugins
Signed package verification, publisher provenance, explicit capabilities, sandbox/OS privilege constraints, timeout/resource quotas and an auditable invocation path. A child process is not a sandbox by itself.

## Workflow and dependency security
Minimize workflow permissions; pin third-party Actions to reviewed commit SHAs. Lock dependencies, review transitive dependencies and produce SBOM. Scan for secrets and known vulnerabilities, then triage findings.

## Security reporting
Vulnerabilities must be disclosed privately in accordance with SECURITY.md, not through public issue descriptions.
