# Contributing to Alpha Pentas

Thank you for contributing to Alpha Pentas. Changes should be focused, reproducible, tested and safe for authorized use.

## Development workflow
1. Read the architecture decisions and security policy before changing protocols, identities or execution boundaries.
2. Work in a feature branch or fork and open a Pull Request with a clear scope, test evidence and risk assessment.
3. Run applicable Go, React and PostgreSQL checks.
4. Address CI failures and review feedback before merging. Follow repository branch protection settings when enabled.
5. Never commit credentials, production data or customer evidence.

## Local checks

```bash
gofmt -w manager agent cli
go vet ./...
go test -race -count=1 ./...
cd console && npm install && npm run build
```

## Change acceptance
- Source is formatted and statically checked.
- Tests cover successful execution, errors and relevant edge cases.
- Database changes have migrations and isolation/concurrency tests.
- Public API and protobuf changes document compatibility.
- Security-sensitive changes document authorization boundaries and failure modes.
- CI is green before claiming a change is tested or release-ready.
