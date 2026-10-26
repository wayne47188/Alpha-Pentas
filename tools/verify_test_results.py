#!/usr/bin/env python3
"""Fail CI when required Go integration tests are absent, skipped, or failed.

Reads go test -json output, including multiple packages. This checker is
intentionally independent of production Go implementation.
"""
import json
import sys
from pathlib import Path

REQUIRED = {
    "TestPostgresEnrollmentLifecycle",
    "TestPostgresSigningDoesNotHoldRowLock",
    "TestPostgresExpiredLeaseFencesStaleSigner",
    "TestPostgresCertificateRevocationEnforced",
    "TestPostgresCertificateScopeAndSuspension",
    "TestPostgresSigningFailureReleasesLease",
}

def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_test_results.py <go-test-json>", file=sys.stderr)
        return 2
    path = Path(sys.argv[1])
    outcomes = {}
    try:
        with path.open(encoding="utf-8") as source:
            for line in source:
                if not line.strip():
                    continue
                entry = json.loads(line)
                name = entry.get("Test")
                action = entry.get("Action")
                if name in REQUIRED and action in {"pass", "fail", "skip"}:
                    outcomes.setdefault(name, []).append(action)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Cannot verify test evidence: {exc}", file=sys.stderr)
        return 1

    invalid = {
        name: outcomes.get(name, [])
        for name in sorted(REQUIRED)
        if outcomes.get(name) != ["pass"]
    }
    if invalid:
        print(f"Required tests missing, skipped, failed, or duplicated: {invalid}", file=sys.stderr)
        return 1
    print("Verified required Go PostgreSQL integration tests executed and passed.")
    return 0

if __name__ == "__main__":
    sys.exit(main())
