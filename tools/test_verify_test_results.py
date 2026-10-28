import json
import tempfile
import unittest
from pathlib import Path

from verify_test_results import verify


class VerifyEvidenceTests(unittest.TestCase):
    def check(self, events):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "results.json"
            output.write_text("\n".join(json.dumps(item) for item in events), encoding="utf-8")
            return verify(output)

    def test_complete(self):
        self.assertEqual(self.check([
            {"Test": "TestPostgresOperatorDenialAudit", "Action": "pass"},
            {"Test": "TestPostgresOperatorCertificateIdentity", "Action": "pass"},
            {"Test": "TestPostgresOperatorGrantRevocationAndIsolation", "Action": "pass"},
            {"Test": "TestPostgresEnrollmentLifecycle", "Action": "pass"},
            {"Test": "TestPostgresSigningDoesNotHoldRowLock", "Action": "pass"},
            {"Test": "TestPostgresExpiredLeaseFencesStaleSigner", "Action": "pass"},
            {"Test": "TestPostgresCertificateRevocationEnforced", "Action": "pass"},
            {"Test": "TestPostgresCertificateScopeAndSuspension", "Action": "pass"},
            {"Test": "TestPostgresSigningFailureReleasesLease", "Action": "pass"},
        ]), 0)

    def test_skipped_fails(self):
        self.assertEqual(self.check([
            {"Test": "TestPostgresOperatorCertificateIdentity", "Action": "pass"},
            {"Test": "TestPostgresEnrollmentLifecycle", "Action": "skip"},
            {"Test": "TestPostgresSigningDoesNotHoldRowLock", "Action": "pass"},
            {"Test": "TestPostgresExpiredLeaseFencesStaleSigner", "Action": "pass"},
            {"Test": "TestPostgresCertificateRevocationEnforced", "Action": "pass"},
            {"Test": "TestPostgresCertificateScopeAndSuspension", "Action": "pass"},
            {"Test": "TestPostgresSigningFailureReleasesLease", "Action": "pass"},
        ]), 1)

    def test_missing_fails(self):
        self.assertEqual(self.check([
            {"Test": "TestPostgresOperatorCertificateIdentity", "Action": "pass"},
            {"Test": "TestPostgresOperatorGrantRevocationAndIsolation", "Action": "pass"},
            {"Test": "TestPostgresEnrollmentLifecycle", "Action": "pass"},
        ]), 1)

    def test_duplicate_fails(self):
        self.assertEqual(self.check([
            {"Test": "TestPostgresOperatorCertificateIdentity", "Action": "pass"},
            {"Test": "TestPostgresOperatorGrantRevocationAndIsolation", "Action": "pass"},
            {"Test": "TestPostgresEnrollmentLifecycle", "Action": "pass"},
            {"Test": "TestPostgresOperatorGrantRevocationAndIsolation", "Action": "pass"},
            {"Test": "TestPostgresEnrollmentLifecycle", "Action": "pass"},
            {"Test": "TestPostgresSigningDoesNotHoldRowLock", "Action": "pass"},
            {"Test": "TestPostgresExpiredLeaseFencesStaleSigner", "Action": "pass"},
            {"Test": "TestPostgresCertificateRevocationEnforced", "Action": "pass"},
            {"Test": "TestPostgresCertificateScopeAndSuspension", "Action": "pass"},
            {"Test": "TestPostgresSigningFailureReleasesLease", "Action": "pass"},
        ]), 1)


if __name__ == "__main__":
    unittest.main()
