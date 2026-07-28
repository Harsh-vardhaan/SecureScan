"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Target Validator Tests: tests/test_validator.py

PURPOSE:
Unit tests validating target input parsing, normalization, and security rules.
=============================================================================
"""

import unittest
from scanner.validator import validate_target


class TestTargetValidator(unittest.TestCase):

    def test_accepted_targets(self):
        """Verify that valid IPv4, IPv6, localhost, and domain targets are accepted."""
        valid_inputs = [
            ("127.0.0.1", "127.0.0.1"),
            ("localhost", "localhost"),
            ("scanme.nmap.org", "scanme.nmap.org"),
            ("192.168.1.10", "192.168.1.10"),
            ("::1", "::1"),
            ("  scanme.nmap.org  ", "scanme.nmap.org"),
            ("SCANME.NMAP.ORG", "scanme.nmap.org"),
        ]

        for raw_target, expected_normalized in valid_inputs:
            with self.subTest(target=raw_target):
                is_valid, normalized, err_msg = validate_target(raw_target)
                self.assertTrue(is_valid, f"Expected {raw_target} to be valid, got error: {err_msg}")
                self.assertEqual(normalized, expected_normalized)
                self.assertEqual(err_msg, "")

    def test_rejected_targets(self):
        """Verify that unsafe, malformed, or out-of-scope targets are rejected."""
        invalid_inputs = [
            "",
            "   ",
            "https://example.com",
            "http://example.com",
            "example.com/path",
            "192.168.1.0/24",
            "192.168.1.1; whoami",
            "example.com -A",
            "host name.com",
            "example..com",
            "-example.com",
            "example-.com",
            "192.168.1.1:80",
            "example.com:8080",
            "target1.com, target2.com",
            "192.168.1.1 && command",
        ]

        for raw_target in invalid_inputs:
            with self.subTest(target=raw_target):
                is_valid, normalized, err_msg = validate_target(raw_target)
                self.assertFalse(is_valid, f"Expected {raw_target} to be rejected, but passed validation.")
                self.assertEqual(normalized, "")
                self.assertNotEqual(err_msg, "")


if __name__ == "__main__":
    unittest.main()
