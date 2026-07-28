"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Flask Application Tests: tests/test_app.py

PURPOSE:
Integration tests for Flask routes, target validation handling, authorization
verification, and mocked scan result rendering.

CRITICAL SECURITY RULE:
All scanner engine calls are mocked using unittest.mock. No actual network
scans are performed during execution of these automated tests.
=============================================================================
"""

import unittest
from unittest.mock import patch
from backend.app import app
from scanner.nmap_scanner import ScannerUnavailableError


class TestFlaskRoutes(unittest.TestCase):

    def setUp(self):
        """Configure test client for Flask application."""
        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        self.client = app.test_client()

    def test_get_dashboard(self):
        """Verify GET / returns HTTP 200 and loads the dashboard HTML."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SecureScan", response.data)
        self.assertIn(b"Automated Vulnerability Assessment", response.data)

    def test_post_without_authorization(self):
        """Verify POST / without authorization checkbox agreement is rejected."""
        response = self.client.post(
            "/",
            data={"target": "127.0.0.1"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"Confirm that you are authorized to scan this target", response.data
        )

    def test_post_with_invalid_target(self):
        """Verify POST / with invalid or malicious target returns a validation error."""
        invalid_payloads = [
            "https://example.com",
            "192.168.1.1; whoami",
            "192.168.1.0/24",
            "example.com -A",
        ]

        for target in invalid_payloads:
            with self.subTest(target=target):
                response = self.client.post(
                    "/",
                    data={"target": target, "auth_confirmed": "1"},
                    follow_redirects=True,
                )
                self.assertEqual(response.status_code, 200)
                self.assertIn(b"Target Validation / Scan Error", response.data)

    @patch("backend.app.run_scan")
    def test_post_successful_mocked_scan(self, mock_run_scan):
        """Verify POST / with valid target and authorization renders mocked scan results."""
        mock_run_scan.return_value = {
            "target": "127.0.0.1",
            "resolved_addresses": ["127.0.0.1"],
            "host_status": "up",
            "hostname": "localhost",
            "scan_started_at": "2026-07-28 12:00:00",
            "scan_duration_seconds": 1.25,
            "open_ports": [
                {
                    "port": 80,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.52",
                }
            ],
            "open_port_count": 1,
        }

        response = self.client.post(
            "/",
            data={"target": "127.0.0.1", "auth_confirmed": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan Results:", response.data)
        self.assertIn(b"127.0.0.1", response.data)
        self.assertIn(b"Apache httpd", response.data)
        self.assertIn(b"2.4.52", response.data)
        mock_run_scan.assert_called_once_with("127.0.0.1")

    @patch("backend.app.run_scan")
    def test_post_handles_scanner_unavailable(self, mock_run_scan):
        """Verify POST / gracefully handles ScannerUnavailableError when Nmap is missing."""
        mock_run_scan.side_effect = ScannerUnavailableError(
            "Nmap is not installed or cannot be found."
        )

        response = self.client.post(
            "/",
            data={"target": "127.0.0.1", "auth_confirmed": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Nmap is not installed or cannot be found", response.data)


if __name__ == "__main__":
    unittest.main()
