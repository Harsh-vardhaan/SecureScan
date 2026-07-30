"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Flask Application Integration Tests: tests/test_app.py

PURPOSE:
Integration tests for Flask web routes, database persistence flow, target validation,
authorization verification, mocked scan execution, saved scan viewing, and scan deletion.

CRITICAL SECURITY RULE:
All scanner engine calls are mocked using unittest.mock. No actual network
scans are performed during execution of these automated tests.
All database tests use isolated temporary SQLite files.
=============================================================================
"""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.app import _env_flag, _local_port, app
from database.db import (
    DatabaseError,
    get_connection,
    get_recent_scans,
    get_scan_by_id,
    initialize_database,
    save_scan,
)
from scanner.nmap_scanner import ScannerUnavailableError


class TestFlaskRoutes(unittest.TestCase):

    def setUp(self):
        """Configure test client and isolated temporary database for Flask application."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_app_securescan.db")

        app.config["TESTING"] = True
        app.config["WTF_CSRF_ENABLED"] = False
        app.config["DATABASE_PATH"] = self.db_path

        # Initialize schema inside temporary DB
        initialize_database(self.db_path)

        self.client = app.test_client()

    def tearDown(self):
        """Clean up temporary directory and database file."""
        self.temp_dir.cleanup()

    def test_get_dashboard(self):
        """Verify GET / returns HTTP 200 and loads the dashboard HTML."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"SecureScan", response.data)
        self.assertIn(b"Automated Vulnerability Assessment", response.data)

    def test_dashboard_presents_bounded_scope_and_accessibility_landmarks(self):
        """Verify portfolio wording remains cautious and keyboard accessible."""
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Web Service Online", response.data)
        self.assertNotIn(b"Engine:</span>", response.data)
        self.assertIn(b"Skip to main content", response.data)
        self.assertIn(b'id="main-content"', response.data)
        self.assertIn(b'aria-live="polite"', response.data)
        self.assertIn(b"one authorized target at a time", response.data)
        self.assertIn(b"top 100 TCP", response.data)
        self.assertIn(b"No UDP scanning or exploitation", response.data)
        self.assertNotIn(b"scanme.nmap.org", response.data)
        self.assertNotIn(b'id="newScanControl"', response.data)
        self.assertIn(b"/static/js/dashboard.js", response.data)

    def test_dashboard_javascript_supports_client_side_new_scan_reset(self):
        """Verify the focused reset handler preserves progressive enhancement."""
        script_path = Path(__file__).parents[1] / "static" / "js" / "dashboard.js"
        script = script_path.read_text(encoding="utf-8")

        self.assertIn('event.preventDefault()', script)
        self.assertIn('resultSection.hidden = true', script)
        self.assertIn('targetInput.value = ""', script)
        self.assertIn('authorizationCheckbox.checked = false', script)
        self.assertIn('startButton.disabled = false', script)
        self.assertIn('buttonText.textContent = "Start Scan"', script)
        self.assertIn('scanForm.scrollIntoView', script)
        self.assertIn('prefers-reduced-motion: reduce', script)
        self.assertIn('targetInput.focus({ preventScroll: true })', script)

    def test_shared_confirmation_script_supports_accessible_modal_behavior(self):
        """Verify focus management, Escape, and deliberate form submission."""
        script_path = Path(__file__).parents[1] / "static" / "js" / "confirm-modal.js"
        script = script_path.read_text(encoding="utf-8")

        self.assertIn('cancelButton.focus()', script)
        self.assertIn('openingControl.focus()', script)
        self.assertIn('event.key === "Escape"', script)
        self.assertIn('event.key !== "Tab"', script)
        self.assertIn("field.disabled = false", script)
        self.assertIn('activeForm.requestSubmit()', script)
        self.assertNotIn("window.confirm", script)

    @patch("backend.app.run_scan")
    def test_new_scan_fallback_get_preserves_history_without_scanning(self, mock_run_scan):
        """Verify the fallback dashboard load keeps saved data and never scans."""
        scan_id = save_scan(
            {
                "target": "new-scan-history.local",
                "host_status": "up",
                "scan_started_at": "2026-07-31 12:00:00",
                "open_ports": [],
            },
            None,
            db_path=self.db_path,
        )

        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"new-scan-history.local", response.data)
        self.assertIn(f"/scans/{scan_id}".encode(), response.data)
        self.assertNotIn(b'id="newScanControl"', response.data)
        mock_run_scan.assert_not_called()

    @patch("backend.app.analyze_scan")
    @patch("backend.app.run_scan")
    def test_health_is_side_effect_free(self, mock_run_scan, mock_analyze_scan):
        """Verify health reports readiness without scanning, analysis, or writes."""
        scan_id = save_scan(
            {"target": "health-check.local", "scan_started_at": "2026-07-30"},
            {},
            db_path=self.db_path,
        )
        before = get_scan_by_id(scan_id, db_path=self.db_path)

        response = self.client.get("/health")
        after = get_scan_by_id(scan_id, db_path=self.db_path)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.get_json(),
            {"status": "healthy", "service": "securescan"},
        )
        self.assertEqual(before, after)
        mock_run_scan.assert_not_called()
        mock_analyze_scan.assert_not_called()

    def test_environment_flag_parsing_is_explicit_and_safe(self):
        """Verify debug mode is disabled unless an explicit true value is used."""
        true_values = ("1", "true", "TRUE", " yes ", "on")
        for value in true_values:
            with self.subTest(value=value), patch.dict(
                os.environ, {"SECURESCAN_DEBUG": value}, clear=False
            ):
                self.assertTrue(_env_flag("SECURESCAN_DEBUG"))

        false_values = ("0", "false", "no", "off", "unexpected", "")
        for value in false_values:
            with self.subTest(value=value), patch.dict(
                os.environ, {"SECURESCAN_DEBUG": value}, clear=False
            ):
                self.assertFalse(_env_flag("SECURESCAN_DEBUG"))

        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(_env_flag("SECURESCAN_DEBUG"))

    def test_local_port_parsing_uses_safe_fallback(self):
        """Verify malformed or out-of-range development ports fall back to 5000."""
        for value in ("invalid", "0", "65536", "-1"):
            with self.subTest(value=value), patch.dict(
                os.environ, {"SECURESCAN_PORT": value}, clear=False
            ):
                self.assertEqual(_local_port(), 5000)

        with patch.dict(os.environ, {"SECURESCAN_PORT": "8080"}, clear=False):
            self.assertEqual(_local_port(), 8080)

    def test_get_dashboard_renders_recent_scans(self):
        """Verify GET / displays real recent saved scans from SQLite."""
        save_scan(
            {
                "target": "10.0.0.99",
                "host_status": "up",
                "hostname": "test-host.local",
                "scan_started_at": "2026-07-28 10:00:00",
                "open_port_count": 1,
            },
            {
                "finding_count": 1,
                "overall_risk": "Medium",
            },
            db_path=self.db_path,
        )

        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"10.0.0.99", response.data)
        self.assertIn(b"test-host.local", response.data)
        self.assertIn(b"Medium", response.data)

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
        """Verify POST / with valid target and authorization renders mocked scan results and persists to DB."""
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
        self.assertIn(b"Security Analysis", response.data)
        self.assertIn(b"Rule-Based Risk Rating", response.data)
        self.assertIn(b"SS-HTTP-001", response.data)
        self.assertIn(b'id="newScanControl"', response.data)
        self.assertIn(b"New Scan", response.data)
        self.assertIn(b'href="/"', response.data)
        self.assertIn(b"Recent Scan History", response.data)
        self.assertIn(b"127.0.0.1", response.data)
        saved_scan_id = get_recent_scans(limit=1, db_path=self.db_path)[0]["id"]
        self.assertIn(f"/scans/{saved_scan_id}/report".encode(), response.data)
        self.assertIn(f"/scans/{saved_scan_id}/report.pdf".encode(), response.data)
        self.assertIn(b"View HTML Report", response.data)
        self.assertIn(b"Download PDF Report", response.data)
        mock_run_scan.assert_called_once_with("127.0.0.1")

    @patch("backend.app.run_scan")
    def test_post_renders_mocked_smb_finding(self, mock_run_scan):
        """Verify mocked SMB port 445 scan renders High Risk SMB finding in HTML."""
        mock_run_scan.return_value = {
            "target": "127.0.0.1",
            "resolved_addresses": ["127.0.0.1"],
            "host_status": "up",
            "hostname": "localhost",
            "scan_started_at": "2026-07-28 12:00:00",
            "scan_duration_seconds": 0.85,
            "open_ports": [
                {
                    "port": 445,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "microsoft-ds",
                    "product": "Windows SMB",
                    "version": "",
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
        self.assertIn(b"SS-SMB-001", response.data)
        self.assertIn(b"SMB Service Exposed", response.data)
        self.assertIn(b"High Risk", response.data)

    @patch("backend.app.run_scan")
    def test_post_renders_no_findings_message(self, mock_run_scan):
        """Verify scan with no open ports renders safe no-findings message."""
        mock_run_scan.return_value = {
            "target": "127.0.0.1",
            "resolved_addresses": ["127.0.0.1"],
            "host_status": "up",
            "hostname": "localhost",
            "scan_started_at": "2026-07-28 12:00:00",
            "scan_duration_seconds": 0.5,
            "open_ports": [],
            "open_port_count": 0,
        }

        response = self.client.post(
            "/",
            data={"target": "127.0.0.1", "auth_confirmed": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"No rule-based security concerns were identified", response.data)

    @patch("backend.app.analyze_scan")
    @patch("backend.app.run_scan")
    def test_post_handles_analyzer_failure_gracefully(self, mock_run_scan, mock_analyze_scan):
        """Verify Flask handles analyzer exception gracefully without discarding scan results."""
        mock_run_scan.return_value = {
            "target": "127.0.0.1",
            "resolved_addresses": ["127.0.0.1"],
            "host_status": "up",
            "hostname": "localhost",
            "scan_started_at": "2026-07-28 12:00:00",
            "scan_duration_seconds": 1.0,
            "open_ports": [
                {"port": 80, "protocol": "TCP", "state": "open", "service": "http", "product": "", "version": ""}
            ],
            "open_port_count": 1,
        }
        mock_analyze_scan.side_effect = RuntimeError("Simulated analyzer failure")

        response = self.client.post(
            "/",
            data={"target": "127.0.0.1", "auth_confirmed": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan Results:", response.data)
        self.assertIn(b"Rule-based security analysis could not be completed", response.data)

    @patch("backend.app.save_scan")
    @patch("backend.app.run_scan")
    def test_post_handles_database_save_failure_gracefully(self, mock_run_scan, mock_save_scan):
        """Verify Flask displays scan results and flashes warning if saving scan fails."""
        mock_run_scan.return_value = {
            "target": "127.0.0.1",
            "resolved_addresses": ["127.0.0.1"],
            "host_status": "up",
            "hostname": "localhost",
            "scan_started_at": "2026-07-28 12:00:00",
            "scan_duration_seconds": 1.0,
            "open_ports": [],
            "open_port_count": 0,
        }
        mock_save_scan.side_effect = RuntimeError("Database write error")

        response = self.client.post(
            "/",
            data={"target": "127.0.0.1", "auth_confirmed": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan Results:", response.data)
        self.assertIn(b"The scan completed, but the result could not be saved to history.", response.data)
        self.assertNotIn(b"View HTML Report", response.data)
        self.assertNotIn(b"Download PDF Report", response.data)

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

    def test_view_scan_detail_route_success(self):
        """Verify GET /scans/<scan_id> loads saved scan details and returns HTTP 200."""
        scan_id = save_scan(
            {
                "target": "scanme.nmap.org",
                "host_status": "up",
                "hostname": "scanme.nmap.org",
                "resolved_addresses": ["45.33.32.156"],
                "scan_started_at": "2026-07-28 14:00:00",
                "scan_duration_seconds": 2.5,
                "open_port_count": 1,
                "open_ports": [{"port": 80, "protocol": "TCP", "state": "open", "service": "http", "product": "Apache", "version": "2.4.7"}],
            },
            {
                "finding_count": 1,
                "overall_risk": "Low",
                "findings": [{"rule_id": "SS-HTTP-001", "title": "HTTP Service Exposed", "severity": "Low", "category": "Web Exposure", "port": 80, "protocol": "TCP", "service": "http", "product": "Apache", "version": "2.4.7", "description": "HTTP port open.", "evidence": "TCP/80 open", "recommendation": "Use HTTPS.", "confidence": "High"}],
            },
            db_path=self.db_path,
        )

        response = self.client.get(f"/scans/{scan_id}")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Historical Scan Record", response.data)
        self.assertIn(b"scanme.nmap.org", response.data)
        self.assertIn(b"45.33.32.156", response.data)
        self.assertIn(b"Apache", response.data)
        self.assertIn(b"SS-HTTP-001", response.data)

    def test_view_scan_detail_missing_id_returns_404(self):
        """Verify GET /scans/<missing_id> returns HTTP 404."""
        response = self.client.get("/scans/99999")
        self.assertEqual(response.status_code, 404)

    def test_view_scan_detail_includes_html_report_button(self):
        """Verify a saved scan detail page links to its HTML report."""
        scan_id = save_scan(
            {"target": "127.0.0.1", "scan_started_at": "2026-07-29"},
            {},
            db_path=self.db_path,
        )

        response = self.client.get(f"/scans/{scan_id}")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"View HTML Report", response.data)
        self.assertIn(f"/scans/{scan_id}/report".encode(), response.data)

    @patch("backend.app.analyze_scan")
    @patch("backend.app.run_scan")
    def test_view_html_report_uses_saved_scan_without_rescanning(
        self, mock_run_scan, mock_analyze_scan
    ):
        """Verify HTML reports use persisted data and never invoke scan or analysis."""
        scan_id = save_scan(
            {
                "target": "192.0.2.25",
                "host_status": "up",
                "hostname": "report-target.local",
                "resolved_addresses": ["192.0.2.25"],
                "scan_started_at": "2026-07-29 10:00:00",
                "scan_duration_seconds": 1.0,
                "open_ports": [
                    {"port": 80, "protocol": "TCP", "state": "open", "service": "http", "product": "Apache", "version": "2.4"}
                ],
            },
            {
                "overall_risk": "Low",
                "findings": [
                    {
                        "rule_id": "SS-HTTP-001",
                        "title": "HTTP Service Exposed",
                        "severity": "Low",
                        "port": 80,
                        "protocol": "TCP",
                        "description": "HTTP is reachable.",
                        "evidence": "TCP/80 open",
                        "recommendation": "Use HTTPS.",
                        "confidence": "High",
                    }
                ],
            },
            db_path=self.db_path,
        )

        before = get_scan_by_id(scan_id, db_path=self.db_path)
        response = self.client.get(f"/scans/{scan_id}/report")
        after = get_scan_by_id(scan_id, db_path=self.db_path)

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Professional Vulnerability Assessment Report", response.data)
        self.assertIn(b"SSR-", response.data)
        self.assertIn(b"192.0.2.25", response.data)
        self.assertIn(b"SS-HTTP-001", response.data)
        self.assertIn(b"Use HTTPS.", response.data)
        self.assertEqual(before, after)
        mock_run_scan.assert_not_called()
        mock_analyze_scan.assert_not_called()

    def test_view_html_report_missing_scan_returns_404(self):
        """Verify reports return 404 when the saved scan does not exist."""
        response = self.client.get("/scans/99999/report")
        self.assertEqual(response.status_code, 404)

    def test_report_pages_include_pdf_actions(self):
        """Verify scan detail and HTML report pages expose PDF download actions."""
        scan_id = save_scan(
            {"target": "127.0.0.1", "scan_started_at": "2026-07-29"},
            {},
            db_path=self.db_path,
        )

        detail_response = self.client.get(f"/scans/{scan_id}")
        html_report_response = self.client.get(f"/scans/{scan_id}/report")

        self.assertIn(b"Download PDF Report", detail_response.data)
        self.assertIn(b"Download PDF", html_report_response.data)
        self.assertIn(b"Print Report", html_report_response.data)
        self.assertIn(f"/scans/{scan_id}/report.pdf".encode(), detail_response.data)

    def test_html_report_displays_complete_scope_and_disclaimer(self):
        """Verify authorization, limitations, and cautious disclaimer are visible."""
        scan_id = save_scan(
            {"target": "127.0.0.1", "scan_started_at": "2026-07-30"},
            {},
            db_path=self.db_path,
        )

        response = self.client.get(f"/scans/{scan_id}/report")
        rendered = response.data.lower()

        self.assertEqual(response.status_code, 200)
        for expected in (
            b"authorized, limited network assessment",
            b"top 100 tcp ports",
            b"udp ports and services were not assessed",
            b"no authenticated security checks",
            b"no exploitation",
            b"no external cve",
            b"point-in-time observations",
            b"do not prove exploitability",
            b"do not prove complete security",
            b"do not prove exploitability, compromise, or complete security",
        ):
            self.assertIn(expected, rendered)

    def test_html_report_handles_empty_ports_and_findings(self):
        """Verify explicit safe empty states are rendered for legacy scans."""
        scan_id = save_scan(
            {"target": "legacy.local", "scan_started_at": "2026-07-30"},
            {},
            db_path=self.db_path,
        )

        response = self.client.get(f"/scans/{scan_id}/report")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            b"No open ports were recorded within the limited top-100 TCP-port scan scope.",
            response.data,
        )
        self.assertIn(
            b"No rule-based security concerns were recorded for this limited assessment.",
            response.data,
        )
        self.assertIn(b"does not prove that the target is fully secure", response.data)

    @patch("backend.app.analyze_scan")
    @patch("backend.app.run_scan")
    def test_pdf_report_route_returns_attachment_without_rescanning(
        self, mock_run_scan, mock_analyze_scan
    ):
        """Verify PDF download uses persisted data without scanning or analysis."""
        scan_id = save_scan(
            {
                "target": "demo target/../../unsafe",
                "host_status": "up",
                "scan_started_at": "2026-07-29 13:00:00",
                "open_ports": [{"port": 443, "protocol": "TCP", "state": "open"}],
            },
            {"overall_risk": "Info"},
            db_path=self.db_path,
        )
        before = get_scan_by_id(scan_id, db_path=self.db_path)

        response = self.client.get(f"/scans/{scan_id}/report.pdf")
        after = get_scan_by_id(scan_id, db_path=self.db_path)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.mimetype, "application/pdf")
        self.assertTrue(response.data.startswith(b"%PDF"))
        disposition = response.headers["Content-Disposition"]
        self.assertIn("attachment;", disposition)
        self.assertIn(f"securescan-report-demo-target-unsafe-{scan_id}.pdf", disposition)
        self.assertNotIn("/", disposition)
        self.assertNotIn("..", disposition)
        self.assertEqual(before, after)
        mock_run_scan.assert_not_called()
        mock_analyze_scan.assert_not_called()

    def test_pdf_report_missing_scan_returns_404(self):
        """Verify PDF download returns 404 for a missing saved scan."""
        response = self.client.get("/scans/99999/report.pdf")
        self.assertEqual(response.status_code, 404)

    @patch("backend.app.generate_pdf_report")
    def test_pdf_generation_failure_returns_controlled_500(self, mock_generate_pdf):
        """Verify PDF generator failures return a controlled response."""
        scan_id = save_scan(
            {"target": "127.0.0.1", "scan_started_at": "2026-07-29"},
            {},
            db_path=self.db_path,
        )
        mock_generate_pdf.side_effect = RuntimeError("simulated PDF failure")

        response = self.client.get(f"/scans/{scan_id}/report.pdf")

        self.assertEqual(response.status_code, 500)
        self.assertIn(b"The PDF report could not be generated", response.data)

    def test_delete_scan_route_requires_post(self):
        """Verify GET /scans/<scan_id>/delete returns HTTP 405 Method Not Allowed."""
        response = self.client.get("/scans/1/delete")
        self.assertEqual(response.status_code, 405)

    def test_delete_scan_route_removes_record_and_redirects(self):
        """Verify POST /scans/<scan_id>/delete removes scan and redirects to dashboard."""
        scan_id = save_scan(
            {"target": "127.0.0.1", "scan_started_at": "2026-07-28"},
            {},
            db_path=self.db_path,
        )

        response = self.client.post(
            f"/scans/{scan_id}/delete",
            data={"confirmed": "1"},
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"successfully deleted", response.data)

        # Confirm scan is deleted
        detail_resp = self.client.get(f"/scans/{scan_id}")
        self.assertEqual(detail_resp.status_code, 404)

    def test_initial_dashboard_hides_current_report_and_clear_actions(self):
        """Verify result-only and history-only controls are absent when empty."""
        response = self.client.get("/")

        self.assertNotIn(b"View HTML Report", response.data)
        self.assertNotIn(b"Download PDF Report", response.data)
        self.assertNotIn(b"Clear Scan History", response.data)

    def test_clear_history_control_and_reusable_modal_markup_render(self):
        """Verify destructive controls supply shared modal metadata."""
        scan_id = save_scan(
            {"target": "modal-test.local", "scan_started_at": "2026-07-31"},
            {},
            db_path=self.db_path,
        )

        dashboard = self.client.get("/")
        detail = self.client.get(f"/scans/{scan_id}")

        for response in (dashboard, detail):
            self.assertIn(b'data-confirm-modal', response.data)
            self.assertIn(b'role="dialog"', response.data)
            self.assertIn(b'aria-modal="true"', response.data)
            self.assertIn(b"/static/js/confirm-modal.js", response.data)
        self.assertIn(b"Clear Scan History", dashboard.data)
        self.assertIn(b"Delete Saved Scan", dashboard.data)
        self.assertIn(b"Delete this saved scan record?", dashboard.data)
        self.assertIn(b"Delete all saved scan records?", dashboard.data)
        self.assertNotIn(b"window.confirm", dashboard.data)
        self.assertNotIn(b"return confirm", dashboard.data)

    def test_unconfirmed_destructive_post_uses_safe_fallback(self):
        """Verify no-JavaScript submissions require a second confirmation."""
        scan_id = save_scan(
            {"target": "fallback-delete.local", "scan_started_at": "2026-07-31"},
            {},
            db_path=self.db_path,
        )

        response = self.client.post(f"/scans/{scan_id}/delete")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Delete Saved Scan", response.data)
        self.assertIn(b"Delete this saved scan record?", response.data)
        self.assertIsNotNone(get_scan_by_id(scan_id, db_path=self.db_path))

    def test_unconfirmed_clear_history_uses_safe_fallback(self):
        """Verify no-JavaScript bulk clearing preserves records until confirmed."""
        scan_id = save_scan(
            {"target": "fallback-clear.local", "scan_started_at": "2026-07-31"},
            {},
            db_path=self.db_path,
        )

        response = self.client.post("/scans/clear")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Clear Scan History", response.data)
        self.assertIn(b"Delete all saved scan records?", response.data)
        self.assertIn(b"This cannot be undone.", response.data)
        self.assertIsNotNone(get_scan_by_id(scan_id, db_path=self.db_path))

    def test_clear_scan_history_rejects_get(self):
        """Verify bulk deletion cannot be invoked with GET."""
        self.assertEqual(self.client.get("/scans/clear").status_code, 405)

    @patch("backend.app.analyze_scan")
    @patch("backend.app.run_scan")
    def test_clear_scan_history_removes_all_records_without_scanning(
        self, mock_run_scan, mock_analyze_scan
    ):
        """Verify confirmed POST cascades and never invokes assessment code."""
        scan_id = save_scan(
            {
                "target": "clear-route.local",
                "open_ports": [
                    {"port": 80, "protocol": "TCP", "state": "open", "service": "http"}
                ],
            },
            {
                "overall_risk": "Medium",
                "finding_count": 1,
                "findings": [
                    {
                        "rule_id": "CLEAR-ROUTE-001",
                        "title": "Synthetic finding",
                        "severity": "Medium",
                        "port": 80,
                        "protocol": "TCP",
                    }
                ],
            },
            db_path=self.db_path,
        )

        response = self.client.post(
            "/scans/clear",
            data={"confirmed": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"All saved scan records were deleted.", response.data)
        self.assertIsNone(get_scan_by_id(scan_id, db_path=self.db_path))
        conn = get_connection(self.db_path)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM open_ports").fetchone()[0], 0)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0], 0)
        conn.close()
        mock_run_scan.assert_not_called()
        mock_analyze_scan.assert_not_called()

    def test_clear_empty_history_is_safe(self):
        """Verify confirmed clearing of an empty history is controlled."""
        response = self.client.post(
            "/scans/clear",
            data={"confirmed": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan history is already empty.", response.data)

    @patch("backend.app.clear_scan_history")
    def test_clear_history_database_failure_is_controlled(self, mock_clear):
        """Verify database details are not exposed when bulk clearing fails."""
        mock_clear.side_effect = DatabaseError("private database path detail")

        response = self.client.post(
            "/scans/clear",
            data={"confirmed": "1"},
            follow_redirects=True,
        )

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Scan history could not be cleared. Please try again.", response.data)
        self.assertNotIn(b"private database path detail", response.data)


if __name__ == "__main__":
    unittest.main()
