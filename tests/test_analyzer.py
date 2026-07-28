"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Analyzer Engine Tests: tests/test_analyzer.py

PURPOSE:
Unit tests for the rule-based vulnerability analyzer engine (vulnerability/analyzer.py).
Verifies rule matching, severity calculation, input immutability, deduplication,
and error handling.

SECURITY & SAFETY:
These tests operate entirely in-memory using static test data. No network calls
or external commands are executed.
=============================================================================
"""

import copy
import unittest
from vulnerability.analyzer import analyze_scan


class TestVulnerabilityAnalyzer(unittest.TestCase):

    def test_1_empty_scan_result_returns_info_risk_and_no_findings(self):
        """1. Verify empty scan result returns no findings and Info overall risk."""
        empty_scan = {
            "target": "127.0.0.1",
            "host_status": "up",
            "open_ports": [],
            "open_port_count": 0,
        }
        result = analyze_scan(empty_scan)
        self.assertEqual(result["finding_count"], 0)
        self.assertEqual(result["findings"], [])
        self.assertEqual(result["overall_risk"], "Info")
        self.assertIn("No rule-based security concerns", result["analysis_note"])

    def test_2_tcp_445_produces_high_smb_finding(self):
        """2. Verify TCP 445 produces a High SMB finding."""
        scan_data = {
            "open_ports": [
                {
                    "port": 445,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "microsoft-ds",
                    "product": "",
                    "version": "",
                }
            ]
        }
        result = analyze_scan(scan_data)
        self.assertEqual(result["finding_count"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "SS-SMB-001")
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["port"], 445)
        self.assertEqual(result["overall_risk"], "High")

    def test_3_tcp_23_produces_high_telnet_finding(self):
        """3. Verify TCP 23 produces a High Telnet finding."""
        scan_data = {
            "open_ports": [
                {
                    "port": 23,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "telnet",
                    "product": "",
                    "version": "",
                }
            ]
        }
        result = analyze_scan(scan_data)
        self.assertEqual(result["finding_count"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "SS-TELNET-001")
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["port"], 23)

    def test_4_tcp_80_produces_low_http_finding(self):
        """4. Verify TCP 80 produces a Low HTTP finding."""
        scan_data = {
            "open_ports": [
                {
                    "port": 80,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.52",
                }
            ]
        }
        result = analyze_scan(scan_data)
        self.assertEqual(result["finding_count"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "SS-HTTP-001")
        self.assertEqual(finding["severity"], "Low")

    def test_5_werkzeug_on_port_5000_produces_medium_flask_dev_finding(self):
        """5. Verify Werkzeug on TCP 5000 produces a Medium development-server finding."""
        scan_data = {
            "open_ports": [
                {
                    "port": 5000,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "http",
                    "product": "Werkzeug httpd",
                    "version": "3.0.1",
                }
            ]
        }
        result = analyze_scan(scan_data)
        self.assertEqual(result["finding_count"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "SS-FLASK-DEV-001")
        self.assertEqual(finding["severity"], "Medium")
        self.assertIn("Flask / Werkzeug", finding["title"])

    def test_6_unknown_service_produces_info_finding(self):
        """6. Verify unknown service produces an Info finding."""
        scan_data = {
            "open_ports": [
                {
                    "port": 9999,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "custom-app",
                    "product": "Unknown",
                    "version": "",
                }
            ]
        }
        result = analyze_scan(scan_data)
        self.assertEqual(result["finding_count"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule_id"], "SS-UNKNOWN-001")
        self.assertEqual(finding["severity"], "Info")

    def test_7_missing_fields_do_not_crash_analysis(self):
        """7. Verify missing or malformed fields do not crash analysis."""
        malformed_inputs = [
            None,
            "not a dict",
            {},
            {"open_ports": "invalid type"},
            {"open_ports": [None, {}, {"port": "invalid_int"}, {"port": 80}]},
        ]
        for idx, malformed in enumerate(malformed_inputs):
            with self.subTest(case=idx):
                res = analyze_scan(malformed)
                self.assertIsInstance(res, dict)
                self.assertIn("findings", res)
                self.assertIn("severity_counts", res)
                self.assertIn("overall_risk", res)

    def test_8_multiple_findings_calculate_correct_severity_counts(self):
        """8. Verify multiple findings calculate correct severity counts."""
        scan_data = {
            "open_ports": [
                {"port": 22, "protocol": "TCP", "state": "open", "service": "ssh", "product": "", "version": ""},  # Low
                {"port": 21, "protocol": "TCP", "state": "open", "service": "ftp", "product": "", "version": ""},  # Medium
                {"port": 445, "protocol": "TCP", "state": "open", "service": "microsoft-ds", "product": "", "version": ""},  # High
                {"port": 443, "protocol": "TCP", "state": "open", "service": "https", "product": "", "version": ""},  # Info
            ]
        }
        result = analyze_scan(scan_data)
        self.assertEqual(result["finding_count"], 4)
        counts = result["severity_counts"]
        self.assertEqual(counts["High"], 1)
        self.assertEqual(counts["Medium"], 1)
        self.assertEqual(counts["Low"], 1)
        self.assertEqual(counts["Info"], 1)
        self.assertEqual(counts["Critical"], 0)

    def test_9_overall_risk_equals_highest_finding_severity(self):
        """9. Verify overall risk equals the highest finding severity."""
        scan_data = {
            "open_ports": [
                {"port": 80, "protocol": "TCP", "state": "open", "service": "http", "product": "", "version": ""},  # Low
                {"port": 135, "protocol": "TCP", "state": "open", "service": "msrpc", "product": "", "version": ""},  # Medium
                {"port": 3389, "protocol": "TCP", "state": "open", "service": "ms-wbt-server", "product": "", "version": ""},  # High
            ]
        }
        result = analyze_scan(scan_data)
        self.assertEqual(result["overall_risk"], "High")

    def test_10_analyzer_does_not_mutate_input_dictionary(self):
        """10. Verify analyzer does not mutate the input dictionary."""
        scan_data = {
            "target": "127.0.0.1",
            "open_ports": [
                {"port": 80, "protocol": "TCP", "state": "open", "service": "http", "product": "Apache", "version": "2.4"}
            ],
        }
        scan_data_copy = copy.deepcopy(scan_data)
        _ = analyze_scan(scan_data)
        self.assertEqual(scan_data, scan_data_copy)

    def test_11_duplicate_rules_are_not_produced_for_same_port(self):
        """11. Verify duplicate rules are not produced for the same port."""
        scan_data = {
            "open_ports": [
                {
                    "port": 80,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.52",
                }
            ]
        }
        result = analyze_scan(scan_data)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        self.assertEqual(len(rule_ids), len(set(rule_ids)))


if __name__ == "__main__":
    unittest.main()
