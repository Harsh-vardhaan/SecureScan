"""Unit tests for normalized, framework-independent HTML report context data."""

import copy
import unittest

from reports.report_generator import build_report_context


class TestReportGenerator(unittest.TestCase):

    def setUp(self):
        self.saved_scan = {
            "id": 42,
            "target": "192.0.2.10",
            "hostname": "demo.internal",
            "host_status": "up",
            "resolved_address": "192.0.2.10",
            "scan_started_at": "2026-07-29 09:00:00",
            "scan_duration_seconds": 1.75,
            "overall_risk": "High",
            "severity_counts": {"Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0},
            "open_ports": [
                {"port": 445, "protocol": "TCP", "state": "open", "service": "microsoft-ds", "product": "SMB", "version": ""}
            ],
            "findings": [
                {
                    "rule_id": "SS-SMB-001",
                    "title": "SMB Service Exposed",
                    "severity": "High",
                    "category": "Network Exposure",
                    "port": 445,
                    "protocol": "TCP",
                    "service": "microsoft-ds",
                    "description": "SMB is reachable.",
                    "evidence": "TCP/445 open",
                    "recommendation": "Restrict SMB access to trusted networks.",
                    "confidence": "High",
                }
            ],
        }

    def test_builds_complete_normalized_context(self):
        report = build_report_context(self.saved_scan)

        self.assertEqual(report["metadata"]["report_id"], "SSR-000042")
        self.assertEqual(report["target"]["name"], "192.0.2.10")
        self.assertEqual(report["overall_risk"], "High")
        self.assertEqual(report["severity_counts"]["High"], 1)
        self.assertEqual(report["open_ports"][0]["port"], 445)
        self.assertEqual(report["findings"][0]["rule_id"], "SS-SMB-001")
        self.assertEqual(len(report["recommendations"]), 1)
        self.assertIn("1 open port", report["executive_summary"])
        self.assertTrue(report["limitations"])
        self.assertIn("authorized", report["disclaimer"])

    def test_does_not_mutate_original_input(self):
        original = copy.deepcopy(self.saved_scan)
        report = build_report_context(self.saved_scan)
        report["open_ports"][0]["service"] = "changed"

        self.assertEqual(self.saved_scan, original)

    def test_handles_empty_saved_scan_fields(self):
        report = build_report_context({"id": 7, "target": "localhost"})

        self.assertEqual(report["metadata"]["report_id"], "SSR-000007")
        self.assertEqual(report["overall_risk"], "Info")
        self.assertEqual(report["open_ports"], [])
        self.assertEqual(report["findings"], [])
        self.assertEqual(report["recommendations"], [])
        self.assertEqual(sum(report["severity_counts"].values()), 0)

    def test_reconstructs_severity_counts_from_findings(self):
        saved_scan = copy.deepcopy(self.saved_scan)
        saved_scan.pop("severity_counts")

        report = build_report_context(saved_scan)

        self.assertEqual(report["severity_counts"]["High"], 1)

    def test_rejects_non_dictionary_input(self):
        with self.assertRaises(ValueError):
            build_report_context(None)


if __name__ == "__main__":
    unittest.main()
