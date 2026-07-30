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
        self.assertIn("1 rule-based finding", report["executive_summary"])
        self.assertIn("High was the highest recorded severity", report["executive_summary"])
        self.assertIn("SMB Service Exposed", report["executive_summary"])
        self.assertIn("TCP/445", report["executive_summary"])
        self.assertEqual(report["metadata"]["report_version"], "1.0")
        self.assertEqual(
            report["metadata"]["classification"],
            "Authorized Security Assessment",
        )
        self.assertTrue(report["limitations"])
        self.assertIn("do not prove exploitability", report["disclaimer"])

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
        self.assertIn("0 open ports", report["executive_summary"])
        self.assertIn("0 rule-based findings", report["executive_summary"])
        self.assertIn("does not prove", report["executive_summary"])

    def test_reconstructs_severity_counts_from_findings(self):
        saved_scan = copy.deepcopy(self.saved_scan)
        saved_scan.pop("severity_counts")

        report = build_report_context(saved_scan)

        self.assertEqual(report["severity_counts"]["High"], 1)

    def test_findings_sort_by_severity_port_and_title(self):
        saved_scan = copy.deepcopy(self.saved_scan)
        saved_scan["findings"] = [
            {
                "rule_id": "INFO",
                "title": "Zulu",
                "severity": "invalid",
                "port": 9000,
                "recommendation": "Review the service.",
            },
            {
                "rule_id": "LOW",
                "title": "Low concern",
                "severity": "Low",
                "port": 80,
                "recommendation": "Review HTTP.",
            },
            {
                "rule_id": "HIGH-B",
                "title": "Beta",
                "severity": "High",
                "port": 445,
                "recommendation": "Restrict access.",
            },
            {
                "rule_id": "CRITICAL",
                "title": "Critical concern",
                "severity": "Critical",
                "port": 1000,
                "recommendation": "Isolate the service.",
            },
            {
                "rule_id": "HIGH-A",
                "title": "Alpha",
                "severity": "High",
                "port": 445,
                "recommendation": "Patch the service.",
            },
        ]

        report = build_report_context(saved_scan)

        self.assertEqual(
            [finding["rule_id"] for finding in report["findings"]],
            ["CRITICAL", "HIGH-A", "HIGH-B", "LOW", "INFO"],
        )
        self.assertEqual(report["findings"][-1]["severity"], "Info")

    def test_recommendations_are_deduplicated_and_prioritized(self):
        saved_scan = copy.deepcopy(self.saved_scan)
        saved_scan["findings"] = [
            {
                "rule_id": "LOW-DUP",
                "title": "Low duplicate",
                "severity": "Low",
                "port": 8080,
                "protocol": "TCP",
                "recommendation": "  Restrict   service access. ",
            },
            {
                "rule_id": "HIGH",
                "title": "High concern",
                "severity": "High",
                "port": 445,
                "protocol": "TCP",
                "recommendation": "Restrict service access.",
            },
            {
                "rule_id": "MEDIUM",
                "title": "Medium concern",
                "severity": "Medium",
                "port": 21,
                "protocol": "TCP",
                "recommendation": "Replace the legacy protocol.",
            },
        ]

        report = build_report_context(saved_scan)

        self.assertEqual(len(report["recommendations"]), 2)
        self.assertEqual(
            [item["severity"] for item in report["recommendations"]],
            ["High", "Medium"],
        )
        self.assertEqual(report["recommendations"][0]["port"], 445)
        self.assertEqual(report["recommendations"][0]["protocol"], "TCP")

    def test_limitations_cover_complete_saved_scan_scope(self):
        report = build_report_context(self.saved_scan)
        limitations = " ".join(report["limitations"]).lower()

        for expected in (
            "top 100 tcp",
            "udp",
            "service-version",
            "authenticated",
            "exploitation",
            "cve",
            "point-in-time",
            "do not prove exploitability",
            "do not prove complete security",
        ):
            self.assertIn(expected, limitations)

    def test_rejects_non_dictionary_input(self):
        with self.assertRaises(ValueError):
            build_report_context(None)


if __name__ == "__main__":
    unittest.main()
