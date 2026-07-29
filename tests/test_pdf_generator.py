"""Tests for framework-independent, in-memory SecureScan PDF generation."""

import copy
import unittest

from reports.pdf_generator import generate_pdf_report
from reports.report_generator import build_report_context


class TestPdfGenerator(unittest.TestCase):

    def setUp(self):
        self.context = build_report_context(
            {
                "id": 27,
                "target": "192.0.2.27",
                "hostname": "pdf-target.local",
                "resolved_address": "192.0.2.27",
                "host_status": "up",
                "scan_started_at": "2026-07-29 12:00:00",
                "scan_duration_seconds": 2.4,
                "overall_risk": "High",
                "severity_counts": {
                    "Critical": 0, "High": 1, "Medium": 0, "Low": 0, "Info": 0,
                },
                "open_ports": [
                    {
                        "port": 445, "protocol": "TCP", "state": "open",
                        "service": "microsoft-ds", "product": "Windows SMB", "version": "3",
                    }
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
                        "description": "SMB is reachable from the assessed network.",
                        "evidence": "TCP/445 open",
                        "recommendation": "Restrict SMB to trusted networks.",
                        "confidence": "High",
                    }
                ],
            }
        )

    def test_returns_valid_pdf_bytes_for_complete_context(self):
        result = generate_pdf_report(self.context)
        self.assertIsInstance(result, bytes)
        self.assertTrue(result.startswith(b"%PDF"))
        self.assertGreater(len(result), 1000)

    def test_missing_optional_fields_generate_successfully(self):
        result = generate_pdf_report({"metadata": {"report_id": "SSR-EMPTY"}})
        self.assertTrue(result.startswith(b"%PDF"))

    def test_empty_ports_generate_successfully(self):
        context = copy.deepcopy(self.context)
        context["open_ports"] = []
        self.assertTrue(generate_pdf_report(context).startswith(b"%PDF"))

    def test_empty_findings_and_recommendations_generate_successfully(self):
        context = copy.deepcopy(self.context)
        context["findings"] = []
        context["recommendations"] = []
        self.assertTrue(generate_pdf_report(context).startswith(b"%PDF"))

    def test_long_finding_content_wraps_without_failure(self):
        context = copy.deepcopy(self.context)
        context["findings"][0]["description"] = "Long description. " * 500
        context["findings"][0]["recommendation"] = "Long recommendation. " * 500
        context["recommendations"][0]["recommendation"] = "Long recommendation. " * 500
        self.assertTrue(generate_pdf_report(context).startswith(b"%PDF"))

    def test_does_not_mutate_original_context(self):
        original = copy.deepcopy(self.context)
        generate_pdf_report(self.context)
        self.assertEqual(self.context, original)

    def test_rejects_non_dictionary_context(self):
        with self.assertRaises(ValueError):
            generate_pdf_report(None)


if __name__ == "__main__":
    unittest.main()
