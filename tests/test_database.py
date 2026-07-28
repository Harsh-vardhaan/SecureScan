"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Database Layer Unit Tests: tests/test_database.py

PURPOSE:
Unit testing for database schema creation, atomic scan saving, query execution,
foreign key cascades, scan deletion, and edge-case field handling.

SAFETY RULE:
All tests use isolated temporary SQLite files. Tests NEVER write to the
production/development database (database/securescan.db).
=============================================================================
"""

import os
import sqlite3
import tempfile
import unittest

from database.db import (
    initialize_database,
    save_scan,
    get_recent_scans,
    get_scan_by_id,
    delete_scan,
    get_connection,
    DatabaseError,
)


class TestDatabaseOperations(unittest.TestCase):

    def setUp(self):
        """Create a temporary directory and temporary database path for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_securescan.db")
        # Ensure clean initialized schema
        initialize_database(self.db_path)

    def tearDown(self):
        """Clean up temporary directory and database files after test."""
        self.temp_dir.cleanup()

    def test_initialize_database_creates_tables_and_indexes(self):
        """Verify initialize_database creates scans, open_ports, findings tables and indexes."""
        conn = get_connection(self.db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = {row["name"] for row in cursor.fetchall()}
        self.assertIn("scans", tables)
        self.assertIn("open_ports", tables)
        self.assertIn("findings", tables)

        cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
        indexes = {row["name"] for row in cursor.fetchall()}
        self.assertIn("idx_scans_created_at", indexes)
        self.assertIn("idx_scans_target", indexes)
        self.assertIn("idx_open_ports_scan_id", indexes)
        self.assertIn("idx_findings_scan_id", indexes)
        self.assertIn("idx_findings_severity", indexes)

        conn.close()

    def test_save_scan_returns_integer_id(self):
        """Verify save_scan inserts record and returns an integer ID."""
        scan_result = {
            "target": "127.0.0.1",
            "resolved_addresses": ["127.0.0.1"],
            "host_status": "up",
            "hostname": "localhost",
            "scan_started_at": "2026-07-28 12:00:00",
            "scan_duration_seconds": 1.5,
            "open_ports": [],
            "open_port_count": 0,
        }
        analysis_result = {
            "findings": [],
            "finding_count": 0,
            "severity_counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0},
            "overall_risk": "Info",
        }

        scan_id = save_scan(scan_result, analysis_result, db_path=self.db_path)
        self.assertIsInstance(scan_id, int)
        self.assertGreater(scan_id, 0)

    def test_save_scan_creates_scans_row(self):
        """Verify save_scan populates scans master table attributes correctly."""
        scan_result = {
            "target": "scanme.nmap.org",
            "resolved_addresses": ["45.33.32.156"],
            "host_status": "up",
            "hostname": "scanme.nmap.org",
            "scan_started_at": "2026-07-28 14:00:00",
            "scan_duration_seconds": 2.75,
            "open_ports": [],
            "open_port_count": 0,
        }
        analysis_result = {
            "findings": [],
            "finding_count": 0,
            "overall_risk": "Low",
        }

        scan_id = save_scan(scan_result, analysis_result, db_path=self.db_path)

        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        row = cursor.fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["target"], "scanme.nmap.org")
        self.assertEqual(row["hostname"], "scanme.nmap.org")
        self.assertEqual(row["resolved_address"], "45.33.32.156")
        self.assertEqual(row["overall_risk"], "Low")
        self.assertEqual(row["scan_duration_seconds"], 2.75)

    def test_open_ports_saved_correctly(self):
        """Verify open ports array entries are correctly persisted into open_ports table."""
        scan_result = {
            "target": "127.0.0.1",
            "host_status": "up",
            "hostname": "localhost",
            "scan_started_at": "2026-07-28 15:00:00",
            "scan_duration_seconds": 0.9,
            "open_port_count": 2,
            "open_ports": [
                {
                    "port": 80,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "http",
                    "product": "Apache httpd",
                    "version": "2.4.52",
                },
                {
                    "port": 443,
                    "protocol": "TCP",
                    "state": "open",
                    "service": "https",
                    "product": "nginx",
                    "version": "1.18.0",
                },
            ],
        }

        scan_id = save_scan(scan_result, {}, db_path=self.db_path)

        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM open_ports WHERE scan_id = ? ORDER BY port ASC", (scan_id,))
        rows = cursor.fetchall()
        conn.close()

        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["port"], 80)
        self.assertEqual(rows[0]["service"], "http")
        self.assertEqual(rows[0]["product"], "Apache httpd")
        self.assertEqual(rows[1]["port"], 443)
        self.assertEqual(rows[1]["product"], "nginx")

    def test_findings_saved_correctly(self):
        """Verify security findings array entries are correctly persisted into findings table."""
        scan_result = {
            "target": "127.0.0.1",
            "host_status": "up",
            "scan_started_at": "2026-07-28 16:00:00",
            "open_port_count": 1,
            "open_ports": [{"port": 21, "protocol": "TCP", "state": "open", "service": "ftp", "product": "", "version": ""}],
        }
        analysis_result = {
            "finding_count": 1,
            "overall_risk": "High",
            "findings": [
                {
                    "rule_id": "SS-FTP-001",
                    "title": "Unencrypted FTP Protocol Exposed",
                    "severity": "High",
                    "category": "Cleartext Authentication Exposure",
                    "port": 21,
                    "protocol": "TCP",
                    "service": "ftp",
                    "product": "vsftpd",
                    "version": "3.0.3",
                    "description": "FTP transmits credentials in plaintext.",
                    "evidence": "TCP/21 open, service: ftp",
                    "recommendation": "Upgrade to SFTP or FTPS.",
                    "confidence": "High",
                }
            ],
        }

        scan_id = save_scan(scan_result, analysis_result, db_path=self.db_path)

        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        rows = cursor.fetchall()
        conn.close()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["rule_id"], "SS-FTP-001")
        self.assertEqual(rows[0]["severity"], "High")
        self.assertEqual(rows[0]["recommendation"], "Upgrade to SFTP or FTPS.")

    def test_get_recent_scans_order_and_limit(self):
        """Verify get_recent_scans returns newest scans first and respects limit."""
        for i in range(1, 6):
            scan = {
                "target": f"192.168.1.{i}",
                "scan_started_at": f"2026-07-28 10:0{i}:00",
                "open_port_count": i,
            }
            save_scan(scan, {}, db_path=self.db_path)

        recent = get_recent_scans(limit=3, db_path=self.db_path)
        self.assertEqual(len(recent), 3)
        self.assertEqual(recent[0]["target"], "192.168.1.5")
        self.assertEqual(recent[1]["target"], "192.168.1.4")
        self.assertEqual(recent[2]["target"], "192.168.1.3")

    def test_get_scan_by_id_returns_nested_ports_and_findings(self):
        """Verify get_scan_by_id returns scan dict with nested open_ports and findings."""
        scan_result = {
            "target": "10.0.0.1",
            "host_status": "up",
            "hostname": "gateway.local",
            "scan_started_at": "2026-07-28 11:00:00",
            "scan_duration_seconds": 1.2,
            "open_port_count": 1,
            "open_ports": [{"port": 80, "protocol": "TCP", "state": "open", "service": "http", "product": "", "version": ""}],
        }
        analysis_result = {
            "finding_count": 1,
            "overall_risk": "Medium",
            "findings": [
                {
                    "rule_id": "SS-HTTP-001",
                    "title": "HTTP Exposure",
                    "severity": "Medium",
                    "category": "Web Exposure",
                    "port": 80,
                    "protocol": "TCP",
                    "service": "http",
                    "product": "",
                    "version": "",
                    "description": "HTTP port open.",
                    "evidence": "TCP/80 open",
                    "recommendation": "Enforce HTTPS.",
                    "confidence": "Medium",
                }
            ],
        }

        scan_id = save_scan(scan_result, analysis_result, db_path=self.db_path)
        scan_detail = get_scan_by_id(scan_id, db_path=self.db_path)

        self.assertIsNotNone(scan_detail)
        self.assertEqual(scan_detail["id"], scan_id)
        self.assertEqual(scan_detail["target"], "10.0.0.1")
        self.assertEqual(len(scan_detail["open_ports"]), 1)
        self.assertEqual(scan_detail["open_ports"][0]["port"], 80)
        self.assertEqual(len(scan_detail["findings"]), 1)
        self.assertEqual(scan_detail["findings"][0]["rule_id"], "SS-HTTP-001")
        self.assertEqual(scan_detail["severity_counts"]["Medium"], 1)

    def test_get_scan_by_id_returns_none_for_missing_id(self):
        """Verify get_scan_by_id returns None for non-existent scan ID."""
        result = get_scan_by_id(99999, db_path=self.db_path)
        self.assertIsNone(result)

    def test_delete_scan_removes_scan_and_cascades(self):
        """Verify delete_scan deletes scans row and CASCADE deletes open_ports and findings."""
        scan_result = {
            "target": "192.168.1.50",
            "host_status": "up",
            "scan_started_at": "2026-07-28 12:00:00",
            "open_port_count": 1,
            "open_ports": [{"port": 22, "protocol": "TCP", "state": "open", "service": "ssh", "product": "OpenSSH", "version": "8.2"}],
        }
        analysis_result = {
            "finding_count": 1,
            "overall_risk": "Low",
            "findings": [
                {
                    "rule_id": "SS-SSH-001",
                    "title": "SSH Service Exposed",
                    "severity": "Low",
                    "category": "Remote Access Exposure",
                    "port": 22,
                    "protocol": "TCP",
                    "service": "ssh",
                    "product": "OpenSSH",
                    "version": "8.2",
                    "description": "SSH port open.",
                    "evidence": "TCP/22 open",
                    "recommendation": "Use key auth.",
                    "confidence": "High",
                }
            ],
        }

        scan_id = save_scan(scan_result, analysis_result, db_path=self.db_path)

        # Confirm inserted
        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS c FROM open_ports WHERE scan_id = ?", (scan_id,))
        self.assertEqual(cursor.fetchone()["c"], 1)
        cursor.execute("SELECT COUNT(*) AS c FROM findings WHERE scan_id = ?", (scan_id,))
        self.assertEqual(cursor.fetchone()["c"], 1)
        conn.close()

        # Delete scan
        success = delete_scan(scan_id, db_path=self.db_path)
        self.assertTrue(success)

        # Verify scan and child records are gone
        self.assertIsNone(get_scan_by_id(scan_id, db_path=self.db_path))

        conn = get_connection(self.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) AS c FROM open_ports WHERE scan_id = ?", (scan_id,))
        self.assertEqual(cursor.fetchone()["c"], 0)
        cursor.execute("SELECT COUNT(*) AS c FROM findings WHERE scan_id = ?", (scan_id,))
        self.assertEqual(cursor.fetchone()["c"], 0)
        conn.close()

    def test_delete_scan_returns_false_for_missing_id(self):
        """Verify delete_scan returns False when attempting to delete non-existent scan ID."""
        result = delete_scan(99999, db_path=self.db_path)
        self.assertFalse(result)

    def test_multiple_scans_remain_isolated(self):
        """Verify multiple saved scans do not cross-contaminate open ports or findings."""
        id1 = save_scan(
            {"target": "10.0.0.1", "scan_started_at": "2026-07-28", "open_ports": [{"port": 80, "protocol": "TCP", "state": "open"}]},
            {"findings": [{"rule_id": "SS-HTTP-001", "title": "HTTP", "severity": "Low", "port": 80}]},
            db_path=self.db_path
        )
        id2 = save_scan(
            {"target": "10.0.0.2", "scan_started_at": "2026-07-28", "open_ports": [{"port": 22, "protocol": "TCP", "state": "open"}]},
            {"findings": [{"rule_id": "SS-SSH-001", "title": "SSH", "severity": "Low", "port": 22}]},
            db_path=self.db_path
        )

        scan1 = get_scan_by_id(id1, db_path=self.db_path)
        scan2 = get_scan_by_id(id2, db_path=self.db_path)

        self.assertEqual(len(scan1["open_ports"]), 1)
        self.assertEqual(scan1["open_ports"][0]["port"], 80)
        self.assertEqual(len(scan2["open_ports"]), 1)
        self.assertEqual(scan2["open_ports"][0]["port"], 22)

    def test_missing_or_malformed_fields_do_not_crash_save_scan(self):
        """Verify save_scan safely handles missing, None, or malformed input dict values."""
        malformed_scan = {
            "target": None,
            "resolved_addresses": "127.0.0.1",
            "host_status": None,
            "scan_started_at": None,
            "scan_duration_seconds": "invalid_float",
            "open_port_count": "invalid_int",
            "open_ports": [
                "not_a_dict",
                {"port": "80_invalid", "protocol": None, "state": None},
            ],
        }
        malformed_analysis = {
            "finding_count": "invalid_count",
            "overall_risk": "SuperCriticalUnrecognizedRisk",
            "findings": [
                "not_a_dict",
                {"rule_id": None, "severity": "UNKNOWN_SEV", "port": "bad_port"},
            ],
        }

        # Must not raise an exception
        scan_id = save_scan(malformed_scan, malformed_analysis, db_path=self.db_path)
        self.assertIsInstance(scan_id, int)

        scan = get_scan_by_id(scan_id, db_path=self.db_path)
        self.assertIsNotNone(scan)
        self.assertEqual(scan["overall_risk"], "Info")


if __name__ == "__main__":
    unittest.main()
