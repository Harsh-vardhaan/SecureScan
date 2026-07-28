"""
=============================================================================
SecureScan - Automated Vulnerability Assessment Platform
Database Persistence Layer: database/db.py

PURPOSE:
Provides SQLite database management functions for saving, retrieving, and
deleting authorized vulnerability scans, open ports, and rule-based findings.

KEY DESIGN PRINCIPLES:
- Built with Python's standard `sqlite3` module (zero external DB dependencies).
- Strictly uses parameterized SQL queries to prevent SQL injection vulnerabilities.
- Executes multi-table inserts atomically within a single transaction.
- Configurable database path for development and isolated unit testing.
=============================================================================
"""

import os
import sqlite3
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Base directory of the SecureScan project root (two levels up from database/db.py or one level up from database/)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "database", "securescan.db")
SCHEMA_FILE_PATH = os.path.join(BASE_DIR, "database", "schema.sql")

VALID_RISK_LEVELS = {"Critical", "High", "Medium", "Low", "Info"}


class DatabaseError(Exception):
    """Custom exception raised when a database operation fails."""
    pass


def get_db_path(custom_path: Optional[str] = None) -> str:
    """
    Resolves the SQLite database file path.
    Prioritizes an explicitly passed custom_path, then SECURESCAN_DATABASE_PATH
    environment variable, and defaults to project_root/database/securescan.db.
    """
    if custom_path:
        return os.path.abspath(custom_path)
    
    env_path = os.environ.get("SECURESCAN_DATABASE_PATH")
    if env_path:
        return os.path.abspath(env_path)
        
    return DEFAULT_DB_PATH


def get_connection(db_path: Optional[str] = None) -> sqlite3.Connection:
    """
    Creates and returns a new SQLite database connection with row factory
    set to sqlite3.Row and foreign key enforcement enabled.
    """
    target_path = get_db_path(db_path)
    db_dir = os.path.dirname(target_path)
    if db_dir and not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)

    try:
        conn = sqlite3.connect(target_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON;")
        return conn
    except sqlite3.Error as e:
        logger.error(f"Failed to connect to database at {target_path}: {e}")
        raise DatabaseError(f"Database connection error: {e}") from e


def initialize_database(db_path: Optional[str] = None) -> None:
    """
    Executes schema.sql to create database tables and indexes if missing.
    Safe to execute multiple times.
    """
    target_path = get_db_path(db_path)
    logger.info(f"Initializing database at path: {target_path}")

    if not os.path.exists(SCHEMA_FILE_PATH):
        raise DatabaseError(f"Schema file not found at: {SCHEMA_FILE_PATH}")

    try:
        with open(SCHEMA_FILE_PATH, "r", encoding="utf-8") as f:
            schema_sql = f.read()

        conn = get_connection(target_path)
        try:
            conn.executescript(schema_sql)
            conn.commit()
            logger.info("Database schema initialized successfully.")
        finally:
            conn.close()
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database schema: {e}")
        raise DatabaseError(f"Database schema initialization error: {e}") from e


def save_scan(
    scan_result: Dict[str, Any],
    analysis_result: Optional[Dict[str, Any]] = None,
    db_path: Optional[str] = None
) -> int:
    """
    Saves a completed scan result, its open ports, and its security findings
    into SQLite atomically inside a single transaction.

    Returns:
        int: The inserted scan ID.

    Raises:
        DatabaseError: If database insertion or transaction commit fails.
    """
    if not isinstance(scan_result, dict):
        raise DatabaseError("Invalid scan_result parameter: expected dictionary.")

    analysis = analysis_result if isinstance(analysis_result, dict) else {}

    # Extract & normalize scan summary attributes safely without mutating inputs
    target = str(scan_result.get("target", "") or "Unknown Target")
    hostname = str(scan_result.get("hostname", "") or "")
    host_status = str(scan_result.get("host_status", "unknown") or "unknown")

    resolved = scan_result.get("resolved_addresses")
    if isinstance(resolved, list):
        resolved_address = ", ".join(str(addr) for addr in resolved if addr)
    elif resolved is not None:
        resolved_address = str(resolved)
    else:
        resolved_address = ""

    scan_started_at = str(
        scan_result.get("scan_started_at") or datetime.now(timezone.utc).isoformat()
    )

    try:
        scan_duration_seconds = float(scan_result.get("scan_duration_seconds", 0.0) or 0.0)
    except (ValueError, TypeError):
        scan_duration_seconds = 0.0

    try:
        open_port_count = int(scan_result.get("open_port_count", 0) or 0)
    except (ValueError, TypeError):
        open_port_count = 0

    try:
        finding_count = int(analysis.get("finding_count", 0) or 0)
    except (ValueError, TypeError):
        finding_count = 0

    overall_risk = str(analysis.get("overall_risk", "Info") or "Info")
    if overall_risk not in VALID_RISK_LEVELS:
        overall_risk = "Info"

    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Insert master scan record
        cursor.execute(
            """
            INSERT INTO scans (
                target, hostname, host_status, resolved_address,
                scan_started_at, scan_duration_seconds, open_port_count,
                finding_count, overall_risk
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                target,
                hostname,
                host_status,
                resolved_address,
                scan_started_at,
                scan_duration_seconds,
                open_port_count,
                finding_count,
                overall_risk,
            ),
        )
        scan_id = cursor.lastrowid
        if not scan_id:
            raise DatabaseError("Failed to obtain lastrowid for inserted scan.")

        # 2. Insert discovered open ports
        open_ports_data = scan_result.get("open_ports")
        if isinstance(open_ports_data, list):
            for port_item in open_ports_data:
                if not isinstance(port_item, dict):
                    continue
                try:
                    port_num = int(port_item.get("port", 0) or 0)
                except (ValueError, TypeError):
                    port_num = 0

                protocol = str(port_item.get("protocol", "TCP") or "TCP").upper()
                state = str(port_item.get("state", "open") or "open")
                service = str(port_item.get("service", "") or "")
                product = str(port_item.get("product", "") or "")
                version = str(port_item.get("version", "") or "")

                cursor.execute(
                    """
                    INSERT INTO open_ports (
                        scan_id, port, protocol, state, service, product, version
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, port_num, protocol, state, service, product, version),
                )

        # 3. Insert rule-based security findings
        findings_data = analysis.get("findings")
        if isinstance(findings_data, list):
            for finding_item in findings_data:
                if not isinstance(finding_item, dict):
                    continue
                rule_id = str(finding_item.get("rule_id", "UNKNOWN") or "UNKNOWN")
                title = str(finding_item.get("title", "Observation") or "Observation")
                severity = str(finding_item.get("severity", "Info") or "Info")
                if severity not in VALID_RISK_LEVELS:
                    severity = "Info"

                category = str(finding_item.get("category", "") or "")
                try:
                    f_port = int(finding_item.get("port", 0) or 0)
                except (ValueError, TypeError):
                    f_port = 0

                f_protocol = str(finding_item.get("protocol", "") or "")
                f_service = str(finding_item.get("service", "") or "")
                f_product = str(finding_item.get("product", "") or "")
                f_version = str(finding_item.get("version", "") or "")
                description = str(finding_item.get("description", "") or "")
                evidence = str(finding_item.get("evidence", "") or "")
                recommendation = str(finding_item.get("recommendation", "") or "")
                confidence = str(finding_item.get("confidence", "") or "")

                cursor.execute(
                    """
                    INSERT INTO findings (
                        scan_id, rule_id, title, severity, category, port,
                        protocol, service, product, version, description,
                        evidence, recommendation, confidence
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        rule_id,
                        title,
                        severity,
                        category,
                        f_port,
                        f_protocol,
                        f_service,
                        f_product,
                        f_version,
                        description,
                        evidence,
                        recommendation,
                        confidence,
                    ),
                )

        conn.commit()
        logger.info(f"Scan ID {scan_id} successfully saved to SQLite.")
        return scan_id

    except Exception as e:
        conn.rollback()
        logger.error(f"Error saving scan to database: {e}")
        raise DatabaseError(f"Failed to save scan record: {e}") from e
    finally:
        conn.close()


def get_recent_scans(limit: int = 10, db_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Retrieves the most recent scans ordered by creation date descending.
    Enforces a safe maximum query limit of 100.
    """
    safe_limit = max(1, min(limit, 100))
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, target, hostname, host_status, resolved_address,
                   scan_started_at, scan_duration_seconds, open_port_count,
                   finding_count, overall_risk, created_at
            FROM scans
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    except sqlite3.Error as e:
        logger.error(f"Error fetching recent scans: {e}")
        raise DatabaseError(f"Failed to retrieve recent scans: {e}") from e
    finally:
        conn.close()


def get_scan_by_id(scan_id: int, db_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """
    Fetches a saved scan record by ID along with its nested open ports,
    security findings, and computed severity metrics.

    Returns:
        Dict[str, Any] | None: Structured scan detail dict, or None if missing.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()

        # 1. Fetch scan summary row
        cursor.execute(
            """
            SELECT id, target, hostname, host_status, resolved_address,
                   scan_started_at, scan_duration_seconds, open_port_count,
                   finding_count, overall_risk, created_at
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        )
        scan_row = cursor.fetchone()
        if not scan_row:
            return None

        scan_dict = dict(scan_row)

        # 2. Fetch associated open ports
        cursor.execute(
            """
            SELECT id, scan_id, port, protocol, state, service, product, version
            FROM open_ports
            WHERE scan_id = ?
            ORDER BY port ASC
            """,
            (scan_id,),
        )
        port_rows = cursor.fetchall()
        scan_dict["open_ports"] = [dict(p) for p in port_rows]

        # 3. Fetch associated security findings
        cursor.execute(
            """
            SELECT id, scan_id, rule_id, title, severity, category, port,
                   protocol, service, product, version, description,
                   evidence, recommendation, confidence
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,),
        )
        finding_rows = cursor.fetchall()
        scan_dict["findings"] = [dict(f) for f in finding_rows]

        # Reconstruct severity counts for Jinja metrics UI
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in scan_dict["findings"]:
            sev = f.get("severity", "Info")
            if sev in severity_counts:
                severity_counts[sev] += 1
        scan_dict["severity_counts"] = severity_counts

        return scan_dict

    except sqlite3.Error as e:
        logger.error(f"Error fetching scan ID {scan_id}: {e}")
        raise DatabaseError(f"Failed to fetch scan detail for ID {scan_id}: {e}") from e
    finally:
        conn.close()


def delete_scan(scan_id: int, db_path: Optional[str] = None) -> bool:
    """
    Deletes a single scan by integer ID.
    Associated open ports and findings are deleted automatically via SQLite CASCADE.

    Returns:
        bool: True if a scan record was deleted, False if scan_id was not found.
    """
    conn = get_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        conn.commit()
        deleted = cursor.rowcount > 0
        if deleted:
            logger.info(f"Scan ID {scan_id} and associated child records deleted successfully.")
        else:
            logger.warning(f"Delete requested for non-existent Scan ID {scan_id}.")
        return deleted
    except sqlite3.Error as e:
        conn.rollback()
        logger.error(f"Error deleting scan ID {scan_id}: {e}")
        raise DatabaseError(f"Failed to delete scan ID {scan_id}: {e}") from e
    finally:
        conn.close()
