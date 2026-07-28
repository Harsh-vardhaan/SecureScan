-- =============================================================================
-- SecureScan - Automated Vulnerability Assessment Platform
-- SQLite Database Schema Definition: database/schema.sql
-- =============================================================================

-- Enable Foreign Key constraints enforcement
PRAGMA foreign_keys = ON;

-- -----------------------------------------------------------------------------
-- 1. Table: scans
-- Stores core metadata and summary statistics for completed vulnerability assessments.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    hostname TEXT,
    host_status TEXT,
    resolved_address TEXT,
    scan_started_at TEXT NOT NULL,
    scan_duration_seconds REAL NOT NULL DEFAULT 0,
    open_port_count INTEGER NOT NULL DEFAULT 0,
    finding_count INTEGER NOT NULL DEFAULT 0,
    overall_risk TEXT NOT NULL DEFAULT 'Info',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- -----------------------------------------------------------------------------
-- 2. Table: open_ports
-- Stores individual open ports, protocols, state, and detected service/product/version details.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS open_ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT,
    product TEXT,
    version TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- 3. Table: findings
-- Stores rule-based vulnerability findings, severity, evidence, and recommendations.
-- -----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    category TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    product TEXT,
    version TEXT,
    description TEXT,
    evidence TEXT,
    recommendation TEXT,
    confidence TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- Performance optimizations for rapid querying by timestamp, target, scan ID, and severity.
-- -----------------------------------------------------------------------------
CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target);
CREATE INDEX IF NOT EXISTS idx_open_ports_scan_id ON open_ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
