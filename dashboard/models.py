"""SQLite schema and database utilities for NIST 800-53 compliance dashboard."""
import sqlite3
import os

DB_PATH_DEFAULT = "./dashboard.db"

FAMILY_NAMES = {
    "AC": "Access Control",
    "AT": "Awareness and Training",
    "AU": "Audit and Accountability",
    "CA": "Assessment, Authorization, and Monitoring",
    "CM": "Configuration Management",
    "CP": "Contingency Planning",
    "IA": "Identification and Authentication",
    "IR": "Incident Response",
    "MA": "Maintenance",
    "MP": "Media Protection",
    "PE": "Physical and Environmental Protection",
    "PL": "Planning",
    "PM": "Program Management",
    "PS": "Personnel Security",
    "RA": "Risk Assessment",
    "SA": "System and Services Acquisition",
    "SC": "System and Communications Protection",
    "SI": "System and Information Integrity",
    "SR": "Supply Chain Risk Management",
}

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS control_owners (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id  TEXT NOT NULL,
    owner_name  TEXT NOT NULL,
    owner_email TEXT,
    role        TEXT DEFAULT 'engineer'
                     CHECK(role IN ('isso','engineer','manager','auditor')),
    team        TEXT,
    created_at  TEXT DEFAULT (datetime('now')),
    updated_at  TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS poam_items (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    poam_id                  TEXT NOT NULL UNIQUE,
    control_id               TEXT NOT NULL,
    control_family           TEXT NOT NULL,
    title                    TEXT NOT NULL,
    description              TEXT NOT NULL,
    severity                 TEXT NOT NULL
                                  CHECK(severity IN ('critical','high','medium','low')),
    status                   TEXT NOT NULL DEFAULT 'open'
                                  CHECK(status IN ('open','in_progress','closed','accepted_risk')),
    owner_id                 INTEGER REFERENCES control_owners(id),
    scheduled_completion_date TEXT,
    actual_completion_date   TEXT,
    auto_generated           INTEGER DEFAULT 1,
    source_report_id         TEXT,
    created_at               TEXT DEFAULT (datetime('now')),
    updated_at               TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS evidence (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id    TEXT NOT NULL,
    title         TEXT NOT NULL,
    doc_type      TEXT CHECK(doc_type IN ('SSP','SAR','POAM','screenshot','policy','other')),
    url           TEXT,
    file_path     TEXT,
    last_reviewed TEXT,
    is_fresh      INTEGER DEFAULT 1,
    created_at    TEXT DEFAULT (datetime('now')),
    updated_at    TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS exceptions (
    id                       INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id               TEXT NOT NULL,
    exception_type           TEXT CHECK(exception_type IN ('risk_acceptance','waiver','compensating_control')),
    title                    TEXT NOT NULL,
    justification            TEXT,
    compensating_control_desc TEXT,
    approved_by              TEXT,
    expiration_date          TEXT,
    status                   TEXT DEFAULT 'active'
                                  CHECK(status IN ('active','expired','revoked')),
    created_at               TEXT DEFAULT (datetime('now')),
    updated_at               TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_history (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id        TEXT NOT NULL UNIQUE,
    scan_date        TEXT NOT NULL,
    total_controls   INTEGER,
    compliant_count  INTEGER,
    compliance_pct   REAL,
    scan_duration_s  REAL,
    triggered_by     TEXT DEFAULT 'manual'
                          CHECK(triggered_by IN ('manual','scheduled','api')),
    created_at       TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS monitoring_schedule (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    control_id      TEXT NOT NULL UNIQUE,
    check_frequency TEXT DEFAULT 'monthly'
                         CHECK(check_frequency IN ('continuous','daily','weekly','monthly','quarterly','manual')),
    check_type      TEXT DEFAULT 'manual'
                         CHECK(check_type IN ('automated','manual','hybrid')),
    last_checked    TEXT,
    next_due        TEXT,
    sla_hours       INTEGER DEFAULT 720,
    updated_at      TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS assets (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_name         TEXT NOT NULL,
    asset_type         TEXT CHECK(asset_type IN ('server','container','network','cloud_service','workstation','other')),
    environment        TEXT CHECK(environment IN ('cloud','on_prem','hybrid')),
    applicable_families TEXT,
    owner_id           INTEGER REFERENCES control_owners(id),
    created_at         TEXT DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_poam_control_id   ON poam_items(control_id);
CREATE INDEX IF NOT EXISTS idx_poam_status        ON poam_items(status);
CREATE INDEX IF NOT EXISTS idx_poam_severity      ON poam_items(severity);
CREATE INDEX IF NOT EXISTS idx_evidence_control   ON evidence(control_id);
CREATE INDEX IF NOT EXISTS idx_exceptions_control ON exceptions(control_id);
CREATE INDEX IF NOT EXISTS idx_scan_history_date  ON scan_history(scan_date DESC);
CREATE INDEX IF NOT EXISTS idx_owners_control     ON control_owners(control_id);
"""


def init_db(db_path: str = DB_PATH_DEFAULT) -> sqlite3.Connection:
    """Create all tables and indexes if they don't exist. Returns open connection.
    Sets row_factory = sqlite3.Row, enables foreign keys, uses WAL journal mode."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.executescript(_SCHEMA_SQL)
    conn.commit()
    return conn


def get_db(db_path: str = DB_PATH_DEFAULT) -> sqlite3.Connection:
    """Return a new connection with row_factory = sqlite3.Row, foreign keys ON."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
