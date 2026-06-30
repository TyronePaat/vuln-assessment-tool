"""
db/models.py
------------
SQLite schema for vuln-assessment-tool persistence.

Directly replaces the in-memory `JOBS` dict in `web/app.py`, which loses all
scan history on every Flask restart. This was tracked as a known issue;
fixing it here also lays the groundwork for the aggregator/compliance
modules planned next (they need scan history to dedupe/trend findings
across time and across targets).

Design notes:
    - `targets`        — one row per distinct scanned URL/host.
    - `scan_reports`    — one row per completed scan run (live or ingested).
                          Mirrors the existing job/result fields already
                          used in JOBS (target, finding_count, risk_counts,
                          report_id) plus a `source` to distinguish live ZAP
                          scans from imported reports (see scanner/ingestion.py).
    - `findings`        — one row per ParsedAlert, FK'd to its scan_report.
                          Stores the same fields as the existing ParsedAlert
                          dataclass (scanner/parser.py) — no new fields
                          invented, this is a direct persistence of what
                          already exists.
    - `finding_history` — tracks a finding's lifecycle across scans of the
                          same target (first_seen, last_seen, resolved_at).
                          Used by the planned aggregator module to compute
                          trend/still-open status; left empty until that
                          module is built, but the table exists now so
                          ingestion/scan-saving code can start writing to it.

This module only defines schema + connection helper. Query logic belongs in
db/repository.py — keeps schema changes and data-access changes independent.
"""

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "vuln_assessment.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    url         TEXT NOT NULL UNIQUE,
    label       TEXT,                      -- optional friendly name, e.g. "Portal Desa Kawiley"
    created_at  TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_reports (
    id              TEXT PRIMARY KEY,       -- job_id / report_id (uuid4 string, matches existing report filenames)
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    source          TEXT NOT NULL DEFAULT 'live',  -- 'live' (ZAPScanner) | 'mock' (MockScanner) | 'imported' (ingestion.py)
    status          TEXT NOT NULL DEFAULT 'running', -- 'running' | 'done' | 'error'
    started_at      TEXT NOT NULL DEFAULT (datetime('now')),
    finished_at     TEXT,
    finding_count   INTEGER DEFAULT 0,
    high_count      INTEGER DEFAULT 0,
    medium_count    INTEGER DEFAULT 0,
    low_count       INTEGER DEFAULT 0,
    info_count      INTEGER DEFAULT 0,
    risk_score      REAL DEFAULT 0,
    report_path     TEXT,                   -- relative path under web/reports/
    error_message   TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_report_id  TEXT NOT NULL REFERENCES scan_reports(id) ON DELETE CASCADE,
    alert_id        TEXT,                   -- ZAP pluginId
    name            TEXT NOT NULL,
    risk            TEXT NOT NULL,           -- High | Medium | Low | Informational
    risk_score      INTEGER,
    confidence      TEXT,
    owasp_id        TEXT,                    -- e.g. "A05:2021"
    owasp_name      TEXT,
    description     TEXT,
    url             TEXT,
    param           TEXT,
    evidence        TEXT,
    solution        TEXT,
    reference       TEXT,
    cwe_id          TEXT,
    wasc_id         TEXT,
    dedup_key       TEXT NOT NULL            -- pluginId-url-param, matches AlertParser._dedup_key
);

CREATE TABLE IF NOT EXISTS finding_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id       INTEGER NOT NULL REFERENCES targets(id) ON DELETE CASCADE,
    dedup_key       TEXT NOT NULL,           -- same logical finding across scans of this target
    name            TEXT NOT NULL,
    risk            TEXT NOT NULL,
    first_seen_scan_id TEXT NOT NULL REFERENCES scan_reports(id),
    last_seen_scan_id  TEXT NOT NULL REFERENCES scan_reports(id),
    first_seen_at   TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen_at    TEXT NOT NULL DEFAULT (datetime('now')),
    resolved_at     TEXT,                    -- NULL = still open as of last scan
    UNIQUE(target_id, dedup_key)
);

CREATE INDEX IF NOT EXISTS idx_scan_reports_target ON scan_reports(target_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan_report ON findings(scan_report_id);
CREATE INDEX IF NOT EXISTS idx_finding_history_target ON finding_history(target_id);
"""


def get_connection() -> sqlite3.Connection:
    """
    Returns a SQLite connection with foreign keys enforced and Row factory
    enabled (so query results behave like dicts — easier to feed straight
    into Jinja2 templates without an extra mapping step).
    """
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Creates all tables if they don't exist yet. Safe to call on every app startup."""
    conn = get_connection()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {DB_PATH}")
