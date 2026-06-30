"""
db/repository.py
-----------------
Data access layer on top of db/models.py.

This is what web/app.py should call instead of reading/writing the JOBS
dict directly, for anything that needs to survive a restart: scan results,
finding history, target list. The in-memory part of JOBS (log_queue, the
running thread) stays in app.py exactly as-is — that's per-process runtime
state, not data, and SQLite isn't the right place for it.

Typical flow once wired into web/app.py:

    1. start_scan() -> repository.create_target_if_missing(url)
                     -> repository.create_scan_report(job_id, target_id, source="live"/"mock")
       (JOBS dict still created as today, for the live log_queue/thread)

    2. run_mock_scan() on success -> repository.complete_scan_report(job_id, summary)
                         on error   -> repository.fail_scan_report(job_id, str(exc))

    3. New /dashboard route -> repository.list_targets_with_last_scan()
       New /target/<id> route -> repository.get_scan_history(target_id)

No changes to scanner/parser.py or scanner/zap_scanner.py are required —
this module only persists what those already produce.
"""

import sqlite3
from typing import Optional

from db.models import get_connection


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def get_or_create_target(url: str, label: Optional[str] = None) -> int:
    """Returns the target id for a URL, creating the row if it doesn't exist yet."""
    conn = get_connection()
    try:
        cur = conn.execute("SELECT id FROM targets WHERE url = ?", (url,))
        row = cur.fetchone()
        if row:
            return row["id"]

        cur = conn.execute(
            "INSERT INTO targets (url, label) VALUES (?, ?)", (url, label)
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def list_targets_with_last_scan() -> list[dict]:
    """
    For the planned /dashboard route: all targets, their most recent scan's
    status/finding_count/risk_score, and total scan count.
    """
    conn = get_connection()
    try:
        rows = conn.execute("""
            SELECT
                t.id              AS target_id,
                t.url             AS url,
                t.label           AS label,
                COUNT(sr.id)      AS scan_count,
                MAX(sr.finished_at) AS last_scan_at,
                (SELECT sr2.status        FROM scan_reports sr2
                  WHERE sr2.target_id = t.id ORDER BY sr2.started_at DESC LIMIT 1) AS last_status,
                (SELECT sr2.finding_count FROM scan_reports sr2
                  WHERE sr2.target_id = t.id ORDER BY sr2.started_at DESC LIMIT 1) AS last_finding_count,
                (SELECT sr2.risk_score    FROM scan_reports sr2
                  WHERE sr2.target_id = t.id ORDER BY sr2.started_at DESC LIMIT 1) AS last_risk_score,
                (SELECT sr2.id            FROM scan_reports sr2
                  WHERE sr2.target_id = t.id ORDER BY sr2.started_at DESC LIMIT 1) AS last_scan_id
            FROM targets t
            LEFT JOIN scan_reports sr ON sr.target_id = t.id
            GROUP BY t.id
            ORDER BY last_scan_at DESC NULLS LAST
        """).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scan reports
# ---------------------------------------------------------------------------

def create_scan_report(scan_id: str, target_url: str, source: str = "live") -> None:
    """
    Call this when a scan starts (mirrors today's JOBS[job_id] = {...} init
    in web/app.py start_scan()). source: 'live' | 'mock' | 'imported'.
    """
    target_id = get_or_create_target(target_url)
    conn = get_connection()
    try:
        conn.execute(
            """INSERT INTO scan_reports (id, target_id, source, status)
               VALUES (?, ?, ?, 'running')""",
            (scan_id, target_id, source),
        )
        conn.commit()
    finally:
        conn.close()


def complete_scan_report(scan_id: str, summary, report_path: str) -> None:
    """
    Call this on successful scan completion. `summary` is the ScanSummary
    dataclass instance already produced by AlertParser.parse() — same object
    web/app.py already has at that point, no extra computation needed.
    Also writes each ParsedAlert as a row in `findings`.
    """
    conn = get_connection()
    try:
        conn.execute(
            """UPDATE scan_reports SET
                   status = 'done',
                   finished_at = datetime('now'),
                   finding_count = ?,
                   high_count = ?,
                   medium_count = ?,
                   low_count = ?,
                   info_count = ?,
                   risk_score = ?,
                   report_path = ?
               WHERE id = ?""",
            (
                summary.total_alerts,
                summary.high,
                summary.medium,
                summary.low,
                summary.informational,
                summary.risk_score,
                report_path,
                scan_id,
            ),
        )

        for alert in summary.alerts:
            dedup_key = f"{alert.alert_id}-{alert.url}-{alert.param}"
            conn.execute(
                """INSERT INTO findings (
                       scan_report_id, alert_id, name, risk, risk_score,
                       confidence, owasp_id, owasp_name, description, url,
                       param, evidence, solution, reference, cwe_id, wasc_id,
                       dedup_key
                   ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, alert.alert_id, alert.name, alert.risk, alert.risk_score,
                    alert.confidence, alert.owasp_id, alert.owasp_name, alert.description,
                    alert.url, alert.param, alert.evidence, alert.solution,
                    alert.reference, alert.cwe_id, alert.wasc_id, dedup_key,
                ),
            )

        conn.commit()
    finally:
        conn.close()

    # Finding history is updated separately so a failure there never blocks
    # the scan itself from being marked complete.
    _update_finding_history(scan_id, summary)


def fail_scan_report(scan_id: str, error_message: str) -> None:
    """Call this when a scan errors out (mirrors today's JOBS[job_id]['status'] = 'error')."""
    conn = get_connection()
    try:
        conn.execute(
            """UPDATE scan_reports SET
                   status = 'error',
                   finished_at = datetime('now'),
                   error_message = ?
               WHERE id = ?""",
            (error_message, scan_id),
        )
        conn.commit()
    finally:
        conn.close()


def get_scan_report(scan_id: str) -> Optional[dict]:
    """Fetches a single scan report row — useful for /report/<id> and /download/<id> after restart."""
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT * FROM scan_reports WHERE id = ?", (scan_id,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_scan_history(target_id: int) -> list[dict]:
    """All scans for one target, most recent first — for the planned /target/<id> route."""
    conn = get_connection()
    try:
        rows = conn.execute(
            """SELECT * FROM scan_reports
               WHERE target_id = ?
               ORDER BY started_at DESC""",
            (target_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_findings_for_scan(scan_id: str) -> list[dict]:
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM findings WHERE scan_report_id = ? ORDER BY risk_score DESC",
            (scan_id,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Finding history (basis for the planned aggregator module)
# ---------------------------------------------------------------------------

def _update_finding_history(scan_id: str, summary) -> None:
    """
    Upserts finding_history rows for this scan's findings, and marks any
    previously-open finding for this target as resolved if it didn't show
    up in this scan. This is intentionally simple — scanner/aggregator.py
    (not yet built) is where dedup-across-tools logic and trend reporting
    will live; this just keeps the raw history table accurate scan-by-scan.
    """
    conn = get_connection()
    try:
        row = conn.execute(
            "SELECT target_id FROM scan_reports WHERE id = ?", (scan_id,)
        ).fetchone()
        if not row:
            return
        target_id = row["target_id"]

        current_keys = set()
        for alert in summary.alerts:
            dedup_key = f"{alert.alert_id}-{alert.url}-{alert.param}"
            current_keys.add(dedup_key)

            existing = conn.execute(
                """SELECT id FROM finding_history
                   WHERE target_id = ? AND dedup_key = ?""",
                (target_id, dedup_key),
            ).fetchone()

            if existing:
                conn.execute(
                    """UPDATE finding_history SET
                           last_seen_scan_id = ?,
                           last_seen_at = datetime('now'),
                           resolved_at = NULL
                       WHERE id = ?""",
                    (scan_id, existing["id"]),
                )
            else:
                conn.execute(
                    """INSERT INTO finding_history (
                           target_id, dedup_key, name, risk,
                           first_seen_scan_id, last_seen_scan_id
                       ) VALUES (?, ?, ?, ?, ?, ?)""",
                    (target_id, dedup_key, alert.name, alert.risk, scan_id, scan_id),
                )

        # Anything open for this target but absent from this scan = resolved.
        open_rows = conn.execute(
            """SELECT id, dedup_key FROM finding_history
               WHERE target_id = ? AND resolved_at IS NULL""",
            (target_id,),
        ).fetchall()
        for r in open_rows:
            if r["dedup_key"] not in current_keys:
                conn.execute(
                    "UPDATE finding_history SET resolved_at = datetime('now') WHERE id = ?",
                    (r["id"],),
                )

        conn.commit()
    finally:
        conn.close()
