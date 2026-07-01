"""
db/repository.py
-----------------
Data access layer — all DB queries go through here, never raw SQL in app.py.
Uses SQLAlchemy sessions from db/models.SessionLocal.

Public interface is identical to the previous sqlite3 version so web/app.py
and scanner/aggregator.py need zero changes — only the internals changed.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

from db.models import (
    SessionLocal, Target, ScanReport, Finding, FindingHistory
)


# ---------------------------------------------------------------------------
# Session helper
# ---------------------------------------------------------------------------

@contextmanager
def _session():
    db = SessionLocal()
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Targets
# ---------------------------------------------------------------------------

def get_or_create_target(url: str, label: Optional[str] = None) -> int:
    with _session() as db:
        target = db.query(Target).filter_by(url=url).first()
        if target:
            return target.id
        target = Target(url=url, label=label)
        db.add(target)
        db.flush()
        return target.id


def list_targets_with_last_scan() -> list[dict]:
    with _session() as db:
        targets = db.query(Target).all()
        result = []
        for t in targets:
            reports = (
                db.query(ScanReport)
                .filter_by(target_id=t.id)
                .order_by(ScanReport.started_at.desc())
                .all()
            )
            last = reports[0] if reports else None
            result.append({
                "target_id":          t.id,
                "url":                t.url,
                "label":              t.label,
                "scan_count":         len(reports),
                "last_scan_at":       last.finished_at.isoformat() if last and last.finished_at else None,
                "last_status":        last.status        if last else None,
                "last_finding_count": last.finding_count if last else None,
                "last_risk_score":    last.risk_score    if last else None,
                "last_scan_id":       last.id            if last else None,
            })
        result.sort(key=lambda x: x["last_scan_at"] or "", reverse=True)
        return result


# ---------------------------------------------------------------------------
# Scan reports
# ---------------------------------------------------------------------------

def create_scan_report(scan_id: str, target_url: str, source: str = "live") -> None:
    target_id = get_or_create_target(target_url)
    with _session() as db:
        report = ScanReport(id=scan_id, target_id=target_id, source=source, status="running")
        db.add(report)


def complete_scan_report(scan_id: str, summary, report_path: str) -> None:
    with _session() as db:
        report = db.query(ScanReport).filter_by(id=scan_id).first()
        if not report:
            return
        report.status        = "done"
        report.finished_at   = _now()
        report.finding_count = summary.total_alerts
        report.high_count    = summary.high
        report.medium_count  = summary.medium
        report.low_count     = summary.low
        report.info_count    = summary.informational
        report.risk_score    = summary.risk_score
        report.report_path   = report_path

        for alert in summary.alerts:
            dedup_key = f"{alert.alert_id}-{alert.url}-{alert.param}"
            db.add(Finding(
                scan_report_id = scan_id,
                alert_id       = alert.alert_id,
                name           = alert.name,
                risk           = alert.risk,
                risk_score     = alert.risk_score,
                confidence     = alert.confidence,
                owasp_id       = alert.owasp_id,
                owasp_name     = alert.owasp_name,
                description    = alert.description,
                url            = alert.url,
                param          = alert.param,
                evidence       = alert.evidence,
                solution       = alert.solution,
                reference      = alert.reference,
                cwe_id         = alert.cwe_id,
                wasc_id        = alert.wasc_id,
                dedup_key      = dedup_key,
            ))

    _update_finding_history(scan_id, summary)


def fail_scan_report(scan_id: str, error_message: str) -> None:
    with _session() as db:
        report = db.query(ScanReport).filter_by(id=scan_id).first()
        if report:
            report.status        = "error"
            report.finished_at   = _now()
            report.error_message = error_message


def get_scan_report(scan_id: str) -> Optional[dict]:
    with _session() as db:
        report = db.query(ScanReport).filter_by(id=scan_id).first()
        return report.to_dict() if report else None


def get_scan_history(target_id: int) -> list[dict]:
    with _session() as db:
        reports = (
            db.query(ScanReport)
            .filter_by(target_id=target_id)
            .order_by(ScanReport.started_at.desc())
            .all()
        )
        return [r.to_dict() for r in reports]


def get_findings_for_scan(scan_id: str) -> list[dict]:
    with _session() as db:
        findings = (
            db.query(Finding)
            .filter_by(scan_report_id=scan_id)
            .order_by(Finding.risk_score.desc())
            .all()
        )
        return [f.to_dict() for f in findings]


# ---------------------------------------------------------------------------
# Finding history
# ---------------------------------------------------------------------------

def _update_finding_history(scan_id: str, summary) -> None:
    with _session() as db:
        report = db.query(ScanReport).filter_by(id=scan_id).first()
        if not report:
            return
        target_id = report.target_id
        now = _now()

        current_keys = set()
        for alert in summary.alerts:
            dedup_key = f"{alert.alert_id}-{alert.url}-{alert.param}"
            current_keys.add(dedup_key)

            existing = (
                db.query(FindingHistory)
                .filter_by(target_id=target_id, dedup_key=dedup_key)
                .first()
            )
            if existing:
                existing.last_seen_scan_id = scan_id
                existing.last_seen_at      = now
                existing.resolved_at       = None
            else:
                db.add(FindingHistory(
                    target_id          = target_id,
                    dedup_key          = dedup_key,
                    name               = alert.name,
                    risk               = alert.risk,
                    first_seen_scan_id = scan_id,
                    last_seen_scan_id  = scan_id,
                    first_seen_at      = now,
                    last_seen_at       = now,
                ))

        # Mark resolved: findings previously open but absent from this scan
        open_rows = (
            db.query(FindingHistory)
            .filter_by(target_id=target_id)
            .filter(FindingHistory.resolved_at.is_(None))
            .all()
        )
        for row in open_rows:
            if row.dedup_key not in current_keys:
                row.resolved_at = now
