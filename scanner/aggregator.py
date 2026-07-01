"""
scanner/aggregator.py
----------------------
Trend analysis and scan-to-scan diff, built on top of db/repository.py.
All DB access now goes through SQLAlchemy sessions (db/models.SessionLocal)
instead of raw sqlite3 — the public API (FindingStatus, ScanDiff, TargetTrend,
and all three functions) is unchanged so web/app.py needs no edits.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, asdict
from typing import Optional

from db.models import SessionLocal, ScanReport, Finding, FindingHistory, Target

logger = logging.getLogger(__name__)


@dataclass
class FindingStatus:
    dedup_key: str
    name: str
    risk: str
    status: str               # "open" | "resolved"
    first_seen_at: str
    last_seen_at: str
    resolved_at: Optional[str]
    scans_seen_in: int

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanDiff:
    target_id: int
    from_scan_id: str
    to_scan_id: str
    fixed: list[str]
    new: list[str]
    still_open: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TargetTrend:
    target_id: int
    url: str
    scan_count: int
    risk_score_series: list[float]
    finding_count_series: list[int]
    open_findings: int
    resolved_findings: int
    trend: str                # "improving" | "worsening" | "stable" | "insufficient_data"

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Public functions
# ---------------------------------------------------------------------------

def get_finding_statuses(target_id: int) -> list[FindingStatus]:
    db = SessionLocal()
    try:
        rows = (
            db.query(FindingHistory)
            .filter_by(target_id=target_id)
            .order_by(
                FindingHistory.resolved_at.is_(None).desc(),
                FindingHistory.last_seen_at.desc(),
            )
            .all()
        )
        result = []
        for r in rows:
            scans_seen = (
                db.query(Finding)
                .join(ScanReport, Finding.scan_report_id == ScanReport.id)
                .filter(
                    ScanReport.target_id == target_id,
                    Finding.dedup_key == r.dedup_key,
                )
                .count()
            )
            result.append(FindingStatus(
                dedup_key     = r.dedup_key,
                name          = r.name,
                risk          = r.risk,
                status        = "resolved" if r.resolved_at else "open",
                first_seen_at = r.first_seen_at.isoformat() if r.first_seen_at else "",
                last_seen_at  = r.last_seen_at.isoformat()  if r.last_seen_at  else "",
                resolved_at   = r.resolved_at.isoformat()   if r.resolved_at   else None,
                scans_seen_in = scans_seen,
            ))
        return result
    finally:
        db.close()


def diff_scans(scan_id_a: str, scan_id_b: str) -> ScanDiff:
    db = SessionLocal()
    try:
        reports = (
            db.query(ScanReport)
            .filter(ScanReport.id.in_([scan_id_a, scan_id_b]))
            .all()
        )
        if len(reports) != 2:
            raise ValueError("One or both scan IDs were not found.")
        if reports[0].target_id != reports[1].target_id:
            raise ValueError("Cannot diff scans belonging to different targets.")

        ordered = sorted(reports, key=lambda r: r.started_at)
        earlier, later = ordered[0], ordered[1]

        def findings_map(scan_id: str) -> dict[str, str]:
            rows = db.query(Finding).filter_by(scan_report_id=scan_id).all()
            return {f.dedup_key: f.name for f in rows}

        before = findings_map(earlier.id)
        after  = findings_map(later.id)

        return ScanDiff(
            target_id    = earlier.target_id,
            from_scan_id = earlier.id,
            to_scan_id   = later.id,
            fixed        = [n for k, n in before.items() if k not in after],
            new          = [n for k, n in after.items()  if k not in before],
            still_open   = [n for k, n in after.items()  if k in before],
        )
    finally:
        db.close()


def get_target_trend(target_id: int) -> TargetTrend:
    db = SessionLocal()
    try:
        target = db.query(Target).filter_by(id=target_id).first()
        if not target:
            raise ValueError(f"No target with id {target_id}")

        scans = (
            db.query(ScanReport)
            .filter_by(target_id=target_id, status="done")
            .order_by(ScanReport.started_at.asc())
            .all()
        )

        open_count = (
            db.query(FindingHistory)
            .filter_by(target_id=target_id)
            .filter(FindingHistory.resolved_at.is_(None))
            .count()
        )
        resolved_count = (
            db.query(FindingHistory)
            .filter_by(target_id=target_id)
            .filter(FindingHistory.resolved_at.isnot(None))
            .count()
        )

        risk_series  = [s.risk_score    for s in scans]
        count_series = [s.finding_count for s in scans]

        return TargetTrend(
            target_id            = target_id,
            url                  = target.url,
            scan_count           = len(scans),
            risk_score_series    = risk_series,
            finding_count_series = count_series,
            open_findings        = open_count,
            resolved_findings    = resolved_count,
            trend                = _classify_trend(risk_series),
        )
    finally:
        db.close()


def _classify_trend(risk_series: list[float], threshold: float = 0.5) -> str:
    if len(risk_series) < 2:
        return "insufficient_data"
    delta = risk_series[-1] - risk_series[-2]
    if delta <= -threshold:
        return "improving"
    if delta >= threshold:
        return "worsening"
    return "stable"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import json, sys
    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage:\n  python -m scanner.aggregator trend <target_id>"
              "\n  python -m scanner.aggregator status <target_id>"
              "\n  python -m scanner.aggregator diff <scan_id_a> <scan_id_b>")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "trend"  and len(sys.argv) == 3:
        print(json.dumps(get_target_trend(int(sys.argv[2])).to_dict(), indent=2))
    elif cmd == "status" and len(sys.argv) == 3:
        print(json.dumps([f.to_dict() for f in get_finding_statuses(int(sys.argv[2]))], indent=2))
    elif cmd == "diff"   and len(sys.argv) == 4:
        print(json.dumps(diff_scans(sys.argv[2], sys.argv[3]).to_dict(), indent=2))
    else:
        print("Invalid arguments."); sys.exit(1)
