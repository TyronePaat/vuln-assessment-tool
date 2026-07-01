"""
db/models.py
------------
SQLAlchemy ORM models for vuln-assessment-tool.

Replaces the previous sqlite3-raw schema. The database URL defaults to a
local SQLite file (zero setup, sufficient for 30-50 government sites), but
can be pointed at PostgreSQL or MySQL by setting the DATABASE_URL env var —
SQLAlchemy handles the rest without any changes to this file or repository.py.

    DATABASE_URL=postgresql://user:pass@host/dbname python web/app.py

Tables:
    targets          — one row per distinct scanned URL/host
    scan_reports     — one row per completed scan run (live, mock, or imported)
    findings         — one row per ParsedAlert, FK'd to scan_reports
    finding_history  — lifecycle of a finding across scans of the same target
                       (first_seen, last_seen, resolved_at) — used by
                       scanner/aggregator.py for trend and diff logic
"""

import os
from datetime import datetime, timezone

from sqlalchemy import (
    Column, Integer, Float, String, Text, DateTime,
    ForeignKey, UniqueConstraint, Index, create_engine, event
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

# ---------------------------------------------------------------------------
# Engine + session factory
# ---------------------------------------------------------------------------

_DEFAULT_DB = f"sqlite:///{os.path.join(os.path.dirname(__file__), 'vuln_assessment.db')}"
DATABASE_URL = os.environ.get("DATABASE_URL", _DEFAULT_DB)

engine = create_engine(
    DATABASE_URL,
    # SQLite-specific: check_same_thread=False allows Flask's multi-threaded
    # request handling. Ignored silently by other DB backends.
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
    echo=False,
)

# Enable FK enforcement for SQLite (a no-op for other backends).
@event.listens_for(engine, "connect")
def _set_sqlite_pragma(dbapi_conn, _):
    if DATABASE_URL.startswith("sqlite"):
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)


# ---------------------------------------------------------------------------
# Base + helpers
# ---------------------------------------------------------------------------

class Base(DeclarativeBase):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Target(Base):
    __tablename__ = "targets"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    url        = Column(String(2048), nullable=False, unique=True)
    label      = Column(String(512))                        # optional friendly name
    created_at = Column(DateTime, default=_now, nullable=False)

    scan_reports    = relationship("ScanReport",   back_populates="target", cascade="all, delete-orphan")
    finding_history = relationship("FindingHistory", back_populates="target", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {"id": self.id, "url": self.url, "label": self.label,
                "created_at": self.created_at.isoformat() if self.created_at else None}


class ScanReport(Base):
    __tablename__ = "scan_reports"

    id            = Column(String(64), primary_key=True)   # job_id / report_id (uuid4)
    target_id     = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    source        = Column(String(16), nullable=False, default="live")
                                                            # 'live' | 'mock' | 'imported'
    status        = Column(String(16), nullable=False, default="running")
                                                            # 'running' | 'done' | 'error'
    started_at    = Column(DateTime, default=_now, nullable=False)
    finished_at   = Column(DateTime)
    finding_count = Column(Integer, default=0)
    high_count    = Column(Integer, default=0)
    medium_count  = Column(Integer, default=0)
    low_count     = Column(Integer, default=0)
    info_count    = Column(Integer, default=0)
    risk_score    = Column(Float,   default=0.0)
    report_path   = Column(String(512))
    error_message = Column(Text)

    target   = relationship("Target",  back_populates="scan_reports")
    findings = relationship("Finding", back_populates="scan_report", cascade="all, delete-orphan")

    __table_args__ = (
        Index("idx_scan_reports_target", "target_id"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "target_id": self.target_id, "source": self.source,
            "status": self.status,
            "started_at":  self.started_at.isoformat()  if self.started_at  else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "finding_count": self.finding_count, "high_count": self.high_count,
            "medium_count": self.medium_count,   "low_count":  self.low_count,
            "info_count":   self.info_count,     "risk_score": self.risk_score,
            "report_path":  self.report_path,    "error_message": self.error_message,
        }


class Finding(Base):
    __tablename__ = "findings"

    id             = Column(Integer, primary_key=True, autoincrement=True)
    scan_report_id = Column(String(64), ForeignKey("scan_reports.id", ondelete="CASCADE"), nullable=False)
    alert_id       = Column(String(32))          # ZAP pluginId
    name           = Column(String(512), nullable=False)
    risk           = Column(String(16),  nullable=False)   # High | Medium | Low | Informational
    risk_score     = Column(Integer)
    confidence     = Column(String(32))
    owasp_id       = Column(String(16))          # e.g. "A05:2021"
    owasp_name     = Column(String(256))
    description    = Column(Text)
    url            = Column(Text)
    param          = Column(String(256))
    evidence       = Column(Text)
    solution       = Column(Text)
    reference      = Column(Text)
    cwe_id         = Column(String(16))
    wasc_id        = Column(String(16))
    dedup_key      = Column(String(512), nullable=False)   # pluginId-url-param

    scan_report = relationship("ScanReport", back_populates="findings")

    __table_args__ = (
        Index("idx_findings_scan_report", "scan_report_id"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "scan_report_id": self.scan_report_id,
            "alert_id": self.alert_id, "name": self.name, "risk": self.risk,
            "risk_score": self.risk_score, "confidence": self.confidence,
            "owasp_id": self.owasp_id, "owasp_name": self.owasp_name,
            "description": self.description, "url": self.url, "param": self.param,
            "evidence": self.evidence, "solution": self.solution,
            "reference": self.reference, "cwe_id": self.cwe_id,
            "wasc_id": self.wasc_id, "dedup_key": self.dedup_key,
        }


class FindingHistory(Base):
    __tablename__ = "finding_history"

    id                = Column(Integer, primary_key=True, autoincrement=True)
    target_id         = Column(Integer, ForeignKey("targets.id", ondelete="CASCADE"), nullable=False)
    dedup_key         = Column(String(512), nullable=False)
    name              = Column(String(512), nullable=False)
    risk              = Column(String(16),  nullable=False)
    first_seen_scan_id = Column(String(64), ForeignKey("scan_reports.id"), nullable=False)
    last_seen_scan_id  = Column(String(64), ForeignKey("scan_reports.id"), nullable=False)
    first_seen_at     = Column(DateTime, default=_now, nullable=False)
    last_seen_at      = Column(DateTime, default=_now, nullable=False)
    resolved_at       = Column(DateTime)                   # NULL = still open

    target = relationship("Target", back_populates="finding_history")

    __table_args__ = (
        UniqueConstraint("target_id", "dedup_key", name="uq_target_dedup"),
        Index("idx_finding_history_target", "target_id"),
    )

    def to_dict(self) -> dict:
        return {
            "id": self.id, "target_id": self.target_id, "dedup_key": self.dedup_key,
            "name": self.name, "risk": self.risk,
            "first_seen_scan_id": self.first_seen_scan_id,
            "last_seen_scan_id":  self.last_seen_scan_id,
            "first_seen_at":  self.first_seen_at.isoformat()  if self.first_seen_at  else None,
            "last_seen_at":   self.last_seen_at.isoformat()   if self.last_seen_at   else None,
            "resolved_at":    self.resolved_at.isoformat()    if self.resolved_at    else None,
        }


# ---------------------------------------------------------------------------
# DB init — called once at app startup
# ---------------------------------------------------------------------------

def init_db() -> None:
    """Creates all tables if they don't exist. Safe to call on every startup."""
    Base.metadata.create_all(bind=engine)


if __name__ == "__main__":
    init_db()
    db_path = DATABASE_URL.replace("sqlite:///", "")
    print(f"Database initialized: {DATABASE_URL}")
