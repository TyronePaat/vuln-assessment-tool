"""
parser.py
---------
Parses raw ZAP alert JSON, deduplicates, maps to OWASP Top 10 (2021),
assigns CVSS-lite severity scores, and produces a clean structured payload
ready for the report generator.
"""

import json
import logging
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OWASP Top 10 (2021) mapping – keyed by ZAP pluginId / alertRef
# ---------------------------------------------------------------------------
OWASP_MAP: dict[str, dict] = {
    # A01 – Broken Access Control
    "10094": {"id": "A01:2021", "name": "Broken Access Control"},
    "10095": {"id": "A01:2021", "name": "Broken Access Control"},
    "40018": {"id": "A01:2021", "name": "Broken Access Control"},
    # A02 – Cryptographic Failures
    "10035": {"id": "A02:2021", "name": "Cryptographic Failures"},
    "10036": {"id": "A02:2021", "name": "Cryptographic Failures"},
    "10038": {"id": "A02:2021", "name": "Cryptographic Failures"},
    "10092": {"id": "A02:2021", "name": "Cryptographic Failures"},
    # A03 – Injection
    "40012": {"id": "A03:2021", "name": "Injection"},
    "40014": {"id": "A03:2021", "name": "Injection"},
    "40018": {"id": "A03:2021", "name": "Injection"},
    "40019": {"id": "A03:2021", "name": "Injection"},
    "40020": {"id": "A03:2021", "name": "Injection"},
    "90019": {"id": "A03:2021", "name": "Injection"},
    # A04 – Insecure Design (generic / no direct pluginId mapping)
    # A05 – Security Misconfiguration
    "10016": {"id": "A05:2021", "name": "Security Misconfiguration"},
    "10021": {"id": "A05:2021", "name": "Security Misconfiguration"},
    "10037": {"id": "A05:2021", "name": "Security Misconfiguration"},
    "10096": {"id": "A05:2021", "name": "Security Misconfiguration"},
    "90001": {"id": "A05:2021", "name": "Security Misconfiguration"},
    # A06 – Vulnerable and Outdated Components
    "10005": {"id": "A06:2021", "name": "Vulnerable and Outdated Components"},
    # A07 – Identification and Authentication Failures
    "10202": {"id": "A07:2021", "name": "Identification and Authentication Failures"},
    "10010": {"id": "A07:2021", "name": "Identification and Authentication Failures"},
    "10011": {"id": "A07:2021", "name": "Identification and Authentication Failures"},
    "10012": {"id": "A07:2021", "name": "Identification and Authentication Failures"},
    # A08 – Software and Data Integrity Failures
    "90022": {"id": "A08:2021", "name": "Software and Data Integrity Failures"},
    # A09 – Security Logging and Monitoring Failures (no direct pluginId)
    # A10 – Server-Side Request Forgery
    "40046": {"id": "A10:2021", "name": "Server-Side Request Forgery (SSRF)"},
}

DEFAULT_OWASP = {"id": "A05:2021", "name": "Security Misconfiguration"}

# Risk label → numeric score (for sorting and risk meter)
RISK_SCORE: dict[str, int] = {
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
}

RISK_COLOR: dict[str, str] = {
    "High": "#DC2626",
    "Medium": "#D97706",
    "Low": "#2563EB",
    "Informational": "#6B7280",
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ParsedAlert:
    alert_id: str
    name: str
    risk: str
    risk_score: int
    risk_color: str
    confidence: str
    owasp_id: str
    owasp_name: str
    description: str
    url: str
    param: str
    evidence: str
    solution: str
    reference: str
    cwe_id: str
    wasc_id: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanSummary:
    target: str
    total_alerts: int
    high: int
    medium: int
    low: int
    informational: int
    risk_score: float          # weighted overall risk 0–10
    owasp_breakdown: dict = field(default_factory=dict)
    alerts: list[ParsedAlert] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class AlertParser:
    """Parses a list of raw ZAP alert dicts into a structured ScanSummary."""

    def __init__(self, target: str) -> None:
        self.target = target

    def parse(self, raw_alerts: list[dict]) -> ScanSummary:
        seen: set[str] = set()
        parsed: list[ParsedAlert] = []

        for alert in raw_alerts:
            key = self._dedup_key(alert)
            if key in seen:
                continue
            seen.add(key)
            parsed.append(self._parse_one(alert))

        parsed.sort(key=lambda a: a.risk_score, reverse=True)

        counts = self._count_by_risk(parsed)
        owasp_breakdown = self._owasp_breakdown(parsed)
        risk_score = self._compute_risk_score(counts)

        return ScanSummary(
            target=self.target,
            total_alerts=len(parsed),
            high=counts["High"],
            medium=counts["Medium"],
            low=counts["Low"],
            informational=counts["Informational"],
            risk_score=risk_score,
            owasp_breakdown=owasp_breakdown,
            alerts=parsed,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _parse_one(self, alert: dict) -> ParsedAlert:
        plugin_id = str(alert.get("pluginId") or alert.get("alertRef") or "")
        owasp = OWASP_MAP.get(plugin_id, DEFAULT_OWASP)
        risk = alert.get("risk", "Informational")

        return ParsedAlert(
            alert_id=plugin_id,
            name=alert.get("name", "Unknown"),
            risk=risk,
            risk_score=RISK_SCORE.get(risk, 1),
            risk_color=RISK_COLOR.get(risk, "#6B7280"),
            confidence=alert.get("confidence", "Unknown"),
            owasp_id=owasp["id"],
            owasp_name=owasp["name"],
            description=alert.get("description", ""),
            url=alert.get("url", ""),
            param=alert.get("param", ""),
            evidence=alert.get("evidence", ""),
            solution=alert.get("solution", ""),
            reference=alert.get("reference", ""),
            cwe_id=alert.get("cweid", ""),
            wasc_id=alert.get("wascid", ""),
        )

    @staticmethod
    def _dedup_key(alert: dict) -> str:
        return f"{alert.get('pluginId','')}-{alert.get('url','')}-{alert.get('param','')}"

    @staticmethod
    def _count_by_risk(alerts: list[ParsedAlert]) -> dict:
        counts = {"High": 0, "Medium": 0, "Low": 0, "Informational": 0}
        for a in alerts:
            counts[a.risk] = counts.get(a.risk, 0) + 1
        return counts

    @staticmethod
    def _owasp_breakdown(alerts: list[ParsedAlert]) -> dict:
        breakdown: dict[str, int] = {}
        for a in alerts:
            label = f"{a.owasp_id} – {a.owasp_name}"
            breakdown[label] = breakdown.get(label, 0) + 1
        return breakdown

    @staticmethod
    def _compute_risk_score(counts: dict) -> float:
        """Simplified CVSS-like weighted score on a 0–10 scale."""
        raw = counts["High"] * 4 + counts["Medium"] * 2 + counts["Low"] * 0.5
        return min(round(raw, 1), 10.0)


# ---------------------------------------------------------------------------
# CLI / utility
# ---------------------------------------------------------------------------

def parse_from_file(json_path: str, target: str) -> ScanSummary:
    raw = json.loads(Path(json_path).read_text())
    return AlertParser(target=target).parse(raw)


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    if len(sys.argv) < 3:
        print("Usage: python parser.py <raw_alerts.json> <target_url>")
        sys.exit(1)

    summary = parse_from_file(sys.argv[1], sys.argv[2])
    print(json.dumps(summary.to_dict(), indent=2, default=str))
