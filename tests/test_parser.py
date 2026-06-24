"""
tests/test_parser.py
--------------------
Unit tests for the alert parser and OWASP categorisation.

Run with:
    pytest tests/
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from scanner.parser import AlertParser, RISK_SCORE


SAMPLE_ALERTS = [
    {
        "alertRef": "40012",
        "name": "Cross Site Scripting (Reflected)",
        "risk": "High",
        "confidence": "Medium",
        "description": "XSS vulnerability",
        "url": "http://testsite.local/search?q=<script>",
        "solution": "Sanitise output.",
        "reference": "https://owasp.org/",
        "cweid": "79",
        "wascid": "8",
        "pluginId": "40012",
        "param": "q",
        "evidence": "<script>alert(1)</script>",
    },
    {
        "alertRef": "10202",
        "name": "Absence of Anti-CSRF Tokens",
        "risk": "Medium",
        "confidence": "Low",
        "description": "CSRF missing",
        "url": "http://testsite.local/login",
        "solution": "Add CSRF tokens.",
        "reference": "https://owasp.org/",
        "cweid": "352",
        "wascid": "9",
        "pluginId": "10202",
        "param": "",
        "evidence": "",
    },
    {
        "alertRef": "10021",
        "name": "X-Content-Type-Options Header Missing",
        "risk": "Low",
        "confidence": "Medium",
        "description": "Missing header",
        "url": "http://testsite.local/",
        "solution": "Set the header.",
        "reference": "https://owasp.org/",
        "cweid": "693",
        "wascid": "15",
        "pluginId": "10021",
        "param": "X-Content-Type-Options",
        "evidence": "",
    },
    # Duplicate of first alert – should be deduped
    {
        "alertRef": "40012",
        "name": "Cross Site Scripting (Reflected)",
        "risk": "High",
        "confidence": "Medium",
        "description": "XSS vulnerability",
        "url": "http://testsite.local/search?q=<script>",
        "solution": "Sanitise output.",
        "reference": "https://owasp.org/",
        "cweid": "79",
        "wascid": "8",
        "pluginId": "40012",
        "param": "q",
        "evidence": "<script>alert(1)</script>",
    },
]


class TestAlertParser:
    def setup_method(self):
        self.parser = AlertParser(target="http://testsite.local")
        self.summary = self.parser.parse(SAMPLE_ALERTS)

    def test_deduplication(self):
        """Duplicate alerts (same pluginId + url + param) should be removed."""
        assert self.summary.total_alerts == 3

    def test_risk_counts(self):
        assert self.summary.high == 1
        assert self.summary.medium == 1
        assert self.summary.low == 1
        assert self.summary.informational == 0

    def test_sorting_by_risk(self):
        """Alerts should be sorted High → Medium → Low → Info."""
        risks = [a.risk for a in self.summary.alerts]
        expected_order = ["High", "Medium", "Low"]
        assert risks == expected_order

    def test_owasp_mapping_xss(self):
        """XSS (pluginId 40012) should map to A03:2021 – Injection."""
        xss = next(a for a in self.summary.alerts if a.alert_id == "40012")
        assert xss.owasp_id == "A03:2021"
        assert "Injection" in xss.owasp_name

    def test_owasp_mapping_csrf(self):
        """CSRF (pluginId 10202) should map to A07:2021."""
        csrf = next(a for a in self.summary.alerts if a.alert_id == "10202")
        assert csrf is not None
        assert "A07" in csrf.owasp_id

    def test_risk_score_positive(self):
        """Risk score should be > 0 when High findings exist."""
        assert self.summary.risk_score > 0

    def test_risk_score_max_10(self):
        """Risk score should never exceed 10."""
        assert self.summary.risk_score <= 10

    def test_owasp_breakdown_populated(self):
        assert len(self.summary.owasp_breakdown) > 0

    def test_to_dict_serialisable(self):
        """ScanSummary.to_dict() should be JSON-serialisable."""
        import json
        d = self.summary.to_dict()
        dumped = json.dumps(d)
        assert len(dumped) > 0


class TestAlertParserEmpty:
    def test_empty_input(self):
        parser = AlertParser(target="http://empty.local")
        summary = parser.parse([])
        assert summary.total_alerts == 0
        assert summary.risk_score == 0.0
        assert summary.high == 0
