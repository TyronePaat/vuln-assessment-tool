"""
scripts/seed_dummy_data.py
---------------------------
Mengisi database dengan data dummy untuk testing dashboard, riwayat target,
dan fitur compare secara manual di browser (bukan lewat pytest).

Membuat 4 target dengan pola berbeda:
  1. https://dummy-satu.sulutprov.go.id  -> tren MEMBAIK (5 scan, risk turun)
  2. https://dummy-dua.sulutprov.go.id   -> tren MEMBURUK (4 scan, risk naik)
  3. https://dummy-tiga.sulutprov.go.id  -> 1 scan gagal + 1 scan sukses
     (untuk tes chart tersembunyi saat done-scan < 2)
  4. https://dummy-empat.sulutprov.go.id -> 1 scan saja (belum ada tren)

Semua data dibuat lewat db/repository.py (bukan insert manual ke tabel),
supaya bentuknya sama persis dengan yang dihasilkan alur scan asli, termasuk
finding_history untuk daftar status temuan (open/resolved).

Cara pakai:
    cd vuln-assessment-tool
    python scripts/seed_dummy_data.py

Lalu jalankan app.py dan buka:
    http://127.0.0.1:5000/dashboard
"""

import sys
import uuid
from pathlib import Path
from datetime import datetime, timedelta, timezone

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))

from db.models import init_db, SessionLocal, ScanReport  # noqa: E402
from db import repository as repo                          # noqa: E402
from scanner.parser import ScanSummary, ParsedAlert         # noqa: E402


def _alert(name, risk, url, param="q", alert_id="40012", owasp_id="A03:2021"):
    scores = {"High": 8, "Medium": 5, "Low": 2, "Informational": 0}
    return ParsedAlert(
        alert_id=alert_id,
        name=name,
        risk=risk,
        risk_score=scores.get(risk, 0),
        risk_color={"High": "red", "Medium": "orange", "Low": "yellow", "Informational": "blue"}.get(risk, "blue"),
        confidence="Medium",
        owasp_id=owasp_id,
        owasp_name="Injection",
        description=f"Contoh temuan dummy: {name}",
        url=url,
        param=param,
        evidence="<script>dummy</script>",
        solution="Perbaiki validasi input.",
        reference="https://owasp.org/",
        cwe_id="79",
        wasc_id="8",
    )


def _summary(target_url, alerts):
    high = sum(1 for a in alerts if a.risk == "High")
    medium = sum(1 for a in alerts if a.risk == "Medium")
    low = sum(1 for a in alerts if a.risk == "Low")
    info = sum(1 for a in alerts if a.risk == "Informational")
    risk_score = round(min(10.0, high * 2.2 + medium * 1.1 + low * 0.4), 2)
    return ScanSummary(
        target=target_url,
        total_alerts=len(alerts),
        high=high, medium=medium, low=low, informational=info,
        risk_score=risk_score,
        owasp_breakdown={},
        alerts=alerts,
    )


def _insert_scan(target_url, days_ago, alerts, source="mock"):
    """Buat 1 scan 'done' dengan started_at di masa lalu (days_ago hari lalu)."""
    scan_id = str(uuid.uuid4())
    repo.create_scan_report(scan_id, target_url, source=source)

    # geser started_at mundur supaya urutan waktunya realistis
    session = SessionLocal()
    try:
        report = session.query(ScanReport).filter_by(id=scan_id).first()
        report.started_at = datetime.now(timezone.utc) - timedelta(days=days_ago)
        session.commit()
    finally:
        session.close()

    summary = _summary(target_url, alerts)
    repo.complete_scan_report(scan_id, summary, report_path=f"web/reports/{scan_id}.html")
    return scan_id


def _insert_failed_scan(target_url, days_ago):
    scan_id = str(uuid.uuid4())
    repo.create_scan_report(scan_id, target_url, source="live")
    session = SessionLocal()
    try:
        report = session.query(ScanReport).filter_by(id=scan_id).first()
        report.started_at = datetime.now(timezone.utc) - timedelta(days=days_ago)
        session.commit()
    finally:
        session.close()
    repo.fail_scan_report(scan_id, "Connection timeout ke target.")
    return scan_id


def seed():
    init_db()

    # ── Target 1: tren MEMBAIK — 5 scan, risk & jumlah temuan makin turun ──
    url1 = "https://dummy-satu.sulutprov.go.id"
    _insert_scan(url1, days_ago=40, alerts=[
        _alert("Cross Site Scripting (Reflected)", "High", url1 + "/search", alert_id="40012"),
        _alert("SQL Injection", "High", url1 + "/login", param="user", alert_id="40018"),
        _alert("Absence of Anti-CSRF Tokens", "Medium", url1 + "/form", alert_id="10202"),
        _alert("X-Content-Type-Options Missing", "Low", url1 + "/", alert_id="10021"),
    ])
    _insert_scan(url1, days_ago=30, alerts=[
        _alert("Cross Site Scripting (Reflected)", "High", url1 + "/search", alert_id="40012"),
        _alert("Absence of Anti-CSRF Tokens", "Medium", url1 + "/form", alert_id="10202"),
        _alert("X-Content-Type-Options Missing", "Low", url1 + "/", alert_id="10021"),
    ])
    _insert_scan(url1, days_ago=20, alerts=[
        _alert("Absence of Anti-CSRF Tokens", "Medium", url1 + "/form", alert_id="10202"),
        _alert("X-Content-Type-Options Missing", "Low", url1 + "/", alert_id="10021"),
    ])
    _insert_scan(url1, days_ago=10, alerts=[
        _alert("X-Content-Type-Options Missing", "Low", url1 + "/", alert_id="10021"),
    ])
    _insert_scan(url1, days_ago=1, alerts=[])
    print(f"[OK] {url1} -> 5 scan (done), tren membaik")

    # ── Target 2: tren MEMBURUK — 4 scan, risk & jumlah temuan makin naik ──
    url2 = "https://dummy-dua.sulutprov.go.id"
    _insert_scan(url2, days_ago=25, alerts=[
        _alert("X-Content-Type-Options Missing", "Low", url2 + "/", alert_id="10021"),
    ])
    _insert_scan(url2, days_ago=18, alerts=[
        _alert("Absence of Anti-CSRF Tokens", "Medium", url2 + "/form", alert_id="10202"),
        _alert("X-Content-Type-Options Missing", "Low", url2 + "/", alert_id="10021"),
    ])
    _insert_scan(url2, days_ago=9, alerts=[
        _alert("SQL Injection", "High", url2 + "/login", param="user", alert_id="40018"),
        _alert("Absence of Anti-CSRF Tokens", "Medium", url2 + "/form", alert_id="10202"),
        _alert("X-Content-Type-Options Missing", "Low", url2 + "/", alert_id="10021"),
    ])
    _insert_scan(url2, days_ago=1, alerts=[
        _alert("SQL Injection", "High", url2 + "/login", param="user", alert_id="40018"),
        _alert("Cross Site Scripting (Reflected)", "High", url2 + "/search", alert_id="40012"),
        _alert("Absence of Anti-CSRF Tokens", "Medium", url2 + "/form", alert_id="10202"),
        _alert("X-Content-Type-Options Missing", "Low", url2 + "/", alert_id="10021"),
    ])
    print(f"[OK] {url2} -> 4 scan (done), tren memburuk")

    # ── Target 3: 1 scan gagal + 1 scan sukses -> chart harus tersembunyi ──
    url3 = "https://dummy-tiga.sulutprov.go.id"
    _insert_failed_scan(url3, days_ago=15)
    _insert_scan(url3, days_ago=2, alerts=[
        _alert("Absence of Anti-CSRF Tokens", "Medium", url3 + "/form", alert_id="10202"),
    ])
    print(f"[OK] {url3} -> 1 scan error + 1 scan done (chart tetap tersembunyi, hanya 1 done)")

    # ── Target 4: 1 scan saja -> "Data Belum Cukup" ──
    url4 = "https://dummy-empat.sulutprov.go.id"
    _insert_scan(url4, days_ago=3, alerts=[
        _alert("Cross Site Scripting (Reflected)", "High", url4 + "/search", alert_id="40012"),
        _alert("SQL Injection", "High", url4 + "/login", param="user", alert_id="40018"),
    ])
    print(f"[OK] {url4} -> 1 scan (done), status 'Data Belum Cukup'")

    print("\nSelesai. Jalankan: python web/app.py")
    print("Lalu buka: http://127.0.0.1:5000/dashboard")


if __name__ == "__main__":
    seed()
