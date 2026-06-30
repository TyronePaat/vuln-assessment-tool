"""
VA Tool — Flask Web Interface
Wraps the existing scanner/parser/report modules with a browser UI.
"""

import uuid
import queue
import threading
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from flask import (
    Flask, render_template, request, jsonify,
    Response, send_from_directory, abort
)

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).parent
REPORTS_DIR = BASE_DIR / "reports"
REPORTS_DIR.mkdir(exist_ok=True)

# Allow imports from the repo root (vuln-assessment-tool/)
sys.path.insert(0, str(BASE_DIR.parent))

from scanner.zap_scanner import MockScanner, ZAPScanner  # noqa: E402
from scanner.parser import AlertParser                    # noqa: E402
from report.generator import ReportGenerator             # noqa: E402

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "va-tool-dev-secret")

# In-memory job store  { job_id: { status, log_queue, result } }
JOBS: dict[str, dict] = {}
JOBS_LOCK = threading.Lock()

# ---------------------------------------------------------------------------
# Scanner pipeline
# ---------------------------------------------------------------------------

def run_mock_scan(job_id: str, target: str, log_q: queue.Queue, use_zap: bool = False,
                  zap_proxy: str = "http://127.0.0.1:8080", api_key: str = ""):
    """Run the real scanner pipeline and stream log lines to the browser."""
    try:
        # ── 1. Scan ──────────────────────────────────────────────────────────
        log_q.put("[INFO]  Initialising scanner…")

        if use_zap:
            log_q.put(f"[INFO]  Connecting to ZAP proxy at {zap_proxy}…")
            scanner = ZAPScanner(target, zap_proxy=zap_proxy, api_key=api_key)
        else:
            log_q.put("[INFO]  Running in demo mode (MockScanner)…")
            scanner = MockScanner(target)

        log_q.put("[INFO]  Spider started — crawling URLs")
        raw_alerts = scanner.run()
        log_q.put(f"[INFO]  Scan complete — {len(raw_alerts)} raw alerts found")

        # ── 2. Parse ─────────────────────────────────────────────────────────
        log_q.put("[INFO]  Parsing and deduplicating alerts…")
        parser = AlertParser(target=target)
        summary = parser.parse(raw_alerts)
        log_q.put("[INFO]  Mapping findings to OWASP Top 10 (2021)…")
        log_q.put("[INFO]  Calculating CVSS-lite risk scores…")

        # ── 3. Report ────────────────────────────────────────────────────────
        log_q.put("[INFO]  Generating HTML report…")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # ScanSummary.alerts is a list of ParsedAlert dataclasses — convert to dicts
        alert_dicts = [a.to_dict() for a in summary.alerts]

        risk_counts = {
            "High":          summary.high,
            "Medium":        summary.medium,
            "Low":           summary.low,
            "Informational": summary.informational,
        }

        report_path = REPORTS_DIR / f"{job_id}.html"
        with app.app_context():
            html = render_template(
                "report.html",
                target=target,
                timestamp=now,
                alerts=alert_dicts,
                risk_counts=risk_counts,
                total=len(alert_dicts),
            )
        report_path.write_text(html, encoding="utf-8")

        # ── 4. Signal done ───────────────────────────────────────────────────
        with JOBS_LOCK:
            JOBS[job_id]["status"]        = "done"
            JOBS[job_id]["report_id"]     = job_id
            JOBS[job_id]["finding_count"] = len(alert_dicts)
            JOBS[job_id]["risk_counts"]   = risk_counts

        log_q.put(f"[DONE]  Scan complete — {len(alert_dicts)} findings identified")
        log_q.put(f"__DONE__{job_id}")

    except Exception as exc:
        log_q.put(f"[ERROR] {exc}")
        log_q.put("__ERROR__")
        with JOBS_LOCK:
            JOBS[job_id]["status"] = "error"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def start_scan():
    data = request.get_json(silent=True) or {}
    target   = (data.get("target")    or "").strip()
    mode     = (data.get("mode")      or "mock").strip()
    zap_proxy = (data.get("zap_proxy") or "http://127.0.0.1:8080").strip()
    api_key  = (data.get("api_key")   or "changeme").strip()

    if not target:
        return jsonify({"error": "Target URL is required."}), 400
    if not target.startswith(("http://", "https://")):
        return jsonify({"error": "Target must start with http:// or https://"}), 400

    job_id = str(uuid.uuid4())
    log_q: queue.Queue = queue.Queue()
    use_zap = (mode == "zap")

    with JOBS_LOCK:
        JOBS[job_id] = {
            "status": "running",
            "target": target,
            "log_queue": log_q,
            "report_id": None,
            "finding_count": 0,
        }

    t = threading.Thread(
        target=run_mock_scan,
        args=(job_id, target, log_q, use_zap, zap_proxy, api_key),
        daemon=True,
    )
    t.start()

    return jsonify({"job_id": job_id})


@app.route("/stream/<job_id>")
def stream(job_id):
    """Server-Sent Events endpoint — streams log lines to the browser."""
    with JOBS_LOCK:
        job = JOBS.get(job_id)
    if not job:
        abort(404)

    log_q = job["log_queue"]
    _job_id = job_id  # capture explicitly for Pylance / closure safety

    def generate():
        while True:
            try:
                line = log_q.get(timeout=30)
            except queue.Empty:
                yield ": keepalive\n\n"
                continue

            if line.startswith("__DONE__"):
                report_id = line.replace("__DONE__", "")
                with JOBS_LOCK:
                    fc = JOBS[_job_id].get("finding_count", 0)
                    rc = JOBS[_job_id].get("risk_counts", {})
                payload = json.dumps({
                    "type": "done",
                    "report_id": report_id,
                    "finding_count": fc,
                    "risk_counts": rc,
                })
                yield f"data: {payload}\n\n"
                break
            elif line == "__ERROR__":
                yield 'data: {"type":"error"}\n\n'
                break
            else:
                payload = json.dumps({"type": "log", "msg": line})
                yield f"data: {payload}\n\n"

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/report/<report_id>")
def view_report(report_id):
    safe_id = "".join(c for c in report_id if c.isalnum() or c == "-")
    path = REPORTS_DIR / f"{safe_id}.html"
    if not path.exists():
        abort(404)
    return path.read_text(encoding="utf-8")


@app.route("/download/<report_id>")
def download_report(report_id):
    safe_id = "".join(c for c in report_id if c.isalnum() or c == "-")
    filename = f"{safe_id}.html"
    if not (REPORTS_DIR / filename).exists():
        abort(404)
    return send_from_directory(REPORTS_DIR, filename,
                               as_attachment=True,
                               download_name="va_report.html")


if __name__ == "__main__":
    app.run(debug=True, port=5000, threaded=True)
