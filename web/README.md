# VA Tool — Flask Web Interface

Adds a browser-based UI to the existing CLI vulnerability assessment tool.

## Directory layout

```
web/
├── app.py                   ← Flask application (single file)
├── requirements.txt         ← Flask dependency
├── reports/                 ← Auto-created; generated HTML reports stored here
└── templates/
    ├── index.html           ← Dashboard (scan form + live log + results)
    └── report.html          ← Report template (Jinja2, white-and-blue govt theme)
```

## Quick start

```bash
# 1. Install dependency
pip install -r web/requirements.txt

# 2. Run
cd web
python app.py

# 3. Open browser
open http://localhost:5000
```

## Usage

1. Enter the target URL in the input field (must start with `http://` or `https://`).
2. Select **Demo Mode** (no ZAP needed) or **Live ZAP Scan**.
3. Click **Start Scan** — progress logs stream in real time.
4. On completion, click **View Report** to open the report in a new tab,
   or **Download HTML** to save a local copy.

## Architecture

```
Browser                  Flask (app.py)
───────                  ─────────────
POST /scan           →   creates job, starts background thread
GET  /stream/{id}    ←   Server-Sent Events: streams log lines
GET  /report/{id}    →   serves the generated HTML report
GET  /download/{id}  →   downloads the HTML report as a file
```

The background thread (``run_mock_scan``) replicates what your existing
``MockScanner → AlertParser → ReportGenerator`` pipeline produces.
To connect the real modules, replace ``run_mock_scan`` with a call to
``scanner.zap_scanner`` and ``report.generator``.

## Connecting your existing code

Replace the ``run_mock_scan`` function in ``app.py`` with:

```python
from scanner.zap_scanner import MockScanner, ZAPScanner
from scanner.parser import AlertParser
from report.generator import ReportGenerator

def run_real_scan(job_id, target, log_q, use_mock=True):
    scanner = MockScanner(target) if use_mock else ZAPScanner(target, ...)
    raw = scanner.scan()
    parser = AlertParser(raw)
    alerts = parser.parse()
    gen = ReportGenerator(alerts, target)
    path = gen.render_html(output_dir=str(REPORTS_DIR), filename=job_id)
    ...
```

## Production notes

- Replace Flask's dev server with **Gunicorn**: `gunicorn -w 1 app:app`
  (use a single worker so the in-memory job store is shared).
- For multi-worker deployments, move ``JOBS`` to Redis.
- Add authentication before exposing this to a network.
