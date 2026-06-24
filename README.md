# VA Tool — Web Application Vulnerability Assessment Tool

> Internship project for a Government Cybersecurity Division  
> Built with OWASP ZAP · Python 3.11+ · Jinja2

---

## Overview

VA Tool automates the discovery and reporting of web application vulnerabilities across government web portals. It integrates with OWASP ZAP to spider and actively scan a target, maps findings to the **OWASP Top 10 (2021)**, and produces a professional **HTML/PDF report** ready for submission to management.

```
┌─────────────┐     raw alerts      ┌─────────────┐    structured data    ┌──────────────┐
│  ZAP Scanner │ ──────────────────► │    Parser    │ ───────────────────► │   Report     │
│  (or Mock)   │                     │ OWASP mapper │                       │  Generator   │
└─────────────┘                      └─────────────┘                        └──────────────┘
                                                                                   │
                                                                          HTML + PDF report
```

---

## Project Structure

```
vuln-assessment-tool/
├── scanner/
│   ├── __init__.py
│   ├── zap_scanner.py      # ZAP API integration + MockScanner for demo
│   └── parser.py           # Alert parser, OWASP mapper, risk scorer
├── report/
│   ├── __init__.py
│   ├── generator.py        # HTML/PDF report renderer
│   └── templates/
│       └── report.html     # Jinja2 report template (white & blue theme)
├── config/
│   └── settings.yaml       # Target URL, ZAP connection, output options
├── docs/
│   └── rules_of_engagement.md  # RoE template (sign before scanning!)
├── tests/
│   └── test_parser.py      # Unit tests (pytest)
├── output/                 # Generated reports land here (git-ignored)
├── main.py                 # CLI entry point
└── requirements.txt
```

---

## Quick Start

### 1. Install dependencies

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run in demo mode (no ZAP required)

```bash
python main.py --target http://testsite.local --mock
```

Open `output/report_*.html` in your browser to see the report.

### 3. Run against a real target (requires OWASP ZAP daemon)

```bash
# Start ZAP daemon first:
# zap.sh -daemon -port 8080 -config api.key=changeme

python main.py \
  --target    http://staging.example.gov \
  --zap-proxy http://127.0.0.1:8080     \
  --api-key   changeme                  \
  --pdf
```

---

## Configuration

Edit `config/settings.yaml`:

```yaml
target:
  url: "http://testsite.local"

zap:
  proxy:   "http://127.0.0.1:8080"
  api_key: "changeme"

report:
  output_dir: "output"
  formats: [html, pdf]

demo_mode: true   # set false for live ZAP
```

---

## Running Tests

```bash
pytest tests/ -v
```

---

## ⚠️ Responsible Use

- **Always obtain written authorisation** before scanning any system.
- Use the Rules of Engagement template in `docs/rules_of_engagement.md`.
- **Never scan production systems** without explicit approval from the system owner and CISO.
- Test against `DVWA` or `OWASP Juice Shop` during development.

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Scanner | OWASP ZAP (via `python-owasp-zap-v2.4`) |
| Parser | Python 3.11 |
| Templating | Jinja2 |
| PDF | WeasyPrint / wkhtmltopdf |
| Config | PyYAML |
| Tests | pytest |

---

## Author

Cybersecurity Intern — Government Cybersecurity Division  
Supervised by: [Supervisor Name]  
Assessment Period: [Start] – [End]
