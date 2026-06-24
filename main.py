#!/usr/bin/env python3
"""
main.py – VA Tool entry point
-----------------------------
Orchestrates the full scan → parse → report pipeline.

Quick start (demo mode, no live ZAP):
    python main.py --target http://testsite.local --mock

With live ZAP:
    python main.py --target http://staging.example.gov \
                   --zap-proxy http://127.0.0.1:8080  \
                   --api-key   YOUR_ZAP_API_KEY
"""

import argparse
import json
import logging
import sys
from pathlib import Path

import yaml

from scanner.zap_scanner import ZAPScanner, MockScanner, ZAP_AVAILABLE
from scanner.parser import AlertParser
from report.generator import ReportGenerator


def load_config(path: str = "config/settings.yaml") -> dict:
    cfg_path = Path(path)
    if cfg_path.exists():
        with cfg_path.open() as f:
            return yaml.safe_load(f) or {}
    return {}


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Web Application Vulnerability Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--target",     help="Target URL (overrides config)")
    p.add_argument("--zap-proxy",  default=None)
    p.add_argument("--api-key",    default=None)
    p.add_argument("--output-dir", default=None)
    p.add_argument("--config",     default="config/settings.yaml")
    p.add_argument("--mock",       action="store_true", help="Use demo scanner (no live ZAP)")
    p.add_argument("--pdf",        action="store_true", help="Also generate a PDF report")
    p.add_argument("--verbose",    action="store_true")
    return p


def main() -> int:
    args = build_arg_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s – %(message)s",
        handlers=[logging.StreamHandler(sys.stdout)],
    )
    logger = logging.getLogger("main")

    cfg = load_config(args.config)

    target = args.target or cfg.get("target", {}).get("url")
    if not target:
        logger.error("No target URL provided. Use --target or set target.url in settings.yaml")
        return 1

    use_mock = args.mock or cfg.get("demo_mode", False) or not ZAP_AVAILABLE
    zap_proxy = args.zap_proxy or cfg.get("zap", {}).get("proxy", "http://127.0.0.1:8080")
    api_key   = args.api_key   or cfg.get("zap", {}).get("api_key", "changeme")
    output_dir = args.output_dir or cfg.get("report", {}).get("output_dir", "output")

    # ── 1. Scan ─────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("VA Tool – starting assessment for: %s", target)
    logger.info("Mode: %s", "DEMO (mock scanner)" if use_mock else "LIVE (OWASP ZAP)")
    logger.info("=" * 60)

    if use_mock:
        scanner = MockScanner(target=target)
    else:
        scanner = ZAPScanner(target=target, zap_proxy=zap_proxy, api_key=api_key)

    raw_alerts = scanner.run()

    # Save raw alerts
    raw_path = Path(output_dir) / "raw_alerts.json"
    raw_path.parent.mkdir(parents=True, exist_ok=True)
    raw_path.write_text(json.dumps(raw_alerts, indent=2))
    logger.info("Raw alerts → %s", raw_path)

    # ── 2. Parse ─────────────────────────────────────────────────────────
    parser  = AlertParser(target=target)
    summary = parser.parse(raw_alerts)

    logger.info(
        "Findings: %d total  |  High: %d  Medium: %d  Low: %d  Info: %d",
        summary.total_alerts, summary.high, summary.medium,
        summary.low, summary.informational,
    )
    logger.info("Overall risk score: %s / 10", summary.risk_score)

    # ── 3. Report ─────────────────────────────────────────────────────────
    generator = ReportGenerator(output_dir=output_dir)
    html_path = generator.generate_html(summary)
    logger.info("HTML report → %s", html_path)

    if args.pdf or "pdf" in cfg.get("report", {}).get("formats", []):
        pdf_path = generator.generate_pdf(summary)
        if pdf_path:
            logger.info("PDF report → %s", pdf_path)

    logger.info("=" * 60)
    logger.info("Assessment complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
