"""
zap_scanner.py
--------------
Integrates with OWASP ZAP via its REST API to spider and actively
scan a target web application.

Usage (standalone):
    python zap_scanner.py --target http://testsite.local --output output/raw_alerts.json
"""

import argparse
import json
import logging
import time
from pathlib import Path
from typing import Optional

# pip install python-owasp-zap-v2.4
try:
    from zapv2 import ZAPv2
    ZAP_AVAILABLE = True
except ImportError:
    ZAP_AVAILABLE = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Default ZAP daemon settings (adjust to match your ZAP instance)
# ---------------------------------------------------------------------------
ZAP_PROXY = "http://127.0.0.1:8080"
ZAP_API_KEY = "changeme"          # set in ZAP → Tools → Options → API


class ZAPScanner:
    """Wraps OWASP ZAP to spider and actively scan a target URL."""

    def __init__(
        self,
        target: str,
        zap_proxy: str = ZAP_PROXY,
        api_key: str = ZAP_API_KEY,
        ajax_spider: bool = False,
    ) -> None:
        self.target = target.rstrip("/")
        self.api_key = api_key
        self.ajax_spider = ajax_spider

        if not ZAP_AVAILABLE:
            raise ImportError(
                "python-owasp-zap-v2.4 is not installed.\n"
                "Run: pip install python-owasp-zap-v2.4"
            )

        proxies = {"http": zap_proxy, "https": zap_proxy}
        self.zap = ZAPv2(apikey=api_key, proxies=proxies)
        logger.info("Connected to ZAP at %s", zap_proxy)

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def run(self) -> list[dict]:
        """Execute spider + active scan and return raw alert list."""
        self._spider()
        self._active_scan()
        alerts = self._collect_alerts()
        logger.info("Scan complete – %d alerts found", len(alerts))
        return alerts

    # ------------------------------------------------------------------
    # Internal steps
    # ------------------------------------------------------------------

    def _spider(self) -> None:
        logger.info("Starting spider on %s …", self.target)
        scan_id = self.zap.spider.scan(self.target, apikey=self.api_key)
        self._wait_for_completion(
            lambda: int(self.zap.spider.status(scan_id)),
            label="Spider",
        )
        logger.info("Spider finished. URLs found: %s", self.zap.spider.results(scan_id))

    def _active_scan(self) -> None:
        logger.info("Starting active scan on %s …", self.target)
        scan_id = self.zap.ascan.scan(self.target, apikey=self.api_key)
        self._wait_for_completion(
            lambda: int(self.zap.ascan.status(scan_id)),
            label="Active scan",
            interval=10,
        )

    def _collect_alerts(self) -> list[dict]:
        raw = self.zap.core.alerts(baseurl=self.target)
        return raw if isinstance(raw, list) else []

    @staticmethod
    def _wait_for_completion(
        progress_fn,
        label: str = "Task",
        interval: int = 5,
    ) -> None:
        while True:
            pct = progress_fn()
            logger.info("%s progress: %d%%", label, pct)
            if pct >= 100:
                break
            time.sleep(interval)


# ---------------------------------------------------------------------------
# Mock scanner – used when ZAP is unavailable (demo / CI mode)
# ---------------------------------------------------------------------------

class MockScanner:
    """Returns realistic-looking sample alerts without a live ZAP instance."""

    SAMPLE_ALERTS = [
        {
            "alertRef": "40012",
            "name": "Cross Site Scripting (Reflected)",
            "risk": "High",
            "confidence": "Medium",
            "description": (
                "Cross-site Scripting (XSS) is an attack technique that involves "
                "echoing attacker-supplied code into a user's browser instance."
            ),
            "url": "http://testsite.local/search?q=<script>alert(1)</script>",
            "solution": (
                "Phase: Architecture and Design\nUse a vetted library or framework "
                "that does not allow this weakness to occur, or provides constructs "
                "that make this weakness easier to avoid."
            ),
            "reference": "https://owasp.org/www-community/attacks/xss/",
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
            "description": (
                "No Anti-CSRF tokens were found in a HTML submission form. A "
                "cross-site request forgery is an attack that involves forcing a "
                "victim to send an HTTP request to a target destination."
            ),
            "url": "http://testsite.local/login",
            "solution": (
                "Phase: Architecture and Design\nUse a vetted library or framework "
                "that does not allow this weakness to occur."
            ),
            "reference": "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
            "cweid": "352",
            "wascid": "9",
            "pluginId": "10202",
            "param": "",
            "evidence": "<form method='POST' action='/login'>",
        },
        {
            "alertRef": "10010",
            "name": "Cookie No HttpOnly Flag",
            "risk": "Medium",
            "confidence": "Medium",
            "description": (
                "A cookie has been set without the HttpOnly flag, which means that "
                "the cookie can be accessed by JavaScript."
            ),
            "url": "http://testsite.local/",
            "solution": "Ensure that the HttpOnly flag is set for all cookies.",
            "reference": "https://owasp.org/www-community/HttpOnly",
            "cweid": "16",
            "wascid": "13",
            "pluginId": "10010",
            "param": "SESSIONID",
            "evidence": "Set-Cookie: SESSIONID=abc123",
        },
        {
            "alertRef": "10016",
            "name": "Web Browser XSS Protection Not Enabled",
            "risk": "Low",
            "confidence": "Medium",
            "description": (
                "Web Browser XSS Protection is not enabled, or is disabled by the "
                "configuration of the 'X-XSS-Protection' HTTP response header on "
                "the web server."
            ),
            "url": "http://testsite.local/",
            "solution": (
                "Ensure that the web browser's XSS filter is enabled, by setting "
                "the X-XSS-Protection HTTP response header to '1'."
            ),
            "reference": "https://owasp.org/www-project-secure-headers/",
            "cweid": "933",
            "wascid": "14",
            "pluginId": "10016",
            "param": "X-XSS-Protection",
            "evidence": "",
        },
        {
            "alertRef": "10021",
            "name": "X-Content-Type-Options Header Missing",
            "risk": "Low",
            "confidence": "Medium",
            "description": (
                "The Anti-MIME-Sniffing header X-Content-Type-Options was not set "
                "to 'nosniff'."
            ),
            "url": "http://testsite.local/about",
            "solution": "Ensure that the application/web server sets the Content-Type header appropriately.",
            "reference": "https://owasp.org/www-project-secure-headers/",
            "cweid": "693",
            "wascid": "15",
            "pluginId": "10021",
            "param": "X-Content-Type-Options",
            "evidence": "",
        },
        {
            "alertRef": "10035",
            "name": "Strict-Transport-Security Header Not Set",
            "risk": "Low",
            "confidence": "High",
            "description": (
                "HTTP Strict Transport Security (HSTS) is a web security policy "
                "mechanism whereby a web server declares that complying user agents "
                "should only interact with it using secure HTTPS connections."
            ),
            "url": "http://testsite.local/",
            "solution": "Ensure that your web server, application server, or application framework enforces the use of HSTS.",
            "reference": "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html",
            "cweid": "319",
            "wascid": "15",
            "pluginId": "10035",
            "param": "Strict-Transport-Security",
            "evidence": "",
        },
        {
            "alertRef": "10096",
            "name": "Timestamp Disclosure - Unix",
            "risk": "Informational",
            "confidence": "Low",
            "description": (
                "A timestamp was disclosed by the application/web server. "
                "Information such as the time the server was last restarted could be used."
            ),
            "url": "http://testsite.local/api/status",
            "solution": "Manually confirm that the timestamp data is not sensitive.",
            "reference": "https://cwe.mitre.org/data/definitions/200.html",
            "cweid": "200",
            "wascid": "13",
            "pluginId": "10096",
            "param": "",
            "evidence": "1687432800",
        },
    ]

    def __init__(self, target: str, **_kwargs) -> None:
        self.target = target

    def run(self) -> list[dict]:
        logger.info("[MOCK] Returning %d sample alerts for %s", len(self.SAMPLE_ALERTS), self.target)
        return self.SAMPLE_ALERTS


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ZAP vulnerability scanner wrapper")
    p.add_argument("--target", required=True, help="Target URL (e.g. http://testsite.local)")
    p.add_argument("--output", default="output/raw_alerts.json", help="Path for raw JSON output")
    p.add_argument("--zap-proxy", default=ZAP_PROXY)
    p.add_argument("--api-key", default=ZAP_API_KEY)
    p.add_argument("--mock", action="store_true", help="Use mock scanner (no live ZAP required)")
    p.add_argument("--verbose", action="store_true")
    return p


def main() -> None:
    args = _build_arg_parser().parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    if args.mock or not ZAP_AVAILABLE:
        scanner = MockScanner(target=args.target)
    else:
        scanner = ZAPScanner(target=args.target, zap_proxy=args.zap_proxy, api_key=args.api_key)

    alerts = scanner.run()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(alerts, indent=2))
    logger.info("Raw alerts saved to %s", out_path)


if __name__ == "__main__":
    main()
