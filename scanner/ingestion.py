"""
ingestion.py
------------
Imports externally-generated ZAP scan exports (XML or JSON) and normalizes
them into the *existing* raw-alert dict shape consumed by
`scanner.parser.AlertParser`.

This is deliberately a thin adapter, not a rewrite: the goal is to feed
imported reports through the same `AlertParser.parse()` pipeline that live
scans already use, so `ParsedAlert` / `ScanSummary` stay the single source
of truth for downstream code (report generator, web UI, future
aggregator/compliance modules).

Supported inputs today:
    - ZAP "Export Alerts to XML" output (Report > Export Alerts > XML)
    - ZAP "Export Alerts to JSON" output (Report > Export Alerts > JSON),
      and the raw JSON shape returned by zap.core.alerts() (same shape your
      live ZAPScanner already produces)

Stretch goal (not implemented): Nikto / Nessus importers. If added later,
they should also normalize into the same raw-alert dict shape and reuse
AlertParser unchanged.
"""

import json
import logging
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Union

from scanner.parser import AlertParser, ScanSummary

logger = logging.getLogger(__name__)

PathLike = Union[str, Path]


class IngestionError(Exception):
    """Raised when an imported report can't be parsed or normalized."""


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def ingest_file(path: PathLike, target: str | None = None) -> ScanSummary:
    """
    Load a ZAP export (.xml or .json) from disk and return a ScanSummary,
    using the same AlertParser pipeline as live scans.

    If `target` is not supplied, it is inferred from the export itself
    (the first alert's host, or the XML report's @host attribute).
    """
    path = Path(path)
    if not path.exists():
        raise IngestionError(f"File not found: {path}")

    suffix = path.suffix.lower()
    if suffix == ".xml":
        raw_alerts, inferred_target = _parse_zap_xml(path)
    elif suffix == ".json":
        raw_alerts, inferred_target = _parse_zap_json(path)
    else:
        raise IngestionError(
            f"Unsupported export format '{suffix}'. Expected .xml or .json."
        )

    resolved_target = target or inferred_target or "unknown-target"
    logger.info(
        "Ingested %d raw alert(s) from %s (target=%s)",
        len(raw_alerts), path.name, resolved_target,
    )

    return AlertParser(target=resolved_target).parse(raw_alerts)


# ---------------------------------------------------------------------------
# XML import (ZAP "Export Alerts to XML")
# ---------------------------------------------------------------------------

def _parse_zap_xml(path: Path) -> tuple[list[dict], str | None]:
    """
    Parses ZAP's native XML alert export.

    ZAP XML export structure (per site):
        <OWASPZAPReport>
          <site name="..." host="..." port="..." ssl="...">
            <alerts>
              <alertitem>
                <pluginid>...</pluginid>
                <alert>...</alert>          <!-- alert name -->
                <name>...</name>
                <riskcode>...</riskcode>
                <riskdesc>High (...)</riskdesc>
                <confidence>...</confidence>
                <confidencedesc>...</confidencedesc>
                <desc>...</desc>
                <instances>
                  <instance>
                    <uri>...</uri>
                    <param>...</param>
                    <evidence>...</evidence>
                  </instance>
                  ...
                </instances>
                <solution>...</solution>
                <reference>...</reference>
                <cweid>...</cweid>
                <wascid>...</wascid>
              </alertitem>
            </alerts>
          </site>
        </OWASPZAPReport>

    Each <instance> becomes its own raw-alert dict (mirrors how the live
    ZAP API returns one alert entry per URL/param combination), which keeps
    AlertParser's existing dedup key (pluginId + url + param) meaningful.
    """
    try:
        tree = ET.parse(path)
    except ET.ParseError as exc:
        raise IngestionError(f"Malformed XML in {path.name}: {exc}") from exc

    root = tree.getroot()
    raw_alerts: list[dict] = []
    inferred_target: str | None = None

    sites = root.findall(".//site")
    if not sites:
        raise IngestionError(
            f"No <site> elements found in {path.name} — is this a ZAP XML export?"
        )

    for site in sites:
        host = site.get("host", "")
        port = site.get("port", "")
        ssl = site.get("ssl", "false").lower() == "true"
        if host and inferred_target is None:
            scheme = "https" if ssl else "http"
            inferred_target = f"{scheme}://{host}" + (f":{port}" if port else "")

        for item in site.findall(".//alertitem"):
            name = _xml_text(item, "alert") or _xml_text(item, "name") or "Unknown"
            plugin_id = _xml_text(item, "pluginid") or ""
            risk = _risk_from_riskcode(_xml_text(item, "riskcode"))
            confidence = _xml_text(item, "confidencedesc") or _xml_text(item, "confidence") or "Unknown"
            description = _xml_text(item, "desc") or ""
            solution = _xml_text(item, "solution") or ""
            reference = _xml_text(item, "reference") or ""
            cwe_id = _xml_text(item, "cweid") or ""
            wasc_id = _xml_text(item, "wascid") or ""

            instances = item.findall(".//instances/instance")
            if not instances:
                # Some exports omit <instances> entirely and put uri/param
                # directly on the alertitem — handle that fallback too.
                raw_alerts.append({
                    "pluginId": plugin_id,
                    "name": name,
                    "risk": risk,
                    "confidence": confidence,
                    "description": description,
                    "url": _xml_text(item, "uri") or "",
                    "param": _xml_text(item, "param") or "",
                    "evidence": _xml_text(item, "evidence") or "",
                    "solution": solution,
                    "reference": reference,
                    "cweid": cwe_id,
                    "wascid": wasc_id,
                })
                continue

            for inst in instances:
                raw_alerts.append({
                    "pluginId": plugin_id,
                    "name": name,
                    "risk": risk,
                    "confidence": confidence,
                    "description": description,
                    "url": _xml_text(inst, "uri") or "",
                    "param": _xml_text(inst, "param") or "",
                    "evidence": _xml_text(inst, "evidence") or "",
                    "solution": solution,
                    "reference": reference,
                    "cweid": cwe_id,
                    "wascid": wasc_id,
                })

    return raw_alerts, inferred_target


def _xml_text(elem: ET.Element, tag: str) -> str | None:
    found = elem.find(tag)
    if found is not None and found.text:
        return found.text.strip()
    return None


def _risk_from_riskcode(code: str | None) -> str:
    """ZAP XML uses numeric riskcode: 0=Info, 1=Low, 2=Medium, 3=High."""
    mapping = {"0": "Informational", "1": "Low", "2": "Medium", "3": "High"}
    return mapping.get((code or "").strip(), "Informational")


# ---------------------------------------------------------------------------
# JSON import (ZAP "Export Alerts to JSON" or raw zap.core.alerts() dump)
# ---------------------------------------------------------------------------

def _parse_zap_json(path: Path) -> tuple[list[dict], str | None]:
    """
    Accepts two JSON shapes:

    1. Raw list of alert dicts, identical to what zap.core.alerts() / your
       existing live ZAPScanner already produces:
           [ {"pluginId": "...", "risk": "High", "url": "...", ...}, ... ]

    2. ZAP's "Export Alerts to JSON" report shape:
           {"site": [ {"@name": "...", "alerts": [ {...}, ... ] }, ... ] }

    Both are normalized into the same flat list[dict] that AlertParser
    already expects — no new fields, no schema changes downstream.
    """
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IngestionError(f"Malformed JSON in {path.name}: {exc}") from exc

    inferred_target: str | None = None
    raw_alerts: list[dict] = []

    if isinstance(data, list):
        # Shape 1 — already flat, matches AlertParser's expected dict keys.
        raw_alerts = data
        if raw_alerts:
            first_url = raw_alerts[0].get("url", "")
            inferred_target = _origin_from_url(first_url)

    elif isinstance(data, dict) and "site" in data:
        # Shape 2 — ZAP's structured export report.
        sites = data["site"]
        if isinstance(sites, dict):
            sites = [sites]

        for site in sites:
            site_name = site.get("@name") or site.get("name")
            if site_name and inferred_target is None:
                inferred_target = site_name

            for alert in site.get("alerts", []):
                instances = alert.get("instances", [])
                base = {
                    "pluginId": str(alert.get("pluginid") or alert.get("pluginId") or ""),
                    "name": alert.get("alert") or alert.get("name", "Unknown"),
                    "risk": alert.get("riskdesc", "").split(" ")[0] or "Informational",
                    "confidence": alert.get("confidencedesc") or alert.get("confidence", "Unknown"),
                    "description": alert.get("desc") or alert.get("description", ""),
                    "solution": alert.get("solution", ""),
                    "reference": alert.get("reference", ""),
                    "cweid": str(alert.get("cweid", "")),
                    "wascid": str(alert.get("wascid", "")),
                }
                if instances:
                    for inst in instances:
                        raw_alerts.append({
                            **base,
                            "url": inst.get("uri", ""),
                            "param": inst.get("param", ""),
                            "evidence": inst.get("evidence", ""),
                        })
                else:
                    raw_alerts.append({
                        **base,
                        "url": alert.get("url", ""),
                        "param": alert.get("param", ""),
                        "evidence": alert.get("evidence", ""),
                    })
    else:
        raise IngestionError(
            f"Unrecognized JSON structure in {path.name} — expected a flat alert "
            "list or a ZAP {'site': [...]} export."
        )

    return raw_alerts, inferred_target


def _origin_from_url(url: str) -> str | None:
    """Extracts scheme://host[:port] from a full URL, for target inference."""
    if not url:
        return None
    try:
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        if not parts.scheme or not parts.netloc:
            return None
        return f"{parts.scheme}://{parts.netloc}"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CLI usage (mirrors parser.py's __main__ block for consistency)
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

    if len(sys.argv) < 2:
        print("Usage: python -m scanner.ingestion <export.xml|export.json> [target_url]")
        sys.exit(1)

    file_arg = sys.argv[1]
    target_arg = sys.argv[2] if len(sys.argv) > 2 else None

    summary = ingest_file(file_arg, target=target_arg)
    print(json.dumps(summary.to_dict(), indent=2, default=str))
