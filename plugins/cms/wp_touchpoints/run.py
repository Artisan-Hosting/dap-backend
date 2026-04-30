#!/usr/bin/env python3
"""WordPress touchpoint audit.

Performs passive GET requests to wp-login.php, xmlrpc.php, and wp-json/ to
capture exposure details. Evidence is written under the run's evidence folder
when available.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, Optional

try:
    import httpx
except ImportError as exc:
    raise SystemExit(json.dumps({
        "test_id": "wp_touchpoints",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

from shared.plugin_context import resolve_web_host
from shared.parallel import parallel_map

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_host(payload: Dict) -> str:
    return resolve_web_host(payload)


def prepare_evidence_dir(payload: Dict, test_id: str) -> Optional[Path]:
    cfg = payload.get("config", {})
    run_root = cfg.get("run_root")
    if not run_root:
        return None
    path = Path(run_root) / "evidence" / test_id
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except Exception:
        return None


def fetch(url: str) -> httpx.Response:
    with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=20) as client:
        return client.get(url)


def main() -> None:
    payload = load_input()
    host = resolve_host(payload)
    if not host:
        json.dump({
            "test_id": "wp_touchpoints",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Provide a web_service fact with host metadata"],
            "notes": "Unable to determine host for WordPress audit",
        }, sys.stdout)
        return

    evidence_dir = prepare_evidence_dir(payload, "wp_touchpoints")
    base = f"https://{host}"

    try:
        login, xmlrpc, rest = [
            response
            for _, response in parallel_map(
                [
                    ("login", f"{base}/wp-login.php"),
                    ("xmlrpc", f"{base}/xmlrpc.php"),
                    ("rest", f"{base}/wp-json/"),
                ],
                lambda item: (item[0], fetch(item[1])),
            )
        ]

        # wp-login analysis
        login_noindex = False
        login_cached = True
        if login.text:
            if evidence_dir:
                (evidence_dir / "wp-login.html").write_text(login.text, encoding="utf-8", errors="ignore")
            meta = re.search(r"<meta[^>]+name=\"robots\"[^>]+content=\"([^\"]+)\"", login.text, re.I)
            if meta and "noindex" in meta.group(1).lower():
                login_noindex = True
        robots_header = login.headers.get("x-robots-tag", "").lower()
        if "noindex" in robots_header:
            login_noindex = True
        cache_headers = " ".join([login.headers.get("cache-control", ""), login.headers.get("pragma", "")]).lower()
        if any(flag in cache_headers for flag in ("no-cache", "no-store", "private")):
            login_cached = False
        if evidence_dir:
            (evidence_dir / "wp-login.headers.txt").write_text(
                "\n".join(f"{k}: {v}" for k, v in login.headers.items()),
                encoding="utf-8",
            )

        # xmlrpc analysis
        xmlrpc_enabled = False
        if xmlrpc.text:
            if evidence_dir:
                (evidence_dir / "xmlrpc.body.txt").write_text(xmlrpc.text, encoding="utf-8", errors="ignore")
            snippet = xmlrpc.text[:200].lower()
            xmlrpc_enabled = "accepts post requests" in snippet
        if evidence_dir:
            (evidence_dir / "xmlrpc.headers.txt").write_text(
                "\n".join(f"{k}: {v}" for k, v in xmlrpc.headers.items()),
                encoding="utf-8",
            )

        # REST API
        rest_accessible = 200 <= rest.status_code < 400
        if evidence_dir and rest.text:
            (evidence_dir / "wp-json.json").write_text(rest.text[:5000], encoding="utf-8", errors="ignore")

        recommendations = []
        status = "pass"
        severity = "informational"

        if xmlrpc_enabled:
            status = "warn"
            severity = "medium"
            recommendations.append("Disable or restrict xmlrpc.php")
        if not login_noindex:
            status = "warn"
            severity = "medium"
            recommendations.append("Ensure wp-login.php is tagged noindex")

        evidence = {
            "wp_login_status": login.status_code,
            "wp_login_noindex": login_noindex,
            "wp_login_cached": not login_cached,
            "xmlrpc_status": xmlrpc.status_code,
            "xmlrpc_enabled": xmlrpc_enabled,
            "wp_json_status": rest.status_code,
            "wp_json_accessible": rest_accessible,
        }

        output = {
            "test_id": "wp_touchpoints",
            "target": host,
            "status": status,
            "severity": severity,
            "evidence": evidence,
            "recommendations": recommendations,
            "notes": None,
        }
    except Exception as exc:
        output = {
            "test_id": "wp_touchpoints",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc)},
            "recommendations": ["Verify HTTPS reachability and retry"],
            "notes": "WordPress touchpoint scan failed",
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
