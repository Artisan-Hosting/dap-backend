#!/usr/bin/env python3
"""Security header inventory.

Collects the presence and values of key defensive headers on the root document.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Optional

try:
    import httpx
except ImportError as exc:
    raise SystemExit(json.dumps({
        "test_id": "web_security_headers",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

from shared.plugin_context import resolve_web_host

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}
HEADER_KEYS = {
    "content-security-policy": "csp_present",
    "strict-transport-security": "hsts_present",
    "x-content-type-options": "xcto_present",
    "referrer-policy": "refpol_present",
    "x-frame-options": "xfo_present",
    "permissions-policy": "permpol_present",
    "cross-origin-resource-policy": "corp_present",
    "cross-origin-opener-policy": "coop_present",
    "cross-origin-embedder-policy": "coep_present",
}


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


def main() -> None:
    payload = load_input()
    host = resolve_host(payload)
    if not host:
        json.dump({
            "test_id": "web_security_headers",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Provide a web_service fact with host metadata"],
            "notes": "Unable to determine host for security header audit",
        }, sys.stdout)
        return

    evidence_dir = prepare_evidence_dir(payload, "web_security_headers")
    url = f"https://{host}/"

    try:
        with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=20) as client:
            resp = client.get(url)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}
        evidence = {}
        missing = []
        for header_name, key in HEADER_KEYS.items():
            value = headers_lower.get(header_name)
            evidence[key] = value
            if evidence_dir and value:
                (evidence_dir / f"{header_name.replace('-', '_')}.txt").write_text(value, encoding="utf-8")
            if key in {"csp_present", "xcto_present", "refpol_present", "xfo_present"} and not value:
                missing.append(header_name)

        status = "pass"
        severity = "informational"
        recommendations = []
        if missing:
            status = "warn"
            severity = "medium"
            recommendations.append(
                "Add defensive headers: " + ", ".join(sorted(missing))
            )
        if not headers_lower.get("strict-transport-security"):
            recommendations.append("Set Strict-Transport-Security on HTTPS responses")

        output = {
            "test_id": "web_security_headers",
            "target": host,
            "status": status,
            "severity": severity,
            "evidence": evidence,
            "recommendations": recommendations,
            "notes": None,
        }
    except Exception as exc:
        output = {
            "test_id": "web_security_headers",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc)},
            "recommendations": ["Verify HTTPS reachability and retry"],
            "notes": "Security header fetch failed",
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
