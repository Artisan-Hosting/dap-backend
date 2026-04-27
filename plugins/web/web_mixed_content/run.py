#!/usr/bin/env python3
"""Mixed content reference counter.

Fetches the root document and counts external `http://` references as outlined
in objective.md §7.
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
        "test_id": "web_mixed_content",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}
HTTP_PATTERN = re.compile(r"http://[a-z0-9][^\"'<>\s]+", re.IGNORECASE)
EXCLUDE = re.compile(r"(localhost|127\.0\.0\.1|::1)", re.IGNORECASE)


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_host(payload: Dict) -> str:
    host = payload.get("target", "")
    for fact in payload.get("facts", []):
        if fact.get("entity") == "web_service":
            attrs = fact.get("attrs", {})
            host = attrs.get("host", host)
            break
    return host or payload.get("target", "")


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
            "test_id": "web_mixed_content",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Provide a web_service fact with host metadata"],
            "notes": "Unable to determine host for mixed content audit",
        }, sys.stdout)
        return

    evidence_dir = prepare_evidence_dir(payload, "web_mixed_content")
    url = f"https://{host}/"

    try:
        with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=30) as client:
            resp = client.get(url)
        html = resp.text or ""
        if evidence_dir:
            (evidence_dir / "root.html").write_text(html, encoding="utf-8", errors="ignore")

        refs = [match for match in HTTP_PATTERN.findall(html) if not EXCLUDE.search(match)]
        unique_hosts = sorted({ref.split("/", 3)[2] for ref in refs}) if refs else []

        status = "pass"
        severity = "informational"
        recommendations = []
        if refs:
            status = "warn"
            severity = "medium" if len(refs) > 5 else "low"
            recommendations.append("Replace hardcoded http:// assets with HTTPS equivalents")

        evidence = {
            "http_reference_count": len(refs),
            "hosts": unique_hosts,
        }
        if evidence_dir and unique_hosts:
            (evidence_dir / "hosts.txt").write_text("\n".join(unique_hosts), encoding="utf-8")

        output = {
            "test_id": "web_mixed_content",
            "target": host,
            "status": status,
            "severity": severity,
            "evidence": evidence,
            "recommendations": recommendations,
            "notes": None,
        }
    except Exception as exc:
        output = {
            "test_id": "web_mixed_content",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc)},
            "recommendations": ["Verify HTTPS reachability and retry"],
            "notes": "Mixed content scan failed",
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
