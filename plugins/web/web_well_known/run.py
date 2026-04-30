#!/usr/bin/env python3
"""Well-known endpoint discovery.

Probes a small set of `/.well-known/` endpoints on the root host and common
subdomains such as `mta-sts.<host>` to surface low-noise configuration and
supporting services.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

try:
    import httpx
except ImportError as exc:  # pragma: no cover - dependency hint for operators
    raise SystemExit(json.dumps({
        "test_id": "web_well_known",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}
ROOT_PATHS = [
    "/.well-known/security.txt",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
    "/.well-known/change-password",
    "/.well-known/host-meta",
]
SUBDOMAIN_PATHS = [
    ("mta-sts", "/.well-known/mta-sts.txt"),
]


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_host(payload: Dict) -> str:
    host = payload.get("target", "")
    for fact in payload.get("facts", []):
        attrs = fact.get("attrs", {})
        if fact.get("entity") == "web_service":
            host = attrs.get("host", host)
            break
        if fact.get("entity") == "site_profile":
            host = attrs.get("host", host)
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


def fetch_root_scheme(host: str) -> str:
    last_error: Exception | None = None
    for scheme in ("https", "http"):
        try:
            with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=15) as client:
                resp = client.get(f"{scheme}://{host}/")
                if resp.status_code < 500:
                    return scheme
        except Exception as exc:
            last_error = exc
    raise RuntimeError(str(last_error) if last_error else "unable to fetch root document")


def probe_url(client: httpx.Client, url: str) -> Optional[httpx.Response]:
    try:
        resp = client.get(url)
    except Exception:
        return None
    return resp if resp.status_code != 404 else None


def record_response(host: str, path: str, url: str, resp: httpx.Response) -> Dict:
    body = resp.text or ""
    preview = body[:160].replace("\n", " ").strip()
    return {
        "host": host,
        "path": path,
        "url": url,
        "status_code": resp.status_code,
        "content_type": resp.headers.get("content-type"),
        "content_length": resp.headers.get("content-length"),
        "body_preview": preview or None,
    }


def main() -> None:
    payload = load_input()
    host = resolve_host(payload)
    if not host:
        json.dump({
            "test_id": "web_well_known",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Provide a site or web_service fact with host metadata"],
            "notes": "Unable to determine host for well-known probe",
        }, sys.stdout)
        return

    evidence_dir = prepare_evidence_dir(payload, "web_well_known")

    try:
        scheme = fetch_root_scheme(host)
        findings: list[Dict] = []

        with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=15) as client:
            for path in ROOT_PATHS:
                url = f"{scheme}://{host}{path}"
                resp = probe_url(client, url)
                if resp is not None and resp.status_code < 500:
                    findings.append(record_response(host, path, url, resp))

            for subdomain, path in SUBDOMAIN_PATHS:
                subhost = f"{subdomain}.{host}"
                url = f"{scheme}://{subhost}{path}"
                resp = probe_url(client, url)
                if resp is not None and resp.status_code < 500:
                    findings.append(record_response(subhost, path, url, resp))

        if evidence_dir:
            (evidence_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

        if findings:
            output = {
                "test_id": "web_well_known",
                "target": host,
                "status": "info",
                "severity": "informational",
                "evidence": {
                    "scheme": scheme,
                    "findings": findings,
                },
                "recommendations": [
                    "Document intentional well-known endpoints and keep their contents minimal",
                    "Review any unexpected well-known resources for information disclosure",
                ],
                "notes": None,
            }
        else:
            output = {
                "test_id": "web_well_known",
                "target": host,
                "status": "pass",
                "severity": "informational",
                "evidence": {"scheme": scheme, "findings": []},
                "recommendations": [],
                "notes": None,
            }
    except Exception as exc:
        output = {
            "test_id": "web_well_known",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc)},
            "recommendations": ["Verify HTTP reachability and retry"],
            "notes": f"Well-known probe failed: {exc}",
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
