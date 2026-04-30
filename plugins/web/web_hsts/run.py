#!/usr/bin/env python3
"""HTTP Strict Transport Security (HSTS) audit.

Performs passive HTTPS/HTTP checks to confirm redirects, capture
`Strict-Transport-Security`, and record TLS expiry. The script expects a
`TestInput` JSON payload on STDIN and emits a `TestOutput` JSON document.
"""

from __future__ import annotations

import json
import socket
import ssl
import sys
import time
from dataclasses import dataclass
from typing import Dict, Tuple

try:
    import httpx
except ImportError as exc:  # pragma: no cover - dependency hint for operators
    raise SystemExit(json.dumps({
        "test_id": "web_hsts",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": [
            "Install httpx >= 0.27 inside the plugin environment",
        ],
        "notes": f"Missing dependency: {exc}",
    }))

from shared.plugin_context import resolve_web_host

USER_AGENT = "ArtisanPassiveAuditor/0.1 (+passive; contact: audits@artisanhosting.net)"
HEADERS = {"User-Agent": USER_AGENT}


@dataclass
class HstsResult:
    target: str
    https_ok: bool
    hsts_header: str | None
    http_redirects_to_https: bool
    https_status: int | None
    cert_days_left: int | None
    error: str | None = None


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_host(payload: Dict) -> Tuple[str, str]:
    target = payload.get("target", "")
    host = resolve_web_host(payload)
    scheme = "https"
    for fact in payload.get("facts", []):
        if fact.get("entity") == "web_service":
            attrs = fact.get("attrs", {})
            scheme = attrs.get("scheme", scheme)
            break
    return scheme or "https", host or target


def tls_days_left(host: str, port: int = 443) -> int | None:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as wrapped:
                cert = wrapped.getpeercert()
        not_after = cert.get("notAfter")
        if not_after:
            expires_struct = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expires_ts = time.mktime(expires_struct)
            return int((expires_ts - time.time()) // 86400)
    except Exception:
        return None
    return None


def check_hsts(host: str) -> HstsResult:
    https_url = f"https://{host}/"
    http_url = f"http://{host}/"

    try:
        with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=20) as client:
            https_resp = client.get(https_url)
            https_ok = 200 <= https_resp.status_code < 500
            hsts_header = https_resp.headers.get("strict-transport-security")

            try:
                http_resp = client.head(http_url, follow_redirects=False, timeout=10)
                location = http_resp.headers.get("location", "")
                http_redirects_to_https = (
                    300 <= http_resp.status_code < 400 and location.startswith("https://")
                )
            except Exception:
                http_redirects_to_https = False

            days_left = tls_days_left(host)
            return HstsResult(
                target=host,
                https_ok=https_ok,
                hsts_header=hsts_header,
                http_redirects_to_https=http_redirects_to_https,
                https_status=https_resp.status_code,
                cert_days_left=days_left,
            )
    except Exception as exc:
        return HstsResult(
            target=host,
            https_ok=False,
            hsts_header=None,
            http_redirects_to_https=False,
            https_status=None,
            cert_days_left=None,
            error=str(exc),
        )


def main() -> None:
    payload = load_input()
    _, host = resolve_host(payload)
    if not host:
        output = {
            "test_id": "web_hsts",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Provide a web_service fact with host metadata"],
            "notes": "Unable to determine host for HSTS audit",
        }
        json.dump(output, sys.stdout)
        return

    result = check_hsts(host)

    if result.error:
        output = {
            "test_id": "web_hsts",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": result.error},
            "recommendations": ["Verify the site is reachable over HTTPS"],
            "notes": "HSTS check failed",
        }
    else:
        if not result.https_ok:
            status = "fail"
            severity = "high"
            recommendations = ["Serve the site over HTTPS", "Install a valid TLS certificate"]
        elif result.hsts_header:
            status = "pass"
            severity = "informational"
            recommendations = ["Confirm HSTS preload suitability (max-age >= 63072000)"]
        else:
            status = "warn"
            severity = "medium"
            recommendations = ["Enable Strict-Transport-Security on HTTPS responses"]
            if not result.http_redirects_to_https:
                recommendations.append("Redirect all HTTP traffic to HTTPS")

        output = {
            "test_id": "web_hsts",
            "target": host,
            "status": status,
            "severity": severity,
            "evidence": {
                "https_status": result.https_status,
                "hsts_header": result.hsts_header,
                "http_redirects_to_https": result.http_redirects_to_https,
                "cert_days_left": result.cert_days_left,
            },
            "recommendations": recommendations,
            "notes": None,
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
