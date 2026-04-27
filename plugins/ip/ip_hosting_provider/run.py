#!/usr/bin/env python3
"""Hosting provider and proxy inference for resolved IPs."""

from __future__ import annotations

import json
import sys
from typing import Dict, Optional, Tuple

try:
    import httpx
except ImportError as exc:  # pragma: no cover
    raise SystemExit(json.dumps({
        "test_id": "ip_hosting_provider",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}
PROVIDER_PATTERNS = {
    "cloudflare": ["cloudflare", "as13335"],
    "aws": ["amazon", "aws", "amazon.com"],
    "gcp": ["google", "gcp", "google cloud"],
    "azure": ["microsoft", "azure", "msn"],
    "digitalocean": ["digitalocean"],
    "linode": ["linode", "akamai connected cloud"],
    "fastly": ["fastly"],
    "akamai": ["akamai"],
    "vercel": ["vercel"],
    "netlify": ["netlify"],
    "cloudfront": ["cloudfront"],
    "contabo": ["contabo"],
}


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_context(payload: Dict) -> Tuple[str, str]:
    host = payload.get("target", "")
    ip = ""
    for fact in payload.get("facts", []):
        if fact.get("entity") == "ip_address":
            attrs = fact.get("attrs", {})
            host = attrs.get("host", host)
            ip = attrs.get("ip", ip)
            break
    return host or payload.get("target", ""), ip


def fetch_ipinfo(ip: str) -> Dict:
    with httpx.Client(headers=HEADERS, timeout=10) as client:
        response = client.get(f"https://ipinfo.io/{ip}/json")
        response.raise_for_status()
        return response.json()


def classify_provider(org: str) -> Tuple[Optional[str], bool]:
    lowered = org.lower()
    for provider, patterns in PROVIDER_PATTERNS.items():
        if any(pattern in lowered for pattern in patterns):
            return provider, provider == "cloudflare"
    return None, False


def main() -> None:
    payload = load_input()
    host, ip = resolve_context(payload)
    if not ip:
        json.dump({
            "test_id": "ip_hosting_provider",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Ensure discovery produced ip_address facts"],
            "notes": "Unable to determine IP for hosting provider check",
        }, sys.stdout)
        return

    try:
        info = fetch_ipinfo(ip)
        org = info.get("org") or ""
        provider, cloudflare_proxy = classify_provider(org)

        json.dump({
            "test_id": "ip_hosting_provider",
            "target": f"{host}|{ip}",
            "status": "info",
            "severity": "informational",
            "evidence": {
                "host": host,
                "ip": ip,
                "provider": provider,
                "organization": org,
                "asn": info.get("org"),
                "cloudflare_proxy": cloudflare_proxy,
                "common_cloud_provider": provider,
            },
            "recommendations": [],
            "notes": None,
        }, sys.stdout)
    except Exception as exc:
        json.dump({
            "test_id": "ip_hosting_provider",
            "target": f"{host}|{ip}",
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc), "ip": ip},
            "recommendations": ["Verify outbound HTTP access and retry"],
            "notes": "IP provider lookup failed",
        }, sys.stdout)


if __name__ == "__main__":
    main()
