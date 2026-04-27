#!/usr/bin/env python3
"""Geolocation sanity check for resolved IPs."""

from __future__ import annotations

import json
import sys
from typing import Dict, Tuple

try:
    import httpx
except ImportError as exc:  # pragma: no cover
    raise SystemExit(json.dumps({
        "test_id": "ip_geolocation",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}


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


def main() -> None:
    payload = load_input()
    host, ip = resolve_context(payload)
    if not ip:
        json.dump({
            "test_id": "ip_geolocation",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Ensure discovery produced ip_address facts"],
            "notes": "Unable to determine IP for geolocation lookup",
        }, sys.stdout)
        return

    try:
        info = fetch_ipinfo(ip)
        country = (info.get("country") or "").upper()
        region = info.get("region")
        city = info.get("city")

        if not country:
            status = "info"
            severity = "informational"
            recommendations = ["Confirm IP location through a secondary source"]
            notes = "Geolocation source did not return a country"
        elif country != "US":
            status = "warn"
            severity = "medium"
            recommendations = ["Verify that this public IP should geolocate outside the US"]
            notes = "Public IP geolocates outside the expected US region"
        else:
            status = "pass"
            severity = "informational"
            recommendations = []
            notes = None

        json.dump({
            "test_id": "ip_geolocation",
            "target": f"{host}|{ip}",
            "status": status,
            "severity": severity,
            "evidence": {
                "host": host,
                "ip": ip,
                "country": country or None,
                "region": region,
                "city": city,
                "postal": info.get("postal"),
                "timezone": info.get("timezone"),
                "loc": info.get("loc"),
            },
            "recommendations": recommendations,
            "notes": notes,
        }, sys.stdout)
    except Exception as exc:
        json.dump({
            "test_id": "ip_geolocation",
            "target": f"{host}|{ip}",
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc), "ip": ip},
            "recommendations": ["Verify outbound HTTP access and retry"],
            "notes": "IP geolocation lookup failed",
        }, sys.stdout)


if __name__ == "__main__":
    main()
