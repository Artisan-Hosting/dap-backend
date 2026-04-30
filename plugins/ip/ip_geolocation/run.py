#!/usr/bin/env python3
"""Geolocation sanity check for resolved IPs."""

from __future__ import annotations

import json
import sys
from typing import Dict

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

from shared.plugin_context import resolve_entity_values

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def fetch_ipinfo(ip: str) -> Dict:
    with httpx.Client(headers=HEADERS, timeout=10) as client:
        response = client.get(f"https://ipinfo.io/{ip}/json")
        response.raise_for_status()
        return response.json()


def main() -> None:
    payload = load_input()
    host, ips = resolve_entity_values(payload, "ip_address", "ip")
    if not ips:
        json.dump({
            "test_id": "ip_geolocation",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Ensure discovery produced ip_address facts"],
            "notes": "Unable to determine any IPs for geolocation lookup",
        }, sys.stdout)
        return

    try:
        observations = []
        saw_non_us = False
        saw_missing_country = False
        had_success = False

        for ip in ips:
            try:
                info = fetch_ipinfo(ip)
                had_success = True
                country = (info.get("country") or "").upper()
                region = info.get("region")
                city = info.get("city")
                if not country:
                    saw_missing_country = True
                    notes = "Geolocation source did not return a country"
                else:
                    notes = None
                    if country != "US":
                        saw_non_us = True
                observations.append({
                    "ip": ip,
                    "country": country or None,
                    "region": region,
                    "city": city,
                    "postal": info.get("postal"),
                    "timezone": info.get("timezone"),
                    "loc": info.get("loc"),
                })
            except Exception as exc:
                observations.append({"ip": ip, "error": str(exc)})

        if not had_success:
            raise RuntimeError("all geolocation lookups failed")

        if saw_non_us:
            status = "warn"
            severity = "medium"
            recommendations = ["Verify that these public IPs should geolocate outside the US"]
            notes = "One or more public IPs geolocate outside the expected US region"
        elif saw_missing_country:
            status = "info"
            severity = "informational"
            recommendations = ["Confirm IP location through a secondary source"]
            notes = "One or more geolocation results did not return a country"
        else:
            status = "pass"
            severity = "informational"
            recommendations = []
            notes = None

        json.dump({
            "test_id": "ip_geolocation",
            "target": host,
            "status": status,
            "severity": severity,
            "evidence": {
                "host": host,
                "ips": ips,
                "observations": observations,
            },
            "recommendations": recommendations,
            "notes": notes,
        }, sys.stdout)
    except Exception as exc:
        json.dump({
            "test_id": "ip_geolocation",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc), "ips": ips},
            "recommendations": ["Verify outbound HTTP access and retry"],
            "notes": "IP geolocation lookup failed",
        }, sys.stdout)


if __name__ == "__main__":
    main()
