#!/usr/bin/env python3
"""DNSBL reputation lookup for IP observations."""

from __future__ import annotations

import ipaddress
import json
import sys
from typing import Dict

try:
    import dns.resolver
except ImportError as exc:  # pragma: no cover
    raise SystemExit(json.dumps({
        "test_id": "ip_reputation_dnsbl",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install dnspython >= 2.4 in the environment"],
        "notes": f"Missing dependency: {exc}",
    }))

from shared.plugin_context import resolve_entity_values

DNSBLS = [
    ("Spamcop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("PSBL", "psbl.surriel.com"),
    ("SORBS", "dnsbl.sorbs.net"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
]


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def reverse_ipv4(ip: str) -> str:
    return ".".join(reversed(ip.split(".")))


def dnsbl_listings(ip: str) -> list[dict]:
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']  # Cloudflare DNS servers
    resolver.lifetime = 3.0
    resolver.timeout = 2.0
    listed = []
    for label, zone in DNSBLS:
        lookup = f"{reverse_ipv4(ip)}.{zone}"
        try:
            answers = resolver.resolve(lookup, "A")
            listed.append({
                "list": label,
                "zone": zone,
                "answers": [answer.to_text() for answer in answers],
            })
        except Exception:
            continue
    return listed


def main() -> None:
    payload = load_input()
    host, ips = resolve_entity_values(payload, "ip_address", "ip")
    if not ips:
        json.dump({
            "test_id": "ip_reputation_dnsbl",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Ensure discovery produced ip_address facts"],
            "notes": "Unable to determine any IPs for DNSBL check",
        }, sys.stdout)
        return

    try:
        observations = []
        listed_any = False
        checked_ipv4 = False
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if addr.version != 4:
                observations.append({
                    "ip": ip,
                    "family": "ipv6",
                    "status": "skipped",
                    "notes": "DNSBL checks are currently limited to IPv4",
                })
                continue

            checked_ipv4 = True
            listed = dnsbl_listings(ip)
            listed_any = listed_any or bool(listed)
            observations.append({
                "ip": ip,
                "family": "ipv4",
                "listed": listed,
                "checked_lists": [label for label, _ in DNSBLS],
            })

        if not checked_ipv4:
            json.dump({
                "test_id": "ip_reputation_dnsbl",
                "target": host,
                "status": "skipped",
                "severity": "informational",
                "evidence": {
                    "host": host,
                    "ips": ips,
                    "observations": observations,
                },
                "recommendations": [],
                "notes": "DNSBL checks are currently limited to IPv4",
            }, sys.stdout)
            return

        status = "warn" if listed_any else "pass"
        severity = "medium" if listed_any else "informational"
        recommendations = []
        if listed_any:
            recommendations.extend([
                "Review abuse or spam signals associated with the IPs",
                "Investigate whether any listed address should remain publicly exposed",
            ])

        json.dump({
            "test_id": "ip_reputation_dnsbl",
            "target": host,
            "status": status,
            "severity": severity,
            "evidence": {
                "host": host,
                "ips": ips,
                "observations": observations,
            },
            "recommendations": recommendations,
            "notes": None,
        }, sys.stdout)
    except Exception as exc:
        json.dump({
            "test_id": "ip_reputation_dnsbl",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc), "ips": ips},
            "recommendations": ["Verify DNS resolver access and retry"],
            "notes": "DNSBL lookup failed",
        }, sys.stdout)


if __name__ == "__main__":
    main()
