#!/usr/bin/env python3
"""DNSBL reputation lookup for IP observations."""

from __future__ import annotations

import ipaddress
import json
import sys
from typing import Dict, Tuple

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

DNSBLS = [
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("Spamcop", "bl.spamcop.net"),
    ("Barracuda", "b.barracudacentral.org"),
    ("PSBL", "psbl.surriel.com"),
    ("SORBS", "dnsbl.sorbs.net"),
    ("UCEPROTECT L1", "dnsbl-1.uceprotect.net"),
]


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
    host, ip = resolve_context(payload)
    if not ip:
        json.dump({
            "test_id": "ip_reputation_dnsbl",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Ensure discovery produced ip_address facts"],
            "notes": "Unable to determine IP for DNSBL check",
        }, sys.stdout)
        return

    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4:
            json.dump({
                "test_id": "ip_reputation_dnsbl",
                "target": f"{host}|{ip}",
                "status": "skipped",
                "severity": "informational",
                "evidence": {"ip": ip, "family": "ipv6"},
                "recommendations": [],
                "notes": "DNSBL checks are currently limited to IPv4",
            }, sys.stdout)
            return

        listed = dnsbl_listings(ip)
        status = "warn" if listed else "pass"
        severity = "medium" if listed else "informational"
        recommendations = []
        if listed:
            recommendations.extend([
                "Review abuse or spam signals associated with the IP",
                "Investigate whether the address should remain publicly exposed",
            ])

        json.dump({
            "test_id": "ip_reputation_dnsbl",
            "target": f"{host}|{ip}",
            "status": status,
            "severity": severity,
            "evidence": {
                "host": host,
                "ip": ip,
                "listed": listed,
                "checked_lists": [label for label, _ in DNSBLS],
            },
            "recommendations": recommendations,
            "notes": None,
        }, sys.stdout)
    except Exception as exc:
        json.dump({
            "test_id": "ip_reputation_dnsbl",
            "target": f"{host}|{ip}",
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc), "ip": ip},
            "recommendations": ["Verify DNS resolver access and retry"],
            "notes": "DNSBL lookup failed",
        }, sys.stdout)


if __name__ == "__main__":
    main()
