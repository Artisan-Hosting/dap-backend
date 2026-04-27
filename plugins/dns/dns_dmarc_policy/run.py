#!/usr/bin/env python3
"""DMARC policy observation.

Leverages dnspython to inspect TXT records under _dmarc.<domain> and related
email alignment records.
"""

from __future__ import annotations

import json
import sys
from typing import Dict, Optional

try:
    import dns.resolver
except ImportError as exc:
    raise SystemExit(json.dumps({
        "test_id": "dns_dmarc_policy",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install dnspython >= 2.4 in the environment"],
        "notes": f"Missing dependency: {exc}",
    }))

COMMON_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "s1",
    "s2",
]


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_domain(payload: Dict) -> str:
    for fact in payload.get("facts", []):
        if fact.get("entity") == "dns_record":
            attrs = fact.get("attrs", {})
            name = attrs.get("name", "")
            if attrs.get("type") == "TXT" and name.startswith("_dmarc"):
                return attrs.get("name", "").split("_dmarc.", 1)[-1] or payload.get("target", "")
    return payload.get("target", "")


def query_txt(name: str) -> list[str]:
    try:
        return [b"".join(r.strings).decode("utf-8", "ignore") for r in dns.resolver.resolve(name, "TXT")]
    except Exception:
        return []


def main() -> None:
    payload = load_input()
    domain = resolve_domain(payload)
    if not domain:
        json.dump({
            "test_id": "dns_dmarc_policy",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Ensure discovery captured DNS TXT records"],
            "notes": "Unable to determine domain for DMARC audit",
        }, sys.stdout)
        return

    dmarc_txts = query_txt(f"_dmarc.{domain}")
    spf_txts = query_txt(domain)
    tls_txts = bool(query_txt(f"_smtp._tls.{domain}"))

    dmarc_present = False
    policy = ""
    rua_present = False
    for entry in dmarc_txts:
        low = entry.lower()
        if low.startswith("v=dmarc1"):
            dmarc_present = True
            if "p=" in low:
                policy = low.split("p=", 1)[1].split(";", 1)[0]
            rua_present = "rua=" in low
            break

    spf_present = any(txt.lower().startswith("v=spf1") for txt in spf_txts)

    status = "pass" if dmarc_present and policy in {"quarantine", "reject"} else "warn"
    severity = "medium" if status == "warn" else "informational"
    recommendations = []
    if not dmarc_present:
        recommendations.append("Publish a DMARC record (v=DMARC1)")
    elif policy not in {"quarantine", "reject"}:
        recommendations.append("Increase DMARC policy to quarantine or reject")
    if not rua_present:
        recommendations.append("Add rua reporting address for DMARC")

    output = {
        "test_id": "dns_dmarc_policy",
        "target": domain,
        "status": status,
        "severity": severity,
        "evidence": {
            "dmarc_txts": dmarc_txts,
            "spf_present": spf_present,
            "tls_rpt_present": tls_txts,
        },
        "recommendations": recommendations,
        "notes": None,
    }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
