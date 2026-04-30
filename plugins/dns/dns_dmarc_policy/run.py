#!/usr/bin/env python3
"""Email posture observation.

Leverages external DNS and a light HTTPS fetch of the MTA-STS policy file to
inspect DMARC, SPF, DKIM, TLS-RPT, MTA-STS, BIMI, and MX/provider posture for
the target domain.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

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

from shared.parallel import parallel_map

COMMON_DKIM_SELECTORS = [
    "default",
    "selector1",
    "selector2",
    "google",
    "k1",
    "k2",
    "s1",
    "s2",
    "smtp",
    "mail",
    "pm",
    "postmark",
    "sendgrid",
    "mailgun",
    "mandrill",
    "mx",
    "sparkpost",
    "amazonses",
    "dkim",
]

PROVIDER_PATTERNS = [
    ("google-workspace", ["aspmx.l.google.com", ".google.com", ".googlemail.com"]),
    ("microsoft-365", [".mail.protection.outlook.com", ".outlook.com"]),
    ("zoho-mail", [".zoho.com", ".zohomail.com"]),
    ("fastmail", [".messagingengine.com"]),
    ("mimecast", [".mimecast.com"]),
    ("proofpoint", [".pphosted.com"]),
    ("mailgun", [".mailgun.org"]),
    ("sendgrid", [".sendgrid.net"]),
    ("proton-mail", [".protonmail.ch", ".protonmail.com"]),
    ("icloud-mail", [".icloud.com", ".me.com"]),
    ("amazon-ses", [".amazonses.com", ".awsapps.com"]),
]

USER_AGENT = "ArtisanPassiveAuditor/0.1 (+passive)"


def load_input() -> Dict[str, Any]:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_domain(payload: Dict[str, Any]) -> str:
    for fact in payload.get("facts", []):
        entity = fact.get("entity")
        attrs = fact.get("attrs", {})
        if entity == "service_profile" and attrs.get("role") == "mail":
            return payload.get("target", "")
        if entity == "dns_record":
            name = attrs.get("name", "")
            if attrs.get("type") == "TXT" and name.startswith("_dmarc"):
                return attrs.get("name", "").split("_dmarc.", 1)[-1] or payload.get("target", "")
    return payload.get("target", "")


def get_resolver():
    """Create a DNS resolver configured to use Cloudflare DNS."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']  # Cloudflare DNS servers
    resolver.lifetime = 3.0
    resolver.timeout = 2.0
    return resolver


def query_txt(name: str) -> list[str]:
    try:
        resolver = get_resolver()
        return [b"".join(record.strings).decode("utf-8", "ignore") for record in resolver.resolve(name, "TXT")]
    except Exception:
        return []


def query_mx(name: str) -> list[str]:
    try:
        resolver = get_resolver()
        return [str(record.exchange).rstrip(".").lower() for record in resolver.resolve(name, "MX")]
    except Exception:
        return []


def query_addresses(name: str) -> list[str]:
    def resolve(record_type: str) -> list[str]:
        try:
            resolver = get_resolver()
            return [record.to_text() for record in resolver.resolve(name, record_type)]
        except Exception:
            return []

    addresses = parallel_map(("A", "AAAA"), resolve)
    flattened = [address for group in addresses for address in group]
    return sorted(dict.fromkeys(flattened))


def is_same_domain_or_subdomain(candidate: str, domain: str) -> bool:
    candidate = candidate.rstrip(".").lower()
    domain = domain.rstrip(".").lower()
    return candidate == domain or candidate.endswith(f".{domain}")


def infer_mail_provider(mx_hosts: list[str], domain: str) -> Dict[str, Optional[str]]:
    for host in mx_hosts:
        lower = host.lower()
        for provider, patterns in PROVIDER_PATTERNS:
            if any(lower == pattern or lower.endswith(pattern) for pattern in patterns):
                return {
                    "name": provider,
                    "evidence_host": host,
                }

    if any(is_same_domain_or_subdomain(host, domain) for host in mx_hosts):
        same_domain = next(host for host in mx_hosts if is_same_domain_or_subdomain(host, domain))
        return {
            "name": "custom-self-hosted",
            "evidence_host": same_domain,
        }

    if mx_hosts:
        return {
            "name": mx_hosts[0],
            "evidence_host": mx_hosts[0],
        }

    return {"name": None, "evidence_host": None}


def spf_posture(txts: list[str]) -> Dict[str, Any]:
    spf = [txt for txt in txts if txt.lower().startswith("v=spf1")]
    all_mechanism = None
    if spf:
        match = re.search(r"(?:^|\s)([+~?-]?all)\b", spf[0], re.IGNORECASE)
        if match:
            all_mechanism = match.group(1).lower()

    return {
        "records": spf,
        "present": bool(spf),
        "valid": len(spf) == 1,
        "multiple_records": len(spf) > 1,
        "flatten_warn": sum(entry.count("include:") for entry in spf) > 5,
        "all_mechanism": all_mechanism,
    }


def dkim_posture(domain: str) -> Dict[str, Any]:
    discovered: list[str] = []
    keylen_ok = "unknown"
    records: dict[str, str] = {}

    selector_results = parallel_map(
        COMMON_DKIM_SELECTORS,
        lambda selector: (selector, query_txt(f"{selector}._domainkey.{domain}")),
    )

    for selector, txt_records in selector_results:
        if not txt_records:
            continue

        record = txt_records[0]
        records[selector] = record
        discovered.append(selector)

        compact = record.replace(" ", "")
        match = re.search(r"\bp=([A-Za-z0-9+/=]+)", compact)
        if not match:
            keylen_ok = "unknown"
            continue

        try:
            bits = len(base64.b64decode(match.group(1), validate=False)) * 8
        except binascii.Error:
            keylen_ok = "unknown"
            continue

        if bits >= 2048:
            keylen_ok = "true"
        elif keylen_ok != "true":
            keylen_ok = "false"

    return {
        "present": bool(discovered),
        "key_length_ok": keylen_ok,
        "discovered_selectors": discovered,
        "records": records,
    }


def parse_dmarc(dmarc_txts: list[str]) -> Dict[str, Any]:
    for entry in dmarc_txts:
        lower = entry.lower()
        if not lower.startswith("v=dmarc1"):
            continue

        policy_match = re.search(r"\bp=([a-z]+)", lower)
        return {
            "present": True,
            "policy": policy_match.group(1) if policy_match else "",
            "rua_present": "rua=" in lower,
            "record": entry,
        }

    return {
        "present": False,
        "policy": "",
        "rua_present": False,
        "record": None,
    }


def parse_tls_rpt(txts: list[str]) -> Dict[str, Any]:
    record = next((txt for txt in txts if txt.lower().startswith("v=tlsrptv1")), None)
    return {
        "present": record is not None,
        "record": record,
    }


def parse_bimi(txts: list[str]) -> Dict[str, Any]:
    record = next((txt for txt in txts if txt.lower().startswith("v=bimi1")), None)
    return {
        "present": record is not None,
        "record": record,
    }


def fetch_mta_sts_policy(domain: str) -> Dict[str, Any]:
    dns_txts = query_txt(f"_mta-sts.{domain}")
    dns_record = next((txt for txt in dns_txts if txt.lower().startswith("v=stsv1")), None)
    policy_url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    posture: Dict[str, Any] = {
        "dns_txts": dns_txts,
        "dns_present": dns_record is not None,
        "policy_url": policy_url,
        "policy_http_status": None,
        "policy_present": False,
        "policy_valid": False,
        "policy_fields": {
            "version": None,
            "mode": None,
            "mx": [],
            "max_age": None,
        },
        "fetch_error": None,
    }
    if dns_record is None:
        return posture

    request = urllib.request.Request(policy_url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            body = response.read().decode("utf-8", "ignore")
            posture["policy_http_status"] = getattr(response, "status", None)
    except urllib.error.HTTPError as exc:
        posture["policy_http_status"] = exc.code
        posture["fetch_error"] = str(exc)
        return posture
    except Exception as exc:
        posture["fetch_error"] = str(exc)
        return posture

    posture["policy_present"] = bool(body.strip())
    fields = posture["policy_fields"]
    for raw_line in body.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = [part.strip() for part in line.split(":", 1)]
        key = key.lower()
        if key == "version":
            fields["version"] = value
        elif key == "mode":
            fields["mode"] = value.lower()
        elif key == "mx":
            fields["mx"].append(value.lower())
        elif key == "max_age":
            fields["max_age"] = value

    posture["policy_valid"] = (
        posture["policy_http_status"] == 200
        and fields["version"] == "STSv1"
        and fields["mode"] in {"enforce", "testing", "none"}
        and bool(fields["max_age"])
    )
    return posture


def build_mx_host_details(mx_hosts: list[str], domain: str) -> list[Dict[str, Any]]:
    return parallel_map(
        mx_hosts,
        lambda host: {
            "host": host,
            "addresses": query_addresses(host),
            "provider_guess": infer_mail_provider([host], domain).get("name"),
        },
    )


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
            "recommendations": ["Ensure discovery captured a mail service profile or the target domain"],
            "notes": "Unable to determine domain for email posture audit",
        }, sys.stdout)
        return

    initial_queries = dict(
        parallel_map(
            [
                ("dmarc", f"_dmarc.{domain}"),
                ("spf", domain),
                ("mx", domain),
                ("tls_rpt", f"_smtp._tls.{domain}"),
                ("bimi", f"default._bimi.{domain}"),
            ],
            lambda item: (
                item[0],
                query_mx(item[1]) if item[0] == "mx" else query_txt(item[1]),
            ),
        )
    )

    dmarc_txts = initial_queries["dmarc"]
    spf_txts = initial_queries["spf"]
    mx_hosts = initial_queries["mx"]
    tls_rpt_txts = initial_queries["tls_rpt"]
    bimi_txts = initial_queries["bimi"]

    dmarc = parse_dmarc(dmarc_txts)
    spf = spf_posture(spf_txts)
    dkim = dkim_posture(domain)
    tls_rpt = parse_tls_rpt(tls_rpt_txts)
    bimi = parse_bimi(bimi_txts)
    mta_sts = fetch_mta_sts_policy(domain)
    provider = infer_mail_provider(mx_hosts, domain)
    mx_host_details = build_mx_host_details(mx_hosts, domain)

    status = "pass"
    severity = "informational"
    recommendations: list[str] = []

    def escalate(next_status: str, next_severity: str) -> None:
        nonlocal status, severity
        severity_rank = {
            "informational": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        status_rank = {
            "pass": 0,
            "info": 1,
            "warn": 2,
            "fail": 3,
            "error": 4,
        }
        if status_rank[next_status] > status_rank[status]:
            status = next_status
        if severity_rank[next_severity] > severity_rank[severity]:
            severity = next_severity

    if not mx_hosts:
        escalate("warn", "medium")
        recommendations.append("Publish MX records for the domain if it is expected to receive mail")

    if not dmarc["present"]:
        escalate("warn", "medium")
        recommendations.append("Publish a DMARC record (v=DMARC1)")
    elif dmarc["policy"] not in {"quarantine", "reject"}:
        escalate("warn", "medium")
        recommendations.append("Increase DMARC policy to quarantine or reject")

    if not spf["present"]:
        escalate("warn", "medium")
        recommendations.append("Publish an SPF record for the root domain")
    if spf["multiple_records"]:
        escalate("warn", "medium")
        recommendations.append("Consolidate SPF into a single TXT record")
    if spf["present"] and not spf["valid"]:
        recommendations.append("Validate SPF syntax and remove malformed entries")
    if spf["flatten_warn"]:
        recommendations.append("Reduce SPF include depth to avoid DNS lookup exhaustion")
    if spf["all_mechanism"] == "+all":
        escalate("fail", "high")
        recommendations.append("Remove +all from SPF because it authorizes every sender")

    if not dkim["present"]:
        escalate("warn", "medium")
        recommendations.append("Publish DKIM selectors for the active mail provider")
    elif dkim["key_length_ok"] == "false":
        escalate("warn", "medium")
        recommendations.append("Rotate DKIM keys to 2048-bit or stronger material")

    if not dmarc["rua_present"]:
        recommendations.append("Add rua reporting address for DMARC")
    if not tls_rpt["present"]:
        recommendations.append("Publish an SMTP TLS reporting record under _smtp._tls")

    if not mta_sts["dns_present"]:
        recommendations.append("Publish an _mta-sts TXT record and policy file")
    elif not mta_sts["policy_valid"]:
        escalate("warn", "medium")
        recommendations.append("Serve a valid MTA-STS policy file from mta-sts.<domain>/.well-known/mta-sts.txt")
    elif mta_sts["policy_fields"]["mode"] != "enforce":
        recommendations.append("Move MTA-STS policy mode to enforce after validation")

    if not bimi["present"]:
        recommendations.append("Consider publishing a BIMI record once DMARC enforcement is stable")

    output = {
        "test_id": "dns_dmarc_policy",
        "target": domain,
        "status": status,
        "severity": severity,
        "evidence": {
            "provider_guess": provider.get("name"),
            "provider_evidence_host": provider.get("evidence_host"),
            "mx_hosts": mx_hosts,
            "mx_host_details": mx_host_details,
            "spf_txts": spf_txts,
            "spf_present": spf["present"],
            "spf_valid": spf["valid"],
            "spf_multiple_records": spf["multiple_records"],
            "spf_flatten_warn": spf["flatten_warn"],
            "spf_all_mechanism": spf["all_mechanism"],
            "dmarc_txts": dmarc_txts,
            "dmarc_present": dmarc["present"],
            "dmarc_policy": dmarc["policy"],
            "dmarc_rua_present": dmarc["rua_present"],
            "dkim_checked_selectors": COMMON_DKIM_SELECTORS,
            "dkim_discovered_selectors": dkim["discovered_selectors"],
            "dkim_present": dkim["present"],
            "dkim_key_length_ok": dkim["key_length_ok"],
            "tls_rpt_present": tls_rpt["present"],
            "tls_rpt_txts": tls_rpt_txts,
            "mta_sts": mta_sts,
            "bimi_present": bimi["present"],
            "bimi_txts": bimi_txts,
            "ptr_ok": "unknown",
        },
        "recommendations": sorted(set(recommendations)),
        "notes": None,
    }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
