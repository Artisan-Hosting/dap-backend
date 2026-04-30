#!/usr/bin/env python3
"""Light external probe of public mail listeners."""

from __future__ import annotations

import json
import socket
import ssl
import sys
from typing import Any, Dict, Optional

try:
    import dns.resolver
except ImportError as exc:
    raise SystemExit(json.dumps({
        "test_id": "mail_server_probe",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install dnspython >= 2.4 in the environment"],
        "notes": f"Missing dependency: {exc}",
    }))

SMTP_PORTS = [
    (25, "smtp", False),
    (465, "smtps", True),
    (587, "submission", False),
    (2525, "alt-submission", False),
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


def load_input() -> Dict[str, Any]:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_domain(payload: Dict[str, Any]) -> str:
    for fact in payload.get("facts", []):
        if fact.get("entity") == "service_profile":
            attrs = fact.get("attrs", {})
            if attrs.get("role") == "mail":
                return payload.get("target", "")
    return payload.get("target", "")


def get_resolver():
    """Create a DNS resolver configured to use Cloudflare DNS."""
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']  # Cloudflare DNS servers
    resolver.lifetime = 3.0
    resolver.timeout = 2.0
    return resolver


def query_mx_records(domain: str) -> list[tuple[int, str]]:
    try:
        resolver = get_resolver()
        records = [
            (int(record.preference), str(record.exchange).rstrip(".").lower())
            for record in resolver.resolve(domain, "MX")
        ]
    except Exception:
        return []
    return sorted(records, key=lambda item: (item[0], item[1]))


def query_addresses(name: str) -> list[str]:
    addresses: list[str] = []
    resolver = get_resolver()
    for record_type in ("A", "AAAA"):
        try:
            for record in resolver.resolve(name, record_type):
                addresses.append(record.to_text())
        except Exception:
            continue
    return sorted(dict.fromkeys(addresses))


def is_same_domain_or_subdomain(candidate: str, domain: str) -> bool:
    candidate = candidate.rstrip(".").lower()
    domain = domain.rstrip(".").lower()
    return candidate == domain or candidate.endswith(f".{domain}")


def infer_provider(mx_host: str, domain: str) -> str:
    lower = mx_host.lower()
    for provider, patterns in PROVIDER_PATTERNS:
        if any(lower == pattern or lower.endswith(pattern) for pattern in patterns):
            return provider
    if is_same_domain_or_subdomain(mx_host, domain):
        return "custom-self-hosted"
    return mx_host


def read_smtp_block(file_obj) -> list[str]:
    lines: list[str] = []
    while True:
        raw = file_obj.readline()
        if not raw:
            break
        line = raw.decode("utf-8", "ignore").strip()
        if not line:
            break
        lines.append(line)
        if len(line) < 4 or line[3] != "-":
            break
    return lines


def smtp_probe(host: str, port: int, implicit_tls: bool) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "host": host,
        "port": port,
        "service": next(name for candidate_port, name, _ in SMTP_PORTS if candidate_port == port),
        "implicit_tls": implicit_tls,
        "reachable": False,
        "banner": [],
        "capabilities": [],
        "supports_starttls": False,
        "supports_auth": False,
        "error": None,
    }
    try:
        with socket.create_connection((host, port), timeout=3) as sock:
            sock.settimeout(3)
            stream = sock
            if implicit_tls:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                stream = context.wrap_socket(sock, server_hostname=host)
                stream.settimeout(3)

            file_obj = stream.makefile("rwb")
            banner = read_smtp_block(file_obj)
            result["banner"] = banner
            result["reachable"] = True

            file_obj.write(b"EHLO artisan-dap.invalid\r\n")
            file_obj.flush()
            ehlo_lines = read_smtp_block(file_obj)
            capabilities = [line[4:].strip() for line in ehlo_lines if line.startswith("250") and len(line) > 4]
            result["capabilities"] = capabilities
            result["supports_starttls"] = any("STARTTLS" in capability.upper() for capability in capabilities)
            result["supports_auth"] = any(capability.upper().startswith("AUTH") for capability in capabilities)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def main() -> None:
    payload = load_input()
    domain = resolve_domain(payload)
    if not domain:
        json.dump({
            "test_id": "mail_server_probe",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Ensure discovery captured a mail service profile or the target domain"],
            "notes": "Unable to determine domain for mail transport probe",
        }, sys.stdout)
        return

    mx_records = query_mx_records(domain)
    mx_hosts = [host for _, host in mx_records]
    host_details = [
        {
            "preference": preference,
            "host": host,
            "addresses": query_addresses(host),
            "provider_guess": infer_provider(host, domain),
        }
        for preference, host in mx_records[:2]
    ]

    probes = []
    for _, host in mx_records[:2]:
        for port, _, implicit_tls in SMTP_PORTS:
            probes.append(smtp_probe(host, port, implicit_tls))

    any_reachable = any(probe["reachable"] for probe in probes)
    tls_capable = any(
        probe["reachable"] and (probe["implicit_tls"] or probe["supports_starttls"])
        for probe in probes
    )

    status = "pass"
    severity = "informational"
    recommendations: list[str] = []
    notes: Optional[str] = None

    if not mx_records:
        status = "warn"
        severity = "medium"
        recommendations.append("Publish MX records for the domain if it is expected to receive mail")
    elif not any_reachable:
        status = "info"
        severity = "informational"
        notes = "No common SMTP listeners responded from this vantage point"
        recommendations.append(
            "If this domain is expected to receive or submit mail directly, verify public SMTP listeners are reachable"
        )
    elif not tls_capable:
        status = "warn"
        severity = "low"
        recommendations.append("Enable STARTTLS or SMTPS on externally reachable SMTP listeners")

    output = {
        "test_id": "mail_server_probe",
        "target": domain,
        "status": status,
        "severity": severity,
        "evidence": {
            "mx_hosts": mx_hosts,
            "mx_host_details": host_details,
            "probed_ports": [port for port, _, _ in SMTP_PORTS],
            "probes": probes,
            "tls_capable_listener_observed": tls_capable,
        },
        "recommendations": sorted(set(recommendations)),
        "notes": notes,
    }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
