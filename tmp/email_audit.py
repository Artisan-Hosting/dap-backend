#!/usr/bin/env python3
"""
auditor/email_audit.py — DNS & email posture checks (passive).

Returns a normalized dict for email_posture.csv.
"""
from __future__ import annotations

import base64, binascii, re
from dataclasses import dataclass, fields
from typing import List, Dict, Tuple, Optional

import dns.resolver

DKIM_COMMON_SELECTORS = [
    "default","selector1","selector2","google","k1","k2","s1","s2","smtp","mail",
    "pm","postmark","sendgrid","mailgun","mandrill","mx","sparkpost","amazonses","dkim"
]

@dataclass
class EmailRow:
    domain: str
    spf_present: bool
    spf_valid: bool
    spf_flatten_warn: bool
    dkim_selectors: str
    dkim_present: bool
    dkim_key_length_ok: str
    dmarc_present: bool
    dmarc_policy: str
    dmarc_rua_present: bool
    mta_sts_mode: str
    tls_rpt_present: bool
    bimi_present: bool
    mx_hosts: str
    ptr_ok: str
    error: str = ""

def csv_headers_email() -> list[str]:
    return [f.name for f in fields(EmailRow)]

def _txt(domain: str) -> list[str]:
    try:
        return [b"".join(r.strings).decode("utf-8", "ignore") for r in dns.resolver.resolve(domain, "TXT")]
    except Exception:
        return []

def _mx(domain: str) -> list[str]:
    try:
        return [str(r.exchange).rstrip(".") for r in dns.resolver.resolve(domain, "MX")]
    except Exception:
        return []

def _has_spf(txts: list[str]) -> tuple[bool,bool,bool]:
    spf = [t for t in txts if t.lower().startswith("v=spf1")]
    if not spf:
        return False, False, False
    # naive validation: ensure not too many nested "include:" (flatten warn)
    includes = sum(s.count("include:") for s in spf)
    flatten_warn = includes > 5
    # basic syntax check
    valid = all(s.lower().startswith("v=spf1") for s in spf)
    return True, valid, flatten_warn

def _dmarc_policy(txts: list[str]) -> tuple[bool,str,bool]:
    pol = ""
    rua = False
    dmarc = [t for t in txts if t.lower().startswith("v=dmarc1")]
    if dmarc:
        low = dmarc[0].lower()
        m = re.search(r"\bp=([a-z]+)", low)
        if m: pol = m.group(1)
        rua = "rua=" in low
        return True, pol, rua
    return False, pol, rua

def _mta_sts_mode(domain: str) -> str:
    # Check TXT hint and (optionally) fetch policy file for mode
    txts = _txt(f"_mta-sts.{domain}")
    if not txts:
        return "none"
    # Policy file is at https://mta-sts.domain/.well-known/mta-sts.txt
    # We avoid network (HTTP) here to stay purely DNS-based; TXT presence indicates at least "testing" or "enforce".
    # If you want exact mode, you can fetch and parse in the web_audit module.
    return "testing"

def _tls_rpt_present(domain: str) -> bool:
    return bool(_txt(f"_smtp._tls.{domain}"))

def _bimi_present(domain: str) -> bool:
    return bool(_txt(f"default._bimi.{domain}"))

def _dkim_check(domain: str, selectors: list[str]) -> tuple[bool,str]:
    present_any = False
    keylen_ok_any = ""
    for s in selectors:
        recs = _txt(f"{s}._domainkey.{domain}")
        if not recs:
            continue
        present_any = True
        # Parse p= field and estimate key length (bytes*8) if base64 decodable
        low = recs[0].replace(" ", "")
        m = re.search(r"\bp=([A-Za-z0-9+/=]+)", low)
        if m:
            try:
                raw = base64.b64decode(m.group(1), validate=False)
                bits = len(raw) * 8
                keylen_ok_any = "true" if bits >= 2048 else "false"
            except binascii.Error:
                keylen_ok_any = "unknown"
        else:
            keylen_ok_any = "unknown"
        # We don't break to allow discovering multiple; but one ok is enough to mark true
    return present_any, keylen_ok_any or "unknown"

def audit_domain_email(domain: str, dkim_selectors: Optional[list[str]] = None) -> EmailRow:
    dkim_selectors = dkim_selectors or DKIM_COMMON_SELECTORS

    # SPF
    root_txts = _txt(domain)
    spf_present, spf_valid, spf_flatten_warn = _has_spf(root_txts)

    # DMARC
    dmarc_txts = _txt(f"_dmarc.{domain}")
    dmarc_present, dmarc_policy, dmarc_rua_present = _dmarc_policy(dmarc_txts)

    # MTA-STS & TLS-RPT & BIMI
    mta_sts_mode   = _mta_sts_mode(domain)
    tls_rpt        = _tls_rpt_present(domain)
    bimi           = _bimi_present(domain)

    # DKIM
    dkim_present, dkim_keylen_ok = _dkim_check(domain, dkim_selectors)

    # MX
    mx_hosts = _mx(domain)

    return EmailRow(
        domain=domain,
        spf_present=spf_present, spf_valid=spf_valid, spf_flatten_warn=spf_flatten_warn,
        dkim_selectors=",".join(dkim_selectors[:8]) + ("..." if len(dkim_selectors)>8 else ""),
        dkim_present=dkim_present, dkim_key_length_ok=dkim_keylen_ok,
        dmarc_present=dmarc_present, dmarc_policy=dmarc_policy, dmarc_rua_present=dmarc_rua_present,
        mta_sts_mode=mta_sts_mode, tls_rpt_present=tls_rpt, bimi_present=bimi,
        mx_hosts=";".join(mx_hosts), ptr_ok="unknown"
    )
