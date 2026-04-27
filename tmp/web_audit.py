#!/usr/bin/env python3
"""
auditor/web_audit.py — Passive web posture checks (GET/HEAD only).
Saves evidence, returns a normalized dict for summary.csv.
"""
from __future__ import annotations

import dataclasses as dc
import json, os, re, socket, ssl, time
from pathlib import Path
from typing import Optional, Dict, Any, Tuple, List

import httpx
from bs4 import BeautifulSoup

H_HTTP = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive; contact: dwhitfield@artisanhosting.net)"}

@dc.dataclass
class EvidenceWriter:
    root: Path
    def __post_init__(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
    def write_text(self, name: str, text: str) -> None:
        (self.root / name).write_text(text, encoding="utf-8", errors="ignore")
    def write_bytes(self, name: str, data: bytes) -> None:
        (self.root / name).write_bytes(data)
    def write_note(self, text: str) -> None:
        self.write_text("notes.md", f"{time.strftime('%F %T')} | {text}\n")

@dc.dataclass
class SummaryRow:
    # Schema mirrors the doc's summary.csv
    host: str
    domain: str
    is_wp: bool
    https_ok: bool
    redirects_http_to_https: bool
    hsts_present: bool
    hsts_value: str
    csp_present: bool
    xcto_present: bool
    refpol_present: bool
    xfo_present: bool
    permpol_present: bool
    corp_present: bool
    coep_present: bool
    coop_present: bool
    cookies_secure: str
    cookies_httponly: str
    cookies_samesite: str
    server_banner: str
    x_powered_by: str
    meta_generator_exposed: bool
    readme_present: bool
    license_present: bool
    xmlrpc_enabled: bool
    wp_login_noindex: bool
    wp_json_accessible: bool
    mixed_http_refs_count: int
    mixed_http_ref_hosts: str
    waf_vendor: str
    public_cache_headers_present: bool
    admin_login_cached: bool
    compression: str
    http_version: str
    ttfb_seconds: float
    cert_days_left: int
    psi_mobile_lcp: str
    psi_mobile_inp_or_tbt: str
    psi_mobile_cls: str
    psi_desktop_lcp: str
    psi_desktop_inp_or_tbt: str
    psi_desktop_cls: str
    title_len: int
    meta_desc_len: int
    has_canonical: bool
    robots_txt_ok: bool
    sitemap_ok: bool
    og_tags_present: bool
    twitter_card_present: bool
    hreflang_present: bool
    security_score_8: int
    performance_score_8: int
    seo_score_8: int
    overall_grade: str
    # optional error
    error: str = ""

def csv_headers_summary() -> list[str]:
    return [f.name for f in dc.fields(SummaryRow)]

def _fetch_head_and_get(client: httpx.Client, base_url: str, evidence: EvidenceWriter, stem: str) -> tuple[httpx.Response, httpx.Response]:
    r_head = client.head(base_url, headers=H_HTTP, follow_redirects=True, timeout=15)
    r_get  = client.get(base_url, headers=H_HTTP, follow_redirects=True, timeout=30)
    evidence.write_text(f"{stem}.headers.txt", "\n".join([f"{k}: {v}" for k, v in r_get.headers.items()]))
    evidence.write_text(f"{stem}.status.txt", f"HEAD={r_head.status_code} GET={r_get.status_code} url={r_get.url}")
    if r_get.content:
        evidence.write_bytes(f"{stem}.html", r_get.content)
    return r_head, r_get

def _time_to_first_byte(client: httpx.Client, url: str) -> float:
    start = time.perf_counter()
    with client.stream("GET", url, headers=H_HTTP, follow_redirects=True, timeout=30) as r:
        for _ in r.iter_raw(1):
            break
    return round(time.perf_counter() - start, 3)

def _tls_days_left(host: str, port: int = 443) -> int:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            cert = ssock.getpeercert()
    # Parse notAfter like 'Nov  5 12:00:00 2025 GMT'
    not_after = cert.get("notAfter")
    if not_after:
        expires_struct = time.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        expires_ts = time.mktime(expires_struct)
        return int((expires_ts - time.time()) // 86400)
    return -1

def _detect_waf_vendor(h: httpx.Headers) -> str:
    hay = " ".join([f"{k}:{v}".lower() for k, v in h.items()])
    if "cf-ray" in hay or "server: cloudflare" in hay: return "cloudflare"
    if "x-sucuri-id" in hay: return "sucuri"
    if "x-akamai" in hay or "akamai-" in hay: return "akamai"
    if "fastly" in hay: return "fastly"
    return "unknown"

def _cookie_flags_summary(set_cookies: list[str]) -> tuple[str,str,str]:
    if not set_cookies:
        return ("unknown","unknown","unknown")
    sec = []
    httponly = []
    samesite = []
    for c in set_cookies:
        lc = c.lower()
        sec.append("secure" in lc)
        httponly.append("httponly" in lc)
        if "samesite=strict" in lc: samesite.append("strict")
        elif "samesite=lax" in lc: samesite.append("lax")
        elif "samesite=none" in lc: samesite.append("none")
        else: samesite.append("")
    def summarize(bools: list[bool]) -> str:
        if all(bools): return "all"
        if any(bools): return "some"
        return "none"
    def summarize_ss(vals: list[str]) -> str:
        if vals and all(v=="strict" for v in vals): return "all_strict"
        if vals and all(v=="lax" for v in vals): return "all_lax"
        uniq = {v for v in vals if v}
        if not uniq: return "unknown"
        if len(uniq)==1: return list(uniq)[0]
        return "mixed"
    return summarize(sec), summarize(httponly), summarize_ss(samesite)

def audit_host(url: str, domain: str, is_wp_hint: str|bool, evidence: EvidenceWriter, enable_psi: bool=False) -> SummaryRow:
    host = url.split("://", 1)[-1].split("/", 1)[0]
    https_ok = False
    redirects_http_to_https = False
    hsts_present = False
    hsts_value = ""
    security_headers = {"csp_present": False, "xcto_present": False, "refpol_present": False, "xfo_present": False,
                        "permpol_present": False, "corp_present": False, "coep_present": False, "coop_present": False}
    cookies_secure = cookies_httponly = cookies_samesite = "unknown"
    server_banner = x_powered_by = ""
    meta_generator_exposed = False
    readme_present = license_present = False
    xmlrpc_enabled = wp_login_noindex = wp_json_accessible = False
    mixed_http_refs_count = 0
    mixed_http_ref_hosts = ""
    waf_vendor = "unknown"
    public_cache_headers_present = admin_login_cached = False
    compression = "unknown"
    http_version = "unknown"
    ttfb_seconds = -1.0
    cert_days_left = -1
    title_len = meta_desc_len = 0
    has_canonical = robots_txt_ok = sitemap_ok = og_tags_present = twitter_card_present = hreflang_present = False
    is_wp = False

    client = httpx.Client(http2=True, headers=H_HTTP)
    try:
        # HTTP -> HTTPS redirect check (HEAD preferred)
        try:
            r_http = client.head(f"http://{host}", follow_redirects=False, timeout=10)
            loc = r_http.headers.get("location","")
            redirects_http_to_https = (300 <= r_http.status_code < 400) and loc.startswith("https://")
            evidence.write_text("http.headers.txt", "\n".join([f"{k}: {v}" for k, v in r_http.headers.items()]))
        except Exception:
            pass

        # HTTPS reachability + evidence
        r_head, r_get = _fetch_head_and_get(client, f"https://{host}/", evidence, stem="root")
        https_ok = (200 <= r_get.status_code < 400)

        # Basic header values
        server_banner = r_get.headers.get("server","")
        x_powered_by  = r_get.headers.get("x-powered-by","")

        # HSTS
        hsts_value = r_get.headers.get("strict-transport-security","")
        hsts_present = bool(hsts_value)

        # Security headers presence
        if r_get.headers.get("content-security-policy"): security_headers["csp_present"] = True
        if r_get.headers.get("x-content-type-options"):   security_headers["xcto_present"] = True
        if r_get.headers.get("referrer-policy"):          security_headers["refpol_present"] = True
        if r_get.headers.get("x-frame-options"):          security_headers["xfo_present"] = True
        if r_get.headers.get("permissions-policy"):       security_headers["permpol_present"] = True
        if r_get.headers.get("cross-origin-resource-policy"): security_headers["corp_present"] = True
        if r_get.headers.get("cross-origin-embedder-policy"): security_headers["coep_present"] = True
        if r_get.headers.get("cross-origin-opener-policy"):   security_headers["coop_present"] = True

        # Cookies flags
        set_cookies = r_get.headers.get_list("set-cookie")
        cookies_secure, cookies_httponly, cookies_samesite = _cookie_flags_summary(set_cookies)

        # HTML parsing
        html = r_get.text or ""
        evidence.write_text("root.html", html)  # already written in _fetch_head_and_get but ensure text version
        soup = BeautifulSoup(html, "html.parser")

        # WP detection + generator exposure
        body_txt = html.lower()
        is_wp = ("wp-content/" in body_txt) or ("wp-includes/" in body_txt) or ('name="generator"' in body_txt and "wordpress" in body_txt)
        meta_gen = soup.find("meta", attrs={"name": re.compile("^generator$", re.I)})
        if meta_gen and ("wordpress" in (meta_gen.get("content","").lower())):
            meta_generator_exposed = True

        # Default files
        try:
            r_readme = client.head(f"https://{host}/readme.html", follow_redirects=True, timeout=10)
            readme_present = (r_readme.status_code == 200)
            evidence.write_text("readme.headers.txt", "\n".join([f"{k}: {v}" for k, v in r_readme.headers.items()]))
        except Exception:
            pass
        try:
            r_license = client.head(f"https://{host}/license.txt", follow_redirects=True, timeout=10)
            license_present = (r_license.status_code == 200)
            evidence.write_text("license.headers.txt", "\n".join([f"{k}: {v}" for k, v in r_license.headers.items()]))
        except Exception:
            pass

        # WordPress touchpoints
        try:
            r_login_h, r_login_g = _fetch_head_and_get(client, f"https://{host}/wp-login.php", evidence, "wp-login")
            if r_login_g.status_code < 500 and r_login_g.text:
                soup_login = BeautifulSoup(r_login_g.text, "html.parser")
                # look for meta robots noindex or x-robots-tag header
                noindex_meta = soup_login.find("meta", attrs={"name": re.compile("^robots$", re.I)})
                wp_login_noindex = (noindex_meta and ("noindex" in (noindex_meta.get("content","").lower())))
                # admin_login_cached heuristic
                cc = r_login_g.headers.get("cache-control","").lower()
                pragma = r_login_g.headers.get("pragma","").lower()
                admin_login_cached = not (("no-cache" in cc) or ("no-store" in cc) or ("private" in cc) or ("no-cache" in pragma))
        except Exception:
            pass
        try:
            r_xmlrpc = client.get(f"https://{host}/xmlrpc.php", headers=H_HTTP, follow_redirects=True, timeout=15)
            evidence.write_text("xmlrpc.body.txt", r_xmlrpc.text)
            xmlrpc_enabled = ("accepts POST requests only" in r_xmlrpc.text) or ("XML-RPC server accepts POST requests only" in r_xmlrpc.text)
        except Exception:
            pass
        try:
            r_wpjson = client.get(f"https://{host}/wp-json/", headers=H_HTTP, follow_redirects=True, timeout=10)
            wp_json_accessible = (r_wpjson.status_code == 200)
        except Exception:
            pass
        try:
            r_uploads = client.get(f"https://{host}/wp-content/uploads/", headers=H_HTTP, follow_redirects=True, timeout=10)
            evidence.write_text("uploads.body.txt", r_uploads.text)
            uploads_dirlisting = (r_uploads.status_code == 200 and "index of" in (r_uploads.text.lower()))
        except Exception:
            uploads_dirlisting = False
        evidence.write_text("uploads.headers.txt", f"dirlisting={uploads_dirlisting}")

        # Mixed content on root
        http_refs = re.findall(r'http://[a-z0-9][^"\'<> \t\r\n]+', html, flags=re.I)
        http_refs = [u for u in http_refs if not re.search(r"(localhost|127\.0\.0\.1)", u, flags=re.I)]
        mixed_http_refs_count = len(set(http_refs))
        if mixed_http_refs_count:
            # optional: top offending hosts (semicolon list)
            hosts = sorted({u.split('/')[2] for u in http_refs})
            mixed_http_ref_hosts = ";".join(hosts[:10])

        # WAF/CDN & caching
        waf_vendor = _detect_waf_vendor(r_get.headers)
        public_cache_headers_present = any(k in r_get.headers for k in ["cache-control","etag","age","cf-cache-status"])

        # Delivery hints
        enc = r_get.headers.get("content-encoding","").lower()
        compression = "br" if "br" in enc else ("gzip" if "gzip" in enc else ("none" if enc=="" else enc))
        # http version
        hv = getattr(r_get, "http_version", "HTTP/1.1")
        http_version = "h2" if "2" in hv else "1.1"
        # h3 hint via alt-svc
        if "h3" in r_get.headers.get("alt-svc",""):
            http_version = "h3"

        # TTFB
        ttfb_seconds = _time_to_first_byte(client, f"https://{host}/")

        # TLS expiry days
        try:
            cert_days_left = _tls_days_left(host, 443)
        except Exception:
            cert_days_left = -1

        # SEO basics on root
        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        title_len = len(title)
        meta_desc = ""
        mdesc = soup.find("meta", attrs={"name": re.compile("^description$", re.I)})
        if mdesc: meta_desc = mdesc.get("content","").strip()
        meta_desc_len = len(meta_desc)
        has_canonical = bool(soup.find("link", attrs={"rel": re.compile("canonical", re.I)}))
        og_tags_present = bool(soup.find("meta", attrs={"property": re.compile("^og:", re.I)}))
        twitter_card_present = bool(soup.find("meta", attrs={"name": re.compile("^twitter:card$", re.I)}))
        hreflang_present = bool(soup.find("link", attrs={"rel": re.compile("^alternate$", re.I), "hreflang": True}))

        # robots.txt + sitemap
        robots_txt_ok = False
        sitemap_ok = False
        try:
            r_robots = client.get(f"https://{host}/robots.txt", headers=H_HTTP, follow_redirects=True, timeout=10)
            if r_robots.status_code == 200:
                robots_txt_ok = True
                evidence.write_text("robots.txt", r_robots.text)
        except Exception:
            pass
        # sitemap.xml or wp-sitemap.xml
        for sm in ("/sitemap.xml","/wp-sitemap.xml"):
            try:
                r_sm = client.get(f"https://{host}{sm}", headers=H_HTTP, follow_redirects=True, timeout=10)
                if r_sm.status_code == 200:
                    sitemap_ok = True
                    evidence.write_text(sm.strip('/'), r_sm.text)
                    break
            except Exception:
                pass

        # Simple scoring (0–8) — heuristic mapping to the doc's rubric
        security_score = 0
        if hsts_present: security_score += 1
        if security_headers["csp_present"]: security_score += 2
        if not meta_generator_exposed: security_score += 1
        if not readme_present and not license_present: security_score += 1
        if cookies_secure == "all" and cookies_httponly == "all": security_score += 1
        if waf_vendor in {"cloudflare","sucuri","akamai","fastly"}: security_score += 1
        if not xmlrpc_enabled: security_score += 1
        performance_score = 0  # (fill via PSI mapping if available later)
        seo_score = 0  # (basic heuristics, optional to expand)

        overall_grade = "Green" if (security_score >= 6) else ("Yellow" if security_score >= 3 else "Red")

        # PSI (optional; only if env key is set and enable_psi)
        psi_mobile_lcp = psi_mobile_inp_or_tbt = psi_mobile_cls = ""
        psi_desktop_lcp = psi_desktop_inp_or_tbt = psi_desktop_cls = ""
        if enable_psi and os.getenv("PAGESPEED_API_KEY"):
            try:
                from auditor.psi_client import fetch_psi_metrics
                metrics = fetch_psi_metrics(url)
                psi_mobile_lcp, psi_mobile_inp_or_tbt, psi_mobile_cls = metrics.get("mobile", ["","",""])
                psi_desktop_lcp, psi_desktop_inp_or_tbt, psi_desktop_cls = metrics.get("desktop", ["","",""])
            except Exception as _e:
                pass

        return SummaryRow(
            host=host, domain=domain, is_wp=is_wp,
            https_ok=https_ok, redirects_http_to_https=redirects_http_to_https,
            hsts_present=hsts_present, hsts_value=hsts_value,
            csp_present=security_headers["csp_present"],
            xcto_present=security_headers["xcto_present"],
            refpol_present=security_headers["refpol_present"],
            xfo_present=security_headers["xfo_present"],
            permpol_present=security_headers["permpol_present"],
            corp_present=security_headers["corp_present"],
            coep_present=security_headers["coep_present"],
            coop_present=security_headers["coop_present"],
            cookies_secure=cookies_secure, cookies_httponly=cookies_httponly, cookies_samesite=cookies_samesite,
            server_banner=server_banner, x_powered_by=x_powered_by, meta_generator_exposed=meta_generator_exposed,
            readme_present=readme_present, license_present=license_present,
            xmlrpc_enabled=xmlrpc_enabled, wp_login_noindex=wp_login_noindex, wp_json_accessible=wp_json_accessible,
            mixed_http_refs_count=mixed_http_refs_count, mixed_http_ref_hosts=mixed_http_ref_hosts,
            waf_vendor=waf_vendor, public_cache_headers_present=public_cache_headers_present, admin_login_cached=admin_login_cached,
            compression=compression, http_version=http_version, ttfb_seconds=ttfb_seconds, cert_days_left=cert_days_left,
            psi_mobile_lcp=psi_mobile_lcp, psi_mobile_inp_or_tbt=psi_mobile_inp_or_tbt, psi_mobile_cls=psi_mobile_cls,
            psi_desktop_lcp=psi_desktop_lcp, psi_desktop_inp_or_tbt=psi_desktop_inp_or_tbt, psi_desktop_cls=psi_desktop_cls,
            title_len=title_len, meta_desc_len=meta_desc_len, has_canonical=has_canonical,
            robots_txt_ok=robots_txt_ok, sitemap_ok=sitemap_ok, og_tags_present=og_tags_present,
            twitter_card_present=twitter_card_present, hreflang_present=hreflang_present,
            security_score_8=security_score, performance_score_8=performance_score, seo_score_8=seo_score,
            overall_grade=overall_grade
        )
    finally:
        client.close()
