# Passive Web Audit — Work Breakdown (SOP)

> Scope: **GET/HEAD only.** No auth, no posting, no scanning/fuzzing, no load tests.

---

## 0) Inputs & Outputs

**Inputs**

* `targets.csv` → columns: `domain, url(optional), notes(optional), is_wp(hint optional)`
* (Domain Review only) `seed_domain`: base domain to enumerate subdomains passively.

**Outputs**

* `out/summary.csv` (one row per hostname/site)
* `out/<host>/...` evidence (headers, html, screenshots, PSI json or copied metrics)
* `out/email_posture.csv` (one row per domain for mail)
* `report.pdf` (compiled later)

---

## 1) Discovery (Domain Review package)

**Goal:** enumerate **live** hostnames without intrusive crawling.

**Steps**

1. **DNS Records** (A/AAAA/CNAME/MX/TXT/CAA):

   * `dig +short A example.com` (same for AAAA/CNAME/MX/TXT/CAA)
   * Save to `out/dns_<domain>.txt`
2. **Certificate Transparency (CT) names** (SANs):

   * Query public CT endpoints (passive). Save unique FQDNs to `out/ct_<domain>.txt`.
3. **Sitemaps/robots seeding (read-only):**

   * GET `https://example.com/robots.txt`, `.../sitemap.xml` (or wp-sitemap.xml). Add discovered hosts/paths.
4. **Host liveness + platform hint (HEAD/GET):**

   * `curl -sSIL https://host/` → capture status, headers, `Server`, `X-Powered-By`.
   * `curl -sSL https://host/` → capture HTML; look for WP markers (`wp-content/`, `generator`).
5. **HTTP→HTTPS behavior:**

   * `curl -sSI http://host/ -o http.headers.txt` and log if 301→HTTPS.

**Data fields to store (per host)**

```
host, http_status, https_status, redirects_http_to_https(bool), server_banner, x_powered_by,
is_wp_detected(bool), has_robots(bool), has_sitemap(bool)
```

---

## 2) Transport & TLS

**Goal:** confirm HTTPS availability and basic TLS posture (observational).

**Steps**

1. **HTTPS reachability:** `curl -o /dev/null -w "%{http_code}" https://host/`
2. **Cert expiry days:**

   * `echo | openssl s_client -servername host -connect host:443 2>/dev/null | openssl x509 -noout -dates`
   * Parse `notAfter` → epoch → days left.
3. **HSTS:** check `Strict-Transport-Security` on `https://host/` (and note `includeSubDomains`/`preload`).

**Data fields**

```
https_ok(bool), cert_days_left(int), hsts_present(bool), hsts_preload(bool), hsts_include_subdomains(bool)
```

---

## 3) HTTP Security Headers

**Goal:** presence/absence only (missing ≠ vuln, but maturity signal).

**Headers to capture (root document response)**

* `Content-Security-Policy`
* `Strict-Transport-Security`
* `X-Content-Type-Options`
* `Referrer-Policy`
* `X-Frame-Options` **and/or** `frame-ancestors` in CSP
* `Permissions-Policy`
* (Optional) cross-origin trio if relevant: `Cross-Origin-Resource-Policy`, `Cross-Origin-Opener-Policy`, `Cross-Origin-Embedder-Policy`

**Commands**

* `curl -sSIL https://host/ -o root.headers.txt`
* Parse header presence and raw value.

**Data fields**

```
csp_present(bool), csp_value,
hsts_present(bool), hsts_value,
xcto_present(bool),
refpol_present(bool), refpol_value,
xfo_present(bool), xfo_value,
permpol_present(bool), permpol_value,
corp_present(bool), coep_present(bool), coop_present(bool)
```

---

## 4) Cookies (observational)

**Goal:** if `Set-Cookie` is present on first response, check flags.

**Steps**

* From `root.headers.txt`, aggregate all `Set-Cookie` lines.
* For each cookie: flags `Secure`, `HttpOnly`, `SameSite=(Lax|Strict|None)`.
* If **no cookies set**, record `unknown` for flags.

**Data fields**

```
cookies_secure(all|some|none|unknown),
cookies_httponly(all|some|none|unknown),
cookies_samesite(all_strict|all_lax|mixed|none|unknown)
```

---

## 5) Exposure & Fingerprinting

**Goal:** reduce attacker intel.

**Checks**

* `X-Powered-By` present?
* Verbose `Server` (e.g., `Apache/2.4.6 (CentOS) PHP/5.6`)?
* `<meta name="generator" content="WordPress x.y">` in HTML?
* **Default files:** `/readme.html`, `/license.txt` (only GET headers).
* **Directory listing:** `https://host/wp-content/uploads/` (200 + “Index of”)

**Commands**

* `curl -sSIL https://host/readme.html`
* `curl -sSL https://host/ -o root.html`
* `grep -i 'name="generator"' root.html`

**Data fields**

```
server_banner, x_powered_by, meta_generator_exposed(bool),
readme_present(bool), license_present(bool),
uploads_dirlisting(bool|unknown)
```

---

## 6) WordPress-Specific Touchpoints

**Goal:** passive signals only.

**Checks**

* `is_wp_detected` by `wp-content/`, `wp-includes/`, or generator tag.
* `https://host/wp-login.php` (GET only):

  * `noindex` meta present? any mixed content?
* `https://host/xmlrpc.php` (GET only):

  * Body contains “XML-RPC server accepts POST requests only” → **enabled** (flag).
* `https://host/wp-json/` (GET): reachable? (No secrets expected.)

**Commands**

* `curl -sSIL https://host/wp-login.php -o wp-login.headers.txt; curl -sSL ... -o wp-login.html`
* `curl -sSIL https://host/xmlrpc.php -o xmlrpc.headers.txt; curl -sSL ... -o xmlrpc.body.txt`
* `grep -i 'noindex' wp-login.html`

**Data fields**

```
wp_login_noindex(bool), xmlrpc_enabled(bool), wp_json_accessible(bool)
```

---

## 7) Mixed Content & Asset Hygiene

**Goal:** count obvious `http://` references (non-local) on key pages.

**Steps**

* In `root.html`, count absolute `http://` URLs (exclude localhost/127.0.0.1).
* (Optional) record top offending hosts.

**Command**

* `grep -Eoi 'http://[a-z0-9][^"'\''<>[:space:]]+' root.html | grep -Evi '(localhost|127\.0\.0\.1)' | sort | uniq -c`

**Data fields**

```
mixed_http_refs_count(int), mixed_http_ref_hosts(json or semicolon list)
```

---

## 8) WAF/CDN & Caching

**Goal:** detect common fronting providers and caching posture.

**Checks**

* Headers suggesting WAF/CDN: `cf-ray`, `server: cloudflare`, `x-sucuri-id`, `x-akamai-*`, `fastly-*`, etc.
* Cache headers on public pages: `cache-control`, `etag`, `age`, `cf-cache-status`.
* **Ensure admin/login not cached** (wp-login headers should be no-cache).

**Data fields**

```
waf_vendor(cloudflare|sucuri|akamai|fastly|none|unknown),
public_cache_headers_present(bool), admin_login_cached(bool)
```

---

## 9) Performance (PSI + delivery basics)

**Goal:** record Core Web Vitals and key delivery hints.

**Steps**

1. **PageSpeed Insights** (manually via UI or API later):

   * Record **Mobile & Desktop**: LCP, INP (or TBT), CLS, and notable Opportunities.
2. **Delivery hints** (from headers):

   * `content-encoding` (br/gzip), `alt-svc` (h3), `server-timing` (optional).
3. **TTFB** (rough): `curl -w "%{time_starttransfer}" -o /dev/null -s https://host/`

**Data fields**

```
psi_mobile_lcp, psi_mobile_inp_or_tbt, psi_mobile_cls,
psi_desktop_lcp, psi_desktop_inp_or_tbt, psi_desktop_cls,
compression(br|gzip|none|unknown), http_version(h2|h3|1.1|unknown),
ttfb_seconds(float)
```

---

## 10) SEO Technical Basics

**Goal:** indexation controls and essentials (homepage only by default).

**Checks**

* `<title>` length; `<meta name="description">` length.
* `<link rel="canonical">` present?
* `robots.txt` reachable? Any `Disallow: /`?
* `sitemap.xml` reachable?
* Social: Open Graph tags (`og:title`, `og:description`, `og:image`), Twitter Card.
* Internationalization: `hreflang` links if multi-locale.

**Commands**

* Parse `root.html` with grep/sed/awk (or a lightweight HTML parser later).

**Data fields**

```
title_len, meta_desc_len, has_canonical(bool),
robots_txt_ok(bool), sitemap_ok(bool),
og_tags_present(bool), twitter_card_present(bool),
hreflang_present(bool)
```

---

## 11) Email Configuration & Deliverability (per domain)

**Goal:** validate DNS and alignment passively; optional signed test with permission.

**Checks**

* **SPF**: `dig TXT domain` → find SPF, check syntax/`redirect`/`include` depth.
* **DKIM**: client supplies selectors **or** detect common (`default`, `selector1`, vendor). `dig TXT selector._domainkey.domain`.
* **DMARC**: `dig TXT _dmarc.domain`.
* **MTA-STS**: `dig TXT _mta-sts.domain` + GET `https://mta-sts.domain/.well-known/mta-sts.txt`.
* **TLS-RPT**: `dig TXT _smtp._tls.domain`.
* **BIMI**: `dig TXT default._bimi.domain` (and VMC presence note).
* **MX/PTR**: `dig MX domain`; check STARTTLS on MX (observational via headers if possible); ensure outbound host PTR matches HELO domain (client input or optional test).

**Data fields**

```
spf_present(bool), spf_valid(bool), spf_flatten_warn(bool),
dkim_selectors(list), dkim_present(bool), dkim_key_length_ok(bool),
dmarc_present(bool), dmarc_policy(none|quarantine|reject), dmarc_rua_present(bool),
mta_sts_mode(none|testing|enforce), tls_rpt_present(bool),
bimi_present(bool), mx_hosts(list), ptr_ok(unknown|yes|no)
```

---

## 12) Accessibility (quick pass)

**Goal:** spot major blockers.

**Checks**

* Focus outlines visible, keyboard navigation works (manual note).
* Image `alt` on key images (spot check in HTML).
* Form labels present.
* Color contrast quick check (manual note or automated later).

**Data fields**

```
a11y_focus_visible(note), a11y_alt_present_on_key_images(yes/no/partial),
a11y_form_labels(yes/no/partial), a11y_contrast_note(text)
```

---

## 13) Scoring & Classification

**Security Score (0–8)**

* HSTS (1), CSP (2), No leakage (no generator/meta) (1), Defaults removed (readme/license) (1),
* Cookie hardening (Secure+HttpOnly when cookies are set) (1),
* WAF/CDN present (1),
* XML-RPC disabled/gated (1).

**Performance Score (0–8)**

* PSI thresholds + delivery hints (define exact rubric later).

**SEO Score (0–8)**

* robots/sitemap/canonical/schema/OG basics (define rubric later).

**Data fields**

```
security_score_8, performance_score_8, seo_score_8, overall_grade(Green|Yellow|Red)
```

---

## 14) Evidence Capture

**Always save:**

* `root.headers.txt`, `root.html`
* `wp-login.headers.txt` + `.html` (if WP), `xmlrpc.*`
* `uploads.headers.txt` + `.body.txt` (for dir listing check)
* `curl` one-liners used (log)
* PSI values (copy to `psi.json` or `psi_notes.txt`)
* DNS outputs (`dns_<domain>.txt`)

---

## 15) Automation Layout (suggested folders)

```
/audit/
  wp_passive_audit.sh
  seo_extract.sh
  email_posture.sh
  psi_notes.md (manual fill or API output)
  /out/
    summary.csv
    email_posture.csv
    <host>/
      root.headers.txt
      root.html
      wp-login.headers.txt
      wp-login.html
      xmlrpc.headers.txt
      xmlrpc.body.txt
      uploads.headers.txt
      uploads.body.txt
      psi_mobile.txt
      psi_desktop.txt
      notes.md
```

---

## 16) CSV Schemas

**`summary.csv`**

```
host,domain,is_wp,https_ok,redirects_http_to_https,hsts_present,hsts_value,csp_present,xcto_present,refpol_present,
xfo_present,permpol_present,corp_present,coep_present,coop_present,
cookies_secure,cookies_httponly,cookies_samesite,
server_banner,x_powered_by,meta_generator_exposed,readme_present,license_present,
xmlrpc_enabled,wp_login_noindex,wp_json_accessible,
mixed_http_refs_count,mixed_http_ref_hosts,
waf_vendor,public_cache_headers_present,admin_login_cached,
compression,http_version,ttfb_seconds,cert_days_left,
psi_mobile_lcp,psi_mobile_inp_or_tbt,psi_mobile_cls,psi_desktop_lcp,psi_desktop_inp_or_tbt,psi_desktop_cls,
title_len,meta_desc_len,has_canonical,robots_txt_ok,sitemap_ok,og_tags_present,twitter_card_present,hreflang_present,
security_score_8,performance_score_8,seo_score_8,overall_grade
```

**`email_posture.csv`**

```
domain,spf_present,spf_valid,spf_flatten_warn,dkim_selectors,dkim_present,dkim_key_length_ok,
dmarc_present,dmarc_policy,dmarc_rua_present,mta_sts_mode,tls_rpt_present,bimi_present,
mx_hosts,ptr_ok
```

---

## 17) Guardrails & QA

* **Never** submit forms, attempt login, or POST to xmlrpc.
* Respect robots.txt for any optional discovery crawl.
* Log timestamps, tool versions, and IP of the audit machine.
* QA check: randomly open 10% of `root.headers.txt` to verify header parsing.

---

## 18) Remediation Playbook (hand-off stubs)

Provide ready-to-paste snippets for:

* **Nginx/Apache/Cloudflare**: HSTS, CSP starter, Referrer-Policy, X-CTO, XFO/frame-ancestors, Permissions-Policy.
* **WP**: disable xmlrpc (or IP-allow), remove `readme.html`/`license.txt`, block uploads execution, `noindex` on login, 2FA plugin guidance.
* **Mixed content**: enable `upgrade-insecure-requests` temporarily; fix hardcoded `http://` in theme/plugin settings.
* **Email**: example SPF flattening pattern, DMARC `p=quarantine/reject` rollout stages, MTA-STS/TLS-RPT templates, DKIM 2048-bit key guidance.

---

## 19) Reporting

* Generate `report.pdf` from CSVs and evidence using your PDF generator (cover → portfolio table → per-site sections → email posture → appendix).
* Include a one-page **Executive Summary**: 3 scores + Top 5 fixes (Impact vs Effort).

---

## 20) Optional Light-Active (only with written permission)

* **Staging**: read-only admin review (roles/2FA/plugins/themes inventory export).
* **Email**: send signed test messages to test inboxes to confirm alignment.
* **Re-verify**: rerun passive checks after remediation for before/after diffs.

---

### Minimal Command Cheat Sheet (drop into scripts)

```bash
# HEAD/GET
curl -sSIL https://$HOST/ -o root.headers.txt
curl -sSL  https://$HOST/ -o root.html

# HTTP->HTTPS
curl -sSI http://$HOST/ -o http.headers.txt

# wp-login & xmlrpc
curl -sSIL https://$HOST/wp-login.php -o wp-login.headers.txt
curl -sSL  https://$HOST/wp-login.php -o wp-login.html
curl -sSIL https://$HOST/xmlrpc.php -o xmlrpc.headers.txt
curl -sSL  https://$HOST/xmlrpc.php -o xmlrpc.body.txt

# uploads dirlisting
curl -sSIL https://$HOST/wp-content/uploads/ -o uploads.headers.txt
curl -sSL  https://$HOST/wp-content/uploads/ -o uploads.body.txt

# TLS dates
echo | openssl s_client -servername $HOST -connect $HOST:443 2>/dev/null | openssl x509 -noout -dates > tls.txt

# Mixed content count
grep -Eoi 'http://[a-z0-9][^"'\''<>[:space:]]+' root.html | \
  grep -Evi '(localhost|127\.0\.0\.1)' | sort | uniq -c > mixed.txt

# DNS & Email
dig +short A $DOMAIN > dns.txt
dig +short TXT $DOMAIN | tee txt_root.txt
dig +short TXT _dmarc.$DOMAIN > dmarc.txt
dig +short TXT _mta-sts.$DOMAIN > mtasts.txt
dig +short TXT _smtp._tls.$DOMAIN > tlsrpt.txt
dig +short TXT default._bimi.$DOMAIN > bimi.txt
```