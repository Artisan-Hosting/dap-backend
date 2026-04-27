#!/usr/bin/env python3
"""Root-page SEO and default-file hygiene audit."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Optional, Tuple

try:
    import httpx
    from bs4 import BeautifulSoup
except ImportError as exc:
    raise SystemExit(json.dumps({
        "test_id": "web_seo_basics",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 and beautifulsoup4 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_host(payload: Dict) -> str:
    host = payload.get("target", "")
    for fact in payload.get("facts", []):
        attrs = fact.get("attrs", {})
        if fact.get("entity") == "web_service":
            host = attrs.get("host", host)
            break
        if fact.get("entity") == "site_profile":
            host = attrs.get("host", host)
    return host or payload.get("target", "")


def prepare_evidence_dir(payload: Dict, test_id: str) -> Optional[Path]:
    cfg = payload.get("config", {})
    run_root = cfg.get("run_root")
    if not run_root:
        return None
    path = Path(run_root) / "evidence" / test_id
    try:
        path.mkdir(parents=True, exist_ok=True)
        return path
    except Exception:
        return None


def fetch_root(host: str) -> Tuple[str, httpx.Response]:
    last_error: Exception | None = None
    for scheme in ("https", "http"):
        try:
            with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=20) as client:
                return scheme, client.get(f"{scheme}://{host}/")
        except Exception as exc:
            last_error = exc
    raise RuntimeError(str(last_error) if last_error else "unable to fetch root document")


def fetch_optional(client: httpx.Client, url: str) -> Optional[httpx.Response]:
    try:
        return client.get(url)
    except Exception:
        return None


def main() -> None:
    payload = load_input()
    host = resolve_host(payload)
    if not host:
        json.dump({
            "test_id": "web_seo_basics",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Provide a site or web-service fact with host metadata"],
            "notes": "Unable to determine host for SEO audit",
        }, sys.stdout)
        return

    evidence_dir = prepare_evidence_dir(payload, "web_seo_basics")

    try:
        scheme, resp = fetch_root(host)
        html = resp.text or ""
        soup = BeautifulSoup(html, "html.parser")

        title = soup.title.string.strip() if soup.title and soup.title.string else ""
        meta_description = ""
        meta = soup.find("meta", attrs={"name": lambda value: isinstance(value, str) and value.lower() == "description"})
        if meta:
            meta_description = (meta.get("content") or "").strip()

        has_canonical = bool(soup.find("link", attrs={"rel": lambda value: value and "canonical" in str(value).lower()}))
        og_tags_present = bool(soup.find("meta", attrs={"property": lambda value: isinstance(value, str) and value.lower().startswith("og:")}))
        twitter_card_present = bool(soup.find("meta", attrs={"name": lambda value: isinstance(value, str) and value.lower() == "twitter:card"}))
        hreflang_present = bool(soup.find("link", attrs={"hreflang": True}))

        robots_txt_ok = False
        sitemap_ok = False
        readme_present = False
        license_present = False

        with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=15) as client:
            robots = fetch_optional(client, f"{scheme}://{host}/robots.txt")
            if robots and robots.status_code == 200:
                robots_txt_ok = True
                if evidence_dir:
                    (evidence_dir / "robots.txt").write_text(robots.text, encoding="utf-8", errors="ignore")

            for sitemap_path in ("/sitemap.xml", "/wp-sitemap.xml"):
                sitemap = fetch_optional(client, f"{scheme}://{host}{sitemap_path}")
                if sitemap and sitemap.status_code == 200:
                    sitemap_ok = True
                    if evidence_dir:
                        (evidence_dir / sitemap_path.strip("/")).write_text(
                            sitemap.text,
                            encoding="utf-8",
                            errors="ignore",
                        )
                    break

            readme = fetch_optional(client, f"{scheme}://{host}/readme.html")
            if readme and readme.status_code == 200:
                readme_present = True

            license_file = fetch_optional(client, f"{scheme}://{host}/license.txt")
            if license_file and license_file.status_code == 200:
                license_present = True

        if evidence_dir:
            (evidence_dir / "root.html").write_text(html, encoding="utf-8", errors="ignore")
            (evidence_dir / "headers.txt").write_text(
                "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                encoding="utf-8",
            )

        recommendations = []
        warn_issues = []
        info_issues = []

        if not title:
            warn_issues.append("missing_title")
            recommendations.append("Add a descriptive <title> tag to the root document")
        if not meta_description:
            warn_issues.append("missing_meta_description")
            recommendations.append("Add a meta description for the root document")
        if not has_canonical:
            warn_issues.append("missing_canonical")
            recommendations.append("Publish a canonical link tag on the root document")
        if not robots_txt_ok:
            warn_issues.append("missing_robots_txt")
            recommendations.append("Publish a robots.txt file")
        if not sitemap_ok:
            warn_issues.append("missing_sitemap")
            recommendations.append("Publish a sitemap.xml or wp-sitemap.xml")
        if readme_present:
            warn_issues.append("readme_exposed")
            recommendations.append("Remove or restrict public access to readme.html")
        if license_present:
            warn_issues.append("license_exposed")
            recommendations.append("Remove or restrict public access to license.txt")
        if not og_tags_present:
            info_issues.append("missing_open_graph")
            recommendations.append("Add Open Graph metadata for link previews")
        if not twitter_card_present:
            info_issues.append("missing_twitter_card")
            recommendations.append("Add a twitter:card meta tag for social previews")

        if warn_issues:
            status = "warn"
            severity = "medium" if {"readme_exposed", "license_exposed"} & set(warn_issues) else "low"
        elif info_issues:
            status = "info"
            severity = "informational"
        else:
            status = "pass"
            severity = "informational"

        output = {
            "test_id": "web_seo_basics",
            "target": host,
            "status": status,
            "severity": severity,
            "evidence": {
                "scheme": scheme,
                "status_code": resp.status_code,
                "title_length": len(title),
                "meta_description_length": len(meta_description),
                "has_canonical": has_canonical,
                "robots_txt_ok": robots_txt_ok,
                "sitemap_ok": sitemap_ok,
                "readme_present": readme_present,
                "license_present": license_present,
                "og_tags_present": og_tags_present,
                "twitter_card_present": twitter_card_present,
                "hreflang_present": hreflang_present,
                "warn_issues": warn_issues,
                "info_issues": info_issues,
            },
            "recommendations": sorted(set(recommendations)),
            "notes": None,
        }
    except Exception as exc:
        output = {
            "test_id": "web_seo_basics",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc)},
            "recommendations": ["Verify reachability and retry"],
            "notes": "SEO metadata scan failed",
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
