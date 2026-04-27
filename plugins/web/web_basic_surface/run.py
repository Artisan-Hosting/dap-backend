#!/usr/bin/env python3
"""Basic web surface audit.

Checks plain sites and frontend apps for exposed dev assets, source maps, and
web-server signature/version disclosures.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, Optional, Sequence, Tuple

try:
    import httpx
except ImportError as exc:  # pragma: no cover - dependency hint for operators
    raise SystemExit(json.dumps({
        "test_id": "web_basic_surface",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

HEADERS = {"User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)"}
SOURCE_MAP_RE = re.compile(r"sourceMappingURL=([^\s]+)|(?:src|href)=[\"']([^\"']+\.map)[\"']", re.IGNORECASE)
SERVER_VERSION_RE = re.compile(r"(?P<family>[A-Za-z][A-Za-z0-9._-]*)/(?P<version>\d+(?:\.\d+){1,3})")

FRAMEWORK_MARKERS = {
    "vite": ["/@vite/client", "import.meta.hot", "data-vite-dev-id", "vite/modulepreload"],
    "react": ["data-reactroot", "react-refresh", "__react", "react/jsx-runtime", "__webpack_hmr"],
    "angular": ["ng-version", "ng-app", "angular.js", "ng-server-context"],
    "nextjs": ["__next_data__", "/_next/", "next.js"],
    "vue": ["__vue__", "vue-app", "data-v-"],
    "sveltekit": ["__sveltekit", "sveltekit"],
}

SAFE_SERVER_MINIMUMS = {
    "nginx": (1, 20, 0),
    "apache": (2, 4, 54),
    "openresty": (1, 21, 4),
}


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_context(payload: Dict) -> Tuple[str, Optional[str]]:
    host = payload.get("target", "")
    provider_hint = None

    for fact in payload.get("facts", []):
        if fact.get("entity") == "web_service":
            attrs = fact.get("attrs", {})
            host = attrs.get("host", host)
        elif fact.get("entity") == "site_profile":
            attrs = fact.get("attrs", {})
            provider_hint = attrs.get("provider") or provider_hint

    return host or payload.get("target", ""), provider_hint


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
                resp = client.get(f"{scheme}://{host}/")
                return scheme, resp
        except Exception as exc:
            last_error = exc
    raise RuntimeError(str(last_error) if last_error else "unable to fetch root document")


def find_markers(text: str, markers: Sequence[str], label: str) -> list[str]:
    lower = text.lower()
    return [f"{label}:{marker}" for marker in markers if marker in lower]


def detect_framework(body: str, headers: Dict[str, str], provider_hint: Optional[str]) -> Tuple[Optional[str], list[str]]:
    lower = body.lower()
    signals: list[str] = []

    if provider_hint:
        hinted = provider_hint.lower()
        if hinted in FRAMEWORK_MARKERS:
            signals.append(f"hint:{hinted}")
            return hinted, signals

    for framework, markers in FRAMEWORK_MARKERS.items():
        found = find_markers(body, markers, framework)
        if found:
            signals.extend(found)
            return framework, signals

    server = headers.get("server", "").lower()
    if "next" in lower or "next" in server:
        signals.append("nextjs:heuristic")
        return "nextjs", signals

    return None, signals


def parse_server_version(server: str) -> Tuple[Optional[str], Optional[Tuple[int, ...]]]:
    match = SERVER_VERSION_RE.search(server)
    if not match:
        return None, None
    family = match.group("family").lower()
    version = tuple(int(part) for part in match.group("version").split("."))
    return family, version


def is_older_than(version: Tuple[int, ...], minimum: Tuple[int, ...]) -> bool:
    length = max(len(version), len(minimum))
    padded_version = version + (0,) * (length - len(version))
    padded_minimum = minimum + (0,) * (length - len(minimum))
    return padded_version < padded_minimum


def analyze_server(headers: Dict[str, str]) -> Tuple[list[dict], list[str], str]:
    findings: list[dict] = []
    recommendations: list[str] = []
    status = "pass"

    server = headers.get("server", "")
    x_powered_by = headers.get("x-powered-by", "")
    content_type = headers.get("content-type", "")

    if server:
        family, version = parse_server_version(server)
        findings.append({"server": server, "family": family, "version": version})
        recommendations.append("Hide the Server header if possible")
        status = "warn"

        server_lower = server.lower()
        if any(name in server_lower for name in ("nginx", "apache", "openresty")) and not version:
            findings.append({"signature_exposed": server})

        if family in SAFE_SERVER_MINIMUMS and version and is_older_than(version, SAFE_SERVER_MINIMUMS[family]):
            status = "fail"
            recommendations.append(f"Upgrade {family} to a supported version")

    if x_powered_by:
        findings.append({"x_powered_by": x_powered_by})
        recommendations.append("Remove X-Powered-By when possible")
        status = "warn" if status != "fail" else status

    if content_type:
        findings.append({"content_type": content_type})

    return findings, recommendations, status


def analyze_source_maps(body: str) -> list[str]:
    hits: list[str] = []
    for left, right in SOURCE_MAP_RE.findall(body):
        hit = left or right
        if hit and hit not in hits:
            hits.append(hit)
    return hits


def main() -> None:
    payload = load_input()
    host, provider_hint = resolve_context(payload)
    if not host:
        json.dump({
            "test_id": "web_basic_surface",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Provide a web_service fact with host metadata"],
            "notes": "Unable to determine host for basic surface audit",
        }, sys.stdout)
        return

    evidence_dir = prepare_evidence_dir(payload, "web_basic_surface")

    try:
        scheme, resp = fetch_root(host)
        html = resp.text or ""
        headers = {k.lower(): v for k, v in resp.headers.items()}
        framework, framework_signals = detect_framework(html, headers, provider_hint)
        source_maps = analyze_source_maps(html)

        if evidence_dir:
            (evidence_dir / "root.html").write_text(html, encoding="utf-8", errors="ignore")
            (evidence_dir / "headers.txt").write_text(
                "\n".join(f"{k}: {v}" for k, v in resp.headers.items()),
                encoding="utf-8",
            )

        findings, recommendations, status = analyze_server(headers)
        dev_artifacts: list[str] = []
        frontend_issues: list[str] = []

        lower = html.lower()
        if framework == "vite":
            if any(marker in lower for marker in ("/@vite/client", "import.meta.hot", "data-vite-dev-id")):
                frontend_issues.append("vite development client or HMR markers exposed")
                status = "fail"
            if "/@vite/client" in lower:
                dev_artifacts.append("@vite/client")
        elif framework == "react":
            if any(marker in lower for marker in ("react-refresh", "__webpack_hmr")):
                frontend_issues.append("React refresh or HMR markers exposed")
                status = "warn" if status == "pass" else status
            if "sourceMappingURL=" in html:
                frontend_issues.append("JavaScript source maps exposed")
                status = "warn" if status != "fail" else status
        elif framework == "angular":
            if "ng-version" in lower:
                frontend_issues.append("Angular version disclosure present")
                status = "warn" if status == "pass" else status
            if "sourceMappingURL=" in html:
                frontend_issues.append("Angular source maps exposed")
                status = "warn" if status != "fail" else status
        elif framework in {"nextjs", "vue", "sveltekit"}:
            if "sourceMappingURL=" in html:
                frontend_issues.append(f"{framework} source maps exposed")
                status = "warn" if status == "pass" else status

        if source_maps:
            frontend_issues.append("Source map references are visible in production HTML")
            if status == "pass":
                status = "warn"

        if framework and not provider_hint and status == "pass":
            status = "info"

        recommendations.extend({
            "vite": ["Disable Vite dev client in production", "Remove source maps from production builds"],
            "react": ["Strip React refresh/HMR code from production", "Remove production source maps"],
            "angular": ["Hide Angular version info", "Remove production source maps"],
            "nextjs": ["Disable production source maps if not needed"],
            "vue": ["Disable production source maps if not needed"],
            "sveltekit": ["Disable production source maps if not needed"],
        }.get(framework or "", []))

        recommendations.extend([
            "Hide server/version banners when possible",
            "Upgrade disclosed server components to a supported release",
        ])

        evidence = {
            "scheme": scheme,
            "status_code": resp.status_code,
            "content_type": headers.get("content-type"),
            "server": headers.get("server"),
            "x_powered_by": headers.get("x-powered-by"),
            "framework": framework,
            "framework_signals": framework_signals,
            "frontend_issues": frontend_issues,
            "source_maps": source_maps,
            "server_findings": findings,
        }

        if status == "fail":
            severity = "high"
        elif status == "warn":
            severity = "medium"
        else:
            severity = "informational"

        output = {
            "test_id": "web_basic_surface",
            "target": host,
            "status": status,
            "severity": severity,
            "evidence": evidence,
            "recommendations": sorted(set(recommendations)),
            "notes": None,
        }
    except Exception as exc:
        output = {
            "test_id": "web_basic_surface",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc)},
            "recommendations": ["Verify reachability and retry"],
            "notes": "Basic surface scan failed",
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
