#!/usr/bin/env python3
"""Small API endpoint fuzzing pass.

Probes a short list of common API paths and reports endpoints that appear to be
real services, schema documents, or protected interfaces.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, Optional

try:
    import httpx
except ImportError as exc:  # pragma: no cover - dependency hint for operators
    raise SystemExit(json.dumps({
        "test_id": "web_api_fuzz",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": ["Install httpx >= 0.27 inside the plugin environment"],
        "notes": f"Missing dependency: {exc}",
    }))

from shared.plugin_context import resolve_web_host
from shared.parallel import parallel_map

HEADERS = {
    "User-Agent": "ArtisanPassiveAuditor/0.1 (+passive)",
    "Accept": "application/json, text/plain, */*",
}
FUZZ_PATHS = [
    "/api",
    "/api/",
    "/api/v1",
    "/api/v1/health",
    "/api/health",
    "/api/status",
    "/health",
    "/healthz",
    "/openapi.json",
    "/swagger.json",
    "/graphql",
]


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    return json.loads(raw) if raw else {}


def resolve_host(payload: Dict) -> str:
    return resolve_web_host(payload)


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


def fetch_root_scheme(host: str) -> str:
    last_error: Exception | None = None
    for scheme in ("https", "http"):
        try:
            with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=3) as client:
                resp = client.get(f"{scheme}://{host}/")
                if resp.status_code < 500:
                    return scheme
        except Exception as exc:
            last_error = exc
    raise RuntimeError(str(last_error) if last_error else "unable to fetch root document")


def classify_response(resp: httpx.Response) -> list[str]:
    reasons: list[str] = []
    body = (resp.text or "").lstrip()
    content_type = (resp.headers.get("content-type") or "").lower()

    if resp.status_code in {401, 403}:
        reasons.append("auth_required")
    if resp.status_code == 405:
        reasons.append("method_not_allowed")
    if resp.status_code in {200, 201, 202, 204}:
        reasons.append("success")
    if resp.status_code in {301, 302, 307, 308}:
        reasons.append("redirect")
    if "json" in content_type or body.startswith("{") or body.startswith("["):
        reasons.append("json_like")
    if any(token in body.lower() for token in ("openapi", "swagger", "graphql")):
        reasons.append("schema_or_graphql")
    return reasons


def probe_endpoint(base: str, path: str) -> Optional[Dict]:
    try:
        with httpx.Client(headers=HEADERS, follow_redirects=True, timeout=15) as client:
            resp = client.get(f"{base}{path}")
    except Exception:
        return None

    reasons = classify_response(resp)
    if resp.status_code == 404:
        return None
    if not reasons and resp.status_code >= 500:
        return None
    return summarize(resp, reasons, path)


def summarize(resp: httpx.Response, reasons: list[str], path: str) -> Dict:
    body = resp.text or ""
    preview = body[:160].replace("\n", " ").strip()
    return {
        "path": path,
        "status_code": resp.status_code,
        "content_type": resp.headers.get("content-type"),
        "content_length": resp.headers.get("content-length"),
        "reasons": reasons,
        "body_preview": preview or None,
    }


def main() -> None:
    payload = load_input()
    host = resolve_host(payload)
    if not host:
        json.dump({
            "test_id": "web_api_fuzz",
            "target": payload.get("target", ""),
            "status": "error",
            "severity": "informational",
            "evidence": {},
            "recommendations": ["Provide a site or web_service fact with host metadata"],
            "notes": "Unable to determine host for API fuzzing",
        }, sys.stdout)
        return

    evidence_dir = prepare_evidence_dir(payload, "web_api_fuzz")

    try:
        scheme = fetch_root_scheme(host)
        base = f"{scheme}://{host}"
        findings: list[Dict] = []

        findings = [
            item
            for item in parallel_map(FUZZ_PATHS, lambda path: probe_endpoint(base, path))
            if item is not None
        ]

        if evidence_dir:
            (evidence_dir / "findings.json").write_text(json.dumps(findings, indent=2), encoding="utf-8")

        if findings:
            strong_hits = [item for item in findings if "json_like" in item["reasons"] or "schema_or_graphql" in item["reasons"]]
            auth_hits = [item for item in findings if "auth_required" in item["reasons"] or "method_not_allowed" in item["reasons"]]
            status = "warn" if strong_hits or any(item["status_code"] in {200, 201, 202, 204} for item in findings) else "info"
            severity = "medium" if strong_hits else "low"
            recommendations = [
                "Review any unexpected API surfaces and trim exposed routes",
                "Keep schema documents and health endpoints intentionally scoped",
            ]
            if auth_hits and not strong_hits:
                recommendations.insert(0, "Confirm protected API routes are intentionally exposed")

            output = {
                "test_id": "web_api_fuzz",
                "target": host,
                "status": status,
                "severity": severity,
                "evidence": {
                    "scheme": scheme,
                    "findings": findings,
                },
                "recommendations": recommendations,
                "notes": None,
            }
        else:
            output = {
                "test_id": "web_api_fuzz",
                "target": host,
                "status": "pass",
                "severity": "informational",
                "evidence": {"scheme": scheme, "findings": []},
                "recommendations": [],
                "notes": None,
            }
    except Exception as exc:
        output = {
            "test_id": "web_api_fuzz",
            "target": host,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": str(exc)},
            "recommendations": ["Verify HTTP reachability and retry"],
            "notes": f"API fuzzing failed: {exc}",
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
