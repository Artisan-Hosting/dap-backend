#!/usr/bin/env python3
"""Minimal PageSpeed Insights helper supporting API keys or service accounts."""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional

import httpx

from shared.parallel import parallel_map

API = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
SCOPE = "https://www.googleapis.com/auth/pagespeedonline"


@dataclass
class _TokenCache:
    value: str
    expiry_epoch: float


_TOKEN: Optional[_TokenCache] = None


def _credentials_path() -> Optional[str]:
    return os.environ.get("PAGESPEED_CREDENTIALS_FILE") or os.environ.get(
        "GOOGLE_APPLICATION_CREDENTIALS"
    )


def credentials_available() -> bool:
    if os.environ.get("PAGESPEED_API_KEY"):
        return True
    path = _credentials_path()
    return bool(path and os.path.exists(path))


def _service_account_token() -> str:
    global _TOKEN

    path = _credentials_path()
    if not path:
        raise RuntimeError(
            "Neither PAGESPEED_API_KEY nor PAGESPEED_CREDENTIALS_FILE/GOOGLE_APPLICATION_CREDENTIALS is set"
        )
    if not os.path.exists(path):
        raise RuntimeError(f"Credentials file not found: {path}")

    now = time.time()
    if _TOKEN and (_TOKEN.expiry_epoch - now) > 60:
        return _TOKEN.value

    try:
        from google.auth.transport.requests import Request
        from google.oauth2 import service_account
    except ImportError as exc:  # pragma: no cover - dependency safeguard
        raise RuntimeError(
            "google-auth is required for service account credentials; install google-auth"
        ) from exc

    # Create service account credentials
    # Scopes parameter ensures OAuth2 flow instead of JWT bearer mode
    credentials = service_account.Credentials.from_service_account_file(
        path, 
        scopes=[SCOPE]
    )
    
    # Disable JWT self-signed access to force OAuth2 token exchange
    # This is critical - it tells google-auth to exchange JWT for access_token
    if hasattr(credentials, "with_always_use_jwt_access"):
        credentials = credentials.with_always_use_jwt_access(False)
    
    # Perform token exchange: JWT -> access_token
    request = Request()
    try:
        credentials.refresh(request)
    except Exception as e:
        raise RuntimeError(
            f"Failed to refresh service account credentials: {e}. "
            f"Ensure the service account has PageSpeed Insights API access enabled."
        )
    
    # Verify we got an access token (not id_token or empty)
    if not hasattr(credentials, 'token') or not credentials.token:
        raise RuntimeError(
            "Failed to obtain access_token from service account refresh. "
            "The service account may lack PageSpeed Insights API permissions. "
            "See: https://cloud.google.com/docs/authentication/getting-started"
        )

    expiry = credentials.expiry
    expiry_epoch = expiry.timestamp() if hasattr(expiry, "timestamp") else now + 3600
    _TOKEN = _TokenCache(credentials.token, float(expiry_epoch))
    return credentials.token


def _auth_headers() -> Dict[str, str]:
    key = os.environ.get("PAGESPEED_API_KEY")
    if key:
        return {"key": key}

    token = _service_account_token()
    return {"Authorization": f"Bearer {token}"}


def _get(url: str, strategy: str) -> dict:
    params = {"url": url, "strategy": strategy, "category": "PERFORMANCE"}
    headers: Dict[str, str] = {}

    creds = _auth_headers()
    if "key" in creds:
        params["key"] = creds["key"]
    else:
        headers.update(creds)

    response = httpx.get(API, params=params, headers=headers, timeout=60)
    response.raise_for_status()
    return response.json()


def _metric_value(audits: dict, audit_id: str) -> Dict[str, object]:
    audit = audits.get(audit_id, {})
    return {
        "value": audit.get("numericValue"),
        "unit": audit.get("numericUnit"),
        "display": audit.get("displayValue"),
        "score": audit.get("score"),
        "title": audit.get("title"),
    }


def _extract_opportunities(audits: dict) -> List[Dict[str, object]]:
    improvements: List[Dict[str, object]] = []
    for audit_id, audit in audits.items():
        details = audit.get("details") or {}
        if not isinstance(details, dict) or details.get("type") != "opportunity":
            continue
        overall_savings_ms = details.get("overallSavingsMs")
        overall_savings_bytes = details.get("overallSavingsBytes")
        improvements.append(
            {
                "id": audit_id,
                "title": audit.get("title"),
                "description": audit.get("description"),
                "display_value": audit.get("displayValue"),
                "score": audit.get("score"),
                "savings_ms": overall_savings_ms,
                "savings_bytes": overall_savings_bytes,
            }
        )

    improvements.sort(
        key=lambda item: (item.get("savings_ms") is None, -(item.get("savings_ms") or 0.0)),
    )
    return improvements[:10]


def _extract_insights(audits: dict) -> List[Dict[str, object]]:
    insights: List[Dict[str, object]] = []
    for audit_id, audit in audits.items():
        details = audit.get("details") or {}
        if isinstance(details, dict) and details.get("type") == "opportunity":
            continue
        score_mode = audit.get("scoreDisplayMode")
        if score_mode not in {"informative", "manual"}:
            continue
        insights.append(
            {
                "id": audit_id,
                "title": audit.get("title"),
                "description": audit.get("description"),
                "display_value": audit.get("displayValue"),
                "score": audit.get("score"),
                "score_display_mode": score_mode,
            }
        )

    insights.sort(key=lambda item: (item.get("score") is None, item.get("score") or 0.0))
    return insights[:10]


def _extract_strategy(payload: dict) -> Dict[str, object]:
    lighthouse = payload.get("lighthouseResult", {})
    audits = lighthouse.get("audits", {})
    categories = lighthouse.get("categories", {})
    perf_category = categories.get("performance", {}) if isinstance(categories, dict) else {}

    metrics = {
        "first_contentful_paint": _metric_value(audits, "first-contentful-paint"),
        "largest_contentful_paint": _metric_value(audits, "largest-contentful-paint"),
        "total_blocking_time": _metric_value(audits, "total-blocking-time"),
        "speed_index": _metric_value(audits, "speed-index"),
        "interaction_to_next_paint": _metric_value(audits, "interaction-to-next-paint"),
        "cumulative_layout_shift": _metric_value(audits, "cumulative-layout-shift"),
    }

    loading_experience = payload.get("loadingExperience", {})
    field_data = loading_experience.get("metrics", {}) if isinstance(loading_experience, dict) else {}

    return {
        "requested_url": payload.get("id") or lighthouse.get("requestedUrl"),
        "final_url": lighthouse.get("finalDisplayedUrl") or lighthouse.get("finalUrl"),
        "analysis_timestamp": payload.get("analysisUTCTimestamp"),
        "performance_score": perf_category.get("score"),
        "metrics": metrics,
        "improvements": _extract_opportunities(audits),
        "insights": _extract_insights(audits),
        "field_data": field_data,
    }


def fetch_psi_metrics(url: str) -> Dict[str, Dict[str, object]]:
    strategies = parallel_map(
        ("mobile", "desktop"),
        lambda strategy: (strategy, _extract_strategy(_get(url, strategy))),
    )
    return dict(strategies)
