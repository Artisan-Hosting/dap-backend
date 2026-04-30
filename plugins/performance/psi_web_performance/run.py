#!/usr/bin/env python3
"""PageSpeed Insights audit.

Calls Google's PSI API using either `PAGESPEED_API_KEY` or a service-account
JSON referenced via `PAGESPEED_CREDENTIALS_FILE`/`GOOGLE_APPLICATION_CREDENTIALS`
to capture key performance metrics (FCP, LCP, TBT, Speed Index, INP, CLS),
surface the calculated performance score, and persist PSI opportunities and
diagnostic insights for both mobile and desktop strategies.

This version additionally accepts credentials via:
  - config.psi_credentials_file  -> path OR raw JSON string
  - config.psi_credentials_json  -> dict or JSON string
  - config.psi_credentials_b64   -> base64-encoded JSON

If JSON content is provided, it is written to a secure temp file and both
PAGESPEED_CREDENTIALS_FILE and GOOGLE_APPLICATION_CREDENTIALS are exported.
"""

from __future__ import annotations

import base64
import json
import os
import stat
import sys
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

try:
    import httpx  # noqa: F401 - confirm dependency is present
except ImportError as exc:
    raise SystemExit(json.dumps({
        "test_id": "psi_web_performance",
        "target": "",
        "status": "error",
        "severity": "informational",
        "evidence": {},
        "recommendations": [
            "Install httpx >= 0.27 and ensure PAGESPEED_API_KEY is configured",
        ],
        "notes": f"Missing dependency: {exc}",
    }))

ROOT = Path(__file__).resolve().parents[3]
TMP_DIR = Path(tempfile.gettempdir()) / "artisan_dap" / "psi"

try:
    from psi_client import credentials_available, fetch_psi_metrics  # type: ignore
except Exception as exc:
    def fetch_psi_metrics(url: str) -> Dict[str, Dict[str, Any]]:
        raise RuntimeError(f"Unable to import psi_client helper: {exc}")

    def credentials_available() -> bool:
        raise RuntimeError(f"Unable to import psi_client helper: {exc}")


def load_input() -> Dict:
    raw = sys.stdin.read().strip()
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(json.dumps({
            "test_id": "psi_web_performance",
            "target": "",
            "status": "error",
            "severity": "informational",
            "evidence": {"error": f"Invalid JSON on stdin: {exc}"},
            "recommendations": ["Ensure the harness passes valid JSON input"],
            "notes": None,
        }))


def resolve_target(payload: Dict) -> str:
    host = payload.get("target", "")
    for fact in payload.get("facts", []):
        if fact.get("entity") == "web_service":
            attrs = fact.get("attrs", {})
            host = attrs.get("host", host)
            break
    return f"https://{host}/" if host else payload.get("target", "")


def _validate_service_account_json(data: Dict[str, Any]) -> bool:
    # Minimal sanity checks for GCP service-account JSON
    if not isinstance(data, dict):
        return False
    if data.get("type") != "service_account":
        return False
    if not data.get("client_email") or not data.get("private_key"):
        return False
    return True


def _write_json_credentials_to_temp(data: Dict[str, Any]) -> Path:
    # Keep transient credentials outside the repo so the workspace stays clean.
    base_dir = TMP_DIR
    base_dir.mkdir(parents=True, exist_ok=True)

    # Create securely; NamedTemporaryFile with delete=False so we can pass path
    fd, path_str = tempfile.mkstemp(prefix="psi_sa_", suffix=".json", dir=str(base_dir))
    path = Path(path_str)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
            fh.flush()
            os.fsync(fh.fileno())
        # Restrict permissions to user read/write only
        path.chmod(stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        # Best-effort cleanup
        try:
            path.unlink(missing_ok=True)  # type: ignore[arg-type]
        except Exception:
            pass
        raise
    return path


def _parse_json_maybe(value: Any) -> Optional[Dict[str, Any]]:
    """Return dict if value is JSON content (dict or JSON string), else None."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        s = value.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                return json.loads(s)
            except json.JSONDecodeError:
                return None
    return None


def _decode_b64_json_maybe(value: Any) -> Optional[Dict[str, Any]]:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        decoded = base64.b64decode(value).decode("utf-8")
        return json.loads(decoded)
    except Exception:
        return None


def _resolve_path_maybe(p: Any) -> Optional[Path]:
    if not isinstance(p, str) or not p.strip():
        return None
    candidate = Path(p).expanduser()
    if not candidate.is_absolute():
        # Try relative to ROOT first, then CWD
        root_rel = (ROOT / candidate)
        if root_rel.exists():
            candidate = root_rel
        else:
            candidate = candidate.resolve()
    return candidate if candidate.exists() else None


def _export_cred_env(path: Path) -> None:
    os.environ["PAGESPEED_CREDENTIALS_FILE"] = str(path)
    # Many Google libraries also honor GOOGLE_APPLICATION_CREDENTIALS
    os.environ.setdefault("GOOGLE_APPLICATION_CREDENTIALS", str(path))


def resolve_and_export_credentials(cfg: Dict[str, Any]) -> Optional[Path]:
    """Find credentials from env or config. If JSON content is provided, write to temp and export env."""
    # 0) If API key is present, we can skip file creds (but still allow them)
    if os.environ.get("PAGESPEED_API_KEY"):
        # Still allow provided file to override if present
        pass

    # 1) Already provided via env and file exists?
    for env_var in ("PAGESPEED_CREDENTIALS_FILE", "GOOGLE_APPLICATION_CREDENTIALS"):
        existing = os.environ.get(env_var)
        path = _resolve_path_maybe(existing)
        if path:
            _export_cred_env(path)
            return path

    # 2) config.psi_credentials_file can be a path OR raw JSON
    file_field = cfg.get("psi_credentials_file")
    json_from_file_field = _parse_json_maybe(file_field)
    if json_from_file_field:
        if not _validate_service_account_json(json_from_file_field):
            raise ValueError("psi_credentials_file contained JSON, but it is not a valid service-account key.")
        path = _write_json_credentials_to_temp(json_from_file_field)
        _export_cred_env(path)
        return path
    path = _resolve_path_maybe(file_field)
    if path:
        try:
            data = json.loads(path.read_text())
        except Exception as exc:
            raise ValueError(f"Unable to read credentials JSON at {path}: {exc}")
        if not _validate_service_account_json(data):
            raise ValueError(f"Credentials at {path} do not look like a valid service-account JSON.")
        _export_cred_env(path)
        return path

    # 3) config.psi_credentials_json (dict or JSON string)
    json_field = _parse_json_maybe(cfg.get("psi_credentials_json"))
    if json_field:
        if not _validate_service_account_json(json_field):
            raise ValueError("psi_credentials_json is not a valid service-account JSON.")
        path = _write_json_credentials_to_temp(json_field)
        _export_cred_env(path)
        return path

    # 4) config.psi_credentials_b64 (base64-encoded JSON)
    b64_field = _decode_b64_json_maybe(cfg.get("psi_credentials_b64"))
    if b64_field:
        if not _validate_service_account_json(b64_field):
            raise ValueError("psi_credentials_b64 decoded content is not a valid service-account JSON.")
        path = _write_json_credentials_to_temp(b64_field)
        _export_cred_env(path)
        return path

    # Nothing resolved; return None
    return None


def main() -> None:
    payload = load_input()
    url = resolve_target(payload)
    cfg = payload.get("config", {}) or {}

    # Resolve/export credentials if provided in config/env
    try:
        cred_path = resolve_and_export_credentials(cfg)
    except Exception as exc:
        json.dump({
            "test_id": "psi_web_performance",
            "target": url,
            "status": "error",
            "severity": "informational",
            "evidence": {"error": f"Credential setup failed: {exc}"},
            "recommendations": [
                "Provide a valid service-account JSON via config.psi_credentials_file/psi_credentials_json/psi_credentials_b64 "
                "or set PAGESPEED_CREDENTIALS_FILE/GOOGLE_APPLICATION_CREDENTIALS to a readable file."
            ],
            "notes": None,
        }, sys.stdout)
        return

    # Check whether creds (or API key) are available to the helper
    try:
        available = credentials_available()
    except Exception:
        available = False

    credential_mode = "api_key" if os.environ.get("PAGESPEED_API_KEY") else (
        "service_account"
        if os.environ.get("PAGESPEED_CREDENTIALS_FILE") or os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
        else "none"
    )

    if not available:
        json.dump({
            "test_id": "psi_web_performance",
            "target": url,
            "status": "skipped",
            "severity": "informational",
            "evidence": {
                "note": (
                    "Set PAGESPEED_API_KEY or provide service account credentials via "
                    "PAGESPEED_CREDENTIALS_FILE/GOOGLE_APPLICATION_CREDENTIALS or config "
                    "(psi_credentials_file / psi_credentials_json / psi_credentials_b64)."
                ),
                "resolved_credentials_file": str(cred_path) if cred_path else None,
                "credential_mode": credential_mode,
            },
            "recommendations": [
                "Provide a PageSpeed API key or service account credentials to enable PSI audits"
            ],
            "notes": None,
        }, sys.stdout)
        return

    try:
        metrics = fetch_psi_metrics(url)
        output = {
            "test_id": "psi_web_performance",
            "target": url,
            "status": "info",
            "severity": "informational",
            "evidence": {
                "mobile": metrics.get("mobile", {}),
                "desktop": metrics.get("desktop", {}),
                "credential_mode": credential_mode,
                "resolved_credentials_file": str(cred_path) if cred_path else os.environ.get(
                    "PAGESPEED_CREDENTIALS_FILE"
                ),
            },
            "recommendations": [
                "Investigate high-impact improvements first (sorted by potential savings)",
            ],
            "notes": None,
        }
    except Exception as exc:
        import traceback
        error_detail = str(exc)
        error_traceback = traceback.format_exc()
        
        # Parse common errors
        recommendations = [
            "Validate API key/credentials, quotas, and network connectivity",
        ]
        
        if "No access token" in error_detail or "id_token" in error_detail:
            recommendations = [
                "Service account token exchange failed - ensure PageSpeed Insights API is enabled in GCP",
                "Visit: https://console.cloud.google.com/apis/library/pagespeedonline.googleapis.com",
                "Enable the API and ensure service account has Editor or custom role with pagespeedonline.*.read",
            ]
        elif "quota" in error_detail.lower():
            recommendations = [
                "PageSpeed Insights API quota exceeded",
                "Check quota at: https://console.cloud.google.com/iam-admin/quotas",
            ]
        elif "permission" in error_detail.lower():
            recommendations = [
                "Service account lacks required permissions",
                "Grant roles/pagespeedonline.apiuser or equivalent to the service account",
            ]
        
        output = {
            "test_id": "psi_web_performance",
            "target": url,
            "status": "error",
            "severity": "informational",
            "evidence": {
                "error": error_detail,
                "credential_mode": credential_mode,
                "resolved_credentials_file": str(cred_path) if cred_path else os.environ.get(
                    "PAGESPEED_CREDENTIALS_FILE"
                ),
            },
            "recommendations": recommendations,
            "notes": "PSI API request failed",
        }

    json.dump(output, sys.stdout)


if __name__ == "__main__":
    main()
