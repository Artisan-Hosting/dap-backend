# Implementation Choices

This file captures the service decisions that are now concrete in code.

## Target Handling

- targets are trimmed and normalized to lowercase `target_key`
- schemes, ports, paths, queries, fragments, and malformed DNS labels are rejected
- by default, hostnames with more than two labels are forced into `single_site` mode via `force_single_site_for_hostnames = true`
- apex-like targets continue to use the configured `default_scope_mode`

## Discovery Fallbacks

- discovery prefers `dig` for DNS lookups, but falls back to the system resolver for A/AAAA addresses and to the `host` command for MX/TXT/CNAME data when `dig` returns no usable records
- this fallback path exists because some environments still allow normal name resolution and HTTPS fetches while `dig` and `crt.sh` are unreliable or blocked
- keeping those fallbacks in discovery is important because missing address, mail, or site-profile facts can collapse planner applicability and make a sweep look like an apex-only run

## Capability Registry

- support is computed from plugin manifest presence, entrypoint existence, runtime support, env readiness, and enable/disable filters
- category is derived from `plugins/<category>/<id>`
- `psi_web_performance` is treated specially because the current manifest lists both API-key and credentials-file env vars even though the plugin supports either credential path; the registry marks it runnable when any supported PSI credential source is available
- `discovery_api_probe` and `discovery_dav_probe` are synthetic supported tests surfaced through the same capability registry so the UI can present them in `GET /v1/tests`; their config toggles control whether discovery performs additional API or DAV follow-up probing on weak hosts

## Queue Recovery

- runs left in `discovering`, `planning`, `running`, or `aggregating` are re-queued on startup
- partial database rows for those runs are cleared before retry
- the worker also recreates the run artifact directory from scratch before reprocessing
- the backend deployment expects one API server process plus one worker subprocess against a single database; running multiple independent backend stacks against the same store is a debugging-only scenario and can produce confusing queue ownership or final snapshots

## Cache and Deduping

- in-flight deduping is implemented via `request_fingerprint`
- cache-hit reuse is implemented when `cache.freshness_window_seconds > 0`
- default `backend.toml` sets `freshness_window_seconds = 0`, which disables cache reuse while keeping the code path available
- cache-hit runs create their own `runs` row and point at the canonical source run with `reused_from_run_id`

## Artifact Layout

Artifacts are stored under:

- `artifacts/<sanitized-target>/<run_id>/logs/...`
- `artifacts/<sanitized-target>/<run_id>/report/report.json`

The database stores relative paths from `storage.artifacts_root` so the filesystem root can move without changing row identity.

## Reporting

- the backend treats `report.json` as canonical
- HTML rendering is not part of the HTTP contract in this service pass
- review metadata is represented as a placeholder block so the frontend contract already has a stable slot for later workflow features

## Local Debugging

- `scripts/debug_backend.py` is the verbose local debug client for the backend
- it captures the supported catalog, run creation response, periodic status polls, final results, and final report payloads under `artifacts/debug-client/<timestamp>/`
