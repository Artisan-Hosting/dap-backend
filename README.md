# Artisan Dynamic Auditing Platform Backend

This repository is now a Rust backend service for the web application described
in `backend_v1.md`.

## Layout

- `src/backend/` — Axum API server, capability registry, MySQL store, and worker process coordination.
- `src/` — Shared engine pieces used by the backend (discovery, planner, plugins, runner).
- `backend.toml` — Backend service configuration.
- `rules.yaml` — Declarative planner rules mapping facts to tests.
- `plugins/` — Hot-swappable plugin stubs with manifests and Python entrypoints.
- `plugins/shared/` — Shared Python helpers that plugin entrypoints can import when they need common payload or context handling.
- `scripts/debug_backend.py` — verbose debug client for listing tests, submitting runs, polling status, and saving raw JSON snapshots.
- `docs/backend_v1/` — documented API, schema, report, and backend contract choices.

### Implemented Prototype Tests

- `wp_touchpoints` — Reads WordPress login, XML-RPC, and REST endpoints to flag `noindex` gaps or exposed XML-RPC (objective.md §6).
- `web_mixed_content` — Counts absolute `http://` references on the root document to highlight mixed content debt (objective.md §7).
- `web_hsts` — Confirms HTTPS reachability, HSTS configuration, and certificate runway.
- `web_security_headers` — Inventories CSP/X-CTO/Referrer-Policy/etc. on the root document.
- `web_seo_basics` — Checks title/meta/canonical/robots/sitemap hygiene plus exposed default files.
- `web_basic_surface` — Flags frontend dev leaks and server signature/version exposure on basic sites.
- `discovery_api_probe` / `discovery_dav_probe` — Discovery-only capabilities surfaced in `GET /v1/tests` when enabled in `backend.toml`; they gate extra probing of ambiguous dead/zombie-looking hosts for API or DAV surfaces.
- `dns_dmarc_policy` — Parses DMARC/SPF/DKIM/TLS-RPT/MTA-STS/BIMI plus MTA-STS policy details for email posture.
- `mail_server_probe` — Lightly probes public SMTP listener ports and EHLO capabilities on MX hosts.
- `ip_reputation_dnsbl` — Checks resolved IPv4s against common DNS block lists.
- `ip_hosting_provider` — Identifies common cloud/CDN providers such as Cloudflare, AWS, GCP, or Azure.
- `ip_geolocation` — Captures city/region/country for resolved IPs and warns when they geolocate outside the US.
- `psi_web_performance` — Calls Google's PSI API when credentials are provided via `PAGESPEED_API_KEY` or `PAGESPEED_CREDENTIALS_FILE`/`GOOGLE_APPLICATION_CREDENTIALS` (service account JSON).

Discovery persists site profiles, dead hosts, planned tests, results, and a canonical `report.json` for each run.
When `dig` is unavailable or returns empty results from this environment, discovery now falls back to the system resolver for A/AAAA records and to `host` for MX/TXT/CNAME lookups so the planner still receives the facts needed for sweep and applicability decisions.

## Getting Started

```bash
# Format and check the project
cargo fmt
cargo check

# Create the MySQL database and update backend.toml first
# Example: mysql -uroot -p -e 'CREATE DATABASE artisan_dap;'

# Start the backend server
cargo run

# Optional: point the server at a different config file
ARTISAN_DAP_BACKEND_CONFIG=backend.toml cargo run
```

Default bind: `127.0.0.1:3000`

Example endpoints:

```bash
curl http://127.0.0.1:3000/v1/tests

curl -X POST http://127.0.0.1:3000/v1/runs \
  -H 'content-type: application/json' \
  -d '{"target":"artisanhosting.net","requested_tests":["dns_dmarc_policy"]}'

# Verbose end-to-end backend debug flow
./scripts/debug_backend.py --target artisanhosting.net --force-refresh
```

### Python Plugin Dependencies

On first startup the backend provisions a shared venv under `venvs/shared/` and installs `httpx`, `beautifulsoup4`, `dnspython`, `google-auth`, and `requests`. Ensure the host has outbound access to PyPI the first time you start the server. Export `PAGESPEED_API_KEY` or a PSI credentials env/file to expose `psi_web_performance` through `GET /v1/tests`.
The internal discovery probe capabilities `discovery_api_probe` and `discovery_dav_probe` are also listed in `GET /v1/tests` when enabled in config; they are not normal plugin jobs and only affect whether discovery performs the extra API or DAV follow-up checks on weak hosts.

At this stage the backend will:

1. Load `backend.toml`.
2. Expose only currently supported tests through `GET /v1/tests`.
3. Persist submitted runs in MySQL.
4. Execute queued runs in a dedicated worker subprocess.
5. Persist discovery facts, planned tests, results, artifacts, and canonical `report.json` output.

## Debugging

- `scripts/debug_backend.py` is the intended local debugging tool for this backend.
- It lists the supported catalog from `GET /v1/tests`, submits a run, polls `GET /v1/runs/{run_id}`, and saves all raw payloads under `artifacts/debug-client/<timestamp>/`.
- The backend currently runs as one API server process plus one dedicated worker subprocess. Running multiple independent backend stacks against the same MySQL database can interfere with queue ownership and make result snapshots confusing.

## Contracts

- Backend v1 draft: `backend_v1.md`
- API/storage/report docs: `docs/backend_v1/`
- OpenAPI spec: `docs/openapi.yaml`

The backend binary supports both server mode and worker mode. `cargo run` starts the API server, which spawns the worker subprocess automatically. `cargo run -- --worker` runs only the worker side against the same config and database.
