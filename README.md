# Artisan Dynamic Auditing Platform Backend

This repository is now a Rust backend service for the web application described
in `backend_v1.md`.

## Layout

- `src/backend/` — Axum API server, capability registry, MySQL store, and worker loop.
- `src/` — Shared engine pieces used by the backend (discovery, planner, plugins, runner).
- `backend.toml` — Backend service configuration.
- `rules.yaml` — Declarative planner rules mapping facts to tests.
- `plugins/` — Hot-swappable plugin stubs with manifests and Python entrypoints.
- `docs/backend_v1/` — documented API, schema, report, and backend contract choices.

### Implemented Prototype Tests

- `wp_touchpoints` — Reads WordPress login, XML-RPC, and REST endpoints to flag `noindex` gaps or exposed XML-RPC (objective.md §6).
- `web_mixed_content` — Counts absolute `http://` references on the root document to highlight mixed content debt (objective.md §7).
- `web_hsts` — Confirms HTTPS reachability, HSTS configuration, and certificate runway.
- `web_security_headers` — Inventories CSP/X-CTO/Referrer-Policy/etc. on the root document.
- `web_seo_basics` — Checks title/meta/canonical/robots/sitemap hygiene plus exposed default files.
- `web_basic_surface` — Flags frontend dev leaks and server signature/version exposure on basic sites.
- `dns_dmarc_policy` — Parses DMARC/SPF/DKIM/TLS-RPT/MTA-STS/BIMI plus MTA-STS policy details for email posture.
- `mail_server_probe` — Lightly probes public SMTP listener ports and EHLO capabilities on MX hosts.
- `ip_reputation_dnsbl` — Checks resolved IPv4s against common DNS block lists.
- `ip_hosting_provider` — Identifies common cloud/CDN providers such as Cloudflare, AWS, GCP, or Azure.
- `ip_geolocation` — Captures city/region/country for resolved IPs and warns when they geolocate outside the US.
- `psi_web_performance` — Calls Google's PSI API when credentials are provided via `PAGESPEED_API_KEY` or `PAGESPEED_CREDENTIALS_FILE`/`GOOGLE_APPLICATION_CREDENTIALS` (service account JSON).

Discovery persists site profiles, dead hosts, planned tests, results, and a canonical `report.json` for each run.

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
```

### Python Plugin Dependencies

On first startup the backend provisions a shared venv under `venvs/shared/` and installs `httpx`, `beautifulsoup4`, `dnspython`, `google-auth`, and `requests`. Ensure the host has outbound access to PyPI the first time you start the server. Export `PAGESPEED_API_KEY` or a PSI credentials env/file to expose `psi_web_performance` through `GET /v1/tests`.

At this stage the backend will:

1. Load `backend.toml`.
2. Expose only currently supported tests through `GET /v1/tests`.
3. Persist submitted runs in MySQL.
4. Execute queued runs in an embedded worker loop.
5. Persist discovery facts, planned tests, results, artifacts, and canonical `report.json` output.

## Contracts

- Backend v1 draft: `backend_v1.md`
- API/storage/report docs: `docs/backend_v1/`
- OpenAPI spec: `docs/openapi.yaml`

The backend binary is server-only now. Audit execution happens through the HTTP API and embedded worker loop rather than through a CLI run command.
