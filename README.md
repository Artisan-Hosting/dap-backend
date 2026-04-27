# Artisan Dynamic Auditing Platform (Prototype)

This repository now includes a heavily-commented Rust prototype that mirrors the
system breakdown in `objective.md` and `outline.md`. The goal is to give new
contributors a runnable starting point while keeping the passive-first posture
emphasized throughout the documentation.

## Layout

- `src/` — Rust core (config loader, recursive passive discovery, planner, orchestrator, runner).
- `config.toml` — Example run configuration used by the CLI.
- `rules.yaml` — Declarative planner rules mapping facts to tests.
- `plugins/` — Hot-swappable plugin stubs with manifests and Python entrypoints.
- `report.draft.json` — Modular JSON report sketch for the aggregator/reporting layer.

### Implemented Prototype Tests

- `wp_touchpoints` — Reads WordPress login, XML-RPC, and REST endpoints to flag `noindex` gaps or exposed XML-RPC (objective.md §6).
- `web_mixed_content` — Counts absolute `http://` references on the root document to highlight mixed content debt (objective.md §7).
- `web_hsts` — Confirms HTTPS reachability, HSTS configuration, and certificate runway.
- `web_security_headers` — Inventories CSP/X-CTO/Referrer-Policy/etc. on the root document.
- `web_basic_surface` — Flags frontend dev leaks and server signature/version exposure on basic sites.
- `dns_dmarc_policy` — Parses DMARC/SPF/TLS-RPT TXT records for email posture.
- `ip_reputation_dnsbl` — Checks resolved IPv4s against common DNS block lists.
- `ip_hosting_provider` — Identifies common cloud/CDN providers such as Cloudflare, AWS, GCP, or Azure.
- `ip_geolocation` — Captures city/region/country for resolved IPs and warns when they geolocate outside the US.
- `psi_web_performance` — Calls Google's PSI API when credentials are provided via `PAGESPEED_API_KEY` or `PAGESPEED_CREDENTIALS_FILE`/`GOOGLE_APPLICATION_CREDENTIALS` (service account JSON).

Discovery also emits `site_profiles.json` so the sweep can summarize CMS/API/mail hints before the planner chooses tests.
The HTML bundle is written to `report/index.html` with one page per active host and a separate `report/dead.html` page.

Every module includes inline comments explaining the intent and future work so
frequent contributors can iterate without guesswork.

## Getting Started

```bash
# Format and check the project
cargo fmt
cargo check

# Execute a dry run (uses stub discovery + placeholder plugins)
cargo run -- --config config.toml --rules rules.yaml --plugins plugins
# Result artifacts land under /tmp/a-dap/runs/<domain>/<uuid>/results/*.json
# Stdout/stderr logs land under /tmp/a-dap/runs/<domain>/<uuid>/logs/*
# Discovery profile summaries land under /tmp/a-dap/runs/<domain>/<uuid>/results/site_profiles.json
```

### Python Plugin Dependencies

On startup the orchestrator provisions an isolated venv under `/tmp/a-dap/venvs/<uuid>/` (via `python3 -m venv`) and installs `httpx`, `beautifulsoup4`, and `dnspython`. Ensure the host has outbound access to PyPI the first time you run the tool. Export `PAGESPEED_API_KEY` to enable the PSI test.

At this stage the orchestrator will:

1. Load `config.toml`.
2. Perform recursive passive discovery (DNS, CT, robots, sitemap, root content) and emit site profiles.
3. Plan tests using `rules.yaml`.
4. Invoke the runner, which now captures stdout/stderr and applies manifest timeouts/env vars.

## Next Steps

- Add more CMS/provider fingerprints and a mail-specific test catalog.
- Expand the planner DSL to cover pattern matching and richer conditions.
- Expand the report renderer around the JSON draft in `report.draft.json`.

Contributors are encouraged to keep comments/docstrings verbose in line with
`human_needs.md` so the codebase remains easy to hand off.
