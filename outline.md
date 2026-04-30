# System Design Specification (SDS)

**Project:** Dynamic Domain Auditing Platform
**Owner:** You
**Version:** 1.0 (Draft)
**Target stack:** Go or Rust core + hot-swappable scripts/containers

## 1. Purpose & Goals

Build a platform that, given a domain (e.g., `artisanhosting.net`), automatically:

* Discovers DNS and web assets.
* Infers technologies (e.g., WordPress).
* Dynamically selects and runs the right audits (HSTS/TLS, WordPress checks, SPF/DKIM/DMARC, MX, CNAME integrity, PSI performance).
* Produces:

  * **HTML report** with custom CSS, review & sign-off UI.
  * **JSON** report for automation/archival.

## 2. Scope

* In-scope: DNS/Web discovery, rules-driven audits via scripts, sandboxed execution, PSI integration (mobile+desktop), reporting, rate limiting, single node (with path to distributed).
* Out-of-scope (v1): active vuln scanning, auth-required tests, intrusive load tests, multi-tenant UI.

## 3. Definitions

* **Fact:** Normalized discovery datum (e.g., `web_service`, `dns_record`).
* **Test:** An audit unit run by a plugin/script producing a normalized result.
* **PSI:** PageSpeed Insights API (Lighthouse results).

## 4. Assumptions & Constraints

* Scripts must be hot-swappable (no core recompile).
* Safe-by-default: read-only checks; aggressive probes opt-in.
* Secrets via env/secret store; PSI key optional but recommended.
* Linux host with namespaces/cgroups/seccomp or OCI runtime.

## 5. Users & Primary Use Cases

* **Engineer/Operator:** run audit on a domain; review report; finalize/sign; send to stakeholder.
* **CI job:** periodic auditing; store JSON; gate releases.

## 6. Functional Requirements (FR)

* **FR-1** Accept target domain + scope policy (include/exclude host globs).
* **FR-2** Enumerate DNS: A/AAAA, CNAME, MX, TXT (SPF/DKIM/DMARC), NS, CAA, SRV, SOA; resolve CNAME chains.
* **FR-3** Web probe: HTTPS reachability, redirects, headers, TLS info, meta/fingerprint (e.g., WordPress).
* **FR-4** Detect stacks (WordPress), CDNs, email providers.
* **FR-5** Plan tests via rule engine mapping facts→tests.
* **FR-6** Execute tests by **scripts/containers** (e.g., `wp_audit.sh`, `web_hsts`, `dns_dmarc_policy`, `psi_web_performance`).
* **FR-7** Enforce timeouts, sandboxing, rate limits; dedupe tasks.
* **FR-8** Aggregate results and compute summary/score.
* **FR-9** Produce **HTML** (with custom CSS) and **JSON** outputs.
* **FR-10** HTML must include **Review & Sign** (finalize, signature metadata).
* **FR-11** PSI audit (mobile+desktop; categories: Performance, Accessibility, Best Practices, SEO).
* **FR-12** Store run artifacts (inputs, facts, results, logs).

## 7. Non-Functional Requirements (NFR)

* **NFR-1** Performance: audit typical SME domain in ≤ 3 min (no PSI throttling).
* **NFR-2** Reliability: retries with exponential backoff on transient failures.
* **NFR-3** Security: no-new-privs; non-root; egress ACLs; secret redaction in logs.
* **NFR-4** Extensibility: new plugins via manifest; no core changes.
* **NFR-5** Observability: structured logs, metrics, traces.

## 8. High-Level Architecture

* **Orchestrator (Go/Rust)** – job lifecycle, queues, concurrency.
* **Discovery** – DNS + web probes → **Facts**.
* **Detectors** – convert signals to `stack:wordpress`, `service:web:https`, etc.
* **Planner (Rules Engine)** – evaluates triggers → schedules tests.
* **Plugin Manager** – loads manifests; validates contracts.
* **Runner** – executes scripts/OCI; enforces sandbox/timeouts/limits.
* **External API Queue** – throttles PSI calls.
* **Aggregator** – merges results; computes score.
* **Reporter** – renders JSON + HTML (your CSS, sign-off).
* **Stores** – filesystem for large artifacts, MySQL for structured backend state.

```
[User/CLI] → Orchestrator → Discovery → Facts → Planner → Tasks → Runner → Results
                                          ↑                         ↓
                                      Detectors                Aggregator → Reporter (HTML/JSON)
                                              External API Queue (PSI)
```

## 9. Data Contracts

### 9.1 Fact (Discovery → Bus)

```json
{
  "target": "example.com",
  "entity": "dns_record",
  "id": "dns:TXT:_dmarc.example.com:v=DMARC1; p=none",
  "attrs": {"type":"TXT","name":"_dmarc.example.com","value":"v=DMARC1; p=none","ttl":300}
}
```

### 9.2 Test Input (Runner → Plugin STDIN)

```json
{
  "target": "example.com",
  "facts": [{"entity":"web_service","attrs":{"host":"www.example.com","scheme":"https","port":443}}],
  "config": {"timeouts":{"http_seconds":10}}
}
```

### 9.3 Test Output (Plugin → STDOUT)

```json
{
  "test_id":"web_hsts",
  "target":"www.example.com",
  "status":"pass",       // pass|warn|fail|error|info|skipped
  "severity":"medium",
  "evidence":{"header":"strict-transport-security: ..."},
  "recommendations":["Consider preload"]
}
```

### 9.4 Canonical Report JSON (`report.json`)

```json
{
  "target":"example.com",
  "summary":{"score":87,"tests":{"pass":23,"warn":7,"fail":2}},
  "sections":[
    {"id":"dns","title":"DNS Posture","results":[]},
    {"id":"web","title":"Web Posture","results":[]},
    {"id":"cms","title":"WordPress","results":[]},
    {"id":"psi","title":"PageSpeed Insights","results":[]}
  ],
  "metadata":{"run_id":"2025-10-30T17:55Z","tool_version":"0.4.0"}
}
```

## 10. Plugin System

### 10.1 Layout

```
plugins/
  dns/dns_dmarc_policy/{manifest.yaml,run.py}
  web/web_hsts/{manifest.yaml,run.sh}
  web/psi_web_performance/{manifest.yaml,run.sh}
  cms/wp_audit/{manifest.yaml,run.sh}
```

### 10.2 Manifest Schema

```yaml
id: web_hsts
name: HTTP Strict Transport Security audit
version: 1.2.0
entrypoint: ./run.sh
runtime: shell   # shell|python|node|binary|oci
triggers:
  any:
    - entity: web_service
      where: { scheme: https }
limits:
  timeout_seconds: 20
  memory_mb: 128
env: [PAGESPEED_API_KEY]   # if needed
```

### 10.3 Runner Contract

* Input on **STDIN** (JSON 9.2). Output on **STDOUT** (JSON 9.3).
* Exit code **0** for successful execution (even if `status=fail` as a finding).
* Non-zero = internal plugin error (`status=error` may be emitted if possible).

## 11. Rules Engine (Planner)

Declarative file (hot-reload):

```yaml
rules:
  - when: 'entity=="web_service" && attrs.scheme=="https"'
    run: ["web_hsts","web_tls_config","web_security_headers","psi_web_performance"]
  - when: 'entity=="stack" && attrs.name=="wordpress"'
    run: ["wp_version_exposure","wp_xmlrpc_exposed","wp_rest_permissions"]
  - when: 'entity=="dns_record" && attrs.type=="TXT" && attrs.value.startsWith("v=spf1")'
    run: ["dns_spf_policy"]
  - when: 'entity=="dns_record" && attrs.type=="MX"'
    run: ["dns_mx_smtp_basic"]
```

## 12. Key Audits (Initial Catalog)

* **DNS:** SPF syntax & policy; DKIM key/tags; DMARC presence/policy; CNAME chain/loop/dangling; MX STARTTLS banner.
* **Web (generic):** HTTPS enforced; HSTS; TLS lint (expiry/SAN/protocols); security headers; CDN cache headers.
* **WordPress:** version exposure; XML-RPC exposure; REST anon user list; login rate-limit heuristic.
* **Performance (PSI):** mobile & desktop category scores; top Opportunities; lab vs field data; map Performance to status: `<50=fail`, `50–89=warn`, `≥90=pass`.

## 13. HTML Report (with Review & Sign)

* **Inputs:** `report.json`, `custom.css`.
* **Renderer:** Go `html/template` or Rust `Tera/Askama`.
* **Sections:** Overview (score, counts), DNS, Web, WordPress, **PageSpeed** (gauges for mobile/desktop; top opportunities).
* **Sign-off block:**

  * Reviewer name/role/date; typed/drawn signature.
  * “Finalize” button computes `sha256(report.json)`, stores metadata in `report.review.json`, sets `data-finalized="true"`, disables inputs.
* **Artifacts:**

  ```
  runs/<ts>/report/{report.json, report.html, assets/custom.css, assets/bundle.js, report.review.json}
  ```

## 14. Configuration (TOML)

```toml
[scope]
domain = "example.com"
include = ["*.example.com"]

[psi]
enabled = true
strategies = ["mobile","desktop"]
categories = ["performance","accessibility","best-practices","seo"]
timeout_seconds = 60

[execution]
max_workers = 8
per_host_concurrency = 2

[execution.queues.external_api]
max_workers = 3
rps = 2

[report]
formats = ["json","html"]
css = "report/assets/custom.css"
```

## 15. Security & Compliance

* Process sandbox: user namespaces, seccomp, `no-new-privs`, read-only root FS; temp working dir per test.
* Optional OCI isolation (Docker/Podman).
* Egress allowlist (default restrict to target domain & PSI endpoint).
* Respect `robots.txt` by default; override via config.
* Secrets manager (env injection), never log keys.
* Legal: require authorization for third-party domains.

## 16. Observability

* **Logs:** JSON lines with run_id/test_id/target/duration.
* **Metrics:** tests/sec, pass/warn/fail counts, PSI call latency, error rates (Prometheus).
* **Tracing:** OpenTelemetry spans per test & external call.

## 17. Performance & Scaling

* Cache DNS by TTL; cache HTTP GETs (ETag/Last-Modified).
* Worker pools: general and external-API queues.
* Distributed mode (phase 2): Redis queue + worker replicas; Postgres for results.

## 18. Error Handling & Retries

* Transient network errors: retry with backoff (jitter).
* PSI 429/5xx: exponential backoff; cap attempts.
* Mark test as `error` with diagnostic evidence after max retries.

## 19. Deployment

* **MVP:** single binary + `plugins/` dir; run on Linux host or container.
* **CI:** GitHub Action/CI job; artifact upload of `runs/<ts>/report/*`.
* Optional PDF render via Puppeteer/wkhtmltopdf in CI.

## 20. Testing & QA

* Contract tests for plugin I/O (golden fixtures).
* Static analysis: shellcheck/bandit.
* E2E tests using known domains (local DNS fixtures).
* Load tests with rate-limited targets.

## 21. Risks & Mitigations

* PSI quota exhaustion → token bucket + caching + notify on 429 spikes.
* Script security → sandbox + code review + limited syscalls.
* False positives on tech detection → multi-signal heuristics; allow manual overrides.

## 22. Milestones

1. **MVP (2–3 weeks)**: core orchestration; DNS+HTTPS discovery; rules; HSTS/TLS/SPF/DKIM/DMARC/CNAME; JSON+HTML (basic).
2. **PSI & WordPress (1–2 weeks)**: PSI plugin + external queue; wp_* checks; HTML PSI section.
3. **Sign-off & Hardening (1–2 weeks)**: finalize hash/signature workflow; sandbox tightening; metrics.
4. **Scale & Polish (ongoing)**: Redis workers; Postgres store; PDF export.

## 23. Appendix: Example Snippets

### PSI Plugin Manifest

```yaml
id: psi_web_performance
name: PageSpeed Insights (Lighthouse) audit
version: 1.0.0
entrypoint: ./run.sh
runtime: shell
triggers:
  any:
    - entity: web_service
      where: { scheme: https }
limits: { timeout_seconds: 60, memory_mb: 256 }
env: [PAGESPEED_API_KEY]
```

### HTML Sign-off (template fragment)

```html
<section id="signoff" data-finalized="{{ .Finalized }}">
  <h2>Review & Sign</h2>
  <label>Reviewer <input name="reviewer" value="{{ .Reviewer }}" {{ if .Finalized }}disabled{{ end }}></label>
  <label>Date <input name="date" value="{{ .Date }}" {{ if .Finalized }}disabled{{ end }}></label>
  <canvas id="sigpad"></canvas>
  <button id="finalize" {{ if .Finalized }}disabled{{ end }}>Finalize</button>
</section>
```

