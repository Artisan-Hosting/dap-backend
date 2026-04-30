# Backend V1 Draft

## 1. Purpose

This document defines the v1 backend shape for turning `artisan_dap` from a CLI-first audit prototype into the backend of a single-tenant web application.

The current repository already has the core audit engine pieces:

- discovery
- planning via `rules.yaml`
- plugin catalog loading from `plugins/*/manifest.yaml`
- plugin execution via `src/runner.rs`
- normalized plugin output via `src/tests.rs::TestOutput`
- HTML rendering via `src/report.rs`

V1 adds the missing service layer around that engine:

- HTTP API
- persistent run records
- persistent queue
- database-backed results and artifacts index
- supported-test catalog for the frontend
- cache and freshness rules

## 2. V1 Scope

V1 is intentionally constrained.

- Single tenant
- Single deployment
- Single node
- One API server process plus one dedicated worker subprocess
- MySQL for structured data
- Filesystem storage for large artifacts
- Web app frontend is the primary client
- CLI shim remains possible later, but is not a v1 driver

## 3. Core Invariants

The backend must enforce these rules.

1. The frontend must only be shown tests the backend can actually run.
2. The backend must validate all requested tests again on submit.
3. A test that is not supported by the deployment must be rejected immediately.
4. A test that is supported globally but is not applicable to the discovered target must be marked as not applicable after planning.
5. If one selected test is not applicable, the run still completes the other applicable tests.
6. HTML is a derived artifact. Canonical data must live in normalized run data plus a canonical `report.json`.
7. Historical runs must not be overwritten by cache reuse or TTL decisions.

## 4. Terms

### 4.1 Supported Test

A test is supported when the backend can execute it in the current deployment.

A test is supported only if all of these are true:

- manifest exists
- entrypoint exists
- runtime is supported by the runner
- required environment variables or credentials are available
- plugin is enabled for this deployment

Supported tests are the only tests exposed by `GET /v1/tests`. This catalog includes normal plugin-backed tests plus a small set of internal discovery capabilities such as `discovery_api_probe` and `discovery_dav_probe` when they are enabled in the deployment config.

### 4.2 Applicable Test

A test is applicable when the planner determines it should run for the requested target after discovery facts are collected.

Examples:

- `psi_web_performance` may be supported by the deployment but only applicable to discovered HTTPS web services
- `dns_dmarc_policy` may be supported by the deployment but not applicable to a target that does not produce the required planning facts

### 4.3 Run

A run is one submitted audit job. It has a server-generated `run_id` and moves through a defined lifecycle.

### 4.4 Planned Test

A planned test is one concrete test invocation derived from discovery and planning. In a domain sweep, a single requested test may become many planned test executions across discovered hosts.

### 4.5 Result

A result is the normalized output from one executed planned test. The current engine already exposes the core payload in `TestOutput`.

### 4.6 Artifact

An artifact is any large or raw output associated with a run or result, such as:

- stdout
- stderr
- rendered HTML
- raw captures saved later by plugins

### 4.7 Freshness Window

A freshness window is the period in which prior results may be reused instead of launching a new execution.

## 5. Current Codebase Mapping

V1 should build around the current engine contracts and the current service layout instead of replacing them.

- binary entrypoint and mode switch: `src/main.rs`
- API server and worker-process coordination: `src/backend/mod.rs`
- worker subprocess loop: `src/backend/worker.rs`
- storage and persistence layer: `src/backend/storage.rs`
- capability registry: `src/backend/capabilities.rs`
- plugin catalog source: `src/plugins.rs`
- rules engine: `src/planner.rs` and `rules.yaml`
- discovery output: `src/discovery.rs`
- test result contract: `src/tests.rs`
- report layer: `src/report.rs`
- report draft: `report.draft.json`

Current implemented service pieces include:

- persistent run, queue, fact, planned-test, result, artifact, and report tables in MySQL
- a dedicated worker subprocess launched by the API server
- cache reuse and freshness-window support
- canonical discovery -> planning -> execution -> aggregation flow in the backend worker
- HTML and JSON report generation paths

Remaining gaps are now mostly around distributed workers, richer plugin isolation, and any future UI workflow beyond the current backend contract.

## 6. High-Level Architecture

The v1 service architecture is:

```text
[Web App]
    |
    v
[HTTP API Server]
    |
    +--> [Capability Registry]
    |
    +--> [Run Store / Queue Store / Results Store]
    |
    +--> [Worker Process]
             |
             v
      [Discovery -> Planner -> Runner -> Aggregator]
             |
             +--> [MySQL]
             +--> [Filesystem Artifacts]
```

V1 keeps the API server and worker in the same binary, but runs them as separate processes. The server starts the worker subprocess with `--worker` and both sides share the same configuration and database.

## 7. Target Model

V1 accepts only domain or hostname targets.

- Accept: `artisanhosting.net`
- Accept: `api.artisanhosting.net`
- Reject: arbitrary URLs with path/query fragments
- Reject: malformed hostnames

The backend stores both:

- `target_input`: original user-provided string
- `target_key`: normalized lowercase target used for lookup and caching

Filesystem-safe sanitized values may still be used for artifact paths, but they are not database identities.

## 8. Test Selection Rules

### 8.1 Frontend Catalog

The frontend gets visible tests from `GET /v1/tests` only.

The frontend must not hardcode hidden or future tests into the UI.

The visible catalog may include internal discovery capabilities that gate extra probing behavior during discovery. These are not user-authored plugin jobs; they are deployment toggles surfaced through the same list so the UI can present them consistently and so operators can disable them when they want a faster, less invasive audit.

### 8.2 Submit Validation

On `POST /v1/runs`, the backend validates:

- target format
- requested test IDs exist in the supported catalog
- request shape is valid

If any requested test is not supported, the entire request is rejected immediately with a client error response.

### 8.3 Planning Outcome

After discovery completes, the planner computes which tests are applicable.

If the user selected tests explicitly, the backend performs:

`requested supported tests` intersect `planner-applicable tests`

Selected tests that are supported but not applicable are recorded as rejected at planning time with reason `not_applicable`.

The run continues with the applicable tests.

## 9. Run Lifecycle

### 9.1 Run States

- `queued`: request accepted and persisted
- `cache_hit`: request satisfied from fresh prior results
- `discovering`: discovery phase in progress
- `planning`: planner phase in progress
- `running`: planned tests executing
- `aggregating`: summary and report generation in progress
- `completed`: run finished successfully, even if some individual tests returned findings or were not applicable
- `failed`: run failed at the system level
- `canceled`: reserved for later manual cancellation support

### 9.2 Per-Requested-Test States

Requested tests should have their own tracking state separate from final audit result status.

- `accepted`
- `rejected_unsupported`
- `rejected_not_applicable`
- `expanded_to_planned_tests`

### 9.3 Per-Planned-Test States

Planned test executions should also have their own lifecycle.

- `queued`
- `running`
- `completed`
- `failed_to_start`
- `skipped_dead_host`

The audit finding status from plugins remains separate and continues to use the existing `TestOutput.status` values such as `pass`, `warn`, `fail`, `error`, `info`, and `skipped`.

## 10. API Surface

### 10.1 `GET /v1/tests`

Returns only tests that are supported by the current deployment.

The response may contain both normal plugin-backed tests and internal discovery capabilities. The latter are gated by backend configuration and control whether discovery performs extra API or DAV follow-up checks on ambiguous hosts.

Example response:

```json
{
  "tests": [
    {
      "id": "web_hsts",
      "name": "HTTP Strict Transport Security audit",
      "version": "0.1.0",
      "runtime": "python",
      "timeout_seconds": 15,
      "category": "web"
    },
    {
      "id": "dns_dmarc_policy",
      "name": "DMARC policy observation",
      "version": "0.1.0",
      "runtime": "python",
      "timeout_seconds": 20,
      "category": "dns"
    }
  ]
}
```

Notes:

- category may be derived from plugin path
- env requirements may be retained internally and do not need to be exposed to the frontend in v1

### 10.2 `POST /v1/runs`

Creates a new audit run or resolves to a cache-backed run record.

Example request:

```json
{
  "target": "artisanhosting.net",
  "requested_tests": ["web_hsts", "psi_web_performance"],
  "force_refresh": false,
  "client_request_id": "webapp-20260427-0001"
}
```

Example accepted response:

```json
{
  "run_id": "run_20260427_000001",
  "state": "queued",
  "target": "artisanhosting.net"
}
```

Immediate rejection example:

```json
{
  "error": "unsupported_tests",
  "unsupported_tests": ["future_magic_test"]
}
```

### 10.3 `GET /v1/runs/{run_id}`

Returns run metadata and progress.

Example response:

```json
{
  "run_id": "run_20260427_000001",
  "target": "artisanhosting.net",
  "state": "running",
  "submitted_at": "2026-04-27T14:00:00Z",
  "started_at": "2026-04-27T14:00:03Z",
  "completed_at": null,
  "cache_hit": false,
  "requested_tests": [
    {"test_id": "web_hsts", "state": "expanded_to_planned_tests"},
    {"test_id": "psi_web_performance", "state": "accepted"}
  ],
  "counts": {
    "planned": 5,
    "completed": 2,
    "failed_to_start": 0,
    "rejected_not_applicable": 0
  }
}
```

### 10.4 `GET /v1/runs/{run_id}/results`

Returns normalized execution outputs and planning rejections.

Example response:

```json
{
  "run_id": "run_20260427_000001",
  "requested_test_outcomes": [
    {
      "test_id": "web_hsts",
      "state": "expanded_to_planned_tests"
    },
    {
      "test_id": "psi_web_performance",
      "state": "rejected_not_applicable",
      "reason": "no applicable https web_service fact discovered"
    }
  ],
  "results": [
    {
      "result_id": "res_001",
      "run_id": "run_20260427_000001",
      "target": "api.artisanhosting.net",
      "test_id": "web_hsts",
      "plugin_version": "0.1.0",
      "status": "warn",
      "severity": "medium",
      "notes": null,
      "evidence": {
        "https_status": 200,
        "hsts_header": null
      }
    }
  ]
}
```

### 10.5 `GET /v1/targets/{target}/latest`

Returns the most recent completed run for a normalized target.

### 10.6 `GET /v1/targets/{target}/history`

Returns historical completed runs for a normalized target, newest first.

### 10.7 `GET /v1/runs/{run_id}/report`

Returns the canonical report payload for the run. In v1 this should return JSON. HTML may be exposed separately later.

## 11. Capability Registry

The capability registry is the backend-owned view of what tests are runnable right now.

It is derived from plugin manifests plus runtime checks.

Inputs:

- plugin manifests on disk
- supported runtimes in the runner
- entrypoint file existence
- required env presence
- deployment-level enabled or disabled flags

Outputs:

- supported test catalog for the frontend
- validation logic for `POST /v1/runs`

V1 should not rely on the frontend to decide what is runnable.

## 12. Queue and Execution Model

### 12.1 Queue

The queue must be persistent and stored in MySQL so accepted runs survive process restarts.

Each run record should carry enough state for the worker to resume or retry safely after restart.

### 12.2 Worker Model

V1 uses one dedicated worker subprocess coordinated with the API server.

The worker repeatedly:

1. claims the next queued run
2. marks it `discovering`
3. performs discovery
4. persists facts and discovered hosts
5. marks it `planning`
6. computes applicable tests
7. records requested-test rejections for non-applicable tests
8. queues planned test executions
9. marks the run `running`
10. executes planned tests under runner limits
11. persists results and artifacts
12. aggregates host and run summaries
13. emits canonical `report.json`
14. marks the run `completed` or `failed`

### 12.3 Rate Limiting

V1 should support three levels of rate limiting.

- global max concurrent planned tests
- per-host concurrency
- external API queue limits for services like PSI

These already align with the existing config model in `RunConfig.execution` and the design intent in `outline.md`.

## 13. Storage Model

### 13.1 Storage Split

Use MySQL for queryable structured data.

Use filesystem storage for large artifacts.

### 13.2 Tables

The following tables are recommended for v1.

#### `runs`

One row per submitted run.

Suggested columns:

- `run_id`
- `target_input`
- `target_key`
- `state`
- `submitted_at`
- `started_at`
- `completed_at`
- `cache_hit`
- `reused_from_run_id`
- `force_refresh`
- `client_request_id`
- `engine_version`
- `rules_version`
- `config_hash`
- `error_message`

#### `run_requested_tests`

One row per requested test ID in the submit request.

Suggested columns:

- `run_id`
- `test_id`
- `state`
- `reason`

#### `facts`

Stores normalized discovery facts.

Suggested columns:

- `fact_id`
- `run_id`
- `target_key`
- `entity`
- `attrs_json`

#### `site_profiles`

Stores discovered site profiles that are currently only written to JSON.

Suggested columns:

- `run_id`
- `host`
- `kind`
- `provider`
- `confidence`
- `signals_json`

#### `dead_hosts`

Stores unreachable or unavailable hosts.

Suggested columns:

- `run_id`
- `host`
- `reason`
- `source`

#### `planned_tests`

One row per concrete execution target derived from planning.

Suggested columns:

- `planned_test_id`
- `run_id`
- `test_id`
- `execution_target`
- `source_fact_id`
- `state`
- `rejection_reason`
- `queued_at`
- `started_at`
- `completed_at`

#### `test_results`

One row per executed planned test.

Suggested columns:

- `result_id`
- `run_id`
- `planned_test_id`
- `target_key`
- `execution_target`
- `test_id`
- `plugin_version`
- `status`
- `severity`
- `evidence_json`
- `recommendations_json`
- `notes`
- `timed_out`
- `exit_code`
- `stderr_non_empty`
- `duration_ms`
- `created_at`

#### `artifacts`

Stores references to filesystem artifacts.

Suggested columns:

- `artifact_id`
- `run_id`
- `result_id`
- `artifact_type`
- `relative_path`
- `content_type`
- `size_bytes`

#### `reports`

Stores the canonical report snapshot reference for a run.

Suggested columns:

- `run_id`
- `report_json_path`
- `report_html_path`
- `generated_at`
- `schema_version`

## 14. Result Identity

Do not key results by `sanitized_domain + test_id`.

That combination is not enough because the same target and test may be run:

- at different times
- under different plugin versions
- under different config values
- under different rule sets
- under different freshness windows
- against different discovered hosts within the same sweep

Recommended identities:

- `run_id`: one submitted run
- `planned_test_id`: one concrete planned execution
- `result_id`: one execution result row
- `target_key`: normalized lookup key
- `test_id`: plugin identifier only, not a unique row key

For lookup, the primary paths should be:

- by `run_id`
- by `target_key` plus sort by time

## 15. Caching, TTL, and Deduping

### 15.1 TTL Meaning

TTL is a freshness rule, not a deletion rule.

TTL answers:

- can prior results be reused
- should a new run be enqueued
- is a result stale for the requested operation

TTL does not:

- delete history
- overwrite historical runs

### 15.2 Cache Key

Freshness and reuse should be based on a cache key or request fingerprint, not just target plus test ID.

Suggested fingerprint inputs:

- `target_key`
- requested test set
- scope mode
- relevant config hash
- rules version
- engine version
- plugin versions for requested tests

### 15.3 Cache Behavior

If `force_refresh` is false and a fresh equivalent result exists, the backend may create a new run record marked `cache_hit` and link it to `reused_from_run_id`.

This keeps user submissions traceable without destroying historical truth.

### 15.4 In-Flight Deduping

If an equivalent run is already `queued`, `discovering`, `planning`, or `running`, the backend may return that in-flight run instead of creating duplicate work.

V1 may implement this after the basic queue and storage model are working.

## 16. Canonical Report Model

The backend should emit a canonical `report.json` for every completed run.

The existing `report.draft.json` is the right starting point, but it needs to be backed by stored run data instead of the HTML renderer rebuilding state directly from ad hoc files.

Minimum report sections for v1:

- run metadata
- requested tests and their outcomes
- summary counts
- site profiles
- dead hosts
- executed test results
- artifact references
- review block placeholder

HTML remains a derived rendering of this canonical report model.

## 17. Error Handling Rules

### 17.1 Request-Level Rejections

Reject immediately when:

- target is invalid
- requested test is unsupported
- request payload is malformed

These should return client errors and should not enter the worker queue.

### 17.2 Planning-Level Rejections

Mark as `rejected_not_applicable` when:

- the requested test is supported by the backend
- but discovery and planning show it does not apply to this run

The run must continue with other applicable tests.

### 17.3 Execution-Level Errors

If a planned test starts but errors or times out, record a normal result row using the current `TestOutput` contract and existing runner metadata.

### 17.4 System-Level Failures

Mark the whole run `failed` only for system failures such as:

- discovery crash
- unrecoverable database failure
- report aggregation failure

Individual audit findings or plugin-level errors should not automatically fail the run.

## 18. Frontend Contract

The frontend is expected to:

- read the supported catalog from `GET /v1/tests`
- allow optional subset selection from that catalog
- submit a target and selected tests
- persist returned `run_id`
- poll by `run_id`
- display both final results and planning-time rejections such as `not applicable`

The frontend must not be the source of truth for test support or applicability.

## 19. Recommended Implementation Order

1. Extract reusable aggregation logic from `src/report.rs` into a report service layer.
2. Add a capability registry on top of `PluginCatalog` and runner/runtime checks.
3. Introduce MySQL-backed `runs`, `run_requested_tests`, `facts`, `planned_tests`, and `test_results`.
4. Introduce persistent artifact indexing while continuing to store stdout and stderr on disk.
5. Add HTTP endpoints for tests, run creation, run status, and run results.
6. Add a persistent queue and dedicated worker subprocess.
7. Emit canonical `report.json` from stored run data.
8. Add TTL and cache reuse once basic end-to-end execution is stable.

## 20. Deferred For Later Versions

These are intentionally out of v1.

- multi-tenant access control
- distributed workers
- external queue service
- object storage
- user-triggered cancellation
- websocket or SSE live streaming
- signed review workflow enforcement
- public API productization

## 21. Summary

V1 should be treated as a service wrapper around the existing engine, not a rewrite of the engine itself.

The key design choices are:

- only expose supported tests to the frontend
- reject unsupported tests immediately
- reject non-applicable selected tests after planning without failing the run
- use `run_id` as the primary identity for retrieval
- store structured data in MySQL and large artifacts on disk
- keep history immutable and use TTL only for freshness and reuse decisions
- run the API server and worker as separate processes from the same binary

That gives the web app a stable backend contract while preserving the current strengths of the discovery, planner, runner, and reporting pipeline already present in this repository.
