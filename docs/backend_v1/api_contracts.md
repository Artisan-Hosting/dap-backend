# API Contracts

Base path: `/v1`

## `GET /v1/tests`

Returns only tests that are runnable in the current deployment.

Response shape:

```json
{
  "tests": [
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

## `POST /v1/runs`

Accepts a new audit submission.

Request shape:

```json
{
  "target": "artisanhosting.net",
  "requested_tests": ["dns_dmarc_policy", "psi_web_performance"],
  "force_refresh": false,
  "client_request_id": "webapp-20260427-0001"
}
```

Behavior:

- `target` must be a hostname or domain only.
- empty `requested_tests` means "run all supported tests currently exposed by `GET /v1/tests`".
- unsupported requested tests are rejected before queueing.
- equivalent in-flight runs are deduped.
- cache-hit reuse is available only when `cache.freshness_window_seconds > 0`.

Accepted response shape:

```json
{
  "run_id": "run_...",
  "state": "queued",
  "target": "artisanhosting.net"
}
```

Immediate unsupported-test rejection:

```json
{
  "error": "unsupported_tests",
  "unsupported_tests": ["future_magic_test"]
}
```

## `GET /v1/runs/{run_id}`

Returns run metadata and progress.

Response shape:

```json
{
  "run_id": "run_...",
  "target": "artisanhosting.net",
  "state": "running",
  "submitted_at": "2026-04-27T14:00:00Z",
  "started_at": "2026-04-27T14:00:03Z",
  "completed_at": null,
  "cache_hit": false,
  "reused_from_run_id": null,
  "requested_tests": [
    {
      "test_id": "dns_dmarc_policy",
      "state": "expanded_to_planned_tests"
    }
  ],
  "counts": {
    "planned": 3,
    "completed": 1,
    "failed_to_start": 0,
    "rejected_not_applicable": 0
  }
}
```

## `GET /v1/runs/{run_id}/results`

Returns requested-test outcomes plus normalized execution results.

Response shape:

```json
{
  "run_id": "run_...",
  "requested_test_outcomes": [
    {
      "test_id": "psi_web_performance",
      "state": "rejected_not_applicable",
      "reason": "no applicable discovery facts satisfied this test's planner rules"
    }
  ],
  "results": [
    {
      "result_id": "res_...",
      "run_id": "run_...",
      "target": "artisanhosting.net",
      "test_id": "dns_dmarc_policy",
      "plugin_version": "0.1.0",
      "status": "pass",
      "severity": "informational",
      "notes": null,
      "evidence": {},
      "recommendations": [],
      "artifacts": []
    }
  ]
}
```

## `GET /v1/targets/{target}/latest`

Returns the newest completed or cache-hit run summary for a normalized target.

## `GET /v1/targets/{target}/history`

Returns historical completed or cache-hit runs for a normalized target, newest first.

Response shape:

```json
{
  "target": "artisanhosting.net",
  "runs": [
    {
      "run_id": "run_...",
      "target": "artisanhosting.net",
      "state": "completed",
      "submitted_at": "2026-04-27T14:00:00Z",
      "completed_at": "2026-04-27T14:01:12Z",
      "cache_hit": false
    }
  ]
}
```

## `GET /v1/runs/{run_id}/report`

Returns the canonical report JSON described in `report_contract.md`.

## Shared Enums

Run states:

- `queued`
- `cache_hit`
- `discovering`
- `planning`
- `running`
- `aggregating`
- `completed`
- `failed`
- `canceled`

Requested test states:

- `accepted`
- `rejected_unsupported`
- `rejected_not_applicable`
- `expanded_to_planned_tests`

Planned test states stored internally:

- `queued`
- `running`
- `completed`
- `failed_to_start`
- `skipped_dead_host`
