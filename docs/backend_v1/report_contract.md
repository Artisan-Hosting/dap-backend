# Canonical Report Contract

Endpoint: `GET /v1/runs/{run_id}/report`

The backend emits one canonical JSON report per completed run and stores its filesystem path in `reports.report_json_path`.

Top-level shape:

```json
{
  "schema_version": "v1",
  "run": {},
  "requested_tests": [],
  "summary": {},
  "site_profiles": [],
  "dead_hosts": [],
  "results": [],
  "artifacts": [],
  "review": {}
}
```

## `run`

Metadata copied from the `runs` table plus engine identity fields:

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

## `requested_tests`

Requested test outcomes shown as:

- `test_id`
- `state`
- `reason`

## `summary`

Two grouped summaries:

- `run_counts`: `planned`, `completed`, `failed_to_start`, `rejected_not_applicable`
- `result_counts`: `pass`, `warn`, `fail`, `error`, `info`, `skipped`

## `site_profiles`

Direct serialization of persisted discovery site profiles.

## `dead_hosts`

Rows from `dead_hosts` enriched with:

- `host`
- `reason`
- `source`

## `results`

Normalized result rows presented to the frontend:

- `result_id`
- `run_id`
- `target`
- `test_id`
- `plugin_version`
- `status`
- `severity`
- `notes`
- `evidence`
- `recommendations`
- `artifacts`

## `artifacts`

Flattened artifact index for the run:

- `artifact_id`
- `run_id`
- `result_id`
- `artifact_type`
- `relative_path`
- `content_type`
- `size_bytes`

## `review`

Reserved review placeholder for later workflow support:

- `finalized`
- `reviewer`
- `reviewed_at`
- `notes`
