# Database Schema

Migration source: `migrations/0001_backend_v1.sql`

## `runs`

One row per submission or cache-hit projection.

Columns:

- `run_id` primary key
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
- `request_fingerprint`
- `error_message`

Indexes:

- `idx_runs_target_key_submitted_at`
- `idx_runs_state_submitted_at`
- `idx_runs_request_fingerprint`

## `run_requested_tests`

One row per requested test in the accepted request set.

Columns:

- `run_id`
- `test_id`
- `state`
- `reason`

Primary key:

- `(run_id, test_id)`

## `facts`

Normalized discovery facts persisted as JSON attribute maps.

Columns:

- `fact_id`
- `run_id`
- `target_key`
- `entity`
- `attrs_json`

Primary key:

- `(run_id, fact_id)`

## `site_profiles`

Discovered host classification summaries.

Columns:

- `run_id`
- `host`
- `kind`
- `provider`
- `confidence`
- `signals_json`

## `dead_hosts`

Discovery-time unreachable hosts.

Columns:

- `run_id`
- `host`
- `reason`
- `source`

## `planned_tests`

Concrete planned executions derived from planner output.

Columns:

- `planned_test_id` primary key
- `run_id`
- `test_id`
- `execution_target`
- `source_fact_id`
- `state`
- `rejection_reason`
- `queued_at`
- `started_at`
- `completed_at`

## `test_results`

One row per produced normalized result.

Columns:

- `result_id` primary key
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

## `artifacts`

Filesystem artifact index.

Columns:

- `artifact_id` primary key
- `run_id`
- `result_id` nullable for run-level artifacts
- `artifact_type`
- `relative_path`
- `content_type`
- `size_bytes`

Current artifact types emitted by the service:

- `stdout`
- `stderr`
- `report_json`

## `reports`

Canonical report snapshot reference for a run.

Columns:

- `run_id` primary key
- `report_json_path`
- `report_html_path`
- `generated_at`
- `schema_version`

## Relationships

- `run_requested_tests`, `facts`, `site_profiles`, `dead_hosts`, `planned_tests`, `test_results`, `artifacts`, and `reports` all attach to `runs.run_id`.
- `test_results.planned_test_id` references `planned_tests.planned_test_id`.
- `artifacts.result_id` references `test_results.result_id` when the artifact belongs to a single result.
- `runs.reused_from_run_id` links cache-hit rows back to the canonical source run.
