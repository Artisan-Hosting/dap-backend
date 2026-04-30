use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use sqlx::{
    FromRow, MySqlPool,
    mysql::{MySqlConnectOptions, MySqlPoolOptions},
};

use crate::{
    backend::{
        config::{CacheConfig, StorageConfig},
        contracts::{
            ArtifactView, CanonicalReportResponse, DeadHostView, PlannedTestState, ReportRunView,
            ReportSummaryView, RequestedTestState, RequestedTestStatusView, ResultStatusCounts,
            ResultView, ReviewBlockView, RunCounts, RunResultsResponse, RunState,
            RunStatusResponse, TargetHistoryResponse, TargetRunSummary,
        },
    },
    discovery::{DeadHost, SiteProfile},
    facts::Fact,
    tests::{TestOutput, TestSeverity, TestStatus},
};

use tracing::warn;

pub const REPORT_SCHEMA_VERSION: &str = "v1";

#[derive(Debug, Clone)]
pub struct Storage {
    pool: MySqlPool,
}

#[derive(Debug, Clone)]
pub struct RunSubmission {
    pub run_id: String,
    pub state: RunState,
    pub target: String,
}

#[derive(Debug, Clone)]
pub struct QueuedRun {
    pub run_id: String,
    pub target_input: String,
    pub target_key: String,
    pub requested_tests: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PendingPlannedTestRow {
    pub planned_test_id: String,
    pub test_id: String,
    pub execution_target: String,
    pub source_fact_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct NewResultRecord {
    pub result_id: String,
    pub run_id: String,
    pub planned_test_id: String,
    pub target_key: String,
    pub execution_target: String,
    pub test_id: String,
    pub plugin_version: String,
    pub output: TestOutput,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub stderr_non_empty: bool,
    pub duration_ms: i64,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct NewArtifactRecord {
    pub artifact_id: String,
    pub run_id: String,
    pub result_id: Option<String>,
    pub artifact_type: String,
    pub relative_path: String,
    pub content_type: String,
    pub size_bytes: i64,
}

#[derive(Debug, Clone, FromRow)]
struct RunRow {
    run_id: String,
    target_input: String,
    target_key: String,
    state: String,
    submitted_at: DateTime<Utc>,
    started_at: Option<DateTime<Utc>>,
    completed_at: Option<DateTime<Utc>>,
    cache_hit: i64,
    reused_from_run_id: Option<String>,
    force_refresh: i64,
    client_request_id: Option<String>,
    engine_version: String,
    rules_version: String,
    config_hash: String,
    #[allow(dead_code)]
    request_fingerprint: String,
    error_message: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
struct RequestedTestRow {
    test_id: String,
    state: String,
    reason: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
struct ResultRow {
    result_id: String,
    run_id: String,
    planned_test_id: String,
    target_key: String,
    execution_target: String,
    test_id: String,
    plugin_version: String,
    status: String,
    severity: String,
    evidence_json: String,
    recommendations_json: String,
    notes: Option<String>,
    timed_out: i64,
    exit_code: Option<i32>,
    stderr_non_empty: i64,
    duration_ms: i64,
    created_at: DateTime<Utc>,
}

#[allow(dead_code)]
#[derive(Debug, Clone, FromRow)]
struct ArtifactRow {
    artifact_id: String,
    run_id: String,
    result_id: Option<String>,
    artifact_type: String,
    relative_path: String,
    content_type: String,
    size_bytes: i64,
}

#[derive(Debug, Clone, FromRow)]
struct SiteProfileRow {
    host: String,
    kind: String,
    provider: Option<String>,
    confidence: f64,
    signals_json: String,
}

#[derive(Debug, Clone, FromRow)]
struct CtSubdomainCacheRow {
    domain: String,
    source: String,
    subdomains_json: String,
    updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, FromRow)]
struct DeadHostRow {
    host: String,
    reason: String,
    source: String,
}

impl Storage {
    pub async fn connect(config: &StorageConfig) -> Result<Self> {
        let options = MySqlConnectOptions::new()
            .host(&config.mysql.host)
            .port(config.mysql.port)
            .database(&config.mysql.database)
            .username(&config.mysql.username)
            .password(&config.mysql.password);

        let pool = MySqlPoolOptions::new()
            .max_connections(config.mysql.max_connections.max(1))
            .connect_with(options)
            .await
            .with_context(|| {
                format!(
                    "failed to connect to mysql database {}@{}:{}/{}",
                    config.mysql.username,
                    config.mysql.host,
                    config.mysql.port,
                    config.mysql.database,
                )
            })?;

        sqlx::migrate!("./migrations")
            .run(&pool)
            .await
            .context("failed to run mysql migrations")?;

        Ok(Self { pool })
    }

    pub async fn recover_incomplete_runs(&self) -> Result<u64> {
        let run_ids: Vec<String> = sqlx::query_scalar(
            "SELECT run_id FROM runs WHERE state IN ('discovering', 'planning', 'running', 'aggregating')",
        )
        .fetch_all(&self.pool)
        .await
        .context("failed to query incomplete runs")?;

        for run_id in &run_ids {
            let mut tx = self.pool.begin().await?;
            sqlx::query("DELETE FROM reports WHERE run_id = ?")
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM artifacts WHERE run_id = ?")
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM test_results WHERE run_id = ?")
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM planned_tests WHERE run_id = ?")
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM dead_hosts WHERE run_id = ?")
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM site_profiles WHERE run_id = ?")
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query("DELETE FROM facts WHERE run_id = ?")
                .bind(run_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE run_requested_tests SET state = 'accepted', reason = NULL WHERE run_id = ?",
            )
            .bind(run_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE runs SET state = 'queued', started_at = NULL, completed_at = NULL, cache_hit = 0, reused_from_run_id = NULL, error_message = NULL WHERE run_id = ?",
            )
            .bind(run_id)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
        }

        Ok(run_ids.len() as u64)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn submit_run(
        &self,
        target_input: &str,
        target_key: &str,
        requested_tests: &[String],
        force_refresh: bool,
        client_request_id: Option<&str>,
        engine_version: &str,
        rules_version: &str,
        config_hash: &str,
        request_fingerprint: &str,
        cache: &CacheConfig,
    ) -> Result<RunSubmission> {
        if !force_refresh && cache.dedupe_inflight {
            if let Some(run) = self.find_inflight_run(request_fingerprint).await? {
                return Ok(run_submission(&run)?);
            }
        }

        if !force_refresh && cache.freshness_window_seconds > 0 {
            if let Some(source_run) = self
                .find_fresh_completed_run(request_fingerprint, cache.freshness_window_seconds)
                .await?
            {
                let run_id = new_prefixed_id("run");
                let now = Utc::now();
                let mut tx = self.pool.begin().await?;

                sqlx::query(
                    "INSERT INTO runs (run_id, target_input, target_key, state, submitted_at, started_at, completed_at, cache_hit, reused_from_run_id, force_refresh, client_request_id, engine_version, rules_version, config_hash, request_fingerprint, error_message) VALUES (?, ?, ?, 'cache_hit', ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, NULL)",
                )
                .bind(&run_id)
                .bind(target_input)
                .bind(target_key)
                .bind(now)
                .bind(now)
                .bind(now)
                .bind(&source_run.run_id)
                .bind(force_refresh)
                .bind(client_request_id)
                .bind(engine_version)
                .bind(rules_version)
                .bind(config_hash)
                .bind(request_fingerprint)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO run_requested_tests (run_id, test_id, state, reason) SELECT ?, test_id, state, reason FROM run_requested_tests WHERE run_id = ?",
                )
                .bind(&run_id)
                .bind(&source_run.run_id)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;

                return Ok(RunSubmission {
                    run_id,
                    state: RunState::CacheHit,
                    target: target_input.to_string(),
                });
            }
        }

        let run_id = new_prefixed_id("run");
        let submitted_at = Utc::now();
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO runs (run_id, target_input, target_key, state, submitted_at, started_at, completed_at, cache_hit, reused_from_run_id, force_refresh, client_request_id, engine_version, rules_version, config_hash, request_fingerprint, error_message) VALUES (?, ?, ?, 'queued', ?, NULL, NULL, 0, NULL, ?, ?, ?, ?, ?, ?, NULL)",
        )
        .bind(&run_id)
        .bind(target_input)
        .bind(target_key)
        .bind(submitted_at)
        .bind(force_refresh)
        .bind(client_request_id)
        .bind(engine_version)
        .bind(rules_version)
        .bind(config_hash)
        .bind(request_fingerprint)
        .execute(&mut *tx)
        .await?;

        for test_id in requested_tests {
            sqlx::query(
                "INSERT INTO run_requested_tests (run_id, test_id, state, reason) VALUES (?, ?, 'accepted', NULL)",
            )
            .bind(&run_id)
            .bind(test_id)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        Ok(RunSubmission {
            run_id,
            state: RunState::Queued,
            target: target_input.to_string(),
        })
    }

    pub async fn claim_next_run(&self) -> Result<Option<QueuedRun>> {
        loop {
            let candidate: Option<String> = sqlx::query_scalar(
                "SELECT run_id FROM runs WHERE state = 'queued' ORDER BY submitted_at ASC LIMIT 1",
            )
            .fetch_optional(&self.pool)
            .await
            .context("failed to poll queued runs")?;

            let Some(run_id) = candidate else {
                return Ok(None);
            };

            let started_at = Utc::now();
            let updated = sqlx::query(
                "UPDATE runs SET state = 'discovering', started_at = COALESCE(started_at, ?) WHERE run_id = ? AND state = 'queued'",
            )
            .bind(started_at)
            .bind(&run_id)
            .execute(&self.pool)
            .await?;

            if updated.rows_affected() == 0 {
                continue;
            }

            let run = self
                .load_run_row(&run_id)
                .await?
                .with_context(|| format!("claimed run {run_id} disappeared"))?;
            let requested_tests = self.load_requested_test_ids(&run_id).await?;

            return Ok(Some(QueuedRun {
                run_id,
                target_input: run.target_input,
                target_key: run.target_key,
                requested_tests,
            }));
        }
    }

    pub async fn set_run_state(&self, run_id: &str, state: RunState) -> Result<()> {
        sqlx::query("UPDATE runs SET state = ? WHERE run_id = ?")
            .bind(state.as_str())
            .bind(run_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn mark_run_failed(&self, run_id: &str, error_message: &str) -> Result<()> {
        sqlx::query(
            "UPDATE runs SET state = 'failed', completed_at = ?, error_message = ? WHERE run_id = ?",
        )
        .bind(Utc::now())
        .bind(error_message)
        .bind(run_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_run_completed(&self, run_id: &str) -> Result<()> {
        sqlx::query("UPDATE runs SET state = 'completed', completed_at = ? WHERE run_id = ?")
            .bind(Utc::now())
            .bind(run_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    pub async fn load_ct_subdomain_cache(
        &self,
        domain: &str,
    ) -> Result<Option<CtSubdomainCacheEntry>> {
        let row = sqlx::query_as::<_, CtSubdomainCacheRow>(
            "SELECT domain, source, subdomains_json, updated_at FROM ct_subdomain_cache WHERE domain = ?",
        )
        .bind(domain.to_lowercase())
        .fetch_optional(&self.pool)
        .await
        .with_context(|| format!("failed to load ct cache for {domain}"))?;

        row.map(ct_cache_entry_from_row).transpose()
    }

    pub async fn upsert_ct_subdomain_cache(
        &self,
        domain: &str,
        source: &str,
        subdomains: &[String],
    ) -> Result<()> {
        let normalized = dedupe_strings(subdomains.to_vec());
        sqlx::query(
            "INSERT INTO ct_subdomain_cache (domain, source, subdomains_json, updated_at) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE source = VALUES(source), subdomains_json = VALUES(subdomains_json), updated_at = VALUES(updated_at)",
        )
        .bind(domain.to_lowercase())
        .bind(source)
        .bind(serde_json::to_string(&normalized)?)
        .bind(Utc::now())
        .execute(&self.pool)
        .await
        .with_context(|| format!("failed to upsert ct cache for {domain}"))?;

        Ok(())
    }

    pub async fn insert_discovery(
        &self,
        run_id: &str,
        facts: &[Fact],
        site_profiles: &[SiteProfile],
        dead_hosts: &[DeadHost],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        let deduped_facts = dedupe_by_key(facts, |fact| fact.id.0.clone());
        if deduped_facts.len() != facts.len() {
            warn!(
                run_id = %run_id,
                original = facts.len(),
                deduped = deduped_facts.len(),
                skipped = facts.len() - deduped_facts.len(),
                "skipping duplicate discovery facts"
            );
        }

        for fact in deduped_facts {
            sqlx::query(
                "INSERT INTO facts (fact_id, run_id, target_key, entity, attrs_json) VALUES (?, ?, ?, ?, ?)",
            )
            .bind(&fact.id.0)
            .bind(run_id)
            .bind(fact.target.to_lowercase())
            .bind(&fact.entity.0)
            .bind(serde_json::to_string(&fact.attrs)?)
            .execute(&mut *tx)
            .await?;
        }

        let deduped_profiles = dedupe_by_key(site_profiles, |profile| {
            (profile.host.clone(), profile.kind.clone())
        });
        if deduped_profiles.len() != site_profiles.len() {
            warn!(
                run_id = %run_id,
                original = site_profiles.len(),
                deduped = deduped_profiles.len(),
                skipped = site_profiles.len() - deduped_profiles.len(),
                "skipping duplicate site profiles"
            );
        }

        for profile in deduped_profiles {
            sqlx::query(
                "INSERT INTO site_profiles (run_id, host, kind, provider, confidence, signals_json) VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(run_id)
            .bind(&profile.host)
            .bind(&profile.kind)
            .bind(&profile.provider)
            .bind(profile.confidence)
            .bind(serde_json::to_string(&profile.signals)?)
            .execute(&mut *tx)
            .await?;
        }

        let deduped_dead_hosts = dedupe_by_key(dead_hosts, |dead| dead.host.clone());
        if deduped_dead_hosts.len() != dead_hosts.len() {
            warn!(
                run_id = %run_id,
                original = dead_hosts.len(),
                deduped = deduped_dead_hosts.len(),
                skipped = dead_hosts.len() - deduped_dead_hosts.len(),
                "skipping duplicate dead host records"
            );
        }

        for dead in deduped_dead_hosts {
            sqlx::query(
                "INSERT INTO dead_hosts (run_id, host, reason, source) VALUES (?, ?, ?, 'discovery')",
            )
            .bind(run_id)
            .bind(&dead.host)
            .bind(&dead.reason)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn set_requested_test_outcome(
        &self,
        run_id: &str,
        test_id: &str,
        state: RequestedTestState,
        reason: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE run_requested_tests SET state = ?, reason = ? WHERE run_id = ? AND test_id = ?",
        )
        .bind(state.as_str())
        .bind(reason)
        .bind(run_id)
        .bind(test_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn insert_planned_tests(
        &self,
        run_id: &str,
        planned_tests: &[PendingPlannedTestRow],
    ) -> Result<()> {
        let queued_at = Utc::now();
        let mut tx = self.pool.begin().await?;

        for planned in planned_tests {
            sqlx::query(
                "INSERT INTO planned_tests (planned_test_id, run_id, test_id, execution_target, source_fact_id, state, rejection_reason, queued_at, started_at, completed_at) VALUES (?, ?, ?, ?, ?, 'queued', NULL, ?, NULL, NULL)",
            )
            .bind(&planned.planned_test_id)
            .bind(run_id)
            .bind(&planned.test_id)
            .bind(&planned.execution_target)
            .bind(&planned.source_fact_id)
            .bind(queued_at)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(())
    }

    pub async fn mark_planned_test_running(&self, planned_test_id: &str) -> Result<()> {
        sqlx::query(
            "UPDATE planned_tests SET state = 'running', started_at = COALESCE(started_at, ?) WHERE planned_test_id = ?",
        )
        .bind(Utc::now())
        .bind(planned_test_id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn record_result(
        &self,
        planned_state: PlannedTestState,
        result: &NewResultRecord,
        artifacts: &[NewArtifactRecord],
    ) -> Result<()> {
        let mut tx = self.pool.begin().await?;

        sqlx::query(
            "INSERT INTO test_results (result_id, run_id, planned_test_id, target_key, execution_target, test_id, plugin_version, status, severity, evidence_json, recommendations_json, notes, timed_out, exit_code, stderr_non_empty, duration_ms, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&result.result_id)
        .bind(&result.run_id)
        .bind(&result.planned_test_id)
        .bind(&result.target_key)
        .bind(&result.execution_target)
        .bind(&result.test_id)
        .bind(&result.plugin_version)
        .bind(result.output.status.as_str())
        .bind(result.output.severity.as_str())
        .bind(serde_json::to_string(&result.output.evidence)?)
        .bind(serde_json::to_string(&result.output.recommendations)?)
        .bind(&result.output.notes)
        .bind(result.timed_out)
        .bind(result.exit_code)
        .bind(result.stderr_non_empty)
        .bind(result.duration_ms)
        .bind(result.created_at)
        .execute(&mut *tx)
        .await?;

        for artifact in artifacts {
            sqlx::query(
                "INSERT INTO artifacts (artifact_id, run_id, result_id, artifact_type, relative_path, content_type, size_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(&artifact.artifact_id)
            .bind(&artifact.run_id)
            .bind(&artifact.result_id)
            .bind(&artifact.artifact_type)
            .bind(&artifact.relative_path)
            .bind(&artifact.content_type)
            .bind(artifact.size_bytes)
            .execute(&mut *tx)
            .await?;
        }

        sqlx::query(
            "UPDATE planned_tests SET state = ?, completed_at = ? WHERE planned_test_id = ?",
        )
        .bind(planned_state.as_str())
        .bind(Utc::now())
        .bind(&result.planned_test_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn record_report(
        &self,
        run_id: &str,
        report_json_path: &str,
        report_html_path: Option<&str>,
        report_json_size: i64,
    ) -> Result<()> {
        let generated_at = Utc::now();
        let mut tx = self.pool.begin().await?;

        sqlx::query("DELETE FROM reports WHERE run_id = ?")
            .bind(run_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM artifacts WHERE run_id = ? AND artifact_type IN ('report_json', 'report_html')",
        )
        .bind(run_id)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO reports (run_id, report_json_path, report_html_path, generated_at, schema_version) VALUES (?, ?, ?, ?, ?)",
        )
        .bind(run_id)
        .bind(report_json_path)
        .bind(report_html_path)
        .bind(generated_at)
        .bind(REPORT_SCHEMA_VERSION)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "INSERT INTO artifacts (artifact_id, run_id, result_id, artifact_type, relative_path, content_type, size_bytes) VALUES (?, ?, NULL, 'report_json', ?, 'application/json', ?)",
        )
        .bind(new_prefixed_id("art"))
        .bind(run_id)
        .bind(report_json_path)
        .bind(report_json_size)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn get_run_status(&self, run_id: &str) -> Result<Option<RunStatusResponse>> {
        let Some(run) = self.load_run_row(run_id).await? else {
            return Ok(None);
        };

        let effective_run_id = self.effective_run_id(&run).await?;
        let counts = self.load_run_counts(&effective_run_id, &run.run_id).await?;
        let requested_tests = self.load_requested_tests(&run.run_id).await?;

        Ok(Some(RunStatusResponse {
            run_id: run.run_id,
            target: run.target_input,
            state: parse_run_state(&run.state)?,
            submitted_at: run.submitted_at,
            started_at: run.started_at,
            completed_at: run.completed_at,
            cache_hit: from_sql_bool(run.cache_hit),
            reused_from_run_id: run.reused_from_run_id,
            requested_tests,
            counts,
        }))
    }

    pub async fn get_run_results(&self, run_id: &str) -> Result<Option<RunResultsResponse>> {
        let Some(run) = self.load_run_row(run_id).await? else {
            return Ok(None);
        };

        let effective_run_id = self.effective_run_id(&run).await?;
        let requested_test_outcomes = self.load_requested_tests(&run.run_id).await?;
        let results = self.load_results(&effective_run_id, &run.run_id).await?;

        Ok(Some(RunResultsResponse {
            run_id: run.run_id,
            requested_test_outcomes,
            results,
        }))
    }

    pub async fn get_run_report(&self, run_id: &str) -> Result<Option<CanonicalReportResponse>> {
        let Some(run) = self.load_run_row(run_id).await? else {
            return Ok(None);
        };

        let effective_run_id = self.effective_run_id(&run).await?;
        let requested_tests = self.load_requested_tests(&run.run_id).await?;
        let run_counts = self.load_run_counts(&effective_run_id, &run.run_id).await?;
        let results = self.load_results(&effective_run_id, &run.run_id).await?;
        let site_profiles = self.load_site_profiles(&effective_run_id).await?;
        let dead_hosts = self.load_dead_hosts(&effective_run_id).await?;
        let artifacts = self.load_artifacts(&effective_run_id, &run.run_id).await?;

        Ok(Some(CanonicalReportResponse {
            schema_version: REPORT_SCHEMA_VERSION.to_string(),
            run: ReportRunView {
                run_id: run.run_id,
                target_input: run.target_input,
                target_key: run.target_key,
                state: parse_run_state(&run.state)?,
                submitted_at: run.submitted_at,
                started_at: run.started_at,
                completed_at: run.completed_at,
                cache_hit: from_sql_bool(run.cache_hit),
                reused_from_run_id: run.reused_from_run_id,
                force_refresh: from_sql_bool(run.force_refresh),
                client_request_id: run.client_request_id,
                engine_version: run.engine_version,
                rules_version: run.rules_version,
                config_hash: run.config_hash,
                error_message: run.error_message,
            },
            requested_tests,
            summary: ReportSummaryView {
                run_counts,
                result_counts: build_result_counts(&results),
            },
            site_profiles,
            dead_hosts,
            results,
            artifacts,
            review: ReviewBlockView {
                finalized: false,
                reviewer: None,
                reviewed_at: None,
                notes: None,
            },
        }))
    }

    pub async fn get_latest_target_run(
        &self,
        target_key: &str,
    ) -> Result<Option<TargetRunSummary>> {
        let row = sqlx::query_as::<_, RunRow>(
            "SELECT run_id, target_input, target_key, state, submitted_at, started_at, completed_at, cache_hit, reused_from_run_id, force_refresh, client_request_id, engine_version, rules_version, config_hash, request_fingerprint, error_message FROM runs WHERE target_key = ? AND state IN ('completed', 'cache_hit') ORDER BY submitted_at DESC LIMIT 1",
        )
        .bind(target_key)
        .fetch_optional(&self.pool)
        .await?;

        row.map(target_summary_from_row).transpose()
    }

    pub async fn get_target_history(&self, target_key: &str) -> Result<TargetHistoryResponse> {
        let rows = sqlx::query_as::<_, RunRow>(
            "SELECT run_id, target_input, target_key, state, submitted_at, started_at, completed_at, cache_hit, reused_from_run_id, force_refresh, client_request_id, engine_version, rules_version, config_hash, request_fingerprint, error_message FROM runs WHERE target_key = ? AND state IN ('completed', 'cache_hit') ORDER BY submitted_at DESC",
        )
        .bind(target_key)
        .fetch_all(&self.pool)
        .await?;

        let mut runs = Vec::with_capacity(rows.len());
        for row in rows {
            runs.push(target_summary_from_row(row)?);
        }

        Ok(TargetHistoryResponse {
            target: target_key.to_string(),
            runs,
        })
    }

    async fn find_inflight_run(&self, request_fingerprint: &str) -> Result<Option<RunRow>> {
        sqlx::query_as::<_, RunRow>(
            "SELECT run_id, target_input, target_key, state, submitted_at, started_at, completed_at, cache_hit, reused_from_run_id, force_refresh, client_request_id, engine_version, rules_version, config_hash, request_fingerprint, error_message FROM runs WHERE request_fingerprint = ? AND state IN ('queued', 'discovering', 'planning', 'running', 'aggregating') ORDER BY submitted_at DESC LIMIT 1",
        )
        .bind(request_fingerprint)
        .fetch_optional(&self.pool)
        .await
        .context("failed to query equivalent inflight run")
    }

    async fn find_fresh_completed_run(
        &self,
        request_fingerprint: &str,
        freshness_window_seconds: u64,
    ) -> Result<Option<RunRow>> {
        let cutoff = Utc::now() - Duration::seconds(freshness_window_seconds as i64);
        sqlx::query_as::<_, RunRow>(
            "SELECT run_id, target_input, target_key, state, submitted_at, started_at, completed_at, cache_hit, reused_from_run_id, force_refresh, client_request_id, engine_version, rules_version, config_hash, request_fingerprint, error_message FROM runs WHERE request_fingerprint = ? AND state IN ('completed', 'cache_hit') AND completed_at >= ? ORDER BY completed_at DESC LIMIT 1",
        )
        .bind(request_fingerprint)
        .bind(cutoff)
        .fetch_optional(&self.pool)
        .await
        .context("failed to query fresh completed run")
    }

    async fn load_run_row(&self, run_id: &str) -> Result<Option<RunRow>> {
        sqlx::query_as::<_, RunRow>(
            "SELECT run_id, target_input, target_key, state, submitted_at, started_at, completed_at, cache_hit, reused_from_run_id, force_refresh, client_request_id, engine_version, rules_version, config_hash, request_fingerprint, error_message FROM runs WHERE run_id = ?",
        )
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await
        .with_context(|| format!("failed to load run {run_id}"))
    }

    async fn load_requested_test_ids(&self, run_id: &str) -> Result<Vec<String>> {
        sqlx::query_scalar(
            "SELECT test_id FROM run_requested_tests WHERE run_id = ? ORDER BY test_id ASC",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await
        .with_context(|| format!("failed to load requested tests for run {run_id}"))
    }

    async fn load_requested_tests(&self, run_id: &str) -> Result<Vec<RequestedTestStatusView>> {
        let rows = sqlx::query_as::<_, RequestedTestRow>(
            "SELECT test_id, state, reason FROM run_requested_tests WHERE run_id = ? ORDER BY test_id ASC",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await
        .with_context(|| format!("failed to load requested test outcomes for run {run_id}"))?;

        let mut requested = Vec::with_capacity(rows.len());
        for row in rows {
            requested.push(RequestedTestStatusView {
                test_id: row.test_id,
                state: parse_requested_test_state(&row.state)?,
                reason: row.reason,
            });
        }
        Ok(requested)
    }

    async fn load_run_counts(
        &self,
        effective_run_id: &str,
        outer_run_id: &str,
    ) -> Result<RunCounts> {
        let planned: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM planned_tests WHERE run_id = ?")
                .bind(effective_run_id)
                .fetch_one(&self.pool)
                .await
                .with_context(|| {
                    format!("failed to load planned count for run {effective_run_id}")
                })?;

        let completed: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM planned_tests WHERE run_id = ? AND state = 'completed'",
        )
        .bind(effective_run_id)
        .fetch_one(&self.pool)
        .await
        .with_context(|| {
            format!("failed to load completed planned count for run {effective_run_id}")
        })?;

        let failed_to_start: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM planned_tests WHERE run_id = ? AND state = 'failed_to_start'",
        )
        .bind(effective_run_id)
        .fetch_one(&self.pool)
        .await
        .with_context(|| {
            format!("failed to load failed_to_start planned count for run {effective_run_id}")
        })?;

        let rejected_not_applicable: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM run_requested_tests WHERE run_id = ? AND state = 'rejected_not_applicable'",
        )
        .bind(outer_run_id)
        .fetch_one(&self.pool)
        .await
        .with_context(|| format!("failed to load requested test counts for run {outer_run_id}"))?;

        Ok(RunCounts {
            planned: as_u64(planned),
            completed: as_u64(completed),
            failed_to_start: as_u64(failed_to_start),
            rejected_not_applicable: as_u64(rejected_not_applicable),
        })
    }

    async fn effective_run_id(&self, run: &RunRow) -> Result<String> {
        let mut current = run.clone();

        for _ in 0..8 {
            let Some(next) = current.reused_from_run_id.clone() else {
                return Ok(current.run_id);
            };

            current = self.load_run_row(&next).await?.with_context(|| {
                format!("run {} references missing source run {next}", run.run_id)
            })?;
        }

        anyhow::bail!(
            "run {} has an unexpectedly deep cache reuse chain",
            run.run_id
        )
    }

    async fn load_results(
        &self,
        source_run_id: &str,
        presented_run_id: &str,
    ) -> Result<Vec<ResultView>> {
        let rows = sqlx::query_as::<_, ResultRow>(
            "SELECT result_id, run_id, planned_test_id, target_key, execution_target, test_id, plugin_version, status, severity, evidence_json, recommendations_json, notes, timed_out, exit_code, stderr_non_empty, duration_ms, created_at FROM test_results WHERE run_id = ? ORDER BY created_at ASC, test_id ASC, execution_target ASC",
        )
        .bind(source_run_id)
        .fetch_all(&self.pool)
        .await
        .with_context(|| format!("failed to load results for run {source_run_id}"))?;

        let artifact_rows = sqlx::query_as::<_, ArtifactRow>(
            "SELECT artifact_id, run_id, result_id, artifact_type, relative_path, content_type, size_bytes FROM artifacts WHERE run_id = ? ORDER BY artifact_type ASC, relative_path ASC",
        )
        .bind(source_run_id)
        .fetch_all(&self.pool)
        .await
        .with_context(|| format!("failed to load artifacts for run {source_run_id}"))?;

        let mut artifacts_by_result: BTreeMap<String, Vec<ArtifactView>> = BTreeMap::new();
        for artifact in artifact_rows
            .into_iter()
            .filter(|row| row.result_id.is_some())
        {
            let Some(result_id) = artifact.result_id.clone() else {
                continue;
            };
            artifacts_by_result
                .entry(result_id)
                .or_default()
                .push(artifact_view_from_row(artifact, presented_run_id));
        }

        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let evidence = serde_json::from_str(&row.evidence_json)?;
            let recommendations = serde_json::from_str(&row.recommendations_json)?;

            results.push(ResultView {
                result_id: row.result_id.clone(),
                run_id: presented_run_id.to_string(),
                target: row.execution_target,
                test_id: row.test_id,
                plugin_version: row.plugin_version,
                status: parse_test_status(&row.status)?,
                severity: parse_test_severity(&row.severity)?,
                notes: row.notes,
                evidence,
                recommendations,
                artifacts: artifacts_by_result
                    .remove(&row.result_id)
                    .unwrap_or_default(),
            });
        }

        Ok(results)
    }

    async fn load_artifacts(
        &self,
        source_run_id: &str,
        presented_run_id: &str,
    ) -> Result<Vec<ArtifactView>> {
        let rows = sqlx::query_as::<_, ArtifactRow>(
            "SELECT artifact_id, run_id, result_id, artifact_type, relative_path, content_type, size_bytes FROM artifacts WHERE run_id = ? ORDER BY artifact_type ASC, relative_path ASC",
        )
        .bind(source_run_id)
        .fetch_all(&self.pool)
        .await
        .with_context(|| format!("failed to load artifacts for run {source_run_id}"))?;

        Ok(rows
            .into_iter()
            .map(|row| artifact_view_from_row(row, presented_run_id))
            .collect())
    }

    async fn load_site_profiles(&self, run_id: &str) -> Result<Vec<SiteProfile>> {
        let rows = sqlx::query_as::<_, SiteProfileRow>(
            "SELECT host, kind, provider, confidence, signals_json FROM site_profiles WHERE run_id = ? ORDER BY host ASC, kind ASC",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await
        .with_context(|| format!("failed to load site profiles for run {run_id}"))?;

        let mut profiles = Vec::with_capacity(rows.len());
        for row in rows {
            profiles.push(SiteProfile {
                host: row.host,
                kind: row.kind,
                provider: row.provider,
                confidence: row.confidence,
                signals: serde_json::from_str(&row.signals_json)?,
            });
        }
        Ok(profiles)
    }

    async fn load_dead_hosts(&self, run_id: &str) -> Result<Vec<DeadHostView>> {
        let rows = sqlx::query_as::<_, DeadHostRow>(
            "SELECT host, reason, source FROM dead_hosts WHERE run_id = ? ORDER BY host ASC",
        )
        .bind(run_id)
        .fetch_all(&self.pool)
        .await
        .with_context(|| format!("failed to load dead hosts for run {run_id}"))?;

        Ok(rows
            .into_iter()
            .map(|row| DeadHostView {
                host: row.host,
                reason: row.reason,
                source: row.source,
            })
            .collect())
    }
}

fn run_submission(run: &RunRow) -> Result<RunSubmission> {
    Ok(RunSubmission {
        run_id: run.run_id.clone(),
        state: parse_run_state(&run.state)?,
        target: run.target_input.clone(),
    })
}

fn target_summary_from_row(row: RunRow) -> Result<TargetRunSummary> {
    Ok(TargetRunSummary {
        run_id: row.run_id,
        target: row.target_input,
        state: parse_run_state(&row.state)?,
        submitted_at: row.submitted_at,
        completed_at: row.completed_at,
        cache_hit: from_sql_bool(row.cache_hit),
    })
}

fn artifact_view_from_row(row: ArtifactRow, presented_run_id: &str) -> ArtifactView {
    ArtifactView {
        artifact_id: row.artifact_id,
        run_id: presented_run_id.to_string(),
        result_id: row.result_id,
        artifact_type: row.artifact_type,
        relative_path: row.relative_path,
        content_type: row.content_type,
        size_bytes: row.size_bytes,
    }
}

fn ct_cache_entry_from_row(row: CtSubdomainCacheRow) -> Result<CtSubdomainCacheEntry> {
    let subdomains: Vec<String> =
        serde_json::from_str(&row.subdomains_json).with_context(|| {
            format!(
                "failed to parse ct subdomain cache for {} from {}",
                row.domain, row.updated_at
            )
        })?;

    Ok(CtSubdomainCacheEntry {
        domain: row.domain,
        source: row.source,
        subdomains,
        updated_at: row.updated_at,
    })
}

pub(crate) fn dedupe_by_key<'a, T, K, F>(items: &'a [T], mut key_fn: F) -> Vec<&'a T>
where
    K: Ord,
    F: FnMut(&T) -> K,
{
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();

    for item in items {
        if seen.insert(key_fn(item)) {
            deduped.push(item);
        }
    }

    deduped
}

pub(crate) fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

#[derive(Debug, Clone)]
pub struct CtSubdomainCacheEntry {
    pub domain: String,
    pub source: String,
    pub subdomains: Vec<String>,
    pub updated_at: DateTime<Utc>,
}

fn build_result_counts(results: &[ResultView]) -> ResultStatusCounts {
    let mut counts = ResultStatusCounts::default();
    for result in results {
        match result.status {
            TestStatus::Pass => counts.pass += 1,
            TestStatus::Warn => counts.warn += 1,
            TestStatus::Fail => counts.fail += 1,
            TestStatus::Error => counts.error += 1,
            TestStatus::Info => counts.info += 1,
            TestStatus::Skipped => counts.skipped += 1,
        }
    }
    counts
}

fn parse_run_state(value: &str) -> Result<RunState> {
    RunState::parse(value).with_context(|| format!("invalid run state {value}"))
}

fn parse_requested_test_state(value: &str) -> Result<RequestedTestState> {
    RequestedTestState::parse(value)
        .with_context(|| format!("invalid requested test state {value}"))
}

fn parse_test_status(value: &str) -> Result<TestStatus> {
    TestStatus::parse(value).with_context(|| format!("invalid test status {value}"))
}

fn parse_test_severity(value: &str) -> Result<TestSeverity> {
    TestSeverity::parse(value).with_context(|| format!("invalid test severity {value}"))
}

fn as_u64(value: i64) -> u64 {
    value.max(0) as u64
}

fn from_sql_bool(value: i64) -> bool {
    value != 0
}

pub fn new_prefixed_id(prefix: &str) -> String {
    format!("{}_{}", prefix, uuid::Uuid::new_v4().simple())
}
