use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::{Context, Result};
use serde_json::json;
use tokio::{
    fs,
    sync::{Mutex, Semaphore},
    task::JoinSet,
    time::{Duration, sleep},
};
use tracing::{error, info};

use crate::{
    backend::{
        AppState,
        contracts::{PlannedTestState, RequestedTestState, RunState},
        storage::{NewArtifactRecord, NewResultRecord, PendingPlannedTestRow, new_prefixed_id},
    },
    discovery::perform_discovery_with_ct_cache,
    tests::{TestInput, TestOutput, TestStatus},
    workspace::sanitize_component,
};

const MAX_DISCOVERED_SUBDOMAINS: usize = 100;

#[derive(Debug, Clone)]
struct RuntimePlannedTest {
    planned_test_id: String,
    test_id: String,
    execution_target: String,
    source_fact_id: Option<String>,
    supporting_facts: Vec<crate::facts::Fact>,
}

#[derive(Debug, Clone)]
struct RunPaths {
    artifacts_root: PathBuf,
    root: PathBuf,
    results_dir: PathBuf,
    logs_dir: PathBuf,
    report_dir: PathBuf,
}

impl RunPaths {
    async fn prepare(base: &Path, target_key: &str, run_id: &str) -> Result<Self> {
        let root = base.join(sanitize_component(target_key)).join(run_id);
        if fs::metadata(&root).await.is_ok() {
            fs::remove_dir_all(&root)
                .await
                .with_context(|| format!("failed to clean artifact root {}", root.display()))?;
        }

        let results_dir = root.join("results");
        let logs_dir = root.join("logs");
        let report_dir = root.join("report");
        fs::create_dir_all(&results_dir).await?;
        fs::create_dir_all(&logs_dir).await?;
        fs::create_dir_all(&report_dir).await?;

        Ok(Self {
            artifacts_root: base.to_path_buf(),
            root,
            results_dir,
            logs_dir,
            report_dir,
        })
    }

    fn relative(&self, path: &Path) -> Result<String> {
        Ok(path
            .strip_prefix(&self.artifacts_root)
            .with_context(|| {
                format!(
                    "{} is outside {}",
                    path.display(),
                    self.artifacts_root.display()
                )
            })?
            .to_string_lossy()
            .to_string())
    }
}

pub async fn run_loop(state: Arc<AppState>) -> Result<()> {
    let active_run_limit = state.config.engine.execution.max_concurrent_tests.max(1);
    let shared_test_budget = Arc::new(Semaphore::new(active_run_limit));
    let mut active_runs = JoinSet::new();
    let mut active_run_count = 0usize;
    let mut accepting_runs = true;

    loop {
        if accepting_runs && state.shutdown.is_triggered() {
            accepting_runs = false;
            info!("worker received shutdown request; draining active runs");
        }

        while accepting_runs && active_run_count < active_run_limit {
            match state.storage.claim_next_run().await {
                Ok(Some(run)) => {
                    let state = state.clone();
                    let shared_test_budget = shared_test_budget.clone();
                    active_runs
                        .spawn(async move { process_run(state, run, shared_test_budget).await });
                    active_run_count += 1;
                }
                Ok(None) => {
                    break;
                }
                Err(err) => {
                    error!(error = %err, "worker queue claim failed");
                    break;
                }
            }
        }

        if active_run_count == 0 {
            if !accepting_runs {
                info!("worker exiting cleanly after shutdown request");
                return Ok(());
            }

            tokio::select! {
                _ = state.shutdown.notified() => {
                    accepting_runs = false;
                }
                _ = sleep(Duration::from_millis(state.config.engine.worker_poll_interval_ms)) => {}
            }

            continue;
        }

        match active_runs.join_next().await {
            Some(Ok(Ok(()))) => {}
            Some(Ok(Err(err))) => {
                error!(error = %err, "run processing failed");
            }
            Some(Err(err)) => {
                error!(error = %err, "run processing task failed to join");
            }
            None => {}
        }

        active_run_count = active_run_count.saturating_sub(1);
    }
}

async fn process_run(
    state: Arc<AppState>,
    run: crate::backend::storage::QueuedRun,
    shared_test_budget: Arc<Semaphore>,
) -> Result<()> {
    if state.shutdown.is_triggered() {
        info!(run_id = %run.run_id, "shutdown requested; finishing current run before exit");
    }
    info!(run_id = %run.run_id, target = %run.target_key, target_input = %run.target_input, "worker claimed run");
    let run_paths = RunPaths::prepare(
        &state.config.storage.artifacts_root,
        &run.target_key,
        &run.run_id,
    )
    .await?;

    let process_result = async {
        let run_config = state
            .config
            .audit_config_for_target(&run.target_key, &run.requested_tests);
        let discovery = perform_discovery_with_ct_cache(
            &run_config,
            &state.storage,
            state.config.cache.ct_subdomain_cache_ttl_seconds,
        )
        .await?;
        state
            .storage
            .insert_discovery(
                &run.run_id,
                &discovery.facts,
                &discovery.site_profiles,
                &discovery.dead_hosts,
            )
            .await?;

        if state.shutdown.is_triggered() {
            info!(
                run_id = %run.run_id,
                "shutdown requested after discovery; leaving run incomplete for recovery"
            );
            return Ok::<(), anyhow::Error>(());
        }

        if discovery.subdomain_count > MAX_DISCOVERED_SUBDOMAINS {
            let reason = format!(
                "domain too big: discovered {} subdomains (limit {})",
                discovery.subdomain_count, MAX_DISCOVERED_SUBDOMAINS
            );

            for requested_test in &run.requested_tests {
                let state_value =
                    if crate::backend::capabilities::is_internal_discovery_probe(requested_test) {
                        RequestedTestState::Accepted
                    } else {
                        RequestedTestState::RejectedNotApplicable
                    };
                let state_reason =
                    if crate::backend::capabilities::is_internal_discovery_probe(requested_test) {
                        None
                    } else {
                        Some(reason.as_str())
                    };
                state
                    .storage
                    .set_requested_test_outcome(
                        &run.run_id,
                        requested_test,
                        state_value,
                        state_reason,
                    )
                    .await?;
            }

            state
                .storage
                .set_run_state(&run.run_id, RunState::Aggregating)
                .await?;
            write_report(state.clone(), &run.run_id, &run_paths).await?;
            state.storage.mark_run_completed(&run.run_id).await?;
            return Ok(());
        }

        state
            .storage
            .set_run_state(&run.run_id, RunState::Planning)
            .await?;

        let requested_lookup: std::collections::BTreeSet<String> = run
            .requested_tests
            .iter()
            .filter(|test_id| !crate::backend::capabilities::is_internal_discovery_probe(test_id))
            .cloned()
            .collect();
        let mut applicable_counts: BTreeMap<String, usize> = BTreeMap::new();
        let mut runtime_tests = Vec::new();

        for planned in state.engine.rules.plan(&discovery.facts) {
            let test_id = planned.test_id.0.clone();
            if !requested_lookup.contains(&test_id) {
                continue;
            }

            *applicable_counts.entry(test_id.clone()).or_default() += 1;
            runtime_tests.push(RuntimePlannedTest {
                planned_test_id: new_prefixed_id("pt"),
                execution_target: derive_execution_target(
                    &planned.supporting_facts,
                    &run.target_key,
                ),
                source_fact_id: planned
                    .supporting_facts
                    .first()
                    .map(|fact| fact.id.0.clone()),
                test_id,
                supporting_facts: planned.supporting_facts,
            });
        }

        for requested_test in &run.requested_tests {
            if crate::backend::capabilities::is_internal_discovery_probe(requested_test) {
                state
                    .storage
                    .set_requested_test_outcome(
                        &run.run_id,
                        requested_test,
                        RequestedTestState::Accepted,
                        None,
                    )
                    .await?;
            } else if applicable_counts.contains_key(requested_test) {
                state
                    .storage
                    .set_requested_test_outcome(
                        &run.run_id,
                        requested_test,
                        RequestedTestState::ExpandedToPlannedTests,
                        None,
                    )
                    .await?;
            } else {
                state
                    .storage
                    .set_requested_test_outcome(
                        &run.run_id,
                        requested_test,
                        RequestedTestState::RejectedNotApplicable,
                        Some("no applicable discovery facts satisfied this test's planner rules"),
                    )
                    .await?;
            }
        }

        let pending_rows: Vec<PendingPlannedTestRow> = runtime_tests
            .iter()
            .map(|planned| PendingPlannedTestRow {
                planned_test_id: planned.planned_test_id.clone(),
                test_id: planned.test_id.clone(),
                execution_target: planned.execution_target.clone(),
                source_fact_id: planned.source_fact_id.clone(),
            })
            .collect();

        state
            .storage
            .insert_planned_tests(&run.run_id, &pending_rows)
            .await?;

        if state.shutdown.is_triggered() {
            info!(
                run_id = %run.run_id,
                "shutdown requested after planning; leaving run incomplete for recovery"
            );
            return Ok::<(), anyhow::Error>(());
        }

        let (main_tests, api_tests): (Vec<_>, Vec<_>) = runtime_tests
            .into_iter()
            .partition(|planned| !crate::tests::runs_in_late_phase(&planned.test_id));

        info!(
            run_id = %run.run_id,
            main_tests = main_tests.len(),
            api_tests = api_tests.len(),
            "split planned tests into main and deferred phases"
        );

        if !main_tests.is_empty() {
            state
                .storage
                .set_run_state(&run.run_id, RunState::Running)
                .await?;
            execute_planned_tests_phase(
                "main",
                state.clone(),
                &run,
                &run_paths,
                main_tests,
                &discovery.dead_hosts,
                shared_test_budget.clone(),
            )
            .await?;
        }

        if state.shutdown.is_triggered() {
            info!(
                run_id = %run.run_id,
                "shutdown requested after main phase; leaving run incomplete for recovery"
            );
            return Ok::<(), anyhow::Error>(());
        }

        if !api_tests.is_empty() {
            info!(
                run_id = %run.run_id,
                tests = api_tests.len(),
                "starting deferred api fuzz phase"
            );
            execute_planned_tests_phase(
                "api_fuzz",
                state.clone(),
                &run,
                &run_paths,
                api_tests,
                &discovery.dead_hosts,
                shared_test_budget.clone(),
            )
            .await?;
            info!(run_id = %run.run_id, "completed deferred api fuzz phase");
        }

        if state.shutdown.is_triggered() {
            info!(
                run_id = %run.run_id,
                "shutdown requested before final aggregation; leaving run incomplete for recovery"
            );
            return Ok::<(), anyhow::Error>(());
        }

        state
            .storage
            .set_run_state(&run.run_id, RunState::Aggregating)
            .await?;
        write_report(state.clone(), &run.run_id, &run_paths).await?;
        state.storage.mark_run_completed(&run.run_id).await?;

        Ok::<(), anyhow::Error>(())
    }
    .await;

    if let Err(err) = process_result {
        state
            .storage
            .mark_run_failed(&run.run_id, &err.to_string())
            .await?;
        return Err(err);
    }

    info!(run_id = %run.run_id, "worker completed run");
    Ok(())
}

async fn execute_planned_tests_phase(
    phase: &'static str,
    state: Arc<AppState>,
    run: &crate::backend::storage::QueuedRun,
    run_paths: &RunPaths,
    planned_tests: Vec<RuntimePlannedTest>,
    dead_hosts: &[crate::discovery::DeadHost],
    shared_test_budget: Arc<Semaphore>,
) -> Result<()> {
    let run_limit = state.config.engine.execution.max_workers.max(1);
    let per_host_limit = state.config.engine.execution.per_host_concurrency.max(1);
    let run_budget = Arc::new(Semaphore::new(run_limit));
    let host_limits: Arc<Mutex<HashMap<String, Arc<Semaphore>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let dead_map: Arc<BTreeMap<String, String>> = Arc::new(
        dead_hosts
            .iter()
            .map(|host| (host.host.to_lowercase(), host.reason.clone()))
            .collect(),
    );

    let mut join_set = JoinSet::new();
    for planned in planned_tests {
        if state.shutdown.is_triggered() {
            info!(
                phase = phase,
                "shutdown requested before scheduling more planned tests"
            );
            break;
        }
        let state = state.clone();
        let run_id = run.run_id.clone();
        let run_paths = run_paths.clone();
        let run_budget = run_budget.clone();
        let shared_test_budget = shared_test_budget.clone();
        let host_limits = host_limits.clone();
        let dead_map = dead_map.clone();

        join_set.spawn(async move {
            let _run_guard = run_budget.acquire_owned().await?;
            let _global_guard = shared_test_budget.acquire_owned().await?;
            let host_key = planned.execution_target.to_lowercase();
            let host_sem = host_semaphore(&host_limits, &host_key, per_host_limit).await;
            let _host_guard = host_sem.acquire_owned().await?;

            if state.shutdown.is_triggered() {
                info!(
                    phase = phase,
                    test_id = %planned.test_id,
                    target = %planned.execution_target,
                    "shutdown requested before planned test start"
                );
                return Ok::<(), anyhow::Error>(());
            }

            execute_one_planned_test(phase, state, &run_id, &run_paths, planned, &dead_map).await
        });
    }

    while let Some(result) = join_set.join_next().await {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return Err(err),
            Err(err) => anyhow::bail!("planned test task failed to join: {err}"),
        }
    }

    Ok(())
}

async fn execute_one_planned_test(
    phase: &'static str,
    state: Arc<AppState>,
    run_id: &str,
    run_paths: &RunPaths,
    planned: RuntimePlannedTest,
    dead_map: &BTreeMap<String, String>,
) -> Result<()> {
    let RuntimePlannedTest {
        planned_test_id,
        test_id,
        execution_target,
        supporting_facts,
        ..
    } = planned;

    info!(
        phase = phase,
        test_id = %test_id,
        target = %execution_target,
        planned_test_id = %planned_test_id,
        "starting planned test"
    );

    state
        .storage
        .mark_planned_test_running(&planned_test_id)
        .await?;

    let plugin_version = state
        .engine
        .plugins
        .get(&crate::tests::TestId(test_id.clone()))
        .map(|record| record.manifest.version.clone())
        .unwrap_or_else(|| "unknown".to_string());

    if !crate::tests::runs_on_dead_host(&test_id) {
        if let Some(reason) = dead_map.get(&execution_target.to_lowercase()) {
            let result = NewResultRecord {
                result_id: new_prefixed_id("res"),
                run_id: run_id.to_string(),
                planned_test_id,
                target_key: execution_target.to_lowercase(),
                execution_target: execution_target.clone(),
                test_id: test_id.clone(),
                plugin_version,
                output: TestOutput::placeholder(
                    test_id,
                    execution_target.clone(),
                    TestStatus::Skipped,
                    format!("host marked dead: {reason}"),
                ),
                timed_out: false,
                exit_code: None,
                stderr_non_empty: false,
                duration_ms: 0,
                created_at: chrono::Utc::now(),
            };

            state
                .storage
                .record_result(PlannedTestState::SkippedDeadHost, &result, &[])
                .await?;
            info!(
                phase = phase,
                test_id = %result.test_id,
                target = %result.execution_target,
                "skipped planned test on dead host"
            );
            return Ok(());
        }
    }

    let Some(record) = state
        .engine
        .plugins
        .get(&crate::tests::TestId(test_id.clone()))
        .cloned()
    else {
        let result = NewResultRecord {
            result_id: new_prefixed_id("res"),
            run_id: run_id.to_string(),
            planned_test_id,
            target_key: execution_target.to_lowercase(),
            execution_target: execution_target.clone(),
            test_id: test_id.clone(),
            plugin_version,
            output: TestOutput::placeholder(
                test_id,
                execution_target.clone(),
                TestStatus::Error,
                "requested plugin is no longer present in the plugin catalog",
            ),
            timed_out: false,
            exit_code: None,
            stderr_non_empty: true,
            duration_ms: 0,
            created_at: chrono::Utc::now(),
        };

        state
            .storage
            .record_result(PlannedTestState::FailedToStart, &result, &[])
            .await?;
        info!(
            phase = phase,
            test_id = %result.test_id,
            target = %result.execution_target,
            "planned test plugin missing"
        );
        return Ok(());
    };

    let input = TestInput {
        target: execution_target.clone(),
        facts: supporting_facts.clone(),
        config: json!({
            "run_root": run_paths.root,
            "results_dir": run_paths.results_dir,
            "logs_dir": run_paths.logs_dir,
            "psi_credentials_file": state.config.engine.psi.as_ref().and_then(|psi| psi.credentials_file.clone()),
        }),
    };

    let execution = state.engine.runner.execute(&record, &input).await;
    let result_id = new_prefixed_id("res");
    let artifacts = persist_stream_artifacts(
        run_id,
        &result_id,
        run_paths,
        &planned_test_id,
        &test_id,
        &execution_target,
        &execution.stdout,
        &execution.stderr,
    )
    .await?;

    let result = NewResultRecord {
        result_id,
        run_id: run_id.to_string(),
        planned_test_id,
        target_key: execution_target.to_lowercase(),
        execution_target,
        test_id,
        plugin_version: record.manifest.version,
        output: execution.output,
        timed_out: execution.timed_out,
        exit_code: execution.exit_code,
        stderr_non_empty: execution.stderr_non_empty,
        duration_ms: execution.duration_ms,
        created_at: chrono::Utc::now(),
    };

    let planned_state = if execution.started {
        PlannedTestState::Completed
    } else {
        PlannedTestState::FailedToStart
    };
    let planned_state_label = planned_state.as_str();

    state
        .storage
        .record_result(planned_state, &result, &artifacts)
        .await?;

    info!(
        phase = phase,
        test_id = %result.test_id,
        target = %result.execution_target,
        planned_state = planned_state_label,
        "finished planned test"
    );

    Ok(())
}

async fn write_report(state: Arc<AppState>, run_id: &str, run_paths: &RunPaths) -> Result<()> {
    let report = state
        .storage
        .get_run_report(run_id)
        .await?
        .with_context(|| format!("run {run_id} disappeared before report generation"))?;

    let path = run_paths.report_dir.join("report.json");
    let payload = serde_json::to_vec_pretty(&report)?;
    fs::write(&path, &payload)
        .await
        .with_context(|| format!("failed to write canonical report to {}", path.display()))?;

    state
        .storage
        .record_report(
            run_id,
            &run_paths.relative(&path)?,
            None,
            payload.len() as i64,
        )
        .await?;

    Ok(())
}

async fn persist_stream_artifacts(
    run_id: &str,
    result_id: &str,
    run_paths: &RunPaths,
    planned_test_id: &str,
    test_id: &str,
    execution_target: &str,
    stdout: &[u8],
    stderr: &[u8],
) -> Result<Vec<NewArtifactRecord>> {
    let base_dir = run_paths
        .logs_dir
        .join(sanitize_component(test_id))
        .join(sanitize_component(execution_target))
        .join(sanitize_component(planned_test_id));
    fs::create_dir_all(&base_dir).await?;

    let mut artifacts = Vec::new();

    if !stdout.is_empty() {
        let stdout_path = base_dir.join("stdout.txt");
        fs::write(&stdout_path, stdout).await?;
        artifacts.push(NewArtifactRecord {
            artifact_id: new_prefixed_id("art"),
            run_id: run_id.to_string(),
            result_id: Some(result_id.to_string()),
            artifact_type: "stdout".to_string(),
            relative_path: run_paths.relative(&stdout_path)?,
            content_type: "text/plain; charset=utf-8".to_string(),
            size_bytes: stdout.len() as i64,
        });
    }

    if !stderr.is_empty() {
        let stderr_path = base_dir.join("stderr.txt");
        fs::write(&stderr_path, stderr).await?;
        artifacts.push(NewArtifactRecord {
            artifact_id: new_prefixed_id("art"),
            run_id: run_id.to_string(),
            result_id: Some(result_id.to_string()),
            artifact_type: "stderr".to_string(),
            relative_path: run_paths.relative(&stderr_path)?,
            content_type: "text/plain; charset=utf-8".to_string(),
            size_bytes: stderr.len() as i64,
        });
    }

    Ok(artifacts)
}

async fn host_semaphore(
    limits: &Arc<Mutex<HashMap<String, Arc<Semaphore>>>>,
    host_key: &str,
    per_host_limit: usize,
) -> Arc<Semaphore> {
    let mut guard = limits.lock().await;
    guard
        .entry(host_key.to_string())
        .or_insert_with(|| Arc::new(Semaphore::new(per_host_limit)))
        .clone()
}

pub(crate) fn derive_execution_target(facts: &[crate::facts::Fact], fallback: &str) -> String {
    facts
        .first()
        .map(|fact| fact.target.clone())
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| fallback.to_string())
}
