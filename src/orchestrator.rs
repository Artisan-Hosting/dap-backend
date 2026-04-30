//! High-level orchestration logic tying discovery, planning, and execution.
//!
//! This module provides an async-friendly harness that mirrors the workflow in
//! `objective.md`: discover → plan → run tests → aggregate. The implementation
//! is deliberately verbose so engineers can see exactly where to extend the
//! system.

use std::{collections::BTreeMap, env, fs, path::PathBuf};

use anyhow::Result;
use chrono::Utc;
use serde::Serialize;
use tracing::{info, warn};

use crate::{
    backend::{Storage, StorageConfig},
    config::RunConfig,
    discovery::{self, DeadHost},
    planner::{PlannerError, RulesEngine},
    plugins::{PluginCatalog, PluginError},
    python_env, report,
    runner::{ExecutionOutcome, Runner},
    tests::{PlannedTest, TestInput, TestOutput, TestSeverity, TestStatus},
    workspace,
};

/// Wraps all moving parts required to execute an audit run.
#[derive(Debug, Clone)]
pub struct Orchestrator {
    pub config: RunConfig,
    rules: RulesEngine,
    plugins: PluginCatalog,
    runner: Runner,
    run_dirs: RunDirectories,
    ct_cache_storage: Storage,
    ct_cache_ttl_seconds: u64,
}

impl Orchestrator {
    /// Construct the orchestrator, connect the CT cache storage, and load rule definitions plus plugin manifests.
    pub async fn new(
        config: RunConfig,
        rules_path: PathBuf,
        plugin_root: PathBuf,
        storage_config: &StorageConfig,
        ct_cache_ttl_seconds: u64,
    ) -> Result<Self, OrchestratorError> {
        let rules = RulesEngine::from_file(rules_path)?;
        let plugins = PluginCatalog::discover(&plugin_root)?;
        let python_path = python_env::ensure_python_env().map_err(OrchestratorError::PythonEnv)?;
        let runner = Runner::new(plugin_root, python_path);
        let run_dirs = RunDirectories::create(&config.domain)?;
        let ct_cache_storage = Storage::connect(storage_config)
            .await
            .map_err(OrchestratorError::Storage)?;

        Ok(Self {
            config,
            rules,
            plugins,
            runner,
            run_dirs,
            ct_cache_storage,
            ct_cache_ttl_seconds,
        })
    }

    /// Execute the full audit workflow.
    pub async fn run(&self) -> Result<()> {
        info!(
            target = %self.config.domain,
            run_id = %self.run_dirs.run_id,
            run_root = %self.run_dirs.root.display(),
            logs_dir = %self.run_dirs.logs_dir.display(),
            "starting orchestrator run",
        );

        let discovery = discovery::perform_discovery_with_ct_cache(
            &self.config,
            &self.ct_cache_storage,
            self.ct_cache_ttl_seconds,
        )
        .await?;
        info!(
            total_facts = discovery.facts.len(),
            dead_hosts = discovery.dead_hosts.len(),
            site_profiles = discovery.site_profiles.len(),
            "discovery generated facts"
        );

        if !discovery.dead_hosts.is_empty() {
            let path = self.run_dirs.record_dead_hosts(&discovery.dead_hosts)?;
            info!(dead_hosts_path = %path.display(), "recorded dead host list");
        }

        if !discovery.site_profiles.is_empty() {
            let path = self
                .run_dirs
                .record_site_profiles(&discovery.site_profiles)?;
            info!(site_profiles_path = %path.display(), "recorded site profile summary");
        }

        let dead_host_map: BTreeMap<String, String> = discovery
            .dead_hosts
            .iter()
            .map(|entry| (entry.host.clone(), entry.reason.clone()))
            .collect();

        let planned = self.rules.plan(&discovery.facts);
        let (main_planned, api_planned): (Vec<_>, Vec<_>) = planned
            .into_iter()
            .partition(|planned| !crate::tests::runs_in_late_phase(&planned.test_id.0));
        let api_tests = api_planned.len();
        info!(
            main_tests = main_planned.len(),
            api_tests = api_tests,
            "planner scheduled tests"
        );

        let mut summary: BTreeMap<String, Vec<SubdomainResultSummary>> = BTreeMap::new();

        if !main_planned.is_empty() {
            info!(tests = main_planned.len(), "starting main test phase");
        }
        for planned_test in main_planned {
            let output = self.execute_test(planned_test, &dead_host_map).await?;
            summary
                .entry(output.test_id.0.clone())
                .or_default()
                .push(SubdomainResultSummary {
                    target: output.target.clone(),
                    status: output.status.clone(),
                    severity: output.severity.clone(),
                    notes: output.notes.clone(),
                });
        }

        if api_tests > 0 {
            info!(tests = api_tests, "starting deferred api fuzz phase");
        }
        for planned_test in api_planned {
            let output = self.execute_test(planned_test, &dead_host_map).await?;
            summary
                .entry(output.test_id.0.clone())
                .or_default()
                .push(SubdomainResultSummary {
                    target: output.target.clone(),
                    status: output.status.clone(),
                    severity: output.severity.clone(),
                    notes: output.notes.clone(),
                });
        }
        if api_tests > 0 {
            info!("completed deferred api fuzz phase");
        }

        let summary_path = self.run_dirs.record_summary(&summary)?;
        info!(
            summary_path = %summary_path.display(),
            tests = summary.len(),
            "recorded subdomain summary",
        );

        if let Some(report_path) = report::render_report(
            &self.run_dirs.root,
            &self.run_dirs.results_dir,
            &self.config.report.formats,
            self.config.report.css.as_deref().map(std::path::Path::new),
        )? {
            info!(report_path = %report_path.display(), "recorded html report bundle");
        }

        info!("orchestrator run complete");
        Ok(())
    }

    async fn execute_test(
        &self,
        planned: PlannedTest,
        dead_hosts: &BTreeMap<String, String>,
    ) -> Result<TestOutput> {
        let PlannedTest {
            test_id,
            supporting_facts,
        } = planned;

        let target = supporting_facts
            .first()
            .map(|fact| fact.target.clone())
            .unwrap_or_else(|| self.config.domain.clone());
        let target_key = target.to_lowercase();

        if !crate::tests::runs_on_dead_host(&test_id.0) {
            if let Some(reason) = dead_hosts.get(&target_key) {
                let output = TestOutput::placeholder(
                    test_id.0,
                    target,
                    TestStatus::Skipped,
                    format!("host marked dead: {reason}"),
                );
                let path = self.run_dirs.record_result(&output)?;
                info!(
                    test_id = %output.test_id.0,
                    target = %output.target,
                    result_path = %path.display(),
                    "test skipped due to dead host",
                );
                return Ok(output);
            }
        }

        let Some(record) = self.plugins.get(&test_id) else {
            warn!(test_id = %test_id.0, "manifest missing; skipping test");
            let output =
                TestOutput::placeholder(test_id.0, target, TestStatus::Skipped, "manifest missing");
            let path = self.run_dirs.record_result(&output)?;
            info!(
                test_id = %output.test_id.0,
                status = ?output.status,
                result_path = %path.display(),
                "recorded placeholder result",
            );
            return Ok(output);
        };

        let psi_credentials = self
            .config
            .psi
            .as_ref()
            .and_then(|psi| psi.credentials_file.as_ref())
            .map(|path| {
                let candidate = PathBuf::from(path);
                if candidate.is_absolute() {
                    candidate
                } else if let Ok(cwd) = env::current_dir() {
                    cwd.join(candidate)
                } else {
                    PathBuf::from(path)
                }
            });

        let config = serde_json::json!({
            "run_root": self.run_dirs.root,
            "results_dir": self.run_dirs.results_dir,
            "logs_dir": self.run_dirs.logs_dir,
            "psi_credentials_file": psi_credentials,
        });

        let input = TestInput {
            target,
            facts: supporting_facts,
            config,
        };

        let execution = self.runner.execute(record, &input).await;
        let test_id = execution.output.test_id.0.clone();
        let target = execution.output.target.clone();
        let status = execution.output.status.clone();
        let output_path = self.run_dirs.record_result(&execution.output)?;
        self.run_dirs.record_streams(&execution)?;
        info!(
            test_id = %test_id,
            target = %target,
            status = ?status,
            result_path = %output_path.display(),
            "test finished",
        );
        Ok(execution.output)
    }
}

/// Error type aggregated from orchestrator initialization steps.
#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error(transparent)]
    Planner(#[from] PlannerError),
    #[error(transparent)]
    Plugins(#[from] PluginError),
    #[error("failed to prepare output directories: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to provision python environment: {0}")]
    PythonEnv(anyhow::Error),
    #[error("failed to connect ct cache storage: {0}")]
    Storage(anyhow::Error),
}

/// Tracks filesystem locations for the current run.
#[derive(Debug, Clone)]
struct RunDirectories {
    pub run_id: String,
    pub root: PathBuf,
    pub results_dir: PathBuf,
    pub logs_dir: PathBuf,
}

impl RunDirectories {
    /// Create `/tmp/a-dap/runs/<domain>/<uuid>/` for the active execution.
    fn create(domain: &str) -> Result<Self, std::io::Error> {
        let run_id = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let root = workspace::create_run_dir(domain)?;
        let results_dir = root.join("results");
        let logs_dir = root.join("logs");

        fs::create_dir_all(&results_dir)?;
        fs::create_dir_all(&logs_dir)?;

        Ok(Self {
            run_id,
            root,
            results_dir,
            logs_dir,
        })
    }

    /// Persist a test result as prettified JSON under the run directory.
    fn record_result(&self, output: &TestOutput) -> Result<PathBuf, std::io::Error> {
        let safe_test = sanitize_id(&output.test_id.0);
        let raw_target = if output.target.trim().is_empty() {
            "unknown"
        } else {
            output.target.as_str()
        };
        let safe_target = {
            let sanitized = sanitize_id(raw_target);
            if sanitized.is_empty() {
                "unknown".to_string()
            } else {
                sanitized
            }
        };
        let test_dir = self.results_dir.join(&safe_test);
        fs::create_dir_all(&test_dir)?;
        let path = test_dir.join(format!("{}.json", safe_target));
        let json = serde_json::to_string_pretty(output)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        fs::write(&path, json)?;
        Ok(path)
    }

    fn record_summary(
        &self,
        summary: &BTreeMap<String, Vec<SubdomainResultSummary>>,
    ) -> Result<PathBuf, std::io::Error> {
        let path = self.results_dir.join("summary_by_host.json");
        let json = serde_json::to_string_pretty(summary)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        fs::write(&path, json)?;
        Ok(path)
    }

    fn record_dead_hosts(&self, dead_hosts: &[DeadHost]) -> Result<PathBuf, std::io::Error> {
        let path = self.results_dir.join("dead_hosts.json");
        let json = serde_json::to_string_pretty(dead_hosts)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        fs::write(&path, json)?;
        Ok(path)
    }

    /// Persist the discovery profile summary so operators can inspect site types.
    fn record_site_profiles(
        &self,
        site_profiles: &[crate::discovery::SiteProfile],
    ) -> Result<PathBuf, std::io::Error> {
        let path = self.results_dir.join("site_profiles.json");
        let json = serde_json::to_string_pretty(site_profiles)
            .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?;
        fs::write(&path, json)?;
        Ok(path)
    }

    /// Persist the captured stdout/stderr stream data for a test execution.
    fn record_streams(&self, execution: &ExecutionOutcome) -> Result<(), std::io::Error> {
        let test_id = execution.output.test_id.0.clone();
        let target = execution.output.target.clone();
        let test_dir = self
            .logs_dir
            .join(sanitize_id(&test_id))
            .join(sanitize_id(&target));
        fs::create_dir_all(&test_dir)?;

        fs::write(test_dir.join("stdout.txt"), &execution.stdout)?;
        fs::write(test_dir.join("stderr.txt"), &execution.stderr)?;

        let meta = serde_json::json!({
            "test_id": test_id,
            "target": target,
            "status": &execution.output.status,
            "timed_out": execution.timed_out,
            "exit_code": execution.exit_code,
            "stderr_non_empty": execution.stderr_non_empty,
        });
        fs::write(
            test_dir.join("execution.json"),
            serde_json::to_string_pretty(&meta)
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err))?,
        )?;

        Ok(())
    }
}

fn sanitize_id(id: &str) -> String {
    id.chars()
        .map(|c| match c {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => c,
            _ => '_',
        })
        .collect()
}

#[derive(Debug, Clone, Serialize)]
struct SubdomainResultSummary {
    target: String,
    status: TestStatus,
    severity: TestSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    notes: Option<String>,
}
