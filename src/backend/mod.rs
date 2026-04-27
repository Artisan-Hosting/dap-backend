mod capabilities;
mod config;
mod contracts;
mod storage;
mod worker;

use std::{collections::BTreeSet, fs, path::PathBuf, sync::Arc};

use anyhow::{Context, Result};
use axum::{
    Json, Router,
    extract::{Path as AxumPath, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, signal, sync::Notify};
use tracing::{error, info};

use crate::{planner::RulesEngine, plugins::PluginCatalog, python_env, runner::Runner};

use self::{
    capabilities::CapabilityRegistry,
    config::BackendConfig,
    contracts::{
        CreateRunRequest, CreateRunResponse, ErrorResponse, RunState, SupportedTestsResponse,
    },
    storage::Storage,
};

pub async fn run(config_path: PathBuf) -> Result<()> {
    let config = BackendConfig::from_file_or_default(&config_path)?;
    let storage = Storage::connect(&config.storage).await?;
    let recovered = storage.recover_incomplete_runs().await?;
    if recovered > 0 {
        info!(
            recovered_runs = recovered,
            "re-queued incomplete runs during startup recovery"
        );
    }

    let rules = RulesEngine::from_file(&config.engine.rules_path)?;
    let plugins = PluginCatalog::discover(&config.engine.plugins_path)?;
    let python_bin =
        python_env::ensure_python_env().context("failed to provision Python runtime")?;
    let runner = Runner::new(config.engine.plugins_path.clone(), python_bin);
    let capabilities = CapabilityRegistry::build(&plugins, &config);
    let rules_version = hash_file(&config.engine.rules_path)?;
    let config_hash = hash_json(&config.engine)?;

    let state = Arc::new(AppState {
        config,
        storage,
        capabilities,
        engine: EngineState {
            rules,
            plugins,
            runner,
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
            rules_version,
            config_hash,
        },
        worker_notify: Arc::new(Notify::new()),
    });

    let worker_state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = worker::run_loop(worker_state).await {
            error!(error = %err, "worker loop exited unexpectedly");
        }
    });

    let app = Router::new()
        .route("/v1/tests", get(get_tests))
        .route("/v1/runs", post(create_run))
        .route("/v1/runs/:run_id", get(get_run_status))
        .route("/v1/runs/:run_id/results", get(get_run_results))
        .route("/v1/runs/:run_id/report", get(get_run_report))
        .route("/v1/targets/:target/latest", get(get_latest_target_run))
        .route("/v1/targets/:target/history", get(get_target_history))
        .with_state(state.clone());

    let listener = TcpListener::bind(&state.config.server.bind)
        .await
        .with_context(|| format!("failed to bind {}", state.config.server.bind))?;
    info!(bind = %state.config.server.bind, "backend listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("axum server failed")?;

    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct AppState {
    pub(crate) config: BackendConfig,
    pub(crate) storage: Storage,
    pub(crate) capabilities: CapabilityRegistry,
    pub(crate) engine: EngineState,
    pub(crate) worker_notify: Arc<Notify>,
}

#[derive(Debug, Clone)]
pub(crate) struct EngineState {
    pub(crate) rules: RulesEngine,
    pub(crate) plugins: PluginCatalog,
    pub(crate) runner: Runner,
    pub(crate) engine_version: String,
    pub(crate) rules_version: String,
    pub(crate) config_hash: String,
}

#[derive(Debug, Clone)]
struct NormalizedTarget {
    input: String,
    key: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    body: ErrorResponse,
}

async fn get_tests(State(state): State<Arc<AppState>>) -> Json<SupportedTestsResponse> {
    Json(SupportedTestsResponse {
        tests: state.capabilities.supported_tests(),
    })
}

async fn create_run(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<CreateRunRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let target = normalize_target(&payload.target)?;

    let requested_tests = if payload.requested_tests.is_empty() {
        state.capabilities.supported_test_ids()
    } else {
        dedupe_tests(&payload.requested_tests)
    };

    if requested_tests.is_empty() {
        return Err(ApiError::service_unavailable(
            "no_supported_tests_available",
            "the deployment does not currently expose any runnable tests",
        ));
    }

    let unsupported_tests: Vec<String> = requested_tests
        .iter()
        .filter(|test_id| !state.capabilities.contains(test_id))
        .cloned()
        .collect();
    if !unsupported_tests.is_empty() {
        return Err(ApiError::unsupported_tests(unsupported_tests));
    }

    let request_fingerprint = build_request_fingerprint(&state, &target.key, &requested_tests)
        .map_err(ApiError::internal)?;
    let submission = state
        .storage
        .submit_run(
            &target.input,
            &target.key,
            &requested_tests,
            payload.force_refresh,
            payload.client_request_id.as_deref(),
            &state.engine.engine_version,
            &state.engine.rules_version,
            &state.engine.config_hash,
            &request_fingerprint,
            &state.config.cache,
        )
        .await
        .map_err(ApiError::internal)?;

    state.worker_notify.notify_one();

    let status = if submission.state == RunState::CacheHit {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };

    Ok((
        status,
        Json(CreateRunResponse {
            run_id: submission.run_id,
            state: submission.state,
            target: submission.target,
        }),
    ))
}

async fn get_run_status(
    State(state): State<Arc<AppState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<contracts::RunStatusResponse>, ApiError> {
    let run = state
        .storage
        .get_run_status(&run_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("run_not_found", "run was not found"))?;
    Ok(Json(run))
}

async fn get_run_results(
    State(state): State<Arc<AppState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<contracts::RunResultsResponse>, ApiError> {
    let run = state
        .storage
        .get_run_results(&run_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("run_not_found", "run was not found"))?;
    Ok(Json(run))
}

async fn get_run_report(
    State(state): State<Arc<AppState>>,
    AxumPath(run_id): AxumPath<String>,
) -> Result<Json<contracts::CanonicalReportResponse>, ApiError> {
    let report = state
        .storage
        .get_run_report(&run_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found("run_not_found", "run was not found"))?;
    Ok(Json(report))
}

async fn get_latest_target_run(
    State(state): State<Arc<AppState>>,
    AxumPath(target): AxumPath<String>,
) -> Result<Json<contracts::TargetRunSummary>, ApiError> {
    let normalized = normalize_target(&target)?;
    let run = state
        .storage
        .get_latest_target_run(&normalized.key)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| {
            ApiError::not_found(
                "run_not_found",
                "no completed runs were found for this target",
            )
        })?;
    Ok(Json(run))
}

async fn get_target_history(
    State(state): State<Arc<AppState>>,
    AxumPath(target): AxumPath<String>,
) -> Result<Json<contracts::TargetHistoryResponse>, ApiError> {
    let normalized = normalize_target(&target)?;
    let history = state
        .storage
        .get_target_history(&normalized.key)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(history))
}

impl ApiError {
    fn bad_request(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: ErrorResponse {
                error: error.into(),
                message: Some(message.into()),
                unsupported_tests: None,
            },
        }
    }

    fn unsupported_tests(unsupported_tests: Vec<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            body: ErrorResponse {
                error: "unsupported_tests".to_string(),
                message: None,
                unsupported_tests: Some(unsupported_tests),
            },
        }
    }

    fn not_found(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            body: ErrorResponse {
                error: error.into(),
                message: Some(message.into()),
                unsupported_tests: None,
            },
        }
    }

    fn service_unavailable(error: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: ErrorResponse {
                error: error.into(),
                message: Some(message.into()),
                unsupported_tests: None,
            },
        }
    }

    fn internal(err: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            body: ErrorResponse {
                error: "internal_error".to_string(),
                message: Some(err.to_string()),
                unsupported_tests: None,
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

fn normalize_target(raw: &str) -> Result<NormalizedTarget, ApiError> {
    let trimmed = raw.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_target",
            "target must not be empty",
        ));
    }

    if trimmed.contains("://")
        || trimmed.contains('/')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains(':')
    {
        return Err(ApiError::bad_request(
            "invalid_target",
            "target must be a hostname or domain without scheme, port, path, or query",
        ));
    }

    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() < 2 {
        return Err(ApiError::bad_request(
            "invalid_target",
            "target must contain at least one dot-separated domain suffix",
        ));
    }

    for label in &labels {
        if label.is_empty() || label.len() > 63 {
            return Err(ApiError::bad_request(
                "invalid_target",
                "target contains an empty or oversized DNS label",
            ));
        }

        let starts_or_ends_with_dash = label.starts_with('-') || label.ends_with('-');
        let has_invalid_char = !label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-');
        if starts_or_ends_with_dash || has_invalid_char {
            return Err(ApiError::bad_request(
                "invalid_target",
                "target contains invalid DNS label characters",
            ));
        }
    }

    Ok(NormalizedTarget {
        input: trimmed.to_string(),
        key: trimmed.to_ascii_lowercase(),
    })
}

fn dedupe_tests(raw: &[String]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut deduped = Vec::new();

    for item in raw {
        let test_id = item.trim();
        if test_id.is_empty() {
            continue;
        }
        if seen.insert(test_id.to_string()) {
            deduped.push(test_id.to_string());
        }
    }

    deduped
}

fn build_request_fingerprint(
    state: &AppState,
    target_key: &str,
    requested_tests: &[String],
) -> Result<String> {
    let mut sorted_tests = requested_tests.to_vec();
    sorted_tests.sort();
    let plugin_versions: Vec<_> = state
        .capabilities
        .versions_for(&sorted_tests)
        .into_iter()
        .map(|(id, version)| json!({ "id": id, "version": version }))
        .collect();
    let payload = json!({
        "target_key": target_key,
        "requested_tests": sorted_tests,
        "scope_mode": scope_mode_name(&state.config.scope_mode_for_target(target_key)),
        "config_hash": state.engine.config_hash,
        "rules_version": state.engine.rules_version,
        "engine_version": state.engine.engine_version,
        "plugin_versions": plugin_versions,
    });
    hash_json(&payload)
}

fn scope_mode_name(mode: &crate::config::ScopeMode) -> &'static str {
    match mode {
        crate::config::ScopeMode::DomainSweep => "domain_sweep",
        crate::config::ScopeMode::SingleSite => "single_site",
    }
}

fn hash_file(path: &PathBuf) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    Ok(hash_bytes(&bytes))
}

fn hash_json<T: serde::Serialize>(value: &T) -> Result<String> {
    let bytes = serde_json::to_vec(value)?;
    Ok(hash_bytes(&bytes))
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

async fn shutdown_signal() {
    let _ = signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{dedupe_tests, normalize_target};

    #[test]
    fn normalizes_valid_targets() {
        let target =
            normalize_target(" API.ArtisanHosting.Net. ").expect("target should normalize");
        assert_eq!(target.input, "API.ArtisanHosting.Net");
        assert_eq!(target.key, "api.artisanhosting.net");
    }

    #[test]
    fn rejects_url_targets() {
        let err = normalize_target("https://artisanhosting.net/path").expect_err("url must fail");
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
    }

    #[test]
    fn dedupes_requested_tests_preserving_order() {
        let tests = dedupe_tests(&[
            "web_hsts".to_string(),
            " web_hsts ".to_string(),
            "dns_dmarc_policy".to_string(),
        ]);
        assert_eq!(tests, vec!["web_hsts", "dns_dmarc_policy"]);
    }
}
