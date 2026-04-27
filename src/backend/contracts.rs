use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::{
    discovery::SiteProfile,
    tests::{TestSeverity, TestStatus},
};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunState {
    Queued,
    CacheHit,
    Discovering,
    Planning,
    Running,
    Aggregating,
    Completed,
    Failed,
    Canceled,
}

impl RunState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::CacheHit => "cache_hit",
            Self::Discovering => "discovering",
            Self::Planning => "planning",
            Self::Running => "running",
            Self::Aggregating => "aggregating",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Canceled => "canceled",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "queued" => Some(Self::Queued),
            "cache_hit" => Some(Self::CacheHit),
            "discovering" => Some(Self::Discovering),
            "planning" => Some(Self::Planning),
            "running" => Some(Self::Running),
            "aggregating" => Some(Self::Aggregating),
            "completed" => Some(Self::Completed),
            "failed" => Some(Self::Failed),
            "canceled" => Some(Self::Canceled),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RequestedTestState {
    Accepted,
    RejectedUnsupported,
    RejectedNotApplicable,
    ExpandedToPlannedTests,
}

impl RequestedTestState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::RejectedUnsupported => "rejected_unsupported",
            Self::RejectedNotApplicable => "rejected_not_applicable",
            Self::ExpandedToPlannedTests => "expanded_to_planned_tests",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "accepted" => Some(Self::Accepted),
            "rejected_unsupported" => Some(Self::RejectedUnsupported),
            "rejected_not_applicable" => Some(Self::RejectedNotApplicable),
            "expanded_to_planned_tests" => Some(Self::ExpandedToPlannedTests),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PlannedTestState {
    Queued,
    Running,
    Completed,
    FailedToStart,
    SkippedDeadHost,
}

impl PlannedTestState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Completed => "completed",
            Self::FailedToStart => "failed_to_start",
            Self::SkippedDeadHost => "skipped_dead_host",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SupportedTestsResponse {
    pub tests: Vec<SupportedTestView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SupportedTestView {
    pub id: String,
    pub name: String,
    pub version: String,
    pub runtime: String,
    pub timeout_seconds: u64,
    pub category: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateRunRequest {
    pub target: String,
    #[serde(default)]
    pub requested_tests: Vec<String>,
    #[serde(default)]
    pub force_refresh: bool,
    #[serde(default)]
    pub client_request_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CreateRunResponse {
    pub run_id: String,
    pub state: RunState,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RequestedTestStatusView {
    pub test_id: String,
    pub state: RequestedTestState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RunCounts {
    pub planned: u64,
    pub completed: u64,
    pub failed_to_start: u64,
    pub rejected_not_applicable: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunStatusResponse {
    pub run_id: String,
    pub target: String,
    pub state: RunState,
    pub submitted_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub cache_hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reused_from_run_id: Option<String>,
    pub requested_tests: Vec<RequestedTestStatusView>,
    pub counts: RunCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactView {
    pub artifact_id: String,
    pub run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_id: Option<String>,
    pub artifact_type: String,
    pub relative_path: String,
    pub content_type: String,
    pub size_bytes: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResultView {
    pub result_id: String,
    pub run_id: String,
    pub target: String,
    pub test_id: String,
    pub plugin_version: String,
    pub status: TestStatus,
    pub severity: TestSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    pub evidence: serde_json::Value,
    #[serde(default)]
    pub recommendations: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunResultsResponse {
    pub run_id: String,
    pub requested_test_outcomes: Vec<RequestedTestStatusView>,
    pub results: Vec<ResultView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetRunSummary {
    pub run_id: String,
    pub target: String,
    pub state: RunState,
    pub submitted_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub cache_hit: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct TargetHistoryResponse {
    pub target: String,
    pub runs: Vec<TargetRunSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportRunView {
    pub run_id: String,
    pub target_input: String,
    pub target_key: String,
    pub state: RunState,
    pub submitted_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub cache_hit: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reused_from_run_id: Option<String>,
    pub force_refresh: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_request_id: Option<String>,
    pub engine_version: String,
    pub rules_version: String,
    pub config_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct ResultStatusCounts {
    pub pass: u64,
    pub warn: u64,
    pub fail: u64,
    pub error: u64,
    pub info: u64,
    pub skipped: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReportSummaryView {
    pub run_counts: RunCounts,
    pub result_counts: ResultStatusCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeadHostView {
    pub host: String,
    pub reason: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ReviewBlockView {
    pub finalized: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reviewed_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CanonicalReportResponse {
    pub schema_version: String,
    pub run: ReportRunView,
    pub requested_tests: Vec<RequestedTestStatusView>,
    pub summary: ReportSummaryView,
    pub site_profiles: Vec<SiteProfile>,
    pub dead_hosts: Vec<DeadHostView>,
    pub results: Vec<ResultView>,
    pub artifacts: Vec<ArtifactView>,
    pub review: ReviewBlockView,
}

#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unsupported_tests: Option<Vec<String>>,
}
