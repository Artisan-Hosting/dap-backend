//! Test-related data structures.
//!
//! These types intentionally mirror the JSON contracts outlined in `outline.md`
//! so plugin authors can rely on stable serialization across languages.

use serde::{Deserialize, Serialize};

use crate::facts::Fact;

/// Unique identifier for a test (e.g., `web_hsts`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TestId(pub String);

/// Status values surfaced by plugin executions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestStatus {
    Pass,
    Warn,
    Fail,
    Error,
    Info,
    Skipped,
}

/// Severity classification attached to findings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TestSeverity {
    Low,
    Medium,
    High,
    Critical,
    Informational,
}

impl Default for TestSeverity {
    fn default() -> Self {
        TestSeverity::Informational
    }
}

/// Input envelope pushed to each plugin over STDIN.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestInput {
    pub target: String,
    pub facts: Vec<Fact>,
    #[serde(default)]
    pub config: serde_json::Value,
}

impl TestInput {
    /// Build an empty input with just the target string.
    pub fn bare(target: impl Into<String>) -> Self {
        Self {
            target: target.into(),
            facts: Vec::new(),
            config: serde_json::Value::Null,
        }
    }
}

/// Output envelope every plugin must emit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestOutput {
    pub test_id: TestId,
    pub target: String,
    pub status: TestStatus,
    #[serde(default)]
    pub severity: TestSeverity,
    #[serde(default)]
    pub evidence: serde_json::Value,
    #[serde(default)]
    pub recommendations: Vec<String>,
    #[serde(default)]
    pub notes: Option<String>,
}

impl TestOutput {
    /// Helper for constructing placeholder outputs while the runner is WIP.
    pub fn placeholder(
        test_id: impl Into<String>,
        target: impl Into<String>,
        status: TestStatus,
        notes: impl Into<String>,
    ) -> Self {
        Self {
            test_id: TestId(test_id.into()),
            target: target.into(),
            status,
            severity: TestSeverity::Informational,
            evidence: serde_json::Value::Null,
            recommendations: Vec::new(),
            notes: Some(notes.into()),
        }
    }
}

/// Metadata describing a planned test invocation.
#[derive(Debug, Clone)]
pub struct PlannedTest {
    pub test_id: TestId,
    pub supporting_facts: Vec<Fact>,
}

impl PlannedTest {
    pub fn new(test_id: impl Into<String>, supporting_facts: Vec<Fact>) -> Self {
        Self {
            test_id: TestId(test_id.into()),
            supporting_facts,
        }
    }
}
