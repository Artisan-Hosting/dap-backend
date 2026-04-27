//! Run configuration primitives.
//!
//! The platform leans on TOML configuration to declare scope, API usage, and
//! execution guardrails. These structs map directly to the sample config shown
//! in `outline.md` §14 and can be deserialized from disk.

use std::{fs, path::Path};

use serde::Deserialize;
use thiserror::Error;

/// High-level configuration for a single audit run.
#[derive(Debug, Clone, Deserialize)]
pub struct RunConfig {
    /// Primary domain supplied by the operator (e.g., `example.com`).
    pub domain: String,
    /// Optional hostname allow-list patterns.
    #[serde(default)]
    pub include: Vec<String>,
    /// Optional hostname deny-list patterns.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Controls whether we sweep the full domain or limit tests to a single site.
    #[serde(default)]
    pub scope: ScopeConfig,
    /// Optional PageSpeed Insights configuration.
    #[serde(default)]
    pub psi: Option<PsiConfig>,
    /// Execution guardrails (worker limits, rate limits, etc.).
    #[serde(default)]
    pub execution: ExecutionConfig,
    /// Reporting knobs (formats, asset paths).
    #[serde(default)]
    pub report: ReportConfig,
}

/// Defines how widely the orchestrator should explore hosts for a run.
#[derive(Debug, Clone, Deserialize)]
pub struct ScopeConfig {
    /// Sweep across discovered subdomains (`domain_sweep`) or target a specific site (`single_site`).
    #[serde(default = "default_scope_mode")]
    pub mode: ScopeMode,
    /// Specific hostname to test when `mode = "single_site"`.
    #[serde(default)]
    pub site: Option<String>,
}

impl Default for ScopeConfig {
    fn default() -> Self {
        Self {
            mode: default_scope_mode(),
            site: None,
        }
    }
}

/// Scope selector within the run configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    /// Enumerate and test multiple hosts across the domain.
    DomainSweep,
    /// Execute tests against a single hostname only.
    SingleSite,
}

/// PageSpeed Insights settings.
#[derive(Debug, Clone, Deserialize)]
pub struct PsiConfig {
    /// Whether PSI collection is enabled for this run.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Strategies to call (e.g., mobile, desktop).
    #[serde(default = "default_strategies")]
    pub strategies: Vec<String>,
    /// Lighthouse categories to request.
    #[serde(default = "default_categories")]
    pub categories: Vec<String>,
    /// Execution timeout in seconds per PSI request.
    #[serde(default = "default_psi_timeout")]
    pub timeout_seconds: u64,
    /// Optional path to a service account JSON file for PSI requests.
    #[serde(default)]
    pub credentials_file: Option<String>,
}

/// Execution guardrails covering concurrency and rate limiting.
#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionConfig {
    /// Maximum in-flight tasks across the orchestrator.
    #[serde(default = "default_max_workers")]
    pub max_workers: usize,
    /// Per-host concurrency controls to avoid hammering a single domain.
    #[serde(default = "default_per_host_concurrency")]
    pub per_host_concurrency: usize,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            max_workers: default_max_workers(),
            per_host_concurrency: default_per_host_concurrency(),
        }
    }
}

/// Reporting output configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct ReportConfig {
    /// Formats to emit (json, html, pdf).
    #[serde(default = "default_report_formats")]
    pub formats: Vec<String>,
    /// Optional path to a CSS file used for HTML rendering.
    #[serde(default)]
    pub css: Option<String>,
}

impl Default for ReportConfig {
    fn default() -> Self {
        Self {
            formats: default_report_formats(),
            css: None,
        }
    }
}

/// Errors surfaced while loading configuration from disk.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// Underlying IO failure (missing file, permissions, etc.).
    #[error("failed to read config: {0}")]
    Io(#[from] std::io::Error),
    /// Serde/TOML parsing failure.
    #[error("failed to parse config: {0}")]
    Parse(#[from] toml::de::Error),
}

impl RunConfig {
    /// Load configuration from a TOML file on disk.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let raw = fs::read_to_string(path)?;
        let cfg: Self = toml::from_str(&raw)?;
        Ok(cfg)
    }
}

fn default_scope_mode() -> ScopeMode {
    ScopeMode::DomainSweep
}

fn default_true() -> bool {
    true
}

fn default_strategies() -> Vec<String> {
    vec!["mobile".into(), "desktop".into()]
}

fn default_categories() -> Vec<String> {
    vec![
        "performance".into(),
        "accessibility".into(),
        "best-practices".into(),
        "seo".into(),
    ]
}

fn default_psi_timeout() -> u64 {
    60
}

fn default_max_workers() -> usize {
    8
}

fn default_per_host_concurrency() -> usize {
    2
}

fn default_report_formats() -> Vec<String> {
    vec!["json".into(), "html".into()]
}
