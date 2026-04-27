use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::config::{ExecutionConfig, PsiConfig, ReportConfig, RunConfig, ScopeConfig, ScopeMode};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackendConfig {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub cache: CacheConfig,
    #[serde(default)]
    pub engine: EngineConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    #[serde(default)]
    pub mysql: MysqlConfig,
    #[serde(default = "default_artifacts_root")]
    pub artifacts_root: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MysqlConfig {
    #[serde(default = "default_mysql_host")]
    pub host: String,
    #[serde(default = "default_mysql_port")]
    pub port: u16,
    #[serde(default = "default_mysql_database")]
    pub database: String,
    #[serde(default = "default_mysql_username", alias = "user")]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default = "default_mysql_max_connections")]
    pub max_connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CacheConfig {
    #[serde(default)]
    pub freshness_window_seconds: u64,
    #[serde(default = "default_true")]
    pub dedupe_inflight: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineConfig {
    #[serde(default = "default_rules_path")]
    pub rules_path: PathBuf,
    #[serde(default = "default_plugins_path")]
    pub plugins_path: PathBuf,
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default = "default_scope_mode")]
    pub default_scope_mode: ScopeMode,
    #[serde(default = "default_true")]
    pub force_single_site_for_hostnames: bool,
    #[serde(default)]
    pub enabled_tests: Vec<String>,
    #[serde(default)]
    pub disabled_tests: Vec<String>,
    #[serde(default = "default_worker_poll_interval_ms")]
    pub worker_poll_interval_ms: u64,
    #[serde(default)]
    pub psi: Option<PsiConfig>,
    #[serde(default)]
    pub execution: ExecutionConfig,
    #[serde(default)]
    pub report: ReportConfig,
}

#[derive(Debug, Error)]
pub enum BackendConfigError {
    #[error("failed to read backend config: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse backend config: {0}")]
    Parse(#[from] toml::de::Error),
}

impl Default for BackendConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig::default(),
            storage: StorageConfig::default(),
            cache: CacheConfig::default(),
            engine: EngineConfig::default(),
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            bind: default_bind(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            mysql: MysqlConfig::default(),
            artifacts_root: default_artifacts_root(),
        }
    }
}

impl Default for MysqlConfig {
    fn default() -> Self {
        Self {
            host: default_mysql_host(),
            port: default_mysql_port(),
            database: default_mysql_database(),
            username: default_mysql_username(),
            password: String::new(),
            max_connections: default_mysql_max_connections(),
        }
    }
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            rules_path: default_rules_path(),
            plugins_path: default_plugins_path(),
            include: Vec::new(),
            exclude: Vec::new(),
            default_scope_mode: default_scope_mode(),
            force_single_site_for_hostnames: default_true(),
            enabled_tests: Vec::new(),
            disabled_tests: Vec::new(),
            worker_poll_interval_ms: default_worker_poll_interval_ms(),
            psi: None,
            execution: ExecutionConfig::default(),
            report: ReportConfig::default(),
        }
    }
}

impl BackendConfig {
    pub fn from_file_or_default(path: &Path) -> Result<Self, BackendConfigError> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let raw = fs::read_to_string(path)?;
        Ok(toml::from_str(&raw)?)
    }

    pub fn scope_mode_for_target(&self, target_key: &str) -> ScopeMode {
        if self.engine.force_single_site_for_hostnames && looks_like_hostname(target_key) {
            ScopeMode::SingleSite
        } else {
            self.engine.default_scope_mode.clone()
        }
    }

    pub fn audit_config_for_target(&self, target_key: &str) -> RunConfig {
        let scope_mode = self.scope_mode_for_target(target_key);
        let scope = match scope_mode {
            ScopeMode::DomainSweep => ScopeConfig {
                mode: ScopeMode::DomainSweep,
                site: None,
            },
            ScopeMode::SingleSite => ScopeConfig {
                mode: ScopeMode::SingleSite,
                site: Some(target_key.to_string()),
            },
        };

        RunConfig {
            domain: target_key.to_string(),
            include: self.engine.include.clone(),
            exclude: self.engine.exclude.clone(),
            scope,
            psi: self.engine.psi.clone(),
            execution: self.engine.execution.clone(),
            report: self.engine.report.clone(),
        }
    }
}

fn looks_like_hostname(target_key: &str) -> bool {
    target_key.split('.').count() > 2
}

fn default_bind() -> String {
    "127.0.0.1:3000".to_string()
}

fn default_artifacts_root() -> PathBuf {
    PathBuf::from("artifacts")
}

fn default_mysql_host() -> String {
    "127.0.0.1".to_string()
}

fn default_mysql_port() -> u16 {
    3306
}

fn default_mysql_database() -> String {
    "artisan_dap".to_string()
}

fn default_mysql_username() -> String {
    "root".to_string()
}

fn default_mysql_max_connections() -> u32 {
    10
}

fn default_rules_path() -> PathBuf {
    PathBuf::from("rules.yaml")
}

fn default_plugins_path() -> PathBuf {
    PathBuf::from("plugins")
}

fn default_scope_mode() -> ScopeMode {
    ScopeMode::DomainSweep
}

fn default_worker_poll_interval_ms() -> u64 {
    1000
}

fn default_true() -> bool {
    true
}
