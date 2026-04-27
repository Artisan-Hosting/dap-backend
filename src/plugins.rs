//! Plugin discovery and manifest parsing.
//!
//! Plugins are expected to live under `plugins/<category>/<id>/` with a
//! `manifest.yaml` that adheres to the schema documented in `outline.md`. This
//! module surfaces a typed representation while keeping parsing errors tidy.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;
use walkdir::WalkDir;

use crate::tests::TestId;

/// High-level plugin catalog used by the backend worker.
#[derive(Debug, Clone)]
pub struct PluginCatalog {
    pub root: PathBuf,
    pub manifests: BTreeMap<TestId, PluginRecord>,
}

/// Errors that can bubble up while discovering manifests.
#[derive(Debug, Error)]
pub enum PluginError {
    #[error("failed to read manifest {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse manifest {path}: {source}")]
    Parse {
        path: PathBuf,
        source: serde_yaml::Error,
    },
}

/// Structured representation of `manifest.yaml`.
#[derive(Debug, Clone, Deserialize)]
pub struct PluginManifest {
    pub id: String,
    pub name: String,
    pub version: String,
    pub entrypoint: String,
    pub runtime: PluginRuntime,
    #[serde(default)]
    pub env: Vec<String>,
    #[serde(default)]
    pub limits: Option<ResourceLimits>,
    #[serde(default)]
    pub triggers: Option<TriggerBlock>,
}

/// Manifest paired with its on-disk directory for execution context.
#[derive(Debug, Clone)]
pub struct PluginRecord {
    pub manifest: PluginManifest,
    pub directory: PathBuf,
}

/// Runtime selection so the runner knows how to execute the entrypoint.
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginRuntime {
    Shell,
    Python,
    Node,
    Binary,
    Oci,
}

/// Optional resource hints provided by plugin authors.
#[derive(Debug, Clone, Deserialize)]
pub struct ResourceLimits {
    #[serde(default)]
    pub timeout_seconds: Option<u64>,
    #[serde(default)]
    pub memory_mb: Option<u64>,
}

/// Trigger declarations copied directly from outline docs.
#[derive(Debug, Clone, Deserialize)]
pub struct TriggerBlock {
    #[serde(default)]
    pub any: Vec<TriggerClause>,
}

/// Individual trigger clause referencing a fact entity.
#[derive(Debug, Clone, Deserialize)]
pub struct TriggerClause {
    pub entity: String,
    #[serde(default)]
    pub r#where: BTreeMap<String, serde_yaml::Value>,
}

impl PluginCatalog {
    /// Walk the plugin tree and load every `manifest.yaml`.
    pub fn discover<P: AsRef<Path>>(root: P) -> Result<Self, PluginError> {
        let root = root.as_ref().to_path_buf();
        let mut manifests = BTreeMap::new();

        for entry in WalkDir::new(&root)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name() == "manifest.yaml")
        {
            let path = entry.path().to_path_buf();
            let raw = fs::read_to_string(&path).map_err(|source| PluginError::Io {
                path: path.clone(),
                source,
            })?;
            let manifest: PluginManifest =
                serde_yaml::from_str(&raw).map_err(|source| PluginError::Parse {
                    path: path.clone(),
                    source,
                })?;
            let directory = path.parent().unwrap_or(&root).to_path_buf();
            manifests.insert(
                TestId(manifest.id.clone()),
                PluginRecord {
                    manifest,
                    directory,
                },
            );
        }

        Ok(Self { root, manifests })
    }

    /// Fetch manifest for a specific test id.
    pub fn get(&self, id: &TestId) -> Option<&PluginRecord> {
        self.manifests.get(id)
    }
}
