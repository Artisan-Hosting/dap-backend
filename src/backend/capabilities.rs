use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    path::Path,
};

use tracing::warn;

use crate::{
    backend::{config::BackendConfig, contracts::SupportedTestView},
    plugins::{PluginCatalog, PluginRecord, PluginRuntime},
    runner::Runner,
};

#[derive(Debug, Clone)]
pub struct CapabilityRegistry {
    supported: BTreeMap<String, SupportedTestView>,
}

impl CapabilityRegistry {
    pub fn build(catalog: &PluginCatalog, config: &BackendConfig) -> Self {
        let enabled: BTreeSet<&str> = config
            .engine
            .enabled_tests
            .iter()
            .map(String::as_str)
            .collect();
        let disabled: BTreeSet<&str> = config
            .engine
            .disabled_tests
            .iter()
            .map(String::as_str)
            .collect();
        let mut supported = BTreeMap::new();

        for record in catalog.manifests.values() {
            let id = record.manifest.id.as_str();

            if !enabled.is_empty() && !enabled.contains(id) {
                warn!(test_id = id, "plugin excluded by enabled_tests filter");
                continue;
            }

            if disabled.contains(id) {
                warn!(test_id = id, "plugin excluded by disabled_tests filter");
                continue;
            }

            if !Runner::supports_runtime(record.manifest.runtime) {
                warn!(test_id = id, runtime = ?record.manifest.runtime, "plugin runtime is not supported");
                continue;
            }

            if !entrypoint_exists(record) {
                warn!(test_id = id, entrypoint = %record.manifest.entrypoint, "plugin entrypoint does not exist");
                continue;
            }

            if !plugin_env_available(record, config) {
                warn!(test_id = id, "plugin env requirements are not satisfied");
                continue;
            }

            supported.insert(
                record.manifest.id.clone(),
                SupportedTestView {
                    id: record.manifest.id.clone(),
                    name: record.manifest.name.clone(),
                    version: record.manifest.version.clone(),
                    runtime: runtime_name(record.manifest.runtime).to_string(),
                    timeout_seconds: record
                        .manifest
                        .limits
                        .as_ref()
                        .and_then(|limits| limits.timeout_seconds)
                        .unwrap_or(60),
                    category: derive_category(catalog, record),
                },
            );
        }

        Self { supported }
    }

    pub fn supported_tests(&self) -> Vec<SupportedTestView> {
        self.supported.values().cloned().collect()
    }

    pub fn contains(&self, test_id: &str) -> bool {
        self.supported.contains_key(test_id)
    }

    pub fn supported_test_ids(&self) -> Vec<String> {
        self.supported.keys().cloned().collect()
    }

    pub fn versions_for<'a>(&'a self, test_ids: &'a [String]) -> Vec<(&'a str, &'a str)> {
        test_ids
            .iter()
            .filter_map(|id| {
                self.supported
                    .get(id)
                    .map(|test| (id.as_str(), test.version.as_str()))
            })
            .collect()
    }
}

fn entrypoint_exists(record: &PluginRecord) -> bool {
    let path = Path::new(&record.manifest.entrypoint);
    let candidate = if path.is_absolute() {
        path.to_path_buf()
    } else {
        record.directory.join(path)
    };

    candidate.exists()
}

fn plugin_env_available(record: &PluginRecord, config: &BackendConfig) -> bool {
    if record.manifest.id == "psi_web_performance" {
        return env::var("PAGESPEED_API_KEY").is_ok()
            || env::var("PAGESPEED_CREDENTIALS_FILE").is_ok()
            || env::var("GOOGLE_APPLICATION_CREDENTIALS").is_ok()
            || config
                .engine
                .psi
                .as_ref()
                .and_then(|psi| psi.credentials_file.as_ref())
                .is_some();
    }

    record.manifest.env.iter().all(|key| env::var(key).is_ok())
}

fn derive_category(catalog: &PluginCatalog, record: &PluginRecord) -> String {
    record
        .directory
        .strip_prefix(&catalog.root)
        .ok()
        .and_then(|relative| relative.iter().next())
        .and_then(|segment| segment.to_str())
        .unwrap_or("uncategorized")
        .to_string()
}

fn runtime_name(runtime: PluginRuntime) -> &'static str {
    match runtime {
        PluginRuntime::Shell => "shell",
        PluginRuntime::Python => "python",
        PluginRuntime::Node => "node",
        PluginRuntime::Binary => "binary",
        PluginRuntime::Oci => "oci",
    }
}
