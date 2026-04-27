//! Shared workspace helpers for isolated runtime artifacts.
//!
//! The prototype keeps every run and temporary Python environment under
//! `/tmp/a-dap` so each execution gets a fresh, isolated folder.

use std::{fs, path::PathBuf};

use uuid::Uuid;

/// Root directory used for all temporary execution state.
pub const WORKSPACE_ROOT: &str = "/tmp/a-dap";

/// Return the workspace root path.
pub fn workspace_root() -> PathBuf {
    PathBuf::from(WORKSPACE_ROOT)
}

/// Create a fresh isolated directory under `/tmp/a-dap/<kind>/<uuid>/`.
pub fn create_isolated_dir(kind: &str) -> Result<PathBuf, std::io::Error> {
    let path = workspace_root().join(kind).join(Uuid::new_v4().to_string());
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Create a fresh run directory under `/tmp/a-dap/runs/<domain>/<uuid>/`.
pub fn create_run_dir(domain: &str) -> Result<PathBuf, std::io::Error> {
    let path = workspace_root()
        .join("runs")
        .join(sanitize_component(domain))
        .join(Uuid::new_v4().to_string());
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Make a filesystem-safe component from operator input.
pub fn sanitize_component(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => ch,
            _ => '_',
        })
        .collect();

    if sanitized.trim_matches('_').is_empty() {
        "unknown".to_string()
    } else {
        sanitized
    }
}
