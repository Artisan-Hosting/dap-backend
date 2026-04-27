//! Minimal Python virtual environment manager.
//!
//! The test plugins rely on Python modules (`httpx`, `beautifulsoup4`,
//! `dnspython`). To avoid one-off manual setup, the orchestrator calls into this
//! helper to create a shared workspace virtualenv, ensure pip is available, and
//! install the required packages. The provisioning happens once per workspace
//! and writes a stamp file so subsequent runs skip redundant `pip install`
//! executions.

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{Context, Result};

use crate::workspace;

/// Stamp file indicating dependencies were successfully installed.
const STAMP_FILE: &str = ".deps-installed";
/// Python packages required by the bundled plugins.
const PYTHON_DEPS: &[&str] = &[
    "httpx",
    "beautifulsoup4",
    "dnspython",
    "google-auth",
    "requests",
];

/// Ensure the backend worker Python virtual environment exists and dependencies are installed.
///
/// Returns the path to the Python interpreter inside the isolated venv.
pub fn ensure_python_env() -> Result<PathBuf> {
    let venv_path = workspace::workspace_root().join("venvs").join("shared");
    fs::create_dir_all(&venv_path)?;
    create_virtualenv(&venv_path)?;

    let python_bin = venv_python(&venv_path);
    ensure_dependencies(&python_bin, &venv_path)?;
    Ok(python_bin)
}

fn create_virtualenv(venv_path: &Path) -> Result<()> {
    if venv_python(venv_path).exists() {
        return Ok(());
    }

    let candidates = if cfg!(windows) {
        ["python", "python3"]
    } else {
        ["python3", "python"]
    };

    let mut last_err: Option<anyhow::Error> = None;
    for candidate in candidates {
        match Command::new(candidate)
            .arg("-m")
            .arg("venv")
            .arg(venv_path)
            .status()
        {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => {
                last_err = Some(anyhow::anyhow!(
                    "{} -m venv exited with status {:?}",
                    candidate,
                    status.code()
                ));
            }
            Err(err) => {
                last_err = Some(anyhow::anyhow!("failed to spawn {}: {}", candidate, err));
            }
        }
    }

    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("unable to create Python virtualenv")))
}

fn ensure_dependencies(python_bin: &Path, venv_path: &Path) -> Result<()> {
    let stamp = venv_path.join(STAMP_FILE);
    let signature = PYTHON_DEPS.join(",");
    if let Ok(existing) = fs::read_to_string(&stamp) {
        if existing.trim() == signature {
            return Ok(());
        }
    }

    // Upgrade pip quietly to avoid old versions missing wheels.
    let status = Command::new(python_bin)
        .args(["-m", "pip", "install", "--upgrade", "pip"])
        .status()
        .context("failed to upgrade pip inside venv")?;
    if !status.success() {
        anyhow::bail!("pip upgrade failed with status {:?}", status.code());
    }

    let mut install_cmd = Command::new(python_bin);
    install_cmd.arg("-m").arg("pip").arg("install");
    install_cmd.arg("--disable-pip-version-check");
    install_cmd.arg("--quiet");
    for dep in PYTHON_DEPS {
        install_cmd.arg(dep);
    }

    let status = install_cmd
        .status()
        .context("failed to install python dependencies")?;
    if !status.success() {
        anyhow::bail!("pip install exited with status {:?}", status.code());
    }

    fs::write(stamp, signature)?;
    Ok(())
}

fn venv_python(venv_path: &Path) -> PathBuf {
    if cfg!(windows) {
        venv_path.join("Scripts").join("python.exe")
    } else {
        venv_path.join("bin").join("python3")
    }
}
