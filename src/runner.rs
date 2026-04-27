//! Test execution harness.
//!
//! The long-term goal is to spawn sandboxed processes (shell scripts, Python,
//! OCI containers) and feed them JSON over STDIN. This version enforces the
//! manifest contract a bit more strictly by applying env vars, honoring
//! per-test timeouts, and capturing stdout/stderr for artifacts.

use std::{env, fs, path::PathBuf, process::Stdio, time::Duration};

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    process::Command,
    task::JoinHandle,
    time::timeout,
};
use tracing::{info, warn};

use crate::{
    plugins::{PluginManifest, PluginRecord, PluginRuntime},
    tests::{TestInput, TestOutput, TestStatus},
};

/// Responsible for invoking plugin entrypoints.
#[derive(Debug, Clone)]
pub struct Runner {
    pub plugin_root: PathBuf,
    pub python_bin: PathBuf,
}

impl Runner {
    pub fn supports_runtime(runtime: PluginRuntime) -> bool {
        matches!(
            runtime,
            PluginRuntime::Python | PluginRuntime::Shell | PluginRuntime::Binary
        )
    }
}

impl Runner {
    /// Create a new runner anchored at the plugin root directory.
    pub fn new(plugin_root: PathBuf, python_bin: PathBuf) -> Self {
        let python_bin = if python_bin.is_absolute() {
            python_bin
        } else {
            env::current_dir()
                .map(|cwd| cwd.join(&python_bin))
                .unwrap_or(python_bin)
        };

        Self {
            plugin_root,
            python_bin,
        }
    }

    /// Execute a plugin manifest by spawning the requested runtime inside the
    /// managed sandbox (Python virtualenv, bash script, or native binary).
    pub async fn execute(&self, record: &PluginRecord, input: &TestInput) -> ExecutionOutcome {
        let started_at = std::time::Instant::now();
        let manifest = &record.manifest;
        let entrypoint = match self.resolve_entrypoint(record, manifest) {
            Ok(path) => path,
            Err(err) => {
                let message = format!("failed to resolve entrypoint for {}: {err}", manifest.id);
                warn!(test_id = %manifest.id, error = %message, "plugin entrypoint resolution failed");
                return ExecutionOutcome::runtime_error(
                    manifest.id.clone(),
                    input.target.clone(),
                    message,
                    false,
                );
            }
        };
        let timeout_seconds = manifest
            .limits
            .as_ref()
            .and_then(|limits| limits.timeout_seconds)
            .filter(|value| *value > 0)
            .unwrap_or(60);
        let timeout_duration = Duration::from_secs(timeout_seconds);

        info!(
            test_id = %manifest.id,
            runtime = ?manifest.runtime,
            entrypoint = %entrypoint.display(),
            timeout_seconds,
            "launching plugin",
        );

        let mut command = match manifest.runtime {
            PluginRuntime::Python => {
                let mut cmd = Command::new(&self.python_bin);
                cmd.arg(&manifest.entrypoint);
                cmd
            }
            PluginRuntime::Shell => {
                let mut cmd = Command::new("/bin/bash");
                cmd.arg(&manifest.entrypoint);
                cmd
            }
            PluginRuntime::Binary => Command::new(&entrypoint),
            PluginRuntime::Node | PluginRuntime::Oci => {
                let message = format!(
                    "runtime {:?} not supported yet for plugin {}",
                    manifest.runtime, manifest.id
                );
                warn!(test_id = %manifest.id, error = %message, "plugin runtime unsupported");
                return ExecutionOutcome::runtime_error(
                    manifest.id.clone(),
                    input.target.clone(),
                    message,
                    false,
                );
            }
        };

        command.current_dir(&record.directory);
        command.kill_on_drop(true);
        command.env_clear();
        command.stdin(Stdio::piped());
        command.stdout(Stdio::piped());
        command.stderr(Stdio::piped());
        self.apply_base_env(&mut command);
        self.apply_manifest_env(&mut command, manifest);

        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(err) => {
                let message = format!("failed to spawn plugin {}: {err}", manifest.id);
                warn!(test_id = %manifest.id, error = %message, "plugin spawn failed");
                return ExecutionOutcome::spawn_failed(
                    manifest.id.clone(),
                    input.target.clone(),
                    message,
                    started_at.elapsed().as_millis() as i64,
                );
            }
        };

        if let Some(mut stdin) = child.stdin.take() {
            let payload = match serde_json::to_vec(input) {
                Ok(payload) => payload,
                Err(err) => {
                    let message = format!("failed to serialize plugin input: {err}");
                    warn!(test_id = %manifest.id, error = %message, "plugin input serialization failed");
                    return ExecutionOutcome::runtime_error(
                        manifest.id.clone(),
                        input.target.clone(),
                        message,
                        true,
                    );
                }
            };

            if let Err(err) = stdin.write_all(&payload).await {
                let message = format!("failed to write plugin input: {err}");
                warn!(test_id = %manifest.id, error = %message, "plugin stdin write failed");
                return ExecutionOutcome::runtime_error(
                    manifest.id.clone(),
                    input.target.clone(),
                    message,
                    true,
                );
            }
        }

        let stdout_task = child.stdout.take().map(spawn_reader);
        let stderr_task = child.stderr.take().map(spawn_reader);

        let (status, timed_out, exit_code) = match timeout(timeout_duration, child.wait()).await {
            Ok(Ok(status)) => {
                let exit_code = status.code();
                (status, false, exit_code)
            }
            Ok(Err(err)) => {
                let message = format!("failed while waiting for plugin {}: {err}", manifest.id);
                warn!(test_id = %manifest.id, error = %message, "plugin wait failed");
                return ExecutionOutcome::runtime_error(
                    manifest.id.clone(),
                    input.target.clone(),
                    message,
                    true,
                );
            }
            Err(_) => {
                warn!(
                    test_id = %manifest.id,
                    timeout_seconds = timeout_duration.as_secs(),
                    "plugin timed out"
                );
                if let Err(err) = child.kill().await {
                    warn!(test_id = %manifest.id, error = %err, "failed to kill timed-out plugin");
                }
                match child.wait().await {
                    Ok(status) => {
                        let exit_code = status.code();
                        (status, true, exit_code)
                    }
                    Err(err) => {
                        let message = format!(
                            "plugin {} timed out after {}s and could not be reaped: {err}",
                            manifest.id,
                            timeout_duration.as_secs()
                        );
                        return ExecutionOutcome::runtime_error(
                            manifest.id.clone(),
                            input.target.clone(),
                            message,
                            true,
                        );
                    }
                }
            }
        };

        let stdout = collect_reader(stdout_task).await;
        let stderr = collect_reader(stderr_task).await;
        let stderr_text = String::from_utf8_lossy(&stderr);
        let stderr_non_empty = !stderr_text.trim().is_empty();

        if timed_out {
            let notes = format!(
                "plugin timed out after {}s{}",
                timeout_duration.as_secs(),
                if stderr_non_empty {
                    format!("; stderr: {}", stderr_text.trim())
                } else {
                    String::new()
                }
            );
            return ExecutionOutcome {
                output: TestOutput::placeholder(
                    manifest.id.clone(),
                    input.target.clone(),
                    TestStatus::Error,
                    notes,
                ),
                stdout,
                stderr,
                started: true,
                timed_out: true,
                exit_code,
                stderr_non_empty,
                duration_ms: started_at.elapsed().as_millis() as i64,
            };
        }

        if !status.success() {
            let notes = format!(
                "plugin exited with status {:?}{}",
                status.code(),
                if stderr_non_empty {
                    format!("; stderr: {}", stderr_text.trim())
                } else {
                    String::new()
                }
            );
            return ExecutionOutcome {
                output: TestOutput::placeholder(
                    manifest.id.clone(),
                    input.target.clone(),
                    TestStatus::Error,
                    notes,
                ),
                stdout,
                stderr,
                started: true,
                timed_out: false,
                exit_code,
                stderr_non_empty,
                duration_ms: started_at.elapsed().as_millis() as i64,
            };
        }

        match serde_json::from_slice::<TestOutput>(&stdout) {
            Ok(mut result) => {
                if result.test_id.0.trim().is_empty() {
                    result.test_id.0 = manifest.id.clone();
                }
                if result.target.trim().is_empty() {
                    result.target = input.target.clone();
                }
                if stderr_indicates_failure(&stderr_text) {
                    let notes = format!("plugin wrote failure-like stderr: {}", stderr_text.trim());
                    return ExecutionOutcome {
                        output: TestOutput::placeholder(
                            manifest.id.clone(),
                            input.target.clone(),
                            TestStatus::Error,
                            notes,
                        ),
                        stdout,
                        stderr,
                        started: true,
                        timed_out: false,
                        exit_code,
                        stderr_non_empty,
                        duration_ms: started_at.elapsed().as_millis() as i64,
                    };
                }

                if stderr_non_empty {
                    result.notes = match result.notes.take() {
                        Some(existing) => {
                            Some(format!("{existing}; stderr: {}", stderr_text.trim()))
                        }
                        None => Some(format!("plugin wrote to stderr: {}", stderr_text.trim())),
                    };
                }

                ExecutionOutcome {
                    output: result,
                    stdout,
                    stderr,
                    started: true,
                    timed_out: false,
                    exit_code,
                    stderr_non_empty,
                    duration_ms: started_at.elapsed().as_millis() as i64,
                }
            }
            Err(err) => {
                let notes = format!(
                    "plugin output was not valid JSON: {err}{}",
                    if stderr_non_empty {
                        format!("; stderr: {}", stderr_text.trim())
                    } else {
                        String::new()
                    }
                );
                ExecutionOutcome {
                    output: TestOutput::placeholder(
                        manifest.id.clone(),
                        input.target.clone(),
                        TestStatus::Error,
                        notes,
                    ),
                    stdout,
                    stderr,
                    started: true,
                    timed_out: false,
                    exit_code,
                    stderr_non_empty,
                    duration_ms: started_at.elapsed().as_millis() as i64,
                }
            }
        }
    }
}

impl Runner {
    /// Copy explicitly-declared env vars from the parent process into the child.
    fn apply_manifest_env(&self, command: &mut Command, manifest: &PluginManifest) {
        for key in &manifest.env {
            match env::var(key) {
                Ok(value) => {
                    command.env(key, value);
                }
                Err(_) => {
                    warn!(test_id = %manifest.id, env = %key, "declared plugin env var is not set");
                }
            }
        }
    }

    /// Apply a minimal baseline environment for child processes.
    fn apply_base_env(&self, command: &mut Command) {
        let tmp_root = PathBuf::from("/tmp/a-dap");
        let home = tmp_root.join("home");
        let tmpdir = tmp_root.join("tmp");

        let _ = fs::create_dir_all(&home);
        let _ = fs::create_dir_all(&tmpdir);

        command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
        command.env("HOME", &home);
        command.env("TMPDIR", &tmpdir);
        command.env("LANG", "C.UTF-8");
        command.env("LC_ALL", "C.UTF-8");
    }

    fn resolve_entrypoint(
        &self,
        record: &PluginRecord,
        manifest: &PluginManifest,
    ) -> anyhow::Result<PathBuf> {
        let entry = PathBuf::from(&manifest.entrypoint);
        let path = if entry.is_absolute() {
            entry
        } else {
            record.directory.join(entry)
        };

        if !path.exists() {
            anyhow::bail!(
                "entrypoint {} for plugin {} does not exist",
                path.display(),
                manifest.id
            );
        }

        let path = std::fs::canonicalize(&path).unwrap_or(path);

        match manifest.runtime {
            PluginRuntime::Shell | PluginRuntime::Python | PluginRuntime::Binary => Ok(path),
            PluginRuntime::Node | PluginRuntime::Oci => anyhow::bail!(
                "runtime {:?} not supported yet for plugin {}",
                manifest.runtime,
                manifest.id
            ),
        }
    }
}

/// Captured output and the best-effort plugin JSON result.
#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    pub output: TestOutput,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub started: bool,
    pub timed_out: bool,
    pub exit_code: Option<i32>,
    pub stderr_non_empty: bool,
    pub duration_ms: i64,
}

impl ExecutionOutcome {
    fn spawn_failed(test_id: String, target: String, message: String, duration_ms: i64) -> Self {
        Self {
            output: TestOutput::placeholder(test_id, target, TestStatus::Error, message.clone()),
            stdout: Vec::new(),
            stderr: message.into_bytes(),
            started: false,
            timed_out: false,
            exit_code: None,
            stderr_non_empty: true,
            duration_ms,
        }
    }

    fn runtime_error(test_id: String, target: String, message: String, started: bool) -> Self {
        Self {
            output: TestOutput::placeholder(test_id, target, TestStatus::Error, message.clone()),
            stdout: Vec::new(),
            stderr: message.into_bytes(),
            started,
            timed_out: false,
            exit_code: None,
            stderr_non_empty: true,
            duration_ms: 0,
        }
    }
}

fn spawn_reader(mut pipe: impl AsyncRead + Unpin + Send + 'static) -> JoinHandle<Vec<u8>> {
    tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Err(err) = pipe.read_to_end(&mut buf).await {
            return format!("failed to read plugin stream: {err}").into_bytes();
        }
        buf
    })
}

async fn collect_reader(handle: Option<JoinHandle<Vec<u8>>>) -> Vec<u8> {
    match handle {
        Some(handle) => match handle.await {
            Ok(buf) => buf,
            Err(err) => format!("failed to join plugin stream reader: {err}").into_bytes(),
        },
        None => Vec::new(),
    }
}

/// Detect obvious failure output without overfitting to a specific plugin.
fn stderr_indicates_failure(stderr: &str) -> bool {
    let trimmed = stderr.trim();
    if trimmed.is_empty() {
        return false;
    }

    let lower = trimmed.to_ascii_lowercase();
    lower.contains("traceback")
        || lower.contains("error:")
        || lower.contains("fatal:")
        || lower.contains("exception")
        || lower.contains("failed")
}
