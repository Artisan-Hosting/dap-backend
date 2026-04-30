//! Binary entrypoint for the backend service.

use std::{env, path::PathBuf};

use anyhow::Result;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use artisan_dap::backend;

#[tokio::main]
async fn main() -> Result<()> {
    install_tracing();
    if is_worker_mode() {
        backend::run_worker(config_path()).await
    } else {
        backend::run_server(config_path()).await
    }
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}

fn config_path() -> PathBuf {
    env::var_os("ARTISAN_DAP_BACKEND_CONFIG")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("backend.toml"))
}

fn is_worker_mode() -> bool {
    env::args_os().any(|arg| arg == "--worker")
}
