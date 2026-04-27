//! Binary entrypoint for the Artisan Dynamic Auditing Platform (DAP).
//!
//! The CLI intentionally exposes only a few options in this draft so we can
//! focus on wiring the core pipeline. Additional flags (output paths, report
//! toggles, etc.) can be layered on once the underlying modules mature.

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use artisan_dap::{Orchestrator, RunConfig, report};

/// Minimal CLI options for driving a run.
#[derive(Debug, Parser)]
#[command(author, version, about = "Dynamic Domain Auditing Platform prototype")]
struct Cli {
    /// Path to the run configuration TOML file.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
    /// Path to the planner rules YAML file.
    #[arg(long, default_value = "rules.yaml")]
    rules: PathBuf,
    /// Root directory containing plugin manifests and entrypoints.
    #[arg(long, default_value = "plugins")]
    plugins: PathBuf,
    /// Render an HTML bundle from an existing results directory.
    #[arg(long, default_value_t = false)]
    report_only: bool,
    /// Existing results directory to render when using --report-only.
    #[arg(long, default_value = "results")]
    results_dir: PathBuf,
    /// Optional output root for the rendered HTML bundle.
    #[arg(long)]
    report_root: Option<PathBuf>,
    /// Optional CSS file to use when rendering a report bundle.
    #[arg(long)]
    report_css: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    install_tracing();
    let cli = Cli::parse();

    if cli.report_only {
        let report_root = cli.report_root.unwrap_or_else(|| {
            cli.results_dir
                .parent()
                .map(|path| path.to_path_buf())
                .unwrap_or_else(|| PathBuf::from("."))
        });
        let formats = vec!["html".to_string()];
        report::render_report(
            &report_root,
            &cli.results_dir,
            &formats,
            cli.report_css.as_deref(),
        )?;
        return Ok(());
    }

    let run_config = RunConfig::from_file(&cli.config)?;
    let orchestrator = Orchestrator::new(run_config, cli.rules, cli.plugins)?;
    orchestrator.run().await?;

    Ok(())
}

fn install_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();
}
