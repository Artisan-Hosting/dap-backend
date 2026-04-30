The main gaps in the test execution flow are:
- plugins/*/manifest.yaml fields like triggers, limits, and env are parsed, but Runner does not enforce them.
- There is no timeout or kill logic around plugin processes.
- There is no sandboxing/isolation yet, just direct process spawn.
- Plugin environment variables are not injected from the manifest.
- stderr is inherited, not captured into run artifacts.
- Execution is still sequential within a run, but the backend now drives it through a dedicated worker subprocess rather than the old in-process Orchestrator::run() path.
- There’s no retry/backoff or richer error classification for plugin failures.
- The flow does not aggregate results into a full report, only per-test JSON plus summary_by_host.json.
- Manifest triggers are effectively unused, since scheduling is driven by rules.yaml instead.
