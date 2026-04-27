CREATE TABLE runs (
    run_id VARCHAR(64) PRIMARY KEY,
    target_input VARCHAR(255) NOT NULL,
    target_key VARCHAR(255) NOT NULL,
    state VARCHAR(32) NOT NULL,
    submitted_at TIMESTAMP(6) NOT NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    cache_hit BIGINT NOT NULL DEFAULT 0,
    reused_from_run_id VARCHAR(64) NULL,
    force_refresh BIGINT NOT NULL DEFAULT 0,
    client_request_id VARCHAR(255) NULL,
    engine_version VARCHAR(64) NOT NULL,
    rules_version VARCHAR(64) NOT NULL,
    config_hash VARCHAR(64) NOT NULL,
    request_fingerprint VARCHAR(64) NOT NULL,
    error_message TEXT NULL,
    FOREIGN KEY (reused_from_run_id) REFERENCES runs(run_id)
);

CREATE INDEX idx_runs_target_key_submitted_at ON runs(target_key, submitted_at);
CREATE INDEX idx_runs_state_submitted_at ON runs(state, submitted_at);
CREATE INDEX idx_runs_request_fingerprint ON runs(request_fingerprint);

CREATE TABLE run_requested_tests (
    run_id VARCHAR(64) NOT NULL,
    test_id VARCHAR(128) NOT NULL,
    state VARCHAR(64) NOT NULL,
    reason TEXT NULL,
    PRIMARY KEY (run_id, test_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE TABLE facts (
    fact_id VARCHAR(64) NOT NULL,
    run_id VARCHAR(64) NOT NULL,
    target_key VARCHAR(255) NOT NULL,
    entity VARCHAR(64) NOT NULL,
    attrs_json LONGTEXT NOT NULL,
    PRIMARY KEY (run_id, fact_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX idx_facts_run_id ON facts(run_id);
CREATE INDEX idx_facts_target_key ON facts(target_key);

CREATE TABLE site_profiles (
    run_id VARCHAR(64) NOT NULL,
    host VARCHAR(255) NOT NULL,
    kind VARCHAR(64) NOT NULL,
    provider VARCHAR(128) NULL,
    confidence DOUBLE NOT NULL,
    signals_json LONGTEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX idx_site_profiles_run_id ON site_profiles(run_id);

CREATE TABLE dead_hosts (
    run_id VARCHAR(64) NOT NULL,
    host VARCHAR(255) NOT NULL,
    reason TEXT NOT NULL,
    source VARCHAR(64) NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX idx_dead_hosts_run_id ON dead_hosts(run_id);

CREATE TABLE planned_tests (
    planned_test_id VARCHAR(64) PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL,
    test_id VARCHAR(128) NOT NULL,
    execution_target VARCHAR(255) NOT NULL,
    source_fact_id VARCHAR(64) NULL,
    state VARCHAR(64) NOT NULL,
    rejection_reason TEXT NULL,
    queued_at TIMESTAMP(6) NOT NULL,
    started_at TIMESTAMP(6) NULL,
    completed_at TIMESTAMP(6) NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX idx_planned_tests_run_id ON planned_tests(run_id);
CREATE INDEX idx_planned_tests_state ON planned_tests(state);

CREATE TABLE test_results (
    result_id VARCHAR(64) PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL,
    planned_test_id VARCHAR(64) NOT NULL,
    target_key VARCHAR(255) NOT NULL,
    execution_target VARCHAR(255) NOT NULL,
    test_id VARCHAR(128) NOT NULL,
    plugin_version VARCHAR(64) NOT NULL,
    status VARCHAR(32) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    evidence_json LONGTEXT NOT NULL,
    recommendations_json LONGTEXT NOT NULL,
    notes TEXT NULL,
    timed_out BIGINT NOT NULL DEFAULT 0,
    exit_code INT NULL,
    stderr_non_empty BIGINT NOT NULL DEFAULT 0,
    duration_ms BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMP(6) NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (planned_test_id) REFERENCES planned_tests(planned_test_id) ON DELETE CASCADE
);

CREATE INDEX idx_test_results_run_id ON test_results(run_id, created_at);
CREATE INDEX idx_test_results_target_key ON test_results(target_key, created_at);

CREATE TABLE artifacts (
    artifact_id VARCHAR(64) PRIMARY KEY,
    run_id VARCHAR(64) NOT NULL,
    result_id VARCHAR(64) NULL,
    artifact_type VARCHAR(64) NOT NULL,
    relative_path VARCHAR(1024) NOT NULL,
    content_type VARCHAR(255) NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE,
    FOREIGN KEY (result_id) REFERENCES test_results(result_id) ON DELETE CASCADE
);

CREATE INDEX idx_artifacts_run_id ON artifacts(run_id);
CREATE INDEX idx_artifacts_result_id ON artifacts(result_id);

CREATE TABLE reports (
    run_id VARCHAR(64) PRIMARY KEY,
    report_json_path VARCHAR(1024) NOT NULL,
    report_html_path VARCHAR(1024) NULL,
    generated_at TIMESTAMP(6) NOT NULL,
    schema_version VARCHAR(32) NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
