CARGO ?= cargo
CONFIG ?= backend.toml
TEMPLATE ?= backend.toml.example

.PHONY: build test run-debug run-release dummy-backend-toml install-dummy-backend-toml backend.toml

build:
	$(CARGO) build

test:
	$(CARGO) test

run-debug:
	ARTISAN_DAP_BACKEND_CONFIG=$(CONFIG) $(CARGO) run

run-release:
	ARTISAN_DAP_BACKEND_CONFIG=$(CONFIG) $(CARGO) run --release

dummy-backend-toml:
	@if [ -e "$(TEMPLATE)" ]; then \
		echo "$(TEMPLATE) already exists"; \
		exit 1; \
	fi
	@cat > "$(TEMPLATE)" <<-'EOF'
	[server]
	bind = "127.0.0.1:3000"

	[storage]
	artifacts_root = "artifacts"

	[storage.mysql]
	host = "127.0.0.1"
	port = 3306
	database = "artisan_dap"
	username = "root"
	password = ""
	max_connections = 10

	[cache]
	freshness_window_seconds = 30
	dedupe_inflight = true
	ct_subdomain_cache_ttl_seconds = 86400

	[engine]
	rules_path = "rules.yaml"
	plugins_path = "plugins"
	default_scope_mode = "domain_sweep"
	force_single_site_for_hostnames = false
	enabled_tests = []
	disabled_tests = []
	worker_poll_interval_ms = 1000

	[engine.discovery_probes]
	api_endpoints = true
	dav_endpoints = true

	[engine.execution]
	max_concurrent_tests = 10
	max_workers = 8
	per_host_concurrency = 2

	[engine.report]
	formats = ["json"]

	[engine.psi]
	enabled = false
	strategies = ["mobile", "desktop"]
	categories = ["performance", "accessibility", "best-practices", "seo"]
	timeout_seconds = 60
	# credentials_file = "/path/to/service-account.json"
	EOF

install-dummy-backend-toml: dummy-backend-toml
	@if [ -e "$(CONFIG)" ] && [ -z "$(FORCE)" ]; then \
		echo "$(CONFIG) already exists; use FORCE=1 to overwrite"; \
		exit 1; \
	fi
	@cp "$(TEMPLATE)" "$(CONFIG)"

backend.toml: install-dummy-backend-toml
