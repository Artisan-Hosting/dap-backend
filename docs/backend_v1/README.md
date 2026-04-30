# Backend V1 Contracts

This folder records the backend-facing shapes introduced for the Axum/Tokio/SQLx service layer.

Files:

- `../openapi.yaml`: OpenAPI 3.0 description of the live HTTP API.
- `api_contracts.md`: HTTP endpoints, request bodies, and response shapes.
- `database_schema.md`: MySQL tables, relationships, and stored state.
- `report_contract.md`: canonical `report.json` payload emitted for completed runs.
- `implementation_choices.md`: backend-specific choices made where `backend_v1.md` left room for implementation details.

Code mapping:

- binary entrypoint and mode switch: `src/main.rs`
- HTTP server and worker-process coordination: `src/backend/mod.rs`
- capability registry: `src/backend/capabilities.rs`
- storage and query layer: `src/backend/storage.rs`
- worker process loop: `src/backend/worker.rs`
- migration: `migrations/0001_backend_v1.sql`
- service config: `backend.toml`

Notes:

- `GET /v1/tests` includes both normal plugin-backed tests and internal discovery capabilities when configured.
- `discovery_api_probe` and `discovery_dav_probe` are internal toggles that gate extra discovery-time probing; they are intentionally not normal plugin jobs.
