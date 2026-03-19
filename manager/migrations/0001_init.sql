PRAGMA foreign_keys = ON;

CREATE TABLE scenarios (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    source_url TEXT NOT NULL,
    active_revision INTEGER,
    compose_project TEXT NOT NULL,
    desired_state TEXT NOT NULL,
    observed_state TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    root_config_json TEXT,
    telemetry_json TEXT NOT NULL DEFAULT '{}',
    external_slots_json TEXT NOT NULL DEFAULT '{}',
    exports_json TEXT NOT NULL DEFAULT '{}',
    failure_count INTEGER NOT NULL DEFAULT 0,
    backoff_until_ms INTEGER,
    last_error TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE scenario_secrets (
    scenario_id TEXT PRIMARY KEY REFERENCES scenarios(id) ON DELETE CASCADE,
    secret_config_json TEXT NOT NULL,
    updated_at_ms INTEGER NOT NULL
);

CREATE TABLE scenario_revisions (
    scenario_id TEXT NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
    revision INTEGER NOT NULL,
    source_url TEXT NOT NULL,
    scenario_ir_json TEXT NOT NULL,
    bundle_root TEXT,
    manager_version TEXT NOT NULL,
    amber_version TEXT NOT NULL,
    ir_version INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (scenario_id, revision)
);

CREATE TABLE scenario_export_services (
    service_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    scenario_id TEXT NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
    export_name TEXT NOT NULL,
    protocol TEXT NOT NULL,
    listen_addr TEXT NOT NULL,
    listen_port INTEGER NOT NULL,
    available INTEGER NOT NULL,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    UNIQUE (scenario_id, export_name)
);

CREATE TABLE scenario_dependencies (
    consumer_scenario_id TEXT NOT NULL REFERENCES scenarios(id) ON DELETE CASCADE,
    slot_name TEXT NOT NULL,
    bindable_service_id TEXT NOT NULL,
    provider_scenario_id TEXT REFERENCES scenarios(id) ON DELETE CASCADE,
    created_at_ms INTEGER NOT NULL,
    PRIMARY KEY (consumer_scenario_id, slot_name)
);

CREATE TABLE operations (
    id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    scenario_id TEXT,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL,
    phase TEXT NOT NULL,
    retry_count INTEGER NOT NULL DEFAULT 0,
    backoff_until_ms INTEGER,
    last_error TEXT,
    result_json TEXT,
    created_at_ms INTEGER NOT NULL,
    updated_at_ms INTEGER NOT NULL,
    started_at_ms INTEGER,
    finished_at_ms INTEGER
);

CREATE INDEX operations_queue_idx
    ON operations(status, backoff_until_ms, created_at_ms);

CREATE UNIQUE INDEX operations_inflight_reconcile_scenario_idx
    ON operations(scenario_id)
    WHERE kind = 'reconcile' AND status IN ('queued', 'running');

CREATE INDEX scenario_dependencies_provider_idx
    ON scenario_dependencies(provider_scenario_id);

CREATE INDEX scenario_export_services_scenario_idx
    ON scenario_export_services(scenario_id);
