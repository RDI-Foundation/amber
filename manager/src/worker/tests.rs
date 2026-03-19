use std::{collections::BTreeMap, net::TcpListener, path::Path, sync::Arc};

use clap::Parser;
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tempfile::TempDir;
use tokio::sync::Notify;
use url::Url;

use super::{
    AppState, OperationWorker,
    bindings::build_operator_services,
    errors::{
        backoff_ms, classify_create_compile_error, classify_upgrade_compile_error,
        retryable_operation_error, retryable_scenario_error,
    },
    graph::topological_order,
};
use crate::{
    ManagerConfig,
    compiler::{self, CompileError},
    config::{ManagerFileConfig, OperatorBindableServiceConfig},
    domain::{
        CreateScenarioRequest, DesiredState, ExportPublishRequest, ExportRequest, ObservedState,
        OperationKind, OperationPayload, OperationStatus, ScenarioTelemetryRequest,
        ServiceProtocol, UpgradeScenarioRequest,
    },
    runtime::RuntimeSupervisor,
    store::{NewPendingScenario, ScenarioStateUpdate, Store, StoredDependency, StoredScenario},
};

#[test]
fn topological_order_places_provider_before_consumer() {
    let scenarios = vec![
        StoredScenario {
            id: "consumer".to_string(),
            source_url: "https://example.com/consumer".to_string(),
            active_revision: Some(1),
            compose_project: "amber_consumer".to_string(),
            desired_state: DesiredState::Running,
            observed_state: ObservedState::Running,
            metadata: json!({}),
            root_config: Some(json!({})),
            telemetry: ScenarioTelemetryRequest::default(),
            external_slots: json!({}),
            exports: json!({}),
            failure_count: 0,
            backoff_until_ms: None,
            last_error: None,
            updated_at_ms: 0,
        },
        StoredScenario {
            id: "provider".to_string(),
            source_url: "https://example.com/provider".to_string(),
            active_revision: Some(1),
            compose_project: "amber_provider".to_string(),
            desired_state: DesiredState::Running,
            observed_state: ObservedState::Running,
            metadata: json!({}),
            root_config: Some(json!({})),
            telemetry: ScenarioTelemetryRequest::default(),
            external_slots: json!({}),
            exports: json!({}),
            failure_count: 0,
            backoff_until_ms: None,
            last_error: None,
            updated_at_ms: 0,
        },
    ];
    let dependencies = vec![StoredDependency {
        consumer_scenario_id: "consumer".to_string(),
        slot_name: "api".to_string(),
        bindable_service_id: "svc_provider_api".to_string(),
        provider_scenario_id: Some("provider".to_string()),
    }];

    assert_eq!(
        topological_order(&scenarios, &dependencies),
        vec!["provider".to_string(), "consumer".to_string()]
    );
}

#[test]
fn build_operator_services_rejects_non_loopback_upstream() {
    let mut config = ManagerFileConfig::default();
    config.bindable_services.insert(
        "db".to_string(),
        OperatorBindableServiceConfig {
            protocol: ServiceProtocol::Http,
            provider: crate::config::OperatorServiceProvider::LoopbackUpstream {
                upstream: "10.0.0.5:8080".parse().expect("socket addr"),
            },
        },
    );

    let err = build_operator_services(config).expect_err("should reject non-loopback upstream");
    assert!(
        err.to_string().contains("loopback upstream"),
        "unexpected error: {err}"
    );
}

#[test]
fn backoff_grows_exponentially() {
    assert_eq!(backoff_ms(2_000, 1), 2_000);
    assert_eq!(backoff_ms(2_000, 2), 4_000);
    assert_eq!(backoff_ms(2_000, 3), 8_000);
}

#[test]
fn create_compile_write_failures_retry_as_scenario_errors() {
    let err = classify_create_compile_error(CompileError::WriteOutput("disk full".to_string()));
    assert!(err.retryable);
    assert!(err.affects_scenario);
    assert_eq!(err.observed_state, Some(ObservedState::Failed));
    assert!(!err.cleanup_runtime);
}

#[test]
fn upgrade_compile_write_failures_retry_without_touching_scenario_state() {
    let err = classify_upgrade_compile_error(CompileError::WriteOutput("disk full".to_string()));
    assert!(err.retryable);
    assert!(!err.affects_scenario);
    assert_eq!(err.observed_state, None);
    assert!(!err.cleanup_runtime);
}

#[test]
fn retryable_helpers_do_not_force_runtime_cleanup() {
    let scenario_err = retryable_scenario_error("temporary failure");
    assert!(scenario_err.retryable);
    assert!(!scenario_err.cleanup_runtime);
    assert!(scenario_err.affects_scenario);

    let operation_err = retryable_operation_error("temporary failure");
    assert!(operation_err.retryable);
    assert!(!operation_err.cleanup_runtime);
    assert!(!operation_err.affects_scenario);
}

#[tokio::test(flavor = "multi_thread")]
async fn prepare_bindings_does_not_probe_published_listener_early() {
    let tempdir = TempDir::new().expect("tempdir");
    let data_dir = tempdir.path().join("manager-data");
    tokio::fs::create_dir_all(&data_dir)
        .await
        .expect("create manager data dir");

    let config = ManagerConfig::parse_from([
        "amber-manager",
        "--listen",
        "127.0.0.1:0",
        "--data-dir",
        data_dir
            .to_str()
            .expect("manager data dir should be valid UTF-8"),
    ]);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(config.database_connect_options())
        .await
        .expect("connect sqlite");
    let store = Store::new(pool);
    store.migrate().await.expect("run migrations");

    let (runtime, _runtime_controller) = RuntimeSupervisor::for_tests(data_dir.clone());
    let notify = Arc::new(Notify::new());
    let state = Arc::new(
        AppState::new(config, ManagerFileConfig::default(), store, runtime, notify)
            .expect("create app state"),
    );
    let worker = OperationWorker::new(state);

    let manifest_url = write_manifest(
        tempdir.path(),
        "provider.json5",
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "provider",
            entrypoint: ["provider"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" },
        }
        "#,
    );
    let compiled = compiler::compile_create(
        &CreateScenarioRequest {
            source_url: manifest_url,
            root_config: json!({}),
            external_slots: BTreeMap::new(),
            exports: BTreeMap::new(),
            metadata: json!({}),
            telemetry: ScenarioTelemetryRequest::default(),
            store_bundle: false,
            start: true,
        },
        None,
    )
    .await
    .expect("compile provider manifest");

    let occupied_listener = TcpListener::bind("127.0.0.1:0").expect("bind occupied listener");
    let publish_addr = occupied_listener
        .local_addr()
        .expect("occupied listener addr");

    let bindings = worker
        .prepare_bindings(
            "scn_test",
            &compiled,
            &BTreeMap::new(),
            &BTreeMap::from([(
                "api".to_string(),
                ExportRequest {
                    publish: Some(ExportPublishRequest {
                        listen: publish_addr,
                    }),
                },
            )]),
            &BTreeMap::new(),
            false,
        )
        .await
        .expect("prepare bindings should not probe published listeners");

    assert_eq!(bindings.export_bindings.len(), 1);
    assert_eq!(
        bindings.export_bindings[0].published_listen,
        Some(publish_addr)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn startup_recovery_does_not_replay_interrupted_upgrade() {
    let (tempdir, state, worker) = setup_worker_test_context().await;
    let scenario_id = "scn_upgrade_recovery";
    let create_operation_id = "op_create_seed";
    let upgrade_operation_id = "op_upgrade_interrupted";
    let manifest_url = write_manifest(
        tempdir.path(),
        "provider.json5",
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "provider",
            entrypoint: ["provider"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" },
        }
        "#,
    );

    let create_request = CreateScenarioRequest {
        source_url: manifest_url.clone(),
        root_config: json!({}),
        external_slots: BTreeMap::new(),
        exports: BTreeMap::new(),
        metadata: json!({}),
        telemetry: ScenarioTelemetryRequest::default(),
        store_bundle: false,
        start: true,
    };
    let create_payload = OperationPayload::Create {
        request: create_request.clone(),
    };
    state
        .store()
        .create_pending_scenario_with_operation(NewPendingScenario {
            scenario_id,
            source_url: &create_request.source_url,
            root_config: &create_request.root_config,
            metadata: &create_request.metadata,
            external_slots: &serde_json::to_value(&create_request.external_slots)
                .expect("serialize external slots"),
            exports: &serde_json::to_value(&create_request.exports).expect("serialize exports"),
            telemetry: &create_request.telemetry,
            desired_state: DesiredState::Running,
            observed_state: ObservedState::Starting,
            compose_project: "amber_scn_upgrade_recovery",
            operation_id: create_operation_id,
            payload: &create_payload,
            now_ms: 1,
        })
        .await
        .expect("seed pending scenario");
    let create_operation = state
        .store()
        .claim_next_scenario_work(1)
        .await
        .expect("claim create work")
        .expect("seed create work");
    worker.process_claimed_work(create_operation).await;

    let created = state
        .store()
        .load_scenario(scenario_id)
        .await
        .expect("load created scenario")
        .expect("created scenario");
    assert_eq!(created.active_revision, Some(1));

    let upgrade_payload = OperationPayload::Upgrade {
        request: UpgradeScenarioRequest {
            source_url: None,
            root_config: Some(json!({})),
            external_slots: Some(BTreeMap::new()),
            exports: Some(BTreeMap::new()),
            metadata: Some(json!({ "generation": 2 })),
            telemetry: Some(ScenarioTelemetryRequest::default()),
            store_bundle: false,
        },
    };
    let staged = state
        .store()
        .stage_scenario_operation(
            scenario_id,
            upgrade_operation_id,
            OperationKind::Upgrade,
            &upgrade_payload,
            ScenarioStateUpdate::default(),
            2,
        )
        .await
        .expect("stage interrupted upgrade");
    assert!(staged);
    let claimed_upgrade = state
        .store()
        .claim_next_scenario_work(2)
        .await
        .expect("claim upgrade work")
        .expect("running upgrade work");
    state
        .store()
        .mark_operation_running(upgrade_operation_id, 2)
        .await
        .expect("mark interrupted upgrade running");
    assert_eq!(
        claimed_upgrade.operation_id.as_deref(),
        Some(upgrade_operation_id)
    );

    worker.enqueue_startup_reconciles().await;

    let recovered_upgrade = state
        .store()
        .get_operation(upgrade_operation_id)
        .await
        .expect("load recovered upgrade")
        .expect("recovered upgrade operation");
    assert_eq!(recovered_upgrade.status, OperationStatus::Failed);
    assert!(
        recovered_upgrade
            .last_error
            .as_deref()
            .is_some_and(|message| message.contains("interrupted upgrades are failed"))
    );

    let reconcile_operation = state
        .store()
        .claim_next_scenario_work(3)
        .await
        .expect("claim startup reconcile")
        .expect("startup reconcile work");
    assert_eq!(reconcile_operation.operation_id, None);
    worker.process_claimed_work(reconcile_operation).await;

    let revisions = state
        .store()
        .list_revisions(scenario_id)
        .await
        .expect("list revisions after startup recovery");
    assert_eq!(revisions.len(), 1);
}

fn write_manifest(root: &Path, name: &str, contents: &str) -> String {
    let path = root.join("manifests").join(name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create manifest dir");
    }
    std::fs::write(&path, contents).expect("write manifest");
    Url::from_file_path(&path)
        .expect("convert file path to URL")
        .to_string()
}

async fn setup_worker_test_context() -> (TempDir, Arc<AppState>, OperationWorker) {
    let tempdir = TempDir::new().expect("tempdir");
    let data_dir = tempdir.path().join("manager-data");
    tokio::fs::create_dir_all(&data_dir)
        .await
        .expect("create manager data dir");

    let config = ManagerConfig::parse_from([
        "amber-manager",
        "--listen",
        "127.0.0.1:0",
        "--data-dir",
        data_dir
            .to_str()
            .expect("manager data dir should be valid UTF-8"),
    ]);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(config.database_connect_options())
        .await
        .expect("connect sqlite");
    let store = Store::new(pool);
    store.migrate().await.expect("run migrations");

    let (runtime, _runtime_controller) = RuntimeSupervisor::for_tests(data_dir);
    let notify = Arc::new(Notify::new());
    let state = Arc::new(
        AppState::new(config, ManagerFileConfig::default(), store, runtime, notify)
            .expect("create app state"),
    );
    let worker = OperationWorker::new(state.clone());
    (tempdir, state, worker)
}
