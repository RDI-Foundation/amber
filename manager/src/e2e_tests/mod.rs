mod harness;

use std::{collections::BTreeMap, net::TcpListener, time::Duration};

use amber_config::{encode_env_value, env_var_for_path};
use reqwest::StatusCode;
use serde_json::json;

use self::harness::{
    TestHarness, create_request, create_request_with_slot, operator_service_config, slot_bindings,
};
use crate::{
    config::ManagerFileConfig,
    domain::{
        BindableServiceResponse, CreateScenarioRequest, DesiredState, EnqueueOperationResponse,
        ExportPublishRequest, ExportRequest, ObservedState, OperationStatus,
        ScenarioRevisionSummaryResponse, ScenarioSummaryResponse, ScenarioTelemetryRequest,
        UpgradeScenarioRequest,
    },
};

async fn create_bound_provider_and_consumer(
    harness: &TestHarness,
) -> (EnqueueOperationResponse, EnqueueOperationResponse) {
    let provider_url = harness.write_provider_manifest("provider.json5");
    let consumer_url = harness.write_consumer_manifest("consumer.json5");

    let provider = harness.create_scenario(&create_request(provider_url)).await;
    let provider_op = harness.wait_for_operation(&provider.operation_id).await;
    assert_eq!(provider_op.status, OperationStatus::Succeeded);

    let provider_service = harness
        .find_export_service(&provider.scenario_id, "api")
        .await
        .expect("provider export service");
    let consumer = harness
        .create_scenario(&create_request_with_slot(
            consumer_url,
            "api",
            provider_service.bindable_service_id,
        ))
        .await;
    let consumer_op = harness.wait_for_operation(&consumer.operation_id).await;
    assert_eq!(consumer_op.status, OperationStatus::Succeeded);

    (provider, consumer)
}

#[tokio::test(flavor = "multi_thread")]
async fn scenario_lifecycle_over_live_http_api() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let provider_url = harness.write_provider_manifest("provider.json5");

    let created = harness
        .create_scenario(&create_request(provider_url.clone()))
        .await;
    let create_op = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(create_op.status, OperationStatus::Succeeded);

    let scenarios: Vec<ScenarioSummaryResponse> = harness.get_json("/v1/scenarios").await;
    assert_eq!(scenarios.len(), 1);
    assert_eq!(scenarios[0].scenario_id, created.scenario_id);
    assert_eq!(scenarios[0].observed_state, ObservedState::Running);

    let detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(detail.active_revision, Some(1));
    assert_eq!(detail.observed_state, ObservedState::Running);
    assert!(detail.exports["api"].available);
    assert_eq!(detail.source_url, provider_url);
    assert!(
        harness
            .find_export_service(&created.scenario_id, "api")
            .await
            .is_some()
    );

    let paused: EnqueueOperationResponse = harness
        .post_empty(&format!("/v1/scenarios/{}/pause", created.scenario_id))
        .await;
    let paused_op = harness.wait_for_operation(&paused.operation_id).await;
    assert_eq!(paused_op.status, OperationStatus::Succeeded);
    let paused_detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(paused_detail.observed_state, ObservedState::Paused);
    assert!(
        harness
            .find_export_service(&created.scenario_id, "api")
            .await
            .is_none()
    );

    let resumed: EnqueueOperationResponse = harness
        .post_empty(&format!("/v1/scenarios/{}/resume", created.scenario_id))
        .await;
    let resumed_op = harness.wait_for_operation(&resumed.operation_id).await;
    assert_eq!(resumed_op.status, OperationStatus::Succeeded);
    let resumed_detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(resumed_detail.observed_state, ObservedState::Running);
    assert!(
        harness
            .find_export_service(&created.scenario_id, "api")
            .await
            .is_some()
    );

    let upgraded: EnqueueOperationResponse = harness
        .post_json(
            &format!("/v1/scenarios/{}/upgrade", created.scenario_id),
            &UpgradeScenarioRequest {
                source_url: None,
                root_config: Some(json!({})),
                external_slots: Some(BTreeMap::new()),
                exports: Some(BTreeMap::new()),
                metadata: Some(json!({ "generation": 2 })),
                telemetry: Some(ScenarioTelemetryRequest::default()),
                store_bundle: false,
            },
        )
        .await;
    let upgraded_op = harness.wait_for_operation(&upgraded.operation_id).await;
    assert_eq!(upgraded_op.status, OperationStatus::Succeeded);
    let upgraded_detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(upgraded_detail.active_revision, Some(2));
    assert_eq!(upgraded_detail.metadata, json!({ "generation": 2 }));

    let revisions: Vec<ScenarioRevisionSummaryResponse> = harness
        .get_json(&format!("/v1/scenarios/{}/revisions", created.scenario_id))
        .await;
    assert_eq!(revisions.len(), 2);
    assert_eq!(revisions[0].revision, 1);
    assert_eq!(revisions[1].revision, 2);

    let deleted: EnqueueOperationResponse = harness
        .delete_json(&format!("/v1/scenarios/{}", created.scenario_id))
        .await;
    let deleted_op = harness.wait_for_operation(&deleted.operation_id).await;
    assert_eq!(deleted_op.status, OperationStatus::Succeeded);

    let (status, body) = harness
        .get_raw(&format!("/v1/scenarios/{}", created.scenario_id))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "unexpected body: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_preserves_omitted_configuration_fields() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let configured_url = harness.write_configured_manifest("configured-upgrade.json5");
    let telemetry_endpoint = "http://127.0.0.1:4318/v1/traces";
    let publish_listener = TcpListener::bind("127.0.0.1:0").expect("bind publish listener");
    let publish_addr = publish_listener.local_addr().expect("publish addr");
    drop(publish_listener);

    let created = harness
        .create_scenario(&CreateScenarioRequest {
            source_url: configured_url,
            root_config: json!({
                "public_value": "alpha",
                "secret_value": "bravo",
            }),
            external_slots: BTreeMap::new(),
            exports: BTreeMap::from([(
                "api".to_string(),
                ExportRequest {
                    publish: Some(ExportPublishRequest {
                        listen: publish_addr,
                    }),
                },
            )]),
            metadata: json!({ "generation": 1 }),
            telemetry: ScenarioTelemetryRequest {
                upstream_otlp_http_endpoint: Some(telemetry_endpoint.to_string()),
            },
            store_bundle: false,
            start: true,
        })
        .await;
    let create_op = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(create_op.status, OperationStatus::Succeeded);

    let upgraded: EnqueueOperationResponse = harness
        .post_json(
            &format!("/v1/scenarios/{}/upgrade", created.scenario_id),
            &UpgradeScenarioRequest {
                source_url: None,
                root_config: None,
                external_slots: None,
                exports: None,
                metadata: Some(json!({ "generation": 2 })),
                telemetry: None,
                store_bundle: false,
            },
        )
        .await;
    let upgraded_op = harness.wait_for_operation(&upgraded.operation_id).await;
    assert_eq!(upgraded_op.status, OperationStatus::Succeeded);

    let detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(detail.active_revision, Some(2));
    assert_eq!(detail.metadata, json!({ "generation": 2 }));
    assert_eq!(detail.root_config, json!({ "public_value": "alpha" }));
    assert_eq!(
        detail.secret_root_config_paths,
        vec!["secret_value".to_string()]
    );
    assert_eq!(
        detail.exports["api"]
            .publish
            .as_ref()
            .expect("published export")
            .listen,
        publish_addr
    );
    assert_eq!(
        detail.telemetry.upstream_otlp_http_endpoint.as_deref(),
        Some(telemetry_endpoint)
    );

    let upgraded_env = harness.read_runtime_env(&created.scenario_id, 2);
    assert_env_contains_root_config(&upgraded_env, "public_value", "alpha");
    assert_env_contains_root_config(&upgraded_env, "secret_value", "bravo");
    assert_env_contains_line(
        &upgraded_env,
        "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT",
        telemetry_endpoint,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_recovers_root_config_after_failed_initial_create() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let configured_url = harness.write_configured_manifest("configured-after-failed-create.json5");
    let telemetry_endpoint = "http://127.0.0.1:4318/v1/traces";

    let created = harness
        .create_scenario(&CreateScenarioRequest {
            source_url: "not a valid url".to_string(),
            root_config: json!({
                "public_value": "alpha",
                "secret_value": "bravo",
            }),
            external_slots: BTreeMap::new(),
            exports: BTreeMap::new(),
            metadata: json!({ "generation": 1 }),
            telemetry: ScenarioTelemetryRequest {
                upstream_otlp_http_endpoint: Some(telemetry_endpoint.to_string()),
            },
            store_bundle: false,
            start: true,
        })
        .await;
    let create_op = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(create_op.status, OperationStatus::Failed);

    let pending_detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(pending_detail.active_revision, None);
    assert_eq!(pending_detail.root_config, json!({}));
    assert!(pending_detail.secret_root_config_paths.is_empty());
    assert_eq!(pending_detail.metadata, json!({ "generation": 1 }));

    let upgraded: EnqueueOperationResponse = harness
        .post_json(
            &format!("/v1/scenarios/{}/upgrade", created.scenario_id),
            &UpgradeScenarioRequest {
                source_url: Some(configured_url),
                root_config: None,
                external_slots: None,
                exports: None,
                metadata: None,
                telemetry: None,
                store_bundle: false,
            },
        )
        .await;
    let upgraded_op = harness.wait_for_operation(&upgraded.operation_id).await;
    assert_eq!(upgraded_op.status, OperationStatus::Succeeded);

    let detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(detail.active_revision, Some(1));
    assert_eq!(detail.metadata, json!({ "generation": 1 }));
    assert_eq!(detail.root_config, json!({ "public_value": "alpha" }));
    assert_eq!(
        detail.secret_root_config_paths,
        vec!["secret_value".to_string()]
    );
    assert_eq!(
        detail.telemetry.upstream_otlp_http_endpoint.as_deref(),
        Some(telemetry_endpoint)
    );

    let runtime_env = harness.read_runtime_env(&created.scenario_id, 1);
    assert_env_contains_root_config(&runtime_env, "public_value", "alpha");
    assert_env_contains_root_config(&runtime_env, "secret_value", "bravo");
    assert_env_contains_line(
        &runtime_env,
        "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT",
        telemetry_endpoint,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn paused_resume_and_reconcile_keep_persisted_runtime_config() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let configured_url = harness.write_configured_manifest("configured.json5");
    let telemetry_endpoint = "http://127.0.0.1:4318/v1/traces";

    let created = harness
        .create_scenario(&CreateScenarioRequest {
            source_url: configured_url,
            root_config: json!({
                "public_value": "alpha",
                "secret_value": "bravo",
            }),
            external_slots: BTreeMap::new(),
            exports: BTreeMap::new(),
            metadata: json!({}),
            telemetry: ScenarioTelemetryRequest {
                upstream_otlp_http_endpoint: Some(telemetry_endpoint.to_string()),
            },
            store_bundle: false,
            start: false,
        })
        .await;
    let create_op = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(
        create_op.status,
        OperationStatus::Succeeded,
        "{create_op:?}"
    );
    assert!(!harness.runtime_dir(&created.scenario_id, 1).exists());

    let resumed: EnqueueOperationResponse = harness
        .post_empty(&format!("/v1/scenarios/{}/resume", created.scenario_id))
        .await;
    let resumed_op = harness.wait_for_operation(&resumed.operation_id).await;
    assert_eq!(resumed_op.status, OperationStatus::Succeeded);

    let initial_env = harness.read_runtime_env(&created.scenario_id, 1);
    assert_env_contains_root_config(&initial_env, "public_value", "alpha");
    assert_env_contains_root_config(&initial_env, "secret_value", "bravo");
    assert_env_contains_line(
        &initial_env,
        "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT",
        telemetry_endpoint,
    );

    let initial_apply_count = harness.runtime.apply_count(&created.scenario_id).await;
    harness
        .runtime
        .mark_unhealthy(&created.scenario_id, "configured scenario became unhealthy")
        .await;
    harness
        .wait_until(
            "configured scenario reconcile",
            Duration::from_secs(10),
            || async {
                harness.runtime.apply_count(&created.scenario_id).await > initial_apply_count
            },
        )
        .await;

    let reconciled_env = harness.read_runtime_env(&created.scenario_id, 1);
    assert_env_contains_root_config(&reconciled_env, "public_value", "alpha");
    assert_env_contains_root_config(&reconciled_env, "secret_value", "bravo");
    assert_env_contains_line(
        &reconciled_env,
        "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT",
        telemetry_endpoint,
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn consumer_binds_to_provider_export_and_blocks_provider_delete() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let (provider, consumer) = create_bound_provider_and_consumer(&harness).await;

    let consumer_detail = harness.scenario_detail(&consumer.scenario_id).await;
    assert_eq!(
        consumer_detail.external_slots["api"]
            .provider_scenario_id
            .as_deref(),
        Some(provider.scenario_id.as_str())
    );

    let (status, body) = harness
        .delete_raw(&format!("/v1/scenarios/{}", provider.scenario_id))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected body: {body}");
    assert!(
        body.contains("depend on its exports"),
        "unexpected body: {body}"
    );

    let provider_detail = harness.scenario_detail(&provider.scenario_id).await;
    let consumer_detail = harness.scenario_detail(&consumer.scenario_id).await;
    assert_eq!(provider_detail.observed_state, ObservedState::Running);
    assert_eq!(consumer_detail.observed_state, ObservedState::Running);
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_delete_stays_blocked_while_consumer_is_observed_running() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let (provider, consumer) = create_bound_provider_and_consumer(&harness).await;

    harness
        .set_scenario_states_for_test(
            &consumer.scenario_id,
            DesiredState::Paused,
            ObservedState::Running,
        )
        .await;

    let (status, body) = harness
        .delete_raw(&format!("/v1/scenarios/{}", provider.scenario_id))
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "unexpected body: {body}");
    assert!(
        body.contains("depend on its exports"),
        "unexpected body: {body}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn provider_upgrade_stays_blocked_while_consumer_is_observed_running() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let (provider, consumer) = create_bound_provider_and_consumer(&harness).await;

    harness
        .set_scenario_states_for_test(
            &consumer.scenario_id,
            DesiredState::Paused,
            ObservedState::Running,
        )
        .await;

    let provider_with_renamed_export = harness.write_manifest(
        "provider-renamed-export.json5",
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "provider",
            entrypoint: ["provider"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api2: "api" },
        }
        "#,
    );
    let upgrade: EnqueueOperationResponse = harness
        .post_json(
            &format!("/v1/scenarios/{}/upgrade", provider.scenario_id),
            &UpgradeScenarioRequest {
                source_url: Some(provider_with_renamed_export),
                root_config: Some(json!({})),
                external_slots: Some(BTreeMap::new()),
                exports: Some(BTreeMap::new()),
                metadata: Some(json!({})),
                telemetry: Some(ScenarioTelemetryRequest::default()),
                store_bundle: false,
            },
        )
        .await;
    let upgrade = harness.wait_for_operation(&upgrade.operation_id).await;
    assert_eq!(upgrade.status, OperationStatus::Failed);
    assert!(
        upgrade
            .last_error
            .as_deref()
            .is_some_and(|message| message.contains("active scenario")),
        "unexpected operation detail: {upgrade:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_applies_new_telemetry_immediately() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let provider_url = harness.write_provider_manifest("provider.json5");
    let initial_endpoint = "http://127.0.0.1:4318/v1/traces";
    let upgraded_endpoint = "http://127.0.0.1:4319/v1/traces";

    let created = harness
        .create_scenario(&CreateScenarioRequest {
            telemetry: ScenarioTelemetryRequest {
                upstream_otlp_http_endpoint: Some(initial_endpoint.to_string()),
            },
            ..create_request(provider_url)
        })
        .await;
    let create_op = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(create_op.status, OperationStatus::Succeeded);
    let initial_env = harness.read_runtime_env(&created.scenario_id, 1);
    assert_env_contains_line(
        &initial_env,
        "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT",
        initial_endpoint,
    );

    let upgraded: EnqueueOperationResponse = harness
        .post_json(
            &format!("/v1/scenarios/{}/upgrade", created.scenario_id),
            &UpgradeScenarioRequest {
                source_url: None,
                root_config: Some(json!({})),
                external_slots: Some(BTreeMap::new()),
                exports: Some(BTreeMap::new()),
                metadata: Some(json!({})),
                telemetry: Some(ScenarioTelemetryRequest {
                    upstream_otlp_http_endpoint: Some(upgraded_endpoint.to_string()),
                }),
                store_bundle: false,
            },
        )
        .await;
    let upgraded_op = harness.wait_for_operation(&upgraded.operation_id).await;
    assert_eq!(upgraded_op.status, OperationStatus::Succeeded);

    let upgraded_env = harness.read_runtime_env(&created.scenario_id, 2);
    assert_env_contains_line(
        &upgraded_env,
        "AMBER_OTEL_UPSTREAM_OTLP_HTTP_ENDPOINT",
        upgraded_endpoint,
    );
    assert!(
        !upgraded_env.contains(initial_endpoint),
        "stale telemetry endpoint remained in runtime env: {upgraded_env}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn upgrade_rejects_dependency_cycle() {
    let harness = TestHarness::new(operator_service_config()).await;
    let operator_service = harness
        .find_operator_service("bootstrap")
        .await
        .expect("bootstrap operator service");
    let relay_url = harness.write_dependency_export_manifest("relay.json5");

    let first = harness
        .create_scenario(&create_request_with_slot(
            relay_url.clone(),
            "dep",
            operator_service.bindable_service_id,
        ))
        .await;
    let first_op = harness.wait_for_operation(&first.operation_id).await;
    assert_eq!(first_op.status, OperationStatus::Succeeded);

    let first_export = harness
        .find_export_service(&first.scenario_id, "api")
        .await
        .expect("first export");
    let second = harness
        .create_scenario(&create_request_with_slot(
            relay_url,
            "dep",
            first_export.bindable_service_id.clone(),
        ))
        .await;
    let second_op = harness.wait_for_operation(&second.operation_id).await;
    assert_eq!(second_op.status, OperationStatus::Succeeded);

    let second_export = harness
        .find_export_service(&second.scenario_id, "api")
        .await
        .expect("second export");
    let upgrade: EnqueueOperationResponse = harness
        .post_json(
            &format!("/v1/scenarios/{}/upgrade", first.scenario_id),
            &UpgradeScenarioRequest {
                source_url: None,
                root_config: Some(json!({})),
                external_slots: Some(slot_bindings("dep", &second_export.bindable_service_id)),
                exports: Some(BTreeMap::new()),
                metadata: Some(json!({})),
                telemetry: Some(ScenarioTelemetryRequest::default()),
                store_bundle: false,
            },
        )
        .await;
    let upgrade_op = harness.wait_for_operation(&upgrade.operation_id).await;
    assert_eq!(upgrade_op.status, OperationStatus::Failed);
    assert!(
        upgrade_op
            .last_error
            .as_deref()
            .is_some_and(|message| message.contains("dependency cycle"))
    );

    let revisions: Vec<ScenarioRevisionSummaryResponse> = harness
        .get_json(&format!("/v1/scenarios/{}/revisions", first.scenario_id))
        .await;
    assert_eq!(revisions.len(), 1);
}

#[tokio::test(flavor = "multi_thread")]
async fn stored_bundle_survives_runtime_output_and_delete_removes_scenario_state() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let provider_url = harness.write_provider_manifest("provider.json5");

    let created = harness
        .create_scenario(&CreateScenarioRequest {
            store_bundle: true,
            ..create_request(provider_url)
        })
        .await;
    let create_op = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(create_op.status, OperationStatus::Succeeded);

    let detail = harness.scenario_detail(&created.scenario_id).await;
    assert!(detail.bundle_stored);
    assert!(harness.bundle_dir(&created.scenario_id, 1).is_dir());
    assert!(harness.runtime_dir(&created.scenario_id, 1).is_dir());

    let deleted: EnqueueOperationResponse = harness
        .delete_json(&format!("/v1/scenarios/{}", created.scenario_id))
        .await;
    let deleted_op = harness.wait_for_operation(&deleted.operation_id).await;
    assert_eq!(deleted_op.status, OperationStatus::Succeeded);
    assert!(!harness.scenario_dir(&created.scenario_id).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn create_retries_after_transient_runtime_failures() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let provider_url = harness.write_provider_manifest("provider.json5");

    harness.runtime.fail_next_apply_any(2).await;

    let created = harness.create_scenario(&create_request(provider_url)).await;
    let operation = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(operation.status, OperationStatus::Succeeded);
    assert_eq!(operation.retry_count, 2);
    assert_eq!(
        harness
            .runtime
            .apply_attempt_count(&created.scenario_id)
            .await,
        3
    );
    assert_eq!(harness.runtime.apply_count(&created.scenario_id).await, 1);

    let detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(detail.observed_state, ObservedState::Running);
}

#[tokio::test(flavor = "multi_thread")]
async fn create_stops_retrying_after_backoff_budget_is_exhausted() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let provider_url = harness.write_provider_manifest("provider.json5");

    harness.runtime.fail_next_apply_any(10).await;

    let created = harness.create_scenario(&create_request(provider_url)).await;
    let operation = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(operation.status, OperationStatus::Failed);
    assert_eq!(operation.retry_count, 3);
    assert_eq!(
        harness
            .runtime
            .apply_attempt_count(&created.scenario_id)
            .await,
        4
    );
    assert_eq!(harness.runtime.apply_count(&created.scenario_id).await, 0);

    let detail = harness.scenario_detail(&created.scenario_id).await;
    assert_eq!(detail.observed_state, ObservedState::Failed);
    assert!(
        detail
            .last_error
            .as_deref()
            .is_some_and(|message| message.contains("fake runtime apply failure"))
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn health_monitor_restarts_unhealthy_provider_without_rewiring_consumer() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let (provider, consumer) = create_bound_provider_and_consumer(&harness).await;

    let initial_consumer_spec = harness
        .runtime
        .last_spec(&consumer.scenario_id)
        .await
        .expect("consumer runtime spec");
    let initial_upstream = initial_consumer_spec.proxy_plan.slot_bindings[0].upstream;
    let initial_provider_apply_count = harness.runtime.apply_count(&provider.scenario_id).await;
    let initial_consumer_apply_count = harness.runtime.apply_count(&consumer.scenario_id).await;

    harness
        .runtime
        .mark_unhealthy(&provider.scenario_id, "provider became unhealthy")
        .await;

    harness
        .wait_until("provider restart", Duration::from_secs(10), || async {
            harness.runtime.apply_count(&provider.scenario_id).await > initial_provider_apply_count
        })
        .await;

    let consumer_spec = harness
        .runtime
        .last_spec(&consumer.scenario_id)
        .await
        .expect("consumer runtime spec");
    let consumer_upstream = consumer_spec.proxy_plan.slot_bindings[0].upstream;
    assert_eq!(consumer_upstream, initial_upstream);
    assert_eq!(
        harness.runtime.apply_count(&consumer.scenario_id).await,
        initial_consumer_apply_count
    );

    let provider_detail = harness.scenario_detail(&provider.scenario_id).await;
    let consumer_detail = harness.scenario_detail(&consumer.scenario_id).await;
    assert_eq!(provider_detail.observed_state, ObservedState::Running);
    assert_eq!(consumer_detail.observed_state, ObservedState::Running);
}

#[tokio::test(flavor = "multi_thread")]
async fn failed_runtime_cleanup_marks_exports_unavailable() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let provider_url = harness.write_provider_manifest("provider.json5");

    let provider = harness.create_scenario(&create_request(provider_url)).await;
    let provider_op = harness.wait_for_operation(&provider.operation_id).await;
    assert_eq!(provider_op.status, OperationStatus::Succeeded);

    harness.runtime.fail_next_apply_any(1).await;
    harness
        .runtime
        .mark_unhealthy(&provider.scenario_id, "provider became unhealthy")
        .await;

    harness
        .wait_until(
            "provider export unavailable",
            Duration::from_secs(10),
            || async {
                harness
                    .find_export_service(&provider.scenario_id, "api")
                    .await
                    .is_some_and(|service| !service.available)
            },
        )
        .await;

    let services: Vec<BindableServiceResponse> = harness.get_json("/v1/bindable-services").await;
    let export = services
        .into_iter()
        .find(|service| {
            service.scenario_id.as_deref() == Some(provider.scenario_id.as_str())
                && service.export.as_deref() == Some("api")
        })
        .expect("provider export service should still be listed");
    assert!(!export.available);

    let detail = harness.scenario_detail(&provider.scenario_id).await;
    assert!(!detail.exports["api"].available);
}

#[tokio::test(flavor = "multi_thread")]
async fn published_exports_precede_internal_loopback_bindings() {
    let harness = TestHarness::new(ManagerFileConfig::default()).await;
    let provider_url = harness.write_provider_manifest("provider.json5");
    let publish_listener = TcpListener::bind("127.0.0.1:0").expect("bind publish listener");
    let publish_addr = publish_listener.local_addr().expect("publish addr");
    drop(publish_listener);

    let created = harness
        .create_scenario(&CreateScenarioRequest {
            exports: BTreeMap::from([(
                "api".to_string(),
                ExportRequest {
                    publish: Some(ExportPublishRequest {
                        listen: publish_addr,
                    }),
                },
            )]),
            ..create_request(provider_url)
        })
        .await;
    let create_op = harness.wait_for_operation(&created.operation_id).await;
    assert_eq!(create_op.status, OperationStatus::Succeeded);

    let spec = harness
        .runtime
        .last_spec(&created.scenario_id)
        .await
        .expect("provider runtime spec");
    let export_bindings = spec
        .proxy_plan
        .export_bindings
        .into_iter()
        .filter(|binding| binding.export == "api")
        .collect::<Vec<_>>();
    assert_eq!(export_bindings.len(), 2);
    assert_eq!(export_bindings[0].listen, publish_addr);
    assert_ne!(export_bindings[1].listen, publish_addr);
    assert_eq!(
        export_bindings[1].listen.ip(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    );
}

fn assert_env_contains_root_config(env_contents: &str, path: &str, value: &str) {
    let key = env_var_for_path(path).expect("root config env var");
    let encoded = encode_env_value(&json!(value)).expect("encoded root config value");
    let escaped = escape_env_value_for_test(&encoded);
    assert_env_contains_line(env_contents, &key, &escaped);
}

fn assert_env_contains_line(env_contents: &str, key: &str, value: &str) {
    let expected = format!("{key}={value}");
    assert!(
        env_contents.lines().any(|line| line == expected),
        "expected runtime env to contain {expected}, got:\n{env_contents}"
    );
}

fn escape_env_value_for_test(value: &str) -> String {
    if value.contains('\n') || value.contains(' ') || value.contains('"') || value.contains('\'') {
        format!("{value:?}")
    } else {
        value.to_string()
    }
}
