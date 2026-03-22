use std::{
    collections::BTreeMap,
    future::Future,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::serve;
use clap::Parser;
use reqwest::{Client, StatusCode};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::json;
use sqlx::sqlite::SqlitePoolOptions;
use tempfile::TempDir;
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle, time::sleep};
use url::Url;

use crate::{
    ManagerConfig,
    api::router,
    config::{ManagerFileConfig, OperatorBindableServiceConfig, OperatorServiceProvider},
    domain::{
        BindableServiceResponse, CreateScenarioRequest, DesiredState, EnqueueOperationResponse,
        ExternalSlotBindingRequest, ObservedState, OperationStatus, OperationStatusResponse,
        ScenarioDetailResponse, ScenarioTelemetryRequest, ServiceProtocol,
    },
    mcp,
    runtime::{FakeRuntimeController, RuntimeSupervisor},
    service::ManagerService,
    store::Store,
    worker::{AppState, HealthMonitor, OperationWorker},
};

pub(super) struct TestHarness {
    _tempdir: TempDir,
    _state: Arc<AppState>,
    client: Client,
    pub(super) runtime: FakeRuntimeController,
    data_dir: PathBuf,
    pub(super) base_url: String,
    task_handles: Vec<JoinHandle<()>>,
}

impl TestHarness {
    pub(super) async fn new(file_config: ManagerFileConfig) -> Self {
        Self::new_inner(file_config, true, 10).await
    }

    pub(super) async fn new_without_worker(file_config: ManagerFileConfig) -> Self {
        Self::new_inner(file_config, false, 10).await
    }

    pub(super) async fn new_with_base_backoff(
        file_config: ManagerFileConfig,
        base_backoff_ms: u64,
    ) -> Self {
        Self::new_inner(file_config, true, base_backoff_ms).await
    }

    async fn new_inner(
        file_config: ManagerFileConfig,
        run_worker: bool,
        base_backoff_ms: u64,
    ) -> Self {
        let tempdir = TempDir::new().expect("tempdir");
        let data_dir = tempdir.path().join("manager-data");
        tokio::fs::create_dir_all(&data_dir)
            .await
            .expect("create manager data dir");

        let config = manager_config(&data_dir, base_backoff_ms);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(config.database_connect_options())
            .await
            .expect("connect sqlite");
        let store = Store::new(pool);
        store.migrate().await.expect("run migrations");

        let (runtime, runtime_controller) = RuntimeSupervisor::for_tests(data_dir.clone());
        let notify = Arc::new(Notify::new());
        let state = Arc::new(
            AppState::new(config, file_config, store, runtime, notify).expect("create app state"),
        );

        let health_monitor = HealthMonitor::new(state.clone());
        let health_handle = tokio::spawn(async move {
            health_monitor.run().await;
        });

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener addr");
        let manager = Arc::new(ManagerService::new(state.clone()));
        let app = router(manager.clone()).nest_service("/mcp", mcp::service(manager));
        let server_handle = tokio::spawn(async move {
            serve(listener, app.into_make_service())
                .await
                .expect("serve test app");
        });

        let mut task_handles = vec![health_handle, server_handle];
        if run_worker {
            let worker = OperationWorker::new(state.clone());
            worker.enqueue_startup_reconciles().await;
            task_handles.push(tokio::spawn(async move {
                worker.run().await;
            }));
        }

        Self {
            _tempdir: tempdir,
            _state: state,
            client: Client::new(),
            runtime: runtime_controller,
            data_dir,
            base_url: format!("http://{addr}"),
            task_handles,
        }
    }

    pub(super) fn write_provider_manifest(&self, name: &str) -> String {
        self.write_manifest(
            name,
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
        )
    }

    pub(super) fn write_consumer_manifest(&self, name: &str) -> String {
        self.write_manifest(
            name,
            r#"
            {
              manifest_version: "0.1.0",
              program: {
                image: "consumer",
                entrypoint: ["consumer"],
                env: { API_URL: "${slots.api.url}" },
              },
              slots: { api: { kind: "http" } },
            }
            "#,
        )
    }

    pub(super) fn write_dependency_export_manifest(&self, name: &str) -> String {
        self.write_manifest(
            name,
            r#"
            {
              manifest_version: "0.1.0",
              program: {
                image: "relay",
                entrypoint: ["relay"],
                env: { DEP_URL: "${slots.dep.url}" },
                network: { endpoints: [{ name: "api", port: 80 }] },
              },
              slots: { dep: { kind: "http" } },
              provides: { api: { kind: "http", endpoint: "api" } },
              exports: { api: "api" },
            }
            "#,
        )
    }

    pub(super) fn write_configured_manifest(&self, name: &str) -> String {
        self.write_manifest(
            name,
            r#"
            {
              manifest_version: "0.1.0",
              config_schema: {
                type: "object",
                properties: {
                  public_value: { type: "string" },
                  secret_value: { type: "string", secret: true },
                },
                required: ["public_value", "secret_value"],
              },
              program: {
                image: "configured",
                entrypoint: ["configured"],
                network: { endpoints: [{ name: "api", port: 80 }] },
              },
              provides: { api: { kind: "http", endpoint: "api" } },
              exports: { api: "api" },
            }
            "#,
        )
    }

    pub(super) fn write_manifest(&self, name: &str, contents: &str) -> String {
        let path = self._tempdir.path().join("manifests").join(name);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create manifest dir");
        }
        std::fs::write(&path, contents).expect("write manifest");
        file_url(&path)
    }

    pub(super) async fn create_scenario(
        &self,
        request: &CreateScenarioRequest,
    ) -> EnqueueOperationResponse {
        self.post_json("/v1/scenarios", request).await
    }

    pub(super) async fn scenario_detail(&self, scenario_id: &str) -> ScenarioDetailResponse {
        self.get_json(&format!("/v1/scenarios/{scenario_id}")).await
    }

    pub(super) async fn find_export_service(
        &self,
        scenario_id: &str,
        export: &str,
    ) -> Option<BindableServiceResponse> {
        self.get_json::<Vec<BindableServiceResponse>>("/v1/bindable-services")
            .await
            .into_iter()
            .find(|service| {
                service.scenario_id.as_deref() == Some(scenario_id)
                    && service.export.as_deref() == Some(export)
            })
    }

    pub(super) async fn find_operator_service(
        &self,
        name: &str,
    ) -> Option<BindableServiceResponse> {
        self.get_json::<Vec<BindableServiceResponse>>("/v1/bindable-services")
            .await
            .into_iter()
            .find(|service| service.display_name.as_deref() == Some(name))
    }

    pub(super) async fn wait_for_operation(&self, operation_id: &str) -> OperationStatusResponse {
        let path = format!("/v1/operations/{operation_id}");
        self.wait_for_value("operation completion", Duration::from_secs(20), || async {
            let operation: OperationStatusResponse = self.get_json(&path).await;
            match operation.status {
                OperationStatus::Queued | OperationStatus::Running => None,
                OperationStatus::Succeeded | OperationStatus::Failed => Some(operation),
            }
        })
        .await
    }

    pub(super) async fn wait_until<F, Fut>(
        &self,
        description: &str,
        timeout: Duration,
        mut check: F,
    ) where
        F: FnMut() -> Fut,
        Fut: Future<Output = bool>,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if check().await {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {description}"
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    pub(super) async fn wait_for_value<F, Fut, T>(
        &self,
        description: &str,
        timeout: Duration,
        mut check: F,
    ) -> T
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Option<T>>,
    {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(value) = check().await {
                return value;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {description}"
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    pub(super) async fn get_json<T: DeserializeOwned>(&self, path: &str) -> T {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("send GET");
        Self::decode_success(response).await
    }

    pub(super) async fn post_json<B: Serialize, T: DeserializeOwned>(
        &self,
        path: &str,
        body: &B,
    ) -> T {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await
            .expect("send POST");
        Self::decode_success(response).await
    }

    pub(super) async fn post_json_raw<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> (StatusCode, String) {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .json(body)
            .send()
            .await
            .expect("send raw POST");
        let status = response.status();
        let body = response.text().await.expect("read raw POST body");
        (status, body)
    }

    pub(super) async fn post_empty<T: DeserializeOwned>(&self, path: &str) -> T {
        let response = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("send empty POST");
        Self::decode_success(response).await
    }

    pub(super) async fn delete_json<T: DeserializeOwned>(&self, path: &str) -> T {
        let response = self
            .client
            .delete(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("send DELETE");
        Self::decode_success(response).await
    }

    pub(super) async fn delete_raw(&self, path: &str) -> (StatusCode, String) {
        let response = self
            .client
            .delete(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("send raw DELETE");
        let status = response.status();
        let body = response.text().await.expect("read raw DELETE body");
        (status, body)
    }

    pub(super) async fn get_raw(&self, path: &str) -> (StatusCode, String) {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .send()
            .await
            .expect("send raw GET");
        let status = response.status();
        let body = response.text().await.expect("read raw body");
        (status, body)
    }

    pub(super) fn scenario_dir(&self, scenario_id: &str) -> PathBuf {
        self.data_dir.join("scenarios").join(scenario_id)
    }

    pub(super) fn revision_dir(&self, scenario_id: &str, revision: i64) -> PathBuf {
        self.scenario_dir(scenario_id)
            .join("revisions")
            .join(revision.to_string())
    }

    pub(super) fn runtime_dir(&self, scenario_id: &str, revision: i64) -> PathBuf {
        self.revision_dir(scenario_id, revision).join("runtime")
    }

    pub(super) fn bundle_dir(&self, scenario_id: &str, revision: i64) -> PathBuf {
        self.revision_dir(scenario_id, revision).join("bundle")
    }

    pub(super) fn read_runtime_env(&self, scenario_id: &str, revision: i64) -> String {
        std::fs::read_to_string(self.runtime_dir(scenario_id, revision).join(".env"))
            .expect("read runtime env")
    }

    pub(super) async fn set_scenario_states_for_test(
        &self,
        scenario_id: &str,
        desired_state: DesiredState,
        observed_state: ObservedState,
    ) {
        self._state
            .store()
            .set_scenario_states(scenario_id, desired_state, observed_state, None, 1_000)
            .await
            .expect("set scenario states for test");
    }

    async fn decode_success<T: DeserializeOwned>(response: reqwest::Response) -> T {
        let status = response.status();
        let body = response.text().await.expect("read response body");
        assert!(status.is_success(), "unexpected status {status}: {body}");
        serde_json::from_str(&body).expect("decode success body")
    }
}

impl Drop for TestHarness {
    fn drop(&mut self) {
        for handle in &self.task_handles {
            handle.abort();
        }
    }
}

pub(super) fn operator_service_config() -> ManagerFileConfig {
    let mut config = ManagerFileConfig::default();
    config.bindable_services.insert(
        "bootstrap".to_string(),
        OperatorBindableServiceConfig {
            protocol: ServiceProtocol::Http,
            provider: OperatorServiceProvider::DirectUrl {
                url: Url::parse("http://127.0.0.1:9000").expect("operator service URL"),
            },
        },
    );
    config
}

pub(super) fn create_request(source_url: String) -> CreateScenarioRequest {
    CreateScenarioRequest {
        source_url,
        root_config: json!({}),
        external_root_config: BTreeMap::new(),
        external_slots: BTreeMap::new(),
        exports: BTreeMap::new(),
        metadata: json!({}),
        telemetry: ScenarioTelemetryRequest::default(),
        store_bundle: false,
        start: true,
    }
}

pub(super) fn create_request_with_slot(
    source_url: String,
    slot_name: &str,
    bindable_service_id: String,
) -> CreateScenarioRequest {
    CreateScenarioRequest {
        source_url,
        root_config: json!({}),
        external_root_config: BTreeMap::new(),
        external_slots: slot_bindings(slot_name, &bindable_service_id),
        exports: BTreeMap::new(),
        metadata: json!({}),
        telemetry: ScenarioTelemetryRequest::default(),
        store_bundle: false,
        start: true,
    }
}

pub(super) fn slot_bindings(
    slot_name: &str,
    bindable_service_id: &str,
) -> BTreeMap<String, ExternalSlotBindingRequest> {
    BTreeMap::from([(
        slot_name.to_string(),
        ExternalSlotBindingRequest {
            bindable_service_id: bindable_service_id.to_string(),
        },
    )])
}

fn manager_config(data_dir: &Path, base_backoff_ms: u64) -> ManagerConfig {
    ManagerConfig::parse_from([
        "amber-manager".to_string(),
        "--listen".to_string(),
        "127.0.0.1:0".to_string(),
        "--data-dir".to_string(),
        data_dir
            .to_str()
            .expect("manager data dir should be valid UTF-8")
            .to_string(),
        "--max-restart-attempts".to_string(),
        "3".to_string(),
        "--base-backoff-ms".to_string(),
        base_backoff_ms.to_string(),
    ])
}

fn file_url(path: &Path) -> String {
    Url::from_file_path(path)
        .expect("convert file path to URL")
        .to_string()
}
