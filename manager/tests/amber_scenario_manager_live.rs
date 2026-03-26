use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use amber_images::{AMBER_HELPER, AMBER_PROVISIONER, AMBER_ROUTER};
use axum::{
    Json, Router,
    extract::State,
    routing::{get, post},
    serve,
};
use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::{
    net::TcpListener as TokioTcpListener,
    sync::{Mutex, Notify},
    task::JoinHandle,
    time::sleep,
};
use url::Url;

const MANAGER_SERVICE_NAME: &str = "amber-scenario-manager";
const ORCHESTRATOR_SERVICE_NAME: &str = "amber-test-orchestrator";
const PROVIDER_V1: &str = "provider-v1";
const PROVIDER_V2: &str = "provider-v2";

#[derive(Clone, Debug, Deserialize)]
struct CheckpointPayload {
    name: String,
    #[serde(default)]
    provider_id: Option<String>,
    #[serde(default)]
    consumer_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct FailurePayload {
    error: String,
}

#[derive(Debug, Deserialize)]
struct WaitReleasePayload {
    name: String,
}

#[derive(Default)]
struct CheckpointGate {
    payload: Mutex<Option<CheckpointPayload>>,
    arrived: Notify,
    released: Mutex<bool>,
}

#[derive(Default)]
struct OrchestratorState {
    checkpoints: Mutex<BTreeMap<String, Arc<CheckpointGate>>>,
    failure: Mutex<Option<String>>,
    failure_notify: Notify,
}

impl OrchestratorState {
    async fn checkpoint(&self, name: &str) -> Arc<CheckpointGate> {
        let mut checkpoints = self.checkpoints.lock().await;
        checkpoints
            .entry(name.to_string())
            .or_insert_with(|| Arc::new(CheckpointGate::default()))
            .clone()
    }

    async fn release(&self, name: &str) {
        let gate = self.checkpoint(name).await;
        *gate.released.lock().await = true;
    }

    async fn failure(&self) -> Option<String> {
        self.failure.lock().await.clone()
    }
}

struct OrchestratorServer {
    addr: SocketAddr,
    state: Arc<OrchestratorState>,
    _task: JoinHandle<()>,
}

impl OrchestratorServer {
    async fn spawn() -> Self {
        let state = Arc::new(OrchestratorState::default());
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind orchestrator listener");
        let addr = listener.local_addr().expect("orchestrator listener addr");
        let app = Router::new()
            .route("/healthz", get(orchestrator_healthz))
            .route("/checkpoint", post(orchestrator_checkpoint))
            .route("/release-status", post(orchestrator_release_status))
            .route("/failure", post(orchestrator_failure))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            serve(listener, app)
                .await
                .expect("serve orchestrator callback API");
        });
        Self {
            addr,
            state,
            _task: task,
        }
    }

    async fn wait_for_checkpoint(
        &self,
        name: &str,
        client: &Client,
        manager: &mut ManagerProcess,
        manager_base_url: &str,
        controller_id: &str,
        timeout: Duration,
    ) -> CheckpointPayload {
        let gate = self.state.checkpoint(name).await;
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(payload) = gate.payload.lock().await.clone() {
                return payload;
            }
            if let Some(error) = self.state.failure().await {
                panic!(
                    "controller scenario reported failure while waiting for checkpoint \
                     {name}:\n{error}"
                );
            }

            manager.assert_alive("waiting for orchestrator checkpoint");
            let controller_detail = get_json(
                client,
                manager_base_url,
                &format!("/v1/scenarios/{controller_id}"),
            )
            .await;
            if controller_detail["observed_state"].as_str() == Some("failed") {
                let controller_failure = tokio::time::timeout(Duration::from_secs(2), async {
                    loop {
                        if let Some(failure) = self.state.failure().await {
                            break Some(failure);
                        }
                        self.state.failure_notify.notified().await;
                    }
                })
                .await
                .ok()
                .flatten();
                let compose_logs = controller_detail["compose_project"]
                    .as_str()
                    .map(compose_project_logs)
                    .unwrap_or_else(|| "controller compose logs unavailable".to_string());
                panic!(
                    "controller scenario failed while waiting for checkpoint {name}: \
                     {controller_detail:#?}\nreported failure:\n{controller_failure:#?}\ncompose \
                     logs:\n{compose_logs}"
                );
            }

            let remaining = deadline.saturating_duration_since(Instant::now());
            assert!(
                !remaining.is_zero(),
                "timed out waiting for controller checkpoint {name}; last controller detail: \
                 {controller_detail:#?}"
            );

            tokio::select! {
                _ = gate.arrived.notified() => {}
                _ = self.state.failure_notify.notified() => {}
                _ = sleep(remaining.min(Duration::from_millis(200))) => {}
            }
        }
    }

    async fn release(&self, name: &str) {
        self.state.release(name).await;
    }
}

async fn orchestrator_healthz() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn orchestrator_checkpoint(
    State(state): State<Arc<OrchestratorState>>,
    Json(payload): Json<CheckpointPayload>,
) -> Json<Value> {
    let gate = state.checkpoint(&payload.name).await;
    *gate.payload.lock().await = Some(payload);
    gate.arrived.notify_waiters();
    Json(json!({ "ok": true }))
}

async fn orchestrator_release_status(
    State(state): State<Arc<OrchestratorState>>,
    Json(payload): Json<WaitReleasePayload>,
) -> Json<Value> {
    let gate = state.checkpoint(&payload.name).await;
    Json(json!({ "released": *gate.released.lock().await }))
}

async fn orchestrator_failure(
    State(state): State<Arc<OrchestratorState>>,
    Json(payload): Json<FailurePayload>,
) -> Json<Value> {
    *state.failure.lock().await = Some(payload.error);
    state.failure_notify.notify_waiters();
    Json(json!({ "ok": true }))
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires docker + docker compose; run manually"]
async fn controller_scenario_manages_provider_consumer_lifecycle_over_manager_slot() {
    run_controller_scenario_manages_provider_consumer_lifecycle("rest").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "requires docker + docker compose; run manually"]
async fn controller_scenario_manages_provider_consumer_lifecycle_over_manager_slot_mcp() {
    run_controller_scenario_manages_provider_consumer_lifecycle("mcp").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn live_manager_can_remove_allowlist_entry_over_rest() {
    run_allowlist_remove_live_test("rest").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn live_manager_can_remove_allowlist_entry_over_mcp() {
    run_allowlist_remove_live_test("mcp").await;
}

async fn run_allowlist_remove_live_test(transport: &str) {
    let tempdir = tempfile::Builder::new()
        .prefix("amber-manager-allowlist-live-")
        .tempdir()
        .expect("create tempdir");

    let manager_port = pick_free_port();
    let manager_addr = SocketAddr::from(([127, 0, 0, 1], manager_port));
    let manager_base_url = format!("http://{manager_addr}");
    let manifests = write_test_manifests(tempdir.path());
    let config_path = write_manager_config_with_allowlist(
        tempdir.path(),
        std::slice::from_ref(&manifests.provider_manifest_url),
    );
    let data_dir = tempdir.path().join("manager-data");
    fs::create_dir_all(&data_dir).expect("create manager data dir");

    let mut manager = ManagerProcess::spawn(&data_dir, &config_path, manager_addr);
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build reqwest client");

    wait_for_manager_ready(&client, &mut manager, &manager_base_url).await;

    match transport {
        "rest" => {
            let created = post_json(
                &client,
                &manager_base_url,
                "/v1/scenarios",
                &provider_create_payload(&manifests.provider_manifest_url),
            )
            .await;
            let scenario_id = created["scenario_id"]
                .as_str()
                .expect("provider scenario_id")
                .to_string();
            let operation_id = created["operation_id"]
                .as_str()
                .expect("provider operation_id");
            wait_for_operation(&client, &mut manager, &manager_base_url, operation_id).await;

            let removed = post_json(
                &client,
                &manager_base_url,
                "/v1/manager/scenario-source-allowlist/remove",
                &json!({ "source_url": manifests.provider_manifest_url.clone() }),
            )
            .await;
            assert_eq!(removed["source_url"], manifests.provider_manifest_url);

            let detail = get_json(
                &client,
                &manager_base_url,
                &format!("/v1/scenarios/{scenario_id}"),
            )
            .await;
            assert_eq!(detail["active_revision"], 1);

            let response = client
                .post(format!("{manager_base_url}/v1/scenarios"))
                .json(&provider_create_payload(&manifests.provider_manifest_url))
                .send()
                .await
                .expect("send blocked REST create");
            let status = response.status();
            let body = response
                .text()
                .await
                .expect("read blocked REST create response");
            assert_eq!(status, StatusCode::BAD_REQUEST, "unexpected body: {body}");
            assert!(
                body.contains("scenario_source_allowlist"),
                "unexpected body: {body}"
            );
        }
        "mcp" => {
            let mut mcp = LiveMcpClient::connect(client.clone(), &manager_base_url).await;

            let created = mcp
                .call_tool(
                    "amber.v1.scenarios.create",
                    provider_create_payload(&manifests.provider_manifest_url),
                )
                .await;
            let scenario_id = created["scenario_id"]
                .as_str()
                .expect("provider scenario_id")
                .to_string();
            let operation_id = created["operation_id"]
                .as_str()
                .expect("provider operation_id")
                .to_string();
            let waited = mcp
                .call_tool(
                    "amber.v1.operations.wait",
                    json!({
                        "operation_id": operation_id,
                        "timeout_ms": 120000,
                        "poll_interval_ms": 200,
                    }),
                )
                .await;
            assert_eq!(waited["timed_out"], false);
            assert_eq!(waited["operation"]["status"], "succeeded");

            let removed = mcp
                .call_tool(
                    "amber.v1.manager.scenario_source_allowlist.remove",
                    json!({ "source_url": manifests.provider_manifest_url.clone() }),
                )
                .await;
            assert_eq!(removed["source_url"], manifests.provider_manifest_url);

            let detail = mcp
                .call_tool(
                    "amber.v1.scenarios.get",
                    json!({ "scenario_id": scenario_id }),
                )
                .await;
            assert_eq!(detail["active_revision"], 1);

            let error = mcp
                .call_tool_error(
                    "amber.v1.scenarios.create",
                    provider_create_payload(&manifests.provider_manifest_url),
                )
                .await;
            assert!(error.contains("scenario_source_allowlist"));
        }
        other => panic!("unsupported transport {other}"),
    }

    let status = manager.shutdown();
    assert!(
        status.success() || status.code().is_none(),
        "amber-manager did not terminate cleanly: {status}"
    );
}

async fn run_controller_scenario_manages_provider_consumer_lifecycle(manager_transport: &str) {
    build_required_internal_images();

    let tempdir = tempfile::Builder::new()
        .prefix("amber-scenario-manager-live-")
        .tempdir()
        .expect("create tempdir");

    let orchestrator = OrchestratorServer::spawn().await;
    let manager_port = pick_free_port();
    let consumer_port = pick_free_port();
    let manager_addr = SocketAddr::from(([127, 0, 0, 1], manager_port));
    let manager_base_url = format!("http://{manager_addr}");

    let manifests = write_test_manifests(tempdir.path());
    let config_path = write_manager_config(tempdir.path(), manager_addr, orchestrator.addr);
    let data_dir = tempdir.path().join("manager-data");
    fs::create_dir_all(&data_dir).expect("create manager data dir");

    let mut manager = ManagerProcess::spawn(&data_dir, &config_path, manager_addr);
    let client = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("build reqwest client");

    wait_for_manager_ready(&client, &mut manager, &manager_base_url).await;

    let manager_service_id = wait_for_bindable_service_id(
        &client,
        &mut manager,
        &manager_base_url,
        MANAGER_SERVICE_NAME,
    )
    .await;
    let orchestrator_service_id = wait_for_bindable_service_id(
        &client,
        &mut manager,
        &manager_base_url,
        ORCHESTRATOR_SERVICE_NAME,
    )
    .await;

    let created = post_json(
        &client,
        &manager_base_url,
        "/v1/scenarios",
        &json!({
            "source_url": manifests.controller_manifest_url,
            "root_config": {
                "provider_url": manifests.provider_manifest_url,
                "consumer_url": manifests.consumer_manifest_url,
                "consumer_publish_port": consumer_port,
                "manager_transport": manager_transport,
            },
            "external_slots": {
                "manager": {
                    "bindable_service_id": manager_service_id,
                },
                "orchestrator": {
                    "bindable_service_id": orchestrator_service_id,
                },
            },
            "exports": {},
            "metadata": {
                "role": "controller",
            },
            "telemetry": {},
            "store_bundle": false,
            "start": true,
        }),
    )
    .await;
    let controller_id = created["scenario_id"]
        .as_str()
        .expect("controller scenario_id")
        .to_string();
    let controller_create_op = created["operation_id"]
        .as_str()
        .expect("controller operation_id");
    wait_for_operation(
        &client,
        &mut manager,
        &manager_base_url,
        controller_create_op,
    )
    .await;

    let children_created = orchestrator
        .wait_for_checkpoint(
            "children_created",
            &client,
            &mut manager,
            &manager_base_url,
            &controller_id,
            Duration::from_secs(240),
        )
        .await;
    let provider_id = children_created
        .provider_id
        .as_deref()
        .expect("children_created provider_id")
        .to_string();
    let consumer_id = children_created
        .consumer_id
        .as_deref()
        .expect("children_created consumer_id")
        .to_string();

    let scenarios = get_json(&client, &manager_base_url, "/v1/scenarios").await;
    let scenarios = scenarios.as_array().expect("scenario list");
    assert_eq!(
        scenarios.len(),
        3,
        "expected controller + provider + consumer, got {scenarios:#?}"
    );

    let provider_detail = get_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{provider_id}"),
    )
    .await;
    assert_eq!(provider_detail["observed_state"], "running");
    assert_eq!(provider_detail["exports"]["api"]["available"], true);

    let consumer_detail = get_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{consumer_id}"),
    )
    .await;
    assert_eq!(consumer_detail["observed_state"], "running");
    assert_eq!(
        consumer_detail["external_slots"]["upstream"]["provider_scenario_id"],
        provider_id
    );

    wait_for_body(
        &client,
        &format!("http://127.0.0.1:{consumer_port}/value.txt"),
        PROVIDER_V1,
        Duration::from_secs(240),
    )
    .await;
    orchestrator.release("children_created").await;

    orchestrator
        .wait_for_checkpoint(
            "consumer_paused",
            &client,
            &mut manager,
            &manager_base_url,
            &controller_id,
            Duration::from_secs(120),
        )
        .await;
    let consumer_detail = get_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{consumer_id}"),
    )
    .await;
    assert_eq!(consumer_detail["observed_state"], "paused");
    let provider_detail = get_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{provider_id}"),
    )
    .await;
    assert_eq!(
        provider_detail["observed_state"], "running",
        "provider stopped when consumer paused: {provider_detail:#?}"
    );
    assert_eq!(provider_detail["exports"]["api"]["available"], true);
    orchestrator.release("consumer_paused").await;

    orchestrator
        .wait_for_checkpoint(
            "provider_paused",
            &client,
            &mut manager,
            &manager_base_url,
            &controller_id,
            Duration::from_secs(120),
        )
        .await;
    let provider_detail = get_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{provider_id}"),
    )
    .await;
    assert_eq!(provider_detail["observed_state"], "paused");
    orchestrator.release("provider_paused").await;

    orchestrator
        .wait_for_checkpoint(
            "provider_stack_resumed",
            &client,
            &mut manager,
            &manager_base_url,
            &controller_id,
            Duration::from_secs(120),
        )
        .await;
    let provider_detail = get_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{provider_id}"),
    )
    .await;
    assert_eq!(provider_detail["observed_state"], "running");
    let consumer_detail = get_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{consumer_id}"),
    )
    .await;
    assert_eq!(consumer_detail["observed_state"], "running");
    wait_for_body(
        &client,
        &format!("http://127.0.0.1:{consumer_port}/value.txt"),
        PROVIDER_V1,
        Duration::from_secs(120),
    )
    .await;
    orchestrator.release("provider_stack_resumed").await;

    orchestrator
        .wait_for_checkpoint(
            "provider_upgraded",
            &client,
            &mut manager,
            &manager_base_url,
            &controller_id,
            Duration::from_secs(120),
        )
        .await;
    let provider_detail = get_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{provider_id}"),
    )
    .await;
    assert_eq!(provider_detail["active_revision"], 2);
    wait_for_body(
        &client,
        &format!("http://127.0.0.1:{consumer_port}/value.txt"),
        PROVIDER_V2,
        Duration::from_secs(120),
    )
    .await;
    orchestrator.release("provider_upgraded").await;

    orchestrator
        .wait_for_checkpoint(
            "children_cleaned_up",
            &client,
            &mut manager,
            &manager_base_url,
            &controller_id,
            Duration::from_secs(120),
        )
        .await;

    let scenarios = get_json(&client, &manager_base_url, "/v1/scenarios").await;
    let scenarios = scenarios.as_array().expect("scenario list");
    assert_eq!(
        scenarios.len(),
        1,
        "unexpected scenarios after cleanup: {scenarios:#?}"
    );
    assert_eq!(scenarios[0]["scenario_id"], controller_id);

    assert_status(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{provider_id}"),
        StatusCode::NOT_FOUND,
    )
    .await;
    assert_status(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{consumer_id}"),
        StatusCode::NOT_FOUND,
    )
    .await;
    orchestrator.release("children_cleaned_up").await;

    let deleted = delete_json(
        &client,
        &manager_base_url,
        &format!("/v1/scenarios/{controller_id}"),
    )
    .await;
    let controller_delete_op = deleted["operation_id"]
        .as_str()
        .expect("controller delete operation_id");
    wait_for_operation(
        &client,
        &mut manager,
        &manager_base_url,
        controller_delete_op,
    )
    .await;

    let scenarios = get_json(&client, &manager_base_url, "/v1/scenarios").await;
    assert_eq!(
        scenarios.as_array().expect("scenario list").len(),
        0,
        "manager still had scenarios after controller delete: {scenarios:#?}"
    );
    assert_scenarios_dir_empty(&data_dir);

    let status = manager.shutdown();
    assert!(
        status.success() || status.code().is_none(),
        "amber-manager did not terminate cleanly: {status}"
    );
}

struct ManifestPaths {
    controller_manifest_url: String,
    provider_manifest_url: String,
    consumer_manifest_url: String,
}

fn write_test_manifests(root: &Path) -> ManifestPaths {
    let manifests_dir = root.join("manifests");
    fs::create_dir_all(&manifests_dir).expect("create manifests dir");

    let provider_manifest = manifests_dir.join("provider.json5");
    let provider_script = manifests_dir.join("provider.py");
    fs::write(&provider_script, provider_script_contents()).expect("write provider script");
    fs::write(&provider_manifest, provider_manifest_contents()).expect("write provider manifest");

    let consumer_manifest = manifests_dir.join("consumer.json5");
    let consumer_script = manifests_dir.join("consumer.py");
    fs::write(&consumer_script, consumer_script_contents()).expect("write consumer script");
    fs::write(&consumer_manifest, consumer_manifest_contents()).expect("write consumer manifest");

    let controller_manifest = manifests_dir.join("controller.json5");
    let controller_script = manifests_dir.join("controller.py");
    fs::write(&controller_script, controller_script_contents()).expect("write controller script");
    fs::write(&controller_manifest, controller_manifest_contents())
        .expect("write controller manifest");

    ManifestPaths {
        controller_manifest_url: file_url(&controller_manifest),
        provider_manifest_url: file_url(&provider_manifest),
        consumer_manifest_url: file_url(&consumer_manifest),
    }
}

fn write_manager_config(
    root: &Path,
    manager_addr: SocketAddr,
    orchestrator_addr: SocketAddr,
) -> PathBuf {
    let config_path = root.join("manager-config.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&json!({
            "bindable_services": {
                MANAGER_SERVICE_NAME: {
                    "protocol": "http",
                    "provider": {
                        "kind": "loopback_upstream",
                        "upstream": manager_addr.to_string(),
                    },
                },
                ORCHESTRATOR_SERVICE_NAME: {
                    "protocol": "http",
                    "provider": {
                        "kind": "loopback_upstream",
                        "upstream": orchestrator_addr.to_string(),
                    },
                },
            },
        }))
        .expect("serialize manager config"),
    )
    .expect("write manager config");
    config_path
}

fn write_manager_config_with_allowlist(root: &Path, allowlist: &[String]) -> PathBuf {
    let config_path = root.join("manager-config.json");
    fs::write(
        &config_path,
        serde_json::to_vec_pretty(&json!({
            "bindable_services": {},
            "bindable_configs": {},
            "scenario_source_allowlist": allowlist,
        }))
        .expect("serialize manager config"),
    )
    .expect("write manager config");
    config_path
}

fn provider_create_payload(source_url: &str) -> Value {
    json!({
        "source_url": source_url,
        "root_config": {
            "value": PROVIDER_V1,
        },
        "external_slots": {},
        "exports": {},
        "metadata": {
            "role": "provider",
        },
        "telemetry": {},
        "store_bundle": false,
        "start": false,
    })
}

fn provider_manifest_contents() -> &'static str {
    r#"{
  manifest_version: "0.1.0",
  experimental_features: ["docker"],
  config_schema: {
    type: "object",
    properties: {
      value: { type: "string" },
    },
    required: ["value"],
    additionalProperties: false,
  },
  program: {
    image: "python:3.12-alpine",
    entrypoint: [
      "python3",
      "-u",
      "-c",
      { file: "./provider.py" },
    ],
    env: {
      VALUE: "${config.value}",
    },
    network: {
      endpoints: [
        { name: "api", port: 8080, protocol: "http" },
      ],
    },
  },
  provides: {
    api: { kind: "http", endpoint: "api" },
  },
  exports: {
    api: "api",
  },
}
"#
}

fn provider_script_contents() -> &'static str {
    r#"import http.server
import os

VALUE = os.environ["VALUE"].encode("utf-8")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/value.txt":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(VALUE)))
        self.end_headers()
        self.wfile.write(VALUE)

    def log_message(self, *_args):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"#
}

fn consumer_manifest_contents() -> &'static str {
    r#"{
  manifest_version: "0.1.0",
  experimental_features: ["docker"],
  program: {
    image: "python:3.12-alpine",
    entrypoint: [
      "python3",
      "-u",
      "-c",
      { file: "./consumer.py" },
    ],
    env: {
      UPSTREAM_URL: "${slots.upstream.url}",
    },
    network: {
      endpoints: [
        { name: "api", port: 8080, protocol: "http" },
      ],
    },
  },
  slots: {
    upstream: { kind: "http" },
  },
  provides: {
    api: { kind: "http", endpoint: "api" },
  },
  exports: {
    api: "api",
  },
}
"#
}

fn consumer_script_contents() -> &'static str {
    r#"import http.server
import os
import urllib.error
import urllib.request

UPSTREAM_URL = os.environ["UPSTREAM_URL"].rstrip("/")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path != "/value.txt":
            self.send_error(404)
            return
        try:
            with urllib.request.urlopen(f"{UPSTREAM_URL}/value.txt", timeout=5) as response:
                body = response.read()
        except Exception as exc:
            payload = f"upstream request failed: {exc}\n".encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
"#
}

fn controller_manifest_contents() -> &'static str {
    r#"{
  manifest_version: "0.1.0",
  experimental_features: ["docker"],
  config_schema: {
    type: "object",
    properties: {
      provider_url: { type: "string" },
      consumer_url: { type: "string" },
      consumer_publish_port: { type: "integer" },
      manager_transport: { type: "string", enum: ["rest", "mcp"] },
    },
    required: ["provider_url", "consumer_url", "consumer_publish_port", "manager_transport"],
    additionalProperties: false,
  },
  program: {
    image: "python:3.12-alpine",
    entrypoint: [
      "python3",
      "-u",
      "-c",
      { file: "./controller.py" },
    ],
    env: {
      MANAGER_URL: "${slots.manager.url}",
      ORCHESTRATOR_URL: "${slots.orchestrator.url}",
      PROVIDER_URL: "${config.provider_url}",
      CONSUMER_URL: "${config.consumer_url}",
      CONSUMER_PUBLISH_PORT: "${config.consumer_publish_port}",
      MANAGER_TRANSPORT: "${config.manager_transport}",
    },
  },
  slots: {
    manager: { kind: "http" },
    orchestrator: { kind: "http" },
  },
}
"#
}

fn controller_script_contents() -> &'static str {
    r#"import json
import os
import threading
import time
import traceback
import urllib.error
import urllib.request

MANAGER_URL = os.environ["MANAGER_URL"].rstrip("/")
ORCHESTRATOR_URL = os.environ["ORCHESTRATOR_URL"].rstrip("/")
PROVIDER_URL = os.environ["PROVIDER_URL"]
CONSUMER_URL = os.environ["CONSUMER_URL"]
CONSUMER_PUBLISH_PORT = int(os.environ["CONSUMER_PUBLISH_PORT"])
MANAGER_TRANSPORT = os.environ["MANAGER_TRANSPORT"]
PROVIDER_V1 = "provider-v1"
PROVIDER_V2 = "provider-v2"


def json_request(base_url, method, path, body=None, timeout=30):
    url = base_url + path
    headers = {}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif method in ("POST", "PUT", "PATCH"):
        data = b""
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed with {exc.code}: {detail}") from exc
    except Exception as exc:
        raise RuntimeError(f"{method} {path} failed: {exc}") from exc
    if not raw:
        return None
    return json.loads(raw.decode("utf-8"))


def manager_request(method, path, body=None):
    return json_request(MANAGER_URL, method, path, body)


def sse_json_rpc_message(raw):
    body = raw.decode("utf-8").replace("\r\n", "\n")
    payloads = []
    for event in body.split("\n\n"):
        data_lines = []
        for line in event.splitlines():
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        payload = "\n".join(data_lines)
        if payload:
            payloads.append(payload)
    if not payloads:
        raise RuntimeError(f"SSE response did not contain JSON-RPC data: {body}")
    return json.loads(payloads[-1])


class McpManagerClient:
    def __init__(self, base_url):
        self.endpoint = base_url + "/mcp"
        self.session_id = None
        self.request_id = 1
        self.initialize()

    def _post(self, payload, *, include_session, timeout=30):
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if include_session:
            headers["mcp-session-id"] = self.session_id
        request = urllib.request.Request(
            self.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.status, response.headers, response.read()
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"MCP POST {payload.get('method')} failed with {exc.code}: {detail}"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"MCP POST {payload.get('method')} failed: {exc}") from exc

    def initialize(self):
        status, headers, raw = self._post(
            {
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "amber-controller-live-test",
                        "version": "0.0.0",
                    },
                },
            },
            include_session=False,
        )
        if status != 200:
            raise RuntimeError(f"MCP initialize returned unexpected status {status}")
        self.session_id = headers.get("mcp-session-id")
        if not self.session_id:
            raise RuntimeError("MCP initialize response did not include mcp-session-id")
        message = sse_json_rpc_message(raw)
        if message.get("error") is not None:
            raise RuntimeError(f"MCP initialize returned error: {message}")
        status, _, _ = self._post(
            {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            },
            include_session=True,
        )
        if status != 202:
            raise RuntimeError(
                f"notifications/initialized returned unexpected status {status}"
            )

    def request(self, method, params=None, timeout=30):
        request_id = self.request_id
        self.request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": {} if params is None else params,
        }
        status, _, raw = self._post(payload, include_session=True, timeout=timeout)
        if status != 200:
            raise RuntimeError(f"MCP request {method} returned unexpected status {status}")
        message = sse_json_rpc_message(raw)
        if message.get("id") != request_id:
            raise RuntimeError(
                f"MCP request {method} returned unexpected id {message.get('id')}"
            )
        if message.get("error") is not None:
            raise RuntimeError(f"MCP request {method} failed: {message['error']}")
        return message["result"]

    def call_tool(self, name, arguments=None, timeout=30):
        result = self.request(
            "tools/call",
            {
                "name": name,
                "arguments": {} if arguments is None else arguments,
            },
            timeout=timeout,
        )
        if result.get("isError") is True:
            raise RuntimeError(f"MCP tool {name} returned isError: {result}")
        return result["structuredContent"]


MCP_MANAGER = None


def orchestrator_request(method, path, body=None, timeout=240):
    return json_request(ORCHESTRATOR_URL, method, path, body, timeout=timeout)


def wait_for_json_ready(name, request_fn, path, field):
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            response = request_fn("GET", path)
        except Exception:
            time.sleep(0.2)
            continue
        if response.get(field) is True:
            return
        time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for {name} readiness")


def wait_for_mcp_manager_ready():
    deadline = time.time() + 120
    while time.time() < deadline:
        try:
            response = MCP_MANAGER.call_tool("amber.v1.manager.ready.get", {})
        except Exception:
            time.sleep(0.2)
            continue
        if response.get("ready") is True:
            return
        time.sleep(0.2)
    raise RuntimeError("timed out waiting for manager MCP readiness")


def wait_for_operation(operation_id):
    if MANAGER_TRANSPORT == "mcp":
        result = MCP_MANAGER.call_tool(
            "amber.v1.operations.wait",
            {
                "operation_id": operation_id,
                "timeout_ms": 120000,
                "poll_interval_ms": 200,
            },
            timeout=150,
        )
        if result.get("timed_out") is True:
            raise RuntimeError(f"timed out waiting for operation {operation_id}")
        operation = result["operation"]
        if operation["status"] == "failed":
            raise RuntimeError(
                f"operation {operation_id} failed: {operation.get('last_error') or operation}"
            )
        return operation

    deadline = time.time() + 120
    while time.time() < deadline:
        operation = manager_request("GET", f"/v1/operations/{operation_id}")
        status = operation["status"]
        if status == "succeeded":
            return operation
        if status == "failed":
            raise RuntimeError(
                f"operation {operation_id} failed: {operation.get('last_error') or operation}"
            )
        time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for operation {operation_id}")


def manager_create_scenario(payload):
    if MANAGER_TRANSPORT == "rest":
        return manager_request("POST", "/v1/scenarios", payload)
    return MCP_MANAGER.call_tool("amber.v1.scenarios.create", payload)


def manager_get_scenario(scenario_id):
    if MANAGER_TRANSPORT == "rest":
        return manager_request("GET", f"/v1/scenarios/{scenario_id}")
    return MCP_MANAGER.call_tool(
        "amber.v1.scenarios.get",
        {"scenario_id": scenario_id},
    )


def manager_pause_scenario(scenario_id):
    if MANAGER_TRANSPORT == "rest":
        response = manager_request("POST", f"/v1/scenarios/{scenario_id}/pause")
    else:
        response = MCP_MANAGER.call_tool(
            "amber.v1.scenarios.pause",
            {"scenario_id": scenario_id},
        )
    return wait_for_operation(response["operation_id"])


def manager_resume_scenario(scenario_id):
    if MANAGER_TRANSPORT == "rest":
        response = manager_request("POST", f"/v1/scenarios/{scenario_id}/resume")
    else:
        response = MCP_MANAGER.call_tool(
            "amber.v1.scenarios.resume",
            {"scenario_id": scenario_id},
        )
    return wait_for_operation(response["operation_id"])


def manager_upgrade_scenario(scenario_id, payload):
    if MANAGER_TRANSPORT == "rest":
        response = manager_request("POST", f"/v1/scenarios/{scenario_id}/upgrade", payload)
    else:
        request = dict(payload)
        request["scenario_id"] = scenario_id
        response = MCP_MANAGER.call_tool("amber.v1.scenarios.upgrade", request)
    return wait_for_operation(response["operation_id"])


def manager_delete_scenario(scenario_id):
    if MANAGER_TRANSPORT == "rest":
        response = manager_request("DELETE", f"/v1/scenarios/{scenario_id}")
    else:
        response = MCP_MANAGER.call_tool(
            "amber.v1.scenarios.delete",
            {"scenario_id": scenario_id},
        )
    return wait_for_operation(response["operation_id"])


def report_checkpoint(name, **extra):
    payload = {"name": name}
    payload.update(extra)
    orchestrator_request("POST", "/checkpoint", payload)
    deadline = time.time() + 240
    while time.time() < deadline:
        status = orchestrator_request("POST", "/release-status", {"name": name})
        if status["released"] is True:
            return
        time.sleep(0.2)
    raise RuntimeError(f"timed out waiting for orchestrator release {name}")


def report_failure(error):
    try:
        orchestrator_request("POST", "/failure", {"error": error})
    except Exception:
        pass


def run_controller():
    global MCP_MANAGER

    if MANAGER_TRANSPORT not in ("rest", "mcp"):
        raise RuntimeError(f"unsupported manager transport: {MANAGER_TRANSPORT}")

    wait_for_json_ready("manager slot", manager_request, "/readyz", "ready")
    wait_for_json_ready("orchestrator slot", orchestrator_request, "/healthz", "ok")

    if MANAGER_TRANSPORT == "mcp":
        MCP_MANAGER = McpManagerClient(MANAGER_URL)
        wait_for_mcp_manager_ready()

    provider = manager_create_scenario(
        {
            "source_url": PROVIDER_URL,
            "root_config": {"value": PROVIDER_V1},
            "external_slots": {},
            "exports": {},
            "metadata": {"role": "provider"},
            "telemetry": {},
            "store_bundle": False,
            "start": True,
        },
    )
    wait_for_operation(provider["operation_id"])
    provider_id = provider["scenario_id"]

    provider_detail = manager_get_scenario(provider_id)
    provider_service = provider_detail["exports"]["api"]["bindable_service_id"]

    consumer = manager_create_scenario(
        {
            "source_url": CONSUMER_URL,
            "root_config": {},
            "external_slots": {
                "upstream": {
                    "bindable_service_id": provider_service,
                },
            },
            "exports": {
                "api": {
                    "publish": {
                        "listen": f"127.0.0.1:{CONSUMER_PUBLISH_PORT}",
                    },
                },
            },
            "metadata": {"role": "consumer"},
            "telemetry": {},
            "store_bundle": False,
            "start": True,
        },
    )
    wait_for_operation(consumer["operation_id"])
    consumer_id = consumer["scenario_id"]
    report_checkpoint(
        "children_created", provider_id=provider_id, consumer_id=consumer_id
    )

    manager_pause_scenario(consumer_id)
    report_checkpoint("consumer_paused", provider_id=provider_id, consumer_id=consumer_id)

    manager_pause_scenario(provider_id)
    report_checkpoint("provider_paused", provider_id=provider_id, consumer_id=consumer_id)

    manager_resume_scenario(provider_id)
    manager_resume_scenario(consumer_id)
    report_checkpoint(
        "provider_stack_resumed", provider_id=provider_id, consumer_id=consumer_id
    )

    manager_upgrade_scenario(
        provider_id,
        {
            "root_config": {"value": PROVIDER_V2},
            "store_bundle": False,
        },
    )
    report_checkpoint("provider_upgraded", provider_id=provider_id, consumer_id=consumer_id)

    manager_delete_scenario(consumer_id)
    manager_delete_scenario(provider_id)
    report_checkpoint(
        "children_cleaned_up", provider_id=provider_id, consumer_id=consumer_id
    )

    threading.Event().wait()


def main():
    try:
        run_controller()
    except Exception:
        report_failure(traceback.format_exc())
        raise


main()
"#
}

struct ManagerProcess {
    child: Option<Child>,
}

impl ManagerProcess {
    fn spawn(data_dir: &Path, config_path: &Path, listen_addr: SocketAddr) -> Self {
        let child = Command::new(env!("CARGO_BIN_EXE_amber-manager"))
            .arg("--listen")
            .arg(listen_addr.to_string())
            .arg("--data-dir")
            .arg(data_dir)
            .arg("--config")
            .arg(config_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn amber-manager");
        Self { child: Some(child) }
    }

    fn assert_alive(&mut self, context: &str) {
        let Some(child) = self.child.as_mut() else {
            panic!("amber-manager process already shut down while {context}");
        };
        if let Some(status) = child.try_wait().expect("poll amber-manager") {
            let (stdout, stderr) = drain_pipes(child);
            panic!(
                "amber-manager exited while {context}\nstatus: \
                 {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
            );
        }
    }

    fn shutdown(&mut self) -> ExitStatus {
        let Some(mut child) = self.child.take() else {
            panic!("amber-manager process already shut down");
        };
        if let Some(status) = child.try_wait().expect("poll amber-manager") {
            return status;
        }
        signal_int(&child);
        let deadline = Instant::now() + Duration::from_secs(10);
        while Instant::now() < deadline {
            if let Some(status) = child.try_wait().expect("poll amber-manager after SIGINT") {
                return status;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let _ = child.kill();
        let status = child
            .wait()
            .expect("wait for amber-manager after forced kill");
        let (stdout, stderr) = drain_pipes(&mut child);
        panic!(
            "amber-manager did not exit after SIGINT\nstatus: \
             {status}\nstdout:\n{stdout}\nstderr:\n{stderr}"
        );
    }
}

impl Drop for ManagerProcess {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

struct LiveMcpClient {
    client: Client,
    endpoint: String,
    session_id: String,
    next_id: u64,
}

impl LiveMcpClient {
    async fn connect(client: Client, base_url: &str) -> Self {
        let endpoint = format!("{base_url}/mcp");
        let response = client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&json!({
                "jsonrpc": "2.0",
                "id": 0,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {
                        "name": "amber-manager-live-test",
                        "version": "0.0.0",
                    },
                },
            }))
            .send()
            .await
            .expect("send MCP initialize");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.expect("read MCP initialize body");
        assert_eq!(status, StatusCode::OK, "initialize failed: {body}");

        let session_id = headers
            .get("mcp-session-id")
            .expect("MCP initialize should return session ID")
            .to_str()
            .expect("MCP session ID should be valid UTF-8")
            .to_string();
        let payload = sse_json_rpc_message(&body);
        assert!(
            payload.get("error").is_none(),
            "initialize returned error: {payload:#?}"
        );

        let initialized = client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &session_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
            }))
            .send()
            .await
            .expect("send MCP initialized notification");
        assert_eq!(initialized.status(), StatusCode::ACCEPTED);

        Self {
            client,
            endpoint,
            session_id,
            next_id: 1,
        }
    }

    async fn call_tool(&mut self, name: &str, arguments: Value) -> Value {
        let result = self
            .request(
                "tools/call",
                json!({
                    "name": name,
                    "arguments": arguments,
                }),
            )
            .await;
        assert_ne!(
            result.get("isError").and_then(Value::as_bool),
            Some(true),
            "tool {name} returned isError: {result:#?}"
        );
        result
            .get("structuredContent")
            .cloned()
            .expect("tool result should include structuredContent")
    }

    async fn call_tool_error(&mut self, name: &str, arguments: Value) -> String {
        let id = self.next_id;
        self.next_id += 1;
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &self.session_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": "tools/call",
                "params": {
                    "name": name,
                    "arguments": arguments,
                },
            }))
            .send()
            .await
            .expect("send MCP tool error request");
        let status = response.status();
        let body = response.text().await.expect("read MCP tool error response");
        assert_eq!(status, StatusCode::OK, "MCP request failed: {body}");
        let payload = sse_json_rpc_message(&body);
        assert_eq!(payload["id"].as_u64(), Some(id));
        if let Some(message) = payload
            .get("error")
            .and_then(|error| error.get("message"))
            .and_then(Value::as_str)
        {
            return message.to_string();
        }

        let result = payload
            .get("result")
            .cloned()
            .expect("MCP error response should contain result or error");
        assert_eq!(
            result.get("isError").and_then(Value::as_bool),
            Some(true),
            "tool {name} unexpectedly succeeded: {result:#?}"
        );
        result
            .get("content")
            .and_then(Value::as_array)
            .and_then(|content| content.first())
            .and_then(|item| item.get("text"))
            .and_then(Value::as_str)
            .expect("tool error should include text content")
            .to_string()
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let response = self
            .client
            .post(&self.endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .header("mcp-session-id", &self.session_id)
            .json(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "method": method,
                "params": params,
            }))
            .send()
            .await
            .expect("send MCP request");
        let status = response.status();
        let body = response.text().await.expect("read MCP response");
        assert_eq!(status, StatusCode::OK, "MCP request failed: {body}");
        let payload = sse_json_rpc_message(&body);
        assert_eq!(payload["id"].as_u64(), Some(id));
        assert!(
            payload.get("error").is_none(),
            "MCP request returned error: {payload:#?}"
        );
        payload
            .get("result")
            .cloned()
            .expect("MCP response should contain result")
    }
}

fn drain_pipes(child: &mut Child) -> (String, String) {
    let mut stdout = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    (stdout, stderr)
}

fn sse_json_rpc_message(body: &str) -> Value {
    let normalized = body.replace("\r\n", "\n");
    let payload = normalized
        .split("\n\n")
        .filter_map(|event| {
            let data = event
                .lines()
                .filter_map(|line| line.strip_prefix("data:"))
                .map(str::trim_start)
                .collect::<Vec<_>>()
                .join("\n");
            (!data.is_empty()).then_some(data)
        })
        .last()
        .unwrap_or_else(|| panic!("SSE response did not contain JSON-RPC data: {body}"));
    serde_json::from_str(&payload)
        .unwrap_or_else(|err| panic!("parse JSON-RPC payload from SSE: {err}; {payload}"))
}

fn compose_project_logs(project: &str) -> String {
    let output = Command::new("docker")
        .arg("compose")
        .arg("-p")
        .arg(project)
        .arg("logs")
        .arg("--no-color")
        .output();
    match output {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if output.status.success() {
                stdout.into_owned()
            } else {
                format!(
                    "docker compose logs failed with \
                     {status}\nstdout:\n{stdout}\nstderr:\n{stderr}",
                    status = output.status
                )
            }
        }
        Err(err) => format!("failed to run docker compose logs: {err}"),
    }
}

async fn wait_for_manager_ready(client: &Client, manager: &mut ManagerProcess, base_url: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        manager.assert_alive("waiting for readiness");
        if let Ok(response) = client.get(format!("{base_url}/readyz")).send().await
            && response.status() == StatusCode::OK
        {
            return;
        }
        sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for amber-manager readiness");
}

async fn wait_for_bindable_service_id(
    client: &Client,
    manager: &mut ManagerProcess,
    base_url: &str,
    display_name: &str,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        manager.assert_alive("waiting for bindable service");
        if let Ok(response) = client
            .get(format!("{base_url}/v1/bindable-services"))
            .send()
            .await
            && response.status().is_success()
        {
            let services = response
                .json::<Value>()
                .await
                .expect("decode bindable services");
            if let Some(bindable_service_id) = services.as_array().and_then(|services| {
                services.iter().find_map(|service| {
                    (service["display_name"].as_str() == Some(display_name))
                        .then(|| service["bindable_service_id"].as_str().map(str::to_string))
                        .flatten()
                })
            }) {
                return bindable_service_id;
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for manager bindable service {display_name}");
}

async fn wait_for_body(client: &Client, url: &str, expected: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    let mut last_body = None;
    while Instant::now() < deadline {
        if let Ok(response) = client.get(url).send().await
            && response.status().is_success()
        {
            let body = response.text().await.expect("read body");
            if body.trim() == expected {
                return;
            }
            last_body = Some(body);
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!(
        "timed out waiting for body {expected} from {url}; last body: {}",
        last_body.unwrap_or_else(|| "<none>".to_string())
    );
}

async fn wait_for_operation(
    client: &Client,
    manager: &mut ManagerProcess,
    base_url: &str,
    operation_id: &str,
) -> Value {
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        manager.assert_alive("waiting for operation completion");
        let operation = get_json(client, base_url, &format!("/v1/operations/{operation_id}")).await;
        match operation["status"].as_str() {
            Some("queued") | Some("running") => {}
            Some("succeeded") => return operation,
            Some("failed") => panic!(
                "operation {operation_id} failed: {}",
                operation["last_error"].as_str().unwrap_or("unknown error")
            ),
            other => panic!("unexpected operation status for {operation_id}: {other:?}"),
        }
        sleep(Duration::from_millis(200)).await;
    }
    panic!("timed out waiting for operation {operation_id}");
}

async fn get_json(client: &Client, base_url: &str, path: &str) -> Value {
    let response = client
        .get(format!("{base_url}{path}"))
        .send()
        .await
        .expect("send GET request");
    decode_success(response).await
}

async fn post_json(client: &Client, base_url: &str, path: &str, body: &Value) -> Value {
    let response = client
        .post(format!("{base_url}{path}"))
        .json(body)
        .send()
        .await
        .expect("send POST request");
    decode_success(response).await
}

async fn delete_json(client: &Client, base_url: &str, path: &str) -> Value {
    let response = client
        .delete(format!("{base_url}{path}"))
        .send()
        .await
        .expect("send DELETE request");
    decode_success(response).await
}

async fn assert_status(client: &Client, base_url: &str, path: &str, expected: StatusCode) {
    let response = client
        .get(format!("{base_url}{path}"))
        .send()
        .await
        .expect("send raw GET request");
    let status = response.status();
    let body = response.text().await.expect("read raw body");
    assert_eq!(status, expected, "unexpected body for {path}: {body}");
}

async fn decode_success(response: reqwest::Response) -> Value {
    let status = response.status();
    let body = response.text().await.expect("read response body");
    assert!(status.is_success(), "unexpected status {status}: {body}");
    serde_json::from_str(&body).expect("decode JSON response")
}

fn build_required_internal_images() {
    let root = workspace_root();
    build_internal_image(
        AMBER_HELPER.reference,
        &root.join("docker/amber-helper/Dockerfile"),
        &root,
    );
    build_internal_image(
        AMBER_ROUTER.reference,
        &root.join("docker/amber-router/Dockerfile"),
        &root,
    );
    build_internal_image(
        AMBER_PROVISIONER.reference,
        &root.join("docker/amber-provisioner/Dockerfile"),
        &root,
    );
}

fn build_internal_image(tag: &str, dockerfile: &Path, context: &Path) {
    if use_prebuilt_images() {
        assert!(
            docker_image_exists(tag),
            "AMBER_TEST_USE_PREBUILT_IMAGES is set but {tag} is not available locally"
        );
        return;
    }

    let status = Command::new("docker")
        .arg("buildx")
        .arg("build")
        .arg("--load")
        .arg("-t")
        .arg(tag)
        .arg("-f")
        .arg(dockerfile)
        .arg(context)
        .status()
        .expect("start docker build");
    assert!(status.success(), "docker build failed for {tag}");
}

fn docker_image_exists(tag: &str) -> bool {
    Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg(tag)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn use_prebuilt_images() -> bool {
    std::env::var_os("AMBER_TEST_USE_PREBUILT_IMAGES").is_some()
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("manager crate should live under the workspace root")
        .to_path_buf()
}

fn assert_scenarios_dir_empty(data_dir: &Path) {
    let scenarios_dir = data_dir.join("scenarios");
    if !scenarios_dir.exists() {
        return;
    }
    let mut entries = fs::read_dir(&scenarios_dir)
        .expect("read scenarios dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect scenario dir entries");
    entries.retain(|entry| {
        entry
            .file_name()
            .to_str()
            .is_some_and(|name| !name.starts_with('.'))
    });
    assert!(
        entries.is_empty(),
        "scenario state directory still had entries: {:?}",
        entries
            .into_iter()
            .map(|entry| entry.file_name())
            .collect::<Vec<_>>()
    );
}

fn file_url(path: &Path) -> String {
    Url::from_file_path(path)
        .expect("convert file path to URL")
        .to_string()
}

fn pick_free_port() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).expect("bind port");
    listener.local_addr().expect("local addr").port()
}

fn signal_int(child: &Child) {
    #[cfg(unix)]
    {
        let Ok(pid) = i32::try_from(child.id()) else {
            return;
        };
        let _ = unsafe { libc::kill(pid, libc::SIGINT) };
    }

    #[cfg(not(unix))]
    {
        let _ = child.id();
    }
}
