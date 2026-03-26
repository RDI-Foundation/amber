use std::{
    collections::{BTreeMap, BTreeSet},
    net::TcpListener,
    time::{Duration, Instant},
};

use reqwest::{Client, StatusCode};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use tokio::time::sleep;

use super::harness::{
    TestHarness, create_request, create_request_with_slot, operator_service_config,
};
use crate::{
    config::ManagerFileConfig,
    domain::{
        BindableConfigResponse, BindableServiceResponse, CreateScenarioRequest,
        EnqueueOperationResponse, ExportPublishRequest, ExportRequest, ObservedState,
        OperationStatus, OperationStatusResponse, ScenarioDetailResponse,
        ScenarioSourceAllowlistEntryResponse, ServiceProtocol,
    },
    ids,
    mcp::{
        BindableConfigsListResponse, BindableServicesListResponse, ExportsListResponse,
        ScenarioRevisionsListResponse, ScenariosListResponse,
    },
    service::{
        ExportDetailResponse, ExportWaitResult, ManagerHealthResponse, ManagerReadyResponse,
        OperationWaitResult, ScenarioConfigSchemaResponse,
    },
};

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

struct McpClient {
    client: Client,
    endpoint: String,
    session_id: String,
    next_id: u64,
}

impl McpClient {
    async fn connect(base_url: &str) -> Self {
        let client = Client::new();
        let endpoint = format!("{base_url}/mcp");

        let initialize = json!({
            "jsonrpc": "2.0",
            "id": 0,
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {
                    "name": "amber-manager-e2e",
                    "version": "0.0.0",
                },
            },
        });
        let response = client
            .post(&endpoint)
            .header("content-type", "application/json")
            .header("accept", "application/json, text/event-stream")
            .json(&initialize)
            .send()
            .await
            .expect("send initialize request");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.text().await.expect("read initialize response");
        assert_eq!(status, StatusCode::OK, "initialize failed: {body}");
        let session_id = headers
            .get("mcp-session-id")
            .expect("initialize should return MCP session ID")
            .to_str()
            .expect("session ID should be valid UTF-8")
            .to_string();
        let payload = sse_json_rpc_message(&body);
        assert!(
            payload.get("error").is_none(),
            "initialize returned error: {payload:#?}"
        );
        assert_eq!(
            payload["result"]["protocolVersion"].as_str(),
            Some("2025-06-18")
        );

        let notification = client
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
            .expect("send initialized notification");
        assert_eq!(notification.status(), StatusCode::ACCEPTED);

        Self {
            client,
            endpoint,
            session_id,
            next_id: 1,
        }
    }

    async fn wait_until_ready(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let ready: ManagerReadyResponse = self
                .call_tool("amber.v1.manager.ready.get", json!({}))
                .await;
            if ready.ready {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "manager never reported ready over MCP"
            );
            sleep(Duration::from_millis(50)).await;
        }
    }

    async fn tools_list(&mut self) -> Vec<Value> {
        self.request("tools/list", json!({}))
            .await
            .get("tools")
            .and_then(Value::as_array)
            .cloned()
            .expect("tools/list should return tools array")
    }

    async fn resources_list(&mut self) -> Vec<Value> {
        self.request("resources/list", json!({}))
            .await
            .get("resources")
            .and_then(Value::as_array)
            .cloned()
            .expect("resources/list should return resources array")
    }

    async fn resource_templates_list(&mut self) -> Vec<Value> {
        self.request("resources/templates/list", json!({}))
            .await
            .get("resourceTemplates")
            .and_then(Value::as_array)
            .cloned()
            .expect("resources/templates/list should return resourceTemplates array")
    }

    async fn read_resource_text(&mut self, uri: &str) -> String {
        self.request("resources/read", json!({ "uri": uri }))
            .await
            .get("contents")
            .and_then(Value::as_array)
            .and_then(|contents| contents.first())
            .and_then(|content| content.get("text"))
            .and_then(Value::as_str)
            .expect("resources/read should return text content")
            .to_string()
    }

    async fn call_tool<T: DeserializeOwned>(&mut self, name: &str, arguments: Value) -> T {
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
        serde_json::from_value(
            result
                .get("structuredContent")
                .cloned()
                .expect("tool result should include structuredContent"),
        )
        .unwrap_or_else(|err| panic!("deserialize tool result for {name}: {err}; {result:#?}"))
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
            .unwrap_or_else(|err| panic!("send MCP tool error request {name}: {err}"));
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|err| panic!("read MCP tool error response for {name}: {err}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "MCP tool error request {name} failed with status {status}: {body}"
        );
        let payload = sse_json_rpc_message(&body);
        assert_eq!(payload["id"].as_u64(), Some(id));
        if let Some(error) = payload.get("error") {
            return error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or_else(|| {
                    panic!("MCP tool error response for {name} missing message: {payload:#?}")
                })
                .to_string();
        }

        let result = payload.get("result").unwrap_or_else(|| {
            panic!("MCP tool error response for {name} missing result: {payload:#?}")
        });
        assert_eq!(
            result.get("isError").and_then(Value::as_bool),
            Some(true),
            "tool {name} unexpectedly succeeded: {payload:#?}"
        );
        result
            .get("content")
            .and_then(Value::as_array)
            .and_then(|content| content.first())
            .and_then(|item| item.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("tool {name} error did not include text: {payload:#?}"))
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
            .unwrap_or_else(|err| panic!("send MCP request {method}: {err}"));
        let status = response.status();
        let body = response
            .text()
            .await
            .unwrap_or_else(|err| panic!("read MCP response for {method}: {err}"));
        assert_eq!(
            status,
            StatusCode::OK,
            "MCP request {method} failed with status {status}: {body}"
        );
        let payload = sse_json_rpc_message(&body);
        assert!(
            payload.get("error").is_none(),
            "MCP request {method} returned error: {payload:#?}"
        );
        assert_eq!(payload["id"].as_u64(), Some(id));
        payload
            .get("result")
            .cloned()
            .unwrap_or_else(|| panic!("MCP response for {method} should contain result"))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_streamable_http_discovers_and_covers_all_tools() {
    let harness = TestHarness::new(operator_service_config()).await;
    let mut mcp = McpClient::connect(&harness.base_url).await;

    let tool_names = mcp
        .tools_list()
        .await
        .into_iter()
        .map(|tool| {
            tool["name"]
                .as_str()
                .expect("tool should have a name")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    let expected_tool_names = [
        "amber.v1.manager.health.get",
        "amber.v1.manager.ready.get",
        "amber.v1.manager.scenario_source_allowlist.remove",
        "amber.v1.bindable_services.list",
        "amber.v1.bindable_services.get",
        "amber.v1.bindable_configs.list",
        "amber.v1.bindable_configs.get",
        "amber.v1.scenarios.list",
        "amber.v1.scenarios.get",
        "amber.v1.scenarios.create",
        "amber.v1.scenarios.upgrade",
        "amber.v1.scenarios.pause",
        "amber.v1.scenarios.resume",
        "amber.v1.scenarios.delete",
        "amber.v1.scenarios.revisions.list",
        "amber.v1.scenarios.config_schema.get",
        "amber.v1.operations.get",
        "amber.v1.operations.wait",
        "amber.v1.exports.list",
        "amber.v1.exports.get",
        "amber.v1.exports.wait",
    ]
    .into_iter()
    .map(str::to_string)
    .collect::<BTreeSet<_>>();
    assert_eq!(tool_names, expected_tool_names);

    let resources = mcp.resources_list().await;
    assert_eq!(resources.len(), 1);
    assert_eq!(resources[0]["uri"].as_str(), Some("amber://modules"));

    let templates = mcp.resource_templates_list().await;
    let template_uris = templates
        .into_iter()
        .map(|template| {
            template["uriTemplate"]
                .as_str()
                .expect("template should expose uriTemplate")
                .to_string()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        template_uris,
        ["amber://module/{name}", "amber://tool/{name}"]
            .into_iter()
            .map(str::to_string)
            .collect()
    );

    let modules_doc = mcp.read_resource_text("amber://modules").await;
    assert!(modules_doc.contains("Amber manager MCP modules"));
    assert!(modules_doc.contains("scenarios"));

    let scenarios_doc = mcp.read_resource_text("amber://module/scenarios").await;
    assert!(scenarios_doc.contains("Scenario inspection"));
    assert!(scenarios_doc.contains("amber.v1.scenarios.create"));

    let create_doc = mcp
        .read_resource_text("amber://tool/amber.v1.scenarios.create")
        .await;
    assert!(create_doc.contains("Input schema"));
    assert!(create_doc.contains("Read scenarios.config_schema.get first"));

    let health: ManagerHealthResponse = mcp
        .call_tool("amber.v1.manager.health.get", json!({}))
        .await;
    assert!(health.ok);
    mcp.wait_until_ready().await;

    let provider_url = harness.write_configured_manifest("mcp-provider.json5");
    let consumer_url = harness.write_consumer_manifest("mcp-consumer.json5");

    let provider_schema: ScenarioConfigSchemaResponse = mcp
        .call_tool(
            "amber.v1.scenarios.config_schema.get",
            json!({ "source_url": provider_url }),
        )
        .await;
    assert_eq!(
        provider_schema.secret_root_config_paths,
        vec!["secret_value"]
    );
    assert_eq!(
        provider_schema.exports["api"].protocol,
        ServiceProtocol::Http.as_str()
    );

    let mut provider_request = create_request(provider_schema.source_url.clone());
    provider_request.root_config = json!({
        "public_value": "provider-v1",
        "secret_value": "provider-secret-v1",
    });
    provider_request.metadata = json!({ "role": "provider" });

    let provider_created: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.create",
            serde_json::to_value(&provider_request).expect("serialize provider request"),
        )
        .await;
    let provider_operation: OperationStatusResponse = mcp
        .call_tool(
            "amber.v1.operations.get",
            json!({ "operation_id": provider_created.operation_id }),
        )
        .await;
    assert_eq!(
        provider_operation.kind,
        crate::domain::OperationKind::Create
    );

    let provider_wait: OperationWaitResult = mcp
        .call_tool(
            "amber.v1.operations.wait",
            json!({ "operation_id": provider_created.operation_id }),
        )
        .await;
    assert!(!provider_wait.timed_out);
    assert_eq!(provider_wait.operation.status, OperationStatus::Succeeded);

    let providers: ScenariosListResponse = mcp
        .call_tool(
            "amber.v1.scenarios.list",
            json!({ "metadata_exact": { "role": "provider" } }),
        )
        .await;
    assert_eq!(providers.scenarios.len(), 1);
    assert_eq!(
        providers.scenarios[0].scenario_id,
        provider_created.scenario_id
    );

    let provider_detail: ScenarioDetailResponse = mcp
        .call_tool(
            "amber.v1.scenarios.get",
            json!({ "scenario_id": provider_created.scenario_id }),
        )
        .await;
    assert_eq!(provider_detail.active_revision, Some(1));
    assert_eq!(provider_detail.observed_state, ObservedState::Running);
    assert_eq!(
        provider_detail.root_config,
        json!({ "public_value": "provider-v1" })
    );
    assert_eq!(
        provider_detail.secret_root_config_paths,
        vec!["secret_value"]
    );
    assert!(provider_detail.exports["api"].available);

    let existing_schema: ScenarioConfigSchemaResponse = mcp
        .call_tool(
            "amber.v1.scenarios.config_schema.get",
            json!({ "scenario_id": provider_created.scenario_id }),
        )
        .await;
    assert_eq!(existing_schema.source_url, provider_schema.source_url);
    assert_eq!(
        existing_schema.secret_root_config_paths,
        provider_schema.secret_root_config_paths
    );

    let exports: ExportsListResponse = mcp
        .call_tool(
            "amber.v1.exports.list",
            json!({
                "scenario_id": provider_created.scenario_id,
                "available": true,
                "protocol": "http",
            }),
        )
        .await;
    assert_eq!(exports.exports.len(), 1);
    let provider_export = exports.exports.into_iter().next().expect("provider export");
    assert_eq!(provider_export.export, "api");
    assert!(provider_export.available);

    let export_by_name: ExportDetailResponse = mcp
        .call_tool(
            "amber.v1.exports.get",
            json!({
                "scenario_id": provider_created.scenario_id,
                "export": "api",
            }),
        )
        .await;
    assert_eq!(
        export_by_name.bindable_service_id,
        provider_export.bindable_service_id
    );

    let export_wait: ExportWaitResult = mcp
        .call_tool(
            "amber.v1.exports.wait",
            json!({
                "scenario_id": provider_created.scenario_id,
                "export": "api",
                "timeout_ms": 1000,
                "poll_interval_ms": 10,
            }),
        )
        .await;
    assert!(!export_wait.timed_out);
    assert!(
        export_wait
            .export_detail
            .expect("available export detail")
            .available
    );

    let provider_services: BindableServicesListResponse = mcp
        .call_tool(
            "amber.v1.bindable_services.list",
            json!({
                "scenario_id": provider_created.scenario_id,
                "available": true,
            }),
        )
        .await;
    assert_eq!(provider_services.bindable_services.len(), 1);
    assert_eq!(
        provider_services.bindable_services[0].bindable_service_id,
        provider_export.bindable_service_id
    );

    let provider_service: BindableServiceResponse = mcp
        .call_tool(
            "amber.v1.bindable_services.get",
            json!({ "bindable_service_id": provider_export.bindable_service_id }),
        )
        .await;
    assert_eq!(provider_service.protocol, ServiceProtocol::Http);

    let mut consumer_request = create_request_with_slot(
        consumer_url,
        "api",
        provider_service.bindable_service_id.clone(),
    );
    consumer_request.metadata = json!({ "role": "consumer" });
    let consumer_created: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.create",
            serde_json::to_value(&consumer_request).expect("serialize consumer request"),
        )
        .await;
    let consumer_wait: OperationWaitResult = mcp
        .call_tool(
            "amber.v1.operations.wait",
            json!({ "operation_id": consumer_created.operation_id }),
        )
        .await;
    assert!(!consumer_wait.timed_out);
    assert_eq!(consumer_wait.operation.status, OperationStatus::Succeeded);

    let consumers: ScenariosListResponse = mcp
        .call_tool(
            "amber.v1.scenarios.list",
            json!({ "metadata_contains": { "role": "cons" } }),
        )
        .await;
    assert_eq!(consumers.scenarios.len(), 1);
    assert_eq!(
        consumers.scenarios[0].scenario_id,
        consumer_created.scenario_id
    );

    let consumer_paused: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.pause",
            json!({ "scenario_id": consumer_created.scenario_id }),
        )
        .await;
    let consumer_paused_wait: OperationWaitResult = mcp
        .call_tool(
            "amber.v1.operations.wait",
            json!({ "operation_id": consumer_paused.operation_id }),
        )
        .await;
    assert_eq!(
        consumer_paused_wait.operation.status,
        OperationStatus::Succeeded
    );
    let consumer_paused_detail: ScenarioDetailResponse = mcp
        .call_tool(
            "amber.v1.scenarios.get",
            json!({ "scenario_id": consumer_created.scenario_id }),
        )
        .await;
    assert_eq!(consumer_paused_detail.observed_state, ObservedState::Paused);

    let consumer_resumed: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.resume",
            json!({ "scenario_id": consumer_created.scenario_id }),
        )
        .await;
    let consumer_resumed_wait: OperationWaitResult = mcp
        .call_tool(
            "amber.v1.operations.wait",
            json!({ "operation_id": consumer_resumed.operation_id }),
        )
        .await;
    assert_eq!(
        consumer_resumed_wait.operation.status,
        OperationStatus::Succeeded
    );
    let consumer_running_detail: ScenarioDetailResponse = mcp
        .call_tool(
            "amber.v1.scenarios.get",
            json!({ "scenario_id": consumer_created.scenario_id }),
        )
        .await;
    assert_eq!(
        consumer_running_detail.observed_state,
        ObservedState::Running
    );

    let provider_upgraded: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.upgrade",
            json!({
                "scenario_id": provider_created.scenario_id,
                "root_config": {
                    "public_value": "provider-v2",
                    "secret_value": "provider-secret-v2",
                },
                "metadata": {
                    "role": "provider",
                    "version": "v2",
                },
                "telemetry": {
                    "upstream_otlp_http_endpoint": "http://127.0.0.1:4318",
                },
            }),
        )
        .await;
    let provider_upgrade_wait: OperationWaitResult = mcp
        .call_tool(
            "amber.v1.operations.wait",
            json!({ "operation_id": provider_upgraded.operation_id }),
        )
        .await;
    assert_eq!(
        provider_upgrade_wait.operation.status,
        OperationStatus::Succeeded
    );
    let upgraded_provider_detail: ScenarioDetailResponse = mcp
        .call_tool(
            "amber.v1.scenarios.get",
            json!({ "scenario_id": provider_created.scenario_id }),
        )
        .await;
    assert_eq!(upgraded_provider_detail.active_revision, Some(2));
    assert_eq!(
        upgraded_provider_detail.root_config,
        json!({ "public_value": "provider-v2" })
    );
    assert_eq!(
        upgraded_provider_detail
            .telemetry
            .upstream_otlp_http_endpoint
            .as_deref(),
        Some("http://127.0.0.1:4318")
    );

    let revisions: ScenarioRevisionsListResponse = mcp
        .call_tool(
            "amber.v1.scenarios.revisions.list",
            json!({ "scenario_id": provider_created.scenario_id }),
        )
        .await;
    assert_eq!(revisions.revisions.len(), 2);

    let consumer_deleted: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.delete",
            json!({ "scenario_id": consumer_created.scenario_id }),
        )
        .await;
    let consumer_delete_wait: OperationWaitResult = mcp
        .call_tool(
            "amber.v1.operations.wait",
            json!({ "operation_id": consumer_deleted.operation_id }),
        )
        .await;
    assert_eq!(
        consumer_delete_wait.operation.status,
        OperationStatus::Succeeded
    );

    let provider_deleted: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.delete",
            json!({ "scenario_id": provider_created.scenario_id }),
        )
        .await;
    let provider_delete_wait: OperationWaitResult = mcp
        .call_tool(
            "amber.v1.operations.wait",
            json!({ "operation_id": provider_deleted.operation_id }),
        )
        .await;
    assert_eq!(
        provider_delete_wait.operation.status,
        OperationStatus::Succeeded
    );

    let remaining: ScenariosListResponse =
        mcp.call_tool("amber.v1.scenarios.list", json!({})).await;
    assert!(remaining.scenarios.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_bindable_configs_list_and_get() {
    let config_name = "shared_secret";
    let harness = TestHarness::new(ManagerFileConfig {
        bindable_services: Default::default(),
        bindable_configs: BTreeMap::from([(config_name.to_string(), json!("bravo"))]),
        scenario_source_allowlist: None,
    })
    .await;
    let mut mcp = McpClient::connect(&harness.base_url).await;

    let listed: BindableConfigsListResponse = mcp
        .call_tool("amber.v1.bindable_configs.list", json!({}))
        .await;
    assert_eq!(listed.bindable_configs.len(), 1);
    assert_eq!(
        listed.bindable_configs[0].bindable_config_id,
        ids::operator_config_id(config_name)
    );
    assert_eq!(listed.bindable_configs[0].json_type, "string");

    let fetched: BindableConfigResponse = mcp
        .call_tool(
            "amber.v1.bindable_configs.get",
            json!({ "bindable_config_id": ids::operator_config_id(config_name) }),
        )
        .await;
    assert_eq!(
        fetched.bindable_config_id,
        ids::operator_config_id(config_name)
    );
    assert_eq!(fetched.json_type, "string");
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_exports_wait_reports_timeout_for_paused_scenario() {
    let harness = TestHarness::new(operator_service_config()).await;
    let mut mcp = McpClient::connect(&harness.base_url).await;
    mcp.wait_until_ready().await;

    let provider_url = harness.write_provider_manifest("mcp-paused-provider.json5");
    let mut request: CreateScenarioRequest = create_request(provider_url);
    request.start = false;

    let created: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.create",
            serde_json::to_value(&request).expect("serialize paused provider request"),
        )
        .await;
    let wait: OperationWaitResult = mcp
        .call_tool(
            "amber.v1.operations.wait",
            json!({ "operation_id": created.operation_id }),
        )
        .await;
    assert_eq!(wait.operation.status, OperationStatus::Succeeded);

    let detail: ScenarioDetailResponse = mcp
        .call_tool(
            "amber.v1.scenarios.get",
            json!({ "scenario_id": created.scenario_id }),
        )
        .await;
    assert_eq!(detail.observed_state, ObservedState::Paused);
    assert!(!detail.exports["api"].available);

    let export_wait: ExportWaitResult = mcp
        .call_tool(
            "amber.v1.exports.wait",
            json!({
                "scenario_id": created.scenario_id,
                "export": "api",
                "timeout_ms": 50,
                "poll_interval_ms": 10,
            }),
        )
        .await;
    assert!(export_wait.timed_out);
    assert!(
        !export_wait
            .export_detail
            .expect("export detail should be present")
            .available
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_exports_tools_handle_pending_exports_without_active_revision() {
    let harness = TestHarness::new_without_worker(operator_service_config()).await;
    let mut mcp = McpClient::connect(&harness.base_url).await;

    let provider_url = harness.write_provider_manifest("mcp-pending-provider.json5");
    let publish_listener = TcpListener::bind("127.0.0.1:0").expect("bind publish listener");
    let publish_addr = publish_listener.local_addr().expect("publish addr");
    drop(publish_listener);
    let mut request: CreateScenarioRequest = create_request(provider_url);
    request.exports.insert(
        "api".to_string(),
        ExportRequest {
            publish: Some(ExportPublishRequest {
                listen: publish_addr,
            }),
        },
    );
    let created: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.create",
            serde_json::to_value(&request).expect("serialize pending provider request"),
        )
        .await;

    let operation: OperationStatusResponse = mcp
        .call_tool(
            "amber.v1.operations.get",
            json!({ "operation_id": created.operation_id }),
        )
        .await;
    assert_eq!(operation.status, OperationStatus::Queued);

    let exports: ExportsListResponse = mcp
        .call_tool(
            "amber.v1.exports.list",
            json!({ "scenario_id": created.scenario_id }),
        )
        .await;
    assert_eq!(exports.exports.len(), 1);
    assert_eq!(exports.exports[0].export, "api");
    assert_eq!(exports.exports[0].protocol, ServiceProtocol::Http);
    assert!(!exports.exports[0].available);

    let export: ExportDetailResponse = mcp
        .call_tool(
            "amber.v1.exports.get",
            json!({
                "scenario_id": created.scenario_id,
                "export": "api",
            }),
        )
        .await;
    assert_eq!(export.export, "api");
    assert_eq!(export.protocol, ServiceProtocol::Http);
    assert!(!export.available);

    let export_wait: ExportWaitResult = mcp
        .call_tool(
            "amber.v1.exports.wait",
            json!({
                "scenario_id": created.scenario_id,
                "export": "api",
                "timeout_ms": 50,
                "poll_interval_ms": 10,
            }),
        )
        .await;
    assert!(export_wait.timed_out);
    let pending_export = export_wait
        .export_detail
        .expect("pending export detail should be present");
    assert_eq!(pending_export.export, "api");
    assert_eq!(pending_export.protocol, ServiceProtocol::Http);
    assert!(!pending_export.available);
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_exports_list_ignores_undeclared_pending_exports() {
    let harness = TestHarness::new_without_worker(operator_service_config()).await;
    let mut mcp = McpClient::connect(&harness.base_url).await;

    let provider_url = harness.write_provider_manifest("mcp-undeclared-export-provider.json5");

    let mut valid_request = create_request(provider_url.clone());
    valid_request
        .exports
        .insert("api".to_string(), ExportRequest { publish: None });
    let valid: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.create",
            serde_json::to_value(&valid_request).expect("serialize valid export request"),
        )
        .await;

    let mut invalid_request = create_request(provider_url);
    invalid_request
        .exports
        .insert("bogus".to_string(), ExportRequest { publish: None });
    let invalid: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.create",
            serde_json::to_value(&invalid_request).expect("serialize invalid export request"),
        )
        .await;

    let exports: ExportsListResponse = mcp.call_tool("amber.v1.exports.list", json!({})).await;
    assert!(
        exports
            .exports
            .iter()
            .any(|export| { export.scenario_id == valid.scenario_id && export.export == "api" })
    );
    assert!(
        !exports
            .exports
            .iter()
            .any(|export| export.export == "bogus")
    );

    let error = mcp
        .call_tool_error(
            "amber.v1.exports.get",
            json!({
                "scenario_id": invalid.scenario_id,
                "export": "bogus",
            }),
        )
        .await;
    assert!(error.contains("does not exist"));
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_wait_tools_reject_oversized_timeouts() {
    let harness = TestHarness::new_without_worker(operator_service_config()).await;
    let mut mcp = McpClient::connect(&harness.base_url).await;

    let provider_url = harness.write_provider_manifest("mcp-oversized-timeout-provider.json5");
    let mut request = create_request(provider_url);
    request
        .exports
        .insert("api".to_string(), ExportRequest { publish: None });
    let created: EnqueueOperationResponse = mcp
        .call_tool(
            "amber.v1.scenarios.create",
            serde_json::to_value(&request).expect("serialize oversized-timeout request"),
        )
        .await;

    let operation_error = mcp
        .call_tool_error(
            "amber.v1.operations.wait",
            json!({
                "operation_id": created.operation_id,
                "timeout_ms": u64::MAX,
            }),
        )
        .await;
    assert!(operation_error.contains("timeout_ms"));

    let export_error = mcp
        .call_tool_error(
            "amber.v1.exports.wait",
            json!({
                "scenario_id": created.scenario_id,
                "export": "api",
                "timeout_ms": u64::MAX,
            }),
        )
        .await;
    assert!(export_error.contains("timeout_ms"));
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_create_rejects_source_url_outside_operator_allowlist() {
    let manifest_harness = TestHarness::new(ManagerFileConfig::default()).await;
    let allowed_url = manifest_harness.write_provider_manifest("mcp-allowlisted-provider.json5");
    let denied_url = manifest_harness.write_provider_manifest("mcp-blocked-provider.json5");

    let harness = TestHarness::new(ManagerFileConfig {
        bindable_services: Default::default(),
        bindable_configs: Default::default(),
        scenario_source_allowlist: Some(BTreeSet::from([allowed_url])),
    })
    .await;
    let mut mcp = McpClient::connect(&harness.base_url).await;

    let error = mcp
        .call_tool_error(
            "amber.v1.scenarios.create",
            serde_json::to_value(create_request(denied_url.clone()))
                .expect("serialize allowlist-blocked create request"),
        )
        .await;
    assert!(error.contains("scenario_source_allowlist"));
    assert!(error.contains(&denied_url));

    let scenarios: ScenariosListResponse =
        mcp.call_tool("amber.v1.scenarios.list", json!({})).await;
    assert!(
        scenarios.scenarios.is_empty(),
        "unexpected scenarios: {scenarios:#?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_remove_allowlist_entry_blocks_future_creates() {
    let manifest_harness = TestHarness::new(ManagerFileConfig::default()).await;
    let allowed_url =
        manifest_harness.write_provider_manifest("mcp-remove-allowlisted-provider.json5");

    let harness = TestHarness::new(ManagerFileConfig {
        bindable_services: Default::default(),
        bindable_configs: Default::default(),
        scenario_source_allowlist: Some(BTreeSet::from([allowed_url.clone()])),
    })
    .await;
    let mut mcp = McpClient::connect(&harness.base_url).await;

    let removed: ScenarioSourceAllowlistEntryResponse = mcp
        .call_tool(
            "amber.v1.manager.scenario_source_allowlist.remove",
            json!({ "source_url": allowed_url.clone() }),
        )
        .await;
    assert_eq!(removed.source_url, allowed_url);

    let error = mcp
        .call_tool_error(
            "amber.v1.scenarios.create",
            serde_json::to_value(create_request(removed.source_url.clone()))
                .expect("serialize removed-allowlist create request"),
        )
        .await;
    assert!(error.contains("scenario_source_allowlist"));
    assert!(error.contains(&removed.source_url));
}

#[tokio::test(flavor = "multi_thread")]
async fn mcp_config_schema_rejects_source_url_outside_operator_allowlist() {
    let manifest_harness = TestHarness::new(ManagerFileConfig::default()).await;
    let allowed_url =
        manifest_harness.write_provider_manifest("mcp-schema-allowlisted-provider.json5");
    let denied_url = manifest_harness.write_provider_manifest("mcp-schema-blocked-provider.json5");

    let harness = TestHarness::new(ManagerFileConfig {
        bindable_services: Default::default(),
        bindable_configs: Default::default(),
        scenario_source_allowlist: Some(BTreeSet::from([allowed_url])),
    })
    .await;
    let mut mcp = McpClient::connect(&harness.base_url).await;

    let error = mcp
        .call_tool_error(
            "amber.v1.scenarios.config_schema.get",
            json!({ "source_url": denied_url.clone() }),
        )
        .await;
    assert!(error.contains("scenario_source_allowlist"));
    assert!(error.contains(&denied_url));
}
