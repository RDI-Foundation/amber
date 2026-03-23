use std::{collections::BTreeMap, net::SocketAddr};

use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const IMPLICIT_OWNER_ID: &str = "default";

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DesiredState {
    Running,
    Paused,
}

impl DesiredState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Paused => "paused",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ObservedState {
    Starting,
    Running,
    Degraded,
    Paused,
    Failed,
}

impl ObservedState {
    pub const DEPENDENCY_BLOCKING_STATES: [&'static str; 3] = ["starting", "running", "degraded"];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Degraded => "degraded",
            Self::Paused => "paused",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationKind {
    Create,
    Pause,
    Resume,
    Upgrade,
    Delete,
    Reconcile,
}

impl OperationKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Pause => "pause",
            Self::Resume => "resume",
            Self::Upgrade => "upgrade",
            Self::Delete => "delete",
            Self::Reconcile => "reconcile",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum OperationStatus {
    Queued,
    Running,
    Succeeded,
    Failed,
}

impl OperationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceProtocol {
    Http,
    Tcp,
}

impl ServiceProtocol {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Tcp => "tcp",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BindableServiceSourceKind {
    OperatorService,
    ScenarioExport,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BindableServiceProviderKind {
    DirectUrl,
    LoopbackUpstream,
    ScenarioExport,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalSlotBindingRequest {
    pub bindable_service_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportPublishRequest {
    #[schemars(with = "String")]
    pub listen: SocketAddr,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportRequest {
    #[serde(default)]
    pub publish: Option<ExportPublishRequest>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioTelemetryRequest {
    #[serde(default)]
    pub upstream_otlp_http_endpoint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateScenarioRequest {
    pub source_url: String,
    #[serde(default)]
    pub root_config: Value,
    #[serde(default)]
    pub external_root_config: BTreeMap<String, String>,
    #[serde(default)]
    pub external_slots: BTreeMap<String, ExternalSlotBindingRequest>,
    #[serde(default)]
    pub exports: BTreeMap<String, ExportRequest>,
    #[serde(default)]
    pub metadata: Value,
    #[serde(default)]
    pub telemetry: ScenarioTelemetryRequest,
    #[serde(default)]
    pub store_bundle: bool,
    #[serde(default = "default_true")]
    pub start: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct UpgradeScenarioRequest {
    #[serde(default)]
    pub source_url: Option<String>,
    #[serde(default)]
    pub root_config: Option<Value>,
    #[serde(default)]
    pub external_root_config: Option<BTreeMap<String, String>>,
    #[serde(default)]
    pub external_slots: Option<BTreeMap<String, ExternalSlotBindingRequest>>,
    #[serde(default)]
    pub exports: Option<BTreeMap<String, ExportRequest>>,
    #[serde(default)]
    pub metadata: Option<Value>,
    #[serde(default)]
    pub telemetry: Option<ScenarioTelemetryRequest>,
    #[serde(default)]
    pub store_bundle: bool,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteScenarioQuery {
    #[serde(default)]
    pub destroy_storage: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioSourceAllowlistEntryRequest {
    pub source_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioSourceAllowlistEntryResponse {
    pub source_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum OperationPayload {
    Create {
        request: CreateScenarioRequest,
    },
    Pause,
    Resume,
    Upgrade {
        request: UpgradeScenarioRequest,
    },
    Delete {
        destroy_storage: bool,
    },
    Reconcile {
        #[serde(default)]
        cleanup_runtime: bool,
    },
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EnqueueOperationResponse {
    pub scenario_id: String,
    pub operation_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OperationStatusResponse {
    pub operation_id: String,
    pub scenario_id: Option<String>,
    pub kind: OperationKind,
    pub status: OperationStatus,
    pub phase: String,
    pub retry_count: u32,
    pub backoff_until_ms: Option<i64>,
    pub last_error: Option<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
    #[serde(default)]
    pub result: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindableServiceResponse {
    pub bindable_service_id: String,
    pub source_kind: BindableServiceSourceKind,
    pub provider_kind: BindableServiceProviderKind,
    #[serde(default)]
    pub display_name: Option<String>,
    pub protocol: ServiceProtocol,
    pub available: bool,
    #[serde(default)]
    pub scenario_id: Option<String>,
    #[serde(default)]
    pub export: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BindableConfigResponse {
    pub bindable_config_id: String,
    #[serde(default)]
    pub display_name: Option<String>,
    pub json_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioSummaryResponse {
    pub scenario_id: String,
    pub source_url: String,
    pub active_revision: Option<i64>,
    pub desired_state: DesiredState,
    pub observed_state: ObservedState,
    pub metadata: Value,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioDetailResponse {
    pub scenario_id: String,
    pub source_url: String,
    pub active_revision: Option<i64>,
    pub desired_state: DesiredState,
    pub observed_state: ObservedState,
    pub metadata: Value,
    pub root_config: Value,
    pub secret_root_config_paths: Vec<String>,
    pub external_slots: BTreeMap<String, ExternalSlotBindingResponse>,
    pub exports: BTreeMap<String, ExportResponse>,
    pub telemetry: ScenarioTelemetryRequest,
    pub compose_project: String,
    pub bundle_stored: bool,
    #[serde(default)]
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExternalSlotBindingResponse {
    pub bindable_service_id: String,
    #[serde(default)]
    pub provider_scenario_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ExportResponse {
    #[serde(default)]
    pub publish: Option<ExportPublishRequest>,
    #[serde(default)]
    pub bindable_service_id: Option<String>,
    #[serde(default)]
    pub available: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScenarioRevisionSummaryResponse {
    pub revision: i64,
    pub source_url: String,
    pub bundle_stored: bool,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ErrorResponse {
    pub error: String,
}

fn default_true() -> bool {
    true
}
