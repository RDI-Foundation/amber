use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;
use sqlx::FromRow;
use thiserror::Error;

use crate::domain::{
    DesiredState, ObservedState, OperationKind, OperationPayload, OperationStatus,
    ScenarioTelemetryRequest,
};

#[derive(Clone, Debug)]
pub struct NewPendingScenario<'a> {
    pub scenario_id: &'a str,
    pub source_url: &'a str,
    pub root_config: &'a Value,
    pub metadata: &'a Value,
    pub external_slots: &'a Value,
    pub exports: &'a Value,
    pub telemetry: &'a ScenarioTelemetryRequest,
    pub desired_state: DesiredState,
    pub observed_state: ObservedState,
    pub compose_project: &'a str,
    pub operation_id: &'a str,
    pub payload: &'a OperationPayload,
    pub now_ms: i64,
}

#[derive(Clone, Debug)]
pub struct NewScenarioRevision<'a> {
    pub scenario_id: &'a str,
    pub revision: i64,
    pub source_url: &'a str,
    pub scenario_ir_json: &'a str,
    pub bundle_root: Option<&'a str>,
    pub ir_version: i64,
    pub created_at_ms: i64,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ScenarioStateUpdate {
    pub desired_state: Option<DesiredState>,
    pub observed_state: Option<ObservedState>,
}

#[derive(Clone, Debug)]
pub struct ScenarioRevisionApplication<'a> {
    pub scenario_id: &'a str,
    pub source_url: &'a str,
    pub revision: i64,
    pub metadata: &'a Value,
    pub root_config: &'a Value,
    pub secret_config: &'a Value,
    pub telemetry: &'a ScenarioTelemetryRequest,
    pub external_slots: &'a Value,
    pub exports: &'a Value,
    pub desired_state: DesiredState,
    pub observed_state: ObservedState,
    pub last_error: Option<&'a str>,
    pub now_ms: i64,
}

#[derive(Clone, Debug)]
pub struct StoredScenario {
    pub id: String,
    pub source_url: String,
    pub active_revision: Option<i64>,
    pub compose_project: String,
    pub desired_state: DesiredState,
    pub observed_state: ObservedState,
    pub metadata: Value,
    pub root_config: Option<Value>,
    pub telemetry: ScenarioTelemetryRequest,
    pub external_slots: Value,
    pub exports: Value,
    pub failure_count: u32,
    pub backoff_until_ms: Option<i64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StoredRevision {
    pub scenario_ir_json: String,
    pub bundle_root: Option<String>,
    pub ir_version: i64,
}

#[derive(Clone, Debug, FromRow)]
pub struct StoredRevisionSummary {
    pub revision: i64,
    pub source_url: String,
    pub bundle_stored: bool,
    pub created_at_ms: i64,
}

#[derive(Clone, Debug)]
pub struct StoredOperation {
    pub id: String,
    pub kind: OperationKind,
    pub scenario_id: Option<String>,
    pub payload: OperationPayload,
    pub status: OperationStatus,
    pub phase: String,
    pub retry_count: u32,
    pub backoff_until_ms: Option<i64>,
    pub last_error: Option<String>,
    pub result: Option<Value>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub started_at_ms: Option<i64>,
    pub finished_at_ms: Option<i64>,
}

#[derive(Clone, Debug)]
pub struct ClaimedScenarioWork {
    pub scenario_id: String,
    pub generation: i64,
    pub cleanup_runtime: bool,
    pub operation_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct InterruptedScenarioWork {
    pub scenario_id: String,
    pub generation: i64,
    pub operation_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct StoredExportService {
    pub service_id: String,
    pub scenario_id: String,
    pub export_name: String,
    pub protocol: String,
    pub listen_addr: String,
    pub listen_port: u16,
    pub available: bool,
}

#[derive(Clone, Debug, FromRow)]
pub struct StoredDependency {
    pub consumer_scenario_id: String,
    pub slot_name: String,
    pub bindable_service_id: String,
    pub provider_scenario_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NewDependency {
    pub slot_name: String,
    pub bindable_service_id: String,
    pub provider_scenario_id: Option<String>,
}

#[derive(Clone, Debug)]
pub struct NewExportService {
    pub service_id: String,
    pub export_name: String,
    pub protocol: String,
    pub listen_addr: String,
    pub listen_port: u16,
}

#[derive(Debug, Error)]
pub enum StoreError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("migration error: {0}")]
    Migration(#[from] sqlx::migrate::MigrateError),

    #[error("invalid stored JSON in {context}: {source}")]
    Json {
        context: &'static str,
        source: serde_json::Error,
    },

    #[error("invalid stored enum value `{value}` for {kind}")]
    InvalidEnum { kind: &'static str, value: String },
}

#[derive(Debug, FromRow)]
pub(super) struct ScenarioRow {
    id: String,
    source_url: String,
    active_revision: Option<i64>,
    compose_project: String,
    desired_state: String,
    observed_state: String,
    metadata_json: String,
    root_config_json: Option<String>,
    telemetry_json: String,
    external_slots_json: String,
    exports_json: String,
    failure_count: i64,
    backoff_until_ms: Option<i64>,
    last_error: Option<String>,
}

#[derive(Debug, FromRow)]
pub(super) struct RevisionRow {
    scenario_ir_json: String,
    bundle_root: Option<String>,
    manager_version: String,
    amber_version: String,
    ir_version: i64,
}

#[derive(Debug, FromRow)]
pub(super) struct OperationRow {
    pub(super) id: String,
    pub(super) kind: String,
    pub(super) scenario_id: Option<String>,
    pub(super) payload_json: String,
    pub(super) status: String,
    pub(super) phase: String,
    pub(super) retry_count: i64,
    pub(super) backoff_until_ms: Option<i64>,
    pub(super) last_error: Option<String>,
    pub(super) result_json: Option<String>,
    pub(super) created_at_ms: i64,
    pub(super) updated_at_ms: i64,
    pub(super) started_at_ms: Option<i64>,
    pub(super) finished_at_ms: Option<i64>,
}

#[derive(Debug, FromRow)]
pub(super) struct ExportServiceRow {
    service_id: String,
    scenario_id: String,
    export_name: String,
    protocol: String,
    listen_addr: String,
    listen_port: i64,
    available: i64,
}

impl TryFrom<ScenarioRow> for StoredScenario {
    type Error = StoreError;

    fn try_from(row: ScenarioRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            source_url: row.source_url,
            active_revision: row.active_revision,
            compose_project: row.compose_project,
            desired_state: parse_desired_state(&row.desired_state)?,
            observed_state: parse_observed_state(&row.observed_state)?,
            metadata: decode_json_with_context("scenarios.metadata_json", &row.metadata_json)?,
            root_config: row
                .root_config_json
                .as_deref()
                .map(|raw| decode_json_with_context("scenarios.root_config_json", raw))
                .transpose()?,
            telemetry: decode_json_with_context("scenarios.telemetry_json", &row.telemetry_json)?,
            external_slots: decode_json_with_context(
                "scenarios.external_slots_json",
                &row.external_slots_json,
            )?,
            exports: decode_json_with_context("scenarios.exports_json", &row.exports_json)?,
            failure_count: u32::try_from(row.failure_count).unwrap_or_default(),
            backoff_until_ms: row.backoff_until_ms,
            last_error: row.last_error,
        })
    }
}

impl TryFrom<RevisionRow> for StoredRevision {
    type Error = StoreError;

    fn try_from(row: RevisionRow) -> Result<Self, Self::Error> {
        let _ = row.manager_version;
        let _ = row.amber_version;
        Ok(Self {
            scenario_ir_json: row.scenario_ir_json,
            bundle_root: row.bundle_root,
            ir_version: row.ir_version,
        })
    }
}

impl TryFrom<OperationRow> for StoredOperation {
    type Error = StoreError;

    fn try_from(row: OperationRow) -> Result<Self, Self::Error> {
        Ok(Self {
            id: row.id,
            kind: parse_operation_kind(&row.kind)?,
            scenario_id: row.scenario_id,
            payload: decode_json_with_context("operations.payload_json", &row.payload_json)?,
            status: parse_operation_status(&row.status)?,
            phase: row.phase,
            retry_count: u32::try_from(row.retry_count).unwrap_or_default(),
            backoff_until_ms: row.backoff_until_ms,
            last_error: row.last_error,
            result: row
                .result_json
                .as_deref()
                .map(|raw| decode_json_with_context("operations.result_json", raw))
                .transpose()?,
            created_at_ms: row.created_at_ms,
            updated_at_ms: row.updated_at_ms,
            started_at_ms: row.started_at_ms,
            finished_at_ms: row.finished_at_ms,
        })
    }
}

impl TryFrom<ExportServiceRow> for StoredExportService {
    type Error = StoreError;

    fn try_from(row: ExportServiceRow) -> Result<Self, Self::Error> {
        Ok(Self {
            service_id: row.service_id,
            scenario_id: row.scenario_id,
            export_name: row.export_name,
            protocol: row.protocol,
            listen_addr: row.listen_addr,
            listen_port: u16::try_from(row.listen_port).map_err(|_| StoreError::InvalidEnum {
                kind: "scenario_export_services.listen_port",
                value: row.listen_port.to_string(),
            })?,
            available: row.available != 0,
        })
    }
}

pub(super) fn encode_json<T: Serialize>(value: &T) -> Result<String, StoreError> {
    serde_json::to_string(value).map_err(|source| StoreError::Json {
        context: "serialize",
        source,
    })
}

pub(super) fn decode_json_with_context<T: DeserializeOwned>(
    context: &'static str,
    raw: &str,
) -> Result<T, StoreError> {
    serde_json::from_str(raw).map_err(|source| StoreError::Json { context, source })
}

fn parse_desired_state(value: &str) -> Result<DesiredState, StoreError> {
    match value {
        "running" => Ok(DesiredState::Running),
        "paused" => Ok(DesiredState::Paused),
        other => Err(StoreError::InvalidEnum {
            kind: "desired_state",
            value: other.to_string(),
        }),
    }
}

fn parse_observed_state(value: &str) -> Result<ObservedState, StoreError> {
    match value {
        "starting" => Ok(ObservedState::Starting),
        "running" => Ok(ObservedState::Running),
        "degraded" => Ok(ObservedState::Degraded),
        "paused" => Ok(ObservedState::Paused),
        "failed" => Ok(ObservedState::Failed),
        other => Err(StoreError::InvalidEnum {
            kind: "observed_state",
            value: other.to_string(),
        }),
    }
}

fn parse_operation_kind(value: &str) -> Result<OperationKind, StoreError> {
    match value {
        "create" => Ok(OperationKind::Create),
        "pause" => Ok(OperationKind::Pause),
        "resume" => Ok(OperationKind::Resume),
        "upgrade" => Ok(OperationKind::Upgrade),
        "delete" => Ok(OperationKind::Delete),
        "reconcile" => Ok(OperationKind::Reconcile),
        other => Err(StoreError::InvalidEnum {
            kind: "operation.kind",
            value: other.to_string(),
        }),
    }
}

fn parse_operation_status(value: &str) -> Result<OperationStatus, StoreError> {
    match value {
        "queued" => Ok(OperationStatus::Queued),
        "running" => Ok(OperationStatus::Running),
        "succeeded" => Ok(OperationStatus::Succeeded),
        "failed" => Ok(OperationStatus::Failed),
        other => Err(StoreError::InvalidEnum {
            kind: "operation.status",
            value: other.to_string(),
        }),
    }
}
