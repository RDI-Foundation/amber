use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use amber_config::collect_leaf_paths;
use amber_scenario::ScenarioIr;
use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};

use crate::{
    compiler::root_schema_from_ir,
    domain::{
        CreateScenarioRequest, DeleteScenarioQuery, DesiredState, EnqueueOperationResponse,
        ErrorResponse, ExportResponse, ExternalSlotBindingRequest, ExternalSlotBindingResponse,
        ObservedState, OperationKind, OperationPayload, OperationStatusResponse,
        ScenarioDetailResponse, ScenarioRevisionSummaryResponse, ScenarioSummaryResponse,
        UpgradeScenarioRequest,
    },
    ids,
    store::{NewPendingScenario, ScenarioStateUpdate, StoreError, StoredOperation},
    worker::AppState,
};

pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/v1/bindable-services", get(list_bindable_services))
        .route("/v1/scenarios", get(list_scenarios).post(create_scenario))
        .route(
            "/v1/scenarios/{id}",
            get(get_scenario).delete(delete_scenario),
        )
        .route("/v1/scenarios/{id}/revisions", get(list_revisions))
        .route("/v1/scenarios/{id}/pause", post(pause_scenario))
        .route("/v1/scenarios/{id}/resume", post(resume_scenario))
        .route("/v1/scenarios/{id}/upgrade", post(upgrade_scenario))
        .route("/v1/operations/{id}", get(get_operation))
        .with_state(state)
}

async fn healthz() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn readyz(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    if state.ready().await {
        return (StatusCode::OK, Json(json!({ "ready": true }))).into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ready": false })),
    )
        .into_response()
}

async fn list_bindable_services(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<crate::domain::BindableServiceResponse>>, ApiError> {
    Ok(Json(
        state
            .bindable_services()
            .await
            .map_err(ApiError::internal)?,
    ))
}

async fn list_scenarios(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<ScenarioSummaryResponse>>, ApiError> {
    let scenarios = state
        .store()
        .list_scenarios()
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(
        scenarios
            .into_iter()
            .map(|scenario| ScenarioSummaryResponse {
                scenario_id: scenario.id,
                source_url: scenario.source_url,
                active_revision: scenario.active_revision,
                desired_state: scenario.desired_state,
                observed_state: scenario.observed_state,
                metadata: scenario.metadata,
                last_error: scenario.last_error,
            })
            .collect(),
    ))
}

async fn create_scenario(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateScenarioRequest>,
) -> Result<Json<EnqueueOperationResponse>, ApiError> {
    let scenario_id = ids::new_scenario_id();
    let operation_id = ids::new_operation_id();
    let desired_state = if request.start {
        crate::domain::DesiredState::Running
    } else {
        crate::domain::DesiredState::Paused
    };
    let observed_state = if request.start {
        crate::domain::ObservedState::Starting
    } else {
        crate::domain::ObservedState::Paused
    };
    let payload = OperationPayload::Create {
        request: request.clone(),
    };
    let external_slots =
        serde_json::to_value(&request.external_slots).map_err(ApiError::internal)?;
    let exports = serde_json::to_value(&request.exports).map_err(ApiError::internal)?;
    let compose_project = ids::compose_project_name(&scenario_id);

    state
        .store()
        .create_pending_scenario_with_operation(NewPendingScenario {
            scenario_id: &scenario_id,
            source_url: &request.source_url,
            root_config: &request.root_config,
            metadata: &request.metadata,
            external_slots: &external_slots,
            exports: &exports,
            telemetry: &request.telemetry,
            desired_state,
            observed_state,
            compose_project: &compose_project,
            operation_id: &operation_id,
            payload: &payload,
            now_ms: now_ms(),
        })
        .await
        .map_err(ApiError::internal)?;
    state.wake_worker();

    Ok(Json(EnqueueOperationResponse {
        scenario_id,
        operation_id,
    }))
}

async fn get_scenario(
    State(state): State<Arc<AppState>>,
    Path(scenario_id): Path<String>,
) -> Result<Json<ScenarioDetailResponse>, ApiError> {
    let scenario = state
        .store()
        .load_scenario(&scenario_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("scenario {} does not exist", scenario_id)))?;

    let active_revision = scenario.active_revision;
    let active_revision_row = if let Some(revision) = active_revision {
        state
            .store()
            .load_revision(&scenario_id, revision)
            .await
            .map_err(ApiError::internal)?
    } else {
        None
    };
    let compiled = active_revision_row
        .as_ref()
        .map(|revision| crate::compiler::inspect_stored_ir(&revision.scenario_ir_json))
        .transpose()
        .map_err(ApiError::internal)?;
    let dependencies = state
        .store()
        .list_dependencies()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .filter(|dependency| dependency.consumer_scenario_id == scenario_id)
        .collect::<Vec<_>>();
    let export_services = state
        .store()
        .list_export_services()
        .await
        .map_err(ApiError::internal)?
        .into_iter()
        .filter(|service| service.scenario_id == scenario_id)
        .map(|service| (service.export_name.clone(), service))
        .collect::<BTreeMap<_, _>>();

    let external_slots: BTreeMap<String, ExternalSlotBindingRequest> =
        serde_json::from_value(scenario.external_slots.clone()).map_err(ApiError::bad_request)?;
    let external_slots = external_slots
        .into_iter()
        .map(|(slot_name, binding)| {
            let provider_scenario_id = dependencies
                .iter()
                .find(|dependency| dependency.slot_name == slot_name)
                .and_then(|dependency| dependency.provider_scenario_id.clone());
            (
                slot_name,
                ExternalSlotBindingResponse {
                    bindable_service_id: binding.bindable_service_id,
                    provider_scenario_id,
                },
            )
        })
        .collect();

    let exports: BTreeMap<String, crate::domain::ExportRequest> =
        serde_json::from_value(scenario.exports.clone()).map_err(ApiError::bad_request)?;
    let export_names = compiled
        .as_ref()
        .map(|compiled| {
            compiled
                .proxy_metadata
                .exports
                .keys()
                .cloned()
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default()
        .into_iter()
        .chain(exports.keys().cloned())
        .collect::<BTreeSet<_>>();
    let exports = export_names
        .into_iter()
        .map(|export_name| {
            let bindable_service_id = ids::export_service_id(&scenario_id, &export_name);
            let request = exports.get(&export_name);
            let available = export_services
                .get(&export_name)
                .is_some_and(|service| service.available);
            (
                export_name,
                ExportResponse {
                    publish: request.and_then(|request| request.publish.clone()),
                    bindable_service_id: Some(bindable_service_id),
                    available,
                },
            )
        })
        .collect();

    let secret_root_config_paths = active_revision_row
        .as_ref()
        .map(secret_paths_from_revision)
        .transpose()?
        .unwrap_or_default();

    Ok(Json(ScenarioDetailResponse {
        scenario_id: scenario.id,
        source_url: scenario.source_url,
        active_revision,
        desired_state: scenario.desired_state,
        observed_state: scenario.observed_state,
        metadata: scenario.metadata,
        root_config: if active_revision.is_some() {
            scenario.root_config.unwrap_or_else(|| json!({}))
        } else {
            // Pending scenarios may be carrying the raw create request so upgrades can
            // preserve omitted config before the first successful revision exists.
            // Do not expose that pre-classification payload over the API.
            json!({})
        },
        secret_root_config_paths,
        external_slots,
        exports,
        telemetry: scenario.telemetry,
        compose_project: scenario.compose_project,
        bundle_stored: active_revision_row
            .as_ref()
            .and_then(|revision| revision.bundle_root.as_ref())
            .is_some(),
        last_error: scenario.last_error,
    }))
}

async fn list_revisions(
    State(state): State<Arc<AppState>>,
    Path(scenario_id): Path<String>,
) -> Result<Json<Vec<ScenarioRevisionSummaryResponse>>, ApiError> {
    ensure_scenario_exists(&state, &scenario_id).await?;
    let revisions = state
        .store()
        .list_revisions(&scenario_id)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(
        revisions
            .into_iter()
            .map(|revision| ScenarioRevisionSummaryResponse {
                revision: revision.revision,
                source_url: revision.source_url,
                bundle_stored: revision.bundle_stored,
                created_at_ms: revision.created_at_ms,
            })
            .collect(),
    ))
}

async fn pause_scenario(
    State(state): State<Arc<AppState>>,
    Path(scenario_id): Path<String>,
) -> Result<Json<EnqueueOperationResponse>, ApiError> {
    ensure_scenario_exists(&state, &scenario_id).await?;
    ensure_scenario_has_no_active_dependents(&state, &scenario_id).await?;
    enqueue_scenario_operation(
        &state,
        &scenario_id,
        OperationKind::Pause,
        OperationPayload::Pause,
        Some(DesiredState::Paused),
        None,
    )
    .await
}

async fn resume_scenario(
    State(state): State<Arc<AppState>>,
    Path(scenario_id): Path<String>,
) -> Result<Json<EnqueueOperationResponse>, ApiError> {
    let scenario = load_scenario(&state, &scenario_id).await?;
    if scenario.active_revision.is_none() {
        return Err(ApiError::bad_request(format!(
            "scenario {} has no active revision to resume",
            scenario_id
        )));
    }
    enqueue_scenario_operation(
        &state,
        &scenario_id,
        OperationKind::Resume,
        OperationPayload::Resume,
        Some(DesiredState::Running),
        Some(ObservedState::Starting),
    )
    .await
}

async fn upgrade_scenario(
    State(state): State<Arc<AppState>>,
    Path(scenario_id): Path<String>,
    Json(request): Json<UpgradeScenarioRequest>,
) -> Result<Json<EnqueueOperationResponse>, ApiError> {
    ensure_scenario_exists(&state, &scenario_id).await?;
    let operation_id = ids::new_operation_id();
    let staged = state
        .store()
        .stage_scenario_operation(
            &scenario_id,
            &operation_id,
            OperationKind::Upgrade,
            &OperationPayload::Upgrade { request },
            ScenarioStateUpdate::default(),
            now_ms(),
        )
        .await
        .map_err(ApiError::internal)?;
    if !staged {
        return Err(ApiError::conflict(format!(
            "scenario {} already has an operation in progress",
            scenario_id
        )));
    }
    state.wake_worker();
    Ok(Json(EnqueueOperationResponse {
        scenario_id,
        operation_id,
    }))
}

async fn delete_scenario(
    State(state): State<Arc<AppState>>,
    Path(scenario_id): Path<String>,
    Query(query): Query<DeleteScenarioQuery>,
) -> Result<Json<EnqueueOperationResponse>, ApiError> {
    ensure_scenario_exists(&state, &scenario_id).await?;
    ensure_scenario_has_no_active_dependents(&state, &scenario_id).await?;
    let operation_id = ids::new_operation_id();
    let staged = state
        .store()
        .stage_scenario_operation(
            &scenario_id,
            &operation_id,
            OperationKind::Delete,
            &OperationPayload::Delete {
                destroy_storage: query.destroy_storage,
            },
            ScenarioStateUpdate::default(),
            now_ms(),
        )
        .await
        .map_err(ApiError::internal)?;
    if !staged {
        return Err(ApiError::conflict(format!(
            "scenario {} already has an operation in progress",
            scenario_id
        )));
    }
    state.wake_worker();
    Ok(Json(EnqueueOperationResponse {
        scenario_id,
        operation_id,
    }))
}

async fn get_operation(
    State(state): State<Arc<AppState>>,
    Path(operation_id): Path<String>,
) -> Result<Json<OperationStatusResponse>, ApiError> {
    let operation = state
        .store()
        .get_operation(&operation_id)
        .await
        .map_err(ApiError::internal)?
        .ok_or_else(|| ApiError::not_found(format!("operation {} does not exist", operation_id)))?;
    Ok(Json(operation_response(operation)))
}

async fn enqueue_scenario_operation(
    state: &Arc<AppState>,
    scenario_id: &str,
    kind: OperationKind,
    payload: OperationPayload,
    desired_state: Option<DesiredState>,
    observed_state: Option<ObservedState>,
) -> Result<Json<EnqueueOperationResponse>, ApiError> {
    let operation_id = ids::new_operation_id();
    let staged = state
        .store()
        .stage_scenario_operation(
            scenario_id,
            &operation_id,
            kind,
            &payload,
            ScenarioStateUpdate {
                desired_state,
                observed_state,
            },
            now_ms(),
        )
        .await
        .map_err(ApiError::internal)?;
    if !staged {
        return Err(ApiError::conflict(format!(
            "scenario {} already has an operation in progress",
            scenario_id
        )));
    }
    state.wake_worker();
    Ok(Json(EnqueueOperationResponse {
        scenario_id: scenario_id.to_string(),
        operation_id,
    }))
}

async fn ensure_scenario_exists(state: &Arc<AppState>, scenario_id: &str) -> Result<(), ApiError> {
    load_scenario(state, scenario_id).await.map(|_| ())
}

async fn load_scenario(
    state: &Arc<AppState>,
    scenario_id: &str,
) -> Result<crate::store::StoredScenario, ApiError> {
    if let Some(scenario) = state
        .store()
        .load_scenario(scenario_id)
        .await
        .map_err(ApiError::internal)?
    {
        return Ok(scenario);
    }
    Err(ApiError::not_found(format!(
        "scenario {} does not exist",
        scenario_id
    )))
}

async fn ensure_scenario_has_no_active_dependents(
    state: &Arc<AppState>,
    scenario_id: &str,
) -> Result<(), ApiError> {
    let blockers = state
        .store()
        .list_dependency_blockers(scenario_id)
        .await
        .map_err(ApiError::internal)?;
    if blockers.is_empty() {
        return Ok(());
    }
    Err(ApiError::conflict(format!(
        "scenario {} cannot be modified because active scenarios depend on its exports: {}",
        scenario_id,
        blockers.join(", ")
    )))
}

fn secret_paths_from_revision(
    revision: &crate::store::StoredRevision,
) -> Result<Vec<String>, ApiError> {
    let scenario_ir: ScenarioIr =
        serde_json::from_str(&revision.scenario_ir_json).map_err(ApiError::internal)?;
    let Some(root_schema) = root_schema_from_ir(&scenario_ir) else {
        return Ok(Vec::new());
    };
    Ok(collect_leaf_paths(&root_schema)
        .map_err(ApiError::internal)?
        .into_iter()
        .filter(|leaf| leaf.secret)
        .map(|leaf| leaf.path)
        .collect())
}

fn operation_response(operation: StoredOperation) -> OperationStatusResponse {
    OperationStatusResponse {
        operation_id: operation.id,
        scenario_id: operation.scenario_id,
        kind: operation.kind,
        status: operation.status,
        phase: operation.phase,
        retry_count: operation.retry_count,
        backoff_until_ms: operation.backoff_until_ms,
        last_error: operation.last_error,
        created_at_ms: operation.created_at_ms,
        updated_at_ms: operation.updated_at_ms,
        started_at_ms: operation.started_at_ms,
        finished_at_ms: operation.finished_at_ms,
        result: operation.result,
    }
}

fn now_ms() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(i64::MAX)
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: err.to_string(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::CONFLICT,
            message: message.into(),
        }
    }

    fn internal(err: impl std::fmt::Display) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: err.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorResponse {
                error: self.message,
            }),
        )
            .into_response()
    }
}

impl From<StoreError> for ApiError {
    fn from(value: StoreError) -> Self {
        Self::internal(value)
    }
}
