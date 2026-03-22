use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};

use crate::{
    domain::{CreateScenarioRequest, DeleteScenarioQuery, ErrorResponse, UpgradeScenarioRequest},
    service::{BindableServiceFilter, ManagerError, ManagerService, ScenarioFilter},
};

pub fn router(service: Arc<ManagerService>) -> Router {
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
        .with_state(service)
}

async fn healthz() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn readyz(State(service): State<Arc<ManagerService>>) -> impl IntoResponse {
    if service.ready().await {
        return (StatusCode::OK, Json(json!({ "ready": true }))).into_response();
    }
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(json!({ "ready": false })),
    )
        .into_response()
}

async fn list_bindable_services(
    State(service): State<Arc<ManagerService>>,
) -> Result<Json<Vec<crate::domain::BindableServiceResponse>>, ApiError> {
    Ok(Json(
        service
            .list_bindable_services(BindableServiceFilter::default())
            .await?,
    ))
}

async fn list_scenarios(
    State(service): State<Arc<ManagerService>>,
) -> Result<Json<Vec<crate::domain::ScenarioSummaryResponse>>, ApiError> {
    Ok(Json(
        service.list_scenarios(ScenarioFilter::default()).await?,
    ))
}

async fn create_scenario(
    State(service): State<Arc<ManagerService>>,
    Json(request): Json<CreateScenarioRequest>,
) -> Result<Json<crate::domain::EnqueueOperationResponse>, ApiError> {
    Ok(Json(service.create_scenario(request).await?))
}

async fn get_scenario(
    State(service): State<Arc<ManagerService>>,
    Path(scenario_id): Path<String>,
) -> Result<Json<crate::domain::ScenarioDetailResponse>, ApiError> {
    Ok(Json(service.get_scenario(&scenario_id).await?))
}

async fn list_revisions(
    State(service): State<Arc<ManagerService>>,
    Path(scenario_id): Path<String>,
) -> Result<Json<Vec<crate::domain::ScenarioRevisionSummaryResponse>>, ApiError> {
    Ok(Json(service.list_revisions(&scenario_id).await?))
}

async fn pause_scenario(
    State(service): State<Arc<ManagerService>>,
    Path(scenario_id): Path<String>,
) -> Result<Json<crate::domain::EnqueueOperationResponse>, ApiError> {
    Ok(Json(service.pause_scenario(&scenario_id).await?))
}

async fn resume_scenario(
    State(service): State<Arc<ManagerService>>,
    Path(scenario_id): Path<String>,
) -> Result<Json<crate::domain::EnqueueOperationResponse>, ApiError> {
    Ok(Json(service.resume_scenario(&scenario_id).await?))
}

async fn upgrade_scenario(
    State(service): State<Arc<ManagerService>>,
    Path(scenario_id): Path<String>,
    Json(request): Json<UpgradeScenarioRequest>,
) -> Result<Json<crate::domain::EnqueueOperationResponse>, ApiError> {
    Ok(Json(service.upgrade_scenario(&scenario_id, request).await?))
}

async fn delete_scenario(
    State(service): State<Arc<ManagerService>>,
    Path(scenario_id): Path<String>,
    Query(query): Query<DeleteScenarioQuery>,
) -> Result<Json<crate::domain::EnqueueOperationResponse>, ApiError> {
    Ok(Json(
        service
            .delete_scenario(&scenario_id, query.destroy_storage)
            .await?,
    ))
}

async fn get_operation(
    State(service): State<Arc<ManagerService>>,
    Path(operation_id): Path<String>,
) -> Result<Json<crate::domain::OperationStatusResponse>, ApiError> {
    Ok(Json(service.get_operation(&operation_id).await?))
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl From<ManagerError> for ApiError {
    fn from(error: ManagerError) -> Self {
        Self {
            status: error.status_code(),
            message: error.message().to_string(),
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
