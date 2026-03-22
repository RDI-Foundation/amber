use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Duration,
};

use amber_config::collect_leaf_paths;
use amber_scenario::ScenarioIr;
use rmcp::schemars::{self, JsonSchema};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::time::{Instant, sleep};

use crate::{
    compiler::{inspect_stored_ir, root_schema_from_ir},
    domain::{
        BindableConfigResponse, BindableServiceProviderKind, BindableServiceResponse,
        BindableServiceSourceKind, CreateScenarioRequest, DesiredState, EnqueueOperationResponse,
        ExportPublishRequest, ExportRequest, ExportResponse, ExternalSlotBindingRequest,
        ExternalSlotBindingResponse, ObservedState, OperationKind, OperationPayload,
        OperationStatus, OperationStatusResponse, ScenarioDetailResponse,
        ScenarioRevisionSummaryResponse, ScenarioSummaryResponse, ServiceProtocol,
        UpgradeScenarioRequest,
    },
    ids,
    json::merge_json,
    store::{NewPendingScenario, ScenarioStateUpdate, StoredOperation, StoredScenario},
    worker::AppState,
};

#[derive(Clone, Debug, Default)]
pub struct BindableServiceFilter {
    pub source_kind: Option<BindableServiceSourceKind>,
    pub provider_kind: Option<BindableServiceProviderKind>,
    pub scenario_id: Option<String>,
    pub export: Option<String>,
    pub available: Option<bool>,
}

#[derive(Clone, Debug, Default)]
pub struct ScenarioFilter {
    pub scenario_id: Option<String>,
    pub source_url: Option<String>,
    pub desired_state: Option<DesiredState>,
    pub observed_state: Option<ObservedState>,
    pub active_revision: Option<i64>,
    pub metadata_exact: Option<Map<String, Value>>,
    pub metadata_contains: Option<Map<String, Value>>,
}

#[derive(Clone, Debug, Default)]
pub struct ExportFilter {
    pub scenario_id: Option<String>,
    pub available: Option<bool>,
    pub protocol: Option<ServiceProtocol>,
}

#[derive(Clone, Debug)]
pub enum ExportLookup {
    ScenarioExport { scenario_id: String, export: String },
    BindableServiceId(String),
}

#[derive(Clone, Debug)]
pub enum ScenarioConfigSchemaLookup {
    SourceUrl(String),
    ScenarioId(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ManagerHealthResponse {
    pub ok: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ManagerReadyResponse {
    pub ready: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct OperationWaitResult {
    pub timed_out: bool,
    pub operation: OperationStatusResponse,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ExportDetailResponse {
    pub scenario_id: String,
    pub export: String,
    pub bindable_service_id: String,
    pub available: bool,
    pub protocol: ServiceProtocol,
    #[serde(default)]
    pub publish: Option<ExportPublishRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ExportWaitResult {
    pub timed_out: bool,
    #[serde(default)]
    pub export_detail: Option<ExportDetailResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConfigSchemaExternalSlot {
    pub required: bool,
    pub kind: String,
    pub url_env: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ConfigSchemaExport {
    pub component: String,
    pub provide: String,
    pub protocol: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema)]
pub struct ScenarioConfigSchemaResponse {
    pub source_url: String,
    #[serde(default)]
    pub root_schema: Option<Value>,
    pub secret_root_config_paths: Vec<String>,
    pub external_slots: BTreeMap<String, ConfigSchemaExternalSlot>,
    pub exports: BTreeMap<String, ConfigSchemaExport>,
    #[serde(default)]
    pub examples: Vec<Value>,
}

#[derive(Clone)]
pub struct ManagerService {
    state: Arc<AppState>,
}

impl ManagerService {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub fn health(&self) -> bool {
        true
    }

    pub async fn ready(&self) -> bool {
        self.state.ready().await
    }

    pub async fn list_bindable_services(
        &self,
        filter: BindableServiceFilter,
    ) -> Result<Vec<BindableServiceResponse>, ManagerError> {
        let services = self
            .state
            .bindable_services()
            .await
            .map_err(ManagerError::internal)?;
        Ok(services
            .into_iter()
            .filter(|service| bindable_service_matches(service, &filter))
            .collect())
    }

    pub async fn get_bindable_service(
        &self,
        bindable_service_id: &str,
    ) -> Result<BindableServiceResponse, ManagerError> {
        self.list_bindable_services(BindableServiceFilter::default())
            .await?
            .into_iter()
            .find(|service| service.bindable_service_id == bindable_service_id)
            .ok_or_else(|| {
                ManagerError::not_found(format!(
                    "bindable service {} does not exist",
                    bindable_service_id
                ))
            })
    }

    pub fn list_bindable_configs(&self) -> Vec<BindableConfigResponse> {
        self.state.bindable_configs()
    }

    pub fn get_bindable_config(
        &self,
        bindable_config_id: &str,
    ) -> Result<BindableConfigResponse, ManagerError> {
        self.list_bindable_configs()
            .into_iter()
            .find(|config| config.bindable_config_id == bindable_config_id)
            .ok_or_else(|| {
                ManagerError::not_found(format!(
                    "bindable config {} does not exist",
                    bindable_config_id
                ))
            })
    }

    pub async fn list_scenarios(
        &self,
        filter: ScenarioFilter,
    ) -> Result<Vec<ScenarioSummaryResponse>, ManagerError> {
        let scenarios = self
            .state
            .store()
            .list_scenarios()
            .await
            .map_err(ManagerError::internal)?;
        Ok(scenarios
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
            .filter(|scenario| scenario_matches_filter(scenario, &filter))
            .collect())
    }

    pub async fn create_scenario(
        &self,
        request: CreateScenarioRequest,
    ) -> Result<EnqueueOperationResponse, ManagerError> {
        self.ensure_scenario_source_allowed(&request.source_url)?;
        let request = self.resolve_bindable_create_request(request)?;
        let scenario_id = ids::new_scenario_id();
        let operation_id = ids::new_operation_id();
        let desired_state = if request.start {
            DesiredState::Running
        } else {
            DesiredState::Paused
        };
        let observed_state = if request.start {
            ObservedState::Starting
        } else {
            ObservedState::Paused
        };
        let payload = OperationPayload::Create {
            request: request.clone(),
        };
        let external_slots =
            serde_json::to_value(&request.external_slots).map_err(ManagerError::internal)?;
        let exports = serde_json::to_value(&request.exports).map_err(ManagerError::internal)?;
        let compose_project = ids::compose_project_name(&scenario_id);

        self.state
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
            .map_err(ManagerError::internal)?;
        self.state.wake_worker();

        Ok(EnqueueOperationResponse {
            scenario_id,
            operation_id,
        })
    }

    pub async fn get_scenario(
        &self,
        scenario_id: &str,
    ) -> Result<ScenarioDetailResponse, ManagerError> {
        Ok(self
            .project_scenario(self.load_scenario_row(scenario_id).await?)
            .await?
            .detail)
    }

    pub async fn list_revisions(
        &self,
        scenario_id: &str,
    ) -> Result<Vec<ScenarioRevisionSummaryResponse>, ManagerError> {
        self.ensure_scenario_exists(scenario_id).await?;
        let revisions = self
            .state
            .store()
            .list_revisions(scenario_id)
            .await
            .map_err(ManagerError::internal)?;
        Ok(revisions
            .into_iter()
            .map(|revision| ScenarioRevisionSummaryResponse {
                revision: revision.revision,
                source_url: revision.source_url,
                bundle_stored: revision.bundle_stored,
                created_at_ms: revision.created_at_ms,
            })
            .collect())
    }

    pub async fn pause_scenario(
        &self,
        scenario_id: &str,
    ) -> Result<EnqueueOperationResponse, ManagerError> {
        self.ensure_scenario_exists(scenario_id).await?;
        self.ensure_scenario_has_no_active_dependents(scenario_id)
            .await?;
        self.enqueue_scenario_operation(
            scenario_id,
            OperationKind::Pause,
            OperationPayload::Pause,
            Some(DesiredState::Paused),
            None,
        )
        .await
    }

    pub async fn resume_scenario(
        &self,
        scenario_id: &str,
    ) -> Result<EnqueueOperationResponse, ManagerError> {
        let scenario = self.load_scenario_row(scenario_id).await?;
        if scenario.active_revision.is_none() {
            return Err(ManagerError::bad_request(format!(
                "scenario {} has no active revision to resume",
                scenario_id
            )));
        }
        self.enqueue_scenario_operation(
            scenario_id,
            OperationKind::Resume,
            OperationPayload::Resume,
            Some(DesiredState::Running),
            Some(ObservedState::Starting),
        )
        .await
    }

    pub async fn upgrade_scenario(
        &self,
        scenario_id: &str,
        request: UpgradeScenarioRequest,
    ) -> Result<EnqueueOperationResponse, ManagerError> {
        let scenario = self.load_scenario_row(scenario_id).await?;
        self.ensure_scenario_source_allowed(
            request
                .source_url
                .as_deref()
                .unwrap_or(&scenario.source_url),
        )?;
        let request = self
            .resolve_bindable_upgrade_request(&scenario, request)
            .await?;
        let operation_id = ids::new_operation_id();
        let staged = self
            .state
            .store()
            .stage_scenario_operation(
                scenario_id,
                &operation_id,
                OperationKind::Upgrade,
                &OperationPayload::Upgrade { request },
                ScenarioStateUpdate::default(),
                now_ms(),
            )
            .await
            .map_err(ManagerError::internal)?;
        if !staged {
            return Err(ManagerError::conflict(format!(
                "scenario {} already has an operation in progress",
                scenario_id
            )));
        }
        self.state.wake_worker();
        Ok(EnqueueOperationResponse {
            scenario_id: scenario_id.to_string(),
            operation_id,
        })
    }

    pub async fn delete_scenario(
        &self,
        scenario_id: &str,
        destroy_storage: bool,
    ) -> Result<EnqueueOperationResponse, ManagerError> {
        self.ensure_scenario_exists(scenario_id).await?;
        self.ensure_scenario_has_no_active_dependents(scenario_id)
            .await?;
        let operation_id = ids::new_operation_id();
        let staged = self
            .state
            .store()
            .stage_scenario_operation(
                scenario_id,
                &operation_id,
                OperationKind::Delete,
                &OperationPayload::Delete { destroy_storage },
                ScenarioStateUpdate::default(),
                now_ms(),
            )
            .await
            .map_err(ManagerError::internal)?;
        if !staged {
            return Err(ManagerError::conflict(format!(
                "scenario {} already has an operation in progress",
                scenario_id
            )));
        }
        self.state.wake_worker();
        Ok(EnqueueOperationResponse {
            scenario_id: scenario_id.to_string(),
            operation_id,
        })
    }

    pub async fn get_operation(
        &self,
        operation_id: &str,
    ) -> Result<OperationStatusResponse, ManagerError> {
        let operation = self
            .state
            .store()
            .get_operation(operation_id)
            .await
            .map_err(ManagerError::internal)?
            .ok_or_else(|| {
                ManagerError::not_found(format!("operation {} does not exist", operation_id))
            })?;
        Ok(operation_response(operation))
    }

    pub async fn wait_operation(
        &self,
        operation_id: &str,
        timeout_ms: Option<u64>,
        poll_interval_ms: Option<u64>,
    ) -> Result<OperationWaitResult, ManagerError> {
        let poll_interval = Duration::from_millis(poll_interval_ms.unwrap_or(200).max(1));
        let deadline = wait_deadline(timeout_ms)?;

        loop {
            let operation = self.get_operation(operation_id).await?;
            match operation.status {
                OperationStatus::Succeeded | OperationStatus::Failed => {
                    return Ok(OperationWaitResult {
                        timed_out: false,
                        operation,
                    });
                }
                OperationStatus::Queued | OperationStatus::Running => {
                    if Instant::now() >= deadline {
                        return Ok(OperationWaitResult {
                            timed_out: true,
                            operation,
                        });
                    }
                    sleep(poll_interval).await;
                }
            }
        }
    }

    pub async fn list_exports(
        &self,
        filter: ExportFilter,
    ) -> Result<Vec<ExportDetailResponse>, ManagerError> {
        let scenarios = match filter.scenario_id.as_deref() {
            Some(scenario_id) => vec![self.load_scenario_row(scenario_id).await?],
            None => self
                .state
                .store()
                .list_scenarios()
                .await
                .map_err(ManagerError::internal)?,
        };
        let protocols_by_service_id = self
            .state
            .bindable_services()
            .await
            .map_err(ManagerError::internal)?
            .into_iter()
            .filter(|service| service.source_kind == BindableServiceSourceKind::ScenarioExport)
            .map(|service| (service.bindable_service_id, service.protocol))
            .collect::<BTreeMap<_, _>>();

        let mut exports = Vec::new();
        for scenario in scenarios {
            let projection = self.project_scenario(scenario).await?;
            for export_name in projection.detail.exports.keys() {
                let fallback_protocol = projection
                    .detail
                    .exports
                    .get(export_name)
                    .and_then(|export| export.bindable_service_id.as_ref())
                    .and_then(|bindable_service_id| {
                        protocols_by_service_id.get(bindable_service_id).cloned()
                    });
                let export =
                    export_detail_from_projection(&projection, export_name, fallback_protocol)?;
                if export_matches_filter(&export, &filter) {
                    exports.push(export);
                }
            }
        }

        exports.sort_by(|left, right| {
            left.scenario_id
                .cmp(&right.scenario_id)
                .then(left.export.cmp(&right.export))
        });
        Ok(exports)
    }

    pub async fn get_export(
        &self,
        lookup: ExportLookup,
    ) -> Result<ExportDetailResponse, ManagerError> {
        match lookup {
            ExportLookup::ScenarioExport {
                scenario_id,
                export,
            } => self.get_scenario_export(&scenario_id, &export).await,
            ExportLookup::BindableServiceId(bindable_service_id) => {
                let service = self.get_bindable_service(&bindable_service_id).await?;
                match (service.source_kind, service.scenario_id, service.export) {
                    (
                        BindableServiceSourceKind::ScenarioExport,
                        Some(scenario_id),
                        Some(export),
                    ) => self.get_scenario_export(&scenario_id, &export).await,
                    (BindableServiceSourceKind::ScenarioExport, _, _) => {
                        Err(ManagerError::internal(format!(
                            "bindable service {} is missing scenario export identity",
                            bindable_service_id
                        )))
                    }
                    _ => Err(ManagerError::not_found(format!(
                        "export with bindable service {} does not exist",
                        bindable_service_id
                    ))),
                }
            }
        }
    }

    pub async fn wait_export(
        &self,
        scenario_id: &str,
        export: &str,
        timeout_ms: Option<u64>,
        poll_interval_ms: Option<u64>,
    ) -> Result<ExportWaitResult, ManagerError> {
        let poll_interval = Duration::from_millis(poll_interval_ms.unwrap_or(200).max(1));
        let deadline = wait_deadline(timeout_ms)?;

        loop {
            let detail = self
                .get_export(ExportLookup::ScenarioExport {
                    scenario_id: scenario_id.to_string(),
                    export: export.to_string(),
                })
                .await?;
            if detail.available {
                return Ok(ExportWaitResult {
                    timed_out: false,
                    export_detail: Some(detail),
                });
            }
            if Instant::now() >= deadline {
                return Ok(ExportWaitResult {
                    timed_out: true,
                    export_detail: Some(detail),
                });
            }
            sleep(poll_interval).await;
        }
    }

    pub async fn get_config_schema(
        &self,
        lookup: ScenarioConfigSchemaLookup,
    ) -> Result<ScenarioConfigSchemaResponse, ManagerError> {
        match lookup {
            ScenarioConfigSchemaLookup::SourceUrl(source_url) => {
                let compiled = self
                    .state
                    .scenario_sources()
                    .inspect(&source_url)
                    .await
                    .map_err(ManagerError::bad_request)?;
                build_config_schema_response(source_url, &compiled)
            }
            ScenarioConfigSchemaLookup::ScenarioId(scenario_id) => {
                let scenario = self.load_scenario_row(&scenario_id).await?;
                let source_url = scenario.source_url.clone();
                let compiled = if let Some(revision) = scenario.active_revision {
                    let revision = self
                        .state
                        .store()
                        .load_revision(&scenario_id, revision)
                        .await
                        .map_err(ManagerError::internal)?
                        .ok_or_else(|| {
                            ManagerError::internal(format!(
                                "scenario {} is missing active revision {}",
                                scenario_id, revision
                            ))
                        })?;
                    inspect_stored_ir(&revision.scenario_ir_json).map_err(ManagerError::internal)?
                } else {
                    self.state
                        .scenario_sources()
                        .inspect(&source_url)
                        .await
                        .map_err(ManagerError::bad_request)?
                };
                build_config_schema_response(source_url, &compiled)
            }
        }
    }

    async fn enqueue_scenario_operation(
        &self,
        scenario_id: &str,
        kind: OperationKind,
        payload: OperationPayload,
        desired_state: Option<DesiredState>,
        observed_state: Option<ObservedState>,
    ) -> Result<EnqueueOperationResponse, ManagerError> {
        let operation_id = ids::new_operation_id();
        let staged = self
            .state
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
            .map_err(ManagerError::internal)?;
        if !staged {
            return Err(ManagerError::conflict(format!(
                "scenario {} already has an operation in progress",
                scenario_id
            )));
        }
        self.state.wake_worker();
        Ok(EnqueueOperationResponse {
            scenario_id: scenario_id.to_string(),
            operation_id,
        })
    }

    fn ensure_scenario_source_allowed(&self, source_url: &str) -> Result<(), ManagerError> {
        self.state
            .scenario_sources()
            .preflight(source_url)
            .map_err(ManagerError::bad_request)
    }

    async fn get_scenario_export(
        &self,
        scenario_id: &str,
        export_name: &str,
    ) -> Result<ExportDetailResponse, ManagerError> {
        let projection = self
            .project_scenario(self.load_scenario_row(scenario_id).await?)
            .await?;
        let bindable_service_id = projection
            .detail
            .exports
            .get(export_name)
            .and_then(|export| export.bindable_service_id.as_ref());
        let fallback_protocol = match bindable_service_id {
            Some(bindable_service_id) => self
                .state
                .bindable_services()
                .await
                .map_err(ManagerError::internal)?
                .into_iter()
                .find(|service| service.bindable_service_id == bindable_service_id.as_str())
                .map(|service| service.protocol),
            None => None,
        };
        export_detail_from_projection(&projection, export_name, fallback_protocol).map_err(
            |error| match error.kind {
                ManagerErrorKind::NotFound => ManagerError::not_found(format!(
                    "export {} does not exist for scenario {}",
                    export_name, scenario_id
                )),
                _ => error,
            },
        )
    }

    async fn ensure_scenario_exists(&self, scenario_id: &str) -> Result<(), ManagerError> {
        self.load_scenario_row(scenario_id).await.map(|_| ())
    }

    async fn load_scenario_row(&self, scenario_id: &str) -> Result<StoredScenario, ManagerError> {
        self.state
            .store()
            .load_scenario(scenario_id)
            .await
            .map_err(ManagerError::internal)?
            .ok_or_else(|| {
                ManagerError::not_found(format!("scenario {} does not exist", scenario_id))
            })
    }

    async fn ensure_scenario_has_no_active_dependents(
        &self,
        scenario_id: &str,
    ) -> Result<(), ManagerError> {
        let blockers = self
            .state
            .store()
            .list_dependency_blockers(scenario_id)
            .await
            .map_err(ManagerError::internal)?;
        if blockers.is_empty() {
            return Ok(());
        }
        Err(ManagerError::conflict(format!(
            "scenario {} cannot be modified because active scenarios depend on its exports: {}",
            scenario_id,
            blockers.join(", ")
        )))
    }

    fn resolve_bindable_create_request(
        &self,
        mut request: CreateScenarioRequest,
    ) -> Result<CreateScenarioRequest, ManagerError> {
        request.root_config = self.resolve_external_root_config(
            request.root_config,
            &request.external_root_config,
            JsonPathWriteMode::InsertOnly,
        )?;
        request.external_root_config.clear();
        Ok(request)
    }

    async fn resolve_bindable_upgrade_request(
        &self,
        scenario: &StoredScenario,
        mut request: UpgradeScenarioRequest,
    ) -> Result<UpgradeScenarioRequest, ManagerError> {
        let Some(external_root_config) = request.external_root_config.as_ref() else {
            return Ok(request);
        };
        let (base_root_config, write_mode) = match request.root_config.take() {
            Some(root_config) => (root_config, JsonPathWriteMode::InsertOnly),
            None => {
                let secret_root_config = self
                    .state
                    .store()
                    .load_secret_config(&scenario.id)
                    .await
                    .map_err(ManagerError::internal)?;
                (
                    merge_json(
                        scenario.root_config.clone().unwrap_or_else(|| json!({})),
                        secret_root_config,
                    ),
                    JsonPathWriteMode::OverwriteExisting,
                )
            }
        };
        request.root_config = Some(self.resolve_external_root_config(
            base_root_config,
            external_root_config,
            write_mode,
        )?);
        request.external_root_config = None;
        Ok(request)
    }

    fn resolve_external_root_config(
        &self,
        root_config: Value,
        external_root_config: &BTreeMap<String, String>,
        write_mode: JsonPathWriteMode,
    ) -> Result<Value, ManagerError> {
        if external_root_config.is_empty() {
            return Ok(root_config);
        }

        let mut resolved = if root_config.is_null() {
            json!({})
        } else {
            root_config
        };
        if !resolved.is_object() {
            return Err(ManagerError::bad_request(
                "root_config must be an object when external_root_config is provided",
            ));
        }

        for (path, bindable_config_id) in external_root_config {
            let value = self
                .state
                .bindable_config_value(bindable_config_id)
                .cloned()
                .ok_or_else(|| {
                    ManagerError::bad_request(format!(
                        "bindable config {} does not exist",
                        bindable_config_id
                    ))
                })?;
            write_json_path(&mut resolved, path, value, write_mode)
                .map_err(ManagerError::bad_request)?;
        }

        Ok(resolved)
    }

    async fn project_scenario(
        &self,
        scenario: StoredScenario,
    ) -> Result<ScenarioProjection, ManagerError> {
        let active_revision = scenario.active_revision;
        let active_revision_row = if let Some(revision) = active_revision {
            self.state
                .store()
                .load_revision(&scenario.id, revision)
                .await
                .map_err(ManagerError::internal)?
        } else {
            None
        };
        let compiled = active_revision_row
            .as_ref()
            .map(|revision| inspect_stored_ir(&revision.scenario_ir_json))
            .transpose()
            .map_err(ManagerError::internal)?;
        let dependencies = self
            .state
            .store()
            .list_dependencies_for_consumer(&scenario.id)
            .await
            .map_err(ManagerError::internal)?;
        let export_services = self
            .state
            .store()
            .list_export_services_for_scenario(&scenario.id)
            .await
            .map_err(ManagerError::internal)?
            .into_iter()
            .map(|service| (service.export_name.clone(), service))
            .collect::<BTreeMap<_, _>>();

        let external_slots: BTreeMap<String, ExternalSlotBindingRequest> =
            serde_json::from_value(scenario.external_slots.clone())
                .map_err(ManagerError::internal)?;
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

        let exports: BTreeMap<String, ExportRequest> =
            serde_json::from_value(scenario.exports.clone()).map_err(ManagerError::internal)?;
        let pending_export_protocols = discover_pending_export_protocols(
            self.state.as_ref(),
            &scenario.source_url,
            compiled.is_none(),
            &exports,
        )
        .await;
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
            .unwrap_or_else(|| pending_export_protocols.keys().cloned().collect());
        let exports = export_names
            .into_iter()
            .map(|export_name| {
                let bindable_service_id = ids::export_service_id(&scenario.id, &export_name);
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

        Ok(ScenarioProjection {
            compiled,
            pending_export_protocols,
            detail: ScenarioDetailResponse {
                scenario_id: scenario.id,
                source_url: scenario.source_url,
                active_revision,
                desired_state: scenario.desired_state,
                observed_state: scenario.observed_state,
                metadata: scenario.metadata,
                root_config: if active_revision.is_some() {
                    scenario.root_config.unwrap_or_else(|| json!({}))
                } else {
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
            },
        })
    }
}

struct ScenarioProjection {
    compiled: Option<crate::compiler::CompiledMaterialization>,
    pending_export_protocols: BTreeMap<String, ServiceProtocol>,
    detail: ScenarioDetailResponse,
}

#[derive(Debug)]
pub struct ManagerError {
    kind: ManagerErrorKind,
    message: String,
}

#[derive(Clone, Copy, Debug)]
enum ManagerErrorKind {
    BadRequest,
    NotFound,
    Conflict,
    Internal,
}

impl ManagerError {
    pub fn bad_request(err: impl std::fmt::Display) -> Self {
        Self {
            kind: ManagerErrorKind::BadRequest,
            message: err.to_string(),
        }
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self {
            kind: ManagerErrorKind::NotFound,
            message: message.into(),
        }
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self {
            kind: ManagerErrorKind::Conflict,
            message: message.into(),
        }
    }

    pub fn internal(err: impl std::fmt::Display) -> Self {
        Self {
            kind: ManagerErrorKind::Internal,
            message: err.to_string(),
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn status_code(&self) -> axum::http::StatusCode {
        match self.kind {
            ManagerErrorKind::BadRequest => axum::http::StatusCode::BAD_REQUEST,
            ManagerErrorKind::NotFound => axum::http::StatusCode::NOT_FOUND,
            ManagerErrorKind::Conflict => axum::http::StatusCode::CONFLICT,
            ManagerErrorKind::Internal => axum::http::StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

fn bindable_service_matches(
    service: &BindableServiceResponse,
    filter: &BindableServiceFilter,
) -> bool {
    filter
        .source_kind
        .is_none_or(|source_kind| service.source_kind == source_kind)
        && filter
            .provider_kind
            .is_none_or(|provider_kind| service.provider_kind == provider_kind)
        && filter
            .scenario_id
            .as_deref()
            .is_none_or(|scenario_id| service.scenario_id.as_deref() == Some(scenario_id))
        && filter
            .export
            .as_deref()
            .is_none_or(|export| service.export.as_deref() == Some(export))
        && filter
            .available
            .is_none_or(|available| service.available == available)
}

#[derive(Clone, Copy)]
enum JsonPathWriteMode {
    InsertOnly,
    OverwriteExisting,
}

fn write_json_path(
    root: &mut Value,
    path: &str,
    value: Value,
    mode: JsonPathWriteMode,
) -> Result<(), String> {
    if path.trim().is_empty() {
        return Err("external_root_config path must not be empty".to_string());
    }
    let mut current = root;
    let mut parts = path.split('.').peekable();
    while let Some(part) = parts.next() {
        if part.is_empty() {
            return Err(format!(
                "external_root_config path {path} must not contain empty segments"
            ));
        }
        let is_last = parts.peek().is_none();
        if is_last {
            let map = current.as_object_mut().ok_or_else(|| {
                format!(
                    "external_root_config path {path} conflicts with a non-object root_config \
                     value"
                )
            })?;
            if matches!(mode, JsonPathWriteMode::InsertOnly) && map.contains_key(part) {
                return Err(format!(
                    "root_config path {path} was provided more than once"
                ));
            }
            map.insert(part.to_string(), value);
            return Ok(());
        }

        if current.is_null() {
            *current = Value::Object(Map::new());
        }
        let map = current.as_object_mut().ok_or_else(|| {
            format!(
                "external_root_config path {path} conflicts with a non-object root_config value"
            )
        })?;
        current = map
            .entry(part.to_string())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    Ok(())
}

fn scenario_matches_filter(scenario: &ScenarioSummaryResponse, filter: &ScenarioFilter) -> bool {
    filter
        .scenario_id
        .as_deref()
        .is_none_or(|scenario_id| scenario.scenario_id == scenario_id)
        && filter
            .source_url
            .as_deref()
            .is_none_or(|source_url| scenario.source_url == source_url)
        && filter
            .desired_state
            .is_none_or(|desired_state| scenario.desired_state == desired_state)
        && filter
            .observed_state
            .is_none_or(|observed_state| scenario.observed_state == observed_state)
        && filter
            .active_revision
            .is_none_or(|active_revision| scenario.active_revision == Some(active_revision))
        && metadata_matches_exact(&scenario.metadata, filter.metadata_exact.as_ref())
        && metadata_matches_contains(&scenario.metadata, filter.metadata_contains.as_ref())
}

fn metadata_matches_exact(metadata: &Value, expected: Option<&Map<String, Value>>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(actual) = metadata.as_object() else {
        return false;
    };
    expected
        .iter()
        .all(|(key, value)| actual.get(key).is_some_and(|actual| actual == value))
}

fn metadata_matches_contains(metadata: &Value, expected: Option<&Map<String, Value>>) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Some(actual) = metadata.as_object() else {
        return false;
    };
    expected.iter().all(|(key, value)| {
        actual
            .get(key)
            .is_some_and(|actual_value| value_contains(actual_value, value))
    })
}

fn value_contains(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::String(actual), Value::String(expected)) => actual.contains(expected),
        _ => actual == expected,
    }
}

fn export_matches_filter(export: &ExportDetailResponse, filter: &ExportFilter) -> bool {
    filter
        .scenario_id
        .as_deref()
        .is_none_or(|scenario_id| export.scenario_id == scenario_id)
        && filter
            .available
            .is_none_or(|available| export.available == available)
        && filter
            .protocol
            .is_none_or(|protocol| export.protocol == protocol)
}

fn parse_service_protocol(protocol: &str) -> Option<ServiceProtocol> {
    match protocol {
        "http" => Some(ServiceProtocol::Http),
        "tcp" => Some(ServiceProtocol::Tcp),
        _ => None,
    }
}

const MAX_WAIT_TIMEOUT_MS: u64 = u32::MAX as u64;

fn wait_deadline(timeout_ms: Option<u64>) -> Result<Instant, ManagerError> {
    let timeout_ms = timeout_ms.unwrap_or(30_000);
    if timeout_ms > MAX_WAIT_TIMEOUT_MS {
        return Err(ManagerError::bad_request(format!(
            "timeout_ms {timeout_ms} exceeds the maximum supported timeout of \
             {MAX_WAIT_TIMEOUT_MS}ms"
        )));
    }
    Instant::now()
        .checked_add(Duration::from_millis(timeout_ms))
        .ok_or_else(|| ManagerError::bad_request(format!("timeout_ms {timeout_ms} is too large")))
}

fn compiled_export_protocol(
    projection: &ScenarioProjection,
    export_name: &str,
) -> Option<ServiceProtocol> {
    projection
        .compiled
        .as_ref()
        .and_then(|compiled| compiled.proxy_metadata.exports.get(export_name))
        .and_then(|metadata| parse_service_protocol(&metadata.protocol))
}

fn export_detail_from_projection(
    projection: &ScenarioProjection,
    export_name: &str,
    fallback_protocol: Option<ServiceProtocol>,
) -> Result<ExportDetailResponse, ManagerError> {
    let export = projection.detail.exports.get(export_name).ok_or_else(|| {
        ManagerError::not_found(format!(
            "export {} does not exist for scenario {}",
            export_name, projection.detail.scenario_id
        ))
    })?;
    let bindable_service_id = export.bindable_service_id.clone().ok_or_else(|| {
        ManagerError::internal(format!(
            "export {} for scenario {} is missing bindable service identity",
            export_name, projection.detail.scenario_id
        ))
    })?;
    let protocol = compiled_export_protocol(projection, export_name)
        .or_else(|| {
            projection
                .pending_export_protocols
                .get(export_name)
                .cloned()
        })
        .or(fallback_protocol)
        .ok_or_else(|| {
            ManagerError::internal(format!(
                "export {} for scenario {} is missing protocol metadata",
                export_name, projection.detail.scenario_id
            ))
        })?;
    Ok(ExportDetailResponse {
        scenario_id: projection.detail.scenario_id.clone(),
        export: export_name.to_string(),
        bindable_service_id,
        available: export.available,
        protocol,
        publish: export.publish.clone(),
    })
}

async fn discover_pending_export_protocols(
    state: &AppState,
    source_url: &str,
    needs_discovery: bool,
    requested_exports: &BTreeMap<String, ExportRequest>,
) -> BTreeMap<String, ServiceProtocol> {
    if !needs_discovery || requested_exports.is_empty() {
        return BTreeMap::new();
    }

    let Ok(compiled) = state.scenario_sources().inspect(source_url).await else {
        return BTreeMap::new();
    };
    compiled
        .proxy_metadata
        .exports
        .into_iter()
        .filter_map(|(export_name, export)| {
            parse_service_protocol(&export.protocol).map(|protocol| (export_name, protocol))
        })
        .collect()
}

fn build_config_schema_response(
    source_url: String,
    compiled: &crate::compiler::CompiledMaterialization,
) -> Result<ScenarioConfigSchemaResponse, ManagerError> {
    Ok(ScenarioConfigSchemaResponse {
        source_url,
        root_schema: compiled.root_schema.clone(),
        secret_root_config_paths: secret_paths_from_root_schema(compiled.root_schema.as_ref())?,
        external_slots: compiled
            .proxy_metadata
            .external_slots
            .iter()
            .map(|(name, slot)| {
                (
                    name.clone(),
                    ConfigSchemaExternalSlot {
                        required: slot.required,
                        kind: slot.kind.to_string(),
                        url_env: slot.url_env.clone(),
                    },
                )
            })
            .collect(),
        exports: compiled
            .proxy_metadata
            .exports
            .iter()
            .map(|(name, export)| {
                (
                    name.clone(),
                    ConfigSchemaExport {
                        component: export.component.clone(),
                        provide: export.provide.clone(),
                        protocol: export.protocol.clone(),
                    },
                )
            })
            .collect(),
        examples: Vec::new(),
    })
}

fn secret_paths_from_revision(
    revision: &crate::store::StoredRevision,
) -> Result<Vec<String>, ManagerError> {
    let scenario_ir: ScenarioIr =
        serde_json::from_str(&revision.scenario_ir_json).map_err(ManagerError::internal)?;
    secret_paths_from_root_schema(root_schema_from_ir(&scenario_ir).as_ref())
}

fn secret_paths_from_root_schema(root_schema: Option<&Value>) -> Result<Vec<String>, ManagerError> {
    let Some(root_schema) = root_schema else {
        return Ok(Vec::new());
    };
    Ok(collect_leaf_paths(root_schema)
        .map_err(ManagerError::internal)?
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
