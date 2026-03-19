use std::collections::BTreeMap;

use serde_json::{Value, json};
use tracing::{error, warn};

use super::{
    OperationWorker,
    bindings::export_topology_changed,
    errors::{
        OperationError, backoff_ms, classify_create_compile_error,
        classify_reconcile_compile_error, classify_upgrade_compile_error, invalid_error,
        invalid_scenario_error, now_ms, retryable_error,
    },
};
use crate::{
    compiler::{self, CompiledMaterialization},
    domain::{
        CreateScenarioRequest, DesiredState, ExportRequest, ExternalSlotBindingRequest,
        ObservedState, ScenarioTelemetryRequest, UpgradeScenarioRequest,
    },
    runtime::RunningScenarioSpec,
    store::{
        ClaimedScenarioWork, NewScenarioRevision, ScenarioRevisionApplication, StoredOperation,
        StoredRevision, StoredScenario,
    },
};

impl OperationWorker {
    pub(super) async fn handle_create(
        &self,
        scenario_id: &str,
        request: &CreateScenarioRequest,
    ) -> Result<Option<Value>, OperationError> {
        let scenario = self.load_scenario(scenario_id).await?;
        let revision = self
            .state
            .store
            .next_revision_number(scenario_id)
            .await
            .map_err(retryable_error)?;
        let revision_dir = self.state.runtime.revision_dir(scenario_id, revision);
        let bundle_dir = request.store_bundle.then(|| revision_dir.join("bundle"));
        let compiled = compiler::compile_create(request, bundle_dir.as_deref())
            .await
            .map_err(classify_create_compile_error)?;
        let bindings = self
            .prepare_bindings(
                scenario_id,
                &compiled,
                &request.external_slots,
                &request.exports,
                &BTreeMap::new(),
                true,
            )
            .await?;
        let desired_state = if request.start {
            DesiredState::Running
        } else {
            DesiredState::Paused
        };

        self.persist_revision(
            &scenario,
            revision,
            &compiled,
            PersistedRevisionInputs {
                source_url: &request.source_url,
                metadata: &request.metadata,
                telemetry: &request.telemetry,
                external_slots: &request.external_slots,
                exports: &request.exports,
            },
            desired_state,
            &bindings.dependencies,
        )
        .await?;

        if desired_state == DesiredState::Running {
            self.reconcile_running(&scenario.id).await?;
        } else {
            self.apply_paused_state(&scenario.id).await?;
        }

        Ok(Some(json!({
            "scenario_id": scenario_id,
            "revision": revision,
        })))
    }

    pub(super) async fn handle_pause(
        &self,
        scenario_id: &str,
    ) -> Result<Option<Value>, OperationError> {
        let scenario = self.load_scenario(scenario_id).await?;
        self.ensure_provider_not_required(&scenario.id).await?;
        self.state
            .store
            .set_scenario_states(
                &scenario.id,
                DesiredState::Paused,
                ObservedState::Paused,
                None,
                now_ms(),
            )
            .await
            .map_err(retryable_error)?;
        self.apply_paused_state(&scenario.id).await?;
        Ok(Some(json!({
            "scenario_id": scenario.id,
            "state": "paused",
        })))
    }

    pub(super) async fn handle_resume(
        &self,
        scenario_id: &str,
    ) -> Result<Option<Value>, OperationError> {
        let scenario = self.load_scenario(scenario_id).await?;
        if scenario.active_revision.is_none() {
            return Err(invalid_scenario_error(format!(
                "scenario {} has no active revision to resume",
                scenario.id
            )));
        }
        self.state
            .store
            .set_scenario_states(
                &scenario.id,
                DesiredState::Running,
                ObservedState::Starting,
                None,
                now_ms(),
            )
            .await
            .map_err(retryable_error)?;
        self.reconcile_running(&scenario.id).await?;
        Ok(Some(json!({
            "scenario_id": scenario.id,
            "state": "running",
        })))
    }

    pub(super) async fn handle_upgrade(
        &self,
        scenario_id: &str,
        request: &UpgradeScenarioRequest,
    ) -> Result<Option<Value>, OperationError> {
        let scenario = self.load_scenario(scenario_id).await?;
        let resolved = self.resolve_upgrade_request(&scenario, request).await?;
        let revision = self
            .state
            .store
            .next_revision_number(&scenario.id)
            .await
            .map_err(retryable_error)?;
        let revision_dir = self.state.runtime.revision_dir(&scenario.id, revision);
        let bundle_dir = request.store_bundle.then(|| revision_dir.join("bundle"));
        let compiled = compiler::compile_upgrade(
            &resolved.source_url,
            &resolved.root_config,
            &resolved.external_slots,
            &resolved.exports,
            request.store_bundle,
            bundle_dir.as_deref(),
        )
        .await
        .map_err(classify_upgrade_compile_error)?;

        self.ensure_export_change_is_safe(&scenario.id, &compiled)
            .await?;
        let bindings = self
            .prepare_bindings(
                &scenario.id,
                &compiled,
                &resolved.external_slots,
                &resolved.exports,
                &BTreeMap::new(),
                true,
            )
            .await?;

        self.persist_revision(
            &scenario,
            revision,
            &compiled,
            PersistedRevisionInputs {
                source_url: &resolved.source_url,
                metadata: &resolved.metadata,
                telemetry: &resolved.telemetry,
                external_slots: &resolved.external_slots,
                exports: &resolved.exports,
            },
            scenario.desired_state,
            &bindings.dependencies,
        )
        .await?;

        if scenario.desired_state == DesiredState::Running {
            self.reconcile_running(&scenario.id).await?;
        } else {
            self.apply_paused_state(&scenario.id).await?;
        }

        Ok(Some(json!({
            "scenario_id": scenario.id,
            "revision": revision,
        })))
    }

    pub(super) async fn handle_delete(
        &self,
        scenario_id: &str,
        destroy_storage: bool,
    ) -> Result<Option<Value>, OperationError> {
        let scenario = self.load_scenario(scenario_id).await?;
        self.ensure_provider_not_required(&scenario.id).await?;
        if let Some(revision) = scenario.active_revision {
            let compose_dir = self.state.runtime.runtime_dir(&scenario.id, revision);
            self.state
                .runtime
                .stop_scenario(
                    &scenario.id,
                    &compose_dir,
                    &scenario.compose_project,
                    destroy_storage,
                )
                .await
                .map_err(retryable_error)?;
        } else {
            self.state.runtime.stop_proxy(&scenario.id).await;
        }
        self.state
            .runtime
            .purge_scenario_state(&scenario.id)
            .await
            .map_err(retryable_error)?;
        self.state
            .store
            .delete_scenario(&scenario.id)
            .await
            .map_err(retryable_error)?;
        Ok(Some(json!({
            "scenario_id": scenario.id,
            "deleted": true,
        })))
    }

    pub(super) async fn handle_reconcile(
        &self,
        scenario_id: &str,
    ) -> Result<Option<Value>, OperationError> {
        let Some(scenario) = self
            .state
            .store
            .load_scenario(scenario_id)
            .await
            .map_err(retryable_error)?
        else {
            return Ok(Some(json!({
                "scenario_id": scenario_id,
                "deleted": true,
            })));
        };

        match scenario.desired_state {
            DesiredState::Running => self.reconcile_running(&scenario.id).await,
            DesiredState::Paused => {
                self.apply_paused_state(&scenario.id).await?;
                Ok(Some(json!({
                    "scenario_id": scenario.id,
                    "state": "paused",
                })))
            }
        }
    }

    async fn persist_revision(
        &self,
        scenario: &StoredScenario,
        revision: i64,
        compiled: &CompiledMaterialization,
        inputs: PersistedRevisionInputs<'_>,
        desired_state: DesiredState,
        dependencies: &[crate::store::NewDependency],
    ) -> Result<(), OperationError> {
        let external_slots =
            serde_json::to_value(inputs.external_slots).map_err(retryable_error)?;
        let exports = serde_json::to_value(inputs.exports).map_err(retryable_error)?;
        let bundle_root = compiled
            .bundle_root
            .as_ref()
            .map(|path| path.display().to_string());
        let now = now_ms();

        self.state
            .store
            .persist_revision_state(
                NewScenarioRevision {
                    scenario_id: &scenario.id,
                    revision,
                    source_url: inputs.source_url,
                    scenario_ir_json: &compiled.scenario_ir_json,
                    bundle_root: bundle_root.as_deref(),
                    ir_version: i64::from(compiled.scenario_ir.version),
                    created_at_ms: now,
                },
                ScenarioRevisionApplication {
                    scenario_id: &scenario.id,
                    source_url: inputs.source_url,
                    revision,
                    metadata: inputs.metadata,
                    root_config: &compiled.non_secret_root_config,
                    secret_config: &compiled.secret_root_config,
                    telemetry: inputs.telemetry,
                    external_slots: &external_slots,
                    exports: &exports,
                    desired_state,
                    observed_state: if desired_state == DesiredState::Running {
                        ObservedState::Starting
                    } else {
                        ObservedState::Paused
                    },
                    last_error: None,
                    now_ms: now,
                },
                dependencies,
            )
            .await
            .map_err(retryable_error)?;
        Ok(())
    }

    async fn resolve_upgrade_request(
        &self,
        scenario: &StoredScenario,
        request: &UpgradeScenarioRequest,
    ) -> Result<ResolvedUpgradeRequest, OperationError> {
        let root_config = match request.root_config.clone() {
            Some(root_config) => root_config,
            None => {
                let secret_root_config = self
                    .state
                    .store
                    .load_secret_config(&scenario.id)
                    .await
                    .map_err(retryable_error)?;
                merge_json_values(
                    scenario.root_config.clone().unwrap_or_else(empty_object),
                    secret_root_config,
                )
            }
        };
        Ok(ResolvedUpgradeRequest {
            source_url: request
                .source_url
                .clone()
                .unwrap_or_else(|| scenario.source_url.clone()),
            metadata: request
                .metadata
                .clone()
                .unwrap_or_else(|| scenario.metadata.clone()),
            root_config,
            telemetry: request
                .telemetry
                .clone()
                .unwrap_or_else(|| scenario.telemetry.clone()),
            external_slots: request
                .external_slots
                .clone()
                .map(Ok)
                .unwrap_or_else(|| decode_external_slots(&scenario.external_slots))?,
            exports: request
                .exports
                .clone()
                .map(Ok)
                .unwrap_or_else(|| decode_exports(&scenario.exports))?,
        })
    }

    async fn reconcile_running(&self, scenario_id: &str) -> Result<Option<Value>, OperationError> {
        let scenario = self.load_scenario(scenario_id).await?;
        let revision = scenario.active_revision.ok_or_else(|| {
            invalid_scenario_error(format!("scenario {} has no active revision", scenario_id))
        })?;
        let (compiled, stored_revision) = self
            .load_runtime_materialization(&scenario, revision)
            .await?;
        let external_slots = decode_external_slots(&scenario.external_slots)?;
        let exports = decode_exports(&scenario.exports)?;
        let dependency_hints = self
            .state
            .store
            .list_dependencies()
            .await
            .map_err(retryable_error)?
            .into_iter()
            .filter(|dependency| dependency.consumer_scenario_id == scenario_id)
            .map(|dependency| {
                (
                    dependency.bindable_service_id.clone(),
                    dependency.provider_scenario_id.clone(),
                )
            })
            .collect::<BTreeMap<_, _>>();
        let bindings = self
            .prepare_bindings(
                scenario_id,
                &compiled,
                &external_slots,
                &exports,
                &dependency_hints,
                false,
            )
            .await?;
        let export_topology_changed = export_topology_changed(
            &self.current_export_services(&scenario.id).await?,
            &bindings.export_services,
        );

        let telemetry = scenario.telemetry.clone();
        let runtime_input = compiler::build_runtime_input(
            &compiled,
            &telemetry,
            &bindings.direct_slot_urls,
            &bindings.slot_proxy_bindings,
            &bindings.export_bindings,
        )
        .map_err(classify_reconcile_compile_error)?;
        let runtime_dir = self.state.runtime.runtime_dir(&scenario.id, revision);
        compiler::write_runtime_output(
            &runtime_dir,
            &compiled.compose_files,
            &runtime_input.env_contents,
        )
        .map_err(classify_reconcile_compile_error)?;
        let spec = RunningScenarioSpec::new(
            &scenario.id,
            &scenario.compose_project,
            runtime_dir,
            runtime_input.proxy_plan,
        );
        self.state
            .runtime
            .apply_running_state(&spec)
            .await
            .map_err(retryable_error)?;
        let now = now_ms();
        self.state
            .store
            .set_export_services(&scenario.id, &bindings.export_services, now)
            .await
            .map_err(retryable_error)?;
        self.state
            .store
            .set_scenario_states(
                &scenario.id,
                DesiredState::Running,
                ObservedState::Running,
                None,
                now,
            )
            .await
            .map_err(retryable_error)?;
        if export_topology_changed {
            self.enqueue_dependent_reconciles(&scenario.id).await;
        }

        Ok(Some(json!({
            "scenario_id": scenario.id,
            "revision": revision,
            "state": "running",
            "ir_version": stored_revision.ir_version,
        })))
    }

    async fn apply_paused_state(&self, scenario_id: &str) -> Result<(), OperationError> {
        let scenario = self.load_scenario(scenario_id).await?;
        if let Some(revision) = scenario.active_revision {
            let compose_dir = self.state.runtime.runtime_dir(&scenario.id, revision);
            self.state
                .runtime
                .stop_scenario(&scenario.id, &compose_dir, &scenario.compose_project, false)
                .await
                .map_err(retryable_error)?;
        } else {
            self.state.runtime.stop_proxy(&scenario.id).await;
        }
        self.state
            .store
            .clear_export_services(&scenario.id)
            .await
            .map_err(retryable_error)?;
        self.state
            .store
            .set_scenario_states(
                &scenario.id,
                DesiredState::Paused,
                ObservedState::Paused,
                None,
                now_ms(),
            )
            .await
            .map_err(retryable_error)?;
        Ok(())
    }

    async fn load_runtime_materialization(
        &self,
        scenario: &StoredScenario,
        revision: i64,
    ) -> Result<(CompiledMaterialization, StoredRevision), OperationError> {
        let stored_revision = self
            .state
            .store
            .load_revision(&scenario.id, revision)
            .await
            .map_err(retryable_error)?
            .ok_or_else(|| {
                invalid_scenario_error(format!(
                    "scenario {} is missing stored revision {}",
                    scenario.id, revision
                ))
            })?;
        let secret_root_config = self
            .state
            .store
            .load_secret_config(&scenario.id)
            .await
            .map_err(retryable_error)?;
        let compiled = compiler::materialize_runtime_from_stored_ir(
            &stored_revision.scenario_ir_json,
            scenario.root_config.clone().unwrap_or_else(empty_object),
            secret_root_config,
        )
        .map_err(classify_reconcile_compile_error)?;
        Ok((compiled, stored_revision))
    }

    pub(super) async fn handle_work_error(
        &self,
        work: &ClaimedScenarioWork,
        operation: Option<&StoredOperation>,
        err: OperationError,
    ) {
        let now = now_ms();
        if err.cleanup_runtime {
            self.cleanup_runtime(&work.scenario_id).await;
        }

        let current_retry = match operation {
            Some(operation) => operation.retry_count,
            None => match self.state.store.load_scenario(&work.scenario_id).await {
                Ok(Some(scenario)) => scenario.failure_count,
                Ok(None) => 0,
                Err(store_err) => {
                    error!(
                        "failed to load scenario {} retry state after work failure: {}",
                        work.scenario_id, store_err
                    );
                    0
                }
            },
        };
        let next_retry = current_retry.saturating_add(1);

        if err.retryable && next_retry <= self.state.config.max_restart_attempts() {
            let backoff_until =
                now.saturating_add(backoff_ms(self.state.config.base_backoff_ms(), next_retry));
            if let Some(observed_state) = err.observed_state {
                self.retry_store_until_ok(
                    || async {
                        self.state
                            .store
                            .set_scenario_retry_state(
                                &work.scenario_id,
                                observed_state,
                                next_retry,
                                Some(backoff_until),
                                &err.message,
                                now,
                            )
                            .await
                    },
                    &format!("set scenario retry state for {}", work.scenario_id),
                )
                .await;
            } else {
                self.retry_store_until_ok(
                    || async {
                        self.state
                            .store
                            .set_scenario_backoff(&work.scenario_id, next_retry, backoff_until, now)
                            .await
                    },
                    &format!("set scenario backoff for {}", work.scenario_id),
                )
                .await;
            }
            self.retry_store_until_ok(
                || async {
                    self.state
                        .store
                        .release_work_for_retry(&work.scenario_id, now)
                        .await
                },
                &format!("release scenario work for retry on {}", work.scenario_id),
            )
            .await;

            if let Some(operation) = operation
                && let Err(store_err) = self
                    .state
                    .store
                    .reschedule_operation(
                        &operation.id,
                        next_retry,
                        "backing_off",
                        backoff_until,
                        &err.message,
                        now,
                    )
                    .await
            {
                error!(
                    "failed to reschedule operation {}: {}",
                    operation.id, store_err
                );
            }
            return;
        }

        if err.affects_scenario {
            let observed_state = err.observed_state.unwrap_or(ObservedState::Failed);
            if err.retryable {
                self.retry_store_until_ok(
                    || async {
                        self.state
                            .store
                            .set_scenario_retry_state(
                                &work.scenario_id,
                                observed_state,
                                next_retry,
                                None,
                                &err.message,
                                now,
                            )
                            .await
                    },
                    &format!("set final scenario retry state for {}", work.scenario_id),
                )
                .await;
            } else {
                self.retry_store_until_ok(
                    || async {
                        self.state
                            .store
                            .set_observed_state(
                                &work.scenario_id,
                                observed_state,
                                Some(&err.message),
                                now,
                            )
                            .await
                    },
                    &format!("set final scenario state for {}", work.scenario_id),
                )
                .await;
            }
        } else {
            self.retry_store_until_ok(
                || async {
                    self.state
                        .store
                        .clear_scenario_backoff(&work.scenario_id, now)
                        .await
                },
                &format!("clear scenario backoff for {}", work.scenario_id),
            )
            .await;
        }

        self.retry_store_until_ok(
            || async {
                self.state
                    .store
                    .complete_scenario_work(&work.scenario_id, work.generation, now)
                    .await
            },
            &format!("complete failed scenario work for {}", work.scenario_id),
        )
        .await;

        if let Some(operation) = operation
            && let Err(store_err) = self
                .state
                .store
                .mark_operation_failed(&operation.id, &err.message, now)
                .await
        {
            error!(
                "failed to mark operation {} failed: {}",
                operation.id, store_err
            );
        }
    }

    pub(super) async fn cleanup_runtime(&self, scenario_id: &str) {
        let scenario = match self.state.store.load_scenario(scenario_id).await {
            Ok(Some(scenario)) => scenario,
            Ok(None) => return,
            Err(err) => {
                warn!(
                    "failed to load scenario {} for cleanup: {}",
                    scenario_id, err
                );
                return;
            }
        };

        let mut runtime_stopped = false;
        if let Some(revision) = scenario.active_revision {
            let compose_dir = self.state.runtime.runtime_dir(scenario_id, revision);
            if let Err(err) = self
                .state
                .runtime
                .stop_scenario(scenario_id, &compose_dir, &scenario.compose_project, false)
                .await
            {
                warn!(
                    "failed to clean up scenario {} after failure: {}",
                    scenario_id, err
                );
            } else {
                runtime_stopped = true;
            }
        } else {
            self.state.runtime.stop_proxy(scenario_id).await;
            runtime_stopped = true;
        }

        if runtime_stopped
            && let Err(err) = self
                .state
                .store
                .set_export_services_available(scenario_id, false, now_ms())
                .await
        {
            warn!(
                "failed to mark export services unavailable for {} after cleanup: {}",
                scenario_id, err
            );
        }
    }

    async fn load_scenario(&self, scenario_id: &str) -> Result<StoredScenario, OperationError> {
        self.state
            .store
            .load_scenario(scenario_id)
            .await
            .map_err(retryable_error)?
            .ok_or_else(|| invalid_error(format!("scenario {} does not exist", scenario_id)))
    }
}

fn empty_object() -> Value {
    json!({})
}

#[derive(Clone, Debug)]
struct ResolvedUpgradeRequest {
    source_url: String,
    metadata: Value,
    root_config: Value,
    telemetry: ScenarioTelemetryRequest,
    external_slots: BTreeMap<String, ExternalSlotBindingRequest>,
    exports: BTreeMap<String, ExportRequest>,
}

struct PersistedRevisionInputs<'a> {
    source_url: &'a str,
    metadata: &'a Value,
    telemetry: &'a ScenarioTelemetryRequest,
    external_slots: &'a BTreeMap<String, ExternalSlotBindingRequest>,
    exports: &'a BTreeMap<String, ExportRequest>,
}

fn decode_external_slots(
    value: &Value,
) -> Result<BTreeMap<String, ExternalSlotBindingRequest>, OperationError> {
    serde_json::from_value(value.clone()).map_err(|err| invalid_scenario_error(err.to_string()))
}

fn decode_exports(value: &Value) -> Result<BTreeMap<String, ExportRequest>, OperationError> {
    serde_json::from_value(value.clone()).map_err(|err| invalid_scenario_error(err.to_string()))
}

fn merge_json_values(mut left: Value, right: Value) -> Value {
    merge_json_value(&mut left, right);
    left
}

fn merge_json_value(left: &mut Value, right: Value) {
    match (left, right) {
        (Value::Object(left_obj), Value::Object(right_obj)) => {
            for (key, value) in right_obj {
                merge_json_value(left_obj.entry(key).or_insert(Value::Null), value);
            }
        }
        (slot, value) => *slot = value,
    }
}
