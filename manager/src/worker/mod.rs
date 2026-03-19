mod bindings;
mod errors;
mod graph;
mod lifecycle;
mod monitor;
#[cfg(test)]
mod tests;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

pub use monitor::HealthMonitor;
use serde_json::{Value, json};
use tokio::{sync::Notify, time::timeout};
use tracing::{error, info};

use self::{
    bindings::{build_operator_services, parse_protocol},
    errors::{OperationError, now_ms},
    graph::topological_order,
};
use crate::{
    ManagerConfig,
    compiler::{ExportRuntimeBinding, SlotRuntimeBinding},
    config::{ConfigError, ManagerFileConfig, OperatorServiceProvider},
    domain::{
        BindableServiceProviderKind, BindableServiceResponse, BindableServiceSourceKind,
        OperationKind, OperationPayload, ServiceProtocol,
    },
    runtime::RuntimeSupervisor,
    store::{NewDependency, NewExportService, Store, StoreError, StoredOperation},
};

pub(super) const IDLE_WAIT: Duration = Duration::from_millis(250);
pub(super) const HEALTH_MONITOR_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Debug)]
pub struct AppState {
    config: ManagerConfig,
    store: Store,
    runtime: RuntimeSupervisor,
    notify: Arc<Notify>,
    operator_services: BTreeMap<String, OperatorBindableService>,
}

impl AppState {
    pub fn new(
        config: ManagerConfig,
        file_config: ManagerFileConfig,
        store: Store,
        runtime: RuntimeSupervisor,
        notify: Arc<Notify>,
    ) -> Result<Self, ConfigError> {
        let operator_services = build_operator_services(file_config)?;
        Ok(Self {
            config,
            store,
            runtime,
            notify,
            operator_services,
        })
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    pub fn wake_worker(&self) {
        self.notify.notify_one();
    }

    pub async fn ready(&self) -> bool {
        self.store.list_scenarios().await.is_ok()
    }

    pub async fn bindable_services(&self) -> Result<Vec<BindableServiceResponse>, StoreError> {
        let mut services = self
            .operator_services
            .values()
            .map(|service| service.response())
            .collect::<Vec<_>>();
        for service in self.store.list_export_services().await? {
            let protocol =
                parse_protocol(&service.protocol).map_err(|err| StoreError::InvalidEnum {
                    kind: "scenario_export_services.protocol",
                    value: err.message,
                })?;
            services.push(BindableServiceResponse {
                bindable_service_id: service.service_id,
                source_kind: BindableServiceSourceKind::ScenarioExport,
                provider_kind: BindableServiceProviderKind::ScenarioExport,
                display_name: Some(format!("{}:{}", service.scenario_id, service.export_name)),
                protocol,
                available: service.available,
                scenario_id: Some(service.scenario_id),
                export: Some(service.export_name),
            });
        }
        services.sort_by(|left, right| left.bindable_service_id.cmp(&right.bindable_service_id));
        Ok(services)
    }
}

#[derive(Clone, Debug)]
pub struct OperationWorker {
    state: Arc<AppState>,
}

impl OperationWorker {
    pub fn new(state: Arc<AppState>) -> Self {
        Self { state }
    }

    pub async fn enqueue_startup_reconciles(&self) {
        let now_ms = now_ms();
        self.recover_interrupted_operations(now_ms).await;

        let scenarios = match self.state.store.list_scenarios().await {
            Ok(scenarios) => scenarios,
            Err(err) => {
                error!("failed to list scenarios for startup reconcile: {err}");
                return;
            }
        };
        let dependencies = match self.state.store.list_dependencies().await {
            Ok(dependencies) => dependencies,
            Err(err) => {
                error!("failed to list dependencies for startup reconcile: {err}");
                return;
            }
        };

        for scenario_id in topological_order(&scenarios, &dependencies) {
            let Some(scenario) = scenarios.iter().find(|scenario| scenario.id == scenario_id)
            else {
                continue;
            };
            if scenario.active_revision.is_none() {
                continue;
            }
            match self.state.store.has_inflight_operation(&scenario.id).await {
                Ok(true) => continue,
                Ok(false) => {}
                Err(err) => {
                    error!(
                        "failed to check inflight operation for {} during startup reconcile: {err}",
                        scenario.id
                    );
                    continue;
                }
            }
            if let Err(err) = self
                .state
                .store
                .enqueue_reconcile_if_absent(&scenario.id, false, now_ms)
                .await
            {
                error!(
                    "failed to enqueue startup reconcile for {}: {err}",
                    scenario.id
                );
            }
        }
        self.state.wake_worker();
    }

    async fn recover_interrupted_operations(&self, now_ms: i64) {
        let operations = match self.state.store.list_running_operations().await {
            Ok(operations) => operations,
            Err(err) => {
                error!("failed to list interrupted operations after manager restart: {err}");
                return;
            }
        };
        for operation in operations {
            if let Err(err) = self.recover_interrupted_operation(&operation, now_ms).await {
                error!(
                    "failed to recover interrupted {} operation {}: {}",
                    operation.kind.as_str(),
                    operation.id,
                    err
                );
            }
        }
    }

    async fn recover_interrupted_operation(
        &self,
        operation: &StoredOperation,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let scenario = match operation.scenario_id.as_deref() {
            Some(scenario_id) => self.state.store.load_scenario(scenario_id).await?,
            None => None,
        };
        let restart_message = restart_interrupted_operation_message(operation.kind);

        match operation.kind {
            OperationKind::Create => {
                if scenario
                    .as_ref()
                    .is_some_and(|scenario| scenario.active_revision.is_none())
                {
                    self.state
                        .store
                        .reschedule_operation(
                            &operation.id,
                            operation.retry_count,
                            "requeued_after_manager_restart",
                            now_ms,
                            restart_message,
                            now_ms,
                        )
                        .await?;
                    info!(
                        "requeued interrupted create operation {} after manager restart",
                        operation.id
                    );
                } else {
                    self.state
                        .store
                        .mark_operation_failed(&operation.id, restart_message, now_ms)
                        .await?;
                    info!(
                        "failed interrupted create operation {} after manager restart",
                        operation.id
                    );
                }
            }
            OperationKind::Pause
            | OperationKind::Resume
            | OperationKind::Reconcile
            | OperationKind::Delete => {
                let Some(scenario_id) = operation.scenario_id.as_deref() else {
                    self.state
                        .store
                        .mark_operation_failed(&operation.id, restart_message, now_ms)
                        .await?;
                    return Ok(());
                };

                if scenario.is_some() {
                    self.state
                        .store
                        .reschedule_operation(
                            &operation.id,
                            operation.retry_count,
                            "requeued_after_manager_restart",
                            now_ms,
                            restart_message,
                            now_ms,
                        )
                        .await?;
                    info!(
                        "requeued interrupted {} operation {} after manager restart",
                        operation.kind.as_str(),
                        operation.id
                    );
                } else if matches!(
                    operation.kind,
                    OperationKind::Delete | OperationKind::Reconcile
                ) {
                    let result = json!({
                        "scenario_id": scenario_id,
                        "deleted": true,
                    });
                    self.state
                        .store
                        .mark_operation_succeeded(&operation.id, Some(&result), now_ms)
                        .await?;
                    info!(
                        "completed interrupted {} operation {} after manager restart",
                        operation.kind.as_str(),
                        operation.id
                    );
                } else {
                    self.state
                        .store
                        .mark_operation_failed(&operation.id, restart_message, now_ms)
                        .await?;
                    info!(
                        "failed interrupted {} operation {} after manager restart",
                        operation.kind.as_str(),
                        operation.id
                    );
                }
            }
            OperationKind::Upgrade => {
                self.state
                    .store
                    .mark_operation_failed(&operation.id, restart_message, now_ms)
                    .await?;
                info!(
                    "failed interrupted upgrade operation {} after manager restart",
                    operation.id
                );
            }
        }

        Ok(())
    }

    pub async fn run(self) {
        loop {
            match self.state.store.claim_next_operation(now_ms()).await {
                Ok(Some(operation)) => self.process_claimed_operation(operation).await,
                Ok(None) => {
                    let _ = timeout(IDLE_WAIT, self.state.notify.notified()).await;
                }
                Err(err) => {
                    error!("failed to claim operation: {err}");
                    tokio::time::sleep(IDLE_WAIT).await;
                }
            }
        }
    }

    async fn process_claimed_operation(&self, operation: StoredOperation) {
        let result = self.process_operation(&operation).await;
        match result {
            Ok(result) => {
                if let Err(err) = self
                    .state
                    .store
                    .mark_operation_succeeded(&operation.id, result.as_ref(), now_ms())
                    .await
                {
                    error!("failed to mark operation {} succeeded: {err}", operation.id);
                }
            }
            Err(err) => self.handle_operation_error(&operation, err).await,
        }
    }

    async fn process_operation(
        &self,
        operation: &StoredOperation,
    ) -> Result<Option<Value>, OperationError> {
        match &operation.payload {
            OperationPayload::Create { request } => self.handle_create(operation, request).await,
            OperationPayload::Pause => self.handle_pause(operation).await,
            OperationPayload::Resume => self.handle_resume(operation).await,
            OperationPayload::Upgrade { request } => self.handle_upgrade(operation, request).await,
            OperationPayload::Delete { destroy_storage } => {
                self.handle_delete(operation, *destroy_storage).await
            }
            OperationPayload::Reconcile { cleanup_runtime } => {
                self.handle_reconcile(operation, *cleanup_runtime).await
            }
        }
    }
}

#[derive(Clone, Debug)]
struct OperatorBindableService {
    service_id: String,
    display_name: String,
    protocol: ServiceProtocol,
    provider: OperatorServiceProvider,
}

impl OperatorBindableService {
    fn response(&self) -> BindableServiceResponse {
        BindableServiceResponse {
            bindable_service_id: self.service_id.clone(),
            source_kind: BindableServiceSourceKind::OperatorService,
            provider_kind: match self.provider {
                OperatorServiceProvider::DirectUrl { .. } => BindableServiceProviderKind::DirectUrl,
                OperatorServiceProvider::LoopbackUpstream { .. } => {
                    BindableServiceProviderKind::LoopbackUpstream
                }
            },
            display_name: Some(self.display_name.clone()),
            protocol: self.protocol,
            available: true,
            scenario_id: None,
            export: None,
        }
    }

    fn to_resolved(&self) -> ResolvedBindableService {
        ResolvedBindableService {
            response: self.response(),
            protocol: self.protocol,
            provider: match &self.provider {
                OperatorServiceProvider::DirectUrl { url } => {
                    ResolvedBindableProvider::DirectUrl(url.to_string())
                }
                OperatorServiceProvider::LoopbackUpstream { upstream } => {
                    ResolvedBindableProvider::LoopbackUpstream(*upstream)
                }
            },
        }
    }
}

#[derive(Clone, Debug)]
struct ResolvedBindableService {
    response: BindableServiceResponse,
    protocol: ServiceProtocol,
    provider: ResolvedBindableProvider,
}

#[derive(Clone, Debug)]
enum ResolvedBindableProvider {
    DirectUrl(String),
    LoopbackUpstream(std::net::SocketAddr),
    ScenarioExport(std::net::SocketAddr),
}

#[derive(Clone, Debug, Default)]
struct PreparedBindings {
    direct_slot_urls: BTreeMap<String, String>,
    slot_proxy_bindings: Vec<SlotRuntimeBinding>,
    export_bindings: Vec<ExportRuntimeBinding>,
    dependencies: Vec<NewDependency>,
    export_services: Vec<NewExportService>,
}

fn restart_interrupted_operation_message(kind: OperationKind) -> &'static str {
    match kind {
        OperationKind::Create => {
            "manager restarted while create was in progress; pending creates without a committed \
             revision were requeued, and committed state is recovered by reconcile"
        }
        OperationKind::Pause => {
            "manager restarted while pause was in progress; the operation was requeued"
        }
        OperationKind::Resume => {
            "manager restarted while resume was in progress; the operation was requeued"
        }
        OperationKind::Upgrade => {
            "manager restarted while upgrade was in progress; interrupted upgrades are failed \
             instead of replayed to avoid duplicate revisions"
        }
        OperationKind::Delete => {
            "manager restarted while delete was in progress; existing scenarios are retried and \
             already-deleted scenarios are treated as completed"
        }
        OperationKind::Reconcile => {
            "manager restarted while reconcile was in progress; the operation was requeued"
        }
    }
}
