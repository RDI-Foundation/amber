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
    compiler::{ExportRuntimeBinding, ScenarioSourceAccess, SlotRuntimeBinding},
    config::{ConfigError, ManagerFileConfig, OperatorServiceProvider},
    domain::{
        BindableServiceProviderKind, BindableServiceResponse, BindableServiceSourceKind,
        OperationKind, OperationPayload, ServiceProtocol,
    },
    runtime::RuntimeSupervisor,
    store::{
        ClaimedScenarioWork, InterruptedScenarioWork, NewDependency, NewExportService, Store,
        StoreError, StoredOperation,
    },
};

pub(super) const IDLE_WAIT: Duration = Duration::from_millis(250);
pub(super) const HEALTH_MONITOR_INTERVAL: Duration = Duration::from_millis(250);
pub(super) const STARTUP_HEALTH_GRACE: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct AppState {
    config: ManagerConfig,
    store: Store,
    runtime: RuntimeSupervisor,
    notify: Arc<Notify>,
    operator_services: BTreeMap<String, OperatorBindableService>,
    scenario_sources: ScenarioSourceAccess,
}

impl AppState {
    pub fn new(
        config: ManagerConfig,
        file_config: ManagerFileConfig,
        store: Store,
        runtime: RuntimeSupervisor,
        notify: Arc<Notify>,
    ) -> Result<Self, ConfigError> {
        let ManagerFileConfig {
            bindable_services,
            scenario_source_allowlist,
        } = file_config;
        let operator_services = build_operator_services(bindable_services)?;
        let scenario_sources = ScenarioSourceAccess::from_config(scenario_source_allowlist)?;
        Ok(Self {
            config,
            store,
            runtime,
            notify,
            operator_services,
            scenario_sources,
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

    pub fn scenario_sources(&self) -> &ScenarioSourceAccess {
        &self.scenario_sources
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
        self.recover_interrupted_work(now_ms).await;

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

        for (offset, scenario_id) in topological_order(&scenarios, &dependencies)
            .into_iter()
            .enumerate()
        {
            let Some(scenario) = scenarios.iter().find(|scenario| scenario.id == scenario_id)
            else {
                continue;
            };
            if scenario.active_revision.is_none() {
                continue;
            }
            if let Err(err) = self
                .state
                .store
                .schedule_reconcile(&scenario.id, false, now_ms.saturating_add(offset as i64))
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

    async fn recover_interrupted_work(&self, now_ms: i64) {
        let interrupted = match self.state.store.list_interrupted_work().await {
            Ok(interrupted) => interrupted,
            Err(err) => {
                error!("failed to list interrupted scenario work after manager restart: {err}");
                return;
            }
        };

        for work in interrupted {
            if let Err(err) = self.recover_interrupted_scenario_work(&work, now_ms).await {
                error!(
                    "failed to recover interrupted scenario work for {}: {}",
                    work.scenario_id, err
                );
            }
        }
    }

    async fn recover_interrupted_scenario_work(
        &self,
        work: &InterruptedScenarioWork,
        now_ms: i64,
    ) -> Result<(), StoreError> {
        let Some(operation_id) = work.operation_id.as_deref() else {
            self.state
                .store
                .requeue_interrupted_work(&work.scenario_id, None, now_ms)
                .await?;
            info!(
                "requeued interrupted background reconcile for {} after manager restart",
                work.scenario_id
            );
            return Ok(());
        };

        let Some(operation) = self.state.store.get_operation(operation_id).await? else {
            self.state
                .store
                .complete_scenario_work(&work.scenario_id, work.generation, now_ms)
                .await?;
            return Ok(());
        };
        let scenario = self.state.store.load_scenario(&work.scenario_id).await?;
        let restart_message = restart_interrupted_operation_message(operation.kind);

        match operation.kind {
            OperationKind::Create => {
                if scenario
                    .as_ref()
                    .is_some_and(|scenario| scenario.active_revision.is_none())
                {
                    self.state
                        .store
                        .requeue_interrupted_operation(
                            &work.scenario_id,
                            &operation.id,
                            operation.retry_count,
                            restart_message,
                            now_ms,
                        )
                        .await?;
                    info!(
                        "requeued interrupted create operation {} for {} after manager restart",
                        operation.id, work.scenario_id
                    );
                } else {
                    self.state
                        .store
                        .fail_operation_and_complete_work(
                            &work.scenario_id,
                            work.generation,
                            &operation.id,
                            restart_message,
                            now_ms,
                        )
                        .await?;
                    info!(
                        "failed interrupted create operation {} for {} after manager restart",
                        operation.id, work.scenario_id
                    );
                }
            }
            OperationKind::Pause | OperationKind::Resume | OperationKind::Delete => {
                if scenario.is_some() {
                    self.state
                        .store
                        .requeue_interrupted_operation(
                            &work.scenario_id,
                            &operation.id,
                            operation.retry_count,
                            restart_message,
                            now_ms,
                        )
                        .await?;
                    info!(
                        "requeued interrupted {} operation {} for {} after manager restart",
                        operation.kind.as_str(),
                        operation.id,
                        work.scenario_id
                    );
                } else {
                    let result = json!({
                        "scenario_id": work.scenario_id,
                        "deleted": true,
                    });
                    self.state
                        .store
                        .succeed_operation_and_complete_work(
                            &work.scenario_id,
                            work.generation,
                            &operation.id,
                            Some(&result),
                            now_ms,
                        )
                        .await?;
                    info!(
                        "completed interrupted {} operation {} after manager restart",
                        operation.kind.as_str(),
                        operation.id
                    );
                }
            }
            OperationKind::Upgrade => {
                self.state
                    .store
                    .fail_operation_and_complete_work(
                        &work.scenario_id,
                        work.generation,
                        &operation.id,
                        restart_message,
                        now_ms,
                    )
                    .await?;
                info!(
                    "failed interrupted upgrade operation {} for {} after manager restart",
                    operation.id, work.scenario_id
                );
            }
            OperationKind::Reconcile => {
                self.state
                    .store
                    .requeue_interrupted_operation(
                        &work.scenario_id,
                        &operation.id,
                        operation.retry_count,
                        restart_message,
                        now_ms,
                    )
                    .await?;
            }
        }

        Ok(())
    }

    pub async fn run(self) {
        loop {
            match self.state.store.claim_next_scenario_work(now_ms()).await {
                Ok(Some(work)) => self.process_claimed_work(work).await,
                Ok(None) => {
                    let _ = timeout(IDLE_WAIT, self.state.notify.notified()).await;
                }
                Err(err) => {
                    error!("failed to claim scenario work: {err}");
                    tokio::time::sleep(IDLE_WAIT).await;
                }
            }
        }
    }

    async fn process_claimed_work(&self, work: ClaimedScenarioWork) {
        let operation = match self.load_claimed_operation(&work).await {
            Ok(operation) => operation,
            Err(err) => {
                error!(
                    "failed to load claimed scenario work for {}: {}",
                    work.scenario_id, err
                );
                return;
            }
        };

        let cleanup_runtime = work.cleanup_runtime
            || operation.as_ref().is_some_and(|operation| {
                matches!(
                    operation.payload,
                    OperationPayload::Reconcile {
                        cleanup_runtime: true
                    }
                )
            });
        if cleanup_runtime {
            self.cleanup_runtime(&work.scenario_id).await;
        }

        let result = match operation.as_ref() {
            Some(operation) => self.process_operation(&work.scenario_id, operation).await,
            None if work.operation_id.is_some() => Err(OperationError {
                message: format!(
                    "scenario {} lost its staged operation {}",
                    work.scenario_id,
                    work.operation_id.as_deref().unwrap_or_default()
                ),
                retryable: false,
                cleanup_runtime: false,
                observed_state: None,
                affects_scenario: false,
            }),
            None => self.handle_reconcile(&work.scenario_id).await,
        };

        match result {
            Ok(result) => {
                let finalize_result = if let Some(operation) = operation.as_ref() {
                    self.retry_store_until_ok(
                        || async {
                            self.state
                                .store
                                .succeed_operation_and_complete_work(
                                    &work.scenario_id,
                                    work.generation,
                                    &operation.id,
                                    result.as_ref(),
                                    now_ms(),
                                )
                                .await
                        },
                        &format!("finalize succeeded operation {}", operation.id),
                    )
                    .await
                } else {
                    self.retry_store_until_ok(
                        || async {
                            self.state
                                .store
                                .complete_scenario_work(
                                    &work.scenario_id,
                                    work.generation,
                                    now_ms(),
                                )
                                .await
                        },
                        &format!("complete scenario work for {}", work.scenario_id),
                    )
                    .await
                };
                if let Err(err) = finalize_result {
                    error!(
                        "failed to finalize successful work for {}: {}",
                        work.scenario_id, err
                    );
                }
            }
            Err(err) => self.handle_work_error(&work, operation.as_ref(), err).await,
        }
    }

    async fn process_operation(
        &self,
        scenario_id: &str,
        operation: &StoredOperation,
    ) -> Result<Option<Value>, OperationError> {
        match &operation.payload {
            OperationPayload::Create { request } => self.handle_create(scenario_id, request).await,
            OperationPayload::Pause => self.handle_pause(scenario_id).await,
            OperationPayload::Resume => self.handle_resume(scenario_id).await,
            OperationPayload::Upgrade { request } => {
                self.handle_upgrade(scenario_id, request).await
            }
            OperationPayload::Delete { destroy_storage } => {
                self.handle_delete(scenario_id, *destroy_storage).await
            }
            OperationPayload::Reconcile { .. } => self.handle_reconcile(scenario_id).await,
        }
    }

    async fn retry_store_until_ok<F, Fut>(
        &self,
        mut op: F,
        description: &str,
    ) -> Result<(), StoreError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<(), StoreError>>,
    {
        loop {
            match op().await {
                Ok(()) => return Ok(()),
                Err(err) if err.is_retryable() => {
                    error!("failed to {}: {}", description, err);
                    tokio::time::sleep(IDLE_WAIT).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn retry_store_until_value<F, Fut, T>(
        &self,
        mut op: F,
        description: &str,
    ) -> Result<T, StoreError>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<T, StoreError>>,
    {
        loop {
            match op().await {
                Ok(value) => return Ok(value),
                Err(err) if err.is_retryable() => {
                    error!("failed to {}: {}", description, err);
                    tokio::time::sleep(IDLE_WAIT).await;
                }
                Err(err) => return Err(err),
            }
        }
    }

    async fn load_claimed_operation(
        &self,
        work: &ClaimedScenarioWork,
    ) -> Result<Option<StoredOperation>, StoreError> {
        let Some(operation_id) = work.operation_id.as_deref() else {
            return Ok(None);
        };

        self.retry_store_until_ok(
            || async {
                self.state
                    .store
                    .mark_operation_running(operation_id, now_ms())
                    .await
            },
            &format!("mark operation {} running", operation_id),
        )
        .await?;

        let operation = self
            .retry_store_until_value(
                || async { self.state.store.get_operation(operation_id).await },
                &format!(
                    "load claimed operation {} for {}",
                    operation_id, work.scenario_id
                ),
            )
            .await?;
        if operation.is_none() {
            error!(
                "claimed scenario work for {} referenced missing operation {}",
                work.scenario_id, operation_id
            );
        }
        Ok(operation)
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
