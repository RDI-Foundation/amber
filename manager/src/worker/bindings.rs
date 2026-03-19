use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

use amber_manifest::CapabilityTransport;
use tracing::warn;

use super::{
    OperationWorker, OperatorBindableService, PreparedBindings, ResolvedBindableProvider,
    ResolvedBindableService,
    errors::{
        OperationError, degraded_error, invalid_error, invalid_scenario_error, retryable_error,
    },
    graph::ScenarioGraph,
    now_ms,
};
use crate::{
    compiler::{CompiledMaterialization, ExportRuntimeBinding, SlotRuntimeBinding},
    config::{ConfigError, ManagerFileConfig, OperatorServiceProvider},
    domain::{
        BindableServiceProviderKind, BindableServiceResponse, BindableServiceSourceKind,
        ExportRequest, ServiceProtocol,
    },
    ids,
    store::{NewDependency, NewExportService, StoredExportService},
};

impl OperationWorker {
    pub(super) async fn prepare_bindings(
        &self,
        scenario_id: &str,
        compiled: &CompiledMaterialization,
        external_slots: &BTreeMap<String, crate::domain::ExternalSlotBindingRequest>,
        requested_exports: &BTreeMap<String, ExportRequest>,
        dependency_hints: &BTreeMap<String, Option<String>>,
        validate_cycles: bool,
    ) -> Result<PreparedBindings, OperationError> {
        let catalog = self.load_bindable_service_catalog().await?;
        let existing_export_listeners = self.existing_export_listeners(scenario_id).await?;
        let mut bindings = PreparedBindings::default();

        for (slot_name, binding) in external_slots {
            let slot_meta = compiled
                .proxy_metadata
                .external_slots
                .get(slot_name)
                .ok_or_else(|| {
                    invalid_scenario_error(format!(
                        "compiled scenario is missing external slot {}",
                        slot_name
                    ))
                })?;
            if slot_meta.kind.transport() != CapabilityTransport::Http {
                return Err(invalid_scenario_error(format!(
                    "external slot {} uses {} but scenario-manager only supports HTTP-transport \
                     external slots",
                    slot_name, slot_meta.kind
                )));
            }

            let Some(service) = catalog.get(&binding.bindable_service_id) else {
                if let Some(Some(provider_scenario_id)) =
                    dependency_hints.get(&binding.bindable_service_id)
                {
                    return Err(degraded_error(format!(
                        "bindable service {} is currently unavailable because provider scenario \
                         {} is not running",
                        binding.bindable_service_id, provider_scenario_id
                    )));
                }
                return Err(invalid_scenario_error(format!(
                    "bindable service {} does not exist",
                    binding.bindable_service_id
                )));
            };

            if !service.response.available {
                let detail = service
                    .response
                    .scenario_id
                    .as_deref()
                    .map(|scenario_id| {
                        format!(" because provider scenario {scenario_id} is not running")
                    })
                    .unwrap_or_default();
                return Err(degraded_error(format!(
                    "bindable service {} is currently unavailable{}",
                    service.response.bindable_service_id, detail
                )));
            }

            if service.protocol != ServiceProtocol::Http {
                return Err(invalid_scenario_error(format!(
                    "bindable service {} uses {} but external slot {} requires HTTP",
                    service.response.bindable_service_id,
                    service.protocol.as_str(),
                    slot_name
                )));
            }

            match &service.provider {
                ResolvedBindableProvider::DirectUrl(url) => {
                    bindings
                        .direct_slot_urls
                        .insert(slot_name.clone(), url.clone());
                }
                ResolvedBindableProvider::LoopbackUpstream(upstream)
                | ResolvedBindableProvider::ScenarioExport(upstream) => {
                    bindings.slot_proxy_bindings.push(SlotRuntimeBinding {
                        slot_name: slot_name.clone(),
                        upstream: *upstream,
                    });
                }
            }

            bindings.dependencies.push(NewDependency {
                slot_name: slot_name.clone(),
                bindable_service_id: service.response.bindable_service_id.clone(),
                provider_scenario_id: service.response.scenario_id.clone(),
            });
        }

        for (export_name, export_meta) in &compiled.proxy_metadata.exports {
            let protocol = parse_protocol(&export_meta.protocol)?;
            let internal_listen = existing_export_listeners
                .get(export_name)
                .copied()
                .unwrap_or(SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::LOCALHOST),
                    pick_export_port()?,
                ));
            let published_listen = requested_exports
                .get(export_name)
                .and_then(|request| request.publish.as_ref())
                .map(|request| request.listen);
            let service_id = ids::export_service_id(scenario_id, export_name);
            bindings.export_bindings.push(ExportRuntimeBinding {
                export_name: export_name.clone(),
                internal_listen,
                published_listen,
            });
            bindings.export_services.push(NewExportService {
                service_id,
                export_name: export_name.clone(),
                protocol: protocol.as_str().to_string(),
                listen_addr: internal_listen.ip().to_string(),
                listen_port: internal_listen.port(),
            });
        }

        if validate_cycles {
            self.ensure_dependency_graph_acyclic(scenario_id, &bindings.dependencies)
                .await?;
        }

        Ok(bindings)
    }

    pub(super) async fn current_export_services(
        &self,
        scenario_id: &str,
    ) -> Result<Vec<StoredExportService>, OperationError> {
        self.state
            .store
            .list_export_services_for_scenario(scenario_id)
            .await
            .map_err(retryable_error)
    }

    async fn existing_export_listeners(
        &self,
        scenario_id: &str,
    ) -> Result<BTreeMap<String, SocketAddr>, OperationError> {
        let mut listeners = BTreeMap::new();
        for service in self.current_export_services(scenario_id).await? {
            let Ok(ip) = service.listen_addr.parse() else {
                continue;
            };
            listeners.insert(
                service.export_name,
                SocketAddr::new(ip, service.listen_port),
            );
        }
        Ok(listeners)
    }

    pub(super) async fn ensure_export_change_is_safe(
        &self,
        provider_scenario_id: &str,
        compiled: &CompiledMaterialization,
    ) -> Result<(), OperationError> {
        let active_consumers = self
            .state
            .store
            .list_dependency_blockers(provider_scenario_id)
            .await
            .map_err(retryable_error)?
            .into_iter()
            .collect::<BTreeSet<_>>();
        let current_exports = self
            .state
            .store
            .list_export_services_for_scenario(provider_scenario_id)
            .await
            .map_err(retryable_error)?
            .into_iter()
            .map(|service| (service.service_id.clone(), service))
            .collect::<BTreeMap<_, _>>();

        for dependency in self
            .state
            .store
            .list_dependencies_for_provider(provider_scenario_id)
            .await
            .map_err(retryable_error)?
        {
            if !active_consumers.contains(&dependency.consumer_scenario_id) {
                continue;
            }
            let Some(current_export) = current_exports.get(&dependency.bindable_service_id) else {
                continue;
            };
            let Some(new_export) = compiled
                .proxy_metadata
                .exports
                .get(&current_export.export_name)
            else {
                return Err(invalid_error(format!(
                    "upgrade would remove export {} that active scenario {} depends on",
                    current_export.export_name, dependency.consumer_scenario_id
                )));
            };
            let new_protocol = parse_protocol(&new_export.protocol)?;
            if new_protocol.as_str() != current_export.protocol {
                return Err(invalid_error(format!(
                    "upgrade would change export {} from {} to {} while active scenario {} \
                     depends on it",
                    current_export.export_name,
                    current_export.protocol,
                    new_protocol.as_str(),
                    dependency.consumer_scenario_id
                )));
            }
        }
        Ok(())
    }

    async fn ensure_dependency_graph_acyclic(
        &self,
        scenario_id: &str,
        replacement_dependencies: &[NewDependency],
    ) -> Result<(), OperationError> {
        let scenarios = self
            .state
            .store
            .list_scenarios()
            .await
            .map_err(retryable_error)?;
        let dependencies = self
            .state
            .store
            .list_dependencies()
            .await
            .map_err(retryable_error)?;
        let mut graph = ScenarioGraph::new(
            scenarios
                .into_iter()
                .map(|scenario| scenario.id)
                .chain(std::iter::once(scenario_id.to_string())),
        );

        for dependency in dependencies
            .into_iter()
            .filter(|dependency| dependency.consumer_scenario_id != scenario_id)
        {
            if let Some(provider) = dependency.provider_scenario_id {
                graph.add_edge(provider, dependency.consumer_scenario_id);
            }
        }
        for dependency in replacement_dependencies {
            if let Some(provider) = dependency.provider_scenario_id.clone() {
                graph.add_edge(provider, scenario_id.to_string());
            }
        }

        if graph.is_acyclic() {
            return Ok(());
        }

        Err(invalid_error(
            "binding these services would introduce a scenario dependency cycle",
        ))
    }

    pub(super) async fn ensure_provider_not_required(
        &self,
        provider_scenario_id: &str,
    ) -> Result<(), OperationError> {
        let blockers = self
            .state
            .store
            .list_dependency_blockers(provider_scenario_id)
            .await
            .map_err(retryable_error)?;
        if blockers.is_empty() {
            return Ok(());
        }
        Err(invalid_error(format!(
            "scenario {} cannot be modified because active scenarios depend on its exports: {}",
            provider_scenario_id,
            blockers.join(", ")
        )))
    }

    async fn load_bindable_service_catalog(
        &self,
    ) -> Result<BTreeMap<String, ResolvedBindableService>, OperationError> {
        let mut services = BTreeMap::new();
        for service in self.state.operator_services.values() {
            services.insert(service.service_id.clone(), service.to_resolved());
        }
        for service in self
            .state
            .store
            .list_export_services()
            .await
            .map_err(retryable_error)?
        {
            let protocol = parse_protocol(&service.protocol)?;
            let upstream = format!("{}:{}", service.listen_addr, service.listen_port)
                .parse::<SocketAddr>()
                .map_err(retryable_error)?;
            services.insert(
                service.service_id.clone(),
                ResolvedBindableService {
                    response: BindableServiceResponse {
                        bindable_service_id: service.service_id,
                        source_kind: BindableServiceSourceKind::ScenarioExport,
                        provider_kind: BindableServiceProviderKind::ScenarioExport,
                        display_name: Some(format!(
                            "{}:{}",
                            service.scenario_id, service.export_name
                        )),
                        protocol,
                        available: service.available,
                        scenario_id: Some(service.scenario_id),
                        export: Some(service.export_name),
                    },
                    protocol,
                    provider: ResolvedBindableProvider::ScenarioExport(upstream),
                },
            );
        }
        Ok(services)
    }

    pub(super) async fn enqueue_dependent_reconciles(&self, provider_scenario_id: &str) {
        let dependencies = match self
            .state
            .store
            .list_dependencies_for_provider(provider_scenario_id)
            .await
        {
            Ok(dependencies) => dependencies,
            Err(err) => {
                warn!(
                    "failed to list dependencies while enqueueing dependents for {}: {}",
                    provider_scenario_id, err
                );
                return;
            }
        };
        let now = now_ms();
        for scenario_id in dependencies
            .into_iter()
            .map(|dependency| dependency.consumer_scenario_id)
            .collect::<BTreeSet<_>>()
        {
            match self
                .state
                .store
                .schedule_reconcile(&scenario_id, false, now)
                .await
            {
                Ok(true) => self.state.wake_worker(),
                Ok(false) => {}
                Err(err) => warn!(
                    "failed to enqueue dependent reconcile for {} after provider {} changed: {}",
                    scenario_id, provider_scenario_id, err
                ),
            }
        }
    }
}

pub(super) fn export_topology_changed(
    current: &[StoredExportService],
    next: &[NewExportService],
) -> bool {
    fn current_topology(services: &[StoredExportService]) -> BTreeMap<&str, (&str, &str, u16)> {
        services
            .iter()
            .map(|service| {
                (
                    service.export_name.as_str(),
                    (
                        service.service_id.as_str(),
                        service.protocol.as_str(),
                        service.listen_port,
                    ),
                )
            })
            .collect()
    }

    fn next_topology(services: &[NewExportService]) -> BTreeMap<&str, (&str, &str, u16)> {
        services
            .iter()
            .map(|service| {
                (
                    service.export_name.as_str(),
                    (
                        service.service_id.as_str(),
                        service.protocol.as_str(),
                        service.listen_port,
                    ),
                )
            })
            .collect()
    }

    current_topology(current) != next_topology(next)
}

pub(super) fn build_operator_services(
    file_config: ManagerFileConfig,
) -> Result<BTreeMap<String, OperatorBindableService>, ConfigError> {
    let mut services = BTreeMap::new();
    for (name, config) in file_config.bindable_services {
        let service_id = ids::operator_service_id(&name);
        if services.contains_key(&service_id) {
            return Err(ConfigError::InvalidConfig(format!(
                "bindable service names collide after normalization: {}",
                name
            )));
        }
        if let OperatorServiceProvider::LoopbackUpstream { upstream } = &config.provider
            && !upstream.ip().is_loopback()
        {
            return Err(ConfigError::InvalidConfig(format!(
                "bindable service {} must use a loopback upstream, got {}",
                name, upstream
            )));
        }
        services.insert(
            service_id.clone(),
            OperatorBindableService {
                service_id,
                display_name: name,
                protocol: config.protocol,
                provider: config.provider,
            },
        );
    }
    Ok(services)
}

pub(super) fn parse_protocol(raw: &str) -> Result<ServiceProtocol, OperationError> {
    super::errors::parse_protocol(raw)
}

fn pick_export_port() -> Result<u16, OperationError> {
    crate::runtime::pick_free_loopback_port().map_err(retryable_error)
}
