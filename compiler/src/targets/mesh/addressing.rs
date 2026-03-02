use std::collections::{BTreeMap, BTreeSet, HashMap};

use amber_scenario::{ComponentId, Scenario};

use crate::{
    binding_query::BindingObject,
    slot_query::SlotObject,
    targets::mesh::plan::{
        MeshError, MeshPlan, ResolvedBinding, ResolvedExternalBinding, ResolvedFrameworkBinding,
        component_label,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum WorkloadId {
    Component(ComponentId),
    Router,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct AllowPlan {
    pub(crate) by_provider: HashMap<WorkloadId, BTreeMap<u16, BTreeSet<WorkloadId>>>,
}

impl AllowPlan {
    pub(crate) fn allow(&mut self, provider: WorkloadId, consumer: WorkloadId, port: u16) {
        if provider == consumer {
            return;
        }
        self.by_provider
            .entry(provider)
            .or_default()
            .entry(port)
            .or_default()
            .insert(consumer);
    }

    pub(crate) fn for_component(
        &self,
        component: ComponentId,
    ) -> Option<&BTreeMap<u16, BTreeSet<WorkloadId>>> {
        self.by_provider.get(&WorkloadId::Component(component))
    }

    pub(crate) fn for_router(&self) -> Option<&BTreeMap<u16, BTreeSet<WorkloadId>>> {
        self.by_provider.get(&WorkloadId::Router)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct MeshAddressPlan {
    pub(crate) slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotObject>>,
    pub(crate) binding_values_by_component: HashMap<ComponentId, BTreeMap<String, BindingObject>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DockerFrameworkBindingPolicy {
    LoopbackTcp,
    Unsupported { reason: &'static str },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LocalAddressingOptions {
    pub(crate) backend_label: &'static str,
    pub(crate) docker_binding: DockerFrameworkBindingPolicy,
}

pub(crate) struct LocalAddressing<'a> {
    scenario: &'a Scenario,
    slot_ports_by_component: &'a HashMap<ComponentId, BTreeMap<String, u16>>,
    options: LocalAddressingOptions,
}

impl<'a> LocalAddressing<'a> {
    pub(crate) fn new(
        scenario: &'a Scenario,
        slot_ports_by_component: &'a HashMap<ComponentId, BTreeMap<String, u16>>,
        options: LocalAddressingOptions,
    ) -> Self {
        Self {
            scenario,
            slot_ports_by_component,
            options,
        }
    }

    fn local_slot_port(&self, component: ComponentId, slot: &str) -> Result<u16, MeshError> {
        self.slot_ports_by_component
            .get(&component)
            .and_then(|ports| ports.get(slot))
            .copied()
            .ok_or_else(|| {
                MeshError::new(format!(
                    "internal error: missing local port allocation for {}.{}",
                    component_label(self.scenario, component),
                    slot
                ))
            })
    }

    fn unsupported_framework_error(&self, capability: &str) -> MeshError {
        MeshError::new(format!(
            "{} does not support framework capability `framework.{capability}`",
            self.options.backend_label
        ))
    }
}

pub(crate) trait Addressing {
    type Error: From<MeshError>;

    fn resolve_binding_url(&mut self, binding: &ResolvedBinding) -> Result<String, Self::Error>;
    fn resolve_external_binding_url(
        &mut self,
        binding: &ResolvedExternalBinding,
    ) -> Result<String, Self::Error>;
    fn resolve_framework_binding_url(
        &mut self,
        binding: &ResolvedFrameworkBinding,
    ) -> Result<String, Self::Error>;
}

impl Addressing for LocalAddressing<'_> {
    type Error = MeshError;

    fn resolve_binding_url(&mut self, binding: &ResolvedBinding) -> Result<String, Self::Error> {
        let local_port = self.local_slot_port(binding.consumer, &binding.slot)?;
        Ok(format!("http://127.0.0.1:{local_port}"))
    }

    fn resolve_external_binding_url(
        &mut self,
        binding: &ResolvedExternalBinding,
    ) -> Result<String, Self::Error> {
        let local_port = self.local_slot_port(binding.consumer, &binding.slot)?;
        Ok(format!("http://127.0.0.1:{local_port}"))
    }

    fn resolve_framework_binding_url(
        &mut self,
        binding: &ResolvedFrameworkBinding,
    ) -> Result<String, Self::Error> {
        if binding.capability.as_str() != "docker" {
            return Err(self.unsupported_framework_error(binding.capability.as_str()));
        }

        match self.options.docker_binding {
            DockerFrameworkBindingPolicy::LoopbackTcp => {
                let local_port = self.local_slot_port(binding.consumer, &binding.slot)?;
                Ok(format!("tcp://127.0.0.1:{local_port}"))
            }
            DockerFrameworkBindingPolicy::Unsupported { reason } => Err(MeshError::new(format!(
                "{} {reason}",
                self.options.backend_label
            ))),
        }
    }
}

pub(crate) fn build_address_plan<A: Addressing>(
    mesh_plan: &MeshPlan,
    mut addressing: A,
) -> Result<MeshAddressPlan, A::Error> {
    let mut slot_values_by_component: HashMap<ComponentId, BTreeMap<String, SlotObject>> =
        HashMap::new();
    let mut binding_values_by_component: HashMap<ComponentId, BTreeMap<String, BindingObject>> =
        HashMap::new();
    for id in &mesh_plan.program_components {
        slot_values_by_component.insert(*id, BTreeMap::new());
        binding_values_by_component.insert(*id, BTreeMap::new());
    }

    let mut insert_url =
        |consumer: ComponentId, slot: &str, binding_name: Option<&str>, url: String| {
            slot_values_by_component
                .entry(consumer)
                .or_default()
                .insert(slot.to_string(), SlotObject { url: url.clone() });

            if let Some(name) = binding_name {
                binding_values_by_component
                    .entry(consumer)
                    .or_default()
                    .insert(name.to_string(), BindingObject { url });
            }
        };

    for binding in &mesh_plan.bindings {
        let url = addressing.resolve_binding_url(binding)?;
        insert_url(
            binding.consumer,
            &binding.slot,
            binding.binding_name.as_deref(),
            url,
        );
    }

    for binding in &mesh_plan.external_bindings {
        let url = addressing.resolve_external_binding_url(binding)?;
        insert_url(
            binding.consumer,
            &binding.slot,
            binding.binding_name.as_deref(),
            url,
        );
    }

    for binding in &mesh_plan.framework_bindings {
        let url = addressing.resolve_framework_binding_url(binding)?;
        insert_url(
            binding.consumer,
            &binding.slot,
            binding.binding_name.as_deref(),
            url,
        );
    }

    Ok(MeshAddressPlan {
        slot_values_by_component,
        binding_values_by_component,
    })
}

pub(crate) type ComponentEgressAllow = HashMap<ComponentId, BTreeMap<ComponentId, BTreeSet<u16>>>;
pub(crate) type RouterEgressAllow = HashMap<ComponentId, BTreeSet<u16>>;

pub(crate) fn build_component_egress_allow(
    allow_plan: &AllowPlan,
) -> (ComponentEgressAllow, RouterEgressAllow) {
    let mut egress_allow: ComponentEgressAllow = HashMap::new();
    let mut egress_router_allow: RouterEgressAllow = HashMap::new();

    for (provider, by_port) in &allow_plan.by_provider {
        match provider {
            WorkloadId::Component(provider_id) => {
                for (port, consumers) in by_port {
                    for consumer in consumers {
                        if let WorkloadId::Component(consumer_id) = consumer {
                            egress_allow
                                .entry(*consumer_id)
                                .or_default()
                                .entry(*provider_id)
                                .or_default()
                                .insert(*port);
                        }
                    }
                }
            }
            WorkloadId::Router => {
                for (port, consumers) in by_port {
                    for consumer in consumers {
                        if let WorkloadId::Component(consumer_id) = consumer {
                            egress_router_allow
                                .entry(*consumer_id)
                                .or_default()
                                .insert(*port);
                        }
                    }
                }
            }
        }
    }

    (egress_allow, egress_router_allow)
}

pub(crate) fn build_allow_plan(
    mesh_plan: &MeshPlan,
    mesh_ports_by_component: &HashMap<ComponentId, u16>,
    router_mesh_port: Option<u16>,
) -> Result<AllowPlan, MeshError> {
    let mut allow = AllowPlan::default();

    for binding in &mesh_plan.bindings {
        let port = *mesh_ports_by_component
            .get(&binding.provider)
            .ok_or_else(|| {
                MeshError::new(format!(
                    "mesh port missing for provider {}",
                    binding.provider.0
                ))
            })?;
        allow.allow(
            WorkloadId::Component(binding.provider),
            WorkloadId::Component(binding.consumer),
            port,
        );
    }

    if !mesh_plan.external_bindings.is_empty() || !mesh_plan.exports.is_empty() {
        let router_port =
            router_mesh_port.ok_or_else(|| MeshError::new("router mesh port missing"))?;
        for binding in &mesh_plan.external_bindings {
            allow.allow(
                WorkloadId::Router,
                WorkloadId::Component(binding.consumer),
                router_port,
            );
        }
        for export in &mesh_plan.exports {
            let provider_port =
                *mesh_ports_by_component
                    .get(&export.provider)
                    .ok_or_else(|| {
                        MeshError::new(format!(
                            "mesh port missing for export provider {}",
                            export.provider.0
                        ))
                    })?;
            allow.allow(
                WorkloadId::Component(export.provider),
                WorkloadId::Router,
                provider_port,
            );
        }
    }

    Ok(allow)
}
