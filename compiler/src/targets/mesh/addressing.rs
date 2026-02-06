use std::collections::{BTreeMap, BTreeSet, HashMap};

use amber_scenario::ComponentId;

use crate::{
    binding_query::BindingObject,
    slot_query::SlotObject,
    targets::mesh::plan::{MeshError, MeshPlan, ResolvedBinding, ResolvedExternalBinding},
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

pub(crate) trait Addressing {
    type Error: From<MeshError>;

    fn resolve_binding_url(&mut self, binding: &ResolvedBinding) -> Result<String, Self::Error>;
    fn resolve_external_binding_url(
        &mut self,
        binding: &ResolvedExternalBinding,
    ) -> Result<String, Self::Error>;
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

    for binding in &mesh_plan.bindings {
        let url = addressing.resolve_binding_url(binding)?;

        slot_values_by_component
            .entry(binding.consumer)
            .or_default()
            .insert(binding.slot.clone(), SlotObject { url: url.clone() });

        if let Some(name) = binding.binding_name.as_ref() {
            binding_values_by_component
                .entry(binding.consumer)
                .or_default()
                .insert(name.clone(), BindingObject { url });
        }
    }

    for binding in &mesh_plan.external_bindings {
        let url = addressing.resolve_external_binding_url(binding)?;

        slot_values_by_component
            .entry(binding.consumer)
            .or_default()
            .insert(binding.slot.clone(), SlotObject { url: url.clone() });

        if let Some(name) = binding.binding_name.as_ref() {
            binding_values_by_component
                .entry(binding.consumer)
                .or_default()
                .insert(name.clone(), BindingObject { url });
        }
    }

    Ok(MeshAddressPlan {
        slot_values_by_component,
        binding_values_by_component,
    })
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
