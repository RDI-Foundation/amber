use std::collections::{BTreeSet, HashMap};

use amber_manifest::{
    CapabilityKind, FrameworkBindingShape, FrameworkCapabilityName, NetworkProtocol,
    framework_capability,
};
use amber_scenario::{BindingFrom, ComponentId, Scenario};

pub(crate) use crate::targets::common::{TargetError as MeshError, component_label};

#[derive(Clone, Debug)]
pub(crate) struct MeshOptions {
    pub(crate) backend_label: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct MeshPlan {
    program_components: Vec<ComponentId>,
    bindings: Vec<ResolvedBinding>,
    exports: Vec<ResolvedExport>,
    strong_deps: HashMap<ComponentId, BTreeSet<ComponentId>>,
}

#[derive(Clone, Debug)]
pub(crate) enum ResolvedBinding {
    Component(ResolvedComponentBinding),
    External(ResolvedExternalBinding),
    Framework(ResolvedFrameworkBinding),
}

impl ResolvedBinding {
    pub(crate) fn consumer(&self) -> ComponentId {
        match self {
            Self::Component(binding) => binding.consumer,
            Self::External(binding) => binding.consumer,
            Self::Framework(binding) => binding.consumer,
        }
    }

    pub(crate) fn slot(&self) -> &str {
        match self {
            Self::Component(binding) => &binding.slot,
            Self::External(binding) => &binding.slot,
            Self::Framework(binding) => &binding.slot,
        }
    }

    pub(crate) fn as_component(&self) -> Option<&ResolvedComponentBinding> {
        match self {
            Self::Component(binding) => Some(binding),
            Self::External(_) | Self::Framework(_) => None,
        }
    }

    pub(crate) fn as_external(&self) -> Option<&ResolvedExternalBinding> {
        match self {
            Self::External(binding) => Some(binding),
            Self::Component(_) | Self::Framework(_) => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedComponentBinding {
    pub(crate) provider: ComponentId,
    pub(crate) consumer: ComponentId,
    pub(crate) provide: String,
    pub(crate) endpoint: EndpointInfo,
    pub(crate) slot: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedExport {
    pub(crate) name: String,
    pub(crate) provider: ComponentId,
    pub(crate) provide: String,
    pub(crate) endpoint: EndpointInfo,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedExternalBinding {
    pub(crate) consumer: ComponentId,
    pub(crate) slot: String,
    pub(crate) external_slot: String,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedFrameworkBinding {
    pub(crate) consumer: ComponentId,
    pub(crate) slot: String,
    pub(crate) capability: FrameworkCapabilityName,
}

#[derive(Clone, Debug)]
pub(crate) struct EndpointInfo {
    pub(crate) port: u16,
    pub(crate) protocol: NetworkProtocol,
}

impl MeshPlan {
    pub(crate) fn new(
        program_components: Vec<ComponentId>,
        bindings: Vec<ResolvedBinding>,
        exports: Vec<ResolvedExport>,
        strong_deps: HashMap<ComponentId, BTreeSet<ComponentId>>,
    ) -> Self {
        Self {
            program_components,
            bindings,
            exports,
            strong_deps,
        }
    }

    pub(crate) fn program_components(&self) -> &[ComponentId] {
        self.program_components.as_slice()
    }

    pub(crate) fn bindings(&self) -> &[ResolvedBinding] {
        self.bindings.as_slice()
    }

    pub(crate) fn bindings_for_consumer(
        &self,
        consumer: ComponentId,
    ) -> impl Iterator<Item = &ResolvedBinding> {
        self.bindings
            .iter()
            .filter(move |binding| binding.consumer() == consumer)
    }

    pub(crate) fn component_bindings(&self) -> impl Iterator<Item = &ResolvedComponentBinding> {
        self.bindings
            .iter()
            .filter_map(ResolvedBinding::as_component)
    }

    pub(crate) fn external_bindings(&self) -> impl Iterator<Item = &ResolvedExternalBinding> {
        self.bindings
            .iter()
            .filter_map(ResolvedBinding::as_external)
    }

    pub(crate) fn needs_router(&self) -> bool {
        self.bindings
            .iter()
            .any(|binding| binding.as_external().is_some())
            || !self.exports.is_empty()
    }

    pub(crate) fn exports(&self) -> &[ResolvedExport] {
        self.exports.as_slice()
    }

    pub(crate) fn strong_deps(&self) -> &HashMap<ComponentId, BTreeSet<ComponentId>> {
        &self.strong_deps
    }
}

pub(crate) fn build_mesh_plan(
    scenario: &Scenario,
    options: MeshOptions,
) -> Result<MeshPlan, MeshError> {
    let program_components: Vec<ComponentId> = scenario
        .components_iter()
        .filter_map(|(id, c)| c.program.as_ref().map(|_| id))
        .collect();

    for binding in &scenario.bindings {
        if slot_kind(scenario, binding.to.component, &binding.to.name)
            == Some(CapabilityKind::Storage)
        {
            continue;
        }
        if let BindingFrom::Component(from) = &binding.from
            && scenario.component(from.component).program.is_none()
        {
            return Err(MeshError::new(format!(
                "binding source {}.{} is not runnable (component has no program)",
                component_label(scenario, from.component),
                from.name
            )));
        }
        if scenario.component(binding.to.component).program.is_none() {
            return Err(MeshError::new(format!(
                "binding target {}.{} is not runnable (component has no program)",
                component_label(scenario, binding.to.component),
                binding.to.name
            )));
        }
    }
    for ex in &scenario.exports {
        if scenario.component(ex.from.component).program.is_none() {
            return Err(MeshError::new(format!(
                "scenario export '{}' points at {}.{} which is not runnable (component has no \
                 program)",
                ex.name,
                component_label(scenario, ex.from.component),
                ex.from.name
            )));
        }
    }

    let mut strong_deps: HashMap<ComponentId, BTreeSet<ComponentId>> = HashMap::new();
    for binding in &scenario.bindings {
        if slot_kind(scenario, binding.to.component, &binding.to.name)
            == Some(CapabilityKind::Storage)
        {
            continue;
        }
        if binding.weak {
            continue;
        }
        let BindingFrom::Component(from) = &binding.from else {
            continue;
        };
        if from.component == binding.to.component {
            continue;
        }
        strong_deps
            .entry(binding.to.component)
            .or_default()
            .insert(from.component);
    }

    let mut bindings = Vec::with_capacity(scenario.bindings.len());
    for binding in &scenario.bindings {
        if slot_kind(scenario, binding.to.component, &binding.to.name)
            == Some(CapabilityKind::Storage)
        {
            continue;
        }
        match &binding.from {
            BindingFrom::Component(from) => {
                let endpoint = resolve_provide_endpoint(scenario, from.component, &from.name)?;
                bindings.push(ResolvedBinding::Component(ResolvedComponentBinding {
                    provider: from.component,
                    consumer: binding.to.component,
                    provide: from.name.clone(),
                    endpoint,
                    slot: binding.to.name.clone(),
                }));
            }
            BindingFrom::Resource(resource) => {
                return Err(MeshError::new(format!(
                    "internal error: non-storage binding {}.{} resolves from resource \
                     `resources.{}` on {}",
                    component_label(scenario, binding.to.component),
                    binding.to.name,
                    resource.name,
                    component_label(scenario, resource.component),
                )));
            }
            BindingFrom::External(slot) => {
                bindings.push(ResolvedBinding::External(ResolvedExternalBinding {
                    consumer: binding.to.component,
                    slot: binding.to.name.clone(),
                    external_slot: slot.name.clone(),
                }));
            }
            BindingFrom::Framework(name) => {
                let Some(spec) = framework_capability(name.as_str()) else {
                    return Err(MeshError::new(format!(
                        "{} does not support unknown framework binding `framework.{name}` (bound \
                         to {}.{})",
                        options.backend_label,
                        component_label(scenario, binding.to.component),
                        binding.to.name
                    )));
                };
                if spec.binding_shape != FrameworkBindingShape::Url {
                    return Err(MeshError::new(format!(
                        "{} does not support non-URL framework binding `framework.{name}` (bound \
                         to {}.{})",
                        options.backend_label,
                        component_label(scenario, binding.to.component),
                        binding.to.name
                    )));
                }
                bindings.push(ResolvedBinding::Framework(ResolvedFrameworkBinding {
                    consumer: binding.to.component,
                    slot: binding.to.name.clone(),
                    capability: name.clone(),
                }));
            }
        }
    }

    let mut exports = Vec::with_capacity(scenario.exports.len());
    for ex in &scenario.exports {
        let endpoint = resolve_provide_endpoint(scenario, ex.from.component, &ex.from.name)?;
        exports.push(ResolvedExport {
            name: ex.name.clone(),
            provider: ex.from.component,
            provide: ex.from.name.clone(),
            endpoint,
        });
    }

    Ok(MeshPlan::new(
        program_components,
        bindings,
        exports,
        strong_deps,
    ))
}

fn slot_kind(scenario: &Scenario, component: ComponentId, slot: &str) -> Option<CapabilityKind> {
    scenario
        .component(component)
        .slots
        .get(slot)
        .map(|decl| decl.decl.kind)
}

pub(crate) fn map_program_components<T>(
    scenario: &Scenario,
    program_components: &[ComponentId],
    mut map: impl FnMut(ComponentId, &str) -> T,
) -> HashMap<ComponentId, T> {
    let mut out = HashMap::with_capacity(program_components.len());
    for id in program_components {
        let local_name = scenario
            .component(*id)
            .moniker
            .local_name()
            .unwrap_or("component");
        out.insert(*id, map(*id, local_name));
    }
    out
}

fn resolve_provide_endpoint(
    scenario: &Scenario,
    component_id: ComponentId,
    provide_name: &str,
) -> Result<EndpointInfo, MeshError> {
    let component = scenario.component(component_id);

    let provide = component.provides.get(provide_name).ok_or_else(|| {
        MeshError::new(format!(
            "provide {}.{} not found",
            component_label(scenario, component_id),
            provide_name
        ))
    })?;

    let program = component.program.as_ref().ok_or_else(|| {
        MeshError::new(format!(
            "provide {}.{} requires a program, but component has none",
            component_label(scenario, component_id),
            provide_name
        ))
    })?;

    let network = program.network().ok_or_else(|| {
        MeshError::new(format!(
            "provide {}.{} requires program.network, but none exists",
            component_label(scenario, component_id),
            provide_name
        ))
    })?;

    let endpoint_name = provide.endpoint.as_deref().ok_or_else(|| {
        MeshError::new(format!(
            "provide {}.{} is missing an endpoint reference",
            component_label(scenario, component_id),
            provide_name
        ))
    })?;

    let endpoint = network
        .endpoints()
        .iter()
        .find(|e| e.name == endpoint_name)
        .ok_or_else(|| {
            MeshError::new(format!(
                "provide {}.{} references unknown endpoint {:?}",
                component_label(scenario, component_id),
                provide_name,
                endpoint_name
            ))
        })?;

    Ok(EndpointInfo {
        port: endpoint.port,
        protocol: endpoint.protocol,
    })
}
