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
    pub(crate) program_components: Vec<ComponentId>,
    pub(crate) bindings: Vec<ResolvedBinding>,
    pub(crate) external_bindings: Vec<ResolvedExternalBinding>,
    pub(crate) framework_bindings: Vec<ResolvedFrameworkBinding>,
    pub(crate) exports: Vec<ResolvedExport>,
    pub(crate) strong_deps: HashMap<ComponentId, BTreeSet<ComponentId>>,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedBinding {
    pub(crate) provider: ComponentId,
    pub(crate) consumer: ComponentId,
    pub(crate) provide: String,
    pub(crate) endpoint: EndpointInfo,
    pub(crate) slot: String,
    pub(crate) binding_name: Option<String>,
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
    pub(crate) binding_name: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedFrameworkBinding {
    pub(crate) consumer: ComponentId,
    pub(crate) slot: String,
    pub(crate) capability: FrameworkCapabilityName,
    pub(crate) binding_name: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct EndpointInfo {
    pub(crate) port: u16,
    pub(crate) protocol: NetworkProtocol,
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

    let mut bindings = Vec::new();
    let mut external_bindings = Vec::new();
    let mut framework_bindings = Vec::new();
    for binding in &scenario.bindings {
        if slot_kind(scenario, binding.to.component, &binding.to.name)
            == Some(CapabilityKind::Storage)
        {
            continue;
        }
        match &binding.from {
            BindingFrom::Component(from) => {
                let endpoint = resolve_provide_endpoint(scenario, from.component, &from.name)?;
                bindings.push(ResolvedBinding {
                    provider: from.component,
                    consumer: binding.to.component,
                    provide: from.name.clone(),
                    endpoint,
                    slot: binding.to.name.clone(),
                    binding_name: binding.name.clone(),
                });
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
                external_bindings.push(ResolvedExternalBinding {
                    consumer: binding.to.component,
                    slot: binding.to.name.clone(),
                    external_slot: slot.name.clone(),
                    binding_name: binding.name.clone(),
                });
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
                framework_bindings.push(ResolvedFrameworkBinding {
                    consumer: binding.to.component,
                    slot: binding.to.name.clone(),
                    capability: name.clone(),
                    binding_name: binding.name.clone(),
                });
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

    Ok(MeshPlan {
        program_components,
        bindings,
        external_bindings,
        framework_bindings,
        exports,
        strong_deps,
    })
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
        .endpoints
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
