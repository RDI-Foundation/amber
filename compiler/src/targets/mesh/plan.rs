use std::{
    collections::{BTreeSet, HashMap},
    fmt,
};

use amber_manifest::{
    CapabilityDecl, FrameworkBindingShape, FrameworkCapabilityName, framework_capability,
};
use amber_scenario::{BindingFrom, ComponentId, Scenario};

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
    pub(crate) capability: CapabilityDecl,
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
    pub(crate) name: String,
    pub(crate) port: u16,
}

#[derive(Debug)]
pub(crate) struct MeshError {
    message: String,
}

impl MeshError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for MeshError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MeshError {}

impl From<String> for MeshError {
    fn from(message: String) -> Self {
        Self::new(message)
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
        if let BindingFrom::Component(from) = &binding.from {
            let Some(source_component) = scenario.component(from.component) else {
                return Err(MeshError::new(format!(
                    "binding source references missing component id {}",
                    from.component.0
                )));
            };
            if source_component.program.is_none() {
                return Err(MeshError::new(format!(
                    "binding source {}.{} is not runnable (component has no program)",
                    component_label(scenario, from.component),
                    from.name
                )));
            }
        }
        let Some(target_component) = scenario.component(binding.to.component) else {
            return Err(MeshError::new(format!(
                "binding target references missing component id {}",
                binding.to.component.0
            )));
        };
        if target_component.program.is_none() {
            return Err(MeshError::new(format!(
                "binding target {}.{} is not runnable (component has no program)",
                component_label(scenario, binding.to.component),
                binding.to.name
            )));
        }
    }
    for ex in &scenario.exports {
        let Some(export_component) = scenario.component(ex.from.component) else {
            return Err(MeshError::new(format!(
                "scenario export '{}' references missing component id {}",
                ex.name, ex.from.component.0
            )));
        };
        if export_component.program.is_none() {
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
            capability: ex.capability.clone(),
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

pub(crate) fn component_label(scenario: &Scenario, id: ComponentId) -> String {
    scenario
        .component(id)
        .map(|component| component.moniker.as_str().to_string())
        .unwrap_or_else(|| format!("<missing-component-{}>", id.0))
}
fn resolve_provide_endpoint(
    scenario: &Scenario,
    component_id: ComponentId,
    provide_name: &str,
) -> Result<EndpointInfo, MeshError> {
    let component = scenario.component(component_id).ok_or_else(|| {
        MeshError::new(format!(
            "component id {} referenced for provide {} but does not exist",
            component_id.0, provide_name
        ))
    })?;

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

    let network = program.network.as_ref().ok_or_else(|| {
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
        name: endpoint.name.clone(),
        port: endpoint.port,
    })
}
