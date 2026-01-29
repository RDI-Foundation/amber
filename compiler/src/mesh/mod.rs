use std::{
    collections::{BTreeSet, HashMap},
    fmt,
    sync::Arc,
};

use amber_manifest::{CapabilityDecl, Manifest};
use amber_scenario::{BindingFrom, ComponentId, ProvideRef, Scenario};

use crate::{DigestStore, manifest_table};

pub(crate) mod config;

#[derive(Clone, Debug)]
pub(crate) struct MeshOptions {
    pub(crate) backend_label: &'static str,
}

#[derive(Clone, Debug)]
pub(crate) struct MeshPlan {
    pub(crate) manifests: Vec<Option<Arc<Manifest>>>,
    pub(crate) program_components: Vec<ComponentId>,
    pub(crate) bindings: Vec<ResolvedBinding>,
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
    store: &DigestStore,
    options: MeshOptions,
) -> Result<MeshPlan, MeshError> {
    let manifests =
        manifest_table::build_manifest_table(&scenario.components, store).map_err(|e| {
            MeshError::new(format!(
                "internal error: missing manifest content for {} (digest {})",
                component_label(scenario, e.component),
                e.digest
            ))
        })?;

    for binding in &scenario.bindings {
        if let BindingFrom::Framework(name) = &binding.from {
            return Err(MeshError::new(format!(
                "{} does not support framework binding `framework.{name}` (bound to {}.{})",
                options.backend_label,
                component_label(scenario, binding.to.component),
                binding.to.name
            )));
        }
    }

    let program_components: Vec<ComponentId> = scenario
        .components_iter()
        .filter_map(|(id, c)| c.program.as_ref().map(|_| id))
        .collect();

    for binding in &scenario.bindings {
        let from = binding_from_component(&binding.from)?;
        if scenario.component(from.component).program.is_none() {
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
        let from = binding_from_component(&binding.from)?;
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
        manifests,
        program_components,
        bindings,
        exports,
        strong_deps,
    })
}

pub(crate) fn component_label(scenario: &Scenario, id: ComponentId) -> String {
    scenario.component(id).moniker.as_str().to_string()
}

fn binding_from_component(from: &BindingFrom) -> Result<&ProvideRef, MeshError> {
    match from {
        BindingFrom::Component(provide) => Ok(provide),
        BindingFrom::Framework(name) => Err(MeshError::new(format!(
            "framework binding framework.{name} should be rejected before planning"
        ))),
    }
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
