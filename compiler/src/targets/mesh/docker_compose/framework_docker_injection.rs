use std::collections::{BTreeMap, BTreeSet, HashMap};

use amber_manifest::{MountSource, ProvideDecl, SlotDecl};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario, SlotRef,
};
use serde_json::json;

use crate::targets::mesh::plan::MeshError;

pub(crate) const FRAMEWORK_DOCKER_GATEWAY_INTERNAL_SLOT: &str = "__amber_internal_framework_docker";
pub(crate) const FRAMEWORK_DOCKER_GATEWAY_ENDPOINT: &str = "docker";
pub(crate) const FRAMEWORK_DOCKER_GATEWAY_PROVIDE: &str = "__amber_internal_framework_docker";
pub(crate) const FRAMEWORK_DOCKER_GATEWAY_IMAGE: &str = "amber-internal://docker-gateway";
pub(crate) const FRAMEWORK_DOCKER_GATEWAY_ENTRYPOINT: &str = "/amber-docker-gateway";
pub(crate) const FRAMEWORK_DOCKER_GATEWAY_PORT: u16 = 23750;
const FRAMEWORK_DOCKER_GATEWAY_MONIKER_BASE: &str = "/__amber_internal_framework_docker_gateway";

#[derive(Clone, Debug)]
pub(crate) struct FrameworkDockerInjection {
    pub(crate) scenario: Scenario,
    pub(crate) gateway_component: Option<ComponentId>,
    pub(crate) proxy_slot_by_component: HashMap<ComponentId, String>,
}

pub(crate) fn rewrite_framework_docker_as_injected_component(
    scenario: &Scenario,
) -> Result<FrameworkDockerInjection, MeshError> {
    let mut framework_binding_consumers = BTreeSet::new();
    let mut proxy_slot_by_component = HashMap::new();
    for binding in &scenario.bindings {
        let BindingFrom::Framework(capability) = &binding.from else {
            continue;
        };
        if capability.as_str() != "docker" {
            continue;
        }
        framework_binding_consumers.insert(binding.to.component);
        proxy_slot_by_component
            .entry(binding.to.component)
            .or_insert_with(|| binding.to.name.clone());
    }

    let mut docker_mount_consumers = BTreeSet::new();
    for (id, component) in scenario.components_iter() {
        let Some(program) = component.program.as_ref() else {
            continue;
        };
        if program.mounts.iter().any(|mount| {
            matches!(&mount.source, MountSource::Framework(capability) if capability.as_str() == "docker")
        }) {
            docker_mount_consumers.insert(id);
        }
    }

    let docker_consumers: BTreeSet<ComponentId> = framework_binding_consumers
        .union(&docker_mount_consumers)
        .copied()
        .collect();
    if docker_consumers.is_empty() {
        return Ok(FrameworkDockerInjection {
            scenario: scenario.clone(),
            gateway_component: None,
            proxy_slot_by_component,
        });
    }

    let mut scenario = scenario.clone();
    let gateway_moniker = unique_gateway_moniker(&scenario);
    let gateway_id = ComponentId(scenario.components.len());
    let gateway_program = injected_gateway_program()?;
    let gateway_provides = BTreeMap::from([(
        FRAMEWORK_DOCKER_GATEWAY_PROVIDE.to_string(),
        injected_gateway_provide_decl()?,
    )]);

    scenario.components.push(Some(Component {
        id: gateway_id,
        parent: Some(scenario.root),
        moniker: Moniker::from(gateway_moniker),
        // Injected runtime-only components are post-manifest IR and do not map to a manifest.
        digest: scenario.component(scenario.root).digest,
        config: None,
        config_schema: None,
        program: Some(gateway_program),
        slots: BTreeMap::new(),
        provides: gateway_provides,
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    }));
    scenario
        .component_mut(scenario.root)
        .children
        .push(gateway_id);

    let gateway_provide = ProvideRef {
        component: gateway_id,
        name: FRAMEWORK_DOCKER_GATEWAY_PROVIDE.to_string(),
    };

    for binding in &mut scenario.bindings {
        let BindingFrom::Framework(capability) = &binding.from else {
            continue;
        };
        if capability.as_str() != "docker" {
            continue;
        }
        binding.from = BindingFrom::Component(gateway_provide.clone());
    }

    let internal_slot = injected_internal_slot_decl();
    for consumer in &docker_mount_consumers {
        if framework_binding_consumers.contains(consumer) {
            continue;
        }
        let component = scenario.component_mut(*consumer);
        component
            .slots
            .entry(FRAMEWORK_DOCKER_GATEWAY_INTERNAL_SLOT.to_string())
            .or_insert_with(|| internal_slot.clone());
        proxy_slot_by_component.insert(
            *consumer,
            FRAMEWORK_DOCKER_GATEWAY_INTERNAL_SLOT.to_string(),
        );
        scenario.bindings.push(BindingEdge {
            name: None,
            from: BindingFrom::Component(gateway_provide.clone()),
            to: SlotRef {
                component: *consumer,
                name: FRAMEWORK_DOCKER_GATEWAY_INTERNAL_SLOT.to_string(),
            },
            weak: false,
        });
    }

    scenario.normalize_child_order_by_moniker();
    scenario.assert_invariants();

    Ok(FrameworkDockerInjection {
        scenario,
        gateway_component: Some(gateway_id),
        proxy_slot_by_component,
    })
}

fn injected_gateway_program() -> Result<amber_manifest::Program, MeshError> {
    serde_json::from_value(json!({
        "image": FRAMEWORK_DOCKER_GATEWAY_IMAGE,
        "entrypoint": [FRAMEWORK_DOCKER_GATEWAY_ENTRYPOINT],
        "network": {
            "endpoints": [
                {
                    "name": FRAMEWORK_DOCKER_GATEWAY_ENDPOINT,
                    "port": FRAMEWORK_DOCKER_GATEWAY_PORT,
                    "protocol": "tcp"
                }
            ]
        }
    }))
    .map_err(|err| {
        MeshError::new(format!(
            "failed to build injected docker gateway program: {err}"
        ))
    })
}

fn injected_internal_slot_decl() -> SlotDecl {
    serde_json::from_value(json!({
        "kind": "docker",
        "optional": false
    }))
    .expect("injected internal framework.docker slot declaration should be valid")
}

fn injected_gateway_provide_decl() -> Result<ProvideDecl, MeshError> {
    serde_json::from_value(json!({
        "kind": "docker",
        "endpoint": FRAMEWORK_DOCKER_GATEWAY_ENDPOINT
    }))
    .map_err(|err| {
        MeshError::new(format!(
            "failed to build injected docker gateway provide declaration: {err}"
        ))
    })
}

fn unique_gateway_moniker(scenario: &Scenario) -> String {
    let mut used = BTreeSet::new();
    for (_, component) in scenario.components_iter() {
        used.insert(component.moniker.as_str().to_string());
    }
    if !used.contains(FRAMEWORK_DOCKER_GATEWAY_MONIKER_BASE) {
        return FRAMEWORK_DOCKER_GATEWAY_MONIKER_BASE.to_string();
    }

    let mut suffix = 1usize;
    loop {
        let candidate = format!("{FRAMEWORK_DOCKER_GATEWAY_MONIKER_BASE}-{suffix}");
        if !used.contains(&candidate) {
            return candidate;
        }
        suffix += 1;
    }
}
