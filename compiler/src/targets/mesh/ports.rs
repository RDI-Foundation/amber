use std::collections::{BTreeMap, HashMap, HashSet};

use amber_scenario::{ComponentId, Scenario};

use super::plan::{
    MeshError, MeshPlan, ResolvedBinding, ResolvedExternalBinding, ResolvedFrameworkBinding,
    component_label,
};

const LOCAL_SLOT_PORT_BASE: u16 = 20000;

#[derive(Clone, Debug, Default)]
pub(crate) struct LocalRoutePorts {
    slot_ports_by_component: HashMap<ComponentId, BTreeMap<String, u16>>,
    reserved_ports_by_component: HashMap<ComponentId, Vec<u16>>,
    binding_ports: HashMap<BindingRouteKey, u16>,
    external_binding_ports: HashMap<ExternalBindingRouteKey, u16>,
    framework_binding_ports: HashMap<FrameworkBindingRouteKey, u16>,
}

impl LocalRoutePorts {
    pub(crate) fn slot_port(&self, component: ComponentId, slot: &str) -> Option<u16> {
        self.slot_ports_by_component
            .get(&component)
            .and_then(|ports| ports.get(slot))
            .copied()
    }

    pub(crate) fn reserved_ports(&self, component: ComponentId) -> &[u16] {
        self.reserved_ports_by_component
            .get(&component)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) fn binding_port(&self, binding: &ResolvedBinding) -> Option<u16> {
        self.binding_ports
            .get(&BindingRouteKey::from(binding))
            .copied()
    }

    pub(crate) fn external_binding_port(&self, binding: &ResolvedExternalBinding) -> Option<u16> {
        self.external_binding_ports
            .get(&ExternalBindingRouteKey::from(binding))
            .copied()
    }

    pub(crate) fn framework_binding_port(&self, binding: &ResolvedFrameworkBinding) -> Option<u16> {
        self.framework_binding_ports
            .get(&FrameworkBindingRouteKey::from(binding))
            .copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct BindingRouteKey {
    consumer: ComponentId,
    slot: String,
    provider: ComponentId,
    provide: String,
}

impl From<&ResolvedBinding> for BindingRouteKey {
    fn from(value: &ResolvedBinding) -> Self {
        Self {
            consumer: value.consumer,
            slot: value.slot.clone(),
            provider: value.provider,
            provide: value.provide.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct ExternalBindingRouteKey {
    consumer: ComponentId,
    slot: String,
    external_slot: String,
}

impl From<&ResolvedExternalBinding> for ExternalBindingRouteKey {
    fn from(value: &ResolvedExternalBinding) -> Self {
        Self {
            consumer: value.consumer,
            slot: value.slot.clone(),
            external_slot: value.external_slot.clone(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FrameworkBindingRouteKey {
    consumer: ComponentId,
    slot: String,
    capability: String,
}

impl From<&ResolvedFrameworkBinding> for FrameworkBindingRouteKey {
    fn from(value: &ResolvedFrameworkBinding) -> Self {
        Self {
            consumer: value.consumer,
            slot: value.slot.clone(),
            capability: value.capability.to_string(),
        }
    }
}

pub(crate) fn allocate_local_route_ports(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
) -> Result<LocalRoutePorts, MeshError> {
    let mut out = LocalRoutePorts::default();

    for id in &mesh_plan.program_components {
        let component = scenario.component(*id);
        let program = component.program.as_ref().unwrap();

        let mut reserved: HashSet<u16> = HashSet::new();
        if let Some(net) = program.network() {
            for ep in &net.endpoints {
                reserved.insert(ep.port);
            }
        }

        let mut slot_ports: BTreeMap<String, Vec<u16>> = BTreeMap::new();
        let mut next = LOCAL_SLOT_PORT_BASE;

        let mut allocate_port = |slot_name: &str| -> Result<u16, MeshError> {
            while reserved.contains(&next) {
                next = next.checked_add(1).ok_or_else(|| {
                    MeshError::new(format!(
                        "ran out of local slot ports allocating for {}",
                        component_label(scenario, *id)
                    ))
                })?;
            }

            let port = next;
            reserved.insert(port);
            slot_ports
                .entry(slot_name.to_string())
                .or_default()
                .push(port);
            next = next.checked_add(1).ok_or_else(|| {
                MeshError::new(format!(
                    "ran out of local slot ports allocating for {}",
                    component_label(scenario, *id)
                ))
            })?;
            Ok(port)
        };

        for binding in mesh_plan
            .bindings
            .iter()
            .filter(|binding| binding.consumer == *id)
        {
            let port = allocate_port(&binding.slot)?;
            out.binding_ports
                .insert(BindingRouteKey::from(binding), port);
        }
        for binding in mesh_plan
            .external_bindings
            .iter()
            .filter(|binding| binding.consumer == *id)
        {
            let port = allocate_port(&binding.slot)?;
            out.external_binding_ports
                .insert(ExternalBindingRouteKey::from(binding), port);
        }
        for binding in mesh_plan
            .framework_bindings
            .iter()
            .filter(|binding| binding.consumer == *id)
        {
            let port = allocate_port(&binding.slot)?;
            out.framework_binding_ports
                .insert(FrameworkBindingRouteKey::from(binding), port);
        }

        let mut reserved_ports: Vec<u16> = reserved.into_iter().collect();
        reserved_ports.sort_unstable();
        out.reserved_ports_by_component.insert(*id, reserved_ports);
        out.slot_ports_by_component.insert(
            *id,
            slot_ports
                .into_iter()
                .filter_map(|(slot, ports)| match ports.as_slice() {
                    [port] => Some((slot, *port)),
                    _ => None,
                })
                .collect(),
        );
    }

    Ok(out)
}

pub(crate) fn placeholder_local_route_ports(
    scenario: &Scenario,
    mesh_plan: &MeshPlan,
) -> LocalRoutePorts {
    let mut out = LocalRoutePorts::default();

    for id in &mesh_plan.program_components {
        let mut slot_ports: BTreeMap<String, Vec<u16>> = BTreeMap::new();

        for binding in mesh_plan
            .bindings
            .iter()
            .filter(|binding| binding.consumer == *id)
        {
            out.binding_ports.insert(BindingRouteKey::from(binding), 0);
            slot_ports.entry(binding.slot.clone()).or_default().push(0);
        }
        for binding in mesh_plan
            .external_bindings
            .iter()
            .filter(|binding| binding.consumer == *id)
        {
            out.external_binding_ports
                .insert(ExternalBindingRouteKey::from(binding), 0);
            slot_ports.entry(binding.slot.clone()).or_default().push(0);
        }
        for binding in mesh_plan
            .framework_bindings
            .iter()
            .filter(|binding| binding.consumer == *id)
        {
            out.framework_binding_ports
                .insert(FrameworkBindingRouteKey::from(binding), 0);
            slot_ports.entry(binding.slot.clone()).or_default().push(0);
        }

        let mut reserved: Vec<u16> = scenario
            .component(*id)
            .program
            .as_ref()
            .and_then(|program| program.network())
            .into_iter()
            .flat_map(|net| net.endpoints.iter().map(|endpoint| endpoint.port))
            .collect();
        reserved.sort_unstable();
        reserved.dedup();
        out.reserved_ports_by_component.insert(*id, reserved);
        out.slot_ports_by_component.insert(
            *id,
            slot_ports
                .into_iter()
                .filter_map(|(slot, ports)| match ports.as_slice() {
                    [port] => Some((slot, *port)),
                    _ => None,
                })
                .collect(),
        );
    }

    out
}

pub(crate) fn allocate_mesh_ports(
    scenario: &Scenario,
    program_components: &[ComponentId],
    base_port: u16,
    route_ports: &LocalRoutePorts,
) -> Result<HashMap<ComponentId, u16>, MeshError> {
    let mut out: HashMap<ComponentId, u16> = HashMap::new();

    for id in program_components {
        let component = scenario.component(*id);
        let program = component.program.as_ref().unwrap();

        let mut reserved: HashSet<u16> = HashSet::new();
        if let Some(net) = program.network() {
            for ep in &net.endpoints {
                reserved.insert(ep.port);
            }
        }
        for &port in route_ports.reserved_ports(*id) {
            reserved.insert(port);
        }

        let mut next = base_port;
        while reserved.contains(&next) {
            next = next.checked_add(1).ok_or_else(|| {
                MeshError::new(format!(
                    "ran out of mesh ports allocating for {}",
                    component_label(scenario, *id)
                ))
            })?;
        }
        out.insert(*id, next);
    }

    Ok(out)
}
