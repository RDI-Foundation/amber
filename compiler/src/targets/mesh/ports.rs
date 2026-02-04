use std::collections::{BTreeMap, HashMap, HashSet};

use amber_scenario::{ComponentId, Scenario};

use super::plan::{MeshError, component_label};

const LOCAL_SLOT_PORT_BASE: u16 = 20000;

pub(crate) fn allocate_slot_ports(
    scenario: &Scenario,
    program_components: &[ComponentId],
) -> Result<HashMap<ComponentId, BTreeMap<String, u16>>, MeshError> {
    let mut out: HashMap<ComponentId, BTreeMap<String, u16>> = HashMap::new();

    for id in program_components {
        let component = scenario.component(*id);
        let program = component.program.as_ref().unwrap();

        let mut reserved: HashSet<u16> = HashSet::new();
        if let Some(net) = program.network.as_ref() {
            for ep in &net.endpoints {
                reserved.insert(ep.port);
            }
        }

        let mut slot_ports: BTreeMap<String, u16> = BTreeMap::new();
        let mut next = LOCAL_SLOT_PORT_BASE;

        for slot_name in component.slots.keys() {
            while reserved.contains(&next) || slot_ports.values().any(|p| *p == next) {
                next = next.checked_add(1).ok_or_else(|| {
                    MeshError::new(format!(
                        "ran out of local slot ports allocating for {}",
                        component_label(scenario, *id)
                    ))
                })?;
            }
            slot_ports.insert(slot_name.clone(), next);
            next = next.checked_add(1).ok_or_else(|| {
                MeshError::new(format!(
                    "ran out of local slot ports allocating for {}",
                    component_label(scenario, *id)
                ))
            })?;
        }

        out.insert(*id, slot_ports);
    }

    Ok(out)
}

pub(crate) fn allocate_mesh_ports(
    scenario: &Scenario,
    program_components: &[ComponentId],
    base_port: u16,
    slot_ports_by_component: &HashMap<ComponentId, BTreeMap<String, u16>>,
) -> Result<HashMap<ComponentId, u16>, MeshError> {
    let mut out: HashMap<ComponentId, u16> = HashMap::new();

    for id in program_components {
        let component = scenario.component(*id);
        let program = component.program.as_ref().unwrap();

        let mut reserved: HashSet<u16> = HashSet::new();
        if let Some(net) = program.network.as_ref() {
            for ep in &net.endpoints {
                reserved.insert(ep.port);
            }
        }
        if let Some(slot_ports) = slot_ports_by_component.get(id) {
            for port in slot_ports.values() {
                reserved.insert(*port);
            }
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
