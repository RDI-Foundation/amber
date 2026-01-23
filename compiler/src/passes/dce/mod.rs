use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use amber_scenario::{BindingFrom, ComponentId, Scenario};

use super::{PassError, ScenarioPass};
use crate::{DigestStore, Provenance};

#[derive(Clone, Copy, Debug, Default)]
pub struct DcePass;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CapKey {
    component: usize,
    name: Arc<str>,
}

#[derive(Clone, Debug)]
enum WorkItem {
    Program(usize),
    Slot(CapKey),
    Provide(CapKey),
}

impl ScenarioPass for DcePass {
    fn name(&self) -> &'static str {
        "dce"
    }

    fn run(
        &self,
        scenario: Scenario,
        provenance: Provenance,
        _store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError> {
        scenario.assert_invariants();

        let n = scenario.components.len();
        let mut incoming = vec![Vec::new(); n];
        for (idx, b) in scenario.bindings.iter().enumerate() {
            let _ = scenario.component(b.to.component);
            if let BindingFrom::Component(from) = &b.from {
                let _ = scenario.component(from.component);
            }
            incoming[b.to.component.0].push(idx);
        }

        let mut live_program = vec![false; n];
        let mut live_slots: HashSet<CapKey> = HashSet::new();
        let mut live_provides: HashSet<CapKey> = HashSet::new();
        let mut live_bindings = vec![false; scenario.bindings.len()];

        let mut work = VecDeque::new();

        for export in &scenario.exports {
            let key = CapKey {
                component: export.from.component.0,
                name: Arc::from(export.from.name.as_str()),
            };
            if live_provides.insert(key.clone()) {
                work.push_back(WorkItem::Provide(key));
            }
        }

        while let Some(item) = work.pop_front() {
            match item {
                WorkItem::Provide(key) => {
                    let component = key.component;
                    if scenario.component(ComponentId(component)).program.is_some()
                        && !live_program[component]
                    {
                        live_program[component] = true;
                        work.push_back(WorkItem::Program(component));
                    }
                }
                WorkItem::Program(component) => {
                    let component = scenario.component(ComponentId(component));
                    mark_used_slots(component, &mut live_slots, &mut work);
                }
                WorkItem::Slot(key) => {
                    let component = key.component;
                    if scenario.component(ComponentId(component)).program.is_some()
                        && !live_program[component]
                    {
                        live_program[component] = true;
                        work.push_back(WorkItem::Program(component));
                    }
                    for &edge_idx in &incoming[component] {
                        let edge = &scenario.bindings[edge_idx];
                        if edge.to.name != key.name.as_ref() {
                            continue;
                        }
                        if live_bindings[edge_idx] {
                            continue;
                        }
                        live_bindings[edge_idx] = true;
                        if let BindingFrom::Component(from) = &edge.from {
                            let provide = CapKey {
                                component: from.component.0,
                                name: Arc::from(from.name.as_str()),
                            };
                            if live_provides.insert(provide.clone()) {
                                work.push_back(WorkItem::Provide(provide));
                            }
                        }
                    }
                }
            }
        }

        let keep = compute_keep_set(&scenario, &live_program, &live_slots, &live_provides);
        Ok(prune_scenario(
            scenario,
            provenance,
            &keep,
            &live_program,
            &live_bindings,
        ))
    }
}

fn mark_used_slots(
    component: &amber_scenario::Component,
    live_slots: &mut HashSet<CapKey>,
    work: &mut VecDeque<WorkItem>,
) {
    let Some(program) = component.program.as_ref() else {
        return;
    };

    let mark_all = |live_slots: &mut HashSet<CapKey>, work: &mut VecDeque<WorkItem>| {
        for slot in component.slots.keys() {
            mark_slot(component.id.0, slot, live_slots, work);
        }
    };

    for arg in &program.args.0 {
        if arg.visit_slot_uses(|slot| mark_slot(component.id.0, slot, live_slots, work)) {
            mark_all(live_slots, work);
            return;
        }
    }

    for value in program.env.values() {
        if value.visit_slot_uses(|slot| mark_slot(component.id.0, slot, live_slots, work)) {
            mark_all(live_slots, work);
            return;
        }
    }
}

fn mark_slot(
    component: usize,
    slot: &str,
    live_slots: &mut HashSet<CapKey>,
    work: &mut VecDeque<WorkItem>,
) {
    let key = CapKey {
        component,
        name: Arc::from(slot),
    };
    if live_slots.insert(key.clone()) {
        work.push_back(WorkItem::Slot(key));
    }
}

fn compute_keep_set(
    scenario: &Scenario,
    live_program: &[bool],
    live_slots: &HashSet<CapKey>,
    live_provides: &HashSet<CapKey>,
) -> Vec<bool> {
    let n = scenario.components.len();
    let mut keep = vec![false; n];
    keep[scenario.root.0] = true;

    for (idx, &live) in live_program.iter().enumerate() {
        keep[idx] |= live;
    }
    for key in live_slots {
        keep[key.component] = true;
    }
    for key in live_provides {
        keep[key.component] = true;
    }

    for idx in 0..n {
        if !keep[idx] {
            continue;
        }
        let mut cur = scenario.component(ComponentId(idx)).parent;
        while let Some(parent) = cur {
            if keep[parent.0] {
                break;
            }
            keep[parent.0] = true;
            cur = scenario.component(parent).parent;
        }
    }

    keep
}

fn prune_scenario(
    scenario: Scenario,
    provenance: Provenance,
    keep: &[bool],
    live_program: &[bool],
    live_bindings: &[bool],
) -> (Scenario, Provenance) {
    let removed: Vec<bool> = keep
        .iter()
        .enumerate()
        .map(|(idx, &keep_component)| !keep_component || scenario.components[idx].is_none())
        .collect();

    let scenario = super::prune_and_rebuild_scenario(
        scenario,
        &removed,
        |id, component| {
            if !live_program[id.0] {
                component.program = None;
                component.slots.clear();
                component.provides.clear();
            }
        },
        |idx, _binding| live_bindings[idx],
    );
    scenario.assert_invariants();

    (scenario, provenance)
}

#[cfg(test)]
mod tests;
