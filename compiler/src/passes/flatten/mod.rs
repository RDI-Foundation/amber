use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
};

use amber_manifest::{BindingSource, BindingTarget, Manifest};
use amber_scenario::{BindingEdge, BindingFrom, Component, ComponentId, Scenario, SlotRef};

use super::{PassError, ScenarioPass};
use crate::{DigestStore, Provenance};

#[derive(Clone, Copy, Debug, Default)]
pub struct CanonicalizeBindingsPass;

#[derive(Clone, Copy, Debug, Default)]
pub struct FlattenPass;

impl ScenarioPass for CanonicalizeBindingsPass {
    fn name(&self) -> &'static str {
        "canonicalize_bindings"
    }

    fn run(
        &self,
        scenario: Scenario,
        provenance: Provenance,
        store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError> {
        let mut scenario = scenario;
        scenario.assert_invariants();

        let manifests = manifest_table(&scenario, store, self.name())?;
        let forward_map = build_forward_map(&scenario, &manifests);
        scenario = rewrite_bindings(scenario, &forward_map);
        scenario = rewrite_binding_decls(scenario, &forward_map);
        scenario.assert_invariants();
        Ok((scenario, provenance))
    }
}

impl ScenarioPass for FlattenPass {
    fn name(&self) -> &'static str {
        "flatten"
    }

    fn run(
        &self,
        scenario: Scenario,
        provenance: Provenance,
        store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError> {
        let mut scenario = scenario;
        scenario.assert_invariants();

        let manifests = manifest_table(&scenario, store, self.name())?;
        let forward_map = build_forward_map(&scenario, &manifests);

        let n = scenario.components.len();
        let mut referenced_by_binding = vec![false; n];
        for b in &scenario.bindings {
            if let BindingFrom::Component(from) = &b.from {
                referenced_by_binding[from.component.0] = true;
            }
            referenced_by_binding[b.to.component.0] = true;
        }

        let root = scenario.root;
        let mut remove = vec![false; n];
        for idx in 0..n {
            let id = ComponentId(idx);
            if id == root {
                continue;
            }
            let Some(component) = scenario.components[idx].as_ref() else {
                remove[idx] = true;
                continue;
            };
            let manifest = manifests[idx].as_ref().expect("manifest should exist");
            if referenced_by_binding[idx] {
                continue;
            }
            if is_pure_routing(component, manifest, &forward_map) {
                remove[idx] = true;
            }
        }

        let mut new_parent: Vec<Option<ComponentId>> = vec![None; n];
        for idx in 0..n {
            if remove[idx] {
                continue;
            }
            let Some(component) = scenario.components[idx].as_ref() else {
                continue;
            };
            new_parent[idx] =
                nearest_kept_ancestor(&scenario.components, &remove, component.parent);
        }

        scenario = super::prune_and_rebuild_scenario(
            scenario,
            &remove,
            |id, component| {
                component.parent = new_parent[id.0];
            },
            |_, _| true,
        );
        scenario.assert_invariants();

        Ok((scenario, provenance))
    }
}

fn manifest_table(
    scenario: &Scenario,
    store: &DigestStore,
    pass_name: &'static str,
) -> Result<Vec<Option<Arc<Manifest>>>, PassError> {
    crate::manifest_table::build_manifest_table(&scenario.components, store).map_err(|e| {
        PassError::Failed {
            pass: pass_name,
            message: format!(
                "missing manifest for digest {} (component {})",
                e.digest, e.component.0
            ),
        }
    })
}

#[derive(Clone, Debug)]
struct ForwardEdge {
    target: SlotRef,
    weak: bool,
}

#[derive(Clone, Debug)]
struct ResolvedTarget {
    target: SlotRef,
    weak: bool,
}

fn build_child_index(components: &[Option<Component>]) -> Vec<BTreeMap<String, ComponentId>> {
    let mut out = Vec::with_capacity(components.len());
    for component in components {
        let mut map = BTreeMap::new();
        let Some(component) = component.as_ref() else {
            out.push(map);
            continue;
        };
        for &child in &component.children {
            let Some(child_component) = components[child.0].as_ref() else {
                continue;
            };
            let Some(name) = child_component.moniker.local_name() else {
                continue;
            };
            map.insert(name.to_string(), child);
        }
        out.push(map);
    }
    out
}

fn build_forward_map(
    scenario: &Scenario,
    manifests: &[Option<Arc<Manifest>>],
) -> HashMap<(ComponentId, String), Vec<ForwardEdge>> {
    let child_index = build_child_index(&scenario.components);
    let mut forward_map: HashMap<(ComponentId, String), Vec<ForwardEdge>> = HashMap::new();

    for (id, _) in scenario.components_iter() {
        let Some(manifest) = manifests[id.0].as_ref() else {
            continue;
        };
        let child_by_name = &child_index[id.0];

        for (target, binding) in manifest.bindings() {
            let BindingTarget::ChildSlot { child, slot } = target else {
                continue;
            };
            let BindingSource::SelfSlot(from_slot) = &binding.from else {
                continue;
            };
            let Some(&child_id) = child_by_name.get(child.as_str()) else {
                continue;
            };
            forward_map
                .entry((id, from_slot.as_str().to_string()))
                .or_default()
                .push(ForwardEdge {
                    target: SlotRef {
                        component: child_id,
                        name: slot.as_str().to_string(),
                    },
                    weak: binding.weak,
                });
        }
    }

    forward_map
}

fn resolve_forward_targets(
    scenario: &Scenario,
    forward_map: &HashMap<(ComponentId, String), Vec<ForwardEdge>>,
    start: &SlotRef,
    stack: &mut HashSet<(ComponentId, String)>,
) -> Vec<ResolvedTarget> {
    let key = (start.component, start.name.clone());
    if !stack.insert(key.clone()) {
        return vec![ResolvedTarget {
            target: start.clone(),
            weak: false,
        }];
    }

    let component = scenario.component(start.component);
    if component.program.is_some() {
        stack.remove(&key);
        return vec![ResolvedTarget {
            target: start.clone(),
            weak: false,
        }];
    }

    let Some(edges) = forward_map.get(&key) else {
        stack.remove(&key);
        return vec![ResolvedTarget {
            target: start.clone(),
            weak: false,
        }];
    };

    let mut out = Vec::new();
    for edge in edges {
        let mut resolved = resolve_forward_targets(scenario, forward_map, &edge.target, stack);
        for target in &mut resolved {
            target.weak |= edge.weak;
        }
        out.extend(resolved);
    }

    stack.remove(&key);
    out
}

fn rewrite_bindings(
    mut scenario: Scenario,
    forward_map: &HashMap<(ComponentId, String), Vec<ForwardEdge>>,
) -> Scenario {
    let mut rewritten: Vec<BindingEdge> = Vec::new();

    for binding in &scenario.bindings {
        let mut stack = HashSet::new();
        let targets = resolve_forward_targets(&scenario, forward_map, &binding.to, &mut stack);

        let keep_name = targets.len() == 1;
        for target in targets {
            let mut edge = binding.clone();
            edge.to = target.target;
            edge.weak = edge.weak || target.weak;
            if !keep_name {
                edge.name = None;
            }
            rewritten.push(edge);
        }
    }

    let mut merged: HashMap<(BindingFrom, SlotRef, Option<String>), BindingEdge> = HashMap::new();
    for binding in rewritten {
        let key = (
            binding.from.clone(),
            binding.to.clone(),
            binding.name.clone(),
        );
        if let Some(existing) = merged.get_mut(&key) {
            // Multiple rewrite paths can produce the same edge. If any path is strong,
            // the merged edge must stay strong.
            existing.weak &= binding.weak;
            continue;
        }
        merged.insert(key, binding);
    }

    let mut bindings: Vec<BindingEdge> = merged.into_values().collect();
    bindings.sort_by(|a, b| binding_sort_key(a).cmp(&binding_sort_key(b)));
    scenario.bindings = bindings;
    scenario.normalize_order();
    scenario
}

fn binding_sort_key(binding: &BindingEdge) -> (u8, usize, &str, usize, &str, bool, bool, &str) {
    let (from_kind, from_component, from_name) = match &binding.from {
        BindingFrom::Component(provide) => (0, provide.component.0, provide.name.as_str()),
        BindingFrom::External(slot) => (1, slot.component.0, slot.name.as_str()),
        BindingFrom::Framework(name) => (2, 0, name.as_str()),
    };
    let (name_present, name) = match binding.name.as_deref() {
        Some(name) => (true, name),
        None => (false, ""),
    };
    (
        from_kind,
        from_component,
        from_name,
        binding.to.component.0,
        binding.to.name.as_str(),
        binding.weak,
        name_present,
        name,
    )
}

fn rewrite_binding_decls(
    mut scenario: Scenario,
    forward_map: &HashMap<(ComponentId, String), Vec<ForwardEdge>>,
) -> Scenario {
    let mut updates: Vec<Option<BTreeMap<String, SlotRef>>> =
        Vec::with_capacity(scenario.components.len());

    for component in scenario.components.iter() {
        let Some(component) = component.as_ref() else {
            updates.push(None);
            continue;
        };
        if component.binding_decls.is_empty() {
            updates.push(None);
            continue;
        }
        let mut updated = BTreeMap::new();
        for (name, slot_ref) in &component.binding_decls {
            let mut stack = HashSet::new();
            let mut targets = resolve_forward_targets(&scenario, forward_map, slot_ref, &mut stack);
            targets.sort_by(|a, b| {
                (a.target.component, &a.target.name).cmp(&(b.target.component, &b.target.name))
            });
            let chosen = targets
                .first()
                .map(|t| t.target.clone())
                .unwrap_or_else(|| slot_ref.clone());
            updated.insert(name.clone(), chosen);
        }
        updates.push(Some(updated));
    }

    for (component, update) in scenario.components.iter_mut().zip(updates) {
        let Some(component) = component.as_mut() else {
            continue;
        };
        if let Some(updated) = update {
            component.binding_decls = updated;
        }
    }

    scenario
}

fn is_pure_routing(
    component: &Component,
    manifest: &Manifest,
    forward_map: &HashMap<(ComponentId, String), Vec<ForwardEdge>>,
) -> bool {
    if component.program.is_some()
        || component.config.is_some()
        || component.config_schema.is_some()
        || component.metadata.is_some()
    {
        return false;
    }
    if !component.provides.is_empty() {
        return false;
    }
    if component.children.is_empty() {
        return false;
    }

    if component.slots.is_empty() {
        return manifest.bindings().is_empty();
    }

    for slot in component.slots.keys() {
        if !forward_map.contains_key(&(component.id, slot.clone())) {
            return false;
        }
    }

    for (target, binding) in manifest.bindings() {
        match (target, &binding.from) {
            (BindingTarget::ChildSlot { .. }, BindingSource::SelfSlot(_)) => {}
            _ => return false,
        }
    }

    true
}

fn nearest_kept_ancestor(
    components: &[Option<Component>],
    remove: &[bool],
    mut cur: Option<ComponentId>,
) -> Option<ComponentId> {
    while let Some(id) = cur {
        if !remove[id.0] && components[id.0].is_some() {
            break;
        }
        cur = components[id.0].as_ref().and_then(|c| c.parent);
    }
    cur
}

#[cfg(test)]
mod tests;
