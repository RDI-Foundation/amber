use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    sync::Arc,
};

use amber_manifest::{BindingSource, BindingTarget, Manifest};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, ProgramMount, Scenario, SlotRef,
};
use miette::Diagnostic;
use thiserror::Error;

use crate::{DigestStore, Provenance, linker::manifest_table};

#[derive(Debug, Error, Diagnostic)]
#[non_exhaustive]
pub enum Error {
    #[error("MIR pass `{pass}` failed: {message}")]
    #[diagnostic(code(compiler::pass_failed))]
    Failed { pass: &'static str, message: String },
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct OptimizeOptions {
    pub(crate) dce: bool,
}

pub(crate) fn optimize_linked_scenario(
    scenario: Scenario,
    provenance: Provenance,
    store: &DigestStore,
    opts: OptimizeOptions,
) -> Result<(Scenario, Provenance), Error> {
    let mut mir = MirScenario::lower(scenario, provenance, store)?;
    mir.canonicalize_bindings();
    if opts.dce {
        mir.flatten_pure_routing();
        mir.prune_dead_code();
    }
    Ok(mir.into_parts())
}

#[cfg(test)]
pub(crate) fn flatten_routing_only(
    scenario: Scenario,
    store: &DigestStore,
) -> Result<Scenario, Error> {
    scenario.assert_invariants();
    let graph = BindingGraph::build(&scenario, store, "flatten")?;
    let scenario = flatten_pure_routing_with_graph(scenario, &graph);
    scenario.assert_invariants();
    Ok(scenario)
}

#[cfg(test)]
pub(crate) fn dce_only(scenario: Scenario) -> Scenario {
    dce_with_semantics(scenario)
}

struct MirScenario {
    scenario: Scenario,
    provenance: Provenance,
    graph: BindingGraph,
}

impl MirScenario {
    fn lower(
        scenario: Scenario,
        provenance: Provenance,
        store: &DigestStore,
    ) -> Result<Self, Error> {
        scenario.assert_invariants();
        let graph = BindingGraph::build(&scenario, store, "mir_lower")?;
        Ok(Self {
            scenario,
            provenance,
            graph,
        })
    }

    fn canonicalize_bindings(&mut self) {
        let scenario = take_scenario(&mut self.scenario);
        self.scenario = rewrite_bindings(scenario, &self.graph.forward_map);
        self.scenario.assert_invariants();
    }

    fn flatten_pure_routing(&mut self) {
        let scenario = take_scenario(&mut self.scenario);
        self.scenario = flatten_pure_routing_with_graph(scenario, &self.graph);
        self.scenario.assert_invariants();
    }

    fn prune_dead_code(&mut self) {
        self.scenario = dce_with_semantics(take_scenario(&mut self.scenario));
        self.scenario.assert_invariants();
    }
    fn into_parts(self) -> (Scenario, Provenance) {
        (self.scenario, self.provenance)
    }
}

fn take_scenario(scenario: &mut Scenario) -> Scenario {
    let root = scenario.root;
    std::mem::replace(
        scenario,
        Scenario {
            root,
            components: Vec::new(),
            bindings: Vec::new(),
            exports: Vec::new(),
        },
    )
}

#[derive(Clone, Debug)]
struct BindingGraph {
    manifests: Vec<Option<Arc<Manifest>>>,
    forward_map: HashMap<(ComponentId, String), Vec<ForwardEdge>>,
}

impl BindingGraph {
    fn build(
        scenario: &Scenario,
        store: &DigestStore,
        pass_name: &'static str,
    ) -> Result<Self, Error> {
        let manifests =
            manifest_table::build_manifest_table(&scenario.components, store).map_err(|e| {
                Error::Failed {
                    pass: pass_name,
                    message: format!(
                        "missing manifest for digest {} (component {})",
                        e.digest, e.component.0
                    ),
                }
            })?;
        let forward_map = build_forward_map(scenario, &manifests);
        Ok(Self {
            manifests,
            forward_map,
        })
    }
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

        for binding_decl in manifest.bindings() {
            let target = &binding_decl.target;
            let binding = &binding_decl.binding;
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
    let mut merged_indices: HashMap<(BindingFrom, SlotRef), usize> = HashMap::new();
    let mut bindings: Vec<BindingEdge> = Vec::new();

    for binding in &scenario.bindings {
        if scenario.component(binding.to.component).program.is_some() {
            merged_indices
                .entry((binding.from.clone(), binding.to.clone()))
                .or_insert(bindings.len());
            bindings.push(binding.clone());
        }
    }

    for binding in &scenario.bindings {
        if scenario.component(binding.to.component).program.is_some() {
            continue;
        }
        let mut stack = HashSet::new();
        let targets = resolve_forward_targets(&scenario, forward_map, &binding.to, &mut stack);

        for target in targets {
            let mut edge = binding.clone();
            edge.to = target.target;
            edge.weak = edge.weak || target.weak;
            let key = (edge.from.clone(), edge.to.clone());
            if let Some(&idx) = merged_indices.get(&key) {
                let existing = &mut bindings[idx];
                // Multiple rewrite paths can produce the same concrete edge. If any path is
                // strong, the canonical edge must stay strong.
                existing.weak &= edge.weak;
                continue;
            }
            merged_indices.insert(key, bindings.len());
            bindings.push(edge);
        }
    }

    scenario.bindings = bindings;
    scenario.normalize_order();
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
    if !component.resources.is_empty() {
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

    for binding_decl in manifest.bindings() {
        let target = &binding_decl.target;
        let binding = &binding_decl.binding;
        match (target, &binding.from) {
            (BindingTarget::ChildSlot { .. }, BindingSource::SelfSlot(_)) => {}
            _ => return false,
        }
    }

    true
}

fn flatten_pure_routing_with_graph(scenario: Scenario, graph: &BindingGraph) -> Scenario {
    let n = scenario.components.len();

    let mut referenced_by_binding = vec![false; n];
    for b in &scenario.bindings {
        if let BindingFrom::Component(from) = &b.from {
            referenced_by_binding[from.component.0] = true;
        }
        if let BindingFrom::Resource(from) = &b.from {
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
        let manifest = graph.manifests[idx]
            .as_ref()
            .expect("manifest should exist");
        if referenced_by_binding[idx] {
            continue;
        }
        if is_pure_routing(component, manifest, &graph.forward_map) {
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
        new_parent[idx] = nearest_kept_ancestor(&scenario.components, &remove, component.parent);
    }

    prune_and_rebuild_scenario(
        scenario,
        &remove,
        |id, component| {
            component.parent = new_parent[id.0];
        },
        |_, _| true,
    )
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

fn prune_and_rebuild_scenario(
    scenario: Scenario,
    removed: &[bool],
    mut update_component: impl FnMut(ComponentId, &mut Component),
    mut keep_binding: impl FnMut(usize, &BindingEdge) -> bool,
) -> Scenario {
    let Scenario {
        root,
        mut components,
        bindings,
        exports,
    } = scenario;

    debug_assert_eq!(removed.len(), components.len());
    debug_assert!(!removed[root.0], "root must not be removed");
    debug_assert!(components[root.0].is_some(), "root component should exist");
    debug_assert!(
        exports
            .iter()
            .all(|export| !removed[export.from.component.0]),
        "scenario export target must not be removed"
    );

    for (idx, component) in components.iter_mut().enumerate() {
        if removed[idx] {
            *component = None;
            continue;
        }

        let id = ComponentId(idx);
        let component = component.as_mut().expect("kept component should exist");
        update_component(id, component);
        component.children.clear();
    }

    let mut edges = Vec::new();
    for (idx, component) in components.iter().enumerate() {
        let Some(component) = component.as_ref() else {
            continue;
        };
        let Some(parent) = component.parent else {
            continue;
        };
        if removed[parent.0] {
            continue;
        }
        edges.push((parent, ComponentId(idx)));
    }
    for (parent, child) in edges {
        let parent_component = components[parent.0].as_mut().expect("parent should exist");
        parent_component.children.push(child);
    }

    let mut new_bindings = Vec::with_capacity(bindings.len());
    for (idx, binding) in bindings.into_iter().enumerate() {
        if !keep_binding(idx, &binding) {
            continue;
        }
        if removed[binding.to.component.0] {
            continue;
        }
        if let BindingFrom::Component(from) = &binding.from
            && removed[from.component.0]
        {
            continue;
        }
        if let BindingFrom::Resource(from) = &binding.from
            && removed[from.component.0]
        {
            continue;
        }
        new_bindings.push(binding);
    }

    let mut scenario = Scenario {
        root,
        components,
        bindings: new_bindings,
        exports,
    };
    scenario.normalize_order();
    scenario
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct CapKey {
    component: usize,
    name: Arc<str>,
}

#[derive(Clone, Debug)]
enum DceWorkItem {
    LiveProgram(usize),
    Slot(CapKey),
    Provide(CapKey),
    Resource(CapKey),
}

struct DceResults {
    keep_components: Vec<bool>,
    live_programs: Vec<bool>,
    live_slots: HashSet<CapKey>,
    live_provides: HashSet<CapKey>,
    live_resources: HashSet<CapKey>,
    live_bindings: Vec<bool>,
}

struct DceSolver<'a> {
    scenario: &'a Scenario,
    incoming: Vec<Vec<usize>>,
    program_used_slots: Vec<HashSet<String>>,
    program_used_resources: Vec<HashSet<String>>,
    keep_components: Vec<bool>,
    live_programs: Vec<bool>,
    live_slots: HashSet<CapKey>,
    live_provides: HashSet<CapKey>,
    live_resources: HashSet<CapKey>,
    live_bindings: Vec<bool>,
    work: VecDeque<DceWorkItem>,
}

impl<'a> DceSolver<'a> {
    fn new(scenario: &'a Scenario) -> Self {
        let mut incoming = vec![Vec::new(); scenario.components.len()];
        for (idx, binding) in scenario.bindings.iter().enumerate() {
            let _ = scenario.component(binding.to.component);
            if let BindingFrom::Component(from) = &binding.from {
                let _ = scenario.component(from.component);
            }
            if let BindingFrom::Resource(from) = &binding.from {
                let _ = scenario.component(from.component);
            }
            incoming[binding.to.component.0].push(idx);
        }
        let program_used_slots = scenario
            .components
            .iter()
            .enumerate()
            .map(|(idx, component)| {
                component
                    .as_ref()
                    .map(|component| {
                        let _ = idx;
                        collect_program_used_slots(component).into_iter().collect()
                    })
                    .unwrap_or_default()
            })
            .collect();
        let program_used_resources = scenario
            .components
            .iter()
            .enumerate()
            .map(|(idx, component)| {
                component
                    .as_ref()
                    .map(|component| {
                        let _ = idx;
                        collect_program_used_resources(component)
                            .into_iter()
                            .collect()
                    })
                    .unwrap_or_default()
            })
            .collect();

        let n = scenario.components.len();
        Self {
            scenario,
            incoming,
            program_used_slots,
            program_used_resources,
            keep_components: vec![false; n],
            live_programs: vec![false; n],
            live_slots: HashSet::new(),
            live_provides: HashSet::new(),
            live_resources: HashSet::new(),
            live_bindings: vec![false; scenario.bindings.len()],
            work: VecDeque::new(),
        }
    }

    fn solve(mut self) -> DceResults {
        for export in &self.scenario.exports {
            self.mark_provide(export.from.component.0, &export.from.name);
        }
        self.seed_externally_rooted_programs();

        while let Some(item) = self.work.pop_front() {
            match item {
                DceWorkItem::LiveProgram(component) => self.apply_live_program(component),
                DceWorkItem::Slot(key) => self.apply_slot(key),
                DceWorkItem::Provide(key) => self.apply_provide(key),
                DceWorkItem::Resource(key) => self.apply_resource(key),
            }
        }

        DceResults {
            keep_components: self.keep_components,
            live_programs: self.live_programs,
            live_slots: self.live_slots,
            live_provides: self.live_provides,
            live_resources: self.live_resources,
            live_bindings: self.live_bindings,
        }
    }

    fn seed_externally_rooted_programs(&mut self) {
        for binding in &self.scenario.bindings {
            let BindingFrom::External(_) = &binding.from else {
                continue;
            };
            if self.program_used_slots[binding.to.component.0].contains(binding.to.name.as_str()) {
                self.mark_program_live(binding.to.component.0);
            }
        }
    }

    fn apply_live_program(&mut self, component: usize) {
        let component_id = ComponentId(component);
        self.mark_program_used_slots(component_id);
        self.mark_program_used_resources(component_id);
    }

    fn apply_slot(&mut self, key: CapKey) {
        self.mark_component_and_ancestors(key.component);
        // Slot liveness alone should not make a component runnable: a live slot can be needed only
        // for config/binding propagation in a structural realm.

        let incoming_edges = self.incoming[key.component].clone();
        for edge_idx in incoming_edges {
            let edge = &self.scenario.bindings[edge_idx];
            if edge.to.name != key.name.as_ref() || self.live_bindings[edge_idx] {
                continue;
            }
            self.live_bindings[edge_idx] = true;
            match &edge.from {
                BindingFrom::Component(from) => {
                    self.mark_provide(from.component.0, &from.name);
                }
                BindingFrom::Resource(from) => {
                    self.mark_resource(from.component.0, &from.name);
                }
                BindingFrom::External(from) => {
                    // Keep the external root slot declaration when a live binding depends on it.
                    self.mark_slot(from.component.0, &from.name);
                }
                BindingFrom::Framework(_) => {}
            }
        }
    }

    fn apply_provide(&mut self, key: CapKey) {
        self.mark_component_and_ancestors(key.component);
        self.mark_program_live(key.component);
    }

    fn apply_resource(&mut self, key: CapKey) {
        self.mark_component_and_ancestors(key.component);
    }

    fn mark_component_and_ancestors(&mut self, component: usize) {
        let mut cur = Some(ComponentId(component));
        while let Some(id) = cur {
            if self.keep_components[id.0] {
                break;
            }
            self.keep_components[id.0] = true;
            cur = self.scenario.component(id).parent;
        }
    }

    fn mark_program_live(&mut self, component: usize) {
        if self.live_programs[component]
            || self
                .scenario
                .component(ComponentId(component))
                .program
                .is_none()
        {
            return;
        }
        self.live_programs[component] = true;
        self.work.push_back(DceWorkItem::LiveProgram(component));
    }

    fn mark_slot(&mut self, component: usize, slot: &str) {
        let key = CapKey {
            component,
            name: Arc::from(slot),
        };
        if self.live_slots.insert(key.clone()) {
            self.work.push_back(DceWorkItem::Slot(key));
        }
    }

    fn mark_provide(&mut self, component: usize, provide: &str) {
        let key = CapKey {
            component,
            name: Arc::from(provide),
        };
        if self.live_provides.insert(key.clone()) {
            self.work.push_back(DceWorkItem::Provide(key));
        }
    }
    fn mark_resource(&mut self, component: usize, resource: &str) {
        let key = CapKey {
            component,
            name: Arc::from(resource),
        };
        if self.live_resources.insert(key.clone()) {
            self.work.push_back(DceWorkItem::Resource(key));
        }
    }
    fn mark_program_used_slots(&mut self, component: ComponentId) {
        let slots: Vec<String> = self.program_used_slots[component.0]
            .iter()
            .cloned()
            .collect();
        for slot in slots {
            self.mark_slot(component.0, &slot);
        }
    }

    fn mark_program_used_resources(&mut self, component: ComponentId) {
        let resources: Vec<String> = self.program_used_resources[component.0]
            .iter()
            .cloned()
            .collect();
        for resource in resources {
            self.mark_resource(component.0, &resource);
        }
    }
}

fn dce_with_semantics(scenario: Scenario) -> Scenario {
    scenario.assert_invariants();

    let results = DceSolver::new(&scenario).solve();
    let keep = compute_keep_set(
        &scenario,
        &results.keep_components,
        &results.live_slots,
        &results.live_provides,
        &results.live_resources,
    );
    let scenario = prune_and_rebuild_scenario(
        scenario,
        &keep
            .iter()
            .map(|&keep_component| !keep_component)
            .collect::<Vec<_>>(),
        |id, component| {
            if !results.live_programs[id.0] {
                component.program = None;
                component
                    .slots
                    .retain(|name, _| is_live_capability(&results.live_slots, id.0, name));
                component
                    .provides
                    .retain(|name, _| is_live_capability(&results.live_provides, id.0, name));
            }
        },
        |idx, _binding| results.live_bindings[idx],
    );
    scenario.assert_invariants();
    scenario
}

fn is_live_capability(live: &HashSet<CapKey>, component: usize, name: &str) -> bool {
    live.contains(&CapKey {
        component,
        name: Arc::from(name),
    })
}

pub(crate) fn collect_program_used_slots(component: &amber_scenario::Component) -> Vec<String> {
    let Some(program) = component.program.as_ref() else {
        return Vec::new();
    };

    let mut used = BTreeSet::new();
    let mut mark_slot = |slot: &str| {
        used.insert(slot.to_string());
    };
    let all_slots = || component.slots.keys().cloned().collect();

    if program.visit_slot_uses(&mut mark_slot) {
        return all_slots();
    }
    used.into_iter().collect()
}

fn collect_program_used_resources(component: &amber_scenario::Component) -> Vec<String> {
    let Some(program) = component.program.as_ref() else {
        return Vec::new();
    };

    let mut used = BTreeSet::new();
    for mount in program.mounts() {
        if let ProgramMount::Resource { resource, .. } = mount {
            used.insert(resource.clone());
        }
    }

    used.into_iter().collect()
}

fn compute_keep_set(
    scenario: &Scenario,
    keep_components: &[bool],
    live_slots: &HashSet<CapKey>,
    live_provides: &HashSet<CapKey>,
    live_resources: &HashSet<CapKey>,
) -> Vec<bool> {
    let n = scenario.components.len();
    let mut keep = vec![false; n];
    keep[scenario.root.0] = true;

    for (idx, &live) in keep_components.iter().enumerate() {
        keep[idx] |= live;
    }
    for key in live_slots {
        keep[key.component] = true;
    }
    for key in live_provides {
        keep[key.component] = true;
    }
    for key in live_resources {
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

#[cfg(test)]
mod tests {
    use amber_manifest::{Program as ManifestProgram, SlotDecl};
    use amber_scenario::{Moniker, ProvideRef};

    use super::*;
    use crate::linker::program_lowering::lower_program;

    fn component(id: usize, moniker: &str) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            moniker: Moniker::from(Arc::from(moniker)),
            digest: amber_manifest::ManifestDigest::new([id as u8; 32]),
            config: None,
            config_schema: None,
            program: None,
            slots: BTreeMap::new(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            children: Vec::new(),
        }
    }

    fn lower_test_program(id: usize, value: serde_json::Value) -> amber_scenario::Program {
        let program: ManifestProgram = serde_json::from_value(value).expect("manifest program");
        lower_program(ComponentId(id), &program, None).expect("program should lower")
    }

    #[test]
    fn rewrite_bindings_preserves_duplicate_authored_edges() {
        let consumer_program = lower_test_program(
            1,
            serde_json::json!({
                "image": "consumer",
                "entrypoint": ["consumer"],
            }),
        );
        let mut scenario = Scenario {
            root: ComponentId(0),
            components: vec![
                Some(component(0, "/")),
                Some(Component {
                    program: Some(consumer_program),
                    ..component(1, "/consumer")
                }),
                Some(component(2, "/provider")),
            ],
            bindings: vec![
                BindingEdge {
                    from: BindingFrom::Component(ProvideRef {
                        component: ComponentId(2),
                        name: "api".to_string(),
                    }),
                    to: SlotRef {
                        component: ComponentId(1),
                        name: "upstream".to_string(),
                    },
                    weak: false,
                },
                BindingEdge {
                    from: BindingFrom::Component(ProvideRef {
                        component: ComponentId(2),
                        name: "api".to_string(),
                    }),
                    to: SlotRef {
                        component: ComponentId(1),
                        name: "upstream".to_string(),
                    },
                    weak: false,
                },
            ],
            exports: Vec::new(),
        };
        scenario.normalize_order();

        let rewritten = rewrite_bindings(scenario, &HashMap::new());
        assert_eq!(rewritten.bindings.len(), 2);
        assert_eq!(rewritten.bindings[0].to.name, "upstream");
        assert_eq!(rewritten.bindings[1].to.name, "upstream");
    }

    fn slot_decl(kind: &str, optional: bool, multiple: bool) -> SlotDecl {
        let mut value = serde_json::json!({ "kind": kind });
        if optional {
            value["optional"] = serde_json::Value::Bool(true);
        }
        if multiple {
            value["multiple"] = serde_json::Value::Bool(true);
        }
        serde_json::from_value(value).expect("slot decl")
    }

    #[test]
    fn collect_program_used_slots_covers_program_surface() {
        let program = lower_test_program(
            0,
            serde_json::json!({
                "path": "${slots.runner.path}",
                "args": [
                    "${slots.api.url}",
                    { "when": "slots.gate", "argv": ["--gate"] },
                    { "each": "slots.peers", "argv": ["--peer", "${item.url}"] },
                ],
                "env": {
                    "HEADERS_URL": "${slots.headers.url}",
                    "PEERS": {
                        "each": "slots.peers",
                        "value": "${item.url}",
                        "join": ","
                    }
                },
                "mounts": [
                    { "path": "/var/lib/state", "from": "slots.state" }
                ]
            }),
        );

        let mut component = component(0, "/");
        component.program = Some(program);
        component
            .slots
            .insert("api".to_string(), slot_decl("http", false, false));
        component
            .slots
            .insert("gate".to_string(), slot_decl("http", true, false));
        component
            .slots
            .insert("headers".to_string(), slot_decl("http", false, false));
        component
            .slots
            .insert("peers".to_string(), slot_decl("http", true, true));
        component
            .slots
            .insert("runner".to_string(), slot_decl("storage", false, false));
        component
            .slots
            .insert("state".to_string(), slot_decl("storage", false, false));
        component
            .slots
            .insert("unused".to_string(), slot_decl("http", false, false));

        assert_eq!(
            collect_program_used_slots(&component),
            vec![
                "api".to_string(),
                "gate".to_string(),
                "headers".to_string(),
                "peers".to_string(),
                "runner".to_string(),
                "state".to_string(),
            ]
        );
    }

    #[test]
    fn collect_program_used_slots_returns_all_slots_for_whole_slots_interpolation() {
        let program = lower_test_program(
            0,
            serde_json::json!({
                "image": "runner",
                "entrypoint": ["runner"],
                "env": {
                    "ALL_SLOTS": "${slots}"
                }
            }),
        );

        let mut component = component(0, "/");
        component.program = Some(program);
        component
            .slots
            .insert("admin".to_string(), slot_decl("http", false, false));
        component
            .slots
            .insert("api".to_string(), slot_decl("http", false, false));

        assert_eq!(
            collect_program_used_slots(&component),
            vec!["admin".to_string(), "api".to_string()]
        );
    }

    #[test]
    fn collect_program_used_slots_normalizes_lowered_file_mount_slot_queries() {
        let program = lower_test_program(
            0,
            serde_json::json!({
                "image": "runner",
                "entrypoint": ["runner"],
                "mounts": [
                    {
                        "path": "/cfg/${slots.api.url}",
                        "from": "config.mount_file"
                    }
                ]
            }),
        );

        let mut component = component(0, "/");
        component.program = Some(program);
        component
            .slots
            .insert("api".to_string(), slot_decl("http", false, false));
        component
            .slots
            .insert("unused".to_string(), slot_decl("http", false, false));

        assert_eq!(
            collect_program_used_slots(&component),
            vec!["api".to_string()]
        );
    }
}

#[cfg(test)]
mod dce_tests;

#[cfg(test)]
mod flatten_tests;
