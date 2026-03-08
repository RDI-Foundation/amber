use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    sync::Arc,
};

use amber_manifest::{
    BindingSource, BindingTarget, InterpolationSource, Manifest, SlotTarget, parse_slot_query,
};
use amber_scenario::{BindingEdge, BindingFrom, Component, ComponentId, Scenario, SlotRef};
use miette::Diagnostic;
use thiserror::Error;

use crate::{DigestStore, Provenance, binding_usage, manifest_table};

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
    mir.verify_binding_interpolations()?;
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

pub(crate) fn verify_binding_interpolations(scenario: &Scenario) -> Result<(), Error> {
    let usage = binding_usage::collect_binding_usage(scenario);
    let declared_bindings = declared_bindings_by_scope(scenario);
    let targets = binding_targets_by_name(scenario);
    let incoming_slots = incoming_slot_set(scenario);
    let mut failures = Vec::new();

    for (&scope, names) in usage.iter() {
        let scope_label = scenario
            .components
            .get(scope.0)
            .and_then(|component| component.as_ref())
            .map(|component| component.moniker.as_str().to_string())
            .unwrap_or_else(|| format!("#{}", scope.0));

        for name in names {
            let declaration_missing = declared_bindings
                .get(&scope)
                .is_none_or(|declared_names| !declared_names.contains(name));
            if declaration_missing {
                failures.push(format!(
                    "{scope_label}: bindings.{name}.url has no binding declaration in this scope"
                ));
                continue;
            }

            let key = (scope, name.clone());
            let Some(bound_targets) = targets.get(&key) else {
                failures.push(format!(
                    "{scope_label}: bindings.{name}.url has no binding declaration"
                ));
                continue;
            };

            let reachable = bound_targets
                .iter()
                .any(|slot| incoming_slots.contains(&(slot.component, slot.name.clone())));
            if reachable {
                continue;
            }

            let target = &bound_targets[0];
            let target_component = scenario
                .components
                .get(target.component.0)
                .and_then(|component| component.as_ref())
                .map(|component| component.moniker.as_str().to_string())
                .unwrap_or_else(|| format!("#{}", target.component.0));
            failures.push(format!(
                "{scope_label}: bindings.{name}.url resolves to {target_component}.{}, but no \
                 binding edge reaches that slot",
                target.name
            ));
        }
    }

    if failures.is_empty() {
        return Ok(());
    }

    Err(Error::Failed {
        pass: "binding_invariant",
        message: format!(
            "unresolvable bindings interpolation paths after MIR pipeline: {}",
            failures.join("; ")
        ),
    })
}

struct MirScenario<'a> {
    scenario: Scenario,
    provenance: Provenance,
    store: &'a DigestStore,
    graph: BindingGraph,
}

impl<'a> MirScenario<'a> {
    fn lower(
        scenario: Scenario,
        provenance: Provenance,
        store: &'a DigestStore,
    ) -> Result<Self, Error> {
        scenario.assert_invariants();
        let graph = BindingGraph::build(&scenario, store, "mir_lower")?;
        Ok(Self {
            scenario,
            provenance,
            store,
            graph,
        })
    }

    fn rebuild_graph(&mut self, pass: &'static str) -> Result<(), Error> {
        self.graph = BindingGraph::build(&self.scenario, self.store, pass)?;
        Ok(())
    }

    fn canonicalize_bindings(&mut self) {
        let scenario = take_scenario(&mut self.scenario);
        let scenario = rewrite_bindings(scenario, &self.graph.forward_map);
        self.scenario = rewrite_binding_decls(scenario, &self.graph.forward_map);
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

    fn verify_binding_interpolations(&mut self) -> Result<(), Error> {
        self.rebuild_graph("mir_verify")?;
        verify_binding_interpolations(&self.scenario)
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

    for component in &scenario.components {
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

fn flatten_pure_routing_with_graph(scenario: Scenario, graph: &BindingGraph) -> Scenario {
    let n = scenario.components.len();
    let binding_usage = binding_usage::collect_binding_usage(&scenario);
    let scopes_with_binding_usage: HashSet<ComponentId> = binding_usage
        .iter()
        .filter_map(|(scope, names)| (!names.is_empty()).then_some(*scope))
        .collect();

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
        let manifest = graph.manifests[idx]
            .as_ref()
            .expect("manifest should exist");
        if referenced_by_binding[idx] {
            continue;
        }
        if scopes_with_binding_usage.contains(&id) {
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
}

struct DceResults {
    keep_components: Vec<bool>,
    live_programs: Vec<bool>,
    live_slots: HashSet<CapKey>,
    live_provides: HashSet<CapKey>,
    live_bindings: Vec<bool>,
}

struct DceSolver<'a> {
    scenario: &'a Scenario,
    incoming: Vec<Vec<usize>>,
    usage: binding_usage::BindingUsage,
    targets_by_name: HashMap<(ComponentId, String), Vec<SlotRef>>,
    keep_components: Vec<bool>,
    live_programs: Vec<bool>,
    live_slots: HashSet<CapKey>,
    live_provides: HashSet<CapKey>,
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
            incoming[binding.to.component.0].push(idx);
        }

        let n = scenario.components.len();
        Self {
            scenario,
            incoming,
            usage: binding_usage::collect_binding_usage(scenario),
            targets_by_name: binding_targets_by_name(scenario),
            keep_components: vec![false; n],
            live_programs: vec![false; n],
            live_slots: HashSet::new(),
            live_provides: HashSet::new(),
            live_bindings: vec![false; scenario.bindings.len()],
            work: VecDeque::new(),
        }
    }

    fn solve(mut self) -> DceResults {
        for export in &self.scenario.exports {
            self.mark_provide(export.from.component.0, &export.from.name);
        }

        while let Some(item) = self.work.pop_front() {
            match item {
                DceWorkItem::LiveProgram(component) => self.apply_live_program(component),
                DceWorkItem::Slot(key) => self.apply_slot(key),
                DceWorkItem::Provide(key) => self.apply_provide(key),
            }
        }

        DceResults {
            keep_components: self.keep_components,
            live_programs: self.live_programs,
            live_slots: self.live_slots,
            live_provides: self.live_provides,
            live_bindings: self.live_bindings,
        }
    }

    fn apply_live_program(&mut self, component: usize) {
        let component_id = ComponentId(component);
        self.mark_program_used_slots(component_id);
        self.mark_binding_targets(component_id, binding_usage::BindingUseSource::Program);
        self.mark_binding_targets(component_id, binding_usage::BindingUseSource::Config);
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

    fn mark_binding_targets(
        &mut self,
        component: ComponentId,
        source: binding_usage::BindingUseSource,
    ) {
        let uses: Vec<(ComponentId, String)> = self
            .usage
            .for_component_with_source(component, source)
            .map(|binding_use| (binding_use.scope, binding_use.name.clone()))
            .collect();

        for (scope, name) in uses {
            let key = (scope, name);
            let Some(target_slots) = self.targets_by_name.get(&key).cloned() else {
                continue;
            };
            for target in target_slots {
                self.mark_slot(target.component.0, &target.name);
            }
        }
    }

    fn mark_program_used_slots(&mut self, component: ComponentId) {
        for slot in collect_program_used_slots(self.scenario.component(component)) {
            self.mark_slot(component.0, &slot);
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

fn collect_slot_condition_use(query: &str, mut mark_slot: impl FnMut(&str)) -> bool {
    match parse_slot_query(query) {
        Ok(parsed) => match parsed.target {
            SlotTarget::All => true,
            SlotTarget::Slot(slot) => {
                mark_slot(slot);
                false
            }
        },
        Err(_) => query.is_empty(),
    }
}

fn collect_program_used_slots(component: &amber_scenario::Component) -> Vec<String> {
    let Some(program) = component.program.as_ref() else {
        return Vec::new();
    };

    let mut used = BTreeSet::new();
    let mark_slot = |slot: &str, used: &mut BTreeSet<String>| {
        used.insert(slot.to_string());
    };
    let all_slots = || component.slots.keys().cloned().collect();

    if let Some(executable) = program.path_ref().or_else(|| program.image_ref())
        && let Ok(parsed) = executable.parse::<amber_manifest::InterpolatedString>()
        && parsed.visit_slot_uses(|slot| mark_slot(slot, &mut used))
    {
        return all_slots();
    }

    for group in program.command().groups() {
        if group.when.source() == InterpolationSource::Slots
            && collect_slot_condition_use(group.when.query(), |slot| mark_slot(slot, &mut used))
        {
            return all_slots();
        }
    }

    for item in &program.command().0 {
        match item {
            amber_manifest::ProgramArgItem::Arg(arg) => {
                if arg.visit_slot_uses(|slot| mark_slot(slot, &mut used)) {
                    return all_slots();
                }
            }
            amber_manifest::ProgramArgItem::Group(group) => {
                for arg in &group.argv.0 {
                    if arg.visit_slot_uses(|slot| mark_slot(slot, &mut used)) {
                        return all_slots();
                    }
                }
            }
        }
    }

    for value in program.env().values() {
        if let Some(when) = value.when()
            && when.source() == InterpolationSource::Slots
            && collect_slot_condition_use(when.query(), |slot| mark_slot(slot, &mut used))
        {
            return all_slots();
        }
        if value
            .value()
            .visit_slot_uses(|slot| mark_slot(slot, &mut used))
        {
            return all_slots();
        }
    }

    used.into_iter().collect()
}

fn compute_keep_set(
    scenario: &Scenario,
    keep_components: &[bool],
    live_slots: &HashSet<CapKey>,
    live_provides: &HashSet<CapKey>,
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

fn declared_bindings_by_scope(scenario: &Scenario) -> HashMap<ComponentId, BTreeSet<String>> {
    let mut out: HashMap<ComponentId, BTreeSet<String>> = HashMap::new();
    for (id, component) in scenario.components_iter() {
        for name in component.binding_decls.keys() {
            out.entry(id).or_default().insert(name.clone());
        }
    }
    for binding in &scenario.bindings {
        let Some(name) = binding.name.as_ref() else {
            continue;
        };
        out.entry(binding.to.component)
            .or_default()
            .insert(name.clone());
    }
    out
}

fn binding_targets_by_name(scenario: &Scenario) -> HashMap<(ComponentId, String), Vec<SlotRef>> {
    let mut out: HashMap<(ComponentId, String), Vec<SlotRef>> = HashMap::new();

    for (id, component) in scenario.components_iter() {
        for (name, slot_ref) in &component.binding_decls {
            let values = out.entry((id, name.clone())).or_default();
            if !values.contains(slot_ref) {
                values.push(slot_ref.clone());
            }
        }
    }
    for binding in &scenario.bindings {
        let Some(name) = binding.name.as_ref() else {
            continue;
        };
        let values = out.entry((binding.to.component, name.clone())).or_default();
        if !values.contains(&binding.to) {
            values.push(binding.to.clone());
        }
    }

    for values in out.values_mut() {
        values.sort_by(|a, b| (a.component, a.name.as_str()).cmp(&(b.component, b.name.as_str())));
    }

    out
}

fn incoming_slot_set(scenario: &Scenario) -> HashSet<(ComponentId, String)> {
    let mut out = HashSet::with_capacity(scenario.bindings.len());
    for binding in &scenario.bindings {
        out.insert((binding.to.component, binding.to.name.clone()));
    }
    out
}

#[cfg(test)]
mod dce_tests;

#[cfg(test)]
mod flatten_tests;
