use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
};

use amber_manifest::{InterpolatedPart, InterpolationSource, Manifest};
use amber_scenario::{ComponentId, Scenario};

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
        store: &DigestStore,
    ) -> Result<(Scenario, Provenance), PassError> {
        let manifests =
            build_manifest_table(&scenario, store).map_err(|message| PassError::Failed {
                pass: self.name(),
                message,
            })?;

        let n = scenario.components.len();
        let mut incoming = vec![Vec::new(); n];
        for (idx, b) in scenario.bindings.iter().enumerate() {
            incoming[b.to.component.0].push(idx);
        }

        let mut live_program = vec![false; n];
        let mut live_slots: HashSet<CapKey> = HashSet::new();
        let mut live_provides: HashSet<CapKey> = HashSet::new();
        let mut live_bindings = vec![false; scenario.bindings.len()];

        let mut work = VecDeque::new();

        let root = scenario.root;
        let root_manifest = &manifests[root.0];
        for export in root_manifest.exports().keys() {
            let resolved =
                crate::linker::resolve_export(&scenario.components, &manifests, root, export)
                    .map_err(|e| PassError::Failed {
                        pass: self.name(),
                        message: e.to_string(),
                    })?;

            let key = CapKey {
                component: resolved.component.0,
                name: Arc::from(resolved.name),
            };
            if live_provides.insert(key.clone()) {
                work.push_back(WorkItem::Provide(key));
            }
        }

        while let Some(item) = work.pop_front() {
            match item {
                WorkItem::Provide(key) => {
                    let component = key.component;
                    if scenario.components[component].has_program && !live_program[component] {
                        live_program[component] = true;
                        work.push_back(WorkItem::Program(component));
                    }
                }
                WorkItem::Program(component) => {
                    mark_used_slots(component, &manifests[component], &mut live_slots, &mut work);
                }
                WorkItem::Slot(key) => {
                    let component = key.component;
                    if scenario.components[component].has_program && !live_program[component] {
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

                        let provide = CapKey {
                            component: edge.from.component.0,
                            name: Arc::from(edge.from.name.as_str()),
                        };
                        if live_provides.insert(provide.clone()) {
                            work.push_back(WorkItem::Provide(provide));
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

fn build_manifest_table(s: &Scenario, store: &DigestStore) -> Result<Vec<Arc<Manifest>>, String> {
    let mut out = Vec::with_capacity(s.components.len());
    for c in &s.components {
        let Some(m) = store.get(&c.digest) else {
            return Err(format!("missing manifest for digest {}", c.digest));
        };
        out.push(m);
    }
    Ok(out)
}

fn mark_used_slots(
    component: usize,
    manifest: &Manifest,
    live_slots: &mut HashSet<CapKey>,
    work: &mut VecDeque<WorkItem>,
) {
    let Some(program) = manifest.program() else {
        return;
    };

    let mut used_all = false;
    let mut used = Vec::new();

    for arg in &program.args.0 {
        for part in &arg.parts {
            let InterpolatedPart::Interpolation { source, query } = part else {
                continue;
            };
            if *source != InterpolationSource::Slots {
                continue;
            }
            if query.is_empty() {
                used_all = true;
                break;
            }
            let slot = query.split('.').next().unwrap_or_default();
            if slot.is_empty() {
                used_all = true;
                break;
            }
            used.push(slot);
        }
        if used_all {
            break;
        }
    }

    if !used_all {
        for v in program.env.values() {
            for part in &v.parts {
                let InterpolatedPart::Interpolation { source, query } = part else {
                    continue;
                };
                if *source != InterpolationSource::Slots {
                    continue;
                }
                if query.is_empty() {
                    used_all = true;
                    break;
                }
                let slot = query.split('.').next().unwrap_or_default();
                if slot.is_empty() {
                    used_all = true;
                    break;
                }
                used.push(slot);
            }
            if used_all {
                break;
            }
        }
    }

    if used_all {
        for slot in manifest.slots().keys() {
            mark_slot(component, slot.as_str(), live_slots, work);
        }
        return;
    }

    used.sort_unstable();
    used.dedup();
    for slot in used {
        mark_slot(component, slot, live_slots, work);
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
        let mut cur = scenario.components[idx].parent;
        while let Some(parent) = cur {
            if keep[parent.0] {
                break;
            }
            keep[parent.0] = true;
            cur = scenario.components[parent.0].parent;
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
    let Scenario {
        root,
        components,
        bindings,
    } = scenario;

    let mut old_to_new = vec![None; components.len()];
    let mut next = 0usize;
    for (old_idx, keep_component) in keep.iter().copied().enumerate() {
        if !keep_component {
            continue;
        }
        old_to_new[old_idx] = Some(next);
        next += 1;
    }

    let mut new_components = Vec::with_capacity(next);
    for (old_idx, mut c) in components.into_iter().enumerate() {
        if old_to_new[old_idx].is_none() {
            continue;
        }

        let new_idx = old_to_new[old_idx].expect("checked is_some");
        c.id = ComponentId(new_idx);
        c.has_program = c.has_program && live_program[old_idx];
        c.parent = c.parent.and_then(|p| old_to_new[p.0].map(ComponentId));

        c.children = c
            .children
            .into_iter()
            .filter_map(|(name, child)| {
                old_to_new[child.0].map(|mapped| (name, ComponentId(mapped)))
            })
            .collect();

        new_components.push(c);
    }

    let new_root = ComponentId(old_to_new[root.0].expect("root is always kept"));

    let mut new_bindings = Vec::new();
    for (idx, mut b) in bindings.into_iter().enumerate() {
        if !live_bindings[idx] {
            continue;
        }
        let from = old_to_new[b.from.component.0]
            .map(ComponentId)
            .expect("live bindings only reference kept components");
        let to = old_to_new[b.to.component.0]
            .map(ComponentId)
            .expect("live bindings only reference kept components");

        b.from.component = from;
        b.to.component = to;
        new_bindings.push(b);
    }

    let mut new_prov = Vec::new();
    for (idx, p) in provenance.components.into_iter().enumerate() {
        if old_to_new[idx].is_some() {
            new_prov.push(p);
        }
    }

    (
        Scenario {
            root: new_root,
            components: new_components,
            bindings: new_bindings,
        },
        Provenance {
            components: new_prov,
        },
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use amber_manifest::{Manifest, ManifestRef};
    use amber_scenario::{BindingEdge, Component, ComponentId, ProvideRef, Scenario, SlotRef};
    use url::Url;

    use super::DcePass;
    use crate::{ComponentProvenance, DigestStore, Provenance, passes::ScenarioPass};

    #[test]
    fn dce_prunes_unused_transitive_subtree() {
        let root: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: {
            router: "file:///router.json5",
            green: "file:///green.json5",
          },
          exports: { tool_proxy: "#green.tool_proxy" },
        }
        "##
        .parse()
        .unwrap();

        let green: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "green",
            args: ["--llm", "${slots.llm.url}"],
          },
          slots: {
            llm: { kind: "llm" },
            admin_api: { kind: "mcp" },
          },
          provides: { tool_proxy: { kind: "mcp" } },
          exports: { tool_proxy: "tool_proxy" },
        }
        "#
        .parse()
        .unwrap();

        let wrapper: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: { image: "wrapper" },
          slots: { litellm: { kind: "http" } },
          provides: { admin_api: { kind: "mcp" } },
          exports: { admin_api: "admin_api" },
        }
        "##
        .parse()
        .unwrap();

        let router: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: { image: "router" },
          components: { wrapper: "file:///wrapper.json5" },
          provides: {
            llm: { kind: "llm" },
            admin_api: { kind: "http" },
          },
          bindings: [
            { to: "#wrapper.litellm", from: "self.admin_api" },
          ],
          exports: { llm: "llm", admin_api: "#wrapper.admin_api" },
        }
        "##
        .parse()
        .unwrap();

        let store = DigestStore::new();
        let root_digest = root.digest();
        let green_digest = green.digest();
        let router_digest = router.digest();
        let wrapper_digest = wrapper.digest();
        store.put(root_digest, Arc::new(root));
        store.put(green_digest, Arc::new(green));
        store.put(router_digest, Arc::new(router));
        store.put(wrapper_digest, Arc::new(wrapper));

        let mut components = vec![
            Component {
                id: ComponentId(0),
                parent: None,
                name: String::new(),
                has_program: false,
                digest: root_digest,
                config: None,
                children: BTreeMap::new(),
            },
            Component {
                id: ComponentId(1),
                parent: Some(ComponentId(0)),
                name: "router".to_string(),
                has_program: true,
                digest: router_digest,
                config: None,
                children: BTreeMap::new(),
            },
            Component {
                id: ComponentId(2),
                parent: Some(ComponentId(0)),
                name: "green".to_string(),
                has_program: true,
                digest: green_digest,
                config: None,
                children: BTreeMap::new(),
            },
            Component {
                id: ComponentId(3),
                parent: Some(ComponentId(1)),
                name: "wrapper".to_string(),
                has_program: true,
                digest: wrapper_digest,
                config: None,
                children: BTreeMap::new(),
            },
        ];

        components[0]
            .children
            .insert("router".to_string(), ComponentId(1));
        components[0]
            .children
            .insert("green".to_string(), ComponentId(2));
        components[1]
            .children
            .insert("wrapper".to_string(), ComponentId(3));

        let bindings = vec![
            // Root wiring: green.llm <- router.llm
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "llm".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(2),
                    name: "llm".to_string(),
                },
                weak: false,
            },
            // Root wiring: green.admin_api <- router.admin_api (resolved to wrapper.admin_api)
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(3),
                    name: "admin_api".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(2),
                    name: "admin_api".to_string(),
                },
                weak: false,
            },
            // Router internal wiring: wrapper.litellm <- router.admin_api
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "admin_api".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(3),
                    name: "litellm".to_string(),
                },
                weak: false,
            },
        ];

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };

        let url = Url::parse("file:///root.json5").unwrap();
        let provenance = Provenance {
            components: vec![
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url.clone()),
                    digest: root_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url.clone()),
                    digest: router_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url.clone()),
                    digest: green_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url),
                    digest: wrapper_digest,
                    observed_url: None,
                },
            ],
        };

        let (scenario, _prov) = DcePass.run(scenario, provenance, &store).unwrap();

        assert_eq!(scenario.components.len(), 3);
        assert!(
            scenario
                .components
                .iter()
                .all(|c| c.name.as_str() != "wrapper")
        );

        assert_eq!(scenario.bindings.len(), 1);
        let edge = &scenario.bindings[0];
        assert_eq!(edge.from.name, "llm");
        assert_eq!(edge.to.name, "llm");
        assert_eq!(scenario.components[edge.to.component.0].name, "green");
        assert_eq!(scenario.components[edge.from.component.0].name, "router");
    }

    #[test]
    fn dce_keeps_dependencies_for_program_slots() {
        let root: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: {
            consumer: "file:///consumer.json5",
            input: "file:///input.json5",
            llm: "file:///llm.json5",
          },
          exports: { out: "#consumer.out" },
        }
        "##
        .parse()
        .unwrap();

        let consumer: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "consumer",
            args: ["--input", "${slots.input.url}", "--llm", "${slots.llm.url}"],
          },
          slots: {
            input: { kind: "mcp" },
            llm: { kind: "llm" },
          },
          provides: { out: { kind: "mcp" } },
          exports: { out: "out" },
        }
        "##
        .parse()
        .unwrap();

        let input: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: { image: "input" },
          provides: { input: { kind: "mcp" } },
          exports: { input: "input" },
        }
        "##
        .parse()
        .unwrap();

        let llm: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: { image: "llm" },
          provides: { llm: { kind: "llm" } },
          exports: { llm: "llm" },
        }
        "##
        .parse()
        .unwrap();

        let store = DigestStore::new();
        let root_digest = root.digest();
        let consumer_digest = consumer.digest();
        let input_digest = input.digest();
        let llm_digest = llm.digest();
        store.put(root_digest, Arc::new(root));
        store.put(consumer_digest, Arc::new(consumer));
        store.put(input_digest, Arc::new(input));
        store.put(llm_digest, Arc::new(llm));

        let mut components = vec![
            Component {
                id: ComponentId(0),
                parent: None,
                name: String::new(),
                has_program: false,
                digest: root_digest,
                config: None,
                children: BTreeMap::new(),
            },
            Component {
                id: ComponentId(1),
                parent: Some(ComponentId(0)),
                name: "consumer".to_string(),
                has_program: true,
                digest: consumer_digest,
                config: None,
                children: BTreeMap::new(),
            },
            Component {
                id: ComponentId(2),
                parent: Some(ComponentId(0)),
                name: "input".to_string(),
                has_program: true,
                digest: input_digest,
                config: None,
                children: BTreeMap::new(),
            },
            Component {
                id: ComponentId(3),
                parent: Some(ComponentId(0)),
                name: "llm".to_string(),
                has_program: true,
                digest: llm_digest,
                config: None,
                children: BTreeMap::new(),
            },
        ];

        components[0]
            .children
            .insert("consumer".to_string(), ComponentId(1));
        components[0]
            .children
            .insert("input".to_string(), ComponentId(2));
        components[0]
            .children
            .insert("llm".to_string(), ComponentId(3));

        let bindings = vec![
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(2),
                    name: "input".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(1),
                    name: "input".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(3),
                    name: "llm".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(1),
                    name: "llm".to_string(),
                },
                weak: false,
            },
        ];

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };

        let url = Url::parse("file:///root.json5").unwrap();
        let provenance = Provenance {
            components: vec![
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url.clone()),
                    digest: root_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url.clone()),
                    digest: consumer_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url.clone()),
                    digest: input_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url),
                    digest: llm_digest,
                    observed_url: None,
                },
            ],
        };

        let (scenario, _prov) = DcePass.run(scenario, provenance, &store).unwrap();

        assert!(scenario.components.iter().any(|c| c.name == "input"));
        assert!(scenario.components.iter().any(|c| c.name == "llm"));
        assert!(
            scenario
                .bindings
                .iter()
                .any(|edge| edge.from.name == "input" && edge.to.name == "input")
        );
        assert!(
            scenario
                .bindings
                .iter()
                .any(|edge| edge.from.name == "llm" && edge.to.name == "llm")
        );
    }

    #[test]
    fn dce_keeps_program_slots_from_env() {
        let root: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: {
            app: "file:///app.json5",
            admin: "file:///admin.json5",
          },
          exports: { out: "#app.out" },
        }
        "##
        .parse()
        .unwrap();

        let app: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "app",
            env: { ADMIN_URL: "${slots.admin.url}" },
          },
          slots: { admin: { kind: "mcp" } },
          provides: { out: { kind: "mcp" } },
          exports: { out: "out" },
        }
        "##
        .parse()
        .unwrap();

        let admin: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: { image: "admin" },
          provides: { admin: { kind: "mcp" } },
          exports: { admin: "admin" },
        }
        "##
        .parse()
        .unwrap();

        let store = DigestStore::new();
        let root_digest = root.digest();
        let app_digest = app.digest();
        let admin_digest = admin.digest();
        store.put(root_digest, Arc::new(root));
        store.put(app_digest, Arc::new(app));
        store.put(admin_digest, Arc::new(admin));

        let mut components = vec![
            Component {
                id: ComponentId(0),
                parent: None,
                name: String::new(),
                has_program: false,
                digest: root_digest,
                config: None,
                children: BTreeMap::new(),
            },
            Component {
                id: ComponentId(1),
                parent: Some(ComponentId(0)),
                name: "app".to_string(),
                has_program: true,
                digest: app_digest,
                config: None,
                children: BTreeMap::new(),
            },
            Component {
                id: ComponentId(2),
                parent: Some(ComponentId(0)),
                name: "admin".to_string(),
                has_program: true,
                digest: admin_digest,
                config: None,
                children: BTreeMap::new(),
            },
        ];

        components[0]
            .children
            .insert("app".to_string(), ComponentId(1));
        components[0]
            .children
            .insert("admin".to_string(), ComponentId(2));

        let bindings = vec![BindingEdge {
            from: ProvideRef {
                component: ComponentId(2),
                name: "admin".to_string(),
            },
            to: SlotRef {
                component: ComponentId(1),
                name: "admin".to_string(),
            },
            weak: false,
        }];

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };

        let url = Url::parse("file:///root.json5").unwrap();
        let provenance = Provenance {
            components: vec![
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url.clone()),
                    digest: root_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url.clone()),
                    digest: app_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    declared_ref: ManifestRef::from_url(url),
                    digest: admin_digest,
                    observed_url: None,
                },
            ],
        };

        let (scenario, _prov) = DcePass.run(scenario, provenance, &store).unwrap();

        assert!(scenario.components.iter().any(|c| c.name == "admin"));
        assert!(
            scenario
                .bindings
                .iter()
                .any(|edge| edge.from.name == "admin" && edge.to.name == "admin")
        );
    }
}
