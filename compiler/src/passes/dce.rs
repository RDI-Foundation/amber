use std::{
    collections::{HashMap, HashSet, VecDeque},
    sync::Arc,
};

use amber_manifest::Manifest;
use amber_scenario::{ComponentId, Moniker, Scenario};

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
        scenario.assert_invariants();

        let manifests = crate::manifest_table::build_manifest_table(&scenario.components, store)
            .map_err(|e| PassError::Failed {
                pass: self.name(),
                message: format!(
                    "missing manifest for digest {} (component {})",
                    e.digest, e.component.0
                ),
            })?;

        let n = scenario.components.len();
        let mut incoming = vec![Vec::new(); n];
        for (idx, b) in scenario.bindings.iter().enumerate() {
            let _ = scenario.component(b.to.component);
            let _ = scenario.component(b.from.component);
            incoming[b.to.component.0].push(idx);
        }

        let mut live_program = vec![false; n];
        let mut live_slots: HashSet<CapKey> = HashSet::new();
        let mut live_provides: HashSet<CapKey> = HashSet::new();
        let mut live_bindings = vec![false; scenario.bindings.len()];

        let mut work = VecDeque::new();

        let mut id_by_moniker: HashMap<Moniker, ComponentId> =
            HashMap::with_capacity(scenario.components.len());
        for (id, component) in scenario.components_iter() {
            id_by_moniker.insert(component.moniker.clone(), id);
        }
        for export in &provenance.root_exports {
            let Some(&component_id) = id_by_moniker.get(&export.endpoint_component_moniker) else {
                return Err(PassError::Failed {
                    pass: self.name(),
                    message: format!(
                        "root export `{}` targets missing component `{}`",
                        export.name, export.endpoint_component_moniker
                    ),
                });
            };
            let key = CapKey {
                component: component_id.0,
                name: Arc::clone(&export.endpoint_provide),
            };
            if live_provides.insert(key.clone()) {
                work.push_back(WorkItem::Provide(key));
            }
        }

        while let Some(item) = work.pop_front() {
            match item {
                WorkItem::Provide(key) => {
                    let component = key.component;
                    if scenario.component(ComponentId(component)).has_program
                        && !live_program[component]
                    {
                        live_program[component] = true;
                        work.push_back(WorkItem::Program(component));
                    }
                }
                WorkItem::Program(component) => {
                    let manifest = manifests[component]
                        .as_ref()
                        .expect("manifest should exist");
                    mark_used_slots(component, manifest, &mut live_slots, &mut work);
                }
                WorkItem::Slot(key) => {
                    let component = key.component;
                    if scenario.component(ComponentId(component)).has_program
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

fn mark_used_slots(
    component: usize,
    manifest: &Manifest,
    live_slots: &mut HashSet<CapKey>,
    work: &mut VecDeque<WorkItem>,
) {
    let Some(program) = manifest.program() else {
        return;
    };

    let mark_all = |live_slots: &mut HashSet<CapKey>, work: &mut VecDeque<WorkItem>| {
        for slot in manifest.slots().keys() {
            mark_slot(component, slot.as_str(), live_slots, work);
        }
    };

    for arg in &program.args.0 {
        if arg.visit_slot_uses(|slot| mark_slot(component, slot, live_slots, work)) {
            mark_all(live_slots, work);
            return;
        }
    }

    for value in program.env.values() {
        if value.visit_slot_uses(|slot| mark_slot(component, slot, live_slots, work)) {
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
            component.has_program &= live_program[id.0];
        },
        |idx, _binding| live_bindings[idx],
    );
    scenario.assert_invariants();

    (scenario, provenance)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use amber_manifest::{CapabilityKind, Manifest, ManifestRef};
    use amber_scenario::{
        BindingEdge, Component, ComponentId, Moniker, ProvideRef, Scenario, SlotRef,
    };
    use url::Url;

    use super::DcePass;
    use crate::{
        ComponentProvenance, DigestStore, Provenance, RootExportProvenance, passes::ScenarioPass,
    };

    fn component(id: usize, moniker: &str) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            moniker: Moniker::from(Arc::from(moniker)),
            has_program: false,
            digest: amber_manifest::ManifestDigest::new([id as u8; 32]),
            config: None,
            children: Vec::new(),
        }
    }

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
            Some(component(0, "/")),
            Some(component(1, "/router")),
            Some(component(2, "/green")),
            Some(component(3, "/router/wrapper")),
        ];
        components[0].as_mut().unwrap().digest = root_digest;
        components[1].as_mut().unwrap().digest = router_digest;
        components[2].as_mut().unwrap().digest = green_digest;
        components[3].as_mut().unwrap().digest = wrapper_digest;

        components[1].as_mut().unwrap().parent = Some(ComponentId(0));
        components[2].as_mut().unwrap().parent = Some(ComponentId(0));
        components[3].as_mut().unwrap().parent = Some(ComponentId(1));
        components[1].as_mut().unwrap().has_program = true;
        components[2].as_mut().unwrap().has_program = true;
        components[3].as_mut().unwrap().has_program = true;

        components[0]
            .as_mut()
            .unwrap()
            .children
            .extend([ComponentId(1), ComponentId(2)]);
        components[1]
            .as_mut()
            .unwrap()
            .children
            .push(ComponentId(3));

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

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };
        scenario.normalize_child_order_by_moniker();

        let url = Url::parse("file:///root.json5").unwrap();
        let provenance = Provenance {
            components: vec![
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: root_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/router")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: router_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/green")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: green_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/router/wrapper")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url,
                    digest: wrapper_digest,
                    observed_url: None,
                },
            ],
            root_exports: vec![RootExportProvenance {
                name: Arc::from("tool_proxy"),
                endpoint_component_moniker: Moniker::from(Arc::from("/green")),
                endpoint_provide: Arc::from("tool_proxy"),
                kind: CapabilityKind::Mcp,
            }],
        };

        let (scenario, _prov) = DcePass.run(scenario, provenance, &store).unwrap();

        assert_eq!(scenario.components.iter().flatten().count(), 3);
        assert!(
            !scenario
                .components
                .iter()
                .flatten()
                .any(|c| c.moniker.local_name() == Some("wrapper"))
        );

        assert_eq!(scenario.bindings.len(), 1);
        let edge = &scenario.bindings[0];
        assert_eq!(edge.from.name, "llm");
        assert_eq!(edge.to.name, "llm");
        assert_eq!(
            scenario.components[edge.to.component.0]
                .as_ref()
                .unwrap()
                .moniker
                .local_name(),
            Some("green")
        );
        assert_eq!(
            scenario.components[edge.from.component.0]
                .as_ref()
                .unwrap()
                .moniker
                .local_name(),
            Some("router")
        );
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
            Some(component(0, "/")),
            Some(component(1, "/consumer")),
            Some(component(2, "/input")),
            Some(component(3, "/llm")),
        ];
        components[0].as_mut().unwrap().digest = root_digest;
        components[1].as_mut().unwrap().digest = consumer_digest;
        components[2].as_mut().unwrap().digest = input_digest;
        components[3].as_mut().unwrap().digest = llm_digest;

        components[1].as_mut().unwrap().parent = Some(ComponentId(0));
        components[2].as_mut().unwrap().parent = Some(ComponentId(0));
        components[3].as_mut().unwrap().parent = Some(ComponentId(0));
        components[1].as_mut().unwrap().has_program = true;
        components[2].as_mut().unwrap().has_program = true;
        components[3].as_mut().unwrap().has_program = true;

        components[0].as_mut().unwrap().children.extend([
            ComponentId(1),
            ComponentId(2),
            ComponentId(3),
        ]);

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

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };
        scenario.normalize_child_order_by_moniker();

        let url = Url::parse("file:///root.json5").unwrap();
        let provenance = Provenance {
            components: vec![
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: root_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/consumer")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: consumer_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/input")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: input_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/llm")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url,
                    digest: llm_digest,
                    observed_url: None,
                },
            ],
            root_exports: vec![RootExportProvenance {
                name: Arc::from("out"),
                endpoint_component_moniker: Moniker::from(Arc::from("/consumer")),
                endpoint_provide: Arc::from("out"),
                kind: CapabilityKind::Mcp,
            }],
        };

        let (scenario, _prov) = DcePass.run(scenario, provenance, &store).unwrap();

        assert!(
            scenario
                .components
                .iter()
                .flatten()
                .any(|c| c.moniker.local_name() == Some("input"))
        );
        assert!(
            scenario
                .components
                .iter()
                .flatten()
                .any(|c| c.moniker.local_name() == Some("llm"))
        );
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
            Some(component(0, "/")),
            Some(component(1, "/app")),
            Some(component(2, "/admin")),
        ];
        components[0].as_mut().unwrap().digest = root_digest;
        components[1].as_mut().unwrap().digest = app_digest;
        components[2].as_mut().unwrap().digest = admin_digest;

        components[1].as_mut().unwrap().parent = Some(ComponentId(0));
        components[2].as_mut().unwrap().parent = Some(ComponentId(0));
        components[1].as_mut().unwrap().has_program = true;
        components[2].as_mut().unwrap().has_program = true;

        components[0]
            .as_mut()
            .unwrap()
            .children
            .extend([ComponentId(1), ComponentId(2)]);

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

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings,
        };
        scenario.normalize_child_order_by_moniker();

        let url = Url::parse("file:///root.json5").unwrap();
        let provenance = Provenance {
            components: vec![
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: root_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/app")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: app_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/admin")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url,
                    digest: admin_digest,
                    observed_url: None,
                },
            ],
            root_exports: vec![RootExportProvenance {
                name: Arc::from("out"),
                endpoint_component_moniker: Moniker::from(Arc::from("/app")),
                endpoint_provide: Arc::from("out"),
                kind: CapabilityKind::Mcp,
            }],
        };

        let (scenario, _prov) = DcePass.run(scenario, provenance, &store).unwrap();

        assert!(
            scenario
                .components
                .iter()
                .flatten()
                .any(|c| c.moniker.local_name() == Some("admin"))
        );
        assert!(
            scenario
                .bindings
                .iter()
                .any(|edge| edge.from.name == "admin" && edge.to.name == "admin")
        );
    }
}
