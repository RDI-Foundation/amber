use amber_manifest::Manifest;
use amber_scenario::{Component, ComponentId, Scenario};

use super::{PassError, ScenarioPass};
use crate::{DigestStore, Provenance};

#[derive(Clone, Copy, Debug, Default)]
pub struct FlattenPass;

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

        let manifests = crate::manifest_table::build_manifest_table(&scenario.components, store)
            .map_err(|e| PassError::Failed {
                pass: self.name(),
                message: format!(
                    "missing manifest for digest {} (component {})",
                    e.digest, e.component.0
                ),
            })?;

        let n = scenario.components.len();
        let mut referenced_by_binding = vec![false; n];
        for b in &scenario.bindings {
            referenced_by_binding[b.from.component.0] = true;
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
            if referenced_by_binding[idx] {
                continue;
            }
            let manifest = manifests[idx].as_ref().expect("manifest should exist");
            if is_pure_routing(component, manifest) {
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

fn is_pure_routing(component: &Component, manifest: &Manifest) -> bool {
    !component.has_program
        && component.config.is_none()
        && !component.children.is_empty()
        && manifest.slots().is_empty()
        && manifest.provides().is_empty()
        && manifest.bindings().is_empty()
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
mod tests {
    use std::sync::Arc;

    use amber_manifest::{CapabilityKind, Manifest, ManifestRef};
    use amber_scenario::{
        BindingEdge, Component, ComponentId, Moniker, ProvideRef, Scenario, SlotRef,
    };
    use url::Url;

    use super::FlattenPass;
    use crate::{
        CompileOutput, ComponentProvenance, DigestStore, Provenance, RootExportProvenance,
        passes::ScenarioPass,
        reporter::{DotReporter, Reporter as _},
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
    fn flatten_removes_pure_routing_nodes_and_preserves_debug_data() {
        let root_manifest: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: { parent: "file:///parent.json5" },
          exports: { cap: "#parent.cap" },
        }
        "##
        .parse()
        .unwrap();

        let parent_manifest: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: { child: "file:///child.json5" },
          exports: { cap: "#child.cap" },
        }
        "##
        .parse()
        .unwrap();

        let child_manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            network: { endpoints: [{ name: "cap", port: 80 }] },
          },
          provides: { cap: { kind: "http", endpoint: "cap" } },
          exports: { cap: "cap" },
        }
        "#
        .parse()
        .unwrap();

        let store = DigestStore::new();
        let root_digest = root_manifest.digest();
        let parent_digest = parent_manifest.digest();
        let child_digest = child_manifest.digest();
        store.put(root_digest, Arc::new(root_manifest));
        store.put(parent_digest, Arc::new(parent_manifest));
        store.put(child_digest, Arc::new(child_manifest));

        let mut components = vec![
            Some(component(0, "/")),
            Some(component(1, "/parent")),
            Some(component(2, "/parent/child")),
        ];
        components[0].as_mut().unwrap().digest = root_digest;
        components[1].as_mut().unwrap().digest = parent_digest;
        components[2].as_mut().unwrap().digest = child_digest;

        components[1].as_mut().unwrap().parent = Some(ComponentId(0));
        components[2].as_mut().unwrap().parent = Some(ComponentId(1));

        components[0]
            .as_mut()
            .unwrap()
            .children
            .push(ComponentId(1));
        components[1]
            .as_mut()
            .unwrap()
            .children
            .push(ComponentId(2));

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: vec![BindingEdge {
                from: ProvideRef {
                    component: ComponentId(2),
                    name: "cap".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(2),
                    name: "cap".to_string(),
                },
                weak: true,
            }],
        };
        scenario.normalize_child_order_by_moniker();

        let url = Url::parse("file:///scenario.json5").unwrap();
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
                    authored_moniker: Moniker::from(Arc::from("/parent")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: parent_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/parent/child")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url,
                    digest: child_digest,
                    observed_url: None,
                },
            ],
            root_exports: vec![RootExportProvenance {
                name: Arc::from("cap"),
                endpoint_component_moniker: Moniker::from(Arc::from("/parent/child")),
                endpoint_provide: Arc::from("cap"),
                kind: CapabilityKind::Http,
            }],
        };

        let (scenario, provenance) = FlattenPass.run(scenario, provenance, &store).unwrap();

        assert_eq!(scenario.components.iter().flatten().count(), 2);
        assert_eq!(provenance.components.len(), 3);

        assert_eq!(
            provenance
                .for_component(ComponentId(2))
                .authored_moniker
                .as_str(),
            "/parent/child"
        );
        assert_eq!(provenance.root_exports.len(), 1);
        assert_eq!(
            provenance.root_exports[0]
                .endpoint_component_moniker
                .as_str(),
            "/parent/child"
        );

        let root_children = &scenario.components[scenario.root.0]
            .as_ref()
            .unwrap()
            .children;
        assert_eq!(root_children.len(), 1);
        let child_id = root_children[0];
        assert_eq!(
            scenario.components[child_id.0]
                .as_ref()
                .unwrap()
                .moniker
                .as_str(),
            "/parent/child"
        );

        let output = CompileOutput {
            scenario,
            store,
            provenance,
            diagnostics: Vec::new(),
        };
        let dot = DotReporter.emit(&output).unwrap();
        assert!(dot.contains("c2 [label=\"/parent/child\"]"), "{dot}");
        assert!(dot.contains("c2 -> e0 [label=\"http\"]"));
    }

    #[test]
    fn flatten_allows_same_name_siblings() {
        let root_manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          components: {
            parent: "file:///parent.json5",
            child: "file:///child_a.json5",
          },
        }
        "#
        .parse()
        .unwrap();

        let parent_manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          components: { child: "file:///child_b.json5" },
        }
        "#
        .parse()
        .unwrap();

        let child_a_manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child_a",
            network: { endpoints: [{ name: "cap", port: 80 }] },
          },
          provides: { cap: { kind: "http", endpoint: "cap" } },
          exports: { cap: "cap" },
        }
        "#
        .parse()
        .unwrap();

        let child_b_manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child_b",
            network: { endpoints: [{ name: "cap", port: 80 }] },
          },
          provides: { cap: { kind: "http", endpoint: "cap" } },
          exports: { cap: "cap" },
        }
        "#
        .parse()
        .unwrap();

        let store = DigestStore::new();
        let root_digest = root_manifest.digest();
        let parent_digest = parent_manifest.digest();
        let child_a_digest = child_a_manifest.digest();
        let child_b_digest = child_b_manifest.digest();
        store.put(root_digest, Arc::new(root_manifest));
        store.put(parent_digest, Arc::new(parent_manifest));
        store.put(child_a_digest, Arc::new(child_a_manifest));
        store.put(child_b_digest, Arc::new(child_b_manifest));

        let mut components = vec![
            Some(component(0, "/")),
            Some(component(1, "/parent/child")), // nested; will be reparented to root
            Some(component(2, "/parent")),       // routing
            Some(component(3, "/child")),        // existing root child
        ];
        components[0].as_mut().unwrap().digest = root_digest;
        components[1].as_mut().unwrap().digest = child_b_digest;
        components[2].as_mut().unwrap().digest = parent_digest;
        components[3].as_mut().unwrap().digest = child_a_digest;

        components[1].as_mut().unwrap().parent = Some(ComponentId(2));
        components[2].as_mut().unwrap().parent = Some(ComponentId(0));
        components[3].as_mut().unwrap().parent = Some(ComponentId(0));

        components[0]
            .as_mut()
            .unwrap()
            .children
            .extend([ComponentId(2), ComponentId(3)]);
        components[2]
            .as_mut()
            .unwrap()
            .children
            .push(ComponentId(1));

        let mut scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: Vec::new(),
        };
        scenario.normalize_child_order_by_moniker();

        let url = Url::parse("file:///scenario.json5").unwrap();
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
                    authored_moniker: Moniker::from(Arc::from("/parent/child")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: child_b_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/parent")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: parent_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_moniker: Moniker::from(Arc::from("/child")),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url,
                    digest: child_a_digest,
                    observed_url: None,
                },
            ],
            root_exports: Vec::new(),
        };

        let (scenario, provenance) = FlattenPass.run(scenario, provenance, &store).unwrap();
        assert_eq!(scenario.components.len(), 4);
        assert_eq!(provenance.components.len(), 4);

        let root = scenario.root;
        let root_children = &scenario.components[root.0].as_ref().unwrap().children;
        assert_eq!(root_children.len(), 2);
        let mut child_monikers: Vec<_> = root_children
            .iter()
            .map(|id| scenario.components[id.0].as_ref().unwrap().moniker.as_str())
            .collect();
        child_monikers.sort();
        assert_eq!(child_monikers, vec!["/child", "/parent/child"]);
        assert!(scenario.components[2].is_none());
        assert_eq!(scenario.components[1].as_ref().unwrap().parent, Some(root));
    }
}
