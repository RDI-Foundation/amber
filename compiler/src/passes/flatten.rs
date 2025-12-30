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
        let Scenario {
            root,
            components,
            bindings,
        } = scenario;
        let Provenance {
            components: prov_components,
            root_exports,
        } = provenance;

        let manifests =
            crate::manifest_table::build_manifest_table(&components, store).map_err(|e| {
                PassError::Failed {
                    pass: self.name(),
                    message: format!(
                        "missing manifest for digest {} (component {})",
                        e.digest, e.component.0
                    ),
                }
            })?;

        let n = components.len();
        let mut referenced_by_binding = vec![false; n];
        for b in &bindings {
            referenced_by_binding[b.from.component.0] = true;
            referenced_by_binding[b.to.component.0] = true;
        }

        let mut remove = vec![false; n];
        for idx in 0..n {
            let id = ComponentId(idx);
            if id == root {
                continue;
            }
            if referenced_by_binding[idx] {
                continue;
            }
            if is_pure_routing(&components[idx], &manifests[idx]) {
                remove[idx] = true;
            }
        }

        resolve_name_collisions(&components, root, &mut remove).map_err(|message| {
            PassError::Failed {
                pass: self.name(),
                message,
            }
        })?;

        let mut new_parent: Vec<Option<ComponentId>> = vec![None; n];
        for idx in 0..n {
            if remove[idx] {
                continue;
            }
            new_parent[idx] = nearest_kept_ancestor(&components, &remove, components[idx].parent);
        }

        let mut old_to_new = vec![None; n];
        let mut next = 0usize;
        for (old_idx, &is_removed) in remove.iter().enumerate() {
            if is_removed {
                continue;
            }
            old_to_new[old_idx] = Some(next);
            next += 1;
        }

        let new_root = ComponentId(old_to_new[root.0].expect("root is never removed"));

        let mut new_components = Vec::with_capacity(next);
        for (old_idx, mut c) in components.into_iter().enumerate() {
            let Some(new_idx) = old_to_new[old_idx] else {
                continue;
            };
            c.id = ComponentId(new_idx);
            c.parent = new_parent[old_idx].and_then(|p| old_to_new[p.0].map(ComponentId));
            c.children = Default::default();
            new_components.push(c);
        }

        let mut edges = Vec::with_capacity(new_components.len().saturating_sub(1));
        for (child_idx, child) in new_components.iter().enumerate() {
            let Some(parent_id) = child.parent else {
                continue;
            };
            let name = child.name.clone();
            edges.push((parent_id, name, ComponentId(child_idx)));
        }
        for (parent_id, name, child_id) in edges {
            let prev = new_components[parent_id.0]
                .children
                .insert(name.clone(), child_id);
            if prev.is_some() {
                return Err(PassError::Failed {
                    pass: self.name(),
                    message: format!(
                        "flatten would create duplicate child name `{name}` under component {}",
                        parent_id.0
                    ),
                });
            }
        }

        let mut new_bindings = Vec::with_capacity(bindings.len());
        for mut b in bindings.into_iter() {
            let from = old_to_new[b.from.component.0]
                .map(ComponentId)
                .expect("flatten does not remove components referenced by bindings");
            let to = old_to_new[b.to.component.0]
                .map(ComponentId)
                .expect("flatten does not remove components referenced by bindings");
            b.from.component = from;
            b.to.component = to;
            new_bindings.push(b);
        }

        let mut new_prov_components = Vec::with_capacity(next);
        for (old_idx, p) in prov_components.into_iter().enumerate() {
            if old_to_new[old_idx].is_some() {
                new_prov_components.push(p);
            }
        }

        Ok((
            Scenario {
                root: new_root,
                components: new_components,
                bindings: new_bindings,
            },
            Provenance {
                components: new_prov_components,
                root_exports,
            },
        ))
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
    components: &[Component],
    remove: &[bool],
    mut cur: Option<ComponentId>,
) -> Option<ComponentId> {
    while let Some(id) = cur {
        if !remove[id.0] {
            break;
        }
        cur = components[id.0].parent;
    }
    cur
}

fn resolve_name_collisions(
    components: &[Component],
    root: ComponentId,
    remove: &mut [bool],
) -> Result<(), String> {
    use std::collections::HashMap;

    loop {
        let mut seen: HashMap<(ComponentId, &str), ComponentId> =
            HashMap::with_capacity(components.len());
        let mut fix: Option<ComponentId> = None;

        for idx in 0..components.len() {
            let id = ComponentId(idx);
            if id == root || remove[idx] {
                continue;
            }

            let Some(parent) = nearest_kept_ancestor(components, remove, components[idx].parent)
            else {
                continue;
            };

            let name = components[idx].name.as_str();
            let key = (parent, name);
            let Some(&prev) = seen.get(&key) else {
                seen.insert(key, id);
                continue;
            };

            fix =
                first_removed_ancestor_on_path(components, remove, components[idx].parent, parent)
                    .or_else(|| {
                        first_removed_ancestor_on_path(
                            components,
                            remove,
                            components[prev.0].parent,
                            parent,
                        )
                    });

            if fix.is_none() {
                return Err(format!(
                    "flatten cannot resolve name collision `{name}` under component {} \
                     (components {} and {})",
                    parent.0, prev.0, id.0
                ));
            }
            break;
        }

        let Some(fix) = fix else {
            return Ok(());
        };
        remove[fix.0] = false;
    }
}

fn first_removed_ancestor_on_path(
    components: &[Component],
    remove: &[bool],
    mut cur: Option<ComponentId>,
    stop: ComponentId,
) -> Option<ComponentId> {
    while let Some(id) = cur {
        if id == stop {
            return None;
        }
        if remove[id.0] {
            return Some(id);
        }
        cur = components[id.0].parent;
    }
    None
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, sync::Arc};

    use amber_manifest::{CapabilityKind, Manifest, ManifestRef};
    use amber_scenario::{BindingEdge, Component, ComponentId, ProvideRef, Scenario, SlotRef};
    use url::Url;

    use super::FlattenPass;
    use crate::{
        CompileOutput, ComponentProvenance, DigestStore, Provenance, RootExportProvenance,
        backend::{Backend as _, DotBackend},
        passes::ScenarioPass,
    };

    fn component(id: usize, name: &str) -> Component {
        Component {
            id: ComponentId(id),
            parent: None,
            name: name.to_string(),
            has_program: false,
            digest: amber_manifest::ManifestDigest::new([id as u8; 32]),
            config: None,
            children: BTreeMap::new(),
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
          provides: { cap: { kind: "http" } },
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
            component(0, ""),
            component(1, "parent"),
            component(2, "child"),
        ];
        components[0].digest = root_digest;
        components[1].digest = parent_digest;
        components[2].digest = child_digest;

        components[1].parent = Some(ComponentId(0));
        components[2].parent = Some(ComponentId(1));

        components[0]
            .children
            .insert("parent".to_string(), ComponentId(1));
        components[1]
            .children
            .insert("child".to_string(), ComponentId(2));

        let scenario = Scenario {
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

        let url = Url::parse("file:///scenario.json5").unwrap();
        let provenance = Provenance {
            components: vec![
                ComponentProvenance {
                    authored_path: Arc::from("/"),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: root_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_path: Arc::from("/parent"),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: parent_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_path: Arc::from("/parent/child"),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url,
                    digest: child_digest,
                    observed_url: None,
                },
            ],
            root_exports: vec![RootExportProvenance {
                name: Arc::from("cap"),
                endpoint_component_path: Arc::from("/parent/child"),
                endpoint_provide: Arc::from("cap"),
                kind: CapabilityKind::Http,
            }],
        };

        let (scenario, provenance) = FlattenPass.run(scenario, provenance, &store).unwrap();

        assert_eq!(scenario.components.len(), 2);
        assert_eq!(provenance.components.len(), 2);

        assert_eq!(
            provenance
                .for_component(ComponentId(1))
                .authored_path
                .as_ref(),
            "/parent/child"
        );
        assert_eq!(provenance.root_exports.len(), 1);
        assert_eq!(
            provenance.root_exports[0].endpoint_component_path.as_ref(),
            "/parent/child"
        );

        assert_eq!(scenario.components[scenario.root.0].children.len(), 1);
        assert!(
            scenario.components[scenario.root.0]
                .children
                .contains_key("child")
        );

        let output = CompileOutput {
            scenario,
            store,
            provenance,
            diagnostics: Vec::new(),
        };
        let dot = DotBackend.emit(&output).unwrap();
        assert!(
            dot.contains("c1 [label=\"/parent/child\\n(opt: /child)\""),
            "{dot}"
        );
        assert!(dot.contains("c1 -> e0 [label=\"http\"]"));
    }

    #[test]
    fn flatten_keeps_routing_node_to_avoid_sibling_name_collision() {
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
          provides: { cap: { kind: "http" } },
          exports: { cap: "cap" },
        }
        "#
        .parse()
        .unwrap();

        let child_b_manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          provides: { cap: { kind: "http" } },
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
            component(0, ""),
            component(1, "child"),  // nested; would be reparented to root
            component(2, "parent"), // routing
            component(3, "child"),  // existing root child
        ];
        components[0].digest = root_digest;
        components[1].digest = child_b_digest;
        components[2].digest = parent_digest;
        components[3].digest = child_a_digest;

        components[1].parent = Some(ComponentId(2));
        components[2].parent = Some(ComponentId(0));
        components[3].parent = Some(ComponentId(0));

        components[0]
            .children
            .insert("parent".to_string(), ComponentId(2));
        components[0]
            .children
            .insert("child".to_string(), ComponentId(3));
        components[2]
            .children
            .insert("child".to_string(), ComponentId(1));

        let scenario = Scenario {
            root: ComponentId(0),
            components,
            bindings: Vec::new(),
        };

        let url = Url::parse("file:///scenario.json5").unwrap();
        let provenance = Provenance {
            components: vec![
                ComponentProvenance {
                    authored_path: Arc::from("/"),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: root_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_path: Arc::from("/parent/child"),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: child_b_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_path: Arc::from("/parent"),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: parent_digest,
                    observed_url: None,
                },
                ComponentProvenance {
                    authored_path: Arc::from("/child"),
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
        assert!(scenario.components[root.0].children.contains_key("parent"));
        assert!(scenario.components[root.0].children.contains_key("child"));

        let parent_id = scenario.components[root.0].children["parent"];
        assert_eq!(scenario.components[parent_id.0].parent, Some(root));
        assert!(
            scenario.components[parent_id.0]
                .children
                .contains_key("child")
        );
    }
}
