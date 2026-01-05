use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{Manifest, ManifestRef};
use amber_scenario::{
    BindingEdge, Component, ComponentId, Moniker, ProvideRef, Scenario, ScenarioExport, SlotRef,
};
use url::Url;

use super::FlattenPass;
use crate::{
    CompileOutput, ComponentProvenance, DigestStore, Provenance,
    passes::ScenarioPass,
    reporter::{Reporter as _, dot::DotReporter},
};

fn component(id: usize, moniker: &str) -> Component {
    Component {
        id: ComponentId(id),
        parent: None,
        moniker: Moniker::from(Arc::from(moniker)),
        digest: amber_manifest::ManifestDigest::new([id as u8; 32]),
        config: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        children: Vec::new(),
    }
}

fn apply_manifest(component: &mut Component, manifest: &Manifest) {
    component.program = manifest.program().cloned();
    component.slots = manifest
        .slots()
        .iter()
        .map(|(name, decl)| (name.as_str().to_string(), decl.clone()))
        .collect();
    component.provides = manifest
        .provides()
        .iter()
        .map(|(name, decl)| (name.as_str().to_string(), decl.clone()))
        .collect();
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

    let cap_decl = child_manifest
        .provides()
        .get("cap")
        .expect("child provides cap")
        .decl
        .clone();

    let store = DigestStore::new();
    let root_digest = root_manifest.digest();
    let parent_digest = parent_manifest.digest();
    let child_digest = child_manifest.digest();
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
    apply_manifest(components[0].as_mut().unwrap(), &root_manifest);
    apply_manifest(components[1].as_mut().unwrap(), &parent_manifest);
    apply_manifest(components[2].as_mut().unwrap(), &child_manifest);

    store.put(root_digest, Arc::new(root_manifest));
    store.put(parent_digest, Arc::new(parent_manifest));
    store.put(child_digest, Arc::new(child_manifest));

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
        exports: vec![ScenarioExport {
            name: "cap".to_string(),
            capability: cap_decl,
            from: ProvideRef {
                component: ComponentId(2),
                name: "cap".to_string(),
            },
        }],
    };
    scenario.normalize_order();

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
    assert_eq!(scenario.exports.len(), 1);
    assert_eq!(scenario.exports[0].name, "cap");
    assert_eq!(scenario.exports[0].from.component, ComponentId(2));
    assert_eq!(scenario.exports[0].from.name, "cap");

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
    apply_manifest(components[0].as_mut().unwrap(), &root_manifest);
    apply_manifest(components[1].as_mut().unwrap(), &child_b_manifest);
    apply_manifest(components[2].as_mut().unwrap(), &parent_manifest);
    apply_manifest(components[3].as_mut().unwrap(), &child_a_manifest);

    store.put(root_digest, Arc::new(root_manifest));
    store.put(parent_digest, Arc::new(parent_manifest));
    store.put(child_a_digest, Arc::new(child_a_manifest));
    store.put(child_b_digest, Arc::new(child_b_manifest));

    let mut scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings: Vec::new(),
        exports: Vec::new(),
    };
    scenario.normalize_order();

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
