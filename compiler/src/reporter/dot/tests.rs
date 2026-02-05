use std::collections::BTreeMap;

use amber_manifest::{FrameworkCapabilityName, Manifest, ManifestDigest};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, SlotRef,
};

use super::{render_dot, render_dot_with_exports};

fn component(id: usize, moniker: &str) -> Component {
    Component {
        id: ComponentId(id),
        parent: None,
        moniker: Moniker::from(moniker.to_string()),
        digest: ManifestDigest::new([id as u8; 32]),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    }
}

fn apply_manifest(component: &mut Component, manifest: &Manifest) {
    component.program = manifest.program().cloned();
    component.config_schema = manifest.config_schema().map(|schema| schema.0.clone());
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
    component.metadata = manifest.metadata().cloned();
}

#[test]
fn dot_renders_clusters_and_edges() {
    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/alpha")),
        Some(component(2, "/beta")),
        Some(component(3, "/alpha/gamma")),
    ];
    components[1].as_mut().unwrap().parent = Some(ComponentId(0));
    components[2].as_mut().unwrap().parent = Some(ComponentId(0));
    components[3].as_mut().unwrap().parent = Some(ComponentId(1));

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
        BindingEdge {
            name: Some("route".to_string()),
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "cap".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(2),
                name: "needs".to_string(),
            },
            weak: false,
        },
        BindingEdge {
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(2),
                name: "weak_cap".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(1),
                name: "opt".to_string(),
            },
            weak: true,
        },
    ];

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: Vec::new(),
    };

    let dot = render_dot(&scenario);
    let expected = r#"digraph scenario {
  rankdir=LR;
  compound=true;
  subgraph cluster_0 {
    penwidth=2;
    label="/";
    subgraph cluster_1 {
      penwidth=1;
      label="/alpha";
      c1 [label="/alpha"];
      c3 [label="/alpha/gamma"];
    }
    c2 [label="/beta"];
  }
  c1 -> c2 [label="cap (route)"];
  c2 -> c1 [label="weak_cap", style=dashed, constraint=false];
}
"#;

    assert_eq!(dot, expected);
}

#[test]
fn dot_renders_root_program_node() {
    let root_manifest: Manifest = r#"
        {
          manifest_version: "0.1.0",
          program: { image: "root", entrypoint: ["root"] },
        }
    "#
    .parse()
    .unwrap();

    let mut components = vec![Some(component(0, "/"))];
    apply_manifest(components[0].as_mut().unwrap(), &root_manifest);

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let dot = render_dot(&scenario);
    let expected = r#"digraph scenario {
  rankdir=LR;
  compound=true;
  subgraph cluster_0 {
    penwidth=2;
    label="/";
    c0 [label="program"];
  }
}
"#;
    assert_eq!(dot, expected);
}

#[test]
fn dot_renders_framework_bindings() {
    let components = vec![Some(component(0, "/")), Some(component(1, "/consumer"))];
    let bindings = vec![BindingEdge {
        name: None,
        from: BindingFrom::Framework(
            FrameworkCapabilityName::try_from("dynamic_children").unwrap(),
        ),
        to: SlotRef {
            component: ComponentId(1),
            name: "control".to_string(),
        },
        weak: false,
    }];

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: Vec::new(),
    };

    let dot = render_dot(&scenario);
    assert!(dot.contains("framework [label=\"framework\""), "{dot}");
    assert!(
        dot.contains("framework -> c1 [label=\"framework.dynamic_children\""),
        "{dot}"
    );
}

#[test]
fn dot_renders_root_exports_as_endpoints() {
    let root_manifest = r##"
            {
              manifest_version: "0.1.0",
              components: { a: "a.json5", b: "b.json5" },
              bindings: [
                { to: "#a.in", from: "#b.out" },
              ],
              exports: { public: "#b.out" },
            }
        "##
    .parse::<Manifest>()
    .unwrap();

    let a_manifest = r#"
            {
              manifest_version: "0.1.0",
              slots: { in: { kind: "http" } },
            }
        "#
    .parse::<Manifest>()
    .unwrap();

    let b_manifest = r#"
	            {
	              manifest_version: "0.1.0",
	              program: {
	                image: "b",
	                entrypoint: ["b"],
	                network: {
	                  endpoints: [{ name: "ep", port: 8080 }],
	                },
	              },
	              provides: { out: { kind: "http", endpoint: "ep" } },
	              exports: { out: "out" },
	            }
	            "#
    .parse::<Manifest>()
    .unwrap();

    let out_decl = b_manifest
        .provides()
        .get("out")
        .expect("b provides out")
        .decl
        .clone();

    let root_digest = root_manifest.digest();
    let a_digest = a_manifest.digest();
    let b_digest = b_manifest.digest();

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/a")),
        Some(component(2, "/b")),
    ];
    components[1].as_mut().unwrap().parent = Some(ComponentId(0));
    components[2].as_mut().unwrap().parent = Some(ComponentId(0));
    components[0].as_mut().unwrap().digest = root_digest;
    components[1].as_mut().unwrap().digest = a_digest;
    components[2].as_mut().unwrap().digest = b_digest;

    components[0]
        .as_mut()
        .unwrap()
        .children
        .extend([ComponentId(1), ComponentId(2)]);
    apply_manifest(components[0].as_mut().unwrap(), &root_manifest);
    apply_manifest(components[1].as_mut().unwrap(), &a_manifest);
    apply_manifest(components[2].as_mut().unwrap(), &b_manifest);

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings: vec![BindingEdge {
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(2),
                name: "out".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(1),
                name: "in".to_string(),
            },
            weak: false,
        }],
        exports: vec![ScenarioExport {
            name: "public".to_string(),
            capability: out_decl,
            from: ProvideRef {
                component: ComponentId(2),
                name: "out".to_string(),
            },
        }],
    };

    let dot = render_dot_with_exports(&scenario);
    let expected = r#"digraph scenario {
  rankdir=LR;
  compound=true;
  subgraph cluster_0 {
    penwidth=2;
    label="/";
    c1 [label="/a"];
    c2 [label="/b"];
  }
  e0 [label="http:8080", shape=box];
  c2 -> c1 [label="out"];
  c2 -> e0 [label="http"];
}
"#;

    assert_eq!(dot, expected);
}

#[test]
fn dot_renders_root_exports_from_root_component() {
    let root_manifest = r#"
            {
              manifest_version: "0.1.0",
              program: {
                image: "root",
                entrypoint: ["root"],
                network: { endpoints: [{ name: "out", port: 80 }] },
              },
              provides: { out: { kind: "http", endpoint: "out" } },
              exports: { public: "out" },
            }
        "#
    .parse::<Manifest>()
    .unwrap();

    let out_decl = root_manifest
        .provides()
        .get("out")
        .expect("root provides out")
        .decl
        .clone();

    let root_digest = root_manifest.digest();

    let mut components = vec![Some(component(0, "/"))];
    components[0].as_mut().unwrap().digest = root_digest;
    apply_manifest(components[0].as_mut().unwrap(), &root_manifest);

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings: Vec::new(),
        exports: vec![ScenarioExport {
            name: "public".to_string(),
            capability: out_decl,
            from: ProvideRef {
                component: ComponentId(0),
                name: "out".to_string(),
            },
        }],
    };

    let dot = render_dot_with_exports(&scenario);
    assert!(dot.contains("c0 [label=\"program\"]"));
    assert!(dot.contains("e0 [label=\"http:80\", shape=box]"));
    assert!(dot.contains("c0 -> e0 [label=\"http\"]"));
}
