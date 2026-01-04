use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{Manifest, ManifestRef};
use amber_scenario::{
    BindingEdge, Component, ComponentId, Moniker, ProvideRef, Scenario, ScenarioExport, SlotRef,
};
use url::Url;

use super::DcePass;
use crate::{ComponentProvenance, DigestStore, Provenance, passes::ScenarioPass};

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
            network: { endpoints: [{ name: "tool_proxy", port: 80 }] },
          },
          slots: {
            llm: { kind: "llm" },
            admin_api: { kind: "mcp" },
          },
          provides: { tool_proxy: { kind: "mcp", endpoint: "tool_proxy" } },
          exports: { tool_proxy: "tool_proxy" },
        }
    "#
    .parse()
    .unwrap();

    let tool_proxy_decl = green
        .provides()
        .get("tool_proxy")
        .expect("green provides tool_proxy")
        .decl
        .clone();

    let wrapper: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "wrapper",
            network: { endpoints: [{ name: "admin_api", port: 80 }] },
          },
          slots: { litellm: { kind: "http" } },
          provides: { admin_api: { kind: "mcp", endpoint: "admin_api" } },
          exports: { admin_api: "admin_api" },
        }
    "##
    .parse()
    .unwrap();

    let router: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "router",
            network: {
              endpoints: [
                { name: "llm", port: 80 },
                { name: "admin_api", port: 81 },
              ],
            },
          },
          components: { wrapper: "file:///wrapper.json5" },
          provides: {
            llm: { kind: "llm", endpoint: "llm" },
            admin_api: { kind: "http", endpoint: "admin_api" },
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
    apply_manifest(components[0].as_mut().unwrap(), &root);
    apply_manifest(components[1].as_mut().unwrap(), &router);
    apply_manifest(components[2].as_mut().unwrap(), &green);
    apply_manifest(components[3].as_mut().unwrap(), &wrapper);

    store.put(root_digest, Arc::new(root));
    store.put(green_digest, Arc::new(green));
    store.put(router_digest, Arc::new(router));
    store.put(wrapper_digest, Arc::new(wrapper));

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
        exports: vec![ScenarioExport {
            name: "tool_proxy".to_string(),
            capability: tool_proxy_decl,
            from: ProvideRef {
                component: ComponentId(2),
                name: "tool_proxy".to_string(),
            },
        }],
    };
    scenario.normalize_order();

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
            network: { endpoints: [{ name: "out", port: 80 }] },
          },
          slots: {
            input: { kind: "mcp" },
            llm: { kind: "llm" },
          },
          provides: { out: { kind: "mcp", endpoint: "out" } },
          exports: { out: "out" },
        }
    "##
    .parse()
    .unwrap();

    let out_decl = consumer
        .provides()
        .get("out")
        .expect("consumer provides out")
        .decl
        .clone();

    let input: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "input",
            network: { endpoints: [{ name: "input", port: 80 }] },
          },
          provides: { input: { kind: "mcp", endpoint: "input" } },
          exports: { input: "input" },
        }
    "##
    .parse()
    .unwrap();

    let llm: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "llm",
            network: { endpoints: [{ name: "llm", port: 80 }] },
          },
          provides: { llm: { kind: "llm", endpoint: "llm" } },
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
    apply_manifest(components[0].as_mut().unwrap(), &root);
    apply_manifest(components[1].as_mut().unwrap(), &consumer);
    apply_manifest(components[2].as_mut().unwrap(), &input);
    apply_manifest(components[3].as_mut().unwrap(), &llm);

    store.put(root_digest, Arc::new(root));
    store.put(consumer_digest, Arc::new(consumer));
    store.put(input_digest, Arc::new(input));
    store.put(llm_digest, Arc::new(llm));

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
        exports: vec![ScenarioExport {
            name: "out".to_string(),
            capability: out_decl,
            from: ProvideRef {
                component: ComponentId(1),
                name: "out".to_string(),
            },
        }],
    };
    scenario.normalize_order();

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
            network: { endpoints: [{ name: "out", port: 80 }] },
          },
          slots: { admin: { kind: "mcp" } },
          provides: { out: { kind: "mcp", endpoint: "out" } },
          exports: { out: "out" },
        }
    "##
    .parse()
    .unwrap();

    let out_decl = app
        .provides()
        .get("out")
        .expect("app provides out")
        .decl
        .clone();

    let admin: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "admin",
            network: { endpoints: [{ name: "admin", port: 80 }] },
          },
          provides: { admin: { kind: "mcp", endpoint: "admin" } },
          exports: { admin: "admin" },
        }
    "##
    .parse()
    .unwrap();

    let store = DigestStore::new();
    let root_digest = root.digest();
    let app_digest = app.digest();
    let admin_digest = admin.digest();
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
    apply_manifest(components[0].as_mut().unwrap(), &root);
    apply_manifest(components[1].as_mut().unwrap(), &app);
    apply_manifest(components[2].as_mut().unwrap(), &admin);

    store.put(root_digest, Arc::new(root));
    store.put(app_digest, Arc::new(app));
    store.put(admin_digest, Arc::new(admin));

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
        exports: vec![ScenarioExport {
            name: "out".to_string(),
            capability: out_decl,
            from: ProvideRef {
                component: ComponentId(1),
                name: "out".to_string(),
            },
        }],
    };
    scenario.normalize_order();

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
