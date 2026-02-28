use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{FrameworkCapabilityName, Manifest, ManifestRef};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, SlotRef,
};
use serde_json::json;
use url::Url;

use super::dce_only;
use crate::{ComponentProvenance, DigestStore, Provenance};

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
            entrypoint: ["--llm", "${slots.llm.url}"],
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
            entrypoint: ["wrapper"],
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
            entrypoint: ["router"],
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
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "llm".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(2),
                name: "llm".to_string(),
            },
            weak: false,
        },
        // Root wiring: green.admin_api <- router.admin_api (resolved to wrapper.admin_api)
        BindingEdge {
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(3),
                name: "admin_api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(2),
                name: "admin_api".to_string(),
            },
            weak: false,
        },
        // Router internal wiring: wrapper.litellm <- router.admin_api
        BindingEdge {
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "admin_api".to_string(),
            }),
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

    let _provenance = provenance;
    let scenario = dce_only(scenario);

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
    let edge_from = match &edge.from {
        BindingFrom::Component(from) => from,
        BindingFrom::Framework(name) => {
            panic!("unexpected framework binding framework.{name}")
        }
        BindingFrom::External(slot) => {
            panic!("unexpected external binding slots.{}", slot.name)
        }
    };
    assert_eq!(edge_from.name, "llm");
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
        scenario.components[edge_from.component.0]
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
            entrypoint: ["--input", "${slots.input.url}", "--llm", "${slots.llm.url}"],
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
            entrypoint: ["input"],
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
            entrypoint: ["llm"],
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
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(2),
                name: "input".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(1),
                name: "input".to_string(),
            },
            weak: false,
        },
        BindingEdge {
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(3),
                name: "llm".to_string(),
            }),
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

    let _provenance = provenance;
    let scenario = dce_only(scenario);

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
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(&edge.from, BindingFrom::Component(from) if from.name == "input")
            && edge.to.name == "input"
    }));
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(&edge.from, BindingFrom::Component(from) if from.name == "llm")
            && edge.to.name == "llm"
    }));
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
            entrypoint: ["app"],
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
            entrypoint: ["admin"],
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
        name: None,
        from: BindingFrom::Component(ProvideRef {
            component: ComponentId(2),
            name: "admin".to_string(),
        }),
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

    let _provenance = provenance;
    let scenario = dce_only(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|c| c.moniker.local_name() == Some("admin"))
    );
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(&edge.from, BindingFrom::Component(from) if from.name == "admin")
            && edge.to.name == "admin"
    }));
}

#[test]
fn dce_prunes_unreachable_named_binding_interpolation_subgraph() {
    let root: Manifest = r##"
        {
          manifest_version: "0.1.0",
          components: {
            live: "file:///live.json5",
            dead: "file:///dead.json5",
            provider: "file:///provider.json5",
          },
          exports: { out: "#live.out" },
        }
    "##
    .parse()
    .unwrap();

    let live: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "live",
            entrypoint: ["live"],
            network: { endpoints: [{ name: "out", port: 80 }] },
          },
          provides: { out: { kind: "http", endpoint: "out" } },
          exports: { out: "out" },
        }
    "##
    .parse()
    .unwrap();
    let out_decl = live
        .provides()
        .get("out")
        .expect("live provides out")
        .decl
        .clone();

    let dead: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "dead",
            entrypoint: ["dead"],
            env: { UPSTREAM_URL: "${bindings.agent.url}" },
          },
          slots: { up: { kind: "http" } },
        }
    "##
    .parse()
    .unwrap();

    let provider: Manifest = r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "provider",
            entrypoint: ["provider"],
            network: { endpoints: [{ name: "api", port: 81 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" },
        }
    "##
    .parse()
    .unwrap();

    let store = DigestStore::new();
    let root_digest = root.digest();
    let live_digest = live.digest();
    let dead_digest = dead.digest();
    let provider_digest = provider.digest();
    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/live")),
        Some(component(2, "/dead")),
        Some(component(3, "/provider")),
    ];
    components[0].as_mut().unwrap().digest = root_digest;
    components[1].as_mut().unwrap().digest = live_digest;
    components[2].as_mut().unwrap().digest = dead_digest;
    components[3].as_mut().unwrap().digest = provider_digest;

    components[1].as_mut().unwrap().parent = Some(ComponentId(0));
    components[2].as_mut().unwrap().parent = Some(ComponentId(0));
    components[3].as_mut().unwrap().parent = Some(ComponentId(0));
    apply_manifest(components[0].as_mut().unwrap(), &root);
    apply_manifest(components[1].as_mut().unwrap(), &live);
    apply_manifest(components[2].as_mut().unwrap(), &dead);
    apply_manifest(components[3].as_mut().unwrap(), &provider);

    store.put(root_digest, Arc::new(root));
    store.put(live_digest, Arc::new(live));
    store.put(dead_digest, Arc::new(dead));
    store.put(provider_digest, Arc::new(provider));

    components[0].as_mut().unwrap().children.extend([
        ComponentId(1),
        ComponentId(2),
        ComponentId(3),
    ]);

    let bindings = vec![BindingEdge {
        name: Some("agent".to_string()),
        from: BindingFrom::Component(ProvideRef {
            component: ComponentId(3),
            name: "api".to_string(),
        }),
        to: SlotRef {
            component: ComponentId(2),
            name: "up".to_string(),
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
                authored_moniker: Moniker::from(Arc::from("/live")),
                declared_ref: ManifestRef::from_url(url.clone()),
                resolved_url: url.clone(),
                digest: live_digest,
                observed_url: None,
            },
            ComponentProvenance {
                authored_moniker: Moniker::from(Arc::from("/dead")),
                declared_ref: ManifestRef::from_url(url.clone()),
                resolved_url: url.clone(),
                digest: dead_digest,
                observed_url: None,
            },
            ComponentProvenance {
                authored_moniker: Moniker::from(Arc::from("/provider")),
                declared_ref: ManifestRef::from_url(url.clone()),
                resolved_url: url,
                digest: provider_digest,
                observed_url: None,
            },
        ],
    };

    let _provenance = provenance;
    let scenario = dce_only(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|c| c.moniker.local_name() == Some("live"))
    );
    assert!(
        !scenario
            .components
            .iter()
            .flatten()
            .any(|c| c.moniker.local_name() == Some("dead"))
    );
    assert!(
        !scenario
            .components
            .iter()
            .flatten()
            .any(|c| c.moniker.local_name() == Some("provider"))
    );
    assert!(scenario.bindings.is_empty());
}

#[test]
fn dce_keeps_ancestors_without_marking_ancestor_program_live() {
    let slot_decl: amber_manifest::SlotDecl =
        serde_json::from_value(json!({ "kind": "http" })).expect("slot decl");
    let provide_decl: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "up" })).expect("provide decl");
    let export_provide_decl: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "out" }))
            .expect("export provide decl");
    let export_capability = export_provide_decl.decl.clone();

    let root_program = serde_json::from_value(json!({
        "image": "root",
        "entrypoint": ["root"],
        "env": { "UP_URL": "${slots.up.url}" },
        "network": { "endpoints": [{ "name": "root", "port": 9000 }] },
    }))
    .expect("root program");
    let consumer_program = serde_json::from_value(json!({
        "image": "consumer",
        "entrypoint": ["consumer"],
        "network": { "endpoints": [{ "name": "out", "port": 9001 }] },
    }))
    .expect("consumer program");
    let provider_program = serde_json::from_value(json!({
        "image": "provider",
        "entrypoint": ["provider"],
        "network": { "endpoints": [{ "name": "up", "port": 9002 }] },
    }))
    .expect("provider program");

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/consumer")),
        Some(component(2, "/provider")),
    ];
    components[1].as_mut().unwrap().parent = Some(ComponentId(0));
    components[2].as_mut().unwrap().parent = Some(ComponentId(0));
    components[0]
        .as_mut()
        .unwrap()
        .children
        .extend([ComponentId(1), ComponentId(2)]);

    components[0].as_mut().unwrap().program = Some(root_program);
    components[0]
        .as_mut()
        .unwrap()
        .slots
        .insert("up".to_string(), slot_decl);

    components[1].as_mut().unwrap().program = Some(consumer_program);
    components[1]
        .as_mut()
        .unwrap()
        .provides
        .insert("out".to_string(), export_provide_decl);

    components[2].as_mut().unwrap().program = Some(provider_program);
    components[2]
        .as_mut()
        .unwrap()
        .provides
        .insert("up".to_string(), provide_decl);

    let bindings = vec![BindingEdge {
        name: None,
        from: BindingFrom::Component(ProvideRef {
            component: ComponentId(2),
            name: "up".to_string(),
        }),
        to: SlotRef {
            component: ComponentId(0),
            name: "up".to_string(),
        },
        weak: false,
    }];

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![ScenarioExport {
            name: "out".to_string(),
            capability: export_capability,
            from: ProvideRef {
                component: ComponentId(1),
                name: "out".to_string(),
            },
        }],
    };

    let scenario = dce_only(scenario);
    let root = scenario.component(ComponentId(0));
    assert!(root.program.is_none(), "ancestor program should be pruned");
    assert!(
        scenario.components[2].is_none(),
        "provider should be pruned when only dead ancestor program references its slot"
    );
    assert!(
        scenario.bindings.is_empty(),
        "binding into pruned ancestor slot should be removed"
    );
    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("consumer")),
        "live exported consumer should remain"
    );
}

#[test]
fn dce_keeps_live_config_binding_slots_without_reviving_scope_program() {
    let slot_decl: amber_manifest::SlotDecl =
        serde_json::from_value(json!({ "kind": "http" })).expect("slot decl");
    let provide_out: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "out" })).expect("out decl");
    let provide_up: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "up" })).expect("up decl");
    let export_capability = provide_out.decl.clone();

    let root_program = serde_json::from_value(json!({
        "image": "root",
        "entrypoint": ["root"],
        "env": { "UP_URL": "${slots.up.url}" },
        "network": { "endpoints": [{ "name": "root", "port": 9100 }] },
    }))
    .expect("root program");
    let consumer_program = serde_json::from_value(json!({
        "image": "consumer",
        "entrypoint": ["consumer"],
        "network": { "endpoints": [{ "name": "out", "port": 9101 }] },
    }))
    .expect("consumer program");
    let provider_program = serde_json::from_value(json!({
        "image": "provider",
        "entrypoint": ["provider"],
        "network": { "endpoints": [{ "name": "up", "port": 9102 }] },
    }))
    .expect("provider program");

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/consumer")),
        Some(component(2, "/provider")),
    ];
    components[1].as_mut().unwrap().parent = Some(ComponentId(0));
    components[2].as_mut().unwrap().parent = Some(ComponentId(0));
    components[0]
        .as_mut()
        .unwrap()
        .children
        .extend([ComponentId(1), ComponentId(2)]);

    components[0].as_mut().unwrap().program = Some(root_program);
    components[0]
        .as_mut()
        .unwrap()
        .slots
        .insert("up".to_string(), slot_decl);
    components[0].as_mut().unwrap().binding_decls.insert(
        "upstream".to_string(),
        SlotRef {
            component: ComponentId(0),
            name: "up".to_string(),
        },
    );

    components[1].as_mut().unwrap().program = Some(consumer_program);
    components[1].as_mut().unwrap().config = Some(json!({
        "upstream_url": "${bindings.upstream.url}",
    }));
    components[1]
        .as_mut()
        .unwrap()
        .provides
        .insert("out".to_string(), provide_out);

    components[2].as_mut().unwrap().program = Some(provider_program);
    components[2]
        .as_mut()
        .unwrap()
        .provides
        .insert("up".to_string(), provide_up);

    let bindings = vec![BindingEdge {
        name: None,
        from: BindingFrom::Component(ProvideRef {
            component: ComponentId(2),
            name: "up".to_string(),
        }),
        to: SlotRef {
            component: ComponentId(0),
            name: "up".to_string(),
        },
        weak: false,
    }];

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![ScenarioExport {
            name: "out".to_string(),
            capability: export_capability,
            from: ProvideRef {
                component: ComponentId(1),
                name: "out".to_string(),
            },
        }],
    };

    let scenario = dce_only(scenario);
    assert!(
        scenario.component(ComponentId(0)).program.is_none(),
        "scope owner program should be pruned; config binding usage should not revive it"
    );
    assert!(
        scenario.components[2].is_some(),
        "provider should remain because root-scope config binding usage keeps root slot `up` live"
    );
    assert_eq!(
        scenario.bindings.len(),
        1,
        "incoming edge to the live root slot should remain"
    );
}

#[test]
fn dce_keeps_framework_bound_slots() {
    let control_slot = serde_json::from_value(json!({ "kind": "mcp" })).unwrap();
    let consumer_program = serde_json::from_value(json!({
        "image": "consumer",
        "entrypoint": ["${slots.control.url}"]
    }))
    .unwrap();

    let mut components = vec![Some(component(0, "/")), Some(component(1, "/consumer"))];
    components[1].as_mut().unwrap().parent = Some(ComponentId(0));
    components[0]
        .as_mut()
        .unwrap()
        .children
        .push(ComponentId(1));
    components[1].as_mut().unwrap().program = Some(consumer_program);
    components[1]
        .as_mut()
        .unwrap()
        .slots
        .insert("control".to_string(), control_slot);

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

    let export_capability =
        serde_json::from_value(json!({ "kind": "http" })).expect("capability decl");

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![ScenarioExport {
            name: "out".to_string(),
            capability: export_capability,
            from: ProvideRef {
                component: ComponentId(1),
                name: "out".to_string(),
            },
        }],
    };

    let url = Url::parse("file:///root.json5").unwrap();
    let provenance = Provenance {
        components: scenario
            .components
            .iter()
            .map(|component| {
                let component = component.as_ref().expect("test component should exist");
                ComponentProvenance {
                    authored_moniker: component.moniker.clone(),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: component.digest,
                    observed_url: None,
                }
            })
            .collect(),
    };

    let _provenance = provenance;
    let scenario = dce_only(scenario);
    assert_eq!(scenario.components.iter().flatten().count(), 2);
    assert_eq!(scenario.bindings.len(), 1);
    match &scenario.bindings[0].from {
        BindingFrom::Framework(name) => assert_eq!(name.as_str(), "dynamic_children"),
        BindingFrom::Component(_) => panic!("expected framework binding"),
        BindingFrom::External(slot) => {
            panic!("unexpected external binding slots.{}", slot.name)
        }
    }
}

#[test]
fn dce_keeps_live_external_root_slot_when_export_makes_consumer_live() {
    let root_slot = serde_json::from_value(json!({ "kind": "a2a" })).expect("slot decl");
    let green_program = serde_json::from_value(json!({
        "image": "green",
        "entrypoint": ["green", "--agent", "${slots.white.url}"],
        "network": {
            "endpoints": [{ "name": "a2a", "port": 9001 }]
        }
    }))
    .expect("program");
    let green_provide: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "a2a", "endpoint": "a2a" })).expect("provide");
    let export_capability = green_provide.decl.clone();

    let mut root = component(0, "/");
    root.slots.insert("white".to_string(), root_slot);
    root.children.push(ComponentId(1));

    let mut green = component(1, "/green");
    green.parent = Some(ComponentId(0));
    green.program = Some(green_program);
    green.slots.insert(
        "white".to_string(),
        serde_json::from_value(json!({ "kind": "a2a" })).unwrap(),
    );
    green.provides.insert("a2a".to_string(), green_provide);

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(green)],
        bindings: vec![BindingEdge {
            name: None,
            from: BindingFrom::External(SlotRef {
                component: ComponentId(0),
                name: "white".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(1),
                name: "white".to_string(),
            },
            weak: true,
        }],
        exports: vec![ScenarioExport {
            name: "green".to_string(),
            capability: export_capability,
            from: ProvideRef {
                component: ComponentId(1),
                name: "a2a".to_string(),
            },
        }],
    };

    let scenario = dce_only(scenario);
    let root_after = scenario
        .components
        .first()
        .and_then(|component| component.as_ref())
        .expect("root should remain");
    assert!(
        root_after.slots.contains_key("white"),
        "live external root slot must not be pruned under DCE"
    );
    assert_eq!(scenario.bindings.len(), 1, "external binding should remain");
    assert!(
        matches!(
            &scenario.bindings[0].from,
            BindingFrom::External(slot) if slot.component == ComponentId(0) && slot.name == "white"
        ),
        "expected external binding from root.white to remain"
    );
}
