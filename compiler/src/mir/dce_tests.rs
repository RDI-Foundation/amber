use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{FrameworkCapabilityName, Manifest};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, SlotRef,
};
use serde_json::json;

use super::dce_only;

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

fn component_mut(components: &mut [Option<Component>], id: usize) -> &mut Component {
    components[id]
        .as_mut()
        .unwrap_or_else(|| panic!("component {id} missing"))
}

fn connect_parent_child(components: &mut [Option<Component>], parent: usize, child: usize) {
    component_mut(components, child).parent = Some(ComponentId(parent));
    component_mut(components, parent)
        .children
        .push(ComponentId(child));
}

fn apply_component_manifest(components: &mut [Option<Component>], id: usize, manifest: &Manifest) {
    let component = component_mut(components, id);
    component.digest = manifest.digest();
    apply_manifest(component, manifest);
}

fn slot(component: usize, name: &str) -> SlotRef {
    SlotRef {
        component: ComponentId(component),
        name: name.to_string(),
    }
}

fn provide(component: usize, name: &str) -> ProvideRef {
    ProvideRef {
        component: ComponentId(component),
        name: name.to_string(),
    }
}

fn component_binding(
    from_component: usize,
    from_name: &str,
    to_component: usize,
    to_name: &str,
) -> BindingEdge {
    BindingEdge {
        name: None,
        from: BindingFrom::Component(provide(from_component, from_name)),
        to: slot(to_component, to_name),
        weak: false,
    }
}

fn named_component_binding(
    binding_name: &str,
    from_component: usize,
    from_name: &str,
    to_component: usize,
    to_name: &str,
) -> BindingEdge {
    BindingEdge {
        name: Some(binding_name.to_string()),
        from: BindingFrom::Component(provide(from_component, from_name)),
        to: slot(to_component, to_name),
        weak: false,
    }
}

fn framework_binding(capability: &str, to_component: usize, to_name: &str) -> BindingEdge {
    BindingEdge {
        name: None,
        from: BindingFrom::Framework(
            FrameworkCapabilityName::try_from(capability).expect("framework capability"),
        ),
        to: slot(to_component, to_name),
        weak: false,
    }
}

fn external_binding(
    from_component: usize,
    from_name: &str,
    to_component: usize,
    to_name: &str,
    weak: bool,
) -> BindingEdge {
    BindingEdge {
        name: None,
        from: BindingFrom::External(slot(from_component, from_name)),
        to: slot(to_component, to_name),
        weak,
    }
}

fn scenario_export(
    name: &str,
    capability: amber_manifest::CapabilityDecl,
    from_component: usize,
    from_name: &str,
) -> ScenarioExport {
    ScenarioExport {
        name: name.to_string(),
        capability,
        from: provide(from_component, from_name),
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

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/router")),
        Some(component(2, "/green")),
        Some(component(3, "/router/wrapper")),
    ];
    apply_component_manifest(&mut components, 0, &root);
    apply_component_manifest(&mut components, 1, &router);
    apply_component_manifest(&mut components, 2, &green);
    apply_component_manifest(&mut components, 3, &wrapper);
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 0, 2);
    connect_parent_child(&mut components, 1, 3);

    let bindings = vec![
        // Root wiring: green.llm <- router.llm
        component_binding(1, "llm", 2, "llm"),
        // Root wiring: green.admin_api <- router.admin_api (resolved to wrapper.admin_api)
        component_binding(3, "admin_api", 2, "admin_api"),
        // Router internal wiring: wrapper.litellm <- router.admin_api
        component_binding(1, "admin_api", 3, "litellm"),
    ];

    let mut scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export(
            "tool_proxy",
            tool_proxy_decl,
            2,
            "tool_proxy",
        )],
    };
    scenario.normalize_order();

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

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/consumer")),
        Some(component(2, "/input")),
        Some(component(3, "/llm")),
    ];
    apply_component_manifest(&mut components, 0, &root);
    apply_component_manifest(&mut components, 1, &consumer);
    apply_component_manifest(&mut components, 2, &input);
    apply_component_manifest(&mut components, 3, &llm);
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 0, 2);
    connect_parent_child(&mut components, 0, 3);

    let bindings = vec![
        component_binding(2, "input", 1, "input"),
        component_binding(3, "llm", 1, "llm"),
    ];

    let mut scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", out_decl, 1, "out")],
    };
    scenario.normalize_order();

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

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/app")),
        Some(component(2, "/admin")),
    ];
    apply_component_manifest(&mut components, 0, &root);
    apply_component_manifest(&mut components, 1, &app);
    apply_component_manifest(&mut components, 2, &admin);
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 0, 2);

    let bindings = vec![component_binding(2, "admin", 1, "admin")];

    let mut scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", out_decl, 1, "out")],
    };
    scenario.normalize_order();

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

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/live")),
        Some(component(2, "/dead")),
        Some(component(3, "/provider")),
    ];
    apply_component_manifest(&mut components, 0, &root);
    apply_component_manifest(&mut components, 1, &live);
    apply_component_manifest(&mut components, 2, &dead);
    apply_component_manifest(&mut components, 3, &provider);
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 0, 2);
    connect_parent_child(&mut components, 0, 3);

    let bindings = vec![named_component_binding("agent", 3, "api", 2, "up")];

    let mut scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", out_decl, 1, "out")],
    };
    scenario.normalize_order();

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
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 0, 2);

    component_mut(&mut components, 0).program = Some(root_program);
    component_mut(&mut components, 0)
        .slots
        .insert("up".to_string(), slot_decl);

    component_mut(&mut components, 1).program = Some(consumer_program);
    component_mut(&mut components, 1)
        .provides
        .insert("out".to_string(), export_provide_decl);

    component_mut(&mut components, 2).program = Some(provider_program);
    component_mut(&mut components, 2)
        .provides
        .insert("up".to_string(), provide_decl);

    let bindings = vec![component_binding(2, "up", 0, "up")];

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", export_capability, 1, "out")],
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
fn dce_keeps_runtime_visible_config_binding_slots_without_reviving_scope_program() {
    let slot_decl: amber_manifest::SlotDecl =
        serde_json::from_value(json!({ "kind": "http" })).expect("slot decl");
    let provide_out: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "out" })).expect("out decl");
    let provide_up: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "up" })).expect("up decl");
    let consumer_schema = json!({
        "type": "object",
        "properties": {
            "upstream_url": { "type": "string" }
        }
    });
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
        "env": { "UPSTREAM_URL": "${config.upstream_url}" },
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
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 0, 2);

    component_mut(&mut components, 0).program = Some(root_program);
    component_mut(&mut components, 0)
        .slots
        .insert("up".to_string(), slot_decl);
    component_mut(&mut components, 0)
        .binding_decls
        .insert("upstream".to_string(), slot(0, "up"));

    component_mut(&mut components, 1).program = Some(consumer_program);
    component_mut(&mut components, 1).config = Some(json!({
        "upstream_url": "${bindings.upstream.url}",
    }));
    component_mut(&mut components, 1).config_schema = Some(consumer_schema);
    component_mut(&mut components, 1)
        .provides
        .insert("out".to_string(), provide_out);

    component_mut(&mut components, 2).program = Some(provider_program);
    component_mut(&mut components, 2)
        .provides
        .insert("up".to_string(), provide_up);

    let bindings = vec![component_binding(2, "up", 0, "up")];

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", export_capability, 1, "out")],
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
fn dce_prunes_non_runtime_visible_config_binding_slots() {
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
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 0, 2);

    component_mut(&mut components, 0).program = Some(root_program);
    component_mut(&mut components, 0)
        .slots
        .insert("up".to_string(), slot_decl);
    component_mut(&mut components, 0)
        .binding_decls
        .insert("upstream".to_string(), slot(0, "up"));

    component_mut(&mut components, 1).program = Some(consumer_program);
    component_mut(&mut components, 1).config = Some(json!({
        "upstream_url": "${bindings.upstream.url}",
    }));
    component_mut(&mut components, 1)
        .provides
        .insert("out".to_string(), provide_out);

    component_mut(&mut components, 2).program = Some(provider_program);
    component_mut(&mut components, 2)
        .provides
        .insert("up".to_string(), provide_up);

    let bindings = vec![component_binding(2, "up", 0, "up")];

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", export_capability, 1, "out")],
    };

    let scenario = dce_only(scenario);
    assert!(
        scenario.component(ComponentId(0)).program.is_none(),
        "scope owner program should still be pruned"
    );
    assert!(
        scenario.components[2].is_none(),
        "provider should be pruned when the config path containing bindings usage is never read \
         at runtime"
    );
    assert!(
        scenario.bindings.is_empty(),
        "incoming edge to the root slot should be pruned with the dead provider"
    );
}

#[test]
fn dce_keeps_runtime_visible_transitive_config_binding_slots() {
    let slot_decl: amber_manifest::SlotDecl =
        serde_json::from_value(json!({ "kind": "http" })).expect("slot decl");
    let provide_out: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "out" })).expect("out decl");
    let provide_up: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "up" })).expect("up decl");
    let middle_schema = json!({
        "type": "object",
        "properties": {
            "upstream_url": { "type": "string" }
        }
    });
    let consumer_schema = json!({
        "type": "object",
        "properties": {
            "target": { "type": "string" }
        }
    });
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
        "env": { "UPSTREAM_URL": "${config.target}" },
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
        Some(component(1, "/middle")),
        Some(component(2, "/middle/consumer")),
        Some(component(3, "/provider")),
    ];
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 1, 2);
    connect_parent_child(&mut components, 0, 3);

    component_mut(&mut components, 0).program = Some(root_program);
    component_mut(&mut components, 0)
        .slots
        .insert("up".to_string(), slot_decl);
    component_mut(&mut components, 0)
        .binding_decls
        .insert("upstream".to_string(), slot(0, "up"));

    component_mut(&mut components, 1).config = Some(json!({
        "upstream_url": "${bindings.upstream.url}",
    }));
    component_mut(&mut components, 1).config_schema = Some(middle_schema);

    component_mut(&mut components, 2).program = Some(consumer_program);
    component_mut(&mut components, 2).config = Some(json!({
        "target": "${config.upstream_url}",
    }));
    component_mut(&mut components, 2).config_schema = Some(consumer_schema);
    component_mut(&mut components, 2)
        .provides
        .insert("out".to_string(), provide_out);

    component_mut(&mut components, 3).program = Some(provider_program);
    component_mut(&mut components, 3)
        .provides
        .insert("up".to_string(), provide_up);

    let bindings = vec![component_binding(3, "up", 0, "up")];

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", export_capability, 2, "out")],
    };

    let scenario = dce_only(scenario);
    assert!(
        scenario.component(ComponentId(0)).program.is_none(),
        "scope owner program should be pruned; transitive config usage should not revive it"
    );
    assert!(
        scenario.components[3].is_some(),
        "provider should remain because a live program reads config that resolves to \
         bindings.upstream.url through template composition"
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
    connect_parent_child(&mut components, 0, 1);
    component_mut(&mut components, 1).program = Some(consumer_program);
    component_mut(&mut components, 1)
        .slots
        .insert("control".to_string(), control_slot);

    let bindings = vec![framework_binding("dynamic_children", 1, "control")];

    let export_capability =
        serde_json::from_value(json!({ "kind": "http" })).expect("capability decl");

    let scenario = Scenario {
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", export_capability, 1, "out")],
    };

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
        bindings: vec![external_binding(0, "white", 1, "white", true)],
        exports: vec![scenario_export("green", export_capability, 1, "a2a")],
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
