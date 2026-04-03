use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{FrameworkCapabilityName, Manifest, Program, ProvideDecl, SlotDecl};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, FrameworkRef, Moniker, ProvideRef,
    ResourceDecl, ResourceRef, Scenario, ScenarioExport, SlotRef, StorageResourceParams,
};
use serde_json::json;

use super::dce_only;
use crate::linker::program_lowering::lower_program;

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
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    }
}

fn apply_manifest(component: &mut Component, manifest: &Manifest) {
    component.program = manifest.program().map(|program| {
        lower_program(component.id, program, None).expect("program fixture should lower")
    });
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
    component.resources = manifest
        .resources()
        .iter()
        .map(|(name, decl)| {
            (
                name.as_str().to_string(),
                ResourceDecl {
                    kind: decl.kind,
                    params: StorageResourceParams {
                        size: decl.params.size.as_ref().map(ToString::to_string),
                        retention: decl.params.retention.as_ref().map(ToString::to_string),
                        sharing: decl.params.sharing.as_ref().map(ToString::to_string),
                    },
                },
            )
        })
        .collect();
}

fn lower_fixture_program(id: usize, program: Program) -> amber_scenario::Program {
    lower_program(ComponentId(id), &program, None).expect("program fixture should lower")
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
        from: BindingFrom::Component(provide(from_component, from_name)),
        to: slot(to_component, to_name),
        weak: false,
    }
}

fn framework_binding(capability: &str, to_component: usize, to_name: &str) -> BindingEdge {
    BindingEdge {
        from: BindingFrom::Framework(FrameworkRef {
            authority: ComponentId(0),
            capability: FrameworkCapabilityName::try_from(capability)
                .expect("framework capability"),
        }),
        to: slot(to_component, to_name),
        weak: false,
    }
}

fn storage_resource_decl(size: Option<&str>) -> ResourceDecl {
    let value = match size {
        Some(size) => json!({
            "kind": "storage",
            "params": { "size": size },
        }),
        None => json!({ "kind": "storage" }),
    };
    serde_json::from_value(value).expect("storage resource decl")
}

fn manifest_slot(kind: &str, optional: bool, multiple: bool) -> SlotDecl {
    let mut value = json!({ "kind": kind });
    if optional {
        value["optional"] = serde_json::Value::Bool(true);
    }
    if multiple {
        value["multiple"] = serde_json::Value::Bool(true);
    }
    serde_json::from_value(value).expect("slot decl")
}

fn externally_rooted_child_scenario(
    slot_name: &str,
    slot_decl: SlotDecl,
    child_program: Program,
) -> Scenario {
    let mut root = component(0, "/");
    root.slots.insert(slot_name.to_string(), slot_decl.clone());
    root.children.push(ComponentId(1));

    let mut child = component(1, "/child");
    child.parent = Some(ComponentId(0));
    child.program = Some(lower_fixture_program(1, child_program));
    child.slots.insert(slot_name.to_string(), slot_decl);

    let mut scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: vec![external_binding(0, slot_name, 1, slot_name, true)],
        exports: Vec::new(),
    };
    scenario.normalize_order();
    scenario
}

fn assert_dce_idempotent(scenario: Scenario) -> Scenario {
    let once = dce_only(scenario);
    let twice = dce_only(once.clone());
    assert_eq!(once, twice, "dce changed the scenario on a second pass");
    once
}

fn external_binding(
    from_component: usize,
    from_name: &str,
    to_component: usize,
    to_name: &str,
    weak: bool,
) -> BindingEdge {
    BindingEdge {
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
        manifest_catalog: BTreeMap::new(),
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
        BindingFrom::Resource(resource) => {
            panic!("unexpected resource binding resources.{}", resource.name)
        }
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
        manifest_catalog: BTreeMap::new(),
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
fn dce_keeps_dependencies_for_repeated_slot_each() {
    let root: Manifest = r##"
    {
      manifest_version: "0.3.0",
      components: {
        consumer: "file:///consumer.json5",
        provider: "file:///provider.json5",
      },
      exports: { out: "#consumer.out" },
    }
    "##
    .parse()
    .unwrap();

    let consumer: Manifest = r##"
        {
          manifest_version: "0.3.0",
          program: {
            image: "consumer",
            entrypoint: [
              "consumer",
              {
                each: "slots.api",
                argv: ["--api", "${item.url}"],
              },
            ],
            network: { endpoints: [{ name: "out", port: 80 }] },
          },
          slots: {
            api: { kind: "http", optional: true, multiple: true },
          },
          provides: { out: { kind: "http", endpoint: "out" } },
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

    let provider: Manifest = r##"
        {
          manifest_version: "0.3.0",
          program: {
            image: "provider",
            entrypoint: ["provider"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" },
        }
    "##
    .parse()
    .unwrap();

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/consumer")),
        Some(component(2, "/provider")),
    ];
    apply_component_manifest(&mut components, 0, &root);
    apply_component_manifest(&mut components, 1, &consumer);
    apply_component_manifest(&mut components, 2, &provider);
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 0, 2);

    let bindings = vec![component_binding(2, "api", 1, "api")];

    let mut scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
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
            .any(|c| c.moniker.local_name() == Some("provider"))
    );
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(&edge.from, BindingFrom::Component(from) if from.name == "api")
            && edge.to.name == "api"
    }));
}

#[test]
fn dce_prunes_dependency_when_repeated_slot_each_is_dead() {
    let root: Manifest = r##"
    {
      manifest_version: "0.3.0",
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
          manifest_version: "0.3.0",
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
          manifest_version: "0.3.0",
          program: {
            image: "dead",
            entrypoint: [
              "dead",
              {
                each: "slots.api",
                argv: ["--api", "${item.url}"],
              },
            ],
          },
          slots: {
            api: { kind: "http", optional: true, multiple: true },
          },
        }
    "##
    .parse()
    .unwrap();

    let provider: Manifest = r##"
        {
          manifest_version: "0.3.0",
          program: {
            image: "provider",
            entrypoint: ["provider"],
            network: { endpoints: [{ name: "api", port: 80 }] },
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

    let bindings = vec![component_binding(3, "api", 2, "api")];

    let mut scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components,
        bindings,
        exports: vec![scenario_export("out", out_decl, 1, "out")],
    };
    scenario.normalize_order();

    let scenario = dce_only(scenario);

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
        manifest_catalog: BTreeMap::new(),
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
fn dce_keeps_storage_slots_used_by_program_mounts() {
    let root: Manifest = r##"
        {
          manifest_version: "0.1.0",
      resources: {
        state: { kind: "storage" },
      },
          components: {
            app: "file:///app.json5",
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
            mounts: [
              { path: "/var/lib/app", from: "slots.state" },
            ],
            network: { endpoints: [{ name: "out", port: 80 }] },
          },
          slots: {
            state: { kind: "storage" },
          },
          provides: {
            out: { kind: "http", endpoint: "out" },
          },
          exports: {
            out: "out",
          },
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

    let mut components = vec![Some(component(0, "/")), Some(component(1, "/app"))];
    apply_component_manifest(&mut components, 0, &root);
    apply_component_manifest(&mut components, 1, &app);
    connect_parent_child(&mut components, 0, 1);

    let mut scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components,
        bindings: vec![BindingEdge {
            from: BindingFrom::Resource(ResourceRef {
                component: ComponentId(0),
                name: "state".to_string(),
            }),
            to: slot(1, "state"),
            weak: false,
        }],
        exports: vec![ScenarioExport {
            name: "out".to_string(),
            capability: out_decl,
            from: provide(1, "out"),
        }],
    };
    scenario.normalize_order();

    let scenario = dce_only(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("app")),
        "app component should stay live when its program mounts storage"
    );
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(&edge.from, BindingFrom::Resource(from) if from.component == ComponentId(0) && from.name == "state")
            && edge.to.name == "state"
    }));
}

#[test]
fn dce_keeps_resource_owner_between_export_and_storage_sink() {
    let storage_slot = serde_json::from_value(json!({ "kind": "storage" })).expect("storage slot");
    let provide_http: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "http" })).expect("provide");
    let out_decl = provide_http.decl.clone();
    let app_program = serde_json::from_value(json!({
        "image": "app",
        "entrypoint": ["app"],
        "mounts": [
            { "path": "/var/lib/app", "from": "slots.state" }
        ],
        "network": {
            "endpoints": [{ "name": "http", "port": 80 }]
        }
    }))
    .expect("program");

    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/allocator")),
        Some(component(2, "/allocator/app")),
    ];
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 1, 2);

    component_mut(&mut components, 1)
        .resources
        .insert("state".to_string(), storage_resource_decl(Some("5Gi")));
    component_mut(&mut components, 2).program = Some(lower_fixture_program(2, app_program));
    component_mut(&mut components, 2)
        .slots
        .insert("state".to_string(), storage_slot);
    component_mut(&mut components, 2)
        .provides
        .insert("http".to_string(), provide_http);

    let mut scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components,
        bindings: vec![BindingEdge {
            from: BindingFrom::Resource(ResourceRef {
                component: ComponentId(1),
                name: "state".to_string(),
            }),
            to: slot(2, "state"),
            weak: false,
        }],
        exports: vec![ScenarioExport {
            name: "http".to_string(),
            capability: out_decl,
            from: provide(2, "http"),
        }],
    };
    scenario.normalize_order();

    let scenario = dce_only(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.as_str() == "/allocator"),
        "resource owner must remain live when a descendant consumes its resource"
    );
    let allocator = scenario
        .components
        .iter()
        .flatten()
        .find(|component| component.moniker.as_str() == "/allocator")
        .expect("allocator component");
    assert!(
        allocator.resources.contains_key("state"),
        "resource owner should retain its declared resource after dce"
    );
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(
            &edge.from,
            BindingFrom::Resource(from)
                if from.component == allocator.id && from.name == "state"
        ) && edge.to.component != allocator.id
    }));
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

    component_mut(&mut components, 0).program = Some(lower_fixture_program(0, root_program));
    component_mut(&mut components, 0)
        .slots
        .insert("up".to_string(), slot_decl);

    component_mut(&mut components, 1).program = Some(lower_fixture_program(1, consumer_program));
    component_mut(&mut components, 1)
        .provides
        .insert("out".to_string(), export_provide_decl);

    component_mut(&mut components, 2).program = Some(lower_fixture_program(2, provider_program));
    component_mut(&mut components, 2)
        .provides
        .insert("up".to_string(), provide_decl);

    let bindings = vec![component_binding(2, "up", 0, "up")];

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
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
fn dce_keeps_framework_bound_slots() {
    let control_slot = serde_json::from_value(json!({ "kind": "mcp" })).unwrap();
    let consumer_program = serde_json::from_value(json!({
        "image": "consumer",
        "entrypoint": ["${slots.control.url}"]
    }))
    .unwrap();

    let mut components = vec![Some(component(0, "/")), Some(component(1, "/consumer"))];
    connect_parent_child(&mut components, 0, 1);
    component_mut(&mut components, 1).program = Some(lower_fixture_program(1, consumer_program));
    component_mut(&mut components, 1)
        .slots
        .insert("control".to_string(), control_slot);

    let bindings = vec![framework_binding("dynamic_children", 1, "control")];

    let export_capability =
        serde_json::from_value(json!({ "kind": "http" })).expect("capability decl");

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
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
        BindingFrom::Resource(resource) => {
            panic!("unexpected resource binding resources.{}", resource.name)
        }
        BindingFrom::External(slot) => {
            panic!("unexpected external binding slots.{}", slot.name)
        }
    }
}

#[test]
fn dce_keeps_child_template_owner_program_without_static_exports() {
    let mut components = vec![Some(component(0, "/")), Some(component(1, "/orchestrator"))];
    connect_parent_child(&mut components, 0, 1);
    component_mut(&mut components, 1).program = Some(lower_fixture_program(
        1,
        serde_json::from_value(json!({
            "image": "orchestrator",
            "entrypoint": ["orchestrator"]
        }))
        .expect("program"),
    ));
    component_mut(&mut components, 1).child_templates.insert(
        "worker".to_string(),
        amber_scenario::ChildTemplate {
            manifest: Some("catalog/worker".to_string()),
            allowed_manifests: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
            visible_exports: None,
            limits: None,
            possible_backends: Vec::new(),
        },
    );

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components,
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let scenario = dce_only(scenario);
    let orchestrator = scenario.components[1]
        .as_ref()
        .expect("template owner should remain");
    assert!(
        orchestrator.program.is_some(),
        "template owner program must survive DCE even without static exports"
    );
    assert!(
        orchestrator.child_templates.contains_key("worker"),
        "template owner child templates must survive DCE"
    );
}

#[test]
fn dce_keeps_static_child_subtree_visible_for_future_dynamic_bindings() {
    let mut components = vec![
        Some(component(0, "/")),
        Some(component(1, "/provider")),
        Some(component(2, "/provider/root")),
    ];
    connect_parent_child(&mut components, 0, 1);
    connect_parent_child(&mut components, 1, 2);
    component_mut(&mut components, 0).child_templates.insert(
        "worker".to_string(),
        amber_scenario::ChildTemplate {
            manifest: Some("catalog/worker".to_string()),
            allowed_manifests: None,
            config: BTreeMap::new(),
            bindings: BTreeMap::new(),
            visible_exports: None,
            limits: None,
            possible_backends: Vec::new(),
        },
    );
    component_mut(&mut components, 2).program = Some(lower_fixture_program(
        2,
        serde_json::from_value(json!({
            "image": "provider",
            "entrypoint": ["provider"]
        }))
        .expect("program"),
    ));
    component_mut(&mut components, 2).provides.insert(
        "out".to_string(),
        serde_json::from_value(json!({ "kind": "http" })).expect("provide decl"),
    );

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components,
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let scenario = dce_only(scenario);
    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.as_str() == "/provider"),
        "static child realm should survive DCE for future dynamic bindings"
    );
    let provider_root = scenario
        .components
        .iter()
        .flatten()
        .find(|component| component.moniker.as_str() == "/provider/root")
        .expect("static child program should remain");
    assert!(
        provider_root.program.is_some(),
        "static child program should remain runnable for future dynamic bindings"
    );
    assert!(
        provider_root.provides.contains_key("out"),
        "static child provides should remain available for future dynamic bindings"
    );
}

#[test]
fn dce_keeps_self_external_root_slot_for_future_dynamic_use() {
    let slot_decl = manifest_slot("http", false, false);
    let root_program = serde_json::from_value(json!({
        "image": "root",
        "entrypoint": ["root"],
    }))
    .expect("program");

    let mut root = component(0, "/");
    root.program = Some(lower_fixture_program(0, root_program));
    root.slots.insert("api".to_string(), slot_decl);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: vec![external_binding(0, "api", 0, "api", true)],
        exports: Vec::new(),
    };

    let scenario = assert_dce_idempotent(scenario);
    let root_after = scenario
        .components
        .first()
        .and_then(|component| component.as_ref())
        .expect("root should remain");
    assert!(
        root_after.program.is_some(),
        "root program must survive when it defines future-dynamic external affordances"
    );
    assert!(
        root_after.slots.contains_key("api"),
        "future-dynamic root external slot must survive DCE"
    );
    assert!(
        scenario.bindings.iter().any(|binding| matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == ComponentId(0)
                    && slot.name == "api"
                    && binding.to.component == ComponentId(0)
                    && binding.to.name == "api"
        )),
        "future-dynamic root external binding must survive DCE"
    );
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
    green.program = Some(lower_fixture_program(1, green_program));
    green.slots.insert(
        "white".to_string(),
        serde_json::from_value(json!({ "kind": "a2a" })).unwrap(),
    );
    green.provides.insert("a2a".to_string(), green_provide);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
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

#[test]
fn dce_keeps_live_external_root_slot_used_in_when_condition() {
    let root_slot = serde_json::from_value(json!({ "kind": "a2a" })).expect("slot decl");
    let green_program = serde_json::from_value(json!({
        "image": "green",
        "entrypoint": [
            "green",
            { "when": "slots.white", "argv": ["--agent"] }
        ],
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
    green.program = Some(lower_fixture_program(1, green_program));
    green.slots.insert(
        "white".to_string(),
        serde_json::from_value(json!({ "kind": "a2a" })).unwrap(),
    );
    green.provides.insert("a2a".to_string(), green_provide);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
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
        "slot used by a conditional `when` must remain live under DCE"
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

#[test]
fn dce_keeps_live_external_root_slot_used_in_env_when_condition() {
    let root_slot = serde_json::from_value(json!({ "kind": "a2a" })).expect("slot decl");
    let green_program = serde_json::from_value(json!({
        "image": "green",
        "entrypoint": ["green"],
        "env": {
            "UPSTREAM_URL": {
                "when": "slots.white.url",
                "value": "${slots.white.url}"
            }
        },
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
    green.program = Some(lower_fixture_program(1, green_program));
    green.slots.insert(
        "white".to_string(),
        serde_json::from_value(json!({ "kind": "a2a" })).unwrap(),
    );
    green.provides.insert("a2a".to_string(), green_provide);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
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
        "slot used by a conditional env `when` must remain live under DCE"
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

#[test]
fn dce_keeps_externally_rooted_child_program_without_exports() {
    let slot_decl = manifest_slot("http", false, false);
    let child_program = serde_json::from_value(json!({
        "image": "child",
        "entrypoint": ["child"],
        "env": { "API_URL": "${slots.api.url}" },
    }))
    .expect("program");

    let mut root = component(0, "/");
    root.slots.insert("api".to_string(), slot_decl.clone());
    root.children.push(ComponentId(1));

    let mut child = component(1, "/child");
    child.parent = Some(ComponentId(0));
    child.program = Some(lower_fixture_program(1, child_program));
    child.slots.insert("api".to_string(), slot_decl);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: vec![external_binding(0, "api", 1, "api", true)],
        exports: Vec::new(),
    };

    let scenario = assert_dce_idempotent(scenario);
    let root_after = scenario.component(ComponentId(0));
    let child_after = scenario
        .components
        .get(1)
        .and_then(|component| component.as_ref())
        .expect("child should remain live");

    assert!(
        child_after.program.is_some(),
        "externally rooted child program must remain"
    );
    assert!(
        root_after.slots.contains_key("api"),
        "external root slot must remain when it roots a child program"
    );
    assert_eq!(scenario.bindings.len(), 1, "external binding should remain");
    assert!(
        matches!(
            &scenario.bindings[0].from,
            BindingFrom::External(slot) if slot.component == ComponentId(0) && slot.name == "api"
        ),
        "expected external binding from root.api to remain"
    );
}

#[test]
fn dce_keeps_externally_rooted_root_program_without_exports() {
    let slot_decl = manifest_slot("http", false, false);
    let root_program = serde_json::from_value(json!({
        "image": "root",
        "entrypoint": ["root"],
        "env": { "API_URL": "${slots.api.url}" },
    }))
    .expect("program");

    let mut root = component(0, "/");
    root.program = Some(lower_fixture_program(0, root_program));
    root.slots.insert("api".to_string(), slot_decl);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: vec![external_binding(0, "api", 0, "api", true)],
        exports: Vec::new(),
    };

    let scenario = assert_dce_idempotent(scenario);
    let root_after = scenario.component(ComponentId(0));

    assert!(
        root_after.program.is_some(),
        "externally rooted root program must remain"
    );
    assert!(
        root_after.slots.contains_key("api"),
        "root external slot must remain when the root program consumes it"
    );
    assert_eq!(
        scenario.bindings.len(),
        1,
        "synthetic self external binding should remain"
    );
    assert!(
        matches!(
            &scenario.bindings[0].from,
            BindingFrom::External(slot) if slot.component == ComponentId(0) && slot.name == "api"
        ),
        "expected self external binding from root.api to remain"
    );
}

#[test]
fn dce_prunes_unused_external_binding_without_exports() {
    let slot_decl = manifest_slot("http", false, false);
    let child_program = serde_json::from_value(json!({
        "image": "child",
        "entrypoint": ["child"],
    }))
    .expect("program");

    let mut root = component(0, "/");
    root.slots.insert("api".to_string(), slot_decl.clone());
    root.children.push(ComponentId(1));

    let mut child = component(1, "/child");
    child.parent = Some(ComponentId(0));
    child.program = Some(lower_fixture_program(1, child_program));
    child.slots.insert("api".to_string(), slot_decl);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: vec![external_binding(0, "api", 1, "api", true)],
        exports: Vec::new(),
    };

    let scenario = assert_dce_idempotent(scenario);
    let root_after = scenario.component(ComponentId(0));

    assert!(
        scenario.components[1].is_none(),
        "child should be pruned when the external-bound slot is never used by its program"
    );
    assert!(
        !root_after.slots.contains_key("api"),
        "dead external root slot should be pruned when nothing live consumes it"
    );
    assert!(
        scenario.bindings.is_empty(),
        "dead external binding should be removed"
    );
}

#[test]
fn dce_keeps_internal_dependencies_of_externally_rooted_program_without_exports() {
    let slot_http = manifest_slot("http", false, false);
    let provide_http: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "admin" }))
            .expect("provide decl");
    let consumer_program = serde_json::from_value(json!({
        "image": "consumer",
        "entrypoint": ["consumer"],
        "env": {
            "API_URL": "${slots.api.url}",
            "ADMIN_URL": "${slots.admin.url}",
        },
    }))
    .expect("program");
    let provider_program = serde_json::from_value(json!({
        "image": "provider",
        "entrypoint": ["provider"],
        "network": { "endpoints": [{ "name": "admin", "port": 9000 }] },
    }))
    .expect("program");

    let mut root = component(0, "/");
    root.slots.insert("api".to_string(), slot_http.clone());
    root.children.extend([ComponentId(1), ComponentId(2)]);

    let mut consumer = component(1, "/consumer");
    consumer.parent = Some(ComponentId(0));
    consumer.program = Some(lower_fixture_program(1, consumer_program));
    consumer.slots.insert("api".to_string(), slot_http.clone());
    consumer
        .slots
        .insert("admin".to_string(), slot_http.clone());

    let mut provider = component(2, "/provider");
    provider.parent = Some(ComponentId(0));
    provider.program = Some(lower_fixture_program(2, provider_program));
    provider.provides.insert("admin".to_string(), provide_http);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(consumer), Some(provider)],
        bindings: vec![
            external_binding(0, "api", 1, "api", true),
            component_binding(2, "admin", 1, "admin"),
        ],
        exports: Vec::new(),
    };

    let scenario = assert_dce_idempotent(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("consumer")),
        "externally rooted consumer must remain"
    );
    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("provider")),
        "provider needed by an externally rooted consumer must remain"
    );
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(
            &edge.from,
            BindingFrom::External(slot)
                if slot.component == ComponentId(0) && slot.name == "api"
        ) && edge.to.component == ComponentId(1)
            && edge.to.name == "api"
    }));
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(&edge.from, BindingFrom::Component(from) if from.component == ComponentId(2) && from.name == "admin")
            && edge.to.component == ComponentId(1)
            && edge.to.name == "admin"
    }));
}

#[test]
fn dce_keeps_externally_rooted_program_when_slot_is_only_used_in_when_without_exports() {
    let slot_decl = manifest_slot("http", true, false);
    let child_program = serde_json::from_value(json!({
        "image": "child",
        "entrypoint": [
            "child",
            { "when": "slots.api", "argv": ["--api"] }
        ],
    }))
    .expect("program");

    let mut root = component(0, "/");
    root.slots.insert("api".to_string(), slot_decl.clone());
    root.children.push(ComponentId(1));

    let mut child = component(1, "/child");
    child.parent = Some(ComponentId(0));
    child.program = Some(lower_fixture_program(1, child_program));
    child.slots.insert("api".to_string(), slot_decl);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: vec![external_binding(0, "api", 1, "api", true)],
        exports: Vec::new(),
    };

    let scenario = assert_dce_idempotent(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("child")),
        "slot use in `when` should be enough to root the child program from an external slot"
    );
    assert_eq!(scenario.bindings.len(), 1, "external binding should remain");
}

#[test]
fn dce_keeps_externally_rooted_program_when_slot_is_only_used_in_repeated_entrypoint_each_without_exports()
 {
    let child_program = serde_json::from_value(json!({
        "image": "child",
        "entrypoint": [
            "child",
            {
                "each": "slots.api",
                "argv": ["--api", "${item.url}"]
            }
        ],
    }))
    .expect("program");

    let scenario =
        externally_rooted_child_scenario("api", manifest_slot("http", true, true), child_program);
    let scenario = assert_dce_idempotent(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("child")),
        "repeated `each` slot use should root the child program from an external slot"
    );
    assert_eq!(scenario.bindings.len(), 1, "external binding should remain");
}

#[test]
fn dce_keeps_externally_rooted_program_when_slot_is_only_used_in_repeated_env_each_without_exports()
{
    let child_program = serde_json::from_value(json!({
        "image": "child",
        "entrypoint": ["child"],
        "env": {
            "API_URLS": {
                "each": "slots.api",
                "value": "${item.url}",
                "join": ","
            }
        },
    }))
    .expect("program");

    let scenario =
        externally_rooted_child_scenario("api", manifest_slot("http", true, true), child_program);
    let scenario = assert_dce_idempotent(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("child")),
        "repeated env `each` slot use should root the child program from an external slot"
    );
    assert_eq!(scenario.bindings.len(), 1, "external binding should remain");
}

#[test]
fn dce_keeps_all_slot_dependencies_for_externally_rooted_program_without_exports() {
    let slot_http = manifest_slot("http", true, false);
    let provide_http: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "admin" }))
            .expect("provide decl");
    let consumer_program = serde_json::from_value(json!({
        "image": "consumer",
        "entrypoint": ["consumer"],
        "env": { "ALL_SLOTS": "${slots}" },
    }))
    .expect("program");
    let provider_program = serde_json::from_value(json!({
        "image": "provider",
        "entrypoint": ["provider"],
        "network": { "endpoints": [{ "name": "admin", "port": 9000 }] },
    }))
    .expect("program");

    let mut root = component(0, "/");
    root.slots.insert("api".to_string(), slot_http.clone());
    root.children.extend([ComponentId(1), ComponentId(2)]);

    let mut consumer = component(1, "/consumer");
    consumer.parent = Some(ComponentId(0));
    consumer.program = Some(lower_fixture_program(1, consumer_program));
    consumer.slots.insert("api".to_string(), slot_http.clone());
    consumer
        .slots
        .insert("admin".to_string(), slot_http.clone());

    let mut provider = component(2, "/provider");
    provider.parent = Some(ComponentId(0));
    provider.program = Some(lower_fixture_program(2, provider_program));
    provider.provides.insert("admin".to_string(), provide_http);

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(consumer), Some(provider)],
        bindings: vec![
            external_binding(0, "api", 1, "api", true),
            component_binding(2, "admin", 1, "admin"),
        ],
        exports: Vec::new(),
    };

    let scenario = assert_dce_idempotent(scenario);

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("consumer")),
        "consumer should remain live when any external binding roots an all-slots program"
    );
    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("provider")),
        "all-slots use should retain internal dependencies of the rooted program"
    );
    assert!(scenario.bindings.iter().any(|edge| {
        matches!(
            &edge.from,
            BindingFrom::Component(from)
                if from.component == ComponentId(2) && from.name == "admin"
        ) && edge.to.component == ComponentId(1)
            && edge.to.name == "admin"
    }));
}

#[test]
fn dce_prunes_dead_incoming_edges_of_live_externally_rooted_program() {
    let slot_http = manifest_slot("http", true, false);
    let provide_http: amber_manifest::ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "admin" }))
            .expect("provide decl");
    let consumer_program = serde_json::from_value(json!({
        "image": "consumer",
        "entrypoint": ["consumer"],
        "env": { "API_URL": "${slots.api.url}" },
    }))
    .expect("program");
    let provider_program = serde_json::from_value(json!({
        "image": "provider",
        "entrypoint": ["provider"],
        "network": { "endpoints": [{ "name": "admin", "port": 9000 }] },
    }))
    .expect("program");

    let mut root = component(0, "/");
    root.slots.insert("api".to_string(), slot_http.clone());
    root.slots.insert("shadow".to_string(), slot_http.clone());
    root.children.extend([ComponentId(1), ComponentId(2)]);

    let mut consumer = component(1, "/consumer");
    consumer.parent = Some(ComponentId(0));
    consumer.program = Some(lower_fixture_program(1, consumer_program));
    consumer.slots.insert("api".to_string(), slot_http.clone());
    consumer
        .slots
        .insert("admin".to_string(), slot_http.clone());
    consumer
        .slots
        .insert("shadow".to_string(), slot_http.clone());

    let mut provider = component(2, "/provider");
    provider.parent = Some(ComponentId(0));
    provider.program = Some(lower_fixture_program(2, provider_program));
    provider.provides.insert("admin".to_string(), provide_http);

    let mut scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(consumer), Some(provider)],
        bindings: vec![
            external_binding(0, "api", 1, "api", true),
            component_binding(2, "admin", 1, "admin"),
            external_binding(0, "shadow", 1, "shadow", true),
        ],
        exports: Vec::new(),
    };
    scenario.normalize_order();

    let scenario = assert_dce_idempotent(scenario);
    let root_after = scenario.component(ComponentId(0));

    assert!(
        scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("consumer")),
        "the consumer should remain live when it is externally rooted through api"
    );
    assert!(
        !scenario
            .components
            .iter()
            .flatten()
            .any(|component| component.moniker.local_name() == Some("provider")),
        "unused internal dependencies should still be pruned from a live consumer"
    );
    assert!(
        !root_after.slots.contains_key("shadow"),
        "unused external root slots should not survive just because the program is live"
    );
    assert_eq!(
        scenario.bindings.len(),
        1,
        "only the binding for the actually used external slot should remain"
    );
    assert!(scenario.bindings.iter().all(|edge| {
        matches!(
            &edge.from,
            BindingFrom::External(slot)
                if slot.component == ComponentId(0) && slot.name == "api"
        ) && edge.to.component == ComponentId(1)
            && edge.to.name == "api"
    }));
}
