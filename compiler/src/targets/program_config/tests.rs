use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use amber_manifest::{Manifest, ManifestDigest, Program as ManifestProgram};
use amber_scenario::{BindingEdge, Component, Moniker, Scenario};

use super::*;
use crate::{
    config::{analysis::ScenarioConfigAnalysis, template::parse_instance_config_template},
    linker::program_lowering::lower_program,
};

fn test_scenario() -> Scenario {
    let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              slots: {
                api: { kind: "http", optional: true },
                upstream: { kind: "http", optional: true, multiple: true },
              },
            }
        "#
    .parse()
    .expect("manifest");

    Scenario {
        root: ComponentId(0),
        components: vec![Some(Component {
            id: ComponentId(0),
            parent: None,
            moniker: Moniker::from(Arc::<str>::from("/")),
            digest: ManifestDigest::new([0; 32]),
            config: None,
            config_schema: None,
            program: None,
            slots: manifest
                .slots()
                .iter()
                .map(|(name, decl)| (name.to_string(), decl.clone()))
                .collect(),
            provides: BTreeMap::new(),
            resources: BTreeMap::new(),
            metadata: None,
            child_templates: BTreeMap::new(),
            children: Vec::new(),
        })],
        bindings: Vec::<BindingEdge>::new(),
        exports: Vec::new(),
        manifest_catalog: BTreeMap::new(),
    }
}

fn test_slot_values() -> BTreeMap<String, SlotValue> {
    BTreeMap::from([
        (
            "api".to_string(),
            SlotValue::One(SlotObject {
                url: "http://127.0.0.1:31001".to_string(),
            }),
        ),
        (
            "upstream".to_string(),
            SlotValue::Many(vec![SlotObject {
                url: "http://127.0.0.1:32001".to_string(),
            }]),
        ),
    ])
}

fn component_with_config_and_program(
    id: usize,
    parent: Option<usize>,
    moniker: &str,
    config_schema: Option<serde_json::Value>,
    config: Option<serde_json::Value>,
    program: Option<serde_json::Value>,
) -> Component {
    let template = parse_instance_config_template(config.as_ref(), config_schema.as_ref())
        .expect("component config template");
    let program = program.map(|program| {
        let program: ManifestProgram = serde_json::from_value(program).expect("manifest program");
        lower_program(ComponentId(id), &program, Some(&template)).expect("program")
    });
    Component {
        id: ComponentId(id),
        parent: parent.map(ComponentId),
        moniker: Moniker::from(Arc::<str>::from(moniker)),
        digest: ManifestDigest::new([id as u8; 32]),
        config,
        config_schema,
        program,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    }
}

fn scenario_with_child(child: Component) -> Scenario {
    let mut root = component_with_config_and_program(0, None, "/", None, None, None);
    root.children.push(child.id);
    Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: Vec::<BindingEdge>::new(),
        exports: Vec::new(),
        manifest_catalog: BTreeMap::new(),
    }
}

fn config_analysis(scenario: &Scenario) -> ScenarioConfigAnalysis {
    ScenarioConfigAnalysis::from_scenario(scenario).expect("config analysis")
}

#[test]
fn build_mount_specs_materializes_literal_config_mounts() {
    let child = component_with_config_and_program(
        1,
        Some(0),
        "/worker",
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "mount_file": { "type": "string" },
            },
            "required": ["mount_file"],
        })),
        Some(serde_json::json!({
            "mount_file": "hello from config",
        })),
        Some(serde_json::json!({
            "image": "app",
            "entrypoint": ["app"],
            "mounts": [
                { "path": "/etc/app/config.txt", "from": "config.mount_file" }
            ],
        })),
    );
    let scenario = scenario_with_child(child);
    let config_analysis = config_analysis(&scenario);
    let mount_specs = build_mount_specs(
        &scenario,
        &config_analysis,
        &[ComponentId(1)],
        RuntimeAddressResolution::Static,
        &HashMap::from([(ComponentId(1), BTreeMap::new())]),
    )
    .expect("mount specs");

    assert_eq!(
        mount_specs.get(&ComponentId(1)),
        Some(&vec![MountSpec::Literal {
            path: "/etc/app/config.txt".to_string(),
            content: "hello from config".to_string(),
        }])
    );
}

#[test]
fn build_mount_specs_defers_slot_mount_templates_for_deferred_runtime_addresses() {
    let config_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "mount_file": { "type": "string" }
        },
        "required": ["mount_file"]
    });
    let config = serde_json::json!({
        "mount_file": "hello from config"
    });
    let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              config_schema: {
                type: "object",
                properties: {
                  mount_file: { type: "string" }
                },
                required: ["mount_file"]
              },
              slots: {
                api: { kind: "http", optional: true }
              },
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  { path: "/tmp/${slots.api.url}", from: "config.mount_file" }
                ]
              }
            }
        "#
    .parse()
    .expect("manifest");
    let template = parse_instance_config_template(Some(&config), Some(&config_schema))
        .expect("component config template");
    let program = lower_program(
        ComponentId(1),
        manifest.program().expect("program"),
        Some(&template),
    )
    .expect("program");
    let child = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: Moniker::from(Arc::<str>::from("/worker")),
        digest: ManifestDigest::new([1; 32]),
        config: Some(config),
        config_schema: Some(config_schema),
        program: Some(program),
        slots: manifest
            .slots()
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };
    let scenario = scenario_with_child(child);
    let config_analysis = config_analysis(&scenario);
    let mount_specs = build_mount_specs(
        &scenario,
        &config_analysis,
        &[ComponentId(1)],
        RuntimeAddressResolution::Deferred,
        &HashMap::from([(ComponentId(1), test_slot_values())]),
    )
    .expect("mount specs");

    assert_eq!(
        mount_specs.get(&ComponentId(1)),
        Some(&vec![MountSpec::Template(MountTemplateSpec {
            when: None,
            each: None,
            path: vec![TemplatePart::lit("/tmp/"), TemplatePart::slot(1, "api.url"),],
            source: vec![
                TemplatePart::lit("config."),
                TemplatePart::lit("mount_file"),
            ],
        })])
    );
}

#[test]
fn build_mount_specs_defers_repeated_slot_item_mount_templates_for_deferred_runtime_addresses() {
    let config_schema = serde_json::json!({
        "type": "object",
        "properties": {
            "mount_file": { "type": "string" }
        },
        "required": ["mount_file"]
    });
    let config = serde_json::json!({
        "mount_file": "hello from config"
    });
    let manifest: Manifest = r#"
            {
              manifest_version: "0.3.0",
              config_schema: {
                type: "object",
                properties: {
                  mount_file: { type: "string" }
                },
                required: ["mount_file"]
              },
              slots: {
                upstream: { kind: "http", optional: true, multiple: true }
              },
              program: {
                image: "app",
                entrypoint: ["app"],
                mounts: [
                  {
                    each: "slots.upstream",
                    path: "/tmp/${item.url}",
                    from: "config.mount_file"
                  }
                ]
              }
            }
        "#
    .parse()
    .expect("manifest");
    let template = parse_instance_config_template(Some(&config), Some(&config_schema))
        .expect("component config template");
    let program = lower_program(
        ComponentId(1),
        manifest.program().expect("program"),
        Some(&template),
    )
    .expect("program");
    let child = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: Moniker::from(Arc::<str>::from("/worker")),
        digest: ManifestDigest::new([1; 32]),
        config: Some(config),
        config_schema: Some(config_schema),
        program: Some(program),
        slots: manifest
            .slots()
            .iter()
            .map(|(name, decl)| (name.to_string(), decl.clone()))
            .collect(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };
    let scenario = scenario_with_child(child);
    let config_analysis = config_analysis(&scenario);
    let mount_specs = build_mount_specs(
        &scenario,
        &config_analysis,
        &[ComponentId(1)],
        RuntimeAddressResolution::Deferred,
        &HashMap::from([(ComponentId(1), test_slot_values())]),
    )
    .expect("mount specs");

    assert_eq!(
        mount_specs.get(&ComponentId(1)),
        Some(&vec![MountSpec::Template(MountTemplateSpec {
            when: None,
            each: None,
            path: vec![
                TemplatePart::lit("/tmp/"),
                TemplatePart::item(1, "upstream", 0, "url"),
            ],
            source: vec![
                TemplatePart::lit("config."),
                TemplatePart::lit("mount_file"),
            ],
        })])
    );
}

#[test]
fn build_mount_specs_allows_config_mount_source_that_resolves_to_secret_path() {
    let child = component_with_config_and_program(
        1,
        Some(0),
        "/worker",
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "source_path": { "type": "string" },
                "token": { "type": "string", "secret": true }
            },
            "required": ["source_path", "token"]
        })),
        Some(serde_json::json!({
            "source_path": "token",
            "token": "shh"
        })),
        Some(serde_json::json!({
            "image": "app",
            "entrypoint": ["app"],
            "mounts": [
                { "path": "/etc/app/config.txt", "from": "config.${config.source_path}" }
            ],
        })),
    );
    let scenario = scenario_with_child(child);
    let config_analysis = config_analysis(&scenario);
    let mount_specs = build_mount_specs(
        &scenario,
        &config_analysis,
        &[ComponentId(1)],
        RuntimeAddressResolution::Static,
        &HashMap::from([(ComponentId(1), BTreeMap::new())]),
    )
    .expect("config mount to a secret path should succeed");

    assert_eq!(
        mount_specs.get(&ComponentId(1)),
        Some(&vec![MountSpec::Literal {
            path: "/etc/app/config.txt".to_string(),
            content: "shh".to_string(),
        }])
    );
}

#[test]
fn resolve_slot_interpolation_rejects_whole_slots_when_component_declares_repeated_slots() {
    let err = resolve_slot_interpolation(
        &test_scenario(),
        ComponentId(0),
        "program.args[0]",
        &InterpolationSource::Slots,
        "",
        &test_slot_values(),
    )
    .expect_err("whole-slots interpolation should fail");

    let message = err.to_string();
    assert!(message.contains("`${slots}`"), "{message}");
    assert!(message.contains("multiple: true"), "{message}");
}

#[test]
fn resolve_slot_interpolation_rejects_singular_query_for_repeated_slot() {
    let err = resolve_slot_interpolation(
        &test_scenario(),
        ComponentId(0),
        "program.args[0]",
        &InterpolationSource::Slots,
        "upstream.url",
        &test_slot_values(),
    )
    .expect_err("singular repeated-slot interpolation should fail");

    let message = err.to_string();
    assert!(message.contains("slot `upstream`"), "{message}");
    assert!(message.contains("multiple: true"), "{message}");
    assert!(message.contains("slots.upstream"), "{message}");
}

#[test]
fn build_endpoint_plan_expands_variadic_config_endpoints() {
    let root = component_with_config_and_program(0, None, "/", None, None, None);
    let child = component_with_config_and_program(
        1,
        Some(0),
        "/api",
        Some(serde_json::json!({
            "type": "object",
            "properties": {
                "ports": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": { "type": "string" },
                            "port": { "type": "integer" },
                            "protocol": { "type": "string" }
                        },
                        "required": ["name", "port", "protocol"]
                    }
                }
            },
            "required": ["ports"]
        })),
        Some(serde_json::json!({
            "ports": [
                { "name": "http", "port": 8080, "protocol": "http" },
                { "name": "admin", "port": 9000, "protocol": "tcp" }
            ]
        })),
        Some(serde_json::json!({
            "image": "service",
            "entrypoint": ["service"],
            "network": {
                "endpoints": [
                    {
                        "when": "config.missing_optional",
                        "name": "debug",
                        "port": 7000
                    },
                    {
                        "each": "config.ports",
                        "name": "${item.name}",
                        "port": "${item.port}",
                        "protocol": "${item.protocol}"
                    }
                ]
            }
        })),
    );

    let mut root = root;
    root.children.push(ComponentId(1));
    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: Vec::<BindingEdge>::new(),
        exports: Vec::new(),
    };

    let endpoint_plan = build_endpoint_plan(&scenario).expect("endpoint plan");

    assert_eq!(
        endpoint_plan.component_endpoints(ComponentId(1)),
        &[
            ExpandedEndpoint {
                name: "http".to_string(),
                port: 8080,
                protocol: amber_manifest::NetworkProtocol::Http,
            },
            ExpandedEndpoint {
                name: "admin".to_string(),
                port: 9000,
                protocol: amber_manifest::NetworkProtocol::Tcp,
            },
        ]
    );
}
