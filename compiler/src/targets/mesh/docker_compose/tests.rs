use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::Duration,
};

use amber_manifest::{
    FrameworkCapabilityName, Manifest, ManifestDigest, ManifestRef, ProvideDecl, SlotDecl,
};
use amber_mesh::{InboundTarget, MeshConfig};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, SlotRef,
};
use serde_json::{Map, Value, json};
use url::Url;

use super::DockerComposeReporter;
use crate::{reporter::Reporter as _, targets::mesh::internal_images::resolve_internal_images};

fn digest(byte: u8) -> ManifestDigest {
    ManifestDigest::new([byte; 32])
}

fn moniker(path: &str) -> Moniker {
    Moniker::from(Arc::from(path))
}

fn internal_images() -> crate::targets::mesh::internal_images::InternalImages {
    resolve_internal_images().expect("internal images should resolve for tests")
}

fn compile_output_with_manifest_overrides(
    scenario: Scenario,
    overrides: BTreeMap<ComponentId, Map<String, Value>>,
) -> crate::CompileOutput {
    let url = Url::parse("file:///scenario.json5").expect("test URL should parse");
    let store = crate::DigestStore::new();

    for component in scenario.components.iter().flatten() {
        let mut manifest = serde_json::Map::new();
        manifest.insert(
            "manifest_version".to_string(),
            Value::String("0.1.0".to_string()),
        );
        if let Some(program) = &component.program {
            manifest.insert(
                "program".to_string(),
                serde_json::to_value(program).unwrap(),
            );
        }
        if !component.slots.is_empty() {
            manifest.insert(
                "slots".to_string(),
                serde_json::to_value(&component.slots).unwrap(),
            );
        }
        if !component.provides.is_empty() {
            manifest.insert(
                "provides".to_string(),
                serde_json::to_value(&component.provides).unwrap(),
            );
        }
        if let Some(extra) = overrides.get(&component.id) {
            for (key, value) in extra {
                manifest.insert(key.clone(), value.clone());
            }
        }

        let manifest: Manifest = serde_json::from_value(Value::Object(manifest)).unwrap();
        store.put(component.digest, Arc::new(manifest));
    }

    let provenance = crate::Provenance {
        components: scenario
            .components
            .iter()
            .map(|component| {
                let component = component
                    .as_ref()
                    .expect("test scenario component should exist");
                crate::ComponentProvenance {
                    authored_moniker: component.moniker.clone(),
                    declared_ref: ManifestRef::from_url(url.clone()),
                    resolved_url: url.clone(),
                    digest: component.digest,
                    observed_url: None,
                }
            })
            .collect(),
    };

    crate::CompileOutput {
        scenario,
        store,
        provenance,
        diagnostics: Vec::new(),
    }
}

fn compile_output(scenario: Scenario) -> crate::CompileOutput {
    compile_output_with_manifest_overrides(scenario, BTreeMap::new())
}

fn error_contains(err: &crate::Error, needle: &str) -> bool {
    match err {
        crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) => {
            errors.iter().any(|err| err.to_string().contains(needle))
        }
        crate::Error::Linker(err) => err.to_string().contains(needle),
        other => other.to_string().contains(needle),
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("compiler crate should live under the workspace root")
        .to_path_buf()
}

fn image_platform_opt(tag: &str) -> Option<String> {
    let output = std::process::Command::new("docker")
        .arg("image")
        .arg("inspect")
        .arg("-f")
        .arg("{{.Architecture}}")
        .arg(tag)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let arch = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if arch.is_empty() {
        return None;
    }
    Some(format!("linux/{arch}"))
}

fn image_platform(tag: &str) -> String {
    image_platform_opt(tag).unwrap_or_else(|| {
        panic!("docker image inspect failed for {tag}");
    })
}

fn ensure_image_platform(tag: &str, platform: &str) {
    let needs_pull = match image_platform_opt(tag) {
        Some(existing) => existing != platform,
        None => true,
    };

    if needs_pull {
        let status = std::process::Command::new("docker")
            .arg("pull")
            .arg("--platform")
            .arg(platform)
            .arg(tag)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "docker pull failed for {tag} ({platform})"
        );
    }

    let actual = image_platform(tag);
    assert_eq!(
        actual, platform,
        "image platform mismatch for {tag}: expected {platform}, got {actual}"
    );
}

fn build_docker_image(tag: &str, dockerfile: &Path, context: &Path) -> String {
    let status = std::process::Command::new("docker")
        .arg("buildx")
        .arg("build")
        .arg("--load")
        .arg("-t")
        .arg(tag)
        .arg("-f")
        .arg(dockerfile)
        .arg(context)
        .status()
        .unwrap();
    assert!(status.success(), "docker build failed for {tag}");
    image_platform(tag)
}

fn build_helper_image() -> String {
    let root = workspace_root();
    let images = internal_images();
    build_docker_image(
        &images.helper,
        &root.join("docker/amber-helper/Dockerfile"),
        &root,
    )
}

fn build_router_image() -> String {
    let root = workspace_root();
    let images = internal_images();
    build_docker_image(
        &images.router,
        &root.join("docker/amber-router/Dockerfile"),
        &root,
    )
}

fn require_same_platform(images: &[(&str, String)]) -> String {
    let (first_tag, first_platform) = images
        .first()
        .expect("at least one image platform should be provided");
    for (tag, platform) in images.iter().skip(1) {
        assert_eq!(
            platform, first_platform,
            "image platform mismatch: {first_tag} is {first_platform}, {tag} is {platform}"
        );
    }
    first_platform.clone()
}

fn parse_compose(yaml: &str) -> super::DockerComposeFile {
    serde_yaml::from_str(yaml).expect("compose yaml should parse")
}

fn service<'a>(compose: &'a super::DockerComposeFile, name: &str) -> &'a super::Service {
    compose
        .services
        .get(name)
        .unwrap_or_else(|| panic!("service {name} missing"))
}

fn env_value(service: &super::Service, key: &str) -> Option<String> {
    let env = service.environment.as_ref()?;
    match env {
        super::Environment::Map(map) => map.get(key).cloned(),
        super::Environment::List(list) => {
            let prefix = format!("{key}=");
            list.iter().find_map(|entry| {
                if entry == key {
                    Some(String::new())
                } else {
                    entry.strip_prefix(&prefix).map(|v| v.to_string())
                }
            })
        }
    }
}

fn extract_compose_env_value(yaml: &str, key: &str) -> Option<String> {
    let compose = parse_compose(yaml);
    compose
        .services
        .values()
        .find_map(|svc| env_value(svc, key))
}

#[test]
fn compose_emits_sidecars_and_programs_and_slot_urls() {
    let server_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["server"],
        "env": {},
        "network": {
            "endpoints": [
                { "name": "api", "port": 8080, "protocol": "http" }
            ]
        }
    }))
    .unwrap();

    let client_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["client"],
        "env": {
            "URL": "${slots.api.url}"
        }
    }))
    .unwrap();

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();
    let provide_http: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(2), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let client = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(client)],
        bindings: vec![BindingEdge {
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(2),
                name: "api".to_string(),
            },
            weak: false,
        }],
        exports: vec![],
    };

    let output = compile_output(scenario);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);
    let images = internal_images();

    // Service names should be injective and include sidecars.
    assert!(compose.services.contains_key("c1-server-net"), "{yaml}");
    assert!(compose.services.contains_key("c1-server"), "{yaml}");
    assert!(compose.services.contains_key("c2-client-net"), "{yaml}");
    assert!(compose.services.contains_key("c2-client"), "{yaml}");

    // Program uses sidecar netns.
    assert_eq!(
        service(&compose, "c2-client").network_mode.as_deref(),
        Some("service:c2-client-net")
    );

    // Sidecar image should be the router binary.
    assert_eq!(service(&compose, "c1-server-net").image, images.router);

    // Compose should not pin static IPs or subnets.
    assert!(!yaml.contains("ipv4_address:"), "{yaml}");
    assert!(!yaml.contains("ipam:"), "{yaml}");

    // Server sidecar config should expose the provide on the program port.
    let server_config_b64 = env_value(
        service(&compose, "c1-server-net"),
        "AMBER_ROUTER_CONFIG_B64",
    )
    .expect("missing server sidecar config");
    let server_config: MeshConfig =
        amber_mesh::decode_config_b64(&server_config_b64).expect("decode server config");
    let inbound = server_config
        .inbound
        .iter()
        .find(|route| route.capability == "api")
        .expect("server inbound route missing");
    assert_eq!(inbound.allowed_issuers.len(), 1);

    // Client sidecar config should listen on the local slot port.
    let client_config_b64 = env_value(
        service(&compose, "c2-client-net"),
        "AMBER_ROUTER_CONFIG_B64",
    )
    .expect("missing client sidecar config");
    let client_config: MeshConfig =
        amber_mesh::decode_config_b64(&client_config_b64).expect("decode client config");
    let outbound = client_config
        .outbound
        .iter()
        .find(|route| route.slot == "api")
        .expect("client outbound route missing");
    assert_eq!(outbound.listen_port, 20000);

    // Slot URL should be rendered with local proxy port base (20000).
    assert_eq!(
        env_value(service(&compose, "c2-client"), "URL").as_deref(),
        Some("http://127.0.0.1:20000")
    );
}

#[test]
fn compose_escapes_entrypoint_dollars() {
    let program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "args": ["sh", "-lc", "echo $API_URL"]
    }))
    .unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: Some(program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: vec![],
        exports: vec![],
    };

    let output = compile_output(scenario);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    let service = compose
        .services
        .values()
        .find(|svc| svc.image == "alpine:3.20")
        .expect("program service should exist");
    let entrypoint = service
        .entrypoint
        .as_ref()
        .expect("entrypoint should exist");
    assert!(entrypoint.iter().any(|arg| arg == "echo $$API_URL"));
}

#[test]
fn compose_resolves_binding_urls_in_child_config() {
    let server_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["server"],
        "env": {},
        "network": {
            "endpoints": [
                { "name": "api", "port": 8080, "protocol": "http" }
            ]
        }
    }))
    .unwrap();

    let client_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["client"],
        "env": {
            "BIND_URL": "${slots.api.url}"
        }
    }))
    .unwrap();

    let observer_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["observer"],
        "env": {
            "UPSTREAM_URL": "${config.upstream_url}"
        }
    }))
    .unwrap();

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();
    let provide_http: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api" })).unwrap();
    let upstream_schema = json!({
        "type": "object",
        "properties": {
            "upstream_url": { "type": "string" }
        },
        "required": ["upstream_url"],
        "additionalProperties": false
    });

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::from([(
            "bind".to_string(),
            SlotRef {
                component: ComponentId(2),
                name: "api".to_string(),
            },
        )]),
        metadata: None,
        children: vec![ComponentId(3), ComponentId(2), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let client = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let observer = Component {
        id: ComponentId(3),
        parent: Some(ComponentId(0)),
        moniker: moniker("/observer"),
        digest: digest(3),
        config: Some(json!({
            "upstream_url": "${bindings.bind.url}"
        })),
        config_schema: Some(upstream_schema),
        program: Some(observer_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(client), Some(observer)],
        bindings: vec![BindingEdge {
            name: Some("bind".to_string()),
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(2),
                name: "api".to_string(),
            },
            weak: false,
        }],
        exports: vec![],
    };

    let mut overrides = BTreeMap::new();
    let mut root_overrides = Map::new();
    root_overrides.insert(
        "components".to_string(),
        json!({
            "server": "file:///server.json5",
            "client": "file:///client.json5",
            "observer": "file:///observer.json5",
        }),
    );
    root_overrides.insert(
        "bindings".to_string(),
        json!([
            { "name": "bind", "to": "#client.api", "from": "#server.api" }
        ]),
    );
    overrides.insert(ComponentId(0), root_overrides);

    let mut observer_overrides = Map::new();
    observer_overrides.insert(
        "config_schema".to_string(),
        json!({
            "type": "object",
            "properties": {
                "upstream_url": { "type": "string" }
            },
            "required": ["upstream_url"],
            "additionalProperties": false
        }),
    );
    overrides.insert(ComponentId(3), observer_overrides);

    let output = compile_output_with_manifest_overrides(scenario, overrides);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    assert!(
        compose
            .services
            .values()
            .any(|svc| { env_value(svc, "BIND_URL").as_deref() == Some("http://127.0.0.1:20000") })
    );
    assert!(compose.services.values().any(|svc| {
        env_value(svc, "UPSTREAM_URL").as_deref() == Some("http://127.0.0.1:20000")
    }));
    assert!(
        !yaml.contains("AMBER_COMPONENT_CONFIG_TEMPLATE_B64"),
        "{yaml}"
    );
}

#[test]
fn compose_resolves_binding_urls_from_grandparent_parent_child_config() {
    let server_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["server"],
        "env": {},
        "network": {
            "endpoints": [
                { "name": "api", "port": 8080, "protocol": "http" }
            ]
        }
    }))
    .unwrap();

    let client_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["client"],
        "env": {}
    }))
    .unwrap();

    let child_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["child"],
        "env": {
            "UPSTREAM_URL": "${config.upstream_url}"
        }
    }))
    .unwrap();

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();
    let provide_http: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api" })).unwrap();
    let upstream_schema = json!({
        "type": "object",
        "properties": {
            "upstream_url": { "type": "string" }
        },
        "required": ["upstream_url"],
        "additionalProperties": false
    });

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::from([(
            "bind".to_string(),
            SlotRef {
                component: ComponentId(2),
                name: "api".to_string(),
            },
        )]),
        metadata: None,
        children: vec![ComponentId(3), ComponentId(2), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let client = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let grandparent = Component {
        id: ComponentId(3),
        parent: Some(ComponentId(0)),
        moniker: moniker("/grandparent"),
        digest: digest(3),
        config: Some(json!({
            "upstream_url": "${bindings.bind.url}"
        })),
        config_schema: Some(upstream_schema.clone()),
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(4)],
    };

    let parent = Component {
        id: ComponentId(4),
        parent: Some(ComponentId(3)),
        moniker: moniker("/grandparent/parent"),
        digest: digest(4),
        config: Some(json!({
            "upstream_url": "${config.upstream_url}"
        })),
        config_schema: Some(upstream_schema.clone()),
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(5)],
    };

    let child = Component {
        id: ComponentId(5),
        parent: Some(ComponentId(4)),
        moniker: moniker("/grandparent/parent/child"),
        digest: digest(5),
        config: Some(json!({
            "upstream_url": "${config.upstream_url}"
        })),
        config_schema: Some(upstream_schema.clone()),
        program: Some(child_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![
            Some(root),
            Some(server),
            Some(client),
            Some(grandparent),
            Some(parent),
            Some(child),
        ],
        bindings: vec![BindingEdge {
            name: Some("bind".to_string()),
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(2),
                name: "api".to_string(),
            },
            weak: false,
        }],
        exports: vec![],
    };

    let mut overrides = BTreeMap::new();
    let mut root_overrides = Map::new();
    root_overrides.insert(
        "components".to_string(),
        json!({
            "server": "file:///server.json5",
            "client": "file:///client.json5",
            "grandparent": "file:///grandparent.json5",
        }),
    );
    root_overrides.insert(
        "bindings".to_string(),
        json!([
            { "name": "bind", "to": "#client.api", "from": "#server.api" }
        ]),
    );
    overrides.insert(ComponentId(0), root_overrides);

    let mut grandparent_overrides = Map::new();
    grandparent_overrides.insert(
        "components".to_string(),
        json!({
            "parent": "file:///parent.json5"
        }),
    );
    grandparent_overrides.insert("config_schema".to_string(), upstream_schema.clone());
    overrides.insert(ComponentId(3), grandparent_overrides);

    let mut parent_overrides = Map::new();
    parent_overrides.insert(
        "components".to_string(),
        json!({
            "child": "file:///child.json5"
        }),
    );
    parent_overrides.insert("config_schema".to_string(), upstream_schema.clone());
    overrides.insert(ComponentId(4), parent_overrides);

    let mut child_overrides = Map::new();
    child_overrides.insert("config_schema".to_string(), upstream_schema);
    overrides.insert(ComponentId(5), child_overrides);

    let output = compile_output_with_manifest_overrides(scenario, overrides);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    assert!(compose.services.values().any(|svc| {
        env_value(svc, "UPSTREAM_URL").as_deref() == Some("http://127.0.0.1:20000")
    }));
    assert!(
        !yaml.contains("AMBER_COMPONENT_CONFIG_TEMPLATE_B64"),
        "{yaml}"
    );
}

#[test]
fn compose_emits_export_metadata_and_labels() {
    let server_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["server"],
        "env": {},
        "network": {
            "endpoints": [
                { "name": "api", "port": 8080, "protocol": "http" }
            ]
        }
    }))
    .unwrap();

    let provide_http: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api" })).unwrap();
    let provide_decl = provide_http.decl.clone();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server)],
        bindings: vec![],
        exports: vec![ScenarioExport {
            name: "public".to_string(),
            capability: provide_decl,
            from: ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            },
        }],
    };

    let output = compile_output(scenario);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    let exports = compose
        .x_amber
        .as_ref()
        .expect("x-amber should be present")
        .exports
        .get("public")
        .expect("public export should exist");
    assert_eq!(exports.component, "/server");
    assert_eq!(exports.provide, "api");
    assert_eq!(exports.protocol, "http");
    assert_eq!(exports.router_mesh_port, 24000);
    let router_meta = compose
        .x_amber
        .as_ref()
        .expect("x-amber should be present")
        .router
        .as_ref()
        .expect("router metadata missing");
    assert_eq!(router_meta.mesh_port, 24000);
    assert_eq!(router_meta.control_port, 24100);

    let router_service = service(&compose, "amber-router");
    assert!(
        router_service
            .ports
            .iter()
            .any(|p| p == "127.0.0.1:24000:24000")
    );
    let labels_json = router_service
        .labels
        .get("amber.exports")
        .expect("router export labels missing");
    let labels_value: serde_json::Value =
        serde_json::from_str(labels_json).expect("labels should be json");
    assert_eq!(labels_value["public"]["router_mesh_port"], 24000);
}

#[test]
fn compose_routes_external_slots_through_router() {
    let client_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["client"],
        "env": {
            "API_URL": "${slots.api.url}"
        }
    }))
    .unwrap();

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::from([("api".to_string(), slot_http.clone())]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(1)],
    };

    let client = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(client)],
        bindings: vec![BindingEdge {
            name: None,
            from: BindingFrom::External(SlotRef {
                component: ComponentId(0),
                name: "api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(1),
                name: "api".to_string(),
            },
            weak: true,
        }],
        exports: Vec::new(),
    };

    let output = compile_output(scenario);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    assert!(compose.services.contains_key("amber-router"));
    let router_service = service(&compose, "amber-router");
    assert!(env_value(router_service, "AMBER_EXTERNAL_SLOT_API_URL").is_some());
    assert!(
        router_service
            .extra_hosts
            .iter()
            .any(|entry| entry == "host.docker.internal:host-gateway")
    );
    assert!(
        compose
            .services
            .values()
            .any(|svc| { env_value(svc, "API_URL").as_deref() == Some("http://127.0.0.1:20000") })
    );
    let external_meta = compose
        .x_amber
        .as_ref()
        .expect("x-amber should be present")
        .external_slots
        .get("api")
        .expect("external slot metadata missing");
    assert_eq!(external_meta.kind, "http");
    assert_eq!(external_meta.url_env, "AMBER_EXTERNAL_SLOT_API_URL");

    let b64 =
        extract_compose_env_value(&yaml, "AMBER_ROUTER_CONFIG_B64").expect("router config env var");
    let config: MeshConfig = amber_mesh::decode_config_b64(&b64).expect("parse router config");
    assert!(config.outbound.is_empty());
    let inbound = config
        .inbound
        .iter()
        .find(|route| route.capability == "api")
        .expect("router external route missing");
    match &inbound.target {
        amber_mesh::InboundTarget::External { url_env, .. } => {
            assert_eq!(url_env, "AMBER_EXTERNAL_SLOT_API_URL");
        }
        other => panic!("unexpected router target: {other:?}"),
    }
}

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_external_slot_routes_to_outside_service() {
    use tempfile::tempdir;

    struct ComposeGuard {
        project: PathBuf,
        envs: Vec<(String, String)>,
    }

    impl ComposeGuard {
        fn new(project: &Path, envs: &[(&str, &str)]) -> Self {
            Self {
                project: project.to_path_buf(),
                envs: envs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }
    }

    impl Drop for ComposeGuard {
        fn drop(&mut self) {
            let mut cmd = Command::new("docker");
            cmd.current_dir(&self.project).arg("compose").args([
                "down",
                "-v",
                "--remove-orphans",
                "--rmi",
                "local",
                "--timeout",
                "1",
            ]);
            for (k, v) in &self.envs {
                cmd.env(k, v);
            }
            let _ = cmd.status();
        }
    }

    struct ExternalContainerGuard {
        name: String,
    }

    impl ExternalContainerGuard {
        fn new(name: &str, network: &str) -> Self {
            let status = Command::new("docker")
                .arg("run")
                .arg("-d")
                .arg("--rm")
                .arg("--name")
                .arg(name)
                .arg("--network")
                .arg(network)
                .arg("busybox:1.36.1")
                .arg("sh")
                .arg("-lc")
                .arg(
                    "mkdir -p /www && echo external-ok > /www/index.html && httpd -f -p 8080 -h \
                     /www",
                )
                .status()
                .unwrap();
            assert!(status.success(), "docker run external server failed");
            Self {
                name: name.to_string(),
            }
        }
    }

    impl Drop for ExternalContainerGuard {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .arg("rm")
                .arg("-f")
                .arg(&self.name)
                .status();
        }
    }

    let dir = tempdir().unwrap();
    let project = dir.path();
    let router_platform = build_router_image();
    let images = internal_images();
    let platform = require_same_platform(&[(&images.router, router_platform)]);
    ensure_image_platform("busybox:1.36.1", &platform);
    ensure_image_platform("alpine:3.20", &platform);

    let client_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "args": ["sh", "-lc", "sleep infinity"],
        "env": {
            "API_URL": "${slots.api.url}"
        }
    }))
    .unwrap();

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::from([("api".to_string(), slot_http.clone())]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(1)],
    };

    let client = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(client)],
        bindings: vec![BindingEdge {
            name: None,
            from: BindingFrom::External(SlotRef {
                component: ComponentId(0),
                name: "api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(1),
                name: "api".to_string(),
            },
            weak: true,
        }],
        exports: Vec::new(),
    };

    let output = compile_output(scenario);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    fs::write(project.join("docker-compose.yaml"), yaml).unwrap();

    let project_name = format!("amber-ext-slot-{}", std::process::id());
    let external_name = format!("{project_name}-external");
    let external_url = format!("http://{external_name}:8080");
    let envs = [
        ("COMPOSE_PROJECT_NAME", project_name.as_str()),
        ("AMBER_EXTERNAL_SLOT_API_URL", external_url.as_str()),
    ];

    let _compose_guard = ComposeGuard::new(project, &envs);

    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        for (k, v) in &envs {
            cmd.env(k, v);
        }
        cmd
    };

    let status = compose(&["up", "-d"]).status().unwrap();
    assert!(status.success(), "docker compose up failed");

    let network = format!("{project_name}_amber_mesh");
    let _external_guard = ExternalContainerGuard::new(&external_name, &network);

    let mut ok = false;
    for _ in 0..30 {
        let output = compose(&[
            "exec",
            "-T",
            "c1-client",
            "sh",
            "-lc",
            r#"wget -qO- --timeout=2 --tries=1 "$API_URL" 2>/dev/null"#,
        ])
        .output()
        .unwrap();
        if output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains("external-ok")
        {
            ok = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    if !ok {
        let compose_logs = compose(&["logs", "--no-color"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|err| format!("failed to capture compose logs: {err}"));
        let external_logs = Command::new("docker")
            .arg("logs")
            .arg(&external_name)
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|err| format!("failed to capture external logs: {err}"));
        panic!(
            "client could not reach external slot via router\ncompose logs:\n{}\nexternal \
             logs:\n{}",
            compose_logs, external_logs
        );
    }
}

#[test]
fn docker_compose_allows_shared_port_with_different_endpoints() {
    let server_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["server"],
        "network": {
            "endpoints": [
                { "name": "a", "port": 80, "protocol": "http" },
                { "name": "b", "port": 80, "protocol": "http" }
            ]
        }
    }))
    .unwrap();

    let client_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["client"],
        "env": {
            "V1": "${slots.v1.url}",
            "ADMIN": "${slots.admin.url}"
        }
    }))
    .unwrap();

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();
    let provide_v1 = serde_json::from_value(json!({ "kind": "http", "endpoint": "a" })).unwrap();
    let provide_admin = serde_json::from_value(json!({ "kind": "http", "endpoint": "b" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(2), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([
            ("v1".to_string(), provide_v1),
            ("admin".to_string(), provide_admin),
        ]),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let client = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(client_program),
        slots: BTreeMap::from([
            ("v1".to_string(), slot_http.clone()),
            ("admin".to_string(), slot_http),
        ]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(client)],
        bindings: vec![
            BindingEdge {
                name: None,
                from: BindingFrom::Component(ProvideRef {
                    component: ComponentId(1),
                    name: "v1".to_string(),
                }),
                to: SlotRef {
                    component: ComponentId(2),
                    name: "v1".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                name: None,
                from: BindingFrom::Component(ProvideRef {
                    component: ComponentId(1),
                    name: "admin".to_string(),
                }),
                to: SlotRef {
                    component: ComponentId(2),
                    name: "admin".to_string(),
                },
                weak: false,
            },
        ],
        exports: vec![],
    };

    let output = compile_output(scenario);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render should succeed");
    let compose = parse_compose(&yaml);
    let mut server_config = None;
    for service in compose.services.values() {
        let Some(b64) = env_value(service, "AMBER_ROUTER_CONFIG_B64") else {
            continue;
        };
        let config: MeshConfig = amber_mesh::decode_config_b64(&b64).expect("decode mesh config");
        let has_v1 = config.inbound.iter().any(|route| route.capability == "v1");
        let has_admin = config
            .inbound
            .iter()
            .any(|route| route.capability == "admin");
        if has_v1 && has_admin {
            server_config = Some(config);
            break;
        }
    }

    let config = server_config.expect("server mesh config missing");
    let v1_port = config
        .inbound
        .iter()
        .find(|route| route.capability == "v1")
        .and_then(|route| match route.target {
            InboundTarget::Local { port } => Some(port),
            _ => None,
        })
        .expect("v1 inbound local target");
    let admin_port = config
        .inbound
        .iter()
        .find(|route| route.capability == "admin")
        .and_then(|route| match route.target {
            InboundTarget::Local { port } => Some(port),
            _ => None,
        })
        .expect("admin inbound local target");
    assert_eq!(v1_port, 80);
    assert_eq!(admin_port, 80);
}

#[test]
fn docker_compose_rejects_framework_bindings() {
    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root)],
        bindings: vec![BindingEdge {
            name: None,
            from: BindingFrom::Framework(
                FrameworkCapabilityName::try_from("dynamic_children").unwrap(),
            ),
            to: SlotRef {
                component: ComponentId(0),
                name: "control".to_string(),
            },
            weak: false,
        }],
        exports: Vec::new(),
    };

    let output = compile_output(scenario);
    let err = DockerComposeReporter.emit(&output).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("framework.dynamic_children"),
        "unexpected error: {message}"
    );
    assert!(
        message.contains("docker-compose reporter does not support framework binding"),
        "unexpected error: {message}"
    );
}

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_ocap_blocks_unbound_callers() {
    use std::{fs, process::Command};

    use tempfile::tempdir;

    struct ComposeGuard {
        project: std::path::PathBuf,
    }

    impl ComposeGuard {
        fn new(project: &std::path::Path) -> Self {
            Self {
                project: project.to_path_buf(),
            }
        }
    }

    impl Drop for ComposeGuard {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .current_dir(&self.project)
                .arg("compose")
                .args([
                    "down",
                    "-v",
                    "--remove-orphans",
                    "--rmi",
                    "local",
                    "--timeout",
                    "1",
                ])
                .status();
        }
    }

    // Build a tiny scenario:
    // - server runs busybox httpd on 8080
    // - allowed client has a binding and uses ${slots.api.url}
    // - denied client has no binding and tries to call server mesh port directly
    //
    // NOTE: This test builds the router image locally and uses its platform.
    let dir = tempdir().unwrap();
    let project = dir.path();
    let platform = build_router_image();
    ensure_image_platform("busybox:1.36.1", &platform);
    ensure_image_platform("alpine:3.20", &platform);
    let _compose_guard = ComposeGuard::new(project);
    let server_host = "c1-server-net";

    // Scenario definition
    let server_program = serde_json::from_value(json!({
        "image": "busybox:1.36.1",
        "args": ["sh", "-lc", "mkdir -p /www && echo hello > /www/index.html && httpd -f -p 8080 -h /www"],
        "network": { "endpoints": [ { "name": "api", "port": 8080, "protocol": "http" } ] }
    }))
    .unwrap();

    let sleeper_program = |env: serde_json::Value| {
        serde_json::from_value(json!({
            "image": "alpine:3.20",
            "args": ["sh", "-lc", "sleep infinity"],
            "env": env
        }))
        .unwrap()
    };

    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();
    let provide_http =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "api" })).unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(2), ComponentId(3), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let allowed = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/allowed"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(sleeper_program(json!({ "URL": "${slots.api.url}" }))),
        slots: BTreeMap::from([("api".to_string(), slot_http.clone())]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let denied = Component {
        id: ComponentId(3),
        parent: Some(ComponentId(0)),
        moniker: moniker("/denied"),
        digest: digest(3),
        config: None,
        config_schema: None,
        program: Some(sleeper_program(json!({}))),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(allowed), Some(denied)],
        bindings: vec![BindingEdge {
            name: None,
            from: BindingFrom::Component(ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            }),
            to: SlotRef {
                component: ComponentId(2),
                name: "api".to_string(),
            },
            weak: false,
        }],
        exports: vec![],
    };

    let output = compile_output(scenario);
    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    fs::write(project.join("docker-compose.yaml"), yaml).unwrap();

    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        cmd
    };

    // Up
    let status = compose(&["up", "-d"]).status().unwrap();
    assert!(status.success(), "docker compose up failed");

    // Allowed should succeed via local slot URL.
    let ok = compose(&[
        "exec",
        "-T",
        "c2-allowed",
        "sh",
        "-lc",
        r#"i=0; while [ $i -lt 10 ]; do if wget -qO- --timeout=1 --tries=1 "$URL" 2>/dev/null | grep -q hello; then exit 0; fi; i=$((i+1)); sleep 1; done; exit 1"#,
    ])
    .output()
    .unwrap();
    if !ok.status.success() {
        let dump = |args: &[&str]| -> String {
            let output = compose(args).output();
            match output {
                Ok(output) => format!(
                    "status: {}\nstdout:\n{}\nstderr:\n{}\n",
                    output.status,
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                ),
                Err(err) => format!("failed to run {:?}: {err}\n", args),
            }
        };
        let debug = format!(
            "allowed stdout:\n{}\nallowed stderr:\n{}\n\nserver container:\n{}\nallowed \
             sidecar:\n{}\ncompose logs:\n{}",
            String::from_utf8_lossy(&ok.stdout),
            String::from_utf8_lossy(&ok.stderr),
            dump(&[
                "exec",
                "-T",
                "c1-server",
                "sh",
                "-lc",
                "ps && (netstat -ltn || ss -ltn || true)"
            ]),
            dump(&[
                "exec",
                "-T",
                "c2-allowed-net",
                "sh",
                "-lc",
                "ip -4 addr && ps"
            ]),
            dump(&["logs", "--no-color"]),
        );
        panic!("allowed client could not reach server via binding\n{debug}");
    }

    // Denied should fail when calling server mesh port directly.
    let denied = compose(&[
        "exec",
        "-T",
        "c3-denied",
        "sh",
        "-lc",
        &format!(r#"wget -qO- --timeout=2 --tries=1 "http://{server_host}:23000/" 2>/dev/null"#),
    ])
    .status()
    .unwrap();
    assert!(
        !denied.success(),
        "denied client unexpectedly reached server"
    );
}

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_config_forwarding_runtime_validation() {
    use std::{fs, process::Command, thread, time::Duration};

    use amber_resolver::Resolver;
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let project = dir.path();
    let router_platform = build_router_image();
    let helper_platform = build_helper_image();
    let images = internal_images();
    let platform = require_same_platform(&[
        (&images.router, router_platform),
        (&images.helper, helper_platform),
    ]);
    ensure_image_platform("busybox:1.36.1", &platform);

    let child_path = project.join("client.json5");
    fs::write(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              api_key: { type: "string" },
              system_prompt: { type: "string" },
            },
            required: ["api_key", "system_prompt"],
            additionalProperties: false,
          },
          program: {
            image: "busybox:1.36.1",
            entrypoint: [
              "sh",
              "-lc",
              "printf 'api_key=%s\\nsystem_prompt=%s\\n' \"$API_KEY\" \"$SYSTEM_PROMPT\" > /tmp/amber-config-output; sleep infinity",
            ],
            env: {
              API_KEY: "${config.api_key}",
              SYSTEM_PROMPT: "${config.system_prompt}",
            },
          },
        }
        "#,
    )
    .unwrap();

    let child_url = Url::from_file_path(&child_path).unwrap();
    let root_invalid_path = project.join("root-missing-prompt.json5");
    fs::write(
        &root_invalid_path,
        format!(
            r#"
            {{
              manifest_version: "0.1.0",
              config_schema: {{
                type: "object",
                properties: {{
                  api_key: {{ type: "string", pattern: "^[A-Z]{{3}}$" }},
                  system_prompt: {{ type: "string" }},
                }},
                required: ["api_key"],
                additionalProperties: false,
              }},
              components: {{
                client: {{
                  manifest: "{child}",
                  config: {{
                    api_key: "${{config.api_key}}",
                  }},
                }},
              }},
            }}
            "#,
            child = child_url
        ),
    )
    .unwrap();

    let root_valid_path = project.join("root.json5");
    fs::write(
        &root_valid_path,
        format!(
            r#"
            {{
              manifest_version: "0.1.0",
              config_schema: {{
                type: "object",
                properties: {{
                  api_key: {{ type: "string", pattern: "^[A-Z]{{3}}$" }},
                  system_prompt: {{ type: "string" }},
                }},
                required: ["api_key"],
                additionalProperties: false,
              }},
              components: {{
                client: {{
                  manifest: "{child}",
                  config: {{
                    api_key: "${{config.api_key}}",
                    system_prompt: "STATIC_PROMPT",
                  }},
                }},
              }},
            }}
            "#,
            child = child_url
        ),
    )
    .unwrap();

    let compiler = crate::Compiler::new(Resolver::new(), crate::DigestStore::default());
    let opts = crate::CompileOptions {
        resolve: crate::ResolveOptions { max_concurrency: 8 },
        optimize: crate::OptimizeOptions { dce: false },
    };
    let rt = tokio::runtime::Runtime::new().unwrap();

    let err = rt
        .block_on(compiler.compile(
            ManifestRef::from_url(Url::from_file_path(&root_invalid_path).unwrap()),
            opts.clone(),
        ))
        .unwrap_err();
    assert!(
        error_contains(&err, "missing required field config.system_prompt"),
        "unexpected compile error: {err}"
    );

    let output = rt
        .block_on(compiler.compile(
            ManifestRef::from_url(Url::from_file_path(&root_valid_path).unwrap()),
            opts,
        ))
        .expect("compile ok");

    let yaml = DockerComposeReporter
        .emit(&output)
        .expect("compose render ok");
    fs::write(project.join("docker-compose.yaml"), yaml).unwrap();

    struct ComposeGuard {
        project: std::path::PathBuf,
        envs: Vec<(String, String)>,
    }

    impl ComposeGuard {
        fn new(project: &std::path::Path, envs: &[(&str, &str)]) -> Self {
            Self {
                project: project.to_path_buf(),
                envs: envs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            }
        }
    }

    impl Drop for ComposeGuard {
        fn drop(&mut self) {
            let mut cmd = Command::new("docker");
            cmd.current_dir(&self.project).arg("compose").args([
                "down",
                "-v",
                "--remove-orphans",
                "--rmi",
                "local",
                "--timeout",
                "1",
            ]);
            for (k, v) in &self.envs {
                cmd.env(k, v);
            }
            let _ = cmd.status();
        }
    }

    let valid_env = [
        ("AMBER_CONFIG_API_KEY", "ABC"),
        ("AMBER_CONFIG_SYSTEM_PROMPT", "OVERRIDE"),
    ];
    let _compose_guard = ComposeGuard::new(project, &valid_env);

    let compose = |envs: &[(&str, &str)], args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd
    };

    let status = compose(&valid_env, &["up", "-d"]).status().unwrap();
    assert!(status.success(), "docker compose up failed");

    let mut rendered = None;
    for _ in 0..20 {
        let output = compose(
            &valid_env,
            &[
                "exec",
                "-T",
                "c1-client",
                "sh",
                "-lc",
                "cat /tmp/amber-config-output",
            ],
        )
        .output();
        if let Ok(output) = output
            && output.status.success()
        {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                rendered = Some(text);
                break;
            }
        }
        thread::sleep(Duration::from_secs(1));
    }

    let rendered = rendered.unwrap_or_else(|| {
        let logs = compose(&valid_env, &["logs", "--no-color"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|err| format!("failed to capture logs: {err}"));
        panic!("timed out waiting for rendered config output\ncompose logs:\n{logs}");
    });

    assert!(
        rendered.contains("api_key=ABC"),
        "missing forwarded api_key in output: {rendered}"
    );
    assert!(
        rendered.contains("system_prompt=STATIC_PROMPT"),
        "static system_prompt missing from output: {rendered}"
    );
    assert!(
        !rendered.contains("system_prompt=OVERRIDE"),
        "static system_prompt should not be overridden: {rendered}"
    );

    let _ = compose(
        &valid_env,
        &[
            "down",
            "-v",
            "--remove-orphans",
            "--rmi",
            "local",
            "--timeout",
            "1",
        ],
    )
    .status();

    let invalid_env = [
        ("AMBER_CONFIG_API_KEY", "bad"),
        ("AMBER_CONFIG_SYSTEM_PROMPT", "OVERRIDE"),
    ];

    let status = compose(&invalid_env, &["up", "-d"]).status().unwrap();
    assert!(status.success(), "docker compose up failed");

    let container_id = compose(&invalid_env, &["ps", "-a", "-q", "c1-client"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    assert!(
        !container_id.is_empty(),
        "failed to resolve container id for c1-client"
    );

    let mut exit = None;
    for _ in 0..10 {
        let inspect = Command::new("docker")
            .arg("inspect")
            .arg("-f")
            .arg("{{.State.Status}} {{.State.ExitCode}}")
            .arg(&container_id)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
        if let Some((status, code)) = text.split_once(' ')
            && status == "exited"
        {
            let code = code.parse::<i32>().unwrap_or(0);
            exit = Some((status.to_string(), code));
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    let (state, code) =
        exit.unwrap_or_else(|| panic!("container did not exit after invalid config"));
    assert_ne!(
        code, 0,
        "invalid dynamic config should fail (state={state} code={code})"
    );

    let logs = compose(&invalid_env, &["logs", "--no-color", "c1-client"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    assert!(
        logs.contains("validation error"),
        "expected runtime validation error, got logs:\n{logs}"
    );

    let _ = compose(
        &invalid_env,
        &[
            "down",
            "-v",
            "--remove-orphans",
            "--rmi",
            "local",
            "--timeout",
            "1",
        ],
    )
    .status();
}
