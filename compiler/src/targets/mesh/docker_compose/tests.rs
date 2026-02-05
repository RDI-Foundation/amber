use std::{
    collections::BTreeMap,
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
    thread,
    time::Duration,
};

use amber_manifest::{FrameworkCapabilityName, ManifestDigest, ManifestRef, ProvideDecl, SlotDecl};
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, SlotRef,
};
use base64::Engine as _;
use serde_json::json;
use url::Url;

use super::{DockerComposeReporter, HELPER_IMAGE, ROUTER_IMAGE, SIDECAR_IMAGE};
use crate::reporter::Reporter as _;

fn digest(byte: u8) -> ManifestDigest {
    ManifestDigest::new([byte; 32])
}

fn moniker(path: &str) -> Moniker {
    Moniker::from(Arc::from(path))
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

fn build_sidecar_image() -> String {
    let root = workspace_root();
    build_docker_image(
        SIDECAR_IMAGE,
        &root.join("docker/amber-sidecar/Dockerfile"),
        &root.join("docker/amber-sidecar"),
    )
}

fn build_helper_image() -> String {
    let root = workspace_root();
    build_docker_image(
        HELPER_IMAGE,
        &root.join("docker/amber-helper/Dockerfile"),
        &root,
    )
}

fn build_router_image() -> String {
    let root = workspace_root();
    build_docker_image(
        ROUTER_IMAGE,
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

fn command_script(service: &super::Service) -> Option<&str> {
    service
        .command
        .as_ref()
        .and_then(|cmd| cmd.last())
        .map(|s| s.as_str())
}

fn http_get(host: &str, port: u16) -> std::io::Result<String> {
    let mut stream = TcpStream::connect((host, port))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;
    let request = format!("GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
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

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

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

    // Sidecar image should be pulled from GHCR.
    assert_eq!(service(&compose, "c1-server-net").image, SIDECAR_IMAGE);

    // Compose should not pin static IPs or subnets.
    assert!(!yaml.contains("ipv4_address:"), "{yaml}");
    assert!(!yaml.contains("ipam:"), "{yaml}");

    // Server sidecar should allow inbound from client on 8080 via DNS resolution.
    let server_sidecar_script =
        command_script(service(&compose, "c1-server-net")).expect("server sidecar command script");
    assert!(server_sidecar_script.contains(r#"resolve_ipv4 "c2-client-net""#));
    assert!(
        server_sidecar_script
            .contains(r#"add_rule "-s $$ip/32 -p tcp -m tcp --dport 8080 -j ACCEPT""#)
    );

    // Sidecar proxies should target DNS names, not static IPs.
    let client_sidecar_script =
        command_script(service(&compose, "c2-client-net")).expect("client sidecar command script");
    assert!(client_sidecar_script.contains("TCP:c1-server-net:8080"));

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

    let yaml = DockerComposeReporter
        .emit(&scenario)
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
        config_schema: Some(json!({
            "type": "object",
            "properties": {
                "upstream_url": { "type": "string" }
            },
            "required": ["upstream_url"],
            "additionalProperties": false
        })),
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

    let yaml = DockerComposeReporter
        .emit(&scenario)
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

    let upstream_schema = json!({
        "type": "object",
        "properties": {
            "upstream_url": { "type": "string" }
        },
        "required": ["upstream_url"],
        "additionalProperties": false
    });

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

    let yaml = DockerComposeReporter
        .emit(&scenario)
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

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    let exports = compose
        .x_amber
        .as_ref()
        .expect("x-amber should be present")
        .exports
        .get("public")
        .expect("public export should exist");
    assert_eq!(exports.published_host, "127.0.0.1");
    assert_eq!(exports.published_port, 18000);
    assert_eq!(exports.target_port, 8080);
    assert_eq!(exports.component, "/server");
    assert_eq!(exports.provide, "api");
    assert_eq!(exports.endpoint, "api");

    let router_sidecar = service(&compose, "amber-router-net");
    assert!(
        router_sidecar
            .ports
            .iter()
            .any(|p| p == "127.0.0.1:18000:22000")
    );
    let labels_json = router_sidecar
        .labels
        .get("amber.exports")
        .expect("router export labels missing");
    let labels_value: serde_json::Value =
        serde_json::from_str(labels_json).expect("labels should be json");
    assert_eq!(labels_value["public"]["published_port"], 18000);
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

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    assert!(compose.services.contains_key("amber-router-net"));
    assert!(
        compose
            .services
            .values()
            .any(|svc| env_value(svc, "AMBER_EXTERNAL_SLOT_API_URL").is_some())
    );
    assert!(
        compose
            .services
            .values()
            .any(|svc| { env_value(svc, "API_URL").as_deref() == Some("http://127.0.0.1:20000") })
    );

    let b64 =
        extract_compose_env_value(&yaml, "AMBER_ROUTER_CONFIG_B64").expect("router config env var");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(b64.as_bytes())
        .expect("decode router config");
    let config: serde_json::Value = serde_json::from_slice(&decoded).expect("parse router config");

    assert_eq!(config["external_slots"][0]["name"], "api");
    assert_eq!(config["external_slots"][0]["listen_port"], 21000);
    assert_eq!(
        config["external_slots"][0]["url_env"],
        "AMBER_EXTERNAL_SLOT_API_URL"
    );
    assert!(config["exports"].as_array().unwrap().is_empty());
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
    let sidecar_platform = build_sidecar_image();
    let router_platform = build_router_image();
    let platform = require_same_platform(&[
        (SIDECAR_IMAGE, sidecar_platform),
        (ROUTER_IMAGE, router_platform),
    ]);
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

    let yaml = DockerComposeReporter
        .emit(&scenario)
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

    let bypass = compose(&[
        "exec",
        "-T",
        "c1-client",
        "sh",
        "-lc",
        &format!(r#"wget -qO- --timeout=2 --tries=1 "http://{external_name}:8080" 2>/dev/null"#),
    ])
    .status()
    .unwrap();
    assert!(
        !bypass.success(),
        "client bypassed router by reaching {external_name} directly"
    );

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
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_export_routes_to_host() {
    use tempfile::tempdir;

    struct ComposeGuard {
        project: PathBuf,
    }

    impl ComposeGuard {
        fn new(project: &Path) -> Self {
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

    let dir = tempdir().unwrap();
    let project = dir.path();
    let sidecar_platform = build_sidecar_image();
    let router_platform = build_router_image();
    let platform = require_same_platform(&[
        (SIDECAR_IMAGE, sidecar_platform),
        (ROUTER_IMAGE, router_platform),
    ]);
    ensure_image_platform("busybox:1.36.1", &platform);

    let server_program = serde_json::from_value(json!({
        "image": "busybox:1.36.1",
        "args": ["sh", "-lc", "mkdir -p /www && echo export-ok > /www/index.html && httpd -f -p 8080 -h /www"],
        "network": { "endpoints": [ { "name": "api", "port": 8080, "protocol": "http" } ] }
    }))
    .unwrap();

    let provide_http: ProvideDecl = serde_json::from_value(json!({
        "kind": "http",
        "endpoint": "api"
    }))
    .unwrap();
    let export_capability = provide_http.decl.clone();

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
            capability: export_capability,
            from: ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            },
        }],
    };

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    let export = compose
        .x_amber
        .as_ref()
        .expect("x-amber should be present")
        .exports
        .get("public")
        .expect("public export should exist");
    let published_port = export.published_port;
    let published_host = if export.published_host == "0.0.0.0" {
        "127.0.0.1".to_string()
    } else {
        export.published_host.clone()
    };

    fs::write(project.join("docker-compose.yaml"), yaml).unwrap();

    let _compose_guard = ComposeGuard::new(project);
    let status = Command::new("docker")
        .current_dir(project)
        .arg("compose")
        .args(["up", "-d"])
        .status()
        .unwrap();
    assert!(status.success(), "docker compose up failed");

    let mut ok = false;
    for _ in 0..30 {
        if let Ok(response) = http_get(&published_host, published_port) {
            if response.contains("export-ok") {
                ok = true;
                break;
            }
        }
        thread::sleep(Duration::from_secs(1));
    }

    if !ok {
        let compose_logs = Command::new("docker")
            .current_dir(project)
            .arg("compose")
            .args(["logs", "--no-color"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|err| format!("failed to capture compose logs: {err}"));
        panic!(
            "export not reachable from host via router \
             ({published_host}:{published_port})\ncompose logs:\n{}",
            compose_logs
        );
    }
}

#[test]
fn errors_on_shared_port_with_different_endpoints() {
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

    let err = DockerComposeReporter.emit(&scenario).unwrap_err();
    assert!(
        err.to_string()
            .contains("docker-compose output cannot enforce separate capabilities"),
        "unexpected error: {err}"
    );
    assert!(
        err.to_string().contains("route to port 80"),
        "unexpected error: {err}"
    );
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

    let err = DockerComposeReporter.emit(&scenario).unwrap_err();
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
    // - denied client has no binding and tries to call server directly by sidecar DNS name:8080
    //
    // NOTE: This test builds the sidecar image locally and uses its platform.
    let dir = tempdir().unwrap();
    let project = dir.path();
    let platform = build_sidecar_image();
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

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    fs::write(project.join("docker-compose.yaml"), yaml).unwrap();

    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        cmd
    };
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
        r#"i=0; while [ $i -lt 6 ]; do if wget -qO- --timeout=1 --tries=1 "$URL" 2>/dev/null | grep -q hello; then exit 0; fi; i=$((i+1)); sleep 1; done; exit 1"#,
    ])
    .output()
    .unwrap();
    if !ok.status.success() {
        let debug = format!(
            "allowed stdout:\n{}\nallowed stderr:\n{}\n\nserver container:\n{}\nserver \
             sidecar:\n{}\nallowed sidecar:\n{}\ncompose logs:\n{}",
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
                "c1-server-net",
                "sh",
                "-lc",
                "ip -4 addr && iptables -S"
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

    let external_check_script = r#"retries="${RETRIES:-5}"
is_private_ip() {
  ip="$1"
  case "$ip" in
    10.*|192.168.*|169.254.*) return 0 ;;
    172.*)
      o2="$(printf '%s' "$ip" | cut -d. -f2)"
      [ "$o2" -ge 16 ] && [ "$o2" -le 31 ] && return 0
      ;;
    100.*)
      o2="$(printf '%s' "$ip" | cut -d. -f2)"
      [ "$o2" -ge 64 ] && [ "$o2" -le 127 ] && return 0
      ;;
  esac
  return 1
}

ip=""
if command -v getent >/dev/null 2>&1; then
  ip="$(getent hosts example.com | awk 'NR==1 {print $1}')"
fi

if [ -n "$ip" ] && is_private_ip "$ip"; then
  echo "example.com resolved to private $ip; checking public IP instead" 1>&2
  i=0; while [ $i -lt "$retries" ]; do
    if wget -qO- --timeout=2 --tries=1 "http://1.1.1.1/" >/dev/null 2>&1; then exit 0; fi
    i=$((i+1)); sleep 1
  done
  exit 1
fi

i=0; while [ $i -lt "$retries" ]; do
  if wget -qO- --timeout=2 --tries=1 "http://example.com/" >/dev/null 2>&1; then exit 0; fi
  i=$((i+1)); sleep 1
done
echo "example.com fetch failed; checking public IP instead" 1>&2
i=0; while [ $i -lt "$retries" ]; do
  if wget -qO- --timeout=2 --tries=1 "http://1.1.1.1/" >/dev/null 2>&1; then exit 0; fi
  i=$((i+1)); sleep 1
done
exit 1
"#;

    // Allowed should reach the public internet (example.com). If Docker itself can't reach a
    // public IP, skip the external check to avoid false failures in restricted environments.
    let docker_public_ok = Command::new("docker")
        .args([
            "run",
            "--rm",
            "alpine:3.20",
            "sh",
            "-lc",
            r#"wget -qO- --timeout=2 --tries=1 "http://1.1.1.1/" >/dev/null 2>&1"#,
        ])
        .status()
        .ok()
        .is_some_and(|status| status.success());
    if docker_public_ok {
        let fast_external = compose(&[
            "exec",
            "-T",
            "c2-allowed",
            "sh",
            "-lc",
            &format!("RETRIES=1\n{external_check_script}"),
        ])
        .output()
        .unwrap();
        if !fast_external.status.success() {
            let iptables_output =
                dump(&["exec", "-T", "c2-allowed-net", "sh", "-lc", "iptables -S"]);
            let output_accept = iptables_output.contains("-P OUTPUT ACCEPT");
            let has_global_reject = iptables_output
                .lines()
                .filter(|line| line.starts_with("-A OUTPUT "))
                .any(|line| {
                    (line.contains(" -j DROP") || line.contains(" -j REJECT"))
                        && !line.contains(" -d ")
                });
            if output_accept && !has_global_reject {
                eprintln!(
                    "skipping external egress assertion: OUTPUT is ACCEPT and no global \
                     drop/reject rules"
                );
            } else {
                let external = compose(&[
                    "exec",
                    "-T",
                    "c2-allowed",
                    "sh",
                    "-lc",
                    &format!("RETRIES=5\n{external_check_script}"),
                ])
                .output()
                .unwrap();
                if !external.status.success() {
                    let debug = format!(
                        "external stdout:\n{}\nexternal stderr:\n{}\n\nallowed sidecar:\n{}",
                        String::from_utf8_lossy(&external.stdout),
                        String::from_utf8_lossy(&external.stderr),
                        dump(&[
                            "exec",
                            "-T",
                            "c2-allowed-net",
                            "sh",
                            "-lc",
                            "ip -4 addr && iptables -S && cat /etc/resolv.conf"
                        ])
                    );
                    panic!("allowed client could not reach example.com\n{debug}");
                }
            }
        }
    } else {
        eprintln!("skipping external egress check: docker cannot reach public IP");
    }

    // Denied should fail when calling server sidecar DNS name directly.
    let denied = compose(&[
        "exec",
        "-T",
        "c3-denied",
        "sh",
        "-lc",
        &format!(r#"wget -qO- --timeout=2 --tries=1 "http://{server_host}:8080/" 2>/dev/null"#),
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
    let sidecar_platform = build_sidecar_image();
    let helper_platform = build_helper_image();
    let platform = require_same_platform(&[
        (SIDECAR_IMAGE, sidecar_platform),
        (HELPER_IMAGE, helper_platform),
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
        .emit(&output.scenario)
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
