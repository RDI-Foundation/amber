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

use amber_images::{AMBER_DOCKER_GATEWAY, AMBER_HELPER, AMBER_ROUTER, AMBER_SIDECAR};
use amber_manifest::{FrameworkCapabilityName, ManifestDigest, ManifestRef, ProvideDecl, SlotDecl};
use amber_resolver::Resolver;
use amber_scenario::{
    BindingEdge, BindingFrom, Component, ComponentId, Moniker, ProvideRef, Scenario,
    ScenarioExport, SlotRef,
};
use base64::Engine as _;
use serde_json::json;
use url::Url;

use super::DockerComposeReporter;
use crate::{CompileOptions, Compiler, DigestStore, OptimizeOptions, reporter::Reporter as _};

const SIDECAR_IMAGE: &str = AMBER_SIDECAR.reference;
const HELPER_IMAGE: &str = AMBER_HELPER.reference;
const ROUTER_IMAGE: &str = AMBER_ROUTER.reference;
const DOCKER_GATEWAY_IMAGE: &str = AMBER_DOCKER_GATEWAY.reference;

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

fn use_prebuilt_images() -> bool {
    std::env::var("AMBER_TEST_USE_PREBUILT_IMAGES").is_ok()
}

fn prebuilt_image_platform(tag: &str) -> String {
    image_platform_opt(tag).unwrap_or_else(|| {
        panic!(
            "AMBER_TEST_USE_PREBUILT_IMAGES is set but {tag} is not available locally. Ensure the \
             image is pulled and tagged before running tests."
        )
    })
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
    if use_prebuilt_images() {
        return prebuilt_image_platform(tag);
    }
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

fn build_docker_gateway_image() -> String {
    let root = workspace_root();
    build_docker_image(
        DOCKER_GATEWAY_IMAGE,
        &root.join("docker/amber-docker-gateway/Dockerfile"),
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
        "entrypoint": ["sh", "-lc", "echo $API_URL"]
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
fn compose_renders_runtime_program_image_from_root_config() {
    let schema = json!({
        "type": "object",
        "properties": {
            "image": { "type": "string" }
        },
        "required": ["image"],
        "additionalProperties": false
    });
    let program = serde_json::from_value(json!({
        "image": "${config.image}",
        "entrypoint": ["run"]
    }))
    .unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: Some(schema),
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
        .find(|svc| svc.image.contains("AMBER_CONFIG_IMAGE"))
        .expect("program service should use runtime root config for image");
    assert_eq!(service.image, "${AMBER_CONFIG_IMAGE?missing config.image}");
    assert!(!yaml.contains("AMBER_TEMPLATE_SPEC_B64"), "{yaml}");
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
fn compose_mounts_use_helper_direct_mode() {
    let program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["app"],
        "mounts": [
            { "path": "/run/app.txt", "from": "config.app" }
        ]
    }))
    .unwrap();

    let config_schema = json!({
        "type": "object",
        "properties": {
            "app": { "type": "string" }
        },
        "required": ["app"]
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
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(1)],
    };

    let child = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/child"),
        digest: digest(1),
        config: Some(json!({ "app": "static" })),
        config_schema: Some(config_schema),
        program: Some(program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    assert!(
        compose.services.contains_key("amber-init"),
        "helper init service missing"
    );
    assert!(yaml.contains("AMBER_DIRECT_ENTRYPOINT_B64"), "{yaml}");
    assert!(yaml.contains("AMBER_MOUNT_SPEC_B64"), "{yaml}");
    assert!(!yaml.contains("AMBER_ROOT_CONFIG_SCHEMA_B64"), "{yaml}");
}

#[test]
fn compose_runtime_mount_requires_config_payload() {
    let program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["app"],
        "mounts": [
            { "path": "/run/app.txt", "from": "config.app" }
        ]
    }))
    .unwrap();

    let config_schema = json!({
        "type": "object",
        "properties": {
            "app": { "type": "string" }
        },
        "required": ["app"]
    });

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: Some(config_schema.clone()),
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(1)],
    };

    let child = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/child"),
        digest: digest(1),
        config: Some(json!({ "app": "${config.app}" })),
        config_schema: Some(config_schema),
        program: Some(program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");

    assert!(yaml.contains("AMBER_DIRECT_ENTRYPOINT_B64"), "{yaml}");
    assert!(yaml.contains("AMBER_MOUNT_SPEC_B64"), "{yaml}");
    assert!(yaml.contains("AMBER_ROOT_CONFIG_SCHEMA_B64"), "{yaml}");
    assert!(
        yaml.contains("AMBER_COMPONENT_CONFIG_TEMPLATE_B64"),
        "{yaml}"
    );
}

#[test]
fn compose_scopes_root_config_env_and_schema() {
    let program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["app"],
        "mounts": [
            { "path": "/run/app.json", "from": "config.app" }
        ]
    }))
    .unwrap();

    let root_schema = json!({
        "type": "object",
        "properties": {
            "app": {
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "log_level": { "type": "string" }
                }
            },
            "token": { "type": "string", "secret": true }
        }
    });

    let component_schema = json!({
        "type": "object",
        "properties": {
            "app": {
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "log_level": { "type": "string" }
                }
            },
            "token": { "type": "string" }
        }
    });

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: Some(root_schema),
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(1)],
    };

    let child = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/child"),
        digest: digest(1),
        config: Some(json!({ "app": "${config.app}", "token": "${config.token}" })),
        config_schema: Some(component_schema),
        program: Some(program),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(child)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);
    let child_service = service(&compose, "c1-child");

    assert!(
        env_value(child_service, "AMBER_CONFIG_APP__NAME").is_some(),
        "missing AMBER_CONFIG_APP__NAME"
    );
    assert!(
        env_value(child_service, "AMBER_CONFIG_APP__LOG_LEVEL").is_some(),
        "missing AMBER_CONFIG_APP__LOG_LEVEL"
    );
    assert!(
        env_value(child_service, "AMBER_CONFIG_TOKEN").is_none(),
        "unexpected AMBER_CONFIG_TOKEN exposure"
    );

    let root_schema_b64 =
        env_value(child_service, "AMBER_ROOT_CONFIG_SCHEMA_B64").expect("root schema env var");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(root_schema_b64.as_bytes())
        .expect("decode root schema");
    let root_schema: serde_json::Value =
        serde_json::from_slice(&decoded).expect("parse root schema");
    assert!(
        root_schema["properties"].get("app").is_some(),
        "pruned schema missing app"
    );
    assert!(
        root_schema["properties"].get("token").is_none(),
        "pruned schema should not include token"
    );
}

#[test]
fn compose_scopes_root_component_payloads() {
    let program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["app"],
        "env": {
            "APP_NAME": "${config.app.name}"
        }
    }))
    .unwrap();

    let root_schema = json!({
        "type": "object",
        "properties": {
            "app": {
                "type": "object",
                "properties": {
                    "name": { "type": "string" },
                    "log_level": { "type": "string" }
                }
            },
            "token": { "type": "string", "secret": true }
        }
    });

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: Some(root_schema),
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
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);
    let program_service = compose
        .services
        .values()
        .find(|svc| svc.image == "alpine:3.20")
        .expect("program service missing");

    assert!(
        env_value(program_service, "AMBER_CONFIG_APP__NAME").is_some(),
        "missing AMBER_CONFIG_APP__NAME"
    );
    assert!(
        env_value(program_service, "AMBER_CONFIG_APP__LOG_LEVEL").is_none(),
        "unexpected AMBER_CONFIG_APP__LOG_LEVEL exposure"
    );
    assert!(
        env_value(program_service, "AMBER_CONFIG_TOKEN").is_none(),
        "unexpected AMBER_CONFIG_TOKEN exposure"
    );

    let root_schema_b64 =
        env_value(program_service, "AMBER_ROOT_CONFIG_SCHEMA_B64").expect("root schema env var");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(root_schema_b64.as_bytes())
        .expect("decode root schema");
    let root_schema: serde_json::Value =
        serde_json::from_slice(&decoded).expect("parse root schema");
    assert!(
        root_schema["properties"]["app"]["properties"]
            .get("name")
            .is_some(),
        "pruned root schema missing app.name"
    );
    assert!(
        root_schema["properties"]["app"]["properties"]
            .get("log_level")
            .is_none(),
        "pruned root schema should not include app.log_level"
    );
    assert!(
        root_schema["properties"].get("token").is_none(),
        "pruned root schema should not include token"
    );

    let component_schema_b64 = env_value(program_service, "AMBER_COMPONENT_CONFIG_SCHEMA_B64")
        .expect("component schema env var");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(component_schema_b64.as_bytes())
        .expect("decode component schema");
    let component_schema: serde_json::Value =
        serde_json::from_slice(&decoded).expect("parse component schema");
    assert!(
        component_schema["properties"]["app"]["properties"]
            .get("name")
            .is_some(),
        "pruned component schema missing app.name"
    );
    assert!(
        component_schema["properties"]["app"]["properties"]
            .get("log_level")
            .is_none(),
        "pruned component schema should not include app.log_level"
    );
    assert!(
        component_schema["properties"].get("token").is_none(),
        "pruned component schema should not include token"
    );

    let component_template_b64 = env_value(program_service, "AMBER_COMPONENT_CONFIG_TEMPLATE_B64")
        .expect("component template env var");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(component_template_b64.as_bytes())
        .expect("decode component template");
    let template: serde_json::Value =
        serde_json::from_slice(&decoded).expect("parse component template");
    let template_json = template.to_string();
    assert!(
        !template_json.contains("log_level"),
        "pruned component template should not include app.log_level"
    );
    assert!(
        !template_json.contains("token"),
        "pruned component template should not include token"
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
fn compose_external_slots_and_exports_work_together_with_and_without_dce() {
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let root_path = dir.path().join("root.json5");
    let green_path = dir.path().join("green.json5");

    fs::write(
        &root_path,
        r##"
        {
          manifest_version: "0.1.0",
          slots: {
            agent: { kind: "a2a" },
          },
          components: {
            green: "green.json5",
          },
          bindings: [
            { to: "#green.agent", from: "self.agent", weak: true },
          ],
          exports: {
            green: "#green.a2a",
          },
        }
        "##,
    )
    .unwrap();

    fs::write(
        &green_path,
        r##"
        {
          manifest_version: "0.1.0",
          program: {
            image: "alpine:3.20",
            entrypoint: ["sleep", "infinity"],
            env: {
              AGENT_URL: "${slots.agent.url}",
            },
            network: {
              endpoints: [{ name: "a2a", port: 9001 }],
            },
          },
          slots: {
            agent: { kind: "a2a" },
          },
          provides: {
            a2a: { kind: "a2a", endpoint: "a2a" },
          },
          exports: {
            a2a: "a2a",
          },
        }
        "##,
    )
    .unwrap();

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let rt = tokio::runtime::Runtime::new().unwrap();

    for dce in [true, false] {
        let opts = CompileOptions {
            optimize: OptimizeOptions { dce },
            ..CompileOptions::default()
        };
        let output = rt
            .block_on(compiler.compile(
                ManifestRef::from_url(Url::from_file_path(&root_path).unwrap()),
                opts,
            ))
            .expect("compile ok");

        let yaml = DockerComposeReporter
            .emit(&output.scenario)
            .expect("compose render ok");
        let b64 = extract_compose_env_value(&yaml, "AMBER_ROUTER_CONFIG_B64")
            .expect("router config env var");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .expect("decode router config");
        let config: serde_json::Value =
            serde_json::from_slice(&decoded).expect("parse router config");

        assert_eq!(config["external_slots"][0]["name"], "agent");
        assert_eq!(config["exports"][0]["name"], "green");
    }
}

#[test]
fn compose_ignores_unused_config_binding_paths_under_dce() {
    let slot_http: SlotDecl = serde_json::from_value(json!({ "kind": "http" })).unwrap();
    let provide_out: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "out" })).unwrap();
    let provide_up: ProvideDecl =
        serde_json::from_value(json!({ "kind": "http", "endpoint": "up" })).unwrap();
    let consumer_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["consumer"],
        "network": {
            "endpoints": [{ "name": "out", "port": 9001, "protocol": "http" }]
        }
    }))
    .unwrap();
    let provider_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "entrypoint": ["provider"],
        "network": {
            "endpoints": [{ "name": "up", "port": 9002, "protocol": "http" }]
        }
    }))
    .unwrap();

    let root = Component {
        id: ComponentId(0),
        parent: None,
        moniker: moniker("/"),
        digest: digest(0),
        config: None,
        config_schema: None,
        program: None,
        slots: BTreeMap::from([("up".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::from([(
            "upstream".to_string(),
            SlotRef {
                component: ComponentId(0),
                name: "up".to_string(),
            },
        )]),
        metadata: None,
        children: vec![ComponentId(1), ComponentId(2)],
    };

    let consumer = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/consumer"),
        digest: digest(1),
        config: Some(json!({
            "upstream_url": "${bindings.upstream.url}"
        })),
        config_schema: None,
        program: Some(consumer_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("out".to_string(), provide_out.clone())]),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let provider = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/provider"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(provider_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("up".to_string(), provide_up)]),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(consumer), Some(provider)],
        bindings: vec![BindingEdge {
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
        }],
        exports: vec![ScenarioExport {
            name: "out".to_string(),
            capability: provide_out.decl.clone(),
            from: ProvideRef {
                component: ComponentId(1),
                name: "out".to_string(),
            },
        }],
    };

    let scenario = crate::mir::dce_only(scenario);
    assert!(
        scenario.components[2].is_none(),
        "provider should be pruned because bindings usage lives under a config path that is never \
         read by runtime"
    );

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render should not require pruned bindings");
    assert!(
        !yaml.trim().is_empty(),
        "compose render should produce non-empty output"
    );
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
        "entrypoint": ["sh", "-lc", "sleep infinity"],
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
        "entrypoint": ["sh", "-lc", "mkdir -p /www && echo export-ok > /www/index.html && httpd -f -p 8080 -h /www"],
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
        if let Ok(response) = http_get(&published_host, published_port)
            && response.contains("export-ok")
        {
            ok = true;
            break;
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
fn docker_compose_wires_framework_docker_binding_via_gateway() {
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

    let worker = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/worker"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(
            serde_json::from_value(json!({
                "image": "busybox:1.37",
                "entrypoint": ["sh", "-lc", "sleep 3600"],
                "env": {
                    "DOCKER_HOST": "${slots.docker.url}"
                }
            }))
            .unwrap(),
        ),
        slots: BTreeMap::from([(
            "docker".to_string(),
            serde_json::from_value(json!({
                "kind": "docker"
            }))
            .unwrap(),
        )]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(worker)],
        bindings: vec![BindingEdge {
            name: Some("docker".to_string()),
            from: BindingFrom::Framework(FrameworkCapabilityName::try_from("docker").unwrap()),
            to: SlotRef {
                component: ComponentId(1),
                name: "docker".to_string(),
            },
            weak: false,
        }],
        exports: Vec::new(),
    };

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    assert!(
        compose.services.contains_key("amber-docker-gateway"),
        "{yaml}"
    );
    assert_eq!(
        service(&compose, "amber-docker-gateway").image,
        DOCKER_GATEWAY_IMAGE
    );
    assert_eq!(
        env_value(service(&compose, "c1-worker"), "DOCKER_HOST").as_deref(),
        Some("tcp://127.0.0.1:20000")
    );
    let worker_sidecar_script =
        command_script(service(&compose, "c1-worker-net")).expect("worker sidecar script");
    assert!(
        worker_sidecar_script.contains("TCP:amber-docker-gateway:23750"),
        "{worker_sidecar_script}"
    );
}

#[test]
fn docker_compose_rejects_unknown_framework_bindings() {
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

    let worker = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/worker"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(
            serde_json::from_value(json!({
                "image": "busybox:1.37",
                "entrypoint": ["sh", "-lc", "sleep 3600"],
            }))
            .unwrap(),
        ),
        slots: BTreeMap::from([(
            "control".to_string(),
            serde_json::from_value(json!({
                "kind": "docker"
            }))
            .unwrap(),
        )]),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(worker)],
        bindings: vec![BindingEdge {
            name: None,
            from: BindingFrom::Framework(
                FrameworkCapabilityName::try_from("dynamic_children").unwrap(),
            ),
            to: SlotRef {
                component: ComponentId(1),
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
        message.contains("unknown framework binding"),
        "unexpected error: {message}"
    );
}

#[test]
fn docker_compose_wires_framework_mounts_via_helper_proxy() {
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

    let worker = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/worker"),
        digest: digest(1),
        config: None,
        config_schema: Some(serde_json::json!({
            "type": "object",
        })),
        program: Some(
            serde_json::from_value(json!({
                "image": "busybox:1.37",
                "entrypoint": ["sh", "-lc", "sleep 3600"],
                "mounts": [
                    { "path": "/var/run/docker.sock", "from": "framework.docker" }
                ],
            }))
            .unwrap(),
        ),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        binding_decls: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(worker)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let yaml = DockerComposeReporter
        .emit(&scenario)
        .expect("compose render ok");
    let compose = parse_compose(&yaml);

    assert!(compose.services.contains_key("amber-init"), "{yaml}");
    assert!(
        compose.services.contains_key("amber-docker-gateway"),
        "{yaml}"
    );
    let worker = service(&compose, "c1-worker");
    let proxy_spec_b64 =
        env_value(worker, "AMBER_DOCKER_MOUNT_PROXY_SPEC_B64").expect("docker mount proxy env var");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(proxy_spec_b64.as_bytes())
        .expect("decode docker mount proxy env");
    let specs: serde_json::Value = serde_json::from_slice(&decoded).expect("proxy spec json");
    assert!(
        specs
            .as_array()
            .expect("proxy specs should be array")
            .iter()
            .any(|spec| {
                spec.get("path").and_then(|value| value.as_str()) == Some("/var/run/docker.sock")
            }),
        "{specs}"
    );
    let sidecar_script =
        command_script(service(&compose, "c1-worker-net")).expect("worker sidecar script");
    assert!(
        sidecar_script.contains("TCP:amber-docker-gateway:23750"),
        "{sidecar_script}"
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
        "entrypoint": ["sh", "-lc", "mkdir -p /www && echo hello > /www/index.html && httpd -f -p 8080 -h /www"],
        "network": { "endpoints": [ { "name": "api", "port": 8080, "protocol": "http" } ] }
    }))
    .unwrap();

    let sleeper_program = |env: serde_json::Value| {
        serde_json::from_value(json!({
            "image": "alpine:3.20",
            "entrypoint": ["sh", "-lc", "sleep infinity"],
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

#[derive(Clone, Copy)]
enum FrameworkDockerBindingForm {
    Mount,
    Url,
}

impl FrameworkDockerBindingForm {
    fn slug(self) -> &'static str {
        match self {
            Self::Mount => "mount",
            Self::Url => "url",
        }
    }

    fn worker_preflight(self) -> &'static str {
        match self {
            Self::Mount => "test -S /var/run/docker.sock;",
            Self::Url => {
                "test -n \"$DOCKER_HOST\"; case \"$DOCKER_HOST\" in tcp://127.0.0.1:*) ;; *) echo \
                 \"unexpected DOCKER_HOST=$DOCKER_HOST\" >&2; exit 1;; esac;"
            }
        }
    }
}

#[derive(Clone, Copy)]
enum FrameworkDockerTeardownMode {
    ComposeRemoveOrphans,
    GatewayShutdownCleanup,
}

impl FrameworkDockerTeardownMode {
    fn slug(self) -> &'static str {
        match self {
            Self::ComposeRemoveOrphans => "remove-orphans",
            Self::GatewayShutdownCleanup => "gateway-shutdown",
        }
    }

    fn down_args(self) -> &'static [&'static str] {
        match self {
            Self::ComposeRemoveOrphans => &["down", "-v", "--remove-orphans"],
            Self::GatewayShutdownCleanup => &["down", "-v"],
        }
    }
}

fn docker_smoke_framework_docker_binding_runs_cli_and_teardown_cleanup(
    binding_form: FrameworkDockerBindingForm,
    teardown_mode: FrameworkDockerTeardownMode,
) {
    use std::{
        fs,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    use tempfile::tempdir;

    struct ComposeGuard {
        project: std::path::PathBuf,
        compose_project: String,
        created_container: String,
    }

    impl ComposeGuard {
        fn new(
            project: &std::path::Path,
            compose_project: String,
            created_container: String,
        ) -> Self {
            Self {
                project: project.to_path_buf(),
                compose_project,
                created_container,
            }
        }
    }

    impl Drop for ComposeGuard {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .current_dir(&self.project)
                .env("COMPOSE_PROJECT_NAME", &self.compose_project)
                .env("AMBER_DOCKER_SOCK", "/var/run/docker.sock")
                .arg("compose")
                .args(["down", "-v", "--remove-orphans", "--timeout", "1"])
                .status();
            let _ = Command::new("docker")
                .args(["rm", "-f", &self.created_container])
                .status();
        }
    }

    let project_dir = tempdir().expect("temp dir");
    let project = project_dir.path();
    let sidecar_platform = build_sidecar_image();
    let helper_platform = build_helper_image();
    let router_platform = build_router_image();
    let gateway_platform = build_docker_gateway_image();
    let platform = require_same_platform(&[
        (SIDECAR_IMAGE, sidecar_platform),
        (HELPER_IMAGE, helper_platform),
        (ROUTER_IMAGE, router_platform),
        (DOCKER_GATEWAY_IMAGE, gateway_platform),
    ]);
    ensure_image_platform("docker:27.3.1-cli", &platform);

    let suffix = format!(
        "{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time after epoch")
            .as_millis()
    );
    let mode = binding_form.slug();
    let created_container = format!("amber-fw-docker-{mode}-{suffix}");
    let teardown = teardown_mode.slug();
    let compose_project = format!("amber-fw-docker-{mode}-{teardown}-test-{suffix}");

    let worker_path = project.join("worker.json5");
    let root_path = project.join("root.json5");
    let runner_cmd = format!(
        "set -eu; {} for i in $(seq 1 30); do if docker version >/dev/null 2>&1; then break; fi; \
         sleep 1; done; docker version >/dev/null; docker rm -f \"${{config.container_name}}\" \
         >/dev/null 2>&1 || true; docker create --network none --name \
         \"${{config.container_name}}\" \"${{config.image_id}}\" true >/tmp/created-id; docker \
         inspect \"${{config.container_name}}\" >/tmp/inspect.json",
        binding_form.worker_preflight()
    );
    let mut worker_program = json!({
        "image": "docker:27.3.1-cli",
        "args": ["sh", "-lc", runner_cmd],
    });
    match binding_form {
        FrameworkDockerBindingForm::Mount => {
            worker_program["mounts"] = json!([
                { "path": "/var/run/docker.sock", "from": "framework.docker" }
            ]);
        }
        FrameworkDockerBindingForm::Url => {
            worker_program["env"] = json!({
                "DOCKER_HOST": "${slots.docker.url}"
            });
        }
    }
    let worker_manifest = json!({
        "manifest_version": "0.1.0",
        "experimental_features": ["docker"],
        "config_schema": {
            "type": "object",
            "properties": {
                "container_name": { "type": "string" },
                "image_id": { "type": "string" },
            },
            "required": ["container_name", "image_id"],
            "additionalProperties": false,
        },
        "program": worker_program,
        "slots": {
            "docker": { "kind": "docker" }
        }
    });
    fs::write(
        &worker_path,
        serde_json::to_vec_pretty(&worker_manifest).expect("serialize worker manifest"),
    )
    .expect("write worker manifest");

    let helper_image_id_output = Command::new("docker")
        .args(["image", "inspect", HELPER_IMAGE, "--format", "{{.Id}}"])
        .output()
        .expect("inspect helper image id");
    assert!(
        helper_image_id_output.status.success(),
        "failed to inspect helper image id\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&helper_image_id_output.stdout),
        String::from_utf8_lossy(&helper_image_id_output.stderr)
    );
    let helper_image_id = String::from_utf8_lossy(&helper_image_id_output.stdout)
        .trim()
        .to_string();
    assert!(
        !helper_image_id.is_empty(),
        "helper image id should not be empty"
    );

    let worker_url = Url::from_file_path(&worker_path)
        .expect("worker file url")
        .to_string();
    let root_manifest = json!({
        "manifest_version": "0.1.0",
        "experimental_features": ["docker"],
        "components": {
            "runner": {
                "manifest": worker_url,
                "config": {
                    "container_name": created_container.clone(),
                    "image_id": helper_image_id.clone(),
                }
            }
        },
        "bindings": [
            { "to": "#runner.docker", "from": "framework.docker" }
        ]
    });
    fs::write(
        &root_path,
        serde_json::to_vec_pretty(&root_manifest).expect("serialize root manifest"),
    )
    .expect("write root manifest");

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    let output = rt
        .block_on(compiler.compile(
            ManifestRef::from_url(Url::from_file_path(&root_path).expect("root file url")),
            CompileOptions {
                resolve: crate::ResolveOptions { max_concurrency: 8 },
                optimize: OptimizeOptions { dce: false },
            },
        ))
        .expect("compile ok");
    let yaml = DockerComposeReporter
        .emit(&output.scenario)
        .expect("compose render ok");
    assert!(yaml.contains("amber-docker-gateway"), "{yaml}");
    fs::write(project.join("docker-compose.yaml"), yaml).expect("write compose yaml");
    let _guard = ComposeGuard::new(project, compose_project.clone(), created_container.clone());

    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project)
            .env("COMPOSE_PROJECT_NAME", &compose_project)
            .env("AMBER_DOCKER_SOCK", "/var/run/docker.sock")
            .arg("compose")
            .args(args);
        cmd
    };

    let up = compose(&["up", "-d"]).output().expect("compose up");
    assert!(
        up.status.success(),
        "docker compose up failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&up.stdout),
        String::from_utf8_lossy(&up.stderr)
    );

    let runner_container = format!("{compose_project}-c1-runner-1");
    let wait = Command::new("docker")
        .args(["wait", &runner_container])
        .output()
        .expect("docker wait runner");
    assert!(
        wait.status.success(),
        "docker wait failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&wait.stdout),
        String::from_utf8_lossy(&wait.stderr)
    );
    let exit_code = String::from_utf8_lossy(&wait.stdout).trim().to_string();
    if exit_code != "0" {
        let runner_logs = Command::new("docker")
            .args(["logs", &runner_container])
            .output()
            .expect("runner logs");
        let runner_sidecar = format!("{compose_project}-c1-runner-net-1");
        let runner_sidecar_logs = Command::new("docker")
            .args(["logs", &runner_sidecar])
            .output()
            .expect("runner sidecar logs");
        let gateway_container = format!("{compose_project}-amber-docker-gateway-1");
        let gateway_logs = Command::new("docker")
            .args(["logs", &gateway_container])
            .output()
            .expect("gateway logs");
        panic!(
            "runner exited with non-zero status ({exit_code})\nwait stdout:\n{}\nwait \
             stderr:\n{}\nrunner logs stdout:\n{}\nrunner logs stderr:\n{}\nsidecar logs \
             stdout:\n{}\nsidecar logs stderr:\n{}\ngateway logs stdout:\n{}\ngateway logs \
             stderr:\n{}",
            String::from_utf8_lossy(&wait.stdout),
            String::from_utf8_lossy(&wait.stderr),
            String::from_utf8_lossy(&runner_logs.stdout),
            String::from_utf8_lossy(&runner_logs.stderr),
            String::from_utf8_lossy(&runner_sidecar_logs.stdout),
            String::from_utf8_lossy(&runner_sidecar_logs.stderr),
            String::from_utf8_lossy(&gateway_logs.stdout),
            String::from_utf8_lossy(&gateway_logs.stderr),
        );
    }

    let inspect_labels = Command::new("docker")
        .args([
            "inspect",
            &created_container,
            "--format",
            "{{ index .Config.Labels \"com.rdi.amber.component\" }}|{{ index .Config.Labels \
             \"com.docker.compose.project\" }}|{{ index .Config.Labels \
             \"com.docker.compose.service\" }}|{{ index .Config.Labels \
             \"com.docker.compose.config-hash\" }}",
        ])
        .output()
        .expect("inspect created container");
    assert!(
        inspect_labels.status.success(),
        "expected created container to exist\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&inspect_labels.stdout),
        String::from_utf8_lossy(&inspect_labels.stderr)
    );
    let labels = String::from_utf8_lossy(&inspect_labels.stdout);
    assert!(
        labels.contains("/runner|"),
        "unexpected component label: {labels}"
    );
    assert!(
        labels.contains(&compose_project),
        "unexpected compose project label: {labels}"
    );
    let parts: Vec<&str> = labels.trim().split('|').collect();
    assert_eq!(parts.len(), 4, "unexpected labels format: {labels}");
    assert_eq!(
        parts[2], "c1-runner",
        "unexpected compose service label: {labels}"
    );
    assert!(
        !parts[3].is_empty(),
        "compose config-hash label should be present: {labels}"
    );

    let down = compose(teardown_mode.down_args())
        .output()
        .expect("compose down");
    assert!(
        down.status.success(),
        "docker compose down failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&down.stdout),
        String::from_utf8_lossy(&down.stderr)
    );

    let inspect_after_down = Command::new("docker")
        .args(["inspect", &created_container])
        .output()
        .expect("inspect after down");
    let cleanup_reason = match teardown_mode {
        FrameworkDockerTeardownMode::ComposeRemoveOrphans => "docker compose down --remove-orphans",
        FrameworkDockerTeardownMode::GatewayShutdownCleanup => {
            "docker gateway shutdown cleanup during docker compose down"
        }
    };
    assert!(
        !inspect_after_down.status.success(),
        "container created through framework.docker was not removed by {cleanup_reason}"
    );
}

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_framework_docker_mount_runs_cli_and_remove_orphans() {
    docker_smoke_framework_docker_binding_runs_cli_and_teardown_cleanup(
        FrameworkDockerBindingForm::Mount,
        FrameworkDockerTeardownMode::ComposeRemoveOrphans,
    );
}

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_framework_docker_url_runs_cli_and_remove_orphans() {
    docker_smoke_framework_docker_binding_runs_cli_and_teardown_cleanup(
        FrameworkDockerBindingForm::Url,
        FrameworkDockerTeardownMode::ComposeRemoveOrphans,
    );
}

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_framework_docker_gateway_shutdown_cleans_created_resources() {
    docker_smoke_framework_docker_binding_runs_cli_and_teardown_cleanup(
        FrameworkDockerBindingForm::Mount,
        FrameworkDockerTeardownMode::GatewayShutdownCleanup,
    );
}

#[test]
fn docker_compose_flattens_routing_components_with_and_without_dce() {
    use tempfile::tempdir;

    let dir = tempdir().unwrap();
    let root_path = dir.path().join("root.json5");
    let green_path = dir.path().join("green.json5");
    let green_program_path = dir.path().join("green_program.json5");
    let agent_path = dir.path().join("agent.json5");

    fs::write(
        &root_path,
        r##"
        {
          manifest_version: "0.1.0",
          components: {
            green: "green.json5",
            agent: "agent.json5",
          },
          bindings: [
            { name: "agent", to: "#green.agent", from: "#agent.a2a" },
          ],
          exports: {
            app: "#green.app",
          },
        }
        "##,
    )
    .unwrap();

    fs::write(
        &green_path,
        r##"
        {
          manifest_version: "0.1.0",
          components: {
            program: "green_program.json5",
          },
          slots: {
            agent: { kind: "a2a" },
          },
          bindings: [
            { name: "agent", to: "#program.agent", from: "self.agent" },
          ],
          exports: {
            app: "#program.app",
          },
        }
        "##,
    )
    .unwrap();

    fs::write(
        &green_program_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "alpine:3.20",
            entrypoint: ["sleep", "infinity"],
            env: {
              AGENT_URL: "${bindings.agent.url}",
            },
            network: {
              endpoints: [{ name: "app", port: 8080 }],
            },
          },
          slots: {
            agent: { kind: "a2a" },
          },
          provides: {
            app: { kind: "http", endpoint: "app" },
          },
          exports: {
            app: "app",
          },
        }
        "#,
    )
    .unwrap();

    fs::write(
        &agent_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "alpine:3.20",
            entrypoint: ["sleep", "infinity"],
            network: {
              endpoints: [{ name: "a2a", port: 9000 }],
            },
          },
          provides: {
            a2a: { kind: "a2a", endpoint: "a2a" },
          },
          exports: {
            a2a: "a2a",
          },
        }
        "#,
    )
    .unwrap();

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let rt = tokio::runtime::Runtime::new().unwrap();

    let mut agent_urls = Vec::new();
    for dce in [true, false] {
        let opts = CompileOptions {
            optimize: OptimizeOptions { dce },
            ..CompileOptions::default()
        };
        let output = rt
            .block_on(compiler.compile(
                ManifestRef::from_url(Url::from_file_path(&root_path).unwrap()),
                opts,
            ))
            .expect("compile ok");

        let yaml = DockerComposeReporter
            .emit(&output.scenario)
            .expect("compose render ok");
        let compose = parse_compose(&yaml);
        let agent_url = compose
            .services
            .values()
            .find_map(|service| env_value(service, "AGENT_URL"))
            .expect("AGENT_URL env missing");
        assert!(
            agent_url.starts_with("http://127.0.0.1:"),
            "AGENT_URL did not resolve to a local proxy URL: {agent_url}"
        );
        agent_urls.push(agent_url);
    }
    assert_eq!(
        agent_urls[0], agent_urls[1],
        "DCE should not change resolved binding URLs"
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
