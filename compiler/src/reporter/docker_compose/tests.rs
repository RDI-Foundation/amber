use std::{
    collections::BTreeMap,
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::Arc,
};

use amber_manifest::{Manifest, ManifestDigest, ManifestRef, ProvideDecl, SlotDecl};
use amber_scenario::{
    BindingEdge, Component, ComponentId, Moniker, ProvideRef, Scenario, ScenarioExport, SlotRef,
};
use serde_json::{Value, json};
use url::Url;

use super::{super::Reporter as _, DockerComposeReporter, HELPER_IMAGE, SIDECAR_IMAGE};

fn digest(byte: u8) -> ManifestDigest {
    ManifestDigest::new([byte; 32])
}

fn moniker(path: &str) -> Moniker {
    Moniker::from(Arc::from(path))
}

fn compile_output(scenario: Scenario) -> crate::CompileOutput {
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

fn error_contains(err: &crate::Error, needle: &str) -> bool {
    match err {
        crate::Error::Linker(crate::linker::Error::Multiple { errors, .. }) => {
            errors.iter().any(|err| err.to_string().contains(needle))
        }
        crate::Error::Linker(err) => err.to_string().contains(needle),
        other => other.to_string().contains(needle),
    }
}

const DEFAULT_MESH_SUBNET: &str = "10.88.0.0/16";

#[derive(Debug)]
struct EnvVarGuard {
    key: &'static str,
    prev: Option<String>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var(key).ok();
        // SAFETY: These ignored e2e tests are expected to run in isolation; we set and restore
        // the process env var only around compose generation.
        unsafe {
            std::env::set_var(key, value);
        }
        Self { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(prev) = &self.prev {
            // SAFETY: See EnvVarGuard::set.
            unsafe {
                std::env::set_var(self.key, prev);
            }
        } else {
            // SAFETY: See EnvVarGuard::set.
            unsafe {
                std::env::remove_var(self.key);
            }
        }
    }
}

fn parse_ipv4_cidr(cidr: &str) -> Option<(u32, u8)> {
    let (addr, prefix) = cidr.split_once('/')?;
    let ip: Ipv4Addr = addr.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    if prefix > 32 {
        return None;
    }
    Some((u32::from(ip), prefix))
}

fn cidr_range(cidr: (u32, u8)) -> (u32, u32) {
    let (addr, prefix) = cidr;
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = addr & mask;
    let broadcast = network | !mask;
    (network, broadcast)
}

fn cidr_overlaps(a: (u32, u8), b: (u32, u8)) -> bool {
    let (a_start, a_end) = cidr_range(a);
    let (b_start, b_end) = cidr_range(b);
    a_start <= b_end && b_start <= a_end
}

fn docker_used_subnets() -> Vec<(u32, u8)> {
    let output = std::process::Command::new("docker")
        .args(["network", "ls", "-q"])
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let ids = String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .map(|s| s.to_string())
        .collect::<Vec<_>>();
    if ids.is_empty() {
        return Vec::new();
    }

    let output = std::process::Command::new("docker")
        .arg("network")
        .arg("inspect")
        .args(&ids)
        .output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
        return Vec::new();
    };

    let mut subnets = Vec::new();
    let Some(networks) = value.as_array() else {
        return subnets;
    };
    for network in networks {
        let Some(configs) = network
            .get("IPAM")
            .and_then(|ipam| ipam.get("Config"))
            .and_then(|cfg| cfg.as_array())
        else {
            continue;
        };
        for cfg in configs {
            let Some(subnet) = cfg.get("Subnet").and_then(|s| s.as_str()) else {
                continue;
            };
            if let Some(parsed) = parse_ipv4_cidr(subnet) {
                subnets.push(parsed);
            }
        }
    }

    subnets
}

fn choose_mesh_subnet() -> String {
    let candidates = [
        "10.200.0.0/16",
        "10.201.0.0/16",
        "10.202.0.0/16",
        "10.203.0.0/16",
        "10.204.0.0/16",
        "10.205.0.0/16",
        "10.206.0.0/16",
        "10.207.0.0/16",
        "10.208.0.0/16",
        "10.209.0.0/16",
        "10.210.0.0/16",
        "10.211.0.0/16",
        "10.212.0.0/16",
        "10.213.0.0/16",
        "10.214.0.0/16",
        "10.215.0.0/16",
        "172.30.0.0/16",
        "172.31.0.0/16",
    ];

    let used = docker_used_subnets();
    for candidate in candidates {
        let Some(parsed) = parse_ipv4_cidr(candidate) else {
            continue;
        };
        let overlaps = used.iter().any(|used| cidr_overlaps(*used, parsed));
        if !overlaps {
            return candidate.to_string();
        }
    }

    DEFAULT_MESH_SUBNET.to_string()
}

fn mesh_base_from_env() -> Ipv4Addr {
    let cidr =
        std::env::var("AMBER_MESH_SUBNET").unwrap_or_else(|_| DEFAULT_MESH_SUBNET.to_string());
    let base = cidr
        .split_once('/')
        .map(|(addr, _)| addr)
        .unwrap_or(cidr.as_str());
    base.parse().unwrap_or_else(|_| Ipv4Addr::new(10, 88, 0, 0))
}

fn sidecar_ipv4(base: Ipv4Addr, id: u32) -> Ipv4Addr {
    let offset = id + 10;
    let third = (offset / 256) as u8;
    let fourth = (offset % 256) as u8;
    let [first, second, ..] = base.octets();
    Ipv4Addr::new(first, second, third, fourth)
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
        .env("DOCKER_DEFAULT_PLATFORM", "linux/amd64")
        .arg("buildx")
        .arg("build")
        .arg("--platform")
        .arg("linux/amd64")
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
        &root.join("docker/amber-compose-helper/Dockerfile"),
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
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        children: vec![ComponentId(2), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        children: Vec::new(),
    };

    let client = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(2),
        config: None,
        program: Some(client_program),
        slots: BTreeMap::from([("api".to_string(), slot_http)]),
        provides: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(client)],
        bindings: vec![BindingEdge {
            from: ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            },
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

    // Service names should be injective and include sidecars.
    assert!(yaml.contains("c1-server-net:"), "{yaml}");
    assert!(yaml.contains("c1-server:"), "{yaml}");
    assert!(yaml.contains("c2-client-net:"), "{yaml}");
    assert!(yaml.contains("c2-client:"), "{yaml}");

    // Program uses sidecar netns.
    assert!(
        yaml.contains(r#"network_mode: "service:c2-client-net""#),
        "{yaml}"
    );

    // Sidecar image should be pulled from GHCR.
    assert!(
        yaml.contains(&format!(r#"image: "{SIDECAR_IMAGE}""#)),
        "{yaml}"
    );

    // Static IP assignment should be stable: c1 => base.0.11, c2 => base.0.12
    let base = mesh_base_from_env();
    let server_ip = sidecar_ipv4(base, 1);
    let client_ip = sidecar_ipv4(base, 2);
    assert!(
        yaml.contains(&format!("ipv4_address: {server_ip}")),
        "{yaml}"
    );
    assert!(
        yaml.contains(&format!("ipv4_address: {client_ip}")),
        "{yaml}"
    );

    // Server sidecar should allow inbound from client on 8080.
    assert!(
        yaml.contains(&format!(
            "iptables -w -A INPUT -p tcp -s {client_ip} --dport 8080 -j ACCEPT"
        )),
        "{yaml}"
    );

    // Slot URL should be rendered with local proxy port base (20000).
    assert!(yaml.contains(r#"URL: "http://127.0.0.1:20000""#), "{yaml}");
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
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        children: vec![ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
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

    assert!(yaml.contains("x-amber:"), "{yaml}");
    assert!(yaml.contains(r#"exports:"#), "{yaml}");
    assert!(yaml.contains(r#""public":"#), "{yaml}");
    assert!(yaml.contains(r#"published_host: "127.0.0.1""#), "{yaml}");
    assert!(yaml.contains("published_port: 18000"), "{yaml}");
    assert!(yaml.contains("target_port: 8080"), "{yaml}");
    assert!(yaml.contains(r#"component: "/server""#), "{yaml}");
    assert!(yaml.contains(r#"provide: "api""#), "{yaml}");
    assert!(yaml.contains(r#"endpoint: "api""#), "{yaml}");
    assert!(yaml.contains("127.0.0.1:18000:8080"), "{yaml}");
    assert!(yaml.contains(r#"amber.exports: "{\"public\""#), "{yaml}");
    assert!(yaml.contains(r#"\"published_port\":18000"#), "{yaml}");
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
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        children: vec![ComponentId(2), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([
            ("v1".to_string(), provide_v1),
            ("admin".to_string(), provide_admin),
        ]),
        children: Vec::new(),
    };

    let client = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(2),
        config: None,
        program: Some(client_program),
        slots: BTreeMap::from([
            ("v1".to_string(), slot_http.clone()),
            ("admin".to_string(), slot_http),
        ]),
        provides: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(client)],
        bindings: vec![
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "v1".to_string(),
                },
                to: SlotRef {
                    component: ComponentId(2),
                    name: "v1".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                from: ProvideRef {
                    component: ComponentId(1),
                    name: "admin".to_string(),
                },
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
    let err = DockerComposeReporter.emit(&output).unwrap_err();
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
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_ocap_blocks_unbound_callers() {
    use std::{fs, process::Command};

    use tempfile::tempdir;

    struct ComposeGuard {
        project: std::path::PathBuf,
        platform: String,
    }

    impl ComposeGuard {
        fn new(project: &std::path::Path, platform: &str) -> Self {
            Self {
                project: project.to_path_buf(),
                platform: platform.to_string(),
            }
        }
    }

    impl Drop for ComposeGuard {
        fn drop(&mut self) {
            let _ = Command::new("docker")
                .current_dir(&self.project)
                .env("DOCKER_DEFAULT_PLATFORM", &self.platform)
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
    // - denied client has no binding and tries to call server directly by sidecar IP:8080 (should fail)
    //
    // NOTE: This test builds the sidecar image locally and uses its platform.
    let dir = tempdir().unwrap();
    let project = dir.path();
    let platform = build_sidecar_image();
    ensure_image_platform("busybox:1.36.1", &platform);
    ensure_image_platform("alpine:3.20", &platform);
    let _compose_guard = ComposeGuard::new(project, &platform);
    let mesh_subnet = choose_mesh_subnet();
    let _mesh_guard = EnvVarGuard::set("AMBER_MESH_SUBNET", &mesh_subnet);
    let server_ip = sidecar_ipv4(mesh_base_from_env(), 1);

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
        program: None,
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        children: vec![ComponentId(2), ComponentId(3), ComponentId(1)],
    };

    let server = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/server"),
        digest: digest(1),
        config: None,
        program: Some(server_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("api".to_string(), provide_http)]),
        children: Vec::new(),
    };

    let allowed = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/allowed"),
        digest: digest(2),
        config: None,
        program: Some(sleeper_program(json!({ "URL": "${slots.api.url}" }))),
        slots: BTreeMap::from([("api".to_string(), slot_http.clone())]),
        provides: BTreeMap::new(),
        children: Vec::new(),
    };

    let denied = Component {
        id: ComponentId(3),
        parent: Some(ComponentId(0)),
        moniker: moniker("/denied"),
        digest: digest(3),
        config: None,
        program: Some(sleeper_program(json!({}))),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(allowed), Some(denied)],
        bindings: vec![BindingEdge {
            from: ProvideRef {
                component: ComponentId(1),
                name: "api".to_string(),
            },
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
        cmd.current_dir(project)
            .env("DOCKER_DEFAULT_PLATFORM", &platform)
            .arg("compose")
            .args(args);
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
        r#"i=0; while [ $i -lt 20 ]; do if wget -qO- --timeout=2 --tries=1 "$URL" | grep -q hello; then exit 0; fi; i=$((i+1)); sleep 1; done; exit 1"#,
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

    // Denied should fail when calling server sidecar IP directly.
    let denied = compose(&[
        "exec",
        "-T",
        "c3-denied",
        "sh",
        "-lc",
        &format!(r#"wget -qO- --timeout=2 --tries=1 "http://{server_ip}:8080/""#),
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
    let mesh_subnet = choose_mesh_subnet();
    let _mesh_guard = EnvVarGuard::set("AMBER_MESH_SUBNET", &mesh_subnet);

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
        platform: String,
        envs: Vec<(String, String)>,
    }

    impl ComposeGuard {
        fn new(project: &std::path::Path, platform: &str, envs: &[(&str, &str)]) -> Self {
            Self {
                project: project.to_path_buf(),
                platform: platform.to_string(),
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
            cmd.current_dir(&self.project)
                .env("DOCKER_DEFAULT_PLATFORM", &self.platform)
                .arg("compose")
                .args([
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
    let _compose_guard = ComposeGuard::new(project, &platform, &valid_env);

    let compose = |envs: &[(&str, &str)], args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project)
            .env("DOCKER_DEFAULT_PLATFORM", &platform)
            .arg("compose")
            .args(args);
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
        if let Ok(output) = output {
            if output.status.success() {
                let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if !text.is_empty() {
                    rendered = Some(text);
                    break;
                }
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
            .env("DOCKER_DEFAULT_PLATFORM", &platform)
            .arg("inspect")
            .arg("-f")
            .arg("{{.State.Status}} {{.State.ExitCode}}")
            .arg(&container_id)
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&inspect.stdout).trim().to_string();
        if let Some((status, code)) = text.split_once(' ') {
            if status == "exited" {
                let code = code.parse::<i32>().unwrap_or(0);
                exit = Some((status.to_string(), code));
                break;
            }
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
