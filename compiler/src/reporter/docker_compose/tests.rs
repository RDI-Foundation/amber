use std::{collections::BTreeMap, sync::Arc};

use amber_manifest::{ManifestDigest, SlotDecl};
use amber_scenario::{BindingEdge, Component, ComponentId, Moniker, ProvideRef, Scenario, SlotRef};
use serde_json::json;

use super::render_docker_compose;

fn digest(byte: u8) -> ManifestDigest {
    ManifestDigest::new([byte; 32])
}

fn moniker(path: &str) -> Moniker {
    Moniker::from(Arc::from(path))
}

#[test]
fn compose_emits_sidecars_and_programs_and_slot_urls() {
    let server_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "args": [],
        "env": {},
        "network": {
            "endpoints": [
                { "name": "api", "port": 8080, "protocol": "http", "path": "/" }
            ]
        }
    }))
    .unwrap();

    let client_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "args": [],
        "env": {
            "URL": "${slots.api.url}"
        }
    }))
    .unwrap();

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

    let yaml = render_docker_compose(&scenario).expect("compose render ok");

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

    // Static IP assignment should be stable: c1 => 10.88.0.11, c2 => 10.88.0.12
    assert!(yaml.contains("ipv4_address: 10.88.0.11"), "{yaml}");
    assert!(yaml.contains("ipv4_address: 10.88.0.12"), "{yaml}");

    // Server sidecar should allow inbound from client on 8080.
    assert!(
        yaml.contains("iptables -w -A INPUT -p tcp -s 10.88.0.12 --dport 8080 -j ACCEPT"),
        "{yaml}"
    );

    // Slot URL should be rendered with local proxy port base (20000) + path.
    assert!(yaml.contains(r#"URL: "http://127.0.0.1:20000/""#), "{yaml}");
}

#[test]
fn errors_on_shared_port_with_different_paths() {
    let server_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
        "network": {
            "endpoints": [
                { "name": "a", "port": 80, "protocol": "http", "path": "/v1" },
                { "name": "b", "port": 80, "protocol": "http", "path": "/admin" }
            ]
        }
    }))
    .unwrap();

    let client_program = serde_json::from_value(json!({
        "image": "alpine:3.20",
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

    let err = render_docker_compose(&scenario).unwrap_err();
    assert!(
        err.contains("Cannot enforce separate capabilities"),
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
    // - denied client has no binding and tries to call server directly by sidecar IP:8080 (should fail)
    //
    // NOTE: This test writes a temp compose project including a sidecar Dockerfile.
    let dir = tempdir().unwrap();
    let project = dir.path();
    let _compose_guard = ComposeGuard::new(project);

    // Sidecar build context expected by reporter.
    fs::create_dir_all(project.join("docker/amber-sidecar")).unwrap();
    fs::write(
        project.join("docker/amber-sidecar/Dockerfile"),
        r#"FROM alpine:3.20
RUN apk add --no-cache iptables ip6tables socat
"#,
    )
    .unwrap();

    // Scenario definition
    let server_program = serde_json::from_value(json!({
        "image": "busybox:1.36.1",
        "args": ["sh", "-lc", "mkdir -p /www && echo hello > /www/index.html && httpd -f -p 8080 -h /www"],
        "network": { "endpoints": [ { "name": "api", "port": 8080, "protocol": "http", "path": "/" } ] }
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

    let yaml = render_docker_compose(&scenario).expect("compose render ok");
    fs::write(project.join("docker-compose.yaml"), yaml).unwrap();

    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        cmd
    };

    // Up
    let status = compose(&["up", "-d", "--build"]).status().unwrap();
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

    // Denied should fail when calling server sidecar IP directly (10.88.0.11 for c1).
    let denied = compose(&[
        "exec",
        "-T",
        "c3-denied",
        "sh",
        "-lc",
        r#"wget -qO- --timeout=2 --tries=1 "http://10.88.0.11:8080/""#,
    ])
    .status()
    .unwrap();
    assert!(
        !denied.success(),
        "denied client unexpectedly reached server"
    );
}
