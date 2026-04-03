use super::*;

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_component_reaches_public_internet_by_default() {
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
    let router_platform = build_router_image();
    let provisioner_platform = build_provisioner_image();
    let images = internal_images();
    let platform = require_same_platform(&[
        (&images.router, router_platform),
        (&images.provisioner, provisioner_platform),
    ]);
    ensure_image_platform("busybox:1.36.1", &platform);

    let client_program = lower_test_program(
        1,
        json!({
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", "sleep infinity"],
        }),
    );

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
        resources: BTreeMap::new(),
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
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(client)],
        bindings: Vec::new(),
        exports: Vec::new(),
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render ok");
    fs::write(project.join(super::COMPOSE_FILENAME), yaml).unwrap();

    let _compose_guard = ComposeGuard::new(project);
    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        cmd
    };

    let status = compose(&["up", "-d"]).status().unwrap();
    assert!(status.success(), "docker compose up failed");

    let probe = [
        "HOST=example.com",
        "BODY=/tmp/public-egress-body.txt",
        "DNS=/tmp/public-egress-dns.txt",
        "timeout 5 nslookup \"$HOST\" >\"$DNS\" 2>&1",
        "wget -qO- --timeout=3 --tries=1 \"http://$HOST/\" >\"$BODY\" \
         2>/tmp/public-egress-wget.txt",
        "grep -q 'Example Domain' \"$BODY\"",
    ]
    .join(" && ");

    let mut ok = false;
    for _ in 0..5 {
        let output = compose(&["exec", "-T", "c1-client", "sh", "-lc", probe.as_str()])
            .output()
            .unwrap();
        if output.status.success() {
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
        let client_diag = compose(&[
            "exec",
            "-T",
            "c1-client",
            "sh",
            "-lc",
            "echo '=== /etc/resolv.conf ==='; cat /etc/resolv.conf 2>&1 || true; \
             echo; echo '=== nslookup example.com ==='; nslookup example.com 2>&1 || true; \
             echo; echo '=== wget http://example.com/ ==='; wget -O- --timeout=3 --tries=1 \
             http://example.com/ 2>&1 || true",
        ])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_else(|err| format!("failed to capture client diagnostics: {err}"));
        panic!(
            "client could not reach the public internet with default Compose egress\nclient \
             diagnostics:\n{}\ncompose logs:\n{}",
            client_diag, compose_logs
        );
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
    let provisioner_platform = build_provisioner_image();
    let images = internal_images();
    let platform = require_same_platform(&[
        (&images.router, router_platform),
        (&images.provisioner, provisioner_platform),
    ]);
    ensure_image_platform("busybox:1.36.1", &platform);
    ensure_image_platform("alpine:3.20", &platform);

    let client_program = lower_test_program(
        1,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["sh", "-lc", "sleep infinity"],
            "env": {
                "API_URL": "${slots.api.url}"
            }
        }),
    );

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
        resources: BTreeMap::new(),
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
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(client)],
        bindings: vec![BindingEdge {
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
    let yaml = render_compose(&output).expect("compose render ok");
    fs::write(project.join(super::COMPOSE_FILENAME), yaml).unwrap();

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
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_a2a_three_party_url_rewrite_routes_follow_up_call() {
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
    let router_platform = build_router_image();
    let provisioner_platform = build_provisioner_image();
    let images = internal_images();
    let platform = require_same_platform(&[
        (&images.router, router_platform),
        (&images.provisioner, provisioner_platform),
    ]);
    ensure_image_platform("busybox:1.36.1", &platform);

    let agent_a_entrypoint = r#"
set -eu
mkdir -p /www/.well-known /www/cgi-bin
cat >/www/.well-known/agent-card.json <<'JSON'
{"name":"agent","description":"test agent","supportedInterfaces":[{"url":"http://127.0.0.1:8080/cgi-bin/a2a","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"capabilities":{},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[]}
JSON
cat >/www/cgi-bin/a2a <<'SH'
#!/bin/sh
touch /tmp/a-invoked
echo 'Status: 200 OK'
echo 'Content-Type: text/plain'
echo
echo 'a-ok'
SH
chmod +x /www/cgi-bin/a2a
httpd -f -p 8080 -h /www
"#;
    let agent_b_entrypoint = r#"
set -eu
mkdir -p /www/cgi-bin
cat >/www/cgi-bin/inbox <<'SH'
#!/bin/sh
set -eu
body="$(cat)"
url="$(printf '%s' "$body" | sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
printf '%s' "$url" >/tmp/received-url
expected_a_base="$(printf '%s' "$A_URL" | sed 's:/*$::')"
expected_a_url="$expected_a_base/cgi-bin/a2a"
if [ -n "$A_URL" ] && [ "$url" = "$expected_a_url" ]; then
  touch /tmp/url-matched-a-slot
fi
if [ -n "$url" ] && wget -qO- --timeout=2 --tries=1 "$url" >/tmp/a-follow-up-response 2>/dev/null; then
  touch /tmp/follow-up-success
fi
echo 'Status: 200 OK'
echo 'Content-Type: text/plain'
echo
echo 'b-ok'
SH
chmod +x /www/cgi-bin/inbox
httpd -f -p 8080 -h /www
"#;
    let client_c_entrypoint = r#"
set -eu
i=0
while [ "$i" -lt 60 ]; do
  card="$(wget -qO- --timeout=2 --tries=1 "$A_URL/.well-known/agent-card.json" 2>/dev/null || true)"
  target="$(printf '%s' "$card" | sed -n 's/.*"url"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n1)"
  if [ -n "$target" ]; then
    payload="{\"url\":\"$target\"}"
    if wget -qO- --timeout=2 --tries=1 --header='Content-Type: application/json' --post-data "$payload" "$B_URL/cgi-bin/inbox" >/tmp/c-send-response 2>/dev/null; then
      touch /tmp/c-send-success
      sleep infinity
    fi
  fi
  i=$((i+1))
  sleep 1
done
touch /tmp/c-send-failed
sleep infinity
"#;

    let agent_a_program = lower_test_program(
        1,
        json!({
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", agent_a_entrypoint],
            "network": {
                "endpoints": [{ "name": "agent", "port": 8080, "protocol": "http" }]
            }
        }),
    );
    let agent_b_program = lower_test_program(
        2,
        json!({
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", agent_b_entrypoint],
            "env": {
                "A_URL": "${slots.agent_a.url}"
            },
            "network": {
                "endpoints": [{ "name": "agent", "port": 8080, "protocol": "http" }]
            }
        }),
    );
    let client_c_program = lower_test_program(
        3,
        json!({
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", client_c_entrypoint],
            "env": {
                "A_URL": "${slots.z_agent_a.url}",
                "B_URL": "${slots.agent_b.url}"
            }
        }),
    );

    let slot_a2a: SlotDecl = serde_json::from_value(json!({ "kind": "a2a" })).unwrap();
    let provide_a2a: ProvideDecl =
        serde_json::from_value(json!({ "kind": "a2a", "endpoint": "agent" })).unwrap();

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
        resources: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(1), ComponentId(2), ComponentId(3)],
    };
    let agent_a = Component {
        id: ComponentId(1),
        parent: Some(ComponentId(0)),
        moniker: moniker("/agent-a"),
        digest: digest(1),
        config: None,
        config_schema: None,
        program: Some(agent_a_program),
        slots: BTreeMap::new(),
        provides: BTreeMap::from([("agent".to_string(), provide_a2a.clone())]),
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };
    let agent_b = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/agent-b"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(agent_b_program),
        slots: BTreeMap::from([("agent_a".to_string(), slot_a2a.clone())]),
        provides: BTreeMap::from([("agent".to_string(), provide_a2a)]),
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };
    let client_c = Component {
        id: ComponentId(3),
        parent: Some(ComponentId(0)),
        moniker: moniker("/client"),
        digest: digest(3),
        config: None,
        config_schema: None,
        program: Some(client_c_program),
        slots: BTreeMap::from([
            ("agent_b".to_string(), slot_a2a.clone()),
            ("z_agent_a".to_string(), slot_a2a),
        ]),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(agent_a), Some(agent_b), Some(client_c)],
        bindings: vec![
            BindingEdge {
                from: BindingFrom::Component(ProvideRef {
                    component: ComponentId(1),
                    name: "agent".to_string(),
                }),
                to: SlotRef {
                    component: ComponentId(2),
                    name: "agent_a".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                from: BindingFrom::Component(ProvideRef {
                    component: ComponentId(1),
                    name: "agent".to_string(),
                }),
                to: SlotRef {
                    component: ComponentId(3),
                    name: "z_agent_a".to_string(),
                },
                weak: false,
            },
            BindingEdge {
                from: BindingFrom::Component(ProvideRef {
                    component: ComponentId(2),
                    name: "agent".to_string(),
                }),
                to: SlotRef {
                    component: ComponentId(3),
                    name: "agent_b".to_string(),
                },
                weak: false,
            },
        ],
        exports: Vec::new(),
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render ok");
    fs::write(project.join(super::COMPOSE_FILENAME), yaml).unwrap();

    let _compose_guard = ComposeGuard::new(project);
    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        cmd
    };

    let status = compose(&["up", "-d"]).status().unwrap();
    assert!(status.success(), "docker compose up failed");

    let mut client_ok = false;
    for _ in 0..60 {
        let output = compose(&[
            "exec",
            "-T",
            "c3-client",
            "sh",
            "-lc",
            "test -f /tmp/c-send-success",
        ])
        .output()
        .unwrap();
        if output.status.success() {
            client_ok = true;
            break;
        }
        thread::sleep(Duration::from_secs(1));
    }

    if !client_ok {
        let compose_logs = compose(&["logs", "--no-color"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|err| format!("failed to capture compose logs: {err}"));
        panic!(
            "client C never completed card discovery + relay call\ncompose logs:\n{}",
            compose_logs
        );
    }

    let follow_up = compose(&[
        "exec",
        "-T",
        "c2-agent-b",
        "sh",
        "-lc",
        "test -f /tmp/follow-up-success && test -f /tmp/url-matched-a-slot",
    ])
    .output()
    .unwrap();
    let received_url = compose(&[
        "exec",
        "-T",
        "c2-agent-b",
        "sh",
        "-lc",
        "cat /tmp/received-url 2>/dev/null || true",
    ])
    .output()
    .unwrap();
    let expected_a_url = compose(&[
        "exec",
        "-T",
        "c2-agent-b",
        "sh",
        "-lc",
        "printf '%s' \"$A_URL\"",
    ])
    .output()
    .unwrap();
    assert!(
        follow_up.status.success(),
        "agent B did not receive an A URL rewritten to B's local slot view\nreceived URL: \
         {}\nA_URL: {}",
        String::from_utf8_lossy(&received_url.stdout).trim(),
        String::from_utf8_lossy(&expected_a_url.stdout).trim(),
    );

    let invoked = compose(&[
        "exec",
        "-T",
        "c1-agent-a",
        "sh",
        "-lc",
        "test -f /tmp/a-invoked",
    ])
    .output()
    .unwrap();
    assert!(
        invoked.status.success(),
        "agent A endpoint was not invoked by agent B follow-up call"
    );
}

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_sidecar_restart_rejoins_mesh() {
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

    let dir = tempdir().unwrap();
    let project = dir.path();
    let router_platform = build_router_image();
    let provisioner_platform = build_provisioner_image();
    let images = internal_images();
    let platform = require_same_platform(&[
        (&images.router, router_platform),
        (&images.provisioner, provisioner_platform),
    ]);
    ensure_image_platform("busybox:1.36.1", &platform);
    ensure_image_platform("alpine:3.20", &platform);

    let server_program = lower_test_program(
        1,
        json!({
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", "mkdir -p /www && echo rejoin-ok > /www/index.html && httpd -f -p 8080 -h /www"],
            "network": {
                "endpoints": [
                    { "name": "api", "port": 8080, "protocol": "http" }
                ]
            }
        }),
    );

    let client_program = lower_test_program(
        2,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["sh", "-lc", "sleep infinity"],
            "env": {
                "URL": "${slots.api.url}"
            }
        }),
    );

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
        resources: BTreeMap::new(),
        metadata: None,
        children: vec![ComponentId(1), ComponentId(2)],
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
        resources: BTreeMap::new(),
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
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(client)],
        bindings: vec![BindingEdge {
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
        exports: Vec::new(),
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render ok");
    fs::write(project.join(super::COMPOSE_FILENAME), yaml).unwrap();

    let project_name = format!("amber-sidecar-restart-{}", std::process::id());
    let envs = [("COMPOSE_PROJECT_NAME", project_name.as_str())];
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

    let check = || {
        for _ in 0..30 {
            let output = compose(&[
                "exec",
                "-T",
                "c2-client",
                "sh",
                "-lc",
                r#"wget -qO- --timeout=2 --tries=1 "$URL" 2>/dev/null"#,
            ])
            .output()
            .unwrap();
            if output.status.success()
                && String::from_utf8_lossy(&output.stdout).contains("rejoin-ok")
            {
                return true;
            }
            thread::sleep(Duration::from_secs(1));
        }
        false
    };

    if !check() {
        let compose_logs = compose(&["logs", "--no-color"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|err| format!("failed to capture compose logs: {err}"));
        panic!(
            "client could not reach server before restart\ncompose logs:\n{}",
            compose_logs
        );
    }

    let status = compose(&["restart", "c1-server-net"]).status().unwrap();
    assert!(status.success(), "docker compose restart failed");

    let wait_running = |service: &str| {
        for _ in 0..20 {
            let output = compose(&["ps", "-q", service]).output().unwrap();
            if !output.status.success() {
                thread::sleep(Duration::from_millis(250));
                continue;
            }
            let id = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if id.is_empty() {
                thread::sleep(Duration::from_millis(250));
                continue;
            }
            let output = Command::new("docker")
                .args(["inspect", "-f", "{{.State.Running}}", &id])
                .output()
                .unwrap();
            if output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true" {
                return true;
            }
            thread::sleep(Duration::from_millis(250));
        }
        false
    };
    assert!(wait_running("c1-server-net"), "sidecar did not start");

    let status = compose(&["restart", "c1-server"]).status().unwrap();
    assert!(status.success(), "docker compose restart failed");

    if !check() {
        let compose_logs = compose(&["logs", "--no-color"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_else(|err| format!("failed to capture compose logs: {err}"));
        panic!(
            "client could not reach server after restart\ncompose logs:\n{}",
            compose_logs
        );
    }
}

#[test]
fn docker_compose_allows_shared_port_with_different_endpoints() {
    let server_program = lower_test_program(
        1,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["server"],
            "network": {
                "endpoints": [
                    { "name": "a", "port": 80, "protocol": "http" },
                    { "name": "b", "port": 80, "protocol": "http" }
                ]
            }
        }),
    );

    let client_program = lower_test_program(
        2,
        json!({
            "image": "alpine:3.20",
            "entrypoint": ["client"],
            "env": {
                "V1": "${slots.v1.url}",
                "ADMIN": "${slots.admin.url}"
            }
        }),
    );

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
        resources: BTreeMap::new(),
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
        resources: BTreeMap::new(),
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
        resources: BTreeMap::new(),
        metadata: None,
        children: Vec::new(),
    };

    let scenario = Scenario {
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(client)],
        bindings: vec![
            BindingEdge {
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
    let yaml = render_compose(&output).expect("compose render should succeed");
    let compose = parse_compose(&yaml);
    let plan = provision_plan(&compose);
    let server_target = plan
        .targets
        .iter()
        .find(|target| {
            let has_v1 = target
                .config
                .inbound
                .iter()
                .any(|route| route.capability == "v1");
            let has_admin = target
                .config
                .inbound
                .iter()
                .any(|route| route.capability == "admin");
            has_v1 && has_admin
        })
        .expect("server mesh config missing");
    let v1_port = server_target
        .config
        .inbound
        .iter()
        .find(|route| route.capability == "v1")
        .and_then(|route| match route.target {
            InboundTarget::Local { port } => Some(port),
            _ => None,
        })
        .expect("v1 inbound local target");
    let admin_port = server_target
        .config
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
