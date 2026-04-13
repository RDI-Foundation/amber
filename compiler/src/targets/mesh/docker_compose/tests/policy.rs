use super::*;

#[test]
#[ignore = "requires docker + docker compose; run manually"]
fn docker_smoke_storage_persists_across_upgrade() {
    use std::{
        fs,
        io::Read,
        net::TcpListener,
        process::{Command, Stdio},
        thread,
        time::Duration,
    };

    use tempfile::tempdir;

    struct ComposeGuard {
        project: std::path::PathBuf,
        envs: Vec<(String, String)>,
    }

    impl ComposeGuard {
        fn new(project: &std::path::Path, envs: Vec<(String, String)>) -> Self {
            Self {
                project: project.to_path_buf(),
                envs,
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
                "--timeout",
                "1",
            ]);
            for (key, value) in &self.envs {
                cmd.env(key, value);
            }
            let _ = cmd.status();
        }
    }

    struct ProxyGuard {
        child: std::process::Child,
    }

    impl Drop for ProxyGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    fn pick_free_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind local port");
        let port = listener
            .local_addr()
            .expect("local listener address")
            .port();
        drop(listener);
        port
    }

    fn drain_pipes(child: &mut std::process::Child) -> (String, String) {
        let mut stdout = String::new();
        if let Some(mut pipe) = child.stdout.take() {
            let _ = pipe.read_to_string(&mut stdout);
        }

        let mut stderr = String::new();
        if let Some(mut pipe) = child.stderr.take() {
            let _ = pipe.read_to_string(&mut stderr);
        }

        (stdout, stderr)
    }

    fn spawn_amber_proxy(
        amber_bin: &Path,
        project: &Path,
        project_name: &str,
        export_port: u16,
    ) -> ProxyGuard {
        let child = Command::new(amber_bin)
            .arg("proxy")
            .arg(project)
            .arg("--project-name")
            .arg(project_name)
            .arg("--export")
            .arg(format!("http=127.0.0.1:{export_port}"))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start amber proxy");
        ProxyGuard { child }
    }

    fn fetch_export_path(export_port: u16, path: &str) -> Option<String> {
        let output = Command::new("curl")
            .arg("-fsS")
            .arg("--max-time")
            .arg("2")
            .arg(format!("http://127.0.0.1:{export_port}/{path}"))
            .output()
            .ok()?;
        output
            .status
            .success()
            .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
    }

    fn compose_logs(project: &Path, envs: &[(&str, &str)]) -> String {
        let mut logs_cmd = Command::new("docker");
        logs_cmd
            .current_dir(project)
            .arg("compose")
            .args(["logs", "--no-color"]);
        for (key, value) in envs {
            logs_cmd.env(key, value);
        }
        logs_cmd
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).to_string())
            .unwrap_or_else(|err| format!("failed to capture compose logs: {err}"))
    }

    fn wait_for_export_path(
        export_port: u16,
        path: &str,
        expected: &str,
        proxy: &mut ProxyGuard,
        project: &Path,
        envs: &[(&str, &str)],
    ) {
        for _ in 0..60 {
            if fetch_export_path(export_port, path).as_deref() == Some(expected) {
                return;
            }
            if let Ok(Some(status)) = proxy.child.try_wait() {
                let (proxy_stdout, proxy_stderr) = drain_pipes(&mut proxy.child);
                let logs = compose_logs(project, envs);
                panic!(
                    "amber proxy exited before {path} served {expected} (status: {status})\nproxy \
                     stdout:\n{proxy_stdout}\nproxy stderr:\n{proxy_stderr}\ncompose logs:\n{logs}"
                );
            }
            thread::sleep(Duration::from_secs(1));
        }

        let (proxy_stdout, proxy_stderr) = drain_pipes(&mut proxy.child);
        let logs = compose_logs(project, envs);
        panic!(
            "export {path} never served {expected}\nproxy stdout:\n{proxy_stdout}\nproxy \
             stderr:\n{proxy_stderr}\ncompose logs:\n{logs}"
        );
    }

    let dir = tempdir().unwrap();
    let project = dir.path();
    let amber_bin = ensure_amber_cli_binary();
    let envs_owned = vec![(
        "COMPOSE_PROJECT_NAME".to_string(),
        format!("amber-storage-upgrade-{}", std::process::id()),
    )];
    let project_name = envs_owned[0].1.clone();
    let compose_envs = envs_owned.clone();
    let envs = compose_envs
        .iter()
        .map(|(key, value)| (key.as_str(), value.as_str()))
        .collect::<Vec<_>>();
    let _compose_guard = ComposeGuard::new(project, envs_owned);

    let v1 = render_compose(&compile_output(storage_scenario(
        "version-v1",
        "persisted-v1",
    )))
    .expect("compose render v1");
    fs::write(project.join(super::COMPOSE_FILENAME), v1.compose_yaml()).unwrap();

    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        for (key, value) in &envs {
            cmd.env(key, value);
        }
        cmd
    };

    let status = compose(&["up", "-d"]).status().unwrap();
    assert!(status.success(), "docker compose up v1 failed");

    let export_port = pick_free_port();
    let mut proxy = spawn_amber_proxy(
        amber_bin.as_path(),
        project,
        project_name.as_str(),
        export_port,
    );
    wait_for_export_path(
        export_port,
        "version.txt",
        "version-v1",
        &mut proxy,
        project,
        &envs,
    );
    wait_for_export_path(
        export_port,
        "state.txt",
        "persisted-v1",
        &mut proxy,
        project,
        &envs,
    );
    drop(proxy);

    let v2 = render_compose(&compile_output(storage_scenario(
        "version-v2",
        "persisted-v2",
    )))
    .expect("compose render v2");
    fs::write(project.join(super::COMPOSE_FILENAME), v2.compose_yaml()).unwrap();

    let status = compose(&["up", "-d"]).status().unwrap();
    assert!(status.success(), "docker compose up v2 failed");

    let mut proxy = spawn_amber_proxy(
        amber_bin.as_path(),
        project,
        project_name.as_str(),
        export_port,
    );
    wait_for_export_path(
        export_port,
        "version.txt",
        "version-v2",
        &mut proxy,
        project,
        &envs,
    );
    wait_for_export_path(
        export_port,
        "state.txt",
        "persisted-v1",
        &mut proxy,
        project,
        &envs,
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
    let router_platform = build_router_image();
    let provisioner_platform = build_provisioner_image();
    let images = internal_images();
    let platform = require_same_platform(&[
        (&images.router, router_platform),
        (&images.provisioner, provisioner_platform),
    ]);
    ensure_image_platform("busybox:1.36.1", &platform);
    ensure_image_platform("alpine:3.20", &platform);
    let _compose_guard = ComposeGuard::new(project);
    let server_host = "c1-server-net";

    let server_program = lower_test_program(
        1,
        json!({
            "image": "busybox:1.36.1",
            "entrypoint": ["sh", "-lc", "mkdir -p /www && echo hello > /www/index.html && httpd -f -p 8080 -h /www"],
            "network": { "endpoints": [ { "name": "api", "port": 8080, "protocol": "http" } ] }
        }),
    );

    let sleeper_program = |id: usize, env: serde_json::Value| {
        lower_test_program(
            id,
            json!({
                "image": "alpine:3.20",
                "entrypoint": ["sh", "-lc", "sleep infinity"],
                "env": env
            }),
        )
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
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
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
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let allowed = Component {
        id: ComponentId(2),
        parent: Some(ComponentId(0)),
        moniker: moniker("/allowed"),
        digest: digest(2),
        config: None,
        config_schema: None,
        program: Some(sleeper_program(2, json!({ "URL": "${slots.api.url}" }))),
        slots: BTreeMap::from([("api".to_string(), slot_http.clone())]),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let denied = Component {
        id: ComponentId(3),
        parent: Some(ComponentId(0)),
        moniker: moniker("/denied"),
        digest: digest(3),
        config: None,
        config_schema: None,
        program: Some(sleeper_program(3, json!({}))),
        slots: BTreeMap::new(),
        provides: BTreeMap::new(),
        resources: BTreeMap::new(),
        metadata: None,
        child_templates: BTreeMap::new(),
        children: Vec::new(),
    };

    let scenario = Scenario {
        manifest_catalog: BTreeMap::new(),
        root: ComponentId(0),
        components: vec![Some(root), Some(server), Some(allowed), Some(denied)],
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
        exports: vec![],
    };

    let output = compile_output(scenario);
    let yaml = render_compose(&output).expect("compose render ok");
    fs::write(project.join(super::COMPOSE_FILENAME), yaml).unwrap();

    let compose = |args: &[&str]| {
        let mut cmd = Command::new("docker");
        cmd.current_dir(project).arg("compose").args(args);
        cmd
    };

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
    let provisioner_platform = build_provisioner_image();
    let images = internal_images();
    let platform = require_same_platform(&[
        (&images.router, router_platform),
        (&images.helper, helper_platform),
        (&images.provisioner, provisioner_platform),
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

    let yaml = render_compose(&output).expect("compose render ok");
    fs::write(project.join(super::COMPOSE_FILENAME), yaml).unwrap();

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
