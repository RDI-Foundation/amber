use super::*;

#[test]
#[ignore = "requires docker + kind + kubectl + curl; run manually"]
fn kubernetes_smoke_storage_upgrade_reuses_pvc() {
    use std::{io::Read, net::TcpListener};

    let fixture_dir = tempdir().expect("create fixture temp dir");
    let scenario_path = write_kubernetes_counter_storage_fixture(fixture_dir.path(), "v1");

    let dir = tempdir().expect("create temp dir");
    let kubeconfig = dir.path().join("kubeconfig");
    let output_dir = dir.path().join("kubernetes");
    let amber_bin = ensure_amber_cli_binary();

    let platform = docker_platform();
    build_helper_image();
    build_router_image();
    build_provisioner_image();
    ensure_image_platform("busybox:1.36.1", &platform);
    let images = internal_images();

    let cluster = KindCluster::from_env_or_create(&kubeconfig);
    let cluster_name = cluster.name.clone();
    let kubeconfig = cluster.kubeconfig.clone();

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

    for image in [
        images.helper.as_str(),
        images.router.as_str(),
        images.provisioner.as_str(),
        "busybox:1.36.1",
    ] {
        let mut cmd = kind_cmd(&kubeconfig);
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    let namespace = format!("amber-storage-{}", std::process::id());
    let cleanup_namespace = |ns: &str| {
        let _ = kubectl_cmd(&kubeconfig)
            .arg("delete")
            .arg("namespace")
            .arg(ns)
            .arg("--ignore-not-found=true")
            .arg("--wait=false")
            .status();
    };
    cleanup_namespace(&namespace);

    let mut create_namespace = kubectl_cmd(&kubeconfig);
    create_namespace
        .arg("create")
        .arg("namespace")
        .arg(&namespace);
    checked_status(&mut create_namespace, "kubectl create namespace");

    let wait_for_body = |expected: &str, namespace: &str| {
        let mut get_router_pod = kubectl_cmd(&kubeconfig);
        get_router_pod
            .arg("get")
            .arg("pod")
            .arg("-n")
            .arg(namespace)
            .arg("-l")
            .arg("amber.io/component=amber-router")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let router_pod = String::from_utf8_lossy(
            &checked_output(&mut get_router_pod, "kubectl get router pod").stdout,
        )
        .trim()
        .to_string();
        assert!(
            !router_pod.is_empty(),
            "expected router pod in namespace {namespace}"
        );

        let mesh_port = pick_free_port();
        let control_port = pick_free_port();
        let export_port = pick_free_port();

        let mesh_log_path = dir.path().join(format!("router-mesh-{expected}.log"));
        let mut mesh_forward = PortForwardGuard::new_with_ports(
            namespace,
            &router_pod,
            mesh_port,
            24000,
            &mesh_log_path,
            &kubeconfig,
        );
        mesh_forward.wait_until_ready(Duration::from_secs(30));

        let control_log_path = dir.path().join(format!("router-control-{expected}.log"));
        let mut control_forward = PortForwardGuard::new_with_ports(
            namespace,
            &router_pod,
            control_port,
            24100,
            &control_log_path,
            &kubeconfig,
        );
        control_forward.wait_until_ready(Duration::from_secs(30));

        let mut proxy = ProxyGuard {
            child: Command::new(&amber_bin)
                .arg("proxy")
                .arg(&output_dir)
                .arg("--export")
                .arg(format!("http=127.0.0.1:{export_port}"))
                .arg("--router-addr")
                .arg(format!("127.0.0.1:{mesh_port}"))
                .arg("--router-control-addr")
                .arg(format!("127.0.0.1:{control_port}"))
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("start amber proxy"),
        };

        let deadline = Instant::now() + Duration::from_secs(60);
        let url = format!("http://127.0.0.1:{export_port}/");
        let mut last_err: Option<String> = None;
        loop {
            let output = Command::new("curl")
                .arg("-fsS")
                .arg("--max-time")
                .arg("2")
                .arg(&url)
                .output();
            match output {
                Ok(output) if output.status.success() => {
                    let body = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    if body == expected {
                        return;
                    }
                    last_err = Some(format!("unexpected response body: {body:?}"));
                }
                Ok(output) => {
                    last_err = Some(format!(
                        "curl failed (status: {})\nstdout:\n{}\nstderr:\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    ));
                }
                Err(err) => last_err = Some(format!("failed to run curl: {err}")),
            }

            if let Ok(Some(status)) = proxy.child.try_wait() {
                let (proxy_stdout, proxy_stderr) = drain_pipes(&mut proxy.child);
                let mesh_logs = mesh_forward.logs();
                let control_logs = control_forward.logs();
                let router_logs = kubectl_logs(namespace, &router_pod, &kubeconfig);
                panic!(
                    "amber proxy exited before export served {expected} (status: {status})\nproxy \
                     stdout:\n{proxy_stdout}\nproxy stderr:\n{proxy_stderr}\nmesh port-forward \
                     logs:\n{mesh_logs}\ncontrol port-forward logs:\n{control_logs}\nrouter \
                     logs:\n{router_logs}"
                );
            }
            if Instant::now() >= deadline {
                let (proxy_stdout, proxy_stderr) = drain_pipes(&mut proxy.child);
                let mesh_logs = mesh_forward.logs();
                let control_logs = control_forward.logs();
                let router_logs = kubectl_logs(namespace, &router_pod, &kubeconfig);
                panic!(
                    "export did not serve {expected} via amber proxy at {url}\n{}\n\nproxy \
                     stdout:\n{proxy_stdout}\nproxy stderr:\n{proxy_stderr}\nmesh port-forward \
                     logs:\n{mesh_logs}\ncontrol port-forward logs:\n{control_logs}\nrouter \
                     logs:\n{router_logs}",
                    last_err.unwrap_or_else(|| "no curl output captured".to_string())
                );
            }
            thread::sleep(Duration::from_millis(500));
        }
    };

    let apply_version = |version: &str| {
        write_kubernetes_output(&output_dir, &compile_fixture(&scenario_path));
        set_kustomization_namespace(&output_dir.join("kustomization.yaml"), &namespace);
        let provisioner_job =
            provisioner_job_name(&output_dir.join("02-rbac/amber-provisioner-job.yaml"));
        let mut apply = kubectl_cmd(&kubeconfig);
        apply.arg("apply").arg("-k").arg(&output_dir);
        checked_status(&mut apply, &format!("kubectl apply {version}"));

        let mut wait_job = kubectl_cmd(&kubeconfig);
        wait_job
            .arg("wait")
            .arg("--for=condition=complete")
            .arg("--timeout=180s")
            .arg("job")
            .arg(&provisioner_job)
            .arg("-n")
            .arg(&namespace);
        let wait_status = wait_job.status().unwrap_or_else(|err| {
            panic!("failed to run kubectl wait provisioner {version}: {err}");
        });
        if !wait_status.success() {
            let diagnostics = kubernetes_failure_diagnostics(&namespace, &kubeconfig);
            panic!(
                "kubectl wait provisioner {version} failed (status: {wait_status})\n{diagnostics}"
            );
        }

        let mut rollout = kubectl_cmd(&kubeconfig);
        rollout
            .arg("rollout")
            .arg("status")
            .arg("deployment/c0-component")
            .arg("--timeout=180s")
            .arg("-n")
            .arg(&namespace);
        let rollout_status = rollout.status().unwrap_or_else(|err| {
            panic!("failed to run kubectl rollout deployment {version}: {err}");
        });
        if !rollout_status.success() {
            let diagnostics = kubernetes_failure_diagnostics(&namespace, &kubeconfig);
            panic!(
                "kubectl rollout deployment {version} failed (status: \
                 {rollout_status})\n{diagnostics}"
            );
        }
    };

    apply_version("v1");
    wait_for_body("v1:1", &namespace);

    write_kubernetes_counter_storage_fixture(fixture_dir.path(), "v2");
    apply_version("v2");
    wait_for_body("v2:2", &namespace);

    cleanup_namespace(&namespace);
}

#[test]
#[ignore = "requires docker + kind + kubectl + curl; run manually"]
fn kubernetes_smoke_config_roundtrip() {
    let fixture_dir = tempdir().expect("create fixture temp dir");
    let scenario_path = write_kubernetes_smoke_fixture(fixture_dir.path());

    let compiler = Compiler::new(Resolver::new(), DigestStore::default());
    let opts = CompileOptions::default();
    let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
    let output = rt
        .block_on(compiler.compile(ManifestRef::from_url(file_url(&scenario_path)), opts))
        .expect("compile kubernetes scenario");

    let artifact = render_artifact(&output);

    let dir = tempdir().expect("create temp dir");
    let kubeconfig = dir.path().join("kubeconfig");
    let output_dir = dir.path().join("kubernetes");
    write_kubernetes_output(&output_dir, &artifact);

    set_env_value(
        &output_dir.join("root-config-secret.env"),
        "AMBER_CONFIG_SERVER_RUNTIME_SECRET",
        "test-secret-value",
    );
    set_env_value(
        &output_dir.join("root-config.env"),
        "AMBER_CONFIG_SERVER_RUNTIME_CONFIG",
        "test-config-value",
    );

    let platform = docker_platform();
    build_helper_image();
    build_router_image();
    build_provisioner_image();
    ensure_image_platform("busybox:1.36", &platform);
    let images = internal_images();

    let cluster = KindCluster::from_env_or_create(&kubeconfig);
    let cluster_name = cluster.name.clone();
    let kubeconfig = cluster.kubeconfig.clone();

    for image in [
        images.helper.as_str(),
        images.router.as_str(),
        images.provisioner.as_str(),
        "busybox:1.36",
    ] {
        let mut cmd = kind_cmd(&kubeconfig);
        cmd.arg("load")
            .arg("docker-image")
            .arg(image)
            .arg("--name")
            .arg(&cluster_name);
        checked_status(&mut cmd, &format!("kind load {image} image"));
    }

    let namespace = kustomization_namespace(&output_dir.join("kustomization.yaml"));
    ensure_namespace_exists(&namespace, &kubeconfig);

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("apply").arg("-k").arg(&output_dir);
    checked_status(&mut cmd, "kubectl apply");

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=available")
        .arg("--timeout=120s")
        .arg("deployment")
        .arg("--all")
        .arg("-n")
        .arg(&namespace);
    checked_status(&mut cmd, "kubectl wait for deployments");

    let client_pod = {
        let mut cmd = kubectl_cmd(&kubeconfig);
        cmd.arg("get")
            .arg("pod")
            .arg("-n")
            .arg(&namespace)
            .arg("-l")
            .arg("amber.io/component=c1-client")
            .arg("-o")
            .arg("jsonpath={.items[0].metadata.name}");
        let output = checked_output(&mut cmd, "kubectl get client pod");
        let pod = String::from_utf8_lossy(&output.stdout).trim().to_string();
        assert!(!pod.is_empty(), "no client pod found");
        pod
    };

    let mut cmd = kubectl_cmd(&kubeconfig);
    cmd.arg("wait")
        .arg("--for=condition=ready")
        .arg("--timeout=120s")
        .arg("pod")
        .arg("-n")
        .arg(&namespace)
        .arg(&client_pod);
    checked_status(&mut cmd, "kubectl wait for client pod");

    let port_forward_log = dir.path().join("port-forward.log");
    let mut port_forward =
        PortForwardGuard::new(&namespace, &client_pod, &port_forward_log, &kubeconfig);
    port_forward.wait_until_ready(Duration::from_secs(30));

    let runtime_secret = fetch(
        "http://localhost:8080/runtime_secret.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
        &kubeconfig,
    );
    let runtime_config = fetch(
        "http://localhost:8080/runtime_config.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
        &kubeconfig,
    );
    let static_secret = fetch(
        "http://localhost:8080/static_secret.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
        &kubeconfig,
    );
    let static_config = fetch(
        "http://localhost:8080/static_config.txt",
        &mut port_forward,
        &namespace,
        &client_pod,
        &kubeconfig,
    );

    assert_eq!(runtime_secret, "test-secret-value");
    assert_eq!(runtime_config, "test-config-value");
    assert_eq!(static_secret, "hardcode-this-secret");
    assert_eq!(static_config, "hardcode-this-config");
}
