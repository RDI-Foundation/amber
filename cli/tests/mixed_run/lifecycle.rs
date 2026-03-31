use super::*;

#[test]
#[ignore = "requires docker + kind + kubectl + qemu + an Ubuntu 24.04 cloud image matching the \
            host architecture; run manually or in CI"]
fn mixed_run_five_site_startup_state_and_teardown() {
    let temp = temp_output_dir("mixed-run-five-site-");
    let kubeconfig = temp.path().join("kubeconfig");
    let kind_cluster = KindCluster::from_env_or_create(&kubeconfig);
    ensure_kind_internal_images(&kind_cluster);
    let kubeconfig_env = kind_cluster.kubeconfig.display().to_string();
    let host_server = HostHttpServer::start();
    let adversarial_port = host_server.port();
    let fixture = write_five_site_fixture(temp.path(), &kind_cluster, adversarial_port);
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &[("KUBECONFIG", &kubeconfig_env)],
    );

    let run_plan = read_json(&run.run_root.join("run-plan.json"));
    assert_eq!(
        run_plan["startup_waves"],
        json!([
            ["compose_e"],
            ["vm_d"],
            ["kind_c"],
            ["compose_b"],
            ["direct_a"]
        ])
    );
    assert_eq!(
        run_plan["assignments"],
        json!({
            "/a": "direct_a",
            "/b": "compose_b",
            "/c": "kind_c",
            "/d": "vm_d",
            "/e": "compose_e"
        })
    );
    assert_eq!(
        run.receipt["sites"]
            .as_object()
            .expect("receipt sites")
            .len(),
        5
    );

    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_a",
        "running",
        Duration::from_secs(30),
    );
    let compose_b_state = wait_for_state_status(
        &run.run_root,
        "compose_b",
        "running",
        Duration::from_secs(30),
    );
    let kind_state =
        wait_for_state_status(&run.run_root, "kind_c", "running", Duration::from_secs(60));
    let vm_state =
        wait_for_state_status(&run.run_root, "vm_d", "running", Duration::from_secs(180));
    let compose_e_state = wait_for_state_status(
        &run.run_root,
        "compose_e",
        "running",
        Duration::from_secs(30),
    );

    for (site_id, state) in [
        ("direct_a", &direct_state),
        ("compose_b", &compose_b_state),
        ("kind_c", &kind_state),
        ("vm_d", &vm_state),
        ("compose_e", &compose_e_state),
    ] {
        assert_eq!(state["run_id"], run.run_id);
        assert_eq!(state["site_id"], site_id);
        assert_eq!(state["status"], "running");
        assert_eq!(
            state["router_identity_id"],
            format!("/site/{site_id}/router")
        );
        assert!(
            state["router_control"].is_string(),
            "site {site_id} should publish router control"
        );
        let desired_links = read_json(
            &run.run_root
                .join("state")
                .join(site_id)
                .join("desired-links.json"),
        );
        assert_eq!(desired_links["schema"], "amber.run.desired_links");
    }

    assert_eq!(
        read_json(
            &run.run_root
                .join("state")
                .join("direct_a")
                .join("desired-links.json")
        )["external_slots"]
            .as_object()
            .expect("direct external slots")
            .len(),
        2
    );
    assert_eq!(
        read_json(
            &run.run_root
                .join("state")
                .join("compose_b")
                .join("desired-links.json")
        )["external_slots"]
            .as_object()
            .expect("compose_b external slots")
            .len(),
        2
    );
    assert_eq!(
        read_json(
            &run.run_root
                .join("state")
                .join("kind_c")
                .join("desired-links.json")
        )["external_slots"]
            .as_object()
            .expect("kind external slots")
            .len(),
        1
    );
    assert_eq!(
        read_json(
            &run.run_root
                .join("state")
                .join("vm_d")
                .join("desired-links.json")
        )["external_slots"]
            .as_object()
            .expect("vm external slots")
            .len(),
        1
    );

    let a_port = pick_free_port();
    let b_port = pick_free_port();
    let c_port = pick_free_port();
    let d_port = pick_free_port();
    let e_port = pick_free_port();
    let mut a_proxy = spawn_proxy(&run.site_artifact_dir("direct_a"), "a_http", a_port, &[]);
    let mut b_proxy = spawn_proxy(&run.site_artifact_dir("compose_b"), "b_http", b_port, &[]);
    let c_router_addr = kind_state["router_mesh_addr"]
        .as_str()
        .expect("kind site should publish router mesh addr")
        .to_string();
    let c_router_control = kind_state["router_control"]
        .as_str()
        .expect("kind site should publish router control")
        .to_string();
    let c_proxy_args = vec![
        "--router-addr".to_string(),
        c_router_addr,
        "--router-control-addr".to_string(),
        c_router_control,
    ];
    let mut c_proxy = spawn_proxy(
        &run.site_artifact_dir("kind_c"),
        "c_http",
        c_port,
        &c_proxy_args,
    );
    let mut d_proxy = spawn_proxy(&run.site_artifact_dir("vm_d"), "d_http", d_port, &[]);
    let mut e_proxy = spawn_proxy(&run.site_artifact_dir("compose_e"), "e_http", e_port, &[]);

    wait_for_path(&mut a_proxy, a_port, "/id", Duration::from_secs(180));
    wait_for_path(&mut b_proxy, b_port, "/id", Duration::from_secs(180));
    wait_for_path(&mut c_proxy, c_port, "/id", Duration::from_secs(180));
    wait_for_path(&mut d_proxy, d_port, "/id", Duration::from_secs(300));
    wait_for_path(&mut e_proxy, e_port, "/id", Duration::from_secs(180));

    assert_eq!(
        wait_for_body(&mut a_proxy, a_port, "/call/b", Duration::from_secs(120)),
        "B"
    );
    assert_eq!(
        wait_for_body(&mut a_proxy, a_port, "/call/c", Duration::from_secs(120)),
        "C"
    );
    assert_eq!(
        wait_for_body(&mut b_proxy, b_port, "/call/c", Duration::from_secs(120)),
        "C"
    );
    assert_eq!(
        wait_for_body(&mut b_proxy, b_port, "/call/d", Duration::from_secs(120)),
        "D"
    );
    assert_eq!(
        wait_for_body(&mut c_proxy, c_port, "/call/d", Duration::from_secs(120)),
        "D"
    );
    assert_eq!(
        wait_for_body(&mut d_proxy, d_port, "/call/e", Duration::from_secs(120)),
        "E"
    );

    let b_adversarial = wait_for_body(
        &mut b_proxy,
        b_port,
        "/adversarial-host",
        Duration::from_secs(60),
    );
    let e_adversarial = wait_for_body(
        &mut e_proxy,
        e_port,
        "/adversarial-host",
        Duration::from_secs(60),
    );
    assert!(
        b_adversarial.starts_with("blocked:"),
        "compose site should not bypass Amber via host, got {b_adversarial}"
    );
    assert!(
        e_adversarial.starts_with("blocked:"),
        "compose site should not bypass Amber via host, got {e_adversarial}"
    );

    stop_proxy(&mut a_proxy);
    stop_proxy(&mut b_proxy);
    stop_proxy(&mut c_proxy);
    stop_proxy(&mut d_proxy);
    stop_proxy(&mut e_proxy);

    let direct_pid = direct_state["process_pid"]
        .as_u64()
        .expect("direct site pid should exist") as u32;
    let vm_pid = vm_state["process_pid"]
        .as_u64()
        .expect("vm site pid should exist") as u32;
    let compose_b_project = compose_b_state["compose_project"]
        .as_str()
        .expect("compose_b project should exist")
        .to_string();
    let compose_e_project = compose_e_state["compose_project"]
        .as_str()
        .expect("compose_e project should exist")
        .to_string();
    let kind_namespace = kind_state["kubernetes_namespace"]
        .as_str()
        .expect("kubernetes namespace should exist")
        .to_string();

    run.stop();
    wait_for_state_status(
        &run.run_root,
        "direct_a",
        "stopped",
        Duration::from_secs(30),
    );
    wait_for_state_status(
        &run.run_root,
        "compose_b",
        "stopped",
        Duration::from_secs(30),
    );
    wait_for_state_status(&run.run_root, "kind_c", "stopped", Duration::from_secs(60));
    wait_for_state_status(&run.run_root, "vm_d", "stopped", Duration::from_secs(60));
    wait_for_state_status(
        &run.run_root,
        "compose_e",
        "stopped",
        Duration::from_secs(30),
    );

    assert!(
        !run.run_root.join("receipt.json").exists(),
        "receipt should be removed after stop"
    );
    assert!(
        compose_ps_ids(&compose_b_project, &run.site_artifact_dir("compose_b")).is_empty(),
        "compose_b should be torn down"
    );
    assert!(
        compose_ps_ids(&compose_e_project, &run.site_artifact_dir("compose_e")).is_empty(),
        "compose_e should be torn down"
    );
    drop(host_server);
    assert!(
        !namespace_exists(
            &kind_namespace,
            &kind_cluster.kubeconfig,
            &kind_cluster.context_name()
        ),
        "kubernetes namespace {kind_namespace} should be deleted"
    );
    assert!(
        !pid_is_alive(direct_pid),
        "direct site pid {direct_pid} should be gone"
    );
    assert!(!pid_is_alive(vm_pid), "vm site pid {vm_pid} should be gone");
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_partial_site_failure_during_launch_cleans_up() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-launch-failure-");
    let fixture = write_partial_launch_failure_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let failed =
        run_manifest_expect_failure(&fixture.manifest, &fixture.placement, &storage_root, &[]);

    let stdout = String::from_utf8_lossy(&failed.output.stdout);
    let stderr = String::from_utf8_lossy(&failed.output.stderr);
    assert!(
        stderr.contains("site supervisor for `missing_kind` exited before becoming ready")
            || stderr.contains("missing_kind"),
        "expected launch failure output\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !failed.run_root.join("receipt.json").exists(),
        "failed launch should not write a receipt"
    );
    assert!(
        !failed.run_root.join("committed").exists(),
        "failed launch should not commit"
    );

    let compose_state = wait_for_state_status(
        &failed.run_root,
        "compose_local",
        "stopped",
        Duration::from_secs(60),
    );
    let compose_project = compose_state["compose_project"]
        .as_str()
        .expect("compose project should be recorded")
        .to_string();
    assert!(
        compose_ps_ids(
            &compose_project,
            &failed
                .run_root
                .join("sites")
                .join("compose_local")
                .join("artifact")
        )
        .is_empty(),
        "compose site should be torn down after launch failure"
    );
}

#[test]
#[ignore = "requires docker + qemu + an Ubuntu 24.04 cloud image matching the host architecture; \
            run manually or in CI"]
fn mixed_run_cleanup_after_coordinator_dies_during_setup() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-precommit-kill-");
    let fixture = write_precommit_cleanup_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = spawn_run_manifest_with_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &[],
        &[("AMBER_TEST_MIXED_RUN_AFTER_WAVE_DELAY_MS", "5000")],
    );
    let run_root = wait_for_single_run_root(&storage_root, Duration::from_secs(60));

    let compose_state = wait_for_state_status(
        &run_root,
        "compose_local",
        "running",
        Duration::from_secs(60),
    );
    stop_child(&mut run);

    let compose_final = wait_for_state_status(
        &run_root,
        "compose_local",
        "stopped",
        Duration::from_secs(90),
    );
    assert_eq!(
        compose_final["last_error"],
        Value::String("coordinator exited before commit".to_string())
    );
    assert!(
        !run_root.join("receipt.json").exists(),
        "pre-commit coordinator exit should not leave a receipt"
    );
    assert!(
        !run_root.join("committed").exists(),
        "pre-commit coordinator exit should not commit"
    );

    let compose_project = compose_state["compose_project"]
        .as_str()
        .expect("compose project should be recorded")
        .to_string();
    assert!(
        compose_ps_ids(
            &compose_project,
            &run_root
                .join("sites")
                .join("compose_local")
                .join("artifact")
        )
        .is_empty(),
        "compose site should be torn down after coordinator death"
    );
}

#[test]
#[ignore = "requires a working direct runtime sandbox; run manually or in CI"]
fn mixed_run_recovers_direct_component_failure_after_setup() {
    let temp = temp_output_dir("mixed-run-direct-restart-");
    let fixture = write_single_site_direct_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );
    let first_pid = direct_state["process_pid"]
        .as_u64()
        .expect("direct process pid should exist") as u32;

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "a_http",
        proxy_port,
        &[],
    );
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    let _ = http_get(proxy_port, "/crash");
    stop_proxy(&mut proxy);

    let recovered = wait_for_state_pid_change(
        &run.run_root,
        "direct_local",
        "process_pid",
        first_pid,
        Duration::from_secs(60),
    );
    assert_ne!(
        recovered["process_pid"]
            .as_u64()
            .expect("replacement direct pid should exist") as u32,
        first_pid
    );
    wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(60),
    );

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("direct_local"),
        "a_http",
        proxy_port,
        &[],
    );
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/id", Duration::from_secs(60)),
        "A"
    );
    stop_proxy(&mut proxy);
    run.stop();
}

#[test]
#[ignore = "requires qemu + an Ubuntu 24.04 cloud image matching the host architecture; run \
            manually or in CI"]
fn mixed_run_recovers_vm_site_failure_after_setup() {
    let temp = temp_output_dir("mixed-run-vm-restart-");
    let fixture = write_single_site_vm_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let vm_state = wait_for_state_status(
        &run.run_root,
        "vm_local",
        "running",
        Duration::from_secs(300),
    );
    let first_pid = vm_state["process_pid"]
        .as_u64()
        .expect("vm site pid should exist") as u32;

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("vm_local"),
        "a_http",
        proxy_port,
        &[],
    );
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(300));
    stop_proxy(&mut proxy);

    kill_pid(first_pid);
    let recovered = wait_for_state_pid_change(
        &run.run_root,
        "vm_local",
        "process_pid",
        first_pid,
        Duration::from_secs(360),
    );
    assert_ne!(
        recovered["process_pid"]
            .as_u64()
            .expect("replacement vm pid should exist") as u32,
        first_pid
    );
    wait_for_state_status(
        &run.run_root,
        "vm_local",
        "running",
        Duration::from_secs(360),
    );

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("vm_local"),
        "a_http",
        proxy_port,
        &[],
    );
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/id", Duration::from_secs(300)),
        "A"
    );
    stop_proxy(&mut proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker + kind + kubectl; run manually or in CI"]
fn mixed_run_recovers_when_kubernetes_site_is_temporarily_unreachable() {
    let temp = temp_output_dir("mixed-run-kind-forward-restart-");
    let kubeconfig = temp.path().join("kubeconfig");
    let kind_cluster = KindCluster::from_env_or_create(&kubeconfig);
    ensure_kind_internal_images(&kind_cluster);
    let kubeconfig_env = kind_cluster.kubeconfig.display().to_string();
    let fixture = write_single_site_kind_fixture(temp.path(), &kind_cluster);
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &[("KUBECONFIG", &kubeconfig_env)],
    );

    let kind_state = wait_for_state_status(
        &run.run_root,
        "kind_local",
        "running",
        Duration::from_secs(120),
    );
    let first_forward_pid = kind_state["port_forward_pid"]
        .as_u64()
        .expect("kubernetes site should publish port-forward pid")
        as u32;
    let proxy_args = vec![
        "--router-addr".to_string(),
        kind_state["router_mesh_addr"]
            .as_str()
            .expect("kind router mesh addr should exist")
            .to_string(),
        "--router-control-addr".to_string(),
        kind_state["router_control"]
            .as_str()
            .expect("kind router control should exist")
            .to_string(),
    ];

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("kind_local"),
        "a_http",
        proxy_port,
        &proxy_args,
    );
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(120));
    stop_proxy(&mut proxy);

    kill_pid(first_forward_pid);
    let recovered = wait_for_state_pid_change(
        &run.run_root,
        "kind_local",
        "port_forward_pid",
        first_forward_pid,
        Duration::from_secs(120),
    );
    assert_ne!(
        recovered["port_forward_pid"]
            .as_u64()
            .expect("replacement port-forward pid should exist") as u32,
        first_forward_pid
    );
    wait_for_state_status(
        &run.run_root,
        "kind_local",
        "running",
        Duration::from_secs(120),
    );

    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(
        &run.site_artifact_dir("kind_local"),
        "a_http",
        proxy_port,
        &proxy_args,
    );
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/id", Duration::from_secs(120)),
        "A"
    );
    stop_proxy(&mut proxy);
    run.stop();
}
