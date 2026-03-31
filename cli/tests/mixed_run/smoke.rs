use super::*;

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_proxy_attaches_by_run_id_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-proxy-run-id-");
    let fixture = write_two_site_fixture(temp.path());

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let proxy_port = pick_free_port();
    let proxy_args = vec![
        "--storage-root".to_string(),
        storage_root.display().to_string(),
    ];
    let mut proxy = spawn_proxy_target(&run.run_id, "a_http", proxy_port, &proxy_args);
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/call/b", Duration::from_secs(60)),
        "B"
    );
    stop_proxy(&mut proxy);

    run.stop();
    assert!(
        !run.run_root.join("receipt.json").exists(),
        "receipt should be removed after amber stop"
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_direct_compose_proxy_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-two-site-");
    let fixture = write_two_site_fixture(temp.path());

    let storage_root = temp.path().join("state");
    let mut run = run_manifest(&fixture.manifest, &fixture.placement, &storage_root);

    let run_plan: Value = serde_json::from_slice(
        &fs::read(run.run_root.join("run-plan.json")).expect("failed to read run-plan.json"),
    )
    .expect("run-plan.json should be valid JSON");
    assert_eq!(
        run_plan["startup_waves"],
        json!([["compose_local"], ["direct_local"]])
    );
    assert_eq!(
        run.receipt["sites"]
            .as_object()
            .expect("receipt sites should be an object")
            .len(),
        2
    );

    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    let body = wait_for_body(&mut proxy, proxy_port, "/call/b", Duration::from_secs(60));
    assert_eq!(body, "B");
    stop_proxy(&mut proxy);

    run.stop();
    assert!(
        !run.run_root.join("receipt.json").exists(),
        "receipt should be removed after amber stop"
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_detached_stop_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-detach-");
    let fixture = write_two_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_detached(&fixture.manifest, &fixture.placement, &storage_root);

    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/call/b", Duration::from_secs(60)),
        "B"
    );
    stop_proxy(&mut proxy);

    run.stop();
    wait_for_condition(
        Duration::from_secs(30),
        || !run.run_root.join("receipt.json").exists(),
        "detached run receipt removal",
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_documented_example_detached_stop_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-doc-example-detach-");
    let fixture = copy_documented_mixed_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let catalog = HostHttpServer::start();
    let catalog_url = docker_host_http_url(catalog.port())
        .trim_end_matches('/')
        .to_string();
    let runtime_env = [
        ("AMBER_CONFIG_TENANT", "acme-local"),
        ("AMBER_CONFIG_CATALOG_TOKEN", "demo-token"),
        ("AMBER_EXTERNAL_SLOT_CATALOG_API_URL", catalog_url.as_str()),
    ];
    let mut run = run_manifest_with_args_and_env(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &["--detach"],
        &runtime_env,
    );

    let direct_state = wait_for_state_status(
        &run.run_root,
        "direct_local",
        "running",
        Duration::from_secs(30),
    );
    let compose_state = wait_for_state_status(
        &run.run_root,
        "compose_local",
        "running",
        Duration::from_secs(30),
    );
    let direct_pid = direct_state["process_pid"]
        .as_u64()
        .expect("direct process pid should be present") as u32;
    let compose_project = compose_state["compose_project"]
        .as_str()
        .expect("compose project should be present")
        .to_string();

    let proxy_port = pick_free_port();
    let proxy_args = vec![
        "--storage-root".to_string(),
        storage_root.display().to_string(),
    ];
    let mut proxy = spawn_proxy_target(&run.run_id, "app", proxy_port, &proxy_args);
    wait_for_path(&mut proxy, proxy_port, "/chain", Duration::from_secs(60));
    let body = wait_for_body(&mut proxy, proxy_port, "/chain", Duration::from_secs(60));
    assert!(
        body.contains("\"site\": \"direct\""),
        "documented example should return the direct web response, got:\n{body}"
    );
    assert!(
        body.contains("\"item\": \"amber mug\""),
        "documented example should reach the outside catalog service, got:\n{body}"
    );
    stop_proxy(&mut proxy);

    run.stop();
    wait_for_condition(
        Duration::from_secs(30),
        || !run.run_root.join("receipt.json").exists(),
        "documented example detached run receipt removal",
    );
    wait_for_condition(
        Duration::from_secs(30),
        || !pid_is_alive(direct_pid),
        "documented example direct process exit",
    );
    wait_for_condition(
        Duration::from_secs(30),
        || {
            compose_ps_ids_with_env(
                &compose_project,
                &run.site_artifact_dir("compose_local"),
                &runtime_env,
            )
            .is_empty()
        },
        "documented example compose teardown",
    );
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_local_observability_scenario_smoke() {
    ensure_internal_images();
    let temp = temp_output_dir("mixed-run-obsv-scenario-");
    let fixture = write_two_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_args(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &["--observability", "local"],
    );

    let requests_log = PathBuf::from(
        run.receipt["observability"]["requests_log"]
            .as_str()
            .expect("run receipt should contain observability log"),
    );
    wait_for_text(&requests_log, "/v1/logs", Duration::from_secs(60));
    let before_lines = fs::read_to_string(&requests_log)
        .unwrap_or_default()
        .lines()
        .count();
    let direct_artifact = run.site_artifact_dir("direct_local");
    let proxy_port = pick_free_port();
    let mut proxy = spawn_proxy(&direct_artifact, "a_http", proxy_port, &[]);
    wait_for_path(&mut proxy, proxy_port, "/id", Duration::from_secs(60));
    assert_eq!(
        wait_for_body(&mut proxy, proxy_port, "/call/b", Duration::from_secs(60)),
        "B"
    );
    wait_for_condition(
        Duration::from_secs(60),
        || {
            fs::read_to_string(&requests_log)
                .map(|contents| contents.lines().count() > before_lines)
                .unwrap_or(false)
        },
        "scenario telemetry after routed traffic",
    );
    stop_proxy(&mut proxy);
    run.stop();
}

#[test]
#[ignore = "requires docker; run manually or in CI"]
fn mixed_run_local_observability_manager_smoke() {
    let temp = temp_output_dir("mixed-run-obsv-manager-");
    let fixture = write_single_site_direct_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let mut run = run_manifest_with_args(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &["--observability", "local"],
    );

    let requests_log = PathBuf::from(
        run.receipt["observability"]["requests_log"]
            .as_str()
            .expect("run receipt should contain observability log"),
    );
    wait_for_text(&requests_log, "/v1/logs", Duration::from_secs(60));
    let before = fs::read_to_string(&requests_log).unwrap_or_default();
    let before_lines = before.lines().count();
    run.stop();
    wait_for_condition(
        Duration::from_secs(30),
        || {
            fs::read_to_string(&requests_log)
                .map(|contents| contents.lines().count() > before_lines)
                .unwrap_or(false)
        },
        "site-manager stop logs",
    );
}
