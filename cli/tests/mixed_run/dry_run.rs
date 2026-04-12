use super::*;

#[test]
fn mixed_run_dry_run_requires_unstable_options() {
    let temp = temp_output_dir("mixed-run-dry-run-gate-");
    let fixture = write_two_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let bundle_root = temp.path().join("launch-bundle");

    let output = amber_command()
        .arg("run")
        .arg(&fixture.manifest)
        .arg("--placement")
        .arg(&fixture.placement)
        .arg("--storage-root")
        .arg(&storage_root)
        .arg("--dry-run")
        .arg("--emit-launch-bundle")
        .arg(&bundle_root)
        .output()
        .expect("failed to run amber run --dry-run");
    assert!(
        !output.status.success(),
        "amber run --dry-run unexpectedly succeeded without -Z \
         unstable-options\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("unstable-options"),
        "dry-run failure should explain the unstable gate\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn mixed_run_dry_run_emits_launch_bundle_without_starting_sites() {
    let temp = temp_output_dir("mixed-run-dry-run-");
    let fixture = write_two_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let bundle_root = temp.path().join("launch-bundle");

    let output = dry_run_manifest(
        &fixture.manifest,
        &fixture.placement,
        &storage_root,
        &bundle_root,
        &[],
    );
    assert!(
        output.status.success(),
        "amber run --dry-run failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        String::from_utf8_lossy(&output.stdout).trim().is_empty(),
        "amber run --dry-run should stay silent on stdout, got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let launch_bundle = read_json(&bundle_root.join("launch-bundle.json"));
    let run_plan = read_json(&bundle_root.join("run-plan.json"));
    assert_eq!(
        launch_bundle["bundle_root"].as_str(),
        Some(bundle_root.to_string_lossy().as_ref())
    );
    assert_eq!(
        launch_bundle["plan_path"].as_str(),
        Some(bundle_root.join("run-plan.json").to_string_lossy().as_ref())
    );
    assert_eq!(launch_bundle["mesh_scope"], run_plan["mesh_scope"]);
    assert_eq!(launch_bundle["assignments"], run_plan["assignments"]);
    assert_eq!(launch_bundle["startup_waves"], run_plan["startup_waves"]);
    assert!(
        launch_bundle["run_id"]
            .as_str()
            .is_some_and(|run_id| !run_id.is_empty()),
        "launch bundle should include a run id"
    );

    let direct_site = &launch_bundle["sites"]["direct_local"];
    assert_eq!(direct_site["kind"], json!("direct"));
    assert!(
        Path::new(
            direct_site["artifact_dir"]
                .as_str()
                .expect("launch bundle should record direct artifact dir")
        )
        .join("direct-plan.json")
        .is_file(),
        "dry-run should materialize direct artifacts"
    );
    assert!(
        Path::new(
            direct_site["supervisor_plan_path"]
                .as_str()
                .expect("launch bundle should record direct supervisor plan path")
        )
        .is_file(),
        "dry-run should materialize direct supervisor plan"
    );
    assert!(
        Path::new(
            direct_site["desired_links_path"]
                .as_str()
                .expect("launch bundle should record direct desired-links path")
        )
        .is_file(),
        "dry-run should materialize direct desired-links file"
    );
    assert!(
        !direct_site["launch_commands"]
            .as_array()
            .expect("direct launch commands should serialize as an array")
            .is_empty(),
        "dry-run should record direct launch commands"
    );
    assert!(
        !direct_site["processes"]
            .as_array()
            .expect("direct process previews should serialize as an array")
            .is_empty(),
        "dry-run should record direct process previews"
    );
    assert!(
        Path::new(
            direct_site["artifact_dir"]
                .as_str()
                .expect("launch bundle should record direct artifact dir")
        )
        .join(".amber")
        .join("direct-runtime.json")
        .is_file(),
        "dry-run should materialize reusable direct runtime state"
    );

    let compose_site = &launch_bundle["sites"]["compose_local"];
    assert_eq!(compose_site["kind"], json!("compose"));
    assert!(
        Path::new(
            compose_site["artifact_dir"]
                .as_str()
                .expect("launch bundle should record compose artifact dir")
        )
        .join("compose.yaml")
        .is_file(),
        "dry-run should materialize compose artifacts"
    );
    assert!(
        Path::new(
            compose_site["supervisor_plan_path"]
                .as_str()
                .expect("launch bundle should record compose supervisor plan path")
        )
        .is_file(),
        "dry-run should materialize compose supervisor plan"
    );
    assert!(
        Path::new(
            compose_site["desired_links_path"]
                .as_str()
                .expect("launch bundle should record compose desired-links path")
        )
        .is_file(),
        "dry-run should materialize compose desired-links file"
    );
    assert!(
        !compose_site["launch_commands"]
            .as_array()
            .expect("compose launch commands should serialize as an array")
            .is_empty(),
        "dry-run should record compose launch commands"
    );
    let stitching = launch_bundle["stitching"]
        .as_array()
        .expect("launch bundle stitching should serialize as an array");
    assert_eq!(stitching.len(), 1);
    assert_eq!(stitching[0]["provider_site"], json!("compose_local"));
    assert_eq!(stitching[0]["consumer_site"], json!("direct_local"));
    assert_eq!(
        stitching[0]["resolution"],
        json!("requires_runtime_discovery")
    );
    assert!(
        stitching[0]["unresolved_reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("Docker")),
        "compose-backed stitching should explain why the exact external URL is not known"
    );

    let direct_desired_links = read_json(
        &bundle_root
            .join("state")
            .join("direct_local")
            .join("desired-links.json"),
    );
    let direct_desired_links = direct_desired_links
        .as_object()
        .expect("desired-links.json should contain an object");
    assert!(
        !direct_desired_links.contains_key("external_slots"),
        "dry-run should not pre-register external slot URLs"
    );
    assert!(
        !direct_desired_links.contains_key("export_peers"),
        "dry-run should not pre-register export peers"
    );

    assert!(
        !bundle_root.join("receipt.json").exists(),
        "dry-run should not write a run receipt"
    );
    assert!(
        !storage_root.join("runs").exists(),
        "dry-run should not allocate a live run under the storage root"
    );
}

#[test]
fn mixed_run_noninteractive_manifest_reports_missing_runtime_inputs() {
    let temp = temp_output_dir("mixed-run-runtime-inputs-missing-");
    let fixture = copy_documented_mixed_site_fixture(temp.path());
    let storage_root = temp.path().join("state");

    let output = amber_command()
        .arg("run")
        .arg(&fixture.manifest)
        .arg("--placement")
        .arg(&fixture.placement)
        .arg("--storage-root")
        .arg(&storage_root)
        .output()
        .expect("failed to run amber run for documented mixed-site example");

    assert!(
        !output.status.success(),
        "amber run unexpectedly succeeded without required runtime \
         inputs\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "missing-input failure should not write stdout, got:\n{}",
        String::from_utf8_lossy(&output.stdout)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    for needle in [
        "missing required runtime inputs",
        "AMBER_CONFIG_TENANT",
        "AMBER_CONFIG_CATALOG_TOKEN",
    ] {
        assert!(
            stderr.contains(needle),
            "missing-input failure should mention `{needle}`\nstderr:\n{stderr}"
        );
    }
    assert!(
        !storage_root.join("runs").exists(),
        "missing-input failure should not allocate a run root"
    );
}

#[test]
fn mixed_run_emit_env_file_writes_annotated_template() {
    let temp = temp_output_dir("mixed-run-emit-env-file-");
    let fixture = copy_documented_mixed_site_fixture(temp.path());
    let output_path = temp.path().join("runtime.env");

    let output = amber_command()
        .arg("run")
        .arg(&fixture.manifest)
        .arg("--placement")
        .arg(&fixture.placement)
        .arg("--emit-env-file")
        .arg(&output_path)
        .output()
        .expect("failed to run amber run --emit-env-file");

    assert!(
        output.status.success(),
        "amber run --emit-env-file failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = fs::read_to_string(&output_path).expect("read emitted env file");
    for needle in [
        "Runtime inputs for `amber run --env-file`",
        "AMBER_CONFIG_TENANT",
        "AMBER_CONFIG_CATALOG_TOKEN",
        "AMBER_EXTERNAL_SLOT_CATALOG_API_URL",
        "AMBER_CONFIG_FILE_CATALOG_TOKEN",
    ] {
        assert!(
            rendered.contains(needle),
            "emitted env file should mention `{needle}`\n{rendered}"
        );
    }
}

#[test]
fn mixed_run_dry_run_accepts_runtime_inputs_from_env_file() {
    let temp = temp_output_dir("mixed-run-runtime-inputs-env-file-");
    let fixture = copy_documented_mixed_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let bundle_root = temp.path().join("launch-bundle");
    let env_file = temp.path().join("runtime.env");
    fs::write(
        &env_file,
        "\
AMBER_CONFIG_TENANT=acme-local\n\
AMBER_CONFIG_CATALOG_TOKEN=demo-token\n\
AMBER_EXTERNAL_SLOT_CATALOG_API_URL=http://127.0.0.1:9100\n",
    )
    .expect("failed to write runtime env file");

    let output = amber_command()
        .arg("run")
        .arg("-Z")
        .arg("unstable-options")
        .arg(&fixture.manifest)
        .arg("--placement")
        .arg(&fixture.placement)
        .arg("--storage-root")
        .arg(&storage_root)
        .arg("--env-file")
        .arg(&env_file)
        .arg("--dry-run")
        .arg("--emit-launch-bundle")
        .arg(&bundle_root)
        .output()
        .expect("failed to run amber run --dry-run with --env-file");

    assert!(
        output.status.success(),
        "amber run --dry-run with --env-file failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let compose_supervisor_plan = fs::read_to_string(
        bundle_root
            .join("state")
            .join("compose_local")
            .join("site-supervisor-plan.json"),
    )
    .expect("failed to read compose site-supervisor-plan.json from launch bundle");
    assert!(
        compose_supervisor_plan.contains("AMBER_CONFIG_TENANT"),
        "dry-run launch bundle should include supplied root config in the compose supervisor plan"
    );
    assert!(
        compose_supervisor_plan.contains("acme-local"),
        "dry-run launch bundle should materialize supplied root config values"
    );
}

#[test]
fn mixed_run_dry_run_accepts_runtime_inputs_from_config_file_flag() {
    let temp = temp_output_dir("mixed-run-runtime-inputs-config-file-");
    let fixture = copy_documented_mixed_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let bundle_root = temp.path().join("launch-bundle");
    let env_file = temp.path().join("runtime.env");
    let secret_file = temp.path().join("catalog-token.txt");
    fs::write(
        &env_file,
        "\
AMBER_CONFIG_TENANT=acme-local\nAMBER_EXTERNAL_SLOT_CATALOG_API_URL=http://127.0.0.1:9100\n\
         ",
    )
    .expect("failed to write runtime env file");
    fs::write(&secret_file, "demo-token\n").expect("failed to write secret file");

    let output = amber_command()
        .arg("run")
        .arg("-Z")
        .arg("unstable-options")
        .arg(&fixture.manifest)
        .arg("--placement")
        .arg(&fixture.placement)
        .arg("--storage-root")
        .arg(&storage_root)
        .arg("--env-file")
        .arg(&env_file)
        .arg("--config-file")
        .arg(format!("catalog_token={}", secret_file.display()))
        .arg("--dry-run")
        .arg("--emit-launch-bundle")
        .arg(&bundle_root)
        .output()
        .expect("failed to run amber run --dry-run with --config-file");

    assert!(
        output.status.success(),
        "amber run --dry-run with --config-file failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let compose_supervisor_plan = fs::read_to_string(
        bundle_root
            .join("state")
            .join("compose_local")
            .join("site-supervisor-plan.json"),
    )
    .expect("failed to read compose site-supervisor-plan.json from launch bundle");
    assert!(compose_supervisor_plan.contains("acme-local"));
    assert!(compose_supervisor_plan.contains("demo-token"));
}

#[test]
fn mixed_run_dry_run_accepts_runtime_inputs_from_file_env_vars() {
    let temp = temp_output_dir("mixed-run-runtime-inputs-file-env-var-");
    let fixture = copy_documented_mixed_site_fixture(temp.path());
    let storage_root = temp.path().join("state");
    let bundle_root = temp.path().join("launch-bundle");
    let env_file = temp.path().join("runtime.env");
    let secret_file = temp.path().join("catalog-token.txt");
    fs::write(&secret_file, "demo-token\n").expect("failed to write secret file");
    fs::write(
        &env_file,
        "\
AMBER_CONFIG_TENANT=acme-local\n\
AMBER_CONFIG_FILE_CATALOG_TOKEN=./catalog-token.txt\n\
AMBER_EXTERNAL_SLOT_CATALOG_API_URL=http://127.0.0.1:9100\n",
    )
    .expect("failed to write runtime env file");

    let output = amber_command()
        .arg("run")
        .arg("-Z")
        .arg("unstable-options")
        .arg(&fixture.manifest)
        .arg("--placement")
        .arg(&fixture.placement)
        .arg("--storage-root")
        .arg(&storage_root)
        .arg("--env-file")
        .arg(&env_file)
        .arg("--dry-run")
        .arg("--emit-launch-bundle")
        .arg(&bundle_root)
        .output()
        .expect("failed to run amber run --dry-run with AMBER_CONFIG_FILE_*");

    assert!(
        output.status.success(),
        "amber run --dry-run with AMBER_CONFIG_FILE_* failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let compose_supervisor_plan = fs::read_to_string(
        bundle_root
            .join("state")
            .join("compose_local")
            .join("site-supervisor-plan.json"),
    )
    .expect("failed to read compose site-supervisor-plan.json from launch bundle");
    assert!(compose_supervisor_plan.contains("acme-local"));
    assert!(compose_supervisor_plan.contains("demo-token"));
}

#[test]
fn mixed_run_dry_run_tolerates_unresolved_vm_preview_config() {
    let temp = temp_output_dir("mixed-run-dry-run-vm-preview-");
    let bundle_root = temp.path().join("launch-bundle");
    let manifest = workspace_root().join("examples/vm-network-storage/scenario.json5");

    let output = amber_command()
        .arg("run")
        .arg("-Z")
        .arg("unstable-options")
        .arg(&manifest)
        .arg("--dry-run")
        .arg("--emit-launch-bundle")
        .arg(&bundle_root)
        .output()
        .expect("failed to run amber run --dry-run for mixed-site example");
    assert!(
        output.status.success(),
        "amber run --dry-run should tolerate unresolved VM preview \
         config\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let launch_bundle = read_json(&bundle_root.join("launch-bundle.json"));
    let vm_site = launch_bundle["sites"]
        .as_object()
        .and_then(|sites| sites.values().find(|site| site["kind"] == json!("vm")))
        .expect("launch bundle should contain a vm site");
    assert!(
        vm_site["virtual_machines"]
            .as_array()
            .is_some_and(|machines| !machines.is_empty()),
        "vm site should still emit VM launch previews"
    );
    let first_vm = &vm_site["virtual_machines"][0];
    assert!(
        first_vm["command"]
            .as_array()
            .is_some_and(|command| !command.is_empty()),
        "vm preview should keep the exact QEMU command when only the base image is unresolved"
    );
    assert!(
        first_vm.get("base_image").is_none(),
        "vm preview should omit unresolved base_image paths instead of inventing one"
    );
    assert!(
        first_vm["unresolved_fields"]
            .as_array()
            .is_some_and(|issues| {
                issues.iter().any(|issue| {
                    issue["field"] == json!("base_image")
                        && issue["detail"]
                            .as_str()
                            .is_some_and(|detail| detail.contains("base_image"))
                })
            }),
        "vm preview should explain which launch field remains unresolved"
    );
}
