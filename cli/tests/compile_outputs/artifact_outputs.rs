use amber_scenario::SCENARIO_IR_VERSION;

use super::*;

#[test]
fn compile_writes_primary_output_and_dot_artifact() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");
    let manifest = workspace_root
        .join("examples")
        .join("reexport")
        .join("scenario.json");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("outputs-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let primary_output = outputs_dir.path().join("scenario");
    let dot_output = outputs_dir.path().join("scenario.dot");
    let compose_output_dir = outputs_dir.path().join("scenario.compose");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&primary_output)
        .arg("--dot")
        .arg(&dot_output)
        .arg("--docker-compose")
        .arg(&compose_output_dir)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile: {err}"));

    if !output.status.success() {
        panic!(
            "amber compile failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    assert!(
        primary_output.is_file(),
        "expected primary output file at {}",
        primary_output.display()
    );
    let primary_contents =
        fs::read_to_string(&primary_output).expect("failed to read primary output file");
    let primary_json: Value =
        serde_json::from_str(&primary_contents).expect("primary output did not contain valid JSON");
    assert_eq!(primary_json["schema"], "amber.scenario.ir");
    assert_eq!(primary_json["version"], SCENARIO_IR_VERSION);
    assert_eq!(primary_json["root"], 0);

    let components = primary_json["components"]
        .as_array()
        .expect("components should be a JSON array");
    assert!(
        components.iter().any(|c| c["moniker"] == "/"),
        "scenario IR missing root component"
    );
    assert!(
        components.iter().any(|c| c["moniker"] == "/parent/child"),
        "scenario IR missing child component"
    );
    for component in components {
        assert!(
            component.get("program").is_some(),
            "scenario IR missing component program field"
        );
        assert!(
            component.get("slots").is_some(),
            "scenario IR missing component slots field"
        );
        assert!(
            component.get("provides").is_some(),
            "scenario IR missing component provides field"
        );
    }

    let child_component = components
        .iter()
        .find(|c| c["moniker"] == "/parent/child")
        .expect("child component should exist");
    let child_program = child_component["program"]
        .as_object()
        .expect("child program should be an object");
    assert_eq!(
        child_program.get("image").and_then(Value::as_str),
        Some("busybox:stable")
    );
    let child_slots = child_component["slots"]
        .as_object()
        .expect("child slots should be an object");
    assert!(child_slots.is_empty(), "expected child slots to be empty");
    let child_provides = child_component["provides"]
        .as_object()
        .expect("child provides should be an object");
    assert!(
        child_provides.contains_key("cap"),
        "child provides missing cap"
    );
    assert_eq!(child_component["provides"]["cap"]["kind"], "http");
    assert_eq!(child_component["provides"]["cap"]["endpoint"], "endpoint");

    let exports = primary_json["exports"]
        .as_array()
        .expect("exports should be a JSON array");
    assert_eq!(exports.len(), 1, "expected one scenario export");
    assert_eq!(exports[0]["name"], "cap");
    assert_eq!(exports[0]["capability"]["kind"], "http");

    assert!(
        dot_output.is_file(),
        "expected dot output file at {}",
        dot_output.display()
    );
    let dot_contents = fs::read_to_string(&dot_output).expect("failed to read dot output file");
    assert!(
        dot_contents.contains("digraph scenario"),
        "dot output did not contain a scenario graph"
    );

    let compose_output = compose_output_dir.join("compose.yaml");
    assert!(
        compose_output.is_file(),
        "expected docker compose output file at {}",
        compose_output.display()
    );
    let compose_readme = compose_output_dir.join("README.md");
    assert!(
        compose_readme.is_file(),
        "expected docker compose README at {}",
        compose_readme.display()
    );
    let compose_readme_contents =
        fs::read_to_string(&compose_readme).expect("failed to read docker compose README");
    assert!(
        compose_readme_contents.contains("compose.yaml"),
        "docker compose README should mention the generated compose file"
    );
    assert!(
        compose_readme_contents.contains("amber proxy ."),
        "docker compose README should include proxy instructions"
    );
    let compose_env_sample = compose_output_dir.join("env.example");
    assert!(
        compose_env_sample.is_file(),
        "expected docker compose env sample at {}",
        compose_env_sample.display()
    );
    let compose_env_sample_contents =
        fs::read_to_string(&compose_env_sample).expect("failed to read docker compose env sample");
    assert!(
        compose_env_sample_contents.contains("No env-based runtime inputs are required"),
        "docker compose env sample should explain when no runtime inputs are needed"
    );
    let compose_contents =
        fs::read_to_string(&compose_output).expect("failed to read docker compose output file");
    assert!(
        compose_contents.contains("services:"),
        "docker compose output missing services section"
    );
    let compose_yaml: YamlValue =
        serde_yaml::from_str(&compose_contents).expect("docker compose output invalid yaml");
    let services = compose_yaml
        .get("services")
        .and_then(YamlValue::as_mapping)
        .expect("compose services should be a map");
    let has_router_image = services.values().any(|service| {
        service.get("image").and_then(YamlValue::as_str) == Some(AMBER_ROUTER.reference)
    });
    assert!(
        has_router_image,
        "docker compose output missing router image"
    );

    let provisioner = services
        .get("amber-provisioner")
        .expect("compose missing provisioner service");
    assert_eq!(
        env_value(provisioner, "AMBER_MESH_PROVISION_PLAN_PATH").as_deref(),
        Some("/amber/plan/mesh-provision-plan.json")
    );
    assert!(env_value(provisioner, "AMBER_MESH_PROVISION_PLAN_B64").is_none());

    let configs = provisioner
        .get("configs")
        .and_then(YamlValue::as_sequence)
        .expect("provisioner configs should be a list");
    assert!(
        configs.iter().any(|c| {
            c.get("source").and_then(YamlValue::as_str) == Some("amber-mesh-provision-plan")
                && c.get("target").and_then(YamlValue::as_str)
                    == Some("/amber/plan/mesh-provision-plan.json")
        }),
        "provisioner missing plan config mount"
    );

    let configs = compose_yaml
        .get("configs")
        .and_then(YamlValue::as_mapping)
        .expect("compose configs should be a map");
    let plan_config = configs
        .get("amber-mesh-provision-plan")
        .and_then(YamlValue::as_mapping)
        .expect("compose missing plan config");
    let plan_json = plan_config
        .get("content")
        .and_then(YamlValue::as_str)
        .expect("plan config missing content");
    serde_json::from_str::<Value>(plan_json).expect("plan config content should be JSON");
}

#[test]
fn compile_unmanaged_export_rejects_placement_file() {
    let outputs_dir = cli_test_outputs_dir("single-site-export-placement-rejects-");
    let fixture = write_single_image_fixture(outputs_dir.path(), "kind_local", "kubernetes");
    let kubernetes_output = outputs_dir.path().join("kubernetes");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--placement")
        .arg(&fixture.placement)
        .arg("--kubernetes")
        .arg(&kubernetes_output)
        .arg(&fixture.manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --kubernetes: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --kubernetes unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("do not accept `--placement`"),
        "expected placement rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_unmanaged_export_rejects_non_exportable_program_mix() {
    let outputs_dir = cli_test_outputs_dir("mixed-export-kind-rejects-");
    let fixture = write_mixed_site_fixture(outputs_dir.path());
    let compose_output = outputs_dir.path().join("compose");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--docker-compose")
        .arg(&compose_output)
        .arg(&fixture.manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --docker-compose: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --docker-compose unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Compose sites") && stderr.contains("only support program.image workloads"),
        "expected homogeneous export rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_unmanaged_export_uses_requested_backend_without_placement() {
    let outputs_dir = cli_test_outputs_dir("single-site-kubernetes-export-");
    let fixture = write_single_image_fixture(outputs_dir.path(), "kind_local", "kubernetes");

    let compose_output = outputs_dir.path().join("compose");
    let compose_attempt = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--docker-compose")
        .arg(&compose_output)
        .arg(&fixture.manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --docker-compose: {err}"));

    assert!(
        compose_attempt.status.success(),
        "amber compile --docker-compose failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        compose_attempt.status,
        String::from_utf8_lossy(&compose_attempt.stdout),
        String::from_utf8_lossy(&compose_attempt.stderr)
    );
    assert!(
        compose_output.join("compose.yaml").is_file(),
        "expected compose.yaml in {}",
        compose_output.display()
    );

    let kubernetes_output = outputs_dir.path().join("kubernetes");
    let kubernetes_attempt = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--kubernetes")
        .arg(&kubernetes_output)
        .arg(&fixture.manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --kubernetes: {err}"));

    assert!(
        kubernetes_attempt.status.success(),
        "amber compile --kubernetes failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        kubernetes_attempt.status,
        String::from_utf8_lossy(&kubernetes_attempt.stdout),
        String::from_utf8_lossy(&kubernetes_attempt.stderr)
    );
    assert!(
        kubernetes_output.join("kustomization.yaml").is_file(),
        "expected kustomization.yaml in {}",
        kubernetes_output.display()
    );
    assert!(
        kubernetes_output.join("README.md").is_file(),
        "expected README.md in {}",
        kubernetes_output.display()
    );
}

#[test]
fn compile_writes_direct_artifact() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");
    let manifest = workspace_root
        .join("examples")
        .join("direct-security")
        .join("scenario.json5");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-outputs-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");
    let artifact_dir = outputs_dir.path().join("direct");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&artifact_dir)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    if !output.status.success() {
        panic!(
            "amber compile --direct failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let direct_plan_path = artifact_dir.join("direct-plan.json");
    let provision_plan_path = artifact_dir.join("mesh-provision-plan.json");
    let run_script_path = artifact_dir.join("run.sh");
    assert!(direct_plan_path.is_file(), "missing direct-plan.json");
    assert!(
        provision_plan_path.is_file(),
        "missing mesh-provision-plan.json"
    );
    assert!(run_script_path.is_file(), "missing run.sh");

    let direct_plan = fs::read_to_string(&direct_plan_path).expect("failed to read direct plan");
    let direct_json: Value =
        serde_json::from_str(&direct_plan).expect("direct plan should be valid JSON");
    assert_eq!(direct_json["version"], DIRECT_PLAN_VERSION);
    let components = direct_json["components"]
        .as_array()
        .expect("direct plan components should be an array");
    assert!(
        !components.is_empty(),
        "direct plan should include at least one component"
    );
    assert!(
        components
            .iter()
            .all(|component| component.get("manifest_url").is_none()),
        "direct plan should not persist manifest_url"
    );
    assert!(
        components.iter().all(|component| {
            component["program"]["execution"]["kind"].as_str() == Some("internal_site_controller")
                || component.get("source_dir").is_some()
        }),
        "manifest-backed direct plan components should retain source_dir"
    );
    assert_eq!(
        direct_json["router"]["control_socket_path"].as_str(),
        Some(DIRECT_CONTROL_SOCKET_RELATIVE_PATH)
    );
    assert_eq!(direct_json["router"]["control_port"].as_u64(), Some(0));

    let proxy_metadata_path = artifact_dir.join("amber-proxy.json");
    let proxy_metadata =
        fs::read_to_string(&proxy_metadata_path).expect("failed to read direct proxy metadata");
    let proxy_json: Value =
        serde_json::from_str(&proxy_metadata).expect("proxy metadata should be valid JSON");
    assert_eq!(
        proxy_json["router"]["control_socket"].as_str(),
        Some(DIRECT_CONTROL_SOCKET_RELATIVE_PATH)
    );
    assert_eq!(proxy_json["router"]["control_port"].as_u64(), Some(0));
}

fn assert_vm_export_succeeded(output: &std::process::Output) {
    assert!(
        output.status.success(),
        "amber compile --vm failed
stdout:
{}
stderr:
{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn compile_vm_export_uses_default_placement() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("vm-outputs-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &manifest,
        r##"{
  manifest_version: "0.1.0",
  config_schema: {
    type: "object",
    properties: {
      base_image: { type: "string" }
    },
    required: ["base_image"],
    additionalProperties: false
  },
  program: {
    vm: {
      image: "${config.base_image}",
      cpus: 1,
      memory_mib: 512,
      cloud_init: {
        user_data: "#cloud-config\nruncmd:\n  - [sh, -lc, 'echo ready >/run/amber-ready']\n"
      },
      network: {
        endpoints: [
          { name: "http", port: 8080, protocol: "http" }
        ],
        egress: "none"
      }
    }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"##,
    )
    .expect("failed to write manifest");

    let artifact_dir = outputs_dir.path().join("vm");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--vm")
        .arg(&artifact_dir)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --vm: {err}"));

    assert_vm_export_succeeded(&output);
    assert!(
        artifact_dir.join("vm-plan.json").is_file(),
        "expected vm-plan.json in {}",
        artifact_dir.display()
    );
    assert!(
        artifact_dir.join("run.sh").is_file(),
        "expected run.sh in {}",
        artifact_dir.display()
    );
}

#[test]
fn compile_vm_export_rejects_framework_component_without_controller_site() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("vm-framework-outputs-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let admin = outputs_dir.path().join("admin.json5");
    fs::write(
        &admin,
        r##"{
  manifest_version: "0.3.0",
  slots: {
    ctl: { kind: "component" }
  },
  program: {
    path: "/bin/echo",
    args: ["admin", "${slots.ctl.url}"],
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"##,
    )
    .expect("failed to write admin manifest");

    let manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    admin: "./admin.json5"
  },
  bindings: [
    { to: "#admin.ctl", from: "framework.component" }
  ],
  exports: {
    admin_http: "#admin.http"
  }
}
"##,
    )
    .expect("failed to write root manifest");

    let artifact_dir = outputs_dir.path().join("vm");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--vm")
        .arg(&artifact_dir)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --vm: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --vm unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("explicit")
            && stderr.contains("controlling direct site")
            && stderr.contains("mixed-site placement"),
        "expected controller-site rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_direct_rejects_program_path_without_separator() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-bare-program-path-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &manifest,
        r##"{
  manifest_version: "0.1.0",
  program: {
    path: "python3",
    args: ["-m", "http.server", "8080"],
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"##,
    )
    .expect("failed to write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(outputs_dir.path().join("direct"))
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --direct unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("without a path separator") && stderr.contains("search PATH"),
        "expected PATH rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_direct_emits_storage_mounts_in_plan() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-storage-plan-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifests_dir = outputs_dir.path().join("manifests");
    fs::create_dir_all(&manifests_dir).expect("failed to create manifests directory");

    let root_manifest = manifests_dir.join("scenario.json5");
    fs::write(
        &root_manifest,
        r#"
        {
          manifest_version: "0.1.0",
          resources: {
            state: { kind: "storage" },
          },
          program: {
            path: "/bin/sh",
            args: ["-lc", "sleep 3600"],
            mounts: [
              { path: "/var/lib/app", from: "resources.state" },
            ],
            network: {
              endpoints: [
                { name: "http", port: 8080, protocol: "http" },
              ],
            },
          },
          provides: {
            http: { kind: "http", endpoint: "http" },
          },
          exports: {
            public: "http",
          },
        }
        "#,
    )
    .expect("write root manifest");

    let direct_output = outputs_dir.path().join("direct-out");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_output)
        .arg(&root_manifest)
        .output()
        .expect("failed to run amber compile --direct");
    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan: Value = serde_json::from_str(
        &fs::read_to_string(direct_output.join("direct-plan.json")).expect("read direct-plan.json"),
    )
    .expect("parse direct-plan.json");

    let mounts = plan["components"][0]["program"]["storage_mounts"]
        .as_array()
        .expect("storage mounts array");
    assert_eq!(mounts.len(), 1, "{plan:#}");
    assert_eq!(mounts[0]["mount_path"], "/var/lib/app");
    let state_subdir = mounts[0]["state_subdir"]
        .as_str()
        .expect("state_subdir should be a string");
    assert!(state_subdir.starts_with("root/state-"), "{state_subdir}");
}
