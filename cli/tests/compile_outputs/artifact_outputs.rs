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
    assert_eq!(primary_json["version"], 5);
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
        components
            .iter()
            .all(|component| component.get("source_dir").is_some()),
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

#[test]
fn compile_writes_vm_artifact() {
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

    if !output.status.success() {
        panic!(
            "amber compile --vm failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let vm_plan_path = artifact_dir.join(VM_PLAN_FILENAME);
    let provision_plan_path = artifact_dir.join("mesh-provision-plan.json");
    let run_script_path = artifact_dir.join("run.sh");
    let readme_path = artifact_dir.join("README.md");
    let env_example_path = artifact_dir.join("env.example");
    let proxy_metadata_path = artifact_dir.join("amber-proxy.json");

    assert!(vm_plan_path.is_file(), "missing vm-plan.json");
    assert!(
        provision_plan_path.is_file(),
        "missing mesh-provision-plan.json"
    );
    assert!(run_script_path.is_file(), "missing run.sh");
    assert!(readme_path.is_file(), "missing README.md");
    assert!(env_example_path.is_file(), "missing env.example");
    assert!(proxy_metadata_path.is_file(), "missing amber-proxy.json");

    let vm_plan: Value = serde_json::from_str(
        &fs::read_to_string(&vm_plan_path).expect("failed to read vm-plan.json"),
    )
    .expect("vm-plan.json should be valid JSON");
    assert_eq!(vm_plan["version"], VM_PLAN_VERSION);
    assert_eq!(vm_plan["mesh_provision_plan"], "mesh-provision-plan.json");
    let components = vm_plan["components"]
        .as_array()
        .expect("vm plan components should be an array");
    assert_eq!(components.len(), 1, "{vm_plan:#}");
    assert_eq!(components[0]["base_image"]["kind"], "runtime_config");
    assert_eq!(components[0]["base_image"]["query"], "base_image");
    assert_eq!(components[0]["cpus"]["kind"], "literal");
    assert_eq!(components[0]["cpus"]["value"], 1);
    assert_eq!(components[0]["memory_mib"]["kind"], "literal");
    assert_eq!(components[0]["memory_mib"]["value"], 512);
    let component = components[0]
        .as_object()
        .expect("vm component should serialize as an object");
    let allowed_root_leaf_paths = component["runtime_config"]["allowed_root_leaf_paths"]
        .as_array()
        .expect("runtime_config.allowed_root_leaf_paths should be an array")
        .iter()
        .map(|value| value.as_str().expect("allowed path should be a string"))
        .collect::<Vec<_>>();
    assert!(
        component.contains_key("runtime_config"),
        "vm component should carry runtime_config when the base image depends on runtime config"
    );
    assert_eq!(allowed_root_leaf_paths, vec!["base_image"]);
    assert!(
        !component.contains_key("mount_spec_b64"),
        "vm component should omit mount_spec_b64 when it is unused"
    );

    let readme = fs::read_to_string(&readme_path).expect("failed to read vm README");
    assert!(
        readme.contains("amber run ."),
        "vm README should explain how to start the output"
    );
    let env_example = fs::read_to_string(&env_example_path).expect("failed to read vm env example");
    assert!(
        env_example.contains("AMBER_CONFIG_BASE_IMAGE"),
        "vm env example should mention runtime config for the base image"
    );

    let proxy_metadata: Value = serde_json::from_str(
        &fs::read_to_string(&proxy_metadata_path).expect("failed to read vm proxy metadata"),
    )
    .expect("vm proxy metadata should be valid JSON");
    assert_eq!(
        proxy_metadata["router"]["control_socket"].as_str(),
        Some(DIRECT_CONTROL_SOCKET_RELATIVE_PATH)
    );
    assert_eq!(proxy_metadata["router"]["control_port"].as_u64(), Some(0));
}

#[test]
fn compile_vm_artifact_supports_runtime_templates() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("vm-runtime-template-")
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
      base_image: { type: "string" },
      message: { type: "string" }
    },
    required: ["base_image", "message"],
    additionalProperties: false
  },
  slots: {
    api: { kind: "http", optional: true }
  },
  program: {
    vm: {
      image: "./images/${config.base_image}",
      cpus: 1,
      memory_mib: 512,
      cloud_init: {
        user_data: "#cloud-config\nwrite_files:\n  - path: /tmp/value\n    content: 'msg=${config.message};api=${slots.api.url}'\n"
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

    if !output.status.success() {
        panic!(
            "amber compile --vm failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let vm_plan_path = artifact_dir.join(VM_PLAN_FILENAME);
    let vm_plan: Value = serde_json::from_str(
        &fs::read_to_string(&vm_plan_path).expect("failed to read vm-plan.json"),
    )
    .expect("vm-plan.json should be valid JSON");
    let component = vm_plan["components"]
        .as_array()
        .and_then(|components| components.first())
        .expect("vm plan should contain one component");

    assert_eq!(component["base_image"]["kind"], "runtime_template");
    assert_eq!(component["base_image"]["parts"][0]["kind"], "literal");
    assert_eq!(component["base_image"]["parts"][0]["value"], "./images/");
    assert_eq!(
        component["base_image"]["parts"][1]["kind"],
        "runtime_config"
    );
    assert_eq!(component["base_image"]["parts"][1]["query"], "base_image");
    assert_eq!(
        component["base_image"]["source_dir"].as_str(),
        outputs_dir.path().to_str()
    );

    assert_eq!(
        component["cloud_init_user_data"]["kind"],
        "runtime_template"
    );
    let cloud_init_parts = component["cloud_init_user_data"]["parts"]
        .as_array()
        .expect("cloud-init template parts should be an array");
    assert!(
        cloud_init_parts
            .iter()
            .any(|part| part["config"] == "message"),
        "cloud-init template should retain config interpolation"
    );
    assert!(
        cloud_init_parts
            .iter()
            .any(|part| part["slot"] == "api.url"),
        "cloud-init template should retain slot interpolation"
    );
    let mut allowed_root_leaf_paths = component["runtime_config"]["allowed_root_leaf_paths"]
        .as_array()
        .expect("runtime_config.allowed_root_leaf_paths should be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("allowed_root_leaf_paths should contain strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    allowed_root_leaf_paths.sort();
    assert_eq!(
        allowed_root_leaf_paths,
        vec!["base_image".to_string(), "message".to_string()]
    );
}

#[test]
fn compile_vm_artifact_resolves_static_child_config_for_scalars_and_cloud_init() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("vm-static-child-config-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let child_manifest = outputs_dir.path().join("child.json5");
    fs::write(
        &child_manifest,
        r##"{
  manifest_version: "0.1.0",
  config_schema: {
    type: "object",
    properties: {
      image: { type: "string" },
      cpu_count: { type: "integer" },
      memory: { type: "integer" },
      banner: { type: "string" }
    },
    required: ["image", "cpu_count", "memory", "banner"],
    additionalProperties: false
  },
  program: {
    vm: {
      image: "${config.image}",
      cpus: "${config.cpu_count}",
      memory_mib: "${config.memory}",
      cloud_init: {
        user_data: "#cloud-config\nwrite_files:\n  - path: /tmp/banner\n    content: '${config.banner}'\n"
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
    .expect("failed to write child manifest");

    let root_manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &root_manifest,
        format!(
            r##"{{
  manifest_version: "0.1.0",
  components: {{
    child: {{
      manifest: "{}",
      config: {{
        image: "./images/base.qcow2",
        cpu_count: 3,
        memory: 1536,
        banner: "hello from parent"
      }}
    }}
  }},
  exports: {{
    http: "#child.http"
  }}
}}
"##,
            child_manifest.display()
        ),
    )
    .expect("failed to write root manifest");

    let artifact_dir = outputs_dir.path().join("vm");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--vm")
        .arg(&artifact_dir)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --vm: {err}"));

    if !output.status.success() {
        panic!(
            "amber compile --vm failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let vm_plan: Value = serde_json::from_str(
        &fs::read_to_string(artifact_dir.join(VM_PLAN_FILENAME))
            .expect("failed to read vm-plan.json"),
    )
    .expect("vm-plan.json should be valid JSON");
    let component = vm_plan["components"]
        .as_array()
        .and_then(|components| components.first())
        .expect("vm plan should contain one component");

    assert_eq!(component["base_image"]["kind"], "static");
    assert_eq!(component["cpus"]["kind"], "literal");
    assert_eq!(component["cpus"]["value"], 3);
    assert_eq!(component["memory_mib"]["kind"], "literal");
    assert_eq!(component["memory_mib"]["value"], 1536);
    assert_eq!(component["cloud_init_user_data"]["kind"], "static");
    assert!(
        component["cloud_init_user_data"]["value"]
            .as_str()
            .is_some_and(|value| value.contains("hello from parent")),
        "{component:#}"
    );
    let component = component
        .as_object()
        .expect("vm component should serialize as an object");
    assert!(
        !component.contains_key("runtime_config"),
        "static child config should not force runtime_config"
    );
}

#[test]
fn compile_vm_artifact_rewrites_runtime_scalar_paths_through_child_config() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("vm-runtime-child-config-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let child_manifest = outputs_dir.path().join("child.json5");
    fs::write(
        &child_manifest,
        r##"{
  manifest_version: "0.1.0",
  config_schema: {
    type: "object",
    properties: {
      image: { type: "string" },
      cpu_count: { type: "integer" },
      memory: { type: "integer" }
    },
    required: ["image", "cpu_count", "memory"],
    additionalProperties: false
  },
  program: {
    vm: {
      image: "${config.image}",
      cpus: "${config.cpu_count}",
      memory_mib: "${config.memory}",
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
    .expect("failed to write child manifest");

    let root_manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &root_manifest,
        format!(
            r##"{{
  manifest_version: "0.1.0",
  config_schema: {{
    type: "object",
    properties: {{
      vm: {{
        type: "object",
        properties: {{
          image: {{ type: "string" }},
          cpu: {{ type: "integer" }},
          memory: {{ type: "integer" }}
        }},
        required: ["image", "cpu", "memory"],
        additionalProperties: false
      }}
    }},
    required: ["vm"],
    additionalProperties: false
  }},
  components: {{
    child: {{
      manifest: "{}",
      config: {{
        image: "${{config.vm.image}}",
        cpu_count: "${{config.vm.cpu}}",
        memory: "${{config.vm.memory}}"
      }}
    }}
  }},
  exports: {{
    http: "#child.http"
  }}
}}
"##,
            child_manifest.display()
        ),
    )
    .expect("failed to write root manifest");

    let artifact_dir = outputs_dir.path().join("vm");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--vm")
        .arg(&artifact_dir)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --vm: {err}"));

    if !output.status.success() {
        panic!(
            "amber compile --vm failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let vm_plan: Value = serde_json::from_str(
        &fs::read_to_string(artifact_dir.join(VM_PLAN_FILENAME))
            .expect("failed to read vm-plan.json"),
    )
    .expect("vm-plan.json should be valid JSON");
    let component = vm_plan["components"]
        .as_array()
        .and_then(|components| components.first())
        .expect("vm plan should contain one component");

    assert_eq!(component["base_image"]["kind"], "runtime_config");
    assert_eq!(component["base_image"]["query"], "image");
    assert_eq!(component["cpus"]["kind"], "runtime_config");
    assert_eq!(component["cpus"]["query"], "cpu_count");
    assert_eq!(component["memory_mib"]["kind"], "runtime_config");
    assert_eq!(component["memory_mib"]["query"], "memory");
    let mut allowed_root_leaf_paths = component["runtime_config"]["allowed_root_leaf_paths"]
        .as_array()
        .expect("runtime_config.allowed_root_leaf_paths should be an array")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("allowed_root_leaf_paths should contain strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    allowed_root_leaf_paths.sort();
    assert_eq!(
        allowed_root_leaf_paths,
        vec![
            "vm.cpu".to_string(),
            "vm.image".to_string(),
            "vm.memory".to_string(),
        ]
    );
    assert!(
        component.get("runtime_config").is_some(),
        "runtime child config should carry runtime_config payload"
    );
    let env_example = fs::read_to_string(artifact_dir.join("env.example"))
        .expect("failed to read vm env example");
    assert!(
        env_example.contains("AMBER_CONFIG_VM__IMAGE"),
        "vm env example should mention runtime config for the forwarded base image"
    );
    assert!(
        env_example.contains("AMBER_CONFIG_VM__CPU"),
        "vm env example should mention runtime config for the forwarded cpu count"
    );
    assert!(
        env_example.contains("AMBER_CONFIG_VM__MEMORY"),
        "vm env example should mention runtime config for the forwarded memory size"
    );
}

#[test]
fn check_rejects_invalid_vm_scalar_config_ref() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("vm-invalid-scalar-check-")
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
      image: { type: "string" }
    },
    required: ["image"],
    additionalProperties: false
  },
  program: {
    vm: {
      image: "${config.image}",
      cpus: "${config.missing}",
      memory_mib: 512,
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

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("check")
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber check: {err}"));

    assert!(
        !output.status.success(),
        "amber check unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("program.vm.cpus"),
        "expected program.vm.cpus in stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("config.missing"),
        "expected missing config path in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_compose_rejects_whole_config_program_image_ref() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("program-image-whole-config-check-")
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
      image: { type: "string" }
    }
  },
  program: {
    image: "${config}",
    entrypoint: ["run"],
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

    let artifact_dir = outputs_dir.path().join("compose");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--docker-compose")
        .arg(&artifact_dir)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --docker-compose: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --docker-compose unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("program.image cannot")
            && stderr.contains("reference the entire runtime config object"),
        "expected whole-config image rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_vm_rejects_whole_config_vm_image_ref() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("vm-image-whole-config-check-")
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
      image: { type: "string" }
    }
  },
  program: {
    vm: {
      image: "${config}",
      cpus: 1,
      memory_mib: 512,
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

    assert!(
        !output.status.success(),
        "amber compile --vm unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("program.vm.image cannot")
            && stderr.contains("reference the entire runtime config object"),
        "expected whole-config vm image rejection in stderr, got:\n{stderr}"
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
