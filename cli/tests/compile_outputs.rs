use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use amber_compiler::reporter::{
    direct::{DIRECT_CONTROL_SOCKET_RELATIVE_PATH, DIRECT_PLAN_VERSION},
    vm::{VM_PLAN_FILENAME, VM_PLAN_VERSION},
};
use amber_images::AMBER_ROUTER;
use amber_manifest::ManifestDigest;
use amber_template::{
    ProgramArgTemplate, ProgramEnvTemplate, RepeatedProgramArgTemplate, RepeatedProgramEnvTemplate,
    RepeatedTemplateSource, TemplatePart, TemplateSpec,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use serde_yaml::Value as YamlValue;

fn env_value(service: &YamlValue, key: &str) -> Option<String> {
    let env = service.get("environment")?;
    match env {
        YamlValue::Mapping(map) => map
            .get(YamlValue::String(key.to_string()))
            .and_then(YamlValue::as_str)
            .map(str::to_string),
        YamlValue::Sequence(seq) => seq.iter().find_map(|entry| {
            let entry = entry.as_str()?;
            let (k, v) = entry.split_once('=')?;
            if k == key { Some(v.to_string()) } else { None }
        }),
        _ => None,
    }
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root")
        .to_path_buf()
}

fn cli_test_outputs_dir(prefix: &str) -> tempfile::TempDir {
    let outputs_root = workspace_root().join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    tempfile::Builder::new()
        .prefix(prefix)
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory")
}

fn write_fixture(path: &Path, contents: &str) {
    fs::write(path, contents).unwrap_or_else(|err| {
        panic!("failed to write fixture {}: {err}", path.display());
    });
}

fn write_json_fixture(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_json::to_vec_pretty(value).expect("fixture should serialize"),
    )
    .unwrap_or_else(|err| panic!("failed to write fixture {}: {err}", path.display()));
}

fn parse_json_file(path: &Path) -> Value {
    serde_json::from_str(
        &fs::read_to_string(path)
            .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display())),
    )
    .unwrap_or_else(|err| panic!("failed to parse {} as json: {err}", path.display()))
}

fn decode_json_b64(raw: &str) -> Value {
    let bytes = STANDARD
        .decode(raw)
        .unwrap_or_else(|err| panic!("base64 payload should decode: {err}"));
    serde_json::from_slice(&bytes).expect("payload should contain valid JSON")
}

fn decode_template_spec(raw: &str) -> TemplateSpec {
    let bytes = STANDARD
        .decode(raw)
        .unwrap_or_else(|err| panic!("template spec should decode: {err}"));
    serde_json::from_slice(&bytes).expect("template spec should contain valid JSON")
}

fn find_component<'a>(plan: &'a Value, moniker: &str) -> &'a Value {
    plan["components"]
        .as_array()
        .expect("components should be an array")
        .iter()
        .find(|component| component["moniker"].as_str() == Some(moniker))
        .unwrap_or_else(|| panic!("expected component {moniker} in plan: {plan:#}"))
}

struct PlacedFixture {
    manifest: PathBuf,
    placement: PathBuf,
}

fn write_single_image_fixture(root: &Path, site_id: &str, site_kind: &str) -> PlacedFixture {
    write_json_fixture(
        &root.join("svc.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "program": {
                "image": "python:3.13-alpine",
                "entrypoint": ["python3", "-u", "-c", "print('ready')"],
                "network": {
                    "endpoints": [
                        { "name": "http", "port": 8080, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );

    let manifest = root.join("root.json5");
    write_json_fixture(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "svc": "./svc.json5"
            },
            "exports": {
                "svc_http": "#svc.http"
            }
        }),
    );

    let site = if site_kind == "kubernetes" {
        json!({ "kind": site_kind, "context": "kind-amber-test" })
    } else {
        json!({ "kind": site_kind })
    };
    let placement = root.join("placement.json5");
    write_json_fixture(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                site_id: site
            },
            "defaults": {
                "image": site_id
            }
        }),
    );

    PlacedFixture {
        manifest,
        placement,
    }
}

fn write_mixed_site_fixture(root: &Path) -> PlacedFixture {
    write_json_fixture(
        &root.join("a.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "slots": {
                "b": { "kind": "http" }
            },
            "program": {
                "path": "/usr/bin/env",
                "args": ["python3", "-u", "-c", "print('ready')"],
                "network": {
                    "endpoints": [
                        { "name": "http", "port": 18080, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );
    write_json_fixture(
        &root.join("b.json5"),
        &json!({
            "manifest_version": "0.3.0",
            "program": {
                "image": "python:3.13-alpine",
                "entrypoint": ["python3", "-u", "-c", "print('ready')"],
                "network": {
                    "endpoints": [
                        { "name": "http", "port": 8080, "protocol": "http" }
                    ]
                }
            },
            "provides": {
                "http": { "kind": "http", "endpoint": "http" }
            },
            "exports": {
                "http": "http"
            }
        }),
    );

    let manifest = root.join("root.json5");
    write_json_fixture(
        &manifest,
        &json!({
            "manifest_version": "0.3.0",
            "components": {
                "a": "./a.json5",
                "b": "./b.json5"
            },
            "bindings": [
                { "to": "#a.b", "from": "#b.http" }
            ],
            "exports": {
                "a_http": "#a.http",
                "b_http": "#b.http"
            }
        }),
    );

    let placement = root.join("placement.json5");
    write_json_fixture(
        &placement,
        &json!({
            "schema": "amber.run.placement",
            "version": 1,
            "sites": {
                "direct_local": { "kind": "direct" },
                "compose_local": { "kind": "compose" }
            },
            "defaults": {
                "path": "direct_local",
                "image": "compose_local"
            }
        }),
    );

    PlacedFixture {
        manifest,
        placement,
    }
}

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
    assert_eq!(primary_json["version"], 4);
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

#[test]
fn compile_compose_preserves_runtime_conditional_entrypoint_item_in_template_spec() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("compose-conditional-entrypoint-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &manifest,
        r##"{
  manifest_version: "0.2.0",
  config_schema: {
    type: "object",
    properties: {
      profile: { type: "string" }
    }
  },
  program: {
    image: "alpine:3.20",
    entrypoint: [
      "server",
      {
        when: "config.profile",
        argv: "--profile ${config.profile}"
      }
    ],
    env: {
      PROFILE: {
        when: "config.profile",
        value: "${config.profile}"
      }
    },
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

    let compose_output_dir = outputs_dir.path().join("compose");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--docker-compose")
        .arg(&compose_output_dir)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --docker-compose: {err}"));

    if !output.status.success() {
        panic!(
            "amber compile --docker-compose failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let compose_output = compose_output_dir.join("compose.yaml");
    let compose_contents =
        fs::read_to_string(&compose_output).expect("failed to read docker compose output file");
    let compose_yaml: YamlValue =
        serde_yaml::from_str(&compose_contents).expect("docker compose output invalid yaml");
    let services = compose_yaml
        .get("services")
        .and_then(YamlValue::as_mapping)
        .expect("compose services should be a map");

    let template_spec_b64 = services
        .values()
        .find_map(|service| env_value(service, "AMBER_TEMPLATE_SPEC_B64"))
        .expect("compose output should include a helper template spec");
    let spec_bytes = STANDARD
        .decode(template_spec_b64)
        .expect("template spec should be valid base64");
    let spec: TemplateSpec =
        serde_json::from_slice(&spec_bytes).expect("template spec should be valid JSON");

    assert_eq!(spec.program.entrypoint.len(), 2);
    assert_eq!(
        spec.program.entrypoint[0],
        ProgramArgTemplate::Arg(vec![TemplatePart::lit("server")])
    );
    match &spec.program.entrypoint[1] {
        ProgramArgTemplate::Arg(_) => {
            panic!("expected runtime conditional entrypoint item in helper template spec")
        }
        ProgramArgTemplate::Conditional(group) => {
            assert_eq!(group.when, "profile");
            assert_eq!(
                group.argv,
                vec![
                    vec![TemplatePart::lit("--profile")],
                    vec![TemplatePart::config("profile")],
                ]
            );
        }
        ProgramArgTemplate::Repeated(_) => {
            panic!("expected conditional entrypoint item, got repeated expansion")
        }
    }
    match spec.program.env.get("PROFILE") {
        Some(ProgramEnvTemplate::Conditional(group)) => {
            assert_eq!(group.when, "profile");
            assert_eq!(group.value, vec![TemplatePart::config("profile")]);
        }
        Some(ProgramEnvTemplate::Value(_)) => {
            panic!("expected runtime conditional env value in helper template spec")
        }
        Some(ProgramEnvTemplate::Repeated(_)) => {
            panic!("expected conditional env value, got repeated expansion")
        }
        None => panic!("expected PROFILE env template"),
    }
}

#[test]
fn compile_compose_resolves_optional_slot_when_before_backend_emission() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("compose-slot-conditional-entrypoint-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifests_dir = outputs_dir.path().join("manifests");
    fs::create_dir_all(&manifests_dir).expect("failed to create manifests directory");

    let root_manifest = manifests_dir.join("root.json5");
    let child_manifest = manifests_dir.join("child.json5");

    fs::write(
        &root_manifest,
        r##"{
  manifest_version: "0.2.0",
  program: {
    image: "root",
    entrypoint: ["root"],
    network: {
      endpoints: [
        { name: "api", port: 8080, protocol: "http" }
      ]
    }
  },
  components: {
    child: "./child.json5"
  },
  provides: {
    api: { kind: "http", endpoint: "api" }
  },
  bindings: [
    { to: "#child.api", from: "provides.api" }
  ],
  exports: {
    http: "#child.http"
  }
}
"##,
    )
    .expect("failed to write root manifest");

    fs::write(
        &child_manifest,
        r##"{
  manifest_version: "0.2.0",
  slots: {
    api: { kind: "http", optional: true }
  },
  program: {
    image: "child",
    entrypoint: [
      "child",
      {
        when: "slots.api.url",
        argv: ["--peer", "${slots.api.url}"]
      }
    ],
    network: {
      endpoints: [
        { name: "http", port: 8081, protocol: "http" }
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
    .expect("failed to write child manifest");

    let compose_output_dir = outputs_dir.path().join("compose");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--docker-compose")
        .arg(&compose_output_dir)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --docker-compose: {err}"));

    if !output.status.success() {
        panic!(
            "amber compile --docker-compose failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let compose_output = compose_output_dir.join("compose.yaml");
    let compose_contents =
        fs::read_to_string(&compose_output).expect("failed to read docker compose output file");
    let compose_yaml: YamlValue =
        serde_yaml::from_str(&compose_contents).expect("docker compose output invalid yaml");
    let services = compose_yaml
        .get("services")
        .and_then(YamlValue::as_mapping)
        .expect("compose services should be a map");

    let child_service = services
        .values()
        .find(|service| service.get("image").and_then(YamlValue::as_str) == Some("child"))
        .expect("compose output missing child service");
    assert!(
        env_value(child_service, "AMBER_TEMPLATE_SPEC_B64").is_none(),
        "slot-based when should be resolved before helper template emission"
    );

    let entrypoint = child_service
        .get("entrypoint")
        .and_then(YamlValue::as_sequence)
        .expect("child service entrypoint should be a list");
    assert_eq!(entrypoint.len(), 3);
    assert_eq!(entrypoint[0].as_str(), Some("child"));
    assert_eq!(entrypoint[1].as_str(), Some("--peer"));
    let peer_url = entrypoint[2]
        .as_str()
        .expect("resolved slot URL should be rendered as a string");
    assert!(
        peer_url.starts_with("http://") || peer_url.starts_with("https://"),
        "expected resolved slot URL in child entrypoint, got {peer_url}"
    );
}

#[test]
fn compile_direct_preserves_runtime_conditional_program_arg_item_in_template_spec() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-conditional-argv-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &manifest,
        r##"{
  manifest_version: "0.2.0",
  config_schema: {
    type: "object",
    properties: {
      profile: { type: "string" }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "python3",
      {
        when: "config.profile",
        argv: "--profile ${config.profile}"
      }
    ],
    env: {
      PROFILE: {
        when: "config.profile",
        value: "${config.profile}"
      }
    },
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

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
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

    let plan_path = direct_out.join("direct-plan.json");
    let plan: Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("failed to read direct plan"))
            .expect("direct plan should contain valid JSON");
    let components = plan["components"]
        .as_array()
        .expect("direct plan components should be an array");
    let execution = &components[0]["program"]["execution"];
    let template_spec_b64 = execution["template_spec_b64"]
        .as_str()
        .expect("helper plan should include a template spec");
    let spec_bytes = STANDARD
        .decode(template_spec_b64)
        .expect("template spec should be valid base64");
    let spec: TemplateSpec =
        serde_json::from_slice(&spec_bytes).expect("template spec should be valid JSON");

    assert_eq!(spec.program.entrypoint.len(), 3);
    assert_eq!(
        spec.program.entrypoint[0],
        ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")])
    );
    assert_eq!(
        spec.program.entrypoint[1],
        ProgramArgTemplate::Arg(vec![TemplatePart::lit("python3")])
    );
    match &spec.program.entrypoint[2] {
        ProgramArgTemplate::Arg(_) => {
            panic!("expected runtime conditional arg item in helper template spec")
        }
        ProgramArgTemplate::Conditional(group) => {
            assert_eq!(group.when, "profile");
            assert_eq!(
                group.argv,
                vec![
                    vec![TemplatePart::lit("--profile")],
                    vec![TemplatePart::config("profile")],
                ]
            );
        }
        ProgramArgTemplate::Repeated(_) => {
            panic!("expected conditional arg item, got repeated expansion")
        }
    }
    match spec.program.env.get("PROFILE") {
        Some(ProgramEnvTemplate::Conditional(group)) => {
            assert_eq!(group.when, "profile");
            assert_eq!(group.value, vec![TemplatePart::config("profile")]);
        }
        Some(ProgramEnvTemplate::Value(_)) => {
            panic!("expected runtime conditional env value in helper template spec")
        }
        Some(ProgramEnvTemplate::Repeated(_)) => {
            panic!("expected conditional env value, got repeated expansion")
        }
        None => panic!("expected PROFILE env template"),
    }
}

#[test]
fn compile_primary_output_keeps_forwarded_root_defaulted_endpoint_and_mount_conditions() {
    let outputs_dir = cli_test_outputs_dir("forwarded-root-primary-defaults-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      child_enabled: { type: "string" },
      mount_text: { type: "string" }
    }
  },
  program: {
    image: "busybox:stable",
    entrypoint: ["sh", "-lc", "sleep infinity"],
    network: {
      endpoints: [
        {
          name: "http",
          port: 8080,
          protocol: "http",
          when: "config.child_enabled"
        }
      ]
    },
    mounts: [
      {
        path: "/etc/feature.txt",
        from: "config.mount_text",
        when: "config.child_enabled"
      }
    ]
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"##,
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_enabled: { type: "string" },
      bridge_mount_text: { type: "string" }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        child_enabled: "${config.bridge_enabled}",
        mount_text: "${config.bridge_mount_text}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      root_enabled: { type: "string", default: "enabled" },
      root_mount_text: { type: "string", default: "hello from root" }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_enabled: "${config.root_enabled}",
        bridge_mount_text: "${config.root_mount_text}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let primary_output = outputs_dir.path().join("scenario.ir.json");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&primary_output)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile: {err}"));

    assert!(
        output.status.success(),
        "amber compile failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&primary_output);
    let worker = find_component(&plan, "/bridge/worker");

    let endpoints = worker["program"]["network"]["endpoints"]
        .as_array()
        .expect("forwarded defaulted endpoint should survive linker lowering");
    assert_eq!(endpoints.len(), 1, "{worker:#}");
    assert_eq!(endpoints[0]["name"].as_str(), Some("http"));

    let mounts = worker["program"]["mounts"]
        .as_array()
        .expect("forwarded defaulted mount should survive linker lowering");
    assert_eq!(mounts.len(), 1, "{worker:#}");
    assert_eq!(mounts[0]["kind"].as_str(), Some("file"));
    assert!(mounts[0]["when"].is_null(), "{worker:#}");
}

#[test]
fn compile_primary_output_keeps_forwarded_object_defaulted_endpoint_and_mount_conditions() {
    let outputs_dir = cli_test_outputs_dir("forwarded-object-primary-defaults-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: "object",
        properties: {
          mode: { type: "string", default: "enabled" },
          mount_text: { type: "string", default: "hello from worker defaults" }
        }
      }
    }
  },
  program: {
    image: "busybox:stable",
    entrypoint: ["sh", "-lc", "sleep infinity"],
    network: {
      endpoints: [
        {
          name: "http",
          port: 8080,
          protocol: "http",
          when: "config.settings.mode"
        }
      ]
    },
    mounts: [
      {
        path: "/etc/feature.txt",
        from: "config.settings.mount_text",
        when: "config.settings.mode"
      }
    ]
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"##,
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_settings: {
        type: "object",
        properties: {
          mode: { type: "string" },
          mount_text: { type: "string" }
        }
      }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        settings: "${config.bridge_settings}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: "object",
        properties: {
          mode: { type: "string" },
          mount_text: { type: "string" }
        }
      }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_settings: "${config.settings}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let primary_output = outputs_dir.path().join("scenario.ir.json");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&primary_output)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile: {err}"));

    assert!(
        output.status.success(),
        "amber compile failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&primary_output);
    let worker = find_component(&plan, "/bridge/worker");

    let endpoints = worker["program"]["network"]["endpoints"]
        .as_array()
        .expect("forwarded object defaulted endpoint should survive linker lowering");
    assert_eq!(endpoints.len(), 1, "{worker:#}");
    assert_eq!(endpoints[0]["name"].as_str(), Some("http"));

    let mounts = worker["program"]["mounts"]
        .as_array()
        .expect("forwarded object defaulted mount should survive linker lowering");
    assert_eq!(mounts.len(), 1, "{worker:#}");
    assert_eq!(mounts[0]["kind"].as_str(), Some("file"));
    assert!(mounts[0]["when"].is_null(), "{worker:#}");
}

#[test]
fn compile_primary_output_preserves_forwarded_root_runtime_mount_condition() {
    let outputs_dir = cli_test_outputs_dir("forwarded-root-primary-runtime-mount-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      child_enabled: { type: "string" },
      mount_text: { type: "string" }
    }
  },
  program: {
    image: "busybox:stable",
    entrypoint: ["sh", "-lc", "sleep infinity"],
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    },
    mounts: [
      {
        path: "/etc/runtime.txt",
        from: "config.mount_text",
        when: "config.child_enabled"
      }
    ]
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"##,
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_enabled: { type: "string" },
      bridge_mount_text: { type: "string" }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        child_enabled: "${config.bridge_enabled}",
        mount_text: "${config.bridge_mount_text}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      root_enabled: { type: "string" },
      root_mount_text: { type: "string", default: "hello from root" }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_enabled: "${config.root_enabled}",
        bridge_mount_text: "${config.root_mount_text}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let primary_output = outputs_dir.path().join("scenario.ir.json");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&primary_output)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile: {err}"));

    assert!(
        output.status.success(),
        "amber compile failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&primary_output);
    let worker = find_component(&plan, "/bridge/worker");
    let mounts = worker["program"]["mounts"]
        .as_array()
        .expect("forwarded runtime mount condition should survive linker lowering");
    assert_eq!(mounts.len(), 1, "{worker:#}");
    assert_eq!(mounts[0]["kind"].as_str(), Some("file"));
    assert_eq!(mounts[0]["when"]["kind"].as_str(), Some("config"));
    assert_eq!(mounts[0]["when"]["path"].as_str(), Some("child_enabled"));
}

#[test]
fn check_accepts_forwarded_root_defaulted_leaf_under_nullable_ancestor() {
    let outputs_dir = cli_test_outputs_dir("forwarded-root-nullable-endpoint-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      child_enabled: { type: "string" }
    }
  },
  program: {
    image: "busybox:stable",
    entrypoint: ["sh", "-lc", "sleep infinity"],
    network: {
      endpoints: [
        {
          name: "http",
          port: 8080,
          protocol: "http",
          when: "config.child_enabled"
        }
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
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: ["object", "null"],
        properties: {
          root_enabled: { type: "string", default: "enabled" }
        }
      }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        child_enabled: "${config.settings.root_enabled}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("check")
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber check: {err}"));

    assert!(
        output.status.success(),
        "amber check failed unexpectedly\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn check_rejects_forwarded_object_default_condition_hidden_behind_nullable_forwarding() {
    let outputs_dir = cli_test_outputs_dir("forwarded-object-nullable-endpoint-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: ["object", "null"],
        properties: {
          mode: { type: "string", default: "enabled" }
        }
      }
    }
  },
  program: {
    image: "busybox:stable",
    entrypoint: ["sh", "-lc", "sleep infinity"],
    network: {
      endpoints: [
        {
          name: "http",
          port: 8080,
          protocol: "http",
          when: "config.settings.mode"
        }
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_settings: {
        type: ["object", "null"],
        properties: {
          mode: { type: "string" }
        }
      }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        settings: "${config.bridge_settings}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: ["object", "null"],
        properties: {
          mode: { type: "string" }
        }
      }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_settings: "${config.settings}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("check")
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber check: {err}"));

    assert!(
        !output.status.success(),
        "amber check unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "depends on runtime config, but endpoints must resolve entirely at compile time"
        ),
        "expected runtime-dependent endpoint error, got:\n{stderr}"
    );
}

#[test]
fn check_rejects_forwarded_object_default_condition_hidden_behind_non_object_forwarding() {
    let outputs_dir = cli_test_outputs_dir("forwarded-object-non-object-endpoint-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: "object",
        properties: {
          mode: { type: "string", default: "enabled" }
        }
      }
    }
  },
  program: {
    image: "busybox:stable",
    entrypoint: ["sh", "-lc", "sleep infinity"],
    network: {
      endpoints: [
        {
          name: "http",
          port: 8080,
          protocol: "http",
          when: "config.settings.mode"
        }
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_settings: {
        type: ["object", "string"],
        properties: {
          mode: { type: "string" }
        }
      }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        settings: "${config.bridge_settings}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: ["object", "string"],
        properties: {
          mode: { type: "string" }
        }
      }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_settings: "${config.settings}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("check")
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber check: {err}"));

    assert!(
        !output.status.success(),
        "amber check unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "depends on runtime config, but endpoints must resolve entirely at compile time"
        ),
        "expected runtime-dependent endpoint error, got:\n{stderr}"
    );
}

#[test]
fn check_rejects_forwarded_null_only_leaf_condition_even_with_component_default() {
    let outputs_dir = cli_test_outputs_dir("forwarded-null-only-endpoint-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      child_enabled: { type: "string", default: "enabled" }
    }
  },
  program: {
    image: "busybox:stable",
    entrypoint: ["sh", "-lc", "sleep infinity"],
    network: {
      endpoints: [
        {
          name: "http",
          port: 8080,
          protocol: "http",
          when: "config.child_enabled"
        }
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_enabled: { type: "null" }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        child_enabled: "${config.bridge_enabled}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      root_enabled: { type: "null" }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_enabled: "${config.root_enabled}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("check")
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber check: {err}"));

    assert!(
        !output.status.success(),
        "amber check unexpectedly succeeded\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "depends on runtime config, but endpoints must resolve entirely at compile time"
        ),
        "expected runtime-dependent endpoint error, got:\n{stderr}"
    );
}

#[test]
fn compile_direct_preserves_forwarded_root_runtime_conditionals_and_scope() {
    let outputs_dir = cli_test_outputs_dir("forwarded-root-direct-runtime-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      child_enabled: { type: "string" }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "worker",
      {
        when: "config.child_enabled",
        argv: ["--feature", "${config.child_enabled}"]
      }
    ],
    env: {
      FEATURE: {
        when: "config.child_enabled",
        value: "${config.child_enabled}"
      }
    },
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_enabled: { type: "string" }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        child_enabled: "${config.bridge_enabled}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      root_enabled: { type: "string" },
      unused_secret: { type: "string" }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_enabled: "${config.root_enabled}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&direct_out.join("direct-plan.json"));
    let worker = find_component(&plan, "/bridge/worker");
    let execution = &worker["program"]["execution"];
    assert_eq!(
        execution["kind"].as_str(),
        Some("helper_runner"),
        "{worker:#}"
    );

    let template_spec = decode_template_spec(
        execution["template_spec_b64"]
            .as_str()
            .expect("runtime forwarded conditional should emit a template spec"),
    );
    assert_eq!(
        template_spec.program.entrypoint[0],
        ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")])
    );
    assert_eq!(
        template_spec.program.entrypoint[1],
        ProgramArgTemplate::Arg(vec![TemplatePart::lit("worker")])
    );
    match &template_spec.program.entrypoint[2] {
        ProgramArgTemplate::Conditional(group) => {
            assert_eq!(group.when, "child_enabled");
            assert_eq!(
                group.argv,
                vec![
                    vec![TemplatePart::lit("--feature")],
                    vec![TemplatePart::config("child_enabled")],
                ]
            );
        }
        other => panic!("expected conditional forwarded arg, got {other:?}"),
    }
    match template_spec.program.env.get("FEATURE") {
        Some(ProgramEnvTemplate::Conditional(group)) => {
            assert_eq!(group.when, "child_enabled");
            assert_eq!(group.value, vec![TemplatePart::config("child_enabled")]);
        }
        other => panic!("expected conditional forwarded env, got {other:?}"),
    }

    let runtime_config = &execution["runtime_config"];
    let allowed_root_leaf_paths = runtime_config["allowed_root_leaf_paths"]
        .as_array()
        .expect("runtime helper should scope root config");
    assert_eq!(
        allowed_root_leaf_paths,
        &vec![Value::String("root_enabled".to_string())]
    );

    let pruned_root_schema = decode_json_b64(
        runtime_config["root_schema_b64"]
            .as_str()
            .expect("runtime helper should include a pruned root schema"),
    );
    assert!(pruned_root_schema["properties"]["root_enabled"].is_object());
    assert!(pruned_root_schema["properties"]["unused_secret"].is_null());

    let component_template = decode_json_b64(
        runtime_config["component_cfg_template_b64"]
            .as_str()
            .expect("runtime helper should include a component config template"),
    );
    let component_template_text =
        serde_json::to_string(&component_template).expect("component template should serialize");
    assert!(
        component_template_text.contains("child_enabled"),
        "{component_template:#}"
    );
    assert!(
        component_template_text.contains("root_enabled"),
        "{component_template:#}"
    );
}

#[test]
fn compile_direct_resolves_forwarded_root_defaulted_conditionals_but_keeps_runtime_values_scoped() {
    let outputs_dir = cli_test_outputs_dir("forwarded-root-direct-defaults-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      child_enabled: { type: "string" }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "worker",
      {
        when: "config.child_enabled",
        argv: ["--feature", "${config.child_enabled}"]
      }
    ],
    env: {
      FEATURE: {
        when: "config.child_enabled",
        value: "${config.child_enabled}"
      }
    },
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_enabled: { type: "string" }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        child_enabled: "${config.bridge_enabled}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      root_enabled: { type: "string", default: "enabled" }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_enabled: "${config.root_enabled}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&direct_out.join("direct-plan.json"));
    let worker = find_component(&plan, "/bridge/worker");
    let execution = &worker["program"]["execution"];
    assert_eq!(
        execution["kind"].as_str(),
        Some("helper_runner"),
        "{worker:#}"
    );

    let template_spec = decode_template_spec(
        execution["template_spec_b64"]
            .as_str()
            .expect("forwarded defaulted value should still emit a template spec"),
    );
    assert_eq!(
        template_spec.program.entrypoint,
        vec![
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("worker")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("--feature")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::config("child_enabled")]),
        ]
    );
    assert_eq!(
        template_spec.program.env.get("FEATURE"),
        Some(&ProgramEnvTemplate::Value(vec![TemplatePart::config(
            "child_enabled"
        )]))
    );

    let runtime_config = &execution["runtime_config"];
    let allowed_root_leaf_paths = runtime_config["allowed_root_leaf_paths"]
        .as_array()
        .expect("runtime helper should scope root config");
    assert_eq!(
        allowed_root_leaf_paths,
        &vec![Value::String("root_enabled".to_string())]
    );
}

#[test]
fn compile_direct_resolves_forwarded_root_defaulted_literal_conditionals_without_helper() {
    let outputs_dir = cli_test_outputs_dir("forwarded-root-direct-literal-defaults-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      child_enabled: { type: "string" }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "worker",
      {
        when: "config.child_enabled",
        argv: ["--feature", "enabled"]
      }
    ],
    env: {
      FEATURE: {
        when: "config.child_enabled",
        value: "enabled"
      }
    },
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_enabled: { type: "string" }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        child_enabled: "${config.bridge_enabled}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      root_enabled: { type: "string", default: "enabled" }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_enabled: "${config.root_enabled}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&direct_out.join("direct-plan.json"));
    let worker = find_component(&plan, "/bridge/worker");
    let execution = &worker["program"]["execution"];
    assert_eq!(execution["kind"].as_str(), Some("direct"), "{worker:#}");
    assert_eq!(
        execution["entrypoint"].as_array(),
        Some(&vec![
            Value::String("/usr/bin/env".to_string()),
            Value::String("worker".to_string()),
            Value::String("--feature".to_string()),
            Value::String("enabled".to_string()),
        ])
    );
    assert_eq!(execution["env"]["FEATURE"].as_str(), Some("enabled"));
    assert!(execution["template_spec_b64"].is_null(), "{worker:#}");
    assert!(execution["runtime_config"].is_null(), "{worker:#}");
}

#[test]
fn compile_direct_resolves_forwarded_object_defaulted_literal_conditionals_without_helper() {
    let outputs_dir = cli_test_outputs_dir("forwarded-object-direct-literal-defaults-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: "object",
        properties: {
          mode: { type: "string", default: "enabled" }
        }
      }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "worker",
      {
        when: "config.settings.mode",
        argv: ["--feature", "enabled"]
      }
    ],
    env: {
      FEATURE: {
        when: "config.settings.mode",
        value: "enabled"
      }
    },
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_settings: {
        type: "object",
        properties: {
          mode: { type: "string" },
          unused_secret: { type: "string" }
        }
      }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        settings: "${config.bridge_settings}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: "object",
        properties: {
          mode: { type: "string" },
          unused_secret: { type: "string" }
        }
      }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_settings: "${config.settings}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&direct_out.join("direct-plan.json"));
    let worker = find_component(&plan, "/bridge/worker");
    let execution = &worker["program"]["execution"];
    assert_eq!(execution["kind"].as_str(), Some("direct"), "{worker:#}");
    assert_eq!(
        execution["entrypoint"].as_array(),
        Some(&vec![
            Value::String("/usr/bin/env".to_string()),
            Value::String("worker".to_string()),
            Value::String("--feature".to_string()),
            Value::String("enabled".to_string()),
        ])
    );
    assert_eq!(execution["env"]["FEATURE"].as_str(), Some("enabled"));
    assert!(execution["template_spec_b64"].is_null(), "{worker:#}");
    assert!(execution["runtime_config"].is_null(), "{worker:#}");
}

#[test]
fn compile_direct_preserves_forwarded_object_defaulted_runtime_values_and_scope() {
    let outputs_dir = cli_test_outputs_dir("forwarded-object-direct-runtime-defaults-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: "object",
        properties: {
          mode: { type: "string", default: "enabled" }
        }
      }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "worker",
      {
        when: "config.settings.mode",
        argv: ["--feature", "${config.settings.mode}"]
      }
    ],
    env: {
      FEATURE: {
        when: "config.settings.mode",
        value: "${config.settings.mode}"
      }
    },
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_settings: {
        type: "object",
        properties: {
          mode: { type: "string" },
          unused_secret: { type: "string" }
        }
      }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        settings: "${config.bridge_settings}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      settings: {
        type: "object",
        properties: {
          mode: { type: "string" },
          unused_secret: { type: "string" }
        }
      }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_settings: "${config.settings}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&direct_out.join("direct-plan.json"));
    let worker = find_component(&plan, "/bridge/worker");
    let execution = &worker["program"]["execution"];
    assert_eq!(
        execution["kind"].as_str(),
        Some("helper_runner"),
        "{worker:#}"
    );

    let template_spec = decode_template_spec(
        execution["template_spec_b64"]
            .as_str()
            .expect("forwarded object runtime value should emit a template spec"),
    );
    assert_eq!(
        template_spec.program.entrypoint,
        vec![
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("worker")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("--feature")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::config("settings.mode")]),
        ]
    );
    assert_eq!(
        template_spec.program.env.get("FEATURE"),
        Some(&ProgramEnvTemplate::Value(vec![TemplatePart::config(
            "settings.mode"
        )]))
    );

    let runtime_config = &execution["runtime_config"];
    let allowed_root_leaf_paths = runtime_config["allowed_root_leaf_paths"]
        .as_array()
        .expect("runtime helper should scope root config");
    assert_eq!(
        allowed_root_leaf_paths,
        &vec![Value::String("settings.mode".to_string())]
    );
}

#[test]
fn compile_primary_output_expands_local_defaulted_config_each_endpoints() {
    let outputs_dir = cli_test_outputs_dir("defaulted-config-each-primary-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      endpoints: {
        type: "array",
        items: {
          type: "object",
          properties: {
            name: { type: "string" },
            port: { type: "integer" },
            protocol: { type: "string" }
          },
          required: ["name", "port", "protocol"]
        },
        default: [
          { name: "http", port: 8080, protocol: "http" },
          { name: "admin", port: 9090, protocol: "tcp" }
        ]
      }
    }
  },
  program: {
    image: "busybox:stable",
    entrypoint: ["sh", "-lc", "sleep infinity"],
    network: {
      endpoints: [
        {
          each: "config.endpoints",
          name: "${item.name}",
          port: "${item.port}",
          protocol: "${item.protocol}"
        }
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
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    worker: {
      manifest: "./worker.json5"
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );

    let primary_output = outputs_dir.path().join("scenario.ir.json");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&primary_output)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile: {err}"));

    assert!(
        output.status.success(),
        "amber compile failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&primary_output);
    let worker = find_component(&plan, "/worker");
    let endpoints = worker["program"]["network"]["endpoints"]
        .as_array()
        .expect("defaulted config each should expand endpoints");
    assert_eq!(endpoints.len(), 2, "{worker:#}");
    assert_eq!(endpoints[0]["name"].as_str(), Some("http"));
    assert_eq!(endpoints[0]["port"].as_u64(), Some(8080));
    assert_eq!(endpoints[1]["name"].as_str(), Some("admin"));
    assert_eq!(endpoints[1]["port"].as_u64(), Some(9090));
}

#[test]
fn compile_direct_expands_local_defaulted_config_each_without_helper() {
    let outputs_dir = cli_test_outputs_dir("defaulted-config-each-direct-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      extra_args: {
        type: "array",
        items: { type: "string" },
        default: ["--feature", "enabled"]
      },
      env_values: {
        type: "array",
        items: { type: "string" },
        default: ["alpha", "beta"]
      }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "worker",
      {
        each: "config.extra_args",
        arg: "${item}"
      }
    ],
    env: {
      FEATURES: {
        each: "config.env_values",
        value: "${item}",
        join: ","
      }
    },
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
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    worker: {
      manifest: "./worker.json5"
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&direct_out.join("direct-plan.json"));
    let worker = find_component(&plan, "/worker");
    let execution = &worker["program"]["execution"];
    assert_eq!(execution["kind"].as_str(), Some("direct"), "{worker:#}");
    assert_eq!(
        execution["entrypoint"].as_array(),
        Some(&vec![
            Value::String("/usr/bin/env".to_string()),
            Value::String("worker".to_string()),
            Value::String("--feature".to_string()),
            Value::String("enabled".to_string()),
        ])
    );
    assert_eq!(execution["env"]["FEATURES"].as_str(), Some("alpha,beta"));
    assert!(execution["template_spec_b64"].is_null(), "{worker:#}");
    assert!(execution["runtime_config"].is_null(), "{worker:#}");
}

#[test]
fn compile_direct_preserves_multi_hop_forwarded_config_each_runtime_and_scope() {
    let outputs_dir = cli_test_outputs_dir("forwarded-config-each-direct-runtime-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      extra_args: {
        type: "array",
        items: { type: "string" },
        default: ["--feature", "enabled"]
      },
      env_values: {
        type: "array",
        items: { type: "string" },
        default: ["alpha", "beta"]
      }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "worker",
      {
        each: "config.extra_args",
        arg: "${item}"
      }
    ],
    env: {
      FEATURES: {
        each: "config.env_values",
        value: "${item}",
        join: ","
      }
    },
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      extra_args: {
        type: "array",
        items: { type: "string" }
      },
      env_values: {
        type: "array",
        items: { type: "string" }
      }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        extra_args: "${config.extra_args}",
        env_values: "${config.env_values}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      extra_args: {
        type: "array",
        items: { type: "string" }
      },
      env_values: {
        type: "array",
        items: { type: "string" }
      }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        extra_args: "${config.extra_args}",
        env_values: "${config.env_values}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&direct_out.join("direct-plan.json"));
    let worker = find_component(&plan, "/bridge/worker");
    let execution = &worker["program"]["execution"];
    assert_eq!(
        execution["kind"].as_str(),
        Some("helper_runner"),
        "{worker:#}"
    );

    let template_spec = decode_template_spec(
        execution["template_spec_b64"]
            .as_str()
            .expect("forwarded config each should emit a template spec"),
    );
    assert_eq!(
        template_spec.program.entrypoint,
        vec![
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("worker")]),
            ProgramArgTemplate::Repeated(RepeatedProgramArgTemplate {
                when: None,
                each: RepeatedTemplateSource::Config {
                    path: "extra_args".to_string()
                },
                arg: Some(vec![TemplatePart::current_item("")]),
                argv: Vec::new(),
                join: None,
            }),
        ]
    );
    assert_eq!(
        template_spec.program.env.get("FEATURES"),
        Some(&ProgramEnvTemplate::Repeated(RepeatedProgramEnvTemplate {
            when: None,
            each: RepeatedTemplateSource::Config {
                path: "env_values".to_string()
            },
            value: vec![TemplatePart::current_item("")],
            join: ",".to_string(),
        }))
    );

    let runtime_config = &execution["runtime_config"];
    let mut allowed_root_leaf_paths = runtime_config["allowed_root_leaf_paths"]
        .as_array()
        .expect("runtime helper should scope root config")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("allowed root leaf paths should be strings")
                .to_string()
        })
        .collect::<Vec<_>>();
    allowed_root_leaf_paths.sort();
    assert_eq!(
        allowed_root_leaf_paths,
        vec!["env_values".to_string(), "extra_args".to_string()]
    );
}

#[test]
fn compile_direct_preserves_forwarded_null_overridable_config_each_runtime_and_scope() {
    let outputs_dir = cli_test_outputs_dir("forwarded-null-only-config-each-direct-");

    let worker_manifest = outputs_dir.path().join("worker.json5");
    let bridge_manifest = outputs_dir.path().join("bridge.json5");
    let root_manifest = outputs_dir.path().join("root.json5");

    write_fixture(
        &worker_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      items: {
        type: ["array", "null"],
        items: { type: "string" },
        default: ["alpha", "beta"]
      }
    }
  },
  program: {
    path: "/usr/bin/env",
    args: [
      "worker",
      {
        each: "config.items",
        arg: "${item}"
      }
    ],
    env: {
      ITEMS: {
        each: "config.items",
        value: "${item}",
        join: ","
      }
    },
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
    );
    write_fixture(
        &bridge_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      bridge_items: { type: "null" }
    }
  },
  components: {
    worker: {
      manifest: "./worker.json5",
      config: {
        items: "${config.bridge_items}"
      }
    }
  },
  exports: {
    http: "#worker.http"
  }
}
"##,
    );
    write_fixture(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  config_schema: {
    type: "object",
    properties: {
      root_items: { type: "null" }
    }
  },
  components: {
    bridge: {
      manifest: "./bridge.json5",
      config: {
        bridge_items: "${config.root_items}"
      }
    }
  },
  exports: {
    http: "#bridge.http"
  }
}
"##,
    );

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan = parse_json_file(&direct_out.join("direct-plan.json"));
    let worker = find_component(&plan, "/bridge/worker");
    let execution = &worker["program"]["execution"];
    assert_eq!(
        execution["kind"].as_str(),
        Some("helper_runner"),
        "{worker:#}"
    );

    let template_spec = decode_template_spec(
        execution["template_spec_b64"]
            .as_str()
            .expect("forwarded null-overridable config each should emit a template spec"),
    );
    assert_eq!(
        template_spec.program.entrypoint,
        vec![
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("worker")]),
            ProgramArgTemplate::Repeated(RepeatedProgramArgTemplate {
                when: None,
                each: RepeatedTemplateSource::Config {
                    path: "items".to_string()
                },
                arg: Some(vec![TemplatePart::current_item("")]),
                argv: Vec::new(),
                join: None,
            }),
        ]
    );
    assert_eq!(
        template_spec.program.env.get("ITEMS"),
        Some(&ProgramEnvTemplate::Repeated(RepeatedProgramEnvTemplate {
            when: None,
            each: RepeatedTemplateSource::Config {
                path: "items".to_string()
            },
            value: vec![TemplatePart::current_item("")],
            join: ",".to_string(),
        }))
    );

    let allowed_root_leaf_paths = execution["runtime_config"]["allowed_root_leaf_paths"]
        .as_array()
        .expect("runtime helper should scope root config");
    assert_eq!(
        allowed_root_leaf_paths,
        &vec![Value::String("root_items".to_string())]
    );
}

#[test]
fn compile_direct_lowers_singular_slot_queries_for_runtime_resolution() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-singular-slot-queries-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let root_manifest = outputs_dir.path().join("root.json5");
    let consumer_manifest = outputs_dir.path().join("consumer.json5");
    let provider_manifest = outputs_dir.path().join("provider.json5");

    fs::write(
        &consumer_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["consumer", "--api-url", "${slots.api.url}"],
    env: {
      API_JSON: "${slots.api}"
    },
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    }
  },
  slots: {
    api: { kind: "http", optional: true }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"#,
    )
    .expect("failed to write consumer manifest");
    fs::write(
        &provider_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["provider"],
    network: {
      endpoints: [
        { name: "api", port: 8081, protocol: "http" }
      ]
    }
  },
  provides: {
    api: { kind: "http", endpoint: "api" }
  },
  exports: {
    api: "api"
  }
}
"#,
    )
    .expect("failed to write provider manifest");
    fs::write(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    consumer: "./consumer.json5",
    provider: "./provider.json5"
  },
  bindings: [
    { to: "#consumer.api", from: "#provider.api" }
  ],
  exports: {
    http: "#consumer.http"
  }
}
"##,
    )
    .expect("failed to write root manifest");

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan_path = direct_out.join("direct-plan.json");
    let plan: Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("failed to read direct plan"))
            .expect("direct plan should contain valid JSON");
    let components = plan["components"]
        .as_array()
        .expect("direct plan components should be an array");
    let consumer = components
        .iter()
        .find(|component| component["moniker"].as_str() == Some("/consumer"))
        .expect("consumer component should exist");
    let consumer_scope = consumer["id"]
        .as_u64()
        .expect("consumer component id should be present") as u64;
    let execution = &consumer["program"]["execution"];
    let template_spec_b64 = execution["template_spec_b64"]
        .as_str()
        .expect("helper plan should include a template spec");
    let spec_bytes = STANDARD
        .decode(template_spec_b64)
        .expect("template spec should be valid base64");
    let spec: TemplateSpec =
        serde_json::from_slice(&spec_bytes).expect("template spec should be valid JSON");

    assert_eq!(
        spec.program.entrypoint,
        vec![
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("consumer")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("--api-url")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::slot(consumer_scope, "api.url")]),
        ]
    );
    assert_eq!(
        spec.program.env.get("API_JSON"),
        Some(&ProgramEnvTemplate::Value(vec![TemplatePart::slot(
            consumer_scope,
            "api",
        )]))
    );
    assert!(
        plan["runtime_addresses"]["slots_by_scope"][consumer_scope.to_string().as_str()]
            .get("api")
            .is_some(),
        "direct runtime addresses should publish the singular slot source"
    );
}

#[test]
fn compile_direct_lowers_repeated_slot_expansion_to_slot_items() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-repeated-slot-items-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let root_manifest = outputs_dir.path().join("root.json5");
    let consumer_manifest = outputs_dir.path().join("consumer.json5");
    let provider_a_manifest = outputs_dir.path().join("provider-a.json5");
    let provider_b_manifest = outputs_dir.path().join("provider-b.json5");

    fs::write(
        &consumer_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: [
      "consumer",
      {
        each: "slots.upstream",
        argv: ["--upstream", "${item.url}"]
      }
    ],
    env: {
      UPSTREAMS: {
        each: "slots.upstream",
        value: "${item.url}",
        join: ","
      }
    },
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    }
  },
  slots: {
    upstream: { kind: "http", optional: true, multiple: true }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"#,
    )
    .expect("failed to write consumer manifest");
    fs::write(
        &provider_a_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["provider-a"],
    network: {
      endpoints: [
        { name: "api", port: 8081, protocol: "http" }
      ]
    }
  },
  provides: {
    api: { kind: "http", endpoint: "api" }
  },
  exports: {
    api: "api"
  }
}
"#,
    )
    .expect("failed to write provider-a manifest");
    fs::write(
        &provider_b_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["provider-b"],
    network: {
      endpoints: [
        { name: "api", port: 8082, protocol: "http" }
      ]
    }
  },
  provides: {
    api: { kind: "http", endpoint: "api" }
  },
  exports: {
    api: "api"
  }
}
"#,
    )
    .expect("failed to write provider-b manifest");
    fs::write(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    consumer: "./consumer.json5",
    provider_a: "./provider-a.json5",
    provider_b: "./provider-b.json5"
  },
  bindings: [
    { to: "#consumer.upstream", from: "#provider_a.api" },
    { to: "#consumer.upstream", from: "#provider_b.api" }
  ],
  exports: {
    http: "#consumer.http"
  }
}
"##,
    )
    .expect("failed to write root manifest");

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
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

    let plan_path = direct_out.join("direct-plan.json");
    let plan: Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("failed to read direct plan"))
            .expect("direct plan should contain valid JSON");
    let components = plan["components"]
        .as_array()
        .expect("direct plan components should be an array");
    let consumer = components
        .iter()
        .find(|component| component["moniker"].as_str() == Some("/consumer"))
        .expect("consumer component should exist");
    let consumer_scope = consumer["id"]
        .as_u64()
        .expect("consumer component id should be present") as u64;
    let execution = &consumer["program"]["execution"];
    let template_spec_b64 = execution["template_spec_b64"]
        .as_str()
        .expect("helper plan should include a template spec");
    let spec_bytes = STANDARD
        .decode(template_spec_b64)
        .expect("template spec should be valid base64");
    let spec: TemplateSpec =
        serde_json::from_slice(&spec_bytes).expect("template spec should be valid JSON");

    assert_eq!(
        spec.program.entrypoint,
        vec![
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("consumer")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("--upstream")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::item(
                consumer_scope,
                "upstream",
                0,
                "url",
            )]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("--upstream")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::item(
                consumer_scope,
                "upstream",
                1,
                "url",
            )]),
        ]
    );
    assert_eq!(
        spec.program.env.get("UPSTREAMS"),
        Some(&ProgramEnvTemplate::Value(vec![
            TemplatePart::item(consumer_scope, "upstream", 0, "url"),
            TemplatePart::lit(","),
            TemplatePart::item(consumer_scope, "upstream", 1, "url"),
        ]))
    );

    let scope_key = consumer_scope.to_string();
    let slot_items = plan["runtime_addresses"]["slot_items_by_scope"][scope_key.as_str()]
        ["upstream"]
        .as_array()
        .expect("slot items should be present");
    assert_eq!(slot_items.len(), 2);
}

#[test]
fn compile_direct_lowers_single_binding_repeated_slot_to_one_runtime_item() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-single-repeated-slot-item-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let root_manifest = outputs_dir.path().join("root.json5");
    let consumer_manifest = outputs_dir.path().join("consumer.json5");
    let provider_manifest = outputs_dir.path().join("provider.json5");

    fs::write(
        &consumer_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: [
      "consumer",
      {
        each: "slots.upstream",
        argv: ["--upstream", "${item.url}"]
      }
    ],
    env: {
      UPSTREAMS: {
        each: "slots.upstream",
        value: "${item.url}",
        join: ","
      }
    },
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    }
  },
  slots: {
    upstream: { kind: "http", optional: true, multiple: true }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"#,
    )
    .expect("failed to write consumer manifest");
    fs::write(
        &provider_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["provider"],
    network: {
      endpoints: [
        { name: "api", port: 8081, protocol: "http" }
      ]
    }
  },
  provides: {
    api: { kind: "http", endpoint: "api" }
  },
  exports: {
    api: "api"
  }
}
"#,
    )
    .expect("failed to write provider manifest");
    fs::write(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    consumer: "./consumer.json5",
    provider: "./provider.json5"
  },
  bindings: [
    { to: "#consumer.upstream", from: "#provider.api" }
  ],
  exports: {
    http: "#consumer.http"
  }
}
"##,
    )
    .expect("failed to write root manifest");

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan_path = direct_out.join("direct-plan.json");
    let plan: Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("failed to read direct plan"))
            .expect("direct plan should contain valid JSON");
    let components = plan["components"]
        .as_array()
        .expect("direct plan components should be an array");
    let consumer = components
        .iter()
        .find(|component| component["moniker"].as_str() == Some("/consumer"))
        .expect("consumer component should exist");
    let consumer_scope = consumer["id"]
        .as_u64()
        .expect("consumer component id should be present") as u64;
    let execution = &consumer["program"]["execution"];
    let template_spec_b64 = execution["template_spec_b64"]
        .as_str()
        .expect("helper plan should include a template spec");
    let spec_bytes = STANDARD
        .decode(template_spec_b64)
        .expect("template spec should be valid base64");
    let spec: TemplateSpec =
        serde_json::from_slice(&spec_bytes).expect("template spec should be valid JSON");

    assert_eq!(
        spec.program.entrypoint,
        vec![
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("/usr/bin/env")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("consumer")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::lit("--upstream")]),
            ProgramArgTemplate::Arg(vec![TemplatePart::item(
                consumer_scope,
                "upstream",
                0,
                "url",
            )]),
        ]
    );
    assert_eq!(
        spec.program.env.get("UPSTREAMS"),
        Some(&ProgramEnvTemplate::Value(vec![TemplatePart::item(
            consumer_scope,
            "upstream",
            0,
            "url",
        )]))
    );

    let scope_key = consumer_scope.to_string();
    let slot_items = plan["runtime_addresses"]["slot_items_by_scope"][scope_key.as_str()]
        ["upstream"]
        .as_array()
        .expect("slot items should be present");
    assert_eq!(slot_items.len(), 1);
}

#[test]
fn compile_direct_preserves_authored_order_signal_for_mixed_source_repeated_slots() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-mixed-source-repeated-slot-order-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let root_manifest = outputs_dir.path().join("root.json5");
    let consumer_manifest = outputs_dir.path().join("consumer.json5");
    let provider_manifest = outputs_dir.path().join("provider.json5");

    fs::write(
        &consumer_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: [
      {
        each: "slots.upstream",
        argv: ["--upstream", "${item.url}"]
      }
    ],
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    }
  },
  slots: {
    upstream: { kind: "http", optional: true, multiple: true }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"#,
    )
    .expect("failed to write consumer manifest");
    fs::write(
        &provider_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["provider"],
    network: {
      endpoints: [
        { name: "api", port: 8081, protocol: "http" }
      ]
    }
  },
  provides: {
    api: { kind: "http", endpoint: "api" }
  },
  exports: {
    api: "api"
  }
}
"#,
    )
    .expect("failed to write provider manifest");
    fs::write(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    consumer: "./consumer.json5",
    provider: "./provider.json5"
  },
  slots: {
    upstream: { kind: "http", optional: true }
  },
  bindings: [
    { to: "#consumer.upstream", from: "slots.upstream", weak: true },
    { to: "#consumer.upstream", from: "#provider.api" }
  ],
  exports: {
    http: "#consumer.http"
  }
}
"##,
    )
    .expect("failed to write root manifest");

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan_path = direct_out.join("direct-plan.json");
    let plan: Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("failed to read direct plan"))
            .expect("direct plan should contain valid JSON");
    let provision_plan_path = direct_out.join(
        plan["mesh_provision_plan"]
            .as_str()
            .expect("mesh provision plan path should exist"),
    );
    let provision_plan: Value = serde_json::from_str(
        &fs::read_to_string(&provision_plan_path).expect("failed to read mesh provision plan"),
    )
    .expect("mesh provision plan should be valid JSON");
    let consumer_target = provision_plan["targets"]
        .as_array()
        .expect("mesh provision targets should be present")
        .iter()
        .find(|target| {
            target["kind"].as_str() == Some("component")
                && target["config"]["identity"]["id"].as_str() == Some("/consumer")
        })
        .expect("consumer provision target should exist");
    let outbound = consumer_target["config"]["outbound"]
        .as_array()
        .expect("outbound routes should be present");
    let component_route = outbound
        .iter()
        .find(|route| {
            route["slot"].as_str() == Some("upstream")
                && route["peer_id"].as_str() == Some("/provider")
        })
        .expect("component route should exist");
    let external_route = outbound
        .iter()
        .find(|route| {
            route["slot"].as_str() == Some("upstream")
                && route["peer_id"].as_str() != Some("/provider")
        })
        .expect("external route should exist");
    let component_port = component_route["listen_port"]
        .as_u64()
        .expect("component route listen_port should exist");
    let external_port = external_route["listen_port"]
        .as_u64()
        .expect("external route listen_port should exist");
    assert!(
        external_port < component_port,
        "authored external binding should keep the first placeholder port, got external={} \
         component={}",
        external_port,
        component_port
    );
}

#[test]
fn compile_direct_assigns_distinct_ports_to_duplicate_repeated_bindings() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-duplicate-repeated-bindings-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let root_manifest = outputs_dir.path().join("root.json5");
    let consumer_manifest = outputs_dir.path().join("consumer.json5");
    let provider_manifest = outputs_dir.path().join("provider.json5");

    fs::write(
        &consumer_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: [
      {
        each: "slots.upstream",
        argv: ["--upstream", "${item.url}"]
      }
    ],
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    }
  },
  slots: {
    upstream: { kind: "http", optional: true, multiple: true }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"#,
    )
    .expect("failed to write consumer manifest");
    fs::write(
        &provider_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["provider"],
    network: {
      endpoints: [
        { name: "api", port: 8081, protocol: "http" }
      ]
    }
  },
  provides: {
    api: { kind: "http", endpoint: "api" }
  },
  exports: {
    api: "api"
  }
}
"#,
    )
    .expect("failed to write provider manifest");
    fs::write(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    consumer: "./consumer.json5",
    provider: "./provider.json5"
  },
  bindings: [
    { to: "#consumer.upstream", from: "#provider.api" },
    { to: "#consumer.upstream", from: "#provider.api" }
  ],
  exports: {
    http: "#consumer.http"
  }
}
"##,
    )
    .expect("failed to write root manifest");

    let direct_out = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&direct_out)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let plan_path = direct_out.join("direct-plan.json");
    let plan: Value =
        serde_json::from_str(&fs::read_to_string(&plan_path).expect("failed to read direct plan"))
            .expect("direct plan should contain valid JSON");
    let components = plan["components"]
        .as_array()
        .expect("direct plan components should be an array");
    let consumer = components
        .iter()
        .find(|component| component["moniker"].as_str() == Some("/consumer"))
        .expect("consumer component should exist");
    let provision_plan_path = direct_out.join(
        plan["mesh_provision_plan"]
            .as_str()
            .expect("mesh provision plan path should exist"),
    );
    let provision_plan: Value = serde_json::from_str(
        &fs::read_to_string(&provision_plan_path).expect("failed to read mesh provision plan"),
    )
    .expect("mesh provision plan should be valid JSON");
    let consumer_target = provision_plan["targets"]
        .as_array()
        .expect("mesh provision targets should be present")
        .iter()
        .find(|target| {
            target["kind"].as_str() == Some("component")
                && target["config"]["identity"]["id"].as_str() == Some("/consumer")
        })
        .expect("consumer provision target should exist");
    let ports: Vec<u64> = consumer_target["config"]["outbound"]
        .as_array()
        .expect("outbound routes should be present")
        .iter()
        .filter(|route| route["slot"].as_str() == Some("upstream"))
        .map(|route| {
            route["listen_port"]
                .as_u64()
                .expect("outbound listen_port should exist")
        })
        .collect();
    assert_eq!(ports.len(), 2);
    assert_ne!(
        ports[0], ports[1],
        "duplicate repeated bindings need distinct ports"
    );

    let consumer_scope = consumer["id"]
        .as_u64()
        .expect("consumer component id should be present")
        .to_string();
    let slot_items = plan["runtime_addresses"]["slot_items_by_scope"][consumer_scope.as_str()]
        ["upstream"]
        .as_array()
        .expect("slot items should be present");
    assert_eq!(slot_items.len(), 2);
}

#[test]
fn compile_direct_resolves_relative_program_path_into_direct_plan() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-relative-program-path-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &manifest,
        r#"{
  manifest_version: "0.1.0",
  program: {
    path: "./bin/server",
    args: ["--port", "8080"],
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
"#,
    )
    .expect("failed to write manifest");

    let artifact_dir = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&artifact_dir)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let direct_plan = fs::read_to_string(artifact_dir.join("direct-plan.json"))
        .expect("failed to read direct plan");
    let direct_json: Value =
        serde_json::from_str(&direct_plan).expect("direct plan should be valid JSON");
    let component = direct_json["components"][0]
        .as_object()
        .expect("component should exist");
    let expected_source_dir = manifest
        .parent()
        .expect("manifest should have a parent")
        .display()
        .to_string();
    let expected_program_path = manifest
        .parent()
        .expect("manifest should have a parent")
        .join("./bin/server")
        .display()
        .to_string();

    assert_eq!(
        component.get("source_dir").and_then(Value::as_str),
        Some(expected_source_dir.as_str())
    );
    assert_eq!(
        component
            .get("program")
            .and_then(|program| program.get("execution"))
            .and_then(|execution| execution.get("entrypoint"))
            .and_then(Value::as_array)
            .and_then(|entrypoint| entrypoint.first())
            .and_then(Value::as_str),
        Some(expected_program_path.as_str())
    );
}

#[test]
fn compile_direct_rejects_scenario_ir_without_resolved_url_for_relative_program_path() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-ir-missing-resolved-url-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &manifest,
        r#"{
  manifest_version: "0.1.0",
  program: {
    path: "./bin/server",
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
"#,
    )
    .expect("failed to write manifest");

    let ir_path = outputs_dir.path().join("scenario.json");
    let ir_compile = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&ir_path)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to compile Scenario IR: {err}"));
    assert!(
        ir_compile.status.success(),
        "amber compile --output failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        ir_compile.status,
        String::from_utf8_lossy(&ir_compile.stdout),
        String::from_utf8_lossy(&ir_compile.stderr)
    );

    let mut ir: Value =
        serde_json::from_str(&fs::read_to_string(&ir_path).expect("failed to read Scenario IR"))
            .expect("Scenario IR should be valid JSON");
    let components = ir["components"]
        .as_array_mut()
        .expect("Scenario IR components should be an array");
    for component in components {
        component
            .as_object_mut()
            .expect("component should be an object")
            .remove("resolved_url");
    }
    let stripped_ir_path = outputs_dir
        .path()
        .join("scenario-without-resolved-url.json");
    fs::write(
        &stripped_ir_path,
        serde_json::to_vec_pretty(&ir).expect("Scenario IR should serialize"),
    )
    .expect("failed to write stripped Scenario IR");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(outputs_dir.path().join("direct"))
        .arg(&stripped_ir_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --direct unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("local file") && stderr.contains("`resolved_url`"),
        "expected resolved_url rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_direct_rejects_invalid_scenario_ir_before_backend_lowering() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-ir-invalid-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let child_manifest = outputs_dir.path().join("client.json5");
    fs::write(
        &child_manifest,
        r#"{
  manifest_version: "0.1.0",
  program: {
    image: "client",
    entrypoint: ["client"],
    env: {
      API_URL: "${slots.api.url}"
    },
    network: {
      endpoints: [
        { name: "http", port: 80, protocol: "http" }
      ]
    }
  },
  slots: {
    api: { kind: "http" }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"#,
    )
    .expect("failed to write child manifest");
    let child_manifest_url = format!(
        "file://{}",
        child_manifest
            .canonicalize()
            .expect("child manifest should canonicalize")
            .display()
    );

    let root_manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &root_manifest,
        format!(
            r##"{{
  manifest_version: "0.1.0",
  slots: {{
    api: {{ kind: "http" }}
  }},
  components: {{
    client: "{}"
  }},
  bindings: [
    {{ to: "#client.api", from: "slots.api", weak: true }}
  ],
  exports: {{
    http: "#client.http"
  }}
}}
"##,
            child_manifest_url
        ),
    )
    .expect("failed to write root manifest");

    let ir_path = outputs_dir.path().join("scenario.json");
    let ir_compile = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&ir_path)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to compile Scenario IR: {err}"));
    assert!(
        ir_compile.status.success(),
        "amber compile --output failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        ir_compile.status,
        String::from_utf8_lossy(&ir_compile.stdout),
        String::from_utf8_lossy(&ir_compile.stderr)
    );

    let mut ir: Value =
        serde_json::from_str(&fs::read_to_string(&ir_path).expect("failed to read Scenario IR"))
            .expect("Scenario IR should be valid JSON");
    ir["components"][0]
        .as_object_mut()
        .expect("root component should be an object")
        .insert("slots".to_string(), serde_json::json!({}));
    let broken_ir_path = outputs_dir.path().join("broken-scenario.json");
    fs::write(
        &broken_ir_path,
        serde_json::to_vec_pretty(&ir).expect("Scenario IR should serialize"),
    )
    .expect("failed to write broken Scenario IR");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(outputs_dir.path().join("direct"))
        .arg(&broken_ir_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --direct unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid Scenario IR input")
            && stderr.contains("external slot source")
            && stderr.contains("targets missing slot"),
        "expected invalid Scenario IR rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_direct_rejects_scenario_ir_repeated_each_on_singular_slot() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-ir-singular-each-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let root_manifest = outputs_dir.path().join("root.json5");
    let consumer_manifest = outputs_dir.path().join("consumer.json5");
    let provider_manifest = outputs_dir.path().join("provider.json5");

    fs::write(
        &consumer_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["consumer"],
    network: {
      endpoints: [
        { name: "http", port: 8080, protocol: "http" }
      ]
    }
  },
  slots: {
    api: { kind: "http", optional: true }
  },
  provides: {
    http: { kind: "http", endpoint: "http" }
  },
  exports: {
    http: "http"
  }
}
"#,
    )
    .expect("failed to write consumer manifest");
    fs::write(
        &provider_manifest,
        r#"{
  manifest_version: "0.3.0",
  program: {
    path: "/usr/bin/env",
    args: ["provider"],
    network: {
      endpoints: [
        { name: "api", port: 8081, protocol: "http" }
      ]
    }
  },
  provides: {
    api: { kind: "http", endpoint: "api" }
  },
  exports: {
    api: "api"
  }
}
"#,
    )
    .expect("failed to write provider manifest");
    fs::write(
        &root_manifest,
        r##"{
  manifest_version: "0.3.0",
  components: {
    consumer: "./consumer.json5",
    provider: "./provider.json5"
  },
  bindings: [
    { to: "#consumer.api", from: "#provider.api" }
  ],
  exports: {
    http: "#consumer.http"
  }
}
"##,
    )
    .expect("failed to write root manifest");

    let ir_path = outputs_dir.path().join("scenario.json");
    let ir_compile = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&ir_path)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to compile Scenario IR: {err}"));
    assert!(
        ir_compile.status.success(),
        "amber compile --output failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        ir_compile.status,
        String::from_utf8_lossy(&ir_compile.stdout),
        String::from_utf8_lossy(&ir_compile.stderr)
    );

    let mut ir: Value =
        serde_json::from_str(&fs::read_to_string(&ir_path).expect("failed to read Scenario IR"))
            .expect("Scenario IR should be valid JSON");
    let components = ir["components"]
        .as_array_mut()
        .expect("Scenario IR components should be an array");
    let consumer = components
        .iter_mut()
        .find(|component| component["moniker"].as_str() == Some("/consumer"))
        .expect("consumer component should exist");
    consumer["program"]["args"] = serde_json::json!([
        {
            "each": "slots.api",
            "arg": "${item.url}"
        }
    ]);
    let invalid_ir_path = outputs_dir.path().join("scenario-invalid-each.json");
    fs::write(
        &invalid_ir_path,
        serde_json::to_vec_pretty(&ir).expect("Scenario IR should serialize"),
    )
    .expect("failed to write invalid Scenario IR");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(outputs_dir.path().join("direct"))
        .arg(&invalid_ir_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --direct unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("slot `api`")
            && stderr.contains("not declared with `multiple")
            && stderr.contains("program.args[0]"),
        "expected singular repeated-each rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_direct_rejects_scenario_ir_missing_version() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-ir-missing-version-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let ir_path = outputs_dir.path().join("scenario-ir.json");
    fs::write(
        &ir_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "amber.scenario.ir",
            "root": 0,
            "components": [],
            "bindings": [],
            "exports": []
        }))
        .expect("Scenario IR should serialize"),
    )
    .expect("failed to write Scenario IR");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(outputs_dir.path().join("direct"))
        .arg(&ir_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --direct unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid Scenario IR input") && stderr.contains("missing field `version`"),
        "expected missing version Scenario IR rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_direct_rejects_scenario_ir_with_non_resource_storage_mount_binding() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-ir-storage-binding-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let ir_path = outputs_dir.path().join("scenario-ir.json");
    fs::write(
        &ir_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema": "amber.scenario.ir",
            "version": 4,
            "root": 0,
            "components": [
                {
                    "id": 0,
                    "moniker": "/",
                    "parent": null,
                    "children": [1],
                    "resolved_url": "file:///tmp/root.json5",
                    "digest": ManifestDigest::new([0u8; 32]).to_string(),
                    "config": null,
                    "slots": {
                        "state": { "kind": "storage" }
                    }
                },
                {
                    "id": 1,
                    "moniker": "/app",
                    "parent": 0,
                    "children": [],
                    "resolved_url": "file:///tmp/app.json5",
                    "digest": ManifestDigest::new([1u8; 32]).to_string(),
                    "config": null,
                    "program": {
                        "image": "busybox:stable",
                        "entrypoint": ["sh"],
                        "mounts": [
                            {
                                "kind": "slot",
                                "path": "/var/lib/app",
                                "slot": "state"
                            }
                        ]
                    },
                    "slots": {
                        "state": { "kind": "storage" }
                    }
                }
            ],
            "bindings": [
                {
                    "from": { "kind": "external", "slot": { "component": 0, "slot": "state" } },
                    "to": { "component": 1, "slot": "state" },
                    "weak": true
                }
            ],
            "exports": []
        }))
        .expect("Scenario IR should serialize"),
    )
    .expect("failed to write Scenario IR");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(outputs_dir.path().join("direct"))
        .arg(&ir_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        !output.status.success(),
        "amber compile --direct unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid Scenario IR input")
            && stderr.contains("mounted storage slot /app.state must be bound")
            && stderr.contains("from a storage resource")
            && stderr.contains("external /.state"),
        "expected mounted storage Scenario IR rejection in stderr, got:\n{stderr}"
    );
}

#[test]
fn compile_direct_allows_absolute_program_path_without_resolved_url() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("direct-ir-absolute-program-path-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifest = outputs_dir.path().join("scenario.json5");
    fs::write(
        &manifest,
        r#"{
  manifest_version: "0.1.0",
  program: {
    path: "/usr/bin/env",
    args: ["python3", "-m", "http.server", "8080"],
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
"#,
    )
    .expect("failed to write manifest");

    let ir_path = outputs_dir.path().join("scenario.json");
    let ir_compile = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&ir_path)
        .arg(&manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to compile Scenario IR: {err}"));
    assert!(
        ir_compile.status.success(),
        "amber compile --output failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        ir_compile.status,
        String::from_utf8_lossy(&ir_compile.stdout),
        String::from_utf8_lossy(&ir_compile.stderr)
    );

    let mut ir: Value =
        serde_json::from_str(&fs::read_to_string(&ir_path).expect("failed to read Scenario IR"))
            .expect("Scenario IR should be valid JSON");
    let components = ir["components"]
        .as_array_mut()
        .expect("Scenario IR components should be an array");
    for component in components {
        component
            .as_object_mut()
            .expect("component should be an object")
            .remove("resolved_url");
    }
    let stripped_ir_path = outputs_dir
        .path()
        .join("scenario-without-resolved-url.json");
    fs::write(
        &stripped_ir_path,
        serde_json::to_vec_pretty(&ir).expect("Scenario IR should serialize"),
    )
    .expect("failed to write stripped Scenario IR");

    let artifact_dir = outputs_dir.path().join("direct");
    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--direct")
        .arg(&artifact_dir)
        .arg(&stripped_ir_path)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile --direct: {err}"));

    assert!(
        output.status.success(),
        "amber compile --direct failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let direct_plan = fs::read_to_string(artifact_dir.join("direct-plan.json"))
        .expect("failed to read direct plan");
    let direct_json: Value =
        serde_json::from_str(&direct_plan).expect("direct plan should be valid JSON");
    let component = direct_json["components"][0]
        .as_object()
        .expect("component should exist");

    assert!(component.get("source_dir").is_none());
    assert_eq!(
        component
            .get("program")
            .and_then(|program| program.get("execution"))
            .and_then(|execution| execution.get("entrypoint"))
            .and_then(Value::as_array)
            .and_then(|entrypoint| entrypoint.first())
            .and_then(Value::as_str),
        Some("/usr/bin/env")
    );
}
