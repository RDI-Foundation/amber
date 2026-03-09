use std::{fs, path::Path, process::Command};

use amber_compiler::reporter::direct::{DIRECT_CONTROL_SOCKET_RELATIVE_PATH, DIRECT_PLAN_VERSION};
use amber_images::AMBER_ROUTER;
use amber_manifest::ManifestDigest;
use amber_template::{ProgramArgTemplate, ProgramEnvTemplate, TemplatePart, TemplateSpec};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::Value;
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
    assert_eq!(primary_json["version"], 2);
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
fn compile_with_binding_interpolation() {
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("cli crate should live under the workspace root");

    let outputs_root = workspace_root.join("target").join("cli-test-outputs");
    fs::create_dir_all(&outputs_root).expect("failed to create outputs directory");
    let outputs_dir = tempfile::Builder::new()
        .prefix("outputs-")
        .tempdir_in(&outputs_root)
        .expect("failed to create outputs directory");

    let manifests_dir = outputs_dir.path().join("manifests");
    fs::create_dir_all(&manifests_dir).expect("failed to create manifests directory");

    let root_manifest = manifests_dir.join("scenario.json5");
    let server_manifest = manifests_dir.join("server.json5");
    let client_manifest = manifests_dir.join("client.json5");
    let observer_manifest = manifests_dir.join("observer.json5");

    fs::write(
        &root_manifest,
        r##"{
  "manifest_version": "0.1.0",
  "components": {
    "server": "./server.json5",
    "client": "./client.json5",
    "observer": {
      "manifest": "./observer.json5",
      "config": {
        "upstream_url": "${bindings.bind.url}"
      }
    }
  },
  "bindings": [
    { "name": "bind", "from": "#server.api", "to": "#client.api" }
  ]
}
"##,
    )
    .expect("failed to write root manifest");

    fs::write(
        &server_manifest,
        r#"{
  "manifest_version": "0.1.0",
  "program": {
    "image": "alpine:3.20",
    "entrypoint": ["server"],
    "env": {},
    "network": {
      "endpoints": [
        { "name": "api", "port": 8080, "protocol": "http" }
      ]
    }
  },
  "provides": {
    "api": { "kind": "http", "endpoint": "api" }
  },
  "exports": {
    "api": "api"
  }
}
"#,
    )
    .expect("failed to write server manifest");

    fs::write(
        &client_manifest,
        r#"{
  "manifest_version": "0.1.0",
  "program": {
    "image": "alpine:3.20",
    "entrypoint": ["client"],
    "env": {
      "BIND_URL": "${slots.api.url}"
    },
    "network": {
      "endpoints": [
        { "name": "health", "port": 9101, "protocol": "http" }
      ]
    }
  },
  "slots": {
    "api": { "kind": "http" }
  },
  "provides": {
    "health": { "kind": "http", "endpoint": "health" }
  },
  "exports": {
    "health": "health"
  }
}
"#,
    )
    .expect("failed to write client manifest");

    fs::write(
        &observer_manifest,
        r#"{
  "manifest_version": "0.1.0",
  "config_schema": {
    "type": "object",
    "properties": {
      "upstream_url": { "type": "string" }
    },
    "required": ["upstream_url"],
    "additionalProperties": false
  },
  "program": {
    "image": "alpine:3.20",
    "entrypoint": ["observer"],
    "env": {
      "UPSTREAM_URL": "${config.upstream_url}"
    },
    "network": {
      "endpoints": [
        { "name": "health", "port": 9102, "protocol": "http" }
      ]
    }
  },
  "provides": {
    "health": { "kind": "http", "endpoint": "health" }
  },
  "exports": {
    "health": "health"
  }
}
"#,
    )
    .expect("failed to write observer manifest");

    let compose_output_dir = outputs_dir.path().join("scenario.compose");

    let compose_compile = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--no-opt")
        .arg("--docker-compose")
        .arg(&compose_output_dir)
        .arg(&root_manifest)
        .output()
        .unwrap_or_else(|err| panic!("failed to run amber compile: {err}"));
    if !compose_compile.status.success() {
        panic!(
            "amber compile (compose) failed\nstatus: {}\nstdout:\n{}\nstderr:\n{}",
            compose_compile.status,
            String::from_utf8_lossy(&compose_compile.stdout),
            String::from_utf8_lossy(&compose_compile.stderr)
        );
    }

    let compose_output = compose_output_dir.join("compose.yaml");
    assert!(
        compose_output.is_file(),
        "expected docker compose output file at {}",
        compose_output.display()
    );
    let compose_contents =
        fs::read_to_string(&compose_output).expect("failed to read docker compose output file");
    let compose_yaml: YamlValue =
        serde_yaml::from_str(&compose_contents).expect("docker compose output invalid yaml");
    let services = compose_yaml
        .get("services")
        .and_then(YamlValue::as_mapping)
        .expect("compose services should be a map");

    let bind_url = services
        .values()
        .find_map(|service| env_value(service, "BIND_URL"));
    assert_eq!(
        bind_url.as_deref(),
        Some("http://127.0.0.1:20000"),
        "expected client BIND_URL to resolve in docker compose output"
    );

    let upstream_url = services
        .values()
        .find_map(|service| env_value(service, "UPSTREAM_URL"));
    assert_eq!(
        upstream_url.as_deref(),
        Some("http://127.0.0.1:20000"),
        "expected observer UPSTREAM_URL to resolve in docker compose output"
    );

    let provisioner = services
        .get("amber-provisioner")
        .expect("compose missing provisioner service");
    assert_eq!(
        env_value(provisioner, "AMBER_MESH_PROVISION_PLAN_PATH").as_deref(),
        Some("/amber/plan/mesh-provision-plan.json")
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
        r#"{
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
"#,
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
        stderr.contains("does not search PATH"),
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
fn compile_compose_preserves_runtime_conditional_entrypoint_group_in_template_spec() {
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
        r#"{
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
"#,
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
            panic!("expected runtime conditional entrypoint group in helper template spec")
        }
        ProgramArgTemplate::Group(group) => {
            assert_eq!(group.when, "profile");
            assert_eq!(
                group.argv,
                vec![
                    vec![TemplatePart::lit("--profile")],
                    vec![TemplatePart::config("profile")],
                ]
            );
        }
    }
    match spec.program.env.get("PROFILE") {
        Some(ProgramEnvTemplate::Group(group)) => {
            assert_eq!(group.when, "profile");
            assert_eq!(group.value, vec![TemplatePart::config("profile")]);
        }
        Some(ProgramEnvTemplate::Value(_)) => {
            panic!("expected runtime conditional env value in helper template spec")
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
    { to: "#child.api", from: "self.api" }
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
        r#"{
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
"#,
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
fn compile_direct_preserves_runtime_conditional_program_arg_group_in_template_spec() {
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
        r#"{
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
"#,
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
            panic!("expected runtime conditional arg group in helper template spec")
        }
        ProgramArgTemplate::Group(group) => {
            assert_eq!(group.when, "profile");
            assert_eq!(
                group.argv,
                vec![
                    vec![TemplatePart::lit("--profile")],
                    vec![TemplatePart::config("profile")],
                ]
            );
        }
    }
    match spec.program.env.get("PROFILE") {
        Some(ProgramEnvTemplate::Group(group)) => {
            assert_eq!(group.when, "profile");
            assert_eq!(group.value, vec![TemplatePart::config("profile")]);
        }
        Some(ProgramEnvTemplate::Value(_)) => {
            panic!("expected runtime conditional env value in helper template spec")
        }
        None => panic!("expected PROFILE env template"),
    }
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
    {{ to: "#client.api", from: "self.api", weak: true }}
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
            "version": 2,
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
                            { "path": "/var/lib/app", "from": "slots.state" }
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
