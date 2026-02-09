use std::{fs, path::Path, process::Command};

use amber_images::AMBER_ROUTER;
use serde_json::Value;
use serde_yaml::Value as YamlValue;

fn env_value(service: &YamlValue, key: &str) -> Option<String> {
    let env = service.get("environment")?;
    match env {
        YamlValue::Mapping(map) => map.get(key).and_then(YamlValue::as_str).map(str::to_string),
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
    let compose_output = outputs_dir.path().join("scenario.docker-compose.yaml");

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--output")
        .arg(&primary_output)
        .arg("--dot")
        .arg(&dot_output)
        .arg("--docker-compose")
        .arg(&compose_output)
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
    assert_eq!(primary_json["version"], 1);
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

    assert!(
        compose_output.is_file(),
        "expected docker compose output file at {}",
        compose_output.display()
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

    let compose_output = outputs_dir.path().join("scenario.docker-compose.yaml");

    let compose_compile = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--no-opt")
        .arg("--docker-compose")
        .arg(&compose_output)
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
