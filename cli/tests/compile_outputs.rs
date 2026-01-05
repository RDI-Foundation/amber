use std::{fs, path::Path, process::Command};

use serde_json::Value;

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

    let output = Command::new(env!("CARGO_BIN_EXE_amber"))
        .arg("compile")
        .arg("--out-dir")
        .arg(outputs_dir.path())
        .arg("--dot")
        .arg("--docker-compose")
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

    let primary_output = outputs_dir.path().join("scenario");
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
        Some("example/child")
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

    let dot_output = outputs_dir.path().join("scenario.dot");
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

    let compose_output = outputs_dir.path().join("scenario.docker-compose.yaml");
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
    assert!(
        compose_contents.contains("context: ./docker/amber-sidecar"),
        "docker compose output missing sidecar build context"
    );
}
