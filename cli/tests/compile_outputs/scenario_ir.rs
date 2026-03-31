use super::*;

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
