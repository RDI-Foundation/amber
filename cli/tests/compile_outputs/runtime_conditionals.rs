use super::*;

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
