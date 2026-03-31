use super::*;

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
