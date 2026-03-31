use super::*;

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
