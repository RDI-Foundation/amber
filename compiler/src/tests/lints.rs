use super::*;

#[tokio::test]
async fn compile_emits_manifest_lints() {
    let dir = tmp_dir("scenario-manifest-lints");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "root",
            entrypoint: ["root"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "endpoint" } },
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert_eq!(output.diagnostics.len(), 2);
    let diagnostics: Vec<_> = output.diagnostics.iter().collect();
    assert!(
        diagnostics
            .iter()
            .all(|diag| diag.severity() == Some(Severity::Warning))
    );
    let codes: Vec<_> = diagnostics
        .iter()
        .filter_map(|diag| diag.code().map(|code| code.to_string()))
        .collect();
    assert!(codes.contains(&"manifest::unused_program".to_string()));
    assert!(codes.contains(&"manifest::unused_provide".to_string()));
    assert!(diagnostics.iter().any(|diag| {
        diag.to_string() == "provide `api` is never used or exported (in component /)"
    }));
}

#[tokio::test]
async fn unused_program_points_to_program_key() {
    use miette::Diagnostic;

    let dir = tmp_dir("unused-program-label");
    let root_path = dir.path().join("root.json5");
    let root_source = r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "unused-program",
            entrypoint: ["/app/start", "--mode", "serve"],
            env: {
              LOG_LEVEL: "info",
              FEATURE_FLAG: "true",
              DATA_DIR: "/app/data",
              CACHE_DIR: "/app/cache",
            },
            mounts: [
              { path: "/app/data", from: "resources.data" },
              { path: "/app/cache", from: "resources.cache" },
            ],
            network: {
              endpoints: [
                { name: "http", port: 8080 },
                { name: "metrics", port: 9090 },
              ],
            },
          },
          resources: {
            data: { kind: "storage", params: { size: "1Gi" } },
            cache: { kind: "storage", params: { size: "1Gi" } },
          },
        }
        "#;
    write_file(&root_path, root_source);

    let compiler = default_compiler();
    let output = compiler
        .compile(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap();

    let report = output
        .diagnostics
        .iter()
        .find(|report| {
            let diag: &dyn Diagnostic = &***report;
            diag.code()
                .is_some_and(|c| c.to_string() == "manifest::unused_program")
        })
        .expect("expected manifest::unused_program diagnostic");
    let diag: &dyn Diagnostic = &**report;
    let labels: Vec<_> = diag
        .labels()
        .expect("unused_program should include a label")
        .collect();
    assert_eq!(labels.len(), 1);

    let label = &labels[0];
    let offset = root_source.find("program:").unwrap();
    assert_eq!(label.offset(), offset);
    assert_eq!(label.len(), "program".len());
}

#[tokio::test]
async fn optimized_compile_keeps_externally_rooted_child_without_exports() {
    let dir = tmp_dir("external-rooted-child-dce");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"],
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "slots.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, optimized_compile_options())
        .await
        .unwrap();

    assert!(
        output
            .scenario
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/child"),
        "optimized compile should retain the externally rooted child"
    );
    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.slots.contains_key("api"),
        "optimized compile should retain the external root slot"
    );
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "api"
        ) && binding.to.name == "api"
    }));
}

#[tokio::test]
async fn optimized_compile_keeps_root_program_driven_by_external_slot_without_exports() {
    let dir = tmp_dir("external-rooted-root-dce");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          program: {
            image: "root",
            entrypoint: ["root"],
            env: { API_URL: "${slots.api.url}" }
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, optimized_compile_options())
        .await
        .unwrap();

    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.program.is_some(),
        "optimized compile should retain the root program when it consumes an external slot"
    );
    assert!(
        root.slots.contains_key("api"),
        "optimized compile should retain the root external slot"
    );
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "api"
        ) && binding.to.component == output.scenario.root
            && binding.to.name == "api"
    }));
}

#[tokio::test]
async fn optimized_compile_keeps_externally_rooted_child_with_repeated_each_without_exports() {
    let dir = tmp_dir("external-rooted-repeated-each-dce");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "child",
            entrypoint: [
              "child",
              { each: "slots.api", argv: ["--api", "${item.url}"] }
            ]
          },
          slots: { api: { kind: "http", optional: true, multiple: true } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              slots: {{ api: {{ kind: "http", optional: true, multiple: true }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "slots.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, optimized_compile_options())
        .await
        .unwrap();

    assert!(
        output
            .scenario
            .components_iter()
            .any(|(_, component)| component.moniker.as_str() == "/child"),
        "optimized compile should retain the externally rooted child when it uses repeated `each`"
    );
    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.slots.contains_key("api"),
        "optimized compile should retain the external root slot for repeated `each`"
    );
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "api"
        ) && binding.to.name == "api"
    }));
}

#[tokio::test]
async fn optimized_compile_keeps_root_program_that_references_all_slots_without_exports() {
    let dir = tmp_dir("external-rooted-all-slots-dce");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            admin: { kind: "http" },
            api: { kind: "http" }
          },
          program: {
            image: "root",
            entrypoint: ["root"],
            env: { ALL_SLOTS: "${slots}" }
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, optimized_compile_options())
        .await
        .unwrap();

    let root = output.scenario.component(output.scenario.root);
    assert!(
        root.program.is_some(),
        "optimized compile should retain a root program that references all slots"
    );
    assert!(
        root.slots.contains_key("admin") && root.slots.contains_key("api"),
        "optimized compile should retain every root slot referenced by `${{slots}}`"
    );
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "admin"
        ) && binding.to.component == output.scenario.root
            && binding.to.name == "admin"
    }));
    assert!(output.scenario.bindings.iter().any(|binding| {
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == output.scenario.root && slot.name == "api"
        ) && binding.to.component == output.scenario.root
            && binding.to.name == "api"
    }));
}

#[tokio::test]
async fn check_suppresses_unused_program_for_externally_rooted_child() {
    let dir = tmp_dir("external-rooted-child-lint");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"],
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "slots.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_suppresses_unused_program_for_root_program_driven_by_external_slot() {
    let dir = tmp_dir("external-rooted-root-lint");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          program: {
            image: "root",
            entrypoint: ["root"],
            env: { API_URL: "${slots.api.url}" }
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_suppresses_unused_program_for_externally_rooted_child_with_repeated_each() {
    let dir = tmp_dir("external-rooted-repeated-each-lint");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "child",
            entrypoint: [
              "child",
              { each: "slots.api", argv: ["--api", "${item.url}"] }
            ]
          },
          slots: { api: { kind: "http", optional: true, multiple: true } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              slots: {{ api: {{ kind: "http", optional: true, multiple: true }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "slots.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_keeps_unused_program_for_external_binding_to_unused_slot() {
    let dir = tmp_dir("external-binding-unused-program-lint");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"]
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "slots.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "expected manifest::unused_program diagnostics, got {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_reports_external_slot_requires_weak_even_with_unrelated_invalid_config() {
    let dir = tmp_dir("mixed-invalid-config-external-weak");
    let root_path = dir.path().join("root.json5");
    let sink_path = dir.path().join("sink.json5");
    let cfg_path = dir.path().join("config-child.json5");

    write_file(
        &sink_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "sink",
            entrypoint: ["sink"],
            env: { API_URL: "${slots.api.url}" }
          },
          slots: { api: { kind: "http" } }
        }
        "#,
    );
    write_file(
        &cfg_path,
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              url: { type: "string" }
            },
            required: ["url"],
            additionalProperties: false
          },
          program: {
            image: "cfg",
            entrypoint: ["cfg"],
            env: { URL: "${config.url}" }
          }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{
                sink: "{sink}",
                cfg: {{
                  manifest: "{cfg}",
                  config: {{ url: "${{slots.api.url}}" }}
                }}
              }},
              bindings: [
                {{ to: "#sink.api", from: "slots.api" }}
              ]
            }}
            "##,
            sink = file_url(&sink_path),
            cfg = file_url(&cfg_path),
        ),
    );

    let compiler = default_compiler();
    let output = compiler
        .check(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap();

    assert!(output.has_errors);
    assert!(
        has_diagnostic_code(&output.diagnostics, "linker::invalid_config"),
        "expected invalid_config diagnostics, got {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        has_diagnostic_code(&output.diagnostics, "linker::external_slot_requires_weak"),
        "expected external_slot_requires_weak diagnostics, got {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        has_diagnostic_code(&output.diagnostics, "linker::unbound_slot"),
        "expected unbound_slot diagnostics, got {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_reports_invalid_export_even_with_unrelated_invalid_config() {
    let dir = tmp_dir("mixed-invalid-config-export-resolution");
    let root_path = dir.path().join("root.json5");
    let sink_path = dir.path().join("sink.json5");
    let cfg_path = dir.path().join("config-child.json5");

    write_file(
        &sink_path,
        r#"
        {
          manifest_version: "0.3.0",
          slots: { api: { kind: "http" } },
          exports: { api: "self.api" }
        }
        "#,
    );
    write_file(
        &cfg_path,
        r#"
        {
          manifest_version: "0.3.0",
          config_schema: {
            type: "object",
            properties: {
              url: { type: "string" }
            },
            required: ["url"],
            additionalProperties: false
          },
          program: {
            image: "cfg",
            entrypoint: ["cfg"],
            env: { URL: "${config.url}" }
          }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{
                sink: "{sink}",
                cfg: {{
                  manifest: "{cfg}",
                  config: {{ url: "${{slots.api.url}}" }}
                }}
              }},
              bindings: [
                {{ to: "#sink.api", from: "slots.api", weak: true }}
              ],
              exports: {{ api: "#sink.api" }}
            }}
            "##,
            sink = file_url(&sink_path),
            cfg = file_url(&cfg_path),
        ),
    );

    let compiler = default_compiler();
    let output = compiler
        .check(
            manifest_ref_for_path(&root_path),
            standard_compile_options(),
        )
        .await
        .unwrap();

    assert!(output.has_errors);
    assert!(
        has_diagnostic_code(&output.diagnostics, "linker::invalid_config"),
        "expected invalid_config diagnostics, got {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
    assert!(
        has_diagnostic_code(&output.diagnostics, "linker::invalid_export"),
        "expected invalid_export diagnostics, got {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_suppresses_unused_program_but_not_unused_provide_for_externally_rooted_child() {
    let dir = tmp_dir("external-rooted-narrow-lint");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"],
            env: { API_URL: "${slots.api.url}" },
            network: { endpoints: [{ name: "out", port: 8080 }] }
          },
          slots: { api: { kind: "http" } },
          provides: {
            out: { kind: "http", endpoint: "out" }
          }
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "slots.api", weak: true }}
              ]
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();
    let diagnostics: Vec<_> = output
        .diagnostics
        .iter()
        .map(|diag| diag.to_string())
        .collect();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        diagnostics
    );
    assert!(
        diagnostics
            .iter()
            .any(|diag| diag == "provide `out` is never used or exported (in component /child)"),
        "expected the child unused-provide warning to remain: {:?}",
        diagnostics
    );
}

#[tokio::test]
async fn check_suppresses_unused_program_for_root_program_that_references_all_slots() {
    let dir = tmp_dir("external-rooted-all-slots-lint");
    let root_path = dir.path().join("root.json5");

    write_file(
        &root_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: {
            admin: { kind: "http" },
            api: { kind: "http" }
          },
          program: {
            image: "root",
            entrypoint: ["root"],
            env: { ALL_SLOTS: "${slots}" }
          }
        }
        "#,
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_program"),
        "unexpected manifest::unused_program diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}

#[tokio::test]
async fn check_treats_weak_binding_targets_as_optional_for_unused_slot_lint() {
    let dir = tmp_dir("scenario-optional-slot-downstream-lint");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ upstream: {{ kind: "http", optional: true }} }},
              components: {{ child: "{child}" }},
              bindings: [
                {{ to: "#child.api", from: "slots.upstream", weak: true }},
              ],
            }}
            "##,
            child = file_url(&child_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(!output.has_errors);
    assert!(
        !has_diagnostic_code(&output.diagnostics, "manifest::unused_slot"),
        "unexpected manifest::unused_slot diagnostics: {:?}",
        output
            .diagnostics
            .iter()
            .map(|diag| diag.to_string())
            .collect::<Vec<_>>()
    );
}
