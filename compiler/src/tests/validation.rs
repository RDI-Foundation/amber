use super::*;

#[tokio::test]
async fn config_validation_error_points_to_invalid_value() {
    use miette::Diagnostic;

    let dir = tmp_dir("scenario-invalid-config-span");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              nested: {
                type: "object",
                properties: { x: { type: "number" } },
                required: ["x"],
              },
            },
            required: ["nested"],
          },
        }
        "#,
    );

    let root_source = format!(
        r##"
        {{
          manifest_version: "0.1.0",
          components: {{
            child: {{
              manifest: "{child}",
              config: {{ nested: {{ x: "bad" }} }},
            }},
          }},
        }}
        "##,
        child = file_url(&child_path),
    );
    write_file(&root_path, &root_source);

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(output.has_errors);

    let report = output
        .diagnostics
        .iter()
        .find(|report| {
            let diag: &dyn Diagnostic = &***report;
            diag.code()
                .is_some_and(|c| c.to_string() == "linker::invalid_config")
        })
        .expect("expected linker::invalid_config diagnostic");
    let diag: &dyn Diagnostic = &**report;
    let labels: Vec<_> = diag
        .labels()
        .expect("invalid_config should include a label")
        .collect();
    assert_eq!(labels.len(), 1);

    let label = &labels[0];
    let offset = root_source.find("\"bad\"").unwrap();
    assert_eq!(label.offset(), offset);
    assert_eq!(label.len(), "\"bad\"".len());
}

#[tokio::test]
async fn missing_required_config_field_points_to_config_key() {
    use miette::Diagnostic;

    let dir = tmp_dir("scenario-missing-config-field-span");
    let root_path = dir.path().join("root.json5");
    let child_path = dir.path().join("child.json5");

    write_file(
        &child_path,
        r#"
        {
          manifest_version: "0.1.0",
          config_schema: {
            type: "object",
            properties: {
              auth_json: { type: "string" },
              agents_md: { type: "string" },
              model: { type: "string" },
              theme: { type: "string" },
              workspace: { type: "string" },
            },
            required: ["auth_json", "agents_md", "model", "theme", "workspace"],
            additionalProperties: false,
          },
          program: {
            image: "child",
            entrypoint: ["child"],
            env: {
              AUTH_JSON: "${config.auth_json}",
              AGENTS_MD: "${config.agents_md}",
              MODEL: "${config.model}",
              THEME: "${config.theme}",
              WORKSPACE: "${config.workspace}",
            },
            network: {
              endpoints: [{ name: "agent", port: 8080 }],
            },
          },
          provides: {
            agent: { kind: "a2a", endpoint: "agent" },
          },
          exports: {
            agent: "self.agent",
          },
        }
        "#,
    );

    let root_source = format!(
        r##"
        {{
          manifest_version: "0.1.0",
          config_schema: {{
            type: "object",
            properties: {{
              auth_json: {{ type: "string" }},
              agents_md: {{ type: "string" }},
            }},
            required: ["auth_json", "agents_md"],
            additionalProperties: false,
          }},
          components: {{
            child: {{
              manifest: "{child}",
              config: {{
                auth_json: "${{config.auth_json}}",
                agents_md: "${{config.agents_md}}",
                theme: "amber",
                workspace: "/tmp/workspace",
              }},
            }},
          }},
          exports: {{ agent: "#child.agent" }},
        }}
        "##,
        child = file_url(&child_path),
    );
    write_file(&root_path, &root_source);

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .check(root_ref, standard_compile_options())
        .await
        .unwrap();

    assert!(output.has_errors);

    let report = output
        .diagnostics
        .iter()
        .find(|report| {
            let diag: &dyn Diagnostic = &***report;
            diag.code()
                .is_some_and(|c| c.to_string() == "linker::invalid_config")
                && diag
                    .to_string()
                    .contains("missing required field config.model")
        })
        .expect("expected linker::invalid_config diagnostic for missing config.model");
    let diag: &dyn Diagnostic = &**report;
    let labels: Vec<_> = diag
        .labels()
        .expect("invalid_config should include a label")
        .collect();
    assert_eq!(labels.len(), 1);

    let label = &labels[0];
    let offset = root_source.find("config:").unwrap();
    assert_eq!(label.offset(), offset);
    assert_eq!(label.len(), "config".len());
}

#[tokio::test]
async fn type_mismatch_reports_expected_and_got() {
    let dir = tmp_dir("scenario-type-mismatch-message");
    let root_path = dir.path().join("root.json5");
    let provider_path = dir.path().join("provider.json5");
    let consumer_path = dir.path().join("consumer.json5");

    write_file(
        &provider_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "child",
            entrypoint: ["child"],
            network: { endpoints: [{ name: "endpoint", port: 80 }] },
          },
          provides: { http: { kind: "http", endpoint: "endpoint" } },
          exports: { http: "http" },
        }
        "#,
    );
    write_file(
        &consumer_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { llm: { kind: "llm" } },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                provider: "{provider}",
                consumer: "{consumer}",
              }},
              bindings: [
                {{ to: "#consumer.llm", from: "#provider.http" }},
              ],
            }}
            "##,
            provider = file_url(&provider_path),
            consumer = file_url(&consumer_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(&err, "expected llm, got http"));
    assert!(!err.to_string().contains("CapabilityDecl"));
}

#[tokio::test]
async fn slot_forwarding_and_export_chain_resolve_to_provider() {
    let dir = tmp_dir("scenario-slot-forwarding");
    let root_path = dir.path().join("root.json5");
    let router_path = dir.path().join("router.json5");
    let gateway_path = dir.path().join("gateway.json5");
    let consumer_path = dir.path().join("consumer.json5");

    write_file(
        &gateway_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          exports: { public_api: "api" },
        }
        "#,
    );
    write_file(
        &router_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              slots: {{ api: {{ kind: "http" }} }},
              components: {{
                gateway: "{gateway}",
              }},
              bindings: [
                {{ to: "#gateway.api", from: "slots.api" }},
              ],
              exports: {{ public_api: "#gateway.public_api" }},
            }}
            "##,
            gateway = file_url(&gateway_path),
        ),
    );
    write_file(
        &consumer_path,
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
              program: {{
                image: "root",
                entrypoint: ["root"],
                network: {{ endpoints: [{{ name: "api", port: 80 }}] }},
              }},
              provides: {{ api: {{ kind: "http", endpoint: "api" }} }},
              components: {{
                router: "{router}",
                consumer: "{consumer}",
              }},
              bindings: [
                {{ to: "#router.api", from: "provides.api" }},
                {{ to: "#consumer.api", from: "#router.public_api" }},
              ],
            }}
            "##,
            router = file_url(&router_path),
            consumer = file_url(&consumer_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    let scenario = &output.scenario;
    let root = scenario.root;
    let consumer_id = scenario
        .components_iter()
        .find(|(_, c)| c.moniker.as_str() == "/consumer")
        .map(|(id, _)| id)
        .expect("consumer component");

    let binding = scenario
        .bindings
        .iter()
        .find(|b| b.to.component == consumer_id && b.to.name == "api")
        .expect("binding to consumer.api");

    assert!(
        matches!(
            &binding.from,
            BindingFrom::Component(provide)
                if provide.component == root && provide.name == "api"
        ),
        "expected consumer.api bound from root.api, got {:?}",
        binding.from
    );
}

#[tokio::test]
async fn variadic_slot_forwarding_preserves_all_sources_and_authored_order() {
    let dir = tmp_dir("scenario-variadic-slot-forwarding");
    let root_path = dir.path().join("root.json5");
    let relay_path = dir.path().join("relay.json5");
    let consumer_path = dir.path().join("consumer.json5");
    let provider_a_path = dir.path().join("provider-a.json5");
    let provider_b_path = dir.path().join("provider-b.json5");

    write_file(
        &provider_a_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "provider-a",
            entrypoint: ["provider-a"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &provider_b_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "provider-b",
            entrypoint: ["provider-b"],
            network: { endpoints: [{ name: "api", port: 80 }] },
          },
          provides: { api: { kind: "http", endpoint: "api" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &consumer_path,
        r#"
        {
          manifest_version: "0.3.0",
          program: {
            image: "consumer",
            entrypoint: [
              "consumer",
              {
                each: "slots.upstream",
                argv: ["--upstream", "${item.url}"],
              },
            ],
            network: { endpoints: [{ name: "http", port: 80 }] },
          },
          slots: {
            upstream: { kind: "http", optional: true, multiple: true },
          },
          provides: { http: { kind: "http", endpoint: "http" } },
          exports: { http: "http" },
        }
        "#,
    );
    write_file(
        &relay_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              slots: {{
                upstream: {{ kind: "http", optional: true, multiple: true }},
              }},
              components: {{
                consumer: "{consumer}",
              }},
              bindings: [
                {{ to: "#consumer.upstream", from: "slots.upstream" }},
              ],
              exports: {{ http: "#consumer.http" }},
            }}
            "##,
            consumer = file_url(&consumer_path),
        ),
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.3.0",
              components: {{
                relay: "{relay}",
                provider_a: "{provider_a}",
                provider_b: "{provider_b}",
              }},
              bindings: [
                {{ to: "#relay.upstream", from: "#provider_a.api" }},
                {{ to: "#relay.upstream", from: "#provider_b.api" }},
              ],
              exports: {{ http: "#relay.http" }},
            }}
            "##,
            relay = file_url(&relay_path),
            provider_a = file_url(&provider_a_path),
            provider_b = file_url(&provider_b_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);

    let with_opt = compiler
        .compile(root_ref.clone(), optimized_compile_options())
        .await
        .expect("compile with optimizations");
    let without_opt = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .expect("compile without optimizations");

    let binding_order = |scenario: &amber_scenario::Scenario| {
        let consumer_id = scenario
            .components_iter()
            .find(|(_, c)| c.moniker.local_name() == Some("consumer"))
            .map(|(id, _)| id)
            .expect("consumer component");

        scenario
            .bindings
            .iter()
            .filter(|binding| binding.to.component == consumer_id && binding.to.name == "upstream")
            .map(|binding| match &binding.from {
                BindingFrom::Component(provide) => scenario
                    .component(provide.component)
                    .moniker
                    .local_name()
                    .expect("provider local name")
                    .to_string(),
                other => panic!("expected component binding, got {other:?}"),
            })
            .collect::<Vec<_>>()
    };

    assert_eq!(
        binding_order(&with_opt.scenario),
        vec!["provider_a", "provider_b"]
    );
    assert_eq!(
        binding_order(&without_opt.scenario),
        vec!["provider_a", "provider_b"]
    );
}

#[tokio::test]
async fn slot_cycle_reports_error() {
    let dir = tmp_dir("scenario-slot-cycle");
    let root_path = dir.path().join("root.json5");
    let a_path = dir.path().join("a.json5");
    let b_path = dir.path().join("b.json5");

    write_file(
        &a_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &b_path,
        r#"
        {
          manifest_version: "0.1.0",
          slots: { api: { kind: "http" } },
          exports: { api: "api" },
        }
        "#,
    );
    write_file(
        &root_path,
        &format!(
            r##"
            {{
              manifest_version: "0.1.0",
              components: {{
                a: "{a}",
                b: "{b}",
              }},
              bindings: [
                {{ to: "#a.api", from: "#b.api" }},
                {{ to: "#b.api", from: "#a.api" }},
              ],
            }}
            "##,
            a = file_url(&a_path),
            b = file_url(&b_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(error_contains(&err, "slot routing cycle detected"));
}

#[tokio::test]
async fn external_root_slot_with_weak_binding_is_allowed() {
    let dir = tmp_dir("external-root-slot-weak");
    let root_path = dir.path().join("root.json5");
    let client_path = dir.path().join("client.json5");

    write_file(
        &client_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "client",
            entrypoint: ["client"],
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
              components: {{ client: "{client}" }},
              bindings: [
                {{ to: "#client.api", from: "slots.api", weak: true }}
              ]
            }}
            "##,
            client = file_url(&client_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let output = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap();

    let scenario = &output.scenario;
    let client_id = scenario
        .components_iter()
        .find(|(_, c)| c.moniker.as_str() == "/client")
        .map(|(id, _)| id)
        .expect("client component");
    let binding = scenario
        .bindings
        .iter()
        .find(|b| b.to.component == client_id && b.to.name == "api")
        .expect("binding to client.api");

    assert!(binding.weak, "binding should be weak");
    assert!(
        matches!(
            &binding.from,
            BindingFrom::External(slot)
                if slot.component == scenario.root && slot.name == "api"
        ),
        "expected external binding from root.api, got {:?}",
        binding.from
    );
}

#[tokio::test]
async fn external_root_slot_requires_weak_binding() {
    let dir = tmp_dir("external-root-slot-strong");
    let root_path = dir.path().join("root.json5");
    let client_path = dir.path().join("client.json5");

    write_file(
        &client_path,
        r#"
        {
          manifest_version: "0.1.0",
          program: {
            image: "client",
            entrypoint: ["client"],
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
              components: {{ client: "{client}" }},
              bindings: [
                {{ to: "#client.api", from: "slots.api" }}
              ]
            }}
            "##,
            client = file_url(&client_path),
        ),
    );

    let compiler = default_compiler();
    let root_ref = manifest_ref_for_path(&root_path);
    let err = compiler
        .compile(root_ref, standard_compile_options())
        .await
        .unwrap_err();

    assert!(
        error_contains(&err, "external slot"),
        "expected external slot weak-binding error, got {err}"
    );
}
